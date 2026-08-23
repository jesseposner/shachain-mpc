#!/usr/bin/env python3
"""Custodian member agent for the distributed shachain PoC.

Runs on the member's own machine and is the only place that member's
private state exists:

  - durable: RSS seed summands (summands.json), dealt member-to-member;
  - volatile: XOR masks for frontier values (masks.json).

The coordinator only ever sends public data (compiled bytecode, the public
plan, an input SPEC naming which private values to supply) and receives
public data back (party-0 stdout with revealed registers, and curve points
computed from this member's own Z_q shares). Fresh masks are generated
here and never leave this process.

Endpoints (JSON over HTTP):
  POST /setup    {index, roster: [{url, mpc_host}], originate: [j...],
                  certs: {filename: b64}}   store certs, deal summands out
  POST /summand  {j, value}                 from a peer member
  POST /step     {name, files: {relpath: b64}, plan, spec, slot,
                  party0_host, port, binary}
                 -> {stdout, points: [[cx_hex, ...], ...]}
  POST /crash    {}                          wipe volatile masks
  GET  /health

Usage: member.py --port 9001 --workdir DIR --mpspdz DIR
"""
import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'scripts'))
import point_export  # noqa: E402

Q = point_export.Q
R_INV = pow(2**256 % Q, -1, Q)


def encode_int(value_bytes):
    val = 0
    for i in range(256):
        val |= ((value_bytes[i // 8] >> (7 - i % 8)) & 1) << i
    return val


class State:
    def __init__(self, workdir, mpspdz):
        self.workdir = workdir
        self.mpspdz = mpspdz
        self.index = None
        self.roster = []
        os.makedirs(os.path.join(workdir, 'Player-Data'), exist_ok=True)
        os.makedirs(os.path.join(workdir, 'Persistence'), exist_ok=True)
        # party binaries resolve their shared libraries relative to cwd
        import glob as _glob
        for lib in _glob.glob(os.path.join(mpspdz, '*.so')):
            dst = os.path.join(workdir, os.path.basename(lib))
            if not os.path.exists(dst):
                os.symlink(lib, dst)
        self.summands_file = os.path.join(workdir, 'summands.json')
        self.masks_file = os.path.join(workdir, 'masks.json')
        self.summands = self._load(self.summands_file)
        self.masks = self._load(self.masks_file)

    @staticmethod
    def _load(path):
        return json.load(open(path)) if os.path.exists(path) else {}

    def save(self):
        json.dump(self.summands, open(self.summands_file, 'w'))
        json.dump(self.masks, open(self.masks_file, 'w'))


STATE = None


def handle_setup(req):
    STATE.index = req['index']
    STATE.roster = req['roster']
    pd = os.path.join(STATE.workdir, 'Player-Data')
    for name, b64 in req.get('certs', {}).items():
        with open(os.path.join(pd, name), 'wb') as f:
            f.write(base64.b64decode(b64))
    if subprocess.run(['openssl', 'rehash', pd], capture_output=True).returncode:
        subprocess.run(['c_rehash', pd], capture_output=True, check=True)
    # Deal the summands this member originates to every other holder
    # (member-to-member; the coordinator never sees them).
    for j in req.get('originate', []):
        value = secrets.token_bytes(32).hex()
        STATE.summands[str(j)] = value
        for i, peer in enumerate(STATE.roster):
            if i != STATE.index and i != j:
                data = json.dumps({'j': j, 'value': value}).encode()
                r = urllib.request.Request(
                    peer['url'] + '/summand', data=data,
                    headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(r, timeout=30).read()
    STATE.save()
    return {'ok': True}


def handle_summand(req):
    STATE.summands[str(req['j'])] = req['value']
    STATE.save()
    return {'ok': True}


def handle_crash(_req):
    STATE.masks = {}
    if os.path.exists(STATE.masks_file):
        os.remove(STATE.masks_file)
    return {'ok': True}


def build_inputs(spec, slot):
    """Resolve the input spec into this member's ordered input integers.
    Fresh masks are generated and staged; committed after the run succeeds."""
    inputs, staged = [], {}
    for j, s in spec['summands']:
        if s == slot:
            value = STATE.summands.get(str(j))
            assert value is not None, f'missing summand {j}'
            inputs.append(encode_int(bytes.fromhex(value)))
    for vid in spec['masked_vids']:
        assert vid in STATE.masks, f'missing mask for {vid}'
        inputs.append(int(STATE.masks[vid], 16))
    for vid in spec['fresh_vids']:
        r = secrets.randbits(256)
        staged[vid] = hex(r)
        inputs.append(r)
    return inputs, staged


def handle_step(req):
    slot = req['slot']
    # 1. Materialize the compiled program.
    for rel, b64 in req['files'].items():
        path = os.path.join(STATE.workdir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(base64.b64decode(b64))
    # 2. Private inputs, in the engine's consumption order.
    inputs, staged = build_inputs(req['spec'], slot)
    with open(os.path.join(STATE.workdir, 'Player-Data',
                           f'Input-P{slot}-0'), 'w') as f:
        f.write('\n'.join(str(v) for v in inputs) + '\n')
    # 3. Clear stale persistence, run the party.
    persist = os.path.join(STATE.workdir, 'Persistence',
                           f'Transactions-P{slot}.data')
    if os.path.exists(persist):
        os.remove(persist)
    cmd = [os.path.join(STATE.mpspdz, req['binary']),
           str(slot), req['name'], '-h', req['party0_host'],
           '-pn', str(req['port'])] + req.get('args', [])
    out = subprocess.run(cmd, cwd=STATE.workdir, capture_output=True,
                         text=True, timeout=600)
    if out.returncode != 0:
        return {'ok': False, 'err': out.stderr[-2000:]}
    for vid, r in staged.items():
        STATE.masks[vid] = r
    STATE.save()
    # 4. If scalars were exported, publish this member's share points.
    points = []
    if os.path.exists(persist):
        raw = point_export.read_shares(persist)
        for k in range(len(raw) // 2 - 1):
            pts = []
            for comp in (raw[2 + 2 * k], raw[3 + 2 * k]):
                x, y = point_export.ec_mul(comp * R_INV % Q)
                pts.append(f'{2 + (y & 1):02x}{x:064x}')
            points.append(pts)
    return {'ok': True, 'stdout': out.stdout, 'points': points}


ROUTES = {'/setup': handle_setup, '/summand': handle_summand,
          '/step': handle_step, '/crash': handle_crash}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = json.dumps({'ok': True, 'index': STATE.index}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        req = json.loads(self.rfile.read(length) or '{}')
        handler = ROUTES.get(self.path)
        try:
            resp = handler(req) if handler else {'ok': False, 'err': '404'}
        except Exception as e:  # surfaced to the coordinator
            resp = {'ok': False, 'err': f'{type(e).__name__}: {e}'}
        body = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    global STATE
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--workdir', required=True)
    ap.add_argument('--mpspdz', default=os.path.expanduser('~/src/MP-SPDZ'))
    args = ap.parse_args()
    os.makedirs(args.workdir, exist_ok=True)
    STATE = State(args.workdir, args.mpspdz)
    server = HTTPServer(('0.0.0.0', args.port), Handler)
    print(f'member agent on :{args.port}, workdir {args.workdir}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
