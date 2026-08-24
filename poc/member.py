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
import hashlib
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
# A single step can be a 48-edge garbling, tens of minutes over a WAN.
STEP_TIMEOUT = int(os.environ.get('STEP_TIMEOUT', 4 * 3600))


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
        self.maskkeys_file = os.path.join(workdir, 'maskkeys.json')
        self.masks_file = os.path.join(workdir, 'masks.json')
        self.sid = ''
        self.contrib = {}
        self.inbox = {}
        self.summands = self._load(self.summands_file)
        # Long-term keys for buffer summands. Key j is held by every member
        # except j, so any quorum can derive every summand and losing one
        # member loses nothing. This is what makes a prepared buffer survive
        # a quorum change instead of needing a rebuild from the seed.
        self.maskkeys = self._load(self.maskkeys_file)
        self.masks = self._load(self.masks_file)

    @staticmethod
    def _load(path):
        return json.load(open(path)) if os.path.exists(path) else {}

    def save(self):
        json.dump(self.summands, open(self.summands_file, 'w'))
        json.dump(self.maskkeys, open(self.maskkeys_file, 'w'))
        json.dump(self.masks, open(self.masks_file, 'w'))


STATE = None

# Only these may be executed by a /step request. The binary name arrives from
# the coordinator, so without a whitelist os.path.join lets a caller name any
# path, including an absolute one.
ALLOWED_BINARIES = {
    'malicious-rep-field-party.x', 'replicated-field-party.x',
    'malicious-rep-bin-party.x', 'replicated-bin-party.x',
    'mal-rep-bmr-party.x', 'rep-bmr-party.x',
    'malicious-shamir-party.x',
}


def safe_path(base, rel):
    """Resolve rel under base, refusing anything that escapes it.

    os.path.join discards base entirely for an absolute rel and happily
    resolves '..', so a caller-supplied key could otherwise write to any
    path this process can reach."""
    base = os.path.realpath(base)
    full = os.path.realpath(os.path.join(base, rel))
    if full != base and not full.startswith(base + os.sep):
        raise ValueError(f'path escapes the working directory: {rel!r}')
    return full


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
        maskkey = secrets.token_bytes(32).hex()
        STATE.summands[str(j)] = value
        STATE.maskkeys[str(j)] = maskkey
        for i, peer in enumerate(STATE.roster):
            if i != STATE.index and i != j:
                data = json.dumps({'j': j, 'value': value,
                                   'maskkey': maskkey}).encode()
                r = urllib.request.Request(
                    peer['url'] + '/summand', data=data,
                    headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(r, timeout=30).read()
    STATE.save()
    return {'ok': True}


# ---- setup ceremony ---------------------------------------------------
#
# Summand j is held by every member except j. Two things have to be true of
# it: nobody chooses it, and every holder ends up with the same bytes.
#
# The original setup satisfied neither. One originator generated each
# summand alone, so a weak generator at that one member handed the whole
# seed to anyone who compromised a single other member, which is a failure
# the corruption model does not even count. And an originator could send
# different bytes to different holders, so different quorums would derive
# different chains.
#
# So: every holder of summand j contributes to it, and the summand is the
# XOR of those contributions, which is uniform if any one contributor's
# generator is sound. Contributions are committed before they are revealed,
# so nobody can see others' values and then pick their own to steer the
# result. Finally every holder publishes a digest of the summand it
# computed, and the coordinator refuses to continue unless all holders of a
# summand agree, which is what catches an equivocating contributor.
#
# One contribution covers both the seed summand and the buffer mask key.


def _commit(contribution, nonce, sid, frm, j):
    return hashlib.sha256(
        contribution + nonce + sid.encode()
        + f'|{frm}|{j}'.encode()).hexdigest()


def handle_ceremony_commit(req):
    """Phase one: generate contributions and publish commitments to them."""
    STATE.index = req['index']
    STATE.roster = req['roster']
    STATE.sid = req['sid']
    pd = os.path.join(STATE.workdir, 'Player-Data')
    for name, b64 in req.get('certs', {}).items():
        with open(os.path.join(pd, name), 'wb') as f:
            f.write(base64.b64decode(b64))
    if subprocess.run(['openssl', 'rehash', pd],
                      capture_output=True).returncode:
        subprocess.run(['c_rehash', pd], capture_output=True, check=True)

    STATE.contrib = {}
    commitments = {}
    for j in range(len(STATE.roster)):
        if j == STATE.index:
            continue                      # a member does not hold summand j=itself
        contribution = secrets.token_bytes(64)   # 32 seed + 32 mask key
        nonce = secrets.token_bytes(32)
        STATE.contrib[j] = (contribution, nonce)
        commitments[str(j)] = _commit(contribution, nonce, STATE.sid,
                                      STATE.index, j)
    STATE.save()
    return {'ok': True, 'commitments': commitments}


def handle_contribution(req):
    """A co-holder's revealed contribution to a summand we also hold."""
    STATE.inbox.setdefault(int(req['j']), {})[int(req['frm'])] = (
        req['contribution'], req['nonce'])
    return {'ok': True}


# Fault injection, for testing that the ceremony's checks actually fire.
# CEREMONY_FAULT=badreveal   reveal a contribution that does not match the
#                            commitment already published
# CEREMONY_FAULT=equivocate  send different bytes to different holders
# CEREMONY_FAULT=badcombine  verify honestly, then store a different summand
CEREMONY_FAULT = os.environ.get('CEREMONY_FAULT', '')


def handle_ceremony_reveal(req):
    """Phase two: reveal to co-holders, verify, combine, and report a digest
    of each summand so the coordinator can detect equivocation."""
    commitments = req['commitments']          # {from: {j: commitment}}
    n = len(STATE.roster)

    first = True
    for j, (contribution, nonce) in STATE.contrib.items():
        for i, peer in enumerate(STATE.roster):
            if i == STATE.index or i == j:
                continue                      # i does not hold summand j
            sent = contribution
            if CEREMONY_FAULT == 'badreveal':
                sent = bytes([contribution[0] ^ 1]) + contribution[1:]
            elif CEREMONY_FAULT == 'equivocate' and first:
                sent = bytes([contribution[0] ^ 1]) + contribution[1:]
                first = False
            body = json.dumps({'j': j, 'frm': STATE.index,
                               'contribution': sent.hex(),
                               'nonce': nonce.hex()}).encode()
            r = urllib.request.Request(
                peer['url'] + '/contribution', data=body,
                headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(r, timeout=30).read()
    return {'ok': True, 'stage': 'revealed'}


def handle_ceremony_combine(req):
    commitments = req['commitments']
    n = len(STATE.roster)
    digests = {}
    for j in range(n):
        if j == STATE.index:
            continue
        parts = {STATE.index: STATE.contrib[j]}
        for frm, (c_hex, nonce_hex) in STATE.inbox.get(j, {}).items():
            parts[frm] = (bytes.fromhex(c_hex), bytes.fromhex(nonce_hex))
        expected_holders = {i for i in range(n) if i != j}
        if set(parts) != expected_holders:
            return {'ok': False,
                    'err': f'summand {j}: contributions from {sorted(parts)}, '
                           f'expected {sorted(expected_holders)}'}
        combined = bytes(64)
        for frm in sorted(parts):
            contribution, nonce = parts[frm]
            want = commitments[str(frm)][str(j)]
            if _commit(contribution, nonce, STATE.sid, frm, j) != want:
                return {'ok': False,
                        'err': f'member {frm} revealed a contribution to '
                               f'summand {j} that does not match its '
                               f'commitment'}
            combined = bytes(a ^ b for a, b in zip(combined, contribution))
        if CEREMONY_FAULT == 'badcombine' and j == min(
                x for x in range(n) if x != STATE.index):
            # every contribution verified, but this holder keeps something
            # else: only the cross-check of holders' digests catches it
            combined = bytes([combined[0] ^ 1]) + combined[1:]
        STATE.summands[str(j)] = combined[:32].hex()
        STATE.maskkeys[str(j)] = combined[32:].hex()
        digests[str(j)] = hashlib.sha256(
            combined + STATE.sid.encode() + b'|summand-digest').hexdigest()
    STATE.contrib = {}
    STATE.inbox = {}
    STATE.save()
    return {'ok': True, 'digests': digests}


def handle_summand(req):
    STATE.summands[str(req['j'])] = req['value']
    if 'maskkey' in req:
        STATE.maskkeys[str(req['j'])] = req['maskkey']
    STATE.save()
    return {'ok': True}


def buffer_summand(j, vid):
    """Summand j of the sharing that hides prepared value `vid`.

    Derived from a long-term key rather than stored, so a buffer of any
    depth costs no secret storage and no per-leaf distribution. Every
    member except j can compute this, which is what lets a quorum change
    happen without rebuilding the buffer.
    """
    key = STATE.maskkeys.get(str(j))
    assert key is not None, f'no mask key {j} held'
    digest = hashlib.sha256(bytes.fromhex(key) + vid.encode()).digest()
    return encode_int(digest)


def handle_reveal(req):
    """Hand over this member's mask for an already-prepared secret.

    A prepared secret is stored as a public masked value plus one secret
    mask per online member, so revealing it is not a computation: the
    members send their masks and the adapter XORs. That makes the payment
    path one round of plain messaging with no MPC session, no circuit and
    no compilation.

    A lying member cannot pass off a wrong secret, because the adapter
    checks the result against the per-commitment point published earlier.
    Whether this release is permitted at all is the authorization layer's
    question, and that layer does not exist yet.
    """
    vid = req['vid']
    have = {}
    for j in req.get('summands', []):
        if str(j) in STATE.maskkeys:
            have[str(j)] = hex(buffer_summand(j, vid))
    if not have:
        return {'ok': False, 'err': f'no summands derivable for {vid}'}
    return {'ok': True, 'summands': have}


def handle_crash(_req):
    STATE.masks = {}
    if os.path.exists(STATE.masks_file):
        os.remove(STATE.masks_file)
    return {'ok': True}


def build_inputs(spec, slot):
    """Resolve the input spec into this member's ordered input integers.

    Buffer summands are derived from long-term keys, so nothing is staged
    and nothing needs saving after a run: any quorum can recompute them."""
    inputs = []
    for j, s in spec['summands']:
        if s == slot:
            value = STATE.summands.get(str(j))
            assert value is not None, f'missing summand {j}'
            inputs.append(encode_int(bytes.fromhex(value)))
    for vid, assignment in spec['masked_vids']:
        for j, s in assignment:
            if s == slot:
                inputs.append(buffer_summand(j, vid))
    for vid, assignment in spec['fresh_vids']:
        for j, s in assignment:
            if s == slot:
                inputs.append(buffer_summand(j, vid))
    return inputs, {}


def handle_step(req):
    slot = req['slot']
    mode = req.get('mode', 'run')
    # 1. Materialize the compiled program.
    for rel, b64 in req['files'].items():
        path = safe_path(STATE.workdir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(base64.b64decode(b64))
    # 2. Private inputs, in the engine's consumption order. A 'garble' step
    # is input-independent: nothing private is needed or supplied.
    input_file = os.path.join(STATE.workdir, 'Player-Data',
                              f'Input-P{slot}-0')
    staged = {}
    if mode == 'garble':
        open(input_file, 'a').close()
    else:
        inputs, staged = build_inputs(req['spec'], slot)
        with open(input_file, 'w') as f:
            f.write('\n'.join(str(v) for v in inputs) + '\n')
    # 3. Clear stale persistence, run the party.
    persist = os.path.join(STATE.workdir, 'Persistence',
                           f'Transactions-P{slot}.data')
    if os.path.exists(persist):
        os.remove(persist)
    pkg = os.path.join(STATE.workdir, f'bmr-pkg-{req["name"]}')
    extra = req.get('args', [])
    if mode == 'garble':
        extra = extra + ['-G', pkg]
    elif mode == 'eval':
        extra = extra + ['-E', pkg]
    binary = req['binary']
    if binary not in ALLOWED_BINARIES:
        return {'ok': False, 'err': f'binary not permitted: {binary!r}'}
    cmd = [os.path.join(STATE.mpspdz, binary),
           str(slot), req['name'], '-h', req['party0_host'],
           '-pn', str(req['port'])] + extra
    out = subprocess.run(cmd, cwd=STATE.workdir, capture_output=True,
                         text=True, timeout=STEP_TIMEOUT)
    if out.returncode != 0:
        return {'ok': False, 'err': out.stderr[-2000:]}
    if mode == 'eval':
        # one-time use: a garbled package must never be evaluated twice
        os.remove(f'{pkg}-P{slot}')
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
    # MP-SPDZ reports timings and round counts on stderr; the coordinator
    # wants those as well as the revealed values on stdout.
    return {'ok': True, 'stdout': out.stdout, 'stderr': out.stderr,
            'points': points}


ROUTES = {'/setup': handle_setup, '/summand': handle_summand,
          '/step': handle_step, '/crash': handle_crash,
          '/reveal': handle_reveal,
          '/ceremony_commit': handle_ceremony_commit,
          '/contribution': handle_contribution,
          '/ceremony_reveal': handle_ceremony_reveal,
          '/ceremony_combine': handle_ceremony_combine}


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
    ap.add_argument('--bind', default='0.0.0.0',
                    help='address to listen on. Prefer the mesh address; the '
                         'default listens on every interface, which is only '
                         'safe behind a private network.')
    args = ap.parse_args()
    os.makedirs(args.workdir, exist_ok=True)
    STATE = State(args.workdir, args.mpspdz)
    server = HTTPServer((args.bind, args.port), Handler)
    print(f'member agent on {args.bind}:{args.port}, '
          f'workdir {args.workdir}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
