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
import iceberg  # noqa: E402

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
        self.phi_file = os.path.join(workdir, 'phi.json')
        self.masks_file = os.path.join(workdir, 'masks.json')
        self.sid = ''
        # phi_j, the replicated PRF seeds from Iceberg's key generation.
        # phi_j is held by every member except j, so any quorum derives
        # every summand and losing one member loses nothing.
        self.phi = self._load(self.phi_file)
        self.masks = self._load(self.masks_file)

    @staticmethod
    def _load(path):
        return json.load(open(path)) if os.path.exists(path) else {}

    def save(self):
        json.dump(self.phi, open(self.phi_file, 'w'))
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
    """Take delivery of this member's phi shares and the channel context.

    In a deployment these arrive from Iceberg's key generation. Here the
    harness supplies them, which is the one place a real system differs.
    """
    STATE.index = req['index']
    STATE.roster = req['roster']
    STATE.sid = req.get('sid', '')
    pd = os.path.join(STATE.workdir, 'Player-Data')
    for name, b64 in req.get('certs', {}).items():
        with open(os.path.join(pd, name), 'wb') as f:
            f.write(base64.b64decode(b64))
    if subprocess.run(['openssl', 'rehash', pd], capture_output=True).returncode:
        subprocess.run(['c_rehash', pd], capture_output=True, check=True)
    # This member's Iceberg share: the seeds whose subsets do not name it.
    STATE.phi.update(req.get('phi', {}))
    STATE.save()
    return {'ok': True}


# ---- key material ------------------------------------------------------
#
# The seed and the buffer mask keys are not generated here. They are
# derived from the seeds in an Iceberg share, which this engine takes as
# given rather than producing.
#
# Iceberg shares a secret as sk = sum over authorised sets A of phi_A, with
# "every share phi_A replicated across all members outside A" (the paper's
# overview), and derives per-tag shares with gen(k, sk_k, w). That is the
# same object this engine needs: a summand held by every member except one,
# and a deterministic per-value derivation from it. An earlier version of
# this file ran a bespoke commit-and-reveal ceremony to build the same
# structure, which was a worse reimplementation of key generation that
# Iceberg has to run anyway.
#
# Drawing phi from vpss1.keygen, which the paper specifies as coming from a
# trusted dealer or a distributed key generation, buys three things. The
# summands are consistent by construction, so no per-value agreement check
# is needed. No entropy depends on a single member. And key generation does
# not pass through this coordinator, which closes the gap a bespoke ceremony
# could not: a corrupted coordinator relaying commitments could show
# different tables to different members.
#
# An Iceberg share is "a collection of 32-byte seeds, one for every group of
# t-1 participants that this participant is NOT a member of". For t=2 that
# is one seed per other participant, which is the structure this engine
# needs. scripts/iceberg.py reimplements the dealing and the tagged hashing
# byte-for-byte from src/modules/iceberg in the benchmark repository, and
# its selftest checks that against the midstates the C hard-codes.
#
# Derivation here uses tags of its own, so a shachain summand cannot collide
# with a signing share drawn from the same seed.

TAG_SEED = iceberg.SHACHAIN_SEED_TAG
TAG_MASK = iceberg.SHACHAIN_MASK_TAG


def _gen(phi_hex, tag, value_id):
    """Derive from an Iceberg seed, with this engine's domain separation.

    Byte-compatible with the tagged hashing in Iceberg's C: see
    scripts/iceberg.py, whose selftest recomputes the midstates the C
    hard-codes and compares them.
    """
    return iceberg.shachain_summand(bytes.fromhex(phi_hex), tag, value_id)


def handle_summand(req):
    """A phi share for an authorised set this member belongs to."""
    STATE.phi[str(req['j'])] = req['phi']
    STATE.save()
    return {'ok': True}


def seed_summand(j):
    """Summand j of the channel's shachain seed."""
    phi = STATE.phi.get(str(j))
    assert phi is not None, f'no phi {j} held'
    return encode_int(_gen(phi, TAG_SEED, STATE.sid))


def buffer_summand(j, vid):
    """Summand j of the sharing that hides prepared value `vid`.

    Derived from a long-term key rather than stored, so a buffer of any
    depth costs no secret storage and no per-leaf distribution. Every
    member except j can compute this, which is what lets a quorum change
    happen without rebuilding the buffer.
    """
    phi = STATE.phi.get(str(j))
    assert phi is not None, f'no phi {j} held'
    return encode_int(_gen(phi, TAG_MASK, vid))


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
        if str(j) in STATE.phi:
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
            inputs.append(seed_summand(j))
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
          '/reveal': handle_reveal}


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
