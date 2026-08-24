#!/usr/bin/env python3
"""Coordinator for the distributed shachain PoC.

Holds only public state (frames, masked values, commitment counters),
compiles each engine step, ships bytecode + public plan + input specs to
the member agents, collects revealed registers and share points, combines
points with replicated cross-checks, and plays the channel against a live
LDK counterparty. Private values never pass through this process.

Modes:
  --local           spawn four member agents on localhost and run the
                    lifecycle (the default local demo)
  --members URLS    comma-separated member URLs (WAN deployment); members
                    must already be running member.py
  --mpc-hosts H     comma-separated hosts the MPC parties dial (defaults to
                    the member URL hosts)

Usage: coordinator.py --local [--updates 6 --after 3]
"""
import argparse
import base64
import glob
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, 'scripts'))
sys.path.insert(0, HERE)
import ref  # noqa: E402
import point_export  # noqa: E402
import planner  # noqa: E402

Q = point_export.Q
P_FIELD = point_export.P_FIELD
M = planner.M
QUORUM = 3
N_MEMBERS = planner.N_MEMBERS
# One MPC step can be a 48-edge garbling, which over a WAN is tens of
# minutes: ~1,600 communication rounds per shachain edge at wide-area
# latency. Keep this well above the slowest step you expect.
STEP_TIMEOUT = int(os.environ.get('STEP_TIMEOUT', 4 * 3600))


def decode_bytes(val):
    out = bytearray(32)
    for i in range(256):
        if (val >> i) & 1:
            out[i // 8] |= 1 << (7 - i % 8)
    return bytes(out)


def decompress(hexpt):
    x = int(hexpt[2:], 16)
    y = pow(x * x * x + 7, (P_FIELD + 1) // 4, P_FIELD)
    if (y * y - x * x * x - 7) % P_FIELD != 0:
        raise ValueError('point is not on the curve')
    if y & 1 != int(hexpt[:2], 16) & 1:
        y = P_FIELD - y
    return (x, y)


def post(url, path, obj, timeout=300):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url + path, data=data,
                                 headers={'Content-Type': 'application/json'})
    resp = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    if not resp.get('ok'):
        raise RuntimeError(f'{url}{path}: {resp.get("err")}')
    return resp


class Coordinator:
    def __init__(self, mpspdz, member_urls, mpc_hosts):
        self.mpspdz = mpspdz
        self.urls = member_urls
        self.mpc_hosts = mpc_hosts
        self.public = planner.new_public()
        self.pl = planner.Planner(self.public)
        self.nonce = 0
        self.port = 14000

    def active_urls(self):
        return [self.urls[i] for i in self.public['quorum']]

    def setup(self):
        certs = {}
        for i in range(QUORUM):
            for ext in ('pem', 'key'):
                name = f'P{i}.{ext}'
                with open(os.path.join(self.mpspdz, 'Player-Data', name),
                          'rb') as f:
                    certs[name] = base64.b64encode(f.read()).decode()
        roster = [{'url': u, 'mpc_host': h}
                  for u, h in zip(self.urls, self.mpc_hosts)]
        # summand j originated by the lowest-indexed member that holds it
        originate = {i: [] for i in range(N_MEMBERS)}
        for j in range(N_MEMBERS):
            originate[0 if j != 0 else 1].append(j)
        for i, url in enumerate(self.urls):
            post(url, '/setup', {'index': i, 'roster': roster,
                                 'originate': originate[i], 'certs': certs})

    def compile_step(self, plan, domain='field'):
        self.nonce += 1
        name = f'shachain_engine-{self.nonce}'
        plan_path = os.path.join(self.mpspdz, 'engine-plan.json')
        json.dump(plan, open(plan_path, 'w'))
        env = dict(os.environ, ENGINE_PLAN=plan_path)
        flags = (['-P', str(Q), '-X'] if domain == 'field' else ['-B', '256'])
        subprocess.run(['./compile.py'] + flags + ['shachain_engine',
                        str(self.nonce)],
                       cwd=self.mpspdz, env=env, check=True,
                       capture_output=True)
        files = {}
        for path in glob.glob(f'{self.mpspdz}/Programs/Bytecode/{name}-*.bc'):
            rel = os.path.relpath(path, self.mpspdz)
            files[rel] = base64.b64encode(open(path, 'rb').read()).decode()
        sch = f'Programs/Schedules/{name}.sch'
        files[sch] = base64.b64encode(
            open(os.path.join(self.mpspdz, sch), 'rb').read()).decode()
        return name, files

    def run_step(self, plan, spec, protocol='field', mode='run',
                 precompiled=None):
        if precompiled:
            name, files = precompiled
            binary, args = 'mal-rep-bmr-party.x', ['-N', '3', '-O']
        elif protocol == 'bmr':
            name, files = self.compile_step(plan, domain='binary')
            binary, args = 'mal-rep-bmr-party.x', ['-N', '3', '-O']
        else:
            name, files = self.compile_step(plan, domain='field')
            binary, args = 'malicious-rep-field-party.x', ['-P', str(Q)]
        self.port += 1
        party0_host = self.mpc_hosts[self.public['quorum'][0]]
        results = [None] * QUORUM
        errors = []

        def call(slot, url):
            try:
                results[slot] = post(url, '/step', {
                    'name': name, 'files': files, 'plan': plan, 'spec': spec,
                    'slot': slot, 'party0_host': party0_host,
                    'port': self.port, 'binary': binary, 'args': args,
                    'mode': mode}, timeout=STEP_TIMEOUT)
            except Exception as e:
                errors.append(f'slot {slot}: {e}')

        threads = [threading.Thread(target=call, args=(slot, url))
                   for slot, url in enumerate(self.active_urls())]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if errors:
            raise RuntimeError('; '.join(errors))
        regs, valids = [], []
        for line in results[0]['stdout'].splitlines():
            if line.startswith('Reg['):
                regs.append(int(line.split('0x')[1].split()[0], 16))
            elif line.startswith('valid '):
                valids.append(int(line.split()[1]))
        return regs, valids, [r['points'] for r in results]

    def combine_points(self, member_points):
        """Replicated cross-check on the published compressed points, then
        sum one point per distinct summand."""
        n = len(member_points[0])
        out = []
        for k in range(n):
            for i in range(QUORUM):
                j = (i + 1) % QUORUM
                assert member_points[i][k][0] == member_points[j][k][1], \
                    f'replicated point mismatch: slots {i}/{j}'
            P = None
            for i in range(QUORUM):
                P = point_export.ec_add(P, decompress(member_points[i][k][0]))
            out.append(P)
        return out

    # -- lifecycle --------------------------------------------------------

    def pregarble_cold_start(self):
        """Compile the (public, input-independent) channel-open program and
        have the quorum garble and stockpile the package. Runs before the
        seed exists."""
        plan, spec, out_vids = self.pl.init_plan()
        precompiled = self.compile_step(plan, domain='binary')
        self._cold = (plan, spec, out_vids, precompiled)
        self.run_step(plan, spec, mode='garble', precompiled=precompiled)

    def init_channel(self, protocol='field'):
        if protocol == 'package':
            plan, spec, out_vids, precompiled = self._cold
            regs, _, _ = self.run_step(plan, spec, mode='eval',
                                       precompiled=precompiled)
        else:
            plan, spec, out_vids = self.pl.init_plan()
            regs, _, _ = self.run_step(plan, spec, protocol=protocol)
        self.pl.store_masked(out_vids, regs)

    def restore(self):
        plan, spec, out_vids = self.pl.restore_plan()
        regs, _, _ = self.run_step(plan, spec)
        self.pl.store_masked(out_vids, regs)
        return len(plan['ops'])

    def prepare_leaf(self):
        plan, spec, out_vids, c, index = self.pl.prepare_plan()
        regs, valids, points = self.run_step(plan, spec)
        assert valids == [1], f'scalar validity check failed: {valids}'
        self.pl.store_masked(out_vids, regs)
        P = self.combine_points(points)[0]
        return c, index, P

    def release_leaf(self, c):
        plan, spec = self.pl.release_plan(c)
        regs, _, _ = self.run_step(plan, spec)
        return decode_bytes(regs[0])

    def crash_all(self):
        for url in self.urls:
            post(url, '/crash', {})


class Counterparty:
    def __init__(self, repo):
        subprocess.run(['cargo', 'build', '-q', '--release'],
                       cwd=os.path.join(repo, 'ldk-check'), check=True)
        self.proc = subprocess.Popen(
            [os.path.join(repo, 'ldk-check', 'target', 'release',
                          'counterparty')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + '\n')
        self.proc.stdin.flush()
        resp = json.loads(self.proc.stdout.readline())
        if not resp.get('ok'):
            raise AssertionError(f'counterparty rejected: {resp}')

    def point(self, index, pt):
        x, y = pt
        compressed = bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')
        self.send({'cmd': 'point', 'idx': index, 'point': compressed.hex()})

    def secret(self, index, secret_bytes):
        self.send({'cmd': 'secret', 'idx': index, 'secret': secret_bytes.hex()})

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def wait_healthy(urls):
    for url in urls:
        for _ in range(50):
            try:
                urllib.request.urlopen(url + '/health', timeout=2).read()
                break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError(f'member at {url} not responding')


def local_oracle_seed(workdirs):
    """--local test oracle: reconstruct the seed from the member state files
    on disk. Only possible because the local demo hosts every member."""
    acc = 0
    for j in range(N_MEMBERS):
        for wd in workdirs:
            s = json.load(open(os.path.join(wd, 'summands.json')))
            if str(j) in s:
                acc ^= int.from_bytes(bytes.fromhex(s[str(j)]), 'big')
                break
    return acc.to_bytes(32, 'big')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--local', action='store_true')
    ap.add_argument('--members', help='comma-separated member URLs')
    ap.add_argument('--mpc-hosts', help='comma-separated MPC party hosts')
    ap.add_argument('--updates', type=int, default=6)
    ap.add_argument('--after', type=int, default=3)
    ap.add_argument('--mpspdz', default=os.path.expanduser('~/src/MP-SPDZ'))
    ap.add_argument('--skip-crash', action='store_true',
                    help='skip the crash, quorum change and RESTORE. Over a '
                         'WAN the RESTORE is tens of sequential hashes and so '
                         'tens of minutes; the local run covers it.')
    ap.add_argument('--cold-start', choices=['package', 'bmr', 'field'],
                    default='package',
                    help='channel-open mode: package pre-garbles the circuit '
                         'at setup (before the seed exists) and evaluates the '
                         'stockpiled package at open in two online rounds; '
                         'bmr garbles in-session; field uses replicated MPC')
    args = ap.parse_args()

    procs, workdirs = [], []
    if args.local:
        root = os.path.join(HERE, 'state-dist')
        if os.path.exists(root):
            shutil.rmtree(root)
        urls, hosts = [], []
        for i in range(N_MEMBERS):
            wd = os.path.join(root, f'member{i}')
            workdirs.append(wd)
            port = 9101 + i
            procs.append(subprocess.Popen(
                [sys.executable, os.path.join(HERE, 'member.py'),
                 '--port', str(port), '--workdir', wd,
                 '--mpspdz', args.mpspdz]))
            urls.append(f'http://127.0.0.1:{port}')
            hosts.append('127.0.0.1')
    else:
        urls = args.members.split(',')
        hosts = (args.mpc_hosts.split(',') if args.mpc_hosts else
                 [u.split('//')[1].split(':')[0] for u in urls])
    wait_healthy(urls)

    src = os.path.join(REPO, 'programs', 'shachain_engine.mpc')
    dst = os.path.join(args.mpspdz, 'Programs', 'Source',
                       'shachain_engine.mpc')
    if not os.path.exists(dst):
        os.symlink(src, dst)

    coord = Coordinator(args.mpspdz, urls, hosts)
    cp = Counterparty(REPO)
    t0 = time.time()
    try:
        print('== setup: dealing RSS summands member-to-member')
        coord.setup()
        oracle = local_oracle_seed(workdirs) if args.local else None
        if args.cold_start == 'package':
            t = time.time()
            coord.pregarble_cold_start()
            print(f'== pre-garbled channel-open package stockpiled '
                  f'({time.time() - t:.1f}s, before the seed is used)')

        label = {'package': 'stockpiled garbled package',
                 'bmr': 'jointly garbled BMR circuit',
                 'field': 'replicated MPC'}[args.cold_start]
        print(f'== channel open: 48-edge cold start via {label}')
        t = time.time()
        coord.init_channel(protocol=args.cold_start)
        print(f'   cold start {time.time() - t:.1f}s')

        def do_update():
            t = time.time()
            c, index, point = coord.prepare_leaf()
            cp.point(index, point)
            line = f'   state {c}: point published'
            if c > 0:
                prev = coord.release_leaf(c - 1)
                prev_index = M - (c - 1)
                cp.secret(prev_index, prev)
                if oracle is not None:
                    assert prev == ref.generate_from_seed(oracle, prev_index)
                line += f', state {c - 1} revoked'
            print(f'{line} ({time.time() - t:.1f}s)')

        print(f'== steady state: {args.updates} updates')
        for _ in range(args.updates):
            do_update()

        if args.skip_crash:
            print('== crash, quorum change and RESTORE skipped')
        else:
            print('== crash: all volatile masks destroyed; member 2 offline')
            coord.crash_all()
            coord.public['quorum'] = [0, 1, 3]
            print('== quorum change to [0, 1, 3] + RESTORE from summands')
            t = time.time()
            hashes = coord.restore()
            print(f'   restored with {hashes} hashes in {time.time() - t:.1f}s')

            print(f'== continuing: {args.after} updates with the new quorum')
            for _ in range(args.after):
                do_update()

        cp.close()
        print(f'== distributed PoC complete in {time.time() - t0:.1f}s: '
              f'LDK accepted every point and secret')
    finally:
        for p in procs:
            p.terminate()


if __name__ == '__main__':
    main()
