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
import hashlib
import secrets
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
import iceberg  # noqa: E402
import planner  # noqa: E402

Q = point_export.Q
P_FIELD = point_export.P_FIELD
M = planner.M
QUORUM = 3
N_MEMBERS = planner.N_MEMBERS
THRESHOLD = 2                      # Iceberg t; quorum is 2t-1 = 3
# One MPC step can be a 48-edge garbling, which over a WAN is tens of
# minutes: ~1,600 communication rounds per shachain edge at wide-area
# latency. Keep this well above the slowest step you expect.
STEP_TIMEOUT = int(os.environ.get('STEP_TIMEOUT', 4 * 3600))
# Report each step's communication rounds, which is what a wide-area
# deployment actually pays for and what batching is meant to reduce.
SHOW_ROUNDS = os.environ.get('SHOW_ROUNDS') == '1'


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
        """Deal the group and hand each member its Iceberg share.

        The shachain does not generate key material of its own. It uses the
        replicated seeds Iceberg's key generation already produces, so the
        two share one setup rather than the shachain running a second,
        weaker one beside it.

        Iceberg specifies that key generation comes from a trusted dealer or
        a distributed key generation. This models the dealer, matching
        secp256k1_iceberg_shares_gen: seeds are H_"Iceberg/dealer"(root, n,
        t, rank), and participant k receives the seeds whose subsets do not
        name it. A deployment substitutes Iceberg's key generation, and
        nothing downstream changes, because what is delivered is the same
        object.

        The setup's security is therefore exactly Iceberg's key generation's,
        which is the point: no better, no worse, and not a second thing to
        analyse.
        """
        certs = {}
        for i in range(QUORUM):
            for ext in ('pem', 'key'):
                name = f'P{i}.{ext}'
                with open(os.path.join(self.mpspdz, 'Player-Data', name),
                          'rb') as f:
                    certs[name] = base64.b64encode(f.read()).decode()
        roster = [{'url': u, 'mpc_host': h}
                  for u, h in zip(self.urls, self.mpc_hosts)]
        sid = self.public.setdefault(
            'sid', hashlib.sha256(''.join(self.urls).encode()).hexdigest())

        root = secrets.token_bytes(32)
        shares = iceberg.deal(root, N_MEMBERS, THRESHOLD)
        del root                      # a dealer that keeps the root is a dealer
        for i, url in enumerate(self.urls):
            held = {str(rank): seed.hex()
                    for rank, seed in shares[i + 1].items()}
            post(url, '/setup', {'index': i, 'roster': roster, 'sid': sid,
                                 'certs': certs, 'phi': held})
        print(f'   dealt {N_MEMBERS} Iceberg shares of '
              f'{len(shares[1])} seeds each')

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
        stream = results[0]['stdout'] + results[0].get('stderr', '')
        for line in stream.splitlines():
            if line.startswith('Reg['):
                regs.append(int(line.split('0x')[1].split()[0], 16))
            elif line.startswith('valid '):
                valids.append(int(line.split()[1]))
            elif SHOW_ROUNDS and 'rounds' in line and line.startswith('Data sent'):
                edges = len(plan.get('ops', []))
                print(f'   [step {name}: {edges} edges, {line.strip()}]')
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
        plan, spec, out_vids, commit = self.pl.init_plan()
        precompiled = self.compile_step(plan, domain='binary')
        self._cold = (plan, spec, out_vids, commit, precompiled)
        self.run_step(plan, spec, mode='garble', precompiled=precompiled)

    def init_channel(self, protocol='field'):
        if protocol == 'package':
            plan, spec, out_vids, commit, precompiled = self._cold
            regs, _, _ = self.run_step(plan, spec, mode='eval',
                                       precompiled=precompiled)
        else:
            plan, spec, out_vids, commit = self.pl.init_plan()
            regs, _, _ = self.run_step(plan, spec, protocol=protocol)
        commit(regs)

    def restore(self):
        plan, spec, out_vids, commit = self.pl.restore_plan()
        regs, _, _ = self.run_step(plan, spec)
        commit(regs)
        return len(plan['ops'])

    def prepare_leaf(self):
        plan, spec, out_vids, c, index, commit = self.pl.prepare_plan()
        regs, valids, points = self.run_step(plan, spec)
        # Everything that could reject this leaf runs before the transition
        # is applied: an abort here leaves the channel exactly where it was.
        assert valids == [1], f'scalar validity check failed: {valids}'
        P = self.combine_points(points)[0]
        commit(regs)
        self.public.setdefault('points', {})[str(c)] = [f'{P[0]:x}', f'{P[1]:x}']
        return c, index, P

    def release_leaf(self, c):
        """Reveal the prepared secret for state c in a single round.

        No MPC. The value is hidden by a replicated sharing whose summands
        every member but one can derive, so the online quorum collectively
        holds all of them. Each member sends what it can derive, duplicates
        are compared, and the result is checked against the point published
        for this state. The point check is what makes a lying member
        harmless, and it is the same equation the counterparty verifies.
        """
        vid = self.public['leaves'][str(c)]
        expected = self.public.get('points', {}).get(str(c))
        if expected is None:
            # Refuse before asking anyone for summands. Without a published
            # point there is nothing to check the released secret against,
            # and an unverifiable release is worse than no release: it is
            # the counterparty's check that we would be skipping.
            raise AssertionError(
                f'no point published for state {c}; refusing to release')
        wanted = list(range(N_MEMBERS))
        seen = {}
        # Query every member at once. Sequential requests would make this
        # three round trips rather than one, which is the whole claim.
        t0 = time.time()
        replies, errors = {}, []

        def ask(url):
            try:
                replies[url] = post(url, '/reveal',
                                    {'vid': vid, 'summands': wanted})
            except Exception as e:
                errors.append(f'{url}: {e}')

        threads = [threading.Thread(target=ask, args=(u,))
                   for u in self.active_urls()]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        if errors:
            raise RuntimeError('; '.join(errors))
        for got in replies.values():
            for j, val in got['summands'].items():
                if j in seen and seen[j] != val:
                    raise AssertionError(
                        f'members disagree on summand {j} of state {c}')
                seen[j] = val
        missing = [j for j in wanted if str(j) not in seen]
        if missing:
            raise AssertionError(f'summands {missing} unavailable for state {c}')

        gather = time.time() - t0
        acc = int(self.public['masked'][vid], 16)
        for val in seen.values():
            acc ^= int(val, 16)
        secret = decode_bytes(acc)

        s = int.from_bytes(secret, 'big') % Q
        got_pt = point_export.ec_mul(s)
        if [f'{got_pt[0]:x}', f'{got_pt[1]:x}'] != expected:
            raise AssertionError(
                f'released secret for state {c} does not match its '
                f'published point; a member supplied a bad summand')
        self.public['next_release'] = c + 1
        if SHOW_ROUNDS:
            print(f'   [release state {c}: one round, {gather * 1000:.0f} ms '
                  f'to gather summands from {len(self.active_urls())} members]')
        return secret

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


def local_oracle_seed(workdirs, sid):
    """--local test oracle: reconstruct the shachain seed in the clear.

    Only possible because the local demo hosts every member, and only used
    to check MPC output against the plaintext reference. A deployment has no
    such function: the seed exists nowhere outside the MPC.
    """
    seeds = {}
    for wd in workdirs:
        seeds.update(json.load(open(os.path.join(wd, 'phi.json'))))
    acc = bytes(32)
    for rank in sorted(seeds, key=int):
        summand = iceberg.shachain_summand(
            bytes.fromhex(seeds[rank]), iceberg.SHACHAIN_SEED_TAG, sid)
        acc = bytes(a ^ b for a, b in zip(acc, summand))
    return acc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--local', action='store_true')
    ap.add_argument('--members', help='comma-separated member URLs')
    ap.add_argument('--mpc-hosts', help='comma-separated MPC party hosts')
    ap.add_argument('--updates', type=int, default=6)
    ap.add_argument('--after', type=int, default=3)
    ap.add_argument('--mpspdz', default=os.path.expanduser('~/src/MP-SPDZ'))
    ap.add_argument('--restore-on-change', action='store_true',
                    help='rebuild the frontier from the seed after a quorum '
                         'change. Not needed once the buffer is a replicated '
                         'sharing; kept to measure what it used to cost.')
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
        oracle = (local_oracle_seed(workdirs, coord.public['sid'])
                  if args.local else None)
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
            print('== crash: volatile state destroyed; member 2 offline')
            coord.crash_all()
            coord.public['quorum'] = [0, 1, 3]
            if args.restore_on_change:
                print('== quorum change to [0, 1, 3], rebuilding from the seed')
                t = time.time()
                hashes = coord.restore()
                print(f'   restored with {hashes} hashes in '
                      f'{time.time() - t:.1f}s')
            else:
                print('== quorum change to [0, 1, 3], continuing without a '
                      'rebuild')
                print('   the prepared buffer is a replicated sharing, so the '
                      'new quorum')
                print('   derives every summand it needs and nothing has to '
                      'be recomputed')

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
