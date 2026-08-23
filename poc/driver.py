#!/usr/bin/env python3
"""End-to-end threshold shachain proof of concept.

Runs a channel lifecycle with a 2-of-4 custodian group (threshold t=2:
quorum of 2t-1 = 3 online members, tolerating 1 corruption, group n=4):

  1. Setup: an RSS seed. Four summands, summand j held by every member
     except j, so any quorum of three holds all four. Summand files are the
     only durable secret state.
  2. Steady state: for each commitment number c, an MPC run advances the
     DFS frontier by exactly the BOLT-required edges, re-shares new frontier
     nodes under fresh XOR masks (volatile state), exports the leaf scalar
     for point publication, and a later run opens the leaf for revocation.
  3. Counterparty: a live LDK process (rust-lightning) receives every point
     and secret, runs its own insert_secret derivation checks, and verifies
     each revealed secret matches the earlier point.
  4. Crash + quorum change: volatile masks are destroyed, one member goes
     offline, the standby joins, and the frontier is rebuilt from the seed
     summands (RESTORE, <= 48 hashes). The channel continues byte-identically.

Public bookkeeping (frame stack, masked values, commitment counter) is
non-secret adapter state. Per-member mask files are volatile session state.
This driver simulates all members on one machine for the local PoC; on a
real deployment each member's state directory lives with that member.

Out of scope, recorded as limitations: the release-authorization layer,
duplicate-consistency checks on summand inputs, and garbled-circuit channel
open (the cold start here runs through the same replicated MPC).

Usage: driver.py [--updates N] [--mpspdz DIR]
"""
import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import ref  # noqa: E402
import point_export  # noqa: E402

Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
M = 2**48 - 1
WIDTH = 48
N_MEMBERS = 4
QUORUM = 3


def encode(value_bytes):
    """32 bytes -> the input-integer convention shared with input.py."""
    val = 0
    for i in range(256):
        val |= ((value_bytes[i // 8] >> (7 - i % 8)) & 1) << i
    return val


def decode(val):
    out = bytearray(32)
    for i in range(256):
        if (val >> i) & 1:
            out[i // 8] |= 1 << (7 - i % 8)
    return bytes(out)


class Member:
    """One custodian's private state: durable summands, volatile masks."""

    def __init__(self, root, index):
        self.index = index
        self.dir = os.path.join(root, f'member{index}')
        os.makedirs(self.dir, exist_ok=True)
        self.summands_file = os.path.join(self.dir, 'summands.json')  # durable
        self.masks_file = os.path.join(self.dir, 'masks.json')        # volatile
        self.summands = self._load(self.summands_file)
        self.masks = self._load(self.masks_file)

    @staticmethod
    def _load(path):
        return json.load(open(path)) if os.path.exists(path) else {}

    def save(self):
        json.dump(self.summands, open(self.summands_file, 'w'))
        json.dump(self.masks, open(self.masks_file, 'w'))

    def crash(self):
        """Lose all volatile state."""
        self.masks = {}
        if os.path.exists(self.masks_file):
            os.remove(self.masks_file)


class Engine:
    def __init__(self, mpspdz, state_root):
        self.mpspdz = mpspdz
        self.state_root = state_root
        os.makedirs(state_root, exist_ok=True)
        self.members = [Member(state_root, i) for i in range(N_MEMBERS)]
        self.public_file = os.path.join(state_root, 'public.json')
        if os.path.exists(self.public_file):
            self.public = json.load(open(self.public_file))
        else:
            self.public = {
                'frames': [],        # [prefix, depth, value_id], top = last
                'masked': {},        # value_id -> public masked value (hex)
                'next_vid': 0,
                'next_commitment': 0,
                'next_release': 0,
                'quorum': [0, 1, 2],
            }
        self.nonce = 0

    def save(self):
        json.dump(self.public, open(self.public_file, 'w'))
        for m in self.members:
            m.save()

    # -- plumbing ---------------------------------------------------------

    def new_vid(self):
        vid = f'v{self.public["next_vid"]}'
        self.public['next_vid'] += 1
        return vid

    def active(self):
        return [self.members[i] for i in self.public['quorum']]

    def run(self, plan, party_inputs):
        """Execute one engine step. party_inputs[slot] is the ordered list of
        input integers for that party slot. Returns the ordered list of
        revealed 256-bit register values plus the list of validity bits."""
        mpspdz = self.mpspdz
        plan_path = os.path.join(self.state_root, 'plan.json')
        json.dump(plan, open(plan_path, 'w'))
        self.nonce += 1
        for slot in range(QUORUM):
            with open(f'{mpspdz}/Player-Data/Input-P{slot}-0', 'w') as f:
                f.write('\n'.join(str(v) for v in party_inputs[slot]) + '\n')
        env = dict(os.environ, ENGINE_PLAN=plan_path)
        name = f'shachain_engine-{self.nonce}'
        subprocess.run(
            ['./compile.py', '-P', str(Q), '-X', 'shachain_engine',
             str(self.nonce)],
            cwd=mpspdz, env=env, check=True, capture_output=True)
        for i in range(QUORUM):
            path = f'{mpspdz}/Persistence/Transactions-P{i}.data'
            if os.path.exists(path):
                os.remove(path)
        out = subprocess.run(
            ['Scripts/mal-rep-field.sh', name, '-P', str(Q)],
            cwd=mpspdz, env=env, check=True, capture_output=True, text=True)
        regs, valids = [], []
        for line in out.stdout.splitlines():
            if line.startswith('Reg['):
                regs.append(int(line.split('0x')[1].split()[0], 16))
            elif line.startswith('valid '):
                valids.append(int(line.split()[1]))
        return regs, valids

    def masked_entry(self, vid, order):
        """Assemble plan 'masked' entry and record each active member's mask
        input for value vid into `order` (per-slot input lists)."""
        for slot, mem in enumerate(self.active()):
            order[slot].append(int(mem.masks[vid], 16))
        return {'id': vid, 'm': self.public['masked'][vid]}

    def fresh_masks(self, vid, order):
        """Generate fresh masks for a 'mask' output; masks are saved only
        after the run succeeds (the caller records them)."""
        pending = []
        for slot, mem in enumerate(self.active()):
            r = secrets.randbits(256)
            order[slot].append(r)
            pending.append((mem, vid, r))
        return pending

    @staticmethod
    def commit_masks(pending):
        for mem, vid, r in pending:
            mem.masks[vid] = hex(r)

    def store_masked(self, vid, revealed):
        self.public['masked'][vid] = hex(revealed)

    # -- lifecycle --------------------------------------------------------

    def setup_seed(self):
        """Create RSS summands: summand j held by every member except j."""
        for j in range(N_MEMBERS):
            summand = secrets.token_bytes(32)
            for i, mem in enumerate(self.members):
                if i != j:
                    mem.summands[str(j)] = summand.hex()
        self.save()

    def seed_plan_inputs(self, order):
        """Plan entry reconstructing the seed from summands, with each
        summand supplied by its lowest-indexed active holder."""
        slots = []
        for j in range(N_MEMBERS):
            slot = next(s for s, mem in enumerate(self.active())
                        if str(j) in mem.summands)
            slots.append(slot)
            mem = self.active()[slot]
            order[slot].append(encode(bytes.fromhex(mem.summands[str(j)])))
        return {'id': 'seed', 'slots': slots}

    def reference_seed(self):
        """Test oracle only: reconstruct the seed in the clear to check the
        MPC against ref.py. A real deployment has no such function."""
        acc = 0
        for j in range(N_MEMBERS):
            holder = next(m for m in self.members if str(j) in m.summands)
            acc ^= int.from_bytes(bytes.fromhex(holder.summands[str(j)]), 'big')
        return acc.to_bytes(32, 'big')

    def init_channel(self):
        """Cold start: build the DFS frontier down to leaf M."""
        order = [[] for _ in range(QUORUM)]
        summand_entry = self.seed_plan_inputs(order)
        ops, frames = [], []
        cur = 'seed'
        prefix = 0
        for bit in range(WIDTH - 1, -1, -1):
            left_vid = self.new_vid()
            frames.append([prefix, bit, left_vid, cur])
            nxt = self.new_vid()
            ops.append({'op': 'hash', 'src': cur, 'bit': bit, 'dst': nxt})
            cur = nxt
            prefix += 1 << bit
        # Frontier frames hold the same value as their source node ('left
        # child costs no hash'): alias vid -> source vid for masking.
        outputs, pend, out_vids = [], [], []
        for pfx, depth, vid, src_vid in frames:
            outputs.append({'id': src_vid, 'kind': 'mask'})
            pend.append(self.fresh_masks(vid, order))
            out_vids.append(vid)
            self.public['frames'].append([pfx, depth, vid])
        # the deep leaf M itself
        leaf_vid = self.new_vid()
        outputs.append({'id': cur, 'kind': 'mask'})
        pend.append(self.fresh_masks(leaf_vid, order))
        out_vids.append(leaf_vid)
        self.public['frames'].append([prefix, 0, leaf_vid])
        plan = {'summands': [summand_entry], 'ops': ops, 'outputs': outputs}
        regs, _ = self.run(plan, order)
        assert len(regs) == len(out_vids)
        for vid, p, r in zip(out_vids, pend, regs):
            self.commit_masks(p)
            self.store_masked(vid, r)
        self.save()

    def restore(self):
        """Rebuild the frontier for the next commitment from the seed alone
        (RESTORE): at each set bit of the next index, keep the left sibling
        as a frame and follow the right edge."""
        self.public['frames'] = []
        self.public['masked'] = {}
        next_index = M - self.public['next_commitment']
        order = [[] for _ in range(QUORUM)]
        summand_entry = self.seed_plan_inputs(order)
        ops = []
        cur, prefix = 'seed', 0
        frames = []
        for bit in range(WIDTH - 1, -1, -1):
            if (next_index >> bit) & 1:
                sib_vid = self.new_vid()
                frames.append([prefix, bit, sib_vid, cur])
                nxt = self.new_vid()
                ops.append({'op': 'hash', 'src': cur, 'bit': bit, 'dst': nxt})
                cur = nxt
                prefix += 1 << bit
        leaf_vid = self.new_vid()
        frames.append([prefix, 0, leaf_vid, cur])
        assert prefix == next_index
        outputs, pend, out_vids = [], [], []
        for pfx, depth, vid, src in frames:
            outputs.append({'id': src, 'kind': 'mask'})
            pend.append(self.fresh_masks(vid, order))
            out_vids.append(vid)
            self.public['frames'].append([pfx, depth, vid])
        # Prepared-but-unreleased leaves were lost with the volatile masks;
        # re-derive each from the seed along its own bit path (TBS: idempotent
        # reconstruction for ReplayLast / pending release).
        for c_r in range(self.public['next_release'],
                         self.public['next_commitment']):
            index = M - c_r
            cur_r = 'seed'
            for bit in range(WIDTH - 1, -1, -1):
                if (index >> bit) & 1:
                    nxt = self.new_vid()
                    ops.append({'op': 'hash', 'src': cur_r, 'bit': bit,
                                'dst': nxt})
                    cur_r = nxt
            re_vid = self.new_vid()
            outputs.append({'id': cur_r, 'kind': 'mask'})
            pend.append(self.fresh_masks(re_vid, order))
            out_vids.append(re_vid)
            self.public['leaves'][str(c_r)] = re_vid
        plan = {'summands': [summand_entry], 'ops': ops, 'outputs': outputs}
        regs, _ = self.run(plan, order)
        for vid, p, r in zip(out_vids, pend, regs):
            self.commit_masks(p)
            self.store_masked(vid, r)
        self.save()
        return len(ops)

    def prepare_leaf(self):
        """Advance the frontier to the next leaf: compute the BOLT-required
        edges, re-mask new frontier nodes, export the leaf scalar for point
        publication. Returns (commitment_number, index, point)."""
        c = self.public['next_commitment']
        index = M - c
        order = [[] for _ in range(QUORUM)]
        plan_masked, ops, outputs = [], [], []
        pend, out_vids = [], []
        # pop frames until we hit the leaf
        frames = self.public['frames']
        top = frames.pop()
        loaded = set()    # persisted vids reconstructed in this run
        computed = set()  # vids produced by this run's ops

        def load(vid):
            if vid not in loaded and vid not in computed:
                plan_masked.append(self.masked_entry(vid, order))
                loaded.add(vid)
            return vid

        while top[1] > 0:
            pfx, depth, vid = top
            load(vid)
            # left child keeps the same secret value: same vid, shallower
            frames.append([pfx, depth - 1, vid])
            right_vid = self.new_vid()
            computed.add(right_vid)
            ops.append({'op': 'hash', 'src': vid, 'bit': depth - 1,
                        'dst': right_vid})
            frames.append([pfx + (1 << (depth - 1)), depth - 1, right_vid])
            top = frames.pop()
        leaf_pfx, _, leaf_vid = top
        assert leaf_pfx == index, (leaf_pfx, index)
        if ops:
            # newly created right children must be re-masked to survive
            for op in ops:
                outputs.append({'id': op['dst'], 'kind': 'mask'})
                pend.append(self.fresh_masks(op['dst'], order))
                out_vids.append(op['dst'])
        else:
            load(leaf_vid)
        outputs.append({'id': leaf_vid, 'kind': 'export'})
        plan = {'masked': plan_masked, 'ops': ops, 'outputs': outputs}
        regs, valids = self.run(plan, order)
        assert valids == [1], f'exported scalar failed validity check: {valids}'
        for vid, p, r in zip(out_vids, pend, regs):
            self.commit_masks(p)
            self.store_masked(vid, r)
        point = point_export.combine_points(self.mpspdz)[0]
        self.public['next_commitment'] = c + 1
        self.public.setdefault('leaves', {})[str(c)] = leaf_vid
        self.save()
        return c, index, point

    def release_leaf(self, c):
        """Open the per-commitment secret for state c (revocation)."""
        vid = self.public['leaves'][str(c)]
        order = [[] for _ in range(QUORUM)]
        plan = {'masked': [self.masked_entry(vid, order)],
                'outputs': [{'id': vid, 'kind': 'open'}]}
        regs, _ = self.run(plan, order)
        self.public['next_release'] = c + 1
        self.save()
        return decode(regs[0])


class Counterparty:
    """Live LDK process; speaks JSONL on stdin/stdout."""

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
        return resp

    def point(self, index, pt):
        x, y = pt
        compressed = bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')
        return self.send({'cmd': 'point', 'idx': index,
                          'point': compressed.hex()})

    def secret(self, index, secret_bytes):
        return self.send({'cmd': 'secret', 'idx': index,
                          'secret': secret_bytes.hex()})

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--updates', type=int, default=6,
                    help='channel updates before the crash test')
    ap.add_argument('--after', type=int, default=3,
                    help='updates after quorum change')
    ap.add_argument('--mpspdz', default=os.path.expanduser('~/src/MP-SPDZ'))
    args = ap.parse_args()

    state = os.path.join(HERE, 'state')
    if os.path.exists(state):
        shutil.rmtree(state)
    # link engine program
    src = os.path.join(REPO, 'programs', 'shachain_engine.mpc')
    dst = os.path.join(args.mpspdz, 'Programs', 'Source',
                       'shachain_engine.mpc')
    if not os.path.exists(dst):
        os.symlink(src, dst)

    eng = Engine(args.mpspdz, state)
    cp = Counterparty(REPO)
    t0 = time.time()

    print('== setup: RSS seed, 4 members, quorum', eng.public['quorum'])
    eng.setup_seed()
    seed = eng.reference_seed()   # test oracle only

    print('== channel open: 48-edge cold start in MPC')
    t = time.time()
    eng.init_channel()
    print(f'   cold start {time.time() - t:.1f}s')

    def do_update():
        c, index, point = eng.prepare_leaf()
        expect = ref.walk(seed, [b for b in range(47, -1, -1)
                                 if (index >> b) & 1])
        cp.point(index, point)
        if c > 0:
            prev = eng.release_leaf(c - 1)
            prev_index = M - (c - 1)
            assert prev == ref.walk(seed, [b for b in range(47, -1, -1)
                                           if (prev_index >> b) & 1])
            cp.secret(prev_index, prev)
        # driver-side sanity: exported point matches the reference secret
        assert point == point_export.ec_mul(
            int.from_bytes(expect, 'big') % Q)
        print(f'   state {c}: point published'
              + (f', state {c-1} revoked' if c > 0 else ''))

    print(f'== steady state: {args.updates} channel updates')
    for _ in range(args.updates):
        do_update()

    print('== crash: volatile masks destroyed; member 2 goes offline')
    for m in eng.members:
        m.crash()
    eng.public['quorum'] = [0, 1, 3]
    print('== quorum change to', eng.public['quorum'],
          '+ RESTORE from seed summands')
    t = time.time()
    hashes = eng.restore()
    print(f'   restored frontier with {hashes} hashes in '
          f'{time.time() - t:.1f}s')

    print(f'== continuing: {args.after} more updates with the new quorum')
    for _ in range(args.after):
        do_update()

    cp.close()
    print(f'== PoC complete in {time.time() - t0:.1f}s: LDK accepted every '
          f'point and secret across crash and quorum change')


if __name__ == '__main__':
    main()
