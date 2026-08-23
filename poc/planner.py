"""Public bookkeeping for the shachain engine: frames, masked values, plans.

Everything in this module is public data. It builds the per-step JSON plan
for programs/shachain_engine.mpc together with an input spec describing
which private inputs each party slot must supply, without ever holding a
private value itself:

  plan  = {summands, masked, ops, outputs}       (engine program input)
  spec  = {'summands': [[j, slot], ...],          summand j from that slot
           'masked_vids': [vid, ...],             every slot: stored mask
           'fresh_vids': [vid, ...]}              every slot: fresh mask

Per-slot input order (must match the engine program):
  own summands in spec order, then one mask per masked_vids entry, then one
  fresh mask per fresh_vids entry.
"""

M = 2**48 - 1
WIDTH = 48
N_MEMBERS = 4


def new_public():
    return {
        'frames': [],        # [prefix, depth, value_id], top of stack = last
        'masked': {},        # value_id -> public masked value (hex)
        'leaves': {},        # commitment number -> leaf value_id
        'next_vid': 0,
        'next_commitment': 0,
        'next_release': 0,
        'quorum': [0, 1, 2],
    }


class Planner:
    def __init__(self, public):
        self.public = public

    def new_vid(self):
        vid = f'v{self.public["next_vid"]}'
        self.public['next_vid'] += 1
        return vid

    def summand_slots(self):
        """[(j, slot supplying summand j)]: the lowest-indexed active member
        that holds summand j (every member except j holds it)."""
        quorum = self.public['quorum']
        out = []
        for j in range(N_MEMBERS):
            slot = next(s for s, m in enumerate(quorum) if m != j)
            out.append([j, slot])
        return out

    def _seed_walk(self, index, ops, frames):
        """Ops walking the seed down to `index`, recording left-sibling
        frames [prefix, depth, new_vid, engine_src_id] along the way."""
        cur, prefix = 'seed', 0
        for bit in range(WIDTH - 1, -1, -1):
            if (index >> bit) & 1:
                frames.append([prefix, bit, self.new_vid(), cur])
                nxt = self.new_vid()
                ops.append({'op': 'hash', 'src': cur, 'bit': bit, 'dst': nxt})
                cur = nxt
                prefix += 1 << bit
        return cur, prefix

    def init_plan(self):
        """Cold start: frontier down to leaf M. Returns (plan, spec, out_vids)
        where out_vids[i] names the value behind revealed register i."""
        spec = {'summands': self.summand_slots(), 'masked_vids': [],
                'fresh_vids': []}
        ops, frames = [], []
        cur, prefix = self._seed_walk(M, ops, frames)
        frames.append([prefix, 0, self.new_vid(), cur])
        outputs, out_vids = [], []
        for pfx, depth, vid, src in frames:
            outputs.append({'id': src, 'kind': 'mask'})
            spec['fresh_vids'].append(vid)
            out_vids.append(vid)
            self.public['frames'].append([pfx, depth, vid])
        plan = {'summands': [{'id': 'seed',
                              'slots': [s for _, s in spec['summands']]}],
                'ops': ops, 'outputs': outputs}
        return plan, spec, out_vids

    def restore_plan(self):
        """Rebuild the frontier for the next commitment from the seed, plus
        re-derive prepared-but-unreleased leaves (pending revocations)."""
        self.public['frames'] = []
        self.public['masked'] = {}
        spec = {'summands': self.summand_slots(), 'masked_vids': [],
                'fresh_vids': []}
        ops, frames = [], []
        next_index = M - self.public['next_commitment']
        cur, prefix = self._seed_walk(next_index, ops, frames)
        frames.append([prefix, 0, self.new_vid(), cur])
        assert prefix == next_index
        outputs, out_vids = [], []
        for pfx, depth, vid, src in frames:
            outputs.append({'id': src, 'kind': 'mask'})
            spec['fresh_vids'].append(vid)
            out_vids.append(vid)
            self.public['frames'].append([pfx, depth, vid])
        for c_r in range(self.public['next_release'],
                         self.public['next_commitment']):
            cur, _ = self._seed_walk(M - c_r, ops, [])
            re_vid = self.new_vid()
            outputs.append({'id': cur, 'kind': 'mask'})
            spec['fresh_vids'].append(re_vid)
            out_vids.append(re_vid)
            self.public['leaves'][str(c_r)] = re_vid
        plan = {'summands': [{'id': 'seed',
                              'slots': [s for _, s in spec['summands']]}],
                'ops': ops, 'outputs': outputs}
        return plan, spec, out_vids

    def prepare_plan(self):
        """Advance the frontier to the next leaf and export its scalar.
        Returns (plan, spec, out_vids, commitment_number, index)."""
        c = self.public['next_commitment']
        index = M - c
        spec = {'summands': [], 'masked_vids': [], 'fresh_vids': []}
        plan_masked, ops, outputs, out_vids = [], [], [], []
        loaded, computed = set(), set()

        def load(vid):
            if vid not in loaded and vid not in computed:
                plan_masked.append({'id': vid, 'm': self.public['masked'][vid]})
                spec['masked_vids'].append(vid)
                loaded.add(vid)

        frames = self.public['frames']
        top = frames.pop()
        while top[1] > 0:
            pfx, depth, vid = top
            load(vid)
            frames.append([pfx, depth - 1, vid])
            right_vid = self.new_vid()
            computed.add(right_vid)
            ops.append({'op': 'hash', 'src': vid, 'bit': depth - 1,
                        'dst': right_vid})
            frames.append([pfx + (1 << (depth - 1)), depth - 1, right_vid])
            top = frames.pop()
        leaf_pfx, _, leaf_vid = top
        assert leaf_pfx == index, (leaf_pfx, index)
        for op in ops:
            outputs.append({'id': op['dst'], 'kind': 'mask'})
            spec['fresh_vids'].append(op['dst'])
            out_vids.append(op['dst'])
        if not ops:
            load(leaf_vid)
        outputs.append({'id': leaf_vid, 'kind': 'export'})
        plan = {'masked': plan_masked, 'ops': ops, 'outputs': outputs}
        self.public['next_commitment'] = c + 1
        self.public['leaves'][str(c)] = leaf_vid
        return plan, spec, out_vids, c, index

    def release_plan(self, c):
        """Open the per-commitment secret for state c."""
        vid = self.public['leaves'][str(c)]
        spec = {'summands': [], 'masked_vids': [vid], 'fresh_vids': []}
        plan = {'masked': [{'id': vid, 'm': self.public['masked'][vid]}],
                'outputs': [{'id': vid, 'kind': 'open'}]}
        self.public['next_release'] = c + 1
        return plan, spec

    def store_masked(self, out_vids, regs):
        assert len(regs) >= len(out_vids), (len(regs), len(out_vids))
        for vid, r in zip(out_vids, regs):
            self.public['masked'][vid] = hex(r)
