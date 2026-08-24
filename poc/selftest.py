"""Properties of the public bookkeeping that no MPC run would expose.

The MPC tests check that the right value comes out. These check that the
state machine around it cannot be left half-advanced, and that a secret is
never handed over without something to check it against. Both are failure
modes a passing lifecycle hides, because nothing fails during a clean run.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))

import iceberg  # noqa: E402
import planner  # noqa: E402

M = planner.M


def fake_regs(out_vids):
    """Stand-in for revealed masked registers, one per output value."""
    return [0xabc0 + i for i in range(len(out_vids))]


def test_prepare_is_atomic():
    """A prepare that is never committed must change nothing public."""
    pub = planner.new_public()
    pl = planner.Planner(pub)
    _, _, out_vids, commit = pl.init_plan()
    commit(fake_regs(out_vids))

    before = (list(pub['frames']), pub['next_commitment'],
              dict(pub['leaves']), dict(pub['masked']))

    # Three aborted attempts: the MPC failed, or the validity check did.
    for _ in range(3):
        pl.prepare_plan()

    after = (list(pub['frames']), pub['next_commitment'],
             dict(pub['leaves']), dict(pub['masked']))
    assert before == after, 'an uncommitted prepare mutated public state'

    # And a committed one advances exactly one commitment.
    _, _, out_vids, c, index, commit = pl.prepare_plan()
    commit(fake_regs(out_vids))
    assert pub['next_commitment'] == 1, pub['next_commitment']
    assert c == 0 and index == M, (c, index)
    print('PASS an aborted prepare leaves the commitment number untouched')


def test_restore_is_atomic():
    """A restore that aborts must not have erased the frontier first."""
    pub = planner.new_public()
    pl = planner.Planner(pub)
    _, _, out_vids, commit = pl.init_plan()
    commit(fake_regs(out_vids))
    for _ in range(3):
        _, _, out_vids, c, index, commit = pl.prepare_plan()
        commit(fake_regs(out_vids))

    before = (list(pub['frames']), dict(pub['masked']))
    for _ in range(3):
        pl.restore_plan()
    after = (list(pub['frames']), dict(pub['masked']))
    assert before == after, 'an uncommitted restore erased public state'
    print('PASS an aborted restore leaves the frontier and masked values')


def test_indices_descend():
    """Lightning consumes indices downward; the frontier must track that."""
    pub = planner.new_public()
    pl = planner.Planner(pub)
    _, _, out_vids, commit = pl.init_plan()
    commit(fake_regs(out_vids))
    last = None
    for expected_c in range(64):
        _, _, out_vids, c, index, commit = pl.prepare_plan()
        commit(fake_regs(out_vids))
        assert c == expected_c, (c, expected_c)
        assert index == M - c, (index, M - c)
        if last is not None:
            assert index < last, (index, last)
        last = index
        assert all(0 <= d < planner.WIDTH for _, d, _ in pub['frames'])
    print(f'PASS {64} prepares keep indices descending from {M:#x}')


def test_masks_are_channel_bound():
    """Two channels sharing Iceberg material must not share masks.

    Value ids restart at v0 for every channel, so a mask derived from the
    id alone would repeat. Revealing one channel's secret would unmask the
    other's, whose masked value is public.
    """
    import tempfile

    import member

    # A real State, so this exercises the derivation the agent actually uses
    # rather than the primitive underneath it.
    member.STATE = member.State(tempfile.mkdtemp(), tempfile.mkdtemp())
    member.STATE.phi = {'0': '00' * 32}

    def mask(sid, vid):
        member.STATE.sid = sid
        return member.buffer_summand(0, vid)

    def seed(sid):
        member.STATE.sid = sid
        return member.seed_summand(0)

    a, b = mask('channel-a', 'v0'), mask('channel-b', 'v0')
    assert a != b, 'same mask for v0 of two channels'
    assert a == mask('channel-a', 'v0'), 'mask derivation is not deterministic'
    assert mask('channel-a', 'v0') != mask('channel-a', 'v1'), 'vid ignored'
    assert seed('channel-a') != a, 'seed and mask derivations collide'
    member.STATE.sid = ''
    try:
        member.buffer_summand(0, 'v0')
    except AssertionError:
        pass
    else:
        raise AssertionError('derived a mask with no channel bound')
    print('PASS masks differ across channels and never collide with seeds')


def test_release_requires_a_point():
    """Releasing without a published point must refuse before any request.

    The point check is the same equation the counterparty verifies, so a
    release nobody can check is the one case where a wrong secret leaves
    the group unnoticed.
    """
    import coordinator

    class Refused(Exception):
        pass

    class Probe(coordinator.Coordinator.__mro__[0]):
        def __init__(self):
            self.public = planner.new_public()
            self.public['leaves']['0'] = 'v0'
            self.public['masked']['v0'] = hex(1)

        def active_urls(self):
            raise Refused('release contacted members without a point')

    try:
        Probe().release_leaf(0)
    except AssertionError as e:
        assert 'no point published' in str(e), e
    except Refused as e:
        raise AssertionError(str(e))
    else:
        raise AssertionError('released a secret with no point to check it')
    print('PASS release refuses, and asks no one, when no point is published')


if __name__ == '__main__':
    test_prepare_is_atomic()
    test_restore_is_atomic()
    test_indices_descend()
    test_masks_are_channel_bound()
    test_release_requires_a_point()
