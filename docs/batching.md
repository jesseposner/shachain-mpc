# Batching: why the engine is slower than the design allows

**Correction first.** The batched figures originally published here and in
the results files came from a code path that computed the wrong answer in
every lane but the first. `circuit.sha256` builds its padding and initial
state with `sbit()`, which is one bit wide, so a vectorised input gave lane 0
the constants and every other lane zeros. Nothing caught it because the
program's check mode revealed lane 0 alone: feeding two lanes, lane 0
matched SHA-256 and lane 1 did not.

`sha256_lanes()` in both programs now broadcasts each constant across all
lanes, the check mode reveals every lane, and `scripts/test.sh` runs three
lanes from three distinct seeds against the reference.

The performance conclusions survive the fix, because the corrected circuit
is nearly the same size: 64 correct lanes cost 1,775 rounds against 1,621
for one lane, and 8 lanes cost 1,635. What did not survive is the claim that
those earlier runs demonstrated correct parallel hashing. They demonstrated
the cost of a circuit of about the right size.

Measured on loopback, malicious 3-party replicated, 10 hash edges per chain:

| shape | hashes | rounds |
|---|---:|---:|
| 1 lane | 1 | 1,621 |
| 8 lanes, one vectorised call | 8 | **1,635** |
| 64 lanes, one vectorised call | 64 | **1,775** |
| 2 chains, separate calls (10 edges each) | 20 | 32,210 |
| 4 chains, separate calls (10 edges each) | 40 | 64,399 |

The lane rows are from the corrected implementation and verified against the
plaintext reference in every lane.

Independent hashes cost nothing extra when they are issued as one
vectorised call over a wide sharing, and cost full price when they are
issued as separate calls. Eight times the work for one percent more rounds,
against four times the rounds for four times the work.

Rounds are what a wide-area deployment pays for: this WAN charges about
40 ms per round, so 16,000 rounds is roughly eleven minutes whether it
carries ten hashes or eighty.

## What this costs today

`programs/shachain_engine.mpc` walks its plan one operation at a time and
calls `sha256` once per operation, which is the serialising shape. Two
consequences:

- **RESTORE pays double.** Its plan holds two independent walks from the
  seed, one rebuilding the frontier and one re-deriving a prepared but
  unreleased leaf. They sit at the same depth and should cost one walk;
  they currently cost two. The WAN run bears this out: RESTORE ran near 100
  minutes where a single 47-hash walk predicts about 50.
- **Bulk precomputation is not available at all.** Preparing the next 2^k
  secrets should expand one frontier node k levels, so 2^k - 1 hashes at
  depth k: 1,024 secrets in ten waits rather than 1,024. Issued one call at
  a time it is 1,024 waits, and the buffer that the whole latency argument
  depends on cannot be filled at a sensible cost.

## The fix

Group each plan's operations into levels by dependency, then issue one
vectorised `sha256` per level instead of one per operation.

The flip bit needs no special handling. Nodes at the same level of a tree
expansion all flip the same bit, since level d flips bit d-1, so a level is
naturally one uniform batch. Where a plan does mix flip positions within a
level, as RESTORE's two walks can, group that level by flip bit and issue
one call per group: still a small constant number of calls per level rather
than one per hash.

Flipping different bits in different lanes of a single call is also
possible, by XOR-ing each bit position with a clear mask naming the lanes
that flip there, but grouping by bit avoids needing it and avoids depending
on the lane layout of `get_input_from(size=N)`, which is not the obvious
one.

## Why this was invisible before the WAN run

At 40 microseconds a round on one machine, serialising 1,024 hashes instead
of batching them is the difference between 0.6 s and 40 s: annoying. At
40 ms a round it is the difference between eleven minutes and eighteen
hours, which decides whether the architecture works.


## Implemented

Both changes are in, measured on loopback by round count, which is what a
wide-area deployment pays for.

**Edges are grouped by level.** `programs/shachain_engine.mpc` assigns each
edge a level (one more than its source), groups by (level, flip bit), and
issues one vectorised call per group. Every edge at the same level of a tree
expansion flips the same bit, so a level is normally one group and needs no
per-lane flip handling.

| step | edges | rounds before | rounds after |
|---|---:|---:|---:|
| cold start | 48 | 77,151 | 77,151 |
| RESTORE | 94 | 151,058 | **77,151** |

RESTORE holds two independent 47-edge walks, the frontier and one pending
leaf, and now costs what one walk costs. At this WAN's 40 ms per round that
turns a 126-minute recovery into about 51 minutes.

**Release needs no MPC at all.** A prepared secret is a public masked value
plus one mask per online member, so revealing it is not a computation. The
members send their masks, the adapter XORs them, and the result is checked
against the point published for that state. The payment path is now one
round of plain messaging with no circuit, no compilation and no MPC
session, against five rounds inside a session before.

A member that supplies a wrong mask cannot pass off a wrong secret: the
point check fails, and it is the same equation the counterparty verifies
when the secret reaches them. Verified in both directions, honest masks
accepted and a single flipped bit rejected. Whether a release is permitted
at all remains the authorization layer's question, and that layer does not
exist yet.

## Where the remaining time goes

Measured rounds for the two non-hashing parts of preparing a leaf, against
the number of leaves prepared in one step:

| leaves | validity check | Boolean to Z_q |
|---:|---:|---:|
| 1 | 16 | 31 |
| 10 | 16 | 31 |
| 100 | 16 | 58 |
| 1,000 | **16** | 436 |

The validity check is flat: sixteen rounds whether you check one scalar or a
thousand, because the tree comparator vectorises perfectly. The conversion is
flat to ten and then grows sublinearly, reaching 0.44 rounds per leaf at a
thousand against 31 unbatched. Its traffic does scale linearly, 0.35 MB to
92 MB, which is the real constraint on how large a refill batch should be.

So refilling a 1,024-leaf buffer costs:

| | rounds | share |
|---|---:|---:|
| hashing, ten tree levels | 16,350 | 97% |
| conversion | ~436 | 2.6% |
| validity check | 16 | 0.1% |

Both of the parts that looked worth optimising are already noise. Refill is
almost entirely SHA-256 depth, and the direct attack on that depth failed
(see experiments/README.md). What remains is either carry-save adder trees
inside the hash, or pre-garbling the subtree expansion the way channel open
is already pre-garbled.

## Sustained throughput per channel

A refill of 2^k leaves costs k tree levels, so k x 1,635 rounds, and buys
2^k payments. At this WAN's 40 ms per round:

| buffer depth | refill time | payments bought | sustained rate |
|---:|---:|---:|---:|
| 64 | 6.5 min | 64 | 1 per 6.1 s |
| 1,024 | 11 min | 1,024 | 1 per 0.64 s |
| 4,096 | 13 min | 4,096 | 1 per 0.19 s |

Deeper buffers are strictly better, because the cost is the depth and the
benefit is the width. The limits are refill traffic, which grows with the
batch, and MP-SPDZ's compiler, which holds the whole circuit in memory. A
production engine compiling step templates once would remove the second.

None of this touches payment latency, which is one round regardless: the
buffer only has to stay ahead of consumption.
