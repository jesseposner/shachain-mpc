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
