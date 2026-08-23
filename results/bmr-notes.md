# BMR exploration notes

Date: 2026-08-23. Same host and MP-SPDZ checkout as the main benchmark, with
`patches/mp-spdz-bmr-phase-timing.patch` applied so the party binaries report
the online phase separately. All runs use `-O` (one-shot: garble the whole
program, then evaluate once), which models precomputed garbled circuits.

## Why BMR

Rep3's cost per edge is ~1,600 communication rounds (the AND-depth of
SHA-256), which puts the 48-edge channel-open cold start at ~77,000 sequential
rounds on the network critical path. BMR moves the depth-dependent work into
garbling, which is input-independent: it can run before the channel, or the
seed, exists. What remains online is a
constant number of communication rounds (measured; input-label exchange plus
output handling) and local evaluation: three when garbling and evaluation
share one process, as in the `-O` table below, and two when a stockpiled
package is evaluated in a fresh process (see below).

## Measurements (3 parties, loopback, malicious unless noted)

| run | online time | online traffic | online rounds | total incl. garbling | garbling traffic (party 0) |
|---|---:|---:|---:|---:|---:|
| K=1 edge | 10 ms | 8.7 KB | 3 | 0.26 s | 34 MB |
| K=10 edges | 100 ms | 8.7 KB | 3 | 2.4 s | 336 MB |
| K=48 cold start | 0.49 s | 8.7 KB | 3 | 11.4 s | 1.61 GB |
| K=48 cold start, semi-honest | 0.54 s | 8.7 KB | 3 | 3.8 s | 659 MB |
| K=48 cold start, Rep3 malicious (comparison) | 2.4 s | 19 MB | 77,516 | 2.4 s | 19 MB |

Online evaluation is ~10 ms per edge of local AES work, single-threaded, and
the online traffic does not grow with K: one label exchange for the whole
chain.

## Findings

1. With pre-garbled circuits, channel open costs two round trips (three if
   garbling and evaluation share a process) plus ~0.5 s of local compute,
   against ~77,000 sequential rounds for Rep3. Over any real network this is
   the difference between sub-second and minutes.
2. The garbling price is ~34 MB per edge per party (malicious; 100 MB global),
   so a 48-edge cold-start package is ~1.6 GB per party. That is affordable as
   a per-channel one-off but rules out garbling deep lookahead buffers;
   steady-state derivation should stay on Rep3 in the background.
3. MP-SPDZ's garbling phase is itself round-heavy (~1,700 rounds per edge) and
   the rounds scale linearly when batching independent circuits, because the
   implementation garbles program segments sequentially. The BMR protocol
   itself admits low-round garbling (gates are garbled in parallel); treat
   these garbling-side round counts as an implementation artifact; the costs
   that bind are garbling bandwidth and compute.
4. Correctness holds under BMR: the K in {0,1,3} chain values match the
   plaintext BOLT reference, semi-honest and malicious (see `scripts/test.sh`).

## Suggested architecture

- Steady state: Rep3 in the background with a lookahead buffer; B2A and scalar
  opening on the hot path (~5 ms, 31 rounds).
- Channel open: pre-garbled 48-edge BMR package per expected channel,
  evaluated in two online rounds at open time; the package is consumed once
  and its storage freed.
- Quorum change: same pattern as channel open, since RESTORE from the seed is
  also a bounded chain of edges (at most 48).

## Stockpiled packages (the missing piece, now built)

MP-SPDZ's BMR originally interleaved garbling and evaluation in one process,
so the input-independence of garbling could not be exercised across time. We
patched the party runtime (see `patches/mp-spdz-bmr-phase-timing.patch`) with
two flags: `-G <file>` garbles the whole program and dumps each party's
package to disk (garbled tables, wire keys, input/output masks, SPDZ wires,
delta), and `-E <file>` loads a package in a fresh process and runs only the
online evaluation.

Measured, malicious, K=48 cold start: garble+dump 17.4 s on loopback and
0.21 GB per party on disk, any time in advance; evaluation later in a fresh
process in 0.47 s, 8.7 KB, and two online rounds, byte-identical to the BOLT
reference. In the distributed PoC the package is stockpiled at setup, before
the seed exists, and channel open drops from ~12-23 s to 1.7 s end to end.

Safety: a package must be evaluated at most once: evaluating the
same garbled circuit on two different inputs leaks, and the runtime does not
stop a second evaluation (we verified it will happily run one), so the PoC
member deletes its package immediately after use and real enforcement
belongs in the authorization layer. And the stored package must be
integrity-bound to the channel and quorum that will consume it.

## Why no cut-and-choose

Review question (Paul): does the garbling trick need cut-and-choose? No, and
the reason is worth recording. Cut-and-choose fixes the classic Yao problem of
a single malicious garbler, whom the evaluator cannot audit: garble many
copies, open a random subset to check, evaluate the rest, paying a
statistical-security multiple in every cost. Here nobody garbles alone. In
BMR the garbled tables are themselves computed inside an actively secure MPC
among the custodians (MP-SPDZ's `mal-rep-bmr` garbles over malicious
replicated GF(2^128) sharing, following the SPDZ-BMR line, eprint 2017/981),
so a corrupt minority cannot substitute a wrong circuit or learn labels; it
can only force an abort. Correct-garbling is inherited from the garbling MPC's
own malicious security, with no replication factor. The claim leans on two
conditions: the garbling run must itself be the malicious protocol
(semi-honest `rep-bmr` garbling would reopen the question), and each garbled
package is strictly one-time-use, since evaluating one circuit on two
different inputs leaks. Single-use enforcement and integrity of the stored
package (a MAC or hash committed at garbling time, checked before evaluation)
belong to the authorization layer.

## Open questions

- Output re-sharing: demonstrated in the PoC. The cold start runs under
  mal-rep-bmr with outputs revealed only as XOR-masked values (each active
  member inputs a fresh mask), and the field engine consumes the same masked
  tuples for every later step. Authenticating member-held masks against a
  malicious party is part of the authorization layer, as with all volatile
  state.
- Garbled-package integrity and single-use enforcement in the authorization
  layer (the mechanism exists; the policy does not).
- A WAN run to confirm the two-round package evaluation behaves as computed.
