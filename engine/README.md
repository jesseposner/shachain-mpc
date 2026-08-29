# engine: the shachain in hand-rolled Rep3

A Rust implementation of the same computation the rest of this repository
measures under MP-SPDZ: BOLT #3 per-commitment secrets derived inside
honest-majority 3-party replicated MPC. MP-SPDZ stays the reference
oracle and the benchmark baseline; this crate is the start of an engine
small enough to audit, in the language the surrounding Lightning software
is written in.

What a framework sells is generality this problem does not need. The
engine evaluates one fixed circuit for exactly three parties: the Bristol
Fashion SHA-256 (22,573 AND gates), bitsliced 64 lanes per machine word,
under the replicated XOR sharing of Araki et al. (CCS 2016). XOR and NOT
are local; an AND costs each party one sent bit per lane. There is no
compiler, no VM, and no protocol negotiation.

## Status: malicious security with abort, first rung

Two backends share one evaluation interface. `Session` is the semi-honest
floor. `MalSession` is maliciously secure with abort, after
Furukawa-Lindell-Nof-Weinstein (Eurocrypt 2017): multiplications happen
only on random triples in preprocessing, so an injected error is
independent of secret wires by construction; triples are verified by an
opened sample plus pairwise sacrifice in buckets assigned by a coin drawn
after the triples are fixed; the online phase is Beaver, linear
operations plus openings, with every opening cross-checked so the two
honest parties always compare views. Statistical parameters follow the
paper (bucket 3, minimum batch 2^20 for 2^-40); we skip its bucket-cache
optimization, as does MP-SPDZ's `ps-rep-bin`, and pay ~9 bits per AND
instead of the optimized 7.

The second rung is distributed zero-knowledge verification
(Boyle-Gilboa-Ishai-Nof, CCS 2019/Asiacrypt 2020; eprint 2023/909 is the
implementation guide) at ~1 bit per AND, behind the same trait. The
three parties currently run in lockstep inside one process; their state
is kept strictly separate and every AND produces the literal word each
party sends, so the arithmetic survives the move to three processes
unchanged.

Measured here, counted rather than modelled:

| | bits/AND/lane | per hash per party |
|---|---:|---:|
| semi-honest floor | 1.000 | 2.82 KB |
| malicious, FLNW rung | 9.012 | 25.4 KB |
| MP-SPDZ `mal-rep-bin`, measured in `results/` | ~16 | ~44 KB |

The malicious figure is exact at zero triple oversupply; a sigma-40 run
whose batch minimum forces 16% oversupply measures 10.1. Throughput is
beside the point (43,000 semi-honest and 4,400 malicious hash-lanes/s on
one core; derivation is network-bound in deployment), but it confirms
compute is nowhere near the constraint.

## Correctness

- The five official BOLT #3 generation vectors, byte-for-byte through the
  MPC (`tests/bolt.rs`).
- Property suite (`tests/properties.rs`): the engine against the `sha2`
  crate for arbitrary messages at arbitrary lane counts, and
  `generate_from_seed` against the plaintext walk across the full 48-bit
  index space, where the fixed vectors pin five indices. Share-then-
  reconstruct is the identity; corrupting any single stored copy of any
  share component is always caught by the replicated cross-check.
- Per-lane distinctness is asserted everywhere it matters: the vectorised
  hashing bug this repository found in MP-SPDZ
  (`upstream/mp-spdz-sha256-vectorised.md`) is the bug class these tests
  exist for.
- Malicious suite (`tests/malicious.rs`): the malicious backend computes
  the same function (oracle against `sha2` and the BOLT walk), its
  traffic lands where FLNW says, and, as a property over the whole
  protocol, one flipped bit in any multiplication or opening message,
  wherever it lands, always surfaces as an abort or a reconstruction
  failure. What tests cannot cover is the 2^-sigma bucket event, a
  coordinated forgery surviving the shuffle; that rests on the paper's
  combinatorics.

## Usage

The circuit file is loaded from an MP-SPDZ checkout (`$MPSPDZ`, or a
sibling directory of this repository) rather than vendored: it carries
the Bristol/KU Leuven license, and this crate is MIT.

```sh
cargo test                              # example + property suites
cargo run --release --bin bench -- 10 1024       # K edges, N lanes
cargo run --release --bin bench -- 10 256 mal    # malicious, sigma 40
```
