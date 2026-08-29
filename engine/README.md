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

## Status: semi-honest core

This is the semi-honest floor, not the destination. The malicious layer
comes next, in two rungs behind one trait: triple sacrifice per
Furukawa-Lindell-Nof-Weinstein (Eurocrypt 2017), ~7 bits per AND per
party amortized and simple enough to audit, then distributed
zero-knowledge verification (Boyle-Gilboa-Ishai-Nof, CCS 2019/Asiacrypt
2020; eprint 2023/909 is the implementation guide) at ~1 bit. The three
parties currently run in lockstep inside one process; their state is kept
strictly separate and every AND produces the literal word each party
sends, so the arithmetic survives the move to three processes unchanged.

Measured here, counted rather than modelled:

| | per hash per party |
|---|---:|
| this core, semi-honest | 2.82 KB (exactly 1 bit/AND/lane) |
| MP-SPDZ `mal-rep-bin`, measured in `results/` | ~44 KB |

The comparison is semi-honest against malicious, so the honest gap to
claim today is smaller than 15x; the malicious rungs above are what close
it for real. Throughput is beside the point (43,000 hash-lanes/s on one
core; derivation is network-bound in deployment), but it confirms compute
is nowhere near the constraint.

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

## Usage

The circuit file is loaded from an MP-SPDZ checkout (`$MPSPDZ`, or a
sibling directory of this repository) rather than vendored: it carries
the Bristol/KU Leuven license, and this crate is MIT.

```sh
cargo test                              # example + property suites
cargo run --release --bin bench -- 10 1024   # K edges, N lanes
```
