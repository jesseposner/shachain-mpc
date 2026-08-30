# engine: the shachain in hand-rolled Rep3

> **Warning: experimental, unreviewed cryptographic code. Do not use it
> in production, and do not put funds behind it.** Nothing here has had
> external security review. The protocol layers implement published
> papers, but no one has checked this code against their proofs; the
> mod-q masking in `src/convert.rs` and the transcript proof in
> `src/dzkp.rs` are reconstructions with no adversarial review at all;
> and the surrounding repository's
> open items (authorization layer, key ceremonies, share refresh) apply
> here in full. This code exists to measure and to be reviewed, not to
> custody anything.

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

The second rung is built (`src/dzkp.rs`): semi-honest evaluation plus a
distributed zero-knowledge proof over the whole transcript, in the
style of Boyle-Gilboa-Ishai-Nof (CCS 2019/Asiacrypt 2020),
reconstructed from that line of work rather than transcribed, and
therefore first in line for review; the FLNW rung stays the
conservative default. The statement "this party's messages were
correct" has a witness the two other parties jointly hold, so a
random-lambda reduction turns the transcript into one inner product,
verified by a recursive fully-linear IOP whose proof messages are
additively split, whose challenges come from joint coins fixed after
each prover message, and whose base case is grounded in values the
honest verifiers compute from their own data. Soundness is ~2^-50 per
verified batch (lambda collision plus degree over GF(2^64)); stated,
not rounded. Verification runs inside `eval_circuit`, before anything
derived from the circuit can be opened, and openings receive each
missing component from both holders. The cost is ~28 rounds and 0.1%
traffic per hash; the FLIOP prover spends real CPU (~4 s per
1,024-lane hash, first-level block products, unoptimized), which
disappears inside the ~65 s the same hash costs a WAN.

The three parties run separated for real: as threads over in-process
channels for the test suites, and as three processes over TCP
(`src/bin/party.rs`), behind one `Wire` trait. Each party holds only its
own two PRF keys and its two wires; a party that aborts drops its wires
and the abort cascades through the ring. TCP writes run on a dedicated
thread per wire, preserving the protocol's sends-never-block invariant:
blocking writes deadlock the ring the moment a refill's multi-megabyte
batches fill the socket buffers, a failure the unbounded in-process
channels could never exhibit. Evaluation is scheduled by AND depth, one
batched message round per level, which makes round count, the quantity a
wide-area deployment actually pays for, a measured property:

| | bits/AND/lane | per hash per party | rounds per hash |
|---|---:|---:|---:|
| semi-honest floor | 1.000 | 2.82 KB | 1,607 |
| malicious, FLNW rung | 9.012 | 25.4 KB | 1,608.6 |
| malicious, dZKP rung | 1.001 | 2.83 KB | 1,635 |
| MP-SPDZ `mal-rep-bin`, measured in `results/` | ~16 | ~44 KB | ~1,635 |

The malicious rounds figure amortizes a six-round verification per
refill batch and one view checkpoint per circuit over the hashes a batch
serves: malicious security costs under two extra rounds per hash. The
bits figure is exact at zero triple oversupply; a sigma-40 run whose
batch minimum forces 16% oversupply measures 10.1. Throughput is beside
the point (56,000 semi-honest and 4,700 malicious hash-lanes/s on three
threads; derivation is network-bound in deployment), but it confirms
compute is nowhere near the constraint.

Three processes over TCP loopback, digests verified against the
plaintext walk by a checked reconstruction at party 0: the 48-edge
cold-start walk at 1,024 lanes runs 77,136 rounds in 1.62 s (21 us per
round including all compute), and a sigma-40 malicious walk completes
with the same round counts as the in-process runs. At this repository's
measured 40 ms per WAN round, 1,607 rounds projects one edge at 64.3 s;
the cross-region measurement of the same circuit under MP-SPDZ was
65.5 s (`results/`), so the engine's WAN model agrees with the only WAN
data that exists to two percent.

## The chain engine

`src/chain.rs` is the piece the rest exists for. A block is the subtree
covering the next 2^h indices, expanded level by level: each level is
one uniform vectorised hash whose lanes are the current frontier (the
left child of a node is the node itself, costing nothing), so a block
costs h hash rounds for 2^h - 1 secrets, and the walk from the seed to
the first block root makes the whole cold start exactly 48 hashes.

Prepared leaves are never reconstructed. Per `docs/buffer-storage.md`,
each leaf is published as a masked value whose summands derive from
long-term keys in the same replicated pattern as the shares: every
summand has two holders, any quorum re-derives everything, and a
release is one round of plain messaging, the adapter comparing the
duplicated copies and XORing them into the masked value, no MPC session
at all. A wrong summand copy is caught by its honest co-holder.

Point export (`src/convert.rs`) needs no arithmetic MPC. The leaf is
also published masked additively mod q, t = (s + s_0 + s_1 + s_2) mod
q, under summands with a domain tag of their own (mask paddings are
never shared between the XOR and mod-q paths). Because each summand is
known to exactly two parties who sit together on one replicated
component, its Boolean sharing costs no communication, and t is one
Boolean circuit built in code, three ripple additions and four
conditional subtractions of q, ~3,600 ANDs and ~1,800 rounds evaluated
once per block across every lane, then opened. Everything after that is
public arithmetic: the per-commitment point is P = t*G minus the
summand points, each published by its two holders and cross-checked,
and the mod-q release is checked against P by the very equation the
counterparty verifies. The construction identifies a secret with its
class mod q, exact unless the 32-byte secret is >= q, the ~2^-128
invalid-scalar branch the rest of this repository documents.

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
- dZKP suite (`tests/dzkp.rs`): the dZKP backend against the sha2
  oracle and the walk; traffic asserted between 1.0 and 1.1 bits per
  AND; and the abort property over the corrupt party's entire outgoing
  stream, evaluation messages, proof shares, residuals, coins, and
  openings alike. Its abort guarantee is statistical (~2^-50), unlike
  the FLNW rung's deterministic single-error catch; no test run will
  see the difference, and the docs say which is which.
- Conversion suite (`tests/convert.rs`): the q-mask circuit against an
  independent bigint reference, the deep-reduction corner forced; a
  block converted under the malicious backend yields points equal to
  `k256::SecretKey`-derived points for the plaintext secrets at every
  index; the mod-q release recovers byte-identical secrets to the XOR
  release and refuses a wrong summand copy, a wrong point copy, and a
  tampered t.
- Chain suite (`tests/chain.rs`, `tests/chain_wide.rs`): a block
  prepared under the malicious backend, released leaf by leaf through
  the masked one-round path, matches the plaintext walk at every index,
  descending; the same at 128 leaves under the semi-honest backend,
  crossing the lane-word boundary; a wrong summand copy is caught; and
  the released sequence is fed to unmodified rust-lightning, which
  accepts all of it, rejects every single-byte corruption, and
  re-derives stored secrets (`ldk-check`, the same harness the MP-SPDZ
  measurements answer to).
- Malicious suite (`tests/malicious.rs`): the malicious backend computes
  the same function (oracle against `sha2` and the BOLT walk), its
  traffic lands where FLNW says, and, as a property over the whole
  protocol, one flipped bit anywhere in a corrupt party's outgoing byte
  stream, triple resharing, opening, or comparison hash, always surfaces
  as an abort or a reconstruction failure, and the abort cascades
  through the wires to every party. What tests cannot cover is the
  2^-sigma bucket event, a coordinated forgery surviving the shuffle;
  that rests on the paper's combinatorics.

## Usage

The circuit file is loaded from an MP-SPDZ checkout (`$MPSPDZ`, or a
sibling directory of this repository) rather than vendored: it carries
the Bristol/KU Leuven license, and this crate is MIT.

```sh
cargo test                              # example + property suites
cargo run --release --bin bench -- 10 1024       # K edges, N lanes, in-process
cargo run --release --bin bench -- 10 256 mal    # malicious, FLNW, sigma 40
cargo run --release --bin bench -- 10 1024 dzkp  # malicious, dZKP, ~1 bit/AND

# Three real processes; run one per machine (or terminal) with the same
# addresses: party <id> <addr0> <addr1> <addr2> <K> <N> [mal [sigma]]
cargo run --release --bin party -- 0 h0:9700 h1:9700 h2:9700 48 1024
```
