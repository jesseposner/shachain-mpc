# shachain-mpc

Exactly BOLT-compatible per-commitment secrets for a thresholdized Lightning
endpoint, evaluated inside honest-majority MPC.

This is the experiment behind the question: if a t-of-n group emulates one
Lightning endpoint ([Iceberg](https://eprint.iacr.org/2026/1757) handles the
signing), can it also emulate the endpoint's BOLT #3 shachain, so that no
coalition below threshold learns an unrevealed per-commitment secret, while the
counterparty sees an ordinary channel? The shachain is SHA-256 based, so it has
none of the algebraic structure that makes threshold signing cheap; the secret
has to be derived inside a Boolean-circuit MPC.

## What is measured

One shachain edge, `x <- SHA256(flip_b(x))`, on a secret-shared 32-byte value,
exactly as BOLT #3 `generate_from_seed` computes it, followed by

1. an exact validity check `1 <= s < q` (q = secp256k1 order) in the Boolean
   domain, and
2. conversion of the 256-bit string into an arithmetic sharing over Z_q, the
   form needed to publish `P = s*G` without revealing `s`.

Shachain derivation is a binary tree with one SHA-256 per edge (see
[Threshold BOLT Shachain notes](#background)), so the per-edge cost is the
per-commitment cost once a traversal frontier is kept.

Protocols (all 3-party replicated secret sharing, one corruption, which is
exactly Iceberg's t=2 signing quorum of 2t-1 members):

| MP-SPDZ binary | security | rounds |
|---|---|---|
| `replicated-bin` / `replicated-field` | semi-honest | circuit depth |
| `malicious-rep-bin` / `malicious-rep-field` | malicious | circuit depth |
| `rep-bmr` / `mal-rep-bmr` | semi-honest / malicious | constant online (garbling precomputable) |

Correctness is checked against a plaintext BOLT #3 reference (`scripts/ref.py`)
under every protocol, including the invalid-scalar branch: `scripts/test.sh`.

## Results (Apple M4 Max, 3 parties on loopback)

Full table: [`results/`](results/). Headline, maliciously secure Rep3:

| | per edge | party-0 traffic | rounds |
|---|---:|---:|---:|
| SHA-256 edge | ~55 ms | 0.40 MB | ~1,600 |
| validity check | ~8 ms | ~0 | ~256 |
| B2A to Z_q (daBits) | ~5 ms | 0.35 MB | ~31 |
| batched over 1,000 channels, edge + check + B2A | 1.25 ms amortized | 125 KB amortized | |

Reading:

- Compute and bandwidth are cheap: maliciously secure, ~1 ms of work and
  ~0.4 MB per commitment when batched across channels.
- Round complexity dominates: ~1,600 sequential rounds per edge (AND-depth of
  SHA-256 with ripple-carry adders) means ~1,600 x RTT over a network,
  seconds per edge in one region, minutes for the 48-edge cold start across
  regions. Loopback hides this.
- So derivation has to run as background precomputation with a lookahead
  buffer. What remains on the hot path is the B2A conversion and a scalar
  opening.
  Channel open is the hard case, since the 48-edge cold start has to finish
  before funding, and it is the reason to look at constant-round garbled
  circuits (BMR) next.

## Layout

```
programs/shachain_step.mpc   the MPC program (K sequential edges, N parallel chains)
scripts/setup.sh             clone, patch and build MP-SPDZ (macOS tested)
scripts/test.sh              correctness against the plaintext reference, all protocols
scripts/bench.sh             benchmark table -> results/<host>-<date>.md
scripts/ref.py               plaintext BOLT #3 reference
scripts/input.py             writes party 0's input file in the program's bit convention
patches/                     MP-SPDZ fixes for Xcode clang 21
results/                     measurements
```

## Usage

```sh
./scripts/setup.sh        # MPSPDZ=... to choose the checkout location
./scripts/test.sh
./scripts/bench.sh
```

Manual runs, from the MP-SPDZ directory:

```sh
./compile.py -B 256 shachain_step 10 1 0 0            # 10 edges, binary only
Scripts/mal-rep-bin.sh shachain_step-10-1-0-0
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
./compile.py -P $Q -X shachain_step 1 1000 1 0        # 1000 chains, with B2A
Scripts/mal-rep-field.sh shachain_step-1-1000-1-0 -P $Q
```

Program arguments: `K` sequential edges, `N` parallel chains, `B2A` (0/1),
`CHECK` (0/1, reveals outputs for testing).

## Background

BOLT #3's `generate_from_seed(seed, I)` walks the set bits of `I` from bit 47
down, flipping each and hashing. Clearing the lowest set bit of `I` gives its
parent `p = I & (I-1)`, and `Gen(seed, I) = SHA256(flip_ctz(I)(Gen(seed, p)))`:
every tree edge is one SHA-256. Lightning consumes indices in decreasing order,
which is a right-child-first DFS of that tree, so keeping the DFS frontier
(at most 49 secret-shared nodes) makes the amortized cost one SHA-256 per
commitment and the cold start 48. Any quorum can rebuild the frontier from the
shared seed in at most 48 hashes, so nothing but the seed sharing needs to
persist across sessions.

## Not covered here

Point export from the Z_q sharing (local `share*G` plus a replicated
consistency check), the release-authorization layer binding revocation to the
channel state machine, quorum changes and share refresh, t > 2 (Shamir among
the 2t-1 quorum), and network runs. One caveat for the BMR direction: a single
party can evaluate a precomputed garbled circuit, but it only obtains output
labels, and decoding them needs shares held by a quorum, so single-party
evaluation moves the work without moving the knowledge. Release of a secret
still requires a quorum and the authorization layer.

## License

MIT
