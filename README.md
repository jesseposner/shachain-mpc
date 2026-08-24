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
| `rep-bmr` / `mal-rep-bmr` | semi-honest / malicious | three online rounds (garbling precomputable) |

Correctness is checked four ways:

- `scripts/ref.py selftest`: the reference implementation against the five
  official BOLT #3 test vectors;
- `scripts/test.sh`: MPC output against the reference under every protocol,
  including the invalid-scalar branch (19 cases);
- `scripts/ldk_check.sh`: secrets derived by the maliciously secure MPC fed to
  LDK's shachain verifier (rust-lightning `CounterpartyCommitmentSecrets`),
  which accepts the sequence, rejects every single-byte corruption, and
  re-derives stored secrets;
- the same script runs the point-export harness
  (`scripts/point_export.py`): each party turns its replicated Z_q share into
  a curve point, replicated pairs are cross-checked by point equality, and
  the combined P equals s*G, with a corrupted-share run aborting as it must.

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
- Channel open looked like the hard case, since the 48-edge cold start has to
  finish before funding. The BMR measurements
  ([results/bmr-notes.md](results/bmr-notes.md)) resolve it: with pre-garbled
  circuits the whole cold start runs in three online rounds plus ~0.5 s of
  local evaluation, for a garbling package of ~1.6 GB per party prepared
  before the channel exists. Steady state stays on Rep3; BMR covers channel
  open and quorum changes.

## End-to-end proof of concept

`poc/` runs the whole design as a distributed lifecycle: per-member agents
holding the only copies of private state (RSS summands dealt member-to-member,
volatile frontier masks), and a coordinator that touches public data only.
The channel does a 48-edge cold start, per-update frontier advances, point
publication with replicated cross-checks, and revocation into a live LDK
counterparty; then a crash, a quorum change to the standby member, and
RESTORE from the seed summands, after which the channel continues
byte-identically (pending pre-crash revocations included). The same agents
deploy across machines for the WAN run. See [poc/README.md](poc/README.md).

## Rounds per operation

Wide-area cost is round count times latency, so rounds are the number to
watch. Measured on loopback, malicious 3-party replicated:

| operation | rounds | wide-area cost | how we know |
|---|---:|---:|---|
| **reveal a prepared secret (a payment)** | **1** | ~0.14 s | derived: one round trip on the slowest leg |
| the same reveal, earlier six-round MPC form | 6 | 0.18 s | measured on the WAN |
| prepare a leaf (validity check, scalar conversion) | 58 | ~2.3 s | derived from 40 ms per round |
| one shachain edge | ~1,635 | 65 s | measured on the WAN |
| 48-edge channel open, computed | 77,151 | 54.5 min | measured on the WAN |
| 48-edge channel open, stockpiled package | 3 online | **4.8 s** | measured on the WAN |
| quorum change, replicated buffer | **0** | **none** | measured: the channel continues without a rebuild |
| buffer refill, 1,024 secrets | ~16,800 | ~11 min | derived; 97% of it is hashing, and it buys 1,024 payments |
| rebuild from the seed (cold start only) | 77,151 | ~51 min | derived; 126 min measured before batching halved it |

Round counts are loopback measurements, which is fine because a round count
is a property of the circuit rather than the network. Wide-area figures are
either measured on four cross-region nodes or derived by multiplying rounds
by the 40 ms per round those nodes exhibited, and the table says which.

A payment costs one round because revealing a prepared secret is not a
computation: the members send the masks they hold and the adapter checks the
result against the point already published. Everything else is background
work feeding a lookahead buffer. See [docs/batching.md](docs/batching.md).

The one-round figure is a round count, not a wide-area measurement. What was
measured over the WAN, at 0.18 s, is the earlier form of the same operation:
a six-round MPC opening (`programs/release_only.mpc`). The one-round form
replaces that session with plain messaging and so should come in at or below
that figure, but the machines were gone before it existed. It deserves a live
measurement before anyone quotes it.

## Recovery costs nothing

A prepared secret used to be hidden by one mask per online member, a 3-of-3
sharing, so a single member dropping out destroyed the buffer and forced a
77,151-round rebuild from the seed: about 51 minutes across three continents,
with the channel frozen throughout. Prepared values are now hidden under a
replicated sharing whose summands are derived from long-term keys, so any
quorum can reconstruct them, a member can drop out with no effect, and the
buffer costs no secret storage at all. See
[docs/buffer-storage.md](docs/buffer-storage.md).

## Layout

```
programs/shachain_step.mpc   the MPC program (K sequential edges, N parallel chains)
scripts/setup.sh             clone, patch and build MP-SPDZ (macOS tested)
scripts/test.sh              correctness against the plaintext reference, all protocols
scripts/bench.sh             benchmark table -> results/<host>-<date>.md
poc/                         distributed lifecycle PoC (see poc/README.md)
scripts/ldk_check.sh         MPC secrets -> LDK verifier; point-export harness
scripts/point_export.py      replicated shares -> published P = s*G with cross-checks
scripts/ref.py               plaintext BOLT #3 reference (selftest = official vectors)
scripts/input.py             writes party 0's input file in the program's bit convention
ldk-check/                   Rust harness around rust-lightning's shachain store
patches/                     MP-SPDZ fixes for Xcode clang 21 and BMR phase timing
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

## Only the outbound chain needs MPC

A channel has two shachains. The one we generate must be derived inside MPC,
since no custodian may learn a future per-commitment secret; that chain is
what everything here measures. The counterparty's chain arrives in plaintext
in `revoke_and_ack`, which our endpoint is meant to learn, so it costs no MPC:
store it in the usual 49 buckets and run BOLT's derivation check locally.
Receiving those secrets is safe for any single custodian to do, because
punishing a cheat also needs our `revocation_basepoint_secret`, which is
threshold-shared. A payment costs one MPC operation, not two.

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

The release-authorization layer binding revocation to the channel state
machine, quorum changes and share refresh, and network runs
(see docs/wan-plan.md). One caveat for the BMR direction: a single
party can evaluate a precomputed garbled circuit, but it only obtains output
labels, and decoding them needs shares held by a quorum, so single-party
evaluation moves the work without moving the knowledge. Release of a secret
still requires a quorum and the authorization layer.

## License

MIT
