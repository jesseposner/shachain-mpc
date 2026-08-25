# shachain-mpc

Exactly BOLT-compatible per-commitment secrets for a thresholdized Lightning
endpoint, evaluated inside honest-majority MPC.

This repository answers one question. If a t-of-n group emulates one
Lightning endpoint
([Iceberg](https://eprint.iacr.org/2026/1757) handles the signing), can it
also emulate the endpoint's BOLT #3 shachain, so that no coalition below
threshold learns an unrevealed per-commitment secret while the counterparty
sees an ordinary channel? The shachain is SHA-256 based, so it has none of
the algebraic structure that makes threshold signing cheap, and the secrets
have to be derived inside a Boolean-circuit MPC.

They can be, and revoking a commitment ends up costing one communication
round.

## Only the outbound chain needs MPC

A channel runs two shachains. The one we generate has to be derived inside
MPC, since no custodian may learn a future per-commitment secret; that chain
is what everything here measures. The counterparty's chain arrives in
plaintext in `revoke_and_ack`, which our endpoint is meant to learn, so it
costs no MPC: store it in the usual 49 buckets and run BOLT's derivation
check locally. Holding every secret received is safe for a single custodian,
because punishing a cheat also needs our `revocation_basepoint_secret`,
which is threshold-shared. So each commitment update costs the group one
prepared secret rather than two.

## Rounds per operation

Wide-area cost is round count times latency, so rounds are the number to
watch.

| operation | rounds | wide-area cost | how we know |
|---|---:|---:|---|
| **reveal a prepared secret (one revocation)** | **1** | **139 ms** | measured on the WAN; 184 ms after a quorum change, tracking its slowest leg |
| the same reveal, earlier six-round MPC form | 6 | 0.18 s | measured on the WAN |
| **quorum change** | **0** | **none** | measured on the WAN: the channel continues, nothing is rebuilt |
| channel open from a stockpiled package | 3 online | **4.8 s** | measured on the WAN |
| channel open, computed instead | 77,151 | 52.7 min | measured on the WAN |
| prepare a leaf: validity check and conversion | 47 | 2.25 s | measured on the WAN; background work |
| one shachain edge | 1,614 | 65.5 s | measured on the WAN |
| refill a 1,024-leaf buffer | 18,870 | 12.6 min | rounds measured per level; time derived at 40 ms. Buys 1,024 revocations for 1.09 CPU s and 47 MB per signer |
| rebuild from the seed (cold start only) | 77,151 | ~51 min | derived; 126 min measured before batching halved it |

Round counts are loopback measurements, which is fine because a round count
is a property of the circuit rather than the network. Wide-area figures are
either measured on four cross-region nodes or derived by multiplying rounds
by the 40 ms per round those nodes exhibited, and the table says which.

## The unit is a revocation, not a payment

Everything above is priced per commitment update, because that is what
consumes a secret: each update revokes the previous commitment and reveals
exactly one. A payment is normally two updates, one carrying
`update_add_htlc` and one carrying `update_fulfill_htlc`, so an isolated
payment consumes two prepared secrets and two rounds, at different moments.
It also runs the other way, since many HTLCs can ride one
`commitment_signed`, which is why a busy channel amortizes below one
revocation per payment. Neither direction changes the engine, which owes the
channel one prepared secret per revocation whatever the traffic looks like.

Two cross-region runs stand behind these. The first
(`results/wan-20260823.md`) measured an earlier system; the second
(`results/wan-20260824.md`) measured this one, after the release path,
recovery and key material changed. Where they disagree, the later run is the
current system and says so.

## Why a revocation is one round

A prepared secret is a public masked value plus a replicated sharing of
summands, so revealing it is not a computation. The members send the
summands they hold, the adapter compares the copies it receives and XORs
them, and the result is checked against the point published for that state.
There is no circuit to evaluate and no MPC session to run. A member
supplying a wrong summand is caught twice: by the duplicate copies, and by the point check,
which is the same equation the counterparty verifies.

Everything expensive is background work feeding a lookahead buffer, and the
buffer only has to stay ahead of consumption. Refilling 2^k leaves costs k
tree levels rather than 2^k hashes, so a 1,024-deep buffer costs 12.6
minutes and sustains a revocation every 0.74 s per channel. That refill
spends 1.09 CPU seconds per signer, under 0.2% of one core, because the cost
is 18,870 sequential round trips and not arithmetic. Buffers do not amortise
across channels, so a node with N channels runs N of them and pays N times
the traffic. See [docs/batching.md](docs/batching.md).

## Recovery costs nothing

A prepared secret was originally hidden by one mask per online member, a
3-of-3 sharing, so a single member dropping out destroyed the buffer and
forced a 77,151-round rebuild from the seed: about 51 minutes across three
continents with the channel frozen throughout. Prepared values are now
hidden under a replicated sharing, derived rather than stored, so any quorum
can reconstruct them and a member can drop out with no effect at all. See
[docs/buffer-storage.md](docs/buffer-storage.md).

## Key material comes from Iceberg

The shachain does not generate a secret of its own. An Iceberg share is
already a collection of seeds, one per group of t-1 participants the holder
is not in, which at t=2 is one seed per other participant: a summand held by
everyone except one member. `scripts/iceberg.py` reimplements Iceberg's
dealing and tagged hashing byte-for-byte from `src/modules/iceberg`, checked
by recomputing the SHA-256 midstates its C hard-codes, and derives shachain
values under tags of their own so they cannot collide with signing shares.

Setup's security is Iceberg's key generation's, rather than that of a second
scheme beside it. See [docs/key-material.md](docs/key-material.md).

## Correctness

| check | what it establishes |
|---|---|
| `scripts/ref.py selftest` | the plaintext reference against the five official BOLT #3 vectors |
| `scripts/test.sh` | MPC output against that reference under six protocols, including the invalid-scalar branch, all lanes of a vectorised hash in order, and Iceberg conformance (28 cases) |
| `poc/selftest.py` | what a clean run never exercises: an aborted transition changes nothing public, a release with no published point is refused before anyone is asked, and two channels never share a mask |
| `scripts/ldk_check.sh` | secrets derived by the maliciously secure MPC fed to rust-lightning's `CounterpartyCommitmentSecrets`, which accepts the sequence, rejects every single-byte corruption, and re-derives stored secrets |
| the same script | point export: each party turns its share into a curve point, replicated pairs are cross-checked by point equality, the combined P equals s*G, and a corrupted share aborts |
| `poc/coordinator.py --local` | the full lifecycle, with an unmodified LDK counterparty judging every point and secret |

The LDK check is the one that matters most: software we did not write,
running the derivation checks it would run against any peer, on secrets that
were never assembled anywhere except inside the MPC.

## End-to-end proof of concept

`poc/` runs the design as a distributed lifecycle: per-member agents holding
the only copies of private state, and a coordinator that touches public data
only. A channel opens from a stockpiled garbled package, advances through
updates, publishes points with replicated cross-checks, and revokes into a
live LDK counterparty; then a member drops out, the standby takes over, and
the channel continues with nothing rebuilt. The same agents deploy across
machines for a wide-area run. See [poc/README.md](poc/README.md).

## Results

- [results/](results/): loopback benchmarks, Shamir at t=3, BMR and package
  persistence, and the cross-region run
- [results/wan-20260823.md](results/wan-20260823.md): four nodes on three
  continents. Sections that predate later changes say so
- [docs/findings.md](docs/findings.md): what is established and what is
  assumed, written for someone deciding whether this is worth pursuing
- [docs/todo.md](docs/todo.md): everything flagged as not-yet-done
- [experiments/](experiments/): measured negative results, kept so the next
  person finds the number instead of repeating the work

## Layout

```
programs/shachain_step.mpc     benchmark program: K edges, N chains, checks, export
programs/shachain_engine.mpc   the engine the PoC drives, one plan per step
programs/release_only.mpc      the release hot path in isolation
poc/                           distributed lifecycle: member agents and coordinator
scripts/iceberg.py             Iceberg's dealing and tagged hashing, byte-compatible
scripts/ref.py                 plaintext BOLT #3 reference (selftest = official vectors)
scripts/point_export.py        replicated shares -> published P = s*G with cross-checks
scripts/setup.sh               clone, patch and build MP-SPDZ (macOS and Linux ARM)
scripts/test.sh                the correctness suite
scripts/bench.sh               benchmark table -> results/<host>-<date>.md
scripts/ldk_check.sh           MPC secrets -> LDK verifier; point-export harness
ldk-check/                     Rust harness and the live counterparty process
wan/                           cross-region run: staging, launch, mesh, teardown
patches/                       MP-SPDZ fixes: clang 21, BMR phase timing, package persistence
experiments/                   optimisations that did not work, with their numbers
```

## Usage

```sh
./scripts/setup.sh                     # MPSPDZ=... to choose the checkout
./scripts/test.sh                      # the correctness suite
./scripts/bench.sh                     # loopback benchmarks
python3 poc/coordinator.py --local     # the full lifecycle on one machine
SHOW_ROUNDS=1 python3 poc/coordinator.py --local    # with per-step round counts
```

For a cross-region run see [wan/README.md](wan/README.md). Manual MPC runs,
from the MP-SPDZ directory:

```sh
./compile.py -B 256 shachain_step 10 1 0 0            # 10 edges, binary only
Scripts/mal-rep-bin.sh shachain_step-10-1-0-0
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
./compile.py -P $Q -X shachain_step 1 1000 1 0        # 1000 chains, with B2A
Scripts/mal-rep-field.sh shachain_step-1-1000-1-0 -P $Q
```

`shachain_step` takes, in order: `K` sequential edges, `N` parallel chains,
`B2A` (0/1), `CHECK` (0/1, reveals every lane for testing), `SEP` (feed the
chains as separate inputs, needed for BMR), `IDX` (walk the exact path for
one shachain index instead of K edges), `EXPORT` (write scalar shares for
point export), and `CONTRIB` (build the input from several parties' XORed
contributions).

## Background

BOLT #3's `generate_from_seed(seed, I)` walks the set bits of `I` from bit 47
down, flipping each and hashing. Clearing the lowest set bit of `I` gives its
parent `p = I & (I-1)`, and `Gen(seed, I) = SHA256(flip_ctz(I)(Gen(seed, p)))`:
every tree edge is one SHA-256. Lightning consumes indices in decreasing
order, which is a right-child-first DFS of that tree, so keeping the DFS
frontier makes the amortized cost one SHA-256 per commitment and the cold
start 48. Because it is a tree rather than a chain, secrets are produced
incrementally and there is never a need to compute them all: 2^48 of them
exist.

## Not covered here

The release-authorization layer, which binds revocation to the channel state
machine and is now the largest unbuilt piece, with several other items
deferred into it (see [docs/todo.md](docs/todo.md)). Also absent: refreshing
shares over the life of a channel, and authenticated coordinator-to-member
calls. Channel open from a stockpiled package was measured only on the
earlier system, as was the six-round release form it is compared against,
which failed in the second run for a reason since fixed (`32221ba`) and has
not been re-run.

Nor has a second channel. Every per-channel cost here is measured, but a
node running many of them is that measurement multiplied, and the scaling
argument in [docs/batching.md](docs/batching.md) rests on refills being
network-bound rather than compute-bound. The cost that scales worst is
channel open, at 1.6 GB of garbling traffic per channel per signer, not the
CPU.

## License

MIT
