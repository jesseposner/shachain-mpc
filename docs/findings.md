# Findings: the BOLT shachain under threshold custody

Written for the Iceberg coauthors and anyone evaluating whether
per-commitment secrets block a thresholdized Lightning endpoint. Everything
below is reproducible from this repository, and each claim names the script
or result file that backs it.

## The question

Iceberg makes a t-of-n group appear to the channel counterparty as one
standard MuSig2 participant. The remaining protocol surface is the BOLT #3
shachain: the endpoint must publish per-commitment points `P_c = s_c*G` and
later reveal the exact 32-byte secrets `s_c`, where the `s_c` chain is
SHA-256-derived from a seed, and the counterparty verifies the chain's
derivation structure (`insert_secret`). SHA-256 has no algebra to exploit, so
the secrets must be derived inside Boolean-circuit MPC or the seed must sit
with some single party.

## Only half the problem needs thresholding

A channel runs two shachains, and only one of them is expensive.

**Ours.** We reveal a per-commitment secret for the state we are retiring.
No custodian may learn a future one, so this chain has to be derived inside
MPC. Everything measured in this repository concerns this chain.

**Theirs.** The counterparty reveals their secret to us in `revoke_and_ack`.
It arrives in plaintext and our endpoint is supposed to learn it. Storing it
is the ordinary 49-bucket structure and checking it is BOLT's local
derivation check, so this chain costs no MPC at all.

Holding every secret we have received is also not, by itself, dangerous. To
punish a cheating counterparty the endpoint needs the revocation private
key, which combines their revealed secret with our own
`revocation_basepoint_secret`, and that basepoint secret is threshold-shared
like any other key. One custodian with the full history of received secrets
and no quorum can do nothing with them.

The practical consequence is that a commitment update costs the group one
prepared outbound secret, while the inbound half is free local work.

The unit there is a revocation, not a payment. Each commitment update revokes
the previous commitment and reveals exactly one secret, and a payment is
normally two updates: one carrying `update_add_htlc`, one carrying
`update_fulfill_htlc`. So an isolated payment consumes two prepared secrets.
Many HTLCs can also share one `commitment_signed`, which takes a busy channel
the other way, below one revocation per payment. The engine owes one prepared secret per revocation
either way.

Nor is the opening itself an MPC operation, though it was when this was first
written. Revealing a prepared secret runs no circuit and no MPC session; see
item 3 below.

## What is established, with evidence

1. **Exact BOLT compatibility, end to end.** The reference implementation
   passes the five official BOLT #3 test vectors (`scripts/ref.py selftest`).
   The MPC output equals the reference byte-for-byte under six protocols,
   including the invalid-scalar branch and every lane of a vectorised hash
   (`scripts/test.sh`, 28 cases). Secrets
   derived by the maliciously secure MPC are accepted by LDK's shachain
   verifier, which also rejects all 32 single-byte corruptions and re-derives
   stored secrets (`scripts/ldk_check.sh`, rust-lightning 0.1).

2. **Cost in Iceberg's own trust model.** For t=2 (quorum of 3, one
   corruption), maliciously secure replicated MPC computes one shachain edge
   in ~58 ms and 0.48 MB per party on loopback, and 1,000 edges batched cost
   the same 1,628 rounds as one, so ~0.35 ms and ~44 KB per edge
   (`results/<host>-<date>.md`, regenerated after the vectorised-hashing fix,
   so every lane is verified). For t=3 (quorum of 5, two corruptions),
   malicious Shamir gives the same round structure at ~10x the bandwidth
   (`results/shamir-t3.md`). Loopback figures like these say what the compute
   and bandwidth cost; they say nothing about the wide-area cost, which is
   round count times latency (`results/wan-20260823.md`).

3. **Rounds, not compute, are the constraint.** One edge is ~1,635 sequential
   communication rounds, the AND-depth of the SHA-256 circuit, which measured
   65 s across three continents against 58 ms on one machine. So derivation
   has to run as background precomputation into a lookahead buffer, and
   refilling 2^k leaves costs k tree levels rather than 2^k hashes, so a
   1,024-deep buffer costs about eleven minutes and sustains a revocation
   every 0.64 s per channel (`docs/batching.md`).

   What is left on the live path is revealing an already-prepared secret,
   and that is one round with no MPC session at all: the members send the
   summands they hold, the adapter compares the copies it receives and
   XORs, and the result is checked against the point already published. The
   measured 139 ms across three continents, and 184 ms after a quorum change
   moved the slowest leg from 118.6 ms to 139.7 ms, which is what a single
   round should do (`results/wan-20260824.md`).

4. **Channel open resolved by garbled circuits.** The 48-edge cold start
   cannot be computed before the seed exists, but its garbled circuit can:
   we added package persistence to MP-SPDZ's BMR, and the measured flow is
   garble and dump in advance (0.21 GB per party on disk), then a fresh
   process evaluates the package in three online rounds and 8.7 KB,
   independent of network latency (`results/bmr-notes.md`). Across three
   continents that made channel open 4.8 s against the 52.7 minutes the same
   cold start takes computed on the critical path
   (`results/wan-20260824.md`).

5. **A quorum change costs nothing.** Prepared secrets are hidden under a
   replicated sharing derived from the seeds, so any quorum reconstructs
   them. Measured across three continents: the Ireland member dropped
   mid-channel, the Frankfurt standby took over, nothing was rebuilt and the
   channel continued with LDK accepting every point and secret. This replaced
   a 77,151-round rebuild that measured 126 minutes, during which the channel
   could not advance (`docs/buffer-storage.md`).

6. **Setup is Iceberg's, not a second scheme.** The shachain generates no key
   material of its own. An Iceberg share is already seeds indexed by the
   groups of t-1 participants the holder is not in, which at t=2 is exactly a
   summand held by everyone except one member. `scripts/iceberg.py`
   reimplements Iceberg's dealing and tagged hashing byte-for-byte, checked
   by recomputing the SHA-256 midstates its C hard-codes, and derives
   shachain values under separate tags (`docs/key-material.md`).

7. **Point export closes the pipeline.** From the replicated Z_q sharing,
   each party computes one curve point per share component locally; replicated
   pairs are cross-checked by point equality, and the sum is `P = s*G`. The
   prototype (`scripts/point_export.py`) verifies against the reference
   scalar and aborts on a corrupted share. Per-party cost is two point
   multiplications, microseconds with libsecp256k1. With one corruption among
   three, every summand has an honest holder, so a tampered point cannot
   survive the cross-check.

## Assumptions and open items, stated plainly

- **daBit conversion binding.** The claim that the exported Z_q sharing
  encodes exactly the 256 output bits rests on MP-SPDZ's malicious-secure
  mixed-circuit machinery (Rotaru-Wood daBits; edaBits paper, eprint
  2020/338). We measured it; we did not re-prove it.
- **The validity check does not gate anything yet.** The circuit computes
  `1 <= s < q` and the harness checks it, but abort-on-invalid is release
  policy, which belongs to the authorization layer. The probability involved
  is ~2^-128 per output.
- **The authorization / anti-rollback layer is unbuilt.** Releasing `s_c`
  must be bound to the same durable channel-state transition that authorizes
  Iceberg signing, with rollback protection at honest custodians. This is the
  largest remaining work item and it is systems design, not cryptography.
- **BMR-to-Rep3 handoff.** The masked-output handoff works and is measured;
  authenticating the member-held summands against a malicious party is part
  of the authorization layer above.
- **Batched throughput rests on our patch to MP-SPDZ's vectorised hashing**,
  which was wrong in every lane but the first. The patch is checked against
  the plaintext reference for three lanes. It is not checked against MP-SPDZ
  upstream, which still has the bug, so a stock checkout produces wrong
  answers in every lane but the first and says nothing about it.
- **Members execute whatever computation the coordinator sends.** This is
  the sharper form of the authorization gap, and authenticating the
  coordinator does not close it. `/step` installs caller-supplied bytecode
  and feeds it real seed summands, and the engine will open any value it is
  asked to open, so a coordinator that is authenticated and malicious can
  have honest members reconstruct the seed. MPC computes the requested
  function securely; nothing here decides whether it was the right function.
  Members have to validate a canonical plan and an approved template
  themselves, or the coordinator is inside the trust boundary. Unauthenticated
  callers are the same hole reached more cheaply: any peer that can reach the
  port can also overwrite a member's seeds. They are safe only behind the
  private network they run on.
- **Prototype quality.** MP-SPDZ is a research framework, carrying three
  out-of-tree patches of ours including one for a correctness bug in its
  vectorised hashing; the point-export harness simulates three parties in one
  process; per-step compilation dominates the prototype's wall clock and none
  of its protocol cost. Nothing here is production software.

## The shape of the answer

The BOLT shachain is not a protocol-level barrier to threshold Lightning. It
is a reactive-MPC engineering problem with a favorable structure: one
single-block SHA-256 per commitment amortized, a 49-node frontier, restart
from the seed alone. The architecture that the numbers support is Rep3 (or
Shamir at t=3) background derivation feeding a lookahead buffer, pre-garbled
BMR packages for channel open and quorum changes, local point export with
replicated cross-checks, and a to-be-designed authorization layer gating
release. The counterparty sees a standard Lightning endpoint throughout, and
LDK, unmodified, agrees.
