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

## What is established, with evidence

1. **Exact BOLT compatibility, end to end.** The reference implementation
   passes the five official BOLT #3 test vectors (`scripts/ref.py selftest`).
   The MPC output equals the reference byte-for-byte under six protocols,
   including the invalid-scalar branch (`scripts/test.sh`, 19 cases). Secrets
   derived by the maliciously secure MPC are accepted by LDK's shachain
   verifier, which also rejects all 32 single-byte corruptions and re-derives
   stored secrets (`scripts/ldk_check.sh`, rust-lightning 0.1).

2. **Cost in Iceberg's own trust model.** For t=2 (quorum of 3, one
   corruption), maliciously secure replicated MPC computes one shachain edge
   in ~55 ms and 0.4 MB per party on loopback; batched across 1,000 channels
   it amortizes to ~1.25 ms and ~125 KB per edge including the scalar-validity
   check and the Boolean-to-Z_q conversion, or ~0.5 ms and ~41 KB without them
   (`results/<host>-<date>.md`). For t=3 (quorum of 5, two corruptions),
   malicious Shamir gives the same round structure at ~10x the bandwidth
   (`results/shamir-t3.md`).

3. **Rounds, not compute, are the constraint.** One edge is ~1,600 sequential
   communication rounds, the AND-depth of the SHA-256 circuit. Over a network
   this is seconds to minutes per edge, so derivation must run as background
   precomputation with a lookahead buffer. The per-update hot path is then
   only the B2A conversion and a scalar opening (~5 ms, 31 rounds).

4. **Channel open resolved by garbled circuits.** The 48-edge cold start
   cannot be computed before the seed exists, but its garbled circuit can:
   we added package persistence to MP-SPDZ's BMR, and the measured flow is
   garble+dump in advance (17 s, 0.21 GB per party on disk), then a fresh
   process evaluates the package in 0.47 s, 8.7 KB, and two online rounds,
   independent of network latency (`results/bmr-notes.md`). The distributed
   PoC stockpiles the package at setup and opens the channel in 1.7 s.

5. **Point export closes the pipeline.** From the replicated Z_q sharing,
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
- **BMR-to-Rep3 handoff.** Feeding a BMR cold-start output into the Rep3
  steady state as an authenticated Boolean sharing has a sketch (XOR-masked
  outputs) but no design for authentication against a malicious party.
- **Loopback numbers.** All measurements are one machine, three or five
  processes. The rounds x RTT model says WAN behavior is derivable, and the
  BMR online phase is the claim that most deserves a live confirmation
  (`docs/wan-plan.md`, deferred).
- **Prototype quality.** MP-SPDZ is a research framework; the point-export
  harness simulates three parties in one process; nothing here is production
  software.

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
