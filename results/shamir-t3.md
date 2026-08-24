# Shamir t=3 measurements

Iceberg's threshold t=3 needs a signing quorum of 2t-1 = 5 online members
tolerating up to 2 corruptions, which is malicious Shamir MPC with 5 parties
and threshold 2 (`malicious-shamir-party.x`, `THRESHOLD=2`). Same host and
seed as the main loopback benchmark. Re-measured after the vectorised-hashing
fix, so every lane is verified; the batched row in the previous version of
this file came from the broken path and was wrong in every lane but the
first.

| run | total | party-0 traffic | rounds |
|---|---:|---:|---:|
| K=1 edge | 0.31 s | 4.1 MB | 1,645 |
| K=10 edges | 2.87 s | 40.3 MB | 16,228 |
| K=1 + B2A (daBits) | 0.34 s | 5.8 MB | 1,689 |
| N=100 batched, K=1 | 6.83 s | 414 MB | 3,037 |

## Reading

**The round structure is unchanged from Rep3.** One edge is about 1,645
rounds against Rep3's 1,635, and ten edges scale linearly in both. Round
count is a property of the SHA-256 circuit's depth, not of the sharing
scheme, so the wide-area cost model and the precompute-and-buffer
architecture carry over from t=2 without change.

**Bandwidth is what t=3 costs.** One edge moves 4.1 MB per party against
Rep3's 0.48 MB, roughly nine times as much, and the batched case moves
414 MB for 100 edges against Rep3's 4.6 MB.

**Batching still works, at a worse constant.** 100 edges cost 3,037 rounds
against 1,645 for one, so 100 times the work for under twice the rounds.
Rep3 does better on both counts (1,880 rounds for the same 100 edges), but
the shape holds.

**What this constrains.** t=3 is viable for a custody provider on
data-centre links, and the round-driven latency is identical to t=2. The
bandwidth is the planning constraint: a deep lookahead buffer costs about
nine times what it does at t=2, so buffer depth and refill batching need
sizing against the available link rather than against t=2's numbers. No
such sizing analysis exists yet.
