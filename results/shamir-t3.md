# Shamir t=3 measurements

Iceberg's threshold t=3 needs a signing quorum of 2t-1 = 5 online members
tolerating up to 2 corruptions, which is exactly malicious Shamir MPC with 5
parties and threshold 2 (`malicious-shamir-party.x`, `THRESHOLD=2`). Same
host, program and seed as the main benchmark; loopback.

| run | total | party-0 traffic | rounds |
|---|---:|---:|---:|
| K=1 edge | 0.33 s | 4.1 MB | ~1,900 |
| K=10 edges | 2.9 s | 40 MB | ~16,500 |
| K=1 + B2A (daBits) | 0.36 s (B2A 17 ms, 44 rounds) | 5.8 MB | ~1,900 |
| N=100 batched, K=1 | 6.4 s (64 ms/edge amortized) | 387 MB | ~3,200 |

Correct output (matches the reference hash).

Reading: the round structure is unchanged from Rep3 (~1,600 sequential rounds
per edge is the circuit's depth, not the protocol's), so the precompute-and-
buffer architecture carries over as-is. What changes is bandwidth: ~4 MB per
edge per party against Rep3's 0.4 MB, and batching amortizes to ~64 ms and
~3.9 MB per edge against Rep3's ~1 ms and ~40 KB. t=3 is therefore viable for
a custody provider on data-center links, but the per-update bandwidth budget
is 10x t=2's, and deep lookahead buffers pay for it linearly.
