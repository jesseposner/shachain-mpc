# End-to-end proof of concept

`driver.py` runs a full channel lifecycle for a 2-of-4 custodian group
(Iceberg t=2: quorum of 3, one corruption tolerated, one standby member):

```
== setup: RSS seed, 4 members, quorum [0, 1, 2]
== channel open: 48-edge cold start in MPC          12.5 s
== steady state: 6 channel updates
   state c: point published, state c-1 revoked      ~2.5 s each
== crash: volatile masks destroyed; member 2 goes offline
== quorum change to [0, 1, 3] + RESTORE             92 hashes, 17.9 s
== continuing: 3 more updates with the new quorum
== PoC complete in 48.5 s: LDK accepted every point and secret
```

What each phase exercises:

- **Setup.** Four RSS summands, summand j held by every member except j, so
  any three members reconstruct the seed inside MPC. Summand files are the
  only durable secret state.
- **Cold start.** The DFS frontier is built down to leaf 2^48-1 through the
  maliciously secure replicated MPC. Frontier values leave each run only as
  XOR-masked tuples: a public masked value plus one fresh mask per active
  member (volatile state).
- **Steady state.** Per commitment, one MPC run advances the frontier by
  exactly the BOLT-required edges, re-masks new nodes, and exports the leaf
  scalar; the driver combines per-member points with replicated cross-checks
  into P_c and sends it to the counterparty. A later run opens the previous
  leaf for revocation.
- **Counterparty.** A live rust-lightning process
  (`ldk-check/src/bin/counterparty.rs`) receives every point and secret,
  runs LDK's own insert_secret derivation checks, and verifies each revealed
  secret matches the earlier point. Any failure aborts the PoC.
- **Crash and quorum change.** All volatile masks are destroyed and one
  member goes offline. The new quorum rebuilds the frontier from the seed
  summands alone, and re-derives any prepared-but-unreleased leaves so the
  pending revocation still completes, byte-identically, after the crash.

Run it (MP-SPDZ built per the main README, cargo available):

```sh
python3 poc/driver.py --updates 6 --after 3
```

Timings are dominated by per-step MP-SPDZ compilation on the driver's
critical path, not by the MPC itself; a production engine would compile
step templates once. Out of scope, recorded here deliberately: the
release-authorization layer (nothing gates `release_leaf`), duplicate
consistency checks on summand inputs, garbled-circuit channel open (the
cold start uses the replicated MPC), and network transport (members are
processes on one machine; the WAN plan covers deployment).
