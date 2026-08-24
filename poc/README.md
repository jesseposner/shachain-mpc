# End-to-end proof of concept

A distributed channel lifecycle for a 2-of-4 custodian group (Iceberg t=2:
quorum of 3, one corruption tolerated, one standby member), split the way a
real deployment is:

- **`member.py`**, one per custodian machine: the only place that member's
  private state exists. Durable RSS seed summands (dealt member-to-member at
  setup; the coordinator never sees them) and volatile XOR masks for
  frontier values. It receives compiled bytecode plus a public input spec,
  supplies its own private inputs, runs its MPC party, and returns public
  data only: revealed registers and curve points computed from its own
  Z_q shares.
- **`coordinator.py`**: public state only. It does the tree bookkeeping
  (`planner.py`), compiles each engine step, ships it to the active quorum,
  combines the members' points with replicated cross-checks, and plays the
  channel against a live LDK counterparty
  (`ldk-check/src/bin/counterparty.rs`), which runs insert_secret and
  checks every revealed secret against its earlier point.

## The local demo

```sh
python3 poc/coordinator.py --local --updates 6 --after 3
```

spawns four member agents on localhost and runs:

```
== setup: dealing RSS summands member-to-member
== pre-garbled channel-open package stockpiled      ~23 s, before the seed is used
== channel open via stockpiled garbled package      ~2 s
== steady state: 6 updates                          0.3 s, or ~5 s when the tree carries
== crash: volatile state destroyed; member 2 offline
== quorum change to [0, 1, 3] + RESTORE             92 hashes, 17.6 s
== continuing: 3 updates with the new quorum
== distributed PoC complete in ~59 s: LDK accepted every point and secret
```

Most updates cost 0.3 s and some cost ~5 s: commitment c needs v2(c) new hash
edges, so most need none and every 2^k-th needs k. Revealing a secret is not
in either figure, because it no longer runs an MPC session at all (see
docs/batching.md).

A quorum change no longer needs a rebuild: prepared values are hidden under
a replicated sharing, so the new quorum derives every summand it needs and
the channel continues. `--restore-on-change` runs the old rebuild anyway, to
measure what recovery used to cost. That rebuild still reconstructs the
frontier from the seed summands alone and
re-derives prepared-but-unreleased leaves, so the revocation pending at
crash time still completes, byte-identically, under the new quorum.

## WAN deployment

Run `member.py --port 9001 --workdir ~/member --mpspdz ~/MP-SPDZ` on each
node (MP-SPDZ built per the main README), then from anywhere with the repo
and an MP-SPDZ checkout for compilation:

```sh
python3 poc/coordinator.py \
  --members http://n0:9001,http://n1:9001,http://n2:9001,http://n3:9001 \
  --mpc-hosts n0,n1,n2,n3
```

MPC parties dial the quorum's slot-0 host on ports 14001+; open those plus
the member HTTP ports between the nodes. See docs/wan-plan.md for the
cross-region topology.

## Honest limitations

- Nothing gates `release_leaf`: the authorization layer is the largest open
  work item and is deliberately absent here.
- Member agents do not authenticate their caller. `/step` validates the
  paths it writes and the binary it runs, and `--bind` can restrict the
  listening address, but any peer that reaches the port can still overwrite
  a member's Iceberg seeds. Coordinator-to-member authentication (mTLS or a
  shared secret) is required before these agents face anything but a private
  network.
- Setup ships all TLS keys to every member, and models Iceberg's trusted
  dealer rather than running its distributed key generation. The key
  material itself is Iceberg's, byte-for-byte; see docs/key-material.md.
- Per-step timing on the coordinator's critical path is dominated by
  MP-SPDZ compilation, not MPC; a production engine compiles step templates
  once.
- Channel open runs as a jointly garbled BMR circuit (no cut-and-choose;
  the garbling is itself a maliciously secure MPC) whose masked outputs
  hand the frontier to the field engine. That handoff is the BMR-to-Rep3
  re-sharing that results/bmr-notes.md had listed as an open question. The
  package is garbled and stockpiled before the seed exists, then evaluated
  at open in two online rounds; `--cold-start bmr` garbles in-session
  instead, and `--cold-start field` falls back to the replicated MPC.
- A garbled package must be evaluated exactly once, since evaluating one
  circuit on two different inputs leaks. The member deletes its package
  after use, but nothing in the runtime enforces that, and a stored package
  should be integrity-bound to the channel and quorum that will consume it.
  Both belong to the same authorization layer as `release_leaf`.
