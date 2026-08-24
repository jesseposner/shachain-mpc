# WAN benchmark plan (superseded)

The plan in this file has been built out as scripts. See
[wan/README.md](../wan/README.md) for the runbook and
`wan/prepare-aws.sh`, `wan/launch-instances.sh`, `wan/run-wan.sh`,
`wan/teardown.sh` for the staging, launch, run and cleanup.

Building it forced two changes to that plan, both worth recording.

- Topology is four nodes joined by a WireGuard mesh rather than raw public
  addressing. MP-SPDZ has every party dial the coordination server as a
  client, party 0 included, and an EC2 instance cannot reach its own public
  IP, so public addressing fails on party 0. The mesh also reduces the
  cross-region firewall surface to one UDP port.
- The lifecycle run uses the distributed PoC (`poc/member.py` on each node,
  `poc/coordinator.py` on member 0), which did not exist when this plan was
  written.
