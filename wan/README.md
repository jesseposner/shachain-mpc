# WAN run

Everything here is staged and ready. One command needs a human because it
starts billable instances; the rest runs unattended.

## What it measures

All published numbers are loopback, so the claim everything else rests on is
still an extrapolation: one shachain edge takes ~1,600 sequential
communication rounds, which makes wall-clock a product of rounds and RTT.
That is the reason derivation has to run as background precomputation and
channel open has to come from a pre-garbled package. This run turns that into data.

| claim | prediction | what confirms it |
|---|---|---|
| Rep3 edge is round-bound | ~1,600 x slowest leg | raw `mal-rep-bin` K=1 |
| hot path is cheap | 31 rounds, well under a second | raw `mal-rep-field` with B2A |
| batching survives WAN | rounds barely grow with N | raw `mal-rep-bin` N=100 |
| **package open is latency-independent** | **2 rounds, ~0.5 s regardless of distance** | **lifecycle channel open** |
| recovery is bounded | <= 48 hashes, one RESTORE | lifecycle crash + quorum change |

Latency is measured over the mesh, which is the path the MPC actually takes.

The fourth row is the headline. The lifecycle also exercises the parts a
microbenchmark cannot: quorum change between continents, and an unmodified
LDK counterparty judging every point and secret.

## Topology

Four `c7g.2xlarge` (Graviton, 8 vCPU), Ubuntu 24.04 arm64, one per region.
This is Iceberg's 2-of-4: threshold t=2, quorum 2t-1=3, group n=4.

| member | region | role |
|---|---|---|
| 0 | us-east-1 | quorum slot 0; also runs the coordinator and the LDK counterparty |
| 1 | us-west-2 | quorum slot 1 |
| 2 | eu-west-1 | quorum slot 2 until the crash |
| 3 | eu-central-1 | standby; takes slot 2 after the quorum change |

Both quorums keep a cross-continental leg (~130 ms before the change,
~145 ms after), so the updates before and after are comparable.

A WireGuard mesh (10.99.0.1 .. 10.99.0.4) joins the four nodes, and every MPC
address is a mesh address. This is a correctness requirement, not tidiness. MP-SPDZ has every party dial the coordination server as a client,
party 0 included (`Networking/Player.cpp`, `Names::setup_names`), and an EC2
instance cannot reach its own public IP, so `-h <party 0 public IP>` fails on
party 0 itself. Inside the mesh every node reaches its own address on a local
interface, which makes one command line correct for every party and every
protocol, including the BMR binaries, which accept no IP file. The mesh also
means the only port that has to be open between regions is UDP 51820.

## Running it

```sh
sh wan/prepare-aws.sh        # key pairs, security groups, AMIs (free)
sh wan/launch-instances.sh   # THE ONE THAT COSTS MONEY (~$0.29/hr x 4)
sh wan/run-wan.sh            # bootstrap, latency matrix, benchmarks, lifecycle
sh wan/teardown.sh           # terminate everything and remove the staging
```

`launch-instances.sh` is resumable: it leaves members that already have a
live instance alone, so re-running after a partial failure launches only what
is missing. A region the account has not used before answers `RunInstances`
with `PendingVerification` while AWS validates it, which `--dry-run` does not
predict and which cleared within minutes for us; the script retries those
regions rather than giving up.

`run-wan.sh` opens UDP 51820 between the node IPs, builds the WireGuard mesh,
bootstraps all four nodes in parallel (~20 min, dominated by the MP-SPDZ
build), then measures. Results are written to
`results/wan-<timestamp>/`: `latency.md`, `raw-benchmarks.txt`,
`lifecycle.txt`, and a bootstrap log per node.

Add `--skip-bootstrap` to re-run measurements on nodes that are already built.

## Budget and cleanup

A full run takes about 45 minutes including the build. That is four
instances at roughly $0.29/hr, so under $2, plus a few cents of cross-region
egress. The key pairs and security groups are free, so nothing else on the
account is billable.

`teardown.sh` kills the instances and deletes the security groups and key
pairs in all four regions. Run it. Instances left running are the only way
this gets expensive.

## Deliberate choices worth knowing

- SSH is open to `0.0.0.0/0` on these ephemeral, key-only nodes. Nothing else
  is exposed: the MPC ports and the member agents listen only inside the
  WireGuard mesh, whose single UDP port is scoped to the four node IPs.
- The coordinator runs on member 0 rather than a laptop, so a home uplink is
  not in the measurement path. It still only handles public data.
- Bootstrap clones this repo from GitHub, so nothing is uploaded and every
  node builds identical binaries from the same commit.
- Skipped deliberately: `mal-rep-bin` K=48 (77k rounds, hours over a WAN) and
  in-session BMR garbling for K=48 (81k rounds). The model covers both once
  the K=1 numbers confirm it, and the stockpiled package is what a real
  deployment uses anyway.
