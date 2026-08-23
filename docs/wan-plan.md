# Deferred: WAN benchmark plan

Status: deferred on 2026-08-23. Nothing is provisioned; the staging below was
created and then deleted. Cost estimate when run: under $2.

Goal: turn the rounds x RTT extrapolation into data. The claims to test:

1. Rep3 malicious, one edge: predicted ~1,600 x slowest-leg RTT.
2. B2A malicious: 31 rounds, predicted a few seconds cross-region.
3. Batched N=100: rounds barely grow, so amortized throughput survives WAN.
4. BMR one-shot online phase: predicted one round trip + ~10 ms/edge local,
   independent of RTT. This is the headline claim.

## Topology

Three c7g.2xlarge (Graviton, 8 vCPU), Ubuntu 24.04 arm64, one per region:
us-east-1 / us-west-2 / eu-west-1 (max leg ~130 ms RTT). AMIs resolve via SSM:
`/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id`.

Security group per region (temporary): TCP 22 and 5000-5200 plus ICMP, open
wide for the benchmark's lifetime, deleted at teardown. Import one SSH key as
`shachain-wan` in each region.

## Procedure

1. Launch the three instances (this is the step that needs human approval).
2. On each: `apt install make g++ libgmp-dev libsodium-dev libssl-dev
   libboost-dev libboost-thread-dev libboost-filesystem-dev
   libboost-iostreams-dev python3`, clone this repo, run `scripts/setup.sh`
   (first Linux exercise of that script; expect to fix the brew guard).
3. `Scripts/setup-ssl.sh 3` on party 0, copy `Player-Data/*.pem` and keys to
   the others. Compile programs identically on each node.
4. Party i runs `<protocol>-party.x -p i -N 3 -h <party0-ip> -pn 5000 <prog>`.
5. Runs, in order: ping matrix; mal-rep-bin K=1; mal-rep-field K=1 with B2A;
   mal-rep-bin K=1 N=100; mal-rep-bmr K=1 -O; rep-bmr K=48 -O (garbling
   ~5,400 rounds, budget ~15 min; gives the K=48 online phase over WAN).
   Skip mal-rep-bin K=48 (77k rounds, hours) and mal-rep-bmr K=48 garbling
   (81k rounds); the model covers them once the K=1 numbers validate it.
6. Record results to `results/wan-<date>.md` with the ping matrix alongside
   the predicted-vs-measured table. Terminate instances, delete security
   groups and key pairs.

## Notes

- MP-SPDZ garbling rounds are implementation-sequential (see
  results/bmr-notes.md finding 3); WAN garbling times will look bad and are
  not the claim under test. The online phase is.
- Cross-region egress for the full run list is ~2 GB total (~$0.04), dominated
  by rep-bmr K=48 garbling traffic.
