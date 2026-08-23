#!/bin/sh
# Drive the WAN run once wan/launch-instances.sh has recorded the nodes.
#
#   1. build a WireGuard mesh so every node has a stable, mutually routable,
#      self-reachable address (10.99.0.1 .. 10.99.0.4);
#   2. bootstrap all four nodes in parallel;
#   3. measure the latency matrix over the same links the MPC uses;
#   4. run the raw per-primitive benchmarks;
#   5. run the full distributed lifecycle against the live LDK counterparty;
#   6. pull everything back into results/wan-<timestamp>/.
#
# The mesh matters for correctness, not just tidiness: MP-SPDZ has every
# party, party 0 included, dial the coordination server as a client
# (Networking/Player.cpp, Names::setup_names), and an EC2 instance cannot
# reach its own public IP. Inside the mesh each node reaches its own address
# on a local interface, so the same command line works for every party and
# for every protocol, including the BMR binaries, which take no IP file.
#
# Usage: sh wan/run-wan.sh [--skip-bootstrap]
set -eu
KEY=${KEY:-shachain-wan}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$HERE")
NODES="$HERE/nodes.txt"
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"
U=ubuntu
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
OUT="$REPO/results/wan-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUT"

[ -s "$NODES" ] || { echo "no wan/nodes.txt; run wan/launch-instances.sh first"; exit 1; }
IPS=$(awk '{print $4}' "$NODES")
set -- $IPS
PUB0=$1
W0=10.99.0.1 W1=10.99.0.2 W2=10.99.0.3 W3=10.99.0.4

echo "=== opening the mesh port between nodes ==="
while read -r IDX R ID IP; do
  SG=$(aws ec2 describe-security-groups --region "$R" \
       --filters Name=group-name,Values="$KEY" \
       --query 'SecurityGroups[0].GroupId' --output text)
  for PEER in $IPS; do
    aws ec2 authorize-security-group-ingress --region "$R" --group-id "$SG" \
      --protocol udp --port 51820 --cidr "$PEER/32" >/dev/null 2>&1 || true
  done
done < "$NODES"

echo "=== waiting for SSH ==="
for IP in $IPS; do
  until $SSH "$U@$IP" true 2>/dev/null; do sleep 5; done
done

echo "=== WireGuard mesh: generating keys ==="
: > "$OUT/wg-pubkeys.txt"
while read -r IDX R ID IP; do
  PUBKEY=$($SSH "$U@$IP" '
    sudo apt-get update -qq >/dev/null 2>&1
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard >/dev/null 2>&1
    sudo mkdir -p /etc/wireguard
    [ -f /etc/wireguard/priv ] || (umask 077; wg genkey | sudo tee /etc/wireguard/priv >/dev/null)
    sudo cat /etc/wireguard/priv | wg pubkey')
  echo "$IDX $IP $PUBKEY" >> "$OUT/wg-pubkeys.txt"
done < "$NODES"
cat "$OUT/wg-pubkeys.txt"

echo "=== WireGuard mesh: configuring ==="
while read -r IDX R ID IP; do
  CONF="[Interface]
Address = 10.99.0.$((IDX + 1))/24
ListenPort = 51820
PostUp = wg set %i private-key /etc/wireguard/priv
"
  while read -r PIDX PIP PPUB; do
    [ "$PIDX" = "$IDX" ] && continue
    CONF="$CONF
[Peer]
PublicKey = $PPUB
AllowedIPs = 10.99.0.$((PIDX + 1))/32
Endpoint = $PIP:51820
PersistentKeepalive = 25
"
  done < "$OUT/wg-pubkeys.txt"
  echo "$CONF" | $SSH "$U@$IP" "sudo tee /etc/wireguard/wg0.conf >/dev/null && \
    sudo systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || sudo wg-quick up wg0 >/dev/null 2>&1 || true"
done < "$NODES"

echo "=== mesh check ==="
$SSH "$U@$PUB0" "for w in $W0 $W1 $W2 $W3; do ping -c1 -W3 -q \$w >/dev/null && echo \"\$w up\" || echo \"\$w UNREACHABLE\"; done"

if [ "${1:-}" != "--skip-bootstrap" ]; then
  echo "=== bootstrapping all four nodes in parallel (~20 min) ==="
  while read -r IDX R ID IP; do
    (
      $SSH "$U@$IP" \
        "curl -sSfL https://raw.githubusercontent.com/jesseposner/shachain-mpc/main/wan/bootstrap.sh -o /tmp/bootstrap.sh && sh /tmp/bootstrap.sh $IDX" \
        > "$OUT/bootstrap-$IDX.log" 2>&1 \
        && echo "member $IDX ready" \
        || echo "member $IDX FAILED (see $OUT/bootstrap-$IDX.log)"
    ) &
  done < "$NODES"
  wait
fi

echo "=== latency matrix (over the mesh, the path the MPC takes) ==="
{
  echo "| from \\\\ to | m0 us-east-1 | m1 us-west-2 | m2 eu-west-1 | m3 eu-central-1 |"
  echo "|---|---|---|---|---|"
  while read -r IDX R ID IP; do
    printf '| m%s %s ' "$IDX" "$R"
    for W in $W0 $W1 $W2 $W3; do
      RTT=$($SSH "$U@$IP" "ping -c 10 -q $W 2>/dev/null | awk -F/ '/rtt|round-trip/{printf \"%.1f\", \$5}'" || true)
      printf '| %s ms ' "${RTT:--}"
    done
    echo '|'
  done < "$NODES"
} | tee "$OUT/latency.md"

echo "=== raw per-primitive benchmarks (parties 0,1,2 = members 0,1,2) ==="
compile_all() { # flags... program args...
  for IP in $(head -3 "$NODES" | awk '{print $4}'); do
    $SSH "$U@$IP" "cd \$HOME/MP-SPDZ && ./compile.py $* >/dev/null 2>&1" &
  done
  wait
}
run_parties() { # binary program extra...
  BIN=$1; PROG=$2; shift 2
  PORT=$((15000 + $$ % 400))
  n=0
  for IP in $(head -3 "$NODES" | awk '{print $4}'); do
    $SSH "$U@$IP" "cd \$HOME/member-state && \$HOME/MP-SPDZ/$BIN $n $PROG -h $W0 -pn $PORT $* 2>&1" \
      > "$OUT/raw-$PROG-p$n.log" 2>&1 &
    n=$((n + 1))
  done
  wait
  echo "--- $PROG ($BIN)"
  grep -hE "^Time = |^Time[0-9] = |^Data sent = |online phase" "$OUT/raw-$PROG-p0.log" || \
    tail -3 "$OUT/raw-$PROG-p0.log"
}

for IP in $(head -3 "$NODES" | awk '{print $4}'); do
  $SSH "$U@$IP" "cd \$HOME/MP-SPDZ && python3 \$HOME/shachain-mpc/scripts/input.py . 0101010101010101010101010101010101010101010101010101010101010101 1100 >/dev/null 2>&1" &
done
wait

{
  compile_all -B 256 shachain_step 1 1 0 0
  run_parties malicious-rep-bin-party.x shachain_step-1-1-0-0

  compile_all -P "$Q" -X shachain_step 1 1 1 0
  run_parties malicious-rep-field-party.x shachain_step-1-1-1-0 -P "$Q"

  compile_all -B 256 shachain_step 1 100 0 0
  run_parties malicious-rep-bin-party.x shachain_step-1-100-0-0
} 2>&1 | tee "$OUT/raw-benchmarks.txt"

echo "=== distributed lifecycle (coordinator on member 0) ==="
$SSH "$U@$PUB0" \
  "cd \$HOME/shachain-mpc && \$HOME/MP-SPDZ/Scripts/setup-ssl.sh 3 >/dev/null 2>&1; \
   python3 poc/coordinator.py \
     --members http://$W0:9001,http://$W1:9001,http://$W2:9001,http://$W3:9001 \
     --mpc-hosts $W0,$W1,$W2,$W3 \
     --mpspdz \$HOME/MP-SPDZ --updates 6 --after 3" \
  2>&1 | tee "$OUT/lifecycle.txt"

echo
echo "results in $OUT"
echo "REMEMBER: sh wan/teardown.sh"
