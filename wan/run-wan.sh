#!/bin/sh
# Drive the WAN run once wan/launch-instances.sh has recorded the nodes.
#
# Phases, in order:
#   mesh    WireGuard between all four nodes (10.99.0.1 .. 10.99.0.4)
#   build   clone the repo, build MP-SPDZ, start each member agent
#   certs   one set of TLS certificates, generated once and distributed
#   ping    latency matrix over the mesh, the path the MPC takes
#   bench   raw per-primitive benchmarks
#   life    the full distributed lifecycle against the live LDK counterparty
#
# Usage:
#   sh wan/run-wan.sh              run every phase
#   sh wan/run-wan.sh mesh build   run only the named phases
#
# The mesh is a correctness requirement, not tidiness. MP-SPDZ has every
# party dial the coordination server as a client, party 0 included
# (Networking/Player.cpp, Names::setup_names), and an EC2 instance cannot
# reach its own public IP. Inside the mesh each node reaches its own address
# on a local interface, so one command line is correct for every party and
# every protocol, including the BMR binaries, which take no IP file.
#
# Note for anyone editing this: ssh reads standard input, so an ssh inside a
# `while read ... done < file` loop will swallow the rest of the file. Use
# $SSHN (ssh -n) inside such loops.
set -u
KEY=${KEY:-shachain-wan}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$HERE")
NODES="$HERE/nodes.txt"
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=15 -o BatchMode=yes"
SSHN="$SSH -n"
U=ubuntu
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
OUT=${OUT:-$REPO/results/wan-$(date +%Y%m%d-%H%M)}
mkdir -p "$OUT"

# capture the requested phases before positional parameters are reused below
PHASES="$*"
[ -n "$PHASES" ] || PHASES="mesh build certs ping bench life"

[ -s "$NODES" ] || { echo "no wan/nodes.txt; run wan/launch-instances.sh first"; exit 1; }
IPS=$(awk '{print $4}' "$NODES")
set -- $IPS
PUB0=$1 PUB1=$2 PUB2=$3
W0=10.99.0.1 W1=10.99.0.2 W2=10.99.0.3 W3=10.99.0.4
want() { case " $PHASES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

echo "phases: $PHASES"
echo "output: $OUT"

if want mesh; then
  echo "=== mesh: opening UDP 51820 between the nodes ==="
  while read -r IDX R ID IP; do
    SG=$(aws ec2 describe-security-groups --region "$R" \
         --filters Name=group-name,Values="$KEY" \
         --query 'SecurityGroups[0].GroupId' --output text)
    for PEER in $IPS; do
      aws ec2 authorize-security-group-ingress --region "$R" --group-id "$SG" \
        --protocol udp --port 51820 --cidr "$PEER/32" >/dev/null 2>&1
    done
  done < "$NODES"

  echo "=== mesh: generating keys ==="
  : > "$OUT/wg-pubkeys.txt"
  while read -r IDX R ID IP; do
    until $SSHN "$U@$IP" true 2>/dev/null; do sleep 5; done
    PUBKEY=$($SSHN "$U@$IP" '
      sudo mkdir -p /etc/wireguard
      command -v wg >/dev/null || {
        sudo apt-get update -qq >/dev/null 2>&1
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard >/dev/null 2>&1
      }
      [ -s /etc/wireguard/priv ] || (umask 077; wg genkey | sudo tee /etc/wireguard/priv >/dev/null)
      sudo cat /etc/wireguard/priv | wg pubkey')
    [ -n "$PUBKEY" ] || { echo "no WireGuard key from member $IDX ($IP)"; exit 1; }
    echo "$IDX $IP $PUBKEY" >> "$OUT/wg-pubkeys.txt"
    echo "  member $IDX $PUBKEY"
  done < "$NODES"
  [ "$(wc -l < "$OUT/wg-pubkeys.txt")" -eq 4 ] || { echo "expected 4 keys"; exit 1; }

  echo "=== mesh: configuring ==="
  while read -r IDX R ID IP; do
    CONF="[Interface]
Address = 10.99.0.$((IDX + 1))/24
ListenPort = 51820
PostUp = wg set %i private-key /etc/wireguard/priv
"
    while read -r PIDX PIP PPUB; do
      [ "$PIDX" != "$IDX" ] || continue
      CONF="$CONF
[Peer]
PublicKey = $PPUB
AllowedIPs = 10.99.0.$((PIDX + 1))/32
Endpoint = $PIP:51820
PersistentKeepalive = 25
"
    done < "$OUT/wg-pubkeys.txt"
    echo "$CONF" | $SSH "$U@$IP" "sudo mkdir -p /etc/wireguard && \
      sudo tee /etc/wireguard/wg0.conf >/dev/null && \
      (sudo systemctl restart wg-quick@wg0 2>/dev/null || \
       (sudo wg-quick down wg0 2>/dev/null; sudo wg-quick up wg0))" >/dev/null
    echo "  member $IDX configured"
  done < "$NODES"

  echo "=== mesh: checking every direction ==="
  FAIL=0
  while read -r IDX R ID IP; do
    for W in $W0 $W1 $W2 $W3; do
      if $SSHN "$U@$IP" "ping -c1 -W3 -q $W >/dev/null 2>&1"; then :; else
        echo "  member $IDX cannot reach $W"; FAIL=1
      fi
    done
  done < "$NODES"
  [ "$FAIL" = 0 ] && echo "  mesh fully connected" || { echo "mesh incomplete; stopping"; exit 1; }
fi

if want build; then
  echo "=== build: bootstrapping all four nodes in parallel (~20 min) ==="
  while read -r IDX R ID IP; do
    ( $SSHN "$U@$IP" \
        "curl -sSfL https://raw.githubusercontent.com/jesseposner/shachain-mpc/main/wan/bootstrap.sh -o /tmp/bootstrap.sh && sh /tmp/bootstrap.sh $IDX" \
        > "$OUT/bootstrap-$IDX.log" 2>&1 \
        && echo "  member $IDX ready" \
        || echo "  member $IDX FAILED (tail $OUT/bootstrap-$IDX.log)" ) &
  done < "$NODES"
  wait
  grep -q FAILED "$OUT/bootstrap-"*.log 2>/dev/null || true
  for i in 0 1 2 3; do
    $SSHN "$U@$(awk -v i=$i '$1==i{print $4}' "$NODES")" \
      "curl -sf http://127.0.0.1:9001/health >/dev/null" \
      && echo "  member $i agent responding" \
      || { echo "  member $i agent NOT responding; stopping"; exit 1; }
  done
fi

if want certs; then
  echo "=== certs: generating on member 0 and distributing ==="
  $SSHN "$U@$PUB0" "cd \$HOME/MP-SPDZ && Scripts/setup-ssl.sh 3 >/dev/null 2>&1 && ls Player-Data/P*.pem" \
    || { echo "certificate generation failed"; exit 1; }
  for f in P0.pem P0.key P1.pem P1.key P2.pem P2.key; do
    $SSHN "$U@$PUB0" "cat \$HOME/MP-SPDZ/Player-Data/$f" > "$OUT/$f"
  done
  for IP in $PUB1 $PUB2; do
    for f in P0.pem P0.key P1.pem P1.key P2.pem P2.key; do
      $SSH "$U@$IP" "cat > \$HOME/MP-SPDZ/Player-Data/$f" < "$OUT/$f"
    done
    $SSHN "$U@$IP" "cd \$HOME/MP-SPDZ && (openssl rehash Player-Data || c_rehash Player-Data) >/dev/null 2>&1"
    echo "  distributed to $IP"
  done
  rm -f "$OUT"/P?.pem "$OUT"/P?.key
fi

if want ping; then
  echo "=== ping: latency matrix over the mesh ==="
  {
    echo "| from \\\\ to | m0 us-east-1 | m1 us-west-2 | m2 eu-west-1 | m3 eu-central-1 |"
    echo "|---|---|---|---|---|"
    while read -r IDX R ID IP; do
      ROW=$(printf '| m%s %s ' "$IDX" "$R")
      for W in $W0 $W1 $W2 $W3; do
        RTT=$($SSHN "$U@$IP" "ping -c 10 -q $W 2>/dev/null | awk -F/ '/rtt|round-trip/{printf \"%.1f\", \$5}'")
        ROW="$ROW| ${RTT:--} ms "
      done
      echo "$ROW|"
    done < "$NODES"
  } | tee "$OUT/latency.md"
fi

if want bench; then
  echo "=== bench: raw per-primitive benchmarks ==="
  B0=$PUB0; B1=$PUB1; B2=$PUB2
  for IP in $B0 $B1 $B2; do
    $SSHN "$IP" true 2>/dev/null
    $SSHN "$U@$IP" "cd \$HOME/MP-SPDZ && python3 \$HOME/shachain-mpc/scripts/input.py . 0101010101010101010101010101010101010101010101010101010101010101 1100 >/dev/null 2>&1" &
  done
  wait

  compile_all() {
    for IP in $B0 $B1 $B2; do
      $SSHN "$U@$IP" "cd \$HOME/MP-SPDZ && ./compile.py $* >/dev/null 2>&1" &
    done
    wait
  }
  run_parties() { # binary program extra...
    BIN=$1; PROG=$2; shift 2
    PORT=$(awk 'BEGIN{srand();printf "%d", 15000+int(rand()*400)}')
    n=0
    for IP in $B0 $B1 $B2; do
      $SSHN "$U@$IP" "cd \$HOME/MP-SPDZ && ./$BIN $n $PROG -h $W0 -pn $PORT $* 2>&1" \
        > "$OUT/raw-$PROG-p$n.log" 2>&1 &
      n=$((n + 1))
    done
    wait
    echo "--- $PROG ($BIN)"
    grep -hE "^Time = |^Time[0-9] = |^Data sent = |online phase" "$OUT/raw-$PROG-p0.log" \
      || tail -3 "$OUT/raw-$PROG-p0.log"
  }

  {
    compile_all -B 256 shachain_step 1 1 0 0
    run_parties malicious-rep-bin-party.x shachain_step-1-1-0-0

    compile_all -P "$Q" -X shachain_step 1 1 1 0
    run_parties malicious-rep-field-party.x shachain_step-1-1-1-0 -P "$Q"

    compile_all -B 256 shachain_step 1 100 0 0
    run_parties malicious-rep-bin-party.x shachain_step-1-100-0-0
  } 2>&1 | tee "$OUT/raw-benchmarks.txt"
fi

if want life; then
  echo "=== life: distributed lifecycle (coordinator on member 0) ==="
  $SSHN "$U@$PUB0" \
    "export PATH=\$HOME/.cargo/bin:\$PATH; \
     cd \$HOME/shachain-mpc && python3 poc/coordinator.py \
       --members http://$W0:9001,http://$W1:9001,http://$W2:9001,http://$W3:9001 \
       --mpc-hosts $W0,$W1,$W2,$W3 \
       --mpspdz \$HOME/MP-SPDZ --updates ${UPDATES:-6} --after ${AFTER:-3} \
       ${COORD_ARGS:-}" \
    2>&1 | tee "$OUT/lifecycle.txt"
fi

echo
echo "results in $OUT"
echo "REMEMBER: sh wan/teardown.sh"
