#!/bin/sh
# End-to-end interoperability: derive the first LEAVES per-commitment secrets
# with the maliciously secure MPC, then feed them to LDK's shachain verifier
# (rust-lightning CounterpartyCommitmentSecrets), exactly as a counterparty
# would during revoke_and_ack processing. Also runs the point-export harness,
# including its corruption check.
set -eu
MPSPDZ=${MPSPDZ:-$HOME/src/MP-SPDZ}
HERE=$(cd "$(dirname "$0")/.." && pwd)
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
SEED=${SEED:-0101010101010101010101010101010101010101010101010101010101010101}
LEAVES=${LEAVES:-8}
M=281474976710655
OUT=$(mktemp)
ln -sf "$HERE/programs/shachain_step.mpc" "$MPSPDZ/Programs/Source/"
cd "$MPSPDZ"
python3 "$HERE/scripts/input.py" . "$SEED"

i=0
while [ $i -lt $LEAVES ]; do
  IDX=$((M - i))
  ./compile.py -B 256 shachain_step 0 1 0 1 0 $IDX >/dev/null
  H=$(Scripts/mal-rep-bin.sh "shachain_step-0-1-0-1-0-$IDX" 2>&1 \
      | sed -n 's/^Reg\[[0-9]*\] = 0x\([0-9a-f]*\).*/\1/p' | head -1)
  [ -n "$H" ] || { echo "no output for index $IDX"; exit 1; }
  echo "$IDX $H" >> "$OUT"
  i=$((i + 1))
done
echo "derived $LEAVES secrets with malicious-rep-bin"

cd "$HERE/ldk-check"
cargo run -q --release --bin ldk-check -- "$OUT"
rm -f "$OUT"

# Point export: derive one scalar with B2A + EXPORT, then publish P = s*G.
cd "$MPSPDZ"
rm -f Persistence/Transactions-P*.data
./compile.py -P $Q -X shachain_step 1 1 1 1 0 0 1 >/dev/null
Scripts/mal-rep-field.sh shachain_step-1-1-1-1-0-0-1 -P $Q >/dev/null 2>&1
EXPECTED=$(python3 "$HERE/scripts/ref.py" "$SEED" 1 | awk '/^scalar/{print $2}')
EXPECTED=$(python3 -c "print($EXPECTED % $Q)")
python3 "$HERE/scripts/point_export.py" . "$EXPECTED"
if python3 "$HERE/scripts/point_export.py" . --corrupt >/dev/null 2>&1; then
  echo "FAIL: corrupted share was not detected"; exit 1
else
  echo "PASS: corrupted share detected by point cross-check"
fi
