#!/bin/sh
# Correctness test: compare MPC output against the plaintext BOLT reference
# under every protocol, including the scalar-validity flag.
set -u
MPSPDZ=${MPSPDZ:-$HOME/src/MP-SPDZ}
HERE=$(cd "$(dirname "$0")/.." && pwd)
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
ln -sf "$HERE/programs/shachain_step.mpc" "$MPSPDZ/Programs/Source/"
cd "$MPSPDZ"
python3 "$HERE/scripts/ref.py" selftest
fail=0
check() { # proto seed K [runtime-args]
  proto=$1; seed=$2; k=$3; shift 3
  case $proto in replicated|mal-rep-bin|rep-bmr|mal-rep-bmr) b2a=0;; *) b2a=1;; esac
  python3 "$HERE/scripts/input.py" . "$seed"
  out=$(Scripts/$proto.sh "shachain_step-$k-1-$b2a-1" "$@" 2>&1)
  got_hash=$(echo "$out" | sed -n 's/^Reg\[[0-9]*\] = 0x\([0-9a-f]*\).*/\1/p' | head -1)
  got_valid=$(echo "$out" | sed -n 's/^valid \(.*\)/\1/p' | head -1)
  got_scalar=$(echo "$out" | sed -n 's/^scalar \(.*\)/\1/p' | head -1)
  ref=$(python3 "$HERE/scripts/ref.py" "$seed" "$k")
  exp_hash=$(echo "$ref" | awk '/^hash/{print $2}')
  exp_valid=$(echo "$ref" | awk '/^valid/{print $2}')
  exp_scalar=$(echo "$ref" | awk '/^scalar/{print $2}')
  if [ "$got_hash" = "$exp_hash" ] && [ "$got_valid" = "$exp_valid" ] && \
     { [ "$b2a" = 0 ] || [ "$got_scalar" = "$exp_scalar" ]; }; then
    echo "PASS $proto K=$k seed=${seed%????????????????????????????????????????????????}... valid=$got_valid"
  else
    echo "FAIL $proto K=$k"; echo "$out" | tail -5; echo "$ref"; fail=1
  fi
}
ONES=0101010101010101010101010101010101010101010101010101010101010101
FFS=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
for K in 0 1 3; do
  ./compile.py -B 256 shachain_step $K 1 0 1 >/dev/null
  ./compile.py -P $Q -X shachain_step $K 1 1 1 >/dev/null
  check replicated $ONES $K
  check mal-rep-bin $ONES $K
  check rep-bmr $ONES $K -O
  check mal-rep-bmr $ONES $K -O
  check rep-field $ONES $K -P $Q
  check mal-rep-field $ONES $K -P $Q
done
# K=0 with an all-0xff input exercises the "not a valid scalar" branch.
check mal-rep-field $FFS 0 -P $Q

# Vectorised hashing must be correct in EVERY lane, not just the first.
# circuit.sha256 builds its constants one bit wide, so with a vectorised
# input only lane 0 was right; nothing caught it because the check mode
# revealed lane 0 alone.
lane_check() {
  python3 - "$MPSPDZ" <<'PYEOF'
import sys
def enc(v):
    b = v.to_bytes(32, 'big'); out = 0
    for i in range(256):
        out |= ((b[i // 8] >> (7 - i % 8)) & 1) << i
    return out
seeds = [int('01' * 32, 16), int('02' * 32, 16), int('03' * 32, 16)]
with open(f'{sys.argv[1]}/Player-Data/Input-P0-0', 'w') as f:
    f.write('\n'.join(str(enc(s)) for s in seeds) + '\n')
PYEOF
  ./compile.py -B 256 shachain_step 1 3 0 1 >/dev/null
  got=$(Scripts/mal-rep-bin.sh shachain_step-1-3-0-1 2>&1         | sed -n 's/^Reg\[[0-9]*\] = 0x\([0-9a-f]*\).*/\1/p' | sort)
  want=$(python3 -c "
import sys; sys.path.insert(0, '$HERE/scripts'); import ref
for s in ('01'*32, '02'*32, '03'*32):
    print(ref.walk(bytes.fromhex(s), [47]).hex())" | sort)
  if [ "$got" = "$want" ]; then
    echo "PASS vectorised hashing correct in all 3 lanes"
  else
    echo "FAIL vectorised lanes"; echo "got: $got"; echo "want: $want"; fail=1
  fi
}
lane_check

# Key material comes from Iceberg rather than from a ceremony of our own,
# so what has to hold is that our reimplementation of its dealing and tagged
# hashing matches the C.
python3 "$HERE/scripts/iceberg.py"
exit $fail
