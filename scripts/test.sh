#!/bin/sh
# Correctness test: compare MPC output against the plaintext BOLT reference
# under every protocol, including the scalar-validity flag.
set -u
MPSPDZ=${MPSPDZ:-$HOME/src/MP-SPDZ}
HERE=$(cd "$(dirname "$0")/.." && pwd)
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
ln -sf "$HERE/programs/shachain_step.mpc" "$MPSPDZ/Programs/Source/"
cd "$MPSPDZ"
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
exit $fail
