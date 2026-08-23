#!/bin/sh
# Benchmark one shachain edge (+ validity check + B2A) under each protocol.
# Writes a table to results/<hostname>-<date>.md and prints it.
set -u
MPSPDZ=${MPSPDZ:-$HOME/src/MP-SPDZ}
HERE=$(cd "$(dirname "$0")/.." && pwd)
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
OUT="$HERE/results/$(hostname -s)-$(date +%Y%m%d).md"
ln -sf "$HERE/programs/shachain_step.mpc" "$MPSPDZ/Programs/Source/"
cd "$MPSPDZ"
python3 "$HERE/scripts/input.py" . 0101010101010101010101010101010101010101010101010101010101010101 1100

row() { # label proto prog [args]
  label=$1; proto=$2; prog=$3; shift 3
  out=$(Scripts/$proto.sh "$prog" "$@" 2>&1)
  total=$(echo "$out" | sed -n 's/^Time = \([0-9.]*\).*/\1/p' | head -1)
  t1=$(echo "$out" | sed -n 's/^Time1 = \([0-9.]*\).*/\1/p' | head -1)
  t2=$(echo "$out" | sed -n 's/^Time2 = \([0-9.]*\).*/\1/p' | head -1)
  t3=$(echo "$out" | sed -n 's/^Time3 = \([0-9.]*\).*/\1/p' | head -1)
  sent=$(echo "$out" | sed -n 's/^Data sent = \([0-9.]*\) MB in ~\([0-9]*\) rounds.*/\1 MB, \2 rounds/p' | head -1)
  printf '| %s | %s | %s | %s | %s | %s |\n' "$label" "${total:-?}" "${t1:-–}" "${t2:-–}" "${t3:-–}" "${sent:-?}"
}

{
  echo "# shachain_step benchmark"
  echo
  echo "Host: $(hostname -s), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), $(date +%Y-%m-%d). 3 parties on loopback. MP-SPDZ $(git rev-parse --short HEAD)."
  echo
  echo "Times in seconds (wall, including preprocessing). T_sha = K edges of SHA-256, T_chk = scalar validity check, T_b2a = Boolean-to-Z_q conversion. Traffic is party 0 only."
  echo
  echo "| run | total | T_sha | T_chk | T_b2a | party-0 traffic |"
  echo "|---|---:|---:|---:|---:|---|"
  for K in 1 10; do
    ./compile.py -B 256 shachain_step $K 1 0 0 >/dev/null 2>&1
    row "seq K=$K, Rep3 bin, semi-honest" replicated shachain_step-$K-1-0-0
    row "seq K=$K, Rep3 bin, malicious" mal-rep-bin shachain_step-$K-1-0-0
    ./compile.py -P $Q -X shachain_step $K 1 1 0 >/dev/null 2>&1
    row "seq K=$K, Rep3 +B2A, semi-honest" rep-field shachain_step-$K-1-1-0 -P $Q
    row "seq K=$K, Rep3 +B2A, malicious" mal-rep-field shachain_step-$K-1-1-0 -P $Q
  done
  bmr_row() { # label proto prog
    label=$1; proto=$2; prog=$3
    out=$(Scripts/$proto.sh "$prog" -O 2>&1)
    total=$(echo "$out" | sed -n 's/^Time = \([0-9.]*\).*/\1/p' | head -1)
    online=$(echo "$out" | sed -n 's/^BMR online phase: \([0-9.e-]*\) seconds, \([0-9.e-]*\) MB.*/\1 s, \2 MB/p' | head -1)
    sent=$(echo "$out" | sed -n 's/^Data sent = \([0-9.]*\) MB in ~\([0-9]*\) rounds.*/\1 MB, \2 rounds/p' | head -1)
    printf '| %s | %s | online: %s | garble incl: %s | – | %s |\n' "$label" "${total:-?}" "${online:-?}" "${total:-?}" "${sent:-?}"
  }
  for K in 1 48; do
    ./compile.py -B 256 shachain_step $K 1 0 0 >/dev/null 2>&1
    bmr_row "seq K=$K, BMR one-shot, semi-honest" rep-bmr shachain_step-$K-1-0-0
    bmr_row "seq K=$K, BMR one-shot, malicious" mal-rep-bmr shachain_step-$K-1-0-0
  done
  ./compile.py -B 256 shachain_step 48 1 0 0 >/dev/null 2>&1
  row "seq K=48 cold start, Rep3 bin, malicious" mal-rep-bin shachain_step-48-1-0-0
  for N in 100 1000; do
    ./compile.py -B 256 shachain_step 1 $N 0 0 >/dev/null 2>&1
    row "par N=$N, Rep3 bin, semi-honest" replicated shachain_step-1-$N-0-0
    row "par N=$N, Rep3 bin, malicious" mal-rep-bin shachain_step-1-$N-0-0
    ./compile.py -P $Q -X shachain_step 1 $N 1 0 >/dev/null 2>&1
    row "par N=$N, Rep3 +B2A, semi-honest" rep-field shachain_step-1-$N-1-0 -P $Q
    row "par N=$N, Rep3 +B2A, malicious" mal-rep-field shachain_step-1-$N-1-0 -P $Q
  done
} | tee "$OUT"
echo "written $OUT"
