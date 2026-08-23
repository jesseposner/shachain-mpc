#!/bin/sh
# Node bootstrap for the WAN run. Runs on a fresh Ubuntu 24.04 arm64 node.
# Clones the repo, builds MP-SPDZ with our patches, builds the LDK
# counterparty, and starts this member's agent.
#
# Usage: bootstrap.sh <member-index>
set -eu
IDX=${1:?usage: bootstrap.sh <member-index>}
REPO=${REPO:-$HOME/shachain-mpc}
MPSPDZ=${MPSPDZ:-$HOME/MP-SPDZ}
PORT=${PORT:-9001}

echo "=== bootstrap member $IDX on $(hostname) ==="

if [ ! -d "$REPO" ]; then
  git clone -q https://github.com/jesseposner/shachain-mpc.git "$REPO"
else
  git -C "$REPO" pull -q --ff-only
fi

# MP-SPDZ: clone, patch, build (the long pole, ~15 min on 8 vCPU)
MPSPDZ="$MPSPDZ" sh "$REPO/scripts/setup.sh"

# Rust toolchain and the LDK counterparty (node 0 runs it; cheap everywhere)
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
fi
. "$HOME/.cargo/env"
cargo build -q --release --manifest-path "$REPO/ldk-check/Cargo.toml"

# Start (or restart) this member's agent
pkill -f "member.py --port $PORT" 2>/dev/null || true
mkdir -p "$HOME/member-state" "$HOME/logs"
nohup python3 "$REPO/poc/member.py" --port "$PORT" \
  --workdir "$HOME/member-state" --mpspdz "$MPSPDZ" \
  > "$HOME/logs/member.log" 2>&1 &

sleep 2
curl -sf "http://127.0.0.1:$PORT/health" >/dev/null \
  && echo "=== member $IDX ready on :$PORT ===" \
  || { echo "member agent failed to start"; tail -20 "$HOME/logs/member.log"; exit 1; }
