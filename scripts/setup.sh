#!/bin/sh
# Fetch, patch and build MP-SPDZ with the party binaries used here.
# Tested on macOS (Apple Silicon, Xcode clang 21) with Homebrew.
set -eu
MPSPDZ=${MPSPDZ:-$HOME/src/MP-SPDZ}
HERE=$(cd "$(dirname "$0")/.." && pwd)
MPSPDZ_COMMIT=892ac0e2a2a9edabbe0249febc0b316ca649b479

if [ "$(uname)" = Darwin ]; then
  brew list --formula | grep -qx gmp || brew install gmp
  brew list --formula | grep -qx libsodium || brew install libsodium
  brew list --formula | grep -qx boost || brew install boost
  brew list --formula | grep -qx 'openssl@3' || brew install openssl@3
elif command -v apt-get >/dev/null; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential git python3 libgmp-dev libsodium-dev libssl-dev \
    libboost-dev libboost-thread-dev libboost-filesystem-dev \
    libboost-iostreams-dev
fi

if [ ! -d "$MPSPDZ" ]; then
  git clone https://github.com/data61/MP-SPDZ.git "$MPSPDZ"
fi
cd "$MPSPDZ"
git checkout -q "$MPSPDZ_COMMIT"
git submodule update --init --depth 1 Programs/Circuits
for patch in mp-spdz-clang21 mp-spdz-bmr-phase-timing; do
  if git apply --check "$HERE/patches/$patch.patch" 2>/dev/null; then
    git apply "$HERE/patches/$patch.patch"
  else
    echo "$patch already applied or does not apply cleanly; continuing"
  fi
done
# ARM (Apple Silicon or Graviton) wants the crypto extensions; on x86 leave
# the default -march=native. The deprecation flag is clang-only.
: > CONFIG.mine
case "$(uname -m)" in
  arm64|aarch64) echo 'ARCH = -march=armv8.2-a+crypto' >> CONFIG.mine ;;
esac
if [ "$(uname)" = Darwin ]; then
  echo 'CXX = /usr/bin/g++' >> CONFIG.mine
  echo 'MY_CFLAGS = -Wno-deprecated-literal-operator' >> CONFIG.mine
fi

make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" \
  replicated-bin-party.x malicious-rep-bin-party.x \
  replicated-field-party.x malicious-rep-field-party.x \
  rep-bmr-party.x mal-rep-bmr-party.x
Scripts/setup-ssl.sh 3
ln -sf "$HERE/programs/shachain_step.mpc" Programs/Source/
echo "MP-SPDZ ready at $MPSPDZ"
