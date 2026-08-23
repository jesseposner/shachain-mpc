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
fi

if [ ! -d "$MPSPDZ" ]; then
  git clone https://github.com/data61/MP-SPDZ.git "$MPSPDZ"
fi
cd "$MPSPDZ"
git checkout -q "$MPSPDZ_COMMIT"
git submodule update --init --depth 1 Programs/Circuits
if ! git apply --check "$HERE/patches/mp-spdz-clang21.patch" 2>/dev/null; then
  echo "patch already applied or does not apply cleanly; continuing"
else
  git apply "$HERE/patches/mp-spdz-clang21.patch"
fi
cat > CONFIG.mine <<CFG
CXX = /usr/bin/g++
ARCH = -march=armv8.2-a+crypto
MY_CFLAGS = -Wno-deprecated-literal-operator
CFG
[ "$(uname -m)" = arm64 ] || sed -i.bak '/^ARCH/d' CONFIG.mine

make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" \
  replicated-bin-party.x malicious-rep-bin-party.x \
  replicated-field-party.x malicious-rep-field-party.x \
  rep-bmr-party.x mal-rep-bmr-party.x
Scripts/setup-ssl.sh 3
ln -sf "$HERE/programs/shachain_step.mpc" Programs/Source/
echo "MP-SPDZ ready at $MPSPDZ"
