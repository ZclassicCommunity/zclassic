#!/usr/bin/env bash
# Install the mingw-w64 cross toolchain (POSIX threads) for Windows builds.
# Run with: sudo bash zcutil/setup-mingw-toolchain.sh
set -euo pipefail

echo "==> apt-get update"
apt-get update

echo "==> installing mingw-w64 (base pulls gcc/g++/binutils/headers + both thread models)"
apt-get install -y \
    g++-mingw-w64-x86-64 \
    gcc-mingw-w64-x86-64 \
    binutils-mingw-w64-x86-64 \
    mingw-w64-x86-64-dev \
    mingw-w64-tools

echo "==> selecting POSIX thread model (required for std::thread / std::mutex)"
# These succeed once the -posix alternatives exist (installed above).
update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix || true
update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix || true

echo "==> verification"
x86_64-w64-mingw32-g++ --version | head -1
x86_64-w64-mingw32-gcc --version | head -1
x86_64-w64-mingw32-strip --version | head -1
echo "thread model: $(x86_64-w64-mingw32-g++ -v 2>&1 | sed -n 's/^Thread model: //p')"
echo "==> OK"
