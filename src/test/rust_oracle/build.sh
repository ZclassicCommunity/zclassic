#!/bin/sh
# Build gen_golden against a Rust-backed depends prefix and regenerate the goldens.
#
#   DEPENDS=<prefix with lib/librustzcash.a> PARAMS=<zcash params dir> src/test/rust_oracle/build.sh [--quick]
#   src/test/rust_oracle/build.sh build-only
#   src/test/rust_oracle/build.sh replay [--prove] [--file <name>]   (replay OUT against librustzcash.a)
#
# Defaults: DEPENDS=<repo>/depends/x86_64-unknown-linux-gnu, PARAMS=$HOME/.zcash-params,
# OUT=<repo>/src/test/data/c23_golden. Needs g++ (C++17) on x86_64 Linux.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../.." && pwd)
DEPENDS=${DEPENDS:-$SRC/../depends/x86_64-unknown-linux-gnu}
PARAMS=${PARAMS:-$HOME/.zcash-params}
OUT=${OUT:-$SRC/test/data/c23_golden}
CXX=${CXX:-g++}
BUILD=${BUILD:-}

for f in librustzcash.a libsodium.a libgmpxx.a libgmp.a; do
    if [ ! -f "$DEPENDS/lib/$f" ]; then
        echo "build.sh: $DEPENDS/lib/$f not found; set DEPENDS to a built depends prefix" >&2
        exit 1
    fi
done
if [ ! -f "$DEPENDS/include/librustzcash.h" ]; then
    echo "build.sh: $DEPENDS/include/librustzcash.h not found" >&2
    exit 1
fi

if [ -z "$BUILD" ]; then
    BUILD=$(mktemp -d "${TMPDIR:-/tmp}/gen_golden.XXXXXX")
fi
mkdir -p "$BUILD"

"$CXX" -std=c++17 -O2 -g -Wall -Wextra -Werror \
    -I"$DEPENDS/include" \
    -o "$BUILD/gen_golden" "$HERE/gen_golden.cpp" \
    "$DEPENDS/lib/librustzcash.a" "$DEPENDS/lib/libsodium.a" \
    "$DEPENDS/lib/libgmpxx.a" "$DEPENDS/lib/libgmp.a" \
    -lpthread -ldl -lm
"${CC:-gcc}" -std=gnu11 -O2 -g -Wall -Wextra -Werror \
    -o "$BUILD/golden_replay" "$HERE/golden_replay.c" \
    "$DEPENDS/lib/librustzcash.a" -lpthread -ldl -lm
echo "build.sh: built $BUILD/gen_golden $BUILD/golden_replay"

if [ "${1:-}" = build-only ]; then
    exit 0
fi
if [ "${1:-}" = replay ]; then
    shift
    exec "$BUILD/golden_replay" --dir "$OUT" --params "$PARAMS" "$@"
fi

mkdir -p "$OUT"
"$BUILD/gen_golden" \
    --src "$SRC" \
    --params "$PARAMS" \
    --out "$OUT" \
    --sapling-txs "$HERE/inputs/mainnet_sapling_txs.txt" \
    --sprout-txs "$HERE/inputs/mainnet_sprout_txs.txt" \
    "$@"
