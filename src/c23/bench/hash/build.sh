#!/bin/sh
# Usage: build.sh <zc-baseline-root> <z23-checkout> <outdir>
# DEPENDS=<prefix> overrides the depends prefix (a candidate worktree can reuse the baseline's).
# Builds the two hash micro-bench drivers. No change to any production tree.
set -eu
ZC=$1; Z23=$2; OUT=$3; HERE=$(cd "$(dirname "$0")" && pwd)
D=${DEPENDS:-$ZC/depends/x86_64-unknown-linux-gnu}
mkdir -p "$OUT"
# The zclassicd side links the tree's own crypto objects + depends libsodium (static).
# A tree with the Z23 SHA-256 backend also has src/libzcl_c23_hash.a; link it when present,
# so the same driver measures before (baseline tree) and after (candidate tree).
HASHLIB=; [ -f "$ZC/src/libzcl_c23_hash.a" ] && HASHLIB=$ZC/src/libzcl_c23_hash.a
g++ -std=gnu++17 -O2 -fwrapv -fno-strict-aliasing -I"$HERE" -I"$ZC/src" -I"$ZC/src/config" -I"$D/include" \
    -DHAVE_CONFIG_H "$HERE/hash_bench_base.cpp" \
    "$ZC/src/crypto/libbitcoin_crypto.a" $HASHLIB "$D/lib/libsodium.a" -o "$OUT/hash_bench_base" -lpthread
# Z23: standalone C23 at -O3, runtime-dispatched (no -march=native).
C=$Z23/core/modules/crypto
gcc -std=c2x -O3 -I"$HERE" -I"$C/include" -I"$Z23/platform/modules/util/include" -I"$Z23/platform/modules/base/include" \
    "$HERE/hash_bench_z23.c" "$C/src/sha256.c" "$C/src/ripemd160.c" "$C/src/blake2b.c" \
    "$C/src/blake2b_avx2.c" "$C/src/simd_dispatch.c" -o "$OUT/hash_bench_z23" -lpthread
