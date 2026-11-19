#!/bin/sh
# Builds gtest/test_sha256_differential.cpp stand-alone with ASan+UBSan (the C
# backend, the glue and CSHA256 itself are all instrumented) and runs it. The
# whole daemon is not sanitised; the full-suite run of the same test is in
# zcash-gtest.
#
# usage: sha256-diff-sanitize.sh <depends-prefix> <config-dir> <outdir> [cc] [cxx]
#   depends-prefix  e.g. depends/x86_64-unknown-linux-gnu (include/gtest, include/sodium.h, lib/libgtest.a)
#   config-dir      directory holding the configured bitcoin-config.h (src/config)
set -eu
D=$1; CFG=$2; OUT=$3; CC=${4:-gcc}; CXX=${5:-g++}
SRC=$(cd "$(dirname "$0")/../.." && pwd)        # .../src
V=$SRC/c23/vendor
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g"
mkdir -p "$OUT"
# zcl_c23_sha256.c #includes the vendored sha256.c.
for f in c23/glue/zcl_c23_sha256.c c23/glue/zcl_c23_hash_log.c; do
    $CC -O2 -std=gnu17 -Wall -Wextra -include "$SRC/c23/glue/zcl_c23_compat.h" -fno-strict-aliasing $SAN \
        -I"$SRC/c23/glue" -I"$V/core/modules/crypto/include" \
        -I"$V/platform/modules/util/include" -I"$V/platform/modules/base/include" \
        -c "$SRC/$f" -o "$OUT/$(basename "$f" .c).san.o"
done
$CXX -O1 -std=gnu++17 $SAN -DZCL_SHA256_DIFF_STANDALONE -DHAVE_CONFIG_H -I"$SRC" -I"$CFG" -I"$CFG/.." -I"$D/include" \
    "$SRC/gtest/test_sha256_differential.cpp" "$SRC/crypto/sha256.cpp" "$SRC/crypto/ripemd160.cpp" \
    "$OUT"/zcl_c23_sha256.san.o "$OUT"/zcl_c23_hash_log.san.o \
    "$D/lib/libgtest.a" -lpthread -o "$OUT/sha256_diff_san"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
    "$OUT/sha256_diff_san"
