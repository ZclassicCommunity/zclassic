#!/bin/sh
# Copyright 2026 The Zclassic developers - MIT License
#
# Standalone build of the C23 Sprout prover tests (no daemon, no Rust).
#
#   sh src/c23/sprout_prover/test/build.sh <out-dir>
#
# Environment: CC (default cc), OPT (default "-O3"), ARCH (default empty,
# i.e. the compiler's generic target; e.g. ARCH=-march=native). Produces
#   <out-dir>/test_sprout_circuit   circuit KAT (no params needed)
#   <out-dir>/test_sprout_prover    prove + verify; needs sprout-groth16.params
set -eu

OUT=${1:?usage: build.sh <out-dir>}
HERE=$(cd "$(dirname "$0")" && pwd)
SP=$(cd "$HERE/.." && pwd)
C23=$(cd "$SP/.." && pwd)
V="$C23/vendor"
CC=${CC:-cc}
AR=${AR:-ar}
OPT=${OPT:--O3}
ARCH=${ARCH:-}
mkdir -p "$OUT/obj"

INC=""
for d in $(find "$V" -type d -name include | sort); do
    INC="$INC -I$d"
done
CFLAGS="-std=gnu2x $OPT $ARCH -Wall -Wextra -pthread"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) SYSLIBS="-lbcrypt -lpsapi"; EXE=.exe ;;
    *) SYSLIBS=""; EXE="" ;;
esac

# The vendored Z23 closure the prover needs (sapling + crypto + base).
# params_init.c needs chain glue and is not used by the prover.
VSRC=""
for f in "$V"/core/modules/sapling/src/*.c "$V"/core/modules/crypto/src/*.c \
         "$V"/platform/modules/base/src/*.c; do
    case "$f" in */params_init.c) continue ;; esac
    VSRC="$VSRC $f"
done
VOBJ=""
for f in $VSRC; do
    o="$OUT/obj/v_$(basename "$f" .c).o"
    # vendored code: build quietly, exactly as shipped
    $CC -std=gnu2x $OPT $ARCH -pthread $INC -c "$f" -o "$o"
    VOBJ="$VOBJ $o"
done

rm -f "$OUT/libz23vendor.a"
# an archive, so only the objects the prover references are linked
$AR rcs "$OUT/libz23vendor.a" $VOBJ

OBJ=""
for f in sprout_circuit sprout_par sprout_prove; do
    $CC $CFLAGS -Wshadow $INC -c "$SP/$f.c" -o "$OUT/obj/$f.o"
    OBJ="$OBJ $OUT/obj/$f.o"
done
$CC $CFLAGS $INC -c "$HERE/test_glue.c" -o "$OUT/obj/test_glue.o"

for t in test_sprout_circuit test_sprout_prover; do
    $CC $CFLAGS $INC -c "$HERE/$t.c" -o "$OUT/obj/$t.o"
    $CC $CFLAGS -o "$OUT/$t$EXE" "$OUT/obj/$t.o" $OBJ "$OUT/obj/test_glue.o" \
        "$OUT/libz23vendor.a" $SYSLIBS -lm
done

# Cross-check against Z23's groth16_prove: both RNG seams are compiled in only
# for this program (-DSPROUT_PROVER_TESTING, -DZCL_TESTING).
$CC -std=gnu2x $OPT $ARCH -pthread -DZCL_TESTING $INC \
    -c "$V/core/modules/sapling/src/groth16_prover.c" -o "$OUT/obj/v_groth16_prover_testing.o"
$CC $CFLAGS -DSPROUT_PROVER_TESTING $INC -c "$SP/sprout_prove.c" \
    -o "$OUT/obj/sprout_prove_testing.o"
$CC $CFLAGS -DSPROUT_PROVER_TESTING -DZCL_TESTING $INC \
    -c "$HERE/test_sprout_crosscheck.c" -o "$OUT/obj/test_sprout_crosscheck.o"
$CC $CFLAGS -o "$OUT/test_sprout_crosscheck$EXE" "$OUT/obj/test_sprout_crosscheck.o" \
    "$OUT/obj/sprout_prove_testing.o" "$OUT/obj/sprout_circuit.o" \
    "$OUT/obj/sprout_par.o" "$OUT/obj/test_glue.o" \
    "$OUT/obj/v_groth16_prover_testing.o" "$OUT/libz23vendor.a" $SYSLIBS -lm

echo "built: $OUT/test_sprout_circuit$EXE $OUT/test_sprout_prover$EXE $OUT/test_sprout_crosscheck$EXE"
