#!/bin/sh
# Copyright (c) 2026 The Zclassic developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Build the PHGR13 differential gate out of tree.
#   src/c23/test/phgr13-gate/build.sh <repo-root> <out-dir> [<reference-commit>]
#
# The reference is libsnark exactly as zclassicd used it: the whole src/ tree of
# <reference-commit> (default: the parent of the commit that removed libsnark, found
# with git) is extracted into <out-dir>/ref and libsnark is built there with the
# flags the old src/Makefile.am used. The candidate is THIS tree: the vendored bn254.c
# (included verbatim by phgr13_adapter.c), bn254_accel.c, the shim
# src/c23/compat/zcl_c23_phgr13.c and the daemon's current src/zcash/Proof.cpp
# (compiled under another namespace name so it can sit beside the reference's).
# Needs gmp, OpenMP, libsodium, libcrypto and boost headers (system, or a depends
# prefix through CPPFLAGS/LDFLAGS).
set -eu
repo=$(cd "${1:?repo root}" && pwd)
out=${2:?build dir}
mkdir -p "$out"
out=$(cd "$out" && pwd)
here=$repo/src/c23/test/phgr13-gate
S=$repo/src
SAP=$S/c23/vendor/core/modules/sapling
if [ $# -ge 3 ]; then
    ref=$3
else
    ref=$(git -C "$repo" log --format=%H -n1 --diff-filter=D -- src/snark/Makefile)^
fi
refc=$(git -C "$repo" rev-parse --verify "$ref^{commit}")
jobs=${JOBS:-8}
CC=${CC:-gcc}
CXX=${CXX:-g++}
CPPFLAGS=${CPPFLAGS:-}
LDFLAGS=${LDFLAGS:-}

# 1. the reference tree and libsnark
if [ ! -f "$out/ref/src/snark/libsnark.a" ]; then
    rm -rf "$out/ref"
    mkdir -p "$out/ref"
    git -C "$repo" archive "$refc" src | tar -x -C "$out/ref"
    snark_cxxflags="$CPPFLAGS -DMULTICORE -fopenmp -DBINARY_OUTPUT -DNO_PT_COMPRESSION=1 -fstack-protector-all -fPIC"
    CC="$CC" CXX="$CXX" CXXFLAGS="$snark_cxxflags" make -j"$jobs" -C "$out/ref/src/snark" \
        CURVE=ALT_BN128 NO_PROCPS=1 NO_DOCS=1 STATIC=1 NO_SUPERCOP=1 \
        NO_COPY_DEPINST=1 NO_COMPILE_LIBGTEST=1 MULTICORE=1 \
        OPTFLAGS="-O2" NO_GTEST=1 \
        FEATUREFLAGS="-DUSE_ASM -DMONTGOMERY_OUTPUT -DNO_PROCPS" lib
fi
ZS=$out/ref/src

# 2. the candidate, as zclassicd builds it (-std=c23). The platform layer's
# util/log_macros.h and util/safe_alloc.h are replaced by the two stubs below
# (LOG_FAIL keeps its `return false`), so the gate links without the daemon's glue.
mkdir -p "$out/stub/util"
cat > "$out/stub/util/log_macros.h" <<'EOT'
#ifndef GATE_LOG_MACROS_H
#define GATE_LOG_MACROS_H
#include <stdbool.h>
#define LOG_FAIL(domain, fmt, ...) do { (void)(domain); return false; } while (0)
#endif
EOT
cat > "$out/stub/util/safe_alloc.h" <<'EOT'
#ifndef GATE_SAFE_ALLOC_H
#define GATE_SAFE_ALLOC_H
#include <stdlib.h>
static inline void *zcl_calloc(size_t n, size_t s, const char *label) { (void)label; return calloc(n, s); }
#endif
EOT
CF="-std=c23 -O3 -fPIC -Wall -I$out/stub -I$SAP/include -I$SAP/src -I$S/c23/compat -I$here"
$CC $CF -c "$here/phgr13_adapter.c" -o "$out/adapter_c.o"
$CC $CF -c "$SAP/src/bn254_accel.c" -o "$out/bn254_accel.o"
$CC $CF -c "$S/c23/compat/zcl_c23_phgr13.c" -o "$out/zcl_c23_phgr13.o"
mkdir -p "$out/newproof" && cp "$S/zcash/Proof.hpp" "$S/zcash/Proof.cpp" "$out/newproof/"
ncf="-std=c++17 -O2 -Dlibzcash=libzcash_new -I$out/newproof -I$ZS -I$ZS/univalue/include -I$here -I$S/c23/compat"
$CXX $ncf -c "$out/newproof/Proof.cpp" -o "$out/new_Proof.o"
$CXX $ncf -c "$here/phgr13_adapter_cpp.cpp" -o "$out/adapter_cpp.o"

# 3. the harness against the reference's own Proof.cpp, gadget.tcc and libsnark
common="-std=c++17 -fopenmp $CPPFLAGS -DMULTICORE -DBINARY_OUTPUT -DNO_PT_COMPRESSION=1 \
 -DCURVE_ALT_BN128 -DMONTGOMERY_OUTPUT -DNO_PROCPS -DSTATIC \
 -I$ZS -I$ZS/snark -I$ZS/snark/libsnark -I$ZS/univalue/include -I$here -I$SAP/include -I$S/c23/compat"
shared=""
for f in zcash/util.cpp uint256.cpp utilstrencodings.cpp support/cleanse.cpp; do
    o="$out/$(echo "$f" | tr '/' '_' | sed 's/\.cpp$/.o/')"
    $CXX $common -O2 -c "$ZS/$f" -o "$o"
    shared="$shared $o"
done
$CXX $common -O2 -c "$ZS/zcash/Proof.cpp" -o "$out/ref_Proof.o"
$CXX $common -O2 -c "$here/phgr13_diff.cpp" -o "$out/phgr13_diff.o"
# shellcheck disable=SC2086
$CXX -fopenmp -o "$out/phgr13_gate" "$out/ref_Proof.o" "$out/phgr13_diff.o" $shared \
    "$out/adapter_c.o" "$out/adapter_cpp.o" "$out/new_Proof.o" "$out/bn254_accel.o" "$out/zcl_c23_phgr13.o" \
    "$ZS/snark/libsnark.a" $LDFLAGS -lgmpxx -lgmp -lsodium -lcrypto -lpthread
echo "built $out/phgr13_gate (reference $refc)"
