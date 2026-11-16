#!/bin/sh
# TEST-ONLY standalone build of the librustzcash C ABI shim (c23/compat) with
# the vendored Z23 core and the TEST glue, plus the smoke program and the C++
# header check. No daemon, no libsodium, no OpenSSL, no Rust.
#
# usage: build-smoke.sh <cc> <std-flag> <outdir> [cxx]
#   e.g. build-smoke.sh gcc -std=gnu17 /tmp/o g++
#        build-smoke.sh clang -std=c23 /tmp/o clang++
# Produces <outdir>/compat_smoke(.exe) and, when <cxx> is given,
# <outdir>/abi_cxx_check(.exe). The compat sources are compiled twice:
#   production flags  (-Werror, as the daemon library will build them)
#   test flags        (-DZCL_C23_COMPAT_TESTING, linked into the smoke)
# Vendored .c files are compiled without -Werror (they are not ours; U1/U2
# proved them warning-free). No -march flags.
set -u
[ $# -ge 3 ] || { echo "usage: $0 <cc> <std-flag> <outdir> [cxx]" >&2; exit 2; }
cc=$1; std=$2; out=$3; cxx=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
compat=$(dirname "$here")
c23=$(dirname "$compat")
v=$c23/vendor
g=$c23/glue
root=$(cd "$c23/../.." && pwd)
mkdir -p "$out" || exit 2

inc="-I$compat -I$g -I$g/chain"
for d in "$v"/core/math/include "$v"/core/modules/*/include "$v"/platform/modules/*/include \
         "$v"/core/modules/sapling/src; do
    inc="$inc -I$d"
done
posix=""
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) libs="-lbcrypt -lshell32"; exe=".exe" ;;
    *) libs=""; exe=""; posix="-D_POSIX_C_SOURCE=200809L" ;;
esac
base="$std -O3 -Wall -Wextra -include $g/zcl_c23_compat.h -fomit-frame-pointer -fno-strict-aliasing $posix $inc"
fail=0
objs=""

compile() { # <src> <obj> <extra flags...>
    src=$1; obj=$2; shift 2
    # shellcheck disable=SC2086
    if ! $cc $base "$@" -c "$src" -o "$obj" 2>"$obj.err"; then
        echo "COMPILE FAIL $src"; sed 's/^/  /' "$obj.err" | head -40; fail=1
    elif [ -s "$obj.err" ]; then
        echo "DIAGNOSTICS $src"; sed 's/^/  /' "$obj.err" | head -40; fail=1
    fi
}

n=0
for rel in $(awk -F"	" 'index($1,"src/c23/vendor/")==1 && substr($1,length($1)-1)==".c" {print $1}' "$c23/Z23_SOURCE.tsv"); do
    b=$(echo "$rel" | sed 's#.*/##; s#\.c$##')
    compile "$root/$rel" "$out/v_$b.o"
    objs="$objs $out/v_$b.o"
    n=$((n + 1))
done
for gf in zcl_c23_stubs zcl_c23_tree_selftest zcl_c23_test_glue; do
    compile "$g/$gf.c" "$out/g_$gf.o"
    objs="$objs $out/g_$gf.o"
done
# Production compile of the shim: must be clean under -Werror.
for cf in librustzcash_compat witness_codec zip32_codec; do
    compile "$compat/$cf.c" "$out/p_$cf.o" -Werror
done
# Test compile (test hook enabled) for the smoke link.
tobjs=""
for cf in librustzcash_compat witness_codec zip32_codec; do
    compile "$compat/$cf.c" "$out/t_$cf.o" -Werror -DZCL_C23_COMPAT_TESTING
    tobjs="$tobjs $out/t_$cf.o"
done
compile "$here/sprout_prove_stub_test.c" "$out/s_stub.o" -Werror
compile "$here/compat_smoke.c" "$out/compat_smoke.o" -Werror -DZCL_C23_COMPAT_TESTING
[ "$fail" -eq 0 ] || { echo "build-smoke FAILED (compile) $cc $std"; exit 1; }

# shellcheck disable=SC2086
if ! $cc $objs $tobjs "$out/s_stub.o" "$out/compat_smoke.o" -pthread $libs \
        -o "$out/compat_smoke$exe" 2>"$out/link.err"; then
    echo "LINK FAIL"; head -40 "$out/link.err"; exit 1
fi
echo "linked $out/compat_smoke$exe ($n vendored .c + glue + compat)"

# Undefined symbols left for the platform (libc/pthread/bcrypt) by the
# production shim + vendor + test glue set.
pobjs="$out/p_librustzcash_compat.o $out/p_witness_codec.o $out/p_zip32_codec.o"
# shellcheck disable=SC2086
nm -g --defined-only $objs $pobjs "$out/s_stub.o" 2>/dev/null | awk 'NF==3{print $3}' | sort -u >"$out/defined.txt"
# shellcheck disable=SC2086
nm -u $objs $pobjs "$out/s_stub.o" 2>/dev/null | awk 'NF>=2{print $NF}' | sed 's/@.*//' | sort -u | comm -23 - "$out/defined.txt" >"$out/undef_residual.txt"
echo "residual undefined: $(tr '\n' ' ' <"$out/undef_residual.txt")"
# The 31 ABI names must be defined by the production shim objects.
# shellcheck disable=SC2086
nm -g --defined-only $pobjs "$out/s_stub.o" 2>/dev/null | awk 'NF==3{print $3}' | sed 's/^_//' | grep '^librustzcash_' | sort -u >"$out/abi_defined.txt"
echo "librustzcash_* defined: $(wc -l <"$out/abi_defined.txt" | tr -d ' ')"

if [ -n "$cxx" ]; then
    # shellcheck disable=SC2086
    if ! $cxx -std=gnu++17 -O2 -Wall -Wextra -Werror -I"$compat" -c "$here/abi_cxx_check.cpp" \
            -o "$out/abi_cxx_check.o" 2>"$out/cxx.err"; then
        echo "C++ COMPILE FAIL"; head -40 "$out/cxx.err"; exit 1
    fi
    # shellcheck disable=SC2086
    if ! $cxx "$out/abi_cxx_check.o" $objs $pobjs "$out/s_stub.o" -pthread $libs \
            -o "$out/abi_cxx_check$exe" 2>"$out/cxxlink.err"; then
        echo "C++ LINK FAIL"; head -40 "$out/cxxlink.err"; exit 1
    fi
    echo "linked $out/abi_cxx_check$exe"
fi
echo "build-smoke OK ($cc $std)"
