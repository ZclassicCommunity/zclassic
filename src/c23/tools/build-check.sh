#!/bin/sh
# Standalone compile + link proof for the vendored Z23 set and the glue.
# usage: build-check.sh <cc> <std> <outdir> [extra cflags...]
#   e.g. build-check.sh gcc -std=c23 /tmp/o     (std is passed verbatim)
# Every vendored .c is compiled -O3 -Wall -Wextra with the compat force-include
# and must emit ZERO diagnostics. Then vendor + glue (stubs, tree self-test,
# TEST glue) + a stub main are linked and the undefined symbols are listed.
# Test-only: production glue (libsodium/OpenSSL/C++ seams) is built by the
# daemon build, not here. No -march flags: one portable binary.
set -u
[ $# -ge 3 ] || { echo "usage: $0 <cc> <std-flag> <outdir> [cflags...]" >&2; exit 2; }
cc=$1; std=$2; out=$3; shift 3
here=$(cd "$(dirname "$0")" && pwd)
c23=$(dirname "$here")
v=$c23/vendor
g=$c23/glue
root=$(cd "$c23/../.." && pwd)
mkdir -p "$out" || exit 2

inc="-I$g -I$g/chain"
for d in "$v"/core/math/include "$v"/core/modules/*/include "$v"/platform/modules/*/include \
         "$v"/core/modules/sapling/src; do
    inc="$inc -I$d"
done
cflags="$std -O3 -Wall -Wextra -include $g/zcl_c23_compat.h -fomit-frame-pointer -fno-strict-aliasing -D_POSIX_C_SOURCE=200809L $inc $*"

vsrc=$(awk -F"	" 'index($1,"src/c23/vendor/")==1 && substr($1,length($1)-1)==".c" {print $1}' "$c23/Z23_SOURCE.tsv")
fail=0
objs=""
n=0
for rel in $vsrc; do
    f=$root/$rel
    base=$(echo "$rel" | sed 's#.*/##; s#\.c$##')
    o=$out/$base.o
    # shellcheck disable=SC2086
    if ! $cc $cflags -c "$f" -o "$o" 2>"$out/$base.err"; then
        echo "COMPILE FAIL $rel"; sed 's/^/  /' "$out/$base.err" | head -20; fail=1
    elif [ -s "$out/$base.err" ]; then
        echo "WARNINGS $rel"; sed 's/^/  /' "$out/$base.err" | head -20; fail=1
    fi
    objs="$objs $o"
    n=$((n + 1))
done
for gf in zcl_c23_stubs zcl_c23_tree_selftest zcl_c23_test_glue; do
    # shellcheck disable=SC2086
    if ! $cc $cflags -c "$g/$gf.c" -o "$out/$gf.o" 2>"$out/$gf.err" || [ -s "$out/$gf.err" ]; then
        echo "GLUE FAIL/WARN $gf"; sed 's/^/  /' "$out/$gf.err" | head -20; fail=1
    fi
    objs="$objs $out/$gf.o"
done
printf 'int main(void){return 0;}\n' >"$out/stubmain.c"
$cc -O3 -c "$out/stubmain.c" -o "$out/stubmain.o" || fail=1
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) libs="-lbcrypt" ;;
    *) libs="" ;;
esac
# shellcheck disable=SC2086
if ! $cc $objs "$out/stubmain.o" -pthread $libs -o "$out/stub.exe" 2>"$out/link.err"; then
    echo "LINK FAIL"; head -30 "$out/link.err"; fail=1
else
    echo "linked $out/stub.exe ($n vendored .c)"
fi
# Undefined symbols of the combined object set (what the final link must still supply).
# Residual undefined symbols = undefined in the object set, defined nowhere in it.
# This is what libc, pthread and (Windows) bcrypt must supply; anything else is a gap.
# shellcheck disable=SC2086
nm -g --defined-only $objs 2>/dev/null | awk 'NF==3{print $3}' | sort -u >"$out/defined.txt"
# shellcheck disable=SC2086
nm -u $objs 2>/dev/null | awk 'NF>=2{print $NF}' | sed 's/@.*//' | sort -u | comm -23 - "$out/defined.txt" >"$out/undef_residual.txt"
echo "residual undefined: $(tr '
' ' ' <"$out/undef_residual.txt")"
[ "$fail" -eq 0 ] && echo "build-check OK ($cc $std)" || echo "build-check FAILED ($cc $std)"
exit "$fail"
