#!/bin/sh
# Differential proof for glue/zcl_c23_tree_selftest.c.
# usage: tree-shim-diff.sh <cc> <z23-repo> <z23-commit> <outdir>
# Builds tools/tree_shim_check.c twice: against the shim, and against Z23's real
# incremental_merkle_tree.c (extracted from git, never vendored; unrelated
# file-checkpoint dependencies are satisfied by dummy symbols, never called).
# Also checks the zclassicd merkle vectors (see tree_shim_check.c) and that the
# outputs of both builds are byte-identical.
set -eu
[ $# -eq 4 ] || { echo "usage: $0 <cc> <z23-repo> <commit> <outdir>" >&2; exit 2; }
cc=$1; repo=$2; commit=$3; out=$4
here=$(cd "$(dirname "$0")" && pwd)
c23=$(dirname "$here")
root=$(cd "$c23/../.." && pwd)
g=$c23/glue
v=$c23/vendor
mkdir -p "$out"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) libs="-lbcrypt" ;; *) libs="" ;; esac
inc="-I$g -I$g/chain"
for d in "$v"/core/math/include "$v"/core/modules/*/include "$v"/platform/modules/*/include \
         "$v"/core/modules/sapling/src; do inc="$inc -I$d"; done
cf="-std=gnu17 -O2 -Wall -Wextra -include $g/zcl_c23_compat.h -D_POSIX_C_SOURCE=200809L"
objs=""
for f in $(awk -F'\t' 'index($1,"src/c23/vendor/")==1 && substr($1,length($1)-1)==".c" {print $1}' "$c23/Z23_SOURCE.tsv"); do
    b=$(basename "$f" .c)
    $cc $cf $inc -c "$root/$f" -o "$out/$b.o"
    objs="$objs $out/$b.o"
done
for f in zcl_c23_stubs zcl_c23_test_glue; do
    $cc $cf $inc -c "$g/$f.c" -o "$out/$f.o"; objs="$objs $out/$f.o"
done
$cc $cf $inc -c "$here/tree_shim_check.c" -o "$out/chk_shim.o"
$cc $cf $inc -DREAL_TREE -c "$here/tree_shim_check.c" -o "$out/chk_real.o"
$cc $cf $inc -c "$g/zcl_c23_tree_selftest.c" -o "$out/shim.o"
# real tree + serialize from Z23 (extracted copy)
z=$out/z23src
rm -rf "$z"; mkdir -p "$z"
git -C "$repo" archive "$commit" core platform | tar -x -C "$z"
zinc="-I$g -I$g/chain"
for d in "$z"/core/math/include "$z"/core/modules/*/include "$z"/platform/modules/*/include; do zinc="$zinc -I$d"; done
$cc $cf $zinc -c "$z/core/modules/sapling/src/incremental_merkle_tree.c" -o "$out/real_tree.o"
$cc $cf $zinc -c "$z/core/math/src/serialize.c" -o "$out/real_ser.o"
{
    for s in platform_positioned_file_close platform_positioned_file_init platform_positioned_file_open \
             platform_positioned_file_read platform_positioned_file_size platform_private_destination_resolve \
             platform_private_file_close platform_private_file_create platform_private_file_flush \
             platform_private_file_init platform_private_file_replace platform_private_file_retire \
             platform_private_file_write_at platform_private_parent_flush zcl_sha3_256; do
        echo "int $s(void){return -1;}"
    done
} >"$out/dummies.c"
$cc -c "$out/dummies.c" -o "$out/dummies.o"
# shellcheck disable=SC2086
$cc "$out/chk_shim.o" "$out/shim.o" $objs -pthread $libs -o "$out/chk_shim"
# shellcheck disable=SC2086
$cc "$out/chk_real.o" "$out/real_tree.o" "$out/real_ser.o" "$out/dummies.o" $objs -pthread $libs -o "$out/chk_real"
d=$root/src/test/data
"$out/chk_shim" "$d/merkle_commitments_sapling.json" "$d/merkle_roots_sapling.json" \
    "$d/merkle_roots_empty_sapling.json" | tr -d '\r' >"$out/shim.txt"
"$out/chk_real" | tr -d '\r' >"$out/real.txt"
grep '^vectors\|^poison' "$out/shim.txt"
grep '^leaf' "$out/shim.txt" >"$out/shim.leaf"
if cmp -s "$out/shim.leaf" "$out/real.txt"; then
    echo "tree shim: IDENTICAL to Z23 incremental_merkle_tree.c on $(wc -l <"$out/real.txt" | tr -d ' ') leaves (root + 1057-byte path)"
else
    echo "tree shim: DIFFERS from Z23" >&2; exit 1
fi
grep -q 'match zclassicd' "$out/shim.txt" || { echo "vector check FAILED" >&2; exit 1; }
