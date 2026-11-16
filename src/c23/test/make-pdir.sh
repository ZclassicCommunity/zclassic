#!/bin/sh
# TEST-ONLY (unit U4). Builds the parameter directory used by the init:
# mutation cases: the three real files (symlinked on POSIX, copied on
# Windows), a copy under another name, same-size copies with one flipped
# byte, a truncated and an extended copy, and a subdirectory.
# The source parameter directory is only read.
#
# usage: make-pdir.sh <params-dir> <out-dir>
set -eu
src=$1
dst=$2
[ -f "$src/sapling-output.params" ] || { echo "make-pdir: $src has no sapling-output.params" >&2; exit 2; }
if [ -f "$dst/.complete" ]; then
    exit 0
fi
mkdir -p "$dst/subdir"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) link() { cp "$1" "$2"; }
        hl() { cmd //c "mklink /H $(cygpath -w "$2") $(cygpath -w "$1")" >/dev/null || cp "$1" "$2"; } ;;
    *) link() { ln -sf "$1" "$2"; }
       hl() { ln -sf "$(readlink -f "$1")" "$2"; } ;;
esac
for f in sapling-spend.params sapling-output.params sprout-groth16.params; do
    [ -e "$dst/$f" ] || link "$src/$f" "$dst/$f"
done
cp "$src/sapling-spend.params" "$dst/spend-copy.params"
# flip one byte in the middle, keeping the size
flip() { # <in> <out> <offset>
    cp "$1" "$2"
    b=$(dd if="$1" bs=1 skip="$3" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
    nb=$(( (b + 1) % 256 ))
    printf "$(printf '\\%03o' "$nb")" | dd of="$2" bs=1 seek="$3" count=1 conv=notrunc 2>/dev/null
}
flip "$src/sapling-output.params" "$dst/output-corrupt.params" 1500000
flip "$src/sapling-spend.params" "$dst/spend-corrupt.params" 20000000
osz=$(wc -c <"$src/sapling-output.params" | tr -d ' ')
head -c $((osz - 1)) "$src/sapling-output.params" >"$dst/output-trunc.params"
cp "$src/sapling-output.params" "$dst/output-long.params"
printf '\n' >>"$dst/output-long.params"
cmp -s "$src/sapling-output.params" "$dst/output-corrupt.params" && { echo "make-pdir: flip failed" >&2; exit 2; }
cmp -s "$src/sapling-spend.params" "$dst/spend-corrupt.params" && { echo "make-pdir: flip failed" >&2; exit 2; }
# canonical file names with wrong content (same size), one directory each
mkcanon() { # <subdir> <corrupt-name> <offset>
    d=$dst/$1; mkdir -p "$d"
    for f in sapling-spend.params sapling-output.params sprout-groth16.params; do
        if [ "$f" = "$2" ]; then flip "$src/$f" "$d/$f" "$3"; else hl "$dst/$f" "$d/$f"; fi
    done
}
mkcanon c-output sapling-output.params 1500000
mkcanon c-spend sapling-spend.params 20000000
mkcanon c-sprout sprout-groth16.params 400000000
touch "$dst/.complete"
echo "make-pdir: $dst ready"
