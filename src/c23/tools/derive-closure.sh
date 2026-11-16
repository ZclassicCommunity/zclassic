#!/bin/sh
# Re-derive the vendored file list from vendor-seeds.txt against a Z23 commit.
# usage: derive-closure.sh <z23-repo> <commit>   (prints sorted Z23 paths)
# Follows quoted #include "..." transitively (same directory first, then the
# Z23 include roots). Unresolved includes are reported on stderr.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <z23-repo> <commit>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
git -C "$1" archive "$2" core platform | tar -x -C "$tmp"
ROOTS="core/modules/sapling/include core/math/include core/modules/core/include core/modules/crypto/include platform/modules/util/include platform/modules/base/include platform/modules/support/include platform/modules/encoding/include platform/modules/platform/include"
seen=" "
queue=$(cat "$here/vendor-seeds.txt" | tr '\n' ' ')
while [ -n "$queue" ]; do
    set -- $queue
    f=$1
    shift
    queue="$*"
    case "$seen" in *" $f "*) continue ;; esac
    seen="$seen$f "
    [ -f "$tmp/$f" ] || { echo "MISSING $f" >&2; exit 1; }
    echo "$f"
    d=$(dirname "$f")
    for inc in $(grep -h '^[[:space:]]*#[[:space:]]*include[[:space:]]*"' "$tmp/$f" | sed -E 's/.*"([^"]+)".*/\1/'); do
        r=""
        if [ -f "$tmp/$d/$inc" ]; then
            r="$d/$inc"
        else
            for R in $ROOTS; do
                if [ -f "$tmp/$R/$inc" ]; then r="$R/$inc"; break; fi
            done
        fi
        if [ -n "$r" ]; then queue="$queue $r"; else echo "UNRESOLVED $f -> $inc" >&2; fi
    done
done | sort -u
