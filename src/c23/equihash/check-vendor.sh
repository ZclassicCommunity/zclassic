#!/bin/sh
# Copyright (c) 2026 The Zclassic developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Verify that src/c23/equihash/vendor is byte-identical to the Z23 files
# listed in Z23_SOURCE.tsv, and (optionally) that a built
# libzc23_equihash.a exports only namespaced symbols.
#
# Usage: check-vendor.sh [path/to/libzc23_equihash.a]
# Environment:
#   Z23_REPO=<z23 git checkout>  also re-derive each blob from Z23 at the
#                                pinned commit (git cat-file), not just from
#                                the recorded id.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tsv="$here/Z23_SOURCE.tsv"
fail=0

commit=$(sed -n 's/^# z23_commit[[:space:]]*\([0-9a-f]\{40\}\).*/\1/p' "$tsv")
[ -n "$commit" ] || { echo "check-vendor: no z23_commit line in $tsv" >&2; exit 1; }

have_sha3=0
if command -v openssl >/dev/null 2>&1 && openssl dgst -sha3-256 /dev/null >/dev/null 2>&1; then
    have_sha3=1
fi

listed=$(mktemp)
trap 'rm -f "$listed"' EXIT INT TERM

tab=$(printf '\t')
grep -v '^#' "$tsv" | while IFS="$tab" read -r local z23path blob sha3; do
    [ -n "$local" ] || continue
    f="$here/$local"
    if [ ! -f "$f" ]; then
        echo "MISSING $local" >&2; echo x >>"$listed.fail"; continue
    fi
    got=$(git hash-object -- "$f")
    if [ "$got" != "$blob" ]; then
        echo "BLOB MISMATCH $local: $got != $blob" >&2; echo x >>"$listed.fail"
    fi
    if [ "$have_sha3" = 1 ]; then
        s=$(openssl dgst -sha3-256 -r "$f" | cut -d' ' -f1)
        if [ "$s" != "$sha3" ]; then
            echo "SHA3 MISMATCH $local: $s != $sha3" >&2; echo x >>"$listed.fail"
        fi
    fi
    if [ -n "${Z23_REPO:-}" ]; then
        up=$(git -C "$Z23_REPO" cat-file -p "$commit:$z23path" | git hash-object --stdin)
        if [ "$up" != "$blob" ]; then
            echo "UPSTREAM MISMATCH $z23path@$commit: $up != $blob" >&2; echo x >>"$listed.fail"
        fi
    fi
    echo "$local" >>"$listed"
done

if [ -f "$listed.fail" ]; then fail=1; rm -f "$listed.fail"; fi

# No unlisted source (.c/.h) may sit under vendor/ (build outputs are ignored).
(cd "$here" && find vendor -type f \( -name '*.c' -o -name '*.h' \) | LC_ALL=C sort) >"$listed.all"
LC_ALL=C sort "$listed" >"$listed.sorted"
extra=$(LC_ALL=C comm -23 "$listed.all" "$listed.sorted")
rm -f "$listed.all" "$listed.sorted"
if [ -n "$extra" ]; then
    echo "UNLISTED vendored file(s):" >&2; echo "$extra" >&2; fail=1
fi

# Symbol namespace: every defined external symbol must start with zc23.
if [ $# -ge 1 ]; then
    lib=$1
    bad=$(nm -g --defined-only "$lib" | awk 'NF==3 && $2 ~ /^[TDBRVW]$/ {print $3}' | grep -v '^_\{0,1\}zc23' || true)
    if [ -n "$bad" ]; then
        echo "UNPREFIXED exported symbol(s) in $lib:" >&2; echo "$bad" >&2; fail=1
    fi
fi

if [ "$fail" -ne 0 ]; then
    echo "check-vendor: FAILED" >&2
    exit 1
fi
n=$(grep -vc '^#' "$tsv")
echo "check-vendor: OK ($n files at Z23 $commit; sha3=$have_sha3; upstream=${Z23_REPO:-no})"
