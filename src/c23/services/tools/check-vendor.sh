#!/bin/sh
# Verify src/c23/services/vendor/ is byte-identical to the Z23 pin recorded in
# Z23_SOURCE.tsv.
# usage: check-vendor.sh [services-dir]   (default: the directory above this script)
# Optional env Z23_REPO=<path>: additionally compare every recorded blob id
# with the blob id Z23 itself has at the pinned commit.
# Fails (non-zero) on: blob drift, missing file, unlisted file under vendor/,
# malformed row, inconsistent commit column, or (when openssl has sha3) a
# core/MANIFEST.sha3 digest mismatch for a sealed file.
set -u
here=$(cd "$(dirname "$0")" && pwd)
svc=${1:-$(dirname "$here")}
svc=$(cd "$svc" && pwd) || exit 2
root=$(cd "$svc/../../.." && pwd)
tsv="$svc/Z23_SOURCE.tsv"
[ -f "$tsv" ] || { echo "FAIL: missing $tsv" >&2; exit 1; }
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

pin=$(sed -n 's/^# z23_commit=//p' "$tsv")
if [ ${#pin} -ne 40 ] || [ -n "$(printf '%s' "$pin" | tr -d '0-9a-f')" ]; then
    bad "header z23_commit is not 40 hex: '$pin'"
fi

have_sha3=0
if command -v openssl >/dev/null 2>&1 &&
   [ "$(printf '' | openssl dgst -sha3-256 2>/dev/null | sed 's/.*= //')" = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a ]; then
    have_sha3=1
fi

listed=$(mktemp) || exit 2
trap 'rm -f "$listed" "$listed.found"' EXIT
n=0
tab=$(printf '\t')
while IFS="$tab" read -r lpath zpath blob commit sha extra; do
    case "$lpath" in '#'*|'') continue ;; esac
    if [ -n "${extra:-}" ] || [ -z "$sha" ]; then bad "malformed row: $lpath"; continue; fi
    n=$((n + 1))
    echo "$lpath" >>"$listed"
    f="$root/$lpath"
    if [ ! -f "$f" ]; then bad "missing $lpath"; continue; fi
    [ "$commit" = "$pin" ] || bad "$lpath: commit column $commit != pin $pin"
    got=$(git hash-object --no-filters -- "$f") || { bad "hash-object failed: $lpath"; continue; }
    [ "$got" = "$blob" ] || bad "$lpath: blob $got != recorded $blob"
    if [ -n "${Z23_REPO:-}" ]; then
        up=$(git -C "$Z23_REPO" rev-parse "$pin:$zpath" 2>/dev/null) || up=missing
        [ "$up" = "$blob" ] || bad "$lpath: Z23 has blob $up at $pin, manifest records $blob"
    fi
    case "$sha" in
        unsealed) ;;
        *)
            if [ "$have_sha3" = 1 ]; then
                g3=$(openssl dgst -sha3-256 "$f" | sed 's/.*= //')
                [ "$g3" = "$sha" ] || bad "$lpath: sha3-256 $g3 != manifest $sha"
            fi ;;
    esac
done <"$tsv"

# Unlisted files anywhere under vendor/ (.gitattributes guard is the one allowed extra).
# An in-tree build leaves automake's own products next to the sources
# (subdir-objects): objects, dependency stamps, coverage notes. They are not
# inputs to anything, so they are not "files under vendor/" for this check.
find "$svc/vendor" -type f \
    ! -name '*.o' ! -name '*.obj' ! -name '*.lo' ! -name '*.Po' ! -name '*.Plo' \
    ! -name '.dirstamp' ! -name '*.gcno' ! -name '*.gcda' >"$listed.found"
while IFS= read -r f; do
    rel=${f#"$root"/}
    [ "$rel" = src/c23/services/vendor/.gitattributes ] && continue
    grep -qxF "$rel" "$listed" || bad "unlisted file $rel"
done <"$listed.found"

if [ "$fail" -ne 0 ]; then echo "check-vendor: FAILED" >&2; exit 1; fi
up=skipped
[ -n "${Z23_REPO:-}" ] && up=on
s3=skipped
[ "$have_sha3" = 1 ] && s3=on
echo "check-vendor: OK ($n rows, pin $pin, sha3 check: $s3, upstream compare: $up)"
