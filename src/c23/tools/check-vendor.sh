#!/bin/sh
# Verify src/c23/vendor/ is byte-identical to the Z23 pin recorded in Z23_SOURCE.tsv.
# usage: check-vendor.sh [c23-dir | manifest.tsv]   (default: the directory above this script)
#   A manifest path (for example zcutil/tools/Z23_SOURCE.tsv) checks the vendor/ directory beside it.
# Optional env Z23_REPO=<path>: additionally prove the pin contains 55245e2bd.
# Fails (non-zero) on: blob drift, missing file, unlisted file under vendor/,
# malformed row, inconsistent commit column, or (when openssl has sha3) a
# core/MANIFEST.sha3 digest mismatch.
set -u
here=$(cd "$(dirname "$0")" && pwd)
c23=${1:-$(dirname "$here")}
case "$c23" in *.tsv) tsv=$(cd "$(dirname "$c23")" && pwd)/$(basename "$c23"); c23=$(dirname "$tsv") ;; *) c23=$(cd "$c23" && pwd) || exit 2; tsv="$c23/Z23_SOURCE.tsv" ;; esac
root=$(cd "$c23/../.." && pwd)
[ -f "$tsv" ] || { echo "FAIL: missing $tsv" >&2; exit 1; }
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

pin=$(sed -n 's/^# z23_commit=//p' "$tsv")
case "$pin" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) bad "header z23_commit is not 40 hex: '$pin'" ;;
esac
grep -q '^# requires_ancestor=55245e2bd$' "$tsv" || bad "header requires_ancestor=55245e2bd missing"
if [ -n "${Z23_REPO:-}" ]; then
    git -C "$Z23_REPO" merge-base --is-ancestor 55245e2bd "$pin" 2>/dev/null ||
        bad "pin $pin does not contain 55245e2bd in $Z23_REPO"
fi

have_sha3=0
if command -v openssl >/dev/null 2>&1 &&
   [ "$(printf '' | openssl dgst -sha3-256 2>/dev/null | sed 's/.*= //')" = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a ]; then
    have_sha3=1
fi

listed=$(mktemp) || exit 2
trap 'rm -f "$listed"' EXIT
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
# An in-tree build leaves objects, depfiles and stamps beside the sources; they
# are build products (git-ignored), not vendored files.
find "$c23/vendor" -type f ! -name "*.o" ! -name "*.obj" ! -name "*.lo" ! -name "*.Po" \
    ! -name "*.Tpo" ! -name ".dirstamp" ! -name "*.gcno" ! -name "*.gcda" >"$listed.found"
while IFS= read -r f; do
    rel=${f#"$root"/}
    [ "$rel" = "${c23#"$root"/}/vendor/.gitattributes" ] && continue
    grep -qxF "$rel" "$listed" || bad "unlisted file $rel"
done <"$listed.found"
rm -f "$listed.found"

if [ "$fail" -ne 0 ]; then echo "check-vendor: FAILED" >&2; exit 1; fi
echo "check-vendor: OK ($n rows, pin $pin, sha3 check: $([ $have_sha3 = 1 ] && echo on || echo skipped))"
