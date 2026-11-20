#!/bin/sh
# Vendor the Z23 helper files listed in vendor-files.txt VERBATIM and rewrite Z23_SOURCE.tsv.
# usage: revendor.sh <z23-repo> <commit>
# Fails closed unless <commit> contains 55245e2bd (the pin policy of src/c23/tools/revendor.sh).
# Removes the old vendor/ tree first. Never edit vendor/ by hand; verify with
#   sh src/c23/tools/check-vendor.sh zcutil/tools/Z23_SOURCE.tsv
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <z23-repo> <commit>" >&2; exit 2; }
repo=$1
here=$(cd "$(dirname "$0")" && pwd)
commit=$(git -C "$repo" rev-parse --verify "$2^{commit}") || { echo "bad commit $2" >&2; exit 1; }
git -C "$repo" merge-base --is-ancestor 55245e2bd "$commit" ||
    { echo "FAIL: $commit does not contain 55245e2bd" >&2; exit 1; }
man=$(mktemp) || exit 1
trap 'rm -f "$man"' EXIT
git -C "$repo" show "$commit:core/MANIFEST.sha3" >"$man"
rm -rf "$here/vendor"
tsv="$here/Z23_SOURCE.tsv"
{
    printf '# Z23 provenance manifest. Verified by src/c23/tools/check-vendor.sh. Do not edit by hand.\n'
    printf '# z23_commit=%s\n' "$commit"
    printf '# requires_ancestor=55245e2bd\n'
    printf '# columns: zclassicd_path<TAB>z23_path<TAB>git_blob_sha1<TAB>z23_commit<TAB>manifest_sha3_256_or_unsealed\n'
} >"$tsv"
n=0
while IFS= read -r p; do
    case "$p" in '#'*|'') continue ;; esac
    dst="$here/vendor/$p"
    mkdir -p "$(dirname "$dst")"
    git -C "$repo" show "$commit:$p" >"$dst"
    blob=$(git -C "$repo" rev-parse "$commit:$p")
    sha=$(awk -v p="$p" 'length($1)==64 && substr($0,67)==p {print $1; exit}' "$man")
    [ -n "$sha" ] || sha=unsealed
    printf 'zcutil/tools/vendor/%s\t%s\t%s\t%s\t%s\n' "$p" "$p" "$blob" "$commit" "$sha" >>"$tsv"
    n=$((n + 1))
done <"$here/vendor-files.txt"
printf '* -text\n' >"$here/vendor/.gitattributes"
git -C "$repo" show "$commit:LICENSE" >"$here/LICENSE.z23"
blob=$(git -C "$repo" rev-parse "$commit:LICENSE")
printf 'zcutil/tools/LICENSE.z23\tLICENSE\t%s\t%s\tunsealed\n' "$blob" "$commit" >>"$tsv"
echo "vendored $n files from $commit"
