#!/bin/sh
# Vendor the Z23 closure VERBATIM and rewrite Z23_SOURCE.tsv.
# usage: revendor.sh <z23-repo> <commit>
# Fails closed unless <commit> contains 55245e2bd (canonical Fr encodings).
# Removes the old vendor/ tree first. Never edit vendor/ by hand.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <z23-repo> <commit>" >&2; exit 2; }
repo=$1
here=$(cd "$(dirname "$0")" && pwd)
c23=$(dirname "$here")
commit=$(git -C "$repo" rev-parse --verify "$2^{commit}") || { echo "bad commit $2" >&2; exit 1; }
git -C "$repo" merge-base --is-ancestor 55245e2bd "$commit" ||
    { echo "FAIL: $commit does not contain 55245e2bd" >&2; exit 1; }
list=$(mktemp) || exit 1
man=$(mktemp) || exit 1
trap 'rm -f "$list" "$man"' EXIT
"$here/derive-closure.sh" "$repo" "$commit" >"$list"
git -C "$repo" show "$commit:core/MANIFEST.sha3" >"$man"
rm -rf "$c23/vendor"
tsv="$c23/Z23_SOURCE.tsv"
{
    printf '# Z23 provenance manifest. Verified by tools/check-vendor.sh. Do not edit by hand.\n'
    printf '# z23_commit=%s\n' "$commit"
    printf '# requires_ancestor=55245e2bd\n'
    printf '# columns: zclassicd_path<TAB>z23_path<TAB>git_blob_sha1<TAB>z23_commit<TAB>manifest_sha3_256_or_unsealed\n'
} >"$tsv"
while IFS= read -r p; do
    dst="$c23/vendor/$p"
    mkdir -p "$(dirname "$dst")"
    git -C "$repo" show "$commit:$p" >"$dst"
    blob=$(git -C "$repo" rev-parse "$commit:$p")
    sha=$(awk -v p="$p" 'length($1)==64 && substr($0,67)==p {print $1; exit}' "$man")
    [ -n "$sha" ] || sha=unsealed
    printf 'src/c23/vendor/%s\t%s\t%s\t%s\t%s\n' "$p" "$p" "$blob" "$commit" "$sha" >>"$tsv"
done <"$list"
printf "* -text
" >"$c23/vendor/.gitattributes"
git -C "$repo" show "$commit:LICENSE" >"$c23/LICENSE.z23"
blob=$(git -C "$repo" rev-parse "$commit:LICENSE")
printf 'src/c23/LICENSE.z23\tLICENSE\t%s\t%s\tunsealed\n' "$blob" "$commit" >>"$tsv"
echo "vendored $(wc -l <"$list") files from $commit"
