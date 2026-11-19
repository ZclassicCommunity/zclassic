#!/bin/sh
# Vendor the Z23 service-parser files VERBATIM and rewrite Z23_SOURCE.tsv.
# usage: revendor.sh <z23-repo> <commit>
# The file list is tools/vendor-files.txt (Z23-relative paths).
# Removes the old vendor/ tree first. Never edit vendor/ by hand.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <z23-repo> <commit>" >&2; exit 2; }
repo=$1
here=$(cd "$(dirname "$0")" && pwd)
svc=$(dirname "$here")
commit=$(git -C "$repo" rev-parse --verify "$2^{commit}") || { echo "bad commit $2" >&2; exit 1; }
man=$(mktemp) || exit 1
trap 'rm -f "$man"' EXIT
git -C "$repo" show "$commit:core/MANIFEST.sha3" >"$man"
rm -rf "$svc/vendor"
tsv="$svc/Z23_SOURCE.tsv"
{
    printf '# Z23 provenance manifest. Verified by tools/check-vendor.sh. Do not edit by hand.\n'
    printf '# z23_commit=%s\n' "$commit"
    printf '# columns: zclassicd_path<TAB>z23_path<TAB>git_blob_sha1<TAB>z23_commit<TAB>manifest_sha3_256_or_unsealed\n'
} >"$tsv"
n=0
while IFS= read -r p; do
    case "$p" in '#'*|'') continue ;; esac
    dst="$svc/vendor/$p"
    mkdir -p "$(dirname "$dst")"
    git -C "$repo" show "$commit:$p" >"$dst"
    blob=$(git -C "$repo" rev-parse "$commit:$p")
    sha=$(awk -v p="$p" 'length($1)==64 && substr($0,67)==p {print $1; exit}' "$man")
    [ -n "$sha" ] || sha=unsealed
    printf 'src/c23/services/vendor/%s\t%s\t%s\t%s\t%s\n' "$p" "$p" "$blob" "$commit" "$sha" >>"$tsv"
    n=$((n + 1))
done <"$here/vendor-files.txt"
printf '* -text\n' >"$svc/vendor/.gitattributes"
git -C "$repo" show "$commit:LICENSE" >"$svc/LICENSE.z23"
blob=$(git -C "$repo" rev-parse "$commit:LICENSE")
printf 'src/c23/services/LICENSE.z23\tLICENSE\t%s\t%s\tunsealed\n' "$blob" "$commit" >>"$tsv"
echo "vendored $n files from $commit"
