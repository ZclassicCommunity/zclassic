#!/bin/sh
# Stream the existing ZQWDMON1 format; no whole-daemon allocation or interpreter.
set -eu
[ "$#" -eq 3 ] || { echo "usage: $0 GUI.exe DAEMON.exe OUTPUT.exe" >&2; exit 1; }
gui=$1 daemon=$2 output=$3
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ ! -e "$output" ] || { echo "ERROR: output already exists: $output" >&2; exit 1; }
sh "$here/check-win-deps.sh" "$gui" "$daemon"
[ "$(tail -c 8 "$gui" | od -An -tx1 | tr -d '[:space:]')" != 5a5157444d4f4e31 ] || {
    echo "ERROR: GUI already has an embedded daemon" >&2; exit 1;
}
source_size=$(wc -c < "$daemon" | tr -d '[:space:]')
[ "$source_size" -gt 0 ] && [ "$source_size" -le 536870912 ] || {
    echo "ERROR: daemon size outside loader limit (1..512 MiB)" >&2; exit 1;
}
tmp=$(mktemp "${output}.tmp.XXXXXX")
payload=
trap 'rm -f "$tmp"; [ -z "$payload" ] || rm -f "$payload"' EXIT
trap 'exit 1' HUP INT TERM
payload=$(mktemp "${output}.daemon.XXXXXX")
# Snapshot first: a concurrent rebuild must not change the bytes between the
# append and hash passes. Inspect the snapshot as well as the original input.
cat "$daemon" > "$payload"
sh "$here/check-win-deps.sh" "$payload"
size=$(wc -c < "$payload" | tr -d '[:space:]')
[ "$size" -gt 0 ] && [ "$size" -le 536870912 ] || {
    echo "ERROR: daemon size outside loader limit (1..512 MiB)" >&2; exit 1;
}
cat "$gui" "$payload" > "$tmp"
openssl dgst -sha256 -binary "$payload" >> "$tmp"
# Encode an unsigned little-endian length, independent of host byte order.
remaining=$size
i=0
while [ "$i" -lt 8 ]; do
    octal=$(printf '%03o' "$((remaining % 256))")
    printf "\\$octal" >> "$tmp"
    remaining=$((remaining / 256))
    i=$((i + 1))
done
printf ZQWDMON1 >> "$tmp"
expected=$(($(wc -c < "$gui") + size + 48))
[ "$(wc -c < "$tmp")" -eq "$expected" ] || {
    echo "ERROR: packaged length mismatch" >&2; exit 1;
}
sh "$here/check-win-deps.sh" "$tmp"
mv "$tmp" "$output"
sha256sum "$output"
