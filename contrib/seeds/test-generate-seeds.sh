#!/bin/sh
# Test for contrib/seeds/generate-seeds.c (POSIX sh, C23 compiler only).
#   1. Regenerates src/chainparamsseeds.h from contrib/seeds/nodes_*.txt and requires
#      it to match the tracked header byte for byte.
#   2. Checks each accepted address form against known bytes, and that malformed
#      input (including a Tor v3 onion, which a 16-byte SeedSpec6 cannot hold) fails.
# usage: test-generate-seeds.sh [source root]      (default: the checkout this script is in)
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=${1:-$(CDPATH= cd -- "$here/../.." && pwd)}
cc=${CC:-cc}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; fails=$((fails + 1)); }

$cc -std=c2x -O2 -Wall -Wextra -Werror -o "$work/generate-seeds" "$here/generate-seeds.c" ||
    { echo "FAIL compile generate-seeds.c" >&2; exit 1; }
gen="$work/generate-seeds"

# 1. byte-for-byte regeneration of the shipped header
"$gen" "$here" > "$work/chainparamsseeds.h"
if cmp -s "$work/chainparamsseeds.h" "$root/src/chainparamsseeds.h"; then
    pass "chainparamsseeds.h regenerates byte for byte from nodes_main.txt and nodes_test.txt"
else
    fail "chainparamsseeds.h differs from the regenerated output"
    diff "$root/src/chainparamsseeds.h" "$work/chainparamsseeds.h" >&2 || true
fi

# 2. address forms. $1 name, $2 input line, $3 expected "{{...}, port}" entry.
fixture="$work/fx"
mkdir "$fixture"
: > "$fixture/nodes_test.txt"
expect() {
    printf '%s\n' "$2" > "$fixture/nodes_main.txt"
    if "$gen" "$fixture" > "$work/out" 2> "$work/err"; then
        got=$(sed -n 's/^    \({{.*}, [0-9]*}\),\{0,1\}$/\1/p' "$work/out" | head -1)
        if [ "$got" = "$3" ]; then pass "$1"; else fail "$1: got '$got' want '$3'"; fi
    else
        fail "$1: generator failed: $(cat "$work/err")"
    fi
}
reject() {
    printf '%s\n' "$2" > "$fixture/nodes_main.txt"
    if "$gen" "$fixture" > /dev/null 2> "$work/err"; then fail "$1: accepted '$2'"
    else pass "$1 (rejected: $(cut -d: -f4- "$work/err" | head -1))"; fi
}
v4='{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff'
expect "ipv4 default port"        "74.50.74.102"          "$v4,0x4a,0x32,0x4a,0x66}, 8033}"
expect "ipv4 with port"           "74.50.74.102:9000"     "$v4,0x4a,0x32,0x4a,0x66}, 9000}"
expect "comment and spaces"       "  74.50.74.102 # seed"  "$v4,0x4a,0x32,0x4a,0x66}, 8033}"
expect "old little-endian 0x form" "0x664a324a"            "$v4,0x4a,0x32,0x4a,0x66}, 8033}"
expect "ipv6 bare, ::"            "2001:db8::1"           "{{0x20,0x01,0x0d,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01}, 8033}"
expect "ipv6 loopback ::1"        "::1"                   "{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01}, 8033}"
expect "ipv6 trailing ::"         "fe80::"                "{{0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, 8033}"
expect "ipv6 bracketed with port" "[2001:db8::2]:9999"    "{{0x20,0x01,0x0d,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02}, 9999}"
expect "ipv6 full, 8 groups"      "1:2:3:4:5:6:7:8"       "{{0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08}, 8033}"
expect "tor v2 onion"             "thfsmmn2jbitcoin.onion" "{{0xfd,0x87,0xd8,0x7e,0xeb,0x43,0x99,0xcb,0x26,0x31,0xba,0x48,0x51,0x31,0x39,0x0d}, 8033}"
reject "ipv4 octet out of range"  "1.2.3.256"
reject "ipv4 too few octets"      "1.2.3"
reject "port zero"                "1.2.3.4:0"
reject "port too large"           "1.2.3.4:65536"
reject "ipv6 two gaps"            "1::2::3"
reject "ipv6 too many groups"     "1:2:3:4:5:6:7:8:9"
reject "ipv6 seven groups"        "1:2:3:4:5:6:7"
reject "garbage"                  "not-an-address"
reject "tor v3 onion"             "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
reject "onion with bad base32"    "it2pj4f7657g3r10.onion"

[ "$fails" -eq 0 ] && { echo "generate-seeds: all tests passed"; exit 0; }
echo "generate-seeds: $fails test(s) failed" >&2
exit 1
