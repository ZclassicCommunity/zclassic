#!/bin/sh
# zcl-port self-test: leases must be shared between runs that have different TMPDIRs, must not
# be reclaimed across pid namespaces, and a bound port must never be handed out.
# usage: zcl-port-selftest.sh      (builds zcl-port into $ZCL_ISO_BIN or zcutil/bin)
set -u
here=$(cd "$(dirname "$0")" && pwd)
bin=${ZCL_ISO_BIN:-$here/../bin}
case $(uname -s) in MINGW*|MSYS*|CYGWIN*) xl=-lws2_32; x=.exe ;; *) xl=; x= ;; esac
mkdir -p "$bin" || exit 2
${CC:-cc} -std=gnu17 -O2 -Wall -Wextra -o "$bin/zcl-port$x" "$here/zcl-port.c" $xl || exit 2
zp=$bin/zcl-port$x
fails=0
bad() { echo "FAIL zcl-port-selftest: $*" >&2; fails=$((fails + 1)); }
unset ZCL_PORT_DIR
t1=$(mktemp -d "${TMPDIR:-/tmp}/zp-a.XXXXXX"); t2=$(mktemp -d "${TMPDIR:-/tmp}/zp-b.XXXXXX"); t3=$(mktemp -d "${TMPDIR:-/tmp}/zp-c.XXXXXX")
trap 'TMPDIR=$t1 "$zp" release --owner $$ >/dev/null 2>&1; rm -rf "$t1" "$t2" "$t3"' EXIT
# 1. different TMPDIRs, a one-port range: the second lease must fail, not repeat the port
a=$(TMPDIR=$t1 ZCL_PORT_RANGE=17895-17899 "$zp" lease 5 --block --owner $$) || bad "first lease failed"
b=$(TMPDIR=$t2 ZCL_PORT_RANGE=17895-17899 "$zp" lease 1 --owner $$ 2>/dev/null) && bad "second lease with another TMPDIR reused a leased port: $b"
l=$(TMPDIR=$t3 "$zp" list | wc -l)
[ "$l" -ge 5 ] || bad "list under a third TMPDIR shows $l leases, want at least 5"
# 2. concurrent leases from distinct TMPDIRs never share a port
for i in 1 2 3 4 5 6; do
    d=$(mktemp -d "${TMPDIR:-/tmp}/zp-p.XXXXXX")
    ( TMPDIR=$d "$zp" lease 4 --block --owner $$ > "$d/out" 2>/dev/null ) &
done
wait
all=$(cat "${TMPDIR:-/tmp}"/zp-p.*/out 2>/dev/null | sort -n)
dups=$(printf '%s\n' "$all" | uniq -d | wc -l)
[ "$dups" -eq 0 ] || bad "$dups duplicate ports across concurrent leases with separate TMPDIRs"
[ "$(printf '%s\n' "$all" | wc -l)" -eq 24 ] || bad "expected 24 leased ports"
rm -rf "${TMPDIR:-/tmp}"/zp-p.*
"$zp" release --owner $$ >/dev/null 2>&1
# 3. a lease made in another pid namespace is not judged dead by pid
if unshare --user --map-root-user --pid --fork --mount-proc true 2>/dev/null; then
    p=$(ZCL_PORT_DIR=/tmp/zcl-port-$(id -u) unshare --user --map-root-user --pid --fork --mount-proc "$zp" lease 1 --owner 99999 --range 17890-17894) || bad "lease in a pid namespace failed"
    st=$("$zp" list | awk -v p="$p" '$1 == p { print $4 }')
    [ "$st" = live ] || bad "foreign-namespace lease of port $p is '$st', want live"
    "$zp" release "$p" >/dev/null 2>&1
else
    echo "zcl-port-selftest: no unshare here, namespace case skipped"
fi
[ "$fails" -eq 0 ] && echo "zcl-port-selftest: ok" || exit 1
