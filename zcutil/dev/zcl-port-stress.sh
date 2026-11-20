#!/bin/sh
# Lease stress: <workers> concurrent processes, each leasing <rounds> blocks of <count>
# ports, binding every port for real, claiming it exclusively, releasing it.
# usage: zcl-port-stress.sh [workers=16] [rounds=50] [count=8]   Exit 0 iff no duplicate,
# no bind failure, no lease failure. Builds both tools into $ZCL_ISO_BIN or zcutil/bin.
set -u
here=$(cd "$(dirname "$0")" && pwd)
bin=${ZCL_ISO_BIN:-$here/../bin}
w=${1:-16}; rounds=${2:-50}; count=${3:-8}
case $(uname -s) in MINGW*|MSYS*|CYGWIN*) xl=-lws2_32; x=.exe ;; *) xl=; x= ;; esac
mkdir -p "$bin" || exit 2
${CC:-cc} -std=gnu17 -O2 -Wall -Wextra -o "$bin/zcl-port$x" "$here/zcl-port.c" $xl || exit 2
${CC:-cc} -std=gnu17 -O2 -Wall -Wextra -o "$bin/zcl-port-stress$x" "$here/zcl-port-stress.c" $xl || exit 2
d=$(mktemp -d "${TMPDIR:-/tmp}/zcl-stress.XXXXXX") || exit 2
trap 'rm -rf "$d" "$d.held"' EXIT
i=0
while [ $i -lt "$w" ]; do
    "$bin/zcl-port-stress$x" "$bin/zcl-port$x" "$d" "$rounds" "$count" >"$d.out.$i" 2>&1 &
    i=$((i + 1))
done
wait
rc=0; cat "$d".out.* | sed 's/^/worker: /'
for f in "$d".out.*; do grep -q 'dups=0 bindfail=0 leasefail=0' "$f" || rc=1; done
rm -f "$d".out.*
[ $rc = 0 ] && echo "zcl-port-stress: OK ($w workers x $rounds rounds x $count ports)" || echo "zcl-port-stress: FAILED"
exit $rc
