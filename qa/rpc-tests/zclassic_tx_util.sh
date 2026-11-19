#!/bin/sh
# TEST-ONLY. Command-line behaviour of zclassic-tx: every case of data/zclassic_tx_util/cases.json
# (the former src/test/bitcoin-util-test.py table) is run and its stdout byte-compared with the
# expected file and its exit status with the expected return code (default 0).
#
# case keys: args (array), input (file fed on stdin), output_cmp (expected stdout file),
#            return_code (expected status, default 0)
#
# usage: sh qa/rpc-tests/zclassic_tx_util.sh <dir with zclassic-tx>     (builds zcutil/bin/jsonq on first use)
set -u
bin=${1:-}
[ -n "$bin" ] || { echo "usage: zclassic_tx_util.sh <dir with zclassic-tx>" >&2; exit 2; }
exe=$bin/zclassic-tx
[ -x "$exe" ] || exe=$bin/zclassic-tx.exe
[ -x "$exe" ] || { echo "zclassic_tx_util: no zclassic-tx in $bin" >&2; exit 2; }
. "$(dirname "$0")/jsonq_lib.sh"
here=$(cd "$(dirname "$0")" && pwd)
data=$here/data/zclassic_tx_util
cases=$data/cases.json
[ -f "$cases" ] || { echo "zclassic_tx_util: missing $cases" >&2; exit 2; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zclassic_tx_util.XXXXXX") || exit 2
trap "rm -rf \"$tmp\"" EXIT INT TERM

total=$(jlen < "$cases") || exit 2
failures=0
i=0
while [ "$i" -lt "$total" ]; do
    nargs=$(jlen "[$i].args" < "$cases")
    set --
    j=0
    while [ "$j" -lt "$nargs" ]; do
        a=$(jget "[$i].args[$j]" < "$cases"; echo x); a=${a%x}; a=${a%?}
        set -- "$@" "$a"
        j=$((j + 1))
    done
    input=$(jgetd "[$i].input" "" < "$cases")
    want=$(jgetd "[$i].output_cmp" "" < "$cases")
    wantrc=$(jgetd "[$i].return_code" 0 < "$cases")
    name="case $i (${want:-rc$wantrc}: $1 ${2:-})"
    if [ -n "$input" ]; then "$exe" "$@" <"$data/$input" >"$tmp/out" 2>"$tmp/err"
    else "$exe" "$@" </dev/null >"$tmp/out" 2>"$tmp/err"; fi
    rc=$?
    bad=""
    # zclassic-tx.exe writes CRLF in text mode; the old harness read stdout with universal newlines.
    tr -d '\r' <"$tmp/out" >"$tmp/out.lf"
    if [ -n "$want" ] && ! cmp -s "$tmp/out.lf" "$data/$want"; then bad="output differs from $want"; fi
    [ "$rc" -eq "$wantrc" ] || bad="$bad return code $rc, want $wantrc"
    if [ -z "$bad" ]; then echo "zclassic_tx_util: PASS $name"
    else echo "zclassic_tx_util: FAIL $name:$bad"; failures=$((failures + 1)); fi
    i=$((i + 1))
done
echo "zclassic_tx_util: $((total - failures))/$total passed"
[ "$failures" -eq 0 ]
