#!/bin/sh
# Golden-output tests for zcl-dev-timings over the fixture outdirs in test/fixture.
# usage: sh test/run.sh <path to zcl-dev-timings>       (UPDATE=1 rewrites test/golden)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tool=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
cd "$here"
fails=0
# case <name> <expected exit> <args...>: stdout and stderr plus an "exit N" line against golden/<name>.txt
case_() {
    name=$1; want=$2; shift 2
    rc=0
    { "$tool" "$@" 2>&1 || rc=$?; } >"golden/$name.new"
    echo "exit $rc" >>"golden/$name.new"
    if [ "$rc" != "$want" ]; then echo "FAIL $name (exit $rc, wanted $want)"; fails=$((fails + 1)); fi
    if [ "${UPDATE:-}" = 1 ]; then mv "golden/$name.new" "golden/$name.txt"; return; fi
    if cmp -s "golden/$name.new" "golden/$name.txt"; then echo "ok   $name"; else
        echo "FAIL $name (differs from golden/$name.txt)"; diff "golden/$name.txt" "golden/$name.new" || true
        fails=$((fails + 1))
    fi
    rm -f "golden/$name.new"
}
mkdir -p golden
F=fixture
case_ three-good 0 $F/good1 $F/good2 $F/good3
case_ missing-receipts 0 $F/good1 $F/norcpt
case_ corrupt-line 0 $F/good1 $F/corrupt
case_ mismatch 1 $F/good1 $F/mismatch
case_ all-unreadable 2 $F/empty $F/does-not-exist
case_ json 0 --json $F/good1 $F/good2 $F/good3
case_ step-filter 0 --step regtest-smoke $F/good1 $F/good2 $F/good3
case_ no-args 2
[ "$fails" = 0 ] || { echo "zcl-dev-timings tests: $fails failure(s)"; exit 1; }
echo "zcl-dev-timings tests: ok"
