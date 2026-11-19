#!/bin/sh
# Fixture tests for zcl-dev: golden outputs on a small tree, plus the failure modes.
# usage: sh test/run.sh <zcl-dev>      UPDATE=1 rewrites the golden files.
set -eu
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp -R "$here/fixture/." "$work/"
git -C "$work" init -q
git -C "$work" add -A
fails=0
# case <name> <expected-exit> <cmd...>: run in the fixture, compare stdout with golden/<name>.out
case_() {
    name=$1; want=$2; shift 2
    rc=0
    "$@" >"$work.out" 2>"$work.err" || rc=$?
    cat "$work.err" >>"$work.out"
    if [ "$rc" -ne "$want" ]; then echo "FAIL $name: exit $rc, wanted $want"; cat "$work.out"; fails=$((fails + 1)); return; fi
    if [ "${UPDATE:-0}" = 1 ]; then cp "$work.out" "$here/golden/$name.out"; return; fi
    if diff -u "$here/golden/$name.out" "$work.out"; then echo "ok   $name"; else echo "FAIL $name"; fails=$((fails + 1)); fi
}
z() { "$bin" -C "$work" "$@"; }
case_ guide-wallet 0 z guide wallet/src/w.cpp
case_ guide-core-json 0 z guide --json src/a.c
case_ guide-multi 0 z guide src/a.c src/b.c
case_ select-mapped 0 sh -c "printf 'src/a.c\nwallet/src/w.cpp\n' | '$bin' -C '$work' select --stdin"
case_ select-docs 0 sh -c "printf 'doc/agent/LESSONS.md\nAGENTS.md\n' | '$bin' -C '$work' select --steps --stdin"
case_ select-unmapped 0 sh -c "printf 'src/a.c\nconfigure.ac\n' | '$bin' -C '$work' select --stdin"
case_ select-json 0 sh -c "printf 'wallet/src/w.cpp\n' | '$bin' -C '$work' select --json --stdin"
case_ check-rules-ok 0 z check-rules
case_ check-docs-ok 0 z check-docs
# a new source file with no rule fails; a rule that matches nothing fails
mkdir -p "$work/src/extra"; printf 'x\n' >"$work/src/extra/c.h"; git -C "$work" add -A
printf 'int z;\n' >"$work/lib.c"; git -C "$work" add -A
case_ check-rules-unmapped 1 z check-rules
rm -rf "$work/src/extra"; rm -f "$work/lib.c"; git -C "$work" add -A
printf 'nothing/*\tunit-a\n' >>"$work/zcutil/dev/impact.rules"
case_ check-rules-dead-rule 1 z check-rules
printf '# rules\nsrc/*.c\tunit-a qa/x.sh\nwallet/src/*\tno-such-step\nqa/*|zcutil/*\t-\n' >"$work/zcutil/dev/impact.rules"
case_ check-rules-bad-step 1 z check-rules
# a lesson naming an untracked path fails check-docs
printf 'DONE src/missing.c — gone.\n' >>"$work/doc/agent/LESSONS.md"
case_ check-docs-bad-path 1 z check-docs
# receipts: the last receipt of a step wins
printf '%s\n' '{"step":"unit-a","verdict":"FAIL"}' '{"step":"other","verdict":"PASS"}' '{"step":"unit-a","verdict":"PASS"}' >"$work/receipts.jsonl"
case_ receipt-latest 0 "$bin" receipt unit-a "$work"
case_ receipt-missing 1 sh -c "cd '$work' && '$bin' receipt nope"
rm -f "$work.out" "$work.err"
if [ "$fails" -ne 0 ]; then echo "zcl-dev tests: $fails FAILED"; exit 1; fi
echo "zcl-dev tests: all passed"
