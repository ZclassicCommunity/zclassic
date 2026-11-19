#!/bin/sh
# Fixture-command tests for zcl-dev-flaky: sh one-liners stand in for qa scripts.
# usage: sh test/run.sh <path to zcl-dev-flaky>
set -eu
tool=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-flaky-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
export ZCL_FLAKY_OUT="$work/out"
fails=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
# expect <name> <exit> <grep-pattern> <args...>
expect() {
    name=$1; want=$2; pat=$3; shift 3
    rc=0
    "$tool" "$@" >"$work/o" 2>&1 || rc=$?
    if [ "$rc" != "$want" ]; then bad "$name (exit $rc, wanted $want: $(tr '\n' ' ' <"$work/o"))"; return; fi
    if ! grep -q -- "$pat" "$work/o"; then bad "$name (no '$pat' in: $(tr '\n' ' ' <"$work/o"))"; return; fi
    ok "$name"
}

expect always-pass 0 '^PASS: 3 runs, 3 passed, 0 failed' -n 3 -- sh -c 'exit 0'
expect always-fail 1 '^FAILING: 3 runs, 0 passed, 3 failed' -n 3 -- sh -c 'exit 3'
grep -q 'exit codes seen: 3$' "$work/o" && ok "failing exit codes" || bad "failing exit codes"

expect flaky-runs 1 '^FLAKY: 5 runs, 3 passed, 2 failed' -n 5 -- \
    sh -c 'if [ "$ZCL_FLAKY_RUN" = 2 ] || [ "$ZCL_FLAKY_RUN" = 5 ]; then echo boom-$ZCL_FLAKY_RUN; exit 1; fi'
grep -q 'first failing log: .*/run-2/log$' "$work/o" && ok "first failing log is run-2" || bad "first failing log is run-2"
log=$(sed -n 's/^first failing log: //p' "$work/o")
grep -q boom-2 "$log" && ok "failing log kept with its output" || bad "failing log kept"
ls -d "$(dirname "$(dirname "$log")")"/run-* | grep -q 'run-5$' && ok "failing run 5 kept" || bad "failing run 5 kept"
! ls -d "$(dirname "$(dirname "$log")")"/run-* | grep -q 'run-1$' && ok "passing run 1 removed" || bad "passing run 1 removed"

expect keep 0 '^PASS: 2 runs' -n 2 --keep -- sh -c 'exit 0'
d=$(sed -n 's/^run directory: //p' "$work/o")
[ -f "$d/run-1/log" ] && [ -f "$d/run-2/log" ] && ok "--keep keeps passing logs" || bad "--keep keeps passing logs"

expect broken 2 '^BROKEN: cannot start' -n 2 -- /nonexistent/zcl-flaky-no-such-binary
expect bad-n 2 'usage' -n 0 -- true
expect no-command 2 'usage' -n 2
expect jobs-cap 2 'usage' -n 2 --jobs 5 -- true

t0=$(date +%s)
expect timeout 1 'killed on timeout' -n 1 --timeout 1 -- sh -c 'sleep 30'
t1=$(date +%s)
[ $((t1 - t0)) -lt 15 ] && ok "timeout kills the process group promptly" || bad "timeout took $((t1 - t0))s"
grep -q 'exit codes seen: timeout' "$work/o" && ok "timeout code listed" || bad "timeout code listed"

expect substitution 0 '^PASS: 2 runs' -n 2 --keep -- sh -c 'echo "$1" >"$1/marker"; echo "$2" >"$1/num"' sh '@WORK@' '@RUN@'
d=$(sed -n 's/^run directory: //p' "$work/o")
[ "$(cat "$d/run-2/num")" = 2 ] && [ "$(cat "$d/run-2/marker")" = "$d/run-2" ] && ok "@WORK@ and @RUN@ substituted" || bad "@WORK@ and @RUN@ substituted"

expect tmpdir 0 '^PASS: 1 runs' -n 1 --keep -- sh -c 'echo "$TMPDIR" >"$TMPDIR/t"'
d=$(sed -n 's/^run directory: //p' "$work/o")
[ "$(cat "$d/run-1/t")" = "$d/run-1" ] && ok "TMPDIR is the run directory" || bad "TMPDIR is the run directory"

# --jobs 3 gives the same verdict as sequential
cmd='if [ "$ZCL_FLAKY_RUN" = 2 ] || [ "$ZCL_FLAKY_RUN" = 5 ]; then exit 1; fi; sleep 0.2'
expect jobs3 1 '^FLAKY: 6 runs, 4 passed, 2 failed' -n 6 --jobs 3 -- sh -c "$cmd"
expect jobs1 1 '^FLAKY: 6 runs, 4 passed, 2 failed' -n 6 --jobs 1 -- sh -c "$cmd"
expect json 1 '"verdict":"FLAKY"' -n 3 --json -- sh -c 'test "$ZCL_FLAKY_RUN" != 3'

# parallel runs really overlap: 4 runs of sleep 1 with --jobs 4 finish well under 4 s
t0=$(date +%s)
"$tool" -n 4 --jobs 4 -- sh -c 'sleep 1' >/dev/null 2>&1
t1=$(date +%s)
[ $((t1 - t0)) -le 3 ] && ok "jobs overlap" || bad "jobs did not overlap ($((t1 - t0))s)"

[ "$fails" = 0 ] || { echo "zcl-dev-flaky tests: $fails failure(s)"; exit 1; }
echo "zcl-dev-flaky tests: ok"
