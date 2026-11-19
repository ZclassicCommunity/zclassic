#!/bin/sh
# Fixture test of zcl-dev verify with stub tools: order, skip of a missing t-fast, stop on failure, exit codes.
# usage: sh test/run.sh <zcl-dev-verify>
set -eu
src=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-verify.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cp "$src" "$work/bin/zcl-dev-verify"
fail() { echo "FAIL verify: $*" >&2; exit 1; }
stub() { # stub <name> <exit-code>: logs its name and arguments
    printf '#!/bin/sh\necho "%s $*" >>"%s/calls"\nexit %s\n' "$1" "$work" "$2" >"$work/bin/$1"
    chmod +x "$work/bin/$1"
}
v=$work/bin/zcl-dev-verify
run() { rc=0; : >"$work/calls"; "$v" "$@" >"$work/out" 2>"$work/err" || rc=$?; }

# 1. no zcl-dev: broken
run; [ "$rc" = 2 ] || fail "missing zcl-dev: exit $rc, want 2"

# 2. no t-fast: skipped visibly, select then lint run in order, pass
stub zcl-dev 0; stub zcl-lint 0
run --base main
[ "$rc" = 0 ] || fail "no t-fast: exit $rc"
grep -q 'SKIPPED' "$work/out" || fail "skip not reported"
[ "$(cat "$work/calls")" = "zcl-dev select main
zcl-lint all" ] || fail "call order: $(cat "$work/calls")"
grep -q 'local-ci.sh --commit HEAD test-changed' "$work/out" || fail "hint missing"

# 3. t-fast present: runs between select and lint with --changed
stub zcl-dev-t-fast 0
run --json
[ "$rc" = 0 ] || fail "with t-fast: exit $rc"
[ "$(cat "$work/calls")" = "zcl-dev select origin/master
zcl-dev-t-fast --changed
zcl-lint all" ] || fail "call order with t-fast: $(cat "$work/calls")"
grep -q '"exit":0' "$work/out" || fail "json missing"

# 4. a failing t-fast stops before lint, exit 1
stub zcl-dev-t-fast 1
run
[ "$rc" = 1 ] || fail "t-fast failure: exit $rc, want 1"
if grep -q zcl-lint "$work/calls"; then fail "lint ran after a t-fast failure"; fi

# 5. a lint finding is exit 1; a broken lint is exit 2
stub zcl-dev-t-fast 0; stub zcl-lint 1
run; [ "$rc" = 1 ] || fail "lint finding: exit $rc, want 1"
stub zcl-lint 2
run; [ "$rc" = 2 ] || fail "lint broken: exit $rc, want 2"

# 6. select failure is broken, nothing else runs
stub zcl-dev 1; stub zcl-lint 0
run; [ "$rc" = 2 ] || fail "select failure: exit $rc, want 2"
[ "$(wc -l <"$work/calls")" -eq 1 ] || fail "steps ran after select failed"

# 7. missing lint is broken, not a pass
stub zcl-dev 0; rm "$work/bin/zcl-lint"
run; [ "$rc" = 2 ] || fail "missing lint: exit $rc, want 2"

# 8. unsafe base ref and unknown option are refused
run --base 'a;b'; [ "$rc" = 2 ] || fail "unsafe ref accepted"
run --nope; [ "$rc" = 2 ] || fail "unknown option accepted"
echo "verify: ok"
