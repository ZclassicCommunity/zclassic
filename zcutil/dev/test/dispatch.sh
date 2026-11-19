#!/bin/sh
# Git-style dispatch of zcl-dev: unknown command, argument passthrough, exit status, help table.
# usage: sh test/dispatch.sh <zcl-dev>
set -eu
src=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-dispatch.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/repo/sub"
cp "$src" "$work/bin/zcl-dev"
cat >"$work/bin/zcl-dev-hello" <<'EOF2'
#!/bin/sh
[ "${1:-}" = --purpose ] && { echo "prints its arguments"; exit 0; }
echo "hello pwd=$(basename "$(pwd)") prefix=${ZCL_DEV_PREFIX:-} args=$*"
exit "${HELLO_RC:-0}"
EOF2
chmod +x "$work/bin/zcl-dev-hello"
git -C "$work/repo" init -q
zd=$work/bin/zcl-dev
fail() { echo "FAIL dispatch: $*" >&2; exit 1; }
rc=0; "$zd" -C "$work/repo" nosuch >"$work/out" 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "unknown command exit $rc, want 2"
grep -q 'unknown command; see zcl-dev help' "$work/out" || fail "unknown command message: $(cat "$work/out")"
rc=0; "$zd" -C "$work/repo" '../evil' >"$work/out" 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "path-like command exit $rc, want 2"
out=$("$zd" -C "$work/repo/sub" hello a 'b c') || fail "hello failed"
[ "$out" = "hello pwd=repo prefix=sub/ args=a b c" ] || fail "hello output: $out"
rc=0; HELLO_RC=7 "$zd" -C "$work/repo" hello >/dev/null || rc=$?
[ "$rc" = 7 ] || fail "child exit status $rc, want 7"
out=$("$zd" help) || fail "help failed"
printf '%s\n' "$out" | grep -q '^  guide ' || fail "help lacks built-in guide"
printf '%s\n' "$out" | grep -q '^  hello  *prints its arguments$' || fail "help lacks discovered hello: $out"
echo "ok   dispatch"
