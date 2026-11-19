#!/bin/sh
# Scripted-session test of zcl-mcp: initialize, tools/list, every tool, malformed frames, refused
# arguments and an unknown tool, against golden replies; plus the 60 s rail (shortened) and its
# process-group kill, the doctor smoke check and the --checkout requirement.
# usage: sh test/run.sh <zcl-mcp>      UPDATE=1 rewrites test/session.golden.
set -eu
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
realbin=$(dirname "$bin")
dev=$here/../../../dev
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-mcp-test.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
fails=0
fail() { echo "FAIL $*"; fails=$((fails + 1)); }

# a private bindir: the real tools, with a stand-in for zcl-dev-tests (a separate unit), so the
# golden file does not move when that tool lands
tb=$work/bin
mkdir -p "$tb"
for f in "$realbin"/zcl-dev "$realbin"/zcl-dev-* "$realbin"/zcl-lint "$realbin"/zcl-run "$realbin"/jsonq "$bin"; do
    [ -f "$f" ] && cp "$f" "$tb/"
done
rm -f "$tb"/zcl-dev-tests
cat >"$tb/zcl-dev-tests" <<'EOF2'
#!/bin/sh
printf '{"stub":"tests","args":"%s"}\n' "$*"
EOF2
chmod +x "$tb/zcl-dev-tests"

# the fixture checkout
co=$work/co
mkdir -p "$co"
cp -R "$dev/code/test/fixture/." "$co/"
mkdir -p "$co/doc/agent"
printf '# Fixture docs\n\nThe docs root of the fixture checkout.\n' >"$co/doc/README.md"
printf '# Agent docs\n\nLessons and traps.\n' >"$co/doc/agent/README.md"
printf 'not a wallet\n' >"$co/src/wallet/wallet.dat"
printf '{"step":"unit-a","ok":true}\n' >"$co/receipts.jsonl"
cp "$dev/wiki/test/facts.good.tsv" "$co/doc/agent/FACTS.tsv"
git -C "$co" init -q
git -C "$co" add -A
git -C "$co" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture

# ---- the scripted session ------------------------------------------------------------------
"$tb/zcl-mcp" --checkout="$co" <"$here/session.in" >"$work/session.raw" 2>"$work/session.err" ||
    fail "zcl-mcp exited with status $?"
sed "s#$co#@CO@#g" "$work/session.raw" >"$work/session.out"
if [ -n "${UPDATE:-}" ]; then
    cp "$work/session.out" "$here/session.golden"
elif ! diff -u "$here/session.golden" "$work/session.out" >"$work/session.diff"; then
    fail "session replies differ from test/session.golden"
    head -40 "$work/session.diff"
fi
grep -q 'serving checkout=' "$work/session.err" || fail "no startup line on stderr"
[ "$(grep -c '' "$work/session.out")" -ge 45 ] || fail "too few replies in the session"

# stdout carries only JSON-RPC replies, one per line
bad=$(grep -vc '^{"jsonrpc":"2.0",' "$work/session.out" || true)
[ "$bad" = 0 ] || fail "$bad stdout lines are not JSON-RPC replies"
if [ -x "$realbin/jsonq" ]; then
    while IFS= read -r l; do
        printf '%s\n' "$l" | "$realbin/jsonq" has jsonrpc >/dev/null 2>&1 || { fail "a reply is not valid JSON: $l"; break; }
    done <"$work/session.out"
fi

# the doctor tool: host-specific output, so check its shape only
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"zcl_doctor","arguments":{}}}' |
    "$tb/zcl-mcp" --checkout="$co" 2>/dev/null >"$work/doctor.out" || fail "doctor session failed"
grep -q 'zcl-doctor/1' "$work/doctor.out" || fail "zcl_doctor did not return the zcl-doctor/1 document"

# ---- the rail: a hung tool is killed with its whole process group --------------------------
fb=$work/fakebin
mkdir -p "$fb"
cp "$realbin/zcl-run" "$fb/"
cat >"$fb/zcl-dev" <<'EOF2'
#!/bin/sh
sleep 37 &
sleep 37
EOF2
chmod +x "$fb/zcl-dev"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"zcl_wiki","arguments":{}}}' |
    "$bin" --checkout="$co" --bindir="$fb" --timeout=1 2>/dev/null >"$work/timeout.out" || fail "timeout session failed"
grep -q 'timeout' "$work/timeout.out" || fail "a hung tool was not reported as a timeout: $(cat "$work/timeout.out")"
grep -q '"isError":true' "$work/timeout.out" || fail "a timeout is not an isError result"
sleep 1
if ps -eo args 2>/dev/null | grep -q '[s]leep 37'; then
    fail "the hung tool's process group was not killed"
    pkill -f 'sleep 37' 2>/dev/null || true
fi

# a missing tool is reported, not fatal
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"zcl_wiki","arguments":{}}}' |
    "$bin" --checkout="$co" --bindir="$work/nonexistent" 2>/dev/null >"$work/missing.out" || fail "missing-tool session failed"
grep -q 'tool_failed\|not_started' "$work/missing.out" || fail "a missing tool binary was not reported"

# ---- command line ----------------------------------------------------------------------------
if "$bin" </dev/null >/dev/null 2>&1; then fail "zcl-mcp started without --checkout"; fi
if "$bin" --checkout="$work/no-such-dir" </dev/null >/dev/null 2>&1; then fail "zcl-mcp accepted a missing checkout"; fi
if "$bin" --checkout="$co" --bogus </dev/null >/dev/null 2>&1; then fail "zcl-mcp accepted an unknown flag"; fi
[ -n "$("$bin" --purpose)" ] || fail "no --purpose line"
"$bin" --checkout="$co" </dev/null >/dev/null 2>&1 || fail "zcl-mcp did not exit 0 at end of input"

if [ "$fails" -ne 0 ]; then echo "zcl-mcp test: $fails FAILED"; exit 1; fi
echo "zcl-mcp test: OK"
