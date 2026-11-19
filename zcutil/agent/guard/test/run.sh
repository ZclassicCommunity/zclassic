#!/bin/sh
# Hook, replay and shim tests for zcl-agent-guard. The rule table is test/selftest.c.
#   sh test/run.sh <path-to-zcl-agent-guard>
set -u
here=$(cd "$(dirname "$0")" && pwd)
g=${1:?usage: run.sh <zcl-agent-guard>}
out=$(mktemp -d "${TMPDIR:-/tmp}/zcl-guard.XXXXXX") || exit 2
trap 'rm -rf "$out"' EXIT
fail=0
bad() { echo "FAIL: $*"; fail=1; }

# hook mode: JSON on stdin; exit 2 plus a stderr line refuses, exit 0 allows
hook() { # name expected-exit expected-stderr-substring json
    printf '%s' "$4" | "$g" > "$out/o" 2> "$out/e"; rc=$?
    [ "$rc" = "$2" ] || bad "$1: exit $rc, want $2"
    [ -z "$3" ] || grep -q "$3" "$out/e" || bad "$1: stderr lacks '$3': $(cat "$out/e")"
}
hook bash-refuse 2 'guard.datadir' '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/.zclassic/blocks"}}'
hook bash-text 2 'AGENTS.md' '{"tool_name":"Bash","tool_input":{"command":"python3 x.py"}}'
hook bash-allow 0 '' '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
hook edit-refuse 2 'guard.vendor_edit' '{"tool_name":"Edit","tool_input":{"file_path":"zcutil/tools/vendor/tools/jsonq.c","old_string":"a","new_string":"b"}}'
hook write-refuse 2 'guard.hosted_ci' '{"tool_name":"Write","tool_input":{"file_path":".github/workflows/ci.yml","content":"on: push"}}'
hook multiedit-refuse 2 'guard.python' '{"tool_name":"MultiEdit","tool_input":{"file_path":"a/b.py","edits":[{"old_string":"a","new_string":"b"}]}}'
hook seal-warn 0 'guard.consensus_seal.*UNSEAL.md' '{"tool_name":"Edit","tool_input":{"file_path":"src/pow.cpp","old_string":"a","new_string":"b"}}'
hook key-order 2 'guard.git_push' '{"tool_input":{"command":"git push origin master"},"tool_name":"Bash","session_id":"s"}'
hook escaped 2 'guard.python' '{"tool_name":"Bash","tool_input":{"command":"echo \"hi\"\npython3 -V"}}'
hook read-tool 0 '' '{"tool_name":"Read","tool_input":{"file_path":"/home/x/.zclassic/debug.log"}}'
hook garbage 0 'unexpected hook input' 'not json'
hook empty 0 'unexpected hook input' ''
hook no-tool 0 '' '{"hook_event_name":"PreToolUse"}'

# CLI verdicts and exit codes
"$g" --bash 'ls' > "$out/o"; [ $? = 0 ] && [ "$(cat "$out/o")" = ALLOW ] || bad "--bash allow"
"$g" --bash 'git push origin master' > "$out/o"; rc=$?
[ "$rc" = 1 ] && grep -q '^REFUSE guard.git_push ' "$out/o" || bad "--bash refuse (rc $rc)"
"$g" --path Edit src/pow.cpp > "$out/o"; rc=$?
[ "$rc" = 0 ] && grep -q '^WARN guard.consensus_seal ' "$out/o" || bad "--path warn (rc $rc)"
"$g" --json --bash 'python3 x' > "$out/o"
grep -q '^{"verdict":"REFUSE","rule":"guard.python","text":"' "$out/o" || bad "--json verdict"
"$g" --bogus > /dev/null 2>&1; [ $? = 64 ] || bad "usage exit"

# replay: golden output, exit 1 on a refusal, paging, hollow scan, missing file
"$g" --replay "$here/transcript.jsonl" > "$out/o"; rc=$?
[ "$rc" = 1 ] || bad "replay exit $rc, want 1"
cmp -s "$out/o" "$here/replay.golden" || { bad "replay golden differs"; diff "$out/o" "$here/replay.golden"; }
"$g" --json --after=2 --replay "$here/transcript.jsonl" > "$out/o"
[ "$(wc -l < "$out/o" | tr -d ' ')" = 3 ] && grep -q '"calls":6,"refused":3,"warned":1,"next":-1' "$out/o" \
    || bad "replay --json --after=2: $(cat "$out/o")"
printf '{"type":"user","message":{"content":"hi"}}\n' > "$out/empty.jsonl"
"$g" --replay "$out/empty.jsonl" > /dev/null 2>&1; [ $? = 2 ] || bad "hollow scan must exit 2"
"$g" --replay "$out/nonexistent" > /dev/null 2>&1; [ $? = 2 ] || bad "missing transcript must exit 2"

# shim: a fresh clone without the binary allows the call and prints the hint
mkdir -p "$out/agent/guard" "$out/bin"
cp "$here/../zcl-agent-guard.sh" "$out/agent/guard/"
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/.zclassic"}}' |
    sh "$out/agent/guard/zcl-agent-guard.sh" > /dev/null 2> "$out/e"; rc=$?
[ "$rc" = 0 ] && grep -q 'make -C zcutil' "$out/e" || bad "shim without binary (rc $rc)"
case $g in *.exe) ext=.exe ;; *) ext= ;; esac
cp "$g" "$out/bin/zcl-agent-guard$ext"
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/.zclassic"}}' |
    sh "$out/agent/guard/zcl-agent-guard.sh" > /dev/null 2> "$out/e"; rc=$?
[ "$rc" = 2 ] && grep -q 'guard.datadir' "$out/e" || bad "shim with binary (rc $rc)"

[ "$fail" = 0 ] && echo "agent-guard run.sh: OK"
exit "$fail"
