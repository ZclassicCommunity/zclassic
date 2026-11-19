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
hook garbage 2 'guard.too_complex' 'not json'
hook empty 0 'empty hook input' ''
hook blank 0 'empty hook input' '   '
hook no-tool 0 '' '{"hook_event_name":"PreToolUse"}'

# input the guard cannot decode must refuse for a checked tool (or a call naming no tool): a
# crafted payload must not switch the guard off by being unreadable. An unchecked tool is allowed.
hook lone-surrogate 2 'guard.too_complex' '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/.zclassic # \ud800"}}'
hook lone-surrogate-path 2 'guard.too_complex' '{"tool_name":"Write","tool_input":{"file_path":"a\udc00","content":"x"}}'
hook no-tool-bad 2 'guard.too_complex' '{"tool_input":{"command":"\ud800"}}'
hook unchecked-bad 0 '' '{"tool_name":"Read","tool_input":{"file_path":"\ud800"}}'
printf '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/.zclassic","x":"\377"}}' |
    "$g" > "$out/o" 2> "$out/e"; rc=$?
[ "$rc" = 2 ] && grep -q 'guard.too_complex' "$out/e" || bad "invalid UTF-8 (rc $rc): $(cat "$out/e")"
deep=$(awk 'BEGIN { for (i = 0; i < 200; i++) printf "["; for (i = 0; i < 200; i++) printf "]" }')
printf '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/.zclassic","x":%s}}' "$deep" |
    "$g" > "$out/o" 2> "$out/e"; rc=$?
[ "$rc" = 2 ] && grep -q 'guard.too_complex' "$out/e" || bad "deep nesting (rc $rc): $(cat "$out/e")"
# a Bash call that holds a refusal and an escape the guard cannot read is still refused
hook refusal-with-escape 2 'guard.datadir' '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/.zclassic"},"x":"é"}'

# a method hidden from the command line, a PowerShell web call, a nested cmd /c, a computed path
hook xargs-client 2 'guard.spend_or_key_export' '{"tool_name":"Bash","tool_input":{"command":"xargs zclassic-cli < /tmp/a"}}'
hook ps-web-spend 2 'guard.spend_or_key_export' '{"tool_name":"PowerShell","tool_input":{"command":"iwr http://127.0.0.1:8232 -Method Post -Body dumpprivkey"}}'
hook cmd-nested 2 'guard.datadir' '{"tool_name":"Bash","tool_input":{"command":"cmd //c \"rd /s /q %APPDATA%\\\\Zclassic\""}}'
hook ps-joinpath 2 'guard.datadir' '{"tool_name":"PowerShell","tool_input":{"command":"Remove-Item -Recurse (Join-Path $env:APPDATA Zclassic)"}}'
hook ps-build-ok 0 '' '{"tool_name":"PowerShell","tool_input":{"command":"Remove-Item -Recurse build\\tmp"}}'
# the hook cwd seeds a command and joins a relative Write path
hook cwd-write 2 'guard.datadir' '{"tool_name":"Write","tool_input":{"file_path":"zclassic.conf","content":"x"},"cwd":"/home/rhett/.zclassic"}'
hook cwd-write-ok 0 '' '{"tool_name":"Write","tool_input":{"file_path":"zclassic.conf","content":"x"},"cwd":"/home/rhett/work/repo"}'
hook cwd-bash 2 'guard.datadir' '{"tool_name":"Bash","tool_input":{"command":"rm -rf blocks"},"cwd":"/home/rhett/.zclassic"}'
hook cwd-bash-ok 0 '' '{"tool_name":"Bash","tool_input":{"command":"rm -rf blocks"},"cwd":"/home/rhett/work/repo"}'

# a warning must reach the model: a PreToolUse "ask" decision on stdout, exit 0 (stderr of an
# exit-0 hook is only a debug log)
printf '%s' '{"tool_name":"Edit","tool_input":{"file_path":"src/pow.cpp","old_string":"a","new_string":"b"}}' |
    "$g" > "$out/o" 2> /dev/null; rc=$?
[ "$rc" = 0 ] || bad "seal-ask: exit $rc"
grep -q '^{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"guard.consensus_seal: .*UNSEAL.md.*"}}$' "$out/o" ||
    bad "seal-ask: stdout lacks the ask decision: $(cat "$out/o")"
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | "$g" > "$out/o" 2> /dev/null
[ ! -s "$out/o" ] || bad "an allowed call must print nothing on stdout"
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"python3 x"}}' | "$g" > "$out/o" 2> /dev/null
[ ! -s "$out/o" ] || bad "a refusal must print nothing on stdout"

# the PowerShell tool is checked like Bash, with PowerShell deleters and writers
hook ps-push 2 'guard.git_push' '{"tool_name":"PowerShell","tool_input":{"command":"git push --force origin master; python3 x"}}'
hook ps-remove 2 'guard.datadir' '{"tool_name":"PowerShell","tool_input":{"command":"Remove-Item -Recurse $env:APPDATA\\ZClassic"}}'
hook ps-setcontent 2 'guard.hosted_ci' '{"tool_name":"PowerShell","tool_input":{"command":"Set-Content .github\\workflows\\ci.yml x"}}'
hook ps-allow 0 '' '{"tool_name":"PowerShell","tool_input":{"command":"Get-ChildItem build"}}'
hook notebook-refuse 2 'guard.vendor_edit' '{"tool_name":"NotebookEdit","tool_input":{"notebook_path":"zcutil/tools/vendor/n.ipynb"}}'
"$g" --ps 'Remove-Item -Recurse $env:APPDATA\ZClassic' > "$out/o"; rc=$?
[ "$rc" = 1 ] && grep -q '^REFUSE guard.datadir ' "$out/o" || bad "--ps refuse (rc $rc)"

# the settings matcher must name every checked tool
m=$(grep '"matcher"' "$here/../../../../.claude/settings.json" 2> /dev/null)
if [ -n "$m" ]; then
    for t in Bash PowerShell Edit Write MultiEdit NotebookEdit; do
        case $m in *"$t"*) ;; *) bad "settings.json matcher lacks $t" ;; esac
    done
fi

# hook input over the 32 MiB cap cannot be parsed and must refuse, not fail open
{
    printf '{"tool_name":"Write","tool_input":{"file_path":".github/workflows/ci.yml","content":"'
    head -c 34000000 /dev/zero | tr '\0' a
    printf '"}}'
} > "$out/big.json"
"$g" < "$out/big.json" > /dev/null 2> "$out/e"; rc=$?
[ "$rc" = 2 ] && grep -q 'guard.too_complex' "$out/e" || bad "oversized input (rc $rc): $(head -c 200 "$out/e")"
rm -f "$out/big.json"

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
