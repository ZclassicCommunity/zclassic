#!/bin/sh
# Fixture tests of zcl-dev-gen: goldens for the three generated documents, both gates passing on the
# fixture and each failing on its defect, the shrink-only baselines, paging, hollow scans.
# usage: sh test/run.sh <zcl-dev-gen>      UPDATE_GOLDEN=1 rewrites test/golden from the current output.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
gen=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-gen-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL gen: $*" >&2; exit 1; }
fresh() { rm -rf "$work/t"; cp -R "$here/fixture" "$work/t"; }
# run <want-rc> <args...>: output in $work/out
run() {
    want=$1; shift
    rc=0; "$gen" -C "$work/t" "$@" >"$work/out" 2>&1 || rc=$?
    [ "$rc" = "$want" ] || fail "$*: exit $rc, want $want: $(cat "$work/out")"
}
has() { grep -q -- "$1" "$work/out" || fail "output lacks '$1': $(cat "$work/out")"; }
# sub <file> <awk-program>: rewrite a fixture file
sub() { awk "$2" "$work/t/$1" >"$work/tmp" && mv "$work/tmp" "$work/t/$1"; }

"$gen" --selftest >/dev/null || fail "built-in selftest"
"$gen" --purpose >/dev/null || fail "--purpose"

# goldens on the good fixture, and both gates pass
fresh
run 0 --check rpc-parity; has "rpc-parity: ok (5 commands"
run 0 --check flags; has "flags: ok"
run 0 rpc-reference --out="$work/RPC_REFERENCE.md"
run 0 args-reference --out="$work/ARGS_REFERENCE.md"
run 0 inventory --no-tools --out="$work/CAPABILITY_INVENTORY.jsonl"
for g in RPC_REFERENCE.md ARGS_REFERENCE.md CAPABILITY_INVENTORY.jsonl; do
    if [ "${UPDATE_GOLDEN:-}" = 1 ]; then mkdir -p "$here/golden"; cp "$work/$g" "$here/golden/$g"; fi
    cmp -s "$work/$g" "$here/golden/$g" || { diff "$here/golden/$g" "$work/$g" | head -20 >&2; fail "$g differs from golden"; }
done
run 0 --check flags --json; has '"check":"flags","count":0'

# defect: duplicate RPC name
fresh; sub src/rpc/net.cpp '/^#ifdef/ { print "    { \"network\", \"stop\", &stop, true }," } { print }'
run 1 --check rpc-parity; has "duplicate RPC name .stop."
# defect: an actor without help text
fresh; sub src/rpc/server.cpp '{ sub(/throw runtime_error\(/, "throw rt_error(") } { print }'
run 1 --check rpc-parity; has "no help text"
# defect: a table row whose actor is not defined anywhere
fresh; sub src/rpc/net.cpp '/^#ifdef/ { print "    { \"network\", \"ghost\", &ghost, true }," } { print }'
run 1 --check rpc-parity; has "ghost.: actor .ghost. has no help text (definition not found)"
# defect: convert-params mismatch (unknown command, index beyond the usage line)
fresh; sub src/rpc/client.cpp '/"addnode", 1/ { print; print "    { \"nosuchcmd\", 0 },"; print "    { \"help\", 3 },"; next } { print }'
run 1 --check rpc-parity
has "names .nosuchcmd., which is not a registered command"
has "help. index 3, but the usage line documents 1 argument"
# a known mismatch can be baselined; a baseline row without a mismatch is stale
printf 'help:3\tfixture: known\n' >>"$work/t/zcutil/dev/gen/rpc-parity-baseline.txt"
sub src/rpc/client.cpp '/nosuchcmd/ { next } { print }'
run 0 --check rpc-parity
printf 'addnode:5\tfixture: gone\n' >>"$work/t/zcutil/dev/gen/rpc-parity-baseline.txt"
run 1 --check rpc-parity; has "stale baseline row .addnode:5."
run 0 --check rpc-parity --update-baseline; has "1 stale row"
run 0 --check rpc-parity
grep -q 'help:3' "$work/t/zcutil/dev/gen/rpc-parity-baseline.txt" || fail "update-baseline dropped a live row"

# defect: an undocumented flag; the baseline refuses to grow
fresh; sub src/util.cpp '/^}/ { print "    GetArg(\"-newflag\", 0);" } { print }'
run 1 --check flags; has "flag .-newflag. is read but not documented"
cp "$work/t/zcutil/dev/gen/flags-undocumented.txt" "$work/before"
run 1 --check flags --update-baseline; has "refusing --update-baseline"
cmp -s "$work/before" "$work/t/zcutil/dev/gen/flags-undocumented.txt" || fail "refused update changed the baseline"
# paging and JSON
sub src/util.cpp '/^}/ { print "    GetArg(\"-newflag2\", 0); GetArg(\"-newflag3\", 0);" } { print }'
run 1 --check flags --after=1; has "newflag2"
grep -q "newflag.," "$work/out" && fail "--after=1 repeated the first finding" || true
run 1 --check flags --json; has '"count":3'
# a baseline row for a flag that is no longer read is stale, and --update-baseline removes it
fresh; sub src/util.cpp '/-hidden/ { next } { print }'
run 1 --check flags; has "stale baseline row .-hidden.: the flag is no longer read"
run 0 --check flags --update-baseline; has "1 stale row"
grep -q 'fixture baseline' "$work/t/zcutil/dev/gen/flags-undocumented.txt" || fail "update-baseline dropped the comment"
grep -q -- '-hidden' "$work/t/zcutil/dev/gen/flags-undocumented.txt" && fail "stale row kept" || true
run 0 --check flags
# a baseline row for a flag that became documented is stale
fresh; sub src/init.cpp '/-bar/ { print "    strUsage += HelpMessageOpt(\"-hidden\", _(\"Now documented\"));" } { print }'
run 1 --check flags; has "stale baseline row .-hidden.: the flag is now documented"

# a missing baseline file is an error for the flags gate (exit 2), never a silent pass
fresh; rm "$work/t/zcutil/dev/gen/flags-undocumented.txt"
run 2 --check flags; has "cannot read baseline"
# hollow scans fail
rm -rf "$work/t"; mkdir -p "$work/t"
run 2 --check rpc-parity; has "hollow scan"
run 2 --check flags --baseline=nothing; has "hollow scan"
fresh; : >"$work/t/src/rpc/server.cpp"; : >"$work/t/src/rpc/net.cpp"; : >"$work/t/src/wallet/rpcwallet.cpp"
run 2 rpc-reference --out="$work/x.md"; has "no CRPCCommand tables"
# usage errors
run 2 bogus; run 2 --check bogus

# tool records come from the sibling zcl-dev when it is built
fresh
if [ -x "$(dirname "$gen")/zcl-dev" ]; then
    run 0 inventory --out="$work/inv.jsonl"
    grep -q '"record":"tool","name":"guide"' "$work/inv.jsonl" || fail "inventory lacks the zcl-dev guide tool record"
fi
echo "ok   gen"
