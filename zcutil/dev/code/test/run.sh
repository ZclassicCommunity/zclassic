#!/bin/sh
# Fixture tests for zcl-dev-code: golden outputs on a small C++ tree (namespaces, class-inline
# methods, lambdas, raw strings, an #include cycle, a Makefile.am with += and $(VAR) expansion),
# plus paging, JSON validity and the failure modes.
# usage: sh test/run.sh <zcl-dev-code>      UPDATE=1 rewrites the golden files.
set -eu
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
bindir=$(dirname "$bin")
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-code-test.XXXXXX")
trap 'rm -rf "$work" "$work.tb" "$work.out" "$work.err"' EXIT
cp -R "$here/fixture/." "$work/"
tb=$work.tb
mkdir -p "$tb"
cp "$bin" "$tb/zcl-dev-code"
# A stand-in for `zcl-dev guide`, so owner is deterministic and the real tool is not needed.
cat >"$tb/zcl-dev" <<'EOF2'
#!/bin/sh
echo "== $2"
echo
echo "rules (AGENTS.md):"
echo "  - Never change consensus."
echo
echo "ci steps (ALL, broad rule: $2): unit-a"
echo "lessons (doc/agent/LESSONS.md):"
echo "  DONE src/core.cpp - keep raw strings out of the brace matcher."
echo
echo "traps (doc/agent/TRAPS.md):"
echo "  (1) Core"
echo
echo "first commands:"
echo "  \$ never shown"
EOF2
chmod +x "$tb/zcl-dev"
git -C "$work" init -q
git -C "$work" add -A
git -C "$work" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture
jq=
for c in "$bindir/jsonq" "$bindir/jsonq.exe"; do [ -x "$c" ] && jq=$c && break; done
[ -n "$jq" ] || { echo "FAIL: jsonq is required (make -C zcutil/tools)"; exit 1; }
fails=0
z() { (cd "$work" && "$tb/zcl-dev-code" "$@"); }
# case_ <name> <expected-exit> <cmd...>: compare stdout+stderr with golden/<name>.out
case_() {
    name=$1; want=$2; shift 2
    rc=0
    "$@" >"$work.out" 2>"$work.err" || rc=$?
    cat "$work.err" >>"$work.out"
    if [ "$rc" -ne "$want" ]; then echo "FAIL $name: exit $rc, wanted $want"; cat "$work.out"; fails=$((fails + 1)); return; fi
    if [ "${UPDATE:-0}" = 1 ]; then cp "$work.out" "$here/golden/$name.out"; return; fi
    if diff -u "$here/golden/$name.out" "$work.out"; then echo "ok   $name"; else echo "FAIL $name"; fails=$((fails + 1)); fi
}
check() { # check <label> <command...>: pass when the command succeeds
    label=$1; shift
    if "$@" >/dev/null 2>&1; then echo "ok   $label"; else echo "FAIL $label"; fails=$((fails + 1)); fi
}
case_ map 0 z map
case_ map-json 0 z map --json
case_ owner-wallet 0 z owner src/wallet/wallet.cpp
case_ owner-header 0 z owner src/common.h
case_ owner-untracked 1 z owner src/nosuch.cpp
case_ impact-common 0 z impact src/common.h
case_ impact-a-tests 0 z impact src/a.h --tests
case_ impact-depth1 0 z impact src/a.h --depth=1
case_ impact-json 0 z impact src/common.h --json
case_ cost-common 0 z cost src/common.h
case_ cost-tu 0 z cost src/core.cpp
case_ file-core 0 z file src/core.cpp
case_ file-core-json 0 z file src/core.cpp --json
case_ file-tests 0 z file src/test/foo_tests.cpp
case_ body-method 0 z body src/core.cpp Counter::Twice
case_ body-short 0 z body src/core.cpp Twice
case_ body-default-arg 0 z body src/core.cpp Default
case_ body-annotated 0 z body src/core.cpp Annotated
case_ body-ctor 0 z body src/core.cpp Counter::Counter
case_ body-test-macro 0 z body src/test/foo_tests.cpp a_is_one
case_ body-missing 1 z body src/core.cpp NoSuchFunction
case_ body-json 0 z body src/core.cpp Max --json
case_ sym-max 0 z sym Max
case_ sym-a-value 0 z sym a_value
case_ sym-missing 1 z sym NoSuchSymbol
case_ sym-template-method 0 z sym Blob::Set
case_ body-template-method 0 z body src/core.cpp Blob::Get
case_ body-gtest-name 0 z body src/test/foo_tests.cpp second_case
case_ sym-bad-name 2 z sym 'a b'
case_ refs-a-value 0 z refs a_value
case_ refs-missing 1 z refs NoSuchSymbolAnywhere
case_ recent 0 z recent --since=1d
case_ recent-bad 2 z recent --since=soon
case_ usage 2 z
case_ unknown-command 2 z nosuch
case_ depth-not-a-number 2 z impact src/a.h --depth=abc
case_ depth-negative 2 z impact src/a.h --depth=-1
case_ after-negative 2 z map --after=-5
case_ after-empty 2 z map --after=
check "cost json: relink has a null n" sh -c "cd '$work' && '$tb/zcl-dev-code' cost src/common.h --json | grep -q '\"kind\":\"relink\",\"path\":\"[^\"]*\",\"n\":null'"
check "owner works run directly from a subdirectory" sh -c "cd '$work/src' && env -u ZCL_DEV_PREFIX '$tb/zcl-dev-code' owner wallet/wallet.cpp"
check "refs ~name is quoted, not tilde-expanded" sh -c "cd '$work' && ! '$tb/zcl-dev-code' refs ~root | grep -q ^location"

# A tracked filename with shell metacharacters must reach the guide as plain data, never run.
meta='src/x$(touch PWNED).cpp'
printf 'int x;\n' >"$work/$meta"
git -C "$work" add -A
case_ owner-metachar 0 z owner "$meta"
if [ -e "$work/PWNED" ]; then echo "FAIL owner executed a filename"; fails=$((fails + 1)); else echo "ok   filename not executed"; fi
quote="src/it's.cpp"
printf 'int y;\n' >"$work/$quote"
git -C "$work" add -A
case_ owner-quote 0 z owner "$quote"

# The raw string, the string literals and the digit separator must not derail the matcher.
check "no fake raw-string function" sh -c "cd '$work' && ! '$tb/zcl-dev-code' file src/core.cpp | grep -q fake"
check "c_entry found inside extern C" sh -c "cd '$work' && '$tb/zcl-dev-code' sym c_entry | grep -q '^func  c_entry'"

# JSON output validates through jsonq.
for sub in "map" "owner src/common.h" "impact src/a.h --tests" "cost src/a.h" "file src/core.cpp" "body src/core.cpp Counter::Twice" "sym Max" "refs a_value" "recent --since=1d"; do
    # shellcheck disable=SC2086
    check "json valid: $sub" sh -c "cd '$work' && '$tb/zcl-dev-code' $sub --json | '$jq' type ."
done

# Paging: 600 includers of common.h overflow one 16 KiB page; --after walks the rest.
mkdir -p "$work/src/many"
i=0
while [ $i -lt 600 ]; do
    printf '#include "common.h"\nint many_%d() { return common_inline(%d); }\n' $i $i >"$work/src/many/m_$i.cpp"
    i=$((i + 1))
done
git -C "$work" add -A
page1=$(cd "$work" && "$tb/zcl-dev-code" impact src/common.h | wc -c)
if [ "$page1" -lt 16384 ]; then echo "ok   page 1 is $page1 bytes (< 16384)"; else echo "FAIL page 1 is $page1 bytes"; fails=$((fails + 1)); fi
(cd "$work" && "$tb/zcl-dev-code" impact src/common.h) | grep -q 'next page: --after=' && echo "ok   page 1 names the next page" || { echo "FAIL page 1 lacks the paging footer"; fails=$((fails + 1)); }
rows=0
after=0
pages=0
while :; do
    json=$(cd "$work" && "$tb/zcl-dev-code" impact src/common.h --json --after=$after)
    size=$(printf '%s' "$json" | wc -c)
    [ "$size" -lt 16384 ] || { echo "FAIL json page at $after is $size bytes"; fails=$((fails + 1)); break; }
    n=$(printf '%s' "$json" | "$jq" count rows)
    rows=$((rows + n))
    pages=$((pages + 1))
    next=$(printf '%s' "$json" | "$jq" get next)
    [ "$next" = null ] && break
    after=$next
    [ $pages -lt 200 ] || { echo "FAIL paging does not terminate"; fails=$((fails + 1)); break; }
done
total=$(cd "$work" && "$tb/zcl-dev-code" impact src/common.h --json | "$jq" get total)
if [ "$rows" = "$total" ] && [ "$pages" -gt 1 ]; then echo "ok   paging walked $rows of $total rows in $pages pages"; else echo "FAIL paging: $rows rows of $total in $pages pages"; fails=$((fails + 1)); fi

# A hollow scan is a failure, never a pass.
empty=$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-code-empty.XXXXXX")
git -C "$empty" init -q
mkdir -p "$empty/zcutil/dev/code"
cp "$here/fixture/zcutil/dev/code/source_roots.def" "$empty/zcutil/dev/code/"
rc=0
(cd "$empty" && "$tb/zcl-dev-code" map >/dev/null 2>&1) || rc=$?
rm -rf "$empty"
if [ "$rc" = 2 ]; then echo "ok   hollow scan exits 2"; else echo "FAIL hollow scan exit $rc, wanted 2"; fails=$((fails + 1)); fi

[ "$fails" -eq 0 ] || { echo "$fails zcl-dev-code test(s) failed"; exit 1; }
echo "zcl-dev-code tests: OK"
