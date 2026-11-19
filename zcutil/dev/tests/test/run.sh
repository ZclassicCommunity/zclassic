#!/bin/sh
# Fixture tests for zcl-dev-tests (tests, t-fast, t-list, check-tests): golden outputs on a small
# tree with two fake Boost files, one gtest file, rules and fake test binaries.
# usage: sh test/run.sh <bin-dir>      UPDATE=1 rewrites the golden files.
# ZCL_TESTS_BIN=<dir with test/test_bitcoin> also verifies the Boost a:b filter on a real build.
set -eu
bindir=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
root=$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-tests.XXXXXX")
trap 'rm -rf "$root"' EXIT
fails=0
n=0
w=""
# fresh <name>: a new committed copy of the fixture in $root/<name>, with fake test binaries
fresh() {
    w=$root/$1
    mkdir -p "$w"
    cp -R "$here/fixture/." "$w/"
    git -C "$w" init -q
    git -C "$w" add -A
    git -C "$w" -c user.name=t -c user.email=t@t commit -q -m fixture
    git -C "$w" update-ref refs/heads/nobase "$(git -C "$w" -c user.name=t -c user.email=t@t commit-tree "$(git -C "$w" hash-object -t tree -w /dev/null)" -m empty)"
    fakes
}
fakes() {
    mkdir -p "$w/src/test"
    cat >"$w/src/test/test_bitcoin" <<'FAKE'
#!/bin/sh
echo "fake test_bitcoin $*"
f=""
for a in "$@"; do case $a in --run_test=*) f=${a#--run_test=} ;; esac; done
case $f in *:*) [ -z "${FAKE_REJECT:-}" ] || { echo "fake: filter rejected" >&2; exit 1; } ;; esac
oldifs=$IFS; IFS=:
for s in $f; do [ "$s" = "${FAKE_DROP:-}" ] || echo "x.cpp(1): Entering test suite \"$s\""; done
IFS=$oldifs
exit "${FAKE_RC:-0}"
FAKE
    # a googletest look-alike: FooSuite and FooFixture are TEST/TEST_F suites; FooParam is TEST_P
    # (instantiated as Inst/FooParam), so only a */FooParam.* pattern finds its test, as in real gtest
    cat >"$w/src/zcash-gtest" <<"FAKE"
#!/bin/sh
echo "fake zcash-gtest $*"
set -f
f="*"
for a in "$@"; do case $a in --gtest_filter=*) f=${a#--gtest_filter=} ;; esac; done
out=""
oldifs=$IFS; IFS=:
for p in $f; do
    case $p in
        "*") out="$out FooSuite.a FooFixture.b Inst/FooParam.c/0" ;;
        "*/FooParam.*") out="$out Inst/FooParam.c/0" ;;
        FooParam.*) ;;
        *.\*) s=${p%.\*}; [ "$s" = "${FAKE_GDROP:-}" ] || out="$out $s.t" ;;
    esac
done
IFS=$oldifs
n=0
for t in $out; do n=$((n + 1)); done
[ -z "${FAKE_ZERO:-}" ] || { out=""; n=0; }
echo "[==========] Running $n tests from suites."
for t in $out; do echo "[ RUN      ] $t"; echo "[       OK ] $t (0 ms)"; done
echo "[  PASSED  ] $n tests."
exit "${FAKE_RC:-0}"
FAKE
    printf '#!/bin/sh\n:\n' >"$w/src/zclassicd"
    chmod +x "$w/src/test/test_bitcoin" "$w/src/zcash-gtest" "$w/src/zclassicd"
    # sources older than the binaries, as on a built tree
    git -C "$w" ls-files | while read -r f; do touch -t 200001010000 "$w/$f"; done
}
# case_ <name> <expected-exit> <cmd...>: run, compare stdout+stderr with golden/<name>.out
case_() {
    name=$1; want=$2; shift 2
    n=$((n + 1))
    rc=0
    "$@" >"$root/out" 2>"$root/err" || rc=$?
    cat "$root/err" >>"$root/out"
    if [ "$rc" -ne "$want" ]; then echo "FAIL $name: exit $rc, wanted $want"; cat "$root/out"; fails=$((fails + 1)); return; fi
    if [ "${UPDATE:-0}" = 1 ]; then cp "$root/out" "$here/golden/$name.out"; return; fi
    if diff -u "$here/golden/$name.out" "$root/out"; then echo "ok   $name"; else echo "FAIL $name"; fails=$((fails + 1)); fi
}
t() { "$bindir/zcl-dev-tests" -C "$w" "$@"; }
# jsoncap: a many-path --json answer is capped under 16 KiB and says what it left out
jsoncap() {
    out=$(t --as=tests --json $many)
    [ "${#out}" -lt 16384 ] && echo "under 16 KiB" || echo "over 16 KiB: ${#out}"
    printf '%s\n' "$out" | grep -o "\"paths_omitted\":[0-9]*"
}
tf() { "$bindir/zcl-dev-t-fast" -C "$w" "$@"; }
tl() { "$bindir/zcl-dev-t-list" -C "$w" "$@"; }
# check-tests reads tracked files and a base ref: ct stages everything first and compares with `nobase`, an
# empty commit made by fresh (a base that resolves and has no baseline); ctn stages nothing.
ct() { git -C "$w" add -A; "$bindir/zcl-dev-check-tests" -C "$w" --base=nobase "$@"; }
ctn() { "$bindir/zcl-dev-check-tests" -C "$w" --base=nobase "$@"; }
mkdir -p "$here/golden"

fresh base
# ---- tests
case_ tests-source 0 t --as=tests src/foo.cpp
case_ tests-header-json 0 t --as=tests --json src/foo.h
case_ tests-test-file 0 t --as=tests src/test/bar_tests.cpp
case_ tests-broad 0 t --as=tests src/core/engine.cpp
case_ tests-narrowed 0 t --as=tests src/narrow.cpp
case_ tests-unmapped 0 t --as=tests src/zzz.cpp
case_ tests-doc 0 t --as=tests doc/x.md
case_ tests-qa 0 t --as=tests qa/rpc-tests/y.sh
case_ tests-no-path 2 t --as=tests
case_ tests-bad-option 2 t --as=tests --bogus
case_ tests-subdir 0 sh -c "cd '$w/src' && '$bindir/zcl-dev-tests' --as=tests foo.cpp"
# ---- t-list
case_ t-list 0 tl
case_ t-list-ci 0 tl ci
case_ t-list-boost-json 0 tl --json boost
case_ t-list-page1 0 env ZCL_DEV_PAGE_BYTES=60 "$bindir/zcl-dev-t-list" -C "$w"
case_ t-list-page2 0 env ZCL_DEV_PAGE_BYTES=60 "$bindir/zcl-dev-t-list" -C "$w" --after=3
case_ t-list-page-json 0 env ZCL_DEV_PAGE_BYTES=60 "$bindir/zcl-dev-t-list" -C "$w" --json --after=2
# ---- t-fast, dry runs print the exact argv
case_ t-fast-dry 0 tf --dry-run src/foo.cpp src/test/bar_tests.cpp
case_ t-fast-dry-json 0 tf --dry-run --json src/foo.cpp
case_ t-fast-dry-broad 0 tf --dry-run src/core/engine.cpp
case_ t-fast-dry-narrow 0 tf --dry-run --narrow src/core/engine.cpp
case_ t-fast-dry-narrowed-rule 0 tf --dry-run src/narrow.cpp
case_ t-fast-dry-qa 0 tf --dry-run qa/rpc-tests/x.sh qa/rpc-tests/y.sh
case_ t-fast-dry-no-qa 0 tf --dry-run --no-qa qa/rpc-tests/x.sh
case_ t-fast-dry-doc 0 tf --dry-run doc/x.md
case_ t-fast-dry-bindir 0 tf --dry-run --bin=build/out src/foo.cpp
case_ t-fast-unsafe-base 2 tf --dry-run --changed='a;b'
case_ t-fast-no-path 2 tf --dry-run
case_ t-fast-empty-diff 2 tf --dry-run --changed=HEAD
# ---- t-fast, real runs against the fake binaries
case_ t-fast-run 0 tf src/foo.cpp src/test/bar_tests.cpp
case_ t-fast-run-json 0 tf --json src/foo.cpp
case_ t-fast-run-qa 0 tf qa/rpc-tests/x.sh
case_ t-fast-run-broad 0 tf src/core/engine.cpp
case_ t-fast-run-fail 1 env FAKE_RC=1 "$bindir/zcl-dev-t-fast" -C "$w" src/foo.cpp
case_ t-fast-run-fallback 0 env FAKE_DROP=bar_extra "$bindir/zcl-dev-t-fast" -C "$w" src/foo.cpp src/test/bar_tests.cpp
case_ t-fast-run-rejected 0 env FAKE_REJECT=1 "$bindir/zcl-dev-t-fast" -C "$w" src/foo.cpp src/test/bar_tests.cpp
# gtest: TEST_P suites need the */Suite.* pattern; a run that ran nothing is a failure
case_ t-fast-run-gtest 0 tf src/gtest/test_foo.cpp
case_ t-fast-run-gtest-zero 1 env FAKE_ZERO=1 "$bindir/zcl-dev-t-fast" -C "$w" src/gtest/test_foo.cpp
case_ t-fast-run-gtest-missing 1 env FAKE_GDROP=FooSuite "$bindir/zcl-dev-t-fast" -C "$w" src/gtest/test_foo.cpp
case_ t-fast-run-gtest-broad-zero 1 env FAKE_ZERO=1 "$bindir/zcl-dev-t-fast" -C "$w" src/core/engine.cpp
# qa argument forms: --bin/--work, a positional bindir, none; a sourced fragment runs its owner on its scenarios
case_ t-fast-dry-qa-forms 0 tf --dry-run qa/rpc-tests/x.sh qa/rpc-tests/p.sh qa/rpc-tests/y.sh qa/rpc-tests/w_scn1.sh
case_ t-fast-dry-qa-bindir 0 tf --dry-run --bin=build/out qa/rpc-tests/x.sh qa/rpc-tests/p.sh
case_ tests-qa-fragment 0 t --as=tests qa/rpc-tests/w_scn1.sh
mkdir -p "$w/sub/qa/rpc-tests"
printf "#!/bin/sh
" >"$w/sub/qa/rpc-tests/w_scn1.sh"
case_ t-fast-dry-fragment-anchored 0 tf --dry-run sub/qa/rpc-tests/w_scn1.sh
many=""
for i in $(seq 1 400); do many="$many src/long_directory_name/file_$i.cpp"; done
mkdir -p "$w/src/long_directory_name"
case_ tests-json-capped 0 jsoncap
# changed against a base commit
printf 'int foo(void) { return 2; }\n' >"$w/src/foo.cpp"
git -C "$w" -c user.name=t -c user.email=t@t commit -q -am change
touch -t 200001010000 "$w/src/foo.cpp"
case_ t-fast-changed-dry 0 tf --dry-run --changed=HEAD~1
# a binary older than a changed source, and a missing binary: exit 3 with the exact make line
touch -t 203001010000 "$w/src/foo.cpp"
case_ t-fast-stale 3 tf src/foo.cpp
case_ t-fast-stale-dry 0 tf --dry-run src/foo.cpp
rm -f "$w/src/test/test_bitcoin"
case_ t-fast-missing 3 tf src/foo.cpp src/gtest/test_foo.cpp
case_ t-fast-missing-dry 0 tf --dry-run src/foo.cpp
# ---- check-tests
fresh ok
case_ check-tests-ok 0 ct
case_ check-tests-ok-json 0 ct --json
fresh unreg
printf 'BOOST_AUTO_TEST_SUITE(new_tests)\n' >"$w/src/test/new_tests.cpp"
printf 'TEST(Newer, a) {}\n' >"$w/src/gtest/test_new.cpp"
case_ check-tests-unregistered 1 ct
fresh dup
printf 'BOOST_AUTO_TEST_SUITE(foo_tests)\n' >"$w/src/test/dup_tests.cpp"
sed 's|test/bar_tests.cpp|test/bar_tests.cpp test/dup_tests.cpp|' "$w/src/Makefile.test.include" >"$w/mk.tmp"
mv "$w/mk.tmp" "$w/src/Makefile.test.include"
case_ check-tests-duplicate-suite 1 ct
fresh dangling
sed 's|test/bignum.h|test/gone.h|' "$w/src/Makefile.test.include" >"$w/mk.tmp"
mv "$w/mk.tmp" "$w/src/Makefile.test.include"
case_ check-tests-dangling 1 ct
fresh rules
printf 'src/foo.cpp\tboost:nosuch gtest:Nope qa:qa/rpc-tests/none.sh bogus\nnothing/*\tnarrow\n' >>"$w/zcutil/dev/tests.rules"
case_ check-tests-bad-rules 1 ct
fresh qa
printf '#!/bin/sh\n' >"$w/qa/rpc-tests/orphan.sh"
case_ check-tests-unreachable-qa 1 ct
printf 'qa/rpc-tests/orphan.sh\n' >>"$w/zcutil/dev/tests/baseline"
case_ check-tests-baselined-qa 0 ct
printf 'qa/rpc-tests/y.sh\n' >>"$w/zcutil/dev/tests/baseline"
case_ check-tests-stale-baseline 1 ct
case_ check-tests-update-baseline 0 ct --update-baseline
case_ check-tests-after-update 0 ct
printf '#!/bin/sh\n' >"$w/qa/rpc-tests/another.sh"
case_ check-tests-update-refused 1 ct --update-baseline
fresh narrowbad
printf "src/main.*\tnarrow\n" >>"$w/zcutil/dev/tests.rules"
case_ check-tests-narrow-forbidden 1 ct
fresh narrowall
printf 'src/core/*\tboost:foo_tests narrow\n' >>"$w/zcutil/dev/tests.rules"
case_ check-tests-narrow-all-not-denylisted 1 ct
fresh untracked
printf 'src/ghost.cpp\tboost:foo_tests\n' >>"$w/zcutil/dev/tests.rules"
printf 'int g;\n' >"$w/src/ghost.cpp"
case_ check-tests-untracked-dead-rule 1 ctn
fresh comment
printf "#!/bin/sh\n" >"$w/qa/rpc-tests/send.sh"
printf "#!/bin/sh\n" >"$w/qa/rpc-tests/orphan2.sh"
printf "    sh qa/rpc-tests/zslp_send.sh\n    run_one # orphan2.sh is mentioned in a trailing comment\n# qa/rpc-tests/orphan2.sh\n" >>"$w/zcutil/local-ci.sh"
case_ check-tests-unreachable-word 1 ct
fresh grown
git -C "$w" -c user.name=t -c user.email=t@t commit -q --allow-empty -m base
printf "#!/bin/sh\n" >"$w/qa/rpc-tests/late.sh"
printf "qa/rpc-tests/late.sh\n" >>"$w/zcutil/dev/tests/baseline"
case_ check-tests-baseline-default-base 1 sh -c "git -C '$w' add -A; '$bindir/zcl-dev-check-tests' -C '$w'"
case_ check-tests-baseline-unknown-ref 2 ct --base=nonexistent
case_ check-tests-baseline-unsafe-ref 2 ct --base='a;b'
case_ check-tests-baseline-base-without-baseline 0 ct
case_ check-tests-baseline-grew 1 ct --base=HEAD
fresh page
for i in 1 2 3 4 5; do printf '#!/bin/sh\n' >"$w/qa/rpc-tests/orph$i.sh"; done
git -C "$w" add -A
case_ check-tests-page 1 env ZCL_DEV_PAGE_BYTES=200 "$bindir/zcl-dev-check-tests" -C "$w" --base=nobase
case_ check-tests-page-next 1 env ZCL_DEV_PAGE_BYTES=200 "$bindir/zcl-dev-check-tests" -C "$w" --base=nobase --after=2
fresh hollow
git -C "$w" rm -q -r --cached src/test src/gtest
rm -rf "$w/src/test" "$w/src/gtest"
case_ check-tests-hollow 2 ct
fresh norules
rm "$w/zcutil/dev/tests.rules"
case_ check-tests-no-rules 2 ct
# ---- dispatch through zcl-dev and the command names
if [ -x "$bindir/zcl-dev" ]; then
    fresh disp
    out=$("$bindir/zcl-dev" -C "$w" tests src/foo.cpp) || true
    want=$("$bindir/zcl-dev-tests" -C "$w" --as=tests src/foo.cpp) || true
    n=$((n + 1))
    if [ "$out" = "$want" ] && [ -n "$out" ]; then echo "ok   dispatch-tests"; else echo "FAIL dispatch-tests: $out"; fails=$((fails + 1)); fi
    out=$("$bindir/zcl-dev" help | grep -c -E '^  (tests|t-fast|t-list|check-tests) ') || true
    n=$((n + 1))
    if [ "$out" = 4 ]; then echo "ok   dispatch-help"; else echo "FAIL dispatch-help: $out of 4 listed"; fails=$((fails + 1)); fi
fi
for c in tests t-fast t-list check-tests; do
    n=$((n + 1))
    p=$("$bindir/zcl-dev-$c" --purpose)
    if [ -n "$p" ]; then echo "ok   purpose-$c"; else echo "FAIL purpose-$c"; fails=$((fails + 1)); fi
done
# ---- the real Boost accepts --run_test=a:b and runs every suite named
if [ -n "${ZCL_TESTS_BIN:-}" ] && [ -x "$ZCL_TESTS_BIN/test/test_bitcoin" ]; then
    n=$((n + 1))
    out=$("$ZCL_TESTS_BIN/test/test_bitcoin" --run_test=bech32_tests:base58_tests --log_level=test_suite 2>&1) || true
    if printf '%s\n' "$out" | grep -q 'Entering test suite "bech32_tests"' && printf '%s\n' "$out" | grep -q 'Entering test suite "base58_tests"'; then
        echo "ok   boost-multi-filter (real test_bitcoin accepts a:b)"
    else
        echo "FAIL boost-multi-filter: the real test_bitcoin did not run both suites"
        fails=$((fails + 1))
    fi
else
    echo "skip boost-multi-filter (set ZCL_TESTS_BIN=<dir with test/test_bitcoin>)"
fi
# ---- the real googletest names TEST_P tests Prefix/Suite.Name/n: the emitted */Suite.* pattern must find them
if [ -n "${ZCL_TESTS_BIN:-}" ] && [ -x "$ZCL_TESTS_BIN/zcash-gtest" ]; then
    n=$((n + 1))
    old=$("$ZCL_TESTS_BIN/zcash-gtest" --gtest_filter='Sha256Differential.*' 2>&1 | grep -c "Backends/Sha256Differential") || true
    out=$("$ZCL_TESTS_BIN/zcash-gtest" --gtest_filter='Sha256Differential.*:*/Sha256Differential.*' 2>&1 | grep -c "\[ RUN .*Backends/Sha256Differential") || true
    if [ "$old" = 0 ] && [ "$out" -gt 0 ]; then echo "ok   gtest-param-filter (Suite.* matches none of the TEST_P tests, */Suite.* runs $out)"
    else echo "FAIL gtest-param-filter: Suite.* ran $old, with */Suite.* ran $out"; fails=$((fails + 1)); fi
else
    echo "skip gtest-param-filter (set ZCL_TESTS_BIN=<dir with zcash-gtest>)"
fi
# ---- a hand-edited tests.rules cannot narrow a path that is not on the narrow allowlist, at run time
fresh narrowrt
printf "src/main.cpp\tboost:foo_tests narrow\n" >>"$w/zcutil/dev/tests.rules"
case_ tests-narrow-ignored-at-runtime 0 t --as=tests src/main.cpp
case_ t-fast-dry-narrow-ignored-at-runtime 0 tf --dry-run src/main.cpp
# ---- default base: origin/master, else merge-base with the upstream branch, else HEAD; each is said
fresh upbase
br=$(git -C "$w" branch --show-current)
git -C "$w" branch up
git -C "$w" config branch.$br.remote .
git -C "$w" config branch.$br.merge refs/heads/up
git -C "$w" -c user.name=t -c user.email=t@t commit -q --allow-empty -m more
case_ check-tests-default-base-upstream 0 sh -c "git -C \"$w\" add -A; \"$bindir/zcl-dev-check-tests\" -C \"$w\" 2>&1 | grep -c \"base: merge-base of HEAD with upstream\""
case_ check-tests-default-base-head 0 sh -c "git -C \"$w\" config --unset branch.$br.merge; git -C \"$w\" add -A; \"$bindir/zcl-dev-check-tests\" -C \"$w\" 2>&1 | grep -c \"base: HEAD\""
# ---- --json caps one element: a long path is cut, not printed whole
long=$(printf "src/%0600d.cpp" 0)
case_ tests-json-element-clamped 0 sh -c "\"$bindir/zcl-dev-tests\" -C \"$w\" --as=tests --json $long | grep -c \"\.\.\.\\\"\""
# ---- path arguments are canonicalized: no traversal form narrows a broad path
fresh traversal
case_ tests-traversal-dotdot 0 t --as=tests src/narrow.cpp/../core/engine.cpp
case_ tests-traversal-dot-segments 0 t --as=tests ./src//core/./engine.cpp
case_ tests-traversal-backslash 0 t --as=tests "src\narrow.cpp\..\core\engine.cpp"
case_ tests-traversal-absolute 0 t --as=tests "$w/src/narrow.cpp/../core/engine.cpp"
case_ tests-traversal-escape 2 t --as=tests src/../../etc/passwd
case_ tests-traversal-root 2 t --as=tests src/..
case_ tests-traversal-subdir 0 sh -c "cd \"$w/src\" && \"$bindir/zcl-dev-tests\" --as=tests narrow.cpp/../core/engine.cpp"
case_ t-fast-dry-traversal 0 tf --dry-run --no-qa src/narrow.cpp/../core/engine.cpp
case_ t-fast-dry-traversal-dir 0 tf --dry-run --no-qa src/narrow.cpp/x/../../core/engine.cpp
# a leaf on the allowlist still narrows, a directory below it does not
case_ t-fast-dry-narrow-leaf 0 tf --dry-run --no-qa src/narrow.cpp
# ---- an ignored narrow row is not folded into the narrowed sentence; why is clamped
fresh mixed
printf "src/main.cpp\tboost:foo_tests narrow\n" >>"$w/zcutil/dev/tests.rules"
case_ tests-mixed-ignored-note 0 t --as=tests src/narrow.cpp src/main.cpp
longp=$(printf "src/%030000d.cpp" 0)
case_ tests-why-clamped 0 sh -c "out=\$(\"$bindir/zcl-dev-tests\" -C \"$w\" --as=tests --json $longp); [ \${#out} -lt 16384 ] && echo under 16 KiB || echo over \${#out}"
if [ "$fails" -ne 0 ]; then echo "zcl-dev-tests: $fails of $n FAILED"; exit 1; fi
echo "zcl-dev-tests: all $n passed"
