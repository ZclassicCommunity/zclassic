#!/bin/sh
# Fixture tests for zcl-dev wiki, read, lessons and know: a throwaway git repository with a doc/
# tree and a source tree, golden outputs, and one fixture per FACTS validator defect.
# usage: sh test/run.sh <bindir>      UPDATE=1 rewrites the golden files.
set -eu
bindir=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
jsonq=$bindir/jsonq
[ -x "$jsonq" ] || { echo "FAIL: $jsonq is missing (make -C zcutil/tools)" >&2; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-wiki-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
repo=$work/r
out=$work/out
mkdir -p "$repo"
fails=0
fail() { echo "FAIL $*"; fails=$((fails + 1)); }

# ---- the fixture repository ---------------------------------------------------------------
cd "$repo"
git init -q
mkdir -p doc/many doc/agent doc/.hidden scripts tools src/core src/tools src/vendor src/leveldb \
    depends build .hidden
cat >doc/README.md <<'EOF2'
# Fixture docs

See [the guide](guide.md) and [the site](https://example.org/a_(b)) plus ![the logo](x.png) and
<https://example.org/raw> and [a reference][1] then `code` stays.

Commands: `zcl-dev wiki`, `zcl-dev nosuchcmd`, `make -C tools`, `make -C missing`, `sh scripts/ok.sh`, `sh scripts/nope.sh`, `./scripts/ok.sh`, `echo hi`, `zcl-dev guide <paths>`

A second paragraph that the summary must not include.
EOF2
printf '# Guide\n\nHow to use the fixture.\n' >doc/guide.md
printf 'Setext Title\n============\n\nBody of setext.\n' >doc/setext.md
printf '# Hidden\n\nnot served\n' >doc/.hidden/x.md
printf '# Many\n\nSeventy pages.\n' >doc/many/README.md
i=1
while [ "$i" -le 70 ]; do
    n=$(printf '%02d' "$i")
    printf '# Page %s\n\nSummary of page %s.\n' "$n" "$n" >"doc/many/p$n.md"
    i=$((i + 1))
done
printf '#!/bin/sh\n# ok\ntrue\n' >scripts/ok.sh
printf 'all:\n\ttrue\n' >tools/Makefile
printf '# src\n\nThe daemon sources.\n' >src/AGENTS.md
printf '# Core\n\nIgnored: AGENTS.md is absent here, README wins.\n' >src/core/README.md
printf '/* Copyright 2020 Someone\n * Distributed under the MIT software license.\n * purpose: parse widgets from bytes */\nint a;\n' >src/core/a.c
printf '/* Copyright 2020 Someone */\n/* Frobnicates the gadget table. */\nint b;\n' >src/core/b.c
printf '// SPDX-License-Identifier: MIT\n// Computes the checksum of a block\nint c;\n' >src/core/c.h
printf 'int d;\n' >src/core/d.cpp
printf 'o' >src/core/x.o
printf '#!/bin/sh\n# Runs the focused tests\ntrue\n' >src/tools/run.sh
printf 'int v;\n' >src/vendor/v.c
printf 'int l;\n' >src/leveldb/l.c
printf 'x\n' >depends/d.mk
printf 'int o;\n' >build/o.c
printf 'int h;\n' >.hidden/h.c
printf 'int e;\n' >.hidden/e.c
printf 'outside
' >"$work/outside.txt"
ln -s "$work" src/escape
ln -s "$work/outside.txt" src/leak.txt
ln -s core src/alias
awk 'BEGIN { for (i = 0; i < 4000; i++) printf "line %05d of the big file\n", i }' >src/big.txt
printf 'a\0b\n' >src/blob.dat
printf 'secret\n' >src/wallet.dat
awk 'BEGIN { for (i = 0; i < 12000; i++) printf "\303\251" }' >src/utf8.txt
EM=$(printf '\342\200\224')
printf '# Lessons\n\nOPEN src/core/a.c %s a first lesson about widgets and a Deadlock in parsing.\nDONE src/core/b.c %s gadgets must stay sorted.\n' "$EM" "$EM" >doc/agent/LESSONS.md
printf '# Traps\n\n## (1) Core\n\nPaths: src/core/\n\n- Do not deadlock the gadget table.\n- Do not reorder widgets.\n' >doc/agent/TRAPS.md
cp "$here/facts.good.tsv" doc/agent/FACTS.tsv
git add -A
git -c user.name=t -c user.email=t@t commit -q -m fixture

# ---- helpers -----------------------------------------------------------------------------------
# run <alias> args...: the command in the fixture repository; stdout then stderr into $out.
run() {
    a=$1; shift
    rc=0
    "$bindir/zcl-dev-$a" "$@" >"$out" 2>"$out.err" || rc=$?
    cat "$out.err" >>"$out"
    return $rc
}
# case_ <name> <want-exit> <alias> args...: compare the combined output with golden/<name>.out
case_() {
    name=$1; want=$2; shift 2
    rc=0
    run "$@" || rc=$?
    if [ "$rc" -ne "$want" ]; then fail "$name: exit $rc, wanted $want"; cat "$out"; return; fi
    if [ "${UPDATE:-0}" = 1 ]; then cp "$out" "$here/golden/$name.out"; return; fi
    if diff -u "$here/golden/$name.out" "$out" >"$work/diff"; then echo "ok   $name"
    else fail "$name"; cat "$work/diff"; fi
}
# check <name> <expected> <actual>
check() {
    if [ "$2" = "$3" ]; then echo "ok   $1"; else fail "$1: wanted '$2', got '$3'"; fi
}
jv() { "$jsonq" "$@"; }

# ---- wiki: docs tree ----------------------------------------------------------------------------
case_ wiki-root 0 wiki
case_ wiki-many-p1 0 wiki many
case_ wiki-many-p2 0 wiki many --after=64
case_ wiki-page 0 wiki setext.md
case_ wiki-hidden 2 wiki .hidden
case_ wiki-dotdot 2 wiki ../etc
case_ wiki-unknown 2 wiki many/zz/yy
case_ wiki-bad-after 2 wiki --after=x
run wiki many; check wiki-many-p1-count 64 "$(grep -c '^  p[0-9]' "$out")"
run wiki many --after=64; check wiki-many-p2-count 6 "$(grep -c '^  p[0-9]' "$out")"
check wiki-many-p2-no-next 0 "$(grep -c '^next:' "$out")"
run wiki many; check wiki-many-next 'next: zcl-dev wiki many --after=64' "$(grep '^next:' "$out")"
# commands: only those that resolve (zcl-dev wiki exists beside the binary)
run wiki; cmds=$(sed -n '/^commands:/,/^children:/p' "$out" | grep '^  ' | tr '\n' '|')
check wiki-commands-resolve '  zcl-dev wiki|  make -C tools|  sh scripts/ok.sh|  ./scripts/ok.sh|  zcl-dev guide <paths>|' "$cmds"
# links rendered as plain text, the second paragraph left out
run wiki; check wiki-summary-links \
    'summary: See the guide and the site plus the logo and https://example.org/raw and a reference then `code` stays.' \
    "$(grep '^summary:' "$out")"
# JSON replies
run wiki --json many; json=$(cat "$out")
check wiki-json-ok true "$(printf '%s' "$json" | jv get ok)"
check wiki-json-children 64 "$(printf '%s' "$json" | jv count children)"
check wiki-json-total 70 "$(printf '%s' "$json" | jv get total)"
check wiki-json-next 'zcl-dev wiki many --after=64' "$(printf '%s' "$json" | jv get next)"
check wiki-json-size 1 "$([ "$(wc -c <"$out")" -lt 16384 ] && echo 1 || echo 0)"
run wiki --json .hidden || true
check wiki-json-refusal EXCLUDED_PATH "$(sed -n '1p' "$out" | jv get code)"

# ---- wiki: source tree --------------------------------------------------------------------------
case_ code-root 0 wiki code
case_ code-src 0 wiki code/src
case_ code-core 0 wiki code/src/core
case_ code-tools 0 wiki code/src/tools
case_ code-vendor 2 wiki code/src/vendor
case_ code-leveldb 2 wiki code/src/leveldb
case_ code-depends 2 wiki code/depends
case_ code-build 2 wiki code/build
case_ code-dot 2 wiki code/.hidden
case_ code-escape 2 wiki code/src/escape
case_ code-unknown 2 wiki code/src/nothing/here
run wiki code/src; check code-src-no-vendor 0 "$(grep -c 'vendor\|leveldb\|escape\|alias\|leak' "$out" || true)"
run wiki code/src/core; check code-core-no-object 0 "$(grep -c 'x\.o' "$out" || true)"

# ---- read ---------------------------------------------------------------------------------------
case_ read-small 0 read doc/guide.md
case_ read-chunk-first 0 read src/big.txt --bytes=100
case_ read-offset-past-end 2 read src/big.txt --offset=999999
case_ read-binary 2 read src/blob.dat
case_ read-dotdot 2 read ../x
case_ read-git 2 read .git/config
case_ read-secret 2 read src/wallet.dat
case_ read-dir 2 read src
case_ read-escape 2 read src/leak.txt
case_ read-missing 2 read src/nope.txt
case_ read-absolute 2 read /etc/passwd
# chunks reassemble to the file
: >"$work/joined"
size=$(wc -c <src/big.txt); off=0
while [ "$off" -lt "$size" ]; do
    run read src/big.txt --offset=$off --bytes=15849
    sed '1d;/^# next:/d' "$out" >>"$work/joined"
    off=$((off + 15849))
done
check read-reassemble 1 "$(cmp -s "$work/joined" src/big.txt && echo 1 || echo 0)"
run read src/big.txt --bytes=15849; check read-chunk-bytes 15849 "$(sed '1d;/^# next:/d' "$out" | wc -c | tr -d ' ')"
run read src/big.txt --bytes=15849; check read-next-hint '# next: zcl-dev read src/big.txt --offset=15849' "$(grep '^# next:' "$out")"
run read src/big.txt --json; check read-json-size 1 "$([ "$(wc -c <"$out")" -lt 16384 ] && echo 1 || echo 0)"
check read-json-bytes 14812 "$(jv get bytes <"$out")"
run read src/big.txt --json --offset=100000; check read-json-eof true "$(jv get eof <"$out")"
run read src/utf8.txt --bytes=1001 --json; check read-utf8-boundary 1000 "$(jv get bytes <"$out")"

# ---- lessons ------------------------------------------------------------------------------------
case_ lessons-find 0 lessons find deadlock
case_ lessons-find-case 0 lessons find DEADLOCK gadget
case_ lessons-find-none 0 lessons find zzzznothing
case_ lessons-find-usage 2 lessons find
run lessons find deadlock --json; check lessons-json-matches 2 "$(jv get matches <"$out")"
check lessons-json-first 'doc/agent/LESSONS.md' "$(jv get results[0].file <"$out" | tr -d '"')"
# every file gets a share of the 8 hits
i=1; : >"$work/many"
while [ "$i" -le 12 ]; do printf 'OPEN src/core/a.c %s common marker lesson %s with enough text\n' "$EM" "$i" >>"$work/many"; i=$((i + 1)); done
cp doc/agent/LESSONS.md "$work/LESSONS.save"
cat "$work/many" >>doc/agent/LESSONS.md
printf -- '- common marker trap\n' >>doc/agent/TRAPS.md
run lessons find common marker
check lessons-cap-hits 8 "$(grep -c '^doc/agent/' "$out")"
check lessons-cap-traps 1 "$(grep -c '^doc/agent/TRAPS.md' "$out")"
cp "$work/LESSONS.save" doc/agent/LESSONS.md
git checkout -q doc/agent/TRAPS.md
# add
case_ lessons-add-ok 0 lessons add OPEN src/core/b.c "a measured failure: the table lost an entry; the invariant is stable order"
check lessons-add-line "OPEN src/core/b.c $EM a measured failure: the table lost an entry; the invariant is stable order" "$(tail -n 1 doc/agent/LESSONS.md)"
case_ lessons-add-dup 2 lessons add OPEN src/core/b.c "a measured failure: the table lost an entry; the invariant is stable order"
case_ lessons-add-done 2 lessons add DONE src/core/b.c "a measured failure with an invariant that holds"
case_ lessons-add-untracked 2 lessons add OPEN src/core/nope.c "a measured failure with an invariant that holds"
case_ lessons-add-multiline 2 lessons add OPEN src/core/b.c "first line of a failure
second line that must not be written"
case_ lessons-add-short 2 lessons add OPEN src/core/b.c "too short"
case_ lessons-add-badpath 2 lessons add OPEN "src/core/b.c; rm -rf x" "a measured failure with an invariant that holds"
case_ lessons-add-usage 2 lessons add OPEN src/core/b.c
# a file without a final newline still gets a line of its own
printf 'OPEN src/core/a.c %s no trailing newline here' "$EM" >doc/agent/LESSONS.md
run lessons add OPEN src/core/c.h "another measured failure with an invariant"
check lessons-add-newline 2 "$(grep -c '' doc/agent/LESSONS.md)"
cp "$work/LESSONS.save" doc/agent/LESSONS.md

# ---- know ---------------------------------------------------------------------------------------
case_ know-subject 0 know src/core/a.c
case_ know-object 0 know widgets
case_ know-unknown 0 know no-such-term
case_ know-usage 2 know
run know --json widgets; check know-json-known KNOWN "$(jv get confidence <"$out" | tr -d '"')"
run know --json no-such-term; check know-json-unknown UNKNOWN "$(jv get confidence <"$out" | tr -d '"')"
case_ know-check-ok 0 know --check
run know --check --json; check know-check-json true "$(jv get ok <"$out")"
# each validator defect, one fixture each; the good table is the base
mkdir -p bad
T=$(printf '	')
defect() { # defect <name> <want-exit> <sed-script>
    sed "$3" doc/agent/FACTS.tsv >"bad/$1.tsv"
    case_ "know-check-$1" "$2" know --check --facts="bad/$1.tsv"
}
defect relation 1 "s|^src/core/a.c${T}needs|src/core/a.c${T}noodles|"
defect context 1 "s/${T}build${T}/${T}nowhere${T}/"
defect undeclared 1 "s/^widgets${T}selects${T}gadgets/widgets${T}selects${T}gizmos/"
defect untracked-path 1 "s|^#!terms src/core/a.c|#!terms src/core/gone.c src/core/a.c|"
defect duplicate 1 "/^widgets${T}selects/p"
defect unused 1 "s|^#!terms src/core/a.c|#!terms spare src/core/a.c|"
defect fields 1 "s/${T}a needs widgets to parse$//"
defect confidence 1 "s/${T}OBSERVED${T}/${T}UNKNOWN${T}/"
defect bad-token 1 "s|^#!terms src/core/a.c|#!terms Bad!Term src/core/a.c|"
defect dup-declaration 1 's/^#!relations needs/#!relations needs needs/'
grep '^#' doc/agent/FACTS.tsv >bad/hollow.tsv
case_ know-check-hollow 2 know --check --facts=bad/hollow.tsv
case_ know-check-missing 2 know --check --facts=bad/none.tsv
# an empty git list is hollow too
mkdir "$work/empty"
rc=0; (cd "$work/empty" && git init -q && "$bindir/zcl-dev-know" --check --facts=x.tsv) >/dev/null 2>&1 || rc=$?
check know-check-empty-repo 2 "$rc"
rc=0; (cd "$work/empty" && "$bindir/zcl-dev-lessons" add OPEN a.c "text that is long enough to pass") >/dev/null 2>&1 || rc=$?
check lessons-add-empty-repo 2 "$rc"
# -C and --purpose
rc=0; "$bindir/zcl-dev-know" -C "$repo" --check >/dev/null 2>&1 || rc=$?
check know-dash-C 0 "$rc"
for a in wiki read lessons know; do
    check "purpose-$a" 1 "$("$bindir/zcl-dev-$a" --purpose | grep -c '.')"
done

# ---- through the dispatcher, when it is built next to the tools ---------------------------------
if [ -x "$bindir/zcl-dev" ]; then
    rc=0; "$bindir/zcl-dev" -C "$repo" wiki code/src/core >"$out" 2>&1 || rc=$?
    check dispatch-wiki 0 "$rc"
    check dispatch-wiki-first 'topic: code/src/core' "$(sed -n 1p "$out")"
    "$bindir/zcl-dev" help | grep -q '^  wiki ' && echo "ok   dispatch-help-wiki" || fail "dispatch-help-wiki"
fi

if [ "$fails" -ne 0 ]; then echo "wiki tests: $fails failed"; exit 1; fi
echo "wiki tests: all passed"
