#!/bin/sh
# zcl-dev-compdb against fixture Makefiles whose compiler is a fake `g++` that `make -n` never runs.
# usage: sh test/run.sh <zcl-dev-compdb> [--update]   (goldens in test/golden/)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tool=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
update=${2:-}
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-compdb-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
work=$(cd "$work" && pwd -P)
fail() { echo "FAIL compdb: $*" >&2; exit 1; }

# fixture <case> [subdir/]<file> < content   (a leading @@ in the content becomes a tab)
fixture() {
    mkdir -p "$work/$1/src/$(dirname "$2")"
    awk '{ sub(/^@@/, "\t"); print }' >"$work/$1/src/$2"
}
touch_src() { c=$1; shift; for f in "$@"; do : >"$work/$c/src/$f"; done; }

# compare <case> <rc>: golden = JSON file, then stderr, then the exit status, with the work dir masked
compare() {
    name=$1; rc=$2
    {
        if [ -f "$work/$name.json" ]; then cat "$work/$name.json"; fi
        echo "--- stderr"
        cat "$work/$name.err"
        echo "exit=$rc"
    } | sed "s|$work|@W@|g" >"$work/$name.out"
    if [ "$update" = --update ]; then cp "$work/$name.out" "$here/golden/$name.txt"; return 0; fi
    diff -u "$here/golden/$name.txt" "$work/$name.out" >&2 || fail "$name differs from golden"
}
run() { # run <case> [tool args after --build-dir]
    name=$1; shift
    rc=0
    (cd "$work" && "$tool" --build-dir "$work/$name" --out "$work/$name.json" "$@") >"$work/$name.stdout" 2>"$work/$name.err" || rc=$?
    compare "$name" "$rc"
    echo "$rc" >"$work/$name.rc"
}
want_rc() { [ "$(cat "$work/$1.rc")" = "$2" ] || fail "$1 exit $(cat "$work/$1.rc"), want $2"; }

# an in-directory compile, C and C++
fixture indir Makefile <<'EOF'
all: a.o z.o
a.o: a.cc
@@g++ -DFOO=1 -I. -MT a.o -MD -MP -MF .deps/a.Tpo -c -o a.o a.cc
z.o: z.c
@@gcc -O2 -c -o z.o z.c
EOF
touch_src indir a.cc z.c
run indir; want_rc indir 0

# a recursive $(MAKE) -C sub gives the right directory, and the directory is restored afterwards
fixture recursive Makefile <<'EOF'
all: top.o sub after.o
top.o: top.cc
@@g++ -c -o top.o top.cc
after.o: after.cc
@@g++ -c -o after.o after.cc
sub:
@@$(MAKE) -C sub
.PHONY: sub
EOF
fixture recursive sub/Makefile <<'EOF'
all: leaf.o
leaf.o: leaf.cc
@@g++ -DLEAF -c -o leaf.o leaf.cc
EOF
touch_src recursive top.cc after.cc sub/leaf.cc
run recursive; want_rc recursive 0

# a libtool --mode=compile line behind a depbase backtick and a trailing mv
fixture libtool Makefile <<'EOF'
all: a.lo
a.lo: a.cc
@@depbase=`echo a.lo | sed 's|[^/]*$$||'`;\
@@/bin/sh ./libtool --tag=CXX --mode=compile g++ -DHAVE_CONFIG_H -MT a.lo -MD -MP -MF $$depbase.Tpo -c -o a.lo a.cc &&\
@@mv -f $$depbase.Tpo $$depbase.Plo
EOF
touch_src libtool a.cc
run libtool; want_rc libtool 0

# a leading ccache is dropped
fixture ccache Makefile <<'EOF'
all: a.o
a.o: a.cc
@@ccache g++ -DCC=1 -c -o a.o a.cc
EOF
touch_src ccache a.cc
run ccache; want_rc ccache 0

# quoted defines
fixture quoted Makefile <<'EOF'
all: q.o
q.o: q.cc
@@g++ -DPACKAGE_STRING="\"x y\"" -DQ='a b' -DE=a\ b -c -o q.o q.cc
EOF
touch_src quoted q.cc
run quoted; want_rc quoted 0

# a continuation line
fixture continued Makefile <<'EOF'
all: c.o
c.o: c.cc
@@g++ -DA \
@@  -DB -c -o c.o c.cc
EOF
touch_src continued c.cc
run continued; want_rc continued 0

# the same source twice: the first is kept, the second counted
fixture duplicate Makefile <<'EOF'
all: a1.o a2.o
a1.o: a.cc
@@g++ -DFIRST -c -o a1.o a.cc
a2.o: a.cc
@@g++ -DSECOND -c -o a2.o a.cc
EOF
touch_src duplicate a.cc
run duplicate; want_rc duplicate 0

# a leftover $( is skipped and counted
fixture subst Makefile <<'EOF'
all: good.o s.o
good.o: good.cc
@@g++ -c -o good.o good.cc
s.o: s.cc
@@g++ -DV=$$(echo 1) -c -o s.o s.cc
EOF
touch_src subst good.cc s.cc
run subst; want_rc subst 0

# an empty project is hollow: exit 2
fixture empty Makefile <<'EOF'
all:
@@@true
EOF
run empty; want_rc empty 2

# a build directory that does not exist is hollow too
rc=0
(cd "$work" && "$tool" --build-dir "$work/nowhere" --out "$work/nowhere.json") >/dev/null 2>"$work/nowhere.err" || rc=$?
[ "$rc" = 2 ] || fail "missing build dir exit $rc, want 2"
[ ! -f "$work/nowhere.json" ] || fail "hollow run wrote a file"

# --check: fresh, stale (edited), stale (missing)
rc=0; (cd "$work" && "$tool" --check --build-dir "$work/indir" --out "$work/indir.json") >/dev/null 2>"$work/chk.err" || rc=$?
[ "$rc" = 0 ] || fail "--check on a fresh file exit $rc"
grep -q 'fresh' "$work/chk.err" || fail "--check did not say fresh"
echo ' ' >>"$work/indir.json"
rc=0; (cd "$work" && "$tool" --check --build-dir "$work/indir" --out "$work/indir.json") >/dev/null 2>"$work/chk.err" || rc=$?
[ "$rc" = 1 ] || fail "--check on an edited file exit $rc, want 1"
grep -q 'stale' "$work/chk.err" || fail "--check did not say stale"
rm "$work/indir.json"
rc=0; (cd "$work" && "$tool" --check --build-dir "$work/indir" --out "$work/indir.json") >/dev/null 2>&1 || rc=$?
[ "$rc" = 1 ] || fail "--check on a missing file exit $rc, want 1"
[ ! -f "$work/indir.json" ] || fail "--check wrote the file"

# no make: UNAVAILABLE, exit 2
rc=0; (cd "$work" && ZCL_COMPDB_MAKE="$work/no-such-make" "$tool" --build-dir "$work/indir" --out "$work/x.json") >/dev/null 2>"$work/nomake.err" || rc=$?
[ "$rc" = 2 ] || fail "no make exit $rc, want 2"
grep -q UNAVAILABLE "$work/nomake.err" || fail "no make did not say UNAVAILABLE"

# options and exits
"$tool" --purpose | grep -q compile_commands || fail "--purpose"
rc=0; "$tool" --nonsense >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "bad flag exit $rc, want 2"
rc=0; "$tool" --out >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "missing value exit $rc, want 2"
echo "compdb tests ok"
