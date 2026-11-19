#!/bin/sh
# zcl-doctor against a fake PATH of POSIX sh stubs: found, missing, wrong-version, fallback, JSON, exits.
# usage: sh test/run.sh <zcl-doctor> [--update]   (goldens in test/golden/)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
doc=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
update=${2:-}
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-doctor-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/root" "$work/home"
fail() { echo "FAIL doctor: $*" >&2; exit 1; }
stub() { printf '#!/bin/sh\n%s\n' "$2" >"$work/bin/$1"; chmod +x "$work/bin/$1"; }
for t in make autoconf automake libtoolize pkg-config m4 git curl patch apt-get; do stub "$t" 'echo "stub 1.0"'; done
stub g++ 'echo "g++ stub 13.0"'
stub cc 'echo "cc stub 14.0"'
run() { # run <name> [args...]: PATH is only the stub dir; output compared with golden/<name>.txt
    name=$1; shift; skip=0
    if [ "${1:-}" = --nogolden ]; then skip=1; shift; fi
    rc=0
    env -i PATH="$work/bin" HOME="$work/home" TMPDIR="$work" ZCL_DOCTOR_PKGMGR=apt-get \
        "$doc" --root="$work/root" "$@" >"$work/$name.out" 2>"$work/$name.err" || rc=$?
    echo "exit=$rc" >>"$work/$name.out"
    if [ $skip = 1 ]; then return 0; fi
    if [ "$update" = --update ]; then cp "$work/$name.out" "$here/golden/$name.txt"; return 0; fi
    diff -u "$here/golden/$name.txt" "$work/$name.out" >&2 || fail "$name differs from golden"
}
run tools-ok --group=tools
rm "$work/bin/automake"
run tools-no-automake --group=tools
grep -q 'fix: sudo apt-get install -y automake' "$work/tools-no-automake.out" || fail "no exact fix for automake"
[ "$(grep -c '^\[FAIL' "$work/tools-no-automake.out")" = 1 ] || fail "more than one red check"
stub automake 'echo "stub 1.0"'
stub g++ 'case "$*" in *-std=c++11*) exit 1;; esac; echo "g++ stub 4.8"'
run build-old-gxx --nogolden --group=build
grep -q '^\[FAIL    \] cxx11' "$work/build-old-gxx.out" || fail "old g++ not red"
stub g++ 'echo "g++ stub 13.0"'
stub cc 'case "$*" in *-std=c23*) exit 1;; esac; echo "cc stub 9.0"'
run build-c23-fallback --nogolden --group=build
grep -q '^\[advisory\] c23-std' "$work/build-c23-fallback.out" || fail "c23 fallback not advisory"
# JSON keys, paging, exit codes
rc=0; env -i PATH="$work/bin" HOME="$work/home" TMPDIR="$work" "$doc" --root="$work/root" --group=tools --json >"$work/j.out" || rc=$?
[ "$rc" = 0 ] || fail "json exit $rc"
grep -q '^{"schema":"zcl-doctor/1"' "$work/j.out" || fail "json schema key"
grep -q '"id":"automake","group":"tools","status":"ok"' "$work/j.out" || fail "json check row"
grep -q '"next_after":null' "$work/j.out" || fail "json next_after"
if [ -x "$here/../../../bin/jsonq" ]; then "$here/../../../bin/jsonq" count checks <"$work/j.out" >/dev/null 2>&1 || fail "jsonq cannot parse the report"; fi
rc=0; "$doc" --group=bogus >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "bad group exit $rc, want 2"
rc=0; "$doc" --nonsense >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "bad flag exit $rc, want 2"
rc=0; env -i PATH="$work/bin" HOME="$work/home" "$doc" --root="$work/root" --group=tools --after=999 >"$work/p.out" 2>"$work/p.err" || rc=$?
[ "$rc" = 2 ] || fail "--after past the end exit $rc, want 2"
for bad in -1 -100000 abc "" 1x; do
    rc=0; env -i PATH="$work/bin" HOME="$work/home" "$doc" --root="$work/root" --group=tools --after="$bad" >"$work/p.out" 2>"$work/p.err" || rc=$?
    [ "$rc" = 2 ] || fail "--after=$bad exit $rc, want 2"
    [ ! -s "$work/p.out" ] || fail "--after=$bad printed a report"
done
n=$(grep -c "^\[" "$work/tools-ok.out")
rc=0; env -i PATH="$work/bin" HOME="$work/home" "$doc" --root="$work/root" --group=tools --after="$n" >"$work/p.out" || rc=$?
[ "$rc" = 0 ] || fail "--after=<count> exit $rc"
# a hostile root must be refused before any sh command line is built
rc=0; env -i PATH="$work/bin" HOME="$work/home" "$doc" "--root=$work/x\$(touch $work/pwn)" --group=repo >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "hostile root exit $rc, want 2"
[ ! -e "$work/pwn" ] || fail "hostile root ran a command"
rc=0; env -i PATH="$work/bin" HOME="$work/home" "$doc" "--root=$work/x\`touch $work/pwn\`" --group=repo >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] && [ ! -e "$work/pwn" ] || fail "backtick root not refused"
rc=0; env -i PATH="$work/bin" HOME="$work/home" TMPDIR="$work/t\$(touch $work/pwn)" "$doc" --root="$work/root" --group=tools >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] && [ ! -e "$work/pwn" ] || fail "hostile TMPDIR not refused"
# output cut: a small budget stops the report early and next_after continues it to the end
rc=0; env -i PATH="$work/bin" HOME="$work/home" ZCL_DOCTOR_OUT_CAP=500 "$doc" --root="$work/root" --group=tools --json >"$work/cut.out" || rc=$?
grep -q "\"next_after\":[0-9]" "$work/cut.out" || fail "no next_after when output is cut"
na=$(sed "s/.*\"next_after\":\([0-9]*\).*/\1/" "$work/cut.out" | tail -1)
rc=0; env -i PATH="$work/bin" HOME="$work/home" ZCL_DOCTOR_OUT_CAP=500 "$doc" --root="$work/root" --group=tools --json --after="$na" >"$work/cut2.out" || rc=$?
grep -q "\"id\":\"" "$work/cut2.out" || fail "continuation after a cut is empty"
rc=0; env -i PATH="$work/bin" HOME="$work/home" ZCL_DOCTOR_OUT_CAP=500 "$doc" --root="$work/root" --group=tools >"$work/cut3.out" || rc=$?
grep -q "output cut; continue with --after=" "$work/cut3.out" || fail "text report not cut with a hint"
"$doc" --selftest >/dev/null || fail "--selftest"
echo "doctor: ok"
