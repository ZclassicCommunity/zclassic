#!/bin/sh
# Selftest of the zcl-lint code-shape rules (filesize, complexity, long-functions, warnsupp) against throw-away
# git repositories built here. usage: selftest_shape.sh <zcl-lint binary>
# Copyright 2026 Rhett Creighton - Apache License 2.0 (derived in spirit from the Z23 gate selftests)
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
[ -x "$bin" ] || { echo "selftest_shape: $bin is not built" >&2; exit 2; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zcl-lint-shape.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT INT TERM
fails=0; n=0
ok() { n=$((n + 1)); }
bad() { fails=$((fails + 1)); echo "FAIL selftest_shape: $*" >&2; }
newrepo() {
    r=$tmp/$1; mkdir -p "$r/zcutil/lint" "$r/src"; cd "$r" || exit 2
    git init -q . && git config user.email t@example.invalid && git config user.name t
}
track() { git add -A >/dev/null 2>&1; }
run() {
    want=$1; pat=$2; shift 2
    out=$("$bin" --root . "$@" 2>&1); rc=$?
    ok
    [ "$rc" = "$want" ] || bad "zcl-lint $*: rc=$rc want $want ($out)"
    [ -z "$pat" ] || printf '%s\n' "$out" | grep -q -- "$pat" || bad "zcl-lint $*: output lacks '$pat': $out"
}
has() { ok; grep -q -- "$2" "$1" || bad "$1 lacks '$2'"; }
hasnt() { ok; if grep -q -- "$2" "$1"; then bad "$1 holds '$2'"; fi; }
rowcount() { ok; c=$(grep -vc '^#' "$1"); [ "$c" = "$2" ] || bad "$1 has $c rows, want $2"; }
lines() { i=0; while [ $i -lt "$1" ]; do printf '%s\n' "$2"; i=$((i + 1)); done; }
ifs() { lines "$1" '    if (a) a--;'; }
fn() { # fn <file> <header> <ifs>: a function with that many if statements
    { printf '%s\n{\n' "$2"; ifs "$3"; printf '    return a;\n}\n'; } > "$1"
}

# ---- filesize ----
newrepo fs
lines 1500 'int x;' > src/edge.c            # exactly at the limit: allowed
lines 900 'int y;' > src/buffer.c           # buffer band: advisory only
lines 1601 'int z;' > src/big.c
track
run 1 'no baseline' filesize
run 0 'created (1 paths, 1601)' filesize --update-baseline
run 0 'ok (1 paths, 1601)' filesize
run 0 '2 file(s) sit in the 801..1500 buffer band' filesize
echo 'int more;' >> src/big.c; track
run 1 'src/big.c: 1602, baseline 1601 (rose)' filesize
run 1 'NOT updated' filesize --update-baseline
lines 1700 'int w;' > src/new.c; track
run 1 'src/new.c: 1700 new' filesize
rm src/new.c; lines 1550 'int z;' > src/big.c; track
run 0 'can be lowered' filesize
run 0 'lowered (1 paths, 1550)' filesize --update-baseline
lines 1200 'int z;' > src/big.c; track
run 0 'lowered (0 paths, 0)' filesize --update-baseline
mkdir -p src/leveldb; lines 3000 'int q;' > src/leveldb/huge.c; track
run 0 'ok (0 paths, 0)' filesize

# ---- complexity ----
newrepo cx
fn src/a.c 'int f(int a)' 16
fn src/b.c 'int g(int a)' 14                       # M = 15: at the cap
track
run 1 'no baseline' complexity
run 0 'created (1 paths, 17)' complexity --update-baseline
has zcutil/lint/complexity.txt 'src/a.c	f(1)	17'
run 0 'ok (1 paths, 17)' complexity
fn src/a.c 'int f(int a)' 17; track
run 1 'f(1)' complexity
run 1 'NOT updated' complexity --update-baseline
{ printf 'int f(int a)\n{\n'; ifs 16; printf '    return a;\n}\nint h(int a) { return a && a || a; }\nint k(void) {\n'; ifs 20; printf '}\n'; } > src/a.c; track
run 1 'k(0)' complexity
fn src/a.c 'int f(int a)' 8; track
run 0 'can be lowered' complexity
run 0 'lowered (0 paths, 0)' complexity --update-baseline
rowcount zcutil/lint/complexity.txt 0

# ---- C++ scanner cases ----
newrepo cxx
{
cat <<'EOT'
#include <vector>
namespace ns {
namespace {
const char *raw = R"x( } { if if if if if if if if if if if if if if if if if )x";
}
class Foo : public Base<int> {
public:
    Foo(int a) : x(a), y{1, 2}, z(Bar{3}) {
        if (a) {}
    }
    int bar(int a) {
EOT
ifs 16
cat <<'EOT'
        return a;
    }
    int bar(int a, int b) {
EOT
ifs 16
cat <<'EOT'
        return a + b;
    }
    int bar2(int a) {
EOT
ifs 16
cat <<'EOT'
        return a;
    }
    int ov(int a) {
EOT
ifs 16
cat <<'EOT'
        return a;
    }
    int ov(int b) {
EOT
ifs 16
cat <<'EOT'
        return b;
    }
    int x, y;
};
bool Foo::operator==(const Foo &o) const noexcept
{
    const char *s = R"y(}{)y";
    (void)s;
EOT
ifs 16
cat <<'EOT'
    return true;
}
template <typename T>
void outer(T t)
{
    auto lam = [&](int q) {
EOT
ifs 16
cat <<'EOT'
        return q;
    };
    lam(1);
}
static const int table[] = { 1, 2, 3 };
BOOST_AUTO_TEST_CASE(big_one)
{
EOT
ifs 16
cat <<'EOT'
}
void after_raw(int a)
{
    for (auto&& e : v) { if (e && a) {} }
    int digits = 1'000'000;
    char c = '}';
}
}
EOT
} > src/m.cpp
track
run 0 'created' complexity --update-baseline
b=zcutil/lint/complexity.txt
has $b 'src/m.cpp	ns::Foo::bar(1)	17'
has $b 'src/m.cpp	ns::Foo::bar(2)	17'
has $b 'src/m.cpp	ns::Foo::bar2(1)	17'
has $b 'src/m.cpp	ns::Foo::ov(1)	17'
has $b 'src/m.cpp	ns::Foo::ov(1)#2	17'
has $b 'src/m.cpp	ns::Foo::operator==(1)	17'
has $b 'src/m.cpp	ns::outer(1)	17'
has $b 'src/m.cpp	ns::BOOST_AUTO_TEST_CASE(big_one)	17'
hasnt $b 'Foo::Foo'
hasnt $b 'after_raw'
rowcount $b 8
run 0 'ok (8 paths, 136)' complexity
{ printf 'void tail(int a) {\n'; ifs 16; printf '}\n'; } > src/t.cpp; track
run 1 'tail(1)' complexity

# ---- long-functions ----
newrepo lf
{ printf 'void big(void)\n{\n'; lines 497 '    x++;'; printf '}\n'; } > src/big.c      # 500 lines: at the cap
{ printf 'void bigger(void)\n{\n'; lines 498 '    x++;'; printf '}\n'; } > src/bigger.c  # 501 lines
track
run 0 'created (1 paths, 501)' long-functions --update-baseline
has zcutil/lint/long-functions.txt 'src/bigger.c	bigger(0)	501'
run 0 'ok (1 paths, 501)' long-functions
{ printf 'void bigger(void)\n{\n'; lines 499 '    x++;'; printf '}\n'; } > src/bigger.c; track
run 1 'bigger(0)' long-functions
{ printf 'void bigger(void)\n{\n'; lines 100 '    x++;'; printf '}\n'; } > src/bigger.c; track
run 0 'lowered (0 paths, 0)' long-functions --update-baseline

# ---- warnsupp ----
newrepo ws
printf '#pragma GCC diagnostic ignored "-Wunused"\n  # pragma clang diagnostic ignored "-Wfoo"\n#pragma warning(disable: 4996)\n#pragma GCC diagnostic push\n#pragma GCC diagnostic pop\n// #pragma GCC diagnostic ignored "-Wcommented"\nint ok;\n' > src/p.c
printf 'AC_MSG_NOTICE([x])\ndnl -Wno-ignored\nCXXFLAGS="$CXXFLAGS -Wno-unused -Wno-foo"\n' > configure.ac
printf 'AM_CXXFLAGS = -Wno-bar\n' > src/Makefile.am
track
run 0 'created (3 paths, 6)' warnsupp --update-baseline
has zcutil/lint/warnsupp.txt 'src/p.c	3'
has zcutil/lint/warnsupp.txt 'configure.ac	2'
run 0 'ok (3 paths, 6)' warnsupp
printf '#pragma GCC diagnostic ignored "-Wmore"\n' >> src/p.c; track
run 1 'src/p.c: 4, baseline 3 (rose)' warnsupp
run 1 'NOT updated' warnsupp --update-baseline
printf 'int x;\n' > src/p.c; track
run 0 'can be lowered' warnsupp

# ---- hollow scans fail ----
newrepo hollow
printf 'plain text\n' > notes.txt; track
for r in filesize complexity long-functions warnsupp; do run 2 'hollow scan' $r; done

echo "selftest_shape: $((n - fails))/$n checks passed"
[ "$fails" = 0 ]
