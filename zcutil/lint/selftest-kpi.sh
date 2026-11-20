#!/bin/sh
# Selftest of zcl-lint kpi and wiring against throw-away git repositories. usage: selftest-kpi.sh <zcl-lint binary>
# Copyright 2026 Rhett Creighton - Apache License 2.0
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
[ -x "$bin" ] || { echo "selftest-kpi: $bin is not built" >&2; exit 2; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zcl-lint-kpi.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT INT TERM
fails=0; n=0
ok() { n=$((n + 1)); }
bad() { fails=$((fails + 1)); echo "FAIL selftest-kpi: $*" >&2; }
run() {
    want=$1; pat=$2; shift 2
    out=$("$bin" --root . "$@" 2>&1); rc=$?
    ok
    [ "$rc" = "$want" ] || bad "zcl-lint $*: rc=$rc want $want ($out)"
    [ -z "$pat" ] || printf '%s\n' "$out" | grep -q -- "$pat" || bad "zcl-lint $*: output lacks '$pat': $out"
}
# A fixture tree in which every metric source exists and every metric is 0 (shell_lines 2) until a case changes it.
newrepo() {
    r=$tmp/$1; mkdir -p "$r/zcutil/lint" "$r/zcutil/dev/gen" "$r/src/test" "$r/src/gtest" "$r/doc/agent"; cd "$r" || exit 2
    git init -q . && git config user.email t@example.invalid && git config user.name t
    mkdir -p .git/info && echo zcutil/bin/ > .git/info/exclude
    for b in no-new-bash no-new-jq banned-str filesize complexity md-links doc-paths secretlog; do
        printf '# baseline\n' > "zcutil/lint/$b.txt"
    done
    printf '# flags\n' > zcutil/dev/gen/flags-undocumented.txt
    printf '# lessons\n' > doc/agent/LESSONS.md
    printf 'test/a_tests.cpp\n' > src/Makefile.test.include
    printf 'gtest/test_a.cpp\n' > src/Makefile.gtest.include
    printf 'int x;\n' > src/test/a_tests.cpp
    printf 'int y;\n' > src/gtest/test_a.cpp
    printf '#!/bin/sh\necho hi\n' > run.sh
}
track() { git add -A >/dev/null 2>&1; }

# ---- kpi ----
newrepo kpi; track
run 2 'zcutil/bin/zcl-dev not built' kpi --update-baseline
ok; [ ! -f zcutil/lint/kpi-floor.txt ] || bad "a floor was written while a metric was unavailable"
mkdir -p zcutil/bin
printf '#!/bin/sh\necho "check-rules: OK (1 files in scope, 1 rules)"\n' > zcutil/bin/zcl-dev; chmod +x zcutil/bin/zcl-dev
run 0 'created' kpi --update-baseline
run 0 'kpi: ok' kpi
printf '#!/bin/sh\njq .a\n' > b.sh; track
run 1 'shell_lines: 4, floor 2 (rose)' kpi
run 1 'NOT updated' kpi --tighten
rm b.sh; track
printf 'x\t3\nz\t2\n' >> zcutil/lint/no-new-jq.txt
run 1 'jq_uses: 5, floor 0 (rose)' kpi
printf '# baseline\n' > zcutil/lint/no-new-jq.txt
printf 'print(1)\n' > t.py; track
run 1 'python_files: 1, floor 0 (rose)' kpi
rm t.py; mkdir -p .github/workflows; printf 'on: push\n' > .github/workflows/ci.yml; track
run 1 'hosted_ci_files: 1, floor 0 (rose)' kpi
rm -rf .github; track
printf 'OPEN a.c - x\n' >> doc/agent/LESSONS.md
run 1 'tracked_lessons_open: 1, floor 0 (rose)' kpi
printf '# lessons\n' > doc/agent/LESSONS.md
printf 'int z;\n' > src/test/b_tests.cpp; track
run 1 'unregistered_tests: 1, floor 0 (rose)' kpi
rm src/test/b_tests.cpp; track
printf '#!/bin/sh\necho "FAIL: no rule matches a.c"\necho "FAIL: no rule matches b.c"\nexit 1\n' > zcutil/bin/zcl-dev
run 1 'unmapped_paths: 2, floor 0 (rose)' kpi
printf '#!/bin/sh\nexit 3\n' > zcutil/bin/zcl-dev
run 2 'unmapped_paths: zcl-dev check-rules did not run' kpi
printf '#!/bin/sh\necho "check-rules: OK"\n' > zcutil/bin/zcl-dev
# an unreadable source is UNAVAILABLE, never 0
mv zcutil/lint/secretlog.txt zcutil/lint/secretlog.off
run 2 'UNAVAILABLE kpi: secret_log_sites' kpi
mv zcutil/lint/secretlog.off zcutil/lint/secretlog.txt
printf '# baseline\nq.c\tf(1)\t20\nq.c\tg(2)\t15\nq.c\th(1)\t16\n' > zcutil/lint/complexity.txt
run 1 'complexity_debt: 6, floor 0 (rose)' kpi
printf '# baseline\n' > zcutil/lint/complexity.txt
run 0 'kpi: ok' kpi
# tightening: a metric below its floor lowers the floor, never raises it
sed 's/^complexity_debt.*/complexity_debt	8/' zcutil/lint/kpi-floor.txt > f.tmp && mv f.tmp zcutil/lint/kpi-floor.txt
printf '# baseline\nq.c\tf(1)\t20\n' > zcutil/lint/complexity.txt
run 0 'can be lowered' kpi
run 0 'kpi: floor lowered' kpi --tighten
ok; grep -q '^complexity_debt	5$' zcutil/lint/kpi-floor.txt || bad "tighten did not write 5"
run 0 'already tight' kpi --tighten
# malformed or incomplete floor
printf 'python_files\t0\n' > zcutil/lint/kpi-floor.txt
run 1 'has no row in' kpi
printf 'bogus\t1\n' > zcutil/lint/kpi-floor.txt
run 2 'bad row' kpi
# no tracked files at all: UNAVAILABLE, never a pass
mkdir -p "$tmp/empty"; cd "$tmp/empty" && git init -q . || exit 2
run 2 '' kpi

# ---- wiring ----
newrepo wiring
cp "$here/rules.def" zcutil/lint/rules.def
{ echo '# docs'; echo '<!-- LINT-RULES-BEGIN -->'
  sed -n 's/^LINT_RULE("\([^"]*\)".*/- `\1`: x/p' zcutil/lint/rules.def
  echo '<!-- LINT-RULES-END -->'; } > doc/local-ci.md
track
run 0 'wiring: ok' wiring
cp doc/local-ci.md good.md
grep -v '`doc-paths`' good.md > doc/local-ci.md
run 1 "rule 'doc-paths' is in zcutil/lint/rules.def but not in the documented list" wiring
{ grep -v 'LINT-RULES-END' good.md; echo '- `phantom`: x'; echo '<!-- LINT-RULES-END -->'; } > doc/local-ci.md
run 1 "documents 'phantom', which is not a rule" wiring
{ grep -v 'LINT-RULES-END' good.md; echo '- `kpi`: again'; echo '<!-- LINT-RULES-END -->'; } > doc/local-ci.md
run 1 "'kpi' appears twice" wiring
grep -v 'LINT-RULES' good.md > doc/local-ci.md
run 1 'no closed' wiring
printf '<!-- LINT-RULES-BEGIN -->\n<!-- LINT-RULES-END -->\n' > doc/local-ci.md
run 1 'is empty' wiring
rm doc/local-ci.md
run 2 'cannot read doc/local-ci.md' wiring
# a table row the binary does not run (stale build)
cp "$here/rules.def" zcutil/lint/rules.def
printf 'LINT_RULE("ghost", lint_rule_ghost, false)\n' >> zcutil/lint/rules.def
{ echo '<!-- LINT-RULES-BEGIN -->'; sed -n 's/^LINT_RULE("\([^"]*\)".*/- `\1`/p' zcutil/lint/rules.def; echo '<!-- LINT-RULES-END -->'; } > doc/local-ci.md
run 1 "rule 'ghost' is in zcutil/lint/rules.def but this zcl-lint binary does not run it" wiring
rm zcutil/lint/rules.def
run 2 'cannot read any rule' wiring

echo "selftest-kpi: $((n - fails))/$n checks passed"
[ "$fails" = 0 ]
