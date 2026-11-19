#!/bin/sh
# Selftest of zcl-lint: every rule against throw-away git repositories (fixture trees built here).
# usage: selftest.sh <zcl-lint binary> [path to src/c23/tools/check-vendor.sh]
# Copyright 2026 Rhett Creighton - Apache License 2.0 (derived in spirit from the Z23 gate selftests)
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
cv=${2:-$here/../../src/c23/tools/check-vendor.sh}
[ -x "$bin" ] || { echo "selftest: $bin is not built" >&2; exit 2; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zcl-lint-selftest.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT INT TERM
fails=0; n=0
ok() { n=$((n + 1)); }
bad() { fails=$((fails + 1)); echo "FAIL selftest: $*" >&2; }

# newrepo <name>: an empty git repository under $tmp, cwd inside it
newrepo() {
    r=$tmp/$1; mkdir -p "$r/zcutil/lint"; cd "$r" || exit 2
    git init -q . && git config user.email t@example.invalid && git config user.name t
}
track() { git add -A >/dev/null 2>&1; }
# run <want-rc> <grep-pattern-or-empty> <args...>: zcl-lint in the current repo
run() {
    want=$1; pat=$2; shift 2
    out=$("$bin" --root . "$@" 2>&1); rc=$?
    ok
    [ "$rc" = "$want" ] || bad "zcl-lint $*: rc=$rc want $want ($out)"
    [ -z "$pat" ] || printf '%s\n' "$out" | grep -q -- "$pat" || bad "zcl-lint $*: output lacks '$pat': $out"
}

# ---- no-new-jq ----
newrepo jq
printf '#!/bin/sh\njq -r .a\ncli | jq .b\necho hi\n' > a.sh
printf '#!/bin/sh\necho no json here\n' > c.sh
printf 'jq mentioned in a text file is not a script\n' > notes.txt
track
run 1 'no baseline' no-new-jq
run 0 'created (1 paths, 2)' no-new-jq --update-baseline
run 0 'ok (1 paths, 2)' no-new-jq
printf 'jq .c\n' >> a.sh; track
run 1 'a.sh: 3, baseline 2 (rose)' no-new-jq
run 1 'NOT updated' no-new-jq --update-baseline
printf '#!/bin/sh\njq .x\n' > b.sh; track
run 1 'b.sh: 1 new' no-new-jq
printf '#!/bin/sh\njq -r .a\n' > a.sh; rm b.sh; track
run 0 'can be lowered' no-new-jq
run 0 'lowered (1 paths, 1)' no-new-jq --update-baseline
run 0 'ok (1 paths, 1)' no-new-jq
printf '#!/usr/bin/env sh\nthe jq tool\n' > env.sh; track
run 1 'env.sh: 1 new' no-new-jq

# ---- no-new-bash ----
newrepo bash
printf '#!/bin/bash\nif [[ -n $x ]]; then echo hi; fi\n' > old.sh
printf '#!/bin/sh\n# [[ in a comment is fine\nif [ -n "$x" ]; then echo ok; fi\nx=$((1 + 2))\n' > posix.sh
track
run 0 'created (1 paths, 2)' no-new-bash --update-baseline
run 0 'ok (1 paths, 2)' no-new-bash
printf '#!/usr/bin/env bash\necho hi\n' > new_tool; track
run 1 'new_tool: 1 new' no-new-bash
rm new_tool; printf '#!/bin/sh\narr=(a b)\ncat <(echo x)\n' > posix.sh; track
run 1 'posix.sh: 2 new' no-new-bash
printf '#!/bin/sh\necho hi\n' > old.sh; rm posix.sh; track
run 0 'lowered' no-new-bash --update-baseline

# ---- banned-str ----
newrepo banned
mkdir -p src/leveldb src/c23/vendor
printf 'void f(char *a, const char *b) {\n  strcpy(a, b);\n  /* strcat(a, b); */\n  puts("sprintf(x)");  // gets(x)\n  sprintf(a, "%%s", b);\n  snprintf(a, 4, "x");\n}\n' > x.c
printf 'void g(char *a) { strcpy(a, "x"); }\n' > src/leveldb/third.c
printf 'void g(char *a) { gets(a); }\n' > src/c23/vendor/v.c
printf 'void h(struct s *p) { p->gets(1); q.sprintf(2); }\n' > member.cpp
track
run 0 'created (1 paths, 2)' banned-str --update-baseline
run 0 'ok (1 paths, 2)' banned-str
printf 'void h(char *a) { vsprintf(a, "x", 0); }\n' > y.h; track
run 1 'y.h: 1 new' banned-str
rm y.h; printf 'void f(char *a, const char *b) {\n  strcpy(a, b);\n  strcpy(a, b);\n  strcpy(a, b);\n}\n' > x.c; track
run 1 'x.c: 3, baseline 2 (rose)' banned-str
printf 'void f(char *a, const char *b) {\n  snprintf(a, 3, "%%s", b);\n}\n' > x.c; track
run 0 'can be lowered' banned-str
run 0 'lowered (0 paths, 0)' banned-str --update-baseline

# ---- md-links ----
newrepo md
mkdir -p docs
printf '# Title\n\nSee [guide](docs/guide.md), [dir](docs), [web](https://example.org/x), [mail](mailto:a@b.c) and [top](#title).\n' > README.md
printf '## Install\n\n[back](../README.md#title) [self](#install) [other](#nowhere)\n\n```\n[fenced](nothing.md)\n```\n\nand `[inline](nothing2.md)`.\n' > docs/guide.md
track
run 1 'docs/guide.md:3: no heading for anchor #nowhere' md-links
run 0 'created (1 paths, 1)' md-links --update-baseline
run 0 'ok (1 paths, 1)' md-links
printf '[gone](docs/missing.md) [esc](../../etc/passwd)\n' >> README.md; track
run 1 'README.md:4: docs/missing.md does not resolve' md-links
run 1 'leaves the repository' md-links
run 1 'README.md: 2 new' md-links
git checkout -q README.md 2>/dev/null || printf '# Title\n\n[guide](docs/guide.md)\n' > README.md
printf '# Title\n\n[guide](docs/guide.md)\n' > README.md; printf '## Install\n\n[self](#install)\n' > docs/guide.md; track
run 0 'can be lowered' md-links
run 0 'lowered (0 paths, 0)' md-links --update-baseline

# ---- vendor (delegates to check-vendor.sh) ----
newrepo vendor
mkdir -p src/c23/tools zcutil/tools/vendor/x
cp "$cv" src/c23/tools/check-vendor.sh
: > configure.ac
# something for every rule to scan (an empty scan set is a failure)
printf '# t\n' > notes.md; printf 'int top;\n' > top.c; printf '#!/bin/sh\n:\n' > top.sh
mkdir -p src; printf 'int top2(void) { return 1; }\n' > src/top2.c
# fixture facts for the documentation rules (doc-claims needs 3 documents, version-facts a version, victory a HANDOFF page)
mkdir -p doc/agent wallet/src
printf "# a
" > doc/a.md; printf "# handoff
" > doc/agent/HANDOFF.md
printf "define(_CLIENT_VERSION_MAJOR, 2)
define(_CLIENT_VERSION_MINOR, 1)
define(_CLIENT_VERSION_REVISION, 2)
define(_CLIENT_VERSION_BUILD, 12)
" > configure.ac
printf "#define APP_VERSION \"2.1.2-beta13\"
" > wallet/src/version.h
printf 'int answer(void) { return 42; }\n' > zcutil/tools/vendor/x/a.c
blob=$(git hash-object zcutil/tools/vendor/x/a.c)
pin=0123456789012345678901234567890123456789
printf '# z23_commit=%s\n# requires_ancestor=55245e2bd\n' "$pin" > zcutil/tools/Z23_SOURCE.tsv
printf 'zcutil/tools/vendor/x/a.c\tx/a.c\t%s\t%s\tunsealed\n' "$blob" "$pin" >> zcutil/tools/Z23_SOURCE.tsv
track
run 0 'vendor: ok (1 manifests)' vendor
printf 'int answer(void) { return 43; }\n' > zcutil/tools/vendor/x/a.c; track
run 1 'does not match its vendored tree' vendor
printf 'int answer(void) { return 42; }\n' > zcutil/tools/vendor/x/a.c; printf 'x\n' > zcutil/tools/vendor/x/extra.c; track
run 1 'does not match its vendored tree' vendor
rm zcutil/tools/vendor/x/extra.c; track
# `all`, and the python hook: hollow (exit 2) when zcutil/check-no-python.sh is absent, run (and fatal) when present
for r in no-new-jq no-new-bash banned-str md-links doc-paths filesize complexity long-functions warnsupp; do "$bin" --root . $r --update-baseline >/dev/null 2>&1; done
run 2 "nothing scanned" no-python
printf 'exit 7\n' > zcutil/check-no-python.sh; track
run 1 '' all
printf 'exit 0\n' > zcutil/check-no-python.sh; track
run 0 'vendor: ok' all
run 2 "unknown rule" bogus-rule

# ---- hollow scans: a tree with nothing to scan fails (rc 2), it never passes ----
newrepo hollow
printf 'plain text, no scripts, no C, no markdown\n' > notes.txt
track
for r in no-new-jq no-new-bash banned-str md-links; do
    run 2 'hollow scan' $r
    run 2 'hollow scan' $r --update-baseline
done
run 2 "has no baseline" vendor --update-baseline

echo "selftest: $((n - fails))/$n checks passed"
[ "$fails" = 0 ]
