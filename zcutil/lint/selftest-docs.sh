#!/bin/sh
# Selftest of the documentation-honesty rules of zcl-lint (doc-claims, doc-paths, version-facts, victory)
# against throw-away git repositories built here. Every fixture defect must fail with file:line.
# usage: selftest-docs.sh <zcl-lint binary>
# Copyright 2026 Rhett Creighton - MIT
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
[ -x "$bin" ] || { echo "selftest-docs: $bin is not built" >&2; exit 2; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zcl-lint-docs.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT INT TERM
fails=0; n=0
ok() { n=$((n + 1)); }
bad() { fails=$((fails + 1)); echo "FAIL selftest-docs: $*" >&2; }

newrepo() {
    r=$tmp/$1; mkdir -p "$r/zcutil/lint/../bin" "$r/doc/agent" "$r/wallet/src" "$r/wallet/contrib/release" "$r/wallet/res"
    cd "$r" || exit 2
    git init -q . && git config user.email t@example.invalid && git config user.name t
    cp "$bin" zcutil/bin/zcl-lint
    printf '# one\n' > a.md; printf '# two\n' > doc/b.md; printf '# three\n' > doc/agent/HANDOFF.md
    printf 'int f;\n' > src.c
    printf '#!/bin/sh\nstep alpha 60 t_alpha\n    step beta-two 60 t_beta\n' > zcutil/local-ci.sh
    printf 'define(_CLIENT_VERSION_MAJOR, 2)\ndefine(_CLIENT_VERSION_MINOR, 1)\ndefine(_CLIENT_VERSION_REVISION, 2)\ndefine(_CLIENT_VERSION_BUILD, 12)\n' > configure.ac
    printf '#define APP_VERSION "2.1.2-beta13"\n' > wallet/src/version.h
}
track() { git add -A >/dev/null 2>&1; }
# setbuild <n>: configure.ac with _CLIENT_VERSION_BUILD n (portable, no sed -i)
setbuild() { printf 'define(_CLIENT_VERSION_MAJOR, 2)
define(_CLIENT_VERSION_MINOR, 1)
define(_CLIENT_VERSION_REVISION, 2)
define(_CLIENT_VERSION_BUILD, %s)
' "$1" > configure.ac; }
run() {
    want=$1; pat=$2; shift 2
    out=$("$bin" --root . "$@" 2>&1); rc=$?
    ok
    [ "$rc" = "$want" ] || bad "zcl-lint $*: rc=$rc want $want ($out)"
    [ -z "$pat" ] || printf '%s\n' "$out" | grep -q -- "$pat" || bad "zcl-lint $*: output lacks '$pat': $out"
}
# claim <text>: replace the body of a.md with one claim comment line
claim() { printf '# one\n\n%s\n' "$1" > a.md; track; }

# ---- doc-claims: every predicate holding ----
newrepo claims
printf 'int AnswerSym;\n' > src.c
claim '<!-- claim: file-present src.c # a note -->'
run 0 'ok (1 claims in 3 documents)' doc-claims
claim '<!-- claim: file-present doc # a tracked directory -->'
run 0 'ok (1 claims' doc-claims
claim '<!-- claim: file-absent nothing/here.c -->'
run 0 'ok (1 claims' doc-claims
claim '<!-- claim: symbol-present AnswerSym src.c -->'
run 0 'ok (1 claims' doc-claims
claim '<!-- claim: symbol-absent NoSuchSym *.c -->'
run 0 'ok (1 claims' doc-claims
claim '<!-- claim: step-exists alpha -->'
run 0 'ok (1 claims' doc-claims
claim '<!-- claim: step-exists beta-two -->'
run 0 'ok (1 claims' doc-claims
printf '#!/bin/sh\nexit 0\n' > zcutil/check-no-python.sh
claim '<!-- claim: rule-passes no-python -->'
run 0 'ok (1 claims' doc-claims

# ---- doc-claims: every predicate stale (false) ----
claim '<!-- claim: file-present missing.c -->'
run 1 'a.md:3: false claim: path is not tracked' doc-claims
claim '<!-- claim: file-absent src.c -->'
run 1 'a.md:3: false claim: path is tracked' doc-claims
claim '<!-- claim: symbol-present Gone src.c -->'
run 1 'a.md:3: false claim: symbol not found' doc-claims
claim '<!-- claim: symbol-absent AnswerSym src.c -->'
run 1 'a.md:3: false claim: symbol found' doc-claims
claim '<!-- claim: step-exists gamma -->'
run 1 'a.md:3: false claim: no such step' doc-claims
claim '<!-- claim: step-exists alph -->'
run 1 'a.md:3: false claim: no such step' doc-claims
printf '#!/bin/sh\nexit 1\n' > zcutil/check-no-python.sh
claim '<!-- claim: rule-passes no-python -->'
run 1 'a.md:3: false claim: rule no-python does not pass' doc-claims

# ---- doc-claims: malformed ----
claim '<!-- claim: no-such-predicate x -->'
run 1 'a.md:3: malformed claim: unknown predicate' doc-claims
claim '<!-- claim: file-present -->'
run 1 'a.md:3: malformed claim: needs exactly one' doc-claims
claim '<!-- claim: file-present a b -->'
run 1 'a.md:3: malformed claim' doc-claims
claim '<!-- claim: symbol-present OnlyOne -->'
run 1 'a.md:3: malformed claim: needs a symbol' doc-claims
claim '<!-- claim: file-present ../escape -->'
run 1 'a.md:3: malformed claim' doc-claims
claim "<!-- claim: file-present x';rm -f y -->"
run 1 'a.md:3: malformed claim' doc-claims
claim '<!-- claim: rule-passes doc-claims -->'
run 1 'a.md:3: malformed claim: a claim cannot ask for itself' doc-claims
claim '<!-- claim: file-present src.c'
run 1 'a.md:3: malformed claim (want' doc-claims
claim '<!-- claim file-present src.c -->'
run 1 'a.md:3: malformed claim (want' doc-claims
# examples in fences and code spans are not claims
printf '# one\n\n```\n<!-- claim: bogus -->\n```\n\nuse `<!-- claim: bogus -->` like so\n' > a.md; track
run 0 'ok (0 claims' doc-claims

# ---- doc-claims: hollow scan (fewer than 3 documents) ----
newrepo hollowclaims
rm doc/b.md doc/agent/HANDOFF.md; track
run 2 'hollow scan' doc-claims
run 2 'has no baseline' doc-claims --update-baseline

# ---- doc-paths ----
newrepo paths
mkdir -p src/sub
printf 'int g;\n' > src/sub/g.c
printf '# one\n\nSee `src/sub/g.c`, `src/sub/`, `src/sub/g.c:12`, `sub/g.c`, `a.md#top`, `zcutil/bin/zcl-lint`, `and/or`, `x/*.c`, `https://e.org/a.c`.\n' > a.md
track
run 0 'created (0 paths, 0)' doc-paths --update-baseline
run 0 'ok (0 paths, 0)' doc-paths
printf '# one\n\nSee `src/sub/missing.c` and `src/gone/` and `docs/new/readme.md`.\n\n```\n`src/in/fence.c`\n```\n' > a.md; track
run 1 'a.md:3: `src/sub/missing.c` does not resolve' doc-paths
run 1 'a.md:3: `src/gone/` does not resolve' doc-paths
run 1 'a.md: 3 new' doc-paths
printf '# one\n\nSee `src/sub/missing.c` <!-- doc-path-ok -->\n' > a.md; track
run 0 'ok (0 paths, 0)' doc-paths
newrepo paths2
mkdir -p src/sub; printf "int g;
" > src/sub/g.c
printf '# one\n\nSee `src/sub/missing.c`.\n' > a.md; track
run 0 'created (1 paths, 1)' doc-paths --update-baseline
run 0 'ok (1 paths, 1)' doc-paths
printf '# one\n\nSee `src/sub/missing.c` and `src/sub/missing2.c`.\n' > a.md; track
run 1 'a.md: 2, baseline 1 (rose)' doc-paths
run 1 'NOT updated' doc-paths --update-baseline
printf '# one\n' > a.md; track
run 0 'can be lowered' doc-paths
run 0 'lowered (0 paths, 0)' doc-paths --update-baseline
newrepo hollowpaths
rm a.md doc/b.md doc/agent/HANDOFF.md; track
run 2 'hollow scan' doc-paths

# ---- version-facts ----
newrepo version
printf '#!/bin/sh\nrelease_version=2.1.2-beta13\n"$d" --version | grep -F "2.1.2-beta13"\nhdiutil create -volname ZClassic-beta13 x\nOPENSSL=1.1.1w\n' > wallet/contrib/release/linux.sh
printf '<key>CFBundleShortVersionString</key><string>2.1.2</string>\n<key>CFBundleVersion</key><string>2.1.2-beta13</string>\n' > wallet/res/Info.plist
track
run 0 'ok (2.1.2-beta13, 4 files)' version-facts
printf '#define APP_VERSION "2.1.2-beta12"\n' > wallet/src/version.h; track
run 1 'wallet/src/version.h: APP_VERSION 2.1.2-beta12, configure.ac says 2.1.2-beta13' version-facts
printf '#define APP_VERSION "2.1.2-beta13"\n' > wallet/src/version.h
printf '#!/bin/sh\nrelease_version=2.1.2-beta13\n"$d" --version | grep -F "2.1.2-beta11"\n' > wallet/contrib/release/linux.sh; track
run 1 'wallet/contrib/release/linux.sh:3: 2.1.2-beta11, configure.ac says 2.1.2-beta13' version-facts
printf '#!/bin/sh\nhdiutil create -volname ZClassic-beta12 x\n' > wallet/contrib/release/linux.sh; track
run 1 'wallet/contrib/release/linux.sh:2: beta12, configure.ac says beta13' version-facts
printf '#!/bin/sh\nV=${VERSION:-2.1.1-rc2}\n' > wallet/contrib/release/linux.sh; track
run 1 'linux.sh:2: 2.1.1-rc2' version-facts
printf '#!/bin/sh\necho ok\n' > wallet/contrib/release/linux.sh
printf '<key>CFBundleShortVersionString</key><string>2.1.1</string>\n' > wallet/res/Info.plist; track
run 1 'Info.plist:1: CFBundleShortVersionString 2.1.1, configure.ac says 2.1.2' version-facts
printf '<key>CFBundleShortVersionString</key><string>2.1.2</string>\n' > wallet/res/Info.plist
setbuild 26; track
run 1 'APP_VERSION 2.1.2-beta13, configure.ac says 2.1.2-rc2' version-facts
setbuild 50
printf '#define APP_VERSION "2.1.2"\n' > wallet/src/version.h; track
run 0 'ok (2.1.2, ' version-facts
printf 'nothing\n' > configure.ac; track
run 2 'hollow scan' version-facts
newrepo noheader
rm wallet/src/version.h; track
run 2 'hollow scan' version-facts

# ---- victory ----
newrepo victory
printf 'x\n' > f.txt; track; git commit -q -m c; sha=$(git rev-parse --short=9 HEAD)
printf '# Handoff\n\nThe node is at tip and the build is green.\n' > doc/agent/HANDOFF.md; track
run 1 'doc/agent/HANDOFF.md:3: victory wording' victory
printf '# Handoff\n\nThe wallet bug is fixed in %s.\n\nsecond paragraph says nothing.\n' "$sha" > doc/agent/HANDOFF.md; track
run 0 'victory: ok' victory
printf '# Handoff\n\nThe wallet bug is fixed in deadbee1234.\n' > doc/agent/HANDOFF.md; track
run 1 'HANDOFF.md:3: victory wording' victory
printf '# Handoff\n\nFully synced: see build/local-ci/run1/receipts.jsonl for the proof.\n' > doc/agent/HANDOFF.md; track
run 0 'victory: ok' victory
printf '# Handoff\n\nThe suite is GREEN (local-ci results in out/local-ci/r3).\n' > doc/agent/HANDOFF.md; track
run 0 'victory: ok' victory
printf '# Handoff\n\nCured on testnet <!-- victory-ok: owner reported it, no receipt yet -->\n' > doc/agent/HANDOFF.md; track
run 0 'victory: ok' victory
printf '# Handoff\n\nCured on testnet <!-- victory-ok: -->\n' > doc/agent/HANDOFF.md; track
run 1 'HANDOFF.md:3: victory wording' victory
printf '# Handoff\n\nfine para\n\nline one\nthe suite is green\n\nnotes\n' > doc/agent/HANDOFF.md; track
run 1 'HANDOFF.md:5: victory wording' victory
printf '# Handoff\n\n```\nat tip and green\n```\n\nThe greenhouse and the prefixed word are not victory.\n' > doc/agent/HANDOFF.md; track
run 0 'victory: ok' victory
git rm -q -f --cached doc/agent/HANDOFF.md; rm doc/agent/HANDOFF.md; track
run 2 'hollow scan' victory

# ---- all: the four rules are in the table ----
newrepo all
track
for r in doc-claims doc-paths version-facts victory; do
    out=$("$bin" --root . "$r" 2>&1); rc=$?; ok
    case "$rc" in 0|1) ;; *) bad "$r: rc=$rc on a minimal fixture ($out)";; esac
done

echo "selftest-docs: $((n - fails))/$n checks passed"
[ "$fails" = 0 ]
