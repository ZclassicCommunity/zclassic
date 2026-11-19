#!/bin/sh
# Fixture-repo tests for the git hooks: throwaway repos under mktemp -d, real `git commit` and
# `git push` with the real shims, zcl-dev-hook and zcl-dev select.
# usage: sh test/run.sh <bindir>      (bindir holds zcl-dev, zcl-dev-hook, zcl-dev-hooks)
set -eu
bindir=$(cd "$1" && pwd)
src=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-hooks-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR ZCL_LANE_COMMIT_OK ZCL_PUSH_OK
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null HOME="$work/home" ZCL_CI_OUT="$work/rc"
mkdir -p "$work/home" "$work/rc"
fails=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
# expect <name> <0|1> <grep-pattern-or-""> <cmd...>: exit status (0 = allowed, nonzero = refused) and message
expect() {
    name=$1; want=$2; pat=$3; shift 3
    rc=0
    "$@" >"$work/out" 2>&1 || rc=$?
    if [ "$want" = 0 ] && [ "$rc" != 0 ]; then bad "$name (refused: $(tr '\n' ' ' <"$work/out"))"; return; fi
    if [ "$want" = 1 ] && [ "$rc" = 0 ]; then bad "$name (allowed, wanted refusal)"; return; fi
    if [ -n "$pat" ] && ! grep -q -- "$pat" "$work/out"; then bad "$name (no '$pat' in: $(tr '\n' ' ' <"$work/out"))"; return; fi
    ok "$name"
}

repo=$work/repo
git init -q "$repo" && git -C "$repo" symbolic-ref HEAD refs/heads/master  # git 2.25 in the CI root has no init -b
git -C "$repo" config user.name tester
git -C "$repo" config user.email t@example.invalid
mkdir -p "$repo/zcutil/dev" "$repo/zcutil/tools/vendor" "$repo/zcutil/bin" "$repo/src"
cp -R "$src/githooks" "$repo/zcutil/githooks"
cp "$bindir"/zcl-dev "$bindir"/zcl-dev-hook "$bindir"/zcl-dev-hooks "$repo/zcutil/bin/"
printf 'zcutil/bin/\n' >"$repo/.gitignore"
printf 'src/*|zcutil/*|.gitignore	unit-a unit-b
weird/*	ALL tor-x
stageonly/*	daemon-linux daemon-win64
scriptonly/*	qa/rpc-tests/x.sh
' >"$repo/zcutil/dev/impact.rules"
cat >"$repo/zcutil/local-ci.sh" <<'EOF2'
step() { :; }
    step unit-a 10 t_a
    step unit-b 10 t_b
    step unit-c 10 t_c
    step tor-x 10 t_tor
    step dry-pass 10 t_dry
    step wallet-qt-logic-widget 10 t_qt
EOF2
printf '# header\n' >"$repo/zcutil/tools/Z23_SOURCE.tsv"
printf 'one\n' >"$repo/zcutil/tools/vendor/v.c"
printf 'a\n' >"$repo/src/a.c"
git -C "$repo" add -A
git -C "$repo" commit -q --no-verify -m init
ci() { git -C "$repo" commit -q --no-verify --allow-empty -m "$1"; }
hooked() { git -C "$repo" commit -q -m "$1"; }
zd() { "$bindir/zcl-dev-hooks" "$@"; }

# ---- install and status
cd "$repo"
expect "status before install is not ready" 1 "NOT ready" zd status
expect "install" 0 "core.hooksPath = zcutil/githooks" zd install
expect "status after install" 0 "hooks: installed" zd status
expect "status json" 0 '"ok":true' zd status --json
git config core.hooksPath other
expect "install refuses a foreign hooksPath" 1 "already 'other'" zd install
expect "install --force" 0 "zcutil/githooks" zd install --force
expect "dispatch through zcl-dev" 0 "hooks: installed" "$bindir/zcl-dev" -C "$repo" hooks status
[ "$(git config core.hooksPath)" = zcutil/githooks ] || bad "hooksPath value"

# ---- pre-commit: primary checkout guard
echo 1 >>src/a.c; git add src/a.c
expect "master commit in primary" 0 "" hooked c1
git checkout -q -b feat
echo 2 >>src/a.c; git add src/a.c
expect "side branch, no other worktree" 0 "" hooked c2
git worktree add -q "$work/wt" -b lane
echo 3 >>src/a.c; git add src/a.c
expect "side branch in primary with a worktree is refused" 1 "primary checkout" hooked c3
expect "ZCL_LANE_COMMIT_OK=1 allows it" 0 "" env ZCL_LANE_COMMIT_OK=1 git commit -q -m c3
echo 4 >>"$work/wt/src/a.c"; git -C "$work/wt" add src/a.c
expect "commit in a linked worktree" 0 "" git -C "$work/wt" commit -q -m w1
git checkout -q master
echo 5 >>src/a.c; git add src/a.c
expect "master in primary with a worktree" 0 "" hooked c4

# ---- pre-commit: python and vendor
echo 'print(1)' >tool.py; git add tool.py
expect "python file refused" 1 "Python is not allowed" hooked py
git rm -q --cached tool.py; rm tool.py
echo two >>zcutil/tools/vendor/v.c; git add zcutil/tools/vendor/v.c
expect "vendor edit without a row change refused" 1 "does not change" hooked v1
printf 'zcutil/tools/vendor/v.c\ttools/v.c\tdeadbeef\n' >>zcutil/tools/Z23_SOURCE.tsv; git add zcutil/tools/Z23_SOURCE.tsv
expect "vendor edit with its row allowed" 0 "" hooked v2
git rm -q zcutil/tools/vendor/v.c
expect "vendor delete without a row change refused" 1 "does not change" hooked v3
git reset -q --hard HEAD

# ---- pre-push
remote=$work/remote.git
git init -q --bare "$remote"
git remote add origin "$remote"
rcpt() { # rcpt <sha> <step> <verdict>
    printf '{"commit":"%s","tree":"t","stage":"test-run/release","step":"%s","verdict":"%s","seconds":1}\n' "$1" "$2" "$3" >>"$work/rc/receipts.jsonl"
}
head=$(git rev-parse HEAD)
expect "unprotected branch needs no receipt" 0 "" git push -q origin feat
expect "push to master without receipt" 1 "no local-ci receipt" git push -q origin master
rcpt "$head" unit-a PASS
expect "partial receipts" 1 "unit-b: no receipt" git push -q origin master
rcpt "$head" unit-b PASS
expect "push with passing receipts" 0 "" git push -q origin master
echo m2 >>src/a.c; git add src/a.c; ci m2; m2=$(git rev-parse HEAD)
rcpt "$head" unit-a PASS; rcpt "$head" unit-b PASS
expect "receipt of another commit does not count" 1 "no local-ci receipt" git push -q origin master
rcpt "$m2" unit-a FAIL; rcpt "$m2" unit-b PASS
expect "a failed step blocks" 1 "unit-a: failed" git push -q origin master
rcpt "$m2" unit-a PASS
expect "a later pass clears the failure" 0 "" git push -q origin master

# ALL expansion
mkdir weird; echo x >weird/x; git add weird/x; ci m3
m3=$(git rev-parse HEAD)
rcpt "$m3" unit-a PASS; rcpt "$m3" unit-b PASS
expect "ALL requires every declared step" 1 "unit-c: no receipt" git push -q origin master
rcpt "$m3" unit-c SKIP
expect "ALL refuses a SKIP-only step" 1 "unit-c: skipped" git push -q origin master
rcpt "$m3" unit-c PASS
expect "ALL requires the stages and the test-build receipts" 1 "daemon-win64: no receipt" git push -q origin master
rcpt "$m3" daemon-linux PASS; rcpt "$m3" daemon-win64 PASS; rcpt "$m3" wallet-linux PASS
expect "ALL still requires build-tests" 1 "build-tests: no receipt" git push -q origin master
rcpt "$m3" build-tests PASS; rcpt "$m3" fetch-params PASS
rcpt "$m3" wallet-qt-logic-widget SKIP
expect "ALL accepts only the Qt step skipped, ignores tor-* (even when a rule names it) and dry-*" 0 "" git push -q origin master

# release/* is protected too
echo m4 >>src/a.c; git add src/a.c; ci m4; m4=$(git rev-parse HEAD)
expect "release branch needs a receipt" 1 "release/1.0" git push -q origin "$m4:refs/heads/release/1.0"
rcpt "$m4" unit-a PASS; rcpt "$m4" unit-b PASS; rcpt "$m4" unit-c PASS
for s in daemon-linux daemon-win64 wallet-linux build-tests fetch-params wallet-qt-logic-widget; do rcpt "$m4" $s PASS; done # the first release push carries weird/ (ALL)
expect "release branch with receipt" 0 "" git push -q origin "$m4:refs/heads/release/1.0"

# a rule that selects only stages must still require their receipts
mkdir stageonly; echo s >stageonly/s; git add stageonly/s; ci s1; s1=$(git rev-parse HEAD)
rcpt "$s1" unit-a PASS; rcpt "$s1" unit-b PASS
expect "stage-only diff requires the stage receipts" 1 "daemon-linux: no receipt" git push -q origin master
rcpt "$s1" daemon-linux PASS
expect "stage-only diff still needs the second stage" 1 "daemon-win64: no receipt" git push -q origin master
rcpt "$s1" daemon-win64 FAIL
expect "a failed stage blocks" 1 "daemon-win64: failed" git push -q origin master
rcpt "$s1" daemon-win64 PASS
expect "stage-only diff with both stage receipts" 0 "" git push -q origin master

# SKIP never counts for an explicitly selected step, even after a FAIL
echo k >>src/a.c; git add src/a.c; ci k1; k1=$(git rev-parse HEAD)
rcpt "$k1" unit-a PASS; rcpt "$k1" unit-b SKIP
expect "explicit step with only a SKIP receipt is refused" 1 "unit-b: skipped" git push -q origin master
rcpt "$k1" unit-b FAIL; rcpt "$k1" unit-b SKIP
expect "a SKIP after a FAIL does not clear it" 1 "unit-b: skipped" git push -q origin master
rcpt "$k1" unit-b PASS
expect "a later PASS admits it" 0 "" git push -q origin master

# empty diff: some PASS receipt for the sha is still required
ci e1; e1=$(git rev-parse HEAD)
expect "empty diff without any receipt" 1 "no local-ci receipt" git push -q origin master
rcpt "$e1" unit-a SKIP
expect "empty diff with only SKIP receipts" 1 "changes no files" git push -q origin master
rcpt "$e1" unit-a PASS
expect "empty diff with a PASS receipt" 0 "" git push -q origin master

# a diff that selects only qa scripts has nothing a receipt can cover
git checkout -q -b so; mkdir scriptonly; echo q >scriptonly/q; git add scriptonly/q; ci so1; so1=$(git rev-parse HEAD)
rcpt "$so1" unit-a PASS; rcpt "$so1" unit-b PASS
expect "script-only selection is refused" 1 "only qa scripts" git push -q origin so:master
git checkout -q master; git branch -q -D so

# the rules come from the pushed commit, not from the dirty work tree
printf 'src/*\t-\nweird/*\tALL\nstageonly/*\tdaemon-linux daemon-win64\nscriptonly/*\tqa/rpc-tests/x.sh\n' >zcutil/dev/impact.rules
echo r >>src/a.c; git add src/a.c; ci r1
expect "dirty rules do not weaken the push" 1 "no local-ci receipt" git push -q origin master
git checkout -q zcutil/dev/impact.rules

# default receipt directory (no ZCL_CI_OUT): 9-character and full-sha directories both work
r1=$(git rev-parse HEAD)
mkdir -p "$work/home/work/zc23-localci-out/$(printf %.9s "$r1")"
printf '{"commit":"%s","tree":"t","stage":"test-run/release","step":"unit-a","verdict":"PASS","seconds":1}\n{"commit":"%s","tree":"t","stage":"test-run/release","step":"unit-b","verdict":"PASS","seconds":1}\n' "$r1" "$r1" >"$work/home/work/zc23-localci-out/$(printf %.9s "$r1")/receipts.jsonl"
expect "default 9-character receipt directory" 0 "" env -u ZCL_CI_OUT git push -q origin master
echo f >>src/a.c; git add src/a.c; ci f1; f1=$(git rev-parse HEAD)
mkdir -p "$work/home/work/zc23-localci-out/$f1"
printf '{"commit":"%s","tree":"t","stage":"test-run/release","step":"unit-a","verdict":"PASS","seconds":1}\n{"commit":"%s","tree":"t","stage":"test-run/release","step":"unit-b","verdict":"PASS","seconds":1}\n' "$f1" "$f1" >"$work/home/work/zc23-localci-out/$f1/receipts.jsonl"
expect "default full-sha receipt directory" 0 "" env -u ZCL_CI_OUT git push -q origin master

# the pushed commit cannot choose its own required set: the remote's rules and steps still apply
git checkout -q -b nar
printf 'src/*|zcutil/*|.gitignore\tunit-a\nweird/*\tALL\nstageonly/*\tdaemon-linux daemon-win64\nscriptonly/*\tqa/rpc-tests/x.sh\n' >zcutil/dev/impact.rules
echo n >>src/a.c; git add -A; ci nar1; nar1=$(git rev-parse HEAD)
rcpt "$nar1" unit-a PASS
expect "a push that narrows impact.rules still needs the base-required steps" 1 "unit-b: no receipt" git push -q origin nar:master
git checkout -q master; git branch -q -D nar
git checkout -q -b nls
grep -v 'unit-c' zcutil/local-ci.sh >"$work/ci.new"; cp "$work/ci.new" zcutil/local-ci.sh
echo n >>src/a.c; git add -A; ci nls1; nls1=$(git rev-parse HEAD)
rcpt "$nls1" unit-a PASS; rcpt "$nls1" unit-b PASS
expect "a push that deletes a local-ci step requires the full set including it" 1 "unit-c: no receipt" git push -q origin nls:master
git checkout -q master; git branch -q -D nls

# local-ci.sh missing at the pushed commit under ALL: refused with a message, ZCL_PUSH_OK still works
git checkout -q -b nolc
git rm -q zcutil/local-ci.sh; mkdir -p weird; echo y >weird/y; git add -A; ci nolc1; nolc1=$(git rev-parse HEAD)
expect "missing local-ci.sh under ALL is refused, not a die" 1 "cannot read zcutil/local-ci.sh" git push -q origin nolc:refs/heads/release/2.0
expect "missing local-ci.sh can use the logged override" 0 "ZCL_PUSH_OK override" env ZCL_PUSH_OK="no local-ci yet" git push -q origin nolc:refs/heads/release/2.0
git checkout -q master; git branch -q -D nolc

# a NEW protected ref does not take its gate from the pushed commit: master's gate applies
git checkout -q -b newr
printf '*	-
' >zcutil/dev/impact.rules
echo n >>src/a.c; git add -A; ci newr1; newr1=$(git rev-parse HEAD)
rcpt "$newr1" unit-a PASS
expect "new release/x whose commit narrows the rules is refused without the base-required receipts" 1 "unit-b: no receipt" git push -q origin newr:refs/heads/release/x
expect "same for a case variant" 1 "unit-b: no receipt" git push -q origin newr:refs/heads/Release/Y
git update-ref -d refs/remotes/origin/master
expect "tracking ref unknown: master read with ls-remote, still refused" 1 "unit-b: no receipt" git push -q origin newr:refs/heads/release/x
git fetch -q origin
expect "narrowing is refused with the logged override still available" 0 "ZCL_PUSH_OK override" env ZCL_PUSH_OK="newref test" git push -q origin newr:refs/heads/release/x
git push -q origin :refs/heads/release/x --no-verify
git remote add empty "$work/empty.git"; git init -q --bare "$work/empty.git"
expect "no master on the remote: a new release/x is refused, not trusted" 1 "no trusted master gate" git push -q empty newr:refs/heads/release/x
expect "no master on the remote: the override still works" 0 "ZCL_PUSH_OK override" env ZCL_PUSH_OK="bootstrap" git push -q empty newr:refs/heads/release/x
git checkout -q master; git branch -q -D newr

# protected refs are matched case-insensitively
expect "case variant of master is protected" 1 "no local-ci receipt" git push -q origin HEAD:refs/heads/Master
expect "case variant of release/ is protected" 1 "no local-ci receipt" git push -q origin HEAD:refs/heads/Release/x

# non-fast-forward and deletion
git checkout -q -b div "$head"
echo d >>src/a.c; git add src/a.c; git commit -q --no-verify -m diverge
d=$(git rev-parse HEAD)
rcpt "$d" unit-a PASS; rcpt "$d" unit-b PASS
expect "non-fast-forward refused even with receipts" 1 "not a fast-forward" git push -q --force origin div:master
expect "ZCL_PUSH_OK overrides, loudly" 0 "ZCL_PUSH_OK override" env ZCL_PUSH_OK="test reason" git push -q --force origin div:master
grep -q "ref=refs/heads/master .*new=$d reason=test reason" "$repo/.git/zcl-push-overrides.log" && ok "override recorded in .git/zcl-push-overrides.log" || bad "override log"
expect "deleting master refused" 1 "deleting refs/heads/master" git push -q origin :master
[ "$(git -C "$remote" rev-parse master)" = "$d" ] || bad "remote master moved unexpectedly"

[ "$fails" = 0 ] && { echo "hooks: all tests passed"; exit 0; }
echo "hooks: $fails FAILED" >&2
exit 1
