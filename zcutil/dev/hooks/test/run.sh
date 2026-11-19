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
git init -q -b master "$repo"
git -C "$repo" config user.name tester
git -C "$repo" config user.email t@example.invalid
mkdir -p "$repo/zcutil/dev" "$repo/zcutil/tools/vendor" "$repo/zcutil/bin" "$repo/src"
cp -R "$src/githooks" "$repo/zcutil/githooks"
cp "$bindir"/zcl-dev "$bindir"/zcl-dev-hook "$bindir"/zcl-dev-hooks "$repo/zcutil/bin/"
printf 'zcutil/bin/\n' >"$repo/.gitignore"
printf '*\tunit-a unit-b\nweird/*\tALL\n' >"$repo/zcutil/dev/impact.rules"
cat >"$repo/zcutil/local-ci.sh" <<'EOF2'
step() { :; }
    step unit-a 10 t_a
    step unit-b 10 t_b
    step unit-c 10 t_c
    step tor-x 10 t_tor
    step dry-pass 10 t_dry
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
expect "ALL accepts a self-skipped step, ignores tor-* and dry-*" 0 "" git push -q origin master

# release/* is protected too
echo m4 >>src/a.c; git add src/a.c; ci m4; m4=$(git rev-parse HEAD)
expect "release branch needs a receipt" 1 "release/1.0" git push -q origin "$m4:refs/heads/release/1.0"
rcpt "$m4" unit-a PASS; rcpt "$m4" unit-b PASS; rcpt "$m4" unit-c PASS
expect "release branch with receipt" 0 "" git push -q origin "$m4:refs/heads/release/1.0"

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
