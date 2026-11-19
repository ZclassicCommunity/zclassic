#!/bin/sh
# Fixture-repo tests for zcl-dev-review: throwaway repos under mktemp -d, commits with Co-Authored-By
# trailers, golden outputs with commit ids replaced by labels (@c1, @r1, ...) and dates by <date>.
# usage: sh test/run.sh <zcl-dev-review>      UPDATE=1 rewrites the golden files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
rv=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d "${TMPDIR:-/tmp}/zcl-review-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null HOME="$work/home"
mkdir -p "$work/home"
repo=$work/repo
labels=$work/labels
: >"$labels"
fails=0
n=0
OPUS="Claude Opus 5.5 <noreply@anthropic.com>"
SONNET="Claude Sonnet 5.5 <noreply@anthropic.com>"
HEADER_LINES='# test header'

g() { git -C "$repo" "$@"; }
lab() { sha=$(g rev-parse "$2"); echo "$1 $sha" >>"$labels"; eval "L_$1=$sha"; }
mk() { # mk <subject> [trailer]: a new commit changing one file
    n=$((n + 1))
    echo "$n" >"$repo/f$n"
    g add "f$n"
    if [ $# -ge 2 ]; then g commit -q -m "$1" -m "Co-Authored-By: $2"; else g commit -q -m "$1"; fi
}
commit_rows() { g commit -q -m "review: record" -- doc/agent/REVIEWS.tsv; }
rows_row() { # rows_row <range> <tree> <authors> <reviewer> <verdict>: a hand-written row appended and committed
    printf '%s\t%s\t%s\t%s\t%s\t2026-01-01T00:00:00Z\thand written\n' "$1" "$2" "$3" "$4" "$5" >>"$repo/doc/agent/REVIEWS.tsv"
    commit_rows
}
normalize() {
    sed_script=$work/sed
    : >"$sed_script"
    while read -r name sha; do
        echo "s/$sha/@$name/g" >>"$sed_script"
        echo "s/$(printf %.7s "$sha")/@$name/g" >>"$sed_script"
    done <"$labels"
    echo 's/[0-9a-f]{40}/<id>/g' >>"$sed_script"
    echo 's/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z/<date>/g' >>"$sed_script"
    echo 's/^  [0-9a-f]{7} /  <sha7> /' >>"$sed_script"
    sed -E -f "$sed_script"
}
compare() { # compare <name> : stdin is the (already normalized) output
    cat >"$work/got"
    if [ "${UPDATE:-}" = 1 ]; then cp "$work/got" "$here/golden/$1.out"; return 0; fi
    if diff -u "$here/golden/$1.out" "$work/got" >"$work/diff" 2>&1; then
        echo "ok   $1"
    else
        echo "FAIL $1"
        cat "$work/diff"
        fails=$((fails + 1))
    fi
}
golden() { # golden <name> <wanted exit> <review args...>
    name=$1; want=$2; shift 2
    rc=0
    (cd "$repo" && "$rv" "$@") >"$work/out" 2>&1 || rc=$?
    if [ "$rc" != "$want" ]; then
        echo "FAIL $name (exit $rc, wanted $want)"
        cat "$work/out"
        fails=$((fails + 1))
        return 0
    fi
    { cat "$work/out"; echo "exit=$rc"; } | normalize | compare "$name"
}
branch() { g checkout -q -b "$1" "$2"; }

# ---- the fixture history ------------------------------------------------------------------
git init -q -b main "$repo"
g config user.name "Pat Human"
g config user.email pat@example.invalid
mkdir -p "$repo/doc/agent"
printf '%s\n' "$HEADER_LINES" >"$repo/doc/agent/REVIEWS.tsv"
g add -A
g commit -q -m "base"
lab base HEAD
mk "feat: one" "$OPUS"
lab c1 HEAD
mk "fix: two" "$SONNET"
lab c2 HEAD
lab tree2 "HEAD^{tree}"

golden usage 2 check
golden uncovered 1 check "$L_base..$L_c2"
golden empty-range-check 0 check "$L_base..$L_base"
golden empty-range-record 1 record --reviewer x --verdict ACCEPT "$L_base..$L_base"
golden bad-verdict 1 record --reviewer x --verdict MAYBE "$L_base..$L_c2"
golden author-same-name 1 record --reviewer "Claude Opus 5.5" --verdict ACCEPT "$L_base..$L_c2"
golden author-normalized 1 record --reviewer claude-opus-5-5 --verdict ACCEPT "$L_base..$L_c2"
golden bad-range-record 2 record --reviewer x --verdict ACCEPT "$L_base"
golden record-accept 0 record --reviewer "Gpt Reviewer" --verdict ACCEPT-WITH-FIXES --evidence "log /tmp/review-1.log" "$L_base..$L_c2"
golden worktree-not-read 1 check "$L_base..$L_c2"
commit_rows
lab r1 HEAD
golden covered 0 check "$L_base..$L_r1"
golden rows-from 0 check --rows-from "$L_r1" "$L_base..$L_c2"
golden rows-from-tip 1 check "$L_base..$L_c2"
golden json-covered 0 check --json "$L_base..$L_r1"
golden json-uncovered 1 check --json "$L_base..$L_c2"
golden not-ancestor 2 check "$L_c2..$L_c1"
golden bad-revision 2 check "$L_base..nosuchrev"

# reviewer is one of the authors (a row written by hand; record refuses to write it)
branch author-row "$L_c2"
rows_row "$L_base..$L_c2" "$L_tree2" "claude sonnet 5.5" "claude-sonnet-5-5" ACCEPT
lab tip_author HEAD
golden author-row 1 check "$L_base..HEAD"

# a row whose tip tree does not match the tip commit is stale
branch bad-tree "$L_c2"
rows_row "$L_base..$L_c2" "0000000000000000000000000000000000000000" "x" "someone else" ACCEPT
lab tip_tree HEAD
golden stale-tree 1 check "$L_base..HEAD"

# commit --amend after the review: the new tip is not covered, the unchanged first commit still is
branch amend "$L_c2"
echo amended >"$repo/fa"
g add fa
g commit -q --amend -m "fix: two" -m "Co-Authored-By: $SONNET"
lab c2a HEAD
g cherry-pick "$L_r1" >/dev/null
lab r1a HEAD
golden stale-amend 1 check "$L_base..$L_r1a"

# REJECT overrides the earlier accept; a later accept restores it
branch reject "$L_r1"
golden reject-record 0 record --reviewer "Strict Rev" --verdict REJECT --evidence "needs work" "$L_base..$L_r1"
commit_rows
lab r2 HEAD
golden reject-override 1 check "$L_base..$L_r2"
golden reject-reaccept 0 record --reviewer "Third Rev" --verdict ACCEPT "$L_base..$L_r2"
commit_rows
lab r3 HEAD
golden reject-then-accept 0 check "$L_base..$L_r3"

# a commit without trailers is human work: record refuses its author as reviewer
branch human "$L_c2"
mk "chore: human edit"
lab c3 HEAD
golden human-uncovered 1 check "$L_c2..$L_c3"
golden human-author 1 record --reviewer "pat-human" --verdict ACCEPT "$L_c2..$L_c3"
golden human-record 0 record --json --reviewer "Other Person" --verdict ACCEPT "$L_c2..$L_c3"
commit_rows
lab r4 HEAD
golden human-covered 0 check "$L_c2..$L_r4"

# malformed rows are exit 2 and name the line
branch malformed "$L_c2"
printf 'not a row\n' >>"$repo/doc/agent/REVIEWS.tsv"
commit_rows
golden malformed-fields 2 check "$L_base..HEAD"
g reset -q --hard "$L_c2"
printf '%s..%s\t%s\ta\tb\tMAYBE\t2026-01-01T00:00:00Z\t\n' "$L_base" "$L_c2" "$L_tree2" >>"$repo/doc/agent/REVIEWS.tsv"
commit_rows
golden malformed-verdict 2 check "$L_base..HEAD"
golden no-rows-file 2 check --rows-from nosuchrev "$L_base..$L_c2"

# paging: many uncovered commits with long subjects stay under 16 KiB a page
branch many "$L_c2"
i=0
long=$(printf 'x%.0s' $(seq 1 300))
while [ $i -lt 80 ]; do
    i=$((i + 1))
    g commit -q --allow-empty -m "change $i $long"
done
lab many_tip HEAD
page() { # page <name> <review args...>: the shape of one page, not its 80 long lines
    name=$1; shift
    rc=0
    (cd "$repo" && "$rv" "$@") >"$work/pg" 2>&1 || rc=$?
    {
        echo "exit=$rc"
        echo "lines=$(wc -l <"$work/pg" | tr -d ' ')"
        [ "$(wc -c <"$work/pg")" -lt 16384 ] && echo "under 16 KiB" || echo "OVER 16 KiB"
        head -2 "$work/pg" | cut -c1-60
        tail -3 "$work/pg" | cut -c1-60
    } | normalize | compare "$name"
}
page paging-first check "$L_c2..HEAD"
next=$(cd "$repo" && "$rv" check "$L_c2..HEAD" | sed -n 's/.*rerun with --after=\([0-9]*\).*/\1/p')
page paging-second check --after="$next" "$L_c2..HEAD"
page paging-past-end check --after=1000 "$L_c2..HEAD"
page paging-json check --json "$L_c2..HEAD"

if [ "$fails" = 0 ]; then echo "review: all tests passed"; exit 0; fi
echo "review: $fails FAILED" >&2
exit 1
