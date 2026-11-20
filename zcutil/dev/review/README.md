# zcl-dev review

`zcl-dev review record|check`: a review verdict kept next to the commits it covers, in the tracked file
[`doc/agent/REVIEWS.tsv`](../../../doc/agent/REVIEWS.tsv). The pre-push hook refuses a push to `master` or
`release/*` whose commits no row covers.

    zcl-dev review record --reviewer R --verdict ACCEPT|ACCEPT-WITH-FIXES|REJECT [--evidence E] [--json] <base>..<tip>
    zcl-dev review check [--json] [--rows-from <commit>] [--after=N] <base>..<tip>

Workflow: a reviewer who is not an author reads `<base>..<tip>`, runs `record` (it appends the row to the
working-tree file and prints the commit command, it never commits), and the row is committed. A commit whose
only changed path is `doc/agent/REVIEWS.tsv` needs no row of its own.

`record` refuses (exit 1) when `<base>` is not an ancestor of `<tip>`, the range is empty, the verdict is not
a token, or the reviewer equals an author of the range after lowercasing and keeping only `[a-z0-9]`
(`Claude Opus 5.5` and `claude-opus-5-5` are one reviewer). Authors come from the `Co-Authored-By:` trailers of
the non-merge commits, `human:<git author>` for a commit without one.

`check` reads the rows from the tip commit (or `--rows-from`), never from the working tree. A commit C is covered
when a row has its base as an ancestor of C and C an ancestor-or-equal of the row tip, the row tip is present with
the tree recorded in `tip_tree`, the verdict is an accept, and the reviewer
is not an author of C. A later `REJECT` row containing C overrides earlier accepts; a later accept restores it.
A commit that no row reaches is reported `no row`; `stale row` is reserved for a row whose base precedes the commit
but whose tip is no longer an ancestor of the checked tip (history was rewritten or amended) or whose tree differs. The `tip_tree`
binding is a consistency check: a commit id already fixes its tree, so the ancestry test is what detects rewriting.
Exit 0 all covered, 1 uncovered commits listed as `<sha7> <subject> (<reason>)` with the reason `no row`, `stale row`,
`reviewer is author` or `rejected`, 2 broken (bad range, unreadable or malformed file with the line named).
Output stays under 16 KiB a page; `--after=N` continues a long list.

Hook: `zcl-dev-hooks.c` links `review-core.c` and runs the same check in-process over `<remote tip>..<pushed commit>`
(the merge base for a forced push, the remote master for a new ref). `ZCL_PUSH_OK` does not waive review; only
`git push --no-verify` does, the operator's explicit choice. Review is in force when the record exists at the base
or at the pushed commit, so a line of history older than the record is not blocked and deleting the record in the
pushed commit is no bypass.

Limits: the record is self-attested text. A reviewer name is not authenticated, the check binds a verdict to a tip
tree and range, not to a person, and `--no-verify` and a merge-created history are outside it. On Windows `record`
replaces the file with remove-then-rename (not atomic there).

Build and test: `make -C zcutil/dev/review check` (selftest, then fixture-repo goldens in `test/golden/`;
`UPDATE=1 sh test/run.sh ../../bin/zcl-dev-review` rewrites them). Libc only; git is run with an argument vector,
never through a shell.
