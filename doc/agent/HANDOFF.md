# HANDOFF: live state of the developer tooling

This page is the one place for statements about "what is true right now". Every load-bearing line below is a
`claim` that `zcutil/bin/zcl-lint doc-claims` re-checks against the tree, so the page cannot quietly go stale.
Update it in the same commit that changes the fact it records.

## How a claim is written

A claim is an HTML comment on one line, anywhere in a tracked Markdown file:

```
<!-- claim: file-present path/to/file # why it matters -->
<!-- claim: file-absent path/that/must/not/exist -->
<!-- claim: symbol-present SYMBOL pathspec -->
<!-- claim: symbol-absent SYMBOL pathspec -->
<!-- claim: rule-passes zcl-lint-rule -->
<!-- claim: step-exists local-ci-step -->
```

`symbol-*` uses `git grep -lwF`. `rule-passes` runs the built `zcutil/bin/zcl-lint` with that one rule (never
`doc-claims` itself). `step-exists` looks for a `step <name>` line in `zcutil/local-ci.sh`. A malformed or false
claim fails with file:line.

## Contract and tooling in the tree

The agent contract and its two companions exist:
<!-- claim: file-present AGENTS.md # the shared contract -->
<!-- claim: file-present CLAUDE.md # imports AGENTS.md -->
<!-- claim: file-present doc/agent/TRAPS.md # check before repairing intentional behaviour -->
<!-- claim: file-present doc/agent/LESSONS.md # one line per measured lesson -->

The developer tools are built from C in `zcutil/`:
<!-- claim: file-present zcutil/dev/zcl-dev.c # the zcl-dev driver -->
<!-- claim: file-present zcutil/lint/zcl-lint.c # the lint driver -->
<!-- claim: file-present zcutil/lint/rules.def # one row per lint rule -->
<!-- claim: symbol-present lint_ratchet zcutil/lint/lintlib.c # the shrink-only ratchet -->
<!-- claim: symbol-present lint_hollow zcutil/lint/lintlib.c # an empty scan fails, never passes -->
<!-- claim: symbol-absent sqlite3_open zcutil/lint # the tools stay libc only -->

## Things that must stay absent

There are no hosted CI workflows, and no Python tooling:
<!-- claim: file-absent .github/workflows # CI runs on our own machines -->
<!-- claim: file-absent zcutil/lint/lint.py # glue is C or POSIX sh -->

## Gates that pass on this tree

The markdown links, banned string calls, vendored files and the no-Python scan each pass:
<!-- claim: rule-passes md-links -->
<!-- claim: rule-passes banned-str -->
<!-- claim: rule-passes vendor -->
<!-- claim: rule-passes no-python -->

## Local CI steps this page relies on

<!-- claim: step-exists zcl-lint # the lint gates run as a local-ci step -->
<!-- claim: step-exists check-no-python -->
<!-- claim: step-exists regtest-smoke -->

## Release version

The node version comes from `configure.ac` (`_CLIENT_VERSION_BUILD` drives the beta suffix) and must agree with
`wallet/src/version.h` and the release scripts; `zcl-lint version-facts` enforces it.
<!-- claim: symbol-present _CLIENT_VERSION_BUILD configure.ac -->
<!-- claim: rule-passes version-facts -->

## Victory wording

In this page a paragraph that says a problem is fixed, cured, fully synced, at tip or green must cite a commit id,
a receipt path or a `local-ci` results path, or carry an exemption comment with a reason (see
`zcl-lint victory`). Opinion without evidence does not belong here.
<!-- victory-ok: this paragraph states the rule and reports no result -->
