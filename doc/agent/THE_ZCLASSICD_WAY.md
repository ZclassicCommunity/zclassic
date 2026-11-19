# The zclassicd way

One development loop for humans and coding agents: orient, take a worktree, edit within ownership, prove it narrowly, lint, get a non-author review, run local CI, push through the admission hook, release. If this page and a deeper document disagree, the deeper document wins and this page is the bug; the authority rules stay in [AGENTS.md](../../AGENTS.md).

Adapted from Z23's standard loop (Z23 `docs/THE_Z23_WAY.md`) for this tree's tools: `zcl-dev`, `zcl-lint` and `zcutil/local-ci.sh` instead of Z23's lanes and land queue. <!-- doc-path-ok -->

## 1. Orient

Build the tools once (`make -C zcutil`, light, no node build needed), then ask before you search:

- `zcutil/bin/zcl-dev guide <paths>` prints the nearest `AGENTS.md` rules, the local-ci steps the paths select, the matching lessons and the [TRAPS.md](TRAPS.md) sections whose `Paths:` lines match. <!-- claim: symbol-present find_traps zcutil/dev/zcl-dev.c -->
- `zcl-dev code map|owner|impact|file|sym|refs <arg>` answers where a symbol lives, who owns a path and what a change reaches (`zcutil/dev/code/code.c`). <!-- claim: file-present zcutil/dev/code/code.c -->
- `zcl-dev wiki [topic]` walks `doc/` and the source tree one topic at a time; `zcl-dev lessons find <words>` searches lessons, traps and facts; `zcl-dev know <term>` answers from [FACTS.tsv](FACTS.tsv) or says `UNKNOWN` ([WIKI.md](WIKI.md)). <!-- claim: file-present zcutil/dev/wiki/Makefile -->
- `zcl-dev doctor` lists what this host lacks to build and test, with the fix for each gap.

Read [TRAPS.md](TRAPS.md) before repairing anything that looks wrong: it may be intentional. Read [CONSENSUS_PARITY.md](CONSENSUS_PARITY.md) before touching a validation path and [DEFENSIVE_CODING.md](DEFENSIVE_CODING.md) before writing new code.

## 2. Take a worktree

One unit of work, one worktree, one branch, from an exact base commit:

```sh
git worktree add ../w-<unit> -b <topic>/<unit> <base-sha>
```

Never edit another person's checkout; never reset, overwrite or commit their dirty files. The pre-commit hook (`zcutil/dev/hooks/zcl-dev-hooks.c`, `pre_commit`) refuses a commit on a named branch in the primary checkout while other worktrees exist (`ZCL_LANE_COMMIT_OK=1` overrides), any staged `*.py`, and a change under `zcutil/tools/vendor/` whose manifest row did not change with it. Heavy builds go through the host's build broker where there is one (`devbuild --wait`). <!-- claim: symbol-present pre_commit zcutil/dev/hooks/zcl-dev-hooks.c --> <!-- claim: symbol-present ZCL_LANE_COMMIT_OK zcutil/dev/hooks/zcl-dev-hooks.c -->

## 3. Edit within ownership

- Change the smallest surface that does the job; reuse an existing helper before writing one.
- Vendored trees (`src/c23/vendor/`, `src/c23/services/vendor/`, `zcutil/tools/vendor/`) change only through their `revendor.sh`.
- Third-party trees (`src/leveldb/`, `src/secp256k1/`, `src/univalue/`, `src/pow/tromp/`, `depends/`) are not reformatted.
- A new source or test file is listed in `src/Makefile.am`, `src/Makefile.test.include` or `src/Makefile.gtest.include` and gets a row in `zcutil/dev/impact.rules`; `zcl-dev check-rules` fails otherwise. <!-- claim: file-present zcutil/dev/impact.rules -->
- Write the test first and watch it fail for the intended reason. Never weaken an assertion, threshold or timeout to make it pass.
- Ratchets only shrink. A file over 1,500 lines, a function over complexity 15 or over 500 lines, a new bashism or a new banned call fails `zcl-lint`; split the code rather than raise a baseline. <!-- claim: symbol-present COMPLEXITY_CAP zcutil/lint/rules/complexity.c --> <!-- claim: symbol-present FILESIZE_LIMIT zcutil/lint/rules/filesize.c -->

## 4. Focused proof

The inner loop is seconds to minutes on a built tree ([TESTING.md](TESTING.md)):

- `zcl-dev tests <path>` prints the Boost suites, gtest suites and qa scripts that cover a path; `zcl-dev t-fast <path>` runs them (`--dry-run` prints the argv, `--changed` uses the committed diff). A consensus, chain-state or wallet path prints `broad:` and runs the full suites. <!-- claim: file-present zcutil/dev/tests/zcl-dev-tests.c -->
- By hand: `src/test/test_bitcoin --run_test=<suite>`, `src/zcash-gtest --gtest_filter='<Suite>.*'`. Never run either binary bare as a quick check.
- One qa script: `sh qa/rpc-tests/<script>.sh --bin <dir> --work <empty dir>`; ports are leased by `qa/lib/isolation.sh`, so none need choosing. <!-- claim: symbol-present lease_ports qa/lib/isolation.sh -->
- Node builds for tests are out of tree, configured with `--enable-tests` ([doc/unit-tests.md](../unit-tests.md)).

## 5. Lint and verify

```sh
make -C zcutil check            # every developer tool's selftest
zcutil/bin/zcl-lint all         # every lint rule and ratchet
zcutil/bin/zcl-dev check-rules  # every source file has an impact rule
zcutil/bin/zcl-dev check-docs   # agent documents point at tracked paths
zcutil/bin/zcl-dev verify       # one trip: select, focused tests, lint
```

`zcl-dev verify --gates` runs the gates after the selftests and stops at the first failure. On Windows the lint step reports `UNAVAILABLE` (exit 2): run it on a POSIX host (`zcutil/dev/verify/zcl-verify.c`). Documentation claims are live: `zcl-lint doc-claims` evaluates every `<!-- claim: ... -->` marker in tracked Markdown, and `doc-paths` resolves every backticked path. <!-- claim: symbol-present UNAVAILABLE zcutil/dev/verify/zcl-verify.c --> <!-- claim: symbol-present lint_rule_doc_claims zcutil/lint/rules.def -->

## 6. Review

Every change is reviewed by someone other than its author, human or model, reading the exact commit. Commits are authored by the repository owner; an AI-written commit ends with a `Co-Authored-By:` trailer naming the model. A recorded-review command is not in this tree yet; the reviewer's verdict goes in the review thread with the commit hash. A change on a validation path also carries the evidence [CONSENSUS_PARITY.md](CONSENSUS_PARITY.md) asks for.

## 7. Local CI

CI runs on our own machines, never on a hosted service ([doc/local-ci.md](../local-ci.md)):

```sh
zcutil/bin/zcl-dev select [base-ref]                               # steps the diff needs
zcutil/local-ci.sh --commit <sha> --only <steps> test <outdir>     # focused
zcutil/local-ci.sh --commit <sha> test-changed <outdir>            # what select chose
zcutil/local-ci.sh --commit <sha> all <outdir>                     # full candidate
```

Every step appends one line to `<outdir>/receipts.jsonl`. Read the failing step's log, not the summary. A SKIP (exit 77) did not run. macOS uses `zcutil/local-ci-macos.sh`. <!-- claim: step-exists zcl-lint --> <!-- claim: step-exists check-dev-tools --> <!-- claim: file-present zcutil/local-ci-macos.sh -->

## 8. Push through admission

`zcl-dev hooks install` points `core.hooksPath` at `zcutil/githooks`. The pre-push hook (`pre_push` in `zcutil/dev/hooks/zcl-dev-hooks.c`) refuses a push to `master` or `release/<name>` unless it is a fast-forward and a local-ci receipt for the exact pushed commit shows every required step passed; the required set is `zcl-dev select` over the pushed diff, united with what the replaced commit's rules required. A SKIP is not a pass. `ZCL_PUSH_OK=<reason>` overrides and is logged. The receipts are self-attested: the hook guards against mistakes and is not proof that a commit was tested. <!-- claim: symbol-present pre_push zcutil/dev/hooks/zcl-dev-hooks.c --> <!-- claim: symbol-present protected_ref zcutil/dev/hooks/zcl-dev-hooks.c --> <!-- claim: file-present zcutil/githooks/pre-push -->

A push is a checkpoint, not the end: fetch, integrate and continue.

## 9. Release

Release binaries come from `zcutil/build-release.sh linux|win64` and the local-ci stages (`daemon-linux` keeps the glibc floor at `GLIBC_2.31`); check the artifact, its footer and hash, not an exit status behind a pipe ([doc/building-quickstart.md](../building-quickstart.md), [doc/release-notes.md](../release-notes.md)). `zcl-lint version-facts` holds the version strings to `configure.ac`. <!-- claim: file-present zcutil/build-release.sh --> <!-- claim: symbol-present lint_rule_version_facts zcutil/lint/rules.def -->

## What never happens

- **Production.** No touching a production service, its datadir (`~/.zclassic*`) or its ports; no wallet file or profile that is not an isolated test copy. <!-- doc-path-ok -->
- **Hosted CI.** No GitHub Actions or other hosted CI is added or dispatched; `zcl-lint kpi` holds `hosted_ci_files` at zero.
- **Python.** None, anywhere: `zcutil/check-no-python.sh` and the pre-commit hook refuse it. New tooling is C; glue is small POSIX sh.
- **Consensus edits without the ritual.** No sealed file changes without [UNSEAL.md](UNSEAL.md), and no unsealed validation-path change without the evidence ladder.
- **Custody.** No spending funds, exporting keys or weakening wallet encryption or privacy.
- **History.** No rewriting shared history, no force-push to a protected branch.
