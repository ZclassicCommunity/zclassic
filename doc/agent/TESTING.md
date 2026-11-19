# Focused tests for agents and developers

`zcl-dev tests`, `t-fast`, `t-list` and `check-tests` pick and run the smallest native test set for a change, outside the proot CI. They replace "run everything and wait" with seconds to minutes on a built tree. The full gate stays `zcutil/local-ci.sh`; this is the inner loop before it.

```sh
make -C zcutil/dev && make -C zcutil/dev/tests     # or: make -C zcutil
zcutil/bin/zcl-dev tests src/bech32.cpp            # prints boost:bech32_tests
zcutil/bin/zcl-dev t-fast --dry-run src/txmempool.cpp
zcutil/bin/zcl-dev t-fast src/test/bech32_tests.cpp
```

## Commands

| Command | Does |
|---|---|
| `zcl-dev tests [--json] <path>...` | Prints the focused set: `boost:<suite>`, `gtest:<Suite>`, `qa:<script>` lines, then `broad:` and `note:` lines. |
| `zcl-dev t-fast [--changed[=base]] [--dry-run] [--narrow] [--no-qa] [--json] [--bin=src] [<path>...]` | Runs that set. `--changed` takes the committed diff against `base` (default `origin/master`, else the upstream merge-base, else `HEAD`). `--dry-run` prints the exact argv, one `exec:` line per command. |
| `zcl-dev t-list [--json] [--after=N] [boost\|gtest\|qa\|ci]` | Every Boost suite, gtest suite, qa script and local-ci step. |
| `zcl-dev check-tests [--json] [--after=N] [--base=ref] [--update-baseline]` | The registration gate (below). | It reads tracked files only: `git add` a new test file before running it. `--json` lists are capped, with `<key>_omitted` counts.

Output stays under 16 KiB. A long list ends with `-- more: rerun with --after=N`; JSON carries `total`, `after` and `next`. Exit codes: 0 ok, 1 finding or failed test, 2 broken input or an empty scan (no paths, no changed files, a hollow `check-tests`), 3 test binary missing or stale.

## How a path maps to tests

The sets are unioned:

1. `zcutil/dev/tests.rules` lines `glob<TAB>boost:<suite> gtest:<Suite> qa:<script> narrow` (globs as in `impact.rules`, `*` crosses `/`).
2. Name heuristic: `src/foo.cpp` or `src/x/foo.h` maps to `src/test/foo_tests.cpp` and `src/gtest/test_foo.cpp`, and to the same names beside the source (`src/wallet/test`, `src/wallet/gtest`), ignoring case. <!-- doc-path-ok -->
3. A test file maps to its own suites. A `qa/rpc-tests/*.sh` script maps to itself.

Suites are read from the sources: `BOOST_AUTO_TEST_SUITE(` and `BOOST_FIXTURE_TEST_SUITE(` in `src/test` and `src/wallet/test`; `TEST(`, `TEST_F(` and `TEST_P(` in `src/gtest` and `src/wallet/gtest`.

## Broad changes are never narrowed silently

`zcutil/dev/impact.rules` is the authority on risk. A path it marks `ALL` (consensus, chain state, daemon wallet, build system) or does not map at all prints

```
broad: run zcutil/local-ci.sh test-changed (broad rule: src/main.cpp)
```

and `t-fast` then runs the full `test_bitcoin` and `zcash-gtest`. `--narrow` runs only the focused set and keeps the `broad:` note. A `tests.rules` line may carry the token `narrow` to take one path out of `ALL` on purpose (today only `src/bech32.*`, address encoding); `check-tests` rejects `narrow` on every path that `impact.rules` marks `ALL` (or maps nowhere) unless it is on the allowlist in `zcl-dev-tests.c` (today `src/bech32.`), so new consensus and chain-state paths stay protected. `tests` prints a note for such a path, and `local-ci.sh test-changed` stays the gate before landing. <!-- doc-path-ok -->

Qt wallet changes (`wallet/src/*`) add an informational line naming the `wallet/tests/*.pro` targets; qmake builds are out of scope.

## Running

* Boost: `src/test/test_bitcoin --run_test=<s1>:<s2> --log_level=test_suite`. Boost 1.85 accepts `a:b` (the self-test checks it against a real build when `ZCL_TESTS_BIN` is set). `--list_content` does not apply the filter, so `t-fast` confirms a multi-suite run by the `Entering test suite` log lines and reruns any suite that did not enter on its own.
* gtest: `src/zcash-gtest --gtest_filter=Suite.*:Suite2.*`; a `TEST_P` suite is named `Prefix/Suite.Name/n` by googletest, so its filter is `Suite.*:*/Suite.*`. googletest exits 0 when a filter matches nothing, so `t-fast` fails a run that reports `Running 0 tests` or never runs a selected suite.
* qa: the argument form comes from the script text: `sh qa/rpc-tests/<x>.sh --bin <bin> --work zcutil/gen/t-fast-work/<x>` when it mentions `--bin`; `sh <script> <bin>` when its usage line takes a positional `<dir ...>` (startup_bad_home, zslp_send, wallet_tokenguard and the like); else `sh <script>`. A sourced fragment (`wallet_matrix_scn<N>.sh`) is not a script: editing it runs the owner (`wallet_matrix.sh`) with `--only` for the scenarios it defines (the load scenario 11 is never selected). Scripts run one after another, never in parallel. Most take leased ports through `qa/lib/isolation.sh`; a few (for example `startup_bad_home.sh`) do not. `--no-qa` skips them.
* `--bin=<dir>` is the directory holding `test/test_bitcoin`, `zcash-gtest` and `zclassicd` (default `src`).

`t-fast` never builds. When a needed binary is missing, or older than a changed `src/` source, it prints the exact line and exits 3 (a dry run prints it as a note and exits 0):

```
make -C src -j$(nproc) test/test_bitcoin
make -C src -j$(nproc) zcash-gtest
```

Prefix those with `devbuild --wait` on a maintainer host.

## The registration gate

`zcl-dev check-tests` fails (exit 1) when:

* a `src/test/*_tests.cpp` (or `src/wallet/test`) is not in `BITCOIN_TESTS` of `src/Makefile.test.include`, or a `src/gtest/*.cpp` (or `src/wallet/gtest`) is not in `zcash_gtest_SOURCES` of `src/Makefile.gtest.include`; or a listed file does not exist (the test would silently never build);
* a Boost suite name is declared in two files;
* a `tests.rules` glob matches no file, or a token names an unknown suite, script or keyword;
* a `qa/rpc-tests/*.sh` script (not `*_lib.sh`, not a `_scn<N>.sh` fragment) is not named by `impact.rules`, `tests.rules` or a non-comment line of `local-ci.sh` (whole-name match, so `send.sh` is not reached by `zslp_send.sh`), and is not called by a script that is;
* `zcutil/dev/tests/baseline` gained a row relative to `--base=<ref>` (default `origin/master`; where that does not resolve, the merge-base with the upstream branch, then `HEAD`, and the command says which; an unsafe or unresolvable explicit ref exits 2; skipped only when the ref resolves and has no baseline). The ratchet trusts the base it is given, so the gate wiring (local-ci, U16) must pass the merge-base with the integration branch, for example `--base=origin/master`; the `HEAD` fallback only catches uncommitted growth.

It exits 2 on a hollow scan (no Boost files, no gtest files or no suites found).

Some scripts in the tree are run by no CI step today. They are listed in `zcutil/dev/tests/baseline`, a ratchet that may only shrink: a new unreachable script fails, a baseline row that became reachable fails, and `check-tests --update-baseline` drops fixed rows but refuses while anything new is unreachable. Fix an entry by running the script from a `local-ci.sh` step or a `qa:` token, never by adding rows.

## Files

* `zcutil/dev/tests/zcl-dev-tests.c`: one binary, installed under four names (`zcl-dev-tests`, `-t-fast`, `-t-list`, `-check-tests`); the command is its own file name, and `zcl-dev` dispatches to it.
* `zcutil/dev/tests.rules`, `zcutil/dev/tests/baseline`: the data.
* `make -C zcutil/dev/tests check`: self-test on a fixture tree with fake test binaries and golden outputs (`UPDATE=1 sh zcutil/dev/tests/test/run.sh zcutil/bin` rewrites them).
* The code is plain C (gnu17, also `-std=c2x`), libc only, and cross-builds with `x86_64-w64-mingw32-gcc`.

The `narrow` token in `tests.rules` is an allowlist enforced when the set is built, by `tests` and `t-fast` as well as by `check-tests`: it only takes effect on `src/bech32.*`. On any other path the row is ignored with a note and the `broad:` full run stays, so a hand-edited rules file cannot narrow a consensus, chain or wallet path. On Windows, `^` is not accepted in refs (cmd.exe strips it); use the `~N` form.

## Repeat and time

A timing-dependent assertion or a suite that swings under host load needs repetition, not a single green run: `zcutil/bin/zcl-dev flaky -n 20 [--jobs 3] -- sh qa/rpc-tests/<script>.sh --bin <dir> --work @WORK@` runs it N times in fresh directories (`@WORK@` is the run directory; qa scripts lease their own ports, so `--jobs` is safe for them) and prints PASS, FLAKY or FAILING with the first failing log ([zcutil/dev/flaky/README.md](../../zcutil/dev/flaky/README.md)). `zcutil/bin/zcl-dev timings <outdir>...` reads local-ci `results.tsv` and `receipts.jsonl` and ranks steps by median seconds, marks steps that got slower, and lists unreadable inputs instead of counting them as zero ([zcutil/dev/timings/README.md](../../zcutil/dev/timings/README.md)).
