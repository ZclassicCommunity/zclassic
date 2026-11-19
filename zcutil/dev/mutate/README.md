# zcl-dev mutate: mutation testing for one C or C++ file

Green tests say the tests pass. They do not say the tests would notice if the code were wrong.
`zcl-dev mutate` measures that: it applies one realistic defect at a time to a file, rebuilds, runs the
focused tests, and reports each mutant the tests let survive. The method comes from Z23's mutation
campaign (`tools/dev/mutation_*.c` at `9a191ef7b`, Apache-2.0, see [NOTICE](../../tools/NOTICE)); the
sources here are derived from it and changed.

```sh
make -C zcutil                                              # builds zcutil/bin/zcl-dev-mutate
zcutil/bin/zcl-dev mutate list src/shutdownmarker.cpp       # the sites, nothing is changed
zcutil/bin/zcl-dev mutate list <file> --lines 120-180 --class relational,return --json
zcutil/bin/zcl-dev mutate run zcutil/dev/wiki/facts.c --max 25 \
    --build "make -C zcutil/dev/wiki" -- make -C zcutil/dev/wiki check
zcutil/bin/zcl-dev mutate restore <file>                    # after a run that was killed with SIGKILL
make -C zcutil/dev/mutate check                             # selftest, c2x syntax check, fixture tests
```

## Operators

Only code the compiler reads is mutated: comments, string and character literals, C++ raw strings
(`R"d(...)d"`) and every preprocessor directive except `#define` are masked out first. Sites are listed
in file order.

| class | mutation |
|---|---|
| relational | ` < ` and ` <= `, ` > ` and ` >= `, ` == ` and ` != `, swapped; only with whitespace on both sides, so template brackets, `<<` and `>>` are never touched |
| logical | ` && ` and ` \|\| ` swapped |
| boundary | a decimal integer literal n becomes n+1 and n-1 (n-1 only when n > 0); never part of an identifier, a float, a hex or octal literal, or the n of `[n]` |
| return | `return true;` and `return false;` swapped |
| statement | a one-line call statement ending in `);` (starting with an identifier or `::`, not a declaration, not `return`, `break` or `continue`) becomes `(void)0;` |

## run

`run <file> [--lines A-B] [--class c,...] [--max N] [--timeout SECS] [--build "<cmd words>"] [--json] -- <test argv...>`

- The file must be tracked, with no unstaged or staged change, outside the vendored and third-party trees
  (`src/c23/vendor`, `src/c23/services/vendor`, `zcutil/tools/vendor`, `src/leveldb`, `src/secp256k1`,
  `src/univalue`, `depends`, `wallet/src/3rdparty`, `src/pow/tromp`), and `<file>.zcl-mutate.orig` must
  not exist. Each refusal exits 2. The `.orig` is checked first: after a SIGKILL the file still holds a
  mutant, so the answer is `restore <file>`, never commit or stash.
- `<file>` is relative to the directory you run from (`list` and `run` alike), but the `--build` command
  and the test argv always run from the repository root, so relative paths in them are root-relative.
- `--build` is split on single spaces into an argv. There is no quoting and no shell: a word cannot
  contain a space, and `&&`, `;`, `>` or `$VAR` are passed literally. Wrap anything more in a script.
- The unmutated file is built and tested first; if that fails, the run stops (exit 2), because no mutant
  result would mean anything.
- The original bytes are kept in memory and in `<file>.zcl-mutate.orig` (created with `O_EXCL`). For each
  site the file is rewritten in place, the build runs (a nonzero exit is UNCOMPILABLE and is not scored),
  then the test runs: exit 0 is SURVIVED, nonzero is KILLED, a timeout (`--timeout`, default 600 seconds,
  for the build and for the test each) is KILLED(timeout). A build that hits the timeout is
  UNCOMPILABLE(build timeout): unscored and counted in the uncompilable column, but named in the
  receipt, in `build_timeouts` of the JSON and in a warning, so raise `--timeout` to score those mutants.
  The original is then written back and checked by re-reading it.
- Build and test run in their own process group, with stdin from `/dev/null` and output to a log file
  under `zcutil/gen/mutate/`; the whole group is killed on timeout, on interrupt and when the command ends.
- SIGINT, SIGTERM and SIGHUP restore the file and exit 130; an exit handler restores too. An
  interrupted run does not rebuild, so the last build output may still hold a mutant: rebuild before
  using it. A normal end rebuilds the restored original (so no mutated binary is left behind), deletes
  the `.orig`, and checks `git diff --quiet -- <file>`; if git still sees a change it exits 2. After a
  SIGKILL, `restore <file>` checks the `.orig` against `git show HEAD:<file>`, writes it back, verifies
  it and deletes the `.orig`.
- A file listed in `zcutil/consensus.seal` gets a warning: the consensus-seal lint fails while a mutant
  is applied. Mutating a consensus file never changes consensus code in a commit; the run refuses dirty
  files and restores before it ends.
- On Windows `list` works; `run` and `restore` print `UNAVAILABLE on Windows: run on a POSIX host` and exit 2.

Output: one line per survivor, `line:col class 'orig' -> 'repl'`, then
`sites S tried T killed K survived V uncompilable U timeouts O score=K/(K+V)` (`n/a` when nothing was
scored). The receipt, one row per tried mutant, goes to `zcutil/gen/mutate/<path with / as _>-<HEAD7>.tsv`;
`--json` prints one object instead. Exit 0 when nothing survived, 1 when something did, 2 when broken.

## Reading a score

A survivor is a hole, but not always in the test you ran: the line may be dead, covered by another
suite, equivalent (the mutant behaves the same, like `v < lo` becoming `v <= lo` before `return lo`), or
not worth pinning (a log line). Deciding which is a reviewer's job. Never weaken an assertion to kill a
mutant. A score is only comparable with itself, on the same file and the same test; it says nothing about
races, memory safety, consensus parity or the code paths the chosen test does not run.

## Files

`zcl-dev-mutate.c` (commands, options, selftest), `mutate_ops.{c,h}` (the code mask and the operators,
pure), `mutate_run.c` (run and restore). `test/mutate_test.c` is the fixture driver, in C so that the
shell-lines floor does not rise; it also plays the test and build commands of its fixture runs
(`--role check|slow|hang|build|slowbuild|hangbuild`). Its inputs are `test/list_fixture.c`, `test/list_fixture.cpp`,
`test/calc.c` and `test/golden/`; `make -C zcutil/dev/mutate check UPDATE=1` rewrites the goldens.
C, libc only, gnu17 that also compiles as c2x; cross builds with `x86_64-w64-mingw32-gcc`.
