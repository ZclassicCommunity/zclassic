# zcutil/lint: zcl-lint ratchet gates

`zcl-lint` is one small C program (libc only, `-std=gnu17`) that holds the line on a few things without a
framework. Its rule logic is derived from three Z23 lint gates (see the header of `zcl-lint.c` and `NOTICE`).

```sh
make -C zcutil/lint            # builds zcutil/bin/zcl-lint
make -C zcutil/lint check      # selftest of every rule against throw-away fixture repositories
make -C zcutil/lint lint       # all rules on this tree (also: make -C src lint-fast)
zcutil/bin/zcl-lint <rule>|all [--update-baseline]
```

| rule | what it counts, per path | baseline |
|---|---|---|
| `no-new-jq` | lines that mention `jq` in shell scripts | `no-new-jq.txt` |
| `no-new-bash` | bash shebang plus bashism lines (`[[`, `<(`, arrays, `${v//x}`, `echo -e` ...) in shell scripts | `no-new-bash.txt` |
| `banned-str` | calls to `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets` in non-vendored C/C++ (comments and strings ignored; `lint-ok:` on the line exempts it) | `banned-str.txt` |
| `md-links` | relative links in tracked `*.md` that do not resolve to a tracked file, and same-file `#anchors` with no heading | `md-links.txt` |
| `vendor` | every `Z23_SOURCE.tsv` manifest must match its vendored tree (delegates to `check-vendor.sh`) | none: hard check |
| `doc-claims` | false or malformed `<!-- claim: PREDICATE args -->` comments in tracked `*.md` (predicates: file-present, file-absent, symbol-present, symbol-absent, rule-passes, step-exists); fewer than 3 documents is a hollow scan | none: hard check |
| `doc-paths` | backticked repository paths in tracked `*.md` that resolve to no tracked file (`<!-- doc-path-ok -->` exempts a line) | `doc-paths.txt` |
| `version-facts` | version strings in `wallet/src/version.h` and the release scripts that disagree with `configure.ac` | none: hard check |
| `victory` | paragraphs of `doc/agent/HANDOFF.md` that say fixed/cured/fully synced/at tip/green with no commit id, receipt path, local-ci results path or `<!-- victory-ok: reason -->` | none: hard check |

A baseline row is `<path><TAB><count>`. The gate fails when a count rises or a path appears that is not listed.
When a count falls it passes and says so: run `zcl-lint <rule> --update-baseline` to lower the baseline
(it refuses while anything rose, and only creates a file that does not exist). Baselines can only shrink.

`no-python` runs `zcutil/check-no-python.sh` (skipped when absent) and `all` runs every rule in `rules.def` order.
Vendored and third-party trees (`src/c23/vendor`, `src/c23/services/vendor`, `zcutil/tools/vendor`,
`src/secp256k1`, `src/leveldb`, `src/univalue`, `depends`, `wallet/src/3rdparty`, `src/pow/tromp`) are out of
scope for the style rules.

## Source layout and adding a rule

`zcl-lint.c` is only the driver. Each rule is one file under `rules/` plus one `LINT_RULE(name, fn, has_baseline)` row in
`rules.def`; `lintlib.{c,h}` hold what rules share: tracked-file iteration (`git ls-files -z`), the single vendored-tree exclusion
list, C/C++ and sh comment and string stripping, baseline read/write and the ratchet, and the hollow-scan floor.
A rule that scans nothing fails: exit 2 and "hollow scan", never a pass. Exit codes: 0 clean, 1 findings, 2 usage, internal error
or hollow scan. `make -C zcutil/lint check` runs the fixture selftest and `lintlib_test.c`.

## Windows (Git Bash)

`make -C zcutil CC=x86_64-w64-mingw32-gcc EXEEXT=.exe` builds `zcl-lint.exe` with the other tools, and
`zcl-dev verify` runs it like every other step. Children start through `CreateProcessA`, never `cmd.exe`: the argv
becomes one command line by the MSVCRT quoting rules (`lint_win_quote_argv`, unit-tested in `lintlib_test.c` on every
host), so `%`, `&`, `|`, `^` and `!` are plain characters, and only an argument with an embedded CR or LF is refused.
Programs are found on `PATH` only (`SearchPathA`, `.exe` added). A `*.sh` file, or a path whose file starts with
`#!`, runs as `sh.exe <script> args...`. When `sh.exe` is not on `PATH` the rule prints
`UNAVAILABLE: sh not found on PATH` and exits 2, so it never passes. On Windows only, `lint_slurp` drops a CR before an
LF, so a `core.autocrlf=true` checkout gets the same verdicts as the LF tree.

Every selftest script runs against `zcl-lint.exe` under Git Bash: `sh zcutil/lint/selftest.sh zcutil/bin/zcl-lint.exe`.
A case that cannot run there must print `SKIP (windows): <reason>` and be listed here. Today none is skipped: all five
scripts and the `zcl-dev verify --selftest` stub fixture (its stubs are `<tool>.sh` on Windows) pass under Git Bash.

## Safety rules (secretlog, testiso, shellport, wallclock)

`secretlog` (custody) flags log and print calls in `src/` and `wallet/src/` whose arguments name a secret (`CKey`, `strWalletPass`, `seed`, `mnemonic`, `HexStr(key`, ...); override a line with `log-ok: reason` in a comment. The baseline is expected to be empty, and every row is a finding to review, not to hide.
`testiso` reads `qa/`, `src/test` and `src/gtest` for literal `/tmp/`, default datadirs without `-datadir=`, and fixed `-port=`/`-rpcport=` in `qa/rpc-tests/*.sh` (`iso-ok: reason` in a comment: `//`, `/* */` or `#`).
`shellport` flags `sed -i`, `stat -c`, `nproc`, `ss`, `readlink -f`, `date -d`, `grep -P`, `timeout` and `| grep -q` under `set -o pipefail` (`# port-ok: reason`). `wallclock` flags assertions decided by elapsed real time (`real-clock: reason`).
`testiso`, `shellport` and `wallclock` baselines use rows `<path>:<kind><TAB><count>` where a path has several kinds. `selftest-safety.sh` holds their fixtures.
## Isolated profile (testing and portable use)
Set `ZCLWALLET_PROFILE_DIR=<existing dir>` (or pass `--profile-dir <dir>`) and the wallet keeps
**all** of its state under that directory and never reads or writes the user's real wallet
profile: QSettings (IniFormat in `<dir>/settings`, not the registry/plist), the wallet log and
`*.dat` stores (`<dir>/appdata`), the extracted-daemon cache (`<dir>/cache`), the notify socket
(`<dir>/run`), default save-dialog folder (`<dir>/exports`), and `zclassic.conf` plus the node
datadir (`<dir>/ZClassic`, passed to the embedded daemon as `-datadir=`). The window title shows
`[profile: <dir>]` while it is active. Only the 1.7 GB zk-SNARK params keep their default
location (read-only); `ZCLWALLET_PARAMS_DIR` moves the wallet's own params check (the daemon
has no params-dir option). A set-but-missing directory is a fatal error, never a silent fallback.
All of this is one header, `src/profilepaths.h`; new code must resolve state locations through it.
Pre-write `<dir>/ZClassic/zclassic.conf` (e.g. `regtest=1`, `server=1`, `listen=0`, `bootstrap=0`)
to run a throwaway regtest wallet.

## Abnormal exit
Window close, File->Exit and SIGINT/SIGTERM (POSIX) all run the orderly `stop` of the embedded
daemon. On Windows the daemon is also bound to a kill-on-close job object
(`src/daemonjob.h`) as a last-resort backstop for a wallet that dies without cleanup; it is
disarmed as soon as an orderly `stop` has been sent so it can never cut a shutdown short.


## Integration re-seed 2026-11-19

The ratchets were seeded from an older tree. Branch `integration/stage-rc6` merged the tooling branch together with product
branches (shutdown marker, header precheck, outbound selection, wire robustness, RPC work queue) that were written and reviewed
before these gates existed. This one-time re-seed sets the rows below to today's measured values, for exactly these rows and no
others; no product code was changed. Every raised or added row is debt, to be paid by a later reviewed refactor and shrunk
through the normal `--update-baseline` path. It is not a precedent: after this section a baseline may only shrink.

filesize (`filesize.txt`):

| path | old | new |
|---|---|---|
| `src/init.cpp` | 3814 | 3989 |
| `src/main.cpp` | 8230 | 8246 |
| `src/net.cpp` | 2552 | 2794 |

complexity (`complexity.txt`), raised rows:

| path and function | old | new |
|---|---|---|
| `src/init.cpp` `AppInit2(2)` | 407 | 424 |
| `src/main.cpp` `ContextualCheckTransaction(5)` | 43 | 44 |
| `src/main.cpp` `ProcessMessage(4)` | 195 | 196 |

complexity, new rows (functions over the cap that had no row):

| path and function | new |
|---|---|
| `src/headerprecheck.cpp` `PreverifyHeadersEquihash(1)` | 21 |
| `src/init.cpp` `MaybeWriteCleanShutdownMarker(2)` | 18 |
| `src/init.cpp` `Shutdown(0)` | 16 |
| `src/net.cpp` `OpenConnectionsLoop(1)` | 18 |
| `src/net.cpp` `SelectOutboundCandidate(4)` | 17 |
| `src/shutdownmarker.cpp` `ParseBinding(2)` | 16 |
| `src/test/fuzz/fuzz_p2p_payload.cpp` `LLVMFuzzerTestOneInput(2)` | 18 |
| `src/test/wire_robustness_tests.cpp` `Mutate(4)` | 17 |

long-functions (`long-functions.txt`):

| path and function | old | new |
|---|---|---|
| `src/init.cpp` `AppInit2(2)` | 2110 | 2160 |
| `src/main.cpp` `ProcessMessage(4)` | 1043 | 1048 |

The tooling rows `zcutil/dev/zcl-port.c` `main(2)` (28 -> 26 after extracting `init_platform`) and `qa/rpc-tests/rpc_busy.sh` (`ss`) were fixed in code, not re-seeded.
