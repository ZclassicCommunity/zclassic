# Local release-candidate CI

## CI

Builds and tests run only on project machines, with `zcutil/local-ci.sh` (Linux and
Windows candidates, tests) and `zcutil/local-ci-macos.sh` (macOS). There is no hosted CI:
the repository has no GitHub Actions workflows, no other CI service configuration and no
Python, and `zcutil/check-no-python.sh` (run by `make check` and by the `test` command)
fails if any of them comes back.

Release candidates are built and tested on the owner's own machines.

| Script | Where it runs | What it does |
| --- | --- | --- |
| `zcutil/local-ci.sh` | Linux build host | `env-setup`, `daemon-linux`, `daemon-win64`, `wallet-linux`, `test`, `test-changed`, `dry`, `macos`, `all`, `shell`, `clean` (options `--only`, `--tor`, `--flavor`, `--pick`) |
| `zcutil/local-ci-macos.sh` | the Mac | macOS daemon candidate, wallet GUI and tests (Homebrew Qt 5), macOS wallet bundle |
| `zcutil/embedded-tor-check.sh` | anywhere | bounded embedded-Tor check of a daemon candidate (run by the macOS stage) |
| `zcutil/local-ci-smoke.sh` | anywhere (Linux, macOS, Windows under Git Bash/MSYS2) | headless Sapling regtest smoke with exact balances |

Nothing here contacts GitHub. Source reaches the Mac as a
`git bundle` over ssh.

## Why a focal root filesystem

Release builds need an `ubuntu:20.04` environment: GCC 9, glibc 2.31 (so the
Linux binaries run on old distributions), mingw-w64 GCC 9.3 (the Windows build).
Building on a newer host raises the glibc floor and changes the Windows toolchain.
`local-ci.sh env-setup` rebuilds that environment with **no root and no container
runtime**: the official `ubuntu-base-20.04.5-base-amd64.tar.gz` is downloaded from
cdimage.ubuntu.com, checked against a pinned SHA-256 and the published `SHA256SUMS`,
unpacked into `~/work/zc23-localci-env`, and the package lists are
installed with `apt-get` inside an unprivileged user namespace
(bubblewrap, `--uid 0`, one mapped uid). A two-function `LD_PRELOAD` shim makes
`chown` succeed (a single-uid namespace cannot chown to other owners, which a few
packages need). Files created inside are owned by you on the host. The build jobs
see only `/w` (a fresh clone of the commit), `/cache` and `/out`.

## Prerequisites

Linux host: unprivileged user namespaces (`unshare -Ur true` works), `bwrap`
(bubblewrap), a host C compiler (for the chown shim), `curl`, `git`, `flock`,
network access for the first run, and about 25 GB of disk for the environment
(2 GB), caches and build trees. Mac: Homebrew `autoconf automake libtool pkg-config
coreutils` (and `libsodium` for the wallet), Xcode command line tools.

## Usage

Linux host (heavy commands go behind the host broker):

```sh
git -C ~/development/zclassic23/legacy worktree add ~/work/zc23-localci <branch>
cd ~/work/zc23-localci
zcutil/local-ci.sh env-setup                     # once; ~6 minutes
devbuild --wait --project z23 --class normal --cpu-limit 8 \
    zcutil/local-ci.sh --commit <sha> all ~/work/zc23-localci-out/<sha>
```

Pin `--commit` to a SHA, not a branch name: the commit is resolved once, cloned
fresh (uncommitted changes are not built), and recorded in every `SOURCE_COMMIT.txt`.
Single steps: `daemon-linux`, `daemon-win64`, `wallet-linux`, `test [--tor]`.
`--jobs N` sets make parallelism (default min(8, nproc)).

Mac, from the Linux host (copies the bundle and script, runs, copies artifacts back):

```sh
ZCL_CI_MAC=mac zcutil/local-ci.sh --commit <sha> macos <outdir>      # daemon
ZCL_CI_MAC=mac ZCL_CI_MAC_ARGS=wallet-tests zcutil/local-ci.sh --commit <sha> macos <outdir>   # wallet GUI + tests (Homebrew qt@5)
ZCL_CI_MAC=mac ZCL_CI_MAC_ARGS=all zcutil/local-ci.sh --commit <sha> macos <outdir>   # + wallet bundle
```

or directly on the Mac:

```sh
sh local-ci-macos.sh --bundle source.bundle --commit <sha> --out ~/work/zc23-localci/out daemon
```

Environment: `ZCL_CI_ENV`, `ZCL_CI_CACHE` (depends sources and built packages,
ccache, the static Qt/OpenSSL for the wallet, Zcash parameters),
`ZCL_CI_OUT`, `ZCL_CI_GOLDEN` (c23 golden corpus), `ZCL_CI_PREV_BIN` (directory
with a previous-release `zclassicd` and `zclassic-cli`, used as the peer in the
smoke and wallet-matrix tests), `ZCL_CI_MAC`, `ZCL_CI_MAC_DIR`, `ZCL_CI_MAC_JOBS`,
`ZCL_CI_EXPECT_VERSION` (default derived from `src/clientversion.h`).
Caches make repeat runs fast: depends are rebuilt only when a recipe changes and
ccache serves unchanged objects. Two runs never write the caches at once (flock).


## Running only what changed

`zcutil/bin/zcl-dev` (a small C tool, built by `make -C zcutil` into `zcutil/bin/`) maps a diff to the steps that
need to run, using the rules in `zcutil/dev/impact.rules`:

```sh
zcutil/bin/zcl-dev guide src/wallet/wallet.cpp     # rules, steps, scripts, lessons, traps, first commands
zcutil/bin/zcl-dev select [base-ref]               # steps for `git diff base...HEAD` (default origin/master)
zcutil/bin/zcl-dev check-rules                     # every source file has a rule, every rule matches a file
zcutil/local-ci.sh --commit <sha> --only wallet_matrix-1-9,zslp_index test <outdir>
ZCL_CI_BASE=<base-ref> zcutil/local-ci.sh --commit <sha> test-changed <outdir>
```

`--only` takes a comma list of `test` step names (the names in the results table; a name
that is not a `step` fails at once, so a typo cannot run nothing and pass); the build always runs, the other steps are neither run nor recorded, and the flavors keep
their usual split (the debug-only steps do not run in the release flavor). A path with no
rule selects everything, and so does a rule with the token `ALL` (consensus, chain state,
`src/main.cpp`, the daemon wallet, chain parameters and the build system use it, so a change
there never runs only a subset); Markdown and `doc/` select only `check-dev-tools`. Stages
(`daemon-linux`, `daemon-win64`, `wallet-linux`) are separate commands: `select` lists them
under `stages:` and `test-changed` prints them as "also needed". A new step needs a rule
in `impact.rules` (`check-rules` checks that its name is a `step` in `local-ci.sh`).

## Receipts

Every step appends one JSON line to `<outdir>/receipts.jsonl`, in the order it finished:
the build (`build-tests`, `fetch-params`), every test step, and the three candidate stages.

| Field | Meaning |
| --- | --- |
| `commit`, `tree` | the commit built and its git tree hash |
| `stage`, `step` | `test-run/<flavor>`, `test-build/<flavor>` or `stage`; the step name |
| `verdict`, `seconds` | `PASS`, `FAIL` or `SKIP`; wall-clock seconds |
| `started` | start time, UTC, ISO 8601 |
| `os`, `arch` | `uname -s` and `uname -m` of where the step ran (no host name) |
| `gcc`, `mingw`, `glibc` | first line of `gcc --version`, `x86_64-w64-mingw32-g++ --version` and `ldd --version` inside the focal rootfs (stages read them from `ZCL-CI-ENV.txt`); empty if absent |
| `env_names`, `env_sha256` | names of the build-relevant variables that are set (`CONFIGURE_FLAGS`, `DEBUG`, `HOST`, `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`, `MAKEFLAGS`, `ZQW_STATIC_GOMP`, `E2E_NODE_ARGS`, and every `ZCL_CI_*`) and the SHA-256 of their sorted `NAME=value` lines; values are never written |
| `log_sha256` | SHA-256 of the step's log file, so a receipt pins what was read |

The environment is the one the step ran in: test steps run under `--clearenv`, so their
digest covers what the CI passes in, not the host's shell. A receipt says what ran and
what it printed; it does not make the result true: read the log it hashes.

```sh
zcutil/bin/zcl-dev receipt wallet_tokenguard <outdir>     # the latest receipt of one step
grep '"verdict":"FAIL"' <outdir>/receipts.jsonl           # every failure of a run
sha256sum <outdir>/test/logs/wallet_tokenguard.log        # must equal its log_sha256
```

`zcutil/local-ci.sh dry <outdir>` runs three fake steps (pass, fail, skip) through the real
`step` and `receipt` code with no root filesystem; `make -C zcutil/dev check` uses it to
test the receipts and `--only`. Receipts use only POSIX sh, `sha256sum` or `shasum`, and
`uname`; there is no `jq`.

## Where artifacts land

`<outdir>/daemon-linux-x86_64/`, `daemon-windows-x86_64/`, `daemon-macos-arm64/`
(each: binaries, `validation.txt`, `SOURCE_COMMIT.txt`, `SHA256SUMS.txt`, the same
layout of a release candidate), `wallet-linux-candidate/` (bundle, validation,
`linux-SHA256SUMS.txt`), `test/` (`results.tsv`, `logs/`), `logs/`. `work/` holds the
build trees; `local-ci.sh clean` removes it.

## Checks performed

Linux daemon: `--help`, `ldd`, highest `GLIBC_` version must be at most 2.31, no
`not found`/`libgomp`, `--version` contains the expected version. Windows daemon:
every import in the system-DLL allowlist, plus exactly one
embedded manifest with `activeCodePage` UTF-8. macOS: `otool -L` allows only
`/usr/lib` and `/System`, `--version`, regtest smoke, bounded embedded-Tor check
(only processes of this run are ever signalled). A failed
`! grep` is a real failure here.

Every release binary also passes `zcutil/check-hardening.sh` (POSIX sh, binutils only;
`make -C src check-security` runs the same script). ELF: PIE, full RELRO (`GNU_RELRO` +
`BIND_NOW`), non-executable stack, `__stack_chk_fail` present (FORTIFY `_chk` symbols and
the CET IBT/SHSTK note are reported as info). PE: `DYNAMIC_BASE`, `NX_COMPAT`,
`HIGH_ENTROPY_VA` and a non-empty `.reloc` section, because without relocations ASLR does
not apply. Mach-O: the PIE flag via `otool -hv` (skipped with a message when `otool` is
absent). One PASS/FAIL/INFO/SKIP line per check; any FAIL makes the stage fail. Run it by
hand on any binary: `sh zcutil/check-hardening.sh path/to/zclassicd`.

`test` runs two builds of the test suites (`--flavor debug|release|both`, default both):

* **debug**: `DEBUG=1` depends and `--enable-debug`, which in this fork
  turns on the checked C++ standard library (`_GLIBCXX_DEBUG`) and lock-order checking.
  It finds container/iterator misuse and lock-order bugs that a release build hides, and
  also runs the full list below. Expect findings that never show in a release build.
* **release**: the configuration that ships (same depends as the daemon candidates, so
  they come from the cache). It runs `check-c23-*`, full `test_bitcoin`, full
  `zcash-gtest` and the regtest smoke, so a release-only problem is not missed.

`--pick REV` cherry-picks a commit (for example a harness fix not yet on the release
branch) onto the test builds only; the picks are recorded in `test*/PICKS.txt`.
Results are in `test/` (debug) and `test-release/`.

The debug stage runs:
`check-dev-tools` (the `zcl-dev` fixture tests, `check-rules`, `check-docs`), `check-c23-vendor`, `check-tools-vendor`, `build-jsonq` (builds and tests `zcutil/bin/jsonq`, which the shell tests use), `zcl-lint` (zcutil/lint ratchets),
`check-c23-no-rust`, `check-c23-tor-symbols`, `check-no-python` (with its self-test), `key1-guard`
(KEY-1 wallet secrecy guard, with poisoned-copy cases), `seed-generator` (byte-for-byte `chainparamsseeds.h`),
`zmq-sub-example`, `wallet-embed-footer` and `wallet-mockrpc` (the C23/sh tools that replaced the
Python ones; they run in both flavors), the tree-root ASan/UBSan check, full
`test_bitcoin`, full `zcash-gtest`, `src/c23/test/run.sh --linked` (golden corpus),
`regtest-smoke.sh`, `wallet_matrix.sh` scenarios 1-9, `wallet_tokenguard.sh` (plain and
with Sapling active), `zslp_index.sh`, the wallet logic and widget tests (Qt from the
environment), and with `--tor` the two-node, three-node and addrv2 Tor tests (they
need real Tor network access). The tests run in a network-less namespace with their
own loopback, so they cannot collide with a running node. One summary table is
printed and the exit status is non-zero on any failure. The tests in `qa/rpc-tests` are
shell scripts.

### The zcl-lint rules

`zcl-lint all` runs these rules in this order. The list must match `zcutil/lint/rules.def`, and the
`wiring` rule fails when it does not.

<!-- LINT-RULES-BEGIN -->
- `no-new-jq`: lines that use jq in shell scripts
- `no-new-bash`: bash shebangs and bashisms
- `banned-str`: strcpy, strcat, sprintf, vsprintf, gets
- `md-links`: broken relative Markdown links
- `vendor`: vendored files stay verbatim
- `no-python`: no Python files or invocations
- `filesize`: files over 1500 lines
- `complexity`: functions above cyclomatic complexity 15
- `long-functions`: functions above 500 lines
- `warnsupp`: warning suppressions
- `doc-claims`: machine-checked statements in Markdown
- `doc-paths`: backticked repository paths that do not exist
- `version-facts`: version numbers in documents
- `victory`: unproven completion claims in documents
- `secretlog`: secret-bearing names in log calls
- `testiso`: tests that touch a shared tmp, datadir or port
- `shellport`: host-specific commands in shell scripts
- `wallclock`: assertions decided by elapsed real time
- `consensus-seal`: the consensus seal
- `kpi`: the tree-health floor, see `doc/agent/KPI.md`
- `wiring`: this list, `rules.def` and `zcl-lint all` agree
<!-- LINT-RULES-END -->

## Runaway steps: timeouts, log cap, ASLR

Every `test` step runs under `timeout` and writes its log through `head -c`, so a hang or
a step that prints forever fails fast instead of filling the disk (once a sanitizer step looped
on `AddressSanitizer:DEADLYSIGNAL` for 33 minutes and wrote an 18 GB log). A step that times
out, or whose log reaches the cap, is recorded as FAIL and the reason is appended to its log.

| Variable | Meaning |
| --- | --- |
| `ZCL_CI_TIMEOUT_<STEP>` | seconds for one step; `<STEP>` is the step name in upper case with `-` and `.` as `_` (`ZCL_CI_TIMEOUT_TREE_ROOT_ASAN=300`) |
| `ZCL_CI_STEP_TIMEOUT` | seconds for every step without its own `ZCL_CI_TIMEOUT_<STEP>`; overrides the built-in defaults |
| `ZCL_CI_LOG_CAP` | most bytes kept of one step log (default 268435456, 256 MiB) |
| `ZCL_CI_NOASLR` | `0` runs the sanitizer step without `setarch -R` |

Built-in defaults: 30 minutes for the `check-c23-*` steps, 15 minutes for `tree-root-asan`,
one hour for the smoke, tokenguard, zslp and Tor steps, two hours for `test_bitcoin-full`,
`zcash-gtest-full`, `c23-run-linked` and the wallet Qt tests, three hours for
`wallet_matrix-1-9`. The sanitizer step runs under `setarch "$(uname -m)" -R` (address-space
randomisation off) when the kernel allows it: an older ASan runtime inside the focal root
filesystem cannot place its shadow memory under a high `vm.mmap_rnd_bits` and dies in a signal
loop now and then. The limits apply to steps; the build stages are bounded by the broker.

## Exit status

`local-ci.sh` exits 0 only when every requested command passed. For `test` that means no step
FAILED in any flavor (a SKIP does not fail), the test run itself completed, and the build
stage succeeded; `all` fails when any of its commands fails.

## Verifying artifacts

```sh
cd daemon-linux-x86_64 && sha256sum -c SHA256SUMS.txt && cat SOURCE_COMMIT.txt
objdump -T zclassicd | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -1     # <= GLIBC_2.31
sh zcutil/local-ci-smoke.sh --bin . --work /tmp/smoke-$$ --port-base 43900
```

Check `SOURCE_COMMIT.txt` equals the commit you meant to release. These are
unsigned candidates; signing and publication stay a separate, deliberate step.

## Windows wallet bundle

The Windows wallet is built natively on the Windows PC (static Qt 5.15.2, MinGW
8.1, static libsodium), as documented in `wallet/contrib/cross/README.md`
("Native Windows validation"). It needs only the daemon from this pipeline:

1. Copy `daemon-windows-x86_64/` to the PC; run `sha256sum -c SHA256SUMS.txt`
   (Git Bash) and confirm `SOURCE_COMMIT.txt` is the commit being released.
2. Build the GUI from the same commit as in the README, then package:
   `sh contrib/cross/package-win.sh release/zclwallet.exe <dir>/zclassicd.exe artifacts/zclwallet-win64.exe`
   and run `sh contrib/cross/check-win-deps.sh` and the windows-packaging tests.
3. Smoke the daemon headlessly first: `sh zcutil/local-ci-smoke.sh --bin <dir> --work <empty scratch dir>`
   (hidden process, scratch datadir, ports 43900-43901, never the real datadir).

## Notes from operating it

* Under the host broker's `normal` class (8 GB memory cap) the debug test build is
  killed at `--jobs 8`; use `--jobs 3` for `test`. The daemon and wallet stages are fine at 8.
* Windows `.exe` files and the wallet bundle are not byte-for-byte reproducible between
  runs (link timestamps); the Linux and macOS daemons are. Compare `SOURCE_COMMIT.txt`
  and the validation output, not the hashes of two different runs.
* Not run here: the macOS wallet bundle
  (`local-ci-macos.sh wallet` builds Qt for about an hour on the first run), and the
  Windows wallet GUI (built natively on the Windows PC, see above).
