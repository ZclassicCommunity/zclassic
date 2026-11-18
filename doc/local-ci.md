# Local release-candidate CI

Release candidates are built and tested on the owner's own machines. The GitHub
workflows are kept, but they run only when started by hand (`workflow_dispatch`);
nothing runs on push or pull request.

| Script | Where it runs | What it does |
| --- | --- | --- |
| `zcutil/local-ci.sh` | Linux build host | `env-setup`, `daemon-linux`, `daemon-win64`, `wallet-linux`, `test`, `macos`, `all`, `shell`, `clean` |
| `zcutil/local-ci-macos.sh` | the Mac | macOS daemon candidate and macOS wallet bundle |
| `zcutil/local-ci-smoke.sh` | anywhere (Linux, macOS, Windows under Git Bash/MSYS2) | headless Sapling regtest smoke with exact balances |

Nothing here pushes to, or starts a run on, GitHub. Source reaches the Mac as a
`git bundle` over ssh.

## Why a focal root filesystem

The GitHub jobs built inside an `ubuntu:20.04` container: GCC 9, glibc 2.31 (so the
Linux binaries run on old distributions), mingw-w64 GCC 9.3 (the Windows build).
Building on a newer host raises the glibc floor and changes the Windows toolchain.
`local-ci.sh env-setup` rebuilds that environment with **no root and no container
runtime**: the official `ubuntu-base-20.04.5-base-amd64.tar.gz` is downloaded from
cdimage.ubuntu.com, checked against a pinned SHA-256 and the published `SHA256SUMS`,
unpacked into `~/work/zc23-localci-env`, and the workflow's package lists are
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
ZCL_CI_MAC=mac ZCL_CI_MAC_ARGS=all zcutil/local-ci.sh --commit <sha> macos <outdir>   # + wallet
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

## Where artifacts land

`<outdir>/daemon-linux-x86_64/`, `daemon-windows-x86_64/`, `daemon-macos-arm64/`
(each: binaries, `validation.txt`, `SOURCE_COMMIT.txt`, `SHA256SUMS.txt`, the same
layout the workflows uploaded), `wallet-linux-candidate/` (bundle, validation,
`linux-SHA256SUMS.txt`), `test/` (`results.tsv`, `logs/`), `logs/`. `work/` holds the
build trees; `local-ci.sh clean` removes it.

## Checks performed

Linux daemon: `--help`, `ldd`, highest `GLIBC_` version must be at most 2.31, no
`not found`/`libgomp`, `--version` contains the expected version. Windows daemon:
every import in the system-DLL allowlist, plus (beyond the workflow) exactly one
embedded manifest with `activeCodePage` UTF-8. macOS: `otool -L` allows only
`/usr/lib` and `/System`, `--version`, regtest smoke, bounded embedded-Tor check
(only processes of this run are ever signalled). Unlike the workflow, a failed
`! grep` is a real failure here.

`test` builds clean with tests (`DEBUG=1`, as `ci.yml`) and runs: `check-c23-vendor`,
`check-c23-no-rust`, `check-c23-tor-symbols`, the tree-root ASan/UBSan check, full
`test_bitcoin`, full `zcash-gtest`, `src/c23/test/run.sh --linked` (golden corpus),
`regtest-smoke.sh`, `wallet_matrix.sh` scenarios 1-9, `wallet_tokenguard.sh` (plain and
with Sapling active), `zslp_index.sh`, the wallet logic and widget tests (Qt from the
environment), and with `--tor` the two-node, three-node and addrv2 Tor tests (they
need real Tor network access). The tests run in a network-less namespace with their
own loopback, so they cannot collide with a running node. One summary table is
printed and the exit status is non-zero on any failure. The Python 2 RPC tests of
`qa/rpc-tests` are not run (no Python).

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
