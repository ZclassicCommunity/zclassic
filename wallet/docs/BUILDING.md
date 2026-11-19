# Building ZclWallet (Qt GUI + single-file all-in-one)

The **ZClassic Qt GUI wallet** is maintained under `wallet/` in
`ZclassicCommunity/zclassic`, covering **Linux**, **Windows**, and **macOS**.

## Beta11 candidate builds

Beta11 rebuilds both the GUI and daemon from the same source revision. Verify
the daemon's source identity, version and hash before packaging; do not fall back
to the old beta6 daemon. Published beta10 downloads remain current until beta11
qualification and publication finish. Consensus rules are unchanged.

- Linux: [`contrib/release/linux.sh`](../contrib/release/linux.sh), run in Ubuntu
  20.04, builds pinned static Qt 5.15.19 and OpenSSL 3.5.9. The release requires
  glibc 2.31+ and system X11/XCB libraries.
- macOS: [`contrib/release/macos.sh`](../contrib/release/macos.sh), run natively on
  Apple Silicon with Homebrew `qt@5` and `libsodium`, bundles transitive libraries,
  measures the minimum OS and verifies the ad-hoc signature and DMG. It is not
  notarized. To avoid inheriting a newer host's Homebrew deployment requirement,
  set `ZCL_SODIUM_STATIC` to the absolute path of `lib/libsodium.a` from the same-source native daemon
  depends prefix, built for the intended minimum OS. The archive hash is recorded
  and its object deployment versions still participate in the minimum-OS check.
  A host's other Homebrew libraries can also raise that minimum. The pinned
  [`macos-toolchain.sh`](../contrib/release/macos-toolchain.sh) builds static Qt
  with native Secure Transport and a macOS 14 toolkit target (Qt 5's build setting;
  the bundled node and complete application still target macOS 15). Pass its absolute
  `qt-static` prefix as `ZCL_QT_PREFIX` when packaging; static builds omit framework
  deployment and check the toolchain archives' OS requirements as well. Use a fresh
  absolute `ZCL_MAC_BUILD_DIR` when switching Qt toolchains. Final dependency,
  minimum-OS, signature and DMG gates still apply. Packaging rejects a measured
  requirement above macOS 15; a deployment target alone does not prove compatibility.
  Packaging also requires absolute `ZCL_DAEMON_BUILD_DIR` and
  `ZCL_DAEMON_DEPENDS_PREFIX` paths for the same-source native daemon build.
  It hashes and audits all static archives under that build's `src` directory
  and the depends prefix's `lib` directory, including Boost and proof libraries.
  Symlinked archives are followed. `ZCL_DAEMON` must match that build's
  `src/zclassicd` byte-for-byte; do not pair a separately stripped copy with it.
  Retain these build inputs until packaging finishes: inspecting only the final
  executable can miss a library that requires a newer OS.
  The Mac packaging gate also builds the HTTPS probe with that same Qt toolkit
  and requires a certificate-verified response from the canonical release endpoint.
  Public app directories and executables receive mode 755, and resources receive
  mode 644 before signing. The gate checks these access bits after signing so a
  private build-account umask cannot silently restrict the distributed app.
- Windows: use static Qt 5.15.2 with native Schannel enabled, MinGW POSIX threads,
  static libsodium and `CONFIG+=zqw_portable`. Package with
  [`contrib/cross/package-win.sh`](../contrib/cross/package-win.sh); both GUI and daemon
  must pass [`contrib/cross/check-win-deps.sh`](../contrib/cross/check-win-deps.sh).
  The published executable is unsigned and needs no GCC/Qt/pthread/OpenSSL DLLs.

The local CI ([doc/local-ci.md](../../doc/local-ci.md)) provides the Linux/macOS environments and
final-payload checks, on project machines only. For maintainers:

```sh
zcutil/local-ci.sh --commit <sha> wallet-linux        # Linux bundle (after daemon-linux of the same commit)
ZCL_CI_MAC=mac ZCL_CI_MAC_ARGS=all zcutil/local-ci.sh --commit <sha> macos <outdir>
```

Check downloaded artifacts, not just build logs: runtime dependencies, extracted
daemon hash/version/cache reuse, certificate-verified HTTPS and native startup.
See [beta8 release notes](../../doc/release-notes-beta8.md) and the release's
`BUILDINFO.txt` and `SHA256SUMS.txt` for the tested artifacts.

The detailed sections below describe older development and packaging paths,
including older version-specific examples and host-local proot scripts. Use the
tracked beta8 release scripts above for current releases; adjust legacy checkout
paths to `zclassic/wallet`.

It covers, in order:

1. [What you are building](#0-what-you-are-building)
2. [The single-file "all-in-one" mechanism (ZQWDMON1 footer)](#1-the-single-file-all-in-one-mechanism)
3. [Prerequisites per platform](#2-prerequisites)
4. [Build the daemon to embed](#3-build-the-daemon-zclassicd-to-embed) (links to the daemon guide)
5. [Linux — plain GUI build](#4-linux--plain-gui-build-dynamic-qt)
6. [Linux — single-file dev build (`make-allinone.sh`)](#5-linux--single-file-dev-build-make-allinonesh)
7. [Linux — portable static-Qt release (`mkrelease.sh`)](#6-linux--portable-static-qt-release-mkreleasesh)
8. [Windows — static-Qt cross build + manual embed](#7-windows--static-qt-cross-build-from-linux)
   - [Windows — native Qt-kit release bundle (`build-windows.sh`)](#7b-windows--native-release-bundle-with-the-qt-kit-build-windowssh)
9. [macOS — `.app` / `.dmg` + ad-hoc codesign (correct ORDER)](#8-macos--app--dmg--ad-hoc-codesign)
10. [Two pitfalls everyone hits: qt5-websockets & libsodium](#9-the-two-pitfalls-you-must-know)
11. [Verifying any build](#10-verifying-any-build)

> Repo paths in this doc assume the wallet is at `/home/rhett/github/zcl-qt-wallet`
> and the daemon at `/home/rhett/github/zclassic`. Adjust to your checkout.

---

## 0. What you are building

The product `TARGET` is `zclwallet` (`zcl-qt-wallet.pro:15`). The GUI uses only
`QT += core gui network` + `widgets` (`zcl-qt-wallet.pro:7,13`) — **no websockets**
(that feature was removed; see [§9](#9-the-two-pitfalls-you-must-know)). It is
C++14 and links a **static libsodium** (`-lsodium` on unix, `-llibsodium` on
win32-g++; `zcl-qt-wallet.pro:130-141`).

There are two flavours of GUI binary:

| Flavour | Qt linkage | Use | Portable? |
|---|---|---|---|
| **plain / dev** | dynamic system Qt5 | local testing | No — needs Qt5 + libs on the user box |
| **release single-file** | static Qt5 | shipping | Yes — one self-contained file |

A "single-file all-in-one" is the GUI binary with the **daemon (`zclassicd`)
appended in a footer**. On first launch the GUI extracts + hash-verifies the
daemon from its own tail and runs it, so **no separate `zclassicd` ships** on
Linux/Windows.

`singleapplication/` is a **vendored in-tree** dir (not a submodule) — nothing to
fetch (`zcl-qt-wallet.pro:100-101`).

---

## 1. The single-file all-in-one mechanism

### Footer layout (Linux & Windows)

A bundled binary is laid out as:

```
[ GUI executable bytes ][ daemon bytes ][ sha256(daemon):32 ][ len(daemon):8 LE u64 ][ magic "ZQWDMON1":8 ]
```

The trailing **48 bytes** are `[sha256:32][len:8 little-endian][magic:8]`. The OS
loader ignores trailing bytes, so the binary still runs.

This exact layout is written in three places (all consistent):
- `contrib/make-allinone.sh:64-72` (dev embed)
- `src/scripts/mkrelease.sh:100-108` (release embed)
- and READ back at runtime by `src/connection.cpp:620-704`
  (`ConnectionLoader::ensureDaemonExtracted`).

(On Windows the description below applies to an unsigned executable. Authenticode signing
appends an 8-byte-aligned attribute certificate table after the footer; for a PE whose
security data directory (index 4, a file offset) is set, the reader requires that table
to end exactly at EOF and to start after the image, and takes the footer that ends 0..7
zero bytes before it. A footer inside the table is not accepted. Non-PE files use EOF only.
The daemon must also lie between the end of the PE image and the footer.)

The extracted daemon (`%LOCALAPPDATA%`/cache `zclassic-node/<sha256>/`) is verified again
right before every launch (`EmbeddedDaemonPin`, first start and crash restart): opened
without following links, hashed through that handle, and on Windows held open with
`FILE_SHARE_READ` only until `QProcess::start` has created the process, so it cannot be
written, deleted or renamed in between; on POSIX the file and its directories must be
owned by the user and not group/world-writable. On failure the node is not started and
the reason is logged (and, on the first start, shown). Residual: on POSIX the check and the `exec` are two
steps (a same-user or root attacker is out of scope); a bundle sibling `zclassicd` is
covered by the bundle checksums, not by this pin.
The reader seeks from EOF: magic = last 8 bytes, `len` = the 8 bytes before it
(little-endian), `sha256` = the 32 bytes before that, and
`payloadOffset = selfSize - 48 - len` (`connection.cpp:653`). It rejects
`len == 0`, `len > 512 MiB` (`MAX_EMBEDDED_DAEMON_BYTES`, `connection.cpp:658`), or
a negative offset.

On first run the daemon is extracted to a **content-addressed cache** named after
the first 16 hex chars of the sha256, under `QStandardPaths::CacheLocation/zclassic-node/<stamp>/`
as `zqw-zclassicd` (`zqw-zclassicd.exe` on Windows) (`connection.cpp:667-682`).
A size-match fast path skips re-hashing on subsequent launches (`connection.cpp:697-700`).

### Daemon resolution order (`connection.cpp:508-530`)

The GUI **prefers a sibling daemon** next to itself, then falls back to the
embedded copy:

- **Linux**: sibling `zqw-zclassicd` → sibling `zclassicd` → `ensureDaemonExtracted()`
- **Windows**: sibling `zclassicd.exe` → `ensureDaemonExtracted()` (extracts to `%LOCALAPPDATA%`)
- **macOS**: sibling `Contents/MacOS/zclassicd` **only** — `ensureDaemonExtracted()`
  returns empty (`connection.cpp:621-622`). macOS **never** extracts/execs an
  embedded daemon because notarization / hardened runtime forbid running a
  runtime-written executable.

> **macOS is structurally different.** There is no ZQWDMON1 footer on the mac
> build; the signed daemon ships as a **sibling** inside the `.app`. Do not try to
> embed the daemon for macOS.

> **Testing the embedded path:** because the GUI prefers a sibling daemon, you must
> run the single file from a directory with **no** sibling `zclassicd`/`zqw-zclassicd`
> (e.g. a scratch dir).

---

## 2. Prerequisites

### Common (all platforms)
- `python3` (used for the footer-embed / footer-verify steps)
- A built **`zclassicd`** to embed — see [§3](#3-build-the-daemon-zclassicd-to-embed).

### Linux — dynamic dev build
A clean Ubuntu/Debian box needs at least:

```bash
sudo apt update
sudo apt install -y build-essential autoconf automake libtool pkg-config \
    qtbase5-dev qttools5-dev-tools qt5-qmake qtbase5-dev-tools \
    wget curl python3 file binutils
```

> The libsodium static archive is built **from source by the build itself** (no
> apt package needed) — see `res/libsodium/buildlibsodium.sh`. It needs `wget` or
> `curl` plus a C toolchain.

Verify Qt is present and is Qt 5.x:

```bash
qmake --version    # expect: Using Qt version 5.15.x
```

### Linux — portable static-Qt release
Requires a **statically compiled Qt 5.15** at `$QT_STATIC`. Building static Qt on a
modern host bakes in a high glibc floor, so the canonical release is built inside an
**Ubuntu 20.04 / glibc 2.31 proot sandbox**. The static-Qt toolchain bootstrap and
the orchestration are **not yet committed to this repo** — see
[Uncommitted tooling](#appendix-uncommitted-tooling-to-be-committed). `mkrelease.sh`
itself (used inside that sandbox) **is** in-repo at `src/scripts/mkrelease.sh`.

### Windows — cross build from Linux (no sudo, no MXE)
- apt mingw toolchain (POSIX thread model) — installed via the **daemon repo's**
  `zcutil/setup-mingw-toolchain.sh` (or `zcutil/install-deps.sh --mingw`):

```bash
sudo bash /home/rhett/github/zclassic/zcutil/setup-mingw-toolchain.sh
x86_64-w64-mingw32-g++ -v 2>&1 | sed -n 's/^Thread model: //p'   # MUST print: posix
```

- A **static cross-Qt 5.15 for win32-g++**, built once by `build-qtbase-win.sh`
  (see [§7](#7-windows--static-qt-cross-build-from-linux)). It needs the qtbase
  source tarball; if you don't have it, fetch
  `qtbase-everywhere-opensource-src-5.15.x.tar.xz` from
  <https://download.qt.io/archive/qt/5.15/>.
- The daemon's mingw libsodium at
  `…/zclassic/depends/x86_64-w64-mingw32/lib/libsodium.a` (produced by the daemon's
  win64 depends build).

### macOS — on a Mac
- Xcode command-line tools (`clang`, `codesign`, `xcrun`)
- A **static Qt 5.15** for macOS (path passed via `-q`)
- Homebrew **`create-dmg`**: `brew install create-dmg`

---

## 3. Build the daemon (`zclassicd`) to embed

**The GUI does not build the daemon.** Build it first using the **daemon build
guide** (in the `zclassic` repo: `doc/building-daemon-from-source.md`, or the
canonical Linux dev quickstart `BUILD.md`). Quick reference:

```bash
# Linux dev daemon (lands in src/zclassicd):
cd /home/rhett/github/zclassic && ./zcutil/build.sh -j$(nproc)

# Linux release daemon (stripped, static-libgomp; for embedding):
cd /home/rhett/github/zclassic && ZQW_STATIC_GOMP=1 ./zcutil/build-release.sh linux -j$(nproc)
# -> release/x86_64-unknown-linux-gnu/zclassicd

# Windows daemon (HOST MUST be an ENV VAR, never positional):
cd /home/rhett/github/zclassic && ZQW_STATIC_GOMP=1 ./zcutil/build-release.sh win64 -j$(nproc)
# -> release/x86_64-w64-mingw32/zclassicd.exe   (already stripped)
```

> Use the **stripped release** daemon for embedding (~13.5 MB Windows, ~176 MB
> Linux with static libgomp). The unstripped `src/zclassicd.exe` is ~278 MB and
> would balloon the all-in-one.

> Set **`ZQW_STATIC_GOMP=1`** so the embedded daemon does not need `libgomp.so.1`
> on a fresh desktop (otherwise the GUI hangs at "syncing" and then "connection
> refused").

> For a **portable Linux** daemon (low glibc floor) the daemon must be built in the
> glibc-2.31 sandbox; `mkrelease.sh` enforces a `<= GLIBC_2.31` gate
> (`mkrelease.sh:36-41`). See the daemon guide (in the `zclassic` repo:
> `doc/building-daemon-from-source.md`).

---

## 4. Linux — plain GUI build (dynamic Qt)

This produces `./zclwallet` linked against your system Qt5. **Not portable**, good
for development.

```bash
cd /home/rhett/github/zcl-qt-wallet

# ALWAYS clean before qmake (see the websockets pitfall in §9):
make distclean 2>/dev/null; rm -f .qmake.stash Makefile

qmake zcl-qt-wallet.pro CONFIG+=release
make -j$(nproc)

# sanity: must NOT list Qt5WebSockets
ldd ./zclwallet | grep -i Qt5
```

`./zclwallet` will look for a sibling/installed `zclassicd` or its own embedded
daemon (it has none in this plain build), so run it next to a `zclassicd` or pass
`--no-embedded` to point it at an external node.

---

## 5. Linux — single-file dev build (`make-allinone.sh`)

`contrib/make-allinone.sh` does a **clean** qmake+make against **dynamic** system
Qt5, then appends the daemon footer and verifies it. The output is **not portable**
(dynamic Qt) but is the fastest way to test the embedded-daemon path.

```bash
# 1. Build the daemon first (dev or release):
cd /home/rhett/github/zclassic && ./zcutil/build.sh -j$(nproc)

# 2. Build + embed (pass the daemon path; script aborts if it is missing/not executable):
cd /home/rhett/github/zcl-qt-wallet
contrib/make-allinone.sh /home/rhett/github/zclassic/src/zclassicd
# -> /home/rhett/github/zcl-qt-wallet/linux-zclwallet-allinone
```

What it does (`contrib/make-allinone.sh`):
- `make distclean; rm -f .qmake.stash Makefile`, then `qmake … CONFIG+=release`
  + `make -j$(nproc)` (lines 42-48).
- **Aborts** if `ldd ./zclwallet` shows `Qt5WebSockets` (lines 51-59).
- Appends `[daemon][sha256:32][len:8 LE][ZQWDMON1:8]` via a Python heredoc
  (lines 64-72), then re-reads and validates the footer (lines 77-111).

**Test the embedded daemon** (run from a dir with no sibling daemon):

```bash
( cd "$(mktemp -d)" && cp /home/rhett/github/zcl-qt-wallet/linux-zclwallet-allinone . && ./linux-zclwallet-allinone )
```

---

## 6. Linux — portable static-Qt release (`mkrelease.sh`)

`src/scripts/mkrelease.sh` is the **portable single-file release** builder. It needs
a **static Qt** and produces `artifacts/linux-zclwallet-v$APP_VERSION` plus a `.deb`
and an LGPL relink-objects tarball.

> **Build this inside the glibc-2.31 proot sandbox**, not on a modern host — a host
> build (glibc 2.39) raises the binary's glibc floor and `mkrelease.sh` will abort
> at its `<= GLIBC_2.31` gate (`mkrelease.sh:36-41`). The sandbox tooling is
> currently uncommitted (see [appendix](#appendix-uncommitted-tooling-to-be-committed)).

### Required environment

| Var | Meaning |
|---|---|
| `QT_STATIC` | base dir of a statically built Qt 5.15 (e.g. `/opt/qt-static`) |
| `APP_VERSION` | version string, must match `src/version.h` (read it from there) |
| `PREV_VERSION` | prior version string (used for an in-place `sed` version bump in `.pro`/README) |
| `ZCASH_DIR` | a zclassic checkout that has the daemon staged at `$ZCASH_DIR/artifacts/zclassicd` |

> The daemon must be at **`$ZCASH_DIR/artifacts/zclassicd`** (note: `artifacts/`,
> not `src/`) — `mkrelease.sh:15-18`.

### Run

```bash
cd /home/rhett/github/zcl-qt-wallet
QT_STATIC=/opt/qt-static \
APP_VERSION=<VERSION> \
PREV_VERSION=<PREV_VERSION> \
ZCASH_DIR=/home/rhett/github/zclassic \
bash src/scripts/mkrelease.sh
```

What it enforces (`src/scripts/mkrelease.sh`):
- daemon contains `MagicBean` (line 24) and glibc floor `<= GLIBC_2.31` (lines 36-41)
- runs `dotranslations.sh`, then `$QT_STATIC/bin/qmake … -spec linux-clang
  CONFIG+=release`, `make clean`, `make -j$(nproc)` (lines 62-78)
- **`ldd zclwallet | grep -i Qt` must be EMPTY** — aborts "FOUND QT; ABORT" if any
  Qt `.so` is linked (the `ldd | grep -i Qt` test is line 83; the "FOUND QT; ABORT" is line 84)
- strips, then appends the `ZQWDMON1` footer (lines 91-108)
- verifies the result is a valid ELF and `tail -c 8 == ZQWDMON1` (line 114)

Artifacts produced in `artifacts/`:
- `linux-zclwallet-v$APP_VERSION` — the portable single file
- `linux-relink-objects-v$APP_VERSION.tar.gz` — `bin/*.o` + `RELINK.txt` for LGPLv3
  static-Qt compliance (lines 122-138; see `docs/QT-LGPL-NOTICE.md`)
- `linux-deb-zclwallet-v$APP_VERSION.deb` — installs `zclwallet` to
  `/usr/local/bin` and the daemon as `zqw-zclassicd` (lines 141-160)

> `mkrelease.sh` also has a **legacy Windows section** (lines 165-226) gated on
> `MXE_PATH`. With `MXE_PATH` unset it exits cleanly after the Linux build. **Do not
> use that MXE path** — the current Windows build is [§7](#7-windows--static-qt-cross-build-from-linux),
> which produces the single-file `.exe`, not the old multi-file zip.

---

## 7. Windows — portable static build

Use the tracked [Windows build and packaging instructions](../contrib/cross/README.md).
The scripts accept explicit toolchain paths and enforce static runtime linking.
A static Qt library alone is insufficient: beta6's GUI still imported GCC,
C++ and pthread DLLs, causing startup failures on clean Windows installations.

Build the GUI with `CONFIG+=zqw_portable` (the cross-build script sets this),
then use `sh contrib/cross/package-win.sh GUI.exe DAEMON.exe OUTPUT.exe`.
The packager checks both components for non-system DLL imports and writes the
existing hash-verified ZQWDMON1 footer without a manual embed step. The daemon
source and consensus rules are unchanged. The beta6 embedded daemon already
passes the import check; the GUI requires a rebuild.

A full static Qt 5.15 installation including QtSvg is required. Build and test
on a clean Windows environment before publishing; packaging regression tests
alone do not establish that the wallet GUI starts correctly.

## 7b. Windows — native release bundle with the Qt kit (`build-windows.sh`)

For a Windows host with the stock Qt installer (dynamic Qt 5.15.2, MinGW 8.1). This
is the dynamic-Qt counterpart of §7 and of `contrib/release/linux.sh`: one command
builds the GUI, deploys Qt, adds the daemon and zips it as
`zclwallet-v2.1.2-beta13-windows-x86_64.zip`.

**Prerequisites** (nothing is installed or changed system-wide): Git Bash or MSYS2;
the Qt kit `C:/Qt/5.15.2/mingw81_64` and its MinGW `C:/Qt/Tools/mingw810_64`;
OpenSSL 1.1.1 DLLs (the installer's `C:/Qt/Tools/OpenSSL/Win_x64/bin`: Qt 5.15 loads
`libssl-1_1-x64.dll` and `libcrypto-1_1-x64.dll` at run time for the https update
check, and OpenSSL 3 does not work); a static `libsodium.a` for x86_64-w64-mingw32;
a reviewed `zclassicd.exe`, `zclassic-cli.exe`, `zclassic-tx.exe`; Windows PowerShell
(or `zip`) for the archive.

```sh
sh wallet/contrib/release/build-windows.sh \
    C:/Qt/5.15.2/mingw81_64 C:/Qt/Tools/mingw810_64 \
    C:/path/to/libsodium.a C:/path/to/daemon-dir C:/path/to/new-output-dir
```

`JOBS=14` sets the make parallelism (default: all CPUs), `ALLINONE=1` also produces
`...-windows-x86_64-allinone.zip` whose `zclwallet.exe` carries the daemon in the
ZQWDMON1 footer of §1 (no `zclassicd.exe` next to it; extracted to `%LOCALAPPDATA%`),
`SKIP_PROBE=1` skips the platform-plugin probe. The output directory must be empty.

Output: `<out>/zclwallet-v2.1.2-beta13-windows-x86_64/` (the bundle, with its own
per-file `SHA256SUMS.txt`), the `.zip`, `<out>/SHA256SUMS.txt` (hashes of the zips) and
`<out>/build/` (logs). The bundle carries the licence files (`LICENSE`, `COPYING`,
`THIRD-PARTY-LICENSES`, `QT-LGPL-NOTICE.md`, `THIRD-PARTY-NOTICES.txt`) and a
`licenses/` folder with the full texts (LGPL-3.0, GPL-3.0, OpenSSL/SSLeay, GCC Runtime
Library Exception, MinGW-w64, winpthreads, libsodium) copied verbatim from
`contrib/release/licenses/` (its README records where each text came from); zip entries get
the commit time (or `SOURCE_DATE_EPOCH`) as their timestamp. `zclwallet.exe` is
byte-reproducible: the `.pro` passes `-Wl,--no-insert-timestamp` and
`-ffile-prefix-map` for the source and build directories, and the About date comes from
`SOURCE_DATE_EPOCH` (commit time by default) instead of `__DATE__`; two builds of one
commit in different directories give the same exe, and with the same
`SOURCE_DATE_EPOCH` the same zip. The script fails if any PE
file in the bundle imports a DLL that is neither a Windows system DLL nor in the bundle,
or if a bundle file is missing from or changed since its `SHA256SUMS.txt`, and runs, with
`PATH` reduced to `System32` and `Windows` and `APPDATA`/`LOCALAPPDATA`/`USERPROFILE`
redirected: `zclwallet.exe --print-profile-paths`, `zclassicd.exe -version` and, from a
scratch copy, `tests/check-platform` (constructs `QGuiApplication` with the real `windows`
platform plugin, creates no window, must print `platform=windows`).

Why `windeployqt --debug`: the kit's DLLs and plugins are release builds with a
`.gnu_debuglink` (separate debug info). `windeployqt` reads that as "debug", sees a
release `zclwallet.exe`, skips every plugin and stops with "Unable to find the
platform plugin"; `--release` (with or without `--force`, `--plugindir`,
`--compiler-runtime`) cannot work around it. `--debug` only changes that matching;
the files deployed are still the kit's release DLLs. The MinGW runtime DLLs
(`libgcc_s_seh-1`, `libstdc++-6`, `libwinpthread-1`) are added by the script's import walk.
The wallet uses QtCore/Gui/Widgets/Network/Svg only (no WebSockets, printing or
multimedia), so none of those modules are bundled.

Try a build without touching your wallet: set `ZCLWALLET_PROFILE_DIR` to an existing
empty folder (or run `try-isolated.cmd` from the bundle). The wallet then keeps its
settings (`.ini`, not the registry), logs, `zclassic.conf` and the node datadir under
that folder, and shows `[profile: <dir>]` in the title bar.

```bat
mkdir %USERPROFILE%\zclwallet-profile
set ZCLWALLET_PROFILE_DIR=%USERPROFILE%\zclwallet-profile
zclwallet.exe --print-profile-paths
```

The headless widget tests need a Qt whose `QMessageBox` survives the offscreen
platform; see `tests/README.md` (and `tests/qt-5.15.2-windows-offscreen.patch`).

---

## 8. macOS — `.app` / `.dmg` + ad-hoc codesign

Build this **on a Mac**. The committed script `src/scripts/mkmacdmg.sh` builds the
`.app`, ships the daemon as a **sibling** inside `Contents/MacOS/`, runs
`macdeployqt`, and creates the `.dmg`. It does **not** codesign — you must add the
ad-hoc sign step **in the correct order** (below).

### 8a. Build the macOS daemon (native, on the Mac)

```bash
cd /path/to/zclassic && ./zcutil/build.sh -j$(sysctl -n hw.ncpu)
# -> src/zclassicd  (and src/zclassic-cli)
```

> `mkmacdmg.sh` expects the daemon at **`$ZCASH_DIR/src/zclassicd`** (and
> `zclassic-cli`), `mkmacdmg.sh:48-51,83-84`.

### 8b. Build the `.app` and `.dmg`

```bash
cd /path/to/zcl-qt-wallet
src/scripts/mkmacdmg.sh -q /path/to/static/Qt -z /path/to/zclassic -v <VERSION>
```

`mkmacdmg.sh` flow:
- `dotranslations.sh`, `$QT_PATH/bin/qmake … CONFIG+=release`, `make -j4` (lines 69-75)
- **`cp $ZCASH_DIR/src/zclassicd` and `zclassic-cli` into
  `zclwallet.app/Contents/MacOS/`** *before* `macdeployqt` (lines 83-84) so
  macdeployqt fixes up the rpaths and a later signature covers them
- `$QT_PATH/bin/macdeployqt zclwallet.app`
- **ad-hoc codesign** (now automated in the script — see 8c)
- `mv zclwallet.app ZclWallet.app`, then `create-dmg …` with an **`hdiutil` fallback** (see 8d)

`res/Info.plist` (`zcl-qt-wallet.pro:114`) sets `CFBundleExecutable=zclwallet`,
`CFBundleIdentifier=org.zclassic.zclwallet`, and `LSMinimumSystemVersion=11.0`
(macOS Big Sur floor).

### 8c. Ad-hoc codesign — **ORDER IS LOAD-BEARING** (now automated)

`mkmacdmg.sh` now ad-hoc-signs automatically: it signs the nested
`Contents/MacOS/zclassic{,-cli}` then `--deep` the `.app`, **immediately AFTER
`macdeployqt` and BEFORE the dmg step**. `macdeployqt` rewrites/copies the Qt
frameworks and **invalidates any earlier signature** — signing before it means the
app launches on Intel but is **instantly SIGKILLed on Apple Silicon**. There is no
Apple Developer ID here, so the sign is **ad-hoc** (`-s -`): it fixes the SIGKILL
but does **not** notarize, so Gatekeeper still flags "unidentified developer" — users
right-click → **Open** once, or `xattr -dr com.apple.quarantine /Applications/ZclWallet.app`.
With a Dev ID, replace `-` with the identity, add `--options runtime`, then notarize + staple.

Verify: `codesign --verify --deep --strict ZclWallet.app && spctl -a -vv ZclWallet.app`.

### 8d. `create-dmg` needs Finder automation — `hdiutil` fallback

`create-dmg` drives **Finder via AppleScript** to lay out the decorative background
+ icon positions. On a **headless / CI / Automation-restricted Mac** that fails with
`AppleEvent timed out (-1712)` and produces **no dmg at all**. The decorative layout
is cosmetic, so `mkmacdmg.sh` now falls back to a plain compressed dmg via `hdiutil`
when `create-dmg` produces no file:

```bash
hdiutil create -volname "ZclWallet-v$APP_VERSION" -srcfolder ZclWallet.app -ov -format UDZO "$DMG"
```

This is functionally identical (a signed `.app` the user drags out) — just without the
custom background. For the polished `create-dmg` layout, run on an **interactive Mac
session** with Automation permission granted to the terminal (System Settings →
Privacy & Security → Automation).

> If you intend to **notarize** (vs ad-hoc) you need a Developer ID identity and
> `xcrun notarytool` / stapling — that is beyond this doc and is done by the mac
> maintainer. A published `.dmg`'s exact sign/notarize status is not
> verifiable from the Linux build box; confirm with the mac maintainer and commit
> the precise invocation.

---

## 9. The two pitfalls you MUST know

### 9a. The qt5-websockets pitfall (the big one)

This branch removed the old websocket pairing feature, so the `.pro` is now
`QT += core gui network widgets` only — **no `QT += websockets`**
(`zcl-qt-wallet.pro:7,13`). **But** an **incremental `make`** over a `Makefile` that
qmake generated from an **older** `.pro` (e.g. `master`, which still has
`QT += websockets`) keeps `-lQt5WebSockets` in the link line. The resulting binary
then demands `libQt5WebSockets.so.5` at runtime and **fails to start** on machines
without `qt5-websockets`.

**Symptom:** `error while loading shared libraries: libQt5WebSockets.so.5`.

**Fix — always do a CLEAN build before qmake:**

```bash
make distclean 2>/dev/null; rm -f .qmake.stash Makefile
qmake zcl-qt-wallet.pro CONFIG+=release
make -j$(nproc)
ldd ./zclwallet | grep -i Qt5WebSockets   # must be EMPTY
```

`make-allinone.sh` (lines 42-59) and `mkrelease.sh` (lines 56,71) already do the
clean automatically, and `make-allinone.sh` **aborts** if `ldd` shows
`Qt5WebSockets`.

### 9b. The libsodium fallback / dead-URL pitfall

The GUI links a **static libsodium 1.0.16** built from source by
`res/libsodium/buildlibsodium.sh`. Two things to know:

1. **Dead primary URL + GitHub fallback + sha pin.** The script tries the (dead)
   `download.libsodium.org` URL then falls back to GitHub
   `github.com/jedisct1/libsodium/releases/download/1.0.16/…`, and verifies sha256
   `eeadc7e1e1bcef09680fb4837d448fbdf57224978f865ac1c16745868fbd0533`
   (`buildlibsodium.sh:13,26-52`). It needs `wget` or `curl`.

2. **Short-circuit on existing `res/libsodium.a`.** The script `exit 0`s immediately
   if `res/libsodium.a` already exists (`buildlibsodium.sh:5`). This is what lets a
   cross/portable build **pre-stage** the right archive. The naming matters:
   - **Linux** links `-lsodium` → `res/libsodium.a` (the unix name).
   - **win32-g++** links `-llibsodium` → `res/liblibsodium.a` (the `lib`-prefixed name).

   This repo ships **neither** `res/liblibsodium.a` (the mingw name, a staged build input, git-ignored) nor `res/libsodium.a`,
   so a fresh **Linux** build correctly triggers `buildlibsodium.sh`. For the Windows
   cross build, `build-gui-win.sh` stages the mingw libsodium to **both** names so the
   Linux build script never runs.

> **Portable-build hazard:** a host-built (new-glibc) `res/libsodium.a` left in place
> would silently raise the single file's glibc floor (the short-circuit skips the
> rebuild). The proot release flow excludes `res/libsodium.a` from its rsync so the
> archive is rebuilt in-sandbox; on a normal host dev build this does not matter.

---

## 10. Verifying any build

```bash
# --- footer present (Linux/Windows single-file) ---
tail -c 8 <bundle>            # must print: ZQWDMON1

# --- still a valid executable ---
readelf -h <linux-bundle> >/dev/null && echo "valid ELF"
file <win-bundle>            # expect: PE32+ executable (GUI) x86-64 ... for MS Windows

# --- footer round-trips (sha matches, embedded daemon is the right kind) ---
python3 - <bundle> <<'PYEOF'
import os, struct, hashlib, sys
p = sys.argv[1]; sz = os.path.getsize(p)
with open(p, 'rb') as f:
    f.seek(-48, 2); h = f.read(32); dl = struct.unpack('<Q', f.read(8))[0]; m = f.read(8)
    f.seek(sz - 48 - dl); d = f.read(dl)
print('magic', m, 'len', dl, 'gui_size', sz-48-dl,
      'sha_ok', hashlib.sha256(d).digest() == h, 'head', d[:2])  # head: b'\x7fE'=ELF, b'MZ'=PE
PYEOF

# --- no Qt .so leaked into a static release (must be EMPTY) ---
ldd <linux-bundle> | grep -i qt

# --- glibc floor of a portable Linux bundle (must be <= 2.31) ---
objdump -T <linux-bundle> | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -1

# --- no surprise dynamic deps (e.g. libgomp leaked) ---
objdump -p <linux-bundle> | grep NEEDED

# --- test the EMBEDDED daemon path (run with NO sibling daemon) ---
( cd "$(mktemp -d)" && cp <linux-bundle> . && ./"$(basename <linux-bundle>)" )
```

> **Do not trust a "green" build log alone.** A piped/tee'd log can report exit 0
> even when the build failed or the artifact is stale. Always verify the artifact:
> footer + sha + (for portable Linux) glibc floor + `ldd`.

---

## Appendix: uncommitted tooling (to be committed)

The following are **load-bearing but not yet in this repo**. They should be
committed so this guide is fully reproducible without tribal knowledge:

| File (current location) | What it does | Suggested home |
|---|---|---|
| `/home/rhett/build-qtbase-win.sh` | cross-builds static qtbase 5.15.x for win32-g++ | `contrib/cross/build-qtbase-win.sh` |
| `/home/rhett/build-gui-win.sh` | cross-builds `release/zclwallet.exe` (does NOT embed) | `contrib/cross/build-gui-win.sh` |
| *(missing)* a shared `embed-daemon.py` | the ZQWDMON1 footer append, identical to `mkrelease.sh:100-108`; today the Windows embed is a manual one-liner | `contrib/embed-daemon.py` (used by Linux/Windows/all-in-one) |
| *(missing)* codesign step in `mkmacdmg.sh` | `codesign --force --deep -s - zclwallet.app` AFTER `macdeployqt`, BEFORE `create-dmg` | edit `src/scripts/mkmacdmg.sh` after line 85 (macdeployqt), before line 91 (create-dmg) |
| `/home/rhett/zclbuild/*` (proot builder: `prun`, `focal/build/{02-openssl-qt.sh,03-daemon.sh,04-gui-bundle.sh,05-static-helpers.sh,build.sh}`) | the only way to produce the portable glibc-2.31 static-Qt Linux single file + `.deb` | a dedicated build-env repo, or `contrib/portable-builder/` |

In-repo and already tracked (reference, do **not** re-commit): `src/scripts/mkrelease.sh`,
`contrib/make-allinone.sh`, `res/libsodium/buildlibsodium.sh`, `src/scripts/dotranslations.sh`,
`src/scripts/mkmacdmg.sh`.

### Known open items
- **Version is hard-coded** (`src/version.h` → `APP_VERSION`); the
  proot release scripts also hard-code it and must be bumped together with a tag.
- **Repo links verified** — the README and docs reference `github.com/ZclassicCommunity/zcl-qt-wallet`
  throughout (the old `ZClassicFoundation/zclwallet` upstream references were removed).
- The sign/notarize details of a published macOS `.dmg` are owned by the mac
  maintainer and are not verifiable from the Linux box.
