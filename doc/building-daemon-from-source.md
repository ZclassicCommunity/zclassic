# Building the ZClassic Daemon (`zclassicd`) from Source

This guide builds the ZClassic daemon (`zclassicd`) plus `zclassic-cli` and
`zclassic-tx` for **Linux (native)**, **Windows (mingw cross)**, and **macOS
(darwin)**. It is written for a future AI or human working from a fresh checkout
with zero prior context.

Repo root assumed throughout: `/home/rhett/github/zclassic`
(adjust if your checkout lives elsewhere). All commands are copy-pasteable and
self-contained.

---

## 0. The single most important rule: `HOST` is an ENVIRONMENT VARIABLE

> **If you are building for Windows or macOS, read this first.**

`zcutil/build.sh` reads the target triple **only from the environment**, never
from a positional argument:

```text
zcutil/build.sh:32-33   if [[ -z "${HOST-}" ]]; then HOST="$BUILD"; fi
zcutil/build.sh:104     HOST="$HOST" BUILD="$BUILD" ... make -C ./depends/
zcutil/build.sh:107     DEPS_DIR="$PWD/depends/$HOST"
```

Consequences:

- **CORRECT** (cross-compiles): `HOST=x86_64-w64-mingw32 ./zcutil/build.sh -j$(nproc)`
- **WRONG** (silently builds a native Linux ELF): `./zcutil/build.sh HOST=x86_64-w64-mingw32`

  In the wrong form the `HOST=...` token is passed to `make` as a harmless no-op
  MAKEARG, `HOST` stays equal to `config.guess` (`x86_64-unknown-linux-gnu`), and
  you get a Linux `zclassicd` with **no** `.exe`. Symptom: `file src/zclassicd*`
  reports `ELF`, not `PE32+`.

The recommended wrapper `zcutil/build-release.sh` avoids this entirely — it maps a
*target word* (`linux` / `win64`) to the correct `HOST` internally
(`build-release.sh:31-54`) and sets it as an env var when invoking `make`
(`build-release.sh:68`). **Prefer `build-release.sh` for releases.**

---

## 1. Prerequisites

### 1.1 Host requirements (from `BUILD.md`)

- OS: Ubuntu 20.04+, Debian 11+, Arch/Manjaro, or compatible Linux. (This box is
  Ubuntu 24.04 / GCC 14, well above the GCC 9+ / Clang 10+ floor.)
- RAM: 4 GB+ recommended. The Rust snark/`librustzcash` compile is RAM-heavy; on
  low-RAM machines use a smaller `-j` (e.g. `-j4`) to avoid OOM.
- Disk: 20 GB+ free.
- First build is slow (**30–60 min**) because `depends/` compiles Boost and builds
  the Rust snark + `librustzcash`.

### 1.2 Install host build dependencies

Auto-detects Ubuntu/Debian (`apt`) or Arch (`pacman`) via `/etc/os-release`; uses
`sudo`.

```bash
cd /home/rhett/github/zclassic
./zcutil/install-deps.sh
```

Ubuntu/Debian package set (`install-deps.sh:56-82`):
`build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool automake
libgmp-dev libdb++-dev libsodium-dev git python3 wget curl zlib1g-dev libssl-dev
libevent-dev`.

Arch set (`install-deps.sh:118-133`):
`base-devel autoconf automake libtool pkgconf gmp db libsodium curl git python
wget openssl libevent`.

### 1.3 The `depends/` system (what gets built, and what it pins)

`./zcutil/build.sh` and `build-release.sh` first build a hermetic dependency
prefix under `depends/<HOST>/`. `depends/` builds: Boost, OpenSSL, libevent,
zeromq, libgmp, libsodium, googletest, Berkeley DB (wallet), plus a **pinned Rust
toolchain** used solely to build `librustzcash` (the zk-proof static lib).

- Rust is **pinned to 1.32.0** and downloaded from `static.rust-lang.org`
  (sha256-checked). The build does **not** use your system `cargo` — `depends` is
  self-contained. (`depends/packages/rust.mk`)
- `librustzcash` is pinned to git commit
  `06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5`, built with
  `cargo build --package librustzcash --frozen --release`.
  (`depends/packages/librustzcash.mk`)
- **Network access required on a clean depends build:** `static.rust-lang.org`,
  the `z.cash` depends-sources mirror, and `github.com`.
- Proton/AMQP is **OFF by default** for all targets (`build.sh:93`,
  `NO_PROTON`).

The three supported host triples (`depends/Makefile:148-153`):

| Platform | HOST triple                | depends host config |
|----------|----------------------------|---------------------|
| Linux    | `x86_64-unknown-linux-gnu` | `depends/hosts/linux.mk` |
| Windows  | `x86_64-w64-mingw32`       | `depends/hosts/mingw32.mk` (+ `default.mk`) |
| macOS    | `x86_64-apple-darwin11`    | `depends/hosts/darwin.mk` |

**Current state of this checkout** (verified):

- `depends/x86_64-unknown-linux-gnu/share/config.site` — **EXISTS** (built).
- `depends/x86_64-w64-mingw32/share/config.site` — **EXISTS** (built).
- `depends/x86_64-apple-darwin11/` — contains only a stray `lib/` dir; **NO**
  `share/config.site`, **NO** `native/bin`, and `depends/SDKs/` does **not**
  exist. macOS cross-build is **not** set up here (see §4).
- `depends/built/{linux,win,osx triples}/` each hold the cached source/package
  tarballs, so the linux + win depends do **not** need re-downloading.

Useful `depends` knobs: `HOST=`, `NO_WALLET=1` (→ `--disable-wallet`, no bdb),
`NO_PROTON`, `DEBUG`, `SOURCES_PATH=`, `BASE_CACHE=`.

### 1.4 Windows cross toolchain (only needed for §3)

```bash
sudo bash /home/rhett/github/zclassic/zcutil/setup-mingw-toolchain.sh
# equivalently:  sudo ./zcutil/install-deps.sh --mingw
```

This installs `g++-mingw-w64-x86-64 gcc-mingw-w64-x86-64
binutils-mingw-w64-x86-64 mingw-w64-x86-64-dev mingw-w64-tools` and **switches the
thread model to POSIX** via `update-alternatives` (`setup-mingw-toolchain.sh:19-20`).

**The POSIX thread model is mandatory** — the C++ uses `std::thread`/`std::mutex`,
which the default `-win32` model omits. Verify (must print `posix`):

```bash
x86_64-w64-mingw32-g++ -v 2>&1 | sed -n 's/^Thread model: //p'   # MUST be: posix
```

### 1.5 Runtime prerequisite (NOT a build prereq): zk parameters

Before *running* `zclassicd` (not before building it), fetch ~1.6 GB of proving
parameters:

```bash
cd /home/rhett/github/zclassic
./zcutil/fetch-params.sh
```

Target dir is `~/.zcash-params` on Linux,
`~/Library/Application Support/ZcashParams` on macOS (`fetch-params.sh:6-8`).
Files: `sprout-proving.key`, `sprout-verifying.key`, `sapling-spend.params`,
`sapling-output.params`, `sprout-groth16.params`. The daemon will fail zk
operations without these, but they are not needed to compile.

> Note on the sprout proving key constant: `fetch-params.sh:11` names it
> `SPROUT_PKEY_NAME='sprout-proving.key.deprecated-sworn-elves'` (the remote
> object name); it is fetched to the local file `sprout-proving.key`.

> **NOTE (GUI single-file wallet does NOT pre-download params from z.cash).**
> z.cash now `403`s the deprecated `sprout-proving.key`, so the GUI no longer
> pre-fetches params over HTTP. Instead the embedded daemon fetches any missing
> params from a bootstrap peer over P2P, hash-verified
> (`init.cpp` `InitSanityCheck` → `FetchZcashParamsFromPeer`, default
> `-bootstrap=true`).

---

## 2. Linux (native) build

There are two flows. **2a (`build.sh`)** is the dev build (binaries land in
`src/`). **2b (`build-release.sh`)** is the stripped release build (binaries land
in `release/<triple>/`).

### 2a. Dev build (binaries in `src/`)

```bash
cd /home/rhett/github/zclassic
./zcutil/build.sh -j$(nproc)
```

Produces `src/zclassicd`, `src/zclassic-cli`, `src/zclassic-tx` (unstripped, with
debug `-g`).

> **build.sh flags are ORDER-SENSITIVE** (`build.sh:73-98`). If you pass any, they
> must appear in this exact order, before MAKEARGS:
> `[ --enable-lcov | --disable-tests ]  [ --disable-mining ]  [ --enable-proton ]  [ -jN ... ]`
> Out-of-order flags are silently treated as make args. Default build is
> `--enable-hardening` with tests **enabled**.

### 2b. Release build (stripped, in `release/x86_64-unknown-linux-gnu/`)

```bash
cd /home/rhett/github/zclassic
./zcutil/build-release.sh linux -j$(nproc)
```

This runs depends → `autogen.sh` → `./configure --prefix=/ --disable-tests` →
`make` → strips `zclassicd`/`zclassic-cli`/`zclassic-tx` into
`release/x86_64-unknown-linux-gnu/` (`build-release.sh:125-137`). If you pass no
make args it defaults to `-j$(nproc)` (`build-release.sh:60-61`).

### 2c. Release build for embedding in the GUI (static libgomp)

A fresh desktop often lacks `libgomp.so.1`; without it the GUI's embedded node
fails to start ("connection refused"). Statically link it:

```bash
cd /home/rhett/github/zclassic
ZQW_STATIC_GOMP=1 ./zcutil/build-release.sh linux -j$(nproc)
```

`ZQW_STATIC_GOMP=1` relinks with the static `libgomp.a` + `-Wl,--as-needed` +
`-ldl` (`build-release.sh:96-123`). **Verify the result has no libgomp dependency**
(see §5).

> **Glibc floor warning (important for distribution).** A native build on a
> modern host bakes in a high glibc floor. The currently committed
> `release/x86_64-unknown-linux-gnu/zclassicd` has floor **GLIBC_2.38** and still
> `NEEDED libgomp.so.1` — i.e. it was *not* built with `ZQW_STATIC_GOMP` and will
> **not** run on older distros (symptom on the user's machine:
> `version GLIBC_2.38 not found`). To produce a **portable** Linux daemon with a
> low glibc floor, build it inside an old-base (glibc 2.31) sandbox with
> `--enable-glibc-back-compat --enable-reduce-exports` and `ZQW_STATIC_GOMP=1`;
> see §6. The Windows `.exe` has no such floor issue.

### 2d. Other Linux variants

```bash
# Build WITHOUT wallet support (smaller, no Berkeley DB):
cd /home/rhett/github/zclassic
make -C depends -j$(nproc) NO_WALLET=1 \
  && ./autogen.sh \
  && CONFIG_SITE="$PWD/depends/$(./depends/config.guess)/share/config.site" \
     ./configure --disable-wallet --disable-tests \
  && make -j$(nproc)

# Build only the depends prefix:
make -C depends -j$(nproc) NO_PROTON=1
```

---

## 3. Windows (mingw cross) build

> **Lead rule (repeat from §0):** `HOST=x86_64-w64-mingw32` must be an **env var**,
> never a positional arg. Prefer `build-release.sh win64`, which sets it for you.

### 3.0 One-time toolchain (see §1.4)

```bash
sudo bash /home/rhett/github/zclassic/zcutil/setup-mingw-toolchain.sh
x86_64-w64-mingw32-g++ -v 2>&1 | sed -n 's/^Thread model: //p'   # MUST print: posix
```

### 3a. Recommended: one-command stripped build

```bash
cd /home/rhett/github/zclassic
./zcutil/build-release.sh win64 -j$(nproc)
```

Produces stripped `release/x86_64-w64-mingw32/zclassicd.exe` (+ `zclassic-cli.exe`,
`zclassic-tx.exe`). `build-release.sh:41-45` errors early if
`x86_64-w64-mingw32-g++` is missing.

For a daemon to be embedded in the Windows GUI (no libgomp runtime dependency):

```bash
cd /home/rhett/github/zclassic
ZQW_STATIC_GOMP=1 ./zcutil/build-release.sh win64 -j$(nproc)
```

(For win64, `build-release.sh:106-110` pulls the **mingw** `libgomp.a` via
`x86_64-w64-mingw32-gcc -print-file-name=libgomp.a`, matching the PE ABI.)

### 3b. Manual path (equivalent to what `build.sh` does), then strip

```bash
cd /home/rhett/github/zclassic
HOST=x86_64-w64-mingw32 ./zcutil/build.sh -j$(nproc)        # -> src/zclassicd.exe (~278 MB unstripped)
x86_64-w64-mingw32-strip -s src/zclassicd.exe              # -> ~13.5 MB stripped
```

> Note: the unstripped `src/zclassicd.exe` is **~278 MB** — that is normal, not a
> build error. Use the **host-prefixed** strip (`x86_64-w64-mingw32-strip`), never
> the host `strip` (it cannot process PE).

### 3c. Confirm it is a real Windows PE (not a silently-built ELF)

```bash
cd /home/rhett/github/zclassic
file release/x86_64-w64-mingw32/zclassicd.exe    # expect: PE32+ executable (console) x86-64 ... for MS Windows
du -h release/x86_64-w64-mingw32/zclassicd.exe   # expect ~13.5 MB stripped
```

If `file` says `ELF`, you used the positional-`HOST` mistake — see §0.

---

## 4. macOS (darwin) build

> **Status on this box: NOT currently buildable as-is.** The darwin depends
> toolchain is incomplete here (`depends/x86_64-apple-darwin11/` has only a stray
> `lib/` dir, no `share/config.site`, no `native/bin`; `depends/SDKs/` is absent).
> `build-release.sh` has **no** `mac`/`osx`/`darwin` target. macOS releases in
> practice are built on a Mac (see §4c), not cross-compiled here.

### 4a. What darwin requires (`depends/hosts/darwin.mk`)

- `OSX_MIN_VERSION=10.8`, `OSX_SDK_VERSION=10.11`
- The macOS 10.11 SDK at `depends/SDKs/MacOSX10.11.sdk` (referenced as
  `$(SDK_PATH)/MacOSX10.11.sdk`). Apple's SDK cannot be freely redistributed, so
  you must source it yourself.
- `darwin_native_toolchain=native_cctools` (clang + cctools `strip`/`ld64`,
  `LD64_VERSION=253.9`).
- `darwin.mk` also references `$(shell xcrun --show-sdk-path)` for its
  CFLAGS/LDFLAGS sysroot, i.e. it expects a working `xcrun` (Xcode) — strongly
  implying the intended darwin build runs **on a Mac**, not as a Linux cross-build.

### 4b. Cross-build attempt (only after providing the SDK + cctools)

These prerequisites are MISSING here and must be provided first. Once
`depends/SDKs/MacOSX10.11.sdk` exists and depends can build `native_cctools`:

```bash
# NOTE: untested here — provided per depends/hosts/darwin.mk; SDK + cctools must exist first.
cd /home/rhett/github/zclassic/depends
make HOST=x86_64-apple-darwin11 -j$(nproc)

cd /home/rhett/github/zclassic
HOST=x86_64-apple-darwin11 ./zcutil/build.sh -j$(nproc)
# build-release.sh has NO darwin target, so strip manually with the cctools strip:
#   x86_64-apple-darwin11-strip src/zclassicd
```

### 4c. Recommended in practice: native build on a Mac

On a Mac with Xcode command-line tools installed:

```bash
# On macOS:
cd /path/to/zclassic
./zcutil/build.sh -j$(sysctl -n hw.ncpu)    # native; binaries in src/
strip src/zclassicd src/zclassic-cli src/zclassic-tx   # optional
./src/zclassicd --version
```

> **Open question to resolve before a real macOS release:** is the shipped macOS
> daemon (a) cross-built from Linux via `HOST=x86_64-apple-darwin11`, or (b) built
> natively on a Mac (the published `.dmg` is arm64, which depends does **not**
> define — depends only knows `x86_64-apple-darwin11`)? Pick one and document it.
> Consider adding an explicit `mac|osx|darwin` target to `build-release.sh` so the
> macOS daemon is reproducible the same way `win64` is.

---

## 5. Output verification

Run these after any build. **Never trust the build's exit code alone** — verify
the artifact.

### 5.1 Format check (`file`) — expected outputs

```bash
cd /home/rhett/github/zclassic

# Linux:
file release/x86_64-unknown-linux-gnu/zclassicd
#   -> ELF 64-bit LSB pie executable, x86-64 ... dynamically linked ... stripped

# Windows:
file release/x86_64-w64-mingw32/zclassicd.exe
#   -> PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows
```

### 5.2 Version string

```bash
./release/x86_64-unknown-linux-gnu/zclassicd --version | head -1
#   -> ZClassic Daemon version v2.1.2-beta5-<hash>
```

Version source of truth: `configure.ac:9` `_CLIENT_VERSION_BUILD = 4` and
`src/clientversion.h:26` `CLIENT_VERSION_BUILD 4`. The `configure.ac:10-11` macro
renders build `N < 25` as `-beta(N+1)`, so build `4` = **beta5**. A `-unk` suffix
instead of a commit hash means the tree had no git tag/`describe` (cosmetic;
build from a tagged checkout for a clean suffix).

### 5.3 Strip confirmation (size drop)

```bash
# Windows: unstripped src copy vs stripped release copy
ls -l /home/rhett/github/zclassic/src/zclassicd.exe                       # 278172057 bytes (~266 MiB) unstripped
du -h /home/rhett/github/zclassic/release/x86_64-w64-mingw32/zclassicd.exe # ~13.5 MB
```

### 5.4 Glibc floor (Linux portability gate)

```bash
objdump -T /home/rhett/github/zclassic/release/x86_64-unknown-linux-gnu/zclassicd \
  | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -1
# A distributable binary should be <= GLIBC_2.31 (built via the §6 old-base path).
# A plain native build on a modern host will show a higher floor (e.g. GLIBC_2.38).
```

### 5.5 No leaked dynamic deps (esp. libgomp)

```bash
# Should NOT list libgomp.so.1 if built with ZQW_STATIC_GOMP:
objdump -p /home/rhett/github/zclassic/release/x86_64-unknown-linux-gnu/zclassicd | grep NEEDED
```

---

## 6. Portable Linux daemon (low glibc floor) — out-of-repo, flag explicitly

The native build (§2) targets the host's glibc and will not run on older distros.
The distributable Linux daemon is built inside an **Ubuntu 20.04 / glibc 2.31
proot sandbox** that lives **outside the git repo** at `/home/rhett/zclbuild`
(uncommitted tribal knowledge — see §8). Inside that sandbox the recipe sets
`NO_PROTON=1`, `CONFIGURE_FLAGS='--enable-glibc-back-compat --enable-reduce-exports'`,
`ZQW_STATIC_GOMP=1`, then calls `zcutil/build-release.sh linux`, yielding a daemon
with a **GLIBC_2.29** floor and no libgomp dependency.

```bash
# Portable Linux daemon via the proot glibc-2.31 sandbox (sandbox is NOT in the repo):
cd /home/rhett/zclbuild
./prun bash /build/03-daemon.sh
# -> /build/daemon/release/x86_64-unknown-linux-gnu/zclassicd (glibc floor ~2.29)
```

**This sandbox and its scripts are not version-controlled.** They should be
committed (see §8) or the portable-build knowledge remains un-reproducible. The
native daemon and the proot daemon are built from the *same* repo source; only the
toolchain/sandbox differs.

---

## 7. Tests

Tests are **only built when you do NOT pass `--disable-tests`**. Since
`build-release.sh` always passes `--disable-tests` (`build-release.sh:86`), you
**must** use a `build.sh` dev build (§2a) without `--disable-tests` so
`test_bitcoin` and `zcash-gtest` get compiled.

```bash
cd /home/rhett/github/zclassic
./zcutil/build.sh -j$(nproc)        # builds the test binaries (tests are ON by default)

# C++ unit tests (runs src/test/test_bitcoin):
make -C src bitcoin_test_check      # src/Makefile.test.include:147

# zcash gtest suite (runs src/zcash-gtest):
make -C src zcash-gtest_check       # src/Makefile.gtest.include:74

# misc local checks (bitcoin-util-test.py + secp256k1 + univalue):
make check-local                    # src/Makefile.test.include:153

# Python RPC integration tests:
qa/pull-tester/rpc-tests.sh
```

> There is no verified single top-level `make check` aggregator; the verified
> entry points are the per-target `*_check` rules above and `check-local`.

---

## 8. Scripts that are NOT in the repo (commit these)

The following are load-bearing build assets that currently live outside any git
repo. A future builder cannot reproduce the portable/cross builds without them —
they should be committed (e.g. under `zcutil/portable/` or a dedicated build-env
repo) with repo paths parameterized:

- `/home/rhett/zclbuild/prun` — proot entrypoint (binds the repos into the
  glibc-2.31 sandbox).
- `/home/rhett/zclbuild/focal/build/03-daemon.sh` — the portable-Linux daemon
  recipe (host-artifact exclusion + `--enable-glibc-back-compat` + static gomp).
- `/home/rhett/zclbuild/focal/build/{build.sh,02-openssl-qt.sh,04-gui-bundle.sh,05-static-helpers.sh}`
  — the rest of the sandbox orchestration (mostly GUI-side, but `build.sh` drives
  the whole sandbox).
- The recipe that provisioned the `focal/` rootfs (apt install list: gcc-9,
  rsync, etc.) is not captured anywhere — add a `00-bootstrap-rootfs.sh` + apt
  manifest.

Already in the repo (reference, do **not** re-commit): `zcutil/build.sh`,
`zcutil/build-release.sh`, `zcutil/install-deps.sh`,
`zcutil/setup-mingw-toolchain.sh`, `zcutil/fetch-params.sh`.

---

## 9. Troubleshooting (gotchas)

**`HOST` as a positional arg → silent Linux binary.**
Symptom: you asked for Windows but `file src/zclassicd*` says `ELF` and there's no
`.exe`. Cause: `./zcutil/build.sh HOST=x86_64-w64-mingw32` (positional).
Fix: `HOST=x86_64-w64-mingw32 ./zcutil/build.sh` (env var) or use
`./zcutil/build-release.sh win64`.

**mingw win32 thread model → compile failure.**
Symptom: errors about `std::thread`/`std::mutex` not in `namespace std`. Cause:
the `x86_64-w64-mingw32-g++` alternative points at `-win32`. Fix:
`sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix`
(and `-gcc`); `setup-mingw-toolchain.sh` does this. Verify with
`x86_64-w64-mingw32-g++ -v | grep 'Thread model'` → `posix`.

**Host-switch object mixing (linux ↔ win64 in the same tree).**
Symptom: link errors about incompatible object architecture (COFF into ELF or
vice-versa). Cause: in-tree static libs (`src/snark`, leveldb, univalue) rebuild
off their own sources, not `config.h`, so a plain `make` won't rebuild them on a
host switch. Fix: `build-release.sh:76-93` auto-detects the host change and runs
`make clean` + `make -C src/snark clean`. If building by hand with `build.sh`, run
those two cleans yourself when switching `HOST`.

**build.sh flag order.**
Out-of-order `--disable-tests`/`--disable-mining`/`--enable-proton` are silently
treated as make args. Order: `[--enable-lcov|--disable-tests] [--disable-mining]
[--enable-proton] [MAKEARGS...]` (`build.sh:73-98`).

**Unstripped `.exe` is ~278 MB.**
Not an error. Strip with `x86_64-w64-mingw32-strip -s` → ~13.5 MB. Use the
host-prefixed strip for PE; the plain host `strip` cannot process PE.

**Tests not built.**
`build-release.sh` always passes `--disable-tests`, so `test_bitcoin`/`zcash-gtest`
won't exist. Do a `build.sh` dev build without `--disable-tests` first (§7).

**High glibc floor / `libgomp.so.1` missing on the user's machine.**
Native builds bake in the host glibc floor and (without `ZQW_STATIC_GOMP`) need
`libgomp.so.1`. For distribution build via the proot glibc-2.31 sandbox (§6) with
`ZQW_STATIC_GOMP=1`. Verify with §5.4 and §5.5.

**`src/` binaries may not exist.**
A clean / release-built tree has binaries only in `release/<triple>/`; `src/`
binaries appear only after a `build.sh` dev build. (Currently:
`release/x86_64-unknown-linux-gnu/` and `release/x86_64-w64-mingw32/` are
populated, `src/zclassicd.exe` exists, but `src/zclassicd` (Linux) does not.)

**macOS cannot be cross-built here as-is.**
Symptom: `make -C depends HOST=x86_64-apple-darwin11` fails building
`native_cctools` / can't find the SDK. Cause: `depends/SDKs/MacOSX10.11.sdk` and
the darwin toolchain are absent (§4). Fix: provide the SDK + cctools, or build on
a Mac.

**First build is slow / OOM.**
30–60 min is normal (Boost + Rust snark + `librustzcash`). On low RAM, lower `-j`
(e.g. `-j4`). A clean depends build needs network access to
`static.rust-lang.org`, the `z.cash` depends mirror, and `github.com`.

**`build-linux-ci.sh` is legacy.**
It hardcodes a stale `VER='v2.1.1-5'` and passes `--disable-man`. Prefer
`build-release.sh` for packaging; treat `build-linux-ci.sh` as legacy.

**Pipe-through-`tail` can report exit 0 on a failed build.**
Don't trust a green log. Always verify the artifact: `file`, `--version`, glibc
floor, `objdump -p ... | grep NEEDED` (§5).
