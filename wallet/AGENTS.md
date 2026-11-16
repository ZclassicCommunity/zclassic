# AGENTS.md — Build Quickstart (read me first)

You are about to build **ZClassic**: the daemon (`zclassicd`) and the all-in-one Qt GUI wallet, for **Linux, Windows, and macOS**. This file is the map. It does not duplicate the detailed guides — it points you at them and lists the traps that have actually bitten us.

> Do **not** trust this doc blindly over the source. Scripts move. Before quoting a line, `grep`/`Read` it. Where a fact is load-bearing, the file:line is cited so you can re-verify in seconds.

---

## 1. Big picture

**Two repos** (both already on this box):

| Repo | Path | Produces |
|------|------|----------|
| Daemon | `/home/rhett/github/zclassic` | `zclassicd`, `zclassic-cli`, `zclassic-tx` (+ `.exe` for win64) |
| GUI wallet | `/home/rhett/github/zcl-qt-wallet` | `zclwallet` GUI, and the **single-file all-in-one** release |

**Single-file embed model** — the shipped GUI is one self-contained executable. The daemon is appended to the GUI binary as a footer and the GUI hash-verifies + extracts it on first launch:

```
[ GUI binary ][ daemon bytes ][ sha256(daemon):32 ][ len(daemon):8 LE u64 ][ magic "ZQWDMON1":8 ]
```

This layout is written/read identically in three places (keep them in sync if you touch it):
- write (release): `zcl-qt-wallet/src/scripts/mkrelease.sh:100-108`
- write (dev): `zcl-qt-wallet/contrib/make-allinone.sh:64-72`
- read (runtime): `zcl-qt-wallet/src/connection.cpp` `ensureDaemonExtracted()` (~`:615-700`)

**macOS is the exception.** Notarization / hardened runtime forbid executing a runtime-written binary, so on macOS the GUI does **not** use the footer — it ships the daemon as a **sibling** inside `zclwallet.app/Contents/MacOS/` (`connection.cpp:621-622` returns empty under `Q_OS_DARWIN`). The ZQWDMON1 embed is Linux/Windows-only.

**Current version:** `v2.1.2-beta5` (daemon `configure.ac` build=4 → beta5; wallet `src/version.h` `APP_VERSION "2.1.2-beta5"`). The version string is hard-coded in several proot scripts — see the gotchas.

---

## 2. Fastest verified path → portable Linux single-file

The release Linux bundle is built inside an **unprivileged proot Ubuntu-20.04 (glibc 2.31) sandbox** — no Docker, no root, no CI. This is the only way to get a low glibc floor that runs on old distros. The whole pipeline lives at `/home/rhett/zclbuild` (entrypoint `prun`).

```bash
# One command: build daemon (if changed) + static-Qt GUI + embed + run the delivery gate.
# Recommended with persistent ccache for fast rebuilds:
cd /home/rhett/zclbuild
EXTRA_BINDS="-b $HOME/.ccache:/root/.ccache" ./prun bash /build/build.sh

# Force a full daemon rebuild too:
./prun bash /build/build.sh --clean
```

Delivered artifact (copied back to the host repo by the build):

```bash
ls -lh /home/rhett/github/zcl-qt-wallet/artifacts/linux-zclwallet-v2.1.2-beta5
```

**Real-display UX matrix** (boots a real Xvfb+twm, NOT offscreen — catches the window-never-maps class of bug). Run from the host, not inside proot:

```bash
/home/rhett/zclbuild/focal/build/run.sh all      # fresh|stub|foreign|nox scenarios
/home/rhett/zclbuild/focal/build/run.sh stub      # one scenario
# prints: RUN_VERDICT=PASS|FAIL (exit=N)
```

One-time toolchain bootstrap (only if `/opt/qt-static` is missing inside the sandbox; takes hours):

```bash
/home/rhett/zclbuild/prun bash /build/02-openssl-qt.sh   # static OpenSSL 1.1.1w + static Qt 5.15.2
```

> ⚠️ **The entire `/home/rhett/zclbuild` tree is NOT in any git repo.** It is the single biggest tribal-knowledge risk. See "Commit-these" below.

For a quick **dynamic-Qt dev single-file** on this host (NOT portable, for testing only):

```bash
cd /home/rhett/github/zclassic && ./zcutil/build.sh -j$(nproc)        # daemon → src/zclassicd
cd /home/rhett/github/zcl-qt-wallet && contrib/make-allinone.sh /home/rhett/github/zclassic/src/zclassicd
# test the EMBEDDED daemon path from a scratch dir (GUI prefers a sibling daemon if present):
( cd "$(mktemp -d)" && cp /home/rhett/github/zcl-qt-wallet/linux-zclwallet-allinone . && ./linux-zclwallet-allinone )
```

---

## 3. Detailed guides (go here for the real procedures)

- **DAEMON — in the `zclassic` repo: `doc/building-daemon-from-source.md`** (Linux native, Windows cross, macOS cross, depends system, tests). Start from `BUILD.md` (canonical Linux dev build) and `zcutil/build-release.sh` (stripped release).
- **GUI wallet — in the `zcl-qt-wallet` repo: `docs/BUILDING.md`** (proot portable Linux + .deb, Windows cross single-file, macOS .app/.dmg, the ZQWDMON1 footer, libsodium staging).

> These two detailed docs are the deliverables that accompany this file. If they are not present yet, they must be authored from the same verified knowledge base — do not improvise build commands from memory.

Quick per-platform entry points:

| Target | Command |
|--------|---------|
| Daemon Linux (dev, → `src/`) | `./zcutil/build.sh -j$(nproc)` |
| Daemon Linux (release, stripped) | `./zcutil/build-release.sh linux -j$(nproc)` |
| Daemon Win64 cross | `sudo bash zcutil/setup-mingw-toolchain.sh` then `./zcutil/build-release.sh win64 -j$(nproc)` |
| Daemon macOS | **No `build-release.sh` darwin target.** depends triple `x86_64-apple-darwin11` exists but the SDK + cctools are **not** on this box — see gotchas. Practically built natively on a Mac. |
| GUI Linux portable | `./prun bash /build/build.sh` (section 2) |
| GUI Windows | `bash /home/rhett/build-qtbase-win.sh` → `bash /home/rhett/build-gui-win.sh` → **manual** footer embed (see gotchas) |
| GUI macOS .dmg | `src/scripts/mkmacdmg.sh -q <qt> -z <zclassic> -v 2.1.2-beta5` (on a Mac) + **manual ad-hoc codesign** |

---

## 4. Canonical gotchas — tight checklist

- [ ] **`HOST` is an ENV VAR, never positional.** `HOST=x86_64-w64-mingw32 ./zcutil/build.sh` ✅. `./zcutil/build.sh HOST=...` ❌ silently builds a **Linux ELF** (the token becomes a no-op make arg). `build.sh:32-33`. Prefer `build-release.sh win64` which sets it internally.
- [ ] **mingw must be the POSIX thread model.** The win32 model lacks `std::thread`/`std::mutex` → compile fails. `setup-mingw-toolchain.sh` sets it; verify: `x86_64-w64-mingw32-g++ -v` must print `Thread model: posix`.
- [ ] **Always clean-build the GUI / clean when switching HOST.** Stale qmake Makefiles re-link `-lQt5WebSockets` (master's `.pro` still had it) → runtime `libQt5WebSockets.so.5` not found. Stale daemon trees mix COFF↔ELF objects. `make distclean && rm -f Makefile .qmake.stash` for the GUI; `build-release.sh` auto-`make clean`s on host change. `make-allinone.sh` aborts via an `ldd | grep Qt5WebSockets` self-check.
- [ ] **Portable Linux MUST be built in the proot glibc-2.31 sandbox**, not on the host. A host build (glibc 2.39) bakes in `__isoc23_*` / `arc4random` / `strlcpy` with no older fallback → `version GLIBC_2.38 not found` on users' machines. `mkrelease.sh` hard-gates at ≤ GLIBC_2.31. Verify: `objdump -T <bin> | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -1` (the good bundle reads `GLIBC_2.29`).
- [ ] **Static-link libgomp** for the embedded daemon (`ZQW_STATIC_GOMP=1`; set by `03-daemon.sh`). A fresh desktop often lacks `libgomp.so.1` → GUI hangs at 96% then "connection refused". Check **both** GUI and daemon: `objdump -p <bin> | grep NEEDED`.
- [ ] **Stale-delivery trap.** The proot build writes inside the chroot at `/build/wallet/artifacts/` (rsync-excluded from the host). `04-gui-bundle.sh:137-142` copies it back and `build.sh`'s gate asserts `sha256(built) == sha256(delivered)`. **Always run via `build.sh`, never `04` alone**, and confirm the `.sha256` sidecar before telling anyone to download.
- [ ] **Windows GUI does NOT embed the daemon automatically.** `build-gui-win.sh` stops at `release/zclwallet.exe`. The ZQWDMON1 footer is a **separate manual Python step** using the **stripped** `src/zclassicd.exe` (`x86_64-w64-mingw32-strip -s`; ~278 MB → ~13.5 MB). Logic = `mkrelease.sh:100-108`.
- [ ] **macOS codesign order is load-bearing and NOT in any script.** `mkmacdmg.sh` has **no** codesign step. Run `codesign --force --deep -s - zclwallet.app` **AFTER** `macdeployqt`, **BEFORE** `create-dmg` — signing before macdeployqt → Apple-Silicon SIGKILL on launch. This rule is memory-only; verify with the Mac dev.
- [ ] **Don't trust the exit code.** A pipe-through-tail can report exit 0 even when the build failed. Always verify the artifact: footer (`tail -c 8 <bundle>` == `ZQWDMON1`), glibc floor, `ldd`/`NEEDED`, and the sha sidecar.
- [ ] **Runtime prereq (not a build prereq):** `./zcutil/fetch-params.sh` downloads ~1.6 GB zk params into `~/.zcash-params` before first run.
- [ ] **macOS cannot currently be cross-built on this box:** `depends/SDKs/` is missing and `depends/x86_64-apple-darwin11` lacks the cctools toolchain. Don't expect `make -C depends HOST=x86_64-apple-darwin11` to succeed as-is.

---

## 5. Verify + publish a release

The published assets live on **`ZclassicCommunity/zcl-qt-wallet`** (release `v2.1.2-beta5`, prerelease). Three platform assets are expected.

**Step 1 — verify each artifact locally before upload:**

```bash
# footer magic on Linux + Windows single files:
tail -c 8 artifacts/linux-zclwallet-v2.1.2-beta5; echo          # → ZQWDMON1
tail -c 8 artifacts/zclwallet-v2.1.2-beta5-win64.exe; echo      # → ZQWDMON1
# Linux glibc floor (must be ≤ 2.31; current good build = 2.29):
objdump -T artifacts/linux-zclwallet-v2.1.2-beta5 | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -1
# no Qt / no stray dynamic deps in the static bundle:
ldd artifacts/linux-zclwallet-v2.1.2-beta5 | grep -i qt        # must be empty
# sha matches its sidecar (proves it's the gated build, not stale):
sha256sum artifacts/linux-zclwallet-v2.1.2-beta5; cat artifacts/linux-zclwallet-v2.1.2-beta5.sha256
```

**Step 2 — 3-platform sha matrix (the actual sha256s belong in the release NOTES, not here — they change every rebuild):**

| Platform | Asset | how to get/verify its sha |
|----------|-------|---------------------------|
| Linux | `linux-zclwallet-v2.1.2-beta5` | `sha256sum` it; must equal the `.sha256` sidecar the gate wrote |
| Windows | `zclwallet-v2.1.2-beta5-win64.exe` | re-verify footer (`tail -c 8` == `ZQWDMON1`) + recompute the embedded-daemon hash from the footer before upload |
| macOS | `macOS-zclwallet-v2.1.2-beta5.dmg` | built + ad-hoc-signed + verified on a Mac |

> ⚠️ **Local vs published can drift.** Any rebuild changes the sha, so the file already on the GitHub release may be older than your local `artifacts/`. Before announcing, compare `sha256sum artifacts/<asset>` against the published asset (`gh release view … --json assets`) and `--clobber` re-upload if the local gated build is the one you intend to ship. Never assume local == published.

**Step 3 — publish (ad-hoc command; not in any committed script — capture it):**

```bash
gh release upload v2.1.2-beta5 --repo ZclassicCommunity/zcl-qt-wallet --clobber \
  artifacts/linux-zclwallet-v2.1.2-beta5 \
  artifacts/zclwallet-v2.1.2-beta5-win64.exe \
  artifacts/macOS-zclwallet-v2.1.2-beta5.dmg
gh release view v2.1.2-beta5 --repo ZclassicCommunity/zcl-qt-wallet --json assets,isPrerelease,tagName
```

---

## 6. Commit-these (currently tribal knowledge, outside any repo)

These produce the releases and exist **only as loose files on this box** — losing them loses the ability to reproduce the builds. Land them in-repo (suggested homes in parens):

- `/home/rhett/zclbuild/` whole pipeline → daemon `zcutil/portable-builder/` or a dedicated repo:
  `prun`, `focal/build/{build.sh,02-openssl-qt.sh,03-daemon.sh,04-gui-bundle.sh,05-static-helpers.sh,run.sh,uxmatrix.sh,wmclose.c,markers.txt}`. Also needs a `00-bootstrap-rootfs.sh` + apt manifest documenting how the `focal/` rootfs was provisioned (gcc-9, meson/ninja/bison, the static `.a` libs, Xvfb/twm), since that recipe is captured nowhere.
- `/home/rhett/build-qtbase-win.sh`, `/home/rhett/build-gui-win.sh` → `zcl-qt-wallet/contrib/cross/`. Note `build-gui-win.sh` does NOT embed the daemon.
- **Missing entirely:** a shared `embed-daemon.py` (the ZQWDMON1 footer append) used by Linux/Windows/all-in-one, and a `codesign` step inside `mkmacdmg.sh` (after `macdeployqt`, before `create-dmg`). The 3-asset `gh release upload --clobber` publish command is also in no script.

**Already in-repo (reference, don't re-create):** `zcl-qt-wallet/src/scripts/mkrelease.sh`, `contrib/make-allinone.sh`, `src/scripts/mkmacdmg.sh`, `res/libsodium/buildlibsodium.sh`, `src/scripts/dotranslations.sh`; daemon `zcutil/{build.sh,build-release.sh,install-deps.sh,setup-mingw-toolchain.sh}`, `BUILD.md`.
