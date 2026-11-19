# wallet agent rules

Imports the root contract: [../AGENTS.md](../AGENTS.md). This file adds only what is specific to the Qt GUI wallet (`zclwallet`). Build procedures: [docs/BUILDING.md](docs/BUILDING.md). Test layers: [docs/TESTING.md](docs/TESTING.md), [tests/README.md](tests/README.md).

## Custody

The wallet holds keys and spends funds. Source inspection, edits and isolated tests do not permit:

- spending, or sending a transaction on a real network;
- exporting, printing or logging keys, seeds or passphrases (not in logs, argv, fixtures or commits);
- opening, rescanning or modifying a real wallet profile or datadir.

Anything that renders, signs or broadcasts goes through the existing send and RPC paths; add no second one.

## Isolated profiles and headless tests

- `ZCLWALLET_PROFILE_DIR=<existing empty dir>` (or `--profile-dir <dir>`) keeps settings, wallet data and the embedded node's datadir inside that directory. Every manual or scripted run of the wallet uses it. See `docs/TESTING.md`.
- Widget and logic tests need no display: `QT_QPA_PLATFORM=offscreen`. They build with the pinned Qt 5.15 kit (the focal distro Qt is 5.12 and too old for `Qt::endl`). Qt project files: `tests/tests.pro` (`tst_logic`), `tests/widget/tst_widget.pro`, and the `check-*.pro` helpers.
- Redirect `APPDATA`, `LOCALAPPDATA` and `USERPROFILE` into a scratch directory on Windows, as `tests/run-windows.sh` does.
- Never start `zclwallet` against a real home in a test. Never leave a daemon or wallet process you started running.

## Windows

- `sh wallet/tests/run-windows.sh QT_DIR MINGW_DIR LIBSODIUM_A [PATCHED_QT_DIR]` builds and runs the wallet test binaries headless under Git Bash. Without a patched `Qt5Widgets.dll` (`tests/qt-5.15.2-windows-offscreen.patch`) the functions that open a `QMessageBox` are expected to crash and are reported `KNOWN-CRASH`; any other failure fails the run.
- The release bundle is `wallet/contrib/release/build-windows.sh` (Qt kit and MinGW named in its header). `tests/windows-packaging.sh` checks the packaging rules against real MinGW fixtures. Use `windeployqt --debug` on kits whose release DLLs carry a debug link.
- Kill a stuck Windows process with `taskkill /F /PID <pid>` for a PID you started; never by image name.

## Embedded daemon footer

The shipped wallet carries `zclassicd` as `[wallet][daemon][sha256:32][len:8 LE][ZQWDMON1]`. Writers: `contrib/release/linux.sh`, `contrib/release/build-windows.sh`, `contrib/make-allinone.sh`. Reader: `src/embeddeddaemon.cpp`. Change all of them together and run `tests/check-embedded.pro`. macOS has no footer (sibling binary in the app bundle). `src/daemonjob.h` explains the Windows job object that stops an orphaned daemon.

## Rules of the tree

- The wallet links the daemon over RPC only. It never includes daemon headers or consensus code.
- Release builds follow the toolchain in the root contract: GCC 9 on the Linux candidate, MinGW 8.1 for the Windows kit, Apple clang for macOS.
- Wallet changes that touch sending, keys, backup or the embedded node need a reviewer who is not the author.
