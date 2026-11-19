# tst_logic — L0 unit suite

Pure-logic unit tests for the ZClassic Qt5 GUI wallet (the **L0** layer from
[`docs/TESTING.md`](../docs/TESTING.md)). Guiless QtTest binary that links ONLY
the wallet's pure-logic translation units plus test shims — **no daemon, no
libsodium, and zero modifications to any file under `src/`**.

## Build + run (inside the proot build chroot)

```sh
/home/rhett/zclbuild/prun bash -c '\
  cd /src/wallet/tests && \
  /opt/qt-static/bin/qmake tests.pro && \
  make -j$(nproc) && \
  QT_QPA_PLATFORM=offscreen ./tst_logic'
```

Expected tail:

```
Totals: 74 passed, 0 failed, 0 skipped, 0 blacklisted
```

`QT_QPA_PLATFORM=offscreen` is required: `addresscombo.cpp` derives from
`QComboBox`, so the target links `QtWidgets` and instantiates a widget — the
offscreen platform plugin lets that happen with no X server.

## What it links

| Product TU (UNMODIFIED) | Why |
|-------------------------|-----|
| `../src/settings.cpp`   | address classifiers + formatters + token name |
| `../src/senttxstore.cpp`| at-rest 0600 store, save-gating |
| `../src/addresscombo.cpp` | label/paren address parsing (D6) |

Plus shims under `shim/` that shadow the heavy product headers **purely via
`INCLUDEPATH` ordering** (`shim/` is searched before `../src`):

- `precompiled.h` — minimal QtCore/QtNetwork-lite PCH; **no `SODIUM_STATIC`, no
  sodium header** (so no libsodium at link time).
- `mainwindow.h` — only the plain-data `ToFields` / `Tx` structs (copied from
  `src/mainwindow.h:18-31`); no `QMainWindow`/`Ui::`.
- `rpc.h` — only the full 8-field `TransactionItem` (copied from `src/rpc.h:16-25`);
  no `RPC` class.
- `addressbook.h` + `addressbook_stub.cpp` — tiny in-memory `AddressBook` with the
  three entry points `addresscombo.cpp` uses, semantics matching
  `src/addressbook.cpp`.

## Checklist coverage (from docs/TESTING.md)

`C3, C5, C6, D6, E7` (field/format pieces needing no RPC), `G1, G4, H1, H2`,
plus exhaustive `Settings` address classifiers
(`isTAddress`/`isZAddress`/`isSaplingAddress`/`isSproutAddress`) and formatters
(`getDecimalString`/`getZCLDisplayFormat`/`getUSDFormat`/token name).

### H1/H2 mirror note

The four H1/H2 classifiers (`looksLikeDbCorruption`, `startupDiagHasMarker`,
`isLongWarmupPhase`, `blocksDirSizeBytes`) are non-extractable members of the
widget-entangled `ConnectionLoader` (`connection.cpp` pulls `ui_*.h` + `RPC` +
the daemon launcher and cannot link at L0), and the no-`src`-modification
constraint forbids extracting them. The bodies under `namespace cxmirror` in
`tst_logic.cpp` are copied **verbatim** from `connection.cpp` at the cited line
numbers and must stay in sync; the tests exercise that exact classification
logic, and `blocksDirSizeBytes` runs real recursive filesystem traversal over a
`QTemporaryDir`. If `connection.cpp`'s marker tables change, update the mirror.

## Safety

`initTestCase()` calls `QStandardPaths::setTestModeEnabled(true)` and sets a
throwaway org/app name, so `QSettings` and `SentTxStore` writes land in a
sandbox (`~/.config/ZClassicTest`, `~/.local/share/ZClassicTest`) — never the
real wallet profile or `~/.zclassic`. The suite cleans up after itself.

## Windows headless widget tests with Qt 5.15.2

The full `widget/tst_widget.pro` suite uses real wallet widgets. For static Qt,
link the offscreen plugin with `QTPLUGIN+=qoffscreen`, then run with
`QT_QPA_PLATFORM=offscreen` and `QT_QPA_FONTDIR=C:/Windows/Fonts`.

Stock Qt 5.15.2 on Windows dereferences a null native platform interface in
`qt_getWindowsSystemMenu()` when an offscreen `QMessageBox` opens. This is a
headless Qt platform defect, not evidence that the native Windows wallet crashes.
For this specific test environment, apply
[`qt-5.15.2-windows-offscreen.patch`](qt-5.15.2-windows-offscreen.patch) to a
dedicated Qt source/build tree and relink the test executable against its Widgets
library. The patch returns no native system menu when no native interface exists;
it leaves the message box and its confirmation buttons in place.

Keep this test dependency separate from production Qt. Record the patch and Qt
version with the results; do not describe a patched headless run as a native
Windows desktop smoke test. The isolated patched-library run on Windows passed
62 widget cases, with no failures and the existing warm-latency case deferred.

### Windows: build the patched QtWidgets and run everything

`run-windows.sh` builds the five test projects (`tests.pro`, `names.pro`,
`tokens.pro`, `tokenssend.pro`, `widget/tst_widget.pro`), runs `tst_widget` one
function per process and the other four binaries once each, and prints one
summary line per binary. It exits non-zero on any failure or crash. Git Bash,
Qt 5.15.2 MinGW kit, matching MinGW and a Windows `libsodium.a` are needed:

```sh
sh wallet/tests/run-windows.sh C:/Qt/5.15.2/mingw81_64 C:/Qt/Tools/mingw810_64 \
   C:/path/to/libsodium.a [PATCHED_QT_DIR]
```

Everything runs with `QT_QPA_PLATFORM=offscreen` and `APPDATA`, `LOCALAPPDATA`,
`USERPROFILE` redirected into the work dir (`OUT`, default
`wallet/tests/build-windows` (created by the run), git-ignored); no window opens, the kit is only <!-- doc-path-ok -->
read, and `JOBS` (default 8) limits build parallelism.

Without `PATCHED_QT_DIR` the 15 functions listed in `KNOWN_CRASH` (inside the
script) crash in `QMessageBox` on stock Qt and are reported as `known-crash`;
they are tolerated only in this mode, and any other failure or crash still fails
the run. These 15 include custody-relevant send-safety checks (auto-shield race
aborts, de-shield acknowledgement), so a stock run is not a complete result. With
`PATCHED_QT_DIR` the list is ignored and all 89 functions must pass.

To build the patched `Qt5Widgets.dll` without building Qt (about 2 minutes at
`-j8`, under 1 GB), build only the Widgets module out-of-tree against the
installed kit. `QT_SRC` is the Qt 5.15.2 source tree (`C:/Qt/5.15.2/Src`) and
`W` an empty scratch directory. The kit is never written to; do not run
`make install`.

```sh
export PATH="/c/Qt/5.15.2/mingw81_64/bin:/c/Qt/Tools/mingw810_64/bin:/usr/bin:$PATH"
W=/c/scratch/qtpatch; QT_SRC=/c/Qt/5.15.2/Src/qtbase
mkdir -p $W/qtbase/src/gui/kernel $W/qtbase/src/corelib/global $W/build/qtbase/src/widgets
cp $QT_SRC/.qmake.conf $W/qtbase/
cp -r $QT_SRC/src/widgets $W/qtbase/src/
cp $QT_SRC/src/gui/kernel/qt_gui_pch.h $W/qtbase/src/gui/kernel/
cp $QT_SRC/src/corelib/global/qt_pch.h $W/qtbase/src/corelib/global/
(cd $W/qtbase/src/widgets && patch -p3 < /path/to/wallet/tests/qt-5.15.2-windows-offscreen.patch)
cd $W/build/qtbase/src/widgets
# The feature lists a Qt build would generate come from the kit's own module files.
M=/c/Qt/5.15.2/mingw81_64/mkspecs/modules
{ grep -E '^QT\.widgets\.(enabled|disabled)_features' $M/qt_lib_widgets.pri
  grep -E '^QT\.widgets_private\.(enabled|disabled)_features' $M/qt_lib_widgets_private.pri
} > qtwidgets-config.pri
K=C:/Qt/5.15.2/mingw81_64/include
qmake $W/qtbase/src/widgets/widgets.pro CONFIG+=release CMAKE_MODULE_TESTS=- \
  "INCLUDEPATH+=$K/QtWidgets $K/QtWidgets/5.15.2 $K/QtWidgets/5.15.2/QtWidgets"
mingw32-make -f Makefile.Release -j8
# result: $W/build/qtbase/bin/Qt5Widgets.dll  -> PATCHED_QT_DIR=$W/build/qtbase/bin
```

Notes: the build directory must mirror the source layout (`build/qtbase/src/widgets`)
or qmake resolves its output paths to the drive root; `CMAKE_MODULE_TESTS=-` skips
the CMake-test check that applies only to Qt's own tree; the kit's headers (public
and private) supply everything the module includes. `tst_widget` still links the
kit's import library, so the patched DLL is a drop-in replacement chosen at run
time (the script puts it first in the runtime directory).

Expected result with the patched DLL: `tst_widget: functions=89 pass=89`, and
`tst_logic` 176 passed, `tst_names` 34, `tst_tokens` 13, `tst_tokenssend` 58, all
0 failed. `perf22_warmLatency` reports a SKIP from the test itself (it is
deferred in the source) and counts as a pass here. Record the patch and Qt
version with the results; a patched headless run is not a native desktop smoke
test.
