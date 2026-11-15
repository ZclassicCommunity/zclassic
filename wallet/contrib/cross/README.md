# Windows portable builds

The beta6 GUI imported `libgcc_s_seh-1.dll`, `libstdc++-6.dll` and
`libwinpthread-1.dll`: static Qt alone did not make it standalone. The portable
qmake configuration now adds `-static -static-libgcc -static-libstdc++`, and the
build fails if the executable still imports a non-system DLL.

Use the MinGW POSIX toolchain and static Qt 5.15 **including QtSvg**. All paths
are configurable; no `/home/rhett` directory is required. Use absolute paths.

```sh
# Optional: build qtbase (also build QtSvg with this Qt's qmake).
SRC=/sources/qtbase-everywhere-opensource-src-5.15.19.tar.xz \
WORK=/build/qt-win PREFIX=/opt/qt-win-static \
bash contrib/cross/build-qtbase-win.sh

QT=/opt/qt-win-static DEPENDS=/src/zclassic/depends/x86_64-w64-mingw32 \
JOBS=8 bash contrib/cross/build-gui-win.sh

# Use an already reviewed, stripped daemon.
mkdir -p artifacts
sh contrib/cross/package-win.sh release/zclwallet.exe \
  /src/zclassic/release/x86_64-w64-mingw32/zclassicd.exe \
  artifacts/zclwallet-win64.exe
```

Packaging requires binutils, OpenSSL's CLI, and standard POSIX utilities.
It checks **both** binaries, refuses an existing output or an already bundled
GUI, streams the existing ZQWDMON1 footer format, and prints the SHA-256.
Strip before packaging; do not strip or sign the resulting bundle without
rechecking the footer expected by the loader.

`OBJDUMP` overrides the default `x86_64-w64-mingw32-objdump`. The system-DLL
allowlist deliberately fails closed: investigate any new dependency before
changing it. UCRT builds require a Windows installation providing UCRT.

```sh
sh tests/windows-packaging.sh
# Native MSYS2 UCRT64 shell:
CC=gcc OBJDUMP=objdump sh tests/windows-packaging.sh
```

The fixture tests require GCC 14+ for C23 (separate from the wallet's C++14
compiler; Qt's MinGW 8.1 can build the wallet but not these C23 fixtures).
The tests build real static and dynamic MinGW fixtures, reject missing/non-PE
inputs and DLL dependencies in either component, and verify the packaged GUI,
daemon, length, hash and magic. They do not start a node or access wallet data.
Before publishing, build the actual wallet and smoke-test on clean Windows
without MinGW or Qt on PATH, using an isolated test account/datadir. Import
inspection does not verify GUI startup or runtime-loaded plugins.

## Native Windows validation

The native candidate was built with Qt 5.15.2 (qtbase + qtsvg), MinGW 8.1
64-bit, and static libsodium 1.0.20. Configure qtbase with `-static
-static-runtime -release -no-opengl -no-openssl -no-dbus -no-icu -nomake
examples -nomake tests`, build/install with `mingw32-make`, then build/install
qtsvg with that static Qt's qmake. Keep Windows PowerShell on PATH for Qt's
MIME-database generator. Stage the matching MinGW sodium archive as described
above, then build the wallet in a separate directory:

```powershell
& C:/path/to/static-qt/bin/qmake.exe C:/src/zcl-qt-wallet/zcl-qt-wallet.pro CONFIG+=release CONFIG+=zqw_portable
mingw32-make -j8
```

Do not commit locally rebuilt `res/liblibsodium.a`; it is a build-stage input.
The packager remains usable from an MSYS2 shell with `OBJDUMP=objdump`.

For native Qt tests use the **windows** backend. Qt 5.15.2's offscreen backend
on Windows can crash in QMessageBox's system-menu lookup. The C23 desktop
runner uses a private desktop without switching the user's desktop and limits
each run to 120 seconds. Its job object cleans up timed-out child processes.

```powershell
gcc -std=c23 -Wall -Wextra -Werror -municode -static tests/windows-desktop-runner.c -o artifacts/runner.exe
$env:QT_QPA_PLATFORM = 'windows'
$env:ZCL_SHOTS_DIR = 'C:/src/zcl-qt-wallet/artifacts/test-shots'
& artifacts/runner.exe C:/build/tests/release/tst_logic.exe 'tst_logic.exe -o logic-results.txt,txt'
& artifacts/runner.exe C:/build/widget/release/tst_widget.exe 'tst_widget.exe -o widget-results.txt,txt'
```

Build the two test targets with the same static Qt (`tests/tests.pro` and
`tests/widget/tst_widget.pro`). File privacy assertions inspect Windows DACLs
rather than Qt's approximate Unix permission flags; an intentionally public
fixture proves the check rejects broader access. Tests use isolated paths,
synthetic transactions and local notification sockets, without a live daemon.

The GUI no longer forces `-dbcache=450`: the existing daemon configuration and
64-bit cache defaults apply (1024 MiB normally, 2048 MiB when rebuilding).
This removes unnecessary cache pressure without changing validation. No
end-to-end chain-sync speedup is claimed without a representative measurement.
