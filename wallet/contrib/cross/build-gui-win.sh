#!/bin/bash
# Cross-build the ZClassic GUI (zclwallet.exe) for Windows using the cross-Qt5 we just
# built (/home/rhett/qt-win-static) + the apt x86_64-w64-mingw32 toolchain + the mingw
# libsodium from the daemon depends. Static Qt -> the .exe needs no Qt DLLs.
set -euo pipefail
GUI="${GUI:-$(cd "$(dirname "$0")/../.." && pwd)}"
QT="${QT:?Set QT to the static Windows Qt prefix (including QtSvg)}"
DEPENDS="${DEPENDS:?Set DEPENDS to the daemon depends/x86_64-w64-mingw32 directory}"
cd "$GUI"

# Clean BEFORE staging: distclean removes res/libsodium.a via QMAKE_CLEAN.
echo "[clean] drop any prior Linux qmake state"
make distclean >/dev/null 2>&1 || true
rm -f Makefile .qmake.stash

# The win32-g++ .pro links `-llibsodium` and PRE_TARGETDEPS res/liblibsodium.a.
echo "[stage] mingw libsodium -> res/liblibsodium.a (+ res/libsodium.a for the extra-target)"
cp -f "$DEPENDS/lib/libsodium.a" res/liblibsodium.a
cp -f "$DEPENDS/lib/libsodium.a" res/libsodium.a      # satisfy QMAKE_EXTRA_TARGETS so buildlibsodium.sh (Linux) never runs

echo "[qmake] cross win32-g++ (release, static Qt)"
"$QT/bin/qmake" zcl-qt-wallet.pro -spec win32-g++ CONFIG+=release CONFIG+=zqw_portable \
  "QMAKE_CC=x86_64-w64-mingw32-gcc" \
  "QMAKE_CXX=x86_64-w64-mingw32-g++" \
  "QMAKE_LINK=x86_64-w64-mingw32-g++" \
  "QMAKE_LINK_C=x86_64-w64-mingw32-gcc" \
  "QMAKE_AR=x86_64-w64-mingw32-ar cqs" \
  "QMAKE_RC=x86_64-w64-mingw32-windres" \
  "QMAKE_OBJCOPY=x86_64-w64-mingw32-objcopy" \
  "QMAKE_STRIP=x86_64-w64-mingw32-strip" \
  "INCLUDEPATH+=$DEPENDS/include" \
  "LIBS+=-L$DEPENDS/lib"

echo "[make]"
make -j"${JOBS:-$(nproc)}"

echo "[result]"
sh contrib/cross/check-win-deps.sh release/zclwallet.exe
echo "GUI_WIN_DONE"
