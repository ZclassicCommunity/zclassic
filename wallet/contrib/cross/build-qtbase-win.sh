#!/bin/bash
# Cross-build qtbase (Core/Gui/Widgets/Network) STATIC for Windows (x86_64-w64-mingw32)
# using the system apt mingw (gcc-13) -- the SAME toolchain that built zclassicd.exe, so
# the GUI .exe and daemon are ABI-consistent. No sudo, no MXE gcc rebuild. Qt's bundled
# zlib/pcre/libpng/freetype/harfbuzz are used; no OpenSSL/GL/DBus/ICU (the wallet talks
# plain HTTP to the local RPC; HTTPS price/update are best-effort and already silenced).
set -euo pipefail
SRC="${SRC:?Set SRC to the Qt 5.15 qtbase source archive}"
WORK="${WORK:?Set WORK to a dedicated Qt build directory}"
PREFIX="${PREFIX:?Set PREFIX to the static Windows Qt install directory}"
mkdir -p "$WORK"; cd "$WORK"
DIR="${DIR:-qtbase-everywhere-src-5.15.19}"
[ -d "$DIR" ] || { echo "[extract] $SRC"; tar xf "$SRC"; }
cd "$DIR"

if [ ! -f Makefile ]; then
  echo "[configure] cross win32-g++ static -> $PREFIX"
  ./configure \
    -opensource -confirm-license \
    -release -static \
    -xplatform win32-g++ \
    -device-option CROSS_COMPILE=x86_64-w64-mingw32- \
    -prefix "$PREFIX" \
    -qt-zlib -qt-libpng -qt-libjpeg -qt-freetype -qt-pcre -qt-harfbuzz \
    -no-opengl -no-openssl -no-dbus -no-icu \
    -nomake examples -nomake tests
fi

echo "[make] qtbase (this is the long part)"
make -j"${JOBS:-$(nproc)}"
echo "[make install] -> $PREFIX"
make install
echo "QTBASE_WIN_DONE prefix=$PREFIX qmake=$PREFIX/bin/qmake"
ls -la "$PREFIX/bin/qmake" 2>/dev/null || echo "WARN: qmake not at expected path"
