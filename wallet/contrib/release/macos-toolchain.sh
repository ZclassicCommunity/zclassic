#!/bin/sh
# Run through devbuild --wait on a shared maintainer host.
set -eu
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || {
    echo 'This toolchain recipe requires a native Apple Silicon Mac.' >&2
    exit 1
}
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
work=${ZCL_MAC_TOOLCHAIN_DIR:-"$root/artifacts/mac-toolchain-5.15.19"}
case "$work" in /*) ;; *) echo 'ZCL_MAC_TOOLCHAIN_DIR must be absolute.' >&2; exit 1 ;; esac
# Qt 5 still references a capture API obsoleted for deployment targets >=15.
# Follow the Qt 5 MacPorts recipe's 14.0 toolkit target; the bundled node remains
# targeted at 15 and packaging independently enforces the complete app's floor.
# https://github.com/macports/macports-ports/blob/master/aqua/qt5/Portfile
export MACOSX_DEPLOYMENT_TARGET=14.0
# Keep Homebrew's optional libraries out of Qt's feature detection.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
mkdir -p "$work"
cd "$work"
fetch() {
    if [ -f "$2" ] && printf '%s  %s\n' "$3" "$2" | shasum -a 256 -c -; then
        return
    fi
    curl --fail --location --proto '=https' --retry 3 --connect-timeout 20 --max-time 900 "$1" -o "$2.part"
    printf '%s  %s\n' "$3" "$2.part" | shasum -a 256 -c -
    mv "$2.part" "$2"
}
fetch https://download.qt.io/archive/qt/5.15/5.15.19/submodules/qtbase-everywhere-opensource-src-5.15.19.tar.xz qtbase.tar.xz 51e91c73abacab81e64efd01bf95794e79c0e605ad80947a024769f0dd620a32
fetch https://download.qt.io/archive/qt/5.15/5.15.19/submodules/qtsvg-everywhere-opensource-src-5.15.19.tar.xz qtsvg.tar.xz cabc95fc12fa84c92e95f08660742a0ce297e6db3deadbefbe7fbec4769b8c13
if [ ! -d qtbase-everywhere-src-5.15.19 ]; then tar -xf qtbase.tar.xz; fi
if [ ! -d qtsvg-everywhere-src-5.15.19 ]; then tar -xf qtsvg.tar.xz; fi
prefix="$work/qt-static"
mkdir -p qt-build svg-build
cd qt-build
if [ ! -f Makefile ]; then
    ../qtbase-everywhere-src-5.15.19/configure -opensource -confirm-license -release -static \
        -prefix "$prefix" -nomake examples -nomake tests -no-opengl -no-openssl -securetransport \
        -no-dbus -no-glib -no-icu -no-cups -qt-zlib -qt-libpng -qt-libjpeg -qt-freetype \
        -qt-pcre -qt-harfbuzz -device-option QMAKE_MACOSX_DEPLOYMENT_TARGET=14.0
fi
make -j4
make install
cd "$work/svg-build"
"$prefix/bin/qmake" ../qtsvg-everywhere-src-5.15.19/qtsvg.pro
make -j4
make install
"$prefix/bin/qmake" -query
printf 'Static Qt prefix: %s\n' "$prefix"
