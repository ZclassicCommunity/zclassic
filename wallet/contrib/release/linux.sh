#!/bin/sh
# Run in Ubuntu 20.04: do not raise the released glibc floor accidentally.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
mkdir -p artifacts/linux-build artifacts/release
work="$root/artifacts/linux-build"
prefix="$work/qt-static"
cd "$work"
fetch() {
    curl --fail --location --retry 3 "$1" -o "$2"
    printf '%s  %s\n' "$3" "$2" | sha256sum -c -
}
if [ ! -x "$prefix/bin/qmake" ]; then
fetch https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz openssl.tar.gz 603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
tar -xf openssl.tar.gz
cd openssl-3.5.9
./Configure linux-x86_64 no-shared no-tests no-module no-legacy --prefix="$work/openssl" --libdir=lib -fPIC
make -j4
make install_sw
cd "$work"
fetch https://download.qt.io/archive/qt/5.15/5.15.19/submodules/qtbase-everywhere-opensource-src-5.15.19.tar.xz qtbase.tar.xz 51e91c73abacab81e64efd01bf95794e79c0e605ad80947a024769f0dd620a32
fetch https://download.qt.io/archive/qt/5.15/5.15.19/submodules/qtsvg-everywhere-opensource-src-5.15.19.tar.xz qtsvg.tar.xz cabc95fc12fa84c92e95f08660742a0ce297e6db3deadbefbe7fbec4769b8c13
tar -xf qtbase.tar.xz
tar -xf qtsvg.tar.xz
mkdir qt-build
cd qt-build
if ! OPENSSL_LIBS="-L$work/openssl/lib -lssl -lcrypto -ldl -pthread" ../qtbase-everywhere-src-5.15.19/configure -opensource -confirm-license -release -static -prefix "$prefix" -nomake examples -nomake tests -no-opengl -openssl-linked -I "$work/openssl/include" -L "$work/openssl/lib" -no-dbus -no-icu -qt-zlib -qt-libpng -qt-libjpeg -qt-freetype -qt-pcre -qt-harfbuzz -xcb; then
    cat config.log
    exit 1
fi
make -j4
make install
cd "$work"
mkdir svg-build
cd svg-build
"$prefix/bin/qmake" ../qtsvg-everywhere-src-5.15.19/qtsvg.pro
make -j4
make install
fi
if [ "${BUILD_TOOLCHAIN_ONLY:-0}" = 1 ]; then exit 0; fi
cp /usr/lib/x86_64-linux-gnu/libsodium.a "$root/res/libsodium.a"
cd "$work"
mkdir gui
cd gui
"$prefix/bin/qmake" "$root/zcl-qt-wallet.pro" CONFIG+=release 'QTPLUGIN.platforms=qxcb qoffscreen' 'QMAKE_LFLAGS+=-static-libgcc -static-libstdc++'
make -j4
strip zclwallet
cd "$work"
fetch https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta6/zclassicd-v2.1.2-beta6-linux-x86_64.tar.gz daemon.tar.gz 1e67a34a79ff8dea6f5c739484f540ceb6d598ace214c1ab68c0d923c56b3dce
tar -xf daemon.tar.gz
daemon="$work/zclassic-2.1.2-beta6-linux-x86_64/zclassicd"
# Check both executable compatibility floors and document runtime libraries.
for binary in "$work/gui/zclwallet" "$daemon"; do
    readelf -h "$binary" >/dev/null
    highest=$(objdump -T "$binary" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -1)
    [ -n "$highest" ]
    [ "$(printf '%s\nGLIBC_2.31\n' "$highest" | sort -V | tail -1)" = GLIBC_2.31 ]
    ldd "$binary" > "$work/dependencies.txt"
    if grep -E 'not found|libQt|libgomp' "$work/dependencies.txt"; then exit 1; fi
    # The unchanged beta6 node uses the standard system C++ runtime. Bound its
    # required symbol version to Ubuntu 20.04's runtime rather than rejecting it.
    cxx=$(objdump -T "$binary" | grep -oE 'GLIBCXX_[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1)
    if [ -n "$cxx" ]; then
        [ "$(printf '%s\nGLIBCXX_3.4.28\n' "$cxx" | sort -V | tail -1)" = GLIBCXX_3.4.28 ]
    fi
    printf '\n%s: %s\n' "$binary" "$highest" >> "$root/artifacts/release/linux-validation.txt"
    cat "$work/dependencies.txt" >> "$root/artifacts/release/linux-validation.txt"
done
output="$root/artifacts/release/zclwallet-v2.1.2-beta8-linux-x86_64"
[ ! -e "$output" ]
size=$(wc -c < "$daemon" | tr -d '[:space:]')
[ "$size" -gt 0 ] && [ "$size" -le 536870912 ]
cat "$work/gui/zclwallet" "$daemon" > "$output.part"
openssl dgst -sha256 -binary "$daemon" >> "$output.part"
remaining=$size
i=0
while [ "$i" -lt 8 ]; do
    octal=$(printf '%03o' "$((remaining % 256))")
    printf "\\$octal" >> "$output.part"
    remaining=$((remaining / 256))
    i=$((i + 1))
done
printf ZQWDMON1 >> "$output.part"
chmod 755 "$output.part"
mv "$output.part" "$output"
# --help does not start the node or access a canonical datadir.
QT_QPA_PLATFORM=offscreen "$output" --help > "$root/artifacts/release/linux-help.txt"
"$daemon" --version >> "$root/artifacts/release/linux-validation.txt"
mkdir "$work/extraction-check"
cd "$work/extraction-check"
"$prefix/bin/qmake" "$root/tests/check-embedded.pro"
make -j4
./check-embedded "$output" "$daemon" >> "$root/artifacts/release/linux-validation.txt"
mkdir "$work/tls-check"
cd "$work/tls-check"
"$prefix/bin/qmake" "$root/tests/check-tls.pro"
make -j4
./check-tls >> "$root/artifacts/release/linux-validation.txt"
cd "$root/artifacts/release"
sha256sum zclwallet-v2.1.2-beta8-linux-x86_64 > linux-SHA256SUMS.txt
