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
fetch https://download.qt.io/archive/qt/5.15/5.15.2/submodules/qtbase-everywhere-src-5.15.2.tar.xz qtbase.tar.xz 909fad2591ee367993a75d7e2ea50ad4db332f05e1c38dd7a5a274e156a4e0f8
fetch https://download.qt.io/archive/qt/5.15/5.15.2/submodules/qtsvg-everywhere-src-5.15.2.tar.xz qtsvg.tar.xz 8bc3c2c1bc2671e9c67d4205589a8309b57903721ad14c60ea21a5d06acb585e
tar -xf qtbase.tar.xz
tar -xf qtsvg.tar.xz
mkdir qt-build
cd qt-build
../qtbase-everywhere-src-5.15.2/configure -opensource -confirm-license -release -static -prefix "$prefix" -nomake examples -nomake tests -no-opengl -no-openssl -no-dbus -no-icu -qt-zlib -qt-libpng -qt-libjpeg -qt-freetype -qt-pcre -qt-harfbuzz -xcb
make -j4
make install
cd "$work"
mkdir svg-build
cd svg-build
"$prefix/bin/qmake" ../qtsvg-everywhere-src-5.15.2/qtsvg.pro
make -j4
make install
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
    if grep -E 'not found|libQt|libgomp|libstdc\+\+' "$work/dependencies.txt"; then exit 1; fi
    printf '\n%s: %s\n' "$binary" "$highest" >> "$root/artifacts/release/linux-validation.txt"
    cat "$work/dependencies.txt" >> "$root/artifacts/release/linux-validation.txt"
done
output="$root/artifacts/release/zclwallet-v2.1.2-beta7-linux-x86_64"
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
cd "$root/artifacts/release"
sha256sum zclwallet-v2.1.2-beta7-linux-x86_64 > linux-SHA256SUMS.txt
