#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
qt=$(brew --prefix qt@5)
cd "$root"
mkdir -p artifacts/mac-build artifacts/release
cp "$(brew --prefix libsodium)/lib/libsodium.a" res/libsodium.a
cd artifacts/mac-build
"$qt/bin/qmake" "$root/zcl-qt-wallet.pro" CONFIG+=release
make -j2
curl --fail --location --retry 3 https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta6/zclassicd-v2.1.2-beta6-macos-arm64.tar.gz -o daemon.tar.gz
printf '%s  daemon.tar.gz\n' 4f2344da82a57b404a1eb5e5497c00ffc635ec4792f8f9e4ab9457e970d5a12a | shasum -a 256 -c -
tar -xf daemon.tar.gz
cp zclassic-2.1.2-beta6-osx-arm64/zclassicd zclwallet.app/Contents/MacOS/
"$qt/bin/macdeployqt" zclwallet.app
codesign --force --timestamp=none --sign - zclwallet.app/Contents/MacOS/zclassicd
codesign --force --deep --timestamp=none --sign - zclwallet.app
codesign --verify --deep --strict --verbose=2 zclwallet.app
QT_QPA_PLATFORM=offscreen zclwallet.app/Contents/MacOS/zclwallet --help > "$root/artifacts/release/macos-help.txt"
zclwallet.app/Contents/MacOS/zclassicd --version > "$root/artifacts/release/macos-validation.txt"
otool -L zclwallet.app/Contents/MacOS/zclwallet >> "$root/artifacts/release/macos-validation.txt"
if otool -L zclwallet.app/Contents/MacOS/zclwallet | grep -E '/opt/homebrew|/usr/local'; then
    echo 'Unbundled developer-machine library dependency' >&2
    exit 1
fi
mkdir dmg-root
mv zclwallet.app dmg-root/ZclWallet.app
ln -s /Applications dmg-root/Applications
output="$root/artifacts/release/zclwallet-v2.1.2-beta7-macos-arm64.dmg"
[ ! -e "$output" ]
hdiutil create -volname ZClassic-beta7 -srcfolder dmg-root -format UDZO "$output"
hdiutil verify "$output"
cd "$root/artifacts/release"
shasum -a 256 zclwallet-v2.1.2-beta7-macos-arm64.dmg > macos-SHA256SUMS.txt
