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
"$qt/bin/macdeployqt" zclwallet.app -verbose=2
otool -l "$root/res/libsodium.a" > minimum-os.txt
# Check every Mach-O, including the daemon, Qt frameworks and platform plugins.
# --version alone could silently resolve a library installed on the build host.
find zclwallet.app -type f -exec sh -c '
    for binary do
        if file "$binary" | grep -q "Mach-O"; then
            own_id=$(otool -D "$binary" | sed -n "2p")
            dependencies=$(otool -L "$binary" | awk -v own="$own_id" '\''NR > 1 && $1 != own { print }'\'') || exit 1
            printf "%s\n" "$dependencies"
            if printf "%s\n" "$dependencies" | grep -E "/opt/homebrew|/usr/local"; then
                echo "Unbundled developer-machine dependency: $binary" >&2
                exit 1
            fi
            otool -l "$binary" >> minimum-os.txt
        fi
    done
' sh {} + >> "$root/artifacts/release/macos-validation.txt"
# Include static sodium object deployment versions as well as final Mach-O files.
# Linkers can warn about newer objects yet retain the GUI's older minimum.
minimum=$(awk '
    /cmd LC_BUILD_VERSION/ { modern=1 }
    modern && $1 == "minos" { version=$2; modern=0 }
    /cmd LC_VERSION_MIN_MACOSX/ { legacy=1 }
    legacy && $1 == "version" { version=$2; legacy=0 }
    version != "" {
        split(version, part, "."); value=part[1]*1000000+part[2]*1000+part[3]
        if (value > largest) { largest=value; highest=version }
        version=""
    }
    END { print highest }
' minimum-os.txt)
[ -n "$minimum" ]
/usr/libexec/PlistBuddy -c "Set :LSMinimumSystemVersion $minimum" zclwallet.app/Contents/Info.plist
printf 'Minimum macOS version: %s\n' "$minimum" >> "$root/artifacts/release/macos-validation.txt"
codesign --force --timestamp=none --sign - zclwallet.app/Contents/MacOS/zclassicd
codesign --force --deep --timestamp=none --sign - zclwallet.app
codesign --verify --deep --strict --verbose=2 zclwallet.app
QT_DEBUG_PLUGINS=1 QT_QPA_PLATFORM=cocoa zclwallet.app/Contents/MacOS/zclwallet --help > "$root/artifacts/release/macos-help.txt"
zclwallet.app/Contents/MacOS/zclassicd --version >> "$root/artifacts/release/macos-validation.txt"
mkdir dmg-root
mv zclwallet.app dmg-root/ZclWallet.app
ln -s /Applications dmg-root/Applications
output="$root/artifacts/release/zclwallet-v2.1.2-beta7-macos-arm64.dmg"
[ ! -e "$output" ]
hdiutil create -volname ZClassic-beta7 -srcfolder dmg-root -format UDZO "$output"
hdiutil verify "$output"
cd "$root/artifacts/release"
shasum -a 256 zclwallet-v2.1.2-beta7-macos-arm64.dmg > macos-SHA256SUMS.txt
