#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
# The native daemon build tree (static-library and exact-build audit) is optional:
# a CI job that only downloads the daemon artifact has no build tree. Without it
# the daemon is still pinned by ZCL_DAEMON_SHA256 and the artifact's SOURCE_COMMIT,
# and every bundled Mach-O file is audited below; the archive audit is skipped
# and recorded as skipped in the validation output.
audit=0
if [ -n "${ZCL_DAEMON_BUILD_DIR:-}${ZCL_DAEMON_DEPENDS_PREFIX:-}" ]; then
    : "${ZCL_DAEMON_BUILD_DIR:?Set both ZCL_DAEMON_BUILD_DIR and ZCL_DAEMON_DEPENDS_PREFIX, or neither}"
    : "${ZCL_DAEMON_DEPENDS_PREFIX:?Set both ZCL_DAEMON_BUILD_DIR and ZCL_DAEMON_DEPENDS_PREFIX, or neither}"
    case "$ZCL_DAEMON_BUILD_DIR:$ZCL_DAEMON_DEPENDS_PREFIX" in
        /*:/*) ;;
        *) echo 'Daemon build and depends paths must be absolute.' >&2; exit 1 ;;
    esac
    test -f "$ZCL_DAEMON_BUILD_DIR/src/libbitcoin_server.a"
    audit=1
fi
qt=${ZCL_QT_PREFIX:-$(brew --prefix qt@5)}
cd "$root"
work=${ZCL_MAC_BUILD_DIR:-"$root/artifacts/mac-build"}
mkdir -p "$work" artifacts/release
# A newer host's Homebrew archive can require a newer macOS than Qt/the node.
# Allow the pinned daemon-depends archive built for the intended deployment OS.
install -m 644 "${ZCL_SODIUM_STATIC:-$(brew --prefix libsodium)/lib/libsodium.a}" res/libsodium.a
shasum -a 256 res/libsodium.a > artifacts/release/macos-libsodium-SHA256SUMS.txt
cd "$work"
static_qt=0
if grep -Eq '^QT_CONFIG[[:space:]]*[+]?=.*[[:space:]]static([[:space:]]|$)' "$qt/mkspecs/qconfig.pri"; then
    static_qt=1
    "$qt/bin/qmake" "$root/zcl-qt-wallet.pro" CONFIG+=release 'QTPLUGIN.platforms=qcocoa qoffscreen'
else
    "$qt/bin/qmake" "$root/zcl-qt-wallet.pro" CONFIG+=release
fi
make -j2
: "${ZCL_DAEMON:?Supply the newly built daemon path}"
: "${ZCL_DAEMON_SHA256:?Supply the verified daemon SHA256}"
printf '%s  %s\n' "$ZCL_DAEMON_SHA256" "$ZCL_DAEMON" | shasum -a 256 -c -
if [ "$audit" = 1 ]; then
    # build-release.sh ships a stripped copy of src/zclassicd; accept either form.
    stripped="$work/zclassicd.stripped"
    strip -o "$stripped" "$ZCL_DAEMON_BUILD_DIR/src/zclassicd"
    cmp -s "$ZCL_DAEMON" "$ZCL_DAEMON_BUILD_DIR/src/zclassicd" || cmp -s "$ZCL_DAEMON" "$stripped" || {
        echo 'The packaged daemon must match the audited native build exactly (stripped or not).' >&2
        exit 1
    }
fi
"$ZCL_DAEMON" --version | grep -F '2.1.2-beta13'
cp "$ZCL_DAEMON" zclwallet.app/Contents/MacOS/zclassicd
if [ "$static_qt" = 0 ]; then
    "$qt/bin/macdeployqt" zclwallet.app -verbose=2
fi
# Qt 5's deployment tool misses Brotli's @rpath-only transitive dependency.
# Newer Homebrew FreeType pulls in libbrotlidec, which needs this sibling.
if [ -f zclwallet.app/Contents/Frameworks/libbrotlidec.1.dylib ]; then
    cp "$(brew --prefix brotli)/lib/libbrotlicommon.1.dylib" zclwallet.app/Contents/Frameworks/
fi
if [ -f zclwallet.app/Contents/Frameworks/libwebp.7.dylib ]; then
    cp "$(brew --prefix webp)/lib/libsharpyuv.0.dylib" zclwallet.app/Contents/Frameworks/
fi
otool -l "$root/res/libsodium.a" > minimum-os.txt
# A final executable can report an older floor than its static inputs. Audit the
# complete native dependency prefix and local archives, including proof code.
if [ "$audit" = 1 ]; then
find -L "$ZCL_DAEMON_BUILD_DIR/src" "$ZCL_DAEMON_DEPENDS_PREFIX/lib" \
    -type f -name '*.a' -print > daemon-archives.txt
test -s daemon-archives.txt
: > "$root/artifacts/release/macos-daemon-archives-SHA256SUMS.txt"
while IFS= read -r archive; do
    shasum -a 256 "$archive" >> "$root/artifacts/release/macos-daemon-archives-SHA256SUMS.txt"
    otool -l "$archive" >> minimum-os.txt
done < daemon-archives.txt
else
    : > "$root/artifacts/release/macos-daemon-archives-SHA256SUMS.txt"
    echo 'daemon static-archive audit skipped: no ZCL_DAEMON_BUILD_DIR (daemon pinned by SHA256 only)' >> "$root/artifacts/release/macos-validation.txt"
fi
if [ "$static_qt" = 1 ]; then
    # A static archive can require a newer OS without raising the executable's
    # load-command minimum. Include toolchain objects in the compatibility gate.
    find -L "$qt/lib" "$qt/plugins" -type f -name '*.a' -exec otool -l {} + >> minimum-os.txt
fi
# Check every Mach-O, including the daemon, Qt frameworks and platform plugins.
# --version alone could silently resolve a library installed on the build host.
# Public application files must not inherit a maintainer's private build umask.
find zclwallet.app -type d -exec chmod 755 {} +
find zclwallet.app -type f -exec chmod 644 {} +
find zclwallet.app -type f -exec sh -c '
    set -eu
    for binary do
        if file "$binary" | grep -q "Mach-O"; then
            chmod 755 "$binary"
            lipo "$binary" -verify_arch arm64
            own_id=$(otool -D "$binary" | sed -n "2p")
            dependencies=$(otool -L "$binary" | awk -v own="$own_id" '\''NR > 1 && $1 != own { print }'\'') || exit 1
            printf "%s\n" "$dependencies"
            if printf "%s\n" "$dependencies" | grep -E "/opt/homebrew|/usr/local"; then
                echo "Unbundled developer-machine dependency: $binary" >&2
                exit 1
            fi
            printf "%s\n" "$dependencies" | awk '\''{print $1}'\'' | while IFS= read -r dependency; do
                case "$dependency" in
                    @rpath/*) resolved="zclwallet.app/Contents/Frameworks/${dependency#@rpath/}" ;;
                    @executable_path/*) resolved="zclwallet.app/Contents/MacOS/${dependency#@executable_path/}" ;;
                    @loader_path/*) resolved="$(dirname "$binary")/${dependency#@loader_path/}" ;;
                    /System/Library/*|/usr/lib/*|"") continue ;;
                    *) echo "Unexpected dependency: $dependency" >&2; exit 1 ;;
                esac
                [ -e "$resolved" ] || { echo "Missing bundled dependency: $dependency ($binary)" >&2; exit 1; }
            done || exit 1
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
# Preserve the published macOS 15 support floor instead of silently raising it
# when Homebrew or an SDK changes on the build machine.
if ! awk -v version="$minimum" 'BEGIN { split(version, p, "."); exit (p[1]*1000000+p[2]*1000+p[3] > 15000000) }'; then
    echo "Dependencies require macOS $minimum; this release must support macOS 15. Use the pinned static toolchain." >&2
    exit 1
fi
/usr/libexec/PlistBuddy -c "Set :LSMinimumSystemVersion $minimum" zclwallet.app/Contents/Info.plist
printf 'Minimum macOS version: %s\n' "$minimum" >> "$root/artifacts/release/macos-validation.txt"
(
    umask 022
    codesign --force --timestamp=none --sign - zclwallet.app/Contents/MacOS/zclassicd
    codesign --force --deep --timestamp=none --sign - zclwallet.app
)
codesign --verify --deep --strict --verbose=2 zclwallet.app
private_dirs=$(find zclwallet.app -type d ! -perm -0555 -print)
private_files=$(find zclwallet.app -type f ! -perm -0444 -print)
[ -z "$private_dirs$private_files" ] || {
    echo 'Application bundle contains files or directories inaccessible to other users.' >&2
    exit 1
}
for binary in zclwallet.app/Contents/MacOS/zclwallet zclwallet.app/Contents/MacOS/zclassicd; do
    [ "$(stat -f '%Lp' "$binary")" = 755 ] || {
        echo "Application executable must have mode 755: $binary" >&2
        exit 1
    }
done
printf 'PASS: public application file modes, including executable mode 755\n' >> "$root/artifacts/release/macos-validation.txt"
QT_DEBUG_PLUGINS=1 QT_QPA_PLATFORM=cocoa zclwallet.app/Contents/MacOS/zclwallet --help > "$root/artifacts/release/macos-help.txt"
zclwallet.app/Contents/MacOS/zclassicd --version >> "$root/artifacts/release/macos-validation.txt"
# Use the same Qt TLS implementation as the wallet, retaining certificate and
# hostname validation for the canonical update endpoint.
mkdir -p tls-check
(
    cd tls-check
    "$qt/bin/qmake" "$root/tests/check-tls.pro" CONFIG+=release
    make -j2
    ./check-tls
) >> "$root/artifacts/release/macos-validation.txt" 2>&1
mkdir dmg-root
chmod 755 dmg-root
mv zclwallet.app dmg-root/ZclWallet.app
ln -s /Applications dmg-root/Applications
output="$root/artifacts/release/zclwallet-v2.1.2-beta11-macos-arm64.dmg"
[ ! -e "$output" ]
hdiutil create -volname ZClassic-beta11 -srcfolder dmg-root -format UDZO "$output"
hdiutil verify "$output"
chmod 644 "$output"
cd "$root/artifacts/release"
shasum -a 256 zclwallet-v2.1.2-beta11-macos-arm64.dmg > macos-SHA256SUMS.txt
