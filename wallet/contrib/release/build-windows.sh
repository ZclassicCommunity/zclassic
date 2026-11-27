#!/bin/sh
# Windows release bundle for the Qt wallet (dynamic Qt 5.15 kit, native MinGW).
# Run from Git Bash / MSYS2 on a Windows host; nothing is installed or changed
# outside OUT_DIR and wallet/res/lib*sodium.a (git-ignored).
#
#   sh wallet/contrib/release/build-windows.sh QT_DIR MINGW_DIR LIBSODIUM_A DAEMON_DIR OUT_DIR
#
#   QT_DIR       Qt kit, e.g. C:/Qt/5.15.2/mingw81_64   (qmake.exe, windeployqt.exe)
#   MINGW_DIR    matching MinGW, e.g. C:/Qt/Tools/mingw810_64   (g++, mingw32-make, objdump)
#   LIBSODIUM_A  static libsodium.a built for x86_64-w64-mingw32
#   DAEMON_DIR   reviewed zclassicd.exe, zclassic-cli.exe, zclassic-tx.exe
#   OUT_DIR      must not exist or be empty
#
# Environment: JOBS (default nproc), VERSION (default 2.1.2-beta14), OPENSSL_DIR
# (dir holding libssl-1_1-x64.dll + libcrypto-1_1-x64.dll; default: the Qt
# installer's Tools/OpenSSL/Win_x64/bin), ALLINONE=1 (also build the variant whose
# zclwallet.exe carries the daemon in the ZQWDMON1 footer), SKIP_PROBE=1.
#
# Output: OUT_DIR/zclwallet-v$VERSION-windows-x86_64/ (the bundle), the same as
# .zip, SHA256SUMS.txt (zip hashes; the bundle has its own per-file one), build/.
set -eu

[ "$#" -eq 5 ] || { sed -n '2,22p' "$0" >&2; exit 2; }
QT=$(cygpath -u "$1") MINGW=$(cygpath -u "$2") SODIUM=$(cygpath -u "$3") DAEMONS=$(cygpath -u "$4") OUT=$(cygpath -u "$5")
VERSION=${VERSION:-2.1.2-beta14}
JOBS=${JOBS:-$(nproc)}
NAME=zclwallet-v$VERSION-windows-x86_64
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
wallet=$(CDPATH= cd -- "$here/../.." && pwd)
die() { echo "ERROR: $*" >&2; exit 1; }
win() { cygpath -w "$1"; }

for t in "$QT/bin/qmake.exe" "$QT/bin/windeployqt.exe" "$MINGW/bin/mingw32-make.exe" \
         "$MINGW/bin/objdump.exe" "$SODIUM" \
         "$DAEMONS/zclassicd.exe" "$DAEMONS/zclassic-cli.exe" "$DAEMONS/zclassic-tx.exe"; do
    [ -f "$t" ] || die "missing $t"
done
OPENSSL_DIR=${OPENSSL_DIR:-$QT/../../Tools/OpenSSL/Win_x64/bin}
for t in libssl-1_1-x64.dll libcrypto-1_1-x64.dll; do
    [ -f "$OPENSSL_DIR/$t" ] || die "Qt 5.15 loads OpenSSL 1.1.x at run time (https update check); missing $OPENSSL_DIR/$t"
done
[ -z "$(ls -A "$OUT" 2>/dev/null || true)" ] || die "OUT_DIR is not empty: $OUT"
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
SYS=$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")/System32
# Toolchain first; keep the MSYS utilities (sh, awk, sha256sum...) after it.
PATH="$QT/bin:$MINGW/bin:/usr/bin:$SYS:$SYS/WindowsPowerShell/v1.0:$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")"
export PATH
OBJDUMP="$MINGW/bin/objdump.exe"
TIMEOUT=$(command -v timeout) || die "timeout(1) not found (MSYS coreutils)"
[ "${ALLINONE:-0}" != 1 ] || command -v openssl >/dev/null || die "ALLINONE=1 needs openssl(1) for the footer hash"
SODIUM=$(CDPATH= cd -- "$(dirname -- "$SODIUM")" && pwd)/$(basename -- "$SODIUM")

# One timestamp for everything that would otherwise embed the clock: the About date in the
# exe (via the .pro), and the zip/bundle mtimes. Default: the commit time.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$wallet" log -1 --format=%ct 2>/dev/null || echo 315619200)}
export SOURCE_DATE_EPOCH

echo "== 1. build (release, Qt $(qmake -query QT_VERSION), -j$JOBS)"
# The .pro links res/libsodium.a and depends on res/liblibsodium.a (both git-ignored).
cp "$SODIUM" "$wallet/res/libsodium.a"
cp "$SODIUM" "$wallet/res/liblibsodium.a"
mkdir -p "$OUT/build/gui"
( cd "$OUT/build/gui" && qmake "$(win "$wallet/zcl-qt-wallet.pro")" CONFIG+=release \
    && mingw32-make -j"$JOBS" release ) > "$OUT/build/gui.log" 2>&1 \
    || { tail -30 "$OUT/build/gui.log" >&2; die "GUI build failed (see $OUT/build/gui.log)"; }
exe=$OUT/build/gui/release/zclwallet.exe
[ -f "$exe" ] || die "build produced no zclwallet.exe"

echo "== 2. deploy Qt"
b=$OUT/$NAME
mkdir "$b"
cp "$exe" "$b/"
# windeployqt must be told --debug: the kit's DLLs and plugins keep a
# .gnu_debuglink (separate_debug_info), which windeployqt reads as "debug"; without
# the flag it sees a release exe, skips every plugin and aborts with "Unable to
# find the platform plugin". The files are still the kit's release builds.
# Qt Widgets needs no ANGLE/software GL/D3D compiler, translations or compiler
# runtime from windeployqt (the MinGW runtime is added from the import walk below).
windeployqt --debug --no-translations --no-angle --no-opengl-sw --no-system-d3d-compiler \
    --no-virtualkeyboard --no-compiler-runtime "$(win "$b/zclwallet.exe")" > "$OUT/build/windeployqt.log" 2>&1 \
    || { cat "$OUT/build/windeployqt.log" >&2; die "windeployqt failed"; }
# Qt5Network opens OpenSSL with LoadLibrary at run time, so the import walk cannot see it.
cp "$OPENSSL_DIR/libssl-1_1-x64.dll" "$OPENSSL_DIR/libcrypto-1_1-x64.dll" "$b/"
cp "$DAEMONS/zclassicd.exe" "$DAEMONS/zclassic-cli.exe" "$DAEMONS/zclassic-tx.exe" "$b/"

# Close the import graph: every DLL imported by any PE in the bundle must be a
# Windows system DLL or must sit in the bundle (copied from the kit/MinGW).
imports() { "$OBJDUMP" -p "$1" | awk '/DLL Name:/ {print $3}'; }
is_system() {
    case $(printf %s "$1" | tr 'A-Z' 'a-z') in api-ms-win-*|ext-ms-win-*) return 0;; esac
    [ -f "$SYS/$1" ]
}
walk() { # $1=dir $2=copy|check
    bad=0 grew=1 nl='
'
    while [ "$grew" = 1 ]; do
        grew=0
        old_ifs=$IFS; IFS=$nl   # one path per line: OUT_DIR may contain spaces
        for f in $(find "$1" -type f \( -name '*.exe' -o -name '*.dll' \)); do
            IFS=$old_ifs
            for d in $(imports "$f"); do
                [ -f "$1/$d" ] && continue
                is_system "$d" && continue
                if [ "$2" = copy ] && [ -f "$QT/bin/$d" ]; then cp "$QT/bin/$d" "$1/"; grew=1
                elif [ "$2" = copy ] && [ -f "$MINGW/bin/$d" ]; then cp "$MINGW/bin/$d" "$1/"; grew=1
                else echo "UNRESOLVED: $(basename "$f") imports $d" >&2; bad=1; fi
            done
        done
        IFS=$old_ifs
        [ "$bad" = 0 ] || return 1
    done
}
walk "$b" copy || die "unresolved non-system imports"

cat > "$b/try-isolated.cmd" <<'EOF'
@echo off
rem Run the wallet fully isolated from your normal ZClassic profile: settings, logs,
rem zclassic.conf, the node datadir and a NEW chain copy live in the folder below.
rem Delete that folder to undo. Only %APPDATA%\ZcashParams is shared (read-only).
if not exist "%USERPROFILE%\zclwallet-profile" mkdir "%USERPROFILE%\zclwallet-profile"
set "ZCLWALLET_PROFILE_DIR=%USERPROFILE%\zclwallet-profile"
cd /d "%~dp0"
start "" "%~dp0zclwallet.exe"
EOF
cat > "$b/README-WINDOWS.txt" <<EOF
ZClassic Qt wallet v$VERSION for Windows x86_64 (unsigned; SmartScreen may warn).
Keep every file in this folder together; zclwallet.exe starts the sibling zclassicd.exe.
try-isolated.cmd starts the wallet in its own profile (see ZCLWALLET_PROFILE_DIR in
wallet/docs/BUILDING.md); zclwallet.exe --print-profile-paths shows where state goes.
SHA256SUMS.txt lists every file. Needs Windows 7 or later, nothing else installed.
Licences: LICENSE (wallet), COPYING and THIRD-PARTY-LICENSES (node),
QT-LGPL-NOTICE.md and THIRD-PARTY-NOTICES.txt (Qt, MinGW runtime, OpenSSL, libsodium);
the full texts (LGPL-3.0, GPL-3.0, OpenSSL, GCC Runtime Library Exception, MinGW-w64,
winpthreads, libsodium) are in the licenses/ folder.
EOF
cp "$wallet/LICENSE" "$wallet/docs/QT-LGPL-NOTICE.md" "$wallet/../COPYING" "$wallet/../THIRD-PARTY-LICENSES" "$b/"
# Full licence texts (verbatim; sources in licenses/README.md). Fail if the set is incomplete.
mkdir "$b/licenses"
for t in LGPL-3.0 GPL-3.0 OpenSSL-LICENSE GCC-Runtime-Library-Exception-3.1 MinGW-w64-COPYING \
         winpthreads-COPYING libsodium-LICENSE; do
    [ -s "$here/licenses/$t.txt" ] || die "missing licence text $here/licenses/$t.txt"
    cp "$here/licenses/$t.txt" "$b/licenses/"
done
cat > "$b/THIRD-PARTY-NOTICES.txt" <<EOF
Third-party run-time files in this folder (unmodified upstream binaries):
- Qt $(qmake -query QT_VERSION) (Qt5*.dll, plugins): LGPLv3, (c) The Qt Company Ltd and
  contributors. Qt is linked dynamically: replace the Qt DLLs with your own build of
  the same Qt version to relink. Source: https://download.qt.io/archive/qt/5.15/
- MinGW-w64 GCC runtime (libgcc_s_seh-1.dll, libstdc++-6.dll): GPLv3 with the GCC
  Runtime Library Exception; libwinpthread-1.dll: MIT-style (MinGW-w64 project).
- OpenSSL 1.1.1 (libssl-1_1-x64.dll, libcrypto-1_1-x64.dll): OpenSSL and SSLeay
  licences. This product includes software developed by the OpenSSL Project for use
  in the OpenSSL Toolkit (http://www.openssl.org/) and cryptographic software written
  by Eric Young (eay@cryptsoft.com). Used only for the https release/price checks.
- libsodium (linked into zclwallet.exe): ISC licence.
Full licence texts are in the licenses/ folder of this bundle:
  licenses/LGPL-3.0.txt                          Qt (LGPLv3)
  licenses/GPL-3.0.txt                           GPLv3, referred to by the LGPLv3; GCC runtime DLLs
  licenses/OpenSSL-LICENSE.txt                   OpenSSL licence + original SSLeay licence
  licenses/GCC-Runtime-Library-Exception-3.1.txt libgcc_s_seh-1.dll, libstdc++-6.dll
  licenses/MinGW-w64-COPYING.txt                 MinGW-w64 runtime and headers
  licenses/winpthreads-COPYING.txt               libwinpthread-1.dll
  licenses/libsodium-LICENSE.txt                 libsodium (ISC)
EOF
( cd "$b" && find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | sort | xargs sha256sum > SHA256SUMS.txt )

echo "== 3. verify bundle"
walk "$b" check || die "bundle has unresolved imports"
echo "import walk: all non-system imports resolve inside the bundle"
quiet=$OUT/build/home; mkdir -p "$quiet/appdata" "$quiet/local" "$quiet/profile"
# Reduced PATH (System32 + Windows only) and redirected profile directories:
# proves no dependency on the Qt/MinGW install and touches no real user state.
runclean() { # $1=dir, rest=command; ZCLWALLET_PROFILE_DIR=build/home/profile
    d=$1 prog=$2; shift 2
    env PATH="$SYS:$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")" QT_QPA_PLATFORM=offscreen \
        APPDATA="$(win "$quiet/appdata")" LOCALAPPDATA="$(win "$quiet/local")" \
        USERPROFILE="$(win "$quiet/profile")" ZCLWALLET_PROFILE_DIR="$(win "$quiet/profile")" \
        "$TIMEOUT" 60 "$d/$prog" "$@" 2>&1
}
check_bundle() { # $1=dir
    runclean "$1" zclwallet.exe --print-profile-paths > "$OUT/build/profile-paths.txt" || die "zclwallet.exe --print-profile-paths failed in $1"; grep -q . "$OUT/build/profile-paths.txt" || die "no profile paths printed"; cat "$OUT/build/profile-paths.txt"
    if [ -f "$1/zclassicd.exe" ]; then runclean "$1" zclassicd.exe -version > "$OUT/build/daemon-version.txt" || die "zclassicd.exe -version failed in $1"; head -1 "$OUT/build/daemon-version.txt"; fi
    return 0
}
check_bundle "$b"

# Scratch copy of the bundle without the wallet/daemon exes, for the check programs.
mkdir -p "$OUT/build/probe" "$OUT/build/probe-bundle"
( cd "$b" && cp -R . "$OUT/build/probe-bundle/" )
rm -f "$OUT/build/probe-bundle/zclassic"*.exe "$OUT/build/probe-bundle/zclwallet.exe"
if [ "${SKIP_PROBE:-0}" != 1 ]; then
    # Initialise the real "windows" platform plugin (constructs QGuiApplication; no
    # window or dialog is created) from the scratch copy.
    ( cd "$OUT/build/probe" && qmake "$(win "$wallet/tests/check-platform.pro")" CONFIG+=release \
        && mingw32-make -j"$JOBS" release ) > "$OUT/build/probe.log" 2>&1 \
        || { tail -20 "$OUT/build/probe.log" >&2; die "probe build failed"; }
    cp "$OUT/build/probe/release/check-platform.exe" "$OUT/build/probe-bundle/"
    walk "$OUT/build/probe-bundle" check || die "probe bundle unresolved"
    out=$(env PATH="$SYS:$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")" QT_DEBUG_PLUGINS=1 QT_LOGGING_TO_CONSOLE=1 \
        APPDATA="$(win "$quiet/appdata")" LOCALAPPDATA="$(win "$quiet/local")" USERPROFILE="$(win "$quiet/profile")" \
        "$TIMEOUT" 60 "$OUT/build/probe-bundle/check-platform.exe" 2>"$OUT/build/probe-plugins.txt") || true
    echo "platform probe: $out"
    case $out in "platform=windows "*) ;; *) die "windows platform plugin did not initialise (see build/probe-plugins.txt)";; esac
fi

zipdir() { # $1=dir-name under OUT -> $1.zip with the folder as the single top-level entry
    # SHA256SUMS.txt must still match and cover every file that goes into the zip.
    ( cd "$OUT/$1" && sha256sum -c --quiet SHA256SUMS.txt ) || die "$1 changed after SHA256SUMS.txt"
    [ "$(find "$OUT/$1" -type f | wc -l)" -eq "$(($(wc -l < "$OUT/$1/SHA256SUMS.txt") + 1))" ] \
        || die "$1 has files not listed in SHA256SUMS.txt"
    # Reproducible entries: every mtime is the commit time (or SOURCE_DATE_EPOCH).
    epoch=$SOURCE_DATE_EPOCH
    find "$OUT/$1" -exec touch -h -d "@$epoch" {} + || die "cannot set timestamps in $1"
    command -v zip >/dev/null 2>&1 && { ( cd "$OUT" && zip -qr -X "$1.zip" "$1" ); return; }
    ps=$(command -v pwsh || command -v powershell) || die "no zip, pwsh or powershell"
    # Entries are written one by one with '/' separators: Windows PowerShell 5.1's
    # Compress-Archive/CreateFromDirectory store '\', which Linux/macOS unzip mangle.
    Z_DIR=$(win "$OUT/$1") Z_ZIP=$(win "$OUT/$1.zip") "$ps" -NoProfile -Command '
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $dir = $env:Z_DIR; $base = Split-Path $dir -Parent
        $z = [IO.Compression.ZipFile]::Open($env:Z_ZIP, "Create")
        try { Get-ChildItem -LiteralPath $dir -Recurse -File | Sort-Object FullName | ForEach-Object {
            $rel = $_.FullName.Substring($base.Length + 1).Replace("\", "/")
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z, $_.FullName, $rel, "Optimal") }
        } finally { $z.Dispose() }' || die "zip failed"
}

if [ "${ALLINONE:-0}" = 1 ]; then
    echo "== 3b. all-in-one variant (daemon appended, same footer as Linux/macOS)"
    a=$OUT/$NAME-allinone
    cp -R "$b" "$a"; rm -f "$a/zclassicd.exe" "$a/SHA256SUMS.txt"
    size=$(wc -c < "$DAEMONS/zclassicd.exe" | tr -d '[:space:]')
    [ "$size" -gt 0 ] && [ "$size" -le 536870912 ] || die "daemon size outside loader limit"
    { cat "$DAEMONS/zclassicd.exe"; openssl dgst -sha256 -binary "$DAEMONS/zclassicd.exe"
      r=$size; i=0; while [ "$i" -lt 8 ]; do printf "\\$(printf %03o $((r % 256)))"; r=$((r / 256)); i=$((i + 1)); done
      printf ZQWDMON1; } >> "$a/zclwallet.exe"
    mkdir -p "$OUT/build/embedded"
    ( cd "$OUT/build/embedded" && qmake "$(win "$wallet/tests/check-embedded.pro")" CONFIG+=release \
        && mingw32-make -j"$JOBS" release ) > "$OUT/build/embedded.log" 2>&1 || die "check-embedded build failed"
    cp "$OUT/build/embedded/release/check-embedded.exe" "$OUT/build/probe-bundle/"
    env PATH="$SYS:$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")" LOCALAPPDATA="$(win "$quiet/local")" \
        "$OUT/build/probe-bundle/check-embedded.exe" "$(win "$a/zclwallet.exe")" "$(win "$DAEMONS/zclassicd.exe")" \
        || die "all-in-one extraction check failed"
    ( cd "$a" && find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | sort | xargs sha256sum > SHA256SUMS.txt )
    walk "$a" check || die "all-in-one unresolved imports"
    runclean "$a" zclwallet.exe --print-profile-paths > /dev/null || die "all-in-one does not start"
    zipdir "$NAME-allinone"
fi

echo "== 4. zip + checksums"
zipdir "$NAME"
( cd "$OUT" && sha256sum "$NAME.zip" $( [ -f "$NAME-allinone.zip" ] && echo "$NAME-allinone.zip" ) > SHA256SUMS.txt )
cat "$OUT/SHA256SUMS.txt"
echo "DONE: $OUT/$NAME.zip"
