#!/bin/sh
# Build and run the five wallet test binaries headless on Windows (Git Bash / MSYS2).
#
#   sh wallet/tests/run-windows.sh QT_DIR MINGW_DIR LIBSODIUM_A [PATCHED_QT_DIR]
#
#   QT_DIR          Qt 5.15.2 kit, e.g. C:/Qt/5.15.2/mingw81_64
#   MINGW_DIR       matching MinGW, e.g. C:/Qt/Tools/mingw810_64
#   LIBSODIUM_A     static libsodium.a built for x86_64-w64-mingw32
#   PATCHED_QT_DIR  optional: directory holding a Qt5Widgets.dll built with
#                   qt-5.15.2-windows-offscreen.patch (see README.md). It is placed
#                   in the runtime directory ahead of the kit's copy.
#
# Environment: JOBS (build jobs, default 8), OUT (work dir, default
# wallet/tests/build-windows, git-ignored), ONLY (one binary name to run, e.g. tst_widget),
# FN_TIMEOUT (seconds per function, default 180).
#
# Everything runs under QT_QPA_PLATFORM=offscreen with APPDATA, LOCALAPPDATA and
# USERPROFILE redirected into $OUT/home, so no real wallet profile is read or written.
# No GUI window is opened and zclwallet.exe is never started. Nothing under the Qt kit
# is modified. tst_widget is run one function per process.
#
# Output: one summary line per binary; per-function results in $OUT/results/*.txt.
# Exit status: 0 only if every function of every binary passed. Without
# PATCHED_QT_DIR, the functions in KNOWN_CRASH below are expected to crash inside
# QMessageBox on stock Qt (qt_getWindowsSystemMenu null dereference); they are reported
# as KNOWN-CRASH and do not fail the run, but any other failure or crash does. With
# PATCHED_QT_DIR that list is ignored and every function must pass.
set -eu

[ "$#" -eq 3 ] || [ "$#" -eq 4 ] || { sed -n '2,29p' "$0" >&2; exit 2; }

# Stock Qt 5.15.2 on Windows crashes (exit 139) in QMessageBox under offscreen.
KNOWN_CRASH="combo2_localNetworkResultTextIsTrue
p11_autoShieldGateAbortsOnSnapshotRace
p12_multiRecipientCoinbaseAborts
p15_coinbaseBandMessageAborts
p16_autoShieldFullConsumeRaceAborts
p17_autoShieldExactNonCoinbaseConsumeRaceGuard
p2_deshieldRequiresAcknowledgement
p6_autoShieldLastResortFailClosed
p7_sproutRecipientChangeWarnOnce
ux13_externalNodeQuitWordingIsHonest
ux14_firstCloseNoticeQuitNowReallyQuits
ux1_backupWithoutConnectionSaysWhy
ux2_reviewSendWithNoPayFromSaysWhy
ux5_firstCloseToTrayExplainsAndOffersQuit
ux7_doubleClickActivityRowShowsDetails"

QT=$(cygpath -u "$1") MINGW=$(cygpath -u "$2") SODIUM=$(cygpath -u "$3")
PATCHED=
[ "$#" -eq 4 ] && PATCHED=$(cygpath -u "$4")
JOBS=${JOBS:-8}
FN_TIMEOUT=${FN_TIMEOUT:-180}
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
wallet=$(CDPATH= cd -- "$here/.." && pwd)
OUT=${OUT:-$here/build-windows}
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
die() { echo "ERROR: $*" >&2; exit 1; }
win() { cygpath -m "$1"; }

for t in "$QT/bin/qmake.exe" "$MINGW/bin/mingw32-make.exe" "$SODIUM" "$QT/bin/Qt5Widgets.dll"; do
    [ -f "$t" ] || die "missing $t"
done
if [ -n "$PATCHED" ]; then
    [ -f "$PATCHED/Qt5Widgets.dll" ] || die "missing $PATCHED/Qt5Widgets.dll"
fi
command -v timeout >/dev/null || die "timeout(1) not found"
SYS=$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")
PATH="$QT/bin:$MINGW/bin:/usr/bin:$SYS/System32:$SYS"
export PATH

# The widget project links res/libsodium.a (and depends on res/liblibsodium.a); both
# are git-ignored.
cp "$SODIUM" "$wallet/res/libsodium.a"
cp "$SODIUM" "$wallet/res/liblibsodium.a"

echo "== build (release, Qt $(qmake -query QT_VERSION), -j$JOBS) in $OUT"
for spec in tst_logic:tests.pro tst_names:names.pro tst_tokens:tokens.pro \
            tst_tokenssend:tokenssend.pro tst_widget:widget/tst_widget.pro; do
    name=${spec%%:*}; pro=${spec#*:}
    mkdir -p "$OUT/b/$name"
    ( cd "$OUT/b/$name" && qmake "$(win "$here/$pro")" CONFIG+=release \
        && mingw32-make -j"$JOBS" release ) > "$OUT/b/$name.log" 2>&1 \
        || { tail -30 "$OUT/b/$name.log" >&2; die "$name build failed (see $OUT/b/$name.log)"; }
    [ -f "$OUT/b/$name/release/$name.exe" ] || [ -f "$OUT/b/$name/$name.exe" ] \
        || die "$name build produced no exe"
done

# Runtime directory: the kit's DLLs and plugins, then the patched Widgets on top.
rt=$OUT/rt
rm -rf "$rt"
mkdir -p "$rt/platforms" "$rt/imageformats" "$rt/iconengines" "$rt/styles"
for d in Core Gui Network Svg Widgets Test; do cp "$QT/bin/Qt5$d.dll" "$rt/"; done
for d in libgcc_s_seh-1 libstdc++-6 libwinpthread-1; do cp "$MINGW/bin/$d.dll" "$rt/"; done
cp "$QT/plugins/platforms/qoffscreen.dll" "$QT/plugins/platforms/qwindows.dll" "$rt/platforms/"
cp "$QT/plugins/imageformats/"q*.dll "$rt/imageformats/" 2>/dev/null || true
cp "$QT/plugins/iconengines/qsvgicon.dll" "$rt/iconengines/" 2>/dev/null || true
cp "$QT/plugins/styles/"*.dll "$rt/styles/" 2>/dev/null || true
rm -f "$rt"/*/*.debug
if [ -n "$PATCHED" ]; then
    cp "$PATCHED/Qt5Widgets.dll" "$rt/Qt5Widgets.dll"
    mode=patched
    echo "== runtime: patched Qt5Widgets.dll from $PATCHED"
else
    mode=stock
    echo "== runtime: stock Qt5Widgets.dll; KNOWN_CRASH functions are tolerated"
fi
sha256sum "$rt/Qt5Widgets.dll" | sed 's/ .*//; s/^/   Qt5Widgets.dll sha256 /'

# Isolated profile; headless platform.
H=$OUT/home
mkdir -p "$H/appdata" "$H/local" "$H/profile" "$OUT/results"
APPDATA=$(cygpath -w "$H/appdata"); LOCALAPPDATA=$(cygpath -w "$H/local")
USERPROFILE=$(cygpath -w "$H/profile"); HOME=$H/profile
QT_QPA_PLATFORM=offscreen; QT_QPA_FONTDIR=C:/Windows/Fonts
QT_PLUGIN_PATH=$(cygpath -w "$rt")
PATH="/usr/bin:$rt:$SYS/System32:$SYS"
export APPDATA LOCALAPPDATA USERPROFILE HOME QT_QPA_PLATFORM QT_QPA_FONTDIR QT_PLUGIN_PATH PATH

is_known() { printf '%s\n' "$KNOWN_CRASH" | grep -qx "$1"; }
rc=0

# run_one NAME FUNCTION|"" -> prints "PASS|FAIL|CRASH" on stdout, writes the log.
run_one() {
    n=$1 f=$2
    exe=$OUT/b/$n/release/$n.exe
    [ -f "$exe" ] || exe=$OUT/b/$n/$n.exe
    log=$OUT/results/$n.${f:-all}.txt
    set +e
    ( cd "$OUT/b/$n" && timeout "$FN_TIMEOUT" "$exe" $f -o "$(win "$log"),txt" ) > "$log.stdout" 2>&1
    st=$?
    set -e
    if grep -q '^Totals: ' "$log" 2>/dev/null; then
        if grep -q '^Totals: .*, 0 failed,' "$log" && [ "$st" -eq 0 ]; then echo PASS; else echo FAIL; fi
    else
        echo CRASH
    fi
}

for n in tst_logic tst_names tst_tokens tst_tokenssend tst_widget; do
    [ -z "${ONLY:-}" ] || [ "$ONLY" = "$n" ] || continue
    if [ "$n" != tst_widget ]; then
        r=$(run_one "$n" "")
        tot=$(grep '^Totals: ' "$OUT/results/$n.all.txt" 2>/dev/null || echo "no totals (crash)")
        echo "$n: $r  $tot"
        [ "$r" = PASS ] || rc=1
        continue
    fi
    exe=$OUT/b/$n/release/$n.exe
    fns=$(cd "$OUT/b/$n" && "$exe" -functions 2>/dev/null | tr -d '\r' | sed 's/()$//' | grep -v '^$')
    pass=0 fail=0 crash=0 known=0 total=0
    : > "$OUT/results/tst_widget.summary.txt"
    for f in $fns; do
        total=$((total + 1))
        r=$(run_one "$n" "$f")
        case $r in
        PASS) pass=$((pass + 1)) ;;
        FAIL) fail=$((fail + 1)); rc=1 ;;
        CRASH)
            if [ "$mode" = stock ] && is_known "$f"; then
                known=$((known + 1)); r=KNOWN-CRASH
            else
                crash=$((crash + 1)); rc=1
            fi ;;
        esac
        echo "$r $f" >> "$OUT/results/tst_widget.summary.txt"
        case $r in PASS|KNOWN-CRASH) ;; *) echo "  $r $f" ;; esac
    done
    echo "tst_widget: functions=$total pass=$pass fail=$fail crash=$crash known-crash=$known mode=$mode"
done

[ "$rc" -eq 0 ] && echo "RESULT: ok" || echo "RESULT: FAILED (see $OUT/results)"
exit "$rc"
