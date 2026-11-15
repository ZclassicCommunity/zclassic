#!/bin/bash

# Accept the variables as command line arguments as well
POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -q|--qt_path)
    QT_PATH="$2"
    shift # past argument
    shift # past value
    ;;
    -z|--zclassic_path)
    ZCASH_DIR="$2"
    shift # past argument
    shift # past value
    ;;
    -v|--version)
    APP_VERSION="$2"
    shift # past argument
    shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [ -z $QT_PATH ]; then 
    echo "QT_PATH is not set. Please set it to the base directory of Qt"; 
    exit 1; 
fi

if [ -z $ZCASH_DIR ]; then
    echo "ZCASH_DIR is not set. Please set it to the base directory of a compiled zclassicd";
    exit 1;
fi

if [ -z $APP_VERSION ]; then
    echo "APP_VERSION is not set. Please set it to the current release version of the app";
    exit 1;
fi

if [ ! -f $ZCASH_DIR/src/zclassicd ]; then
    echo "Could not find compiled zclassicd in $ZCASH_DIR/src/.";
    exit 1;
fi

if ! cat src/version.h | grep -q "$APP_VERSION"; then
    echo "Version mismatch in src/version.h"
    exit 1
fi

export PATH=$PATH:/usr/local/bin

#Clean
echo -n "Cleaning..............."
make distclean >/dev/null 2>&1
rm -f artifacts/macOS-zclwallet-v$APP_VERSION.dmg
echo "[OK]"


echo -n "Configuring............"
# Build
QT_STATIC=$QT_PATH src/scripts/dotranslations.sh >/dev/null
$QT_PATH/bin/qmake zcl-qt-wallet.pro CONFIG+=release >/dev/null
echo "[OK]"


echo -n "Building..............."
make -j4 >/dev/null
echo "[OK]"

#Qt deploy
echo -n "Deploying.............."
mkdir artifacts >/dev/null 2>&1
rm -f artifcats/zclwallet.dmg >/dev/null 2>&1
rm -f artifacts/rw* >/dev/null 2>&1
cp $ZCASH_DIR/src/zclassicd zclwallet.app/Contents/MacOS/
cp $ZCASH_DIR/src/zclassic-cli zclwallet.app/Contents/MacOS/
$QT_PATH/bin/macdeployqt zclwallet.app
echo "[OK]"

# Ad-hoc codesign — MUST run AFTER macdeployqt. macdeployqt relocates/rewrites the
# bundled Qt frameworks and invalidates their linker signatures; on Apple Silicon an
# app with an invalid signature is SIGKILLed at launch ("code signature invalid").
# Sign the nested executables (incl. the sibling daemon in Contents/MacOS) first,
# then --deep the whole .app. There is no Apple Developer ID here, so this is AD-HOC
# (-s -): it fixes the Apple-Silicon SIGKILL but does NOT notarize, so Gatekeeper
# still flags "unidentified developer" — users right-click -> Open once, or run
# `xattr -dr com.apple.quarantine /Applications/ZclWallet.app` (see docs/BUILDING.md
# + release notes). With a Dev ID, replace `-` with the identity and add
# --options runtime, then notarize + staple.
echo -n "Ad-hoc signing........."
codesign --force --timestamp=none --sign - zclwallet.app/Contents/MacOS/zclassic-cli >/dev/null 2>&1 || true
codesign --force --timestamp=none --sign - zclwallet.app/Contents/MacOS/zclassicd  >/dev/null 2>&1 || true
codesign --force --deep --timestamp=none --sign - zclwallet.app >/dev/null 2>&1
if codesign --verify --deep --strict zclwallet.app >/dev/null 2>&1; then echo "[OK]"; else echo "[WARN: codesign verify failed — check on the Mac]"; fi


echo -n "Building dmg..........."
mv zclwallet.app ZclWallet.app
DMG="artifacts/macOS-zclwallet-v$APP_VERSION.dmg"
rm -f "$DMG"
# `create-dmg` drives Finder via AppleScript to lay out the decorative
# background/icons. On a headless / CI / Automation-restricted Mac that fails with
# "AppleEvent timed out (-1712)" and produces NO dmg. The decorative layout is
# cosmetic, so fall back to a plain compressed dmg via hdiutil — functionally
# identical (a signed .app the user drags out). For the polished layout, run on an
# interactive Mac with Automation permission granted to the terminal.
create-dmg --volname "ZclWallet-v$APP_VERSION" --volicon "res/logo.icns" --window-pos 200 120 --icon "ZclWallet.app" 200 190  --app-drop-link 600 185 --hide-extension "ZclWallet.app"  --window-size 800 400 --hdiutil-quiet --background res/dmgbg.png  "$DMG" ZclWallet.app >/dev/null 2>&1
if [ ! -f "$DMG" ]; then
    echo -n "[create-dmg failed → hdiutil fallback]..."
    hdiutil create -volname "ZclWallet-v$APP_VERSION" -srcfolder ZclWallet.app -ov -format UDZO "$DMG" >/dev/null 2>&1
fi
[ -f "$DMG" ] && echo "[OK]" || echo "[FAIL: no dmg produced]"

#mkdir bin/dmgbuild >/dev/null 2>&1
#sed "s/RELEASE_VERSION/${APP_VERSION}/g" res/appdmg.json > bin/dmgbuild/appdmg.json
#cp res/logo.icns bin/dmgbuild/
#cp res/dmgbg.png bin/dmgbuild/

#cp -r zclwallet.app bin/dmgbuild/

#appdmg --quiet bin/dmgbuild/appdmg.json artifacts/macOS-zclwallet-v$APP_VERSION.dmg >/dev/null
if [ ! -f artifacts/macOS-zclwallet-v$APP_VERSION.dmg ]; then
    echo "[ERROR]"
    exit 1
fi
echo  "[OK]"
