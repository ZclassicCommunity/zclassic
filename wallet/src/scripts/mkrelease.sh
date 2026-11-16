#!/bin/bash
if [ -z $QT_STATIC ]; then 
    echo "QT_STATIC is not set. Please set it to the base directory of a statically compiled Qt"; 
    exit 1; 
fi

if [ -z $APP_VERSION ]; then echo "APP_VERSION is not set"; exit 1; fi
if [ -z $PREV_VERSION ]; then echo "PREV_VERSION is not set"; exit 1; fi

if [ -z $ZCASH_DIR ]; then
    echo "ZCASH_DIR is not set. Please set it to the base directory of a ZClassic project with built ZClassic binaries."
    exit 1;
fi

if [ ! -f $ZCASH_DIR/artifacts/zclassicd ]; then
    echo "Couldn't find zclassicd in $ZCASH_DIR/artifacts/. Please build zclassicd."
    exit 1;
fi

# Ensure that zclassicd is a real MagicBean build. (The single-file release embeds
# only the daemon; zclassic-cli is no longer packaged, and the Windows zclassicd.exe
# is checked in the Windows section below so a Linux-only build can run on its own.)
echo -n "zclassicd version........."
if grep -q "MagicBean" $ZCASH_DIR/artifacts/zclassicd; then
    echo "[OK]"
else
    echo "[ERROR]"
    echo "zclassicd doesn't look like a MagicBean build"
    exit 1
fi

# Portability gate: the embedded daemon must not require a newer glibc than our
# old-base builder targets (Ubuntu 20.04 / glibc 2.31). Built on a newer host it
# would silently fail to start on older distros.
echo -n "zclassicd portability...."
MAXGLIBC=$(objdump -T "$ZCASH_DIR/artifacts/zclassicd" 2>/dev/null | grep -oE "GLIBC_[0-9]+\.[0-9]+" | sort -V | tail -1)
if [ -n "$MAXGLIBC" ] && [ "$(printf '%s\nGLIBC_2.31\n' "$MAXGLIBC" | sort -V | tail -1)" = "GLIBC_2.31" ]; then
    echo "[OK] (max ${MAXGLIBC})"
else
    echo "[ERROR]"
    echo "zclassicd requires newer than glibc 2.31 (max ${MAXGLIBC:-unknown}); build it on the old-base builder."
    exit 1
fi

echo -n "Version files.........."
# Replace the version number in the .pro file so it gets picked up everywhere
sed -i "s/${PREV_VERSION}/${APP_VERSION}/g" zcl-qt-wallet.pro > /dev/null

# Also update it in the README.md
sed -i "s/${PREV_VERSION}/${APP_VERSION}/g" README.md > /dev/null
# CRITICAL: the version the app actually REPORTS comes from src/version.h
# (#define APP_VERSION "..."). zcl-qt-wallet.pro and README.md carry no version
# string, so the two seds above are cosmetic — bump version.h here too or the
# build silently ships the OLD version while printing a green [OK].
sed -i "s/${PREV_VERSION}/${APP_VERSION}/g" src/version.h > /dev/null
if ! grep -q "\"${APP_VERSION}\"" src/version.h; then
  echo "[FAIL]"; echo "FATAL: src/version.h not bumped to ${APP_VERSION} (APP_VERSION #define mismatch)"; exit 1
fi
echo "[OK]"

echo -n "Cleaning..............."
rm -rf bin/*
rm -rf artifacts/*
make distclean >/dev/null 2>&1
echo "[OK]"

echo ""
echo "[Building on" `lsb_release -r`"]"

echo -n "Configuring............"
QT_STATIC=$QT_STATIC bash src/scripts/dotranslations.sh >/dev/null
$QT_STATIC/bin/qmake zcl-qt-wallet.pro -spec linux-clang CONFIG+=release > /dev/null
echo "[OK]"


echo -n "Building..............."
rm -rf bin/zcl-qt-wallet* > /dev/null
rm -rf bin/zclwallet* > /dev/null
make clean > /dev/null
# Abort on a failed compile/link instead of silently shipping a stale binary.
if ! make -j$(nproc) > /dev/null || [ ! -x zclwallet ]; then
    echo "[ERROR]"
    echo "GUI build failed (zclwallet not produced); see the make output above"
    exit 1
fi
echo "[OK]"


# Test for Qt
echo -n "Static link............"
if [[ $(ldd zclwallet | grep -i "Qt") ]]; then
    echo "FOUND QT; ABORT"; 
    exit 1
fi
echo "[OK]"


echo -n "Bundling..............."
strip zclwallet
mkdir -p artifacts >/dev/null 2>&1
# Single-file release: append the daemon to the (static-Qt) GUI executable,
# followed by a trailing footer:  [ sha256(daemon):32 | len(daemon):8 LE | magic "ZQWDMON1":8 ]
# The ELF still runs (the loader ignores trailing bytes); on first launch the GUI
# extracts + hash-verifies the daemon to a per-user cache (see
# ConnectionLoader::ensureDaemonExtracted). No separate zclassicd file ships.
SINGLE=artifacts/linux-zclwallet-v$APP_VERSION
cp zclwallet "$SINGLE"
python3 - "$ZCASH_DIR/artifacts/zclassicd" "$SINGLE" <<'PYEOF'
import sys, hashlib, struct
daemon = open(sys.argv[1], 'rb').read()
with open(sys.argv[2], 'ab') as f:
    f.write(daemon)                              # GUI | daemon
    f.write(hashlib.sha256(daemon).digest())     #     | sha256 (32)
    f.write(struct.pack('<Q', len(daemon)))      #     | len    (8, little-endian)
    f.write(b'ZQWDMON1')                         #     | magic  (8)
PYEOF
chmod +x "$SINGLE"
echo "[OK]"

echo -n "Verifying bundle......."
# Must still be a valid ELF AND carry our trailing magic.
if readelf -h "$SINGLE" >/dev/null 2>&1 && [ "$(tail -c 8 "$SINGLE")" = "ZQWDMON1" ]; then
    echo "[OK]"
else
    echo "[ERROR]"
    echo "Single-file bundle is not a valid ELF or is missing the daemon footer"
    exit 1
fi

echo -n "Relink objects........."
# LGPLv3 (static Qt): publish ZclWallet's object files + a link recipe so anyone
# can relink the app against their own build of Qt. See docs/QT-LGPL-NOTICE.md.
{
  echo "ZclWallet v$APP_VERSION - relink instructions (LGPLv3 / static Qt)"
  echo
  echo "These are ZclWallet's compiled object files (bin/*.o). To relink against"
  echo "your own statically-built Qt 5.15, place its libraries in your qmake kit and"
  echo "re-run the final link, e.g.:"
  echo
  echo "  <your-qt>/bin/qmake zcl-qt-wallet.pro -spec linux-clang CONFIG+=release"
  echo "  make            # re-runs the final 'clang++ -o zclwallet bin/*.o ... <Qt libs>' link"
  echo
  echo "Full application source (MIT): https://github.com/ZclassicCommunity/zcl-qt-wallet"
  echo "Qt 5.15 source (LGPLv3): https://download.qt.io/archive/qt/5.15/"
} > bin/RELINK.txt
tar czf artifacts/linux-relink-objects-v$APP_VERSION.tar.gz bin/*.o bin/RELINK.txt zcl-qt-wallet.pro docs/QT-LGPL-NOTICE.md >/dev/null 2>&1
echo "[OK]"

echo -n "Building deb..........."
debdir=bin/deb/zclwallet-v$APP_VERSION
mkdir -p $debdir > /dev/null
mkdir    $debdir/DEBIAN
mkdir -p $debdir/usr/local/bin

cat src/scripts/control | sed "s/RELEASE_VERSION/$APP_VERSION/g" > $debdir/DEBIAN/control

cp zclwallet                   $debdir/usr/local/bin/
cp $ZCASH_DIR/artifacts/zclassicd $debdir/usr/local/bin/zqw-zclassicd

mkdir -p $debdir/usr/share/pixmaps/
cp res/zclwallet.xpm           $debdir/usr/share/pixmaps/

mkdir -p $debdir/usr/share/applications
cp src/scripts/desktopentry    $debdir/usr/share/applications/zcl-qt-wallet.desktop

dpkg-deb --build $debdir >/dev/null
cp $debdir.deb                 artifacts/linux-deb-zclwallet-v$APP_VERSION.deb
echo "[OK]"



echo ""
echo "[Windows]"

if [ -z $MXE_PATH ]; then 
    echo "MXE_PATH is not set. Set it to ~/github/mxe/usr/bin if you want to build Windows"
    echo "Not building Windows"
    exit 0; 
fi

if [ ! -f $ZCASH_DIR/artifacts/zclassicd.exe ]; then
    echo "Couldn't find zclassicd.exe in $ZCASH_DIR/artifacts/. Please build zclassicd.exe"
    exit 1;
fi


if [ ! -f $ZCASH_DIR/artifacts/zclassic-cli.exe ]; then
    echo "Couldn't find zclassic-cli.exe in $ZCASH_DIR/artifacts/. Please build zclassicd.exe"
    exit 1;
fi

export PATH=$MXE_PATH:$PATH

echo -n "Configuring............"
make clean  > /dev/null
rm -f zcl-qt-wallet-mingw.pro
rm -rf release/
#Mingw seems to have trouble with precompiled headers, so strip that option from the .pro file
cat zcl-qt-wallet.pro | sed "s/precompile_header/release/g" | sed "s/PRECOMPILED_HEADER.*//g" > zcl-qt-wallet-mingw.pro
echo "[OK]"


echo -n "Building..............."
x86_64-w64-mingw32.static-qmake-qt5 zcl-qt-wallet-mingw.pro CONFIG+=release > /dev/null
make -j32 > /dev/null
echo "[OK]"


echo -n "Packaging.............."
mkdir release/zclwallet-v$APP_VERSION  
cp release/zclwallet.exe          release/zclwallet-v$APP_VERSION 
cp $ZCASH_DIR/artifacts/zclassicd.exe    release/zclwallet-v$APP_VERSION > /dev/null
cp $ZCASH_DIR/artifacts/zclassic-cli.exe release/zclwallet-v$APP_VERSION > /dev/null
cp README.md                          release/zclwallet-v$APP_VERSION 
cp LICENSE                            release/zclwallet-v$APP_VERSION 
cd release && zip -r Windows-binaries-zclwallet-v$APP_VERSION.zip zclwallet-v$APP_VERSION/ > /dev/null
cd ..

mkdir artifacts >/dev/null 2>&1
cp release/Windows-binaries-zclwallet-v$APP_VERSION.zip ./artifacts/
echo "[OK]"

if [ -f artifacts/Windows-binaries-zclwallet-v$APP_VERSION.zip ] ; then
    echo -n "Package contents......."
    if unzip -l "artifacts/Windows-binaries-zclwallet-v$APP_VERSION.zip" | wc -l | grep -q "11"; then 
        echo "[OK]"
    else
        echo "[ERROR]"
        exit 1
    fi
else
    echo "[ERROR]"
    exit 1
fi
