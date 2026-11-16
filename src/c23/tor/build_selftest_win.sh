#!/bin/sh
# Cross-build the Windows self-test with mingw-w64 (POSIX sh, no Python).
#   DEPS=<prefix> OUT=<exe> sh build_selftest_win.sh
# DEPS defaults to ../../../depends/x86_64-w64-mingw32 relative to this file.
# Fully static: the only DLL imports are Windows system libraries. Run under
# `devbuild --wait`.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
DEPS=${DEPS:-$here/../../../depends/x86_64-w64-mingw32}
OUT=${OUT:-$here/zcl_tor_selftest_win.exe}
CC=${CC:-x86_64-w64-mingw32-gcc}
WINDRES=${WINDRES:-x86_64-w64-mingw32-windres}
obj=${OUT%.exe}.manifest.o
# The manifest asks Windows 10 1903+ for a UTF-8 ANSI code page, so the narrow
# file APIs inside Tor open UTF-8 datadir paths (see README.md, Windows).
$WINDRES -O coff -i "$here/zcl_tor_win.rc" -o "$obj"
FLAGS="-std=gnu17 -O2 -g -Wall -Wextra -Werror -I$DEPS/include -I$here"
# shellcheck disable=SC2086
$CC $FLAGS -static -o "$OUT" \
    "$here/zcl_tor_selftest_win.c" "$here/zcl_tor_embed.c" "$here/zcl_tor_dispatch.c" "$here/zcl_tor_inproc.c" \
    "$here/zcl_tor_proc_win.c" "$here/keyfile.c" "$obj" \
    -L"$DEPS/lib" -ltor -led25519_donna -led25519_ref10 -lkeccak-tiny \
    -levent -lssl -lcrypto -lz \
    -lws2_32 -liphlpapi -lcrypt32 -ladvapi32 -lshell32 -luser32 -lgdi32 -lbcrypt -lshlwapi
rm -f "$obj"
echo "built $OUT"
