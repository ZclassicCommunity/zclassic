#!/bin/sh
# Build zcl_tor_selftest against the depends prefix (POSIX sh, no Python).
#   DEPS=<prefix> OUT=<binary> SAN=1 sh build_selftest.sh
# DEPS defaults to ../../../depends/x86_64-pc-linux-gnu relative to this file.
# SAN=1 adds -fsanitize=address,undefined. Run under `devbuild --wait`.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
DEPS=${DEPS:-$here/../../../depends/x86_64-pc-linux-gnu}
OUT=${OUT:-$here/zcl_tor_selftest}
CC=${CC:-gcc}
FLAGS="-std=gnu17 -O2 -g -Wall -Wextra -Werror -I$DEPS/include -I$here"
if [ "${SAN:-0}" = 1 ]; then
    FLAGS="$FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
fi
# shellcheck disable=SC2086
$CC $FLAGS -o "$OUT" \
    "$here/zcl_tor_selftest.c" "$here/zcl_tor_embed.c" "$here/zcl_tor_dispatch.c" \
    "$here/zcl_tor_proc_posix.c" "$here/keyfile.c" \
    -L"$DEPS/lib" -ltor -led25519_donna -led25519_ref10 -lkeccak-tiny \
    -levent_pthreads -levent -lssl -lcrypto -lz -lm -lpthread -ldl
echo "built $OUT"
