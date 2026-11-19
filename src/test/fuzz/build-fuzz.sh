#!/bin/sh
# Builds the opt-in fuzz targets (fuzz_block, fuzz_tx, fuzz_p2p_payload) against
# the static libraries of an already configured and built tree. Nothing here
# touches autotools or the default build; see README.md.
#
# usage: build-fuzz.sh <builddir-with-configured-tree> <outdir> [cxx]
#   builddir  the configured and built tree (the directory holding src/Makefile
#             and src/libbitcoin_server.a); an in-tree build is the supported layout
#   outdir    receives fuzz_block, fuzz_tx, fuzz_p2p_payload
#   cxx       C++ compiler, default g++. A clang++ links libFuzzer
#             (-fsanitize=fuzzer); any other compiler links replay_main.cpp,
#             which replays the files in the directories given on its command
#             line.
# Both flavours add -fsanitize=address,undefined to the harness code only: the
# project libraries are linked as built (uninstrumented).
set -eu
[ $# -ge 2 ] || { echo "usage: $0 <builddir> <outdir> [cxx]" >&2; exit 2; }
B=$(cd "$1" && pwd)
OUT=$2
CXX=${3:-g++}
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$B/src
[ -f "$SRC/Makefile" ] && [ -f "$SRC/libbitcoin_server.a" ] || {
    echo "build-fuzz.sh: $SRC has no Makefile or libbitcoin_server.a; configure and build the tree first" >&2
    exit 2
}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

# Ask the configured Makefile for the include and library flags it uses for
# test_bitcoin, so they cannot drift from the real link line.
PMK=$OUT/.print.mk
trap 'rm -f "$PMK"' EXIT
printf 'print-%%: ; @echo '"'"'$($*)'"'"'\n' > "$PMK"
mkv() { make -s --no-print-directory -C "$SRC" -o Makefile -o config.status -f Makefile -f "$PMK" "print-$1"; }

DEFS=$(mkv DEFS)
DEFAULT_INCLUDES=$(mkv DEFAULT_INCLUDES)
CPPFLAGS=$(mkv CPPFLAGS)
AM_CPPFLAGS=$(mkv AM_CPPFLAGS)
INCLUDES=$(mkv BITCOIN_INCLUDES)
LDFLAGS=$(mkv LDFLAGS)
BOOST_LIBS=$(mkv BOOST_LIBS)
BDB_LIBS=$(mkv BDB_LIBS)
SSL_LIBS=$(mkv SSL_LIBS)
CRYPTO_LIBS=$(mkv CRYPTO_LIBS)
EVENT_LIBS=$(mkv EVENT_LIBS)
EVENT_PT_LIBS=$(mkv EVENT_PTHREADS_LIBS)
ZCASH_LIBS=$(mkv LIBZCASH_LIBS)
TOR_LIBS=$(mkv TOR_LIBS)
TOR_SYS_LIBS=$(mkv TOR_SYSTEM_LIBS)
ZMQ_LIBS=$(mkv ZMQ_LIBS)


# Static libraries, in test_bitcoin's LDADD order (src/Makefile.test.include).
ARCHIVES=
for a in libbitcoin_wallet.a libbitcoin_server.a libzcl_tokenguard.a libzcl_tor.a libbitcoin_cli.a \
         libbitcoin_common.a libbitcoin_util.a crypto/libbitcoin_crypto.a libzcl_c23_hash.a \
         univalue/.libs/libunivalue.a leveldb/libleveldb.a leveldb/libmemenv.a \
         secp256k1/.libs/libsecp256k1.a libzcash.a libzcl_c23.a libzcl_c23_seam.a; do
    [ -f "$SRC/$a" ] && ARCHIVES="$ARCHIVES $SRC/$a"
done
# libbitcoin_consensus.a exists only in some configurations.
[ -f "$SRC/libbitcoin_consensus.a" ] && ARCHIVES="$ARCHIVES $SRC/libbitcoin_consensus.a"

SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
case $CXX in
    *clang*) MODE=libfuzzer; DRIVER="-fsanitize=fuzzer" ; COMPILE_SAN="$SAN -fsanitize=fuzzer-no-link" ;;
    *)       MODE=replay;    DRIVER="$HERE/replay_main.cpp"; COMPILE_SAN="$SAN" ;;
esac

# -std=gnu++17 is only needed if the tree was configured with it; follow the
# tree's own CXX setting for the dialect when it names one.
STD=$(mkv CXX | sed -n 's/.*\(-std=[a-z+0-9]*\).*/\1/p')
[ -n "$STD" ] || STD=-std=c++11

# The include flags are relative to src/ (-I.), so compile from there.
cd "$SRC"
for t in fuzz_block fuzz_tx fuzz_p2p_payload; do
    echo "build-fuzz.sh: $t ($MODE)"
    # shellcheck disable=SC2086
    $CXX $STD -g -O1 $COMPILE_SAN -DHAVE_CONFIG_H $DEFS $DEFAULT_INCLUDES $CPPFLAGS $AM_CPPFLAGS $INCLUDES \
        -fwrapv -fno-strict-aliasing -pthread \
        "$HERE/$t.cpp" $DRIVER $LDFLAGS \
        -Wl,--start-group $ARCHIVES $TOR_LIBS $BOOST_LIBS $BDB_LIBS $SSL_LIBS $CRYPTO_LIBS \
        $EVENT_PT_LIBS $EVENT_LIBS $ZCASH_LIBS $TOR_SYS_LIBS $ZMQ_LIBS -lpthread -ldl -lm -Wl,--end-group \
        -o "$OUT/$t"
done
echo "build-fuzz.sh: built $OUT/fuzz_block $OUT/fuzz_tx $OUT/fuzz_p2p_payload ($MODE)"
case $MODE in
    libfuzzer) echo "run: $OUT/fuzz_block -max_total_time=60 $HERE/corpus/block" ;;
    replay)    echo "run: $OUT/fuzz_block $HERE/corpus/block" ;;
esac
