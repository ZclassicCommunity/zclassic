#!/usr/bin/env bash
# Build optimized, STRIPPED release binaries for Linux or Windows (mingw), in
# one command. This wraps the normal depends + autogen + configure + make flow
# and then strips the daemon/cli/tx binaries into release/<host-triple>/.
#
# Usage:
#   zcutil/build-release.sh [linux|win64] [extra make args...]
#
# Examples:
#   zcutil/build-release.sh linux            # native build, all cores
#   zcutil/build-release.sh win64 -j8        # Win64 cross-build, 8 jobs
#
# Windows builds need the mingw-w64 POSIX cross toolchain:
#   sudo bash zcutil/setup-mingw-toolchain.sh
#
# Env overrides:
#   MAKE=...             make program (default: make)
#   CONFIGURE_FLAGS=...  extra ./configure flags (appended)
#   STRIP=...            strip program (default: per-target)

set -euo pipefail

# cd to repo root regardless of where we're invoked from.
gprefix() { if type -p "g$1" >/dev/null 2>&1; then echo "g$1"; else echo "$1"; fi; }
READLINK="$(gprefix readlink)"
cd "$(dirname "$("$READLINK" -f "$0")")/.."

TARGET="${1:-linux}"
[ $# -gt 0 ] && shift || true

case "$TARGET" in
    linux|host|native)
        HOST="$(./depends/config.guess)"
        STRIP="${STRIP:-strip}"
        EXEEXT=""
        ;;
    win64|mingw|windows)
        HOST="x86_64-w64-mingw32"
        STRIP="${STRIP:-x86_64-w64-mingw32-strip}"
        EXEEXT=".exe"
        if ! type -p x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
            echo "error: mingw-w64 cross toolchain not found (x86_64-w64-mingw32-g++)." >&2
            echo "       install it with: sudo bash zcutil/setup-mingw-toolchain.sh" >&2
            exit 1
        fi
        ;;
    -h|--help)
        sed -n '2,22p' "$0"; exit 0
        ;;
    *)
        echo "usage: $0 [linux|win64] [make args...]" >&2
        exit 1
        ;;
esac

MAKE="${MAKE:-make}"
CONFIGURE_FLAGS="${CONFIGURE_FLAGS:-}"

# Default to a parallel build if the caller passed no make args.
MAKEARGS=( "$@" )
[ ${#MAKEARGS[@]} -eq 0 ] && MAKEARGS=( "-j$(nproc)" )

CONFIG_SITE_FILE="$PWD/depends/$HOST/share/config.site"

echo "==> target=$TARGET host=$HOST  (strip=$STRIP)"

echo "==> [1/4] building depends for $HOST"
"$MAKE" -C depends HOST="$HOST" "${MAKEARGS[@]}"

if [ ! -f "$CONFIG_SITE_FILE" ]; then
    echo "error: $CONFIG_SITE_FILE not found after depends build." >&2
    exit 1
fi

# Detect whether the tree was last configured for a DIFFERENT host. The in-tree
# static libs (leveldb, univalue, snark) key off their own sources, not
# config.h, so a plain `make` will NOT rebuild them on a host switch and the
# link mixes object architectures (e.g. COFF libs into an ELF binary). Capture
# the previous host before ./configure overwrites config.log.
PREV_HOST=""
[ -f config.log ] && PREV_HOST="$(sed -n 's/.*host_alias *= *\([^ ]*\).*/\1/p' config.log | head -1)"

echo "==> [2/4] autogen + configure"
./autogen.sh
# shellcheck disable=SC2086
CONFIG_SITE="$CONFIG_SITE_FILE" ./configure --prefix=/ --disable-tests --disable-bench $CONFIGURE_FLAGS

if [ -n "$PREV_HOST" ] && [ "$PREV_HOST" != "$HOST" ]; then
    echo "==> host changed ($PREV_HOST -> $HOST): cleaning stale build outputs to avoid mixing object architectures"
    "$MAKE" clean || true
    # snark is in EXTRA_DIST (not SUBDIRS) so the top-level clean misses it.
    "$MAKE" -C src/snark clean || true
fi

echo "==> [3/4] building zclassicd / zclassic-cli / zclassic-tx"
"$MAKE" "${MAKEARGS[@]}"

OUT="release/$HOST"
mkdir -p "$OUT"
echo "==> [4/4] stripping into $OUT/"
for b in zclassicd zclassic-cli zclassic-tx; do
    src="src/${b}${EXEEXT}"
    if [ -f "$src" ]; then
        cp -f "$src" "$OUT/${b}${EXEEXT}"
        "$STRIP" "$OUT/${b}${EXEEXT}"
        printf '    %-20s %s\n' "${b}${EXEEXT}" "$(du -h "$OUT/${b}${EXEEXT}" | cut -f1)"
    else
        echo "    (skipped: $src not built)"
    fi
done

echo "==> done. Stripped release binaries:"
file "$OUT"/* 2>/dev/null | sed 's/^/    /'
