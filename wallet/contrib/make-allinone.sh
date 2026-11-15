#!/bin/bash
# =============================================================================
# make-allinone.sh -- build the single-file ("all-in-one") ZClassic wallet from
# source on a DEVELOPER machine (dynamic Qt5; for testing/debugging, NOT a
# portable release -- see src/scripts/mkrelease.sh for the static-Qt release).
#
# Produces ONE file: the GUI executable with the daemon appended via a trailing
# footer  [ daemon | sha256(daemon):32 | len(daemon):8 LE | "ZQWDMON1":8 ].
# The ELF still runs; on first launch the GUI extracts + hash-verifies the daemon
# from its own tail to a per-user cache (ConnectionLoader::ensureDaemonExtracted)
# and runs it -- no separate zclassicd file ships.
#
# Usage (from the repo root, with the daemon already built):
#   contrib/make-allinone.sh /path/to/zclassic/src/zclassicd
#
# WHY THIS DOES A *CLEAN* BUILD (the qt5-websockets gotcha):
#   This branch removed the old websocket mobile-pairing feature, so the wallet
#   no longer uses QtWebSockets. But an INCREMENTAL `make` over a Makefile that
#   qmake generated from an OLDER .pro (which had `QT += websockets` -- still the
#   case on master) keeps `-lQt5WebSockets` in the link line, so the binary then
#   demands libQt5WebSockets.so.5 at runtime (e.g. `pacman -S qt5-websockets`).
#   `make distclean` + a fresh `qmake` regenerates the Makefile from the CURRENT
#   .pro, so the binary only needs the Qt modules actually used (core gui network
#   widgets). The ldd self-check below ABORTS if Qt5WebSockets ever leaks back in.
# =============================================================================
set -euo pipefail

DAEMON="${1:-}"
if [ -z "$DAEMON" ] || [ ! -x "$DAEMON" ]; then
  echo "usage: contrib/make-allinone.sh /path/to/zclassic/src/zclassicd" >&2
  echo "  (build the daemon first: in the zclassic repo, ./zcutil/build.sh -j\$(nproc))" >&2
  exit 1
fi
DAEMON="$(readlink -f "$DAEMON")"
cd "$(dirname "$0")/.."          # repo root

command -v qmake  >/dev/null 2>&1 || { echo "ERROR: qmake (Qt5) not on PATH" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found" >&2; exit 1; }
QV="$(qmake -query QT_VERSION 2>/dev/null || echo '?')"
case "$QV" in 5.*) : ;; *) echo "WARNING: qmake reports Qt $QV; this app targets Qt 5.x" >&2 ;; esac

echo "== CLEAN (drop any stale Makefile / qmake cache so old module deps can't leak) =="
make distclean >/dev/null 2>&1 || true
rm -f .qmake.stash Makefile

echo "== qmake + build (Qt $QV) =="
qmake zcl-qt-wallet.pro CONFIG+=release
make -j"$(nproc)"
[ -x ./zclwallet ] || { echo "ERROR: build did not produce ./zclwallet" >&2; exit 1; }

echo "== runtime Qt deps (must NOT include libQt5WebSockets) =="
ldd ./zclwallet | grep -iE 'Qt5' | sed 's/^/  /' || true
if ldd ./zclwallet | grep -qi 'Qt5WebSockets'; then
  echo "ERROR: zclwallet still links libQt5WebSockets." >&2
  echo "  You are almost certainly building a branch whose .pro still has" >&2
  echo "  'QT += websockets' (e.g. master). Build feature/single-binary-tray-startup," >&2
  echo "  which removed that feature, and re-run this script (it did a clean qmake)." >&2
  exit 1
fi

echo "== embed daemon -> single file (ZQWDMON1 footer) =="
OUT="linux-zclwallet-allinone"
cp ./zclwallet "$OUT"
python3 - "$DAEMON" "$OUT" <<'PYEOF'
import sys, hashlib, struct
d = open(sys.argv[1], 'rb').read()
with open(sys.argv[2], 'ab') as f:
    f.write(d)                            # daemon bytes
    f.write(hashlib.sha256(d).digest())   # sha256 (32)
    f.write(struct.pack('<Q', len(d)))    # len    (8, little-endian)
    f.write(b'ZQWDMON1')                  # magic  (8)
PYEOF
chmod +x "$OUT"

# verify it is still a valid ELF and the embedded daemon footer is internally
# consistent before handing users a file that runtime extraction depends on.
if ! readelf -h "$OUT" >/dev/null 2>&1; then
  echo "ERROR: '$OUT' is not a valid ELF" >&2
  exit 1
fi
if ! python3 - "$OUT" <<'PYEOF'
import hashlib
import os
import struct
import sys

path = sys.argv[1]
size = os.path.getsize(path)
if size < 48:
    raise SystemExit("file too small for daemon footer")

with open(path, "rb") as f:
    f.seek(-48, os.SEEK_END)
    expected_hash = f.read(32)
    daemon_len = struct.unpack("<Q", f.read(8))[0]
    magic = f.read(8)

    if magic != b"ZQWDMON1":
        raise SystemExit("missing ZQWDMON1 footer")
    if daemon_len == 0 or daemon_len > size - 48:
        raise SystemExit("invalid embedded daemon length")

    f.seek(size - 48 - daemon_len)
    daemon = f.read(daemon_len)
    if hashlib.sha256(daemon).digest() != expected_hash:
        raise SystemExit("embedded daemon checksum mismatch")
PYEOF
then
  echo "ERROR: '$OUT' has an invalid embedded daemon footer" >&2
  exit 1
fi

echo
echo "DONE -> $(pwd)/$OUT  ($(stat -c%s "$OUT") bytes)"
echo "Run it from a directory with NO sibling 'zclassicd'/'zqw-zclassicd' so it uses the"
echo "EMBEDDED daemon (the GUI prefers a sibling daemon binary if one is present):"
echo "  ( cd \"\$(mktemp -d)\" && cp \"$(pwd)/$OUT\" . && ./$OUT )"
