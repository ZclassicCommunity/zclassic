#!/bin/sh
# -reindex must not lose blocks to a stale record header between two records, and must not
# leave an 8-byte hole behind itself. Regtest, shell only, no Python.
#
# 1. generate 100 blocks, stop cleanly, insert a stale record header (what a
#    hard-killed earlier run can leave in the gap after a reindex) before each of many records,
#    then -reindex: height and best block hash must equal the original every time.
# 2. generate, -reindex, generate more: the records in blk00000.dat must be contiguous (no gap
#    between the last pre-reindex record and the first post-reindex record), and a second
#    -reindex must reach the full height.
# 3. a truncated final record and a region of zeros mid-file: -reindex stops or skips
#    gracefully (loads everything before the damage) and the node stays up.
#
# usage: reindex_stale_header.sh --bin <dir> --work <dir> [--base port]
# Needs jq (the shared helpers use it for money arithmetic). Never point this at a real datadir.
BIN=""; WORK=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;;
        *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
NU_ARGS=""   # default regtest upgrade heights: the blocks (287-byte records) the reproduction was found with
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
BASE=${PORT_BASE:-$((24000 + ($$ % 15000)))}
SD=$WORK/stale; rm -rf "$SD"; mkdir -p "$SD"; : >"$SD/pids"
SCN_LOG=$WORK/checks.log; : >"$SCN_LOG"; SCN_ID=stale; OBS_LOG=$WORK/obs.log; : >"$OBS_LOG"
trap 'stop_all' EXIT
MAGIC="aa e8 3f 5f"   # regtest message start
BLK=$SD/node0/regtest/blocks/blk00000.dat

# wait_height <height> <seconds>: node 0 reports at least this height
wait_height() {
    w=0
    while [ $w -lt $(( $2 * 2 )) ]; do
        h=$(cli 0 getblockcount 2>/dev/null); case $h in ''|*[!0-9]*) ;; *) [ "$h" -ge "$1" ] && return 0 ;; esac
        w=$((w + 1)); sleep 0.5
    done
    return 1
}
# u32 <file> <offset>: little-endian 32-bit value
u32() { od -An -tu4 -j "$2" -N4 "$1" | tr -d ' '; }
is_magic() { [ "$(od -An -tx1 -j "$2" -N4 "$1" | sed 's/^ *//;s/ *$//')" = "$MAGIC" ]; }
# records <file>: offsets of consecutive records from the start of the file, one per line
records() {
    o=0; sz=$(wc -c <"$1")
    while [ $((o + 8)) -le "$sz" ] && is_magic "$1" "$o"; do
        echo "$o"; o=$((o + 8 + $(u32 "$1" $((o + 4)))))
    done
}
# insert_header <src> <dst> <offset> <len>: dst = src with a stale record inserted at offset: magic,
# a declared length, then 134 filler bytes. The real record that follows starts with magic + a length
# whose two high bytes are zero, so a block parsed from the stale record reads the 134 filler bytes,
# the real magic and the two low length bytes as its header, then an empty solution and zero
# transactions (the two zero length bytes): it deserializes cleanly and ends exactly where the real
# record's data starts, so the loader used to skip the real record's magic and lose the rest of the
# chain. (Bare 8-byte magic+length, as a hard kill can leave, bites only when the next record happens
# to parse that way, which depends on the nonce bytes.)
insert_header() { # the declared length is always 500 (bytes f4 01 00 00)
    { head -c "$3" "$1"
      printf '\252\350\077\137'
      awk 'BEGIN { printf "%c%c%c%c", 244, 1, 0, 0 }'   # declared length 500
      head -c 134 /dev/zero | tr '\000' '\021'
      tail -c +$(($3 + 1)) "$1"; } >"$2"
}

# ---- scenario 1 -----------------------------------------------------------
start 0 "$BIN" -listen=0 || exit 1
cli 0 generate 100 >/dev/null
H0=$(cli 0 getblockcount); B0=$(cli 0 getbestblockhash)
ck "chain built" "$H0" 100
stop 0
cp "$BLK" "$SD/orig.blk"
records "$SD/orig.blk" >"$SD/offs"
N=$(wc -l <"$SD/offs"); ck "records found in the block file" "$N" 101
tried=0; failed=0
for k in 3 7 11 15 19 23 27 31 35 39 43 47 51 55 59 63 67 71 75 79 83 87 91 95 98; do
    P=$(sed -n "$((k + 1))p" "$SD/offs"); L=500
    insert_header "$SD/orig.blk" "$BLK" "$P" "$L"
    tried=$((tried + 1))
    if start 0 "$BIN" -listen=0 -reindex; then
        wait_height 100 20; h=$(cli 0 getblockcount); b=$(cli 0 getbestblockhash)
        if [ "$h" != "$H0" ] || [ "$b" != "$B0" ]; then failed=$((failed + 1)); bad "stale header before record $k (offset $P): height $h of $H0, tip $b"; fi
        stop 0
    else
        failed=$((failed + 1)); bad "stale header before record $k: node did not start"
    fi
done
ck "stale header: $tried insertion positions tried, positions that lost blocks" "$failed" 0
[ "$tried" -ge 20 ] || bad "fewer than 20 positions tried"
cp "$SD/orig.blk" "$BLK"

# ---- scenario 3 (on the same chain) ---------------------------------------
# truncated final record
P=$(sed -n "101p" "$SD/offs"); head -c $((P + 100)) "$SD/orig.blk" >"$BLK"
if start 0 "$BIN" -listen=0 -reindex; then
    wait_height 99 20; sleep 1; ck "truncated final record: height after -reindex" "$(cli 0 getblockcount)" 99
    alive "truncated final record"; stop 0
else bad "truncated final record: node did not start"; fi
# zeros in place of record 60 (header and data)
cp "$SD/orig.blk" "$BLK"; P=$(sed -n "61p" "$SD/offs"); L=$(u32 "$SD/orig.blk" $((P + 4)))
dd if=/dev/zero of="$BLK" bs=1 seek="$P" count=$((L + 8)) conv=notrunc 2>/dev/null
if start 0 "$BIN" -listen=0 -reindex; then
    wait_height 59 20; sleep 1; ck "zeroed record 60: height after -reindex" "$(cli 0 getblockcount)" 59
    alive "zeroed record 60"; stop 0
else bad "zeroed record 60: node did not start"; fi

# ---- scenario 2 -----------------------------------------------------------
rm -rf "$SD/node0/regtest/blocks" "$SD/node0/regtest/chainstate" "$SD/node0/regtest/database"
start 0 "$BIN" -listen=0 || exit 1
cli 0 generate 50 >/dev/null; stop 0
start 0 "$BIN" -listen=0 -reindex || exit 1
wait_height 50 30; ck "reindex of 50 blocks" "$(cli 0 getblockcount)" 50
cli 0 generate 30 >/dev/null; H2=$(cli 0 getblockcount); B2=$(cli 0 getbestblockhash); ck "generate after reindex" "$H2" 80
stop 0
nrec=$(records "$BLK" | wc -l)
ck "records are contiguous after reindex then generate (no 8-byte gap)" "$nrec" 81
start 0 "$BIN" -listen=0 -reindex || exit 1
wait_height 80 30; ck "second reindex reaches full height" "$(cli 0 getblockcount)" 80
ck "second reindex best block hash" "$(cli 0 getbestblockhash)" "$B2"
stop 0

np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
say "reindex stale header: $np pass, $nf fail"
[ "$nf" = 0 ] && [ "$np" -gt 0 ]
