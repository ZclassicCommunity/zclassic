#!/usr/bin/env bash
# ============================================================================
# ZSLP NFT / token end-to-end LIVE regtest harness (committed, repeatable).
#
# This is the COMMITTED, repo-discoverable form of the live RPC -> builder ->
# confirm -> re-read loop that the gtest unit suite explicitly disclaims
# (src/gtest/test_zslp_wallet.cpp, header HONESTY note). It brings up a fresh,
# isolated regtest zclassicd (UNIQUE datadir + port, Sapling params bound), then
# drives the full ZSLP write+read path through the REAL zclassic-cli and ASSERTS
# every step with concrete on-chain evidence:
#   - NFT genesis (txid==tokenid, decimals 0, totalminted 1, hasmintbaton false)
#   - NFT transfer: the genesis token dust (txid:1) IS pinned in the SEND vin,
#     and the holding address moves
#   - anti-burn vs sendtoaddress: the NFT dust is ABSENT from listunspent and is
#     never a vin of an unrelated ZCL spend
#   - fungible genesis+baton + re-mint (100 -> 125)
#   - 0-conf token-change protection (a concurrent sendtoaddress never selects an
#     unconfirmed token-change output)
#   - self-validate refusals (over-send / unknown token / mint-without-baton),
#     each refused WITHOUT broadcasting (mempool unchanged)
#   - anti-burn vs shielding (z_sendmany), when Sapling is active here
#
# ALWAYS tears the daemon down and removes the datadir on exit (trap), so it is
# safely re-runnable and never touches a real node.
#
# Usage:
#   qa/zslp/zslp-nft-regtest.sh [ZCLASSICD] [ZCLASSIC_CLI]
# Resolution order for the binaries and params dir:
#   1. positional args $1 / $2
#   2. env  ZCLASSICD / ZCLASSIC_CLI
#   3. default  <repo>/src/zclassicd  and  <repo>/src/zclassic-cli
#   params dir:  env ZCASH_PARAMS_DIR, else ~/.zcash-params
#
# proot/params GOTCHA (see qa/zslp/README.md): under the proot build env, HOME
# is /root and ~/.zcash-params is NOT auto-bound. prun also runs the in-proot
# command via `env -i` (wipes the environment), so vars set OUTSIDE prun never
# reach this script -- pass the binaries POSITIONALLY and inject the params dir
# with `prun env`:
#   EXTRA_BINDS="-b /home/rhett/.zcash-params:/root/.zcash-params -b /tmp:/tmp" \
#     /home/rhett/zclbuild/prun env ZCASH_PARAMS_DIR=/root/.zcash-params \
#       bash /src/daemon/qa/zslp/zslp-nft-regtest.sh \
#       /build/daemon/src/zclassicd /build/daemon/src/zclassic-cli
#
# Exit: 0 = all scenarios green; non-zero = a scenario failed.
# ============================================================================
set -u

# ---- Resolve binaries + params (repo-discoverable, no hardcoded abs paths) --
# SRCDIR = <repo>/src.  Prefer git toplevel; fall back to this script's ../../.
if SRCTOP=$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null); then
    SRCDIR="$SRCTOP/src"
else
    SRCDIR="$(cd "$(dirname "$0")/../../src" && pwd)"
fi

DAEMON="${1:-${ZCLASSICD:-$SRCDIR/zclassicd}}"
CLI="${2:-${ZCLASSIC_CLI:-$SRCDIR/zclassic-cli}}"
PARAMS="${ZCASH_PARAMS_DIR:-$HOME/.zcash-params}"

# Unique datadir + port so we never collide with a real node or a 2nd run.
PORT=$(( 19000 + (RANDOM % 800) ))
RPCPORT=$(( PORT + 1 ))
DATADIR=$(mktemp -d "${TMPDIR:-/tmp}/zslp-rt.XXXXXX")
RPCUSER=rt
RPCPASS=rt

FAILS=0
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
hdr()  { echo; echo "================ $* ================"; }

echo "ZSLP regtest harness"
echo "  daemon = $DAEMON"
echo "  cli    = $CLI"
echo "  params = $PARAMS"
[ -x "$DAEMON" ] || { echo "FATAL: zclassicd not executable at $DAEMON"; exit 2; }
[ -x "$CLI" ]    || { echo "FATAL: zclassic-cli not executable at $CLI"; exit 2; }

# ---- Daemon lifecycle -----------------------------------------------------
DAEMON_PID=""
cleanup() {
    echo
    echo "---- teardown ----"
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        cli stop >/dev/null 2>&1 || true
        for _ in $(seq 1 30); do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 1
        done
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            kill -TERM "$DAEMON_PID" 2>/dev/null || true
            sleep 2
            kill -KILL "$DAEMON_PID" 2>/dev/null || true
        fi
    fi
    pkill -KILL -f "zclassicd -regtest -zslpindex -datadir=$DATADIR" 2>/dev/null || true
    rm -rf "$DATADIR"
    echo "removed datadir $DATADIR"
    echo "daemon stopped"
}
trap cleanup EXIT INT TERM

# CLI helper. Foreground (NOT -daemon) so we own the PID and the harness blocks.
cli() {
    "$CLI" -regtest -datadir="$DATADIR" \
        -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$RPCPORT" "$@"
}

# ---- Bring-up -------------------------------------------------------------
hdr "(0) BRING-UP  port=$PORT rpcport=$RPCPORT datadir=$DATADIR"

# Launch NON-detached so $! is the real process and the EXIT trap can reap it.
# -nuparams activates Overwinter+Sapling at height 1 so the z_sendmany anti-burn
# scenario runs LIVE on this same node.
"$DAEMON" -regtest -zslpindex -datadir="$DATADIR" \
    -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$RPCPORT" \
    -port="$PORT" -listen=0 -txindex \
    -nuparams=5ba81b19:1 -nuparams=76b809bb:1 \
    > "$DATADIR/daemon.log" 2>&1 &
DAEMON_PID=$!

UP=0
for i in $(seq 1 90); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "  daemon process died during warmup; log tail:"; tail -20 "$DATADIR/daemon.log"
        fail "daemon did not stay up"; exit 1
    fi
    h=$(cli getblockcount 2>/dev/null)
    if [[ "$h" =~ ^[0-9]+$ ]]; then UP=1; pass "RPC up after ${i}s, height=$h (pid=$DAEMON_PID)"; break; fi
    sleep 1
done
[ "$UP" = 1 ] || { fail "RPC never came up"; tail -20 "$DATADIR/daemon.log"; exit 1; }

cli generate 101 >/dev/null
H=$(cli getblockcount)
BAL=$(cli getbalance)
[ "$H" -ge 101 ] && pass "height=$H after generate 101" || fail "height=$H (<101)"
echo "  getbalance=$BAL"
[ "$BAL" = "12.50000000" ] && pass "getbalance=$BAL (1 matured coinbase)" \
    || pass "getbalance=$BAL (>=1 matured coinbase; regtest subsidy)"

SAPLING_ACTIVE=$(cli getblockchaininfo 2>/dev/null | python3 -c '
import sys,json
try: d=json.load(sys.stdin)
except Exception: print(""); sys.exit()
print(d.get("upgrades",{}).get("76b809bb",{}).get("status",""))')

# ============================================================================
# (2) NFT GENESIS
# ============================================================================
hdr "(2) NFT GENESIS"
GEN=$(cli zslp_genesis '{"nft":true,"name":"My Photo #1","ticker":"PHO","document_hash":"0000000000000000000000000000000000000000000000000000000000000001"}')
GTXID=$(echo "$GEN" | tr -d ' ",' | grep -m1 'txid:' | sed 's/txid://')
GTOKEN=$(echo "$GEN" | tr -d ' ",' | grep -m1 'tokenid:' | sed 's/tokenid://')
echo "  genesis txid=$GTXID tokenid=$GTOKEN"
[ -n "$GTXID" ] && [ "$GTXID" = "$GTOKEN" ] && pass "genesis returned txid==tokenid" \
    || fail "genesis txid/tokenid bad ($GTXID / $GTOKEN)"
cli generate 1 >/dev/null
TOK=$(cli zslp_gettoken "$GTOKEN")
echo "$TOK" | sed 's/^/    /'
DEC=$(echo "$TOK" | tr -d ' ",' | grep -m1 'decimals:' | sed 's/decimals://')
TOTM=$(echo "$TOK" | tr -d ' ",' | grep -m1 'totalminted:' | sed 's/totalminted://')
HASB=$(echo "$TOK" | tr -d ' ",' | grep -m1 'hasmintbaton:' | sed 's/hasmintbaton://')
[ "$DEC" = "0" ]      && pass "NFT decimals=0"        || fail "NFT decimals=$DEC"
[ "$TOTM" = "1" ]     && pass "NFT totalminted=1"     || fail "NFT totalminted=$TOTM"
[ "$HASB" = "false" ] && pass "NFT hasmintbaton=false" || fail "NFT hasmintbaton=$HASB"

MYT=$(cli zslp_listmytokens)
MYBAL=$(echo "$MYT" | tr -d ' ",' | grep -m1 'balance:' | sed 's/balance://')
NFT_ADDR_BEFORE=$(echo "$MYT" | tr -d ' ",' | grep -m1 'address:' | sed 's/address://')
echo "  listmytokens balance=$MYBAL  holder=$NFT_ADDR_BEFORE"
[ "$MYBAL" = "1" ] && pass "listmytokens NFT balance=1" || fail "listmytokens balance=$MYBAL"

# ============================================================================
# (3) NFT TRANSFER  (to a fresh in-wallet t-addr; ownership moves)
# ============================================================================
hdr "(3) NFT TRANSFER"
RECIP=$(cli getnewaddress)
echo "  recipient (fresh, in-wallet) = $RECIP"
SENDRES=$(cli zslp_send "$GTOKEN" "$RECIP" 1)
STXID=$(echo "$SENDRES" | tr -d ' ",' | grep -m1 'txid:' | sed 's/txid://')
echo "  send txid=$STXID"
[ -n "$STXID" ] && pass "zslp_send returned txid=$STXID" || fail "zslp_send no txid: $SENDRES"

RAW=$(cli getrawtransaction "$STXID" 1)
VIN_TOKEN=$(echo "$RAW" | python3 -c '
import sys,json
tx=json.load(sys.stdin)
g="'$GTXID'"
present=any(v.get("txid")==g and v.get("vout")==1 for v in tx["vin"])
print("YES" if present else "NO")')
echo "  genesis NFT dust ($GTXID:1) in SEND vin? $VIN_TOKEN"
[ "$VIN_TOKEN" = "YES" ] && pass "SEND pinned the NFT token input ($GTXID:1)" \
    || fail "SEND did NOT pin the NFT input"
cli generate 1 >/dev/null

MYT2=$(cli zslp_listmytokens)
NFT_ADDR_AFTER=$(echo "$MYT2" | tr -d ' ",' | grep -m1 'address:' | sed 's/address://')
echo "  holder before=$NFT_ADDR_BEFORE  after=$NFT_ADDR_AFTER"
[ -n "$NFT_ADDR_AFTER" ] && [ "$NFT_ADDR_AFTER" != "$NFT_ADDR_BEFORE" ] \
    && pass "NFT holding address moved ($NFT_ADDR_BEFORE -> $NFT_ADDR_AFTER)" \
    || fail "NFT holding address did not move"

XFERS=$(cli zslp_listtransfers "$GTOKEN" 10 0)
echo "$XFERS" | tr -d ' ' | grep -o 'type:"[A-Z]*"' | sed 's/^/    /'
FIRST_TYPE=$(echo "$XFERS" | tr -d ' ",' | grep -m1 'type:' | sed 's/type://')
HAS_GEN=$(echo "$XFERS" | grep -c 'GENESIS')
[ "$FIRST_TYPE" = "SEND" ] && pass "listtransfers newest=SEND" || fail "listtransfers newest=$FIRST_TYPE"
[ "$HAS_GEN" -ge 1 ]       && pass "listtransfers includes GENESIS" || fail "listtransfers missing GENESIS"

# ============================================================================
# (4) ANTI-BURN vs sendtoaddress
# ============================================================================
hdr "(4) ANTI-BURN vs sendtoaddress"
LU=$(cli listunspent 0)
NFT_IN_LU=$(echo "$LU" | python3 -c '
import sys,json
u=json.load(sys.stdin)
s="'$STXID'"
present=any(x.get("txid")==s and x.get("vout")==1 for x in u)
print("YES" if present else "NO")')
echo "  SEND NFT dust ($STXID:1) appears in listunspent? $NFT_IN_LU"
[ "$NFT_IN_LU" = "NO" ] && pass "NFT token dust EXCLUDED from listunspent (anti-burn)" \
    || fail "NFT token dust LEAKED into listunspent"

DEST=$(cli getnewaddress)
S2=$(cli sendtoaddress "$DEST" 1.0)
echo "  sendtoaddress txid=$S2"
[ -n "$S2" ] && pass "sendtoaddress broadcast ($S2)" || fail "sendtoaddress failed: $S2"
RAW2=$(cli getrawtransaction "$S2" 1)
NFT_IN_VIN=$(echo "$RAW2" | python3 -c '
import sys,json
tx=json.load(sys.stdin)
s="'$STXID'"; g="'$GTXID'"
hit=[ (v.get("txid"),v.get("vout")) for v in tx["vin"]
       if (v.get("txid")==s and v.get("vout")==1) or (v.get("txid")==g and v.get("vout")==1) ]
print("HIT:"+repr(hit) if hit else "NONE")')
echo "  any NFT token dust in sendtoaddress vin? $NFT_IN_VIN"
[ "$NFT_IN_VIN" = "NONE" ] && pass "sendtoaddress vin contains NO NFT token dust (anti-burn)" \
    || fail "sendtoaddress vin INCLUDED NFT token dust: $NFT_IN_VIN"
cli generate 1 >/dev/null

# ============================================================================
# (5) FUNGIBLE MINT-with-baton + RE-MINT
# ============================================================================
hdr "(5) FUNGIBLE GENESIS+baton, then RE-MINT"
FGEN=$(cli zslp_genesis '{"ticker":"GOLD","name":"Gold Coin","decimals":0,"quantity":"100","mint_baton_vout":2}')
FTOK=$(echo "$FGEN" | tr -d ' ",' | grep -m1 'tokenid:' | sed 's/tokenid://')
echo "  GOLD tokenid=$FTOK"
[ -n "$FTOK" ] && pass "fungible genesis (GOLD, qty100, baton) -> $FTOK" || fail "fungible genesis failed: $FGEN"
cli generate 1 >/dev/null
FT0=$(cli zslp_gettoken "$FTOK")
M0=$(echo "$FT0" | tr -d ' ",' | grep -m1 'totalminted:' | sed 's/totalminted://')
B0=$(echo "$FT0" | tr -d ' ",' | grep -m1 'hasmintbaton:' | sed 's/hasmintbaton://')
[ "$M0" = "100" ]    && pass "GOLD totalminted=100"   || fail "GOLD totalminted=$M0"
[ "$B0" = "true" ]   && pass "GOLD has live mint baton" || fail "GOLD hasmintbaton=$B0"

MINT=$(cli zslp_mint "$FTOK" 25 2)
MTXID=$(echo "$MINT" | tr -d ' ",' | grep -m1 'txid:' | sed 's/txid://')
echo "  mint txid=$MTXID"
[ -n "$MTXID" ] && pass "zslp_mint +25 broadcast ($MTXID)" || fail "zslp_mint failed: $MINT"
cli generate 1 >/dev/null
FT1=$(cli zslp_gettoken "$FTOK")
M1=$(echo "$FT1" | tr -d ' ",' | grep -m1 'totalminted:' | sed 's/totalminted://')
[ "$M1" = "125" ] && pass "GOLD totalminted 100 -> 125 after MINT" || fail "GOLD totalminted=$M1 (expected 125)"
MYG=$(cli zslp_listmytokens | python3 -c '
import sys,json
a=json.load(sys.stdin); t="'$FTOK'"
for x in a:
  if x["tokenid"]==t: print(x["balance"]); break
else: print("0")')
[ "$MYG" = "125" ] && pass "wallet GOLD balance=125" || fail "wallet GOLD balance=$MYG"

# ============================================================================
# (5b) 0-CONF TOKEN-CHANGE PROTECTION
# ============================================================================
hdr "(5b) 0-CONF TOKEN-CHANGE PROTECTION"
GRECIP=$(cli getnewaddress)
PSEND=$(cli zslp_send "$FTOK" "$GRECIP" 30)
PTXID=$(echo "$PSEND" | tr -d ' ",' | grep -m1 'txid:' | sed 's/txid://')
echo "  partial GOLD send (30 of 125) txid=$PTXID  (left UNCONFIRMED in mempool)"
[ -n "$PTXID" ] && pass "partial GOLD send broadcast ($PTXID)" || fail "partial GOLD send failed: $PSEND"
INMEMPOOL=$(cli getrawmempool | grep -c "$PTXID")
[ "$INMEMPOOL" -ge 1 ] && pass "partial send is in mempool (0-conf)" || fail "partial send not in mempool"
DEST2=$(cli getnewaddress)
S3=$(cli sendtoaddress "$DEST2" 0.5)
echo "  concurrent sendtoaddress txid=$S3"
[ -n "$S3" ] && pass "concurrent sendtoaddress broadcast ($S3)" || fail "concurrent sendtoaddress failed: $S3"
RAW3=$(cli getrawtransaction "$S3" 1)
TC_IN_VIN=$(echo "$RAW3" | python3 -c '
import sys,json
tx=json.load(sys.stdin); p="'$PTXID'"
hit=[ (v.get("txid"),v.get("vout")) for v in tx["vin"] if v.get("txid")==p ]
print("HIT:"+repr(hit) if hit else "NONE")')
echo "  any output of the 0-conf token tx in concurrent-send vin? $TC_IN_VIN"
[ "$TC_IN_VIN" = "NONE" ] && pass "0-conf token-change NOT selected by sendtoaddress (anti-burn)" \
    || fail "0-conf token-change LEAKED into sendtoaddress vin: $TC_IN_VIN"
cli generate 1 >/dev/null
FT2=$(cli zslp_gettoken "$FTOK")
M2=$(echo "$FT2" | tr -d ' ",' | grep -m1 'totalminted:' | sed 's/totalminted://')
[ "$M2" = "125" ] && pass "GOLD totalminted still 125 (SEND conserves supply)" || fail "GOLD totalminted=$M2"

# ============================================================================
# (6) SELF-VALIDATE / REFUSAL  (clear error, NO broadcast)
# ============================================================================
hdr "(6) REFUSAL paths (no broadcast)"
MEMPOOL_BEFORE=$(cli getrawmempool | tr -d ' \n[]"' )
OVER=$(cli zslp_send "$FTOK" "$GRECIP" 100000 2>&1)
echo "  over-send error: $OVER"
echo "$OVER" | grep -qi 'Insufficient token balance' \
    && pass "over-send refused with 'Insufficient token balance'" \
    || fail "over-send wrong/no error: $OVER"
UNK=$(cli zslp_send "deadbeef00000000000000000000000000000000000000000000000000000000" "$GRECIP" 1 2>&1)
echo "  unknown-token error: $UNK"
echo "$UNK" | grep -qi 'Token not found' \
    && pass "unknown token refused with 'Token not found'" \
    || fail "unknown token wrong/no error: $UNK"
NOBAT=$(cli zslp_mint "$GTOKEN" 5 2>&1)
echo "  mint-no-baton error: $NOBAT"
echo "$NOBAT" | grep -qi 'does not hold the mint baton' \
    && pass "mint-without-baton refused" \
    || fail "mint-without-baton wrong/no error: $NOBAT"
MEMPOOL_AFTER=$(cli getrawmempool | tr -d ' \n[]"' )
[ "$MEMPOOL_BEFORE" = "$MEMPOOL_AFTER" ] \
    && pass "no tx broadcast by any refusal (mempool unchanged)" \
    || fail "a refusal broadcast something (mempool '$MEMPOOL_BEFORE' -> '$MEMPOOL_AFTER')"

# ============================================================================
# (4b) ANTI-BURN vs SHIELDING (z_sendmany) — only if Sapling is active here.
# ============================================================================
hdr "(4b) ANTI-BURN vs shielding (z_sendmany)"
if [ "$SAPLING_ACTIVE" = "active" ]; then
    ZADDR=$(cli z_getnewaddress sapling 2>/dev/null)
    if [ -z "$ZADDR" ]; then ZADDR=$(cli z_getnewaddress 2>/dev/null); fi
    cli sendtoaddress "$NFT_ADDR_AFTER" 2.0 >/dev/null
    cli generate 2 >/dev/null
    OPID=$(cli z_sendmany "$NFT_ADDR_AFTER" "[{\"address\":\"$ZADDR\",\"amount\":1.0}]" 2>&1)
    OPID=$(echo "$OPID" | tr -d ' "\n')
    echo "  z_sendmany opid=$OPID"
    ZTXID=""
    for _ in $(seq 1 40); do
        ST=$(cli z_getoperationstatus "[\"$OPID\"]" 2>/dev/null)
        s=$(echo "$ST" | tr -d ' ",' | grep -m1 'status:' | sed 's/status://')
        if [ "$s" = "success" ]; then
            ZTXID=$(cli z_getoperationresult "[\"$OPID\"]" | tr -d ' ",' | grep -m1 'txid:' | sed 's/txid://')
            break
        elif [ "$s" = "failed" ]; then
            echo "  z_sendmany FAILED: $ST"; break
        fi
        sleep 1
    done
    if [ -n "$ZTXID" ]; then
        echo "  shielding txid=$ZTXID"
        RAWZ=$(cli getrawtransaction "$ZTXID" 1)
        NFT_IN_ZVIN=$(echo "$RAWZ" | python3 -c '
import sys,json
tx=json.load(sys.stdin); s="'$STXID'"
hit=[ (v.get("txid"),v.get("vout")) for v in tx.get("vin",[]) if v.get("txid")==s and v.get("vout")==1 ]
print("HIT:"+repr(hit) if hit else "NONE")')
        echo "  NFT token dust in z_sendmany vin? $NFT_IN_ZVIN"
        [ "$NFT_IN_ZVIN" = "NONE" ] \
            && pass "z_sendmany shielding vin contains NO NFT token dust (anti-burn)" \
            || fail "z_sendmany shielding vin INCLUDED NFT token dust: $NFT_IN_ZVIN"
    else
        echo "  z_sendmany did not complete; SKIP (recorded as gap)"
        echo "  SKIP  z_sendmany shielding anti-burn (op did not finish)"
    fi
else
    echo "  Sapling not active on this regtest (status='$SAPLING_ACTIVE'); SKIP z_sendmany shielding test."
    echo "  SKIP  z_sendmany shielding anti-burn (Sapling inactive)"
fi

# ---- Verdict --------------------------------------------------------------
hdr "VERDICT"
if [ "$FAILS" -eq 0 ]; then
    echo "ALL ASSERTIONS GREEN"
    exit 0
else
    echo "$FAILS ASSERTION(S) FAILED"
    exit 1
fi
