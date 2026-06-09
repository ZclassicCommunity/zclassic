#!/usr/bin/env bash
# ============================================================================
# ZNAM (ZCL Names) end-to-end LIVE regtest harness (committed, repeatable).
#
# Proves the DECENTRALIZED name registry works on REAL consensus, end to end
# through the REAL zclassic-cli, with NO central server:
#   name_register -> name_resolve -> name_update -> name_setrecord ->
#   name_settext -> name_transfer -> (fund new owner) -> name_renew
# and the two invariants that matter most:
#   - FIFS: a SECOND register of an active name is a NO-OP, NOT a consensus
#     failure (the block still validates and connects).
#   - REORG: invalidateblock on the block that registered a name
#     DETERMINISTICALLY reverts the overlay (name_resolve -> null), proving the
#     live-path LIFO undo via the real ChainTip DisconnectBlock signal.
#
# Ownership is the vin[0] P2PKH signer (FIFS). NON-consensus / opt-in: the daemon
# runs with -znamindex; an unchanged node ignores ZNAM OP_RETURNs entirely.
#
# ALWAYS tears the daemon down and removes the datadir on exit (trap).
#
# Usage:  qa/znam/register-update-transfer-renew-reorg.sh [ZCLASSICD] [ZCLASSIC_CLI]
# Exit:   0 = all scenarios green; non-zero = a scenario failed.
# ============================================================================
set -u

if SRCTOP=$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null); then
    SRCDIR="$SRCTOP/src"
else
    SRCDIR="$(cd "$(dirname "$0")/../../src" && pwd)"
fi
DAEMON="${1:-${ZCLASSICD:-$SRCDIR/zclassicd}}"
CLI="${2:-${ZCLASSIC_CLI:-$SRCDIR/zclassic-cli}}"

PORT=$(( 19000 + (RANDOM % 800) ))
RPCPORT=$(( PORT + 1 ))
DATADIR=$(mktemp -d "${TMPDIR:-/tmp}/znam-rt.XXXXXX")
RPCUSER=rt
RPCPASS=rt

FAILS=0
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
hdr()  { echo; echo "================ $* ================"; }
jget() { echo "$1" | tr -d ' ",' | grep -m1 "$2:" | sed "s/.*$2://"; }

echo "ZNAM regtest harness"
echo "  daemon = $DAEMON"
echo "  cli    = $CLI"
[ -x "$DAEMON" ] || { echo "FATAL: zclassicd not executable at $DAEMON"; exit 2; }
[ -x "$CLI" ]    || { echo "FATAL: zclassic-cli not executable at $CLI"; exit 2; }

DAEMON_PID=""
cleanup() {
    echo; echo "---- teardown ----"
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        cli stop >/dev/null 2>&1 || true
        for _ in $(seq 1 30); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 1; done
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$DATADIR"
    echo "removed datadir $DATADIR; daemon stopped"
}
trap cleanup EXIT INT TERM

cli() {
    "$CLI" -regtest -datadir="$DATADIR" \
        -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$RPCPORT" "$@"
}

# ---- Bring-up (NON-consensus name index on) -------------------------------
hdr "(0) BRING-UP  port=$PORT rpcport=$RPCPORT datadir=$DATADIR"
"$DAEMON" -regtest -znamindex -datadir="$DATADIR" \
    -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$RPCPORT" \
    -port="$PORT" -listen=0 \
    -nuparams=5ba81b19:1 -nuparams=76b809bb:1 \
    > "$DATADIR/daemon.log" 2>&1 &
DAEMON_PID=$!

UP=0
for i in $(seq 1 90); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "  daemon died during warmup; log tail:"; tail -20 "$DATADIR/daemon.log"
        fail "daemon did not stay up"; exit 1
    fi
    h=$(cli getblockcount 2>/dev/null)
    if [[ "$h" =~ ^[0-9]+$ ]]; then UP=1; pass "RPC up after ${i}s, height=$h"; break; fi
    sleep 1
done
[ "$UP" = 1 ] || { fail "RPC never came up"; tail -20 "$DATADIR/daemon.log"; exit 1; }
sleep 1   # let the background ZNAM catch-up reach tip + register on the bus

cli generate 110 >/dev/null
# A plain (non-coinbase) spendable coin to OWN names from (realistic + works on
# any network). On regtest coinbase is transparently spendable, but we create a
# normal output anyway so the path matches mainnet usage.
ALICE=$(cli getnewaddress)
cli sendtoaddress "$ALICE" 50 >/dev/null
cli generate 1 >/dev/null
pass "funded owner address $ALICE"

# ---- (1) REGISTER + RESOLVE ----------------------------------------------
hdr "(1) name_register + name_resolve"
ONION="abcdefghijklmnop234567qrstuvwx.onion"
REG=$(cli name_register "alice" 1 "$ONION" "$ALICE")
echo "$REG" | sed 's/^/    /'
TXID=$(jget "$REG" txid)
[ -n "$TXID" ] && pass "register broadcast (txid=$TXID)" || { fail "register failed: $REG"; exit 1; }
cli generate 1 >/dev/null
RES=$(cli name_resolve "alice")
echo "$RES" | grep -q "$ONION"        && pass "resolve shows primary onion value" || fail "resolve missing value: $RES"
echo "$RES" | grep -q "$ALICE"        && pass "resolve owner == $ALICE"           || fail "owner mismatch: $RES"
echo "$RES" | grep -q '"status": "active"' && pass "status active"                || fail "not active: $RES"

# ---- (2) FIFS conflict is a NO-OP, not a consensus failure ---------------
hdr "(2) FIFS: second register of an active name is a no-op (block still valid)"
H_BEFORE=$(cli getblockcount)
cli name_register "alice" 1 "evil$ONION" "$ALICE" >/dev/null 2>&1 || true
cli generate 1 >/dev/null
H_AFTER=$(cli getblockcount)
[ "$H_AFTER" -gt "$H_BEFORE" ] && pass "chain advanced ($H_BEFORE -> $H_AFTER) — no consensus failure" \
    || fail "chain did not advance (conflict caused a consensus failure?)"
RES2=$(cli name_resolve "alice")
echo "$RES2" | grep -q "$ONION" && ! echo "$RES2" | grep -q "evil" \
    && pass "owner/value unchanged (FIFS no-op)" || fail "FIFS conflict mutated state: $RES2"

# ---- (3) UPDATE primary --------------------------------------------------
hdr "(3) name_update"
cli name_update "alice" 2 "zs1aliceupdatedprimary" >/dev/null
cli generate 1 >/dev/null
RES=$(cli name_resolve "alice")
echo "$RES" | grep -q "zs1aliceupdatedprimary" && pass "primary updated to zaddr" || fail "update not applied: $RES"

# ---- (4) SET_RECORD (multi-coin) -----------------------------------------
hdr "(4) name_setrecord (btc)"
cli name_setrecord "alice" 4 "bc1qalicebtcexample" >/dev/null
cli generate 1 >/dev/null
RES=$(cli name_resolve "alice")
echo "$RES" | grep -q "bc1qalicebtcexample" && pass "btc record present" || fail "setrecord not applied: $RES"

# ---- (5) SET_TEXT --------------------------------------------------------
hdr "(5) name_settext (url)"
cli name_settext "alice" "url" "https://alice.example" >/dev/null
cli generate 1 >/dev/null
RES=$(cli name_resolve "alice")
echo "$RES" | grep -q "alice.example" && pass "text record present" || fail "settext not applied: $RES"

# ---- (6) TRANSFER --------------------------------------------------------
hdr "(6) name_transfer"
BOBADDR=$(cli getnewaddress)
cli name_transfer "alice" "$BOBADDR" >/dev/null
cli generate 1 >/dev/null
RES=$(cli name_resolve "alice")
echo "$RES" | grep -q "$BOBADDR" && pass "owner transferred to $BOBADDR" || fail "transfer not applied: $RES"
# old owner can no longer update
cli name_update "alice" 1 "shouldfail.onion" >/dev/null 2>&1
cli generate 1 >/dev/null
RES=$(cli name_resolve "alice")
! echo "$RES" | grep -q "shouldfail" && pass "old owner update rejected (no-op)" || fail "old owner still controls: $RES"

# ---- (7) RENEW by the new owner (fund it first) --------------------------
hdr "(7) fund new owner + name_renew"
cli sendtoaddress "$BOBADDR" 10 >/dev/null
cli generate 1 >/dev/null
EXP_BEFORE=$(jget "$(cli name_info alice)" expiryHeight)
cli name_renew "alice" >/dev/null
cli generate 1 >/dev/null
EXP_AFTER=$(jget "$(cli name_info alice)" expiryHeight)
echo "  expiry $EXP_BEFORE -> $EXP_AFTER"
[ -n "$EXP_AFTER" ] && [ "$EXP_AFTER" -gt "$EXP_BEFORE" ] && pass "renew extended expiry" \
    || fail "renew did not extend expiry ($EXP_BEFORE -> $EXP_AFTER)"

# ---- (8) REORG undo (the decisive test) ----------------------------------
hdr "(8) reorg: invalidateblock reverts a registration"
cli name_register "bob" 1 "bob1234567.onion" "$BOBADDR" >/dev/null
cli generate 1 >/dev/null
BOBBLOCK=$(cli getbestblockhash)
RESB=$(cli name_resolve "bob")
echo "$RESB" | grep -q "bob1234567.onion" && pass "bob registered + active pre-reorg" || fail "bob not active: $RESB"
cli invalidateblock "$BOBBLOCK" >/dev/null
sleep 1
RESB2=$(cli name_resolve "bob" 2>/dev/null)
if [ -z "$RESB2" ] || echo "$RESB2" | grep -qx 'null'; then
    pass "reorg reverted bob (name_resolve -> null) — live LIFO undo works"
else
    fail "bob NOT reverted after invalidateblock: $RESB2"
fi
# alice (registered in earlier, still-active blocks) survives the reorg
RESA=$(cli name_resolve "alice" 2>/dev/null)
echo "$RESA" | grep -q "$BOBADDR" && pass "alice survived the reorg (owner intact)" || fail "alice lost after reorg: $RESA"

# ---- summary -------------------------------------------------------------
hdr "RESULT"
if [ "$FAILS" -eq 0 ]; then echo "ALL ZNAM SCENARIOS GREEN"; else echo "$FAILS scenario(s) FAILED"; fi
exit $(( FAILS > 0 ? 1 : 0 ))
