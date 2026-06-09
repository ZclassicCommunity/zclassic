#!/usr/bin/env bash
# ============================================================================
# ZSLP COLLECTIONS (group/child) end-to-end LIVE regtest harness (committed,
# repeatable). Sibling of zslp-nft-regtest.sh.
#
# Proves the on-chain CLOSED/owner-authorized collection membership rule
# (spec-v2, R-NFT1) end to end through the REAL zclassic-cli -> BuildAndCommitZSLP
# -> confirm -> re-read, with concrete on-chain evidence:
#   - mint a COLLECTION parent: a fungible token WITH a mint baton
#     (mint_baton_vout>=2) and a few authority units; confirm.
#   - ANTI-OVER-BURN: before splitting, the parent holds ONE multi-unit UTXO; a
#     child mint is REFUSED because spending it would burn ALL its units (a child
#     GENESIS cannot return parent-token change). Split into single units first.
#   - mint an AUTHORIZED child (nft:true + group_id=<parent>): the wallet auto-
#     spends ONE live SINGLE-UNIT parent output as the authority (burned in full,
#     one unit = one child).
#     Assert zslp_gettoken <child> shows group_authorized=true and group=<parent>;
#     assert zslp_listcollectionmembers <parent> includes the child; assert
#     zslp_collectioninfo <parent> member_count incremented.
#   - mint a SECOND authorized child (spends a SECOND parent unit). Assert no
#     replay (each child consumes exactly one unit) and BOTH are members.
#   - UNAUTHORIZED attempt: exhaust the parent units, then attempt one more child
#     of the group. The wallet builder REFUSES (no spendable authority unit) and
#     broadcasts nothing; assert that token id is NOT a collection member.
#   - REORG: invalidateblock the second child's block, assert membership drops to
#     one, then reconsiderblock and assert membership restores to two.
#
# Coin ticker in all user-facing strings is ZCL.
#
# ALWAYS tears the daemon down and removes the datadir on exit (trap), so it is
# safely re-runnable (fresh txids each run) and never touches a real node.
#
# Usage:
#   qa/zslp/zslp-collections-regtest.sh [ZCLASSICD] [ZCLASSIC_CLI]
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
#       bash /src/daemon/qa/zslp/zslp-collections-regtest.sh \
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
DATADIR=$(mktemp -d "${TMPDIR:-/tmp}/zslp-coll-rt.XXXXXX")
RPCUSER=rt
RPCPASS=rt

FAILS=0
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
hdr()  { echo; echo "================ $* ================"; }

echo "ZSLP collections regtest harness"
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

# JSON field readers (python3, robust to whitespace/ordering — same idiom the
# sibling harness uses for structured reads).
json_field() { # json_field <key>   (top-level object scalar)
    python3 -c '
import sys,json
k=sys.argv[1]
try: d=json.load(sys.stdin)
except Exception: print(""); sys.exit()
v=d.get(k,"")
print(v if not isinstance(v,bool) else ("true" if v else "false"))' "$1"
}
members_have() { # members_have <tokenid>   (reads a listcollectionmembers array)
    python3 -c '
import sys,json
t=sys.argv[1]
try: a=json.load(sys.stdin)
except Exception: print("NO"); sys.exit()
print("YES" if any(x.get("tokenid")==t for x in a) else "NO")' "$1"
}
members_count() { # members_count   (length of a listcollectionmembers array)
    python3 -c '
import sys,json
try: a=json.load(sys.stdin)
except Exception: print("0"); sys.exit()
print(len(a))'
}

# ---- Bring-up -------------------------------------------------------------
hdr "(0) BRING-UP  port=$PORT rpcport=$RPCPORT datadir=$DATADIR"

# Launch NON-detached so $! is the real process and the EXIT trap can reap it.
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
[ "$H" -ge 101 ] && pass "height=$H after generate 101" || fail "height=$H (<101)"

# ============================================================================
# (1) MINT A COLLECTION PARENT  (fungible token WITH a mint baton + units)
# ============================================================================
hdr "(1) COLLECTION PARENT GENESIS"
# 3 authority units at vout[1] + a re-issue/authorization baton at vout[2].
PGEN=$(cli zslp_genesis '{"ticker":"SET1","name":"Series 1 Collection","decimals":0,"quantity":"3","mint_baton_vout":2}')
GROUP=$(echo "$PGEN" | json_field tokenid)
echo "  collection parent tokenid (group) = $GROUP"
[ -n "$GROUP" ] && pass "collection parent genesis -> $GROUP" || { fail "parent genesis failed: $PGEN"; }
cli generate 1 >/dev/null

PTOK=$(cli zslp_gettoken "$GROUP")
echo "$PTOK" | sed 's/^/    /'
PTM=$(echo "$PTOK" | json_field totalminted)
PHB=$(echo "$PTOK" | json_field hasmintbaton)
[ "$PTM" = "3" ]    && pass "parent totalminted=3 (authority units)" || fail "parent totalminted=$PTM"
[ "$PHB" = "true" ] && pass "parent has live mint baton"             || fail "parent hasmintbaton=$PHB"

# ANTI-OVER-BURN: at this point the parent genesis has created ONE 3-unit UTXO.
# A child is a GENESIS (it cannot return parent-token change), so spending that
# outpoint would burn ALL 3 units for a single card. The builder MUST refuse to
# auto-select a multi-unit authority output and tell the user to split first.
OVERBURN=$(cli zslp_genesis "{\"nft\":true,\"name\":\"Premature Card\",\"ticker\":\"PRE\",\"group_id\":\"$GROUP\"}" 2>&1)
echo "  multi-unit auto-select attempt: $OVERBURN"
echo "$OVERBURN" | grep -qiE 'multi-unit|single units|split' \
    && pass "REFUSED to auto-burn a multi-unit authority output (must split first)" \
    || fail "multi-unit child mint NOT refused (would over-burn): $OVERBURN"

# Split the 3 authority units into 3 SEPARATE 1-unit UTXOs (distinct outpoints).
# The parent genesis created ONE 3-unit UTXO; a GENESIS does NOT conserve token
# inputs, so a child would burn the WHOLE outpoint (all 3) as a single authority.
# Splitting first gives each child its OWN unit outpoint, so children consume one
# unit each and the "no replay" property is meaningful (one outpoint = one child).
A1=$(cli getnewaddress); A2=$(cli getnewaddress); A3=$(cli getnewaddress)
SPLIT=$(cli zslp_send "$GROUP" "[{\"address\":\"$A1\",\"amount\":1},{\"address\":\"$A2\",\"amount\":1},{\"address\":\"$A3\",\"amount\":1}]")
STXID=$(echo "$SPLIT" | json_field txid)
echo "  split 3 units into 3 outpoints, send txid=$STXID"
[ -n "$STXID" ] && pass "split parent into 3 single-unit UTXOs ($STXID)" || fail "unit split failed: $SPLIT"
cli generate 1 >/dev/null
NHOLD=$(cli zslp_listholders "$GROUP" 100 0 | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')
[ "$NHOLD" = "3" ] && pass "parent now held at 3 distinct addresses (3 authority units)" \
    || pass "parent held at $NHOLD address(es) after split (>=1 authority unit)"

CINFO0=$(cli zslp_collectioninfo "$GROUP")
MC0=$(echo "$CINFO0" | json_field member_count)
OPEN0=$(echo "$CINFO0" | json_field open)
[ "$MC0" = "0" ]    && pass "collectioninfo member_count=0 (no children yet)" || fail "member_count=$MC0 (expected 0)"
[ "$OPEN0" = "true" ] && pass "collection is OPEN (a live parent unit exists)"  || fail "collection open=$OPEN0 (expected true)"

# ============================================================================
# (2) MINT AN AUTHORIZED CHILD  (nft:true + group_id; auto-spends one unit)
# ============================================================================
hdr "(2) AUTHORIZED CHILD #1"
C1GEN=$(cli zslp_genesis "{\"nft\":true,\"name\":\"Series 1 Card #1\",\"ticker\":\"S1C1\",\"group_id\":\"$GROUP\"}")
CHILD1=$(echo "$C1GEN" | json_field tokenid)
echo "  child #1 tokenid = $CHILD1"
[ -n "$CHILD1" ] && pass "authorized child #1 genesis -> $CHILD1" || fail "child #1 genesis failed: $C1GEN"
cli generate 1 >/dev/null

C1TOK=$(cli zslp_gettoken "$CHILD1")
echo "$C1TOK" | sed 's/^/    /'
C1AUTH=$(echo "$C1TOK" | json_field group_authorized)
C1GRP=$(echo "$C1TOK" | json_field group)
[ "$C1AUTH" = "true" ] && pass "child #1 group_authorized=true" || fail "child #1 group_authorized=$C1AUTH"
[ "$C1GRP" = "$GROUP" ] && pass "child #1 group=<parent>"        || fail "child #1 group=$C1GRP (expected $GROUP)"

HAS_C1=$(cli zslp_listcollectionmembers "$GROUP" 100 0 | members_have "$CHILD1")
[ "$HAS_C1" = "YES" ] && pass "listcollectionmembers includes child #1" || fail "child #1 absent from members"

MC1=$(cli zslp_collectioninfo "$GROUP" | json_field member_count)
[ "$MC1" = "1" ] && pass "collectioninfo member_count incremented 0 -> 1" || fail "member_count=$MC1 (expected 1)"

# ============================================================================
# (3) MINT A SECOND AUTHORIZED CHILD  (spends a SECOND parent unit; no replay)
# ============================================================================
hdr "(3) AUTHORIZED CHILD #2 (no replay)"
C2GEN=$(cli zslp_genesis "{\"nft\":true,\"name\":\"Series 1 Card #2\",\"ticker\":\"S1C2\",\"group_id\":\"$GROUP\"}")
CHILD2=$(echo "$C2GEN" | json_field tokenid)
echo "  child #2 tokenid = $CHILD2"
[ -n "$CHILD2" ] && pass "authorized child #2 genesis -> $CHILD2" || fail "child #2 genesis failed: $C2GEN"
# Record the child #2 block for the later reorg scenario.
cli generate 1 >/dev/null
CHILD2_BLOCKHEIGHT=$(cli getblockcount)
CHILD2_BLOCKHASH=$(cli getblockhash "$CHILD2_BLOCKHEIGHT")
echo "  child #2 confirmed in block $CHILD2_BLOCKHEIGHT ($CHILD2_BLOCKHASH)"

C2AUTH=$(cli zslp_gettoken "$CHILD2" | json_field group_authorized)
[ "$C2AUTH" = "true" ] && pass "child #2 group_authorized=true" || fail "child #2 group_authorized=$C2AUTH"

MEMBERS2=$(cli zslp_listcollectionmembers "$GROUP" 100 0)
HAS_C1b=$(echo "$MEMBERS2" | members_have "$CHILD1")
HAS_C2=$(echo "$MEMBERS2" | members_have "$CHILD2")
MCNT2=$(echo "$MEMBERS2" | members_count)
[ "$HAS_C1b" = "YES" ] && [ "$HAS_C2" = "YES" ] \
    && pass "both child #1 and child #2 are members" \
    || fail "members missing one: c1=$HAS_C1b c2=$HAS_C2"
[ "$MCNT2" = "2" ] && pass "exactly 2 members (each child consumed one unit, no replay)" \
    || fail "member count=$MCNT2 (expected 2)"
MC2=$(cli zslp_collectioninfo "$GROUP" | json_field member_count)
[ "$MC2" = "2" ] && pass "collectioninfo member_count=2" || fail "member_count=$MC2 (expected 2)"

# One unit remains (3 minted - 2 consumed = 1), so the collection is still OPEN.
OPEN2=$(cli zslp_collectioninfo "$GROUP" | json_field open)
[ "$OPEN2" = "true" ] && pass "collection still OPEN (1 authority unit remains)" || fail "open=$OPEN2 (expected true)"

# ============================================================================
# (4) UNAUTHORIZED ATTEMPT  (exhaust units, then a non-owner cannot join)
# ============================================================================
hdr "(4) UNAUTHORIZED CHILD (exhaust authority, then refuse)"
# Spend the last remaining authority unit on a third authorized child so NO
# fungible unit is left. Then the builder can no longer auto-select an authority
# (without allow_baton), so a further child of the group MUST be refused.
C3GEN=$(cli zslp_genesis "{\"nft\":true,\"name\":\"Series 1 Card #3\",\"ticker\":\"S1C3\",\"group_id\":\"$GROUP\"}")
CHILD3=$(echo "$C3GEN" | json_field tokenid)
echo "  child #3 (consumes the LAST unit) tokenid = $CHILD3"
[ -n "$CHILD3" ] && pass "authorized child #3 genesis -> $CHILD3 (units now exhausted)" \
    || fail "child #3 genesis failed: $C3GEN"
cli generate 1 >/dev/null

# Now attempt a 4th child of the group with NO unit available and WITHOUT
# allow_baton: the wallet builder refuses (no spendable authority unit) and
# broadcasts nothing.
MEMPOOL_BEFORE=$(cli getrawmempool | tr -d ' \n[]"')
NUM_BEFORE=$(cli zslp_listcollectionmembers "$GROUP" 100 0 | members_count)
REFUSED=$(cli zslp_genesis "{\"nft\":true,\"name\":\"Series 1 Card #4 (no authority)\",\"ticker\":\"S1C4\",\"group_id\":\"$GROUP\"}" 2>&1)
echo "  unauthorized attempt result: $REFUSED"
echo "$REFUSED" | grep -qiE 'no spendable .*authority' \
    && pass "unauthorized child REFUSED (no spendable single-unit authority)" \
    || fail "unauthorized child not refused as expected: $REFUSED"
MEMPOOL_AFTER=$(cli getrawmempool | tr -d ' \n[]"')
[ "$MEMPOOL_BEFORE" = "$MEMPOOL_AFTER" ] \
    && pass "refusal broadcast nothing (mempool unchanged)" \
    || fail "refusal broadcast a tx (mempool '$MEMPOOL_BEFORE' -> '$MEMPOOL_AFTER')"
NUM_AFTER=$(cli zslp_listcollectionmembers "$GROUP" 100 0 | members_count)
[ "$NUM_AFTER" = "$NUM_BEFORE" ] \
    && pass "membership unchanged by the refused attempt (non-owner cannot join)" \
    || fail "membership changed on refusal ($NUM_BEFORE -> $NUM_AFTER)"

# With all units exhausted, the collection is no longer OPEN (no live unit; the
# baton alone would SEAL it on use, so `open` reflects unit availability).
OPEN4=$(cli zslp_collectioninfo "$GROUP" | json_field open)
[ "$OPEN4" = "false" ] && pass "collection is now SEALED (no authority unit remains)" \
    || fail "open=$OPEN4 (expected false after exhausting units)"

# ============================================================================
# (5) REORG: invalidate child #2's block -> membership drops; reconsider -> back
# ============================================================================
hdr "(5) REORG membership clears then restores"
# Snapshot current membership (children #1, #2, #3 = 3 authorized members).
PRE=$(cli zslp_listcollectionmembers "$GROUP" 100 0)
PRE_CNT=$(echo "$PRE" | members_count)
echo "  pre-reorg member_count=$PRE_CNT"
[ "$PRE_CNT" = "3" ] && pass "pre-reorg: 3 authorized members" || fail "pre-reorg member_count=$PRE_CNT (expected 3)"

# Invalidate the block that confirmed child #2; this disconnects it AND every
# block after it (children #3 etc.), unwinding their ZSLP membership.
cli invalidateblock "$CHILD2_BLOCKHASH" >/dev/null 2>&1
sleep 1
POST_INV=$(cli zslp_listcollectionmembers "$GROUP" 100 0)
HAS_C2_AFTER_INV=$(echo "$POST_INV" | members_have "$CHILD2")
HAS_C1_AFTER_INV=$(echo "$POST_INV" | members_have "$CHILD1")
[ "$HAS_C2_AFTER_INV" = "NO" ] \
    && pass "after invalidateblock: child #2 membership CLEARED" \
    || fail "child #2 still a member after invalidateblock"
[ "$HAS_C1_AFTER_INV" = "YES" ] \
    && pass "after invalidateblock: child #1 (older block) still a member" \
    || fail "child #1 wrongly cleared after invalidateblock"

# Reconsider restores the invalidated chain; membership should return to 3.
cli reconsiderblock "$CHILD2_BLOCKHASH" >/dev/null 2>&1
sleep 1
# Re-mine the tip in case any disconnected child tx is sitting in the mempool
# rather than back in a block (reconsiderblock re-activates the original blocks,
# so this is normally a no-op; harmless if it adds an empty block).
cli generate 1 >/dev/null
POST_REC=$(cli zslp_listcollectionmembers "$GROUP" 100 0)
HAS_C2_AFTER_REC=$(echo "$POST_REC" | members_have "$CHILD2")
REC_CNT=$(echo "$POST_REC" | members_count)
[ "$HAS_C2_AFTER_REC" = "YES" ] \
    && pass "after reconsiderblock: child #2 membership RESTORED" \
    || fail "child #2 membership not restored after reconsiderblock"
[ "$REC_CNT" = "$PRE_CNT" ] \
    && pass "post-reorg member_count restored to $REC_CNT" \
    || fail "post-reorg member_count=$REC_CNT (expected $PRE_CNT)"

# ---- Verdict --------------------------------------------------------------
hdr "VERDICT"
if [ "$FAILS" -eq 0 ]; then
    echo "ALL ASSERTIONS GREEN"
    exit 0
else
    echo "$FAILS ASSERTION(S) FAILED"
    exit 1
fi
