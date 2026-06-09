#!/usr/bin/env bash
# ============================================================================
# NFT SELL pillar end-to-end LIVE regtest harness (committed, repeatable).
#
# Proves the non-consensus atomic NFT->ZCL sale (mechanism A',
# doc/nft/NFT_SELL_DESIGN.md) on REAL consensus, end to end through the REAL
# zclassic-cli: nft_makeoffer -> nft_verifyoffer -> nft_takeoffer -> confirm,
# asserting with on-chain evidence that in ONE transaction:
#   - the NFT moves to the buyer's address (vout[1]); the seller no longer holds it
#   - the seller is paid the asking price at vout[2]
#   - the final tx vin = [seller NFT input, buyer funding input(s)] and
#     vout = [OP_RETURN, buyer NFT dust, seller payout]
# and proves TAMPER REJECTION:
#   - editing vout[2] price -> the merged tx's vin[0] VerifyScript fails (relay
#     rejects: mandatory-script-verify-flag / non-mandatory)
#   - a forged offer whose vin[0] is NOT the live NFT -> nft_verifyoffer ok=false
#     with a clear reason
#   - nft_takeoffer refuses a !ok offer (no broadcast)
# and proves CANCEL:
#   - nft_canceloffer self-spends the NFT; a later take on the stale blob fails
#
# A "buyer" here is a SECOND wallet address inside the same node funded by the
# seller; the swap is built, the buyer's funding input is appended + signed, and
# the single tx is broadcast + confirmed. (One node, two roles — sufficient to
# prove the atomic on-chain settlement; the offer blob is shared as a string.)
#
# ALWAYS tears the daemon down and removes the datadir on exit (trap).
#
# Usage:
#   qa/zslp/nft-sell-regtest.sh [ZCLASSICD] [ZCLASSIC_CLI]
# Resolution: positional $1/$2, then env ZCLASSICD/ZCLASSIC_CLI, then
# <repo>/src/zclassicd and <repo>/src/zclassic-cli. params: env
# ZCASH_PARAMS_DIR, else ~/.zcash-params.
#
# proot/params GOTCHA (see qa/zslp/README.md): prun runs in-proot via `env -i`,
# so pass binaries POSITIONALLY and inject params with `prun env`:
#   EXTRA_BINDS="-b /home/rhett/.zcash-params:/root/.zcash-params -b /tmp:/tmp" \
#     /home/rhett/zclbuild/prun env ZCASH_PARAMS_DIR=/root/.zcash-params \
#       bash /src/daemon/qa/zslp/nft-sell-regtest.sh \
#       /build/daemon/src/zclassicd /build/daemon/src/zclassic-cli
#
# Exit: 0 = all scenarios green; non-zero = a scenario failed.
# ============================================================================
set -u

# ---- Resolve binaries + params (repo-discoverable) ------------------------
if SRCTOP=$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null); then
    SRCDIR="$SRCTOP/src"
else
    SRCDIR="$(cd "$(dirname "$0")/../../src" && pwd)"
fi
DAEMON="${1:-${ZCLASSICD:-$SRCDIR/zclassicd}}"
CLI="${2:-${ZCLASSIC_CLI:-$SRCDIR/zclassic-cli}}"
PARAMS="${ZCASH_PARAMS_DIR:-$HOME/.zcash-params}"

PORT=$(( 19000 + (RANDOM % 800) ))
RPCPORT=$(( PORT + 1 ))
DATADIR=$(mktemp -d "${TMPDIR:-/tmp}/nft-sell-rt.XXXXXX")
RPCUSER=rt
RPCPASS=rt

FAILS=0
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
hdr()  { echo; echo "================ $* ================"; }

# Extract a top-level JSON string field by key from a value blob (quote-stripped).
jget() { echo "$1" | tr -d ' ",' | grep -m1 "$2:" | sed "s/.*$2://"; }

echo "NFT SELL regtest harness"
echo "  daemon = $DAEMON"
echo "  cli    = $CLI"
echo "  params = $PARAMS"
[ -x "$DAEMON" ] || { echo "FATAL: zclassicd not executable at $DAEMON"; exit 2; }
[ -x "$CLI" ]    || { echo "FATAL: zclassic-cli not executable at $CLI"; exit 2; }

# ---- Daemon lifecycle -----------------------------------------------------
DAEMON_PID=""
cleanup() {
    echo; echo "---- teardown ----"
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        cli stop >/dev/null 2>&1 || true
        for _ in $(seq 1 30); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 1; done
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            kill -TERM "$DAEMON_PID" 2>/dev/null || true; sleep 2
            kill -KILL "$DAEMON_PID" 2>/dev/null || true
        fi
    fi
    pkill -KILL -f "zclassicd -regtest -zslpindex -datadir=$DATADIR" 2>/dev/null || true
    rm -rf "$DATADIR"
    echo "removed datadir $DATADIR"; echo "daemon stopped"
}
trap cleanup EXIT INT TERM

cli() {
    "$CLI" -regtest -datadir="$DATADIR" \
        -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$RPCPORT" "$@"
}

# ---- Bring-up -------------------------------------------------------------
hdr "(0) BRING-UP  port=$PORT rpcport=$RPCPORT datadir=$DATADIR"
"$DAEMON" -regtest -zslpindex -datadir="$DATADIR" \
    -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$RPCPORT" \
    -port="$PORT" -listen=0 -txindex \
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

cli generate 110 >/dev/null
H=$(cli getblockcount)
[ "$H" -ge 110 ] && pass "height=$H after generate 110" || fail "height=$H (<110)"

# ============================================================================
# (1) MINT an NFT (the seller's asset)
# ============================================================================
hdr "(1) NFT GENESIS"
GEN=$(cli zslp_genesis '{"nft":true,"name":"SellMe #1","ticker":"SLM","document_hash":"00000000000000000000000000000000000000000000000000000000000000aa"}')
TOKEN=$(jget "$GEN" tokenid)
echo "  tokenid=$TOKEN"
[ -n "$TOKEN" ] && pass "NFT minted ($TOKEN)" || { fail "genesis failed: $GEN"; exit 1; }
cli generate 1 >/dev/null

# The seller's current NFT holding address.
MYT=$(cli zslp_listmytokens)
SELLER_NFT_ADDR=$(jget "$MYT" address)
echo "  seller NFT holder = $SELLER_NFT_ADDR"

# ============================================================================
# (2) BUYER requests a fresh receive address (handshake)
# ============================================================================
hdr "(2) BUYER nft_requestbuy"
REQ=$(cli nft_requestbuy "{\"tokenId\":\"$TOKEN\"}")
echo "$REQ" | sed 's/^/    /'
BUYER_ADDR=$(jget "$REQ" buyerNftAddr)
[ -n "$BUYER_ADDR" ] && pass "buyer fresh NFT addr = $BUYER_ADDR" || fail "requestbuy gave no address"
[ "$BUYER_ADDR" != "$SELLER_NFT_ADDR" ] && pass "buyer addr differs from seller holder" \
    || fail "buyer addr equals seller holder"

# ============================================================================
# (3) SELLER makes the offer (sealed to the buyer addr)
# ============================================================================
hdr "(3) SELLER nft_makeoffer"
PRICE=300000000   # 3 ZCL in zatoshi
PAYOUT=$(cli getnewaddress)   # seller's payout t-address (track its balance)
echo "  price=$PRICE zat  payout=$PAYOUT"
OFFER=$(cli nft_makeoffer "{\"tokenId\":\"$TOKEN\",\"priceZat\":\"$PRICE\",\"buyerNftAddr\":\"$BUYER_ADDR\",\"payoutAddr\":\"$PAYOUT\"}")
echo "$OFFER" | sed 's/^/    /'
OFFER_BLOB=$(jget "$OFFER" offerBlob)
OFFER_ID=$(jget "$OFFER" offerId)
NFT_OUTPOINT=$(jget "$OFFER" nftOutpoint)
[ -n "$OFFER_BLOB" ] && pass "offer blob produced (id=$OFFER_ID)" || { fail "makeoffer failed: $OFFER"; exit 1; }
echo "  nftOutpoint=$NFT_OUTPOINT"

# The NFT outpoint must now be LOCKED against coin selection.
LOCKED=$(cli listlockunspent)
echo "$LOCKED" | grep -q "$TOKEN" && pass "NFT outpoint is locked (listlockunspent)" \
    || fail "NFT outpoint NOT locked: $LOCKED"

# ============================================================================
# (4) BUYER verifies the offer (mandatory, read-only)
# ============================================================================
hdr "(4) BUYER nft_verifyoffer"
VER=$(cli nft_verifyoffer "{\"offerBlob\":\"$OFFER_BLOB\"}")
echo "$VER" | sed 's/^/    /'
VOK=$(jget "$VER" ok)
VPRICE=$(jget "$VER" priceZat)
VBUYER=$(jget "$VER" buyerNftAddr)
VTOKEN=$(jget "$VER" tokenId)
[ "$VOK" = "true" ]            && pass "verifyoffer ok=true" || fail "verifyoffer ok=$VOK"
[ "$VPRICE" = "$PRICE" ]       && pass "verify price matches ($VPRICE)" || fail "verify price=$VPRICE"
[ "$VBUYER" = "$BUYER_ADDR" ]  && pass "verify buyerNftAddr matches" || fail "verify buyer=$VBUYER"
[ "$VTOKEN" = "$TOKEN" ]       && pass "verify tokenId matches" || fail "verify token=$VTOKEN"

# ============================================================================
# (5) TAMPER REJECTIONS (before any honest broadcast)
# ============================================================================
hdr "(5) TAMPER REJECTIONS"

# Reusable Python helpers (CompactSize read/write) to (de)construct an offer
# blob and re-wrap a tampered partial tx. The blob layout (from rpc/nftoffer.cpp
# CNftOfferBlob) is: magic(4) ver(1) tokenId(32) priceZat(8 LE) payout(str)
# buyer(str) expiry(4 LE) offerHex(str), each str = CompactSize len + bytes.
read_pyhelpers() { cat <<'PYEOF'
import sys,base64,binascii
def rd_cs(raw,i):
    n=raw[i]; i+=1
    if n<253: return n,i
    if n==253: return int.from_bytes(raw[i:i+2],"little"),i+2
    if n==254: return int.from_bytes(raw[i:i+4],"little"),i+4
    return int.from_bytes(raw[i:i+8],"little"),i+8
def rd_str(raw,i):
    n,i=rd_cs(raw,i); return raw[i:i+n],i+n
def wr_cs(n):
    if n<253: return bytes([n])
    if n<0x10000: return b"\xfd"+n.to_bytes(2,"little")
    if n<0x100000000: return b"\xfe"+n.to_bytes(4,"little")
    return b"\xff"+n.to_bytes(8,"little")
def wr_str(b): return wr_cs(len(b))+b
def strip(b):
    b=b.strip()
    return b[len("znftoffer:"):] if b.startswith("znftoffer:") else b
PYEOF
}

# (5a) Forged offer: re-point vin[0] at a NON-NFT live outpoint -> verify FAILS.
# Decode the partial, swap vin[0].prevout to a fresh ordinary UTXO, re-encode,
# wrap a fresh znftoffer blob (so verifyoffer re-derives every field + rejects).
OFFER_HEX=$( { read_pyhelpers; cat <<PYEOF
b=strip("$OFFER_BLOB")
raw=base64.b64decode(b)
i=5+32+8
payout,i=rd_str(raw,i); buyer,i=rd_str(raw,i); i+=4
hexs,i=rd_str(raw,i)
sys.stdout.write(hexs.decode())
PYEOF
} | python3)
echo "  decoded offerHex len=${#OFFER_HEX}"

# Pick a plain (non-NFT) live UTXO to forge vin[0] onto.
FORGE_UTXO=$(cli listunspent 1 | python3 -c '
import sys,json
u=json.load(sys.stdin)
for x in u:
    if x.get("amount",0) and x.get("spendable"):
        print(x["txid"], x["vout"]); break')
FORGE_TXID=$(echo "$FORGE_UTXO" | awk "{print \$1}")
FORGE_VOUT=$(echo "$FORGE_UTXO" | awk "{print \$2}")
echo "  forging vin[0] -> $FORGE_TXID:$FORGE_VOUT (a plain non-NFT UTXO)"

FORGED_HEX=$( { read_pyhelpers; cat <<PYEOF
tx=bytearray(binascii.unhexlify("$OFFER_HEX"))
# Overwinter/Sapling: header(4) + nVersionGroupId(4) then vin count (CompactSize),
# then vin[0].prevout = txid(32 LE) + vout(4 LE).
off=4+4
nin,off=rd_cs(tx,off)
tx[off:off+32]=bytes.fromhex("$FORGE_TXID")[::-1]   # display->internal LE
tx[off+32:off+36]=int("$FORGE_VOUT").to_bytes(4,"little")
sys.stdout.write(binascii.hexlify(tx).decode())
PYEOF
} | python3)

# Re-wrap as a znftoffer blob (header advisory; verify re-derives from hex).
FORGED_BLOB=$( { read_pyhelpers; cat <<PYEOF
magic=b"ZNFT"+bytes([1])
tokenId=bytes.fromhex("$TOKEN")[::-1]
price=int("$PRICE").to_bytes(8,"little")
expiry=(0).to_bytes(4,"little")
blob=magic+tokenId+price+wr_str(b"$PAYOUT")+wr_str(b"$BUYER_ADDR")+expiry+wr_str(b"$FORGED_HEX")
sys.stdout.write("znftoffer:"+base64.b64encode(blob).decode())
PYEOF
} | python3)

FVER=$(cli nft_verifyoffer "{\"offerBlob\":\"$FORGED_BLOB\"}" 2>&1)
FOK=$(jget "$FVER" ok)
echo "  forged verify ok=$FOK"
echo "$FVER" | grep -qi 'reason' && echo "$FVER" | python3 -c '
import sys,json
try:
  d=json.load(sys.stdin)
  for r in d.get("reasons",[]): print("      reason:",r)
except Exception: pass' 2>/dev/null
[ "$FOK" = "false" ] && pass "forged offer (vin[0] not the live NFT) -> verify ok=false" \
    || fail "forged offer was NOT rejected (ok=$FOK)"

# (5b) takeoffer must REFUSE a !ok (forged) offer (no broadcast).
MEMPOOL_BEFORE=$(cli getrawmempool | tr -d ' \n[]"')
FTAKE=$(cli nft_takeoffer "{\"offerBlob\":\"$FORGED_BLOB\"}" 2>&1)
echo "  forged take -> $FTAKE" | head -c 200; echo
echo "$FTAKE" | grep -qi 'verification' && pass "takeoffer refused the forged offer" \
    || fail "takeoffer did NOT refuse the forged offer: $FTAKE"
MEMPOOL_AFTER=$(cli getrawmempool | tr -d ' \n[]"')
[ "$MEMPOOL_BEFORE" = "$MEMPOOL_AFTER" ] && pass "no broadcast from the refused take (mempool unchanged)" \
    || fail "refused take broadcast something"

# (5c) Price-edit: shave a satoshi off vout[2] in the partial. The buyer's
# MANDATORY nft_verifyoffer must reject it (re-derives price from vout[2] and
# finds it no longer matches the header/agreed price). Re-wrap with the header
# still claiming the original price (the on-the-wire attack).
TAMPER_HEX=$( { read_pyhelpers; cat <<PYEOF
tx=bytearray(binascii.unhexlify("$OFFER_HEX"))
# Walk: header(4)+groupid(4), vin (prevout 36 + scriptSig + seq 4), then vout.
off=4+4
nin,off=rd_cs(tx,off)
for _ in range(nin):
    off+=36                        # prevout
    sl,off=rd_cs(tx,off); off+=sl  # scriptSig
    off+=4                         # sequence
nout,off=rd_cs(tx,off)
off+=8; sl,off=rd_cs(tx,off); off+=sl   # vout[0]
off+=8; sl,off=rd_cs(tx,off); off+=sl   # vout[1]
val=int.from_bytes(tx[off:off+8],"little")  # vout[2].nValue
tx[off:off+8]=(val-1).to_bytes(8,"little")  # shave 1 zat off the payout
sys.stdout.write(binascii.hexlify(tx).decode())
PYEOF
} | python3)

TAMPER_BLOB=$( { read_pyhelpers; cat <<PYEOF
magic=b"ZNFT"+bytes([1])
tokenId=bytes.fromhex("$TOKEN")[::-1]
price=int("$PRICE").to_bytes(8,"little")        # header LIES (claims original)
expiry=(0).to_bytes(4,"little")
blob=magic+tokenId+price+wr_str(b"$PAYOUT")+wr_str(b"$BUYER_ADDR")+expiry+wr_str(b"$TAMPER_HEX")
sys.stdout.write("znftoffer:"+base64.b64encode(blob).decode())
PYEOF
} | python3)

PVER=$(cli nft_verifyoffer "{\"offerBlob\":\"$TAMPER_BLOB\"}")
POK=$(jget "$PVER" ok)
echo "$PVER" | python3 -c '
import sys,json
try:
  d=json.load(sys.stdin)
  for r in d.get("reasons",[]): print("      reason:",r)
except Exception: pass' 2>/dev/null
PRICE_REASON=$(echo "$PVER" | grep -ci 'payout) value does not match priceZat')
{ [ "$POK" = "false" ] && [ "$PRICE_REASON" -ge 1 ]; } \
    && pass "price-edit (vout[2] shaved) -> verifyoffer ok=false (price mismatch)" \
    || fail "price-edit not caught by verifyoffer (ok=$POK reason=$PRICE_REASON)"

# (5d) Belt-and-suspenders at the SCRIPT layer: the seller's EXISTING vin[0]
# scriptSig (an ALL signature over the original outputs) must FAIL VerifyScript
# once vout[2] is edited. signrawtransaction with an EMPTY key array uses ONLY a
# temp keystore (NOT the wallet), so it canNOT re-sign vin[0] (no key) — it just
# re-verifies the existing scriptSig and reports it in errors. We supply vin[0]'s
# prevout so the checker has the script+amount.
NFT_OP_TX=$(echo "$NFT_OUTPOINT" | cut -d: -f1)
NFT_OP_N=$(echo "$NFT_OUTPOINT" | cut -d: -f2)
TXO=$(cli gettxout "$NFT_OP_TX" "$NFT_OP_N")
PREV_SPK_HEX=$(echo "$TXO" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"]["hex"])')
PREV_AMT=$(echo "$TXO" | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
PREVTXS="[{\"txid\":\"$NFT_OP_TX\",\"vout\":$NFT_OP_N,\"scriptPubKey\":\"$PREV_SPK_HEX\",\"amount\":$PREV_AMT}]"
SIGN_RES=$(cli signrawtransaction "$TAMPER_HEX" "$PREVTXS" "[]" 2>&1)
SIGN_COMPLETE=$(echo "$SIGN_RES" | python3 -c '
import sys,json
try: print(json.load(sys.stdin).get("complete"))
except: print("err")')
SIGN_VIN0_ERR=$(echo "$SIGN_RES" | python3 -c '
import sys,json
try:
  d=json.load(sys.stdin); errs=d.get("errors",[])
  print("YES" if any(e.get("vout")==int("'$NFT_OP_N'") for e in errs) else "NO")
except: print("NO")')
echo "  signrawtransaction(empty-keys) complete=$SIGN_COMPLETE vin0_err=$SIGN_VIN0_ERR"
{ [ "$SIGN_COMPLETE" = "False" ] && [ "$SIGN_VIN0_ERR" = "YES" ]; } \
    && pass "price-edit breaks the seller's vin[0] signature (VerifyScript fails)" \
    || fail "seller sig still verified after price-edit (complete=$SIGN_COMPLETE vin0_err=$SIGN_VIN0_ERR)"

# (5e) SIGNATURE-TAMPERED offer caught by nft_verifyoffer (the new VerifyScript
# backstop). Edit vout[2].nValue AND rewrite the blob header's priceZat to the
# SAME edited value so EVERY field re-derivation passes (vout[2].value==priceZat,
# addresses match, token matches, vin[0] live) — the ONLY thing now broken is the
# seller's ALL signature, which was made over the ORIGINAL value. Pre-fix this
# slipped past verifyoffer and was only caught at broadcast; now ok MUST be false
# with the VerifyScript reason.
SIGTAMPER_NEWPRICE=$((PRICE - 100000))   # 0.001 ZCL lower than signed value
SIGTAMPER_HEX=$( { read_pyhelpers; cat <<PYEOF
tx=bytearray(binascii.unhexlify("$OFFER_HEX"))
off=4+4
nin,off=rd_cs(tx,off)
for _ in range(nin):
    off+=36
    sl,off=rd_cs(tx,off); off+=sl
    off+=4
nout,off=rd_cs(tx,off)
off+=8; sl,off=rd_cs(tx,off); off+=sl   # vout[0]
off+=8; sl,off=rd_cs(tx,off); off+=sl   # vout[1]
tx[off:off+8]=int("$SIGTAMPER_NEWPRICE").to_bytes(8,"little")  # vout[2].nValue
sys.stdout.write(binascii.hexlify(tx).decode())
PYEOF
} | python3)

# Re-wrap with the header priceZat ALSO set to the edited value (fields consistent).
SIGTAMPER_BLOB=$( { read_pyhelpers; cat <<PYEOF
magic=b"ZNFT"+bytes([1])
tokenId=bytes.fromhex("$TOKEN")[::-1]
price=int("$SIGTAMPER_NEWPRICE").to_bytes(8,"little")   # header MATCHES the edit
expiry=(0).to_bytes(4,"little")
blob=magic+tokenId+price+wr_str(b"$PAYOUT")+wr_str(b"$BUYER_ADDR")+expiry+wr_str(b"$SIGTAMPER_HEX")
sys.stdout.write("znftoffer:"+base64.b64encode(blob).decode())
PYEOF
} | python3)

SVER=$(cli nft_verifyoffer "{\"offerBlob\":\"$SIGTAMPER_BLOB\"}")
SOK=$(jget "$SVER" ok)
echo "$SVER" | python3 -c '
import sys,json
try:
  d=json.load(sys.stdin)
  for r in d.get("reasons",[]): print("      reason:",r)
except Exception: pass' 2>/dev/null
SIG_REASON=$(echo "$SVER" | grep -ci 'VerifyScript failed')
PRICEFIELD_REASON=$(echo "$SVER" | grep -ci 'payout) value does not match priceZat')
# fields must be consistent (no price-field mismatch) so we prove the NEW backstop
# fired, not the old field check.
{ [ "$SOK" = "false" ] && [ "$SIG_REASON" -ge 1 ] && [ "$PRICEFIELD_REASON" -eq 0 ]; } \
    && pass "sig-tampered offer (fields consistent) -> verifyoffer ok=false via VerifyScript" \
    || fail "sig-tamper not caught by the new VerifyScript backstop (ok=$SOK sigReason=$SIG_REASON priceField=$PRICEFIELD_REASON)"

# takeoffer must also refuse the sig-tampered offer (no broadcast).
MEMPOOL_BEFORE_ST=$(cli getrawmempool | tr -d ' \n[]"')
STAKE=$(cli nft_takeoffer "{\"offerBlob\":\"$SIGTAMPER_BLOB\"}" 2>&1)
echo "$STAKE" | grep -qi 'verification' && pass "takeoffer refused the sig-tampered offer" \
    || fail "takeoffer did NOT refuse the sig-tampered offer: $STAKE"
MEMPOOL_AFTER_ST=$(cli getrawmempool | tr -d ' \n[]"')
[ "$MEMPOOL_BEFORE_ST" = "$MEMPOOL_AFTER_ST" ] && pass "no broadcast from the refused sig-tamper take" \
    || fail "refused sig-tamper take broadcast something"

# (5f) ANTI-BURN funding guard: nft_takeoffer must REFUSE explicit fundingInputs
# that include a ZSLP-protected (token/baton) outpoint (nftoffer.cpp ~:789-791).
# The seller's own NFT outpoint ($NFT_OUTPOINT) is a live qty-1 token UTXO — feed
# it as a funding input and prove the buyer-side guard fires (exercising the
# explicit-fundingInputs path, not only the auto-selector).
MEMPOOL_BEFORE_AB=$(cli getrawmempool | tr -d ' \n[]"')
ABTAKE=$(cli nft_takeoffer "{\"offerBlob\":\"$OFFER_BLOB\",\"fundingInputs\":[\"$NFT_OUTPOINT\"]}" 2>&1)
echo "  anti-burn take -> $(echo "$ABTAKE" | head -c 200)"
echo "$ABTAKE" | grep -qi 'anti-burn' && pass "takeoffer refused a ZSLP-token funding input (anti-burn fired)" \
    || fail "takeoffer did NOT refuse the token funding input: $ABTAKE"
MEMPOOL_AFTER_AB=$(cli getrawmempool | tr -d ' \n[]"')
[ "$MEMPOOL_BEFORE_AB" = "$MEMPOOL_AFTER_AB" ] && pass "no broadcast from the refused anti-burn take" \
    || fail "refused anti-burn take broadcast something"

# (5g) OVERSHOOT consent (§2.5): supply ONE large explicit funding input so the
# overpay (funds in - price - dust - fee) far exceeds the dust threshold. Without
# acknowledge:true nft_takeoffer must REFUSE and NAME the overshoot (no broadcast).
BIG_UTXO=$(cli listunspent 1 | python3 -c '
import sys,json
u=sorted(json.load(sys.stdin), key=lambda x:-x.get("amount",0))
for x in u:
    if x.get("spendable") and x.get("amount",0) > 5:   # >5 ZCL => big overshoot
        print(x["txid"], x["vout"]); break')
BIG_TXID=$(echo "$BIG_UTXO" | awk "{print \$1}")
BIG_VOUT=$(echo "$BIG_UTXO" | awk "{print \$2}")
if [ -n "$BIG_TXID" ]; then
    echo "  overshoot funding input -> $BIG_TXID:$BIG_VOUT"
    MEMPOOL_BEFORE_OS=$(cli getrawmempool | tr -d ' \n[]"')
    OSTAKE=$(cli nft_takeoffer "{\"offerBlob\":\"$OFFER_BLOB\",\"fundingInputs\":[\"$BIG_TXID:$BIG_VOUT\"]}" 2>&1)
    echo "  overshoot take (no ack) -> $(echo "$OSTAKE" | head -c 200)"
    echo "$OSTAKE" | grep -qi 'overpay' && echo "$OSTAKE" | grep -qi 'acknowledge:true' \
        && pass "overshoot WITHOUT acknowledge -> refused, names the overpay" \
        || fail "overshoot not refused/named without acknowledge: $OSTAKE"
    MEMPOOL_AFTER_OS=$(cli getrawmempool | tr -d ' \n[]"')
    [ "$MEMPOOL_BEFORE_OS" = "$MEMPOOL_AFTER_OS" ] && pass "no broadcast from the refused overshoot take" \
        || fail "refused overshoot take broadcast something"
else
    fail "could not find a large UTXO to drive the overshoot test"
fi

# ============================================================================
# (6) HONEST TAKE -> atomic swap confirms
# ============================================================================
hdr "(6) BUYER nft_takeoffer (honest)"
# An honest buyer can rarely fund to the exact zat (no change output is possible
# under ALL), so the auto-selected fund overshoots to fee and the §2.5 guard
# requires explicit consent. The honest flow therefore passes acknowledge:true
# (the buyer has run nft_verifyoffer and accepts the small fee overshoot). This
# is the CLEAN swap and it still settles green.
PAYOUT_BAL_BEFORE=$(cli getreceivedbyaddress "$PAYOUT" 0)
TAKE=$(cli nft_takeoffer "{\"offerBlob\":\"$OFFER_BLOB\",\"acknowledge\":true}")
echo "$TAKE" | sed 's/^/    /'
SWAP_TXID=$(jget "$TAKE" txid)
[ -n "$SWAP_TXID" ] && pass "takeoffer broadcast swap tx ($SWAP_TXID)" || { fail "takeoffer failed: $TAKE"; exit 1; }

# Decode the final swap tx: assert vin/vout shape + the seller NFT input present.
RAW=$(cli getrawtransaction "$SWAP_TXID" 1)
echo "  --- decoded swap tx ---"
echo "$RAW" | python3 -c '
import sys,json
tx=json.load(sys.stdin)
print("    vin  count =",len(tx["vin"]))
for k,v in enumerate(tx["vin"]):
    print("      vin[%d]= %s:%s"%(k, v.get("txid"), v.get("vout")))
print("    vout count =",len(tx["vout"]))
for k,o in enumerate(tx["vout"]):
    spk=o["scriptPubKey"]
    addrs=spk.get("addresses",[])
    print("      vout[%d] val=%s type=%s addr=%s"%(k,o["value"],spk.get("type"),addrs))'

# vin[0] is the seller's NFT outpoint.
NFT_TX=$(echo "$NFT_OUTPOINT" | cut -d: -f1)
NFT_N=$(echo "$NFT_OUTPOINT" | cut -d: -f2)
VIN0_OK=$(echo "$RAW" | python3 -c '
import sys,json
tx=json.load(sys.stdin)
v=tx["vin"][0]
print("YES" if v.get("txid")=="'$NFT_TX'" and int(v.get("vout"))==int("'$NFT_N'") else "NO")')
[ "$VIN0_OK" = "YES" ] && pass "swap vin[0] is the seller NFT outpoint ($NFT_OUTPOINT)" \
    || fail "swap vin[0] is NOT the NFT outpoint"

# >=2 inputs (seller NFT + buyer funding); exactly 3 outputs.
NIN=$(echo "$RAW" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["vin"]))')
NOUT=$(echo "$RAW" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["vout"]))')
[ "$NIN" -ge 2 ]  && pass "swap has >=2 inputs (seller NFT + buyer funding) ($NIN)" || fail "swap inputs=$NIN"
[ "$NOUT" -eq 3 ] && pass "swap has exactly 3 outputs (OP_RETURN, NFT dust, payout)" || fail "swap outputs=$NOUT"

# vout[1] pays the buyer addr; vout[2] pays the seller payout addr at the price.
V1_ADDR=$(echo "$RAW" | python3 -c '
import sys,json;tx=json.load(sys.stdin)
print((tx["vout"][1]["scriptPubKey"].get("addresses") or [""])[0])')
V2_ADDR=$(echo "$RAW" | python3 -c '
import sys,json;tx=json.load(sys.stdin)
print((tx["vout"][2]["scriptPubKey"].get("addresses") or [""])[0])')
V2_VAL=$(echo "$RAW" | python3 -c '
import sys,json;tx=json.load(sys.stdin)
print(int(round(tx["vout"][2]["value"]*1e8)))')
[ "$V1_ADDR" = "$BUYER_ADDR" ] && pass "vout[1] pays the buyer NFT addr" || fail "vout[1] addr=$V1_ADDR"
[ "$V2_ADDR" = "$PAYOUT" ]     && pass "vout[2] pays the seller payout addr" || fail "vout[2] addr=$V2_ADDR"
[ "$V2_VAL" = "$PRICE" ]       && pass "vout[2] value == price ($PRICE)" || fail "vout[2] value=$V2_VAL"

# Confirm + assert the LEDGER moved the NFT to the buyer addr.
cli generate 1 >/dev/null
NFT_BAL_BUYER=$(cli zslp_listmytokens | python3 -c '
import sys,json
a=json.load(sys.stdin); t="'$TOKEN'"; b="'$BUYER_ADDR'"
for x in a:
  if x["tokenid"]==t:
    for ad in x.get("addresses",[]):
      if ad["address"]==b: print(ad["balance"]); break
    break
else: print("0")')
echo "  NFT balance at buyer addr after confirm = ${NFT_BAL_BUYER:-0}"
[ "${NFT_BAL_BUYER:-0}" = "1" ] && pass "NFT now credited to the BUYER addr (qty 1)" \
    || fail "NFT not at buyer addr (bal=${NFT_BAL_BUYER:-0})"

# The seller's old holding address no longer holds it.
SELLER_STILL=$(cli zslp_listmytokens | python3 -c '
import sys,json
a=json.load(sys.stdin); t="'$TOKEN'"; s="'$SELLER_NFT_ADDR'"
for x in a:
  if x["tokenid"]==t:
    for ad in x.get("addresses",[]):
      if ad["address"]==s: print(ad["balance"]); break
    else: print("0")
    break
else: print("0")')
[ "${SELLER_STILL:-0}" = "0" ] && pass "seller's old holder no longer holds the NFT" \
    || fail "seller still holds NFT (bal=$SELLER_STILL)"

# The seller is paid: payout addr received >= price (confirmed).
PAYOUT_BAL_AFTER=$(cli getreceivedbyaddress "$PAYOUT" 1)
PAYOUT_ZAT=$(python3 -c "print(int(round(float('$PAYOUT_BAL_AFTER')*1e8)))")
echo "  payout addr received = $PAYOUT_BAL_AFTER ($PAYOUT_ZAT zat)"
[ "$PAYOUT_ZAT" -ge "$PRICE" ] && pass "seller PAID: payout addr received >= price" \
    || fail "seller not paid (received $PAYOUT_ZAT < $PRICE)"

# verifyoffer on the now-filled offer must report it's no longer live.
VER2=$(cli nft_verifyoffer "{\"offerBlob\":\"$OFFER_BLOB\"}")
VOK2=$(jget "$VER2" ok)
[ "$VOK2" = "false" ] && pass "verifyoffer on the FILLED offer -> ok=false (vin[0] spent)" \
    || fail "filled offer still verifies ok=$VOK2"

# listoffers shows it filled.
LIST=$(cli nft_listoffers)
LSTAT=$(echo "$LIST" | python3 -c '
import sys,json
a=json.load(sys.stdin); oid="'$OFFER_ID'"
for x in a:
  if x["offerId"]==oid: print(x["status"]); break
else: print("missing")')
[ "$LSTAT" = "filled" ] && pass "listoffers status=filled" || fail "listoffers status=$LSTAT"

# ============================================================================
# (7) CANCEL: make a 2nd offer, cancel it, prove a stale take fails
# ============================================================================
hdr "(7) CANCEL flow"
# Mint a 2nd NFT to sell, so the cancel test is independent of the filled one.
GEN2=$(cli zslp_genesis '{"nft":true,"name":"CancelMe #2","ticker":"CNL"}')
TOKEN2=$(jget "$GEN2" tokenid)
cli generate 1 >/dev/null
BUYER2=$(cli getnewaddress)
OFFER2=$(cli nft_makeoffer "{\"tokenId\":\"$TOKEN2\",\"priceZat\":\"100000000\",\"buyerNftAddr\":\"$BUYER2\"}")
OBLOB2=$(jget "$OFFER2" offerBlob)
OID2=$(jget "$OFFER2" offerId)
[ -n "$OBLOB2" ] && pass "2nd offer created (id=$OID2)" || fail "2nd makeoffer failed: $OFFER2"

CANCEL=$(cli nft_canceloffer "{\"offerId\":\"$OID2\"}")
CTXID=$(jget "$CANCEL" txid)
[ -n "$CTXID" ] && pass "canceloffer self-spent the NFT ($CTXID)" || fail "cancel failed: $CANCEL"
cli generate 1 >/dev/null

# A take on the stale blob must now fail (vin[0] already spent by the cancel).
STALE=$(cli nft_takeoffer "{\"offerBlob\":\"$OBLOB2\"}" 2>&1)
echo "  stale take -> $(echo "$STALE" | head -c 160)"
echo "$STALE" | grep -qiE 'verification|spent|live' && pass "stale take after cancel is rejected" \
    || fail "stale take was NOT rejected: $STALE"

# The cancelled offer's outpoint is unlocked again.
LOCKED2=$(cli listlockunspent)
echo "$LOCKED2" | grep -q "$(echo "$(jget "$OFFER2" nftOutpoint)" | cut -d: -f1)" \
    && fail "cancelled NFT outpoint still locked" \
    || pass "cancelled NFT outpoint is unlocked"

# ============================================================================
# (8) OVERSHOOT acknowledge:true PROCEEDS and surfaces overshootZat (§2.5)
# ============================================================================
hdr "(8) OVERSHOOT acknowledge path"
# Fresh NFT + offer; fund with ONE big input + acknowledge:true -> the take MUST
# succeed AND report a large overshootZat (the donated miner fee).
GEN3=$(cli zslp_genesis '{"nft":true,"name":"AckMe #3","ticker":"ACK"}')
TOKEN3=$(jget "$GEN3" tokenid)
cli generate 1 >/dev/null
BUYER3=$(cli getnewaddress)
PAYOUT3=$(cli getnewaddress)
OFFER3=$(cli nft_makeoffer "{\"tokenId\":\"$TOKEN3\",\"priceZat\":\"100000000\",\"buyerNftAddr\":\"$BUYER3\",\"payoutAddr\":\"$PAYOUT3\"}")
OBLOB3=$(jget "$OFFER3" offerBlob)
[ -n "$OBLOB3" ] && pass "3rd offer created" || fail "3rd makeoffer failed: $OFFER3"

BIG_UTXO3=$(cli listunspent 1 | python3 -c '
import sys,json
u=sorted(json.load(sys.stdin), key=lambda x:-x.get("amount",0))
for x in u:
    if x.get("spendable") and x.get("amount",0) > 5:
        print(x["txid"], x["vout"]); break')
BIG3_TXID=$(echo "$BIG_UTXO3" | awk "{print \$1}")
BIG3_VOUT=$(echo "$BIG_UTXO3" | awk "{print \$2}")
ACKTAKE=$(cli nft_takeoffer "{\"offerBlob\":\"$OBLOB3\",\"fundingInputs\":[\"$BIG3_TXID:$BIG3_VOUT\"],\"acknowledge\":true}")
echo "$ACKTAKE" | sed 's/^/    /'
ACK_TXID=$(jget "$ACKTAKE" txid)
ACK_OVERSHOOT=$(jget "$ACKTAKE" overshootZat)
[ -n "$ACK_TXID" ] && pass "overshoot WITH acknowledge:true -> take proceeds (txid=$ACK_TXID)" \
    || fail "acknowledge:true take did NOT proceed: $ACKTAKE"
{ [ -n "$ACK_OVERSHOOT" ] && [ "$ACK_OVERSHOOT" -gt 100000 ]; } \
    && pass "overshootZat surfaced in result ($ACK_OVERSHOOT zat donated to fees)" \
    || fail "overshootZat not surfaced/too small ($ACK_OVERSHOOT)"
cli generate 1 >/dev/null
# The big NFT moved to buyer3 -> confirms the acknowledged swap actually settled.
ACK_NFT_BAL=$(cli zslp_listmytokens | python3 -c '
import sys,json
a=json.load(sys.stdin); t="'$TOKEN3'"; b="'$BUYER3'"
for x in a:
  if x["tokenid"]==t:
    for ad in x.get("addresses",[]):
      if ad["address"]==b: print(ad["balance"]); break
    break
else: print("0")')
[ "${ACK_NFT_BAL:-0}" = "1" ] && pass "acknowledged swap settled: NFT now at buyer3" \
    || fail "acknowledged swap did not settle (bal=${ACK_NFT_BAL:-0})"

# ---- Verdict --------------------------------------------------------------
hdr "VERDICT"
if [ "$FAILS" -eq 0 ]; then
    echo "ALL ASSERTIONS GREEN"; exit 0
else
    echo "$FAILS ASSERTION(S) FAILED"; exit 1
fi
