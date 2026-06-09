# Selling a ZClassic NFT for ZCL — non-consensus sell/trade design

> **REMOVED — shielded data channel / on-chain private files.** Any reference below to a
> shielded-pool private sale or private negotiation "over the ZDC1 channel" (`src/datachannel/`) is
> **obsolete**: the ZDC1 / shielded data-channel capability has been **removed entirely** from the
> daemon. ZClassic deliberately provides **no wallet path to store arbitrary files on-chain**. The
> sell/offer design itself is unaffected.

**Status:** design + **BUILT** — the daemon SELL RPCs have landed (atomic swap
regtest-proven; see the status table at the end). Evidence-driven; supersedes the SELL
sections of `doc/nft/ONCHAIN_TRADES.md` (which is partly wrong about the layout — see §0).
Every load-bearing claim cites `file:line` from this tree. Constraint: **no
consensus change.** Old, unmodified miners and relay nodes (IsStandard /
RequireStandard) must accept and mine every transaction this design produces; we
add only off-consensus wallet tooling + RPC.

Honesty legend (same as ONCHAIN_TRADES.md):
- **trustless** — settlement enforced by consensus; nobody can cheat.
- **trust-minimized** — the *coin* movement is consensus-atomic, but the *NFT
  token semantics* are an off-consensus indexer convention every honest node
  recomputes; a cheat can be *mined* but credits nobody, and is detectable.
- **trusted** — relies on a third party (escrow arbiter) behaving.

---

## (0) The correction that drives this whole design

`ONCHAIN_TRADES.md §2.2` proposes this layout for the atomic swap:

```
vin[0]  = seller NFT dust   (signed SINGLE|ANYONECANPAY)
vout[0] = seller ZCL payout (pinned by SINGLE to vin[0])   ← WRONG
vout[1] = buyer NFT dust
vout[2] = OP_RETURN ZSLP SEND
```

**That transaction is not a valid ZSLP transfer and the buyer would receive
nothing.** Two facts from the live indexer make it impossible:

1. **The ZSLP message is parsed from `vout[0]` ONLY.** `CZSLPIndexer::ParseTx`
   reads `tx.vout[0].scriptPubKey` and requires it to parse as an SLP message;
   anything at `vout[0]` that is not a valid SLP OP_RETURN means *the tx has no
   SLP message* (`src/zslp/zslpindexer.cpp:205-234`, esp. 229-234). If `vout[0]`
   is the seller's P2PKH payout, the tx is a non-SLP tx — the SEND never
   happens, and the NFT input the tx spends is simply **burned**
   (`zslpstore.cpp:437-446`: every spent token UTXO is consumed/burned
   regardless of whether a message is present).

2. **SEND credits the token positionally to `vout[1+j]`.** The new owner's dust
   must sit at `vout[1]` (for a single-output SEND), `vout[1+j]` in general
   (`zslpstore.cpp:577-585`). So the OP_RETURN must be `vout[0]` and the buyer's
   NFT dust must be `vout[1]`.

3. **The indexer is now UTXO-bound conservation, not credit-only.** It reads
   `tx.vin`, burns spent token UTXOs, and a SEND is valid only if
   `availIn >= requiredOut` for that token (`zslpstore.cpp:548-588`;
   `WouldBeValid` mirror at `zslpstore.cpp:703-748`). ONCHAIN_TRADES.md's claim
   that ZSLP "never reads `tx.vin`" and "only credits" (its lines 40-45,
   appendix 230-232) is **stale** — the working tree's indexer DOES debit the
   spent NFT input and DOES enforce conservation. Good: that makes the NFT leg
   *trust-minimized* (a forged SEND that doesn't actually spend the live NFT
   UTXO credits nobody), not merely advisory.

Now combine with the sighash rule:

- `SIGHASH_SINGLE` commits the input being signed at index `k` to **only the
  output at the same index `k`** (`src/script/interpreter.cpp:1087-1095`:
  `hashOutputs` = hash of `txTo.vout[nIn]` alone).

So if the seller spends the NFT at `vin[0]` and signs `SINGLE`, the only output
the seller pins is `vout[0]` — which **must be the OP_RETURN** (value 0, no
address, not a payout). The seller therefore **cannot pin their ZCL payout with
`SIGHASH_SINGLE` while also producing a layout the ZSLP indexer accepts.** The
index that SINGLE forces the seller to pin is occupied by the protocol-mandated
OP_RETURN.

**Conclusion:** the per-output `SIGHASH_SINGLE|ANYONECANPAY` "open template"
trick does not fit ZSLP. We need a mechanism where the seller commits to the
*entire* output set (so OP_RETURN@0, buyer-NFT@1, seller-payout@k are all fixed),
and leaves only the *inputs* open for the buyer to fund. That is exactly what
`SIGHASH_ALL|ANYONECANPAY` does. This doc's primary mechanism is built on that,
not on SINGLE.

---

## (1) Mechanisms evaluated

| Mechanism | Fits ZSLP layout? | Atomic? | Trust | Verdict |
|---|---|---|---|---|
| **A. SINGLE\|ANYONECANPAY open-output swap** (ONCHAIN_TRADES.md) | **NO** — SINGLE pins vout[0]=OP_RETURN, can't pin payout | n/a | — | **rejected** (breaks ZSLP, §0) |
| **A′. ALL\|ANYONECANPAY fixed-template swap** (this doc) | **YES** — seller fixes the whole output set incl. OP_RETURN | **yes (coin legs)** | trust-minimized | **PRIMARY** |
| **B. 2-of-3 P2SH arbiter escrow** | yes (settlement is an ordinary SEND) | no (multi-tx) | **trusted** | **FALLBACK** (high-value / disputed) |
| **C. Shielded-pool private sale** (ZDC1) | n/a | **no** (privacy ⇒ no atomicity, proven) | trusted (sequential) | **not for settlement**; use for private negotiation only |

---

## (2) PRIMARY mechanism — A′: fixed-template `SIGHASH_ALL|ANYONECANPAY` offer

### 2.1 The idea

`ANYONECANPAY` zeroes `hashPrevouts` and `hashSequence`
(`interpreter.cpp:1077-1085`), so a buyer can **append funding inputs** without
invalidating the seller's signature. Plain `ALL` (the `SINGLE`/`NONE`-free base
type) commits to the hash of **all outputs** (`interpreter.cpp:1087-1089`). So
with `ALL|ANYONECANPAY` the seller binds the **complete, exact output set** —
OP_RETURN, buyer's NFT dust, and the seller's payout — and leaves only the input
side open. The buyer may add inputs (and **only** inputs), then sign their own
inputs and broadcast.

This is the inverse of the SINGLE trick: SINGLE fixes one output and opens the
rest; ALL fixes *all* outputs and opens the inputs. ZSLP needs all three outputs
fixed at known indices, so ALL is the correct base type. The cost: the buyer
cannot add a change output to themselves *in this transaction* (any new output
breaks the seller's `ALL` signature). The buyer must instead bring an input (or
inputs) whose value equals payout + buyer-dust + fee *exactly*, or accept that
the remainder becomes fee. This is the central UX problem and §2.5 solves it.

### 2.2 Exact transaction template (the only valid one)

```
nVersion       = 4 (Sapling), nVersionGroupId = 0x892F2085   (CreateNewContextualCMutableTransaction)
nExpiryHeight  = E   (offer deadline; see §2.6)
nLockTime      = 0

vin[0]  = SELLER's NFT-bearing dust UTXO         ← seller signs, ALL|ANYONECANPAY
vin[1..]= BUYER's funding input(s)               ← appended + signed by buyer, ALL|ANYONECANPAY
                                                   (buyer also uses ANYONECANPAY so each
                                                    party signs only their own inputs)

vout[0] = OP_RETURN  ZSLP SEND { tokenId, [1] }  ← value 0; credits qty 1 to vout[1]
vout[1] = BUYER's new NFT dust (P2PKH buyerAddr) ← D sat (fee-rate-derived dust floor); ZSLP new owner
vout[2] = SELLER's ZCL payout (P2PKH sellerAddr) ← the asking price, in zatoshi
```

**`D` is FEE-RATE-DERIVED, not a hardcoded 546.** Compute the dust floor at build
time from the live relay fee rate — `CTxOut::GetDustThreshold = 3 * minRelayTxFee.
GetFee(serializeSize+148)` (`transaction.h:452-467`), ≈ 54 sat at the default
`-minrelaytxfee`. The builder uses a safe multiple of the *current* floor (the
`SLP_TOKEN_DUST = 546` constant is the conventional default and is what the wallet
mint/send path uses today, but if `-minrelaytxfee` is raised network-wide, recompute
`D` dynamically rather than trusting a literal so the output never falls below dust
and gets the tx rejected). Both legs (`vout[1]` and the seller's spent `Vin0`) use
the same derived floor so the fee math (below) nets out.

Three outputs, fixed order, fixed values — **all** committed by the seller's
`ALL` signature. The buyer's only freedom is which inputs to add. This is the
template both wallets hard-code; users never see indices.

Why each position:
- `vout[0]` OP_RETURN: mandatory for ZSLP parse (`zslpindexer.cpp:229-234`).
- `vout[1]` buyer NFT dust: SEND `output_quantities=[1]` credits qty 1 to
  `vout[1+0]=vout[1]` (`zslpstore.cpp:581-585`). Conservation holds: availIn = 1
  (the NFT UTXO at `vin[0]`), requiredOut = 1, `availIn == requiredOut`
  (`WouldBeValid` 735-746 demands exact conservation).
- `vout[2]` seller payout: the price. Plain P2PKH to the seller.

**Fee math (no buyer change output).** Let `P` = price (zatoshi), `D` = the
fee-rate-derived dust floor (buyer NFT dust, computed at build time; ≈ 546 with the
default relay fee), `Vin0` = the NFT dust value (the seller's spent NFT UTXO, also at
the dust floor). Total output value = `0 + D + P`. The buyer's appended inputs
must sum to `S` where:

```
fee = (Vin0 + S) − (D + P)
```

The buyer picks inputs so `S` covers `P + D + fee − Vin0` with the surplus
becoming fee. Because the buyer cannot add a change output without breaking the
seller's `ALL` sig, **any overshoot is donated to miners**. §2.5 is entirely
about not overpaying.

### 2.3 Who signs what — offer → fill

1. **Seller makes the offer (`nft_makeoffer`).** Wallet locates the live NFT
   dust UTXO (`ZSLPFindWalletTokenUtxos`, `zslpwallet.cpp:137-193`). **Precondition:
   the NFT UTXO must be CONFIRMED** — `nft_makeoffer` re-runs the ZSLP self-validate
   (`WouldBeValid`) on the partial, and that reads the **confirmed** indexer store
   (`zslpstore.cpp:703-748`; the indexer is `ChainTip`-only, no mempool/0-conf path),
   so an unconfirmed NFT cannot be validated as the live token; refuse with a clear
   "your NFT is still confirming" reason. The wallet hand-builds the 3-output
   template above (createrawtransaction **cannot** emit the OP_RETURN —
   `rawtransaction.cpp:554-571` only does address outputs — so the tooling assembles
   `vout[0]` from the existing SLP SEND encoder `ZSLPBuildSendOpReturn`/`slp.h`),
   sets `nExpiryHeight = E`, then signs **only `vin[0]`** with
   `signrawtransaction(hex, [nftPrevTx], [], "ALL|ANYONECANPAY")` (the RPC signs only
   inputs it has keys for and leaves the rest — `rawtransaction.cpp:953-979`).
   **Result: `complete:true`.** A single-input `ALL|ANYONECANPAY` signature over a
   COMPLETE, fixed 3-output template is itself complete — `vin[0]` is the only input
   the seller contributes and it is fully signed (there are no other seller inputs
   waiting on a signature). `complete:true` here is correct and expected — it does
   **not** mean the tx is broadcast-ready (it has no funding inputs yet); it means
   the seller's half is finished. **That hex IS the offer.** The wallet also
   **locks the NFT outpoint** against coin selection (`LockCoin`, mirroring
   `zslpwallet.cpp:42-47`) so it can't be spent as fee or double-offered.

2. **Offer shared (§4).** The hex + a small metadata header travels as a file,
   clipboard string, or QR — **never** a web service.

3. **Buyer verifies (`nft_verifyoffer`, mandatory).** Decodes the hex
   (`decoderawtransaction`), checks: `vout[0]` parses as a SEND for `tokenId`
   with `[1]` to `vout[1]`; `vin[0]` is the **live** token UTXO for `tokenId`
   (`zslp_gettoken` + the UTXO is unspent in the live view); `vout[2]` price ==
   advertised price; not expired (`E > tip+3`); and re-runs the ZSLP
   `WouldBeValid` conservation check on the (still-incomplete) tx so the UI can
   promise "you will own this." Surfaces a reason string on any failure.

4. **Buyer fills (`nft_takeoffer`).** The buyer does **NOT** touch any output —
   `vout[1]` (the buyer's NFT-dust address) is already baked into the seller's
   `ALL`-signed output set and **cannot be rewritten** (any output edit invalidates
   `vin[0]`). The offer was **sealed to the buyer's address** at make-offer time via
   the buyer-address handshake (§2.4): the buyer handed the seller a fresh receive
   address (`nft_requestbuy`/copy-paste), the seller baked `vout[1] = buyerNftAddr`
   into the signed template, and `nft_verifyoffer` already confirmed it matches the
   buyer's own key. The buyer therefore only **appends funding input(s) `vin[1..]`**
   chosen by the exact-input selector (§2.5; these funding inputs MUST EXCLUDE all
   ZSLP-protected outpoints — see §2.5/§6 anti-burn), signs the buyer's own inputs
   with `ALL|ANYONECANPAY`, lets `CombineSignatures` (`rawtransaction.cpp:970`) merge
   the seller's pre-existing `vin[0]` scriptSig, then `sendrawtransaction`. (For a
   truly-open listing with no pre-agreed buyer address, use the §2.4 ALT 2-message
   seller-signs-last flow instead — there is no way to keep the offer one-sided AND
   let the buyer choose `vout[1]`, because ZSLP positional crediting forces the
   buyer's address into the seller's signed set.)

5. **Settlement.** The tx confirms wholly or not at all. The seller's NFT UTXO
   is spent **iff** the seller's payout and the buyer's NFT dust exist in the
   same tx (all co-committed by the seller's `ALL` sig). On block connect the
   indexer parses `vout[0]`, burns `vin[0]`, and credits qty 1 to `vout[1]` =
   the buyer (`zslpstore.cpp:548-588`). `zslp_listmytokens` now shows the NFT
   under the buyer.

### 2.4 The vout[1] ownership detail — who names the buyer?

`vout[1]` (buyer's NFT dust address) is part of the seller's `ALL`-signed output
set, so it **cannot be a placeholder the buyer rewrites** — rewriting it would
break the seller's signature. Two correct options:

- **(Chosen) Offer is buyer-specific.** The offer is created *for a specific
  buyer address*: `nft_makeoffer { ..., buyerNftAddr }`. The seller bakes
  `vout[1] = buyerNftAddr` into the signed template. The offer can then only be
  filled by whoever controls funds and wants the NFT at that address. For a
  public listing the buyer first tells the seller (over the §4 channel or a
  one-RPC handshake) a fresh receive address; the seller returns a sealed offer.
  This is a 1-round-trip negotiation, not a fully one-sided post — an honest
  trade-off forced by ZSLP's positional crediting.

- **(Alt) Open offer via a re-sign round.** Seller posts an *unsigned* template
  + price; buyer fills `vout[1]` with their address and their inputs; buyer
  sends it back; seller signs `vin[0]` last. This is fully general but is a
  2-message protocol and the seller signs last (so the seller could withhold —
  no worse than not trading). Use only if a buyer-agnostic listing is required.

The chosen path keeps the seller's commitment one-sided (post-and-forget for a
known buyer address) and avoids a second seller signature. The do-not-make-me-
think flow (§5) hides the address handshake behind "Buy" → wallet auto-sends a
fresh address → seller wallet auto-seals.

### 2.5 Solving "buyer can't add change" — the exact-input problem

Because no buyer change output is allowed (it would break `ALL`), the buyer must
fund with inputs whose total minus payout minus dust equals the fee they're
willing to pay. Three layered tactics, all client-side, all standard:

1. **Pre-sized funding UTXO.** The wallet, when the user taps Buy, first does a
   tiny ordinary self-send creating one UTXO of value exactly
   `P + D + fee` (it knows `Vin0 == D`, the derived dust floor). Then `vin[1]` is
   that single UTXO and the swap has **zero waste**. Cost: one cheap prep tx
   (confirmed or 0-conf; 0-conf is fine since the buyer is spending their own
   output). This is the default. (The prep-tx self-send must also exclude any
   ZSLP-protected outpoints from its own coin selection — never fund the pre-size
   UTXO with a token UTXO.)
2. **Accept-overshoot.** If the user wants one-tap with no prep tx, pick the
   smallest input combination ≥ target and **donate the remainder to fee**,
   showing the user the (usually tiny) overshoot explicitly: "network fee ~X
   (incl. Y rounding)." Honest, never silent.
3. **Seller-funded dust.** The buyer dust at `vout[1]` (value `D`, the derived dust
   floor) is paid from the seller's NFT input value (`Vin0 == D`), so it nets out and
   the buyer only funds `P + fee`. Encoded in the fee math (§2.2).

The pre-sized-UTXO tactic makes A′ as clean as the rejected SINGLE design while
staying ZSLP-correct. **`fundrawtransaction` is forbidden here** for two
reasons: it inserts a change output at a random vout index
(`src/wallet/wallet.cpp:3697-3698`, `GetRandInt`) which breaks the seller's
`ALL` sig, and it adds an output at all (forbidden under `ALL`). The buyer
selector must hand-pick inputs only.

### 2.6 Expiry, cancel, conservation, fee — recap of the guards

- **Expiry.** Set `nExpiryHeight = E` deliberately far out (e.g. +N×1440
  blocks). `createrawtransaction` validates `E ≥ tip + TX_EXPIRING_SOON_THRESHOLD`
  and `E < TX_EXPIRY_HEIGHT_THRESHOLD = 5e8` (`rawtransaction.cpp:514-518`;
  `consensus.h:31`). The default wallet delta (~20 blocks) is far too short, so
  the offer builder sets E explicitly. Offer card shows "Expires in Xd."
- **Cancel = self-spend the NFT UTXO.** `nft_canceloffer` does a 1-output
  self-send of the NFT (a valid ZSLP SEND to the seller's own fresh address),
  which spends `vin[0]`'s prevout. Any outstanding offer referencing it is now
  unfillable: `signrawtransaction`/`sendrawtransaction` will fail "Input not
  found or already spent" (`rawtransaction.cpp:956-958`). Costs one cheap tx.
- **Conservation is enforced by the template + self-validate.** availIn=1,
  requiredOut=1; `WouldBeValid` requires `availIn == requiredOut`
  (`zslpstore.cpp:743-746`), so the NFT is never burned. Both `nft_makeoffer`
  (on the partial) and `nft_takeoffer` (on the final, before broadcast)
  re-run the real parse + `WouldBeValid` — the same self-validate seam
  `BuildAndCommitZSLP` already uses (`zslpwallet.cpp:417-467`).
- **Fee = buyer.** Seller's NFT input value flows to dust; buyer's inputs cover
  payout + dust + fee (§2.2).
- **Anti-burn (both sides).** Seller side: the NFT dust is locked while an offer is
  live; ordinary coin selection already excludes confirmed token UTXOs via
  `fExcludeZSLPTokens` / `ZSLPIsProtectedTokenOutpoint` (`wallet.cpp` anti-burn;
  `zslpwallet.cpp:100-135`). **Buyer side (REQUIRED): the funding inputs the buyer
  appends in `nft_takeoffer` MUST EXCLUDE every ZSLP-protected outpoint** — re-apply
  the same `ZSLPIsProtectedTokenOutpoint` filter to the buyer's funding selection. If
  the buyer accidentally funds the swap with one of their own token UTXOs, the live
  indexer's `ApplyTransaction` debits that spent token input as a burn (the SEND
  declares only the seller's NFT, so the buyer's accidentally-spent token is consumed
  for nothing). The fill builder must hand-pick funding inputs and reject any
  protected outpoint before signing.

### 2.7 Trust statement for A′

- **Trustless for the coin leg:** the seller's `ALL` signature co-commits "spend
  my NFT" with "pay me exactly P at vout[2] and give the buyer the NFT at
  vout[1]." The buyer cannot take the NFT without paying P, and cannot reduce P
  or redirect the NFT, because any output edit invalidates `vin[0]`'s signature.
  The seller cannot take the buyer's money without releasing the NFT, because
  both are the same atomic tx.
- **Trust-minimized for the token leg:** ZSLP attribution is off-consensus.
  But the indexer now debits `vin[0]` and enforces conservation, so a *forged*
  offer (one whose `vin[0]` is not the live NFT) credits the buyer nothing and
  is caught by `nft_verifyoffer` *before* the buyer ever signs. The residual
  trust is only "all honest nodes run the same indexer rules" — which is the
  same assumption the whole NFT feature already rests on.
- **NOT trustless:** the buyer-address handshake (§2.4) and price discovery are
  off-chain; nothing about the *negotiation* is enforced. Only the *final
  settlement* is atomic.

---

## (3) FALLBACK mechanism — B: 2-of-3 P2SH arbiter escrow (trusted)

For high-value or disputed sales where a buyer-specific atomic offer is
insufficient (e.g. cross-party trust is low and an external dispute path is
wanted), use a 2-of-3 P2SH escrow. Primitives confirmed present and tested:
`TX_MULTISIG` + `GetScriptForMultisig` (`src/script/standard.cpp:53,310-317`),
`OP_CHECKMULTISIG` (script-tested `multisig_tests.cpp:65-66`), P2SH always-on
(`main.cpp:2610`).

```
redeem = OP_2 <buyerPubKey> <sellerPubKey> <arbiterPubKey> OP_3 OP_CHECKMULTISIG
```

Flow: buyer funds the P2SH with the price; seller delivers the NFT (an ordinary
ZSLP SEND to the buyer); buyer + seller co-sign the payout release (no arbiter
needed in the happy path). On dispute the **arbiter** co-signs with the honest
party. This is **trusted** — the arbiter can collude — and is **not atomic**
(funding, delivery, and release are separate txs). Offer it only as an opt-in
for off-spec trades, never the default. (Cross-chain HTLCs are out of scope:
CSV/relative timelocks are absent — `script.h:163` OP_NOP3 inert,
`interpreter.cpp:222` — so only absolute-CLTV HTLCs are buildable, which the NFT
sell flow does not need.)

---

## (4) Offer encoding — file / clipboard / QR, no web service

An offer is `{ header || rawHex }`. Header is a tiny, versioned, self-describing
blob so a wallet can render the card *before* trusting the hex:

```
ZNFTOFFER1  (magic)
tokenId       : 32-byte hex
priceZat      : varint
sellerPayout  : address string
buyerNftAddr  : address string (the offer is sealed to this; §2.4)
expiryHeight  : uint32
offerHex      : the partial ALL|ANYONECANPAY tx hex
```

Serialized as base64 of a CBOR/compact-binary struct, prefixed `znftoffer:` for
URI/clipboard handling. Transport options (all offline, none a server):
- **File** `*.znftoffer` — email/airdrop/USB; the GUI registers the extension.
- **Clipboard** — "Copy offer" / "Paste offer" buttons.
- **QR** — the base64 string in a QR for phone-to-desktop; chunked if > QR
  capacity (multi-frame animated QR, standard).
- **Shielded memo (optional, private negotiation only)** — the offer (or just
  a pointer) can ride a 512-byte Sapling memo via the ZDC1 channel
  (`src/datachannel/zdc.{h,cpp}`, currently not yet RPC-wired) so price
  discovery and the address handshake stay private; **settlement is still the
  public tx of §2.** This is mechanism C used correctly (private path, public
  atomic settle) — never as a private settlement, which is provably impossible
  (ONCHAIN_TRADES.md §4: shielded notes carry no script, binding sig is
  single-party whole-tx).

The wallet keeps a **local** offer store (sent + received) for `nft_listoffers`.
There is deliberately no central order book; a community relay could gossip
offer blobs, but it is untrusted plumbing — every wallet re-verifies via
`nft_verifyoffer` and the blob can never move funds on its own.

---

## (5) GUI flow — do-not-make-me-think

**Sell (on an owned NFT card):**
1. "Sell" → sheet: *Price in ZCL* (one field), *Expires in [7 days ▾]*.
2. (If selling to a known buyer) paste/scan the buyer's "request to buy" code;
   else "Create open listing" (uses the §2.4 alt re-sign flow).
3. Tap **List** → wallet calls `nft_makeoffer`, locks the NFT dust, produces the
   offer blob. Shows: "Offer ready — Copy / Save / Show QR. Expires in 7d."
4. The card shows a "Listed" badge + a **Cancel** button (→ `nft_canceloffer`,
   confirmed as "This voids the listing and frees your NFT").

**Buy (from an offer blob):**
1. "Buy an NFT" → Paste / Open file / Scan QR.
2. Wallet auto-runs `nft_verifyoffer`. Card renders: image (from the ZSLP
   document hash via ContentEngine), name, **price**, **"Expires in 6d,"** and a
   green check (verify passed) or amber warning (with the reason).
3. Confirmation sheet: *You pay **P ZCL** (+ ~fee F). You receive: <NFT name>.*
   plus the **honest privacy line**: *"This trade settles publicly on-chain —
   price and addresses are visible. Only negotiation can be private."*
4. Tap **Buy** → wallet (a) creates a pre-sized funding UTXO (§2.5) silently,
   (b) calls `nft_takeoffer`, (c) shows a spinner → **"NFT received"** when the
   indexer credits it. No mention of vout indices, ANYONECANPAY, or templates.

Reuses existing GUI infra: `doRPCWithDefaultErrorHandling` (rpc.cpp), the
ContentEngine/nftImgCache image pipeline, `Settings::getExplorerTxURL` for the
settlement-tx link, and the L0/L1 offscreen harness for tests. Every sell RPC is
new and must get tst_logic + tst_widget coverage (no test exists today — GAP).

---

## (6) RPC API

All non-consensus tooling; each emits a **standard transparent tx** old nodes
relay+mine. Each new RPC needs an entry in `src/rpc/client.cpp` arg-conversion
(numeric/object params) or args arrive as strings — currently only `zslp_*` have
entries (`client.cpp:138-145`), none for sell.

- **`nft_makeoffer { tokenId, priceZat, payoutAddr?, buyerNftAddr, expiryHeight? }`
  → `{ offerBlob, offerId, nftOutpoint }`**
  Finds the live NFT UTXO (**must be CONFIRMED** — the self-validate below reads the
  confirmed indexer store; refuse if still confirming, §2.3 step 1); hand-builds the
  §2.2 template (OP_RETURN SEND@0, buyer dust@1 at the fee-rate-derived dust floor
  `D` sealed to `buyerNftAddr`, payout@2); sets `nExpiryHeight`; signs **only vin[0]**
  with `ALL|ANYONECANPAY` — a single-input `ALL|ANYONECANPAY` sign over the complete
  3-output template returns **`complete:true`** (the seller's only input is fully
  signed; "complete" does not mean broadcast-ready — there are no funding inputs yet);
  locks `nftOutpoint`; returns the base64 offer blob. Re-runs `WouldBeValid` on the
  partial before returning. (`payoutAddr` defaults to a fresh wallet address;
  `expiryHeight` defaults to tip + ~7d of blocks.)

- **`nft_verifyoffer { offerBlob }`
  → `{ ok, tokenId, priceZat, payoutAddr, buyerNftAddr, expiryHeight, reasons[] }`**
  Mandatory safety check. Decodes; confirms `vout[0]` is a SEND of `tokenId`
  crediting `vout[1]`; confirms `vin[0]` is the **live** token UTXO (via
  `zslp_gettoken` + unspent check); confirms `vout[2]` price; confirms not
  expired and NFT not already spent; runs ZSLP `WouldBeValid`. Surfaces every
  failure reason. Read-only — never signs or broadcasts.

- **`nft_takeoffer { offerBlob, fundingInputs?, changeAddr? }`
  → `{ txid }`**
  Calls `nft_verifyoffer` first (refuses if not ok). Selects exact funding
  inputs (§2.5; if none given, auto pre-size). **REQUIRED anti-burn: every funding
  input the buyer appends MUST be filtered through `ZSLPIsProtectedTokenOutpoint`
  and rejected if it is a ZSLP token/baton UTXO** — otherwise `ApplyTransaction`
  burns any token UTXO the buyer accidentally funds with (the SEND only declares the
  seller's NFT). Appends `vin[1..]` only (no new outputs — the buyer touches no
  output; `vout[1]` is sealed to the buyer's address in the seller-signed set, §2.3
  step 4); signs buyer inputs `ALL|ANYONECANPAY`; `CombineSignatures` merges the
  seller's `vin[0]`; final self-validate (real parse + `WouldBeValid`);
  `sendrawtransaction`. (`changeAddr` is used only by the optional pre-size prep tx,
  whose own coin selection must also exclude protected outpoints; never a swap
  output.)

- **`nft_listoffers { mine? }` → `[ { offerId, tokenId, priceZat, expiryHeight, status } ]`**
  Reads the local offer store (sent and received). Status: open / filled /
  expired / canceled, recomputed against the live UTXO set.

- **`nft_canceloffer { offerId }` → `{ txid }`**
  Self-spends the NFT UTXO (a 1-output ZSLP SEND to a fresh own address),
  invalidating any offer that referenced it; unlocks the outpoint.

- **`nft_requestbuy { offerId? | tokenId }` → `{ buyerNftAddr, requestBlob }`**
  Produces the buyer's fresh receive address + a small request blob for the
  §2.4 buyer-address handshake (so the seller can seal a buyer-specific offer).
  Optional convenience; the handshake can also be plain address copy/paste.

*(reused as-is)* `zslp_gettoken`, `zslp_listmytokens`, `zslp_listtransfers`
(ownership/provenance), `decoderawtransaction`, `signrawtransaction`,
`sendrawtransaction`. The only genuinely new daemon plumbing is (a) the OP_RETURN
SEND carrier — already present as the ZSLP SEND encoder used by
`BuildAndCommitZSLP`, so reuse it; `createrawtransaction` still can't emit
OP_RETURN (`rawtransaction.cpp:554-571`) so the offer builder assembles `vout[0]`
directly — and (b) the offer-blob (de)serializer + local store.

---

## (7) Attack surface and mitigations

| Attack | What it tries | Mitigation |
|---|---|---|
| **Fake / forged offer** (vin[0] isn't the live NFT, or SEND malformed) | Get the buyer to pay for an NFT they won't receive | `nft_verifyoffer` is **mandatory** and re-runs the real indexer parse + `WouldBeValid` (`zslpstore.cpp:703-748`) + a live-UTXO check on `vin[0]` *before the buyer signs*. A forged SEND credits the buyer nothing; verify catches it pre-payment. |
| **Price tampering** | Buyer (or relayer) lowers `vout[2]`, or seller raises it after posting | Impossible without breaking the seller's `ALL` sig: `vout[2]` value+address are in `hashOutputs` (`interpreter.cpp:1087-1089`). Any edit ⇒ `VerifyScript` fails (`rawtransaction.cpp:976`); tx is invalid. |
| **NFT redirect** | Buyer makes `vout[1]` pay someone else / themselves at a different addr | Same: `vout[1]` is in the seller's `ALL`-signed output set. The offer is sealed to `buyerNftAddr` (§2.4); editing it invalidates `vin[0]`. |
| **Adding a buyer change output** | Buyer keeps the overpay | Any extra output breaks `ALL`. By design there is no change output; the exact-input selector (§2.5) or honest-overshoot disclosure handles value. |
| **Front-running / offer theft** | A watcher sees the broadcast fill and races a competing tx | The fill spends the seller's specific NFT UTXO (`vin[0]`); a racer would need that same prevout (can't — only the seller signed it) so cannot steal the NFT. A racer *could* try to be the one who fills a **public open** offer (§2.4 alt) first; mitigate by sealing offers to a specific `buyerNftAddr` (the chosen path), which makes the offer fillable only by that buyer. |
| **Double-spend of the NFT before sale** | Seller spends/sells the NFT elsewhere while an offer is live | (a) The wallet **locks** the NFT outpoint while an offer is live; (b) if the seller spends it anyway (e.g. another wallet), the offer's `vin[0]` becomes a spent prevout and the fill fails "already spent" (`rawtransaction.cpp:956-958`); the buyer loses nothing (they never paid). Re-verify at fill time closes the TOCTOU window. |
| **Replay of an old offer** | Re-broadcast a stale offer to re-trigger a sale | The offer's `vin[0]` is a specific UTXO; once filled it is spent and cannot be respent (consensus). `nExpiryHeight` also bounds the window. A second broadcast is a double-spend that consensus rejects. |
| **Free-option / stale-price griefing** | Buyer sits on a long-lived offer as a free option while price moves | Keep `nExpiryHeight` tight relative to volatility; seller can `nft_canceloffer` anytime (cheap self-spend) (§2.6). |
| **Accidental NFT burn (coin selection)** | Wallet spends the NFT dust as ordinary fee/change | Anti-burn already excludes token UTXOs from selection (`fExcludeZSLPTokens` / `ZSLPIsProtectedTokenOutpoint`, `zslpwallet.cpp:100-135`); the offer additionally `LockCoin`s it. |
| **Buyer underpays via input games** | Buyer adds inputs that don't cover payout | Consensus: a tx whose outputs exceed inputs is invalid (it would have negative fee) — `sendrawtransaction` rejects it. Plus `nft_takeoffer` computes funding to cover `P + D + fee`. |
| **Malleated buyer scriptSig** | Third party mauls the broadcast tx | The settlement is a single broadcast; standard malleability concerns apply but cannot change outputs (seller `ALL` sig). Buyer can re-broadcast from their own copy if needed. |
| **Indexer divergence** | A node runs different ZSLP rules and disagrees on ownership | This is the residual trust-minimized assumption. `WouldBeValid`/`ApplyTransaction` are the single shared rule set (`zslpstore.cpp`), pinned by the R-VECTORS gtest corpus; divergence is a node bug, not a protocol cheat. Promoting ZSLP to consensus is the only way to remove it (out of scope, ONCHAIN_TRADES.md §6). |

---

## (8) What is NOT trustless — explicit

1. **The token leg is trust-minimized, not trustless.** ZSLP is off-consensus.
   The coin movement is atomic; the *meaning* "buyer now owns the NFT" holds
   because every honest node recomputes the same indexer result and the
   indexer now enforces UTXO conservation — but the chain itself does not
   validate it. A forgery is detectable (and credits nobody), not chain-blocked.
2. **Negotiation is not enforced.** Price discovery and the buyer-address
   handshake (§2.4) happen off-chain. Either party can walk away before
   settlement.
3. **Privacy and atomicity are mutually exclusive** (proven in
   ONCHAIN_TRADES.md §4: no script on z-notes, single-party whole-tx binding
   sig). The shielded pool can carry **private negotiation**, but settlement is
   a **public transparent tx** — price, both addresses, and the asset are
   visible. Sequential "pay shielded, then deliver NFT" is plain counterparty
   trust; we will never label it atomic.
4. **Escrow (mechanism B) is trusted** — the arbiter can collude. Opt-in only.

---

## (9) Build status / honesty ledger

| Piece | Status |
|---|---|
| Sighash `ALL\|ANYONECANPAY` masking | **present + tested** (`interpreter.cpp:1077-1089`; sighash/transaction tests) |
| `signrawtransaction` partial-sign + sighashtype + CombineSignatures | **present + tested** (`rawtransaction.cpp:911-979`; `rpc_tests.cpp`) |
| ZSLP SEND OP_RETURN encoder (reused for vout[0]) | **present** (`slp.h`, used by `BuildAndCommitZSLP`) |
| ZSLP UTXO-bound conservation + `WouldBeValid` self-validate seam | **present + tested** (`zslpstore.cpp:413-748`; ~103 ZSLP gtests) |
| Anti-burn coin-lock | **present** (`zslpwallet.cpp:100-135`; `wallet.cpp` `fExcludeZSLPTokens`) |
| `createrawtransaction` OP_RETURN | **absent** — builder hand-assembles vout[0] (GAP, but worked around with the existing encoder) |
| `nft_makeoffer/verifyoffer/takeoffer/listoffers/canceloffer/requestbuy` | **built** (`src/rpc/nftoffer.cpp:1094-1104`, register fn `:1106`; regtest `qa/zslp/nft-sell-regtest.sh`, 6 gtests) |
| Offer blob (de)serializer + local store | **built** (`src/rpc/nftoffer.cpp`) |
| GUI sell/buy flow + L0/L1 tests | **unbuilt** (this design); reuses ContentEngine + RPC wrapper + explorer URL |
| Escrow (mechanism B) | **primitives present + tested; flow unbuilt** |

**Bottom line:** A trust-minimized, coin-atomic NFT→ZCL sale is buildable today
on existing consensus with **`SIGHASH_ALL|ANYONECANPAY` over the fixed ZSLP
3-output template** — *not* the SINGLE|ANYONECANPAY design in ONCHAIN_TRADES.md,
which produces a tx the ZSLP indexer rejects (§0). Reconcile ONCHAIN_TRADES.md
to this doc before any implementation.
