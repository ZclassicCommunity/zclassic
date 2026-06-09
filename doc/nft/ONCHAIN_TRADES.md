> ## ⚠️ SUPERSEDED by `NFT_SELL_DESIGN.md`
> The `SIGHASH_SINGLE|ANYONECANPAY` design described below is **WRONG and
> funds-losing** — it pins the seller's payout to `vout[0]`, but `vout[0]` MUST be
> the ZSLP OP_RETURN, so the seller's price is never bound and the seller's NFT
> input is **burned** while the buyer pays nothing back. The correct, build-ready
> design is `doc/nft/NFT_SELL_DESIGN.md` (a fixed-template
> `SIGHASH_ALL|ANYONECANPAY` offer: OP_RETURN@vout[0] / buyer-NFT@vout[1] /
> seller-payout@vout[2]). **Do not implement anything from this file.** It is kept
> only for history. Several factual claims below (notably "ZSLP never reads
> `tx.vin` / only credits") are also **stale** — the live indexer debits spent
> token inputs and enforces conservation (`availIn == requiredOut`). See
> `NFT_SELL_DESIGN.md §0`.

# On-chain NFT ↔ ZCL trades on ZClassic — what's possible and how

**Status:** ⚠️ **SUPERSEDED — see banner above and `NFT_SELL_DESIGN.md`.** This was
a design doc, evidence-driven. Every capability claim below cites `file:line` from this repo (ZClassic = Zcash 2.x fork, Bitcoin Core 0.11–0.12 lineage + Overwinter + Sapling, Equihash PoW). Where a thing is **not** in the code, it is marked *unavailable* / *needs-consensus-change* — we do **not** assume Bitcoin/Zcash upstream behavior survived into ZClassic unless it was read in-tree.

Legend for honesty about trust:
- **trustless** — settlement enforced by consensus; no party can cheat.
- **trust-minimized** — settlement of the *value* is consensus-enforced, but one layer (here: ZSLP token semantics) relies on every node running the same off-consensus indexer rules; a counterparty can be *caught* but the chain itself does not enforce it.
- **trusted** — depends on a third party (e.g. an escrow arbiter) behaving.

---

## (1) Bottom line — what trades are possible

| Trade | Verdict | Mechanism | Trust |
|---|---|---|---|
| **Transparent NFT ↔ transparent ZCL**, atomic single tx | **available** (script layer) | `SIGHASH_SINGLE\|ANYONECANPAY` signed-offer; seller signs only their NFT input + fixed payout, buyer funds the rest | **trust-minimized** — coin legs are consensus-atomic; ZSLP token attribution is indexer-convention, not consensus |
| **Cross-chain NFT ↔ external coin** | **partial** | P2SH HTLC: hashlock + **absolute** CLTV refund | trust-minimized (standard cross-chain free-option risk; **no** relative-timelock because CSV is absent) |
| **Escrowed / disputed sale** | **available** | 2-of-3 P2SH multisig with a human arbiter | **trusted** (the arbiter) |
| **Any leg shielded** (private ZCL or private NFT), atomic | **unavailable** | — | impossible in-codebase |
| **Fully-private programmable asset trade** | **needs-consensus-change** | ZSA-style shielded assets | not present |

**The one honest sentence:** A trustless, atomic NFT↔ZCL trade is achievable **today** only in the **fully transparent** domain, as a single `SIGHASH_SINGLE|ANYONECANPAY` partial-signed transaction; the *coin movement* is consensus-atomic but the *NFT token semantics* are an off-consensus indexer convention (so it's trust-**minimized**, not chain-enforced), and **anything touching the shielded pool cannot be made atomic** because shielded notes carry no script and the Sapling binding signature is built by a single party over the whole transaction.

### Why these verdicts (the five hypotheses, confirmed against source)

1. **SINGLE|ANYONECANPAY masking is preserved on mainnet — CONFIRMED.** ZClassic runs the ZIP-243 (Sapling) sighash. In `SignatureHash()` (`src/script/interpreter.cpp:1069-1156`): `ANYONECANPAY` zeroes `hashPrevouts` (1077-1079) and `hashSequence` (1081-1085) so other parties may add inputs; `SINGLE` commits `hashOutputs` to **only** `vout[nIn]` (1087-1095); and the signed input's own prevout + scriptCode + amount + nSequence are always re-committed (1145-1153) so the signed input and its amount stay bound. `signrawtransaction` accepts `"SINGLE|ANYONECANPAY"` (`src/rpc/rawtransaction.cpp:920`), only signs SINGLE inputs that have a matching output index (965: `i < mergedTx.vout.size()`), merges counterparty sigs via `CombineSignatures` (970), and returns `{hex, complete}` even when incomplete (983-984). Overwinter+Sapling are active at mainnet height 476969 (`src/chainparams.cpp:107-110`).

2. **P2SH + CLTV available; CSV absent — CONFIRMED.** `ConnectBlock` sets script flags `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKDATASIG_SIGOPS` unconditionally — no height gate (`src/main.cpp:2610`); DERSIG/BIP66 is always enforced (2612). `OP_CHECKLOCKTIMEVERIFY` is fully implemented and gated on its flag (`src/script/interpreter.cpp:180-219`). But `OP_NOP3` — the opcode CSV would occupy — is **not** aliased to `OP_CHECKSEQUENCEVERIFY` (`src/script/script.h:163`) and falls into the inert generic-NOP case (`src/script/interpreter.cpp:222-228`). A repo-wide grep for `CHECKSEQUENCEVERIFY` / `CheckSequence` / `SequenceLocks` / `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` returns **nothing**. ⇒ Absolute timelocks work; **relative** timelocks (BIP68/BIP112) do not exist.

3. **Shielded notes have no script — CONFIRMED.** `SpendDescription` is `{cv, anchor, nullifier, rk, zkproof, spendAuthSig}` with **no** `CScript`/`scriptSig`/`scriptPubKey` field (`src/primitives/transaction.h:43-85`); spend authority is a zk proof plus a randomized-key signature only. ⇒ No hashlock, timelock, or covenant can be attached to a z-note.

4. **Sapling binding sig is single-party over the whole tx — CONFIRMED.** `transaction_builder.cpp` issues exactly one `librustzcash_sapling_binding_sig(ctx, mtx.valueBalance, dataToBeSigned, …)` (295-299) from one accumulating proving context, and `dataToBeSigned = SignatureHash(scriptCode, mtx, NOT_AN_INPUT, SigHashType(), 0, …)` (281) — i.e. **SIGHASH_ALL over the whole transaction** (`SigHashType()` defaults to ALL). There is no API to merge a second party's spend description / value-commitment randomness. ⇒ Two mutually-distrusting parties cannot jointly assemble one shielded bundle, and any counterparty edit invalidates the binding/spend-auth signatures.

5. **Fully-private atomic trades ⇒ needs-consensus-change — follows from (3)+(4).** No script on notes + single-party whole-tx binding sig means privacy and atomicity cannot be combined here. Programmable shielded assets (ZSA-style) are absent from the tree.

### The ZSLP reality check (this changes the framing of "NFT")

The task premise — *"owning the NFT = controlling that dust UTXO; transfer = a ZSLP SEND"* — is the **intended** model. **⚠️ STALE: the paragraphs below described an
early credit-only indexer that NO LONGER matches the code.** The live indexer is
now UTXO-bound: it **reads `tx.vin`**, **debits** spent token UTXOs, and **enforces
conservation** (`availIn == requiredOut`) — see `zslpstore.cpp:548-588` and the
`WouldBeValid` mirror at `zslpstore.cpp:703-748`, and `NFT_SELL_DESIGN.md §0`. The
write path (`zslp_genesis` / `zslp_send` / `zslp_mint`) and a wallet anti-burn
fence also now exist. The original (now-incorrect) claims, kept for history:

- ~~The indexer reads only `tx.vout` … It never reads `tx.vin`.~~ **WRONG today** —
  it reads `tx.vin` and debits spent token UTXOs.
- ~~`ApplySend` only credits the recipient … never debits a sender, never checks
  the sender ever held the token, enforces no conservation.~~ **WRONG today** — a
  SEND is valid only if `availIn >= requiredOut` for the token; surplus is token-
  change, and a forged SEND that doesn't spend the live NFT credits nobody.
- ~~The RPC surface is read-only … there is no `zslp_send` / mint / transfer
  builder.~~ **WRONG today** — `zslp_genesis`, `zslp_send`, and `zslp_mint` exist
  (`src/rpc/zslp.cpp`) and `-zslpindex` defaults **ON** (`init.cpp:3272`).
- ZSLP is referenced **nowhere** in `src/main.cpp` or `src/consensus/` (still true —
  ZSLP remains non-consensus).

**Consequence (still true):** an "NFT" here is an off-consensus ledger fact every
honest node recomputes, not a script-custodied consensus asset. The atomic-swap
mechanism below makes the **ZCL payment leg** consensus-atomic and binds it to the
**spending of a specific dust UTXO**; what it cannot do by itself is make the
token's *meaning* consensus-truth. Because the indexer now enforces conservation,
the token leg is **trust-minimized** (a forgery credits nobody), not merely
advisory.

---

## (2) The transparent atomic swap — `SIGHASH_SINGLE|ANYONECANPAY` signed-offer marketplace

This is the recommended, available-today path. The NFT is modeled as **control of one specific transparent dust UTXO** that the ZSLP indexer currently attributes the token to. The seller publishes a *signed half-transaction* (an "offer"); any buyer can complete and broadcast it.

### 2.1 How masking makes a one-sided signed offer possible

Because `ANYONECANPAY` zeroes `hashPrevouts`/`hashSequence` (interpreter.cpp:1077-1085), a buyer may **append funding inputs** without invalidating the seller's signature. Because `SINGLE` commits to **only `vout[nIn]`** (interpreter.cpp:1090-1094), a buyer may **append additional outputs** (the NFT-recipient dust, change) after the one output the seller pinned. The seller's signed input still binds its own prevout + amount (1149-1151), so the seller's NFT UTXO cannot be swapped out and its value cannot be changed. **Net: the seller commits exactly two things — "I spend *this* NFT UTXO" and "I receive *this exact* payout at the same index" — and leaves everything else open.**

### 2.2 Exact transaction layout

`SIGHASH_SINGLE` pins the signed input at index *k* to the output at index *k*. So the seller's NFT input and the seller's payout output must share an index. Use this layout:

```
vin[0]  = seller's NFT-bearing dust UTXO          ← seller signs THIS, SINGLE|ANYONECANPAY
vin[1..]= buyer's funding inputs                   (appended by buyer)

vout[0] = seller's ZCL payout (P2PKH to seller)    ← pinned by SINGLE to vin[0]; the price
vout[1] = buyer's new NFT dust output (P2PKH)       (appended by buyer; ZSLP credits the token here)
vout[2] = OP_RETURN ZSLP SEND message               (appended by buyer/tooling)
vout[3] = buyer's change                            (appended by buyer)
```

Index alignment is the whole game: **seller input index == seller payout index == 0**. The OP_RETURN can sit at any index for *script* purposes, **but** the ZSLP SEND convention credits `outputQuantities[j]` to `vout[1+j]` (`zslpindexer.cpp:181-182`) — so the buyer's NFT dust must land at the vout index the SEND message names (here `vout[1]`, the first credited output). The marketplace tooling owns this alignment; users never see it.

Two structural facts that the tooling must respect:
- **`createrawtransaction` cannot emit an OP_RETURN.** It only accepts valid address outputs via `GetScriptForDestination` (`src/rpc/rawtransaction.cpp:554-571`). The OP_RETURN/SEND carrier must be hand-assembled (see §7 / port `op_return_push.h`) or added by a thin new RPC.
- **Only one OP_RETURN per relayable tx**, ≤ 223 bytes (`TX_NULL_DATA` once: `src/script/standard.cpp:197`; `MAX_OP_RETURN_RELAY = 223`: `src/script/standard.h:34`). A ZSLP SEND fits easily.

### 2.3 Who signs what — the offer → fill flow

1. **Seller makes the offer.** Seller builds a skeleton with `vin[0]` = their NFT UTXO and `vout[0]` = a P2PKH paying *themselves* the asking price. Seller calls `signrawtransaction` with `sighashtype = "SINGLE|ANYONECANPAY"`, signing only that one input (the RPC signs only inputs whose coins/keys it has and skips the rest: `rawtransaction.cpp:953-966`). Result: partially-signed hex, `complete:false` (983-984). **This hex *is* the offer.** It is a self-contained, transferable, take-it-or-leave-it order: anyone who can read it can fill it, and no one can alter the seller's price or asset.

2. **Offer published.** The hex (plus metadata: tokenId, price, sellerPayout index) is posted anywhere — a relay, a gossip topic, a file, the shielded memo channel (§5). No on-chain footprint until filled.

3. **Buyer fills.** Buyer **hand-assembles** funding: appends their inputs (`vin[1..]`), appends `vout[1]` = NFT dust to themselves, appends the OP_RETURN SEND, appends change. Buyer signs **their** inputs with `SIGHASH_ALL` (the default). `CombineSignatures` (`rawtransaction.cpp:970`) merges the seller's pre-existing scriptSig with the buyer's. Buyer `sendrawtransaction`.

4. **Settlement.** The tx either confirms wholly or not at all. The seller's NFT UTXO is consumed **iff** the seller's payout exists in the same tx, because both are co-committed under the seller's one signature. Atomic for the coin legs.

5. **Indexer recognizes the transfer.** On block connect the ZSLP `ValidationInterface` observer parses the OP_RETURN SEND and credits the token to `vout[1]`'s address (`zslpindexer.cpp:174-187`) — i.e. the buyer. Buyer wallet now shows the NFT via `zslp_listmytokens`.

### 2.4 Griefing, partial-fill, fee, and expiry considerations (and mitigations)

- **Do NOT use `fundrawtransaction` on the buyer side.** It inserts change at a **random** vout position (`src/wallet/wallet.cpp:3679-3682`), which would shove the seller's pinned `vout[0]` out of index 0 and **break the SINGLE signature**. The buyer must **hand-place** outputs to keep the seller's payout at its committed index. (Stated explicitly because it is the #1 footgun.)
- **Offer lifetime is bounded, not infinite.** A raw tx carries `nExpiryHeight`. `createrawtransaction` accepts an `expiryheight` arg but rejects "expiring soon" (`nextBlockHeight + TX_EXPIRING_SOON_THRESHOLD`, where the threshold is 3: `src/main.h:71`, check at `rawtransaction.cpp:518`) and caps it below `TX_EXPIRY_HEIGHT_THRESHOLD = 500000000` (`src/consensus/consensus.h:31`, check at 514). The wallet's default delta is only ~20 blocks (`DEFAULT_PRE_BUTTERCUP_TX_EXPIRY_DELTA`, `src/main.h:68`; post-Buttercup scaled, 69) — far too short for a posted offer. **Mitigation:** the offer builder must set a deliberately distant `expiryheight` (e.g. weeks/months of blocks out) and the offer card must show the expiry. After it lapses the seller re-issues. There is no "never-expires" offer via this RPC.
- **Free-option / stale-price griefing.** A posted, long-lived signed offer is a free option to the buyer: the seller is committed at a fixed price until expiry while the market moves. **Mitigation:** keep expiry tight relative to volatility; let the seller cancel by *self-spending the NFT UTXO* (which invalidates the offer, since the offer's `vin[0]` is then a spent prevout — `signrawtransaction` would mark it "Input not found or already spent": `rawtransaction.cpp:956-958`). Cancellation costs one cheap self-send.
- **No partial fills.** An NFT is qty-1 indivisible (ZSLP NFT = decimals 0 / qty 1 / no baton: `src/zslp/slp.h:49-50`), so partial fill is not a concern for single NFTs. For fungible-token lots you would issue separate offers per lot size; SINGLE pins exactly one payout output, so a single offer is one all-or-nothing price.
- **Fee responsibility.** The buyer adds inputs and change, so the **buyer pays the fee** naturally (seller's input value all flows to the pinned payout; buyer's inputs cover payout + dust + fee + change). Tooling computes fee on the buyer side.
- **Accidental NFT burn.** The wallet has **zero ZSLP awareness** (no ZSLP references in `src/wallet/`), so ordinary coin-selection can spend an NFT-bearing dust UTXO as plain coin and the indexer would silently strand the token. **Mitigation:** the marketplace wallet must mark NFT dust outpoints as **locked / non-spendable for normal selection**, and only release them through the offer builder.
- **Token validity is buyer-verified, not chain-verified.** Because `ApplySend` never validates inputs, a malicious seller could publish a tx whose ZSLP SEND is malformed or whose `vin[0]` does not actually carry the live token. **Mitigation (mandatory):** before counter-signing, the buyer verifies via `zslp_gettoken` / `zslp_listtransfers` (+ a UTXO check) that `vin[0]` is the live token-bearing UTXO and that the SEND vout mapping is well-formed. A verifier RPC (§7) should do this so the UX is one click.

---

## (3) Cross-chain + escrow — only the opcodes that audited as available

### 3.1 HTLC (hashlock + **absolute** CLTV refund) — **partial / available with the CSV caveat**

P2SH is mandatory and always-on (`src/main.cpp:2610`; `IsPayToScriptHash` BIP16 pattern at `src/script/script.cpp:230-234`). CLTV is implemented and consensus-active (interpreter.cpp:180-219; `CheckLockTime` at 1210-1244). Hashlock primitives are present (`OP_SHA256`, `OP_HASH160`, `OP_HASH256`, `OP_EQUALVERIFY` in `script.h`). So this redeem script works **wrapped in P2SH**:

```
OP_IF
    OP_SHA256 <H = SHA256(preimage)> OP_EQUALVERIFY
    <recipientPubKey> OP_CHECKSIG
OP_ELSE
    <refundLockHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <refundPubKey> OP_CHECKSIG
OP_ENDIF
```

- **Claim branch:** recipient reveals `preimage`, satisfying the hashlock + their signature.
- **Refund branch:** after `refundLockHeight`, the funder reclaims. The refund spend must set tx `nLockTime >= refundLockHeight` and a non-final `nSequence` on the input (CLTV's anti-bypass requires the input be non-final; `CheckLockTime` at interpreter.cpp:1210-1244). `createrawtransaction` lets you set both `nLockTime` and per-input `nSequence` (`rawtransaction.cpp:504-509, 542-547`).

**Hard caveat — no relative timelocks.** `OP_CHECKSEQUENCEVERIFY`/BIP112 is absent (§1, hypothesis 2). HTLC timeouts must be **absolute block heights**, not "N blocks after funding." This is workable for cross-chain atomic swaps (you pick concrete heights per chain) but rules out Lightning-style relative-locktime channels and any construction that needs a relative refund timer.

**Trust level:** trust-minimized. The preimage reveal links the two legs across chains; standard cross-chain **free-option / premium risk** applies (the party who moves second has an option). Not perfectly trustless, but no third party.

### 3.2 2-of-3 arbiter escrow — **available, but *trusted***

`TX_MULTISIG` template (`m OP_PUBKEYS n OP_CHECKMULTISIG`) and `GetScriptForMultisig` exist (`src/script/standard.cpp:53`), `OP_CHECKMULTISIG` supports up to 20 keys (interpreter.cpp:739-834), and 2-of-3 is relay-standard. Redeem script (P2SH-wrapped):

```
OP_2 <buyerPubKey> <sellerPubKey> <arbiterPubKey> OP_3 OP_CHECKMULTISIG
```

Either buyer+seller cooperate (no arbiter needed) or, on dispute, the **arbiter** co-signs with the honest party. **This is the right tool for human-mediated disputes, and it is explicitly *trusted***: the arbiter is a third party who can collude. It is not trustless; offer it as an opt-in for high-value or off-spec trades, never as the default.

`OP_CHECKDATASIG`/`OP_CHECKDATASIGVERIFY` are also implemented (interpreter.cpp:692-737; opcodes `script.h:173-174`; flag in `main.cpp:2610`), enabling **oracle-gated** script branches (a branch that requires a signature over an external message). This is a bonus primitive — useful for oracle-resolved escrow conditions — but it introduces an oracle trust assumption and is out of scope for the core swap.

---

## (4) The privacy wall — why any shielded leg breaks trustless atomicity

There are **two independent, code-confirmed reasons** a shielded leg cannot be part of a trustless atomic swap. Either alone is fatal.

**Reason A — shielded notes have no script.** `SpendDescription` = `{cv, anchor, nullifier, rk, zkproof, spendAuthSig}` (`src/primitives/transaction.h:43-85`); `OutputDescription` is `{cv, cm, ephemeralKey, encCiphertext, …, zkproof}`; `SaplingNote`/`SproutNote` are pure `{value, keys, randomness}` structs (`src/zcash/Note.hpp:25-51`). **No `CScript` anywhere.** There is no place to attach a hashlock, a timelock, or a covenant to a z-note — so you cannot build an HTLC or a SINGLE-pinned payout on the shielded side at all.

**Reason B — the binding signature is single-party over the whole tx.** The Sapling binding key is the sum of per-spend/per-output value-commitment randomness, all generated **locally inside one builder** (`transaction_builder.cpp:21` generates each `alpha`/`rcv`; the one ctx accumulates them, 187/204/245). The bundle is closed by exactly one `librustzcash_sapling_binding_sig(ctx, mtx.valueBalance, dataToBeSigned, …)` call (295-299), and `dataToBeSigned` is `SignatureHash(…, NOT_AN_INPUT, SigHashType(), …)` = **SIGHASH_ALL over the entire transaction** (281). There is **no API to import a counterparty's spend description or randomness**, and **no `ANYONECANPAY`/`SINGLE` analogue for shielded** sigs — the whole shielded bundle commits to the whole tx, so *any* edit by a counterparty invalidates it. The Sprout/joinsplit path is likewise single-party (one ephemeral ed25519 key signs the whole joinsplit: `src/wallet/asyncrpcoperation_sendmany.cpp:543`).

Combined: a single party must build the entire shielded bundle, signing over the entire transaction — which is the exact opposite of the two-party "each signs only their part" pattern that makes the transparent SINGLE|ANYONECANPAY swap work. **Therefore a mixed trade (e.g. transparent NFT for shielded ZCL) cannot be made atomic in a single transaction**, and no HTLC/covenant can live on a z-note. Privacy + atomicity are mutually exclusive in this codebase.

**Honest downgrade path (not atomic):** you *can* do a **sequential, trust-required** flow — buyer sends shielded ZCL, then seller sends the NFT — but that is plain counterparty trust (whoever moves first can be cheated), not an atomic swap. Don't dress it up as trustless.

---

## (5) The hybrid — private negotiation, public atomic settlement

You cannot make settlement private and atomic. But you **can** keep *negotiation and price discovery* private while settlement is public and atomic. This is the realistic "privacy-respecting marketplace."

**What can be private (off-chain or shielded-memo channel):**
- Discovery, bids, counter-bids, and the eventual price. The shielded **memo field** (the 512-byte encrypted memo carried in an `OutputDescription`'s `encCiphertext`) is a sender→recipient private channel: a buyer can send a tiny shielded note to the seller's z-address carrying an encrypted "I'll take offer X at price P" memo. This reveals only that *some* shielded note moved (standard Sapling metadata), not the parties' identities or the price to the public.
- The matching of buyer↔seller. Off-chain, the parties can exchange the **partial offer hex** privately (over the memo channel, a private relay, or any side channel). Until broadcast, there is **no on-chain trace**.

**What is unavoidably public at settlement:**
- The settlement transaction is **fully transparent** (the swap is transparent-only, §2). On-chain you will see: the seller's NFT UTXO spent, the seller's payout address + amount (the price), the buyer's funding inputs/change, the buyer's new NFT dust, and the ZSLP SEND OP_RETURN. **Price, both parties' transparent addresses, and the asset are public.**
- You **cannot** hide the price by routing the payout through the shielded pool *in the same tx*, because that shielded leg would re-break atomicity (§4).

**The realistic hybrid recipe:** negotiate privately (memo channel / off-chain), agree on a price, exchange the signed partial offer privately, then broadcast one transparent atomic settlement. **Private price discovery + private matchmaking + public, trust-minimized atomic settlement.** Be explicit to users that the *final trade* (price, addresses, asset) is public; only the *path to it* was private.

---

## (6) What would need a consensus change (and why it's out of scope)

To get a **fully-private, atomic** NFT↔ZCL trade you need **programmable shielded assets (ZSA-style)** at the consensus layer. Concretely, the codebase would need:

1. **A predicate/script (or asset-type + spend condition) on shielded notes** — to attach a hashlock/timelock/covenant to a private note (Reason A, §4 — `SpendDescription` has no script today).
2. **A multi-party shielded bundle assembly + a partial/maskable shielded sighash** — so two distrusting parties can each contribute spends/outputs and the binding signature can be assembled jointly (Reason B, §4 — today it's one `librustzcash_sapling_binding_sig` call over a whole-tx SIGHASH_ALL message by a single party).
3. **A consensus-enforced shielded asset type** (ZSA) so the NFT itself is a private, conserved, chain-validated asset rather than a transparent dust UTXO annotated by an off-consensus indexer.

Each requires new circuits, new transaction fields, a network upgrade with an activation height (the `vUpgrades` machinery exists — `src/chainparams.cpp:107-117` — but defining a new upgrade is a hard fork), and an audited Rust crypto backend. **Out of scope for this design**, which is deliberately *no-consensus-change, ship-today*. Separately, even for the transparent path, making the **NFT leg trust-minimized rather than trusted** would benefit from a **UTXO-bound ZSLP rule** (debit-by-spent-input, conservation checked) — that can be done as a stricter non-consensus indexer rule first, and only later promoted to consensus.

---

## (7) API sketch + native UX

### 7.1 RPCs — thin wrappers over existing primitives (DRY: reuse `createrawtransaction` + `signrawtransaction` + `sendrawtransaction`)

The only genuinely new plumbing is (a) an OP_RETURN/data carrier (createrawtransaction lacks one — `rawtransaction.cpp:554-571`) and (b) a ZSLP conservation **verifier** (the indexer doesn't check — `zslpstore.cpp:348-390`). Everything else composes existing RPCs.

- **`nft_makeoffer { tokenId, nftOutpoint, priceZat, payoutAddr, expiryHeight }` → `{ offerHex, offerId }`**
  Builds the skeleton (`vin[0]` = `nftOutpoint`, `vout[0]` = P2PKH `payoutAddr` for `priceZat`), sets `nExpiryHeight = expiryHeight` (validated: ≥ `tip+3`, < 5e8 — §2.4), then internally calls `signrawtransaction(hex, [prevtx], [], "SINGLE|ANYONECANPAY")` to sign only `vin[0]`. Returns the partial hex. Locks `nftOutpoint` against the wallet's coin-selection (anti-burn, §2.4).

- **`nft_takeoffer { offerHex, fundingInputs?, changeAddr, buyerNftAddr }` → `{ txid }`**
  Verifies the offer (calls `nft_verifyoffer` first), **hand-assembles** funding (appends inputs, `vout[1]` = dust to `buyerNftAddr`, the OP_RETURN ZSLP SEND crediting `vout[1]`, change to `changeAddr` — **never** `fundrawtransaction`, §2.4), signs the buyer's inputs SIGHASH_ALL via `signrawtransaction`, then `sendrawtransaction`. Returns txid.

- **`nft_verifyoffer { offerHex }` → `{ ok, tokenId, price, payoutAddr, expiry, reasons[] }`**
  The mandatory safety RPC: confirms `vin[0]` is the live token-bearing UTXO via `zslp_gettoken`/`zslp_listtransfers` + UTXO existence, that the SINGLE-pinned `vout[0]` price matches, that the SEND mapping will credit the buyer's intended output, and that the offer hasn't expired / the NFT UTXO isn't already spent. Surfaces *why* if not ok.

- **`nft_listoffers` / `nft_canceloffer { offerId }`**
  `listoffers` reads the local/relayed offer store. `canceloffer` self-spends the NFT dust UTXO (one cheap tx) to invalidate any outstanding offer referencing it (§2.4).

- *(reused as-is)* `zslp_gettoken`, `zslp_listmytokens`, `zslp_listtransfers` for ownership/provenance display; `decoderawtransaction` for offer inspection.

All of the above are non-consensus tooling: they emit standard transparent transactions and never touch validation, PoW, or the shielded builder.

### 7.2 Native UX — don't-make-me-think

- **"List for sale"** button on any owned NFT card → modal: *price in ZCL*, *expires in [7 days ▾]*. One tap calls `nft_makeoffer`, locks the dust UTXO, and shows the offer card. No mention of SINGLE, vout indices, or expiry heights.
- **Offer cards** (a marketplace grid): NFT image (the image-hash is the ZSLP document hash), name, **price**, **"Expires in 6d"**, and a green **"Buy"** button. A small shield/check badge = `nft_verifyoffer` passed; an amber badge = "verify before buying."
- **"Buy"** → confirmation sheet: *You pay X ZCL + ~fee. You receive: <NFT name>.* One tap calls `nft_takeoffer` (which verifies first, then funds + signs + broadcasts). Spinner → "NFT received" when the indexer credits it.
- **Honest privacy line** in the buy/sell sheets: *"This trade settles publicly on-chain (price and addresses are visible). Negotiation can be private."* — so we never imply a transparent swap is private.
- **Cancel** on your own offer card → `nft_canceloffer`, confirmed as "This frees the NFT and voids the listing."
- **Anti-burn guardrail** in the wallet: NFT dust UTXOs are visually flagged and excluded from ordinary send coin-selection; sending one requires going through the marketplace flow.

---

## Appendix — verdict per capability (with evidence)

| Capability | Verdict | Key evidence |
|---|---|---|
| P2SH / BIP16 | available (consensus, always-on) | `main.cpp:2610`; `script.cpp:230-234` |
| OP_CHECKLOCKTIMEVERIFY / BIP65 | available (consensus, always-on) | `interpreter.cpp:180-219`, `1210-1244`; `main.cpp:2610` |
| OP_CHECKSEQUENCEVERIFY / BIP112 (CSV) | **unavailable** | `script.h:163` (no alias); `interpreter.cpp:222-228` (inert NOP); grep returns nothing |
| Hashlocks (SHA256/HASH160/EQUALVERIFY) | available | `interpreter.cpp:634-658, 499-525` |
| OP_CHECKMULTISIG (≤20 keys, 2-of-3 std) | available | `interpreter.cpp:739-834`; `standard.cpp:53` |
| OP_CHECKDATASIG (oracle branches) | available | `interpreter.cpp:692-737`; `script.h:173-174` |
| Disabled opcodes (CAT/SUBSTR/MUL/… /CODESEPARATOR) | hard-fail | `interpreter.cpp:118-134` |
| ZIP-243 SINGLE\|ANYONECANPAY masking | available (live mainnet) | `interpreter.cpp:1069-1156`; `chainparams.cpp:107-110` |
| signrawtransaction partial-sign + sighashtype | available | `rawtransaction.cpp:911-927, 953-990` |
| createrawtransaction OP_RETURN carrier | **unavailable** (needs new arg/RPC) | `rawtransaction.cpp:554-571` |
| createrawtransaction locktime + expiryheight | available (expiry bounded) | `rawtransaction.cpp:504-527`; `consensus.h:31`; `main.h:71` |
| Script on shielded notes | **unavailable** | `transaction.h:43-85`; `Note.hpp:25-51` |
| Multi-party shielded bundle assembly | **unavailable** | `transaction_builder.cpp:281, 295-299` |
| ZSLP token = consensus-enforced asset | **no** (off-consensus, credit-only) | `zslpstore.cpp:348-390`; `zslpindexer.cpp:160-187`; no refs in `main.cpp`/`consensus/` |
| ZSLP transfer builder RPC | **unavailable** (read-only RPCs) | `rpc/zslp.cpp` |
| Wallet ZSLP/NFT-burn awareness | **unavailable** (anti-burn must be added) | no ZSLP refs in `src/wallet/` |
