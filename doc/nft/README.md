# ZClassic Native NFTs — Documentation Index

This folder specifies **native, no-browser NFTs on ZClassic**: minting any file/image/video,
holding and verifying it, gifting and atomically trading it. Everything here is designed to ride
**unchanged network consensus** (old, unmodified nodes relay and mine these transactions; no
consensus change is ever required). Security comes from a **non-consensus overlay that every
honest wallet re-validates deterministically** — not from the chain rejecting bad transactions.

> **Removed:** the former shielded data-channel / arbitrary-file-transfer capability ("private
> files/NFTs over the shielded data channel", the `z_senddatafile`/`z_listdatatransfers`/
> `z_getdatatransfer` RPCs, the `-datachannel` option, and the ZDC1 codec) has been **removed
> entirely** from the daemon. ZClassic deliberately provides **no wallet path to store arbitrary
> files on-chain**. NFT content is always off-chain, bound to the token only by a `document_hash`
> fingerprint. Doc sections below that still describe the data channel are historical.

> One-line model: **a forgery can be mined, but it credits nobody** — uniqueness/ownership are
> a deterministic function of the confirmed chain that every correct implementation computes
> identically.

> **Build status (dev/testnet):** MINT + VIEW = built (daemon RPCs + native GUI). SELL (NFT⇄ZCL
> atomic swap) = built in the daemon (CLI, regtest-proven); the native GUI for SELL is next.
> SHIELD (the former on-chain private-file data channel) has been **removed** — ZClassic provides
> no wallet path to store arbitrary files on-chain. See **NATIVE_NFT_GUIDE §1** for file:line
> ground truth.

---

## 🏗 For contributors — how protocols are built (read first)

**[PROTOCOL_STANDARD.md](PROTOCOL_STANDARD.md)** — **NORMATIVE.** The single standard for how
*any* ZSLP-family overlay feature (fungible tokens, NFTs, collections, the sell/offer
mechanism) is designed, encoded, versioned, validated, tested, and
documented. Read it before changing or adding a protocol. It encodes the five hard invariants
(never affect consensus · never put files on-chain · security = deterministic re-validation ·
UTXO-bound authority · backward-compatible/append-only), the mandatory layer pipeline
(parser → bridge → indexer → store+undo → wallet+self-validate → RPC → GUI), the versioning
rules (`ZSLP_SPEC_VERSION` vs `ZSLP_INDEX_VERSION`), the test/review gates, and a numbered
repeatable recipe — with collections as the worked example.

## ⭐ Start here

**[NATIVE_NFT_GUIDE.md](NATIVE_NFT_GUIDE.md)** — the single, canonical, build-ready guide.
It answers "what can I do" (works-now / building-now / next), gives the per-screen native-Qt UI
spec (gallery, detail, mint-from-file, send/gift, later trade — exact widget trees,
states, copy, and `zslp_genesis`/`zslp_send` RPC calls), and the non-negotiables. **Read this
first. Everything below is reference depth.** (The former on-chain private-file data channel has
been removed; NFT content is always off-chain.)

**[NFT_API_REFERENCE.md](NFT_API_REFERENCE.md)** — the **authoritative per-RPC call-shape
reference**, generated against the as-built daemon source: every `zslp_*` / `nft_*` RPC
(and the `z_sendmany` `inputs` coin-control parameter) with its parameters,
return shape, error codes, runnable `zclassic-cli` examples, the gating-flag table, and an
end-to-end mint→list→info→transfer→sell→buy walkthrough. Use the guide for "what/why", this for
"exact call shape". `help <command>` in the daemon remains ground truth.

## Canonical reference docs (cited by the guide)

After the guide, these remain authoritative for their own domain:

1. **[SECURITY_MODEL.md](SECURITY_MODEL.md)** — **the canonical security spec.** The
   non-consensus model, the bit-exact canonical validation rules (R-1…R-25), the threat table,
   the wallet anti-burn suite (R-WALLET-1…11), the honest uniqueness statement, and the two
   closure criteria (R-VECTORS test corpus + R-DIFF second-implementation differential test).
   **If anything elsewhere conflicts with this doc, this doc wins.**
2. **[MINT_TRANSFER_SPEC.md](MINT_TRANSFER_SPEC.md)** — the **write path**: the shared
   OP_RETURN tx builder (mint genesis + conservation-valid transfer), self-validation before
   broadcast, dust/fee/anti-burn funding, and the proof that unchanged nodes relay+mine it.
   **Authoritative for the `zslp_genesis`/`zslp_send` contract.**
3. **[NATIVE_UI_CONSOLIDATED_SPEC.md](NATIVE_UI_CONSOLIDATED_SPEC.md)** — the deep, file:line-
   grounded native-Qt widget-tree reference the guide's §2 summarizes.
4. **[CONTENT_MODEL.md](CONTENT_MODEL.md)** — **any file/image/video → NFT** via
   content-addressing: on-chain fingerprint (SHA-256 + Merkle root for large files), off-chain
   bytes, streaming verification (a multi-GB video hashes in bounded memory).
5. **[ZDC1_CODEC_SPEC.md](ZDC1_CODEC_SPEC.md)** — **HISTORICAL / REMOVED.** The shielded
   data-channel codec it described is no longer in the daemon; ZClassic provides no on-chain
   file path. Kept only for historical traceability.
6. **[NFT_SELL_DESIGN.md](NFT_SELL_DESIGN.md)** — **authoritative for trades.** Selling an NFT
   for ZCL via a fixed-template `SIGHASH_ALL|ANYONECANPAY` signed offer (OP_RETURN ZSLP
   SEND@vout[0] / buyer NFT dust@vout[1] / seller ZCL payout@vout[2]); the mandatory
   `nft_verifyoffer` check; why any shielded leg cannot be trustlessly atomic; the
   private-negotiation / public-settlement hybrid.

## Superseded (kept for traceability, do not delete)

- **[ONCHAIN_TRADES.md](ONCHAIN_TRADES.md)** — the early transparent-trade sketch;
  **SUPERSEDED by NFT_SELL_DESIGN.md.** Its `SIGHASH_SINGLE|ANYONECANPAY` layout is WRONG and
  funds-losing (SINGLE pins vout[0]=OP_RETURN, not the payout → burns the seller NFT), and
  several of its ZSLP claims are stale; kept for history only — do not implement from it.

These fed the guide and are superseded by it for the role noted; kept for depth/history:

- **[NATIVE_UX.md](NATIVE_UX.md)**, **[NATIVE_UI_BUILD_PLAN.md](NATIVE_UI_BUILD_PLAN.md)** —
  the two source UI docs; **superseded by NATIVE_NFT_GUIDE.md §2 + NATIVE_UI_CONSOLIDATED_SPEC.md.**
- **[PRIVACY_STACK.md](PRIVACY_STACK.md)**, **[PRIVACY.md](PRIVACY.md)**,
  **[PRIVACY_UX.md](PRIVACY_UX.md)** — the privacy normative/UX sources;
  **superseded by NATIVE_NFT_GUIDE.md §3.** Their on-chain private-file / data-channel content
  is **historical**: that capability has been removed from the daemon.
- **[CAPABILITY_MAP.md](CAPABILITY_MAP.md)** — the code-verified status map;
  **folded into NATIVE_NFT_GUIDE.md §1** (kept for its file:line citations).
- **[ENABLEMENT.md](ENABLEMENT.md)** — early why/aspirational matrix; **superseded for status by
  NATIVE_NFT_GUIDE.md §1.** Its stale lines (gallery "fed by fixtures / 0 zslp_* calls" —
  `refreshNFTs` already calls the real RPCs) are corrected in the guide; trust the guide and the
  code. (Note: the data-channel codec it mentions has since been removed; there is no
  `src/datachannel/`.)

---

## Supporting analyses (fed the canonical docs above)

These are the per-topic threat models and requirement lists the synthesis drew from. Useful for
depth and traceability; **`SECURITY_MODEL.md` is the normative summary of all of them.**

| Topic | Threat model | Requirements / spec |
|---|---|---|
| Forgery & conservation | [zslp-forgery-conservation-threat-model.md](zslp-forgery-conservation-threat-model.md) | folded into SECURITY_MODEL R-10…R-19 |
| Cross-impl determinism | — | [zslp-determinism-spec.md](zslp-determinism-spec.md), [CANONICAL_VALIDATION_SPEC.md](CANONICAL_VALIDATION_SPEC.md), [zslp-canonical-validation-conformance-checklist.md](zslp-canonical-validation-conformance-checklist.md) |
| Holder anti-burn | [holder-anti-burn-threat-model.md](holder-anti-burn-threat-model.md) | [holder-anti-burn-requirements.md](holder-anti-burn-requirements.md), [zslp-wallet-antiburn-ux-honesty.md](zslp-wallet-antiburn-ux-honesty.md) |
| Reorg / confirmations | [REORG_CONFIRMATION_SAFETY.md](REORG_CONFIRMATION_SAFETY.md) | [REORG_CONFIRMATION_REQUIREMENTS.md](REORG_CONFIRMATION_REQUIREMENTS.md) |
| Impersonation & uniqueness | [IMPERSONATION_UNIQUENESS.md](IMPERSONATION_UNIQUENESS.md) | folded into SECURITY_MODEL R-UX-1…R-UX-9 |
| DoS / spam / griefing | [THREATS_DOS_SPAM_GRIEF.md](THREATS_DOS_SPAM_GRIEF.md) | [REQUIREMENTS_DOS_SPAM_GRIEF.md](REQUIREMENTS_DOS_SPAM_GRIEF.md) |
| Short overview | [zslp-security-model.md](zslp-security-model.md) (superseded by SECURITY_MODEL.md) | — |

*Cleanup note:* the supporting docs overlap by design (independent reviewers). A later pass may
fold them entirely into the canonical set; until then, cite `SECURITY_MODEL.md` as normative.

---

## Implementation status (code, not just docs)

The single, code-verified status table now lives in **[NATIVE_NFT_GUIDE.md §1](NATIVE_NFT_GUIDE.md)**
(works-now / building-now / next, tied to file:line ground truth). It is maintained in one place so
build-status never drifts across docs again. **See the guide §1.**

**Run the journey (regtest).** End-to-end, runnable proof of the write/sell paths lives in
`qa/zslp/` — `zslp-nft-regtest.sh` (mint → inspect → transfer → anti-burn → list) and
`nft-sell-regtest.sh` (makeoffer → verifyoffer → takeoffer, plus forged/tampered-offer
rejection). See `qa/zslp/README.md`.

---

## Non-negotiables (apply to every doc and every line of code here)

- **Never change consensus.** If a feature needs a new consensus rule, it is out of scope.
- **Honest UX.** The image-match badge means *"these bytes match the on-chain fingerprint"* —
  never "genuine/official/original." Issuer trust is social (signed attestation / verified
  list), not a network badge. Ownership is *pending* until ~10 confirmations.
- **Privacy.** Never auto-fetch a remote `documenturl`; bytes come from local cache or an
  explicit user action. No `QtWebEngine`/browser anywhere.
- **Holder safety.** An ordinary send must never spend/burn an NFT's carrier UTXO.
