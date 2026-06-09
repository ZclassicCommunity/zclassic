# ZClassic Native NFTs — The Honest Capability Map

> **REMOVED — shielded data channel / on-chain private files.** Any "Shield" / private-file / ZDC1
> data-channel capability listed below (`z_senddatafile` / `z_listdatatransfers` /
> `z_getdatatransfer`, the `-datachannel` option, the ZDC1 codec) has been **removed entirely**
> from the daemon. ZClassic deliberately provides **no wallet path to store arbitrary files
> on-chain**. NFT content is always off-chain, bound to the token only by a `document_hash`
> fingerprint. Treat every such row as **historical**.

*What a user can actually do with NFTs from inside the full-node GUI — every item tagged
works-now / building-now / next, tied to ground truth in the code, and independently checked
to require **no consensus change** and to be **secure under the non-consensus model**.*

> **Read this first.** This is the plain-language, build-status-accurate front door. For the
> normative rules see `SECURITY_MODEL.md` (the single source of truth on validation/threats);
> for the write path see `MINT_TRANSFER_SPEC.md`; for trades see `NFT_SELL_DESIGN.md` (the older
`ONCHAIN_TRADES.md` is SUPERSEDED — its `SINGLE|ANYONECANPAY` layout is funds-losing); for the
> private stack see `PRIVACY_STACK.md` + `ZDC1_CODEC_SPEC.md`. This guide SUPERSEDES the
> capability-status portions of `ENABLEMENT.md` (see "Consolidation" at the end) — where it and
> ENABLEMENT disagree on what is built, **this guide and the code win.**

---

## The one-paragraph model (so every status below is read correctly)

ZClassic consensus does not know NFTs exist. An NFT is a **non-consensus overlay**: a token is a
baton-less SLP GENESIS (`decimals=0, quantity=1`) carried in a single `OP_RETURN`, and every
honest wallet/indexer recomputes the same token ledger as a deterministic function of the
confirmed chain. The hard consequence, stated honestly everywhere in the UI: **a forgery can be
mined, but it credits nobody** — the chain will relay/mine an invalid token tx, and every correct
observer interprets it as crediting no one (and burning its token inputs). Three corollaries the
UI must hold to: (1) **ownership is PENDING until ~10 confirmations** (`DEFAULT_MAX_REORG_DEPTH`),
because 1–9 confs are reorg-reversible; (2) the **image badge means only "these bytes match this
token's on-chain fingerprint"** — never genuine/official/original; (3) **identity is the genesis
txid**, never the name/ticker/image (those are freely reusable).

---

## Capability map

> **Status note (folded into the guide).** This map is kept for its file:line citations; the
> single live status table is `NATIVE_NFT_GUIDE.md §1`. Since this map was first written, the
> write path, the SHIELD data-channel RPCs, and the SELL RPCs have all landed — the cells below
> are updated to match the built tree on `feature/zslp-nft-indexer`.

Legend — **works-now** = code in-tree and built (cited file); **building-now** = a separate
workflow is actively writing it against a fixed contract; **next** = designed, not yet written.

### A. Discover, verify, and inspect (the read path) — **works-now**

| What the user does | Mechanism (verified in code) | Requires |
|---|---|---|
| **See the NFTs this wallet owns**, in a native dark gallery with a verify badge and public/private pill — no browser | GUI `RPC::refreshNFTs()` calls the real `zslp_listmytokens` then `zslp_gettoken` per token and feeds `NFTGalleryModel`/`nftgallerydelegate` (`zcl-qt-wallet/src/rpc.cpp:863`; gallery files `nftgallery*.{h,cpp}`). The daemon side is `zslp_listmytokens` (`src/rpc/zslp.cpp:204`). | `-zslpindex` (default ON this branch) + wallet build |
| **Verify an image** against its on-chain fingerprint (✓ match / ✗ mismatch / ? pending) — locally, never fetching the remote URL | `ContentEngine` streaming SHA-256 + verify on a worker thread (`zcl-qt-wallet/src/contentengine.{h,cpp}`); badge copy is "matches its on-chain fingerprint" only | local cached bytes |
| **Look up any public token** by genesis txid: ticker, name, document_url, 32-byte hash, decimals, height, totalMinted, baton state | `zslp_gettoken` -> `CZSLPStore::GetToken` (`src/rpc/zslp.cpp:84`, `TokenToJSON` at `:57`) | `-zslpindex` |
| **Confirm a real 1-of-1 + supply cap** (`totalMinted==1 && hasMintBaton==false`) | baton-less GENESIS; `totalMinted` now counts only created quantity (R-GEN-3) | `-zslpindex` |
| **Read full public transfer history** (every GENESIS/MINT/SEND, newest-first, reorg-safe) | `zslp_listtransfers` (`src/rpc/zslp.cpp:155`); ordering normative (R-RPC-2) | `-zslpindex` |
| **Browse all indexed tokens** (bounded paging) | `zslp_listtokens` (`src/rpc/zslp.cpp:120`), clamped to `ZSLP_LIST_MAX=1000` | `-zslpindex` |
| **Trust the ledger is forgery-proof** (a forged SEND/MINT credits nobody; an NFT can't be duplicated) | UTXO-bound conservation indexer; `vout[0]`-only parse landed (`src/zslp/zslpindexer.cpp:229`), single `ZSLP_SEND_MAX_OUTPUTS=19`, no mempool/0-conf path (`ChainTip`-only, `zslpindexer.h`). ~101 ZSLP gtests across `src/gtest/test_zslp*.cpp` | `-zslpindex` |

### B. Create and move NFTs (the write path) — **works-now (daemon)**

The daemon RPCs are built, committed, and registered on `feature/zslp-nft-indexer`. The GUI
dialogs that call them are **designed** (`NATIVE_UI_BUILD_PLAN.md`) and degrade honestly until
they are wired in a build that carries the RPCs.

| What the user will do | Daemon contract (the exact RPC names/params the UI calls) | State |
|---|---|---|
| **Mint a public 1-of-1** (drag a file, hash it locally, fill name, broadcast a baton-less GENESIS) | `zslp_genesis '{nft:true, name, document_url, document_hash, [ticker], [to (t-addr)], [mint_baton_vout]}'` (`nft:true` forces decimals 0/quantity 1/no baton) | built (`src/rpc/zslp.cpp:326`, registered `:649-661`; encoders `slp_build_genesis` + builder spec `MINT_TRANSFER_SPEC.md`) |
| **Transfer / gift** an NFT to a recipient's t-address | `zslp_send` (token_id, to_address, amount=1, optional change_address) | built (`src/rpc/zslp.cpp:541`, registered `:649-661`) |
| **Airdrop / batch** up to 19 token outputs in one tx | `zslp_send` multi-output (indexer crediting already works) | built |
| **Limited / numbered editions** ("N of 100") | `zslp_genesis` qty=N baton-OFF, or N separate 1-of-1s + `zslp_send` | built (rides B above) |
| **Hold an NFT without burning it** — an ordinary send/shield/sweep never spends the carrier dust | Wallet anti-burn: `AvailableCoins` now excludes protected token/dust outpoints by default (`fExcludeZSLPTokens=true`, `wallet.h:1124`; `ZSLPIsProtectedTokenOutpoint`, `wallet.cpp:3198`), built on the primitive `ZSLPFindWalletTokenUtxos` + `SLP_TOKEN_DUST=546` (`src/wallet/zslpwallet.{h,cpp}`); the self-validate-before-broadcast gate (R-WALLET-9) is wired (`zslpwallet.cpp:465`) | built — holder safety mechanically complete; the shipped guarantee provided spend paths use the default token-excluding `AvailableCoins` |

### C. Create / mint dialogs and detail view (the native UI) — **next**

| What the user will do | Where it's designed | State |
|---|---|---|
| **Open a detail dialog** (large verified render, provenance rows, copy id/fingerprint, prev/next) | `NATIVE_UI_BUILD_PLAN.md` §2 (`NFTDetailDialog`) | next (spec build-ready; GUI dialog files not created) |
| **Create-NFT mint wizard** (drop file -> streaming fingerprint -> public/private -> review "what becomes public" -> Create) | `NATIVE_UI_BUILD_PLAN.md` §3 (`NftMintDialog`); calls `zslp_genesis` | next (depends on B's RPCs; Private radio gated off by `isPrivateMintWired()==false`) |
| **Card sets / "collect them all"** completion bar | `ENABLEMENT.md` §3.2; manifest convention only | next (no on-chain group/child field; membership is issuer-claimed, see honesty note) |

### D. Private NFTs and the shielded data channel — **works-now (daemon, CLI; default-OFF); native GUI next**

| What the user will do | Mechanism | State |
|---|---|---|
| **The ZDC1 codec itself** (frame/reassemble/AEAD/ciphertext fingerprint) | `src/datachannel/zdc.{h,cpp}` — built + self-tested AND **compiled into the daemon** (`src/Makefile.am:248,295`; 25 daemon gtests in `test_zdc.cpp`, ASan/UBSan-clean, secret-zeroized) | works-now (compiled into the daemon) |
| **Send a private file / message** (sealed bytes on-chain; selective disclosure via the returned key / viewing key) | Daemon RPCs `z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer` built + registered (`src/rpc/datachannel.cpp:704-711`, register fn `:713`); default-OFF behind `-datachannel`, permanence-consent, verify-before-decrypt | works-now (daemon, CLI; native GUI next) |
| **Receive a private NFT in the gallery** (decrypt locally, render natively, verify badge) | render half done; needs the GUI binary-memo branch (`rpc.cpp` ~756) + datachannel route | next (binary-memo fix gates all private receive) |

*(A single `zslp_mint_private` RPC and a separate `z_revealkey` seal-then-reveal trigger are
designed but NOT built; the as-built private-mint path is `z_senddatafile` + an ordinary
`zslp_genesis` whose `document_hash` = the ciphertext fingerprint. See `NATIVE_NFT_GUIDE.md §3.3`.)*

### E. Trade NFT ⇄ ZCL — **works-now (daemon, CLI)** (transparent), and a hard ceiling

| Trade | Honest verdict | State |
|---|---|---|
| **Transparent NFT ⇄ transparent ZCL**, atomic single tx | **built** via a fixed-template `SIGHASH_ALL\|ANYONECANPAY` signed offer (seller pins the WHOLE output set — OP_RETURN ZSLP SEND@vout[0] / buyer NFT dust@vout[1] / seller ZCL payout@vout[2]; buyer appends funding inputs); coin legs are consensus-atomic, token attribution is indexer-convention (so **trust-minimized**, not trustless). `SINGLE\|ANYONECANPAY` does NOT work for ZSLP (it would pin vout[0]=OP_RETURN, not the payout, and burn the seller NFT). | built (`nft_makeoffer`/`nft_verifyoffer`/`nft_takeoffer`/`nft_listoffers`/`nft_canceloffer`/`nft_requestbuy`, `src/rpc/nftoffer.cpp:1094-1104`, register fn `:1106`; regtest `qa/zslp/nft-sell-regtest.sh`, 6 gtests); only the GUI offer dialog is pending |
| **Any leg shielded**, atomic | **impossible in-codebase** — z-notes carry no script and the Sapling binding sig is single-party over the whole tx (`NFT_SELL_DESIGN.md` §4 / superseded `ONCHAIN_TRADES.md` §4, code-confirmed) | not on roadmap |
| **Escrowed/disputed sale** | possible via 2-of-3 P2SH multisig, but **trusted** (the arbiter) | next, opt-in only |

---

## What a non-consensus overlay can NEVER do (structural ceilings — hold the line in UI copy)

These are not roadmap gaps. Engineering AND product copy must never imply otherwise.

1. **No enforced royalties / resale cut / transfer veto / clawback** — the chain is a UTXO ledger
   with no transfer hook; enforcement would be a forbidden consensus change. Royalty = off-chain
   goodwill; never ship a field that implies enforcement.
2. **No enforced scarcity of the underlying art** — `document_hash` proves *which* bytes, never
   *exclusivity*. Anyone can copy the bytes; a private prior-holder keeps a plaintext copy forever.
3. **No ticker / name / issuer uniqueness** — anyone can mint a different token (new txid)
   reusing any metadata. Identity is the genesis txid + an out-of-band signed attestation or a
   tokenId-keyed verified list (centralized trust, names its maintainer). No trustless "verified
   creator" exists.
4. **No on-chain set/collection membership** — no group/parent/child field; sets are manifest
   convention and two indexers can legitimately disagree. (NFT1 group/child is deferred,
   `SECURITY_MODEL.md` R-NFT1 / T12.)
5. **No atomic/trustless trade for any shielded leg** — privacy + atomicity are mutually exclusive
   here (`ONCHAIN_TRADES.md` §4).
6. **Public ZSLP is fully public and linkable** — ownership rides transparent 546-sat dust; it
   degrades wallet hygiene and correlates addresses. Tokens cannot ride shielded outputs.
7. **Private ≠ undetectable** — the shielded channel hides content/recipient/amount/metadata but
   leaks the count/size/timing burst and, if fees come from a t-address, the sender. It is a
   confidentiality channel, not steganography.
8. **Permanence is a node-operator liability** — every byte (incl. encrypted private NFTs) is
   stored by every full node forever, no pruning. Keep assets small; default-OFF + size cap.
9. **Ownership is PENDING below ~10 confs** — 1–9 confs are reorg-reversible; the node finalizes at
   depth 10 and hard-stops at 99. UI shows pending->final on a single named constant.
10. **The wallet must NEVER auto-fetch a `document_url`** (leaks IP + interest). Bytes come from
    local cache or explicit user action only. No QtWebEngine/browser anywhere — native Qt only.

---

## Independent safety check (no consensus change; secure under the non-consensus model)

I verified each capability against the code on this branch:

- **No consensus change required, anywhere.** The indexer overrides only `ChainTip` and never
  `SyncTransaction` (`src/zslp/zslpindexer.h`), so there is no mempool/0-conf or validation path —
  it is a derived, disposable store. The write path (`MINT_TRANSFER_SPEC.md` §6) produces an
  ordinary `TX_NULL_DATA` payment that unmodified nodes relay/mine; ZSLP is referenced nowhere in
  `src/main.cpp` or `src/consensus/`. The codec rides the existing Sapling memo. The trade path
  composes existing `signrawtransaction`/`sendrawtransaction` and adds no opcode.
- **Forgery credits nobody — confirmed in code.** `vout[0]`-only parse landed
  (`zslpindexer.cpp:229`, closing the message-position and multi-OP_RETURN forks T1/T2); a single
  `ZSLP_SEND_MAX_OUTPUTS=19` constant is enforced across parser/bridge/store (closing the SEND-cap
  fork T7); availIn requires recognized token inputs (forged SEND credits nobody, T4). ~101 ZSLP
  gtests exercise these (`test_zslp*.cpp`, including a versioned vector corpus).
- **Honest UX is achievable and specced.** Badge copy, pending-until-10, name-not-unique cue, and
  "no auto-fetch" are normative in `SECURITY_MODEL.md` R-UX-1..9 and carried verbatim into the UI
  plan's banned-words list.
- **Holder anti-burn — closed and committed** (capability B last row). `AvailableCoins`
  now excludes protected token/dust outpoints by default (`fExcludeZSLPTokens=true`,
  `wallet.h:1124`; `ZSLPIsProtectedTokenOutpoint`, `wallet.cpp:3198`) and the
  self-validate-before-broadcast gate is wired (`zslpwallet.cpp:465`). Holding is therefore
  mechanically burn-safe; it is the shipped guarantee provided spend paths use the default
  token-excluding `AvailableCoins`. Do not let UI copy imply burn-proof holding outside
  a build that carries these changes.

---

## Consolidation plan (kill the sprawl; never delete, mark superseded)

`doc/nft/` has 26 files with heavy, partly-stale overlap. Concrete plan:

**1. This guide becomes the status front door.** `CAPABILITY_MAP.md` supersedes the
*capability-status* role of `ENABLEMENT.md`. Mark ENABLEMENT in `README.md` as
"superseded for build-status by CAPABILITY_MAP.md; kept for the why/aspirational discussion." Do
not delete ENABLEMENT — its limits prose and headline-experience write-ups are still useful — but
fix its stale lines (it still says the gallery is "fed by fixtures / 0 zslp_* calls" while
`refreshNFTs` already calls the real RPCs; it says "no `src/datachannel/`" while the codec exists).

**2. Collapse the supporting threat-model pairs into SECURITY_MODEL.md (already the normative
synthesis).** Mark these six as "superseded by SECURITY_MODEL.md, kept for traceability":
`zslp-forgery-conservation-threat-model.md`, `zslp-determinism-spec.md`,
`zslp-canonical-validation-conformance-checklist.md`, `holder-anti-burn-threat-model.md`,
`holder-anti-burn-requirements.md`, `zslp-wallet-antiburn-ux-honesty.md`,
`IMPERSONATION_UNIQUENESS.md`, `REORG_CONFIRMATION_SAFETY.md`,
`REORG_CONFIRMATION_REQUIREMENTS.md`, `THREATS_DOS_SPAM_GRIEF.md`,
`REQUIREMENTS_DOS_SPAM_GRIEF.md`, and the short `zslp-security-model.md` (README already calls it
superseded). `CANONICAL_VALIDATION_SPEC.md` overlaps SECURITY_MODEL §2 nearly 1:1 — keep ONE
normative copy (SECURITY_MODEL) and reduce CANONICAL_VALIDATION_SPEC to a pointer, or fold its
file:line citations in; mark it superseded either way.

**3. Collapse the four privacy docs.** `PRIVACY_STACK.md`, `ZDC1_CODEC_SPEC.md`, `PRIVACY_UX.md`,
`PRIVACY.md` overlap heavily and **all reference a `shielded-data-protocol.md` that does not
exist** (broken cross-ref). Pick `PRIVACY_STACK.md` as the canonical private-NFT doc (it has the
stack, wire format, honest limits, and end-to-end flow), keep `ZDC1_CODEC_SPEC.md` as the codec
reference, fold `PRIVACY_UX.md`/`PRIVACY.md` into PRIVACY_STACK, and either restore the missing
`shielded-data-protocol.md` or replace every reference to it with `PRIVACY_STACK.md`/
`ZDC1_CODEC_SPEC.md`.

**4. Canonical set after consolidation (the only docs a new reader needs):**
`README.md` (index) -> `CAPABILITY_MAP.md` (this, status) -> `SECURITY_MODEL.md` (normative
rules/threats) -> `MINT_TRANSFER_SPEC.md` (write path) -> `NATIVE_UX.md` + `NATIVE_UI_BUILD_PLAN.md`
(GUI) -> `CONTENT_MODEL.md` (any-file fingerprinting) -> `PRIVACY_STACK.md` + `ZDC1_CODEC_SPEC.md`
(private) -> `ONCHAIN_TRADES.md` (trades). Everything else is "superseded, kept for traceability."

**5. Single status table, one place.** The implementation-status table belongs ONLY in this guide;
remove or replace the duplicate (and now-stale) status tables in `README.md` and `ENABLEMENT.md`
with a one-line "see CAPABILITY_MAP.md" so build-status is never maintained in three places again.
