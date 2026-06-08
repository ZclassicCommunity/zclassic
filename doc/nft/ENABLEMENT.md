# Everything ZClassic NFTs Will Enable

> **REMOVED — shielded data channel / on-chain private files.** The shielded data-channel /
> arbitrary-file-transfer capability referenced below (`z_senddatafile` / `z_listdatatransfers` /
> `z_getdatatransfer`, the `-datachannel` option, the ZDC1 codec, `src/datachannel/`) has been
> **removed entirely** from the daemon. ZClassic deliberately provides **no wallet path to store
> arbitrary files on-chain**. NFT content is always off-chain, bound to the token only by a
> `document_hash` fingerprint. Treat every such reference below as **historical**.

*A definitive enablement map for engineers and product — what's real today, what's a contained build, and what a non-consensus layer can never do.*

> **Status legend** — used throughout this document:
> - ✅ **Works today** — code exists, ships in the daemon/GUI, verified in-tree.
> - 🔨 **Needs build** — a contained, well-scoped build on top of existing primitives. Not research.
> - 🌫️ **Aspirational** — possible only as off-chain/social convention, or requires a forbidden consensus change. Honest about being unenforceable.

---

## 1. The big picture — what makes ZClassic NFTs distinct

Most "NFT" chains give you one thing: a **public** token that points at an **off-chain** image (an IPFS/HTTP URL). The token is on-chain; the art is on someone's server; ownership is a public ledger entry anyone can scrape.

ZClassic can do that public flavor too — but it is **not the differentiator**. ZClassic has a shielded pool (Sapling) with an encrypted 512-byte memo on every shielded output. That memo is a **private, encrypted data channel built into consensus-grade transport**. It changes what an NFT can *be*:

**The differentiator: PRIVATE NFTs.** An NFT whose **image bytes themselves are encrypted on-chain** inside Sapling memos — not a hash pointing at a public URL, but the actual asset, sealed, delivered end-to-end to a recipient's viewing key. Ownership is **key possession**, not a public ledger row. Content, recipient, amount, and all metadata are hidden. This is *confidential art with no public attribution* — something a transparent-only NFT chain structurally cannot offer.

And the **strongest design is a hybrid**: a public, auditable, transferable ZSLP ownership token whose on-chain hash commits to a *private* encrypted payload. Public chain-of-custody + private art. You choose the trade-off: full anonymity (private), full auditability (public), or provenance-without-exposure (hybrid).

ZClassic therefore offers **two non-consensus substrates**, each with a different honest superpower:

| Substrate | Carrier | Superpower | Honest ceiling |
|---|---|---|---|
| **Transparent ZSLP** | OP_RETURN (SLP Token Type 1, ≤223B) | Public, auditable, indexed provenance + supply cap | Public/linkable; enforces nothing but supply-cap + hash-integrity |
| **Shielded data channel** | Sapling 512B memos (ZDC1 framing) | Private encrypted bytes; ownership = key possession | Confidentiality only — sender keeps a copy; ~64KB practical ceiling |

**One unifying truth across both:** these are **non-consensus** layers. The base chain (a UTXO ledger with no scripting hooks) never inspects them. So they can do *verifiable provenance, capped editions, public and private gifting, native hash-verified gallery UX* — and they **cannot** do enforced royalties, enforced scarcity of the underlying art, atomic trustless trades, clawback, or DRM. This document is religious about that line.

### The one cryptographic guarantee, and the one integrity binding

Everything honest reduces to two facts the chain *actually* gives you:

1. **Supply cap = 1 (or N).** A baton-less GENESIS (`mint_baton_vout < 2`) emits an empty baton push, so the protocol admits **no future MINT**. Total supply is provably capped by the OP_RETURN bytes themselves. Base consensus never inspects the OP_RETURN, so this is **protocol-meaningful (to any ZSLP-aware reader)**, not enforced by the base chain — but it is the strongest of the guarantees about quantity.
2. **Image integrity binding.** `document_hash = SHA256(image_bytes)` proves that the bytes you hold are *exactly* the bytes the minter committed to. It proves **which** image, not **authorship**, not **exclusivity**, and not **rights**.

Everything else — ticker/name uniqueness, collection membership, "official issuer," editions count, royalties, expiry — is **indexer/UI convention with zero on-chain enforcement.**

---

## 2. Capability matrix (grouped by status)

### ✅ Works today (verified in-tree)

| Capability | What you get | Mechanism | Requires |
|---|---|---|---|
| **Confidential bytes on-chain** | Send ≤512 raw bytes encrypted to a z-addr; read them back as hex | `z_sendmany` accepts binary memo (no UTF-8 enforcement); Sapling ChaCha20-Poly1305-to-ivk; `z_listreceivedbyaddress` returns full memo via `HexStr(entry.memo)` | Nothing — *daemon* round-trips binary today (the GUI lossily coerces binary memos until the binary-safe read path lands; see the binary-memo fix below) |
| **Look up a public NFT** | Paste a genesis txid → ticker, name, documenturl, 32B hash, decimals, height, totalminted, baton state | `zslp_gettoken` → `CZSLPStore::GetToken` → `TokenToJSON` | `-zslpindex` (default ON this branch) |
| **Prove a 1-of-1 + provenance origin** | Confirm `totalminted==1 && hasmintbaton==false`; see genesis height | `zslp_gettoken` totalminted + baton; cap is real via baton-less GENESIS | `-zslpindex` |
| **Full public transfer history** | Every GENESIS/MINT/SEND with txid, amount, height, blockhash, recipient, newest-first | `zslp_listtransfers` iterates `'x'`+tokenId keyspace; reorg-safe undo log | `-zslpindex` |
| **List NFTs this wallet owns** | Public tokens held at your t-addresses, balance + holding address | `zslp_listmytokens` intersects wallet t-keys with per-(token,address) balance index | `-zslpindex` + wallet-enabled build |
| **Browse / discover indexed NFTs** | Page through all indexed tokens (bounded `ZSLP_LIST_MAX=1000`) | `zslp_listtokens` deterministic skip/take over `'t'` keyspace | `-zslpindex` |
| **Native gallery + verify pipeline** | Dark-themed QListView gallery, threaded image cache, SHA-256 verify badge (✓/✗/?), private pill — no browser | `nftgallerymodel` / `nftgallerydelegate` / `nftimagecache` (bundle sha `f8f2bde2`) | Built; **fed by fixtures** until wired |
| **Privacy properties (the hiding)** | Memo content, recipient, amount, metadata all hidden | Inherent to Sapling — applies the moment bytes ride a shielded memo | Nothing |

### 🔨 Needs build (contained, on top of existing primitives)

| Capability | What it unlocks | What must be built | Hard dependency |
|---|---|---|---|
| **Wire gallery to real data** | Verify badge over *real* ZSLP tokens, not fixtures | `rpc.cpp` calls `zslp_*` → map to `QVector<NFTItem>` (today: 0 `zslp_*` calls, fixture-fed) | Read RPCs (DONE) |
| **Mint a public 1-of-1** | Creator hashes image, fills metadata, broadcasts a baton-less GENESIS | `zslp_genesis` RPC (absent) via `CRecipient.scriptPubKey` + `CWallet::CreateTransaction` (createrawtransaction has NO data branch); GUI mint dialog (threaded SHA256) | Gallery wiring |
| **Transfer / gift a public NFT** | Send a 1-of-1 to a recipient's t-address; history updates | `zslp_send` RPC (absent); GUI gift dialog reusing send-guard; same CreateTransaction OP_RETURN path | Public minting |
| **Airdrop / batch distribution** | Drop to up to **19** token outputs per tx | `zslp_send` multi-output (indexer crediting already works); GENESIS + SEND fan-out | Public minting |
| **Creator identity surface** | Show genesis txid + issuing t-address as identity (not the name) | GUI surfaces txid + issuer prominently (read data exists) | Public minting |
| **ZDC1 framing + reassembly** | Chain a file across many memos, survive out-of-order arrival | `src/datachannel/frame.{h,cpp}` (CRC32 + header), reassembly state machine keyed `(zaddr, transfer_id, seq)` (absent — no `src/datachannel/`) | Confidential bytes (DONE) |
| **App-layer AEAD** | File key independent of Sapling epk → reveal-later | `src/datachannel/aead.cpp` (libsodium already linked, zero new deps) | ZDC1 framing |
| **Private file transfer (≤64KB)** | Deliver a small private file/asset end-to-end on-chain | `z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer` / `z_receivedatafile`; GUI dialog with size/cost cap; **default-OFF + permanence consent** | ZDC1 + AEAD |
| **Fix GUI binary-memo DROP bug** | Binary frames stop being silently discarded | `rpc.cpp` ~756-760: it coerces memo hex into a QString then drops `.trimmed().isEmpty()` — needs a **ZDC1-magic-detect branch** before the text-inbox path; send path `sendtab.cpp` forces `memo.toUtf8().toHex()` | Prereq for any private receive |
| **Private NFT object** | Sealed image; ownership = key possession; nothing publicly attributable | ZSLP-shaped record inside encrypted START frame + asset in DATA frames; GUI private-mint + reveal-key affordances; feed gallery from decrypted-memo scans | Private file transfer |
| **Private receipt in gallery** | Incoming private NFT decrypts locally, renders native, shows verify badge | Magic-detect + datachannel route + model feed; render half is DONE | Private NFT object + binary-memo fix |
| **Card sets / completion** | Group header + "You own 18 of 30" completion bar | Manifest JSON schema + fetch/parse; grouped `CollectionsModel`; gallery section/completion UI (Phase D) | Public minting + gallery wiring |
| **Limited / numbered editions** | "Edition N of 100" capped supply | `zslp_genesis` (qty=N, baton OFF) + `zslp_send`; serial #N = N separate 1-of-1s | Public minting |

### 🌫️ Aspirational (off-chain convention or forbidden consensus change)

| Capability | Why it's aspirational | The honest most-you-can-do |
|---|---|---|
| **Hybrid public-pointer + private payload** | Union of two *unbuilt* tracks (minting + full data channel) | Real once both ship; design is sound. Trades anonymity for auditability. |
| **Royalties / resale enforcement** | UTXO model has **no** transfer hook; enforcement = forbidden consensus change | Advisory metadata only, labeled "**not enforced on-chain**." Never ship a field that implies enforcement. |
| **Atomic swap (single-tx)** | — | **NOW BUILT** (no longer aspirational): the co-signed single SEND+ZCL tx (`ALL\|ANYONECANPAY`) is implemented + regtest-proven (`src/rpc/nftoffer.cpp` `nft_makeoffer`/`verifyoffer`/`takeoffer`). Trust-minimized, transparent counterparties. (2-of-2 multisig / HTLC escrow remains research — CSV/BIP112 is inert, so only absolute-CLTV HTLCs are buildable.) |
| **Trade NFT for ZCL (buy/sell)** | — | **NOW BUILT** (no longer aspirational): the seller's `ALL\|ANYONECANPAY` signature couples the NFT spend + payment in ONE atomic tx (`nft_makeoffer`→`nft_takeoffer`); price + NFT recipient are cryptographically pinned and `nft_verifyoffer` checks them before the buyer pays. Trust-minimized, **not** fully trustless — see `NFT_SELL_DESIGN.md` §8. |
| **Marketplace / order book / price feed** | No matching engine, escrow, or oracle on this chain | External off-chain marketplace using the read RPCs; wallet links out. |
| **Time-boxed passes / expiring tickets** | No consensus expiry primitive; token stays spendable forever | UI-enforced honor system for low-stakes passes only. |
| **"Official issuer" / verified-creator badge** | No on-chain identity or issuer-uniqueness | Out-of-band published genesis txid + a *curated allowlist* (centralized trust). No trustless answer exists. |
| **Provable rarity tiers** | OP_RETURN has no room; rarity is a manifest assertion | Off-chain manifest label, content-addressed at best. "Legendary" is a label, not a chain property. |

---

## 3. The headline experiences

### 3.1 Public 1-of-1 mint (verifiable provenance) — 🔨

A creator picks an image; the wallet hashes it (threaded `QCryptographicHash::Sha256`), fills ticker/name/documenturl, and broadcasts a **baton-less GENESIS** (decimals=0, qty=1, no mint baton). The genesis txid *is* the permanent token id.

- **Build:** `slp_build_genesis` → `CScript s; s << OP_RETURN << bytes` → `CreateTransaction` as `vout[0]` + a 546-sat dust recipient + change. New `zslp_genesis` RPC + GUI mint dialog. `createrawtransaction` cannot help (only `GetScriptForDestination`).
- **What's real:** supply cap (baton-less) + hash-integrity (`document_hash`). Holder's wallet shows ✓ when local bytes re-hash to the on-chain hash.
- **Honest copy for the UI:** identity is the **genesis txid + minting address**, never the name. Every mint spends real coin (fee + dust) — surface cost before broadcast. A dropped/expired tx marks the NFT **pending**, not owned. Ticker/name are **not unique** — anyone can mint "Curio Cards."

### 3.2 Curio-style card sets (collections + "collect them all") — 🔨 → 🌫️

A group/parent GENESIS whose `documenturl` points at a **canonical manifest JSON** listing child token_ids + traits + per-card image hashes, plus N independent baton-less child GENESIS NFTs.

- **Set-completion:** intersect the manifest's child token_ids with `zslp_listmytokens` (balance ≥ 1) → "18 / 30 owned" + completion bar in a grouped `CollectionsModel`. Today the gallery is a **flat** fixture-fed QListView with a single `collection` caption and no completion/series/rarity roles.
- **The hard truth:** SLP has **no** group/parent/child field anywhere (`slp_message` has only ticker/name/document_url/document_hash/decimals/mint_baton_vout/initial_quantity). Membership is **100% manifest convention** — two indexers can legitimately disagree, anyone can claim any token is "in" your set, and if the manifest host vanishes the set structure is orphaned (individual cards still verify via `document_hash`). Pin the creator's own minting wallet/genesis txids as the source of truth; content-address the manifest (IPFS CID) so it can't be silently edited.

### 3.3 Private NFTs (the differentiator) — 🔨

An NFT whose **image bytes are sealed encrypted on-chain**; ownership = possession of the decryption key. Nothing publicly visible or attributable.

- **Flow:** ZSLP-shaped metadata record carried *inside* the encrypted START frame; asset bytes ride DATA frames (ZDC1: 32B header + 480B payload). Record commits via `sha256(ciphertext)`. App-layer AEAD (`K_file` independent of Sapling epk) means a **KEY frame** can be sent in-band, deferred ≥10 confirmations, or delivered fully out-of-band → **sealed-content-then-key-reveal** (timed drops, sealed bids, "unlock at event").
- **Receipt:** the gallery decrypts locally, renders natively (no browser, no remote fetch), shows the ✓ badge. The render half is **done** (`f8f2bde2`); the data half is entirely missing, and the **binary-memo DROP bug must be fixed first**.
- **The central honesty point:** key-possession ownership **cannot be exclusive**. The sender/prior owner always keeps a plaintext copy; you can re-deliver a key but never revoke the old one without re-encrypting and re-broadcasting. There is no public provenance — deniable by design. That is both the feature and the limitation.

### 3.4 Private file transfer (the substrate) — 🔨

The general-purpose channel under private NFTs: split a file into 480B chunks, optionally AEAD-encrypt, frame each in ZDC1, batch up to ~107 outputs/tx across `z_sendmany`. START carries encrypted `{filename, size, content_type, file_sha256}`; END carries `sha256(ciphertext)`. Receiver reassembles **seq-keyed** (mandatory — `mapWallet` iterates by txid hash, not chain order), verifies both hashes, decrypts.

- **Honest physics (two different numbers, don't conflate them):**
  - 480B usable/chunk, ~948 on-chain bytes/output (≈2× expansion). The **200KB block / 102KB tx** limits are size caps on a *single block/tx*, **not** a throughput cap — saturating every block, ~210 chunk-outputs/block × ~480 usable bytes ≈ **~100 KB usable per full block**, so 1 MB ≈ ~10 full blocks ≈ **~12.5 min** at the current 75s block spacing (`POST_BUTTERCUP_POW_TARGET_SPACING`). That puts the **block-saturating consensus ceiling at ~4.8 MB/hr** at 75s spacing (~2.4 MB/hr at the legacy 150s `PRE_BUTTERCUP` spacing).
  - The **recommended self-throttle** is far lower: send **one modest, polite transaction per block** instead of saturating blocks — this is a **self-imposed politeness throttle, NOT a consensus cap**, and is where a sub-MB/hr figure belongs. Be a good chain citizen, not a block hog.
  - Every byte is stored by every full node **forever, no pruning.**
- **Verdict from design review:** ≤4KB **great**, ≤64KB **fine**, 50–250KB tolerable-but-slow, multi-MB **hard NO**. Ship **default-OFF** with a hard size cap and a one-time **permanence-consent** dialog. DoS guards (per-sender concurrent-transfer quota, 7-day TTL, CRC32 + END-sha256 gate before assembly) from day one.

---

## 4. Honest limits & non-goals (what a non-consensus layer cannot do)

These are not roadmap gaps — they are **structural ceilings**. Engineering and product must hold the same line in copy and design.

1. **No enforced royalties / resale cut / transfer veto / clawback.** The chain is a UTXO ledger with no scripting hook. Enforcement would require a consensus change, which is **forbidden** (never touch consensus/PoW/validation). Any royalty is off-chain goodwill — never ship a field that *implies* enforcement.
2. **No enforced scarcity of the underlying art.** `document_hash` proves *integrity* (which bytes), never *exclusivity*. Anyone can copy the bytes; a private prior-holder keeps their plaintext forever.
3. **No ticker/name/issuer uniqueness.** Anyone can mint a token named anything. Identity is the **genesis txid + minting address** — only meaningful if the creator publishes it out-of-band against a source you already trust. A "verified creator" badge requires a curated allowlist (centralized).
4. **No on-chain set/collection membership.** No group/parent/child field exists. Sets are manifest convention; two indexers can disagree.
5. **No atomic / trustless trading.** No multisig escrow, no HTLC, no matching. A SEND is one-sided with no payment leg. Whoever moves first bears full counterparty risk. **Do not ship anything that implies atomic or trustless trading.**
6. **Public ZSLP is fully public and linkable.** Ownership and every transfer ride transparent t-address dust — the *opposite* of shielded. Each owned token is a 546-sat dust UTXO degrading wallet hygiene and correlating addresses. ZSLP cannot ride shielded outputs (z-addresses can't hold ZSLP tokens).
7. **Private ≠ undetectable.** The shielded channel hides content, recipient, amount, metadata. It **leaks** the count/size/timing of the output burst (coarse file-size signal) and, **if fees come from a t-address, the sender.** A burst of all-512B shielded memos is a distinct "data channel" signature. It is a confidentiality channel, **not** steganography. Mitigations (shielded-only funding, single-use recipient z-addr, randomized delays) are disciplined UX the user can get wrong.
8. **Permanence is a node-operator liability.** Opaque encrypted bytes are stored by every full node forever with no pruning. Keep assets ≤64KB; multi-MB is irresponsible chain bloat.
9. **Hash binding breaks on transcode/resize.** SHA-256 is over exact original bytes. The wallet must pin original bytes. If off-chain/uncached bytes vanish, the hash is orphaned — provably *which* image, just unviewable.
10. **PRIVACY HARD RULE.** The wallet must **NEVER** silently auto-fetch a `documenturl` image over the network (leaks IP + interest). Image bytes come from **local cache or explicit user action only**; an uncached NFT shows an amber "not cached" state. No `QtWebEngine`/browser anywhere — all native Qt delegate paint.

---

## 5. Build dependency order (what unlocks what)

Each layer is a hard prerequisite for the next. The first layer is **done**; the chain of builds is contained, not research (encoders are ported, libsodium is linked, the gallery render path bundles clean).

```
[0] Read index + read RPCs ............................ ✅ DONE
     zslp_gettoken/listtokens/listtransfers/listmytokens
     -zslpindex default ON; reorg-safe LevelDB store + undo log
     slp_build_genesis/mint/send encoders ported
        │
        ▼
[1] Gallery wiring ................................... 🔨  (unlocks: live verify badges)
     rpc.cpp → call zslp_* → map to QVector<NFTItem>
     (today: 0 zslp_* calls, fixture-fed; render pipeline already built)
        │
        ▼
[2] Public minting RPCs (Phase B) ................... 🔨  (unlocks: mint / gift / airdrop / editions / set anchors)
     zslp_genesis + zslp_send via CRecipient.scriptPubKey + CreateTransaction
     (createrawtransaction has NO data branch)
     GUI mint + gift dialogs (threaded SHA256, send-guard)
        │
        ├──────────────────────────────► [5] Card sets / completion ... 🔨 (Phase D)
        │                                   manifest schema + grouped CollectionsModel
        │                                   + completion bar; needs [1]+[2]
        │
        ▼
[3] Shielded data channel (ZDC1) .................... 🔨  (unlocks: any >512B private payload)
     FIRST: fix GUI binary-memo DROP (rpc.cpp ~756-760) + send path (sendtab.cpp)
     src/datachannel/frame.{h,cpp} (CRC32 + header)
     src/datachannel/aead.cpp (libsodium, zero new deps)
     z_senddatafile / z_listdatatransfers / z_getdatatransfer / z_receivedatafile
     seq-keyed reassembly + DoS guards; default-OFF + permanence consent
        │
        ▼
[4] Private NFTs .................................... 🔨  (the differentiator)
     ZSLP-shaped record in encrypted START frame + asset in DATA frames
     KEY frame → sealed-then-reveal; gallery fed by decrypted-memo scans
        │
        ▼
[6] Hybrid (public pointer + private payload) ....... 🌫️
     union of [2] + [3]/[4]: public ZSLP token whose hash commits to private ciphertext
     (transfer_id = token_id); auditable custody + confidential bytes
```

**Critical sequencing notes:**
- **[1] before [2]:** wire the gallery to real read data before minting, so the first thing a creator mints is immediately visible + verified.
- **Binary-memo fix gates all of [3]/[4]:** until `rpc.cpp` ~756-760 stops coercing binary memos into a QString and dropping empties, no ZDC1 frame ever reaches a handler. Fix it *first*.
- **[2] and [3] are independent tracks:** public minting (transparent) and the shielded channel (private) can be built in parallel; they only converge at [6] hybrid.
- **Default-OFF everywhere it spends/stores:** minting spends real coin; the data channel writes permanent all-node bytes. Both ship with explicit cost/permanence consent and safe defaults (Krug: "don't make me think" — obvious affordances, plain copy, instant feedback).

---

### Appendix — the north star, stated plainly

> ZClassic can deliver a **verified, locally hash-checked, native-Qt NFT gallery** with accurate "owned vs known" counts, **public 1-of-1 provenance**, and a genuinely distinct **private NFT** experience where the art itself is sealed on-chain and ownership is key possession.
>
> "Known" is always relative to a manifest you trust. "Owned privately" always means *you can decrypt it*, never *you alone have it*. Nothing on-chain stops a counterfeit "Curio Cards," enforces a royalty, or makes a trade atomic.
>
> Build the honest version. Label the limits in the UI. Never imply enforcement the chain cannot provide.
