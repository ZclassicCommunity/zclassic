# ZClassic NFTs — Capabilities & Vision

> Canonical capability/vision doc. Where this disagrees with `NATIVE_NFT_GUIDE.md` or
> `NFT_FEATURE_CHECKLIST.md`, **this doc and the code win** — those two are stale-conservative
> (they still call the Sell GUI greenfield, call image-verify the worst gap, and call the
> write path untested; all three are now built and tested). Survey-verified against the live
> working trees: daemon on `feature/zslp-nft-indexer`, GUI on `feature/nft-gallery`.

---

## North star

ZClassic NFTs let anyone turn a file into a one-of-a-kind, on-chain collectible whose
ownership is **public and verifiable forever** — minted, viewed, gifted, and sold for **ZCL**
directly from the wallet, with **zero changes to consensus**. An NFT is not a new coin type:
it is a thin, non-consensus overlay (a ZSLP `OP_RETURN` riding a 546-sat transparent dust
output) that old, unmodified nodes relay and mine without knowing it exists, while every
honest wallet deterministically re-derives the same token state from confirmed history. The
money you hold, gift, and sell for is always **ZCL**. Ownership and every transfer are
**always public** — they live on transparent UTXOs that anyone can read. The single privacy
feature is the **ZDC1 shielded data-channel**, which keeps the *file's bytes* private (encrypted
inside Sapling memos) without ever hiding *who owns the token*.

**One thing to internalize:** privacy here means *private file content*, never *private
ownership*. If you mint a "private" NFT, the world still sees that you own token X and sees
every time it changes hands — they just can't read the sealed bytes behind it.

---

## The four pillars

### Pillar 1 — Mint (create an NFT)

**What it is.** Take any file, fingerprint it locally with SHA-256 (the bytes never leave your
machine), and broadcast a baton-less ZSLP GENESIS: decimals 0, quantity 1, no mint baton — a
true 1-of-1. The fingerprint (`document_hash`) is what makes the collectible *verifiable* later.

**How you do it (CLI).**
```
zslp_genesis '{"nft":true,"name":"My Piece","document_hash":"<sha256-of-file>","ticker":"SET","document_url":"https://...","to":"<t-addr>"}'
```
Returns `{ "txid", "tokenid" }`. The daemon self-validates the build with `WouldBeValid`
before it ever broadcasts. (`src/rpc/zslp.cpp:328`)

**How you do it (GUI).** `NftMintDialog`: drag a file → it streams a fingerprint → fill name
and details → choose public (private is gated off, see Pillar 3) → review → **Create**.
Create is gated on having both a name and a fingerprint; pasted web links are rejected as the
anchor; and the dialog shows a permanence warning ("this goes on the public ledger
permanently…") before you commit. Wired via `MainWindow::openMintDialog` → `RPC::mintNFT`
(`rpc.cpp:1045`, warning at `nftmintdialog.cpp:105`).

**Status: BUILT+TESTED.** The full write path (genesis → gettoken → send → listmytokens) runs
in `qa/zslp/zslp-nft-regtest.sh`; GUI mint has 4 widget tests (`nftMint_*`). This was the
single biggest doc-claimed hole — it is **closed**.

**Adjacent mint capabilities:**

- **Fungible / divisible tokens** (decimals 0–9, quantity, optional re-issue mint baton at
  `mint_baton_vout >= 2`) — same `zslp_genesis` without the `nft` preset.
  **BUILT-CLI-ONLY** (no GUI; covered by the regtest GOLD case).
- **Re-issue supply** of a fungible token by spending its live mint baton:
  `zslp_mint "tokenid" amount (baton_vout)` (`zslp.cpp:464`). NFTs never use this.
  **BUILT-CLI-ONLY.**
- **Limited / numbered editions ("N of 100")** — `zslp_genesis` with quantity=N and the baton
  off, or N separate 1-of-1s. **BUILT-CLI-ONLY** (RPC supports it; no GUI affordance;
  edition numbering is a manifest convention, not enforced on-chain).
- **Anti-burn holder safety** — ordinary send/shield/sweep operations will never accidentally
  spend a token's carrier dust. Two independent guards: the builder self-validate gate
  (`BuildAndCommitZSLP` → `WouldBeValid`) and coin selection that drops protected outpoints
  (`AvailableCoins(fExcludeZSLPTokens=true)` via `ZSLPIsProtectedTokenOutpoint`).
  **BUILT+TESTED** (self-validate gate is gtested; the decision is also exercised end-to-end
  in the regtest and sell flows).
- **Deliberate burn / retire-an-edition** — there is no sanctioned destroy primitive.
  Anti-burn protects against accidents; intentional burning has no RPC or GUI.
  **DESIGNED-NOT-BUILT.**

---

### Pillar 2 — View / Verify (discover, inspect, prove)

**What it is.** See the NFTs your wallet owns in a native dark-themed gallery (a real Qt
`QListView` in IconMode — no embedded browser), and *prove* that the file you hold matches the
fingerprint recorded on-chain. Verification is local-only: the wallet never fetches the
`document_url` to check it.

**How you do it (CLI).**
- `zslp_listmytokens` → tokens with a positive balance at your addresses
  (per-address roll-up, `zslp.cpp:191`).
- `zslp_gettoken "id"` → full public metadata for one token (`zslp.cpp:73`).
- `zslp_listtokens (count from)` → browse all tokens, clamped to `ZSLP_LIST_MAX=1000`
  (`zslp.cpp:107`).
- `zslp_listtransfers "id" (count from)` → full public provenance, newest-first and
  reorg-safe (`zslp.cpp:142`).

**How you do it (GUI).** The gallery (`NFTGalleryModel` / `NFTGalleryDelegate`, fed by
`RPC::refreshNFTs`, `rpc.cpp:824`) shows each owned NFT with a verify badge and a
public/private pill. Opening one gives `NFTDetailDialog`: a large verified render, the mint id,
fingerprint, received date, copy actions, prev/next navigation, an explorer deep-link, and
Send / Sell / Attach buttons. The badge honestly reads "these bytes match the on-chain
fingerprint" — never "genuine," "official," or "original."

The image check runs in `ContentEngine`, which streams SHA-256 / Merkle hashing on a worker
pool and returns ✓ match / ✗ mismatch / ? pending (`contentengine.cpp`). If you *received* an
NFT but don't have the bytes yet, the detail dialog's "Attach the file you have…" button lets
you point at a local file; a match flips the badge green and caches the path
(`nftdetaildialog.cpp:165,569`).

**Status: BUILT+TESTED.** Gallery model/delegate, content engine (14 `ce*`/cache tests),
attach-to-verify (`nftDetail_attachFileVerifiesBadge` / `attachNonMatchStaysUnverified`), and
the detail dialog's verified / mismatch / no-bytes badge-copy paths all have widget tests. The
attach-and-verify flow was the doc's "confirmed worst gap" — it is **closed**.

**Honest limits in View/Verify:**

- **Browse-all from the GUI** — `zslp_listtokens` exists but the GUI only renders tokens you
  own. **BUILT-CLI-ONLY** for whole-chain browsing.
- **Provenance in the GUI** — `zslp_listtransfers` exists and is reorg-safe, but **no GUI code
  calls it** (grep-confirmed empty). The detail dialog advertises provenance, yet the
  chain-of-custody history is currently only reachable via CLI. **GUI: DESIGNED-NOT-BUILT.**
- **Freshness** — `refreshNFTs` repaints mainly on a new block, and ownership shows PENDING
  below `DEFAULT_MAX_REORG_DEPTH=10` confirmations. A same-block re-open can momentarily look
  empty. **BUILT+TESTED (partial)** — minor.
- **Hash-less NFTs** — `document_hash` is *optional* for `nft=true`, so a CLI- or
  foreign-minted NFT with no anchor is permanently unverifiable (badge stays neutral). The
  GUI mint always requires an anchor; a daemon-side "require an anchor" rule is still a pending
  decision. **DESIGNED-NOT-BUILT.**

---

### Pillar 3 — Shield (private FILE CONTENT via ZDC1) — *bytes private, ownership still public*

**What it is.** The ZDC1 shielded data-channel makes the *content* of a file private without
touching token ownership. Bytes are sealed with a per-transfer key
(ChaCha20-Poly1305 AEAD), framed, and shipped as Sapling shielded-memo outputs inside one
shielded transaction. This rides the existing `z_sendmany`-style memo path with **no consensus
change**. It hides the payload and the data-transfer linkage; it does **not** hide who owns the
token. A "private NFT" is just a normal public NFT whose `document_hash` points at the sealed
ciphertext instead of a plaintext file.

**How you do it (CLI).**
- Send: `z_senddatafile '{"fromaddress":"<z>","toaddress":"<z>","filepath":"...","acknowledge_permanent":true}'`
  → `{ operationid, transfer_id, fingerprint, frames, key }` (`datachannel.cpp:157`). The
  daemon enforces a required-true `acknowledge_permanent`, shielded from/to addresses, a
  **per-file cap of 40000 bytes** (`ZDC_MAX_FILE_BYTES`; the file's top comment saying "64 KB"
  is stale), a 90-frame single-tx ceiling, 256 max in-flight, a 72h TTL, and a basic rate
  guard.
- List: `z_listdatatransfers` (`datachannel.cpp:372`).
- Receive: `z_getdatatransfer '{"transfer_id":"...","verify_fingerprint":true}'`
  (`datachannel.cpp:407`) — verify-before-decrypt; it refuses to hand back plaintext if the
  on-chain ciphertext doesn't match the expected anchor, with honest `ERR_NO_KEY` /
  `ERR_AEAD_FAIL` / `ERR_HASH_MISMATCH` errors.
- Private NFT (the as-built 2-step recipe): `z_senddatafile` for the sealed bytes, then an
  ordinary `zslp_genesis` whose `document_hash` is the ciphertext fingerprint.
- Selective disclosure to an auditor or buyer: reuse the per-transfer `key`, or hand over an
  incoming viewing key via `z_exportviewingkey` (read/prove only, never spend).

**Status: BUILT-CLI-ONLY**, default-OFF behind `-experimentalfeatures -datachannel`
(dev/testnet only). The ZDC1 codec itself (frame / reassemble / AEAD /
ciphertext-fingerprint / verify-before-decrypt) is **BUILT+TESTED** (25 `test_zdc.cpp`
blocks), and a full cross-wallet private round-trip runs in `qa/zslp/zdc-xwallet-regtest.sh`.

**How you do it (GUI).** You don't, yet. Private mint / send / receive are hard-gated off:
`RPC::isPrivateMintWired()` returns `false` (`rpc.h:326`). The mint dialog shows "Private
collectibles are coming in this release" (`nftmintdialog.cpp:90`) and the send dialog shows
"Private gift — coming soon" (`nftsenddialog.cpp:80`). The binary-safe memo-read fix (sniff
the `ZDC1` magic on the raw 512-byte memo before constructing a `QString`) is **not** applied
on the GUI side. **GUI: DESIGNED-NOT-BUILT.**

**Also not built / out of scope:**
- `z_revealkey` (seal-now, reveal-key-later) and `zslp_mint_private` (one-shot private mint)
  are not in the command table. **DESIGNED-NOT-BUILT.**
- Shielding token *value/ownership* through Sapling is impossible on existing consensus
  (shielded notes carry no script). **Correctly out of scope.**

---

### Pillar 4 — Sell / Trade (NFT ⇄ ZCL)

**What it is.** A transparent, single-transaction atomic swap of an NFT for ZCL. The template
is a fixed 3-output transaction signed `SIGHASH_ALL | ANYONECANPAY`:
vout[0] is the ZSLP SEND `OP_RETURN`, vout[1] is the buyer's NFT dust, vout[2] is the seller's
ZCL payout. The seller signs only their NFT input (vin[0]); the buyer appends funding inputs.
The coin legs are **consensus-atomic** — either the whole swap confirms or none of it does.
Token *attribution* is an indexer convention, so this is **trust-minimized, not trustless**,
and it is **never private** — price and both addresses settle publicly on-chain.

**How you do it (CLI).** (`src/rpc/nftoffer.cpp:1178-1186`)
- `nft_makeoffer` — compose an offer (locks the seller's outpoint in the wallet).
- `nft_verifyoffer` — mandatory pre-pay check; runs `VerifyScript` on vin[0].
- `nft_takeoffer` — buyer funds and broadcasts (anti-burn applied to buyer funding; no
  `fundrawtransaction`).
- `nft_listoffers`, `nft_canceloffer` (releases the lock), `nft_requestbuy`.

**How you do it (GUI).** From the detail dialog's **Sell** button, `NFTSellDialog` lets you set
price / expiry / buyer address, click **List**, and get a shareable offer blob with
Copy / Save (`*.znftoffer`) / Cancel (`nftdetaildialog.cpp:146,462`). From the gallery's
**Buy an NFT** button, `NFTBuyDialog` lets you paste or open an offer, auto-runs
`nft_verifyoffer` for a green/amber verdict, and gates **Buy** on a verified offer plus an
overshoot acknowledgement before calling `nft_takeoffer`
(`mainwindow.cpp:3041,3205`). RPC wrappers `nftMakeOffer / nftVerifyOffer / nftTakeOffer /
nftListOffers / nftCancelOffer` plus `zclToZat` live at `rpc.cpp:1261-1438`. The buy dialog
states honestly that the swap "settles publicly on-chain — price and both addresses are
visible" (`nftbuydialog.cpp:114`); a fingerprint-mismatch item disables List.

**Status: BUILT+TESTED.** 6 `test_nftoffer.cpp` gtests plus `qa/zslp/nft-sell-regtest.sh`
exercise the atomic swap and its refusals (signature-tamper, forged, overshoot). The GUI has
`nftSell_*` (×4) and `nftBuy_*` (×5) widget tests. **Caveat: the sell/buy dialog files are
UNCOMMITTED** (untracked `nftselldialog.*` / `nftbuydialog.*` in the GUI tree) — commit them
before they're lost. The docs still call this greenfield; that is stale — it is built.

**Sell — honest limits / not built:**
- **Open / floor listings and marketplace browse** — v1 requires a specific buyer address
  (`buyerNftAddr` mandatory); offers are shared offline as base64 blobs through a local
  `nftoffers.json` store; there is no in-app marketplace. **FUTURE-IDEA** (documented follow-up).
- **Any shielded leg atomic** — impossible in-codebase (a Sapling binding signature is
  single-party). **Out of scope.**
- **Escrowed / disputed sale (2-of-3 P2SH multisig)** — the script primitives exist and are
  tested (P2SH / CLTV / multisig), but there's no flow, RPC, or trusted-arbiter design.
  **FUTURE-IDEA.**

---

## Collections, gifting, and provenance

**Gift / transfer an NFT (one-way, always public).** `zslp_send "tokenid" "to_address"
(amount change_address)` (`zslp.cpp:543`); GUI `NFTSendDialog` via `RPC::sendNFT`
(`rpc.cpp:1108`), where a fingerprint-mismatch item hard-disables Send.
**BUILT+TESTED** (regtest send leg + `nftSend_*` ×4 widget tests). Every transfer is
transparent and visible on-chain.

**Airdrop / batch.** The builder can fan out up to `ZSLP_SEND_MAX_OUTPUTS=19` token outputs in
one `zslp_send`, but the RPC argument surface is single-recipient.
**BUILT-CLI-ONLY (builder-capable).**

**Collections / card-sets ("collect them all").** A shared `ticker` groups tokens into a set,
and the GUI maps `ticker` → collection so the gallery can group owned items. But there is **no
on-chain full slot list** — the daemon only knows the tokens *you* hold — so any "set board"
must show owned slots plus "manifest not available" and must never invent a slot count. The
set-board model/delegate is spec'd (guide §2.7) but not built; today the gallery groups by
collection only. **DESIGNED-NOT-BUILT.**

**Provenance.** Full public chain-of-custody is available via `zslp_listtransfers` (newest
-first, reorg-safe), but **no GUI surfaces it yet**. **CLI: BUILT-CLI-ONLY. GUI:
DESIGNED-NOT-BUILT.**

**The no-fork guarantee.** The whole overlay depends on the ZSLP `OP_RETURN` passing
`IsStandard` unchanged so old nodes relay and mine it. Today this is enforced only by a
223-byte builder-length assert and is **not** tied by any test to mainnet
`-datacarriersize` / policy. The claim is sound by construction but **BUILT but UNDER-TESTED** —
the "no consensus fork" property is not yet test-proven against real mainnet policy.

---

## Status matrix

| Capability | CLI | GUI | Tested | Status |
|---|---|---|---|---|
| Mint public 1-of-1 NFT | `zslp_genesis` | `NftMintDialog` | regtest + 4 widget | **BUILT+TESTED** |
| Mint fungible/divisible token | `zslp_genesis` | — | regtest GOLD | BUILT-CLI-ONLY |
| Re-issue supply (mint baton) | `zslp_mint` | — | regtest exercises | BUILT-CLI-ONLY |
| Numbered editions ("N of 100") | `zslp_genesis` | — | (RPC-supported) | BUILT-CLI-ONLY |
| Anti-burn holder safety | builder + coin-select | (automatic) | gtest + regtest | **BUILT+TESTED** |
| Deliberate burn / retire | — | — | — | DESIGNED-NOT-BUILT |
| See NFTs I own (gallery) | `zslp_listmytokens` | `NFTGalleryModel` | L0 model/delegate | **BUILT+TESTED** |
| Verify image vs fingerprint | (local) | `ContentEngine` | 14 ce/cache tests | **BUILT+TESTED** |
| Attach received file → verify | (local) | `NFTDetailDialog` | 2 widget tests | **BUILT+TESTED** |
| NFT detail dialog | `zslp_gettoken` | `NFTDetailDialog` | badge widget tests | **BUILT+TESTED** |
| Browse all tokens | `zslp_listtokens` | — | — | BUILT-CLI-ONLY |
| Provenance / transfer history | `zslp_listtransfers` | — (uncalled) | — | CLI: BUILT-CLI-ONLY / GUI: DESIGNED-NOT-BUILT |
| ZDC1 codec (seal/verify bytes) | (lib) | — | 25 zdc tests | **BUILT+TESTED** |
| Send private file (ZDC1) | `z_senddatafile` | — | xwallet regtest | BUILT-CLI-ONLY (default-OFF) |
| List/receive private transfer | `z_listdatatransfers` / `z_getdatatransfer` | — | xwallet regtest | BUILT-CLI-ONLY (default-OFF) |
| Selective disclosure (key/IVK) | `z_exportviewingkey` | — | — | BUILT-CLI-ONLY |
| Private NFT (sealed bytes) | 2-step (`z_senddatafile`+`zslp_genesis`) | — | — | BUILT-CLI-ONLY (default-OFF) |
| GUI private mint/send/receive | — | gated off (`isPrivateMintWired()==false`) | — | DESIGNED-NOT-BUILT |
| `z_revealkey` / `zslp_mint_private` | — | — | — | DESIGNED-NOT-BUILT |
| Transfer / gift NFT (public) | `zslp_send` | `NFTSendDialog` | regtest + 4 widget | **BUILT+TESTED** |
| Airdrop / batch (≤19 outputs) | `zslp_send` (builder) | — | — | BUILT-CLI-ONLY |
| Atomic NFT⇄ZCL swap | `nft_makeoffer`/`verifyoffer`/`takeoffer` | `NFTSellDialog`/`NFTBuyDialog` | 6 gtest + regtest + 9 widget | **BUILT+TESTED** (UNCOMMITTED) |
| Collections / card-set board | (`ticker` group) | gallery groups only | — | DESIGNED-NOT-BUILT |
| Open listings / marketplace | — | — | — | FUTURE-IDEA |
| Escrowed / disputed sale | (primitives only) | — | P2SH/CLTV tested | FUTURE-IDEA |
| No-fork (IsStandard) guarantee | builder assert | — | length-assert only | BUILT but UNDER-TESTED |

Flags: `-zslpindex` defaults **ON**; `-datachannel` defaults **OFF** behind
`-experimentalfeatures`.

---

## What's next / designed-not-built / future ideas

**Closest to shipping (designed, partly wired, just needs GUI/finish):**
1. **GUI provenance** — wire `zslp_listtransfers` into `NFTDetailDialog` so chain-of-custody is
   visible, not just advertised. The daemon side is done.
2. **GUI Shield** — flip `isPrivateMintWired()`, apply the binary-safe `ZDC1`-magic memo read
   in `rpc.cpp`, and surface private mint / send / receive. The codec and CLI are done and
   tested; this is GUI work only.
3. **Card-set board** — build the spec'd set model/delegate (guide §2.7), strictly honest about
   unknown slots ("manifest not available," never an invented count).

**Designed but not built (daemon/RPC):**
4. **`zslp_mint_private`** one-shot private mint and **`z_revealkey`** (seal-now,
   reveal-key-later) — collapse today's manual 2-step private-NFT recipe into one command.
5. **Deliberate burn / retire** — a sanctioned destroy primitive (anti-burn already prevents
   accidents).
6. **Daemon-side "require an anchor" rule** — decide whether `nft=true` should mandate a
   `document_hash` so no NFT is born permanently unverifiable.

**Future ideas (no flow yet):**
7. **Open / floor listings + in-app marketplace browse** — drop the mandatory buyer address;
   share and discover offers natively instead of via offline blobs.
8. **Escrowed / disputed sale** — a 2-of-3 P2SH multisig flow over the existing tested script
   primitives.

**Hardening that gates "ship to mainnet":**
9. **Commit everything.** All ZSLP/ZDC/offer code is uncommitted (daemon working tree;
   untracked GUI sell/buy dialogs). This is the highest-priority risk.
10. **Test the no-fork constraint** against real mainnet `IsStandard` / `-datacarriersize`
    policy, not just the 223-byte builder assert.

**Permanent non-goals (correctly out of scope):**
- Private *ownership/value* of tokens through Sapling — shielded notes carry no script.
- An atomic swap with a shielded leg — a Sapling binding signature is single-party.
