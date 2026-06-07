# ZClassic Native NFTs — The Build-Ready Guide (START HERE)

*The single, canonical, build-ready document for native (no-browser) NFTs on ZClassic:
what you can do, how every screen is built, how privacy works, and the rules nothing may
break. It is status-accurate against the code on `feature/zslp-nft-indexer` (the branch that
actually carries ZSLP — `feature/native-bootstrap-sync-review` has none of it), not
aspirational. Every file:line citation below is against `feature/zslp-nft-indexer`. NOTE: the
entire write path (mint/transfer RPCs, the tx builder, and the AvailableCoins anti-burn
exclusion) currently lives in the **working tree** of that branch and is **not yet committed**
— `git status` shows `M src/rpc/zslp.cpp`, `M src/wallet/wallet.{cpp,h}`, and untracked
`?? src/wallet/zslpwallet.{h,cpp}`. The committed tip carries only the read path.*

> **One-line model:** ZClassic consensus does not know NFTs exist. An NFT is a
> **non-consensus overlay** every honest wallet re-derives identically from the confirmed
> chain. The hard consequence, stated honestly everywhere in the UI: **a forgery can be
> mined, but it credits nobody.** Security is *agreement*, not chain rejection.

---

## What this guide consolidates

This guide is the synthesis of, and front door to, the supporting docs below. Where this
guide and an older doc disagree on **what is built**, this guide and the code win.

| Supporting doc | Role it played | Status |
|---|---|---|
| `CAPABILITY_MAP.md` | works-now / building-now / next status, code-verified | folded into §1 (kept for file:line traceability) |
| `NATIVE_UI_CONSOLIDATED_SPEC.md` | per-screen native-Qt build spec (Audit-A) | folded into §2 (kept as the deep widget-tree reference) |
| `NATIVE_UX.md` + `NATIVE_UI_BUILD_PLAN.md` | the two source UI docs Audit-A reconciled | **superseded** by §2 / `NATIVE_UI_CONSOLIDATED_SPEC.md` |
| `PRIVACY_STACK.md` + `ZDC1_CODEC_SPEC.md` | the four-layer private stack + codec reference | folded into §3 (`ZDC1_CODEC_SPEC.md` kept as codec reference) |
| `PRIVACY.md` + `PRIVACY_UX.md` | privacy normative + UX (Audit-B reconciled) | **superseded** by §3 |
| `SECURITY_MODEL.md` | the normative validation rules / threat table (R-*) | **still normative** — §4 points here; this guide never overrides it |
| `MINT_TRANSFER_SPEC.md` | the write-path tx builder + RPC contract | **still authoritative** for the `zslp_genesis`/`zslp_send` contract |
| `CONTENT_MODEL.md` | any-file → fingerprint (SHA-256 + Merkle, streaming) | **still authoritative** for content addressing |
| `NFT_SELL_DESIGN.md` | the NFT→ZCL sell/trade design (fixed-template `SIGHASH_ALL\|ANYONECANPAY`) | **authoritative for trades — now BUILT** (daemon RPCs landed, atomic swap regtest-proven; design rows mid-fix) |
| `ONCHAIN_TRADES.md` | early transparent-trade sketch | **SUPERSEDED** by `NFT_SELL_DESIGN.md` — its `SINGLE\|ANYONECANPAY` layout is wrong/funds-losing; kept for history only |
| `ENABLEMENT.md` and the threat-model pairs | early why/aspirational + per-topic threat models | **superseded for status** (kept for traceability) |

**Canonical reader path:** this guide → `SECURITY_MODEL.md` (normative rules) →
`MINT_TRANSFER_SPEC.md` (write path) → `NATIVE_UI_CONSOLIDATED_SPEC.md` (deep widget trees)
→ `CONTENT_MODEL.md` → `ZDC1_CODEC_SPEC.md` (codec) → `NFT_SELL_DESIGN.md` (trades).
Everything else is "superseded, kept for traceability" (including `ONCHAIN_TRADES.md`).

---

# 1. WHAT YOU CAN DO

The plain-language capability map. **works-now** = code in-tree and built (cited file);
**building-now** = a separate workflow is actively writing it against a fixed contract;
**next** = designed, not yet written.

### The model behind every status (read once)

A ZClassic NFT is a baton-less SLP **GENESIS** (`decimals=0, quantity=1`) carried in a single
`OP_RETURN`. Every honest wallet/indexer recomputes the same token ledger as a deterministic
function of the confirmed chain. Three things the UI must always hold to:

1. **Ownership is PENDING until ~10 confirmations** (`DEFAULT_MAX_REORG_DEPTH`), because 1–9
   confs are reorg-reversible.
2. **The image badge means only "these bytes match this token's on-chain fingerprint"** —
   never genuine / official / original.
3. **Identity is the genesis txid**, never the name / ticker / image (those are freely reusable).

### A. Discover, verify, inspect (the read path) — **works-now**

You can do all of this today:

- **See the NFTs this wallet owns** in a native dark gallery with a verify badge and
  public/private pill — no browser. (`RPC::refreshNFTs()` calls the real `zslp_listmytokens`
  then `zslp_gettoken` per token and feeds `NFTGalleryModel`; `zcl-qt-wallet/src/rpc.cpp:863`.
  Daemon `zslp_listmytokens` at `src/rpc/zslp.cpp:191`.)
- **Verify an image** against its on-chain fingerprint (✓ match / ✗ mismatch / ? pending),
  locally, **never fetching the remote URL**. (`ContentEngine` streaming SHA-256 + verify on a
  worker thread; `zcl-qt-wallet/src/contentengine.{h,cpp}`.)
- **Look up any public token** by genesis txid (ticker, name, document_url, 32-byte hash,
  decimals, height, totalMinted, baton state). (`zslp_gettoken`; `src/rpc/zslp.cpp:73`.)
- **Confirm a real 1-of-1 + supply cap** (`totalMinted==1 && hasMintBaton==false`).
- **Read full public transfer history** (newest-first, reorg-safe). (`zslp_listtransfers`;
  `src/rpc/zslp.cpp:142`.)
- **Browse all indexed tokens** (bounded paging, clamped to `ZSLP_LIST_MAX=1000`).
  (`zslp_listtokens`; `src/rpc/zslp.cpp:107`.)
- **Trust the ledger is forgery-proof** — a forged SEND/MINT credits nobody; an NFT can't be
  duplicated. (UTXO-bound conservation indexer; `vout[0]`-only parse at
  `src/zslp/zslpindexer.cpp:229`; single `ZSLP_SEND_MAX_OUTPUTS=19`; `ChainTip`-only, no
  mempool/0-conf path. ~101 ZSLP gtests across `src/gtest/test_zslp*.cpp`.)

### B. Create and move NFTs (the write path) — **works-now (daemon, working tree); GUI next**

These daemon RPCs are built; they are present in the `feature/zslp-nft-indexer` working tree
(uncommitted) and not yet exercised by the GUI. The GUI dialogs (§2) are designed and degrade
honestly until they are wired to call the RPCs in a build that carries them.

- **Mint a public 1-of-1** — drag a file, hash it locally, fill in a name, broadcast a
  baton-less GENESIS. → `zslp_genesis '{nft:true, name, document_url, document_hash,
  [ticker], [to (t-addr)]}'` → `{txid, tokenid}`. `nft:true` forces `decimals=0`,
  `quantity=1`, and no mint baton; an optional `mint_baton_vout` (must be `>=2`) issues a
  re-issue baton for the fungible case. *(RPC implemented in the working tree on
  `feature/zslp-nft-indexer` — `src/rpc/zslp.cpp:330`, registered in the command table at
  `:661` — not yet committed/merged; encoders + `MINT_TRANSFER_SPEC.md` ready.)*
- **Transfer / gift** an NFT to a recipient. → `zslp_send(token_id, to_address, amount=1,
  [change_address])` → `{txid}`. *(RPC implemented in the working tree on
  `feature/zslp-nft-indexer` — `src/rpc/zslp.cpp:545`, registered at `:663` — not yet
  committed/merged. `zslp_mint` (fungible re-issue) also lands here at `:466`/`:662`.)*
- **Airdrop / batch** up to 19 token outputs in one tx — rides `zslp_send` multi-output.
- **Limited / numbered editions** ("N of 100") — `zslp_genesis` qty=N baton-off, or N separate
  1-of-1s.
- **Hold an NFT without burning it** — an ordinary send/shield/sweep must never spend the
  carrier dust. Two distinct mechanisms back this, and BOTH are now wired in the working tree
  on `feature/zslp-nft-indexer` (uncommitted):
  - **The write path's own self-validate-before-broadcast gate (R-WALLET-9) IS wired.**
    `BuildAndCommitZSLP` calls `store->WouldBeValid(...)` (`src/wallet/zslpwallet.cpp:460`)
    and aborts with *"self-validate: built tx would not be valid in the token ledger (…)"*
    BEFORE `CommitTransaction` (`:475`). The builder never broadcasts a tx that would not be
    valid in the token ledger.
  - **Ordinary-send anti-burn via `AvailableCoins` token-UTXO exclusion IS wired.**
    `AvailableCoins` now takes `fExcludeZSLPTokens` (default `true`, `wallet.h:1124`) and
    drops protected token/dust outpoints via `ZSLPIsProtectedTokenOutpoint(...)`
    (`wallet.cpp:3197`), so no ordinary send/shield/sweep coin-selection path picks up a
    carrier UTXO (explicitly preset/coin-controlled inputs are exempt so the ZSLP builder can
    still pin its own token inputs). The primitive itself (`ZSLPFindWalletTokenUtxos` +
    `SLP_TOKEN_DUST=546`, `src/wallet/zslpwallet.{h,cpp}`) underpins both.

  Holder safety is therefore mechanically complete in the working tree — see §4. It becomes
  the shipped guarantee once these uncommitted changes are committed/merged AND the standard
  spend paths are confirmed to call `AvailableCoins` with the default (token-excluding) value.
  Do not let any UI copy imply burn-proof holding outside a build that carries these changes.

### C. Native mint / detail / set UI — **next**

Designed in §2 (and `NATIVE_UI_CONSOLIDATED_SPEC.md`); GUI dialog files not yet created.

- **Detail dialog** (`NFTDetailDialog`): large verified render, provenance rows, copy id /
  fingerprint, prev/next.
- **Create-NFT mint wizard** (`NftMintDialog`): drop file → streaming fingerprint → public/
  private → review "what becomes public" → Create. Calls `zslp_genesis`. The Private tile is
  gated off (`isPrivateMintWired()==false`) until the shielded channel lands.
- **Card sets / "collect them all"** completion bar (manifest convention only — see ceilings).

### D. Private NFTs and the shielded data channel — **works-now (daemon, CLI; default-OFF, experimental); native GUI next**

- **The ZDC1 codec itself** (frame / reassemble / AEAD / seal-then-reveal / ciphertext
  fingerprint) is **built + self-tested AND now compiled into the daemon**
  (`src/datachannel/zdc.{h,cpp}` in `src/Makefile.am:247,294`; codec self-checks +
  25 daemon gtests in `test_zdc.cpp`, ASan/UBSan-clean, secret-zeroized).
- **Send a private file / message** (sealed bytes on-chain, ownership = key possession,
  selective disclosure via viewing key) — daemon RPCs `z_senddatafile` /
  `z_listdatatransfers` / `z_getdatatransfer` ARE present and registered
  (`src/rpc/datachannel.cpp:597-599`), **default-OFF** behind
  `-experimentalfeatures -datachannel` (each returns `-32601` when off), with
  daemon-enforced `acknowledge_permanent=true` and verify-before-decrypt. They ride the
  existing Sapling binary-memo path; no consensus change. Live round-trip proven. Full
  as-built contract in §3. *(Private minting — a single `zslp_mint_private` RPC — is
  designed but NOT built; the built private-mint path today is `z_senddatafile` for the
  sealed bytes plus an ordinary `zslp_genesis` whose `document_hash` commits to the
  ciphertext fingerprint. See §3.3.)*
- **Receive a private NFT in the gallery** (decrypt locally, render natively, verify badge) —
  needs the GUI binary-memo branch fix (`rpc.cpp` ~756) that sniffs the `ZDC1` magic on RAW
  bytes before any `QString` conversion. No native SHIELD GUI exists yet, so SHIELD is
  CLI-only on dev/testnet today.

### E. Trade NFT ⇄ ZCL — **works-now (daemon, CLI; dev/testnet)**, and a hard ceiling

- **Transparent NFT ⇄ transparent ZCL, atomic single tx** — **built** via a
  fixed-template `SIGHASH_ALL|ANYONECANPAY` signed offer (seller signs ONLY their
  NFT input `vin[0]` over the COMPLETE 3-output template: OP_RETURN ZSLP SEND@vout[0]
  / buyer NFT dust@vout[1] / seller ZCL payout@vout[2]; `ANYONECANPAY` lets the buyer
  append funding inputs, `ALL` pins the whole output set). Coin legs are
  consensus-atomic, token attribution is indexer-convention, so **trust-minimized,
  not trustless**. The daemon RPCs `nft_makeoffer` / `nft_verifyoffer` (mandatory) /
  `nft_takeoffer` / `nft_listoffers` / `nft_canceloffer` / `nft_requestbuy` ARE built
  and registered (`src/rpc/nftoffer.cpp:1180-1186`, compiled `src/Makefile.am:292`),
  regtest-proven at `qa/zslp/nft-sell-regtest.sh` with 6 gtests; see
  `NFT_SELL_DESIGN.md` (authoritative). Only the native GUI offer dialog (§2.8) is
  still pending. **Note:** `SIGHASH_SINGLE|ANYONECANPAY` does
  NOT work for ZSLP — SINGLE would pin the OP_RETURN (vout[0]) instead of the payout
  and burn the seller's NFT; see `NFT_SELL_DESIGN.md §0`.
- **Any leg shielded, atomic** — *impossible in-codebase* (z-notes carry no script; the Sapling
  binding sig is single-party over the whole tx). Not on the roadmap.
- **Escrowed / disputed sale** — possible via 2-of-3 P2SH multisig, but **trusted** (the
  arbiter). Opt-in only.

---

# 2. NATIVE UI SPEC

100% native Qt (`QListView` + `QStyledItemDelegate` + `QPainter`, `QDialog`, `QLabel`/`QPixmap`).
**NO QtWebEngine, NO QtMultimedia, NO browser, anywhere.** Video = poster + open-in-external-
player. C++14 (no `std::optional`/`string_view`; empty-`QString` sentinels + `int verifyState`
0/1/2). Reuses `dark.qss` tokens — adds no new color.

> Deep widget-tree reference (file:line-grounded) lives in `NATIVE_UI_CONSOLIDATED_SPEC.md`.
> This section is the build-ready summary every developer can build straight from.

### 2.0 Seven binding reconciliations (the source docs were WRONG vs the live tree — follow these)

1. **ONE ContentEngine.** The live tree already builds `nftImgCache = new NFTImageCache(nftModel,
   this)` (`mainwindow.cpp:3053`) and `NFTImageCache : public ContentEngine`. Dialogs take a
   `ContentEngine*` and are handed the **existing** `nftImgCache` (upcast). Do **not** create a
   second engine — that's a duplicate 4-thread pool.
2. **Write RPCs are `zslp_genesis` (mint) and `zslp_send` (transfer/gift)** — never `zslp_mint`
   (that's fungible re-issue), never `z_sendmany`/`executeTransaction` (that's only the *future*
   private leg).
3. **Reuse `Settings::getExplorerTxURL(txid)`** (`settings.cpp:421`) — it already appends the
   txid and returns "" on testnet. Do **not** add a new `getExplorerUrl()`.
4. **Add the additive `ContentEngine::posterReady(quint64 token, QImage img, int verifyState)`
   signal** (mirrors `verifyDone`, emit from `deliver()`). It does not exist yet and the detail
   view needs it. This is the **one and only** ContentEngine change.
5. **`getNFTThumbSize()` does NOT exist.** Either ship it as a genuinely new getter/setter, or
   (recommended) **cut the density toggle from v1**.
6. **Fix the subhead copy.** The live `setupNFTTab` ships `"Your NFTs. Each asset is checked
   against its on-chain hash."` (`mainwindow.cpp:3031`) — "hash" as a noun is banned. Use
   **"Your NFTs. The image on each card is checked against its on-chain fingerprint."**
7. **Honor `indexOff`.** `setNFTItems` currently does `(void)indexOff;` (`mainwindow.cpp:3107`);
   `refreshNFTs` already computes `indexOff` from RPC error code -1 (`rpc.cpp:989-999`). Wire it
   to the 4-page stack so the index-off state can actually show.

### 2.1 Shared visual + interaction system (specified once; every screen conforms)

**Tokens (from `dark.qss` + `nftgallerydelegate.cpp`):** app `#0f1115` · card `#15171c` · inset
`#1d2027` · hairline `#2a2d35` · text `#e6e6e6` · dim/AA-floor `#9aa0a6` · private-green `#1f7a1f`
· hero-green `#2a9d2a`/`#34c759` · public/pending-amber `#d9822b` · mismatch-red `#c0392b`. **Add
no new color.**

**Verify badge (status, never a control — no click).** Tinted SVG (`check`/`x`/`question`) on a
dark disc; gallery 16px, detail/mint 20px. The verdict sentences, identical everywhere:
- verified (1): **"This image matches its on-chain fingerprint."**
- mismatch (2): **"This image does NOT match what was recorded on-chain. Don't trust it."**
- pending (0): **"Checking this image…"** (no local bytes: **"Image not downloaded."**)

**Privacy pill.** Green "Private" / amber "Public", leading dot. One-liners: Private — **"Only
you can see this. Its ownership is shielded."**; Public — **"Anyone can verify this on the public
ledger."**

**Card anatomy** (`baseCardSize()` 168×208): square cover-fit thumb (radius 8) · verify badge
top-right of thumb · privacy pill below thumb · bold elided name · dim elided collection.

**The one action set** (same verbs/labels/order wherever an NFT action appears): Open · **Send /
Gift** (green primary) · Save image… · Copy id · Copy fingerprint · Copy collection · Re-check
image · Open in your video player (video kind) · View in explorer (public + configured +
confirmed only). **No "open link"/network item in any browse context menu.** Private items never
expose explorer.

**Banned from every visible string:** "hash" as a noun (say "fingerprint"), SHA-256, OP_RETURN,
GENESIS, token, mint-baton, zslpindex, ivk, "memo" (say "note"), t-addr/z-addr (say "public
(transparent) / private (shielded) address"), and never "Genuine/Authentic/Official/Original" on
the badge.

### 2.2 Gallery (`gallery-grid`)

**Widget tree (top→bottom):**
- **Heading row:** `QLabel#nftGalleryHeading` "Collections" + `QLabel#nftCountChip` ("12 items"
  → "12 of 40" filtered, right-aligned).
- **Subhead:** `QLabel#nftGallerySubhead` = **"Your NFTs. The image on each card is checked
  against its on-chain fingerprint."** (fix per §2.0.6).
- **Toolbar `QHBoxLayout#nftToolbar` (NEW, h=36):** `[search QLineEdit#nftSearch flex] [Filter ▾]
  [Group ▾] [Sort ▾]`. (Density toggle optional — recommend cut for v1.)
  - search placeholder "Search your collection"; Filter = All / Private only / Public only /
    Verified / Needs attention; Group = No groups / By collection / By privacy; Sort = Recently
    received / Name A–Z / Collection.
- **Grid:** the existing `QListView#nftGalleryView` (IconMode, wrapping, `setUniformItemSizes`) +
  `NFTGalleryDelegate`.
- **State stack:** wrap the view in `QStackedWidget#nftGalleryStack` (4 pages — see §2.3).

**Architecture:** a NEW `QSortFilterProxyModel` over the **untouched** `NFTGalleryModel` drives
search/filter/sort/group in-process (no I/O).

**RPC:** none directly — fed by `RPC::refreshNFTs()` on the normal poll (`zslp_listmytokens` →
per-token `zslp_gettoken` → `MainWindow::setNFTItems()`). Every item gets `cachePath=""`
(privacy), so cards stay pending until local bytes exist.

**States:** LOADING (page 3, cards shimmer + amber "?") · EMPTY (page 1, toolbar hidden) ·
ZERO-RESULT (toolbar stays, "Nothing matches" + active filter in words + "Clear filters") ·
VERIFIED/MISMATCH/PENDING per badge · PENDING-NO-BYTES ("Image not downloaded. Open to fetch it
yourself." — never auto-fetched) · PRIVATE/PUBLIC · INDEX-OFF (page 2) · OFFLINE (keep last good
grid, dim the count chip, no spinner-of-doom).

**Interactions:** live search over name+collection · filter/group/sort instant via proxy ·
single-click selects · **double-click/Enter/Space → `openNFTDetail` via `connect(view,
&QListView::activated, ...)` — ACTIVATED ONLY (do NOT also connect `doubleClicked`, or detail
opens twice).** Context menu = browse subset (no link/network item).

### 2.3 First-run / empty (`first-run`, the 4-page stack)

Same centered hero-card geometry on every page so layout never jumps (`#15171c`/hairline/radius
12, max-width 520, centered).

- **Page 0 — gallery** (rows present).
- **Page 1 — EMPTY:** quiet-grey frame glyph (not red/amber), title **"No collectibles yet"**,
  body **"When someone sends you a collectible, or you make one, it shows up here — and the
  wallet checks each picture against its on-chain fingerprint. Nothing to do right now."**, green
  primary **"Make your first collectible"** (opens mint when it lands; before that, **"Show me how
  it works"**), flat link **"What is a collectible?"**.
- **Page 2 — INDEX-OFF (rare/legacy state):** the collectibles index is **ON by default**
  (`-zslpindex` defaults true; `init.cpp:3272-3274`), so this page shows ONLY when a node was
  explicitly started with `-zslpindex=0` or runs a pre-feature daemon. Amber toggle glyph,
  title **"Collectibles tracking is turned off"**, body **"This node was started with
  collectibles tracking off. Turn it back on and the wallet will start finding your
  collectibles — a one-time catch-up scan runs in the background."**, green primary **"Turn on
  collectibles"**. Managed daemon → confirm + restart + scan. Foreign/old daemon → reveal an
  inset with the exact re-enable conf line **`zslpindex=1`** + **"Copy line"** (never a dead
  end). *(This conf line is the ONE place the raw setting name is allowed — it's literal config,
  not prose; and it is the re-enable action, since the index is on by default.)*
- **Page 3 — LOADING:** **"Looking for your collectibles…"** + indeterminate `QProgressBar` +
  **"This runs in the background. You can keep using the wallet."**

**State selection (RPC):** `refreshNFTs` already computes `indexOff` from RPC error code -1
(`rpc.cpp:989-999`) and calls `setNFTItems(empty, indexOff)`. **Wire `setNFTItems` to honor
`indexOff`** (today `(void)indexOff;`): indexOff→page 2; success+empty→page 1; success+rows→page
0; first call outstanding→page 3. Latch the last good page so a transient poll error never
flickers back to empty/off.

### 2.4 Detail dialog (`nft-detail`) — `NFTDetailDialog` (NEW: `src/nftdetaildialog.{h,cpp}`)

Programmatic, modeless-modal (`open()` not `exec()` so the poll loop keeps flowing and back-fill
lands). Min 760×560. Carries the `NFTItem` by value + the ordered POD list by value (no model
pointer) for prev/next.

```cpp
explicit NFTDetailDialog(const NFTItem& item, const QVector<NFTItem>& ordered, int startIndex,
                         ContentEngine* engine, RPC* rpc, QWidget* parent = nullptr);
```
`MainWindow::openNFTDetail(const QModelIndex&)` snapshots the ordered list from `nftModel` and
constructs the dialog with the **existing `nftImgCache`** as `ContentEngine*` (§2.0.1), then
`setAttribute(WA_DeleteOnClose); open();`.

**Layout:**
- **Title bar (h=44):** name 16pt/700 + collection 11pt dim ("Not part of a set" if none); flat
  close glyph.
- **Left — image stage (min 380×380):** centered `QLabel#nftDetailStage` painting the full QPixmap
  `KeepAspectRatio SmoothTransformation` (never upscaled past 1024 native; letterboxed on
  `#1d2027`). 20px verify badge top-right. Shimmer while decoding.
- **Right — info panel (fixed 320):**
  1. **Verify line:** full-width inset, 20px badge + 13pt verdict sentence; color via
     `#nftDetailVerifyLine[state="verified|mismatch|pending"]` dyn-prop (NEW qss, ~3 lines).
  2. **Privacy pill row** + one-liner.
  3. **Details card:** **Mint id** (genesis txid = identity; short 8…8 + copy), **Received** (ISO
     date + "block N", or **"Just arrived — confirming…"** when confs<10), **Creator**
     ("Unknown" — the chain records no issuer), **Set** ("Wild Series — 7 of 30" or "Not part of
     a set"), **Image fingerprint** (short 8…8 + copy). Footnote: **"This name and image aren't
     unique — anyone can mint another collectible that reuses them. Only the mint id is one of a
     kind."**
  4. **Action bar (pinned, h=48):** green **"Send / Gift"** primary · **"Save image…"** · **"Copy
     id"** · overflow **"More"** = Copy fingerprint / Copy collection / Re-check image / View in
     explorer.

**RPC the detail dialog calls:**
- **Poster + verify (local bytes only):** `engine->posterFor(localPath, docHashHex, docHashHex,
  512)` and `engine->verify(localPath, docHashHex, token)`, where
  `localPath = ContentEngine::cacheGet(m_item.docHashHex)` (empty = not on device → never
  fetched). Token-guarded so a fast prev/next drops a stale neighbor's reply. Receives the decoded
  pixmap via the new `posterReady` signal (§2.0.4).
- **Provenance back-fill (NEW `RPC::nftProvenance(tokenId, cb)`):** `zslp_gettoken "tokenId"` →
  set Set/series from `ticker`; Creator stays "Unknown"; any error → honest defaults, no dialog.
- **Received date back-fill (NEW `RPC::txReceivedDate(txid, cb)`):** `gettransaction "txid"` →
  `confirmations` + `blocktime`; confs<10 → "Just arrived — confirming…"; ≥10 → ISO date + "block
  N".
- **View in explorer:** `QDesktopServices::openUrl(QUrl(Settings::getExplorerTxURL(m_item.txid)))`
  after a one-time confirm **"This opens an outside website and may reveal your interest.
  Continue?"** — enabled only if `!getExplorerTxURL(m_item.txid).isEmpty() && !m_item.isPrivate`
  (§2.0.3).
- **Send / Gift:** opens `NFTSendDialog` pre-filled (§2.6). On a MISMATCH item, confirm "This
  image failed its on-chain check. Send anyway?" first.

**Media by kind** (`ContentEngine::classifyKind`; every branch touches only `cacheGet`):
- **Image:** full QPixmap on the stage; resize re-scales from the held source (no re-decode/
  re-hash).
- **Video:** NO in-app playback. Typed film-strip poster + play glyph + caption **"Video · <MIME>
  · <NN.N MB>"** + verify badge + primary **"Open in your video player"** →
  `QDesktopServices::openUrl(QUrl::fromLocalFile(localPath))`, enabled only when local bytes exist
  AND `verifyState == 1`.
- **Document:** typed MIME glyph + "Open" (external only). **Bytes:** typed glyph + "Save as…".
  Never auto-execute.

### 2.5 Mint-from-file (`mint-flow`) — `NftMintDialog` (NEW: `src/nftmintdialog.{h,cpp}`)

Programmatic, modal. Recommended 3-page stack (PICK → DETAILS → REVIEW) so the
"async-hash-gates-Next" contract is trivial.

```cpp
NftMintDialog dlg(nftImgCache /*the existing ContentEngine*/, rpc, this);
if (dlg.exec() == QDialog::Accepted) rpc->refreshNFTs();
```

**Pages:**
- **1 — Your image (dropzone):** drag/drop or "Choose a file…". GUARD with
  `ContentEngine::isRemoteUrl(path)` → reject http(s) drops inline ("For your privacy, drop a
  local file — not a web link."). On a file: `classifyKind` for the glyph, `posterFor` for an
  image poster, prefill name from the basename, then `hashFile(path, token)` (STREAMING — a 2 GB
  file hashes in ~1 MiB RAM). Indeterminate progress + "Reading your file…". Next disabled until
  `descriptorReady`.
- **2 — Details:** Name (required, soft 50-char counter), Collection (optional), Note.
- **3 — Who can see it:** two tiles — **Private** (green) and **Public** (amber).
- **4 — Review & confirm:** thumb + name/collection + visibility pill + "Fingerprint 1f2a…9c0d" +
  size + "What goes on-chain (public)" line + the honesty line + fee row + "After this you'll have
  N ZCL".

> **Gating polarity (load-bearing).** The building-now write path is the **public**
> `zslp_genesis`; the **private** path needs the not-yet-built ZDC1 channel. So in the first
> shipped cut the **Public tile is wired and default-selected**, and the **Private tile is
> "Coming in this release"** (gated off by `isPrivateMintWired()==false`). This is the OPPOSITE
> of NATIVE_UX's "Private default." **Gate OFF whichever path's RPC is missing; never ship a
> Private-default mint with no working broadcast (a dead Create button).** Flip to Private-default
> once ZDC1 lands (build order step 6).

**RPC the mint dialog calls — `RPC::mintNFT(descriptor, opts, cb)` → `zslp_genesis`:**
```
zslp_genesis '{ "nft": true, "ticker": <collection>, "name": <name>,
                "document_url": <url or "">, "document_hash": <64-hex anchor> }'
  -> { "txid", "tokenid" }   (tokenid == txid)
```
`nft:true` forces `decimals=0, quantity=1` and no baton. `document_hash` = the descriptor's `merkleRoot` for
large files else `sha256Whole`, lowercase hex. On success, `ContentEngine::cachePut(anchorHex,
srcPath)` so the new card verifies green immediately, then `accept()` → `refreshNFTs()`. On error,
show the daemon message verbatim inline (never a fabricated success).

**States:** EMPTY/PICK · REMOTE-URL REJECTED · HASHING (Next disabled) · READY ("Fingerprint
ready.") · UNREADABLE · PRIVATE COMING-SOON (today: Private tile disabled "Coming in this
release", Public forced-on; Create never dead) · REVIEW · CREATING · MINT ERROR (inline daemon
message) · SUCCESS (toast "NFT created — Aurora #14" + "Show it") · low-balance.

**Key copy:** "Minting does NOT upload your file anywhere. Only its fingerprint goes on-chain —
the file stays on your computer."

### 2.6 Send / Gift (`send-gift`) — `NFTSendDialog` (NEW: `src/nftsenddialog.{h,cpp}`)

Modal; constructor **requires** an `NFTItem` (no empty state). windowTitle "Send a gift".

**Cards:**
- **1 — What you're giving:** 72×72 inset thumb fed from disk cache + verify badge + name +
  collection + privacy pill. Read-only.
- **2 — Who gets it:** "Send to" + the existing `AddressCombo` + "Address book". One
  reserved-height live status line: valid private → green "Looks good — a private (shielded)
  address"; valid public → amber "Looks good — a public (transparent) address"; invalid → red
  "That doesn't look like a ZClassic address". Validation is local/debounced (no per-keystroke
  RPC).
- **3 — How private:** **Public gift** [amber] — wired now via `zslp_send`. **Private gift**
  [green] — the shielded-memo path, "Coming soon", disabled until ZDC1 lands. (OPPOSITE polarity
  of NATIVE_UX for the same building-now reason.)
- **4 — Add a note (optional, collapsed):** public gifts hide it ("Public gifts can't include a
  private note.").

**RPC the send dialog calls — `RPC::sendNFT(tokenId, toAddress, cb)` → `zslp_send`:**
```
zslp_send "tokenid" "to_address" 1   -> { "txid" }
```
amount defaults to 1. The daemon builder enforces anti-burn + self-validate-before-broadcast; the
UI never builds a raw spend. Private gift (future) routes via the ZDC1 channel — NOT `zslp_send`;
this is the ONLY place `executeTransaction` would be correct, and only for the private leg.

The green action label states the outcome: Public → "Send gift". Disabled until valid recipient
AND not a red mismatch AND not already in flight.

**States:** ready · thumb pending/verified/MISMATCH ("This picture doesn't match its fingerprint
— we won't send it.", action disabled) · recipient empty/valid-private/valid-public/invalid ·
sending · sent ("Gift sent. It's on its way to them.") · error (inline red + daemon reason + "Try
again", nothing sent) · index-off (Public still works).

### 2.7 Set / collection board (`set-collection`)

A stacked page **inside the Collections tab** (`QStackedWidget` index 1; index 0 = gallery),
reached by clicking a set thumbnail. Header (back "‹ Collections" + set name + "Created by
{creator} · {N} cards" + completion meter "3 of 7 collected", green track fill) · the board
(`QListView` IconMode fed by a NEW `SetBoardModel`, painted by `SetSlotDelegate :
NFTGalleryDelegate` — owned slots = the §2.1 card; missing slots = ghost variant: 55% opacity,
"#N" numeral, "Not collected", **no image request issued**) · footer help bar (only when
missing>0): "Missing {n} cards. They arrive when someone sends them to your wallet." + quiet "Show
my receive address". **No in-app buy/trade.**

**RPC:** set membership comes from the already-fetched `zslp_gettoken` metadata (the `ticker`
groups a card-set; `refreshNFTs` maps `ticker`→`collection`, `rpc.cpp:949`). **There is no
on-chain source for the full slot list** — the daemon only knows the tokens you HOLD. Until a
creator-published manifest is resolved locally/explicitly, the board shows **owned slots + a calm
"manifest not available" note** rather than fabricating ghost slots. **Never invent slot
counts/numbers/names.**

The creator's verified-issuer tick appears ONLY when its mint id is on a named verified-issuer
list; tooltip "On {maintainer}'s verified-issuer list" — never a bare "Verified" (it's social,
not a network guarantee).

### 2.8 Trade UI — **next** (daemon SELL RPCs already built)

The daemon SELL RPCs are built (atomic swap, regtest-proven — see §1.E); the remaining work is
the native GUI. The detail dialog's "More" menu gains "Offer for ZCL…" → a native offer dialog
that composes `nft_makeoffer`/`nft_verifyoffer`/`nft_takeoffer` (transparent only, fixed-template
`SIGHASH_ALL|ANYONECANPAY`). UI copy must say **trust-minimized, not trustless** (token
attribution is indexer convention), must always run `nft_verifyoffer` before `nft_takeoffer`, and
must never imply a shielded leg can be atomic. No in-app marketplace.

### 2.9 File map + build order (grounded in the live tree)

**New files:** `src/nftdetaildialog.{h,cpp}` · `src/nftmintdialog.{h,cpp}` ·
`src/nftsenddialog.{h,cpp}` · `src/setboardmodel.{h,cpp}` · `src/setslotdelegate.{h,cpp}` · a
`QSortFilterProxyModel` (inline or small `nftgalleryproxy.{h,cpp}`).

**Edited files:** `src/mainwindow.{h,cpp}` (4-page stack; toolbar; set-board page; `openNFTDetail`
+ the single `activated` connect; `openMintDialog`; honor `indexOff`; fix subhead; pass the
existing `nftImgCache`) · `src/contentengine.{h,cpp}` (ADD `posterReady` + emit in `deliver()` —
nothing else) · `src/rpc.{h,cpp}` (ADD `mintNFT`→`zslp_genesis`, `sendNFT`→`zslp_send`,
`nftProvenance`→`zslp_gettoken`, `txReceivedDate`→`gettransaction`; `isPrivateMintWired()` →
hard-false until ZDC1) · `src/settings.{h,cpp}` (REUSE `getExplorerTxURL`; add `getNFTThumbSize`
ONLY if density kept) · `res/styles/dark.qss` (append object-name rules using existing tokens
only) · `application.qrc` + `res/icons/` (new tinted SVGs) · `zcl-qt-wallet.pro` (add the new
sources; no new Qt module).

**Build order (each step shippable):** (1) RPC + settings + `posterReady` scaffolding; (2)
gallery state-stack + proxy + first-run/index-off; (3) detail dialog; (4) set board; (5) mint +
send (public, `zslp_genesis`/`zslp_send`); (6) private channel (ZDC1) → flip the gating so Private
becomes the safe default per NATIVE_UX.

**Performance/privacy contract (defect if violated):** no web/multimedia ever · bounded
`QThreadPool(4)`, worker produces only `QImage` (QPixmap built on the GUI thread) · two-tier cache,
resize re-scales from held source · in-flight dedupe · `setUniformItemSizes` (no relayout on
scroll) · one shimmer timer over visible pending only (missing slots issue ZERO image requests) ·
fingerprint-guarded models + in-process proxy · hot path touches ONLY local bytes; `isRemoteUrl`
rejects http(s); the only network touches are explicit confirmed user actions + the mint/send
broadcast · RPC stays off the GUI/paint thread via `doRPC`.

---

# 3. PRIVACY

Private NFTs and a general shielded data channel. **Default-OFF**, permanence-consent-gated, rides
**unchanged consensus** (every byte is a 512-byte Sapling memo carried by the existing
`z_sendmany` hex-memo path and read back via `z_listreceivedbyaddress`). No fork, no opcode, no
builder change.

> Codec reference: `ZDC1_CODEC_SPEC.md`. This section is the AS-BUILT daemon RPC contract
> plus the (still-pending) native UX, grounded in the live codec (`src/datachannel/zdc.h`,
> compiled into the daemon) and the built RPCs in `src/rpc/datachannel.cpp`
> (`z_senddatafile`/`z_listdatatransfers`/`z_getdatatransfer`, registered at `:597-599`,
> default-OFF behind `-datachannel`). The §3.4 UX is native-GUI design, not yet built — SHIELD
> is CLI-only today.

### 3.1 The four-layer stack, in plain terms

1. **Carrier — existing shielded memos.** Each frame is a 512-byte Sapling memo to one z-addr.
   Consensus already hides who/whom/amount/contents; we add nothing to consensus.
2. **Framing + reassembly — ZDC1 codec.** A file/message is split into chained frames (START /
   CHUNK / END, optional KEY) with a 4-byte `ZDC1` magic, grouped by `(zaddr, transfer_id)` and
   reassembled. Built + self-tested AND compiled into the daemon (`src/Makefile.am:247,294`).
3. **Encryption — AEAD + ciphertext fingerprint.** Bytes are sealed with a per-transfer key;
   `ciphertext_fingerprint(frames)` is a 32-byte commitment. **Verify-before-decrypt:** the public
   token's `document_hash` == that fingerprint, so a holder verifies the on-chain anchor before
   ever decrypting.
4. **Selective disclosure.** As built, `z_senddatafile` always emits the KEY frame on-chain and
   returns the per-transfer `key` to the sender, so the sender can selectively disclose by
   handing that key (or, for everything ever sent to a receiving z-addr, the **incoming viewing
   key** via `z_exportviewingkey`) to an auditor/buyer — read/prove only, never spend. *(A
   separate seal-now / reveal-the-key-later RPC — `z_revealkey` — is designed but NOT built; see
   §3.3.)*

**Keys live in the daemon, never in the GUI** (Option A). The GUI links no libsodium; it only
detects the `ZDC1` magic on raw memo bytes and calls the RPCs below.

### 3.2 Cross-cutting RPC contract (applies to every RPC in §3.3)

- **Naming/category:** `z_*` prefix, `"wallet"` category, async `opid` reused through the existing
  `z_getoperationstatus`/`z_getoperationresult` (no new status RPC). Reads are `okSafeMode=true`,
  mutating ops `false`.
- **Default-OFF master switch:** `fDataChannelEnabled = fExperimentalMode && GetBoolArg(
  "-datachannel", false)`. When off, EVERY RPC throws **`RPC_METHOD_NOT_FOUND (-32601)`** with
  *"Data channel is disabled. Start zclassicd with -experimentalfeatures -datachannel to enable
  private file/message transfers (experimental, default-off)."* — the SAME code an absent method
  returns, so the GUI's existing `-32601` "feature not present" latch (the one used for
  `getwalletsummary` at `zcl-qt-wallet/src/rpc.cpp:1828-1835`) handles it identically and never
  flickers a false error. *(Note: this `-32601` latch is the precedent to reuse here. The ZSLP
  index-off path is a DIFFERENT mechanism — `refreshNFTs` detects index-off via RPC error code
  `-1` (`RPC_MISC_ERROR`) at `rpc.cpp:989-999`, `indexOff = (code == -1)`, not `-32601`. Use
  whichever code the daemon actually throws: the data channel throws `-32601`, so it inherits
  the `getwalletsummary`-style latch, not the ZSLP index-off `-1` path.)*
- **Permanence consent is unbypassable:** every *sending* RPC takes a **REQUIRED-true**
  `acknowledge_permanent` in its options. Absent/false → `RPC_INVALID_PARAMETER (-8)`: *"This
  permanently writes encrypted data to every full node forever and is not deletable. Pass
  acknowledge_permanent=true to confirm."* (Enforced at the daemon, so a raw-RPC caller cannot
  bypass the honesty contract.)
- **Shielded-funding required** (sender de-anon foot-gun): `fromaddress` must be a Sapling z-addr;
  a t-addr → `RPC_INVALID_ADDRESS_OR_KEY (-5)`: *"Private transfers must be funded from a private
  (shielded) address, or the sender is deanonymized. Use a z-addr."*
- **Shielded recipient required:** `toaddress` must be a Sapling z-addr (a memo can't attach to a
  t-addr anyway).
- **DoS governance (as built):** a per-file cap of **40000 bytes** (`ZDC_MAX_FILE_BYTES`,
  `src/rpc/datachannel.cpp:84` — a clean advertised value below the single-tx frame ceiling;
  larger files are rejected, not fanned out) · a single shielded tx per transfer, hard single-tx
  frame ceiling `ZDC_MAX_FRAMES_PER_TX = 90` (3 control + up to 87 DATA frames) · `ZDC_MAX_INFLIGHT
  = 256` tracked transfers · `72 h` TTL GC of inflight transfers (the codec holds no clock).
  *(A larger 64 KB-default / 256 KB-hard-cap / rate-limit / multi-tx-fan-out governance scheme is
  designed in `ZDC1_CODEC_SPEC.md` but the as-built daemon uses the single-tx 40000-byte cap
  above.)*

### 3.3 The as-built daemon RPC surface

Three RPCs are built and registered (`src/rpc/datachannel.cpp:597-599`), default-OFF behind
`-experimentalfeatures -datachannel`. Each takes exactly **one JSON object** (not positional
args). Below is the as-built contract; the §3.4 native UX and the seal-then-reveal / private-mint
RPCs further down are **designed but NOT built** and are marked as such.

**`z_senddatafile '{options}'`** — send a private file or message. Exactly one of `filepath`
(the daemon reads the local file — it does NOT auto-fetch URLs) or `hexdata` (raw bytes as hex)
is required; both ≤ **40000 bytes**. Options:
- `fromaddress` (REQUIRED, a Sapling z-addr in this wallet),
- `toaddress` (REQUIRED, recipient Sapling z-addr),
- `filepath` OR `hexdata` (exactly one, ≤ 40000 bytes),
- `acknowledge_permanent` (REQUIRED-true; absent/false → it refuses),
- `filename` (optional, recorded in metadata),
- `content_type` (optional MIME, recorded in metadata).

It encodes the bytes into ZDC1 frames and emits them as N Sapling output memos in ONE shielded
tx. Returns:
```
{ "operationid", "transfer_id" (random 64-bit, 16 hex),
  "fingerprint" (32-byte ciphertext anchor = NFT document_hash),
  "frames", "key" }
```
The per-transfer `key` is **always** returned to the sender (for selective disclosure); the
on-chain anchor is the random-`transfer_id`-keyed `fingerprint`, NOT a `token_id`.

**`z_listdatatransfers`** — no parameters. Returns the transfers this node knows about (sent this
session; an in-memory registry, not persisted):
```
[ { "transfer_id", "fingerprint", "direction", "frames",
    "status", "fromaddress", "toaddress", "filename" }, ... ]
```
`status` is currently the literal string `"recorded"`.

**`z_getdatatransfer '{options}'`** — reassemble a transfer from the on-chain Sapling memos this
wallet holds, **verify-before-decrypt** (confirm the ciphertext fingerprint matches the recorded
anchor BEFORE any AEAD decrypt), then decrypt. Options:
- `transfer_id` (16-hex id) OR `fingerprint` (64-hex anchor) — one required,
- `address` (optional; the z-addr that received the frames — defaults to the recorded `toaddress`),
- `verify_fingerprint` (optional; a 64-hex anchor known OUT OF BAND, e.g. a published NFT
  `document_hash`. If given, the on-chain ciphertext MUST hash to THIS value or the call refuses
  to decrypt — `ERR_HASH_MISMATCH`, no plaintext — even when the local registry anchor matches).

Returns:
```
{ "transfer_id", "fingerprint",
  "verified" (on-chain anchor == recorded anchor),
  "complete", "frames_received",
  "hexdata", "size", "filename", "content_type"  (only on a verified+decrypted result),
  "error"  (honest codec error string otherwise) }
```

> **Designed, NOT built (do not call these against the daemon):**
> - **`z_revealkey`** — a seal-now / reveal-the-key-later trigger that would send a final KEY
>   frame for a previously sealed transfer. The as-built `z_senddatafile` instead always emits
>   the KEY frame and returns the key to the sender; there is no separate reveal RPC.
> - **`zslp_mint_private`** — a single RPC to mint a 1-of-1 whose asset bytes are sealed over
>   ZDC1. The as-built private-mint path is **two steps**: `z_senddatafile` for the sealed bytes
>   (which returns the ciphertext `fingerprint`), then an ordinary `zslp_genesis` whose
>   `document_hash` is set to that fingerprint (verify-before-decrypt). A `transfer_id == token_id`
>   binding is impossible (the genesis txid is not known until the genesis is built), so the
>   anchor is the random-`transfer_id` `fingerprint`.

**Selective disclosure — REUSE, do NOT add a new RPC.** Selective disclosure to an auditor/buyer is
the per-transfer `key` returned by `z_senddatafile`, or — for everything ever sent to a receiving
z-addr — the existing **`z_exportviewingkey`** (`rpcwallet.cpp:4752`): handing over the *incoming
viewing key* lets a third party read the sealed memos (prove contents/receipt) WITHOUT spend
authority. **Honest caveat (surfaced in UX):** a viewing key reveals ALL memos to that address —
so use a single-use receiving z-addr per private NFT, making the disclosure per-item.

**What the as-built surface deliberately omits:** no `z_receivedatafile` (folded into list+get);
no new status RPC (the async op reuses `z_getoperationstatus`/`z_getoperationresult`); no bespoke
selective-disclosure RPC (reuse `z_exportviewingkey`); the codec's structural ceiling is never the
policy (the single-tx 40000-byte cap is).

### 3.4 Native UX for each privacy action

100% native Qt, C++14, reuses `dark.qss` + the green **Private** pill + image-match badge. NO
QtWebEngine. Vocabulary-locked: "sealed", "the key", "note", "private (shielded) address" — never
"memo"/"ivk"/"AEAD".

> **Status:** this §3.4 is native-GUI **design — NOT built.** No SHIELD GUI exists yet; SHIELD is
> CLI-only today (the three as-built RPCs in §3.3). Where the design below calls `z_revealkey`,
> `zslp_mint_private`, or a `keymode`/`outputformat` option, those are **designed, not built**
> (see §3.3): the as-built daemon always emits the KEY frame and returns the key to the sender,
> and the as-built `z_getdatatransfer` returns `hexdata` directly. Treat the calls below as the
> intended GUI contract, mapped onto the as-built `z_senddatafile`/`z_listdatatransfers`/
> `z_getdatatransfer` until the optional features land.

- **Prerequisite read-path fix (binary-safe).** Before any private item can be read, fix the lossy
  memo decode at `zcl-qt-wallet/src/rpc.cpp` (~756-790): today it UTF-8-coerces binary ZDC1 frames
  into replacement chars. The additive C++14 fix **sniffs the 4-byte magic on RAW bytes before any
  `QString` conversion** (`raw.size()==512 && raw[0..3]==0x5A,0x44,0x43,0x31`) and routes those to
  a data-channel handler that calls `z_listdatatransfers`/`z_getdatatransfer`; everything else
  stays on the unchanged text-inbox path. Keys stay in the daemon.

- **Send a private message:** a "Private" mode of the send tab (or `NFTSendPrivateDialog`). Live
  recipient validation (valid private → green; valid public → amber "A private send needs a private
  (shielded) address"). A `QPlainTextEdit` + "0 / 4 KB" counter. A live consequence table (no
  daemon round-trip): "Becomes N small private notes" = `ceil(size/464) + 2` (+1 if send-with-key)
  — the same number an observer counts on-chain, so it IS the honest size signal. The one honesty
  line, always visible: *"Hidden: who it's from, who it's to, the amount, and the contents.
  Visible: that a private transfer happened, roughly when, and about how big. It stays on the
  network permanently."* Primary label states the outcome: send-with-key → "Send privately";
  reveal-later → "Send sealed". On press → `z_senddatafile(from, to, datahex=utf8(message),
  {keymode, acknowledge_permanent:true})` → watch the returned `opid`.

- **Send a private file:** same dialog, a dropzone ("Drop a file here", "Up to ~40 KB on the
  network"). File read on a bounded worker (never `readAll` on the GUI thread); the GUI passes
  `hexdata` (or `filepath`) + `filename` + `content_type`. File-too-big is a calm inline amber
  state at the 40000-byte cap (never silent truncation). *(The seal-now / reveal-later choice
  — `keymode` — is a designed option, not built; the as-built send always includes the key.)*
  Footnote: "Either way, only they can ever open it."

- **Receive** (drives Activity row status from `z_listdatatransfers.state`): `arriving` →
  "Arriving… 3 of 5 notes" (greyed) · `sealed` → amber dot + "Waiting for the key" + "Ask sender"
  + an "I have a key" paste field → `z_getdatatransfer(..., {keyhex})` (the CALM face of
  seal-then-reveal, never an error tone) · `ready` → green dot + "Private message"/"Private file —
  aurora.png" + **Open** / **Save…** (Save streams via `z_getdatatransfer(outputformat:"none")`
  then a chunked fetch; bytes written verbatim, never auto-executed).

- **Mint a private NFT:** in the mint dialog the **Private (only people you choose)** tile is green
  and DEFAULT-selected *only once ZDC1 is wired* (until then it's "Coming in this release", §2.5).
  Body: "The image and details are sealed. Stored encrypted on the ledger; only someone you give
  the key to can open it." On Create → `zslp_mint_private({name, ticker, asset:hex, fromaddress,
  keymode:"reveal-later", acknowledge_permanent:true})`. The "What becomes public" table lists only
  name/ticker/`document_hash`(the ciphertext fingerprint)/`documenturl`; the image bytes stay
  sealed. Gallery shows the SAME green Private pill and SAME image-match badge — but the badge runs
  against `z_getdatatransfer` assemble (AEAD + plaintext hash) AND the on-chain `document_hash ==
  ciphertext_fingerprint` check. The verify-line copy is unchanged: "This image matches its
  on-chain fingerprint." (a bytes-match, NOT genuine/official/original). Ownership shows PENDING
  until ~10 confirmations.

- **The consent gate (default-OFF + permanence):** first use of ANY private surface shows a
  one-time consent dialog stating the limits in plain words — confidential-not-undetectable; the
  size/timing/existence leaks; permanent on every node forever; no DRM; no consensus enforcement.
  Accept sets a `QSettings` flag AND supplies `acknowledge_permanent:true` to the RPCs. If the
  daemon returns `-32601`, show the calm "feature is off" page (latched like the ZSLP index-off
  page): managed daemon → confirm → write `datachannel=1` + `experimentalfeatures=1` + restart;
  foreign daemon → show the exact conf lines + "Copy". Never a dead end.

- **Reveal the key / selectively disclose:** **Reveal the key** — one tap in Activity on a
  `reveal-later` item → `z_revealkey(from, to, transfer_id, {acknowledge_permanent:true})`. Copy:
  "Unlock this for them" / on success "Key sent — they can open it now." An "I'll hand over the key
  myself" path shows the stored key for the user's own channel ("Sending the key on the network is
  permanent; handing it over yourself keeps it off the network"). **Selectively disclose** — the
  detail dialog's "More" → "Let someone verify this privately…" wraps `z_exportviewingkey` for the
  item's receiving z-addr, with the honest caveat: "This lets them read everything ever sent to
  this private address — not just this item. Because this item used its own one-time private
  address, that means just this item." It hands over a *viewing* key (read/prove only), never the
  spending key. Honest transfer limit, stated plainly: key-possession cannot stop a prior holder
  keeping a copy; the chain proves the fingerprint and (via ZSLP UTXO conservation) who holds the
  1-of-1 token, never the pixels. **No DRM, no anti-copy.**

---

# 4. NON-NEGOTIABLES

These apply to every doc and every line of code here. They are not roadmap items — engineering AND
product copy must never imply otherwise. (The normative validation rules and threat table live in
`SECURITY_MODEL.md`; if anything here conflicts with it, that doc wins.)

1. **Consensus never changes.** If a feature needs a new consensus rule, it is out of scope.
   Independently verified on this branch: the indexer overrides only `ChainTip` and never
   `SyncTransaction` (`src/zslp/zslpindexer.h`) — no mempool/0-conf/validation path; ZSLP is
   referenced nowhere in `src/main.cpp` or `src/consensus/`; the write path emits ordinary
   `TX_NULL_DATA` payments that unmodified nodes relay/mine; the codec rides existing Sapling
   memos; trades compose existing raw-tx RPCs and add no opcode. Keep this grep (`zslp` in
   `main.cpp`/`consensus/`) as a CI guard so any accidental coupling is caught.

2. **Honest badge.** The green check means ONLY *"these bytes match the on-chain fingerprint"* —
   **never genuine / authentic / official / original**. Issuer trust is **social** (signed
   attestation / verified-issuer list keyed by mint id), not a network badge. No trustless
   "verified creator" exists.

3. **Ownership is PENDING until ~10 confirmations** (`DEFAULT_MAX_REORG_DEPTH = 10`). 1–9 confs are
   reorg-reversible; the node finalizes at depth 10 and hard-stops at 99. UI shows pending→final on
   that single named constant.

4. **Never auto-fetch a `document_url`** (leaks IP + interest). Bytes come from local cache
   (`ContentEngine::cacheGet`) or ONE explicit, confirmed user action. `ContentEngine::isRemoteUrl`
   rejects any `http(s)://` source. **No QtWebEngine / browser / QtMultimedia anywhere — native Qt
   only.** Privacy is default-OFF, permanence-consent-gated, shielded-funded by default; private ≠
   undetectable (count/size/timing leak); permanence is a node-operator liability (keep assets
   small, 40000-byte per-file cap).

5. **Holder safety.** An ordinary send / shield / sweep must **never** spend or burn an NFT's
   carrier dust UTXO. Two distinct mechanisms back this, and BOTH are now wired in the working
   tree on `feature/zslp-nft-indexer` (uncommitted, capability B): (a) the write path's own
   self-validate-before-broadcast gate (R-WALLET-9) IS wired — `BuildAndCommitZSLP` calls
   `store->WouldBeValid(...)` (`src/wallet/zslpwallet.cpp:460`) and aborts before
   `CommitTransaction` (`:475`); and (b) ordinary-send anti-burn IS wired — `AvailableCoins`
   takes `fExcludeZSLPTokens` (default `true`, `wallet.h:1124`) and drops protected token/dust
   outpoints via `ZSLPIsProtectedTokenOutpoint(...)` (`wallet.cpp:3197`). Holding is therefore
   mechanically burn-safe in the working tree; it is the shipped guarantee once these changes
   are committed/merged. No UI copy or doc may imply burn-proof holding outside a build that
   carries these changes.

### Structural ceilings a non-consensus overlay can NEVER do (hold the line in UI copy)

No enforced royalties / resale cut / transfer veto / clawback · no enforced scarcity of the
underlying art (the fingerprint proves *which* bytes, never *exclusivity*) · no ticker / name /
issuer uniqueness (identity is the genesis txid) · no on-chain set/collection membership (sets are
manifest convention; never invent slot counts) · no atomic/trustless trade for any shielded leg ·
public ZSLP is fully public and linkable (ownership rides transparent 546-sat dust) · private ≠
undetectable · permanence is permanent on every node forever.

---

*Single-sourced from `CAPABILITY_MAP.md`, `NATIVE_UI_CONSOLIDATED_SPEC.md`, the Audit-B privacy
RPC+UX spec, and verified against the live tree (`zcl-qt-wallet/src` GUI + `src/zslp`/`src/rpc`/
`src/wallet`/`src/datachannel` daemon) on `feature/zslp-nft-indexer` (the branch that carries
ZSLP; the write path is present in that branch's working tree, uncommitted). Doc-only — no source
touched, no build run. Hard rules upheld: no consensus change, no browser/multimedia, no
auto-fetch, honest badge, holder safety, C++14.*
