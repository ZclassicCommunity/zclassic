# ZClassic NFT — Consolidated Native UI Spec (Audit-A, build-ready)

> **REMOVED — shielded data channel / on-chain private files.** The "Private" tile / ZDC1 shielded
> channel this spec describes has been **removed entirely** from the daemon (the `z_senddatafile` /
> `z_listdatatransfers` / `z_getdatatransfer` RPCs, the `-datachannel` option, the ZDC1 codec).
> ZClassic deliberately provides **no wallet path to store arbitrary files on-chain**. NFT content
> is always off-chain, bound to the token only by a `document_hash` fingerprint. Treat every
> Private-tile / ZDC1 section below as **historical** — do not build a private-mint UI.

**Status:** BUILD-READY consolidation. Reconciles `NATIVE_UX.md` (six-screen synthesis) and
`NATIVE_UI_BUILD_PLAN.md` (detail + mint file-level plan) against the **actual** shipping GUI tree
on `zcl-qt-wallet@feature/nft-gallery`, the **actual** daemon read RPCs, and the **building-now**
write-path contract (`zslp_genesis` + `zslp_send`). Doc-only — no source edited, no build run.

This is the single document a builder follows for every NFT screen: widget tree, every state, exact
user-facing copy, and the exact RPC each screen calls. Where the two source docs disagreed with the
code or with the building-now contract, **this doc picks the code/contract and says so loudly** (see
§0.1 reconciliations and the findings list returned alongside this file).

**Grounding (verified against the live tree, this pass):**
- `zcl-qt-wallet/src/nft.h` — `NFTItem` POD (8 fields; line 21-30).
- `zcl-qt-wallet/src/nftgallerymodel.h` — `NFTGalleryModel` (`itemAt`/`isValidRow`/`rowCount`/roles).
- `zcl-qt-wallet/src/nftgallerydelegate.{h,cpp}` — the card paint, `tintedIcon`, `verifyColor`,
  `privacyColor`, badge geometry, `baseCardSize()` 168×208.
- `zcl-qt-wallet/src/contentengine.{h,cpp}` — the ONE engine (`posterFor`/`verify`/`hashFile`/
  `classifyKind`/`humanSize`/`cacheGet`/`cachePut`/`isRemoteUrl`/`streamingSha256`; signals
  `descriptorReady`, `verifyDone`). **`posterReady` does NOT yet exist** (additive, see §3.6).
- `zcl-qt-wallet/src/nftimagecache.h` — `NFTImageCache : public ContentEngine` (a thin subclass shim).
  **The live `nftImgCache` member IS a `ContentEngine`** — dialogs reuse it, no new engine instance.
- `zcl-qt-wallet/src/mainwindow.cpp:3017 setupNFTTab()`, `:3103 setNFTItems()`.
- `zcl-qt-wallet/src/rpc.cpp:863 refreshNFTs()` — the live `zslp_listmytokens` + `zslp_gettoken` poll.
- `zcl-qt-wallet/src/settings.{h,cpp}` — `getShowNFTGallery()` (75), `getExplorerTxURL(txid)` (134),
  `getMinerFee()` (137), `getZCLDisplayFormat(bal)` (125). **No `getExplorerUrl`, no `getNFTThumbSize`.**
- `zcl-qt-wallet/res/styles/dark.qss` — `QPushButton:default` green `#1f7a1f`→hover `#2a9d2a` (93-96);
  all NFT tokens present.
- daemon `MINT_TRANSFER_SPEC.md` — write RPCs `zslp_genesis` / `zslp_send` (the building-now contract).

---

## 0. Hard constraints (every screen obeys; flagged in findings if violated)

- **100% native Qt.** `QListView`+`QStyledItemDelegate`+`QPainter`, `QDialog`, `QLabel`/`QPixmap`.
  NO QtWebEngine, NO QtMultimedia, NO browser, anywhere. Video = poster + open-in-external-player.
- **No consensus change.** Everything rides unchanged nodes. Mint/send are ordinary OP_RETURN+dust txs.
- **Honest badge.** The green check means ONLY "these bytes match the on-chain fingerprint." NEVER
  genuine/authentic/official/original. Issuer trust is social (signed attestation / verified-issuer
  list keyed by mint id). Uniqueness lives only at the mint-id (genesis txid) level. Ownership is
  **pending until ~10 confirmations** (`DEFAULT_MAX_REORG_DEPTH = 10`).
- **Privacy floor.** NEVER auto-fetch a remote `documenturl`. Bytes come from local cache
  (`ContentEngine::cacheGet`) or ONE explicit, confirmed user action. `ContentEngine::isRemoteUrl`
  rejects any `http(s)://` source. The live `refreshNFTs` already forces `cachePath=""` (rpc.cpp:960).
- **Holder safety.** An ordinary send must never spend an NFT carrier UTXO — enforced daemon-side by the
  anti-burn builder; the UI never constructs a raw spend of a token outpoint.
- **C++14 only.** No `std::optional`/`std::string_view`. Empty-`QString` sentinels + `int verifyState`
  (0/1/2). Header-signature type includes live in the `.h`.
- **DRY.** Reuse the ONE `ContentEngine`, the delegate's `tintedIcon`, the dark.qss tokens, the `doRPC`
  connector. Add no new color token.
- **Banned from every visible string (P1):** SHA-256, "hash" as a noun (say "fingerprint"), OP_RETURN,
  GENESIS, token, mint-baton, zslpindex, t-addr/z-addr (say "public (transparent) / private (shielded)
  address"), ivk, memo (say "note"). And never "Genuine/Authentic/Official/Original" on the badge.

### 0.1 Reconciliations (where the source docs were wrong vs the live tree — builder MUST follow these)

1. **Engine: reuse `nftImgCache`, do NOT create a second `ContentEngine`.** `nftImgCache` is constructed
   as `new NFTImageCache(nftModel, this)` (mainwindow.cpp:3053) and `NFTImageCache : public ContentEngine`
   (nftimagecache.h:22). It already exposes `posterFor/verify/hashFile/classifyKind/...`. The build plan's
   `nftEngine = new ContentEngine(...)` is redundant and would create a second pool. Dialogs take a
   `ContentEngine*` parameter and are handed the existing `nftImgCache` (upcast). There is exactly ONE engine.
2. **Write RPCs are `zslp_genesis` (mint) and `zslp_send` (transfer/gift) — NOT `zslp_mint`, NOT
   `z_sendmany`.** This is the building-now contract. The build plan's `RPC::mintNFT` already targets
   `zslp_genesis` (good); its prose elsewhere drifts to `zslp_mint` — ignore that. CONTENT_MODEL §6A names
   the high-level NFT call `zslp_mint` — ignore that too; `zslp_mint` is fungible re-issue, never NFT.
   NATIVE_UX §3.4 routes Send/Gift through `RPC::executeTransaction`/`z_sendmany` — that is ONLY for the
   later *private shielded-memo* gift, NOT the building-now public NFT transfer, which is `zslp_send`.
3. **Explorer getter: reuse `Settings::getExplorerTxURL(txid)` (settings.cpp:421), do NOT add
   `getExplorerUrl()`.** It already appends the txid and returns "" on testnet. The detail view's
   "View in explorer" enable-gate = `!getExplorerTxURL(m_item.txid).isEmpty() && !m_item.isPrivate`,
   and it opens exactly that string. (The build plan's new base getter is unnecessary.)
4. **`posterReady` signal does not exist on `ContentEngine` yet.** It must be added (additive, mirrors
   `verifyDone`) for the detail view's large image. This is a real prerequisite edit (§3.6). The
   model-only `posterFor→onImageReady` path cannot feed a dialog cleanly.
5. **`getNFTThumbSize()` does not exist.** Ship the gallery density toggle as a NEW
   `Settings::getNFTThumbSize()/setNFTThumbSize()` getter/setter, OR cut density from v1 (recommended:
   cut it from the first cut to reduce surface — it is the lowest-value toolbar control). If kept, it is
   a real new getter, not an existing one.
6. **Existing subhead copy violates P1.** `setupNFTTab` ships
   `tr("Your NFTs. Each asset is checked against its on-chain hash.")` (mainwindow.cpp:3031) — "hash" is
   banned. Fix to `"Your NFTs. The image on each card is checked against its on-chain fingerprint."`
7. **`indexOff` is currently ignored** (`setNFTItems` does `(void)indexOff;`, mainwindow.cpp:3107). The
   first-run/empty page-2 (index-off) screen depends on it being honored. Wiring the 4-page stack makes
   this real.

---

## 1. Shared visual + interaction system (all screens reuse, do not re-invent)

### 1.1 Tokens (verified in dark.qss + nftgallerydelegate.cpp namespace)
app `#0f1115` · card `#15171c` · inset `#1d2027` · hairline `#2a2d35` · text `#e6e6e6` ·
dim/AA-floor `#9aa0a6` · private-green `#1f7a1f` · hero-green `#2a9d2a`/`#34c759` · public/pending-amber
`#d9822b` · mismatch-red `#c0392b` · hover-border `#3d4450`. **Add no new color.**

### 1.2 Verify badge (one language everywhere) — `NFTGalleryDelegate::tintedIcon` recipe
SVGs already bundled: `:/icons/res/icons/{check,x,question}.svg`. Tint: 1→green check, 2→red x,
0→amber question (`verifyColor()`/`verifyIconResource()`). Dark disc behind it. Gallery/board badge
16px (`kVerifyPx`); detail/mint 20px. **Status, never a control** (no click). Verdict sentences,
identical wherever shown:
- 1 verified: **"This image matches its on-chain fingerprint."**
- 2 mismatch: **"This image does NOT match what was recorded on-chain. Don't trust it."**
- 0 pending: **"Checking this image…"** (or, no local bytes: **"Image not downloaded."**)

### 1.3 Privacy pill (one vocabulary) — `privacyColor()`/`privacyLabel()`
Green "Private" / amber "Public", alpha-38 fill + 1px border + leading dot (P7). One-liners:
- Private: **"Only you can see this. Its ownership is shielded."**
- Public: **"Anyone can verify this on the public ledger."**

### 1.4 Card anatomy — `NFTGalleryDelegate::baseCardSize()` = 168×208
Square thumb (cover-fit crop, radius 8) · verify badge top-right of thumb · privacy pill below thumb ·
bold name (`#e6e6e6`, elided) · collection (`#9aa0a6` 0.85×, elided). Shimmer placeholder while the
thumbnail is null (already painted by the delegate). One shared `QTimer` would animate the shimmer for
visible pending cards only (perf C6) — the live delegate paints a *static* shimmer; animating it is an
optional polish, not a correctness item.

### 1.5 The one action set (same verbs/labels/order wherever an action on an NFT appears)
Open · **Send / Gift** (bright green primary) · Save image… · Copy id · Copy image hash · Copy
collection · Re-check image · Open in your video player (video kind) · View in explorer (public +
configured, confirmed). **No "open link"/network item in any browse context menu.** Private items never
expose explorer.

### 1.6 Copy voice
Plain, warm, second person, no jargon, no emoji spam. State the outcome a button produces. Reuse the
exact verdict sentences so the user learns them once.

---

## 2. Gallery + first-run/empty + set-board (the browse surfaces)

These extend the existing `setupNFTTab()` page (mainwindow.cpp:3017), all additions programmatic, gated
on `Settings::getShowNFTGallery()`. No `.ui` change.

### 2.1 Collections gallery (`gallery-grid`)

**Widget tree (top→bottom):**
- **Heading row:** `QLabel#nftGalleryHeading` "Collections" + `QLabel#nftCountChip` ("12 items" →
  "12 of 40" filtered) at the right.
- **Subhead:** `QLabel#nftGallerySubhead` (FIX the live copy per §0.1.6):
  **"Your NFTs. The image on each card is checked against its on-chain fingerprint."**
- **Toolbar `QHBoxLayout#nftToolbar` (NEW, h=36):** `[search QLineEdit#nftSearch flex] [Filter ▾]
  [Group ▾] [Sort ▾]` (density toggle OPTIONAL per §0.1.5 — recommend cut for v1).
  - `nftSearch` placeholder "Search your collection", leading magnifier + trailing clear-X.
  - `nftFilter`: All / Private only / Public only / Verified / Needs attention.
  - `nftGroup`: No groups (default) / By collection / By privacy.
  - `nftSort`: Recently received / Name A–Z / Collection.
- **Grid:** the existing `QListView#nftGalleryView` (IconMode, Adjust, wrapping, uniformItemSizes —
  all already set) + `NFTGalleryDelegate`.
- **State stack:** wrap the view in `QStackedWidget#nftGalleryStack` (4 pages: 0 gallery, 1 empty,
  2 index-off, 3 loading — see §2.2).

**Architecture:** a NEW `QSortFilterProxyModel` over the untouched `NFTGalleryModel` drives
search/filter/sort/group (in-process, no I/O, fingerprint-guarded source — perf C7). "By collection"
inserts non-selectable section-header rows.

**RPC:** none directly — the gallery is fed by `RPC::refreshNFTs()` (rpc.cpp:863) on the normal poll:
`zslp_listmytokens` → for each token `zslp_gettoken "tokenid"` (batched) → `MainWindow::setNFTItems()`.
Every item gets `cachePath=""` (privacy), so cards stay pending until local bytes exist.

**States:** LOADING (page 3 first call; cards shimmer + amber "?"; count chip shows real local count at
once) · EMPTY (page 1, toolbar hidden) · ZERO-RESULT (toolbar stays, panel "Nothing matches" + active
filter in words + "Clear filters") · VERIFIED/MISMATCH/PENDING per badge · PENDING-NO-BYTES ("Image not
downloaded. Open to fetch it yourself." — never auto-fetched) · PRIVATE/PUBLIC · INDEX-OFF (page 2) ·
OFFLINE (keep last good grid, count chip dims, no spinner-of-doom).

**Interactions:** live search over name+collection · filter/group/sort instant via proxy · single-click
select; **double-click/Enter/Space → `MainWindow::openNFTDetail` via `connect(view,
&QListView::activated, ...)` (activated ONLY — it covers double-click AND Enter/Space; do NOT also
connect `doubleClicked` or detail opens twice).** Context menu = §1.5 browse subset (Open, Copy name,
Copy fingerprint, Copy transaction id, Re-check image — no link/network item).

**Copy:** "Collections" · the fixed subhead · "Search your collection" · "12 items"/"12 of 40" ·
"No NFTs yet" · "Nothing matches" · "Clear filters" · "Checking this image…" ·
"Image not downloaded. Open to fetch it yourself." ·
"Public collectibles are turned off. Your private NFTs are still shown." · "Re-check image" ·
"Copy fingerprint".

### 2.2 First-run / empty (`first-run`, the 4-page stack)

Wrap the single `QListView` in `QStackedWidget#nftGalleryStack`. Heading stays "Collections" in every
state; the subhead is state-dependent. Same centered hero-card geometry on every page so layout never
jumps (`#15171c`/hairline/radius 12/28px pad, max-width 520, centered).

- **Page 0 — gallery** (rows present).
- **Page 1 — EMPTY:** quiet-grey `#2f343d` 56px frame glyph (NOT red/amber — empty, not broken), title
  **"No collectibles yet"**, body **"When someone sends you a collectible, or you make one, it shows up
  here — and the wallet checks each picture against its on-chain fingerprint. Nothing to do right
  now."**, ONE green primary **"Make your first collectible"** (opens the mint dialog when it lands;
  before that, **"Show me how it works"**), flat link **"What is a collectible?"**.
- **Page 2 — INDEX-OFF:** amber `#d9822b` 56px toggle glyph (attention, not broken), title
  **"Collectibles tracking is turned off"**, body **"Turn this on and the wallet will start finding your
  collectibles. It does a one-time catch-up scan in the background, so syncing stays fast for people who
  don't collect."**, green primary **"Turn on collectibles"**, flat link **"Why is this a separate
  setting?"**. Managed daemon → confirm + restart + scan. Foreign/old daemon → reveal a `#1d2027` inset
  with the exact conf line **"zslpindex=1"** + **"Copy line"** (never a dead end). *(This conf line is
  the one place the raw setting name is allowed — it is literal config, not user-facing prose.)*
- **Page 3 — LOADING:** **"Looking for your collectibles…"** + indeterminate `QProgressBar` +
  **"This runs in the background. You can keep using the wallet."**

**State selection (RPC):** the existing `refreshNFTs` already distinguishes the index-off case: its error
handler (rpc.cpp:978-1000) computes `indexOff` from RPC error code -1 and calls
`setNFTItems(empty, indexOff)`. **Wire `setNFTItems` to honor `indexOff`** (today it does
`(void)indexOff;`): indexOff→page 2; success+empty→page 1; success+rows→page 0; first call
outstanding→page 3. Latch the last good page fingerprint-style so a transient poll error never flickers
back to empty/off; daemon-unreachable keeps the last state.

### 2.3 Set / collection board (`set-collection`)

A stacked page **inside the Collections tab** (`QStackedWidget` index 1; index 0 = the gallery), reached
by clicking a set thumbnail. Header strip (back "‹ Collections" + set name + "Created by {creator} ·
{N} cards" + completion meter "3 of 7 collected" with green `#1f7a1f` track fill) · the board
(`QListView` IconMode fed by a NEW `SetBoardModel`, painted by a NEW `SetSlotDelegate :
NFTGalleryDelegate` — owned slots = §1.4 card; missing slots = ghost variant: 55% opacity, "#N" numeral,
"Not collected", **no image request issued**) · footer help bar (only when missing>0): "Missing {n}
cards. They arrive when someone sends them to your wallet." + quiet "Show my receive address" (opens the
existing Receive tab). **No in-app buy/trade.**

**RPC:** set membership comes from the already-fetched `zslp_gettoken` metadata (the `ticker` groups a
card-set; the live `refreshNFTs` maps `ticker`→`collection`, rpc.cpp:949). A full canonical-manifest
"all slots" board needs a creator-published manifest resolved locally/explicitly — until then the board
shows owned slots + a "manifest not available" calm note rather than fabricating ghost slots.

**States:** loading-board · empty-set (all ghosts) · verified/mismatch/pending owned slot · missing slot
· private-set · index-off (public sets only; private from the memo scan) · set-complete (green pulse +
"Set complete" + footer hides) · stale/offline.

The creator's verified-issuer tick appears ONLY when its mint id is on a named verified-issuer list;
tooltip "On {maintainer}'s verified-issuer list" — never a bare "Verified" (it is social, not a network
guarantee).

---

## 3. Detail dialog (`nft-detail`) — `NFTDetailDialog` (NEW)

New `src/nftdetaildialog.{h,cpp}`, programmatic, modeless-modal (`open()` not `exec()` so the poll loop
keeps flowing and back-fill lands). Min 760×560. Carries the `NFTItem` by value + the ordered POD list by
value (no model pointer) for prev/next. Geometry in `QSettings("NFTDetail/geometry")`.

### 3.1 Constructor + entry
```cpp
explicit NFTDetailDialog(const NFTItem& item, const QVector<NFTItem>& ordered, int startIndex,
                         ContentEngine* engine, RPC* rpc, QWidget* parent = nullptr);
```
`MainWindow::openNFTDetail(const QModelIndex&)` snapshots the ordered list from `nftModel`
(`itemAt`/`isValidRow`/`rowCount`, all present) and constructs the dialog with **`nftImgCache`** as the
`ContentEngine*` (the existing engine — §0.1.1) and `rpc`, then `dlg->setAttribute(WA_DeleteOnClose);
dlg->open();`. Wire once: `connect(view, &QListView::activated, this, &MainWindow::openNFTDetail)`.

### 3.2 Layout
- **Title bar (h=44):** name 16pt/700 (elided) + collection 11pt `#9aa0a6` ("Not part of a set" if
  none); flat close glyph; hairline below.
- **Left — image stage (stretch 1, min 380×380):** card holding a centered `QLabel#nftDetailStage`
  painting the full QPixmap `KeepAspectRatio SmoothTransformation` (never upscaled past 1024 native;
  letterboxed on `#1d2027`). 20px verify badge top-right. Shimmer while decoding.
- **Right — info panel (fixed 320):**
  1. **Verify line:** full-width inset row, 20px badge + 13pt sentence; color via
     `#nftDetailVerifyLine[state="verified|mismatch|pending"]` dyn-prop (NEW qss, ~3 lines).
  2. **Privacy pill row** + 11pt one-liner (§1.3).
  3. **Details card:** label/value grid. **Mint id** (the genesis txid = identity; short 8…8 + copy),
     **Received** (ISO date + "block N", or "Just arrived — confirming…" when confs<10, or "block N
     (date pending)" before `gettransaction` returns), **Creator** ("Unknown" — the chain records no
     issuer), **Set** ("Wild Series — 7 of 30" or "Not part of a set"), **Image hash** (short
     docHashHex 8…8 + copy). Footnote: **"This name and image aren't unique — anyone can mint another
     collectible that reuses them. Only the mint id is one of a kind."**
  4. **Action bar (pinned, h=48):** §1.5 set — green **"Send / Gift"** primary · **"Save image…"** ·
     **"Copy id"** · overflow **"More" (…)** = Copy image hash / Copy collection / Re-check image /
     View in explorer (disabled unless public + configured).

### 3.3 RPC the detail dialog calls
- **Poster + verify (local bytes only):** `engine->posterFor(localPath, docHashHex, docHashHex, 512)`
  and `engine->verify(localPath, docHashHex, token)` where `localPath = ContentEngine::cacheGet(
  m_item.docHashHex)` (empty = not on device → never fetched). Token-guarded so a fast prev/next drops a
  stale neighbor's reply.
- **Provenance back-fill (NEW `RPC::nftProvenance(tokenId, cb)`):** `zslp_gettoken "tokenId"` → on
  success set Set/series from `ticker`; Creator stays "Unknown" (no issuer field on chain); any error →
  honest defaults, no dialog.
- **Received date back-fill (NEW `RPC::txReceivedDate(txid, cb)`):** `gettransaction "txid"` →
  `confirmations` + `blocktime`; confs<10 → "Just arrived — confirming…"; ≥10 → ISO date + "block N".
- **View in explorer:** `QDesktopServices::openUrl(QUrl(Settings::getExplorerTxURL(m_item.txid)))` after
  a one-time confirm "This opens an outside website and may reveal your interest. Continue?" — enabled
  only if `!getExplorerTxURL(m_item.txid).isEmpty() && !m_item.isPrivate` (§0.1.3).
- **Send / Gift:** opens `NFTSendDialog` pre-filled (§5). Until the send dialog ships, a toast
  "Sending NFTs is coming soon." On a MISMATCH item, confirm "This image failed its on-chain check.
  Send anyway?" first.

### 3.4 Media by kind (`ContentEngine::classifyKind`) — every branch touches ONLY the cacheGet result
- **Image:** `posterFor` → full QPixmap on the stage; resize re-scales from the held source (no
  re-decode/re-hash, perf C3).
- **Video:** NO in-app playback. Typed film-strip poster (never a faked frame) + overlaid play glyph +
  caption **"Video · <MIME> · <NN.N MB>"** (`humanSize`) + verify badge + primary
  **"Open in your video player"** → `QDesktopServices::openUrl(QUrl::fromLocalFile(localPath))`, ENABLED
  only when local bytes exist AND `verifyState == 1` (openUrl silently fails on a missing/remote path).
- **Document:** typed MIME glyph + "Open" (+ optional "Reveal in folder"). External only.
- **Bytes:** typed glyph + size summary + "Save as…". Never auto-execute.

### 3.5 States
LOADING (shimmer; "Checking this image…"; Send/Gift + Copy id enabled; Save + Open-in-player disabled) ·
VERIFIED (green; all enabled; bytes-match only) · MISMATCH (red; image dimmed ~60% + thin red inset;
Save stays enabled; Send confirms first) · PENDING/UNCACHED-private ("This image lives in your wallet's
local cache." no fetch button) · PENDING/UNCACHED-public ("Image not on this device yet." + explicit
"Get image" only when a documenturl is back-filled AND public; in C1 the POD carries no documenturl →
no Get-image button) · PRIVATE/PUBLIC · EMPTY METADATA ("Unknown"/"Not part of a set"/"block —
(unknown)") · RECEIVED-PENDING (confs<10 → "Just arrived — confirming…") · INDEX-OFF (wallet-local
fields render + "Turn on the collectibles index to see full provenance." — no error dialog) ·
ERROR/not-an-image (amber "This file isn't an image we can show." + neutral glyph) · RESIZE · PREV/NEXT.

### 3.6 Prerequisite engine edit (the one real ContentEngine change)
Add (additive, mirrors `verifyDone`) to `contentengine.h` next to line 200:
`void posterReady(quint64 token, QImage img, int verifyState);` and emit it from `deliver()` (the
GUI-thread landing) in addition to the model call, keyed by a token the caller passed. The dialog
connects to it and builds the QPixmap on the GUI thread in `onPosterReady`. Do NOT hand the dialog a
throwaway model; do NOT read the on-disk poster cache by hand (racy). *(Acceptable-only fallback if a
reviewer rejects the signal: read the on-disk poster cache after `posterFor` completes — but the signal
is the planned approach and keeps zero model coupling.)*

---

## 4. Mint dialog (`mint-flow`) — `NftMintDialog` (NEW)

New `src/nftmintdialog.{h,cpp}`, programmatic, modal (`exec()` — self-contained create flow). Either the
NATIVE_UX 4-card single-scroll layout OR the build-plan 3-page stack (PICK→DETAILS→REVIEW) — pick ONE;
both are native, keep state, and honor the same copy/states. The 3-page stack makes the
"async-hash-gates-Next" contract trivial and is the recommended cut.

### 4.1 Entry + wiring
Toolbar "Create NFT…" button in `setupNFTTab` + `MainWindow::openMintDialog()`:
```cpp
NftMintDialog dlg(nftImgCache /*the existing ContentEngine*/, rpc, this);
if (dlg.exec() == QDialog::Accepted) rpc->refreshNFTs();
```

### 4.2 Cards / pages
- **1 — Your image (dropzone):** drag/drop or "Choose a file…". GUARD with
  `ContentEngine::isRemoteUrl(path)` → reject http(s) drops inline (privacy). On a file:
  `classifyKind` for the poster glyph, `posterFor(path, key, "", 160)` for an image poster, prefill name
  from the basename, then `hashFile(path, token)` (STREAMING — a 2 GB file hashes in ~1 MiB RAM).
  Indeterminate progress + "Reading your file…". Next disabled until `descriptorReady`.
- **2 — Details:** Name (required, "e.g. Aurora #014", soft 50-char counter), Collection (optional,
  "e.g. Zcl Originals"), Note (label swaps Private↔Public).
- **3 — Who can see it:** two tiles. **Private** (green, default selected) — "The image and details are
  sealed…". **Public** (amber). **When the private channel RPC is unwired (TODAY), the *Private* tile is
  the one gated** — see §0.1 nuance below. A consequence caption always states the current choice.
- **4 — Review & confirm:** thumb + name/collection + visibility pill + "Fingerprint 1f2a…9c0d" + size +
  a "What goes on-chain (public)" line + the honesty line + fee row
  (`Settings::getZCLDisplayFormat(getMinerFee())`) + "After this you'll have N ZCL".

> **Gating nuance (resolve at build time).** Two facts collide: the building-now write path is the
> **public** `zslp_genesis`/`zslp_send`, while NATIVE_UX makes **Private** the safe default. So in the
> first shipped cut, the PUBLIC tile is the one that is actually wired (it calls `zslp_genesis`), and the
> PRIVATE tile is "Coming in this release" (it needs the ZDC1 shielded channel). This is the OPPOSITE of
> NATIVE_UX §3.3's "Private default, Public coming soon." **Builder MUST pick based on which daemon RPC
> exists**: gate OFF whichever path's RPC is missing, default-select the wired one, and keep the copy
> honest ("Coming in this release" + steer to the wired choice — never a dead Create button). The
> build-plan's `isPrivateMintWired()==false` correctly gates Private off today. Do not ship a
> Private-default mint that has no working broadcast path.

### 4.3 RPC the mint dialog calls — `RPC::mintNFT(descriptor, opts, cb)` → `zslp_genesis` (building-now)
```
zslp_genesis '{ "ticker": <collection>, "name": <name>, "document_url": <url or "">,
                "document_hash": <64-hex anchor>, "decimals": 0, "quantity": 1 }'
  -> { "txid", "tokenid" }   (tokenid == txid)
```
The GUI forces `decimals=0, quantity=1` (NFT). `document_hash` = the descriptor's `merkleRoot` for large
files else `sha256Whole`, lowercase hex (round-trips `gettoken.documenthash`). On success,
`ContentEngine::cachePut(anchorHex, srcPath)` stores the local bytes content-addressed so the new card
verifies green immediately, then `accept()` → `refreshNFTs()`. On error, show the daemon message verbatim
inline (never a crash, never a fabricated success). PRIVATE (when wired later) routes the bytes over the
ZDC1 shielded channel — a separate RPC, not `zslp_genesis`.

### 4.4 States
EMPTY/PICK · REMOTE-URL REJECTED ("For your privacy, drop a local file — not a web link.") · HASHING
(indeterminate; Next disabled) · READY ("Fingerprint ready."; Next enabled) · UNREADABLE ("That file
couldn't be read. Try another.") · PUBLIC selected (doc-url field optional) · PRIVATE selected (when
wired) · PRIVATE COMING-SOON (the default today — Private tile disabled "Coming in this release", Public
forced-on; Create never dead) · REVIEW · CREATING ("Creating…", footer disabled) · MINT ERROR (inline
daemon message) · SUCCESS (`accept()`; toast "NFT created — Aurora #14" + "Show it"; gallery refreshes) ·
low-balance ("Not enough ZCL to cover the network fee.").

### 4.5 Copy
"Create an NFT" / "Create NFT…" · "Drop an image here" / "Choose a file…" / "PNG, JPG, GIF, SVG, WebP —
up to 20 MB" · "For your privacy, drop a local file — not a web link." · "Reading your file…" /
"Fingerprint ready." / "That file couldn't be read. Try another." · "Name"/"Collection"/"Note" · the
two privacy-tile bodies · "Coming in this release" · "Network fee" · "After this you'll have N ZCL" ·
"Minting does NOT upload your file anywhere. Only its fingerprint goes on-chain — the file stays on your
computer." · "Create NFT" / "Creating…" / "Cancel" · "NFT created — Aurora #14" / "Show it".

---

## 5. Send / Gift (`send-gift`) — `NFTSendDialog` (NEW)

New `src/nftsenddialog.{h,cpp}`, modal, constructor **requires** an `NFTItem` (no empty state).
windowTitle "Send a gift". Four cards + footer.

### 5.1 Cards
- **1 — What you're giving:** 72×72 inset thumb fed exactly like the gallery
  (`engine->posterFor(docHashHex, cachePath, docHashHex, 72)` — instant from disk cache) + verify badge
  + name + collection + privacy pill. Read-only.
- **2 — Who gets it:** "Send to" + the existing `AddressCombo` (autocompleting recipient widget) +
  "Address book". One reserved-height live status line: valid private → green "Looks good — a private
  (shielded) address"; valid public → amber "Looks good — a public (transparent) address"; invalid →
  red "That doesn't look like a ZClassic address". Recipient type drives card 3.
- **3 — How private:** two radio rows. **Public gift** [amber] — wired now via `zslp_send` to a
  transparent recipient. **Private gift** [green] — the shielded-memo path; "Coming soon", disabled
  until the ZDC1 channel lands. (Again the OPPOSITE polarity of NATIVE_UX §3.4, for the same building-now
  reason as mint — §0.1.2/§4.2.) An unsupported choice is disabled with the fix inline (P4).
- **3b — When should they get the key?** (Private only; reveal animated) — "Send it all now" /
  "Send the picture now, the key when you're ready". (Future, with the private channel.)
- **4 — Add a note (optional, collapsed):** `QPlainTextEdit` + byte counter. Public gifts hide the note
  ("Public gifts can't include a private note.").

### 5.2 RPC the send dialog calls
- **Local address validation:** debounced, GUI-side (no per-keystroke RPC) — drives the status line.
- **Public gift (building-now):** `RPC::sendNFT(tokenId, toAddress, cb)` →
  `zslp_send "tokenid" "to_address" 1` → `{ "txid" }`. amount defaults to 1 (single NFT). The daemon
  builder enforces anti-burn + self-validate-before-broadcast; the UI never builds a raw spend.
- **Private gift (future):** the shielded-memo path via `RPC::executeTransaction`/the ZDC1 channel —
  NOT `zslp_send`. This is the ONLY place `executeTransaction` is correct, and only for the private leg.
- The green action label states the outcome: Public → "Send gift"; Private+all-now → "Send gift
  privately"; Private+reveal-later → "Send the picture". Disabled until valid recipient AND not a red
  mismatch AND not already in flight.

### 5.3 States
opened/ready · thumb pending/verified/MISMATCH (mismatch → "This picture doesn't match its fingerprint —
we won't send it.", action disabled) · recipient empty/valid-private/valid-public/invalid · Public chosen
· Private chosen (future) · sending ("Sending…", inputs disabled) · sent ("Gift sent. It's on its way to
them.") · error (inline red + daemon reason + "Try again", nothing sent) · index-off (Public still works;
it does not need the read index).

### 5.4 Copy
"Send a gift" · "What you're giving" · "Send to" · "Address book" · "Who can see this gift" · "Looks good
— a private (shielded) address" / "Looks good — a public (transparent) address" / "That doesn't look like
a ZClassic address" · "Public gift" / "Private gift" · "Coming soon" · "Add a note" · "Send gift" ·
"Sending…" · "Gift sent. It's on its way to them." · "Try again".

---

## 6. End-to-end happy paths (building-now / public, ships first)

1. **Browse → open → gift (public).** Collections paints instantly (shimmer + amber "?"; count chip
   live). Thumbs stream from disk cache; badges flip green. Double-click → detail (verify line "This
   image matches its on-chain fingerprint."). Send / Gift → NFTSendDialog pre-filled + verified. Paste a
   transparent recipient → green/amber status line. Public gift pre-selected. "Send gift" → `zslp_send`
   → "Gift sent." Gallery refreshes next poll.
2. **Mint (public, building-now).** Empty page → "Make your first collectible" → NftMintDialog. Drop an
   image → streaming fingerprint → "Ready". Name (required). Public is the wired choice today (Private =
   "Coming in this release"). Review shows what becomes public + the does-not-upload line + fee. Create
   NFT → `zslp_genesis` → toast + "Show it".
3. **Collect a set.** Set card → board swaps in. Owned bright/detailed; missing dim/numbered/"Not
   collected". "3 of 7 collected". Footer: "Missing 4 cards. They arrive when someone sends them to your
   wallet." + receive-address button.

---

## 7. Performance + privacy contract (defect if violated)

C1 no web/multimedia ever · C2 bounded `QThreadPool(4)`; worker produces only `QImage`, never QPixmap;
QPixmap built on the GUI thread · C3 two-tier cache, re-open free, resize re-scales from held source ·
C4 in-flight dedupe · C5 no relayout on scroll (`setUniformItemSizes`) · C6 one shimmer timer (visible
pending only; missing slots issue ZERO image requests) · C7 fingerprint-guarded models + in-process
proxy · C8 tinted glyphs cached · C9 hot path touches ONLY local bytes; `isRemoteUrl` rejects http(s);
the only network touches are explicit confirmed user actions + the mint/send broadcast · C10 RPC stays
off the GUI/paint thread via `doRPC`; dialogs render instantly from the value-copied POD and back-fill.

---

## 8. File map (grounded in the live tree)

**New files:** `src/nftdetaildialog.{h,cpp}` · `src/nftmintdialog.{h,cpp}` · `src/nftsenddialog.{h,cpp}`
· `src/setboardmodel.{h,cpp}` · `src/setslotdelegate.{h,cpp}` · a `QSortFilterProxyModel` (inline or a
small `nftgalleryproxy.{h,cpp}`).

**Edited files:**
- `src/mainwindow.{h,cpp}` — 4-page `QStackedWidget#nftGalleryStack`; toolbar; set-board page;
  `openNFTDetail` + the single `connect(view,&QListView::activated,...)`; `openMintDialog`; **honor
  `indexOff` in `setNFTItems`** (today `(void)indexOff;`); **fix the subhead copy** (§0.1.6). Pass the
  existing `nftImgCache` (a `ContentEngine*`) to the dialogs — do NOT add a second engine (§0.1.1).
- `src/nftgallerydelegate.{h,cpp}` — disc ring (P7) + mismatch inner hairline + privacy leading dot;
  optional density property (only if §0.1.5 density kept).
- `src/contentengine.{h,cpp}` — ADD the additive `posterReady(quint64, QImage, int)` signal + emit in
  `deliver()` (§3.6). Nothing else.
- `src/rpc.{h,cpp}` — ADD `mintNFT(descriptor, opts, cb)`→`zslp_genesis`; `sendNFT(tokenId, toAddr,
  cb)`→`zslp_send`; `nftProvenance(tokenId, cb)`→`zslp_gettoken`; `txReceivedDate(txid, cb)`→
  `gettransaction`. All via `doRPC`, graceful-fallback to honest defaults. `isPrivateMintWired()` →
  hard-false until ZDC1.
- `src/settings.{h,cpp}` — REUSE `getExplorerTxURL(txid)` (no new `getExplorerUrl`, §0.1.3). Add
  `getNFTThumbSize()/setNFTThumbSize()` ONLY if density is kept (§0.1.5).
- `res/styles/dark.qss` — append NFT object-name rules using existing tokens only
  (`#nftDetailVerifyLine[state=...]`, `#nftDetailStage`, `#nftDetailCard`, `#dropZone`, `#nftCreateBtn`
  inheriting the existing green). No token changes.
- `application.qrc` + `res/icons/` — NEW SVGs (none exist yet): magnifier (search), copy glyph,
  frame/picture glyph (empty-state), toggle glyph (index-off), film/play glyph (video). Tinted at
  runtime via `tintedIcon()`.
- `zcl-qt-wallet.pro` — add the new `.cpp/.h` to `SOURCES`/`HEADERS`. No new Qt module.

**Build order (each step shippable):** (1) RPC + settings + `posterReady` scaffolding; (2) gallery
state-stack + proxy + first-run/index-off; (3) detail dialog; (4) set board; (5) mint (public,
`zslp_genesis`) + send (public, `zslp_send`); (6) private channel (ZDC1) → flip the gating so Private
becomes the safe default per NATIVE_UX once the shielded path is wired.

---

## 9. Honesty ledger
- No in-app marketplace / buy button. The set board says "they arrive when someone sends them to your
  wallet" + a receive address.
- "Private" ≠ "only one copy can exist." Hidden from the public; a prior holder can keep their copy.
- The building-now write path is PUBLIC (`zslp_genesis`/`zslp_send`); the Private tiles are the honest
  "Coming in this release" until the ZDC1 shielded channel lands — the OPPOSITE polarity of NATIVE_UX's
  Private-default, intentionally, because we never ship a default with no working broadcast path.
- No silent remote fetches. A "not downloaded" image is the honest state, fetched only on explicit
  confirmed action.
- Unknown stays "Unknown". Creator is "Unknown" because the chain records no issuer.
- The green check is a bytes-match only — never genuine/authentic/official/original. Ownership is
  pending until ~10 confirmations.

*Synthesized from NATIVE_UX.md + NATIVE_UI_BUILD_PLAN.md, reconciled against the live
`zcl-qt-wallet@feature/nft-gallery` tree and the building-now `zslp_genesis`/`zslp_send` contract. All
file:line references verified this pass. Hard rules upheld: no consensus change, no browser/multimedia,
no auto-fetch, honest badge, C++14, holder safety.*
