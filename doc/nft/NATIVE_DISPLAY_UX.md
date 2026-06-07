# ZClassic Native NFT Display & Shield UX — Canonical Design

*The single canonical design doc for the **native** (no web browser) NFT display surface in
the ZClassic wallet: how an owner views, verifies, and privately ships the **file content**
behind a ZSLP NFT. Status-accurate against the GUI on `feature/nft-gallery`
(`zcl-qt-wallet`) and the daemon data-channel on `feature/zslp-nft-indexer` (`zclassic`).*

> **The coin is ZClassic / ZCL.** Every balance, fee, dust output, and price in this
> document is denominated in **ZCL**. Zcash-lineage code identifiers (`zclassicd`,
> `z_sendmany`, `.zcash-params`, Sapling, ivk) keep their upstream names, but the money a
> user holds, sends, and sells for is always **ZCL**.

---

## 0. The two truths this whole surface must tell honestly

Read these before any pixel. They are load-bearing and every screen must obey them.

1. **Ownership is ALWAYS public.** A ZSLP NFT rides a **transparent dust UTXO** (0.00001
   ZCL). Who owns which token, and every transfer of it, is **fully visible on-chain** to
   anyone, forever. There is **no shielded ownership, no anonymous holder, no confidential
   transfer.** The wallet must never say or imply otherwise. The honest one-liner, used
   verbatim across gallery and detail, is:
   > "● Public — anyone can verify this on the public ledger."

2. **The only privacy here is file content.** The **ZDC1 shielded data-channel** makes the
   **bytes of a file private** by encrypting them (ChaCha20-Poly1305 AEAD) and shipping the
   ciphertext inside Sapling shielded memos. It hides the **payload** and the data-transfer
   linkage — it does **not** hide who owns the token. And even the bytes are stored as
   **public ciphertext on every full node permanently** (encrypted-but-undeletable):
   "private" means confidential, **not** undetectable and **not** erasable.

3. **A green ✓ means one narrow thing.** "The local bytes match the on-chain fingerprint."
   It does **not** mean genuine, official, authorized, or one-of-a-kind. Anyone can mint a
   copy that reuses the same picture. Only the **mint id** is unique. The verify copy must
   never overstate.

4. **Non-consensus overlay.** ZSLP NFTs and the data-channel are an OP_RETURN / Sapling-memo
   overlay. Old, unmodified nodes relay and mine the outputs unchanged; there is **no
   consensus fork.** Security comes from **every honest wallet deterministically
   re-validating confirmed history**, not from miners enforcing it.

### Honesty tags used throughout

Every capability below is tagged exactly one of:

- **BUILT+TESTED** — code exists, has automated tests (gtest/L0/L1), proven.
- **BUILT-CLI-ONLY** — daemon code exists and works from the RPC console; **no GUI surface**
  and no automated end-to-end seam test.
- **DESIGNED-NOT-BUILT** — specified here/in the guide; no code yet.
- **FUTURE-IDEA** — directional only; not specified to build.

---

## 1. Design principles

The owner is not a developer. They double-click a wallet, click a Collections tab, and want
to *see* their stuff and *send* a file to a friend without learning a vocabulary. Five
principles, in priority order:

### 1.1 In-app rendering only — never a browser, never an auto-fetch
There is **no QtWebEngine, no QtMultimedia, no embedded browser** anywhere in this surface
(`zcl-qt-wallet.pro` declares only `QT += svg widgets`). Every render entry point takes a
**local filesystem path or a `:/resource` only**. A remote `http(s)`/`ftp`/`ipfs`/`zdc1`/UNC
/ protocol-relative path is **rejected** by `ContentEngine::isRemoteUrl()` and resolves to an
honest null/pending fallback. **There is zero network code in the render layer.** This is a
security stance, not a limitation we apologize for: an NFT image can never phone home, never
leak that you opened it, never pull a tracking pixel. **BUILT+TESTED.**

### 1.2 Never auto-fetch; the owner is always in control of bytes
The wallet will not silently download or resolve a file from anywhere. The bytes that render
are bytes the owner already has on this device (via **Attach the file you have…**, the
content-addressed blob store, or — designed — an arrived ZDC1 transfer). The default live
state for a freshly received NFT is therefore **"Image not on this device,"** and that is the
*correct, honest* state, not a bug. (See §2.3 and §5.)

### 1.3 Instant / fast — never block the GUI thread
All hashing, classification, and decoding run on a **bounded 4-thread `QThreadPool`**.
Workers touch only `QByteArray`/`QCryptographicHash`/`QImageReader`/`QImage` — **never
`QPixmap`** (that is GUI-thread-only, built in `deliver`). Files stream through one reused
**1 MiB buffer**, so a 2 GB file hashes in ~1 MiB of RAM; an in-flight multi-GB hash aborts
cleanly on shutdown (`cancelAll()` + `waitForDone()`). The paint hot path allocates **no
pixmaps**. **BUILT+TESTED.** (Full architecture in §5.)

### 1.4 Honest verification, always visible, never overstated
Three badge states — pending / verified / mismatch — plus a **fourth neutral terminal state**
for "no local bytes to check" (the common production state). The green check is scoped to
"bytes match the fingerprint" and the public-ownership line sits next to it on every card and
detail view. Honesty copy is uniform and load-bearing (§2.6). **BUILT+TESTED.**

### 1.5 Zero jargon
No "UTXO", "Merkle root", "AEAD", "ivk", "ciphertext" in primary copy. Use **"fingerprint"**
for the content hash, **"mint id"** for the token id, **"public ledger"** for the chain,
**"file is private"** for the data-channel encryption. Technical terms live only in tooltips,
an expandable "Details" disclosure, or the RPC console — never in the first thing the owner
reads.

---

## 2. The gallery — Collections tab

The Collections tab is a `QStackedWidget`. **Index 0 = gallery** (BUILT+TESTED). **Index 1 =
set/collection board** (DESIGNED-NOT-BUILT, §4).

### 2.1 Layout (index 0) — BUILT+TESTED

- A **`QListView` in IconMode**: `setResizeMode(Adjust)` (cards reflow on window resize),
  `setUniformItemSizes(true)`, `setSpacing(8)`, single-selection, static movement,
  mouse-tracking for hover.
- **`activated`** (double-click *and* Enter) opens the detail dialog — connected exactly once
  (no double-open bug).
- Model: **`NFTGalleryModel : QAbstractListModel`** of `NFTItem` POD rows
  (`name / collection / txid / docHashHex / cachePath / receivedHeight / isPrivate /
  verifyState`). Thumbnails live in a parallel `_thumbs` `QPixmap` vector index-aligned with
  `_items`.
- Delegate: **`NFTGalleryDelegate`**, a fixed **168×208** card (DPR-scaled): rounded card
  `#15171c` + hairline `#2a2d35`; a square cover-fit thumbnail
  (`KeepAspectRatioByExpanding` + crop); a verify badge on a dark disc top-right; a **"Public"
  pill — always amber `#d9822b`, never a green "Private"** (issue #119 honesty); a bold elided
  name and a dim elided collection caption.
- **Churn-free polling:** `setItems()` is fingerprint-guarded (a SHA-1 over all
  render-affecting fields). An identical re-feed each poll = **zero churn** (no flicker, no
  reflow). `onImageReady` updates **every** row whose `docHashHex` matches and emits a tight
  per-row `dataChanged`.

### 2.2 Gallery states

| State | When | What the owner sees | Status |
|---|---|---|---|
| **Empty / first run** | No tokens held | Friendly intro card ("Your NFTs will appear here…"); hides once rows arrive | BUILT+TESTED |
| **Index off** | `zslp` index disabled | State line with a **copyable `zslpindex=1` hint** | BUILT+TESTED |
| **Loading (first poll)** | RPC in flight | Today: static state line. **Designed:** skeleton shimmer cards | line BUILT; skeletons DESIGNED-NOT-BUILT |
| **Populated, no local bytes** | Live production default | A wall of cards each showing **"Image not on this device"** + neutral "–" badge | BUILT+TESTED (and is the #1 UX gap, §2.3) |
| **Populated, bytes attached** | After Attach / blob hit | Real thumbnails, green ✓ badges | BUILT+TESTED |

### 2.3 The #1 "don't-make-me-think" gap: no production thumbnails

**This is the most important thing to fix.** In shipped builds, `RPC::refreshNFTs()`
(`rpc.cpp:871-1010`, via `zslp_listmytokens` + batched `zslp_gettoken`) sets
**`it.cachePath = QString()` for every item by privacy design**, so every live card is
`verifyState 0` with no thumbnail — a wall of identical gray "Image not on this device" cards.
The blob store and **Attach** exist, but there is **no first-class flow to populate posters**.

Designed remedies, in priority order (all **DESIGNED-NOT-BUILT**):

1. **Inline "Attach image" affordance on the card** — a card with no local bytes shows a
   subtle "+ Add image" hover action that opens the same file-picker → `hashFile` →
   match-gate → `cachePut` → re-request poster flow that the detail dialog uses.
2. **Drag-and-drop a folder of held files onto the gallery** → bulk-hash every file once,
   auto-match each against held tokens' `docHashHex`, and populate every matching poster in
   one pass. (Bounded by the same 4-thread pool; show a non-modal progress chip.)
3. **Auto-resolve from an arrived ZDC1 transfer** — once a private data-channel content for a
   token you hold has been received and verified (§6), the verified plaintext is written to
   the blob store and the poster appears with **no manual Attach.** This is the long-term
   "it just works" path and it depends on the Shield receive flow shipping.

### 2.4 Search / filter / group / sort — DESIGNED-NOT-BUILT

`NATIVE_NFT_GUIDE.md §2.0/§2.2` specifies live search over name+collection, a Filter
(All / Verified / Needs-attention / …), a Group (By collection / By privacy), and Sort. **None
is built** — there is no `QSortFilterProxyModel`; the model is a flat, unsorted list in raw
RPC order.

**Designed implementation:** insert a `QSortFilterProxyModel` between `NFTGalleryModel` and
the view. A debounced (~150 ms) search box drives `setFilterFixedString` over a synthesized
name+collection role. Filter/Group/Sort are toolbar combo-boxes mapping to proxy predicates
and a sort role. Keep the model's fingerprint guard intact: the proxy filters, the source
model still no-churns on identical re-feeds. "Needs-attention" filter = `verifyState == 2`
(mismatch) plus the no-local-bytes terminal state, surfacing exactly the cards that want the
owner's action.

### 2.5 Zoom tiers — DESIGNED-NOT-BUILT

Gallery currently hard-codes `nftThumbPx = 152` (`mainwindow.h:373`). A denser/larger zoom
would re-decode rather than reuse. **Designed:** a 3-stop zoom (compact / standard / large)
that requests new poster sizes; because posters are content-addressed by `"<hash>@<px>"`, each
stop caches independently and the RAM `QPixmapCache` keeps recently-used sizes warm.

### 2.6 Honesty copy on every card (uniform, BUILT+TESTED)

- **"Public" pill** — always amber, always present.
- **Badge meaning** never appears as "genuine/official." Green ✓ tooltip: *"The image on this
  device matches the fingerprint recorded on the public ledger. It does not mean the NFT is
  official — anyone can mint a copy using the same picture."*
- The no-local-bytes neutral state reads **"Image not on this device"** (gallery) — not a
  perpetual amber spinner.

---

## 3. The detail / verify view

`NFTDetailDialog` (`src/nftdetaildialog.{cpp,h}`) — **BUILT+TESTED**.

### 3.1 Layout

- **760×560.** Left = an image **stage** (`kStagePx = 380`, requests `kPosterPx = 512`).
  Right = an info panel: verify line + badge, **Public pill**, mint id, received block/date,
  set line, fingerprint shown abbreviated **8…8**, and the honesty footnote.
- **Footnote (verbatim, load-bearing):** *"Only the mint id is one of a kind."*
- **Ownership line (verbatim):** *"● Public — anyone can verify this on the public ledger."*
  Never "private/shielded."

### 3.2 Actions

| Action | Behavior | Notes |
|---|---|---|
| **Send / Gift** | Opens transparent transfer of the token | Token transfer is **public** — copy must say so |
| **Sell** | Opens sell dialog | **Disabled on mismatch** (`verifyState == 2`) |
| **Save image…** | Writes the local image to disk | Only when bytes are present |
| **Copy id** / **Copy fingerprint** | Clipboard | — |
| **Re-check image** | Re-runs verify on the local bytes | — |
| **View in explorer** | **Confirm-dialog gated** (leaving the app) | Honest "this opens a website" warning |
| **Prev / Next** | Walks the gallery | A fresh token retires a stale neighbor's late reply (§5.4) |
| **Attach the file you have…** | The one path a received NFT reaches green ✓ | See §3.3 |

### 3.3 "Attach the file you have…" — the verification handshake (BUILT+TESTED)

This is the **only** path by which a received NFT's image reaches the green badge today:

1. Owner explicitly picks a **local file**.
2. `ContentEngine::hashFile()` computes the anchor.
3. **Match-gate** against the token's `docHashHex` — accepts **either** a bare whole-file
   SHA-256 (small/single-leaf) **or** a chunked Merkle root (`anchorHexFor` / `verify()` rule,
   §5.5).
4. On match: `cachePut` writes the verified bytes to the content blob store, then
   `requestPoster()` re-renders → green ✓.
5. **Disabled honestly** for a hash-less NFT (nothing to check against).

### 3.4 Verify states in detail (consistent with gallery)

- **0 pending** → amber "?" (`question.svg`).
- **1 verified** → green "✓" (`check.svg`, `#1f7a1f` / `#2a9d2a`).
- **2 mismatch** → red "✗" (`x.svg`, `#c0392b`) — Sell disabled.
- **No-local-bytes terminal** → neutral dim "–" + *"Can't check this image — its file isn't on
  this computer."* (**not** a perpetual spinner). This is the common production state.

### 3.5 Detail-view gaps — DESIGNED-NOT-BUILT

- **Neighbor prefetch.** Prev/Next re-requests a poster each step with no look-ahead; fast
  scrubbing tears down/rebuilds. **Designed:** prefetch 1-ahead / 1-behind so scrubbing feels
  instant. Posters are content-addressed, so the prefetched neighbor is a warm-cache hit.
- **Resize re-fit.** `onPosterReady` scales once to the current stage size; `m_sourcePixmap`
  is retained but there is no `resizeEvent` re-fit, so a maximized dialog shows a small image.
  **Designed:** re-scale `m_sourcePixmap` to the stage on `resizeEvent` (no re-decode).
- **Provenance back-fill is a stub.** `nftProvenance` / `txReceivedDate` RPC back-fill runs
  with QPointer lifetime guards, but provenance is a **no-op stub** (the chain records no
  creator). Creator / set / series rows are **honest defaults only** today.

---

## 4. The collection / set board (Collections tab, index 1) — DESIGNED-NOT-BUILT

`NATIVE_NFT_GUIDE.md §2.7` specifies a stacked page for card-sets/groups: a **set header**, a
**completion meter** ("3 of 7 collected"), and a per-set card board. **None is built.** Today
"collection" is only a one-line dim caption; tokens are not grouped, and **`nft.h` has no
`groupId` / `childOf`** field.

**Designed implementation:**

1. **Data model.** Add `groupId` (the ZSLP group/parent token id) and `childOf` to `NFTItem`,
   populated by `refreshNFTs()` from the ZSLP group→child relationship (group GENESIS + child
   tokens). A second model groups child rows under their group row.
2. **Navigation.** Clicking a set caption on a card, or a "View set" action in detail,
   switches the `QStackedWidget` to index 1 with that set selected; a back button returns to
   the gallery preserving scroll position.
3. **Set header.** Set name, a **completion meter** ("collected M of N") where N is the set's
   declared child count and M is the count this wallet holds, and the same **Public** honesty
   pill (set membership is on-chain and public).
4. **Card board.** The same delegate, but cards the owner does **not** hold render as dim
   "not yet collected" placeholders (no fabricated image, honest empty glyph) — never implying
   ownership the ledger doesn't show.
5. **Honesty.** "Completion" is *what this wallet holds of a publicly-declared set* — it is
   not a private or exclusive status. Membership and completion are derivable by anyone from
   the public ledger.

---

## 5. Rendering + caching architecture (the engine we already have)

The whole render surface runs on **one shared engine**. This section is the contract any new
display feature builds on.

### 5.1 One engine, one instance — BUILT+TESTED

- **`ContentEngine`** (`src/contentengine.{h,cpp}`) is the single class.
  **`NFTImageCache`** (`src/nftimagecache.{h,cpp}`) is now a **thin back-compat alias-subclass**
  — no duplicate logic.
- **One instance per `MainWindow`** (`nftImgCache`, `mainwindow.cpp:3132`), passed to the
  gallery, detail, mint, send, sell, and buy dialogs (everywhere as
  `nftImgCache /*ContentEngine*/`). New surfaces reuse this instance — never spin up a second
  engine.
- It turns any **local** file's bytes into: (a) a `verifyState` (0 pending / 1 verified /
  2 mismatch), (b) a poster/thumbnail `QImage`, (c) a chunked Merkle root.

### 5.2 Three async ops, one runnable — BUILT+TESTED

One `ContentTask : QRunnable` carries `Op_Poster` / `Op_Hash` / `Op_Verify`:

| Method | Caller | Inflight key |
|---|---|---|
| `request()` / `posterFor()` | gallery (token == 0) | `"<hash>@<px>"` (hash-addressed) |
| `posterForToken()` | detail (token > 0) | `"poster#<token>"` |
| `hashFile()` | Attach handshake | `"hashjob#<token>"` |
| `verify()` | re-check | `"verify#<token>"` |

### 5.3 The two delivery paths

- **Gallery (`request`/`posterFor`, token == 0):** worker classifies (MIME header sniff),
  streams + verifies, decodes the image **downscaled at decode**, writes an **atomic PNG** to
  the on-disk poster cache (`AppData/nft_posters/<hash>_<px>.png`), then crosses back via
  `QMetaObject::invokeMethod(..., QueuedConnection)` to **`deliver()` on the GUI thread**,
  which builds the `QPixmap`, seeds `QPixmapCache`, and calls
  `NFTGalleryModel::onImageReady(hash, pm, verifyState)`.
- **Detail (`posterForToken`, token > 0):** the **same** decode/verify, but delivers the large
  `QImage` via the **`posterReady(token, img, verifyState)`** signal to **one** caller
  (`NFTDetailDialog::onPosterReady`). `token == 0` / empty-path / bad-size / remote-URL all
  emit `posterReady(token, null, CE_Pending)` so the dialog **never hangs**.

### 5.4 Two-tier (really three-store) cache — BUILT+TESTED

- **RAM `QPixmapCache` (128 MB)** keyed by the inflight key.
- **On-disk poster PNG cache** (`AppData/nft_posters/`) — decoded thumbnails.
- **Separate content-addressed blob store** (`AppData/nft_content/<hash>`) — **verified raw
  bytes**, opt-in via `cachePut`.
- **Critical correctness rule:** `request()` short-circuits to `CE_Verified` **without
  rehash** *only* when the **trusted-hash blob exists** — correctly **not** gated on mere
  poster-PNG existence (which would mis-report a mismatch as verified). New code must preserve
  this.
- **Path-traversal safe:** `safeKey()` keeps only `[0-9a-f]`, length-capped 80; `cachePut`
  re-asserts the destination stays inside `blobCacheDir()`.
- **Stale-reply retirement (detail):** a fresh `token` retires a stale neighbor's late reply
  on fast prev/next, so scrubbing never shows the wrong image.

### 5.5 How it stays fast (perf characteristics) — BUILT+TESTED

- **Bounded `QThreadPool` = 4 workers.** Workers never touch `QPixmap`.
- **Streaming, bounded RAM:** never `readAll()`; one reused **1 MiB** buffer
  (`kHashBufBytes`); `std::atomic<bool>` cancel checked every block; dtor `cancelAll()` +
  `waitForDone()`.
- **Decode guards:** source wider than 4096 px or file > 10 MB is `setScaledSize()`-downscaled
  at decode (`kDecodeCapPx = 1024`), then `scaledToWidth(sizePx)`.
- **Dedupe:** identical in-flight key dropped; every non-delivering exit (cancel / null owner)
  releases the key via the `ContentTask` dtor safety net (inflight-key leak fix).
- **Anchor rule (`anchorHexFor`):** multi-chunk → Merkle root; small/single-leaf → bare
  whole-file SHA-256. `verify()` accepts **either** form. `computeVerify` does a fast
  single-pass bare-SHA first and only falls back to the full Merkle pass on a non-match
  (double-hash fix). **This is why "Attach" accepts both hash shapes.**

### 5.6 What renders, and what is honestly *not* faked — BUILT+TESTED

- **Image** (`CK_Image`, `image/*`): real `QImageReader` decode → thumbnail/poster (also
  attempted when MIME sniff is ambiguous, so an odd-extension image still gets a thumb).
- **Video / Document / Bytes:** **no decode, no fake frame.** `renderTypedPoster()` paints a
  native `QPainter` glyph on the dark inset (`#1d2027`): film-strip + play triangle (video),
  folded-corner ruled sheet (document), box + tick (bytes). **Honest** — the static bundle has
  no codec, so we never fake a video frame.
- **Format coverage caveat:** PNG always works; **JPEG/GIF/WEBP/SVG depend on which Qt
  `imageformats` plugins are compiled into the static bundle.** The `.pro` lists only platform
  plugins, so **format-plugin coverage must be confirmed in the actual shipped bundle** before
  promising a format to the owner.

### 5.7 Placeholder vs. real (so no one ships a fixture)

- **Real/honest:** the engine, verify math, threading, all three caches, badge states,
  no-bytes terminal copy, typed glyph posters, public-ownership copy.
- **Fixtures only:** thumbnails from `loadNFTFixtures()` (`:/nft/sample*.png`) are gated behind
  `NFT_GALLERY_FIXTURES` and are **not in shipped builds.** In the shipped path every
  `cachePath` is empty by design (§2.3), `collection` is just the ZSLP ticker (fallback
  "ZSLP"), and `isPrivate` is always false.

---

## 6. SHIELD — private send / receive of file content (THE NEXT BUILD)

This is the next thing to build, so this section is **implementation-ready**. It is the **GUI
surface over the ZDC1 shielded data-channel**. The daemon side is **BUILT-CLI-ONLY**; the GUI
is **DESIGNED-NOT-BUILT**. Build the GUI to the as-built daemon contract below — not to the
older, stale docs.

> **Honesty banner the Shield UI must show, verbatim, before the first send:**
> *"This makes the **file's contents** private — it is encrypted so only the person you send
> it to can open it. It does **not** make ownership of your NFT private: who holds the token
> is always public on the ledger. The encrypted file is stored **permanently and publicly** on
> every node — it can never be deleted, only kept unreadable to others."*

### 6.1 What's actually built underneath (the contract)

- **ZDC1 codec — BUILT+TESTED** (25 gtests, `src/gtest/test_zdc.cpp`; standalone harness
  `src/datachannel/test/zdc_test.cpp`; compiled into the daemon).
  - **AEAD:** libsodium `crypto_aead_chacha20poly1305_ietf` combined mode, the **only** cipher
    (`CIPHER_CHACHA20POLY1305 = 0x01`).
  - **Per-transfer key:** 32 random bytes (`randombytes_buf`), **fresh per transfer, never
    reused, never logged**, zeroized on destruct/replace/TTL-expire. **No KDF** — the key is
    raw CSPRNG, independent of any wallet secret and of the Sapling ivk.
  - **Nonce:** `transfer_id(8 BE) ‖ nonce_ctr(4 BE)`; reserved-counter band (START = 0xFFFFFFFF,
    END = 0xFFFFFFFE) fixes a real prior nonce-reuse bug; locked by `TEST(ZDC, NonceUniqueness)`.
  - **document_hash = ciphertext fingerprint** (`ciphertext_fingerprint`, `zdc.cpp:523`):
    SHA-256 over DATA-frame ciphertexts in seq order — deterministic, **key-independent**
    (stable before/after key reveal). This is the on-chain anchor that a ZSLP NFT's
    `document_hash` commits to, **binding the public token to the private bytes without
    revealing them.**
  - **Verify-before-decrypt:** `z_getdatatransfer` recomputes the anchor and compares it to
    the expected anchor **before any decrypt**; it **never returns plaintext on failure.**
- **Three daemon RPCs — BUILT-CLI-ONLY** (`src/rpc/datachannel.cpp`), registered **only** under
  `-datachannel` (default OFF, `init.cpp:527`). When off, the dispatcher returns
  `RPC_METHOD_NOT_FOUND (-32601)`.
- **Cross-wallet receive — BUILT-CLI-ONLY, unproven by automated E2E.** The current daemon has
  the registry-free reconstruct-from-chain path (`datachannel.cpp:504-536`,
  `GetFilteredNotes(requireSpendingKey=false)` so a **viewing-key-only** wallet can read its
  frames; the ivk decrypts the L1 memos, the on-chain KEY frame populates the L3 key,
  `verify_fingerprint` gates the open). **No ivk/spending key ever leaves the wallet.** The
  stale "#117 structurally impossible" line in `NFT_FINAL_REVIEW.md` / `PRIVACY.md` describes
  an **older** revision — **the code is ahead of those docs.** The remaining real caveat is
  **key delivery**: the in-band KEY frame works (`include_key_frame = true`,
  `datachannel.cpp:288`); out-of-band/reveal-later is **DESIGNED-NOT-BUILT**.
- **Selective disclosure via `z_exportviewingkey` (Sapling ivk) — DESIGNED-NOT-BUILT.**
  `rpcdump.cpp` throws *"Currently, only Sprout zaddrs are supported"* (line 832); the data
  channel is Sapling-only, so the ivk cannot be exported today. **As-built disclosure is via
  sharing the per-transfer L3 key** returned by `z_senddatafile` plus `verify_fingerprint`.
  The GUI must offer **only** the L3-key path until the Sapling ivk export ships.

### 6.2 Exact daemon RPCs the GUI calls

**`z_senddatafile`** (async; poll with `z_getoperationresult`):
- IN: `{ fromaddress (Sapling z), toaddress (Sapling z), filepath | hexdata (exactly one,
  ≤ 40000 B), acknowledge_permanent: true (REQUIRED), filename?, content_type? }`.
- OUT: `{ operationid, transfer_id (16-hex), fingerprint (64-hex = NFT document_hash), frames,
  key (hex per-transfer key for selective disclosure) }`. Async result also yields
  `{ txid, transfer_id, fingerprint, frames }`.
- Enforces, at the daemon: **permanence ack**, **Sapling from-addr with spending key in
  wallet** (no watch-only send), **shielded change**, **40000-byte cap**, **90-frame single-tx
  guard**. The 40000-byte cap is principled, not arbitrary: a single shielded tx fits
  ~99 frames under the post-Sapling tx-size budget, and the codec then picks a **chosen
  ceiling of 90 frames** (`ZDC_MAX_FRAMES_PER_TX`) for headroom — 87 DATA frames × 464
  usable bytes ≈ the 40000-byte file cap.

**`z_listdatatransfers`** — IN: none. OUT: array of
`{ transfer_id, fingerprint, direction ("sent"), frames, status ("recorded"), fromaddress,
toaddress, filename }`. **Session/in-memory only** — lists only what *this* node sent *this*
session; expired by 72h TTL. **The GUI must not present this as a durable history.**

**`z_getdatatransfer`** — reassemble + verify-before-decrypt. IN:
`{ transfer_id (16-hex) | fingerprint (64-hex), address? (defaults to recorded toaddress,
else scans all viewable addrs), verify_fingerprint? (64-hex out-of-band anchor) }`. OUT:
`{ transfer_id, fingerprint, verified, complete, frames_received, onchain_fingerprint?,
expected_fingerprint?, hexdata (plaintext — only if verified+decrypted), size, filename,
content_type, error }`.

**The four honest error codes the receive UI must distinguish** (never collapse to a generic
"failed"):
- `ERR_HASH_MISMATCH` — on-chain fingerprint ≠ expected anchor → **refuses to decrypt.**
- `ERR_NO_KEY` — frames complete but no KEY frame visible to this wallet (not the recipient /
  sealed transfer).
- `ERR_AEAD_FAIL` — tamper or wrong key.
- `ERR_INCOMPLETE` — frames still missing (post-decrypt, an END-plaintext SHA-256 cross-check
  can also raise `ERR_HASH_MISMATCH`).

### 6.3 Enabling the channel (prerequisite gate) — DESIGNED-NOT-BUILT

`-datachannel` defaults **OFF**. The GUI needs a **Settings → Privacy → "Enable private file
sending"** toggle that adds `-datachannel=1` to the daemon config and prompts a restart
(mirror the existing `zclassicd` config-edit + restart pattern). When off, every Shield
action is disabled with an honest *"Turn on private file sending in Settings to use this."*
(probe by attempting an RPC and treating `-32601` as "off"). No `-experimentalfeatures`
requirement in the as-built daemon.

### 6.4 SHIELD — Send flow (DESIGNED-NOT-BUILT, implementation-ready)

Entry points: detail dialog **"Send file privately…"** action, and a Collections-tab
**"Send a private file"** button. A modal wizard, never a free-form form.

**Step 1 — Pick the file.**
- File picker, local only. Show the chosen filename + size.
- **Hard 40000-byte cap, enforced in the UI up front** (the daemon also re-projects actual
  serialized size including real spend count, so an unusual UTXO set can still be rejected —
  surface that as a clear "this file is too large to send privately in one transaction,"
  never a raw `bad-txns-oversize`).
- Optional `content_type` is inferred from extension; let the owner override.

**Step 2 — Choose from / to (Sapling z-addresses).**
- **From:** a combo of the wallet's Sapling z-addresses that hold a spending key and enough
  ZCL for **N × 0.00001 ZCL dust + fee** (N = frame count, shown live as the file is picked).
  Watch-only addresses are excluded (the daemon rejects them).
- **To:** the recipient's Sapling z-address (paste/scan). Validate live (green/red, mirroring
  the send-tab address validation). The recipient **must** be a Sapling z-addr.
- Change returns **shielded** to the from-address — state this so the owner isn't surprised.

**Step 3 — Consent (mandatory, the daemon enforces it too).**
- A checkbox the owner must tick: **"I understand this encrypted file is stored permanently
  and publicly, and can never be deleted."** This maps to `acknowledge_permanent = true`. The
  Send button stays disabled until ticked.
- Restate the ownership-is-public truth (§6 banner). Show the live cost estimate
  (N dust + fee, in ZCL) and frame count.

**Step 4 — Sending (async).**
- Call `z_senddatafile`, then poll `z_getoperationresult` on the returned `operationid`. Show
  a non-modal progress chip ("Encrypting and sending…"), never a frozen dialog.
- On success, show: the **fingerprint** (= the NFT `document_hash`, labeled "Content
  fingerprint — this is what links the file to your NFT"), the **txid** (with the gated "View
  in explorer"), and the **per-transfer key**.

**Step 5 — Deliver the key (the load-bearing honesty step).**
- The in-band KEY frame is already on-chain (as-built default), so a recipient holding the
  matching ivk can open the file **without** you sharing anything. **But** the GUI must be
  honest that on-chain in-band reveal commits the key at send time and its confidentiality
  rests entirely on Sapling encryption to the recipient's ivk — a compromised ivk exposes the
  key.
- Offer **"Copy disclosure key"** (the L3 key) + **"Copy content fingerprint"** for explicit,
  out-of-band selective disclosure to a third party who is not the recipient. Label it plainly:
  *"Anyone with this key and fingerprint can open and verify this file — share it only with
  people you want to read it."*
- **Do not** offer ivk-export-based disclosure in the GUI yet (Sapling
  `z_exportviewingkey` is DESIGNED-NOT-BUILT).

### 6.5 SHIELD — Receive flow (DESIGNED-NOT-BUILT, implementation-ready)

The cross-wallet receive path is **BUILT-CLI-ONLY** in the daemon (registry-free,
`datachannel.cpp:504`); the GUI is what's missing. Two entry modes:

**Mode A — Open a file linked to an NFT you hold.**
- From the detail view of a token whose `docHashHex` is a known data-channel fingerprint, a
  **"Open private file"** action calls `z_getdatatransfer { fingerprint, address? }` with the
  token's fingerprint as the expected anchor.
- The daemon **verifies before decrypt**; on `verified == true && complete == true`, write the
  returned plaintext to the **content blob store** and re-request the poster → the gallery and
  detail thumbnails populate automatically (§2.3 path 3). This is the "it just works" loop.

**Mode B — Open by transfer id / fingerprint (paste).**
- A **"Receive a private file"** dialog accepts a `transfer_id` **or** `fingerprint`, an
  optional receiving z-addr (defaults to scanning all viewable addrs), and an optional
  out-of-band `verify_fingerprint`.
- If the sender shared an out-of-band L3 disclosure key (the as-built selective-disclosure
  path), provide a field for it; otherwise rely on the in-band KEY frame + the recipient's ivk.

**Receive states (map 1:1 to the daemon error taxonomy, §6.2):**

| Daemon result | UI state | Copy |
|---|---|---|
| `verified && complete` | Success | "File verified and opened." Save / preview / (if it's an image) attach-to-NFT |
| `ERR_INCOMPLETE` / `complete==false` | Still arriving | "Some pieces haven't confirmed yet. Try again in a few minutes." |
| `ERR_NO_KEY` | Can't open | "This file isn't addressed to you, or the key isn't on-chain for this wallet." |
| `ERR_HASH_MISMATCH` | Refused | "The file on-chain doesn't match the expected fingerprint. Not opened." (never show plaintext) |
| `ERR_AEAD_FAIL` | Refused | "Couldn't decrypt — the file may be tampered or the key is wrong. Not opened." |

**Cross-wallet caveat to surface honestly:** receive is **unproven by automated E2E** (no
regtest/cross-RPC seam test exists yet). Until that test lands, treat the GUI receive flow as
**beta** in release notes and keep the honest error states above sharp.

### 6.6 Metadata leakage the Shield UI must not hide

This is a **confidentiality** channel, **not steganographic / not undetectable.** The number
of outputs ≈ transfer size, burst timing, and the mere existence of a shielded tx are
observable; an all-max-memo output run hints "data channel." The send confirmation should
include a one-line, plain-language disclosure: *"Sending a private file is itself visible on
the ledger (the encrypted contents are not). Private does not mean undetectable."* Never imply
the transfer is invisible.

### 6.7 Shield — built-vs-designed summary

| Capability | Status |
|---|---|
| ZDC1 codec (AEAD, nonce, AAD, fingerprint, reassembly, error taxonomy) | **BUILT+TESTED** (25 gtests) |
| `z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer` | **BUILT-CLI-ONLY** |
| Cross-wallet verify-then-open via recipient ivk (registry-free) | **BUILT-CLI-ONLY**, no E2E |
| In-band KEY frame (as-built default) | **BUILT-CLI-ONLY** |
| Send wizard / Receive dialog / Settings enable toggle (the whole GUI) | **DESIGNED-NOT-BUILT** |
| Selective disclosure via Sapling `z_exportviewingkey` (ivk) | **DESIGNED-NOT-BUILT** |
| Seal-then-reveal / out-of-band key (`z_revealkey`, `keymode`), `zslp_mint_private` | **DESIGNED-NOT-BUILT** |
| Off-chain ciphertext + on-chain fingerprint for files > 40000 B; one-ciphertext-N-recipients fan-out | **FUTURE-IDEA** |

---

## 7. Accessibility + performance budget

### 7.1 Accessibility (DESIGNED — verify against shipped widgets)

- **Color is never the only signal.** Verify badges carry a glyph (✓ / ✗ / ? / –) *and* color
  *and* a text label, so red/green color-blindness never hides "mismatch."
- **Keyboard-first.** Gallery `activated` already fires on **Enter** (not just double-click);
  detail Prev/Next, Attach, and all actions must be Tab-reachable with visible focus rings;
  the Shield wizard advances on Enter and cancels on Esc.
- **Screen-reader labels.** Each card exposes an accessible name ("`<name>`, `<collection>`,
  `<verify state>`, Public"). Buttons get accessible descriptions matching the honesty copy.
- **Text scaling / DPI.** Cards are DPR-scaled; copy must not clip at 125–200% scaling (the
  delegate elides name/collection — confirm elision, not truncation, at large fonts).
- **Reduced motion.** Skeleton shimmer (when built) honors a "reduce motion" preference by
  falling back to a static placeholder.

### 7.2 Performance budget (measured against the as-built engine)

| Target | Budget | Backed by |
|---|---|---|
| GUI thread never blocks on render work | 0 ms blocking; all hash/decode off-thread | 4-thread `QThreadPool`, GUI-thread only builds `QPixmap` — **BUILT+TESTED** |
| Peak RAM per in-flight hash | ~1 MiB regardless of file size | reused `kHashBufBytes` 1 MiB buffer, no `readAll()` — **BUILT+TESTED** |
| RAM thumbnail cache ceiling | 128 MB | `QPixmapCache` cap — **BUILT+TESTED** |
| Decode cap | ≤ 1024 px working size; > 4096 px or > 10 MB downscaled at decode | `kDecodeCapPx`, `setScaledSize()` — **BUILT+TESTED** |
| Gallery re-poll churn | zero repaint on identical data | SHA-1 fingerprint guard in `setItems()` — **BUILT+TESTED** |
| Paint hot path | zero pixmap allocation | delegate uses pre-built thumbs — **BUILT+TESTED** |
| Detail prev/next | should feel instant | **needs** 1-ahead/1-behind prefetch — **DESIGNED-NOT-BUILT** |
| Shutdown with multi-GB hash in flight | clean abort | `cancelAll()` + `waitForDone()` — **BUILT+TESTED** |
| Private send (Shield) | non-blocking async; ≤ 40000 B/file; ≤ 90 frames/tx | daemon `z_senddatafile` async + caps — **BUILT-CLI-ONLY** |

---

## 8. Key file map

**GUI (`/home/rhett/github/zcl-qt-wallet`):**
- `src/contentengine.{h,cpp}` — the one shared engine (`posterForToken`→`posterReady`;
  gallery `request`→`onImageReady`; `isRemoteUrl`).
- `src/nftimagecache.{h,cpp}` — back-compat alias shim.
- `src/nftgallery{model,delegate}.{cpp,h}`, `src/nft.h` (no `groupId`/`childOf` yet).
- `src/nftdetaildialog.{cpp,h}`.
- `src/mainwindow.cpp:3013-3367` (setupNFTTab / openNFTDetail / setNFTItems /
  loadNFTFixtures), `src/mainwindow.h:373` (`nftThumbPx=152`).
- `src/rpc.cpp:871-1010` (`refreshNFTs` → `setNFTItems`; `cachePath` always empty by design).

**Daemon (`/home/rhett/github/zclassic`):**
- `src/datachannel/zdc.{h,cpp}` (codec, AEAD, nonce, `ciphertext_fingerprint` at zdc.cpp:523).
- `src/rpc/datachannel.cpp` (the 3 RPCs; registry-free cross-wallet path at 504-536;
  `include_key_frame=true` at 288; permanence ack at 206-213; 40000-byte cap at 84).
- `src/wallet/asyncrpcoperation_senddatafile.{h,cpp}` (one shielded tx, N same-recipient
  outputs; size re-projection guard).
- `src/wallet/rpcdump.cpp:832` (Sapling `z_exportviewingkey` Sprout-only TODO).
- `src/init.cpp:527` (`-datachannel` default 0).
- `src/gtest/test_zdc.cpp`, `src/datachannel/test/zdc_test.cpp` (codec tests).

**Docs:**
- `doc/nft/NATIVE_NFT_GUIDE.md` §2.0–2.7 (display spec; search/filter/group/sort + set board
  DESIGNED-NOT-BUILT), §3.3 (as-built data-channel contract).
- `doc/nft/PRIVACY.md` (honesty banner; stale on cross-wallet #117 — code is ahead).
- `doc/nft/NFT_FINAL_REVIEW.md` (whole-feature status; also stale on #117).

---

*Canonical as-built contract for the data channel: `NATIVE_NFT_GUIDE.md §3.3`. Whole-feature
status: `NFT_FINAL_REVIEW.md`. The coin is ZClassic / ZCL throughout. NFT ownership is always
public; only file content is private.*
