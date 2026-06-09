# ZClassic NFT — Native UX Design

> **REMOVED — shielded data channel / on-chain private files.** The private-NFT / ZDC1 data-channel
> read/write paths this doc designs (binary-safe `ZDC1`-magic memo handling, the data-channel inbox)
> have been **removed entirely** from the daemon. ZClassic deliberately provides **no wallet path to
> store arbitrary files on-chain**. NFT content is always off-chain, bound to the token only by a
> `document_hash` fingerprint. Treat every ZDC1 / private-read section below as **historical**.

**Status:** Design spec (synthesis of 6 screen specs). Grounds on real, shipping code.
**Repos:** daemon `/home/rhett/github/zclassic`; GUI `/home/rhett/github/zcl-qt-wallet` (branch `feature/nft-gallery`).
**Constraint:** C++14 only (`zcl-qt-wallet.pro CONFIG += c++14`). NO `std::optional` / `std::string_view`. Use empty-`QString` sentinels and default-initialized struct members.
**Theme:** `res/styles/dark.qss` — the "Quiet+" dark wallet. All NFT surfaces reuse its existing tokens; no new color is introduced.
**Rendering:** 100% native Qt (`QListView` + `QStyledItemDelegate` + `QPainter`). NO QtWebEngine / HTML / browser, anywhere — this is a hard owner constraint and a differentiator.

This document is the single source of truth that reconciles six screens into one coherent product:

1. **gallery-grid** — Collections gallery (home of your NFTs)
2. **nft-detail** — single-NFT detail dialog
3. **mint-flow** — "Create an NFT"
4. **send-gift** — give an NFT to someone
5. **set-collection** — the "collect them all" board for one card-set
6. **first-run / empty** — zero-NFTs + the index-off variant

Where two screens described the same element differently, this doc **picks one** and every screen conforms. The cross-screen contracts live in §1 (principles), §2 (visual system), and §5 (performance). The per-screen sections (§3) defer to them and only describe what is unique.

---

## 0. The product in one breath

A first-timer opens **Collections** and sees their own pictures in a dark grid that looks like the rest of the wallet — not a list of hashes, not a web page. Each card answers a collector's only two questions with color, a dot, **and** a ring (so nobody has to decode a palette):

- **"Is this mine-and-hidden?"** → one word: **Private** (green) or **Public** (amber).
- **"Does this picture match what was recorded on-chain?"** → one corner badge: **check** (green) / **x** (red) / **question** (amber). (Match only — it does not say the collectible is the original/official one; §2.2.)

Click a card → it opens **large**, with one plain green/red/amber sentence at the top of the info panel that answers "is this real?" without ever showing the word SHA-256. The brightest button is the safe, delightful one (**Send / Gift**, **Save image**); risky or outside-the-wallet actions are quiet and ask first.

Three differentiators we lead with, in human terms:
1. **Local image-to-fingerprint check, natively** — the wallet recomputes the on-chain fingerprint locally and shows a green check that the picture's bytes match what this collectible recorded. No server, no browser. (It does NOT prove the collectible is the original/official one or who made it — see §2.2.)
2. **Private NFTs ship first** — because the daemon already does shielded memos, ZClassic offers *private sealed collectibles* before most chains can do public ones.
3. **It feels like the wallet** — same dark theme, same nav rail, same delegate-rendering craft as the privacy badges.

---

## 1. Design principles — the "don't make me think" rules we commit to

These are non-negotiable across all six screens (Steve Krug, adapted for a privacy wallet).

**P1 — No crypto jargon, ever, in user-facing copy.**
"fingerprint" not SHA-256/hash. "on-chain record" / "on the ledger" not consensus/OP_RETURN. "sealed" / "only people you choose" not encrypted-memo/viewing-key. "collectible" is used in first-run/learn copy; "NFT" is acceptable in headings and buttons but never a protocol term. **Banned from all visible strings:** SHA-256, OP_RETURN, GENESIS, token, mint-baton, zslpindex, t-addr/z-addr (say "public (transparent) address" / "private (shielded) address"), ivk, memo (use "note"/"message").

**P2 — One obvious next action per state.** Every screen has exactly one bright (green `#1f7a1f`) primary at any moment. Empty → "Show me how it works". Zero-result → "Clear filters". Detail → "Send / Gift". Mint → "Create NFT". The eye lands on one thing.

**P3 — Safe default is the default.** Private is pre-selected everywhere a visibility choice exists. Private leaks nothing and works on today's daemon. Public is the deliberate, explained, confirmed choice.

**P4 — No dead ends, no silent failures.** A disabled control always carries a one-line *reason and fix* ("Private gifts need a private (shielded) address — paste one above."). Not-yet-built paths show **"Coming soon" / "Coming in this release"** disabled, never missing — so the user never wonders if they broke something. A missing image says exactly how to get it. A turned-off public index never hides the private NFTs that work today.

**P5 — Status, not controls, for safety signals.** Verify badge and privacy pill are read-only indicators; they are never clickable controls on the grid/board. Verification *detail* lives in the detail dialog. This keeps browse surfaces uncluttered and unmisclickable.

**P6 — Instant, tactile feedback.** Copy actions flip the button label to "Copied ✓" for ~1.2 s. Filters/search update the count chip live ("12 of 40"). Selecting a visibility tile *rewrites a live consequence table* before the user commits. Nothing waits on a daemon round-trip to render.

**P7 — Color is never the only signal (accessibility).** Privacy = color + a leading **dot glyph** + the lead-capped word. Verify = color + glyph (check/x/question) + a **1px ring** around the badge disc. Mismatch additionally gets a red inner hairline. Screen-reader names (`setAccessibleName`) announce the verdict.

**P8 — Privacy is the floor, not a setting.** The wallet NEVER silently fetches a remote `documenturl` image (it would leak IP + collecting interest). Image bytes come from the local cache or **one explicit user action**, behind a one-time confirm. A "not downloaded" item is the deliberate, honest representation of "not local".

**P9 — Reuse the wallet's taught vocabulary.** Every badge, pill, card surface, and button style a user sees in Collections is the same one they already learned on the gallery. No screen teaches a new visual word.

**P10 — Honest about limits.** "Private" = hidden from the public, not "only one copy can ever exist." Unknown facts render the literal word **"Unknown"** / **"Not part of a set"** — never blank, never fabricated. There is intentionally **no in-app marketplace / buy button** (the chain can't honor it); missing cards say "they arrive when someone sends them to your wallet" + one receive-address button.

---

## 2. Visual system (shared)

All values are **verified present** in `res/styles/dark.qss` and `src/nftgallerydelegate.cpp`. Reuse only; do not invent tokens.

### 2.1 Color tokens

| Token | Hex | Meaning / use |
|---|---|---|
| app bg | `#0f1115` | page / window / `QDialog` background (deepest) |
| card | `#15171c` | a card/group surface on the page |
| inset | `#1d2027` | elevated content within a card: rows, inputs, tables, thumbnails |
| hairline | `#2a2d35` | 1px border on every card/inset |
| text | `#e6e6e6` | primary live text |
| dim text | `#9aa0a6` | secondary/labels (AA floor for live text — never dimmer) |
| title white | `#ffffff` | headings, selected tab |
| private/green | `#1f7a1f` | **Private** everywhere; verified badge; primary buttons; progress fill |
| hero green | `#34c759` | brightened green for a single success tick / 100% set-complete pulse (`#2a9d2a`) |
| public/amber | `#d9822b` | **Public**/transparent everywhere; pending-verify "?"; a setting needs attention |
| danger red | `#c0392b` | RESERVED — mismatch / "this could leak or is broken" only |
| ghost dims (delegate-local `QColor` consts) | `#3d4450` ghost numeral / hover border, `#2f343d` empty-state glyph — **decorative only** (not live text). The missing-slot card **name/caption is live text and renders at `#9aa0a6` (the AA floor), never dimmer** — `dark.qss:200-201` explicitly rejects `#6b7177` (~3.1:1) for live text | declared in-code like `kDim`, used only on the set board + empty states |

**Color discipline:** green = safe/yours/image matches its on-chain fingerprint. Amber = public/attention/pending. Red = ONLY mismatch or a real leak risk. Never use red for "empty" (empty uses quiet grey so it never reads as broken).

### 2.2 The verify badge — one language everywhere

Drawn via the existing `NFTGalleryDelegate::tintedIcon(resource, color, px)` cache (QSvgRenderer → tinted QPixmap, keyed by resource+color+px, rendered once). SVGs already bundled (`check.svg` / `x.svg` / `question.svg`, sha f8f2bde2).

| `verifyState` | Icon | Color | Disc ring (1px, P7) | Plain meaning |
|---|---|---|---|---|
| 1 VERIFIED | check | `#1f7a1f` | green ring | "this picture matches its on-chain fingerprint" |
| 2 MISMATCH | x | `#c0392b` | red ring + red inner thumb hairline | "does not match its on-chain fingerprint" |
| 0 PENDING | question | `#d9822b` | amber ring | "checking this image…" / "image not downloaded" |

- **Geometry is shared:** dark disc + tinted glyph, badge at the **top-right of the thumbnail/image**. Gallery/board = 16px; detail/mint = 20px.
- **Copy is shared** (full strings in §3 per screen, but the verdict sentences are identical wherever they appear): "This image matches its on-chain fingerprint." / "This image does not match its on-chain fingerprint. It may have been changed." / "Checking this image…".
- The badge is **status, never a control** (P5). Hover shows a tooltip repeating the sentence.

> **What the green check means — and what it does NOT (honesty rule, non-negotiable).** The check means **only** that the picture's bytes on this device match the fingerprint this collectible recorded on the ledger. It is a bytes-match check, nothing more. **It does NOT mean the collectible is "genuine," "authentic," "official," or "the original," and it says nothing about who made it.** Anyone can create a *different* collectible (a different mint id) that reuses the same name and the same image — that copy will show the very same green check. So the badge copy is **always** "matches its on-chain fingerprint," **never** "Genuine / Authentic / Official / the Original." Three separate things must never be blurred together:
>   1. **Image match** (this badge) — "the bytes match the on-chain fingerprint." Cryptographic, local, trustless.
>   2. **Who made it (issuer)** — *not* something this badge or any "verified" pill can show. It comes only from outside the network: a signed attestation from the issuer, or a verified-issuer list **keyed by mint id** that names the human or group maintaining it. There is no network-guaranteed "verified" badge for an issuer.
>   3. **Uniqueness** — exists **only at the mint-id (genesis txid) level**. The name, ticker, and image are **not** unique and can be reused by a different collectible. Identity is the mint id, never the name or the picture.
>
> And a receipt is **pending, not final, until ~10 confirmations** (the node's finalization depth, `DEFAULT_MAX_REORG_DEPTH = 10`): a short reorg can briefly undo a just-arrived collectible, so ownership/authenticity is shown as **pending** until then (see §3.2).

### 2.3 The privacy pill — one vocabulary everywhere

Reuses the delegate's privacy-pill `QPainter` path and `privacyColor(bool)`.

| State | Pill | Fill | Leading dot | One-liner (detail/send) |
|---|---|---|---|---|
| Private | green "Private" | `#1f7a1f` @ ~38 alpha | green dot | "Only you can see this. Its ownership is shielded." |
| Public | amber "Public" | `#d9822b` @ ~38 alpha | amber dot | "Anyone can verify this on the public ledger." |

Lead-capped word + leading dot glyph (P7). A private item **never** offers a public explorer link or any remote fetch.

### 2.4 The card — one anatomy everywhere

The 168×208 card from `NFTGalleryDelegate::baseCardSize()` is the shared material. Gallery, set board (owned slots), detail thumbnail, mint review thumb, and send card-1 thumb all use the same paint craft so the app feels like one surface.

```
+--------------------------+   body:   #15171c, 1px #2a2d35 hairline, radius 12 (kCardRadius)
|  +--------------------+ ●|   hover:  border #3d4450
|  |   square thumb     | ◐|   select: border #1f7a1f 1.6px
|  |   inset #1d2027    |  |   thumb:  square inset, radius 8 (kThumbRadius), cover-fit crop
|  |   radius 8         |  |   badge●: verify badge top-right of thumb (§2.2)
|  +--------------------+  |   shimmer while pending (one shared QTimer, visible cards only)
|  ● Private               |   privacy pill ● below thumb (§2.3)
|  Aurora #014             |   name: bold #e6e6e6, elided
|  Zcl Originals           |   collection: #9aa0a6 0.85x, elided
+--------------------------+
```

**Density:** Comfortable 168×208 (default) ↔ Compact 132×168. The delegate reads an int density role/property; paint stays geometry-driven (no new pixmaps). Persisted via a **new** `Settings::getNFTThumbSize()` getter/setter (to be added — see §6.1).

**Variants (still the same card):**
- **Set-board owned slot:** identical, but the collection line is replaced by a small "#N" slot-number caption (collection is redundant inside a set).
- **Set-board MISSING slot ("ghost"):** body + hairline kept; thumb area is flat inset `#1d2027` with NO shimmer (it isn't loading) + a centered **decorative** `#3d4450` "#N" ghost numeral (decorative, not live text, so a sub-AA grey is fine here); caption = card **name** at `#9aa0a6` (the AA floor — live text never drops below it; `dark.qss:200-201` explicitly rejects `#6b7177` ~3.1:1 for live text) + a "Not collected" label at `#9aa0a6`; no badge, no pill. The "missing" affordance is carried by the **~55% painter opacity + ghost numeral + the "Not collected" label**, NOT by a sub-AA text color — so owned cards pop forward and completion reads from the silhouette alone while the name stays AA-legible.

### 2.5 Typography & spacing

- Page heading: 18–20pt / 700, `#e6e6e6`–`#ffffff`. Subhead: 12–14pt `#9aa0a6`, wordWrap.
- Card name: bold ~13–14pt `#e6e6e6`; collection ~11–12pt `#9aa0a6`.
- Dialog title: 16pt / 700 `#e6e6e6`; section/card titles 13–15pt / 600.
- IDs/hashes/values: fixed-pitch (`QFont::setFamily("monospace")`), right-aligned, shown **short** as `first8…last8` with a one-click copy and a hover tooltip carrying the full string.
- Layout rhythm matches `setupNFTTab()`: 12px outer margins, 8px grid spacing; cards 12–16px inner padding, 12–16px gap; dialog rows 14–16px.
- Card radius 12, inset/thumb radius 8 (already the qss + delegate constants).

### 2.6 The one consistent action set

The same verbs, same labels, same order, wherever an action on an NFT appears (card context menu, detail dialog, set-slot dialog):

| Action | Label | Where | Notes |
|---|---|---|---|
| Open | (double-click / Enter / Space) | gallery, board | opens detail dialog |
| **Send / Gift** | "Send / Gift" (button) / "Send / Gift…" (menu) | detail, context menu, board slot | the bright primary; opens NFTSendDialog |
| Save image | "Save image…" | detail | disabled until bytes exist; writes verbatim bytes |
| Copy id | "Copy id" | detail, context menu | → "Copied ✓" 1.2s |
| Copy fingerprint | "Copy fingerprint" / "Copy image hash" | detail (More), context menu | full lowercase hex |
| Copy name / collection | "Copy name" / "Copy collection" | context menu, detail (More) | |
| Copy transaction id | "Copy transaction id" | context menu | |
| Re-check image | "Re-check image" | context menu | re-queues NFTImageCache for this hash |
| View in explorer | "View in explorer" | detail (More), disabled | only if `getExplorerUrl()` set AND `isPrivate==false`; asks once before opening a browser |

There is **no "open link" / no network item** in any browse context menu. Private items never expose an explorer entry.

### 2.7 Copy voice (shared)

Plain, warm, second person, no exclamation spam, no emoji. State the outcome a button will produce ("Send gift privately" vs "Send the picture"). Reassure rather than alarm ("Nothing to do right now."). When something is off, say what to do, in one sentence. Reuse exact verdict sentences across screens so the user learns them once.

---

## 3. The screens

Each screen extends the shared system above. Only screen-unique layout, states, and copy are listed.

### 3.1 Collections gallery (gallery-grid)

**Role:** a browser/launcher, not a detail or mint screen. Extends the existing `setupNFTTab()` page (`mainwindow.cpp:3017`): same `QVBoxLayout(nftTab)`, 12px margins, 8px spacing. All additions programmatic, gated on `Settings::getShowNFTGallery()`. No `.ui` change.

**Layout (top → bottom):**
- **A — Heading block (exists):** `QLabel#nftGalleryHeading` "Collections" (18pt/700 `#e6e6e6`) + subhead "Your NFTs. The image on each card is checked against its on-chain fingerprint." (`#9aa0a6`, 12pt). A live count chip at the right of the heading row (`QLabel#nftCountChip`, 11pt `#9aa0a6` on `#1d2027` pill, 6px radius): "12 items" → "12 of 40" when filtered.
- **B — Toolbar (NEW, one `QHBoxLayout#nftToolbar`, h=36, spacing 8):**
  `[ search QLineEdit#nftSearch  flex ] [ Filter ▾ ] [ Group ▾ ] [ Sort ▾ ] [ density ⊞ ]`
  - `nftSearch`: dark.qss input, placeholder "Search your collection", leading magnifier via `QLineEdit::addAction(LeadingPosition)` (reusing the tint pattern) + trailing clear-X when non-empty; min-width 220, stretch 1.
  - `nftFilter`: All / Private only / Public only / Verified / Needs attention (~140).
  - `nftGroup`: No groups (default, flat per private-first decision) / By collection / By privacy (~150).
  - `nftSort`: Recently received / Name A–Z / Collection (~160).
  - `nftDensity`: checkable flat `QToolButton`, tinted grid glyph, tooltip "Card size".
- **C — The grid (exists):** `QListView#nftGalleryView` IconMode, `setResizeMode(Adjust)` + `setWrapping(true)` + `setUniformItemSizes(true)`. Cards from §2.4. Auto-packs 3 cards at ~620px up to 7+ at 1400px.
- **D — State overlays (NEW):** a `QStackedLayout` wrapping the view's place: grid vs empty/zero-result panel (centered, max-width 360; large tinted frame glyph, title `#e6e6e6`, body `#9aa0a6`, one primary). Toolbar is **hidden when true item count is 0** (nothing to filter), **shown when count>0 even if a filter yields zero rows** (so the user can clear it).

**Architecture decision (consistency):** search/filter/sort/group live in a **`QSortFilterProxyModel`** (NEW) over the untouched `NFTGalleryModel` + `NFTGalleryDelegate`. The source model and delegate are unchanged; the delegate only gains a density property. "By collection" inserts non-selectable section-header rows (role-driven). Re-feeding identical data emits zero churn (the fingerprint-guard technique already in `setItems`).

**States:** LOADING (cards render immediately with shimmer + amber "?"; count chip shows real local count at once — metadata is local, only images async) · EMPTY (toolbar hidden — see §3.6) · ZERO-RESULT (toolbar stays; panel "Nothing matches" + active filter in plain words + "Clear filters") · VERIFIED / MISMATCH / PENDING / **PENDING-NO-BYTES** ("Image not downloaded. Open to fetch it yourself." — NEVER auto-fetched, P8) · PRIVATE / PUBLIC · **INDEX-OFF** (one-line inset banner above the grid: "Public collectibles are turned off. Your private NFTs are still shown." + quiet "How to turn on" — never blocks the private grid) · OFFLINE (keep last good grid from on-disk thumb cache, count chip dims, no spinner-of-doom).

**Interactions:** live search over name+collection (case-insensitive), count chip → "N of M", Esc/clear-X resets · Filter/Group/Sort instant via proxy · density toggle swaps size + persists · hover lightens border + plain-language tooltip · single-click select; double-click/Enter/Space opens detail · arrow keys move selection (native IconMode), Home/End/PageUp/Down; Tab/`/` focuses search · **context menu = the §2.6 set** (Open, Copy name, Copy fingerprint, Copy transaction id, Re-check image — no link/network item) · a pending-no-bytes card fetches bytes ONLY when opened and only after the in-detail "Get image" confirm.

**Copy:** "Collections" · "Your NFTs. The image on each card is checked against its on-chain fingerprint." · "Search your collection" · filter/group/sort labels above · "12 items" / "12 of 40" · "No NFTs yet" · "Nothing matches" · "Clear filters" · "Checking this image…" · "This image does not match its on-chain fingerprint. It may have been changed." · "Image not downloaded. Open to fetch it yourself." · "Public collectibles are turned off. Your private NFTs are still shown." · "How to turn on" · "Re-check image" · "Copy fingerprint" · "Card size".

### 3.2 Single-NFT detail (nft-detail)

**Role:** show ONE NFT large and answer "is this really mine, does this image match its on-chain fingerprint, what can I do with it?" Modal `QDialog` (new `src/nftdetaildialog.{h,cpp}`, built programmatically like `setupNFTTab`), opened on click/Enter/double-click. Geometry remembered in `QSettings("NFTDetail/geometry")`. Min 760×560, resizable, centered on parent. Carries the `NFTItem` **by value** (cheap POD copy), plus a lightweight ordered list of the gallery's item ids (or a proxy reference) so prev/next can step — **no model pointer**.

> **POD scope (don't over-claim what's in hand at open):** the value-copied `NFTItem` POD is only `{name, collection, txid, docHashHex, cachePath, receivedHeight, isPrivate, verifyState}` (see `src/nft.h`). **Creator, exact Set/series-position, the exact received-DATE, and `documenturl` are NOT fields on the POD** — they arrive later via async RPC (`zslp_gettoken` / `gettransaction`) and are back-filled into the already-open dialog (C10). In particular the **"Received" ISO date specifically needs a `gettransaction` lookup** to map the block height to a timestamp — the POD carries only `receivedHeight`. Until those land, the corresponding rows show "Unknown" / "Not part of a set" / "block N (date pending)", never blank or fabricated.

**Layout:**
- **Title bar (h=44):** name 16pt/700 `#e6e6e6` (elided) + collection 11pt `#9aa0a6` ("Not part of a set" if none); right = flat close glyph (tinted x.svg). 1px `#2a2d35` hairline below.
- **Left column — image stage (stretch 1, min 380×380):** a card (`#15171c`/radius 12/hairline) holding a centered `QLabel("imageStage")` painting the full QPixmap with `KeepAspectRatio SmoothTransformation` (never upscales past 1024 native; letterboxed on `#1d2027`). Verify badge (20px, §2.2) floats top-right of the image. Shimmer while decoding (same visual language as the gallery).
- **Right column — info panel (fixed 320, `QVBoxLayout` spacing 12):**
  1. **Verify line (top, can't-miss):** full-width inset row (`#1d2027`/radius 10/hairline/pad 10) = 20px badge + one 13pt sentence; color swaps by `state` dynamic property (verified green / mismatch red / pending amber).
  2. **Privacy pill row:** §2.3 pill + an 11pt `#9aa0a6` one-liner.
  3. **Details card (`#15171c`/radius 12/hairline/pad 12):** label/value grid. Left labels 11pt `#9aa0a6`; right values 12pt `#e6e6e6`, right-aligned monospace for ids/hashes. Rows: **Mint id** (the genesis txid — *this* is the collectible's identity, not its name; short txid 8…8 + copy), **Received** (ISO date + "block 1,842,001" or "block — (unknown)"; until ~10 confirmations this row reads "Just arrived — confirming…" because a short reorg can briefly undo it, so ownership is shown **pending, not final**), **Creator** (issuer or "Unknown" — never fabricated; "Unknown" is honest because the chain does not record who minted it), **Set** ("Wild Series — 7 of 30" or "Not part of a set"), **Image hash** (short docHashHex 8…8 + copy). Hairline between rows; long values elide with hover tooltip. A 11pt `#9aa0a6` footnote under the grid: "This name and image aren't unique — anyone can mint another collectible that reuses them. Only the mint id is one of a kind." Ownership/authenticity is shown **pending until ~10 confirmations** (`DEFAULT_MAX_REORG_DEPTH = 10`), then final.
  4. **Action bar (pinned, h=48, hairline above):** the §2.6 set — primary green **"Send / Gift"** left-weighted; **"Save image…"**, **"Copy id"**; an overflow **"More" (…)** menu with "Copy image hash", "Copy collection", and a DISABLED-by-default "View in explorer" (only enabled if `getExplorerUrl()` set AND `isPrivate==false`).

**States:** LOADING (shimmer + amber "Checking this image…"; Send/Gift + Copy id enabled — they need only the id; Save disabled until a pixmap exists) · VERIFIED (green: "This image matches its on-chain fingerprint."; all enabled — note this is a bytes-match only, NOT a "genuine/original" claim per §2.2) · MISMATCH (red: "This image does NOT match what was recorded on-chain. Don't trust it."; image dimmed 60% with thin red inset; Save stays enabled; Send/Gift shows a confirm first) · PENDING/UNCACHED (amber "Image not on this device yet." + a single explicit "Get image" button ONLY if a documenturl exists AND `isPrivate==false`; for private items the line reads "This image lives in your wallet's local cache." with no fetch button — P8) · PRIVATE / PUBLIC (one-liners per §2.3; explorer only for public+configured) · EMPTY METADATA ("Unknown" / "Not part of a set") · INDEX-OFF (wallet-local fields still show + calm note "Turn on the collectibles index to see full provenance." — no error dialog) · ERROR (amber "This file isn't an image we can show." + neutral broken-image glyph, never a crash).

**Interactions:** resize re-scales from the held source QPixmap (no re-decode/re-hash) · click image = no-op (no lightbox in v1) · Copy flips to "Copied ✓" 1.2s · **Send / Gift** opens NFTSendDialog pre-filled; in C0/C1 it routes to a "Sending NFTs is coming soon." toast rather than a dead button; on a MISMATCH item it first confirms "This image failed its on-chain check. Send anyway?" · Save image → `QFileDialog` defaulting to `<name>.png`, writes cached bytes verbatim · Get image (pending+public only) → one-shot worker fetch, hash-verify before display, inline progress, never auto-runs · More → explorer opens via `QDesktopServices::openUrl` only when enabled+public and asks once "This opens an outside website and may reveal your interest. Continue?" · Esc closes; left/right arrow steps to prev/next gallery item — this works because the dialog was handed the **ordered list of item ids** at construction (not a model pointer), so it walks that list and re-feeds the same dialog with the neighbor's POD (no flicker, no model coupling); verify line + details are `setAccessibleName`'d.

**Copy:** all sentences listed in the states + "Mint id" · "Received" · "Just arrived — confirming…" · "Creator" · "Set" · "Image hash" · "Unknown" · "Not part of a set" · "block — (unknown)" · "This name and image aren't unique — anyone can mint another collectible that reuses them. Only the mint id is one of a kind." · the §2.6 action labels · "Copied ✓" · "Get image" · "Turn on the collectibles index to see full provenance." · "This image failed its on-chain check. Send anyway?" / "Send anyway" · "Sending NFTs is coming soon." · "This opens an outside website and may reveal your interest. Continue?".

### 3.3 Create an NFT (mint-flow)

**Role:** turn one local image into a verifiable NFT, impossible to get wrong. New `src/nftmintdialog.{h,cpp}`, modal `QDialog`, fixed 560px wide, built `setupUi`-style like `memodialog` (C++14-trivial). Body = a `QScrollArea` (frameless, transparent viewport) of **4 numbered cards** (`QFrame#card`: `#15171c`/hairline/radius 12/16px pad/14px gap); footer pinned outside the scroll.

**Cards:**
- **1 — Your image (dropzone).** 528×180 `QFrame#dropZone`: inset `#1d2027`, 2px DASHED `#3d4450` border, radius 10. 40px tinted image glyph (`#9aa0a6`), 14pt "Drop an image here", 12pt "PNG, JPG, GIF, SVG, WebP — up to 20 MB", `QPushButton "Choose a file…"`. On drag-hover: border solid `#1f7a1f`, bg `#20242c`. After a file: collapses to a 528×96 loaded row — 72×72 thumbnail (via NFTImageCache), filename (elided middle) + "1.8 MB · 1024×1024", a "Fingerprint" mono line elided first8…last8 with copy, a green "Ready" pill once hashing completes, a flat "Replace" link top-right.
- **2 — Details.** `QFormLayout` of dark.qss inputs: **Name** (required, placeholder "e.g. Aurora #14", soft 50-char cap with live "32/50" counter), **Collection** (optional, "e.g. Zcl Originals — leave blank for a one-off"), **Note** (`QPlainTextEdit`, live "0/200"; label swaps Private↔Public — see states).
- **3 — Who can see it (the safety heart).** Two full-width selectable tiles (each a `QFrame` with a `QRadioButton`; selected gets a 2px accent border + faint tinted fill):
  - **Private (only people you choose)** — green accent, default selected. Body: "The image and details are sealed. Stored encrypted on the ledger; only someone you give the key to can open it. Your balance and addresses stay shielded."
  - **Public (anyone can verify and trade)** — amber accent. Body: "The name, collection, fingerprint and a link live on the public ledger forever. Anyone can look it up. The image itself stays off-chain — only its fingerprint is recorded." When public-mint RPCs are unwired, Tile B is **DISABLED** with an amber "Coming in this release" pill.
  - A 12pt `#9aa0a6` caption under the tiles always states the consequence of the current choice.
- **4 — Review & confirm.** Inset summary (`#1d2027`/radius 8): 56×56 thumb + "Name · Collection", a visibility pill (§2.3), "Fingerprint 1f2a3b…9c0d", "Size 1.8 MB". Below it a **"What happens" two-column micro-table** (green-dot "Stays private" / amber-dot "Becomes public"), auto-filled from the current choice (Private → right column shows just "Nothing"). Then a fee row: "Network fee 0.0001 ZCL · After this you'll have 5.2340 ZCL" (balance-after turns `#d9822b` near a safe floor).

**Footer (pinned):** flat "Cancel" + green default `QPushButton "Create NFT"`. Enables only when name + image + verified-hash are present (Private). Public-while-unwired keeps it disabled with helper text.

**States:** empty ("Add an image to continue") · drag-hover · wrong-file (inline `#d9822b` "That file isn't an image we can read — try a PNG or JPG." / "That file is larger than 20 MB. Pick a smaller image." — no modal) · hashing (indeterminate bar + "Fingerprinting…", threaded, responsive) · ready (green "Ready", primary enables once Name non-empty) · verify-mismatch (red badge, "Couldn't read those bytes cleanly — choose the file again.", primary disabled — we never mint a hash we couldn't reproduce) · private-selected (default; Note label "Note (sealed with it)"; Review right column "Nothing") · public-selected-and-wired (future; Note "Note (this becomes public)"; a one-time "I understand this is permanent and public." checkbox gates the primary) · **public-UNWIRED** (greyed tile + "Coming in this release"; clicking it shows the calm "Public minting arrives in a coming update. For now, create it Private — you can always make a public copy later." and Private stays selected) · submitting (Private, when C2 lands: primary → spinner "Creating…", inputs disabled, Cancel → "Run in background") · index-off · success (closes to a slim non-modal toast "NFT created — Aurora #14" + "Show it" that selects the new card; gallery auto-refreshes) · low-balance ("Not enough ZCL to cover the network fee.").

**Copy:** the strings above + "Create an NFT" · "1  Your image" / "2  Details" / "3  Who can see it" / "4  Review & confirm" · "Drop an image here" · "PNG, JPG, GIF, SVG, WebP — up to 20 MB" · "Choose a file…" · "Replace" · "Fingerprint" · "Ready" · "Fingerprinting…" · "Stays private" / "Becomes public" / "Nothing" · "Network fee" · "After this you'll have 5.2340 ZCL" · "A small flat network fee, paid to keep the network running. It does not go to us." · "Create NFT" · "Creating…" · "Run in background" · "Cancel" · "Discard this draft?" · "NFT created — Aurora #14" · "Show it" · "Copied" · "Public features need the token index on — turn it on in Settings.".

### 3.4 Send / Gift (send-gift)

**Role:** give one NFT you own to someone — pick who, optional note, Public vs Private, confirm. For Private gifts make the two-step "send the picture, hand over the key" flow feel like one calm action. New `NFTSendDialog`, modeled on `memodialog.ui` / `confirm.ui`; constructor **requires** an `NFTItem` (no empty state to design). Fixed width 520, geometry in `QSettings`. windowTitle "Send a gift".

**Layout — four cards + footer:**
- **1 — What you're giving (anchor, ~96px).** 72×72 inset thumb (fed exactly like the gallery: `NFTImageCache::request(docHashHex, cachePath, docHashHex, 72)` — instant from disk cache, shimmer while pending), verify badge bottom-right (§2.2). Right: name (15pt `#ffffff` bold), collection (12pt `#9aa0a6`), privacy pill (§2.3). Read-only — answers "this is the one, right?".
- **2 — Who gets it.** title "Send to". `AddressCombo` (the wallet's existing autocompleting recipient widget) full width; placeholder "Paste an address or pick a contact"; a "Address book" ghost button on the title row. One reserved-height live status line below it: empty→hidden / valid private→green "Looks good — a private (shielded) address" / valid public→amber "Looks good — a public (transparent) address" / invalid→red "That doesn't look like a ZClassic address". Recipient type **drives** card 3.
- **3 — How private.** title "Who can see this gift". Two full-width `#1d2027` click-target radio rows:
  - **Private gift** [green pill] — "Only you and the person you send to can see this. The picture travels hidden, and you hand over the key to unlock it."
  - **Public gift** [amber pill] — "Anyone can look up that this collectible moved to them. Their wallet address becomes visible on the public ledger."
  Default follows the NFT + recipient (Private NFT to a private addr → Private; Public NFT → Public). An unsupported choice is **disabled with the fix inline** (P4): Private disabled for a transparent recipient → "Private gifts need a private (shielded) address — paste one above." Public when ZSLP RPCs are absent → "Coming soon", disabled.
- **3b — When should they get the key? (reveals only when Private, animated `setVisible`).** Two rows: **Send it all now** (default) "We send the picture and the key together. They can open it the moment it arrives." / **Send the picture now, the key when you're ready** "The picture goes out sealed. You unlock it for them later with one tap from Activity — good for a surprise on a certain day." Footnote "Either way, only they can ever open it."
- **4 — Add a note (optional, collapsible, collapsed by default).** `QPlainTextEdit` (memodialog pattern) + right-aligned "0 / 512 bytes" counter (amber >480, hard cap 512). Helper "A short message that rides along, hidden, for them only." For a Public gift the note is hidden entirely with "Public gifts can't include a private note."

**Footer:** fee line "Network fee 0.0001 ZCL · You'll still have 5.2340 ZCL" + `QDialogButtonBox` [Cancel] and a green default action whose **label states the outcome** (the don't-make-me-think payoff): Private+send-all-now → "Send gift privately"; Private+reveal-later → "Send the picture"; Public → "Send gift". Action disabled until valid recipient AND a verified-or-pending thumb (blocks on red mismatch) AND not already in flight.

**States:** opened/ready · thumb pending (gift not blocked on a slow decode, only on a real mismatch) · thumb verified · thumb MISMATCH (red "This picture doesn't match its fingerprint — we won't send it.", action disabled) · recipient empty/valid-private/valid-public/invalid · Private chosen (3b + note reveal) · Public chosen (3b + note hidden with explanations) · sending (action → spinner "Sending…", inputs disabled, Cancel → "Close (keeps sending)") · sent-now ("Gift sent. It's on its way to them.") · sent-picture-only ("Picture sent, sealed. Unlock it for them anytime from Activity." + an Activity entry with a "Hand over key" action) · error (inline red banner + daemon's plain reason + "Try again", nothing sent) · index-off (Public disabled, Private fully works).

**Interactions:** debounced local address validation (no per-keystroke RPC) drives the status line + enables Private/action · Address book picks an address and re-validates · choosing Private reveals 3b with a soft expand; Public collapses it and hides the note; the action label updates instantly · whole radio row is the click target (hover lifts `#1d2027`→`#23272f`, pointing hand) · note expand/collapse via chevron; Esc/Cancel before send guards a typed note with "Discard your note?" · send uses the existing `RPC::executeTransaction`/`z_sendmany` async path with the wallet's `watchTxStatus`; reveal-later sends only sealed picture frames now and records a "Hand over key" one-tap for later · fully keyboard-navigable; the action label always tells you what Enter will do.

**Copy:** all sentences above + "Send a gift" · "What you're giving" · "Send to" · "Address book" · "Who can see this gift" · "When should they get the key?" · "Either way, only they can ever open it." · "Add a note" · "0 / 512 bytes" · "Verified — this picture matches its on-chain fingerprint" / "Checking…" / "Mismatch — not safe to send" · "Coming soon" · "Public collectibles need the collectibles index turned on (Settings ▸ Advanced)." · "Try again".

### 3.5 Set / collection board (set-collection)

**Role:** "collect them all" board for one card-set (Curio-Cards style) — show completion and the gap at a glance, calmly. A stacked page **inside the Collections tab** (`QStackedWidget` index 1; index 0 = the gallery `QListView`), reached by clicking a set thumbnail, with a back affordance. No new nav-rail entry.

**Layout:**
- **1 — Header strip (~64px):** flat back "‹ Collections" (`QToolButton`, dim `#9aa0a6`→hover `#e6e6e6`, 40px hit area). Center-left: set name 20pt/700 `#e6e6e6`; under it 12pt `#9aa0a6` "Created by {creator} · {N} cards" (a creator shows a tiny green tinted check ONLY when its mint id is on a named verified-issuer list — its tooltip says "On {maintainer}'s verified-issuer list", never a bare "Verified"; this is a social/external signal, NOT a network guarantee — §2.2 item 2). Right: completion meter — 13pt "3 of 7 collected" above a 6px rounded track (inset `#1d2027` bg, **green `#1f7a1f` fill**, NOT amber, NOT a rainbow); at 7/7 the fill animates once to brighter `#2a9d2a` + a single green "Set complete" pill.
- **2 — The board (hero):** a `QListView` IconMode configured identically to the gallery, fed by a **`SetBoardModel`** (sibling of `NFTGalleryModel`) whose rows are ALL slots in canonical manifest order — owned and missing alike — painted by a **`SetSlotDelegate : NFTGalleryDelegate`**. Owned slots paint as §2.4 (with "#N" caption); missing slots paint as the ghost variant (§2.4) — dim, numbered, "Not collected", 55% opacity, **no image request issued** (nothing to decode, no network).
- **3 — Footer help bar (~44px, only when missing>0):** left 12pt dim "Missing 4 cards. They arrive when someone sends them to your wallet." Right: one quiet secondary button "Show my receive address" (hairline border, NOT a loud green CTA) → opens the existing Receive tab. **No in-app buy/trade** (P10).

**States:** loading-board (set name/creator instant from cached token; owned slots shimmer only while decoding; missing slots final immediately so the board shape is correct on first paint) · empty-set (full board of ghosts, "0 of 7 collected", "You haven't collected any of these yet. They arrive when someone sends them to your wallet.") · verified/mismatch/pending owned slot (§2.2; mismatch shows a `#c0392b` "Image doesn't match its record" caption, never silently hidden, never auto-refetched) · missing slot (the default for any slot you don't hold) · private-set (owned slots show the green Private pill; subline adds "Private set — only you can see what you hold"; missing slots carry no pill) · **index-off** (public sets only: a single calm inset card "Turn on collection tracking to see sets" + "How to turn it on"; private sets unaffected — they come from the memo scan) · set-complete (green pulse, "Set complete" pill, footer hides entirely, brief "You've collected the whole set.") · stale/offline (last known count + dim "(updating…)", never flash a wrong lower count).

**Interactions:** click a set card → `QStackedWidget` index 1 (built once, reused); back via "‹ Collections" / Esc / Backspace → index 0 with the gallery scroll preserved · hover owned slot brightens (border `#3d4450`, pointing hand, tooltip "Card #N · {name} · received {date}"); hover missing stays dim (tooltip "Card #N · {name} · not collected yet") — the hover difference teaches owned-vs-missing with no legend · double-click/Enter owned → the detail dialog (§3.2); missing → a lightweight "not collected" dialog (manifest preview + "Show my receive address") · arrow keys move selection; the verify badge has no click action on the board (status, not control — P5).

**Copy:** "3 of 7 collected" · "Set complete" · "You've collected the whole set." · "Created by {creator} · {N} cards" · "Not collected" · "Missing {n} cards. They arrive when someone sends them to your wallet." · "You haven't collected any of these yet. They arrive when someone sends them to your wallet." · "Show my receive address" · "Card #{n} · {name} · not collected yet" / "Card #{n} · {name} · received {date}" · "Image doesn't match its record" · "Private set — only you can see what you hold" · "Each card is checked against its on-chain record." · "Turn on collection tracking to see sets" · "How to turn it on" · "updating…" · "‹ Collections".

### 3.6 First-run / empty (Collections empty + index-off)

**Role:** make a brand-new user with zero NFTs instantly understand "this is where collectible art you've been sent or made lives, and the wallet checks each picture against its on-chain fingerprint" and give them ONE obvious action; when the daemon's index is off, replace the empty state with a plain explanation + the one toggle. Never a dead end.

**Structural change (the only one):** wrap the existing single `QListView` in a `QStackedWidget#nftGalleryStack` with **four pages** — 0=gallery, 1=empty, 2=index-off, 3=loading — and flip pages instead of show/hide juggling. The heading stays "Collections" in every state; the subhead is **state-dependent**.

**Pages (same centered hero-card geometry so the layout never jumps — `#15171c`/hairline/radius 12/28px pad/16px spacing, max-width 520, centered):**
- **1 — EMPTY:** 56px tinted frame glyph in quiet grey `#2f343d` (NOT red, NOT amber — "empty", not "broken"), title "No collectibles yet", body "When someone sends you a collectible, or you make one, it shows up here — and the wallet checks each picture against its on-chain fingerprint. Nothing to do right now.", ONE green primary "Show me how it works" (Phase C1; becomes "Make your first collectible" when mint lands in C2), a subordinate flat link "What is a collectible?".
- **2 — INDEX-OFF:** 56px tinted toggle-off glyph in amber `#d9822b` (a setting needs attention, not broken), title "Collectibles tracking is turned off", body "Turn this on and the wallet will start finding your collectibles. It does a one-time catch-up scan in the background, so syncing stays fast for people who don't collect.", green primary "Turn on collectibles", flat link "Why is this a separate setting?". On a **managed daemon**: a confirm ("The wallet will restart and do a one-time scan in the background…" [Not now]/[Turn it on]) → writes the flag → restart → loading. On a **foreign/old daemon** (`-32601` or unmanaged): the CTA instead reveals a `#1d2027` inset with the exact conf line "zslpindex=1" + a [Copy line] button — never a dead end.
- **3 — LOADING:** "Looking for your collectibles…" + an indeterminate `QProgressBar` (`#1f7a1f` chunk) + "This runs in the background. You can keep using the wallet." Non-modal, never a blocking spinner. Resolves to Empty(1) or Gallery(0).

**State selection** rides the existing poll loop (`rpc.cpp doRPC`) calling `zslp_listmytokens`: index-disabled error → page 2; `-32601` → page 2 conf-line variant; success+empty → page 1; success+rows → page 0; first call outstanding → page 3. The last good page is **latched fingerprint-style** (mirroring the `getwalletsummary -32601` latch at `rpc.cpp:1641`) so a transient poll error never flickers back to empty/off. Daemon-unreachable reuses the wallet's existing global "Not connected" banner and **keeps the last state** (showing empty/off would falsely imply "you have none").

**Copy:** subhead (first-run) "Collectibles are one-of-a-kind images you've been sent or made. The wallet checks each picture against its on-chain fingerprint." · the titles/bodies/CTAs above · "What is a collectible?" · "Why is this a separate setting?" → inline expander "It's off by default so the wallet syncs quickly for everyone. Turn it on only if you want to collect." · foreign-daemon inset "Your wallet is connected to a node you didn't start here. Add this one line to its zclassic.conf, then restart it:" / field "zslpindex=1" / "Copy line" · turn-on confirm "The wallet will restart and do a one-time scan in the background. You can keep using everything else while it runs." [Not now]/[Turn it on] · "Looking for your collectibles…" / "This runs in the background. You can keep using the wallet."

---

## 4. End-to-end happy paths

### 4.1 Browse → open → send (the everyday loop — ships first, private)
1. Tap **Collections** in the nav rail. The grid paints instantly with shimmer thumbs + amber "?" badges; the count chip shows the real local count at once.
2. Thumbs stream in from the on-disk cache; badges flip to green checks. The user scans the silhouette — green pills = mine-and-hidden, green checks = the picture matches its on-chain fingerprint (a bytes-match, not a "genuine/original" claim — §2.2).
3. Type a name in search → "12 of 40"; or pick "Verified" in Filter. Instant, no I/O.
4. Double-click a card → **detail dialog** opens large, almost always painting from cache immediately. The verify line reads "This image matches its on-chain fingerprint."
5. Click **Send / Gift** → **NFTSendDialog** opens with the picture already chosen and verified (step "is this the right one?" answered before a word is read).
6. Paste/pick a recipient → the live status line confirms "a private (shielded) address". Private gift + "Send it all now" are pre-selected.
7. The green button reads "Send gift privately". Press it → spinner → "Gift sent. It's on its way to them." The gallery refreshes on the next poll.

### 4.2 Mint (create your first NFT)
1. From Collections empty state ("Make your first collectible", C2) or a future mint entry → **NFTMintDialog**.
2. Drop an image → threaded SHA-256 runs (indeterminate bar, "Fingerprinting…"), the dropzone collapses to a loaded row with a thumbnail and "Ready".
3. Type a Name (required). Collection optional. **Private** is pre-selected; the consequence caption + the "Stays private / Becomes public" table show "Nothing" becomes public.
4. Review shows thumb, visibility pill, fingerprint, size, and "Network fee 0.0001 ZCL · After this you'll have 5.2340 ZCL".
5. **Create NFT** → "Creating…" → broadcast → dialog closes to a toast "NFT created — Aurora #14" with "Show it". (Public path shows "Coming in this release" and steers to Private — never a dead end.)

### 4.3 Collect a set
1. In Collections, a set card → click → the **set board** swaps in (`QStackedWidget` index 1). Owned cards are bright and detailed; missing ones are dim, numbered, "Not collected". The completion meter reads "3 of 7 collected".
2. Hover teaches owned-vs-missing (owned brightens, missing stays dim). Double-click an owned card → detail; a missing card → "not collected yet" + "Show my receive address".
3. The footer states the honest path: "Missing 4 cards. They arrive when someone sends them to your wallet." with one quiet receive-address button.
4. When the last card arrives, the green fill pulses to `#2a9d2a`, a "Set complete" pill appears, and the footer simply disappears — the reward is the absence of remaining work.

---

## 5. Native performance contract (shared, enforced everywhere)

This is a **contract**: any NFT code that violates it is a defect.

**C1 — No web, ever.** No QtWebEngine / HTML / browser on any path. Every NFT pixel is a `QPixmap` on a `QLabel` / `QListView`, painted with `QPainter`. (Verified: the C0 delegate/cache contain none.)

**C2 — The threading contract (already enforced in `nftimagecache.cpp`).** A bounded `QThreadPool` (`setMaxThreadCount(4)`) decodes off the GUI thread. The worker reads bytes from the AppData cache, **SHA-256-verifies** against `docHashHex`, `QImageReader::setScaledSize` down-scales huge sources **at decode time**, and produces **only a `QImage`** — it NEVER touches `QPixmap`. It hands back via `QMetaObject::invokeMethod(..., Qt::QueuedConnection)` to `deliver()`, where the `QPixmap` is built **on the GUI thread** and `onImageReady(hash, pixmap, verifyState)` updates rows by `docHashHex`. Thumbs live in a parallel index-aligned `QVector<QPixmap>`.

**C3 — Caching is two-tier and re-open is free.** `QPixmapCache` (128 MB) + on-disk `AppData/nft_thumbs/{hash}_{size}.png` (and `AppData/nft_images/{hash}` for full bytes). Re-opening the gallery, opening detail, or seeing the same image in send/mint paints from cache with no decode. SHA-256 verification runs **once** per row on the worker; the result is cached — the detail dialog and board read `verifyState`, they never re-hash. Resizing the detail image re-scales from the held source pixmap (cheap `SmoothTransformation`), never re-decodes or re-hashes.

**C4 — In-flight guard, no duplicate work.** The cache's `_inflight` set (mutex-guarded) drops a duplicate request for the same key; `Replace` in the mint dialog and a superseded decode cancel cleanly (mirrors `_inflight`).

**C5 — No relayout on scroll.** `setUniformItemSizes(true)` + a fixed delegate `sizeHint` = `sizeHint` queried once. `resizeMode Adjust` + `setWrapping(true)` reflow columns cheaply on window resize. The density toggle changes a size constant, not the pipeline — instant.

**C6 — One shimmer timer.** A single shared `QTimer` drives one repaint of only the **visible pending** cards (`viewport()->update` over the pending index-rect set) — not a timer per card. Missing set-board slots issue ZERO image requests and never shimmer (they aren't loading).

**C7 — Flicker-free refresh.** Models are **fingerprint-guarded** (`NFTGalleryModel::setItems`, `SetBoardModel::setItems`): a wallet poll returning identical state emits no model signals → no relayout, no thumbnail re-request, no flicker. The `QSortFilterProxyModel` runs in-process (no I/O) over the guarded source.

**C8 — Tinted glyphs cached.** `tintedIcon(resource, color, px)` renders each badge/dot/toolbar glyph once and caches it in a `QHash` keyed by resource+color+px (the `PrivacyBadgeDelegate` pattern). Zero pixmap allocation on hover/repaint.

**C9 — PRIVACY = PERFORMANCE-SAFE (the hard rule, P8).** The hot path touches **only local bytes** — the file the user picked and the on-disk cache. A remote `documenturl` image is **NEVER auto-fetched** (no IP/interest leak, no surprise network stall). Bytes arrive only from cache or one explicit user action ("Get image" / "Create NFT" / "Save image"), each behind a confirm where it leaves the device. The only network action a mint/send makes is the user's explicit final broadcast.

**C10 — RPC stays off the GUI thread and off the paint path.** Provenance (`zslp_gettoken` / `zslp_listtransfers` / `zslp_listmytokens`) and the empty-state selection ride the existing async `rpc.cpp` poll connector; dialogs render instantly with wallet-local fields (name, txid, height, privacy, verify) and fill remote provenance when it returns. No per-paint or per-scroll RPC. Public ZSLP rows come from cached `zslp_*` JSON-RPC polled on the existing refresh loop, never blocking paint.

---

## 6. Implementation map (files + build order)

Grounded in the real tree. Existing C0 files confirmed present on `feature/nft-gallery`: `src/nft.h`, `src/nftgallerymodel.{h,cpp}`, `src/nftgallerydelegate.{h,cpp}`, `src/nftimagecache.{h,cpp}`; `setupNFTTab()` at `mainwindow.cpp:3017`; `setupNavRail()` + `makeRailButton` at `mainwindow.cpp:1255`/`1278`; Collections rail button at `1311`.

### 6.1 Existing files that change

| File | Change |
|---|---|
| `src/mainwindow.cpp` | Wrap `nftGalleryView` in `QStackedWidget#nftGalleryStack` (4 pages, §3.6); add Region-B toolbar (§3.1); add the set-board `QStackedWidget` page + `SetBoardModel`/`SetSlotDelegate` wiring (§3.5); refine subhead/count-chip; gate on `Settings::getShowNFTGallery()`. Mind the nav-rail live-index re-sync. |
| `src/mainwindow.h` | Declarations for the stack, proxy model, set-board model/delegate, dialog launchers. |
| `src/nftgallerydelegate.{h,cpp}` | Add a density property/role (Comfortable 168×208 ↔ Compact 132×168); add the disc **ring** (P7) + mismatch inner hairline + privacy leading-dot. Source model untouched. |
| `src/rpc.{h,cpp}` | Empty-state selection over `zslp_listmytokens` with the `-32601`/index-off branches + fingerprint latch (mirror `rpc.cpp:1641`); provenance reads for the detail/board; the index-off conf-write/restart helper. **Private receive path** parses `z_listreceivedbyaddress` notes (C1). The current code at `rpc.cpp:~756-760` **lossily coerces binary memos through a `QString` conversion** (`QByteArray::fromHex(...)` → `QString`, then drops `.trimmed().isEmpty()`), which mangles non-text frames; **ADD a parallel binary-safe read path** (detect the `ZDC1` magic and route to a data-channel handler) before private NFTs can be read — leave the existing text-inbox path intact. |
| `src/settings.{h,cpp}` | `getShowNFTGallery()` exists today; **ADD `getNFTThumbSize()` and `getExplorerUrl()` as NEW getters/setters** (neither exists yet — only `getShowNFTGallery()` and the unrelated `getExplorerTxURL`/`getExplorerAddressURL` are present); persist density. |
| `res/styles/dark.qss` | Append NFT object-name rules using existing tokens ONLY: `#nftEmptyCard`/`#nftIndexOffCard`/`#nftLoadingCard`, `#nftEmptyTitle`/`#nftIndexOffTitle`, `#nftEmptyBody`, `#nftEmptyLearn`/`#nftIndexOffWhy` hover, `NFTDetailDialog#nftDetailDialog`, `#nftVerifyLine[state="verified|mismatch|pending"]` color swap, `#nftDetailsCard`. Primary buttons inherit the existing green accent (no new rule). |
| `application.qrc` + `res/icons/` | **New SVG assets needed.** Today `res/icons/` ships only the badge/privacy glyphs relevant here — `check.svg`, `x.svg`, `question.svg` (plus the existing `eye.svg` / `eye-off.svg` / `shield-lock.svg`, which the NFT screens don't reuse). The screens additionally need, **none of which exist yet**: a **magnifier** (search), a **grid/density** glyph, a **copy** glyph, a **frame/picture** glyph (empty-state), and a **toggle/index-off** glyph. Add all five (single source, tinted at runtime via `tintedIcon()`), and register them in `application.qrc`. |
| `zcl-qt-wallet.pro` | Add the new `.cpp`/`.h` to `SOURCES`/`HEADERS`. The `QThreadPool` path needs no new Qt module (`QtConcurrent` not required). C++14 only. |

### 6.2 New files

| File | Role |
|---|---|
| `src/nftdetaildialog.{h,cpp}` | Modal detail dialog (§3.2), programmatic, `QSettings("NFTDetail/geometry")`, async hash verify via NFTImageCache. |
| `src/nftmintdialog.{h,cpp}` | Guided create dialog (§3.3), `setupUi`-style like memodialog, worker-thread chunked SHA-256 (mirror `connection.cpp:928`). |
| `src/nftsenddialog.{h,cpp}` | Gift/transfer dialog (§3.4), constructor requires an `NFTItem`, reuses `AddressCombo` + `RPC::executeTransaction`. |
| `src/setboardmodel.{h,cpp}` | `QAbstractListModel` sibling of `NFTGalleryModel`; rows = full set in manifest order, owned|missing; fingerprint-guarded `setItems`; reuses `onImageReady`. |
| `src/setslotdelegate.{h,cpp}` | `: NFTGalleryDelegate`; forks owned-card paint + adds ghost missing-slot paint + "#N" numeral; reuses `tintedIcon()` + dark.qss QColor consts. |
| (proxy) | A `QSortFilterProxyModel` instance for the gallery search/filter/sort/group — may live inline in `mainwindow.cpp` or a small `nftgalleryproxy.{h,cpp}` if section-header rows warrant a subclass. |

### 6.3 Build order (each step shippable, smallest-usable-first)

1. **Gallery polish + proxy + density + empty/loading pages + index-off (page 2/3).** GUI-only, fixtures + the existing C0 pipeline. Toolbar, count chip, ring/dot accessibility, first-run hero. This is the demo, zero chain risk. (§3.1, §3.6)
2. **Detail dialog.** Opens from the gallery; reuses the cache; verify line + details grid + the §2.6 action set (Send/Gift routed to a "coming soon" toast in C0/C1). (§3.2)
3. **Private read path (C1).** Wire `rpc.cpp` to scan `z_listreceivedbyaddress` notes (first add the parallel binary-safe read path at `rpc.cpp:~756-760` — detect the `ZDC1` magic and route to a data-channel handler, rather than letting the lossy `QString` coercion mangle binary frames); the index-off page selection goes live. Real private NFTs appear; detail/badge run against real bytes. (§3.6 selection, C9/C10)
4. **Set board.** `SetBoardModel` + `SetSlotDelegate` + the in-tab `QStackedWidget` page; private sets from the memo scan. (§3.5)
5. **Mint + send (C2, private).** `NFTMintDialog` (`z_sendmany` self-send) + `NFTSendDialog` (incl. the reveal-later "Hand over key" Activity hook). Now a complete private-NFT loop on today's daemon. (§3.3, §3.4)
6. **Public ZSLP (C3, gated on daemon).** When `zslp_genesis/mint/send` exist (daemon `CRecipient.scriptPubKey` + `CreateTransaction` — NOT `createrawtransaction`), enable the Public tiles, public provenance in detail/board, and "By collection" completion. Until then every Public affordance is the honest disabled "Coming in this release". (§3.3 states, §3.5 index-off)

---

## 7. Honesty ledger (what we will NOT pretend)

- **No in-app marketplace / buy button.** The chain can't honor it; the set board says "they arrive when someone sends them to your wallet" + a receive address.
- **"Private" ≠ "only one copy can exist."** It means hidden from the public; a prior holder can keep their plaintext copy. Copy avoids implying exclusivity.
- **Public minting is not wired yet.** Every public path is a calm, disabled "Coming soon" / "Coming in this release" that steers to Private — never a dead button, never a fabricated success.
- **No silent remote fetches.** Privacy floor (P8/C9). A "not downloaded" image is the honest state, fetched only on explicit, confirmed user action.
- **Unknown stays "Unknown".** Never blank, never fabricated provenance.

---

*Synthesized from six native screen specs. Verified against `zcl-qt-wallet@feature/nft-gallery` (`nft.h`, `nftgallerydelegate.cpp`, `nftimagecache.cpp`, `dark.qss`, `mainwindow.cpp`) and the daemon's ZSLP + Sapling-memo reality. Hard rules upheld: never touch consensus/PoW/validation; ZSLP + data channel are non-consensus; no auto-fetch of remote images; don't-make-me-think throughout.*
