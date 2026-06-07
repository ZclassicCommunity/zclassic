# ZClassic NFT — Native UI Build Plan (Detail View + Mint Dialog)

Status: BUILD-READY SPEC (no source edited, no build run — a daemon build is in flight).
GUI repo: `/home/rhett/github/zcl-qt-wallet` @ branch `feature/nft-gallery`.
Grounding docs (this repo): `doc/nft/NATIVE_UX.md` (§3.2 detail, §3.3 mint, §2.2 honesty, §6.3 build order),
`doc/nft/CONTENT_MODEL.md` (ContentEngine API, media kinds, video-out verdict), `doc/nft/MINT_TRANSFER_SPEC.md`
(`zslp_genesis`/`zslp_mint` shape, CRecipient+CreateTransaction, "what becomes public").

This plan turns the two MISSING native surfaces into code-from-it detail: exact new files, classes, members,
signals/slots, every edited file with function + approx line, the per-media-kind render path, every state, the
exact microcopy, and the C++14 / threading / privacy / no-web constraints honored.

Hard, non-negotiable owner constraints (apply to BOTH surfaces):
- Native Qt widgets ONLY. NO QtWebEngine, NO QtMultimedia, NO embedded browser. (The static bundle ships
  neither; video is poster + "Open in your video player" via `QDesktopServices::openUrl`.)
- C++14 only (`zcl-qt-wallet.pro:41 CONFIG += c++14`). NO `std::optional` / `std::string_view`. Sentinels =
  empty `QString` + int verifyState (0/1/2), exactly as `nft.h:29` and `contentengine.h:64`/`79`.
- DRY: reuse `ContentEngine` (never add a second hash/verify path), the delegate's `tintedIcon` SVG pattern,
  the dark.qss token set, the `doRPC` error-aware connector. No new color tokens.
- Privacy floor (P8/C9): the dialogs touch ONLY local bytes. NO `documenturl` is ever auto-fetched on
  open/paint/hover. The only network touches are explicit, confirmed user clicks ("Get image", "View in
  explorer", the mint broadcast).
- Honesty (§2.2): the badge is ALWAYS "matches its on-chain fingerprint" (a bytes-match), NEVER
  "genuine/authentic/official/original". Unknown fields render the literal "Unknown" / "Not part of a set".
  Ownership is PENDING until ~10 confs (`DEFAULT_MAX_REORG_DEPTH = 10`).

---

## 1. Overview + shared pieces (DRY)

These already exist and BOTH dialogs reuse them — do not re-implement.

### 1.1 The POD and the engine (existing, unchanged)
- `src/nft.h` — `NFTItem { QString name, collection, txid, docHashHex, cachePath; qint64 receivedHeight; bool isPrivate; int verifyState; }`.
  Value-copied into the model and into the detail dialog. NOTE the POD does **not** carry creator, set
  position, received-DATE, or documenturl — those are async back-fill only (see §2.6).
- `src/contentengine.h` — the ONE streaming content engine. Reused, **not** modified by the detail view except
  for ONE small additive signal (see §2.2 "posterReady flag"). Key surface:
  - `void posterFor(path, hash, expectedHashHex, sizePx)` — decode+downscale+verify off-thread; delivers a
    QPixmap to the **model's** `onImageReady` on the GUI thread.
  - `void verify(path, expectedHashHex, token)` -> emits `verifyDone(quint64 token, int verifyState)` (GUI thread).
  - `void hashFile(path, token)` -> emits `descriptorReady(quint64 token, ContentDescriptor d)` (GUI thread).
  - statics: `classifyKind(path, mimeOut) -> ContentKind {CK_Image,CK_Video,CK_Document,CK_Bytes}`,
    `humanSize(bytes)`, `cacheGet(hashHex) -> localPath or ""`, `cachePut(hashHex, srcPath)`, `isRemoteUrl(path)`.
  - `struct ContentDescriptor { bool ok; QByteArray merkleRoot, sha256Whole; quint64 fileSize; quint32 chunkSize, chunkCount; QString mime, filename; QByteArray posterHash; bool isPrivate; }` (registered metatype, `contentengine.h:229`).

### 1.2 Shared visual vocabulary — lift from `nftgallerydelegate.cpp`
Both dialogs render the same three primitives the gallery card already paints. **Reuse the exact tokens and the
tinted-SVG helper concept** so the surfaces are visually identical:

- **Verify badge.** SVGs already bundled: `:/icons/res/icons/{check,x,question}.svg`. Tint per state:
  `1 -> #1f7a1f` (check), `2 -> #c0392b` (x), `0 -> #d9822b` (question). The delegate's `tintedIcon(resource,color,px)`
  (alpha-mask -> `CompositionMode_SourceIn` fill, `nftgallerydelegate.cpp:74`) is the canonical recipe — port the
  same 12-line body into each dialog as a private `tintedIcon()` helper (or a tiny shared free function in a new
  `src/nfticons.h` — OPTIONAL; the duplicated 12 lines are acceptable and keep zero new headers). The detail view
  uses a 20px badge; the gallery uses 16px; the mint poster uses a 40px kind glyph.
- **Privacy pill.** Green `#1f7a1f` "Private" / amber `#d9822b` "Public", filled at alpha 38 with a 1px border —
  exactly `nftgallerydelegate.cpp:179-200`. Detail view draws this as a styled `QFrame` (qss, not QPainter).
- **dark.qss token set (the ONLY palette, add no new color):** app `#0f1115`, card `#15171c`, inset `#1d2027`,
  hairline `#2a2d35`, text `#e6e6e6`, dim/AA-floor `#9aa0a6`, private-green `#1f7a1f`, public/pending-amber
  `#d9822b`, mismatch-red `#c0392b`, hover-border `#3d4450`.

### 1.3 The §2.6 action set (shared, reused from the gallery context menu spec)
Open · Send/Gift · Save image · Copy id · Copy image hash (fingerprint) · Copy collection · Re-check image ·
View in explorer (public-only, confirmed). The detail view exposes the full set; the mint dialog exposes none
of these (it is a creation flow, not an item surface).

### 1.4 Two NEW Settings getters (additive, both surfaces touch)
`Settings::getExplorerUrl()` and `Settings::isPrivateMintWired()`-style flags do NOT exist (`settings.cpp` only has
`getExplorerTxURL`/`getExplorerAddressURL`/`getMinerFee`/`getZCLDisplayFormat`). See §2.4 (detail) and §4 (mint)
for the exact additions. `isPrivateMintWired()` lives on **RPC** (it gates a daemon capability), `getExplorerUrl()`
lives on **Settings** (it gates a UI affordance).

---

## 2. Detail View — `NFTDetailDialog`

### 2.1 New files
- `src/nftdetaildialog.h`
- `src/nftdetaildialog.cpp`

Programmatic build (NO `.ui`, matching `setupNFTTab` and the §3.2 spec). Modeless-modal (`open()` not `exec()`),
so the poll loop + async RPC keep flowing and back-fill lands in the already-open dialog (perf contract C10).

### 2.2 Class `NFTDetailDialog : public QDialog`

```cpp
// nftdetaildialog.h  (C++14: includes for header-signature types live HERE)
#include <QDialog>
#include <QVector>
#include <QPointer>
#include <QString>
#include <QPixmap>
#include "nft.h"            // NFTItem (by value, header signature)
class ContentEngine;        // fwd — pointer member only
class RPC;                  // fwd — pointer member only
class QLabel; class QFrame; class QPushButton; class QToolButton;

class NFTDetailDialog : public QDialog {
    Q_OBJECT
public:
    explicit NFTDetailDialog(const NFTItem& item,
                             const QVector<NFTItem>& ordered, int startIndex,
                             ContentEngine* engine, RPC* rpc, QWidget* parent = nullptr);

protected:
    void keyPressEvent(QKeyEvent*) override;   // Left/Right step; Esc closes (default)
    void resizeEvent(QResizeEvent*) override;  // re-scale from m_sourcePixmap (C3)
    void closeEvent(QCloseEvent*) override;    // save QSettings("NFTDetail/geometry")

private slots:
    void onVerifyDone(quint64 token, int verifyState);     // ContentEngine::verifyDone
    void onPosterReady(quint64 token, QImage img, int verifyState); // NEW signal — see flag
    void stepPrev();
    void stepNext();
    void doCopyId();
    void doSaveImage();
    void doRecheck();
    void doOpenInPlayer();
    void doViewInExplorer();
    void doSendGift();

private:
    void buildUi();                 // construct the (reused) widget tree ONCE
    void loadItem(int newIndex);    // re-feed the SAME widgets from m_ordered[newIndex]
    void renderKind();              // switch the image stage by m_kind
    void applyVerifyState(int s);   // set m_verifyLine dyn-prop state= + repolish
    void backfillProvenance();      // async RPC: provenance + received date
    void setProvenanceRow(...);     // tiny helpers to repaint value cells

    // --- value state (POD-cheap copies) ---
    NFTItem               m_item;
    QVector<NFTItem>      m_ordered;     // value copy — NO model pointer
    int                   m_index = 0;
    QPointer<ContentEngine> m_engine;    // QPointer: late-callback safe on forced close
    QPointer<RPC>         m_rpc;
    quint64               m_verifyToken = 0;   // monotonic; drops stale neighbor replies
    quint64               m_provToken   = 0;   // monotonic; drops stale provenance replies
    QPixmap               m_sourcePixmap;      // full-res source; resize re-scales w/o re-decode (C3)
    QString               m_localBytesPath;    // cacheGet(docHashHex); "" = not on this device
    int                   m_kind = 0;          // ContentKind; default CK_Image
    QString               m_mime;
    // async back-fill (default = honest "Unknown" sentinels)
    QString               m_creator;           // "" -> "Unknown"
    QString               m_setLabel;          // "" -> "Not part of a set"
    QString               m_receivedDate;      // "" -> "block N (date pending)"
    int                   m_confirmations = -1;

    // --- widgets (raw, parented to the dialog) ---
    QLabel*     m_titleName       = nullptr;
    QLabel*     m_titleCollection = nullptr;
    QToolButton* m_closeBtn       = nullptr;
    QLabel*     m_imageStage      = nullptr;   // the big rendered asset
    QLabel*     m_badgeOverlay    = nullptr;   // 20px verify badge, floated top-right of stage
    QFrame*     m_verifyLine      = nullptr;   // dyn-prop state= drives the qss color swap
    QLabel*     m_verifyIcon      = nullptr;
    QLabel*     m_verifyText      = nullptr;
    QFrame*     m_privacyPill     = nullptr;
    QLabel*     m_privacyOneLiner = nullptr;
    QLabel*     m_valMintId  = nullptr;  QLabel* m_valReceived = nullptr;
    QLabel*     m_valCreator = nullptr;  QLabel* m_valSet      = nullptr;
    QLabel*     m_valImageHash = nullptr;
    QPushButton* m_btnSendGift  = nullptr;
    QPushButton* m_btnSaveImage = nullptr;
    QPushButton* m_btnCopyId    = nullptr;
    QToolButton* m_btnMore      = nullptr;     // QMenu: Copy image hash / Copy collection / View in explorer / Re-check
    QPushButton* m_btnGetImage  = nullptr;     // hidden in C1 (no documenturl on POD)
    QPushButton* m_btnOpenInPlayer = nullptr;  // video kind only
    QToolButton* m_prevBtn = nullptr;  QToolButton* m_nextBtn = nullptr;
};
```

The dialog holds the ordered list **by value** so prev/next walks neighbors with zero model coupling. `m_engine`
and `m_rpc` are `QPointer` for forced-close safety (both outlive the dialog as `MainWindow` members, but the
guard costs nothing).

**OPEN IMPLEMENTER FLAG (resolve before step 2.b of the build order) — poster delivery.**
`ContentEngine::posterFor()` today delivers ONLY to `NFTGalleryModel::onImageReady` (a model slot). To feed the
dialog's large image cleanly, do the **recommended, DRY** thing: add a per-call signal to ContentEngine

```cpp
// contentengine.h, next to verifyDone (line ~200), additive, no behavior change for the model path:
void posterReady(quint64 token, QImage img, int verifyState);
```

and emit it from `deliver()` (the existing GUI-thread landing, `contentengine.h:206`) **in addition to** the
model call, keyed by a token the caller passed. This is the cleanest symmetric sibling of `verifyDone`. (The
worker still produces a `QImage` only; the dialog builds nothing off-thread.) The QImage->QPixmap on the dialog
side happens on the GUI thread in `onPosterReady`. Do **NOT** give the dialog a throwaway `NFTGalleryModel`, and
do **NOT** read the on-disk poster cache by hand (racy). *(If a reviewer rejects touching ContentEngine for the
detail step, the only acceptable fallback is the on-disk poster-cache read after `posterFor` completes — but the
signal is preferred and is the planned approach. Either way the dialog gets NO model pointer.)*

### 2.3 Edited files (detail view)

| File | Where | Change |
|---|---|---|
| `src/mainwindow.h` | private slots near `setNFTItems` (~line 125) | declare `void openNFTDetail(const QModelIndex& index);` |
| `src/mainwindow.cpp` | end of `setupNFTTab()` (~line 3055, right after `view->setItemDelegate(...)`, before `outer->addWidget(view,1)` at 3057) | add `connect(view, &QListView::activated, this, &MainWindow::openNFTDetail);` — **activated only** (it fires on double-click AND Enter/Space per §3.1; do NOT also connect `doubleClicked` or it opens twice). Then add the `openNFTDetail` body (see §2.5). |
| `src/contentengine.h` | next to `verifyDone` (~line 200) | add `void posterReady(quint64 token, QImage img, int verifyState);` (additive signal — see the flag above) |
| `src/contentengine.cpp` | inside `deliver()` (the GUI-thread landing for poster workers) | also `emit posterReady(token, img, verifyState);` for callers that requested a per-call delivery (carry the token through the worker the same way `verify()` already carries one) |
| `src/rpc.h` | next to `refreshNFTs` (declared ~line 216, public sibling region) | add `void nftProvenance(QString tokenId, const std::function<void(QString creator, QString setLabel)>& cb);` and `void txReceivedDate(QString txid, const std::function<void(QString isoDate, int confirmations)>& cb);` |
| `src/rpc.cpp` | after `refreshNFTs` (~line 1000) | implement both (see §4.2). Both follow the `doRPC(payload, successCb, errorCb)` error-aware pattern (`connection.h:356`) and the graceful-fallback style of `refreshNFTs` — any error leaves the field at its honest default, never a dialog. |
| `src/settings.h` / `src/settings.cpp` | next to `getExplorerTxURL` (`settings.cpp:421`) | add `static QString getExplorerUrl();` returning the explorer **base** (`"https://explorer.zcl.zelcore.io/tx/"`, `""` on testnet) — distinct from the existing `getExplorerTxURL(txid)` which appends a txid. The detail view's "View in explorer" needs the bare base for the enable-gate and appends `m_item.txid` itself. |
| `res/styles/dark.qss` | append | `#nftDetailVerifyLine[state="verified"] { color:#1f7a1f; }` `[state="mismatch"]{color:#c0392b;}` `[state="pending"]{color:#d9822b;}`; `#nftDetailStage{ background:#1d2027; border-radius:8px; }`; `#nftDetailCard{ background:#15171c; border:1px solid #2a2d35; border-radius:12px; }`; pill selectors `#nftDetailPrivacyPill[priv="true"]`/`[priv="false"]`. ~20 lines; no token changes. |
| `zcl-qt-wallet.pro` | `SOURCES +=` after `src/contentengine.cpp` (line 51); `HEADERS +=` after `src/contentengine.h` (line 81) | add `src/nftdetaildialog.cpp` / `.h`. No new Qt module (core gui network svg widgets already linked; QtConcurrent NOT needed). |
| `tests/tests.pro` (L0) and/or `tests/widget/tst_widget.pro` (L1) | HEADERS/SOURCES | add `nftdetaildialog.h`/`.cpp` if a `tst_widget` open/prev-next/state case is written (recommended, see build order). |

### 2.4 Settings getter (exact)

```cpp
// settings.h, near line 134
static QString getExplorerUrl();                  // base, e.g. "https://explorer.zcl.zelcore.io/tx/"; "" on testnet
// settings.cpp, near line 421 (mirror getExplorerTxURL's testnet guard)
QString Settings::getExplorerUrl() {
    if (Settings::getInstance()->isTestnet()) return "";
    return "https://explorer.zcl.zelcore.io/tx/";
}
```

### 2.5 `MainWindow::openNFTDetail` body (the only gallery edit besides the connect)

```cpp
void MainWindow::openNFTDetail(const QModelIndex& index) {
    if (!index.isValid() || !nftModel) return;
    // Snapshot the ordered POD list (NO model pointer handed to the dialog).
    QVector<NFTItem> ordered;
    const int n = nftModel->rowCount();
    ordered.reserve(n);
    for (int r = 0; r < n; ++r)
        if (nftModel->isValidRow(r)) ordered.push_back(nftModel->itemAt(r)); // itemAt/isValidRow exist, model.h:54
    const int start = index.row();
    if (start < 0 || start >= ordered.size()) return;
    auto* dlg = new NFTDetailDialog(ordered.at(start), ordered, start,
                                    nftEngine /*see mint §3 — or reuse a ContentEngine*/, rpc, this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->open();   // NOT exec() — keep the poll loop + back-fill flowing (C10)
}
```

NOTE on the engine pointer: the detail view needs a **ContentEngine** (for `posterFor`/`verify`). The gallery
today wires `nftImgCache` (an `NFTImageCache`), `mainwindow.cpp:3053`. The mint surface (§3) adds an
`nftEngine = new ContentEngine(nftModel, this);` member — **share that one member with the detail view** (one
ContentEngine for the whole NFT subsystem). If the detail view ships before the mint surface, add the
`nftEngine` member in this step instead. Either way there is exactly ONE `ContentEngine` instance.
`NFTGalleryModel` already exposes `itemAt(int)` + `isValidRow(int)` (`nftgallerymodel.h:54`); no new accessor is
strictly required (an optional `const QVector<NFTItem>& items() const` is a nicety, not needed).

### 2.6 Wiring — DIALOG -> ContentEngine + RPC

`loadItem(i)` is the single re-feed entry (initial open AND every prev/next):

```cpp
void NFTDetailDialog::loadItem(int i) {
    m_index = i; m_item = m_ordered.at(i);
    // reset back-fill to honest defaults so a fast step never shows the neighbor's data
    m_creator.clear(); m_setLabel.clear(); m_receivedDate.clear(); m_confirmations = -1;
    // wallet-local POD fields paint INSTANTLY (no RPC on the paint path, C10)
    m_titleName->setText(m_item.name);
    m_titleCollection->setText(m_item.collection.isEmpty() ? tr("Not part of a set") : m_item.collection);
    m_valMintId->setText(shortId(m_item.txid));        // 8…8
    m_valImageHash->setText(shortId(m_item.docHashHex));
    applyPrivacy(m_item.isPrivate);
    // resolve local bytes (empty sentinel = not on this device) — PRIVACY: cacheGet only, never a URL
    m_localBytesPath = ContentEngine::cacheGet(m_item.docHashHex);
    m_kind = m_localBytesPath.isEmpty() ? CK_Image
                                        : ContentEngine::classifyKind(m_localBytesPath, m_mime);
    renderKind();
    // verify badge + poster — token-guarded so a stale neighbor reply is dropped
    if (m_engine && !m_localBytesPath.isEmpty()) {
        const quint64 t = ++m_verifyToken;
        m_engine->verify(m_localBytesPath, m_item.docHashHex, t);
        if (m_kind == CK_Image)
            m_engine->posterFor(m_localBytesPath, m_item.docHashHex, m_item.docHashHex, 512); // delivers posterReady
    } else {
        applyVerifyState(m_item.verifyState);  // POD's last-known state; pending/uncached states below
    }
    backfillProvenance();   // async RPC, bumped m_provToken
    m_prevBtn->setEnabled(i > 0);
    m_nextBtn->setEnabled(i + 1 < m_ordered.size());
}
```

- `connect(m_engine, &ContentEngine::verifyDone, this, &NFTDetailDialog::onVerifyDone)` and
  `connect(m_engine, &ContentEngine::posterReady, this, &NFTDetailDialog::onPosterReady)` are made ONCE in
  `buildUi()`. Both slots guard `if (token != m_verifyToken) return;` (drops a stale neighbor's reply after a
  fast prev/next).
- `onPosterReady` builds the QPixmap on the GUI thread, stores it as `m_sourcePixmap`, scales it into
  `m_imageStage` with `KeepAspectRatio + SmoothTransformation`, and calls `applyVerifyState(verifyState)` (the
  badge + line flip together).
- `backfillProvenance()`:

```cpp
void NFTDetailDialog::backfillProvenance() {
    if (!m_rpc) return;
    const quint64 tok = ++m_provToken;
    m_rpc->nftProvenance(m_item.txid, [tok,this](QString creator, QString setLabel){
        if (tok != m_provToken) return;                 // stale neighbor — drop
        m_creator  = creator;  m_setLabel = setLabel;
        m_valCreator->setText(creator.isEmpty() ? tr("Unknown") : creator);
        m_valSet->setText(setLabel.isEmpty() ? tr("Not part of a set") : setLabel);
    });
    m_rpc->txReceivedDate(m_item.txid, [tok,this](QString iso, int confs){
        if (tok != m_provToken) return;
        m_receivedDate = iso; m_confirmations = confs;
        if (confs >= 0 && confs < 10)                   // DEFAULT_MAX_REORG_DEPTH
            m_valReceived->setText(tr("Just arrived — confirming…"));
        else if (!iso.isEmpty())
            m_valReceived->setText(iso + tr("  ·  block %1").arg(m_item.receivedHeight));
        else
            m_valReceived->setText(tr("block %1 (date pending)").arg(m_item.receivedHeight));
    });
}
```

Both lambdas guard on the monotonic `m_provToken` bumped per `loadItem`, so a fast prev/next never paints the
previous item's provenance into the new one.

### 2.7 Prev / Next stepping

`m_prevBtn`/`m_nextBtn` + Left/Right in `keyPressEvent` + (optional) a `QShortcut` all call `stepPrev`/`stepNext`,
which bound-check and call `loadItem(i±1)`. `loadItem` re-feeds the **same** widgets (no new dialog, no model
pointer, no flicker — §3.2 "walks that list and re-feeds the same dialog with the neighbor's POD"). Disable
`m_prevBtn` at index 0 and `m_nextBtn` at `size-1`.

### 2.8 Media-by-kind — `renderKind()`

Kind from `ContentEngine::classifyKind(m_localBytesPath, m_mime)`. PRIVACY: every branch touches ONLY
`m_localBytesPath` (the cacheGet result) — NO documenturl, ever.

- **IMAGE (`CK_Image`):** request the large pixmap via `m_engine->posterFor(localPath, docHashHex, docHashHex, 512)`;
  paint the full QPixmap on `m_imageStage` with `KeepAspectRatio + SmoothTransformation`, letterboxed on
  `#1d2027`, never upscaled past 1024 native. Hold the source in `m_sourcePixmap` so resize re-scales without
  re-decode/re-hash (perf contract C3).
- **VIDEO (`CK_Video`):** NO in-app playback (QtMultimedia is out). Show a typed film-strip/poster placeholder
  (NEVER a faked frame) with an overlaid play glyph, a `Video · <MIME> · <NN.N MB>` caption (size via
  `ContentEngine::humanSize`), the verify badge, and a prominent primary `m_btnOpenInPlayer` ->
  `QDesktopServices::openUrl(QUrl::fromLocalFile(m_localBytesPath))` (mirrors `mainwindow.cpp:1847/2558`).
  ENABLED ONLY when `m_localBytesPath` is non-empty AND `verifyState == 1` — `openUrl` silently fails on a
  missing/remote path, so gate it (honest limit #1).
- **DOCUMENT (`CK_Document`):** large typed MIME icon (tinted via the delegate's `tintedIcon` pattern) +
  "Open" (`openUrl` of the file) + optional "Reveal in folder" (`openUrl` of the dir, `mainwindow.cpp:2558`).
  External only, never embedded.
- **BYTES (`CK_Bytes`):** typed glyph + a size/hex summary (`humanSize`) + "Save as…" (`QFileDialog`). Never
  auto-execute bytes.

All kinds also paint: name, collection, the mono copyable mint id (`txid`), the received height/date, the
verify badge, and the local/not-on-device state.

### 2.9 Actions

- **Send / Gift** (`m_btnSendGift`, the bright green primary): in C0/C1 a `QMessageBox`/toast
  "Sending NFTs is coming soon." (later opens the NFTSendDialog pre-filled). On a MISMATCH item (`verifyState==2`)
  it first confirms "This image failed its on-chain check. Send anyway?" `[Send anyway]/[Cancel]`.
- **Save image…** (`m_btnSaveImage`): `QFileDialog::getSaveFileName` default `<sanitized name>.png`; writes the
  cached bytes VERBATIM from `m_localBytesPath` (`QFile::copy`). DISABLED until `m_localBytesPath` is non-empty.
  Stays ENABLED in the MISMATCH state (the user may still want the bytes).
- **Copy id** (`m_btnCopyId`): `QApplication::clipboard()->setText(m_item.txid)`; flip label to "Copied ✓" for
  1.2 s via `QTimer::singleShot`, then revert.
- **More** (`m_btnMore`, `QToolButton` + `QMenu`): "Copy image hash" (full lowercase `m_item.docHashHex`),
  "Copy collection", "Re-check image" (re-issues `m_engine->verify(...)` with a bumped token), and "View in
  explorer" ENABLED ONLY if `!Settings::getExplorerUrl().isEmpty()` AND `m_item.isPrivate == false`; on trigger
  ask once "This opens an outside website and may reveal your interest. Continue?" then
  `QDesktopServices::openUrl(QUrl(Settings::getExplorerUrl() + m_item.txid))` (same primitive as
  `mainwindow.cpp:3266` / `sendtab.cpp:1580`).
- **Get image** (`m_btnGetImage`): hidden in C1 (no documenturl on the POD). When a documenturl is back-filled
  AND the item is public, show it as a single explicit, confirmed, hash-verify-before-display, one-shot fetch.

### 2.10 States (detail)

| State | Behavior |
|---|---|
| LOADING / decoding | `m_imageStage` shimmer; verify line amber "Checking this image…" + 20px "?" badge; Send/Gift + Copy id ENABLED (need only the id); Save + Open-in-player DISABLED. Provenance rows at honest defaults until RPC returns. |
| VERIFIED (1) | green "This image matches its on-chain fingerprint."; `m_verifyLine` `state="verified"`; 20px green check top-right; ALL actions enabled. Copy/tooltip note: a bytes-match ONLY, never "genuine/original". |
| MISMATCH (2) | red "This image does NOT match what was recorded on-chain. Don't trust it."; `state="mismatch"`; 20px red x + thin red inset hairline; image dimmed ~60%; Save stays ENABLED; Send/Gift confirms first. |
| PENDING / UNCACHED — private | amber "This image lives in your wallet's local cache." with NO fetch button (P8/C9). |
| PENDING / UNCACHED — public (documenturl known, back-filled) | amber "Image not on this device yet." + single explicit "Get image" (one-shot, hash-verify, never auto-runs). In C1 no documenturl on POD => no Get-image button. |
| PRIVATE | green "Private" pill + "Only you can see this. Its ownership is shielded."; explorer permanently disabled/absent. |
| PUBLIC | amber "Public" pill + "Anyone can verify this on the public ledger."; explorer enabled iff `getExplorerUrl()` set. |
| EMPTY METADATA | Creator => "Unknown"; Set => "Not part of a set"; unknown height => "block — (unknown)". Never blank/fabricated. |
| RECEIVED-PENDING (confs < 10) | Received row "Just arrived — confirming…"; ownership shown pending until 10 confs. >=10 => ISO date + "block 1,842,001". Until `gettransaction` returns => "block N (date pending)". |
| INDEX-OFF | wallet-local fields still render; calm note "Turn on the collectibles index to see full provenance." replaces the back-filled rows — no error dialog. |
| ERROR / not-an-image | amber "This file isn't an image we can show." + neutral broken-image glyph; never a crash. Video => film-strip + caption + "Open in your video player". Document => typed icon + "Open". Bytes => typed glyph + size + "Save as…". |
| RESIZE | re-scales from `m_sourcePixmap`, `KeepAspectRatio + SmoothTransformation`, never upscaled past 1024 native, letterboxed on `#1d2027` (no re-decode/re-hash, C3). |
| PREV/NEXT step | `loadItem()` re-feeds the same widgets; prev disabled at 0, next at last; stale neighbor verify/provenance dropped by the token guards. |

---

## 3. Mint Dialog — `NftMintDialog` ("Create NFT")

### 3.1 New files
- `src/nftmintdialog.h` — `class NftMintDialog : public QDialog` (Q_OBJECT), built programmatically (NO `.ui`,
  matching `setupNFTTab` `mainwindow.cpp:3017`; a `.ui` would force a `FORMS`+uic entry and a fragile generated
  layout for the dynamic preview/progress).
- `src/nftmintdialog.cpp` — ~520 lines. No new third-party deps. Includes `contentengine.h`, `rpc.h`,
  `settings.h`, and `QFileDialog`, `QDragEnterEvent`, `QDropEvent`, `QMimeData`, `QDesktopServices` (already
  app-wide, `sendtab.cpp:1580`), `QProgressBar`, `QStackedWidget`, `QRadioButton`, `QLineEdit`.

Single-window, vertically-stepped (a `QStackedWidget` with 3 pages: PICK -> DETAILS -> REVIEW), NOT a wizard,
so Back/Next never loses state. (NATIVE_UX §3.3 describes a single-scroll 4-card layout; this stepped form is the
implementation-chosen equivalent — both are native, both keep state, both honor the same copy/states. Pick ONE;
this plan ships the 3-page stack because it makes the async-hash-gates-Next contract trivial.)

### 3.2 Class `NftMintDialog : public QDialog`

```cpp
// nftmintdialog.h
#include <QDialog>
#include <QString>
#include "contentengine.h"   // ContentDescriptor by value (registered metatype), ContentKind
class RPC; class QStackedWidget; class QLabel; class QPushButton; class QLineEdit;
class QRadioButton; class QProgressBar;

class NftMintDialog : public QDialog {
    Q_OBJECT
public:
    explicit NftMintDialog(ContentEngine* engine, RPC* rpc, QWidget* parent = nullptr);
protected:
    void dragEnterEvent(QDragEnterEvent*) override;
    void dropEvent(QDropEvent*) override;
private slots:
    void onBrowse();
    void onFileChosen(const QString& path);
    void onDescriptorReady(quint64 token, ContentDescriptor d);
    void onPrivacyToggled();
    void goNext(); void goBack(); void onCreate();
    void onMintDone(bool ok, QString txidOrErr);
private:
    void buildPickPage(); void buildDetailsPage(); void buildReviewPage();
    void renderPoster(const QString& path);
    void refreshReview();
    void setBusy(bool b);
    bool privateMintAvailable() const;   // -> m_rpc->isPrivateMintWired() (hard-false today)

    QStackedWidget* stack = nullptr;
    // PAGE 0 PICK
    QLabel* dropZone = nullptr; QPushButton* btnBrowse = nullptr;
    // PAGE 1 DETAILS
    QLabel* posterLabel=nullptr; QLabel* kindLabel=nullptr; QLabel* fileMetaLabel=nullptr;
    QLineEdit* edtName=nullptr; QLineEdit* edtCollection=nullptr;
    QRadioButton* rdoPublic=nullptr; QRadioButton* rdoPrivate=nullptr;
    QLabel* privacyExplain=nullptr; QLineEdit* edtDocUrl=nullptr;
    QProgressBar* hashProgress=nullptr; QLabel* hashStatus=nullptr;
    // PAGE 2 REVIEW
    QLabel* reviewPoster=nullptr; QLabel* reviewSummary=nullptr; QLabel* feeLabel=nullptr;
    QLabel* publicityLabel=nullptr; QLabel* honestyLabel=nullptr; QLabel* mintError=nullptr;
    // FOOTER (persistent)
    QPushButton* btnBack=nullptr; QPushButton* btnNext=nullptr;
    QPushButton* btnCancel=nullptr; QPushButton* btnCreate=nullptr;
    // state
    QString m_srcPath; ContentDescriptor m_desc; int m_kind = CK_Bytes;
    bool m_descReady=false; quint64 m_token=0; bool m_creating=false;
    ContentEngine* m_engine=nullptr; RPC* m_rpc=nullptr;
    static quint64 kHashToken;   // monotonic seed for hash tokens
};
```

DRY: no per-page widget classes — pages are plain `QWidget*` built by `buildXxxPage()` helpers, matching how
`setupNFTTab` builds inline. `ContentDescriptor` is taken/stored by value (registered metatype,
`contentengine.h:229`). C++14: empty-QString sentinels, `ContentDescriptor.ok` / int-state sentinels.

### 3.3 Edited files (mint)

| File | Where | Change |
|---|---|---|
| `src/mainwindow.cpp` | `setupNFTTab()` (3017-3079) | (a) insert a toolbar HBox `nftToolbar` under `sub` (after line 3035): `stretch + QPushButton tr("Create NFT…")` objectName `nftCreateBtn`. (b) construct the shared engine: `nftEngine = new ContentEngine(nftModel, this);` alongside `nftImgCache` (3053). (c) `connect(btnCreateNFT, &QPushButton::clicked, this, &MainWindow::openMintDialog);` at the end of `setupNFTTab`. |
| `src/mainwindow.h` | NFT block (350-356) | `ContentEngine* nftEngine = nullptr;` (fwd-declare `class ContentEngine;` near line 22 next to `NFTGalleryModel`/`NFTImageCache`); private slot `void openMintDialog();`. Keep `#include "nft.h"` (line 6). |
| `src/rpc.h` | next to `sendZTransaction` (line 65) | a POD `struct MintOpts { QString name; QString collection; QString documentUrl; bool isPrivate=false; };` + `void mintNFT(const ContentDescriptor& descriptor, const MintOpts& opts, const std::function<void(bool ok, QString txidOrError)>& cb);` + `bool isPrivateMintWired() const;`. (Forward-declare `struct ContentDescriptor;` or include `contentengine.h`; take `descriptor` by const ref with the include in rpc.cpp.) |
| `src/rpc.cpp` | after `sendZTransaction` (~533) | implement `mintNFT` (see §4.1) + `isPrivateMintWired()` returning a hard `false` (until the ZDC1 private channel exists). |
| `zcl-qt-wallet.pro` | `SOURCES +=` after `src/nftdetaildialog.cpp`; `HEADERS +=` after `src/nftdetaildialog.h` | add `src/nftmintdialog.cpp`/`.h`. No `FORMS` entry (programmatic). QtSvg present (pro line 14) for the kind glyphs; widgets present (line 20). |
| `res/styles/dark.qss` | append | `#dropZone` (1px DASHED `#3d4450` border, inset `#1d2027` bg, generous radius/pad, hover border `#3d4450`/solid `#1f7a1f` on drag); `#nftCreateBtn` (accent: bg `#1f7a1f`, hover `#2a9d2a` — mirror the `QPushButton:default` rule at `dark.qss:93-96`); `#mintPrivacyExplain`/`#mintHonesty` (color `#9aa0a6`, the AA floor); `#mintFee` (color `#e6e6e6`, bold). ~25 lines; no token changes. |

### 3.4 Entry point + wiring (mint)

```cpp
void MainWindow::openMintDialog() {
    if (!nftEngine || !rpc) return;
    NftMintDialog dlg(nftEngine, rpc, this);          // modal, stack-allocated (sendtab.cpp:1039 pattern)
    if (dlg.exec() == QDialog::Accepted)
        rpc->refreshNFTs();                           // instant feedback (it also polls)
}
```

**FILE PICK -> HASH.** `onBrowse()` -> `QFileDialog::getOpenFileName(this, tr("Choose a file to turn into an NFT"),
lastDir, tr("All files (*)"))`. `dropEvent` reads `event->mimeData()->urls().first().toLocalFile()`. Both funnel to
`onFileChosen(path)`:
- **GUARD** with `ContentEngine::isRemoteUrl(path)` (`contentengine.h:190`) — reject any http(s) drop with an
  inline red label (privacy hard rule), stay on PICK.
- `m_srcPath = path; m_kind = ContentEngine::classifyKind(path, mime)` to pick the poster glyph; `renderPoster(path)`
  via `m_engine->posterFor(path, key, "", 160)` for images OR a typed glyph for video/document/bytes; prefill
  `edtName` with `QFileInfo(path).completeBaseName()`; advance to DETAILS; start hashing:
  `m_descReady=false; m_token = ++kHashToken; m_engine->hashFile(path, m_token)` (`contentengine.h:106` — STREAMING,
  bounded RAM, never freezes the UI even for a 2 GB video). Show `hashProgress` indeterminate +
  `hashStatus = tr("Reading your file… %1").arg(humanSize)`. Disable `btnNext` until the descriptor is ready.

**ASYNC LANDING.** `connect(m_engine, &ContentEngine::descriptorReady, this, &NftMintDialog::onDescriptorReady)` in
the ctor. `onDescriptorReady(token, d)`:
```cpp
if (token != m_token) return;                          // a faster re-drop superseded it
if (!d.ok) { hashStatus->setText(tr("That file couldn't be read. Try another.")); /* keep Next disabled */ }
else {
    m_desc = d; m_descReady = true; hashProgress->hide();
    hashStatus->setText(tr("Fingerprint ready."));
    fileMetaLabel->setText(d.filename + "  •  " + ContentEngine::humanSize(d.fileSize));
    btnNext->setEnabled(true);
}
```
The descriptor carries `merkleRoot + sha256Whole + fileSize + mime + filename` (`contentengine.h:64`); the
on-chain anchor is the merkle root (large files) / sha256 (small), shown as the fingerprint in REVIEW.

**PRIVACY TOGGLE.** `rdoPublic`/`rdoPrivate` exclusive. `onPrivacyToggled()`:
- PUBLIC -> `privacyExplain = tr("Public: anyone can look up this NFT's name and fingerprint on-chain. You may also add an optional link to where the file lives.")`; show `edtDocUrl`.
- PRIVATE -> `privacyExplain = tr("Private: only people you share it with can see it. The provenance is shielded.")`; hide `edtDocUrl`.
- **CRITICAL GATE:** `if (!privateMintAvailable()) { rdoPrivate->setEnabled(false); /* append dim tr("Coming in this release") */ rdoPublic->setChecked(true); }`. `privateMintAvailable() -> m_rpc->isPrivateMintWired()` which is hard-false until the ZDC1 channel RPC lands. This yields a clearly-disabled RADIO, NOT a dead Create button.

**REVIEW (`refreshReview`, on entering page 2).**
```cpp
feeLabel->setText(tr("Network fee: %1").arg(Settings::getZCLDisplayFormat(Settings::getMinerFee()))); // 0.0001 ZCL
// what becomes public (honest):
if (rdoPublic->isChecked())
  publicityLabel->setText(tr("What goes on-chain (public): the file's fingerprint, the name \"%1\"%2.")
      .arg(edtName->text().trimmed())
      .arg(edtDocUrl->text().trimmed().isEmpty() ? QString()
           : tr(", and your link %1").arg(edtDocUrl->text().trimmed())));
else
  publicityLabel->setText(tr("What goes on-chain: only an encrypted record. The name and fingerprint are shielded."));
honestyLabel->setText(tr("Minting does NOT upload your file anywhere. Only its fingerprint goes on-chain — the file stays on your computer."));
// reviewSummary lists name/collection/kind/size
```

**CREATE.** `onCreate()`:
```cpp
setBusy(true);                                         // disable footer; btnCreate text -> tr("Creating…")
MintOpts opts{ edtName->text().trimmed(), edtCollection->text().trimmed(),
               rdoPublic->isChecked() ? edtDocUrl->text().trimmed() : QString(),
               rdoPrivate->isChecked() };
m_rpc->mintNFT(m_desc, opts, [this](bool ok, QString r){ onMintDone(ok, r); });
```
`onMintDone(ok, txid)`: if ok -> `ContentEngine::cachePut(fingerprintHex, m_srcPath)` (store local bytes
content-addressed so the new card verifies green immediately) -> `accept()`. else -> `setBusy(false)` + show the
inline `mintError` label with the daemon message.

**POST-SUCCESS in MainWindow.** `openMintDialog`'s `exec()==Accepted` -> `rpc->refreshNFTs()` (`rpc.cpp:863`)
re-polls `zslp_listmytokens`; `setNFTItems` (`mainwindow.cpp:3103`) feeds the new card. Because `cachePut` stored
the bytes, a follow-up could populate `cachePath` for instant verify (a one-line future hook in `refreshNFTs`:
`cacheGet(documenthash)` per item — noted, not required for v1).

### 3.5 Media-by-kind (mint poster — DETAILS + REVIEW, never a player)

`ContentEngine::classifyKind(path, mime)` (`contentengine.h:165`) -> `CK_Image/CK_Video/CK_Document/CK_Bytes`.
- IMAGE: `m_engine->posterFor(path, key, "", 160)` -> decoded+downscaled QImage on the GUI thread -> `posterLabel`.
- VIDEO: typed film/play SVG glyph tinted via the SAME `tintedIcon` mask the delegate uses
  (`nftgallerydelegate.cpp:74`) + caption `Video • <size>`. NO in-app playback (no-faked-frame rule).
- DOCUMENT / BYTES: a typed document/file glyph + caption.
- PROGRESS for large files: `hashFile` streams 1 MiB blocks (`kHashBufBytes`, `contentengine.h:193`) on a
  bounded-pool thread and signals ONCE at the end — so there is no per-byte callback. The dialog shows an
  INDETERMINATE `QProgressBar` (`setRange(0,0)`) plus the file size in `hashStatus`, honestly communicating
  "working" without faking a percentage. (A determinate bar would need a new progress signal on ContentEngine —
  out of scope for v1; indeterminate is correct and non-blocking.) The worker NEVER touches a QPixmap
  (`contentengine.h:16`) — `posterLabel`'s pixmap is built on the GUI thread by `posterFor`'s deliver path.

### 3.6 States (mint)

| State | Behavior |
|---|---|
| EMPTY / PICK (page 0) | drop zone + Browse. btnNext hidden/disabled; only Cancel active. |
| REMOTE-URL REJECTED (page 0, transient) | dropped http(s) URL -> inline red `#c0392b` "For your privacy, drop a local file — not a web link."; stay on page 0. |
| HASHING (page 1, descriptor pending) | poster + filename shown; `hashProgress` indeterminate; `hashStatus` "Reading your file…"; btnNext DISABLED. Streaming `hashFile` keeps the UI responsive for multi-GB files. |
| READY (page 1, d.ok) | `hashProgress` hidden; `hashStatus` "Fingerprint ready."; kind+poster+size; name/collection editable; privacy radios live; btnNext ENABLED. |
| UNREADABLE (page 1, d.ok==false) | `hashStatus` "That file couldn't be read. Try another."; btnNext stays DISABLED. |
| PUBLIC selected | `edtDocUrl` visible+optional; public explain. |
| PRIVATE selected (when wired) | `edtDocUrl` hidden; private explain. |
| PRIVATE COMING-SOON (RPC not wired — the DEFAULT today) | `rdoPrivate` DISABLED with adjacent dim "Coming in this release"; `rdoPublic` forced-on. Create is NEVER dead — it stays enabled for Public. |
| REVIEW (page 2) | fee + "what becomes public" + honesty line + summary; btnBack + btnCreate (accent green) + Cancel. |
| CREATING (page 2 busy) | footer disabled; btnCreate text "Creating…"; no spinner widget (text change + disabled state). |
| MINT ERROR | inline red label under the summary with the daemon message; footer re-enabled to retry or cancel. |
| SUCCESS | `accept()`; gallery refreshes; the new card appears verified-green (cachePut stored the bytes). |

---

## 4. Shared RPC additions

### 4.1 `RPC::mintNFT` + `isPrivateMintWired` (mint dialog) — `rpc.cpp` after `sendZTransaction` (~533)

Per MINT_TRANSFER_SPEC: the GUI calls the daemon `zslp_genesis`/`zslp_mint` thin-shell RPC (which builds the
OP_RETURN tx natively via `CRecipient{scriptPubKey,nAmount,fSubtractFeeFromAmount}` -> `CWallet::CreateTransaction`
-> `CommitTransaction`, with the §2.6 vout-ordering safety so the NFT is never burned). The GUI side mirrors
`sendZTransaction` (`rpc.cpp:516-532`):

```cpp
bool RPC::isPrivateMintWired() const { return false; }   // hard-false until the ZDC1 private channel RPC exists

void RPC::mintNFT(const ContentDescriptor& d, const MintOpts& opts,
                  const std::function<void(bool, QString)>& cb) {
    if (conn == nullptr) { QTimer::singleShot(0, [cb]{ cb(false, tr("Not connected.")); }); return; }
    if (opts.isPrivate && !isPrivateMintWired()) {       // belt-and-suspenders; the dialog gates this first
        QTimer::singleShot(0, [cb]{ cb(false, tr("Private minting is coming in this release.")); });
        return;
    }
    // anchor: merkle root for large files, whole-file sha256 for small (engine accepts either on verify).
    const QByteArray anchor = !d.merkleRoot.isEmpty() ? d.merkleRoot : d.sha256Whole;
    json params = {
        { "ticker",        opts.collection.toStdString() },   // collection groups a card-set (ticker)
        { "name",          opts.name.toStdString() },
        { "document_hash", anchor.toHex().constData() },       // 64-hex / 32B, round-trips gettoken.documenthash
        { "document_url",  opts.documentUrl.toStdString() },   // "" for private / no link
        { "decimals",      0 },                                // NFT: forced 0
        { "quantity",      1 }                                 // NFT: forced 1
    };
    json payload = {
        { "jsonrpc", "1.0" }, { "id", "someid" },
        { "method", "zslp_genesis" },                          // per MINT_TRANSFER_SPEC §; (zslp_mint is fungible re-issue)
        { "params", { params } }
    };
    conn->doRPC(payload,
        [cb](const json& reply){ cb(true, QString::fromStdString(reply.is_string()
                                          ? reply.get<std::string>() : reply.dump())); },
        [cb](QNetworkReply* rep, const json& parsed){
            QString msg = (!parsed.is_discarded() && parsed.is_object()
                           && parsed.contains("error") && parsed["error"].is_object()
                           && !parsed["error"]["message"].is_null())
                          ? QString::fromStdString(parsed["error"]["message"])
                          : rep->errorString();
            cb(false, msg);
        });
}
```

NOTE the method name: per MINT_TRANSFER_SPEC the **NFT genesis** call is `zslp_genesis` (with `decimals=0,
quantity=1` forced by the GUI "Create NFT" flow, §3 line 203); `zslp_mint tokenid amount` is fungible
re-issue. The original mint-spec brief referenced `zslp_mint` generically — implement against `zslp_genesis` for
NFT creation. As of today **neither exists in the daemon** (`grep` finds zero refs to `RPC::mintNFT`/`zslp_mint`
in the GUI; the daemon shells are step 5/6 of NATIVE_UX §6.3). So `mintNFT` is spec'd against a NOT-YET-WIRED
daemon RPC; the GUI degrades cleanly: PRIVATE is gated off by `isPrivateMintWired()==false` (a disabled radio),
and a PUBLIC call against a daemon without `zslp_genesis` returns the daemon's error verbatim into the inline
`mintError` label — never a crash, never a fabricated success.

### 4.2 `RPC::nftProvenance` + `RPC::txReceivedDate` (detail view back-fill) — `rpc.cpp` after `refreshNFTs` (~1000)

Both follow the error-aware `doRPC` pattern and the graceful-fallback style of `refreshNFTs` — any error leaves
the field at its honest default ("Unknown" / "block N (date pending)"), never a dialog.

```cpp
void RPC::nftProvenance(QString tokenId, const std::function<void(QString,QString)>& cb) {
    if (conn == nullptr) { cb(QString(), QString()); return; }   // honest defaults
    json payload = { {"jsonrpc","1.0"}, {"id","someid"},
                     {"method","zslp_gettoken"}, {"params",{ tokenId.toStdString() }} };
    conn->doRPC(payload,
        [cb](const json& tok){
            // creator stays "Unknown" (the chain records no issuer); setLabel from ticker/group when known.
            QString setLabel = (tok.is_object() && tok.contains("ticker") && tok["ticker"].is_string())
                               ? QString::fromStdString(tok["ticker"]) : QString();
            cb(QString(), setLabel);
        },
        [cb](QNetworkReply*, const json&){ cb(QString(), QString()); });  // index-off / error -> defaults
}

void RPC::txReceivedDate(QString txid, const std::function<void(QString,int)>& cb) {
    if (conn == nullptr) { cb(QString(), -1); return; }
    json payload = { {"jsonrpc","1.0"}, {"id","someid"},
                     {"method","gettransaction"}, {"params",{ txid.toStdString() }} };
    conn->doRPC(payload,
        [cb](const json& r){
            int confs = (r.is_object() && r.contains("confirmations") && r["confirmations"].is_number())
                        ? r["confirmations"].get<int>() : -1;
            QString iso;
            if (r.is_object() && r.contains("blocktime") && r["blocktime"].is_number())
                iso = QDateTime::fromSecsSinceEpoch(r["blocktime"].get<qint64>(), Qt::UTC)
                          .toString(Qt::ISODate);     // drives the confs<10 "Just arrived — confirming…" rule
            cb(iso, confs);
        },
        [cb](QNetworkReply*, const json&){ cb(QString(), -1); });   // -> "block N (date pending)"
}
```

`RPC::mintNFT` belongs to the mint dialog; `nftProvenance`/`txReceivedDate` belong to the detail view. All three
are additive; none touch the consensus/money path.

---

## 5. The honest copy set (verbatim, both surfaces)

**Verify line (shared, identical wherever it appears):**
- verified: "This image matches its on-chain fingerprint."
- mismatch: "This image does NOT match what was recorded on-chain. Don't trust it."
- pending: "Checking this image…"

**Pending / privacy:**
- pending private: "This image lives in your wallet's local cache."
- pending public: "Image not on this device yet."
- private one-liner: "Only you can see this. Its ownership is shielded."
- public one-liner: "Anyone can verify this on the public ledger."

**Detail rows + honest defaults:**
- labels: "Mint id" · "Received" · "Creator" · "Set" · "Image hash"
- defaults: "Unknown" · "Not part of a set" · "block — (unknown)" · "Just arrived — confirming…" · "block N (date pending)"
- footnote: "This name and image aren't unique — anyone can mint another collectible that reuses them. Only the mint id is one of a kind."
- title collection fallback: "Not part of a set"

**Detail actions + feedback:**
- "Send / Gift" · "Save image…" · "Copy id" · "More" · "Copy image hash" · "Copy collection" · "View in explorer" · "Re-check image" · "Get image" · "Open in your video player"
- "Copied ✓" (1.2 s, then revert)
- send-from-mismatch confirm: "This image failed its on-chain check. Send anyway?" `[Send anyway] / [Cancel]`
- send coming-soon (C0/C1): "Sending NFTs is coming soon."
- explorer confirm: "This opens an outside website and may reveal your interest. Continue?"
- index-off note: "Turn on the collectibles index to see full provenance."
- error not-image: "This file isn't an image we can show."
- video caption: "Video · <MIME> · <NN.N MB>" (size via `ContentEngine::humanSize`)

**Mint copy:**
- title "Create an NFT" · toolbar button "Create NFT…"
- drop zone "Drag a file here, or" + "Choose a file…" · hint "Any image, video, document, or file."
- remote reject "For your privacy, drop a local file — not a web link."
- "Reading your file…" (with size) · "Fingerprint ready." · "That file couldn't be read. Try another."
- name "Name" / placeholder "e.g. Aurora #014" · collection "Collection" / placeholder "e.g. Zcl Originals"
- public radio "Public" — "Public: anyone can look up this NFT's name and fingerprint on-chain. You may also add an optional link to where the file lives."
- private radio "Private" — "Private: only people you share it with can see it. The provenance is shielded."
- private coming-soon tag "Coming in this release"
- url "Link to the file (optional)" / placeholder "https://…"
- review fee "Network fee: 0.0001 ZCL"
- what's public (public): "What goes on-chain (public): the file's fingerprint, the name \"<name>\"[, and your link <url>]."
- what's public (private): "What goes on-chain: only an encrypted record. The name and fingerprint are shielded."
- honesty (always): "Minting does NOT upload your file anywhere. Only its fingerprint goes on-chain — the file stays on your computer."
- buttons "Back" · "Next" · "Cancel" · "Create NFT" (creating: "Creating…")
- error prefix "Couldn't create the NFT: <daemon message>"

**BANNED from every visible string (P1 / §2.2):** SHA-256, "hash" as a noun (use "fingerprint"), OP_RETURN,
GENESIS, token, mint-baton, zslpindex, t-addr/z-addr, ivk, memo; and NEVER "Genuine"/"Authentic"/"Official"/
"Original" on the badge — only "matches its on-chain fingerprint".

---

## 6. C++14 + threading + privacy + no-web constraints (honored)

- **C++14 ONLY** (`.pro:41`). NO `std::optional`/`std::string_view`. Sentinels: empty `QString`
  (`cacheGet` returns "" for absent; `m_creator==""` => "Unknown"), `ContentDescriptor.ok`, int verifyState
  (0/1/2). MintOpts/ContentDescriptor are POD aggregates (in-class initializers only). Put includes for any
  header-signature type IN the `.h` (detail: `#include "nft.h"`, `<QDialog>`, `<QVector>`, `<QPointer>`,
  `<QPixmap>`; mint: `#include "contentengine.h"`, `<QDialog>`).
- **THREADING (CONTENT_MODEL §4.2, load-bearing):** all hashing/verify/poster-decode runs on ContentEngine's
  bounded `QThreadPool` worker, which touches ONLY `QByteArray/QCryptographicHash/QImageReader/QImage` — NEVER a
  QPixmap. The QPixmap is built on the GUI thread in the dialog's slot. The dialogs NEVER read/hash files
  themselves — they only call `posterFor`/`verify`/`hashFile`/`cacheGet`/`classifyKind` and consume the
  GUI-thread signals (`posterReady`/`verifyDone`/`descriptorReady`). Async replies are token-guarded
  (`m_verifyToken`/`m_provToken` in detail; `m_token` in mint, bumped per `loadItem`/`onFileChosen`) so a fast
  prev/next or re-drop never paints a stale neighbor's pixmap/verdict/provenance.
- **RPC OFF the paint path (C10):** provenance + mint go through the `doRPC` connector; the detail view renders
  INSTANTLY from the value-copied POD and back-fills when replies land — `open()` not `exec()` keeps the poll
  loop flowing. The mint dialog uses `exec()` (it is a self-contained modal create flow with its own async hash;
  no poll-loop dependency).
- **PRIVACY (P8/C9):** `ContentEngine::isRemoteUrl` REJECTS http(s) on every dropped/typed source; the dialogs
  never point the engine at a documenturl; the only network touches are the explicit, confirmed "Get image" /
  "View in explorer" / mint broadcast. The optional documenturl is stored on-chain ONLY for PUBLIC mints and is
  shown verbatim in REVIEW so the user sees exactly what becomes public; file bytes are NEVER uploaded
  (`cachePut` copies them only into the LOCAL content-addressed blob store).
- **NO QtWebEngine / NO QtMultimedia / NO browser** anywhere (static bundle ships neither). Video => poster +
  `QDesktopServices::openUrl` gated on local verified bytes.
- **DRY:** reuse ContentEngine (no parallel hash/verify path), the delegate's `tintedIcon` for glyphs/badges
  (`:/icons/res/icons/{check,x,question}.svg` already bundled), the dark.qss token set (add no new color), the
  `sendtab.cpp:1039` modal pattern (mint) and the `mainwindow.cpp:3266`/`sendtab.cpp:1580` `openUrl` primitive
  (explorer/player), `Settings::getMinerFee()`/`getZCLDisplayFormat` for the fee. ADD only the two new getters:
  `Settings::getExplorerUrl()` and `RPC::isPrivateMintWired()` (neither exists).

---

## 7. BUILD ORDER (each step shippable; verify via proot + L0/L1)

Builder: `cd /home/rhett/zclbuild && ./prun bash /build/build.sh` (incremental; `--clean` for a daemon rebuild).
Tests: `cd /home/rhett/zclbuild && ./prun bash /build/wallet/tests/... ` via `run-l0-l1.sh` —
`./prun bash /build/../run-l0-l1.sh` builds + runs L0 (`tst_logic`, guiless) and L1 (`tst_widget`, offscreen).
The host repo is bound into the proot at `/src/wallet`. NEVER edit during the in-flight daemon build; queue these
edits after it lands. Each step is GUI-only and off the money path.

1. **Settings + RPC scaffolding (no UI yet).**
   - Add `Settings::getExplorerUrl()` (settings.h/.cpp).
   - Add `RPC::isPrivateMintWired()` (returns false), the `MintOpts` POD, and the THREE new RPC declarations
     (`mintNFT`, `nftProvenance`, `txReceivedDate`) + implementations (rpc.h/.cpp).
   - Add the additive `ContentEngine::posterReady` signal + the `deliver()` emit (contentengine.h/.cpp).
   - **Verify:** `./prun bash /build/build.sh` compiles clean; `run-l0-l1.sh` L0 still 104 / L1 34 (no behavior
     change, only additive symbols). This is the riskiest-to-link step done first so the surfaces build against
     stable symbols.

2. **Detail view (NATIVE_UX §6.3 step 2).**
   - Create `src/nftdetaildialog.{h,cpp}`; register in `zcl-qt-wallet.pro` (SOURCES/HEADERS).
   - Wire `MainWindow::openNFTDetail` + the single `connect(view,&QListView::activated,...)` in `setupNFTTab`
     (also add the shared `nftEngine` ContentEngine member here if mint hasn't landed).
   - Append the detail dark.qss selectors.
   - **Verify:** build clean. L1 widget test (add a `tst_widget` case): construct the dialog from a fixture
     `QVector<NFTItem>`, assert (a) opens without a model pointer, (b) prev/next bound-checks + disables at ends,
     (c) `applyVerifyState(1/2/0)` sets the correct dyn-prop + copy, (d) a stale `onVerifyDone(oldToken,…)` is
     dropped. Offscreen: `QT_QPA_PLATFORM=offscreen`. Manual smoke under `uxmatrix.sh` (real-xcb) is optional but
     confirms double-click/Enter opens exactly once.

3. **Mint dialog (NATIVE_UX §6.3 step 5, GUI half).**
   - Create `src/nftmintdialog.{h,cpp}`; register in `.pro`.
   - Add the toolbar "Create NFT…" button + `nftEngine` (if not added in step 2) + `openMintDialog` in
     `setupNFTTab`.
   - Append the mint dark.qss selectors (`#dropZone`, `#nftCreateBtn`, `#mintPrivacyExplain`, `#mintHonesty`,
     `#mintFee`).
   - **Verify:** build clean. L1 case: drop/pick a fixture file -> `descriptorReady` (token-guarded) enables
     Next; remote-URL drop is rejected and stays on PICK; PRIVATE radio is disabled while
     `isPrivateMintWired()==false` and `rdoPublic` is forced-on; REVIEW shows fee + the honest "what becomes
     public" + the does-not-upload line; `onCreate` against an unwired daemon surfaces the error inline (no
     crash, no fabricated success). L0 can unit-test any pure helper extracted (e.g. the fingerprint-short
     formatter) if added.

4. **Full-suite gate + bundle.**
   - `run-l0-l1.sh`: L0 (`tst_logic`) and L1 (`tst_widget`) both green at the expected counts (104 / 34 +
     any new cases).
   - `./prun bash /build/build.sh` end-to-end green with the DELIVERY GATE (host sha == chroot-built sha) so no
     stale binary ships.
   - Manual `uxmatrix.sh` xcb smoke of the Collections tab: open detail, step prev/next, open mint, drop a file,
     toggle privacy, hit Create against the (unwired) daemon and confirm the calm inline error.

Each step compiles and is independently shippable; the detail view (step 2) is the smallest usable unit and can
ship before mint. Public minting itself stays gated until the daemon `zslp_genesis` shell lands (NATIVE_UX §6.3
step 6) — the GUI is ready and degrades honestly until then.
