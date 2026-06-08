# ZClassic NFT — Content Model (any file / image / video → NFT)

> **REMOVED — shielded data channel / on-chain private files.** The "private bytes over ZDC1
> Sapling memos" path referenced below (the `zdc1://` scheme, the ZDC1 data channel) has been
> **removed entirely** from the daemon. ZClassic deliberately provides **no wallet path to store
> arbitrary files on-chain** — public *or* private. All NFT content stays off-chain; the chain
> holds only the 32-byte `document_hash` fingerprint. Treat every ZDC1 / private-bytes mention
> below as **historical**.

**Status:** design, single source of truth. THIS workflow ships the GUI content engine
(Section 4 + 6B); the daemon mint RPC (Section 6A) is designed-now / implemented-later.

**Hard invariants (do not violate):**
- **No consensus change.** The ZSLP genesis OP_RETURN format and `slp_parse` /
  `slp_build_genesis` stay byte-identical. An NFT is just a standard tx whose `vout[0]`
  is an OP_RETURN + transparent dust — already-valid script semantics.
- **Privacy.** Never auto-fetch a remote `documenturl` on the paint/poll/hover path
  (IP + interest leak). Bytes come from local cache or an **explicit** user action only.
  This mirrors the existing `refreshNFTs` guard that forces `cachePath=""`
  (`zcl-qt-wallet/src/rpc.cpp:835,960`).
- **No browser, no QtWebEngine, ever.** No QtMultimedia (it is `-skip`'d from the static
  Qt build — see Section 7).
- **C++14 only.** No `std::optional` / `std::string_view`; use empty-`QString` sentinels
  and an `int verifyState`. Put includes for any header-signature type in the header.
- **DRY.** ONE content engine, not parallel copies. `nftimagecache` becomes the seed.
- **Honest about limits.** No anti-copy. No in-app video playback in v1. Don't promise it.

---

## 1. The model in one page

A file can be ANY size; a blockchain cannot hold ANY size (every node stores every byte
forever, and the OP_RETURN relay cap is **223 bytes total** —
`zclassic/src/script/standard.h:34`). So the ONLY honest way to make a 2 GB video — or any
file — an NFT without a consensus change is **content-addressing**:

```
   ON-CHAIN (tiny, permanent)            OFF-CHAIN (the bytes, free to live anywhere)
   ┌───────────────────────────┐        ┌──────────────────────────────────────────┐
   │ ZSLP GENESIS OP_RETURN     │        │ local disk · creator URL · ipfs://CID ·   │
   │  • document_hash (32B)  ───┼──┐     │ ZDC1 Sapling-memo chain (small private)   │
   │    = FINGERPRINT           │  │      └──────────────────────────────────────────┘
   │  • document_url (≤~153B)   │  │                       │
   │    = structured pointer    │  │  wallet HASHES the bytes (streaming) and
   │  • ticker / name / qty=1   │  │  COMPARES to the on-chain fingerprint:
   └───────────────────────────┘  └──►  match  → green "genuine" badge (verifyState 1)
                                        differ → red  "tampered" badge (verifyState 2)
```

- **The chain proves the FINGERPRINT, never the pixels.** Copying a file is always
  possible; passing a copy off as THE NFT is not — verify fails, and you don't hold the
  ZSLP UTXO that carries ownership.
- **Security** = the wallet recomputes SHA-256 (small files) or a chunked Merkle root
  (large files) over the bytes and compares to the on-chain anchor. **Uniqueness /
  ownership** come from the already-hardened UTXO-bound ZSLP conservation layer
  (unchanged; carries the verified forgery fix in the daemon working tree).
- **PUBLIC NFT:** descriptor + fingerprint on-chain; bytes off-chain; anyone verifies.
- **PRIVATE NFT:** asset bytes encrypted; ownership shielded. Small content rides the
  shielded **ZDC1** Sapling-memo data channel (designed separately). Large private video:
  encrypted bytes off-chain/peer + the on-chain fingerprint anchor (over **ciphertext**)
  + a key reveal on transfer. Integrity is verified BEFORE any decrypt is attempted.

**Efficiency is mandatory:** streaming hash (never `readAll` a whole file — a 2 GB video
must hash in ~1 MiB of RAM), all hashing OFF the GUI thread on a bounded pool, a chunked
Merkle root that enables incremental / streamed verification, and an on-disk
content-addressed cache (store once, reuse).

---

## 2. The content descriptor + on-chain encoding

### 2.1 On-chain (Tier 1) — reuse the existing genesis fields, byte-for-byte

The genesis struct (`zclassic/src/zslp/slp.h:43-52`) gives us exactly:
`ticker[64]`, `name[128]`, `document_url[256]`, `document_hash[32]` + `has_document_hash`,
`decimals`, `mint_baton_vout`, `initial_quantity`. An NFT is the 1-of-1 shape the wallet
already recognizes: **`decimals==0 && balance==1`** (`zcl-qt-wallet/src/rpc.cpp:832`),
no baton.

**Byte budget (the binding constraint).** Empty pushes encode as `OP_PUSHDATA1 0x00`
= **2 bytes** each (`op_return_push.h:74-78`). Fixed genesis cost with empty ticker/name/url
and a 32B `document_hash`:

```
  OP_RETURN              1
  Lokad   push (1+4)     5     "SLP\0"
  type    push (1+1)     2     0x01
  "GENESIS"push (1+7)    8
  ticker  (empty)        2
  name    (empty)        2
  document_url (empty)   2
  document_hash (1+32)  33
  decimals (1+1)         2
  baton   (empty)        2
  qty     (1+8)          9
  ──────────────────────────
  FIXED TOTAL           68     →  223 − 68 = 155 bytes shared by ticker + name + url
```

A push ≤ 0x4b uses a 1-byte prefix; 76..255 bytes uses a 2-byte `PUSHDATA1` prefix
(`op_return_push.h:49-71`). So with empty ticker/name, the usable `document_url` payload
is **~153 bytes**. `document_url[256]` in the struct is fine; the **~153-byte WIRE cap is
the real limit** and MUST be enforced at build time (the whole encoded script length vs
223), because `slp_build_genesis` silently returns 0 on overflow (`slp.c:177-233`).

> There is **no room for a NEW on-chain field** (a second 32B Merkle push would need 33
> more bytes). The Merkle structure therefore lives OFF-CHAIN; `document_hash` is the
> single on-chain anchor that transitively pins everything.

### 2.2 `document_hash` (32B) — the dual-mode anchor

`document_hash` is parsed at exactly `len==32` (`slp.c:90-96`). We define it by file size,
and the wallet picks the algorithm deterministically (see the ambiguity rule below):

- **SMALL file (≤ chunk_size):** `document_hash = SHA-256(file)` — exactly today's verify
  (`nftimagecache.cpp:66-72`), generalized to non-image bytes. Unchanged for images.
- **LARGE file (> chunk_size):** `document_hash = MERKLE ROOT` over 1 MiB chunks (below).
  The root binds BOTH the whole content AND the chunk layout, enabling streamed
  verification of a 2 GB video without ever holding the file.

### 2.3 `document_url` (≤~153B) — a STRUCTURED pointer, not a raw http link

The fragment after the scheme always points at content (the manifest by hash, or the bytes
by content address), never embeds them, so a 4 GB video's URL is still tiny. Grammar:

```
  ipfs://<cidv1>                      content-addressed, the CID self-verifies (preferred)
  https://host/path/<name>.zdm        creator-hosted manifest (large files)
  zdm:<32-hex-prefix>                  manifest-by-hash; bytes resolved out-of-band
  zdc1://<manifest-hash-hex>          private: bytes over ZDC1 Sapling memos
  https://host/path/file.png          small public single-file (bytes directly)
```

Prefer **short `ipfs://CID`** over long gateway URLs — a long path overflows the ~153B cap.
`document_url` is OPTIONAL and is **never fetched by the daemon** and never auto-fetched by
the GUI.

### 2.4 The off-chain manifest (Tier 2) — `ZDM1`, self-anchoring

For LARGE files, `document_url` points at a small, canonical, fixed-endian **manifest**
that carries the Merkle metadata that does not fit in ~153 on-chain bytes. Two equivalent
framings were proposed — (a) the on-chain anchor is the manifest's own SHA-256, or (b) the
anchor is the **Merkle root** that the manifest re-states. We adopt **(b), root-as-anchor**,
because it preserves streamed verification (the chain anchor directly validates streamed
chunks); the manifest re-states the root and the whole-file SHA-256 for a cheap single-shot
cross-check. The manifest is resolved from local cache or explicit user action, hashed, and
its self-stated root checked against the on-chain anchor BEFORE any field is trusted.

`ZDM1` exact layout (little-endian; deterministic so two encoders produce byte-identical
bytes → stable hash; **bounds-checked parse, never asserts** — mirror the never-assert JSON
readers in `rpc.cpp`):

```
  off  0  magic        "ZDM1"          4B
  off  4  version      0x01            1B
  off  5  flags        1B   bit0=private/encrypted  bit1=has-poster  bit2=multi-part
  off  6  merkle_root  32B  (== document_hash on chain, large-file mode)
  off 38  sha256_whole 32B  (whole-file SHA-256, single-shot small-file cross-check)
  off 70  file_size     8B  uint64 LE (exact decrypted byte length)
  off 78  chunk_size    4B  uint32 LE (PINNED = 1 MiB = 1048576)
  off 82  chunk_count   4B  uint32 LE (= ceil(file_size / chunk_size))
  off 86  mime_len      1B; mime    ≤127 ASCII   ("video/mp4","image/png",…)
  ...     name_len      2B LE; filename UTF-8 ≤1024 (original BASENAME, no path)
  ...     poster_hash   32B  present iff flags bit1 (SHA-256 of a small JPEG/PNG poster,
                              itself a separate content-addressed blob — lets the gallery
                              show a thumbnail for a video WITHOUT the video)
  ...     (private only) key_wrap: 12B nonce + AEAD-wrapped 32B content key (Tier 3)
```

The full per-chunk hash list (32B × chunk_count) MAY be appended (a 2 GB file → 2048
leaves → 64 KiB), or recomputed on the fly from the bytes — the root in the header is the
authority. Typical header-only manifest ≈ 150–400 B; with the chunk list ≈ 64 KiB for 2 GB.

### 2.5 The Merkle tree — PINNED parameters (a wire commitment)

```
  CHUNK SIZE  = 1 MiB (1048576), fixed in v1. (2 GB → 2048 leaves → 11-deep tree;
                one streamed chunk needs ~11 sibling hashes ≈ 352 B proof. Matches the
                streaming read buffer.)
  LEAF        leaf_i   = SHA-256(0x00 || chunk_bytes_i)
  INTERNAL    node     = SHA-256(0x01 || left || right)
  ODD NODE    PROMOTE the lone node unchanged to the next level — do NOT duplicate it.
  1-LEAF      a file ≤ chunk_size has root = leaf_0 = SHA-256(0x00 || bytes).
  HASH        SHA-256 everywhere (the wallet's existing primitive).
```

- **Domain separation** (`0x00` leaf / `0x01` internal) prevents the second-preimage /
  leaf-vs-internal confusion (the CVE-2012-2459-class ambiguity).
- **Odd-node PROMOTION, not duplication.** Duplicating the last node is the exact bug that
  enables the Bitcoin Merkle dup-tx forgery; promotion is unambiguous. (One input design
  suggested Bitcoin-style duplication; we **reject** it in favor of promotion.)
- **1-leaf ≠ bare SHA-256.** `SHA-256(0x00 || bytes) != SHA-256(bytes)`. This is the
  **anchor-ambiguity rule** below; it is the main subtlety, documented loudly.

### 2.6 ANCHOR-AMBIGUITY RULE (mandatory, deterministic)

The wallet must know which algorithm produced `document_hash`:

- **SMALL path (no resolvable manifest):** `document_hash = SHA-256(bytes)` (bare).
- **LARGE path (a `.zdm` manifest resolves locally or by explicit user action):**
  `document_hash = Merkle root` (domain-separated, per 2.5).

Selector: **does a `.zdm` manifest resolve?** No → bare-SHA-256 mode. Yes → root mode.
The manifest ALWAYS carries `sha256_whole` so the wallet can cross-check either way. Keep
**both code paths**; do not try to unify them silently.

---

## 3. Large-file / video strategy + streamed verification

### 3.1 What "owning a video NFT" means (state it in the UI)

The chain proves the **fingerprint** and (via ZSLP UTXO conservation) **who holds the
1-of-1 token** — never the pixels. There is **no DRM, no anti-copy**. If the off-chain copy
disappears you own a verifiable fingerprint to nothing → **permanence is the holder's /
creator's responsibility** (pin to IPFS, keep the file). The wallet should warn at mint and
offer to keep a local content-addressed copy.

### 3.2 Streamed / incremental verification (bounded memory)

The worker NEVER holds the whole file. One pass, two hash contexts, a single reused 1 MiB
buffer:

1. **Resolve + hash the small manifest first** (if large mode); compare its self-stated
   root to the on-chain `document_hash`. If it fails → **MISMATCH immediately, no big read.**
2. **Stream the bytes chunk-by-chunk.** For each 1 MiB read: feed one per-chunk
   `QCryptographicHash(Sha256)` to get `leaf_i`, AND a rolling whole-file
   `QCryptographicHash::addData()` for the single-shot cross-check. Compare `leaf_i` to the
   manifest's chunk hash **as it goes** — a tamper in chunk *K* fails at chunk *K* without
   ever reading *K+1*. Combine leaves per Section 2.5; compare the final root to the anchor.

Peak RAM = `chunk_size` + a couple of hash contexts ≈ **1–2 MiB, independent of file size**.
This satisfies "verify a 2 GB video in bounded memory" and "verify as it downloads/plays":
a future chunked-transfer pipeline calls `verifyChunk(i, bytes)` the instant chunk *i*
lands, gating playback/sharing of only-verified prefixes.

### 3.3 Public vs private large

- **PUBLIC video:** manifest + bytes off-chain; `document_hash` = Merkle root anchors the
  manifest/bytes; anyone verifies.
- **PRIVATE large video:** encrypt plaintext with a per-asset symmetric key **BEFORE**
  chunking; **the Merkle is over CIPHERTEXT** (`flags` bit0 set, `key_wrap` block present).
  The on-chain anchor commits to ciphertext, so the public chain reveals nothing about
  plaintext, and a holder can **verify integrity before the key arrives**. Decrypt happens
  ONLY after the integrity check passes (no decrypt oracle). The small symmetric key is
  revealed over the separate ZDC1 Sapling-memo channel — NOT the bytes.

---

## 4. The content engine (refactor of `nftimagecache`)

**The must-fix:** the current worker does `bytes = f.readAll()` then
`QCryptographicHash::hash(bytes,…)` (`nftimagecache.cpp:60-67`) — fine for the ≤10 MB image
guard (`kMaxFileBytes`, line 33), **fatal for a 2 GB video** (whole file in RAM). Refactor
into ONE general streaming engine; image decode becomes a consumer of it, not a parallel
copy.

### 4.1 Plan (DRY, gallery never breaks)

- **Step A.** Copy `nftimagecache.{h,cpp}` → `src/contentengine.{h,cpp}`, rename class
  `NFTImageCache` → `ContentEngine`, keep the existing 4-arg `request()` as an inline
  forwarder so callers compile unchanged this pass.
- **Step B.** Add a 1-line shim (`typedef ContentEngine NFTImageCache;` or keep
  `nftimagecache.h` as an include shim) so `mainwindow.cpp:3053/3124/3204` and `rpc.cpp`
  keep working with ZERO edits; flip names later.
- **Step C.** Register `contentengine.{h,cpp}` in `zcl-qt-wallet.pro` and `tests/tests.pro`
  the same way `nftimagecache` is (`tests.pro:51,64`). C++14 only.
- **Step D.** Add L0 tests in `tests/tst_logic.cpp` next to
  `nftCachePipelineVerifyMismatchPending()` (`:1355`) reusing the `QTemporaryDir` +
  `writeTestPng` + `XDG_DATA_HOME` + `QSignalSpy` harness (`:1253,:1359`).

### 4.2 Preserved threading contract (verbatim — it is already correct)

- Bounded `QThreadPool` `setMaxThreadCount(4)` (`nftimagecache.cpp:139`).
- The worker touches **only** `QByteArray` / `QCryptographicHash` / `QImageReader` /
  `QImage` — **NEVER `QPixmap`**.
- Cross back via `QMetaObject::invokeMethod(..., Qt::QueuedConnection)` to a GUI-thread
  `deliver()`, where the `QPixmap` is built and `onImageReady(hash, QPixmap, verifyState)`
  is called (`nftimagecache.cpp:111-118,180-198`).
- `QPointer` target guard; in-flight `QSet` dedupe keyed `hash@sizePx`
  (`:157-178`); atomic `QSaveFile` cache write (`:99-107`). **Zero network code.**

### 4.3 New behavior

- **Streaming hash** over a fixed **1 MiB** buffer, replacing `readAll`. A
  `std::atomic<bool>` cancel flag checked **every 1 MiB block** (a 2 GB / 100 GB hash must
  abort on shutdown / wrong-file-drop). Dtor must `cancelAll()` — `_pool.clear()` only drops
  not-yet-started runnables and cannot stop a running multi-GB hash (`:143-148`).
- **Chunked Merkle** (1 MiB leaves, domain-separated, odd→promote) computed in the SAME
  pass; root kept SEPARATE from the whole-file SHA-256.
- **Classify by MIME** (`QMimeDatabase`, header sniff — no full read): `image/*` → existing
  `QImageReader` decode-time downscale path (UNCHANGED, gallery byte-identical);
  `video/*`, `application/pdf`, `text/*`, arbitrary bytes → **no decode**, render a typed
  poster (film-strip glyph for video, MIME-family glyph for documents) on the `#1d2027`
  inset. **Never fake a video frame** (no codec — Section 7).
- **Content-addressed cache, keyed by hash** (store once, dedupe across NFTs):
  `AppData/nft_posters/<hash>_<px>.png` (today's thumb cache, generalized) and
  `AppData/nft_content/<first2hex>/<hash>` for verified raw bytes — the bytes store is
  **opt-in, NEVER auto-populated** (privacy). A completed verify can drop a `<hash>.ok`
  stamp so re-open re-verifies cheaply (stat, not re-hash).
- **Privacy guard, hard:** `request()` / verify accept a **local path or `:/resource`
  ONLY**; assert/guard against `http(s)://` as `bytesPath`. `refreshNFTs` keeps
  `cachePath=""` (`rpc.cpp:960`); the engine never auto-fetches a `documenturl`.

### 4.4 POD descriptor (C++14, no `std::optional`)

```cpp
// src/contentengine.h
struct ContentDescriptor {            // POD, value-copyable aggregate
    bool       ok          = false;   // false => unreadable / empty
    QByteArray merkleRoot;            // 32B (== anchor in large mode)
    QByteArray sha256Whole;           // 32B (whole-file, cross-check)
    quint64    fileSize    = 0;
    quint32    chunkSize   = 1048576;
    quint32    chunkCount  = 0;
    QString    mime;                  // sniffed; "" => sniff failed
    QString    filename;              // basename only, no path
    QByteArray posterHash;            // 32B or empty
    bool       isPrivate   = false;
};
enum VerifyState { Pending = 0, Verified = 1, Mismatch = 2 };  // matches nft.h:29
```

---

## 5. Native media display + mint UX

### 5.1 IN-APP VIDEO PLAYBACK — HONEST VERDICT: NOT in v1

**Infeasible in the static single-file bundle, on real evidence:**
- The static Qt build passes `-skip qtmultimedia` (and `-skip qtwebengine`) —
  `zclbuild/focal/build/02-openssl-qt.sh:29-30`. No `QMediaPlayer`/`QVideoWidget`.
- The GUI links only `core gui network svg widgets` (`zcl-qt-wallet.pro:7,14,20`); grep
  for multimedia / QMediaPlayer / gstreamer / ffmpeg / libvlc / webengine = **0 matches**.
- The bundle gate **fails the build if any optional `.so` stays dynamic**
  (`04-gui-bundle.sh:120-128`) — a gstreamer-backed QtMultimedia would break the
  "user installs nothing" single-file thesis, and still couldn't decode H.264/HEVC without
  system codecs.

**v1 video UX (native, bundle-safe):** the detail view shows a **poster** (creator-supplied
poster blob, or a typed film-strip placeholder — never a fake frame), an overlaid play
glyph, a `Video · <MIME> · <NN.N MB> · <MM:SS>` caption, the genuine/tampered badge, and a
primary button **"Open in your video player"** →
`QDesktopServices::openUrl(QUrl::fromLocalFile(localPath))` — a primitive already used in
the repo (`mainwindow.cpp:1847,2558`; `sendtab.cpp:1580`), proven native and bundle-safe.
The button is **enabled only when local verified bytes exist**; for a public NFT whose
bytes aren't cached it reads **"Fetch & verify (NN.N MB)"** and downloads **on explicit
click only** (never on paint — privacy). In-app playback is a separate, later, explicitly
funded phase (libVLC/ffmpeg in the bundle — licensing/codec surface); **do not promise it.**

### 5.2 The detail view (a NEW surface)

The gallery `QListView` (`mainwindow.cpp:3038-3058`) has **no** `activated`/`doubleClicked`
wiring today. Add `connect(view, &QListView::activated, this, &MainWindow::openNFTDetail)`.
`openNFTDetail(QModelIndex)` builds a modeless `NFTDetailView` (QDialog or stacked panel)
styled with the dark.qss tokens, rendering per kind:

- **Image:** full `QPixmap` (request a larger `sizePx`, e.g. 512).
- **Video:** poster / film-strip placeholder + "Open in your video player" + caption.
- **Document:** large MIME icon + "Open" + "Reveal in folder" (`openUrl` of the dir).
- **Bytes:** hex/size summary + "Save as…" (`QFileDialog`) — never auto-execute bytes.

All kinds show: name, collection, txid (mono, copyable), genesisheight, the
genuine/tampered/pending badge, and a "Bytes: local / not downloaded" line. The
remote-fetch button is the ONLY network touch and only on explicit click.

### 5.3 Mint wizard (GUI now; final broadcast gated on the daemon RPC)

Entirely local until the final broadcast:

1. **Drop / pick ANY file** → MIME + kind + name + size shown.
2. **Stream-hash with progress** (off-GUI-thread, cancelable, bounded 1 MiB buffer) →
   `document_hash` (+ Merkle leaves for > 1 MiB). Populate the content-addressed cache
   (store once). Key the mint job by **source PATH** (the hash isn't known yet, so the
   `hash@sizePx` dedupe key doesn't apply during mint).
3. **Name / collection (ticker) / optional `document_url`** (where the creator hosts bytes).
   **Live-validate** the encoded script length vs 223 and block mint before broadcast;
   prefer short `ipfs://CID`.
4. **Public vs Private** toggle (green/amber tokens). Private records intent + builds the
   same fingerprint (over ciphertext); bytes ride ZDC1 (separate workflow).
5. **Review:** shows EXACTLY what becomes public (name, ticker/descriptor, `document_url`,
   the 32B hash, byte size) vs what stays private; shows the fee; one explicit **Mint**.

Until the daemon mint RPC lands, the final **Mint** button is disabled / "coming soon" so
the wizard never dead-ends.

---

## 6. API surface

### 6A. Daemon mint RPCs (designed now, implemented later)

New TU `src/rpc/zslpmint.cpp`, registered via a sibling
`RegisterZSLPMintRPCCommands(CRPCTable&)` declared+called in `rpc/register.h` (mirror the
read-only `RegisterZSLPRPCCommands` at `register.h:23,32`). `#ifdef ENABLE_WALLET` (else
`RPC_METHOD_NOT_FOUND`); `okSafeMode=false` (mutating). **Non-consensus:** they only
assemble a standard OP_RETURN + dust tx.

**Why NOT `createrawtransaction`:** its `sendTo` arg is keyed by ADDRESS —
`DecodeDestination(name_)` + `GetScriptForDestination` (`rawtransaction.cpp:554-571`); an
OP_RETURN has no address, so it cannot be expressed and would throw
`RPC_INVALID_ADDRESS_OR_KEY`. It also yields an unfunded/unsigned skeleton. The mint must
emit a `scriptPubKey` we choose AND atomically fund+sign+broadcast — that is exactly
`CRecipient{scriptPubKey,nAmount,fSubtractFeeFromAmount}` (`wallet.h:129-134`) +
`CreateTransaction` + `CommitTransaction` (`wallet.h:1242-1244`).

```
zslp_opreturn "datahex" ( "toaddress" amount )      # generic OP_RETURN carrier (the core)
  datahex   : raw OP_RETURN PAYLOAD hex (NOT incl. 0x6a); ≤220B; daemon prepends OP_RETURN
              + one canonical push. Pure carrier — does NOT understand SLP. ZDC1/ZNAM reuse it.
  -> { txid, size, fee }

zslp_mint {options}                                  # high-level "make this an NFT" (built on ^)
  options = {
    "name":        (string, required)  ≤128 UTF-8 bytes
    "ticker":      (string, optional)  ≤64  bytes
    "documenthash":(string, optional)  64-hex (32B) = SHA-256(file) OR Merkle root
    "documenturl": (string, optional)  ≤~153B structured URI; HINT ONLY, never fetched
    "decimals":    (numeric, default 0)   NFT => 0
    "quantity":    (numeric, default 1)   NFT => 1
    "mintbaton":   (bool,    default false)
    "toaddress":   (string, optional)  t-addr for the token dust; default = fresh wallet key
    "merkleroot":  (string, optional)  64-hex (carried in documenthash for v1; see note)
    "fee":         (numeric, optional)
  }
  -> { txid, tokenid(==txid), vout(token dust), batonvout|null, size, fee }
```

**Build path:** `slp_build_genesis(script,223,…)` → `CScript opret(script,script+n)` →
`vecSend = [ {opret,0,false}, {dust→toaddr,546,false}, (baton {dust,…} iff mintbaton) ]`
→ `CreateTransaction(vecSend, wtx, reservekey, fee, chgPos, err, NULL, true)` →
`CommitTransaction`. **Validate before building:** decimals 0..9; quantity fits the 8B BE
field; documenthash/merkleroot exactly 64 lowercase-hex; name/ticker/url byte-lengths vs the
slp buffers; **the whole encoded script ≤ 223** (throw a clear error, don't let
`slp_build_genesis` silently return 0); toaddress is a valid t-addr (ZSLP rides transparent
dust only); wallet unlocked + funded.

**Two open byte decisions to resolve before mint impl:**
1. **Change-output vout shift (highest risk).** SLP pins token to `vout[1]`, baton to
   `mint_baton_vout >= 2` (`slp.c:107`). `CreateTransaction` appends change at an arbitrary
   position; if it lands at `vout <= baton` it breaks the positional binding. **Pin SLP
   outputs first and force change LAST** (coinControl), or post-validate `chgPos` and
   rebuild.
2. **Where the Merkle root lives.** Genesis has ONE 32B `document_hash` slot. v1: ship
   **`document_hash` = Merkle root for large files / bare SHA-256 for small** (Section 2.6);
   `sha256_whole` lives in the manifest. The descriptor still computes the root for future
   chunked transfer. (A second OP_RETURN push is rejected — 223B has no room.)

### 6B. GUI `ContentEngine` API (this workflow — extend `nftimagecache`)

Zero network code; all calls take a LOCAL path/resource only.

```cpp
// async hash + describe (streaming, bounded RAM); NEVER blocks the GUI thread
void hashFile(const QString& path, quint64 token);
signals: void descriptorReady(quint64 token, ContentDescriptor d);

// async verify bytes against an on-chain anchor -> Pending/Verified/Mismatch
void verify(const QString& path, const QString& expectedHashHex, quint64 token);
signals: void verifyDone(quint64 token, int verifyState);

// async poster/thumbnail for ANY content (image now; video/doc => typed placeholder).
// == today's request(); delivers via the existing onImageReady contract.
void posterFor(const QString& path, const QString& hash,
               const QString& expectedHashHex, int sizePx);

// pure, testable, no I/O — for streamed/chunked verify and unit tests
bool verifyChunk(const ContentDescriptor& d, int idx, const QByteArray& chunkBytes);

// content-addressed on-disk cache, keyed by hash (store once)
static QString cacheGet(const QString& hashHex);             // "" if absent (sentinel)
static bool    cachePut(const QString& hashHex, const QString& srcPath);  // atomic copy

// back-compat forwarder so existing callers compile unchanged this pass
void request(const QString& hash, const QString& bytesPath,
             const QString& onChainHashHex, int sizePx);
```

**GUI wiring (`rpc.cpp`):** add `RPC::mintNFT(descriptor, opts, cb)` symmetric to
`refreshNFTs` (`rpc.cpp:863`): on an explicit user "Mint" action (not paint), call
`zslp_mint` with `{name, documenthash:d.merkleRootOrSha256, documenturl:userOrEmpty,
decimals:0, quantity:1}`; on success `cachePut` the local bytes so the new card verifies
instantly, then `refreshNFTs()`. `refreshNFTs` stays UNCHANGED (`cachePath=""`). When a card
is opened, `MainWindow` calls `ContentEngine::cacheGet(docHashHex)`; non-empty → `posterFor`
+ `verify`; empty → "pending" + offer "Locate file…" (user-explicit, no network).

---

## 7. Build / dependency order + honest limits

### 7.1 Build & test invocations (verified)

- **Full pass:** `./prun bash /build/build.sh` (`zclbuild/prun` →
  `focal/build/build.sh`) — 03 daemon (carries the verified UTXO-bound forgery fix) + 04 GUI
  bundle + delivery gate (asserts `sha256(host) == sha256(chroot)` and the static/optional-so
  gates).
- **GUI unit tests:** `/home/rhett/zclbuild/run-l0-l1.sh` — L0 `tst_logic` (guiless) and L1
  `tst_widget` (`QT_QPA_PLATFORM=offscreen`) via `qmake tests.pro && make`. Baseline
  **L0 104 / L1 34**.
- Register `contentengine.{h,cpp}` in `tests/tests.pro` HEADERS+SOURCES (like
  `nftimagecache` at `:51,64`) and in `zcl-qt-wallet.pro`.

### 7.2 Implementation order

1. `contentengine.{h,cpp}` from `nftimagecache` (Section 4) + streaming hash + chunked
   Merkle + cancel + content-addressed cache; image path unchanged; back-compat shim.
2. L0 tests in `tst_logic.cpp` (Section 7.4); green L0/L1.
3. Native detail view + per-kind rendering + "Open in your video player" (Section 5).
4. Mint wizard UI, **Mint disabled** pending the daemon RPC.
5. *(Later phase)* daemon `zslp_opreturn` + `zslp_mint` (Section 6A); enable Mint.

### 7.3 Honest limits (state in UI/docs; do not hide)

1. **No in-app video playback** in the static bundle (Section 5.1). Verify + poster +
   open-externally only. The open button requires a LOCAL verified file (`openUrl` on a
   missing/remote path silently fails) — gate it.
2. **Bytes can NEVER be on-chain** (223B cap). The chain stores a 32B fingerprint; the bytes
   live off-chain and **permanence is the holder's responsibility**. Warn at mint; offer a
   local copy.
3. **No Merkle field on-chain** — the tree is only transitively pinned via `document_hash`.
   A peer needs the (small) manifest before chunk-streaming; a withheld/garbled manifest
   fails fast but isn't recoverable from the chain alone.
4. **Owning ≠ controlling the pixels.** No DRM, no anti-copy. Verify fails for a tampered
   file; ownership is the ZSLP UTXO.
5. **Anchor ambiguity** (1-leaf Merkle ≠ bare SHA-256): the manifest-resolves selector is
   mandatory (Section 2.6).
6. **URL byte budget** (~153B): validate the encoded script ≤ 223 BEFORE signing; prefer
   `ipfs://CID`.
7. **Domain separation + odd-node promotion** are mandatory anti-malleability; a naive
   duplicate-last is a latent forgery vector.
8. **Encrypted NFTs:** Merkle over CIPHERTEXT, verify integrity BEFORE decrypt (no decrypt
   oracle).
9. **Privacy regression risk:** the new detail-view fetch button is the first network touch
   in this subsystem — strictly explicit-click, never on paint/hover/poll.
10. **C++14:** no `std::optional`/`string_view` (cost real build cycles before); empty-QString
    / sentinel-int, header includes for header-signature types.

### 7.4 Tests to add (L0, `tst_logic.cpp`)

- `streamHashEqualsWholeHash`: streaming SHA-256 == `QCryptographicHash::hash(readAll)` for
  sizes {0, 1, 1 MiB−1, 1 MiB, 1 MiB+1, 3 MiB, 5 MiB} (parity with the old path).
- `merkleRootDeterministic` + `merkleDetectsTamperedChunk`: flip one byte in chunk *K* →
  `verifyState=2`, `failedChunk=K`, chunks `< K` already verified; an unrelated byte in the
  same chunk changes only that leaf.
- `merkleSingleLeafDegenerate`: file ≤ chunk_size → root = `SHA-256(0x00||bytes)` ≠ bare
  SHA-256 (the ambiguity rule).
- `manifestRoundTrip`: `build`→`parse` byte-identical (hash stability); bounds-checked parse
  rejects a truncated/hostile blob without asserting.
- `manifestHashShortCircuit`: a bad manifest hash fails before the big read.
- `verifyStates`: Verified / Mismatch / Pending (extend
  `nftCachePipelineVerifyMismatchPending`, `:1355`).
- `cacheRoundTrip`: `cachePut`/`cacheGet` round-trip; miss → "".
- `nftKindClassification` + `nftHumanSize`: png/jpg→Image, mp4/mov→Video, pdf→Document,
  unknown→Bytes; "12.3 MB".
- `boundedMemory`: hash a synthetic 64 MiB temp file and assert completion (proves no
  `readAll` OOM path). Pure `verifyChunk`/`parse`/`build` are I/O-free for fast L0.
