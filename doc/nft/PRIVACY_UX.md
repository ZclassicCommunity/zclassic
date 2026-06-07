# ZClassic Private NFTs & Shielded Data Channel — Native Privacy UX

**Status:** Design spec + shipped codec. Grounds on the working ZDC1 codec at
`src/datachannel/zdc.{h,cpp}` (tested: `src/datachannel/test/`, 800+ checks, 0
failures) and on the UX contracts in `doc/nft/NATIVE_UX.md`.
**Repos:** daemon `/home/rhett/github/zclassic`; GUI `/home/rhett/github/zcl-qt-wallet`.
**Constraint (codec):** C++11, libsodium-only, no daemon/chain/Qt deps — builds
standalone for tests AND into the daemon unchanged.
**Constraint (GUI):** C++14 only (`zcl-qt-wallet.pro`), 100% native Qt
(`QPainter`/delegates), no QtWebEngine. Reuse `dark.qss` tokens only.
**Consensus:** UNCHANGED. Rides the existing Sapling shielded pool + 512-byte
encrypted memos. No fork, no new opcode, default-OFF / opt-in.

This document is the privacy-UX companion to NATIVE_UX.md. Where NATIVE_UX.md
defines the gallery/detail/mint/send screens, this defines the **private**
behaviours layered on them: send a private file/message, receive private items,
reveal the key, the private pill in the gallery, and private mint — all in the
"don't make me think" voice, honest about metadata leakage and permanence.

---

## 0. The product in one breath

You pick a person (a private/shielded address), attach a file or type a message,
and the wallet shows — before you commit — exactly how big it is, how many notes
it becomes, the flat fee, and one honest line about what stays hidden and what
leaks. You press **Send privately**. On the other side, private items appear in
**Activity**; they open the moment the key is present, or sit calmly in a
**"Waiting for the key"** state until the sender reveals it. Revealing is one
tap. A private NFT shows the same green **Private** pill and the same image-match
check as any other — it just decrypts locally first.

The whole thing reuses the vocabulary the user already learned on the gallery
(NATIVE_UX P9). Nothing here teaches a new visual word.

---

## 1. Vocabulary lock (extends NATIVE_UX §1, P1)

Banned protocol terms stay banned. The data channel adds these plain words, used
identically everywhere:

| Plain word (UI) | Means (engineering) | Never say |
|---|---|---|
| **sealed** | AEAD-encrypted under the per-transfer key | "encrypted memo", "AEAD" |
| **the key** | the 32-byte per-transfer symmetric key | "symmetric key", "K_file" |
| **reveal the key** / **hand over the key** | deliver the KEY frame / key out-of-band | "send the KEY frame" |
| **note** / **message** | a memo's contents | "memo", "512-byte field" |
| **private (shielded) address** | a z-addr | "z-addr", "ivk" |
| **piece / item / file** | the content stream | "transfer", "ZDC1 frames" |
| **a few small notes** | the chained shielded outputs | "outputs", "chunks" |
| **permanent on the network** | stored by every node forever | "chain bloat", "unprunable" |

The word **"private"** in this app means **hidden from the public, not
one-of-a-kind** (NATIVE_UX P10). Copy never implies a sealed file can't be
copied once opened.

---

## 2. The one honesty line (non-negotiable, appears on every send)

Every private-send surface shows ONE calm sentence (12pt `#9aa0a6`, no red unless
something is actually wrong) that tells the truth about a shielded data transfer:

> **"Hidden: who it's from, who it's to, the amount, and the contents. Visible:
> that a private transfer happened, roughly when, and about how big. It stays on
> the network permanently."**

This is the load-bearing honesty. It is shown, not hidden behind a tooltip,
because the size→#notes mapping genuinely leaks an approximate size (more notes =
bigger file) and we refuse to oversell "private" as "undetectable". For a tiny
message it shrinks to:

> **"Only the person you choose can read this. The fact that you sent something
> private is still visible, and it stays on the network permanently."**

---

## 3. SEND A PRIVATE FILE / MESSAGE

New `NFTSendPrivateDialog` (or a "Private" mode of the existing send tab),
modeled on `memodialog.ui` + `confirm.ui`. Fixed width 560. Built programmatically
(C++14-trivial, no `.ui` churn). One bright green primary at all times (P2).

### 3.1 Anatomy (top to bottom)

1. **Who gets it.** Title "Send to". The wallet's `AddressCombo`. One reserved-
   height live status line (debounced local validation, no per-keystroke RPC):
   - valid private → green "Looks good — a private (shielded) address"
   - valid public → amber "A private send needs a private (shielded) address —
     paste one above." (and the primary stays disabled, P4: reason+fix inline)
   - invalid → red "That doesn't look like a ZClassic address."

2. **What you're sending.** A tab-pair: **Message** (a `QPlainTextEdit`, live
   "0 / 4 KB", soft amber past 3.5 KB) or **File** (a 528×140 dropzone identical
   to the mint dropzone — "Drop a file here", "Up to 64 KB on the network", a
   "Choose a file…" button). After a file: a 528×72 loaded row — 56×56 icon,
   filename (elided middle), "1.8 KB · image/png".

3. **The consequence table (rewrites live, P6).** The instant a file/message is
   present, an inset (`#1d2027`/radius 8) fills in — NO daemon round-trip:

   ```
   Size            1.8 KB
   Becomes         5 small private notes        <- ceil(size / 464) + 2 (start/end)
   Network fee     0.0001 ZCL                   <- one fee per tx; ~107 notes/tx
   After this      5.2340 ZCL
   ```

   The "Becomes N small private notes" row is computed purely from the codec
   constants: `DATA_PLAINTEXT_PER_FRAME = 464`, plus START + END frames, plus an
   optional KEY frame. This is the same number an observer can count on-chain,
   which is *why* we surface it — it is the honest size signal.

4. **Who can open it, and when (the seal-then-reveal choice).** Two rows, shown
   only after a valid private recipient (animated `setVisible`):
   - **Send it sealed, with the key (default)** — "They can open it the moment it
     arrives." (= `include_key_frame = true`)
   - **Send it sealed now, reveal the key later** — "It arrives locked. You
     unlock it for them anytime from Activity — good for a surprise on a certain
     day." (= `include_key_frame = false`; a "Reveal the key" action is recorded)
   Footnote: "Either way, only they can ever open it."

5. **The honesty line** (§2), full-width inset, always visible.

### 3.2 Footer + states

Footer: the fee line + [Cancel] + a green primary whose **label states the
outcome** (NATIVE_UX payoff): send-with-key → **"Send privately"**; reveal-later
→ **"Send sealed"**. Disabled until valid private recipient AND non-empty
content AND not in flight.

States: ready · file-too-big (inline amber "That file is larger than 64 KB.
Private on-chain transfers are for small files — pick a smaller one, or share it
another way.", primary disabled — we cap, we never silently truncate) ·
sealing/sending (primary → spinner "Sending…", Cancel → "Close (keeps sending)")
· sent-with-key ("Sent privately. They can open it now.") · sent-sealed ("Sent
sealed. Unlock it for them anytime from Activity." + an Activity entry carrying a
"Reveal the key" action) · error (inline red + the daemon's plain reason + "Try
again"; nothing sent) · low-balance ("Not enough ZCL for the network fee.").

---

## 4. RECEIVE — private items appear, decrypt when the key is present

Private items surface in **Activity** (and, for NFTs, the gallery). The receive
engine is the codec's `Decoder` driven by the binary-safe read path (§7).

### 4.1 The three receive states (drive the row's right-side status)

| Codec state | UI state | Row status | Action |
|---|---|---|---|
| not `is_complete()` | **Arriving** | "Arriving… 3 of 5 notes" (live count from `ChunksReceived`/`ChunksExpected`) | — (greyed) |
| `is_complete() && !have_key()` | **Waiting for the key** | amber dot + "Waiting for the key" | "Ask sender" (copies a short note) — never a dead end (P4) |
| `is_complete() && have_key()` | **Ready** | green dot + "Private message" / "Private file — aurora.png" | **Open** / **Save…** |

The **"Waiting for the key"** state is the visible face of seal-then-reveal: the
bytes are fully here and verified-complete, but `assemble()` returns `ERR_NO_KEY`
until the key arrives (in-band KEY frame, or the recipient pastes a key they were
given out-of-band). The row never errors and never disappears — it waits calmly.

### 4.2 Open / Save

**Open** runs `Decoder::assemble()`. On `OK` the content + manifest are in hand;
a message shows inline, a file offers **Save…** (`QFileDialog` defaulting to the
manifest filename, writes the exact bytes). On `ERR_AEAD_FAIL` / `ERR_HASH_MISMATCH`
the row turns red: "This file failed its security check — it may be damaged or
wasn't meant for this wallet." (honest, never a crash). `ERR_INCOMPLETE` cannot
happen here because Open is only offered in **Ready**.

### 4.3 DoS / hygiene (carry from PRIVACY_STACK §5, wallet-side only)

- Incomplete `(zaddr, transfer_id)` transfers expire after a TTL (default 7 days)
  so START-spam can't grow memory unbounded. UI: an arriving item older than the
  TTL with gaps shows "This didn't finish arriving." + a quiet "Dismiss".
- A per-sender concurrent-transfer cap; over it, new STARTs are dropped (logged,
  not shown). The codec already gates oversize at `parse_header` (`ERR_OVERSIZE`)
  and bounds `chunk_count <= MAX_CHUNK_COUNT`.

---

## 5. REVEAL KEY — one clear action

For an item the user sent with **reveal-later**, Activity shows a green
**"Reveal the key"** button on that entry. One tap:

1. Confirms once, plainly: "Unlock this for {recipient}? After this they can open
   it. You can't take it back." [Cancel] [Reveal the key]
2. Builds the KEY frame with `Encoder::encode_key_frame(transfer_id, key,
   chunk_count, frame)` and sends it as a single tiny shielded output to the same
   recipient (one note, one fee).
3. On success the entry flips to "Key revealed — they can open it now."

There is exactly one reveal action and one confirm. The key the wallet holds for
a pending reveal is stored encrypted at rest with the rest of the wallet secrets;
it is **never** shown to the user as hex (P1) and never logged (the codec's
`status_str` never includes key material).

**Out-of-band reveal (most private):** for the truly sensitive case the recipient
side also accepts a key the sender handed over by other means. The receive row in
**Waiting for the key** offers a quiet "I have a key" → a single paste field →
`Decoder::set_key()`. Wrong key → calm red "That key doesn't open this item."
(= `ERR_AEAD_FAIL`), try again. Nothing on-chain in this path.

---

## 6. PRIVATE NFT in the gallery + PRIVATE MINT

### 6.1 Private pill + the content engine (reuse, don't fork)

A private NFT is, on the wire, a ZDC1 transfer whose plaintext is the asset bytes
(small) or an off-chain pointer (large, per CONTENT_MODEL.md), plus the ZSLP
ownership record. In the gallery it is rendered by the **same** delegate:

- **Private pill** (green, NATIVE_UX §2.3): "Only you can see this. Its ownership
  is shielded." A private item NEVER offers an explorer link or any remote fetch
  (P8).
- **Verify badge** (NATIVE_UX §2.2): the wallet decrypts the asset bytes locally
  (via `Decoder::assemble`), then runs the existing content engine
  (`nftimagecache` streaming SHA-256) and shows the same green check / red x /
  amber question. For private NFTs the on-chain fingerprint anchors the
  **ciphertext** (CONTENT_MODEL §"PRIVATE NFT"), and the codec's END frame
  additionally binds the **plaintext** SHA-256 — so the gallery can show "matches
  its on-chain fingerprint" with the exact same sentence and zero new vocabulary.

A private NFT that is structurally complete but key-not-yet-present shows the
**"Waiting for the key"** treatment on its card (amber question badge + the pill
still green) instead of a broken image — honest, never a dead end.

### 6.2 Private mint (NATIVE_UX §3.3 "Who can see it" tile A, now wired)

Tile **A — Private (only people you choose)** is the default-selected, green
option. Its body copy (already in NATIVE_UX): *"The image and details are sealed.
Stored encrypted on the ledger; only someone you give the key to can open it.
Your balance and addresses stay shielded."*

Mint pipeline (all wallet-side, no consensus change):
1. Hash the chosen image with the existing content engine → the fingerprint.
2. `ZdcAead::generate_key()` → a fresh per-mint key (never reused).
3. `Encoder::encode(token_id, key, assetBytes, meta, include_key_frame, frames)`
   with `transfer_id = the ZSLP token_id` so the public token cryptographically
   commits to the private bytes (the END ciphertext/ plaintext hash ties them).
4. The ZSLP genesis carries `document_hash` over the ciphertext (CONTENT_MODEL).
5. Frames go out as chained tiny shielded outputs to the owner's own private
   address (self-custody of the sealed bytes).

Review card (NATIVE_UX §3.3 card 4) gains, for Private, the §3.3 consequence
table ("Stays private" → right column "Nothing") plus the **"Becomes N small
private notes"** row and the §2 honesty line. The fee row is the real per-tx fee
× the number of txs (`ceil(frames / 107)`).

---

## 7. The binary-safe GUI read path (design; GUI edit deferred — build in flight)

**The bug** (`zcl-qt-wallet/src/rpc.cpp` ~756–760): a memo arrives as a hex
string in JSON; the code does
`QString(QByteArray::fromHex(...))` and then `.trimmed().isEmpty()`. Constructing
a `QString` from raw bytes runs them through the local 8-bit/UTF-8 codec, which
**mangles every non-text byte** — exactly the ZDC1 frame bytes. `f600` (the empty
marker) is special-cased, but a binary frame is silently corrupted into the text
inbox or dropped.

**The fix (a PARALLEL path, text path untouched):**

```
// memoHex is the raw JSON memo string (hex). Decode to BYTES, never QString.
QByteArray memoBytes = QByteArray::fromHex(
        QByteArray::fromStdString(i["memo"].get<json::string_t>()));

if (memoBytes.size() == 512 && isZdc1Frame(memoBytes)) {
    // Route to the data-channel receive engine. Do NOT touch the text inbox.
    dataChannel->ingest(zaddr, txid,
        reinterpret_cast<const unsigned char*>(memoBytes.constData()),
        memoBytes.size());
} else {
    // EXISTING text path, unchanged:
    QString memo(memoBytes);                 // text memos only reach here
    if (!memo.startsWith("f600") && !memo.trimmed().isEmpty())
        memos[zaddr + txid] = memo;
}
```

`isZdc1Frame()` is a 5-byte check (magic + version) — it must NOT pull in
libsodium on the GUI side for the *detection* step. Two clean options:

- **(A, preferred) thin daemon RPCs.** The daemon owns the codec and exposes
  `z_listdatatransfers` / `z_getdatatransfer(transfer_id)` /
  `z_receivedatafile`. The GUI calls them and renders §4 states from the JSON.
  The GUI never links libsodium for this; the daemon already does. This keeps the
  key material in the daemon/wallet, never in the GUI process.
- **(B) GUI-side codec.** Compile `src/datachannel/zdc.{h,cpp}` into the GUI and
  call `zdc::PeekFrame`/`Decoder` directly. Simpler to prototype, but puts the
  per-transfer key in the GUI process; only acceptable if the GUI already holds
  spending keys.

**Decision: ship (A).** Keys stay where the spend authority already is; the GUI
stays a thin renderer; the codec lives in exactly one place. The detection-only
`isZdc1Frame()` (magic+version, no crypto) can live GUI-side either way so the
text inbox is fixed even before the RPCs land.

---

## 8. API surface (what the daemon/GUI call)

The codec (`src/datachannel/zdc.h`) is the whole library surface. Send side:

```
zdc::ZdcAead::generate_key(key);                 // 32B CSPRNG per transfer
zdc::Encoder::encode(transfer_id, key, plaintext, meta,
                     include_key_frame, frames); // -> N x 512-byte memos
zdc::Encoder::encode_key_frame(transfer_id, key, chunk_count, frame); // reveal later
```

Receive side:

```
zdc::Decoder d;
for (each 512-byte memo) d.add_frame(memo);      // any order, dups OK
d.is_complete();                                  // structurally here?
d.have_key();                                     // key present?
d.set_key(key);                                   // out-of-band reveal
d.assemble(out_plaintext, out_meta);              // OK / ERR_NO_KEY / ERR_*
```

These map 1:1 onto the daemon RPCs in §7(A). Recommended RPC shapes:

- `z_senddatamemo(fromaddr, toaddr, hexpayload, {filename, content_type,
  reveal_later})` → `{transfer_id, opids[]}`. Enforces the 64 KB default cap and
  ≤107 outputs/tx batching.
- `z_listdatatransfers()` → array of `{transfer_id, direction, state
  (arriving|waiting_key|ready|failed), chunks_received, chunks_expected,
  filename, size}`.
- `z_getdatatransfer(transfer_id, [outpath])` → on Ready, returns the bytes (or
  writes to `outpath`); else the state. Never returns the key.
- `z_revealdatakey(transfer_id, toaddr)` → sends the KEY frame; `{opid}`.

---

## 9. Honest limits (must appear in the one-time consent + the §2 line)

Default-OFF, opt-in, behind a one-time consent dialog:

> **"Private files on the network — read this once."**
> "ZClassic can send a sealed file or message that only the person you choose can
> open. The network hides who it's from, who it's to, the amount, and the
> contents. It does **not** hide that a private transfer happened, roughly when,
> or about how big it was. Everything you send this way is stored by every node
> **permanently** and cannot be deleted. Keep files small. Don't send anything
> you couldn't live with being stored forever, even sealed."
> [Not now] [I understand — turn it on]

What we never claim: untraceable, deletable, one-of-a-kind, DRM-protected, or
that sending a public-source fee hides the sender (fund from shielded inputs).
The green check means **bytes match the on-chain fingerprint** — nothing about
genuine/official/who-made-it (NATIVE_UX §2.2 honesty rule, carried verbatim).

---

## 10. Why this design (security rationale, one place)

- **Nonce uniqueness is structural, not lucky.** The 12-byte AEAD nonce =
  `transfer_id(8) || counter(4)`; the key is fresh per transfer, and each frame
  gets a distinct counter by ROLE (DATA→chunk index, START→0xFFFFFFFF,
  END→0xFFFFFFFE; KEY isn't encrypted). The naive "counter = wire seq" would make
  START(0) and DATA-chunk-0(0) share a nonce — catastrophic — so the codec maps
  roles to a reserved counter band instead. Verified: 13 encrypted frames → 13
  unique nonces; START vs DATA-0 never collide.
- **Header is AAD.** version/type/transfer_id/seq/chunk_count are authenticated,
  so a reordered/retyped/cross-spliced frame fails to decrypt.
- **Two integrity layers.** Per-frame Poly1305 tag (security; catches any flipped
  byte — verified 80/80 single-bit flips caught with the CRC repaired) + an END
  SHA-256 over the whole plaintext (binds the NFT fingerprint; catches a re-sealed
  substitute chunk → `ERR_HASH_MISMATCH`). The header CRC32 is transport-only and
  explicitly NOT a security control.
- **Seal-then-reveal is first-class.** A complete-but-keyless transfer returns
  `ERR_NO_KEY`; the recipient genuinely cannot open it until the key arrives.

Codec status: `src/datachannel/zdc.{h,cpp}` compiles standalone and under the
daemon's strict `-std=c++11 -pedantic-errors -Wall -Wextra` with zero warnings;
tests in `src/datachannel/test/` pass (800+ checks, 0 failures) plus an
independent adversarial verification (nonce uniqueness, tamper sweep,
seal/reveal, wrong-key, out-of-order/dup) all green.
