# ZClassic Private NFTs — The Privacy Stack (ZDC1) and What We Are Enabling

> **REMOVED — HISTORICAL DOCUMENT.** The ZDC1 shielded data-channel / arbitrary-file-transfer
> capability described here (`z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer`, the
> `-datachannel` option, the `src/datachannel/` codec) has been **removed entirely** from the
> daemon. ZClassic deliberately provides **no wallet path to store arbitrary files on-chain**. NFT
> content is always off-chain, bound to the token only by a `document_hash` fingerprint. This doc
> is retained for historical traceability only.

**Status:** the codec (`src/datachannel/zdc.{h,cpp}`) is built, unit-tested, **and compiled into
the daemon** (`src/Makefile.am:248,295`). The daemon RPCs (`z_senddatafile` /
`z_listdatatransfers` / `z_getdatatransfer`) are **built, default-OFF** behind `-datachannel`
(`src/rpc/datachannel.cpp:704-711`, register fn `:713`); only the native GUI wiring is later. NON-consensus,
default-OFF, experimental track. Rides UNCHANGED consensus: it uses only the existing Sapling
shielded pool and the 512-byte encrypted memo that ZClassic already supports. No opcode, no fork,
no builder change. *(The as-built RPC contract is `NATIVE_NFT_GUIDE.md §3.3`; where this doc's
RPC sketch differs, the guide wins.)*

> Companion docs: `ZDC1_CODEC_SPEC.md` (the codec wire spec), `CONTENT_MODEL.md`
> (content-addressing / fingerprint anchor for any-size files).

---

## 1. Plain answer: what privacy technology are we enabling?

We are turning ZClassic's shielded payments into a **private data channel**, and on top of
that a **private NFT**. Concretely, a user can:

- **Send a private message** that only the recipient can read (`<= ~4 KB`, one transaction).
- **Send a private file** — an image, a document, a contract (`<= 40000 bytes` on-chain is the
  as-built ceiling: `ZDC_MAX_FILE_BYTES`, a single shielded tx per transfer; larger files keep
  the bytes off-chain and put only an encrypted fingerprint on-chain).
- **"Seal now, reveal the key later"** — publish the encrypted content immediately, then
  reveal the decryption key whenever you choose. Until you do, *not even the recipient* can
  open it. This is a first-class, on-chain timelock-by-choice.
- **Mint a private NFT** — a 1-of-1 token whose asset bytes are encrypted and whose
  ownership is shielded. "Owning" it means holding the key (and, for public provenance, the
  ZSLP token that commits to the encrypted bytes).
- **Selectively disclose** — because the Sapling layer is keyed to a *viewing key*, the owner
  can hand an auditor/buyer a viewing key to prove receipt/contents without giving up spend
  authority.

The honest one-liner: **this is a confidentiality channel, not an invisibility cloak.** The
*contents* and the *recipient* are well hidden; the *fact that a shielded transfer happened*,
its *approximate size*, and its *timing* are not. See Section 6.

---

## 2. The 4-layer stack

```
  L3  PRIVATE NFT / FILE / MESSAGE  (application)   <- this codec + daemon RPC + GUI
        per-transfer 32B key, per-chunk AEAD, content-hash anchor, seal-then-reveal
        ─────────────────────────────────────────────────────────────────────────
  L2  ZDC1 TRANSPORT (framing + reassembly)         <- this codec  src/datachannel/zdc.*
        512B memo = one ZDC1 frame (32B header + 480B payload); START/DATA/END/KEY;
        out-of-order / dup / missing tolerant; size caps
        ─────────────────────────────────────────────────────────────────────────
  L1  SAPLING ENCRYPTED MEMO  (consensus base)      <- already in ZClassic
        512B memo per shielded output, ChaCha20-Poly1305-IETF to recipient's ivk;
        only the incoming-viewing-key holder can read the memo AT ALL
        ─────────────────────────────────────────────────────────────────────────
  L0  SAPLING SHIELDED POOL  (consensus base)       <- already in ZClassic
        zk-SNARKs hide sender, recipient, and amount
```

- **L0 + L1 are consensus-enforced and free.** Every shielded output already carries a
  512-byte memo encrypted to the recipient's incoming viewing key (`ivk`). Only that
  recipient can decrypt it. This is the privacy foundation; the codec never bypasses it.
- **L2 (ZDC1 transport)** chains many tiny (e.g. 0.00001 ZCL) shielded outputs, each memo
  carrying one **frame**, to move an arbitrary byte stream across the 512-byte limit.
- **L3 (application AEAD)** adds an *independent* libsodium ChaCha20-Poly1305 layer under a
  per-transfer symmetric key, so that (a) you can publish ciphertext now and reveal the key
  later, (b) a break in L1 does not cascade into L3, and (c) one ciphertext can be opened by
  N recipients (one KEY frame each).

The codec implements **L2 and L3**. L0/L1 belong to the daemon's existing Sapling path; the
codec output (a list of 512-byte memos) is fed straight into `z_sendmany`.

---

## 3. The wire format (ZDC1 frame)

Each Sapling memo = exactly one frame: **32-byte header + 480-byte payload**, all multi-byte
fields big-endian. (Constants verified against `src/zcash/Zcash.h:17` `ZC_MEMO_SIZE=512`.)

```
off len field         notes
0   4   magic         0x5A444331 "ZDC1"
4   1   version       0x01
5   1   type          0x01 START | 0x02 DATA | 0x03 END | 0x04 KEY
6   1   flags         bit0 = payload is L3 ciphertext
7   1   cipher_id     0x00 none | 0x01 ChaCha20-Poly1305
8   8   transfer_id   random 64-bit (or a ZSLP token_id); separates concurrent transfers
16  4   seq           DATA chunk index 0-based; START=0; END=chunk_count
20  4   chunk_count   total DATA chunks (authoritative in START)
24  2   payload_len   0..480 valid bytes in this frame
26  4   crc32         CRC-32 over the 480B payload field — TRANSPORT integrity ONLY
30  2   reserved      0
32  480 payload       L3 ciphertext (DATA/START/END) or raw key (KEY)
```

**Frame roles:**
- **START** — payload = AEAD-encrypted `TransferMeta` `{filename, content_type,
  total_plaintext_size, chunk_count}`. Carries the authoritative `chunk_count`.
- **DATA** — payload = AEAD-encrypted plaintext chunk. **464 plaintext bytes/frame**
  (480 payload − 16-byte Poly1305 tag).
- **END** — payload = AEAD-encrypted SHA-256 of the *full plaintext*. The content-hash anchor.
- **KEY** — payload = the raw 32-byte per-transfer key. Distinct frame so reveal-later is
  first-class; its on-chain confidentiality is the Sapling L1 encryption to the recipient.

**On-chain efficiency** (from real constants, `ZDC1_CODEC_SPEC.md`): 948 on-chain
bytes per 480-byte frame (≈1.975× expansion); the **200 KB block** (`consensus.h:27`) is the
binding throughput limit, ~210 outputs/block, ~0.5 MB/hr best case. **This is why we cap.**

---

## 4. Security model (why "tested" matters)

All security properties below are exercised by `src/datachannel/test/zdc_test.cpp`
(260 checks, all passing, no gtest). Build + run:

```
g++ -std=c++11 src/datachannel/zdc.cpp src/datachannel/test/zdc_test.cpp -lsodium -o /tmp/zdc_test && /tmp/zdc_test
```

### 4.1 AEAD nonce uniqueness (the catastrophic case)
ChaCha20-Poly1305-IETF nonce = 12 bytes; reuse under one key is catastrophic. We make reuse
**impossible by construction**:

- **Key** is fresh per transfer (32 bytes from `randombytes_buf`). So uniqueness reduces to:
  every L3-encrypted frame in ONE transfer must use a distinct 32-bit counter.
- **Nonce = `transfer_id`(8 BE) || `nonce_ctr`(4 BE)`**, where `nonce_ctr` is a per-frame
  **counter**, NOT the wire `seq`:
  - `DATA[i]` -> `i`  (`0 .. chunk_count-1`, `<= 65534`)
  - `START`   -> `0xFFFFFFFF`
  - `END`     -> `0xFFFFFFFE`
  - `KEY` is not L3-encrypted, so it consumes no counter.

> **Why not just use `seq`?** START carries `seq=0` and DATA chunk 0 also carries `seq=0`; using
> the raw wire field would collide their nonces under the same key — catastrophic. The reserved
> high-counter band for the singleton control frames removes the collision deterministically,
> proven for the multi-chunk AND the empty-transfer (`chunk_count==0`) case.

### 4.2 Key handling
Per-transfer 32-byte key from a CSPRNG; never reused across transfers; never logged
(`status_str()` never emits key bytes). The KEY frame carries it, or it travels out-of-band.

### 4.3 Integrity — three distinct mechanisms, do not conflate them
- **Per-chunk Poly1305 tag (SECURITY).** Any flipped byte in ciphertext, tag, or AAD fails
  decryption with `ERR_AEAD_FAIL`. Tested over every byte position.
- **Overall PLAINTEXT hash (SECURITY).** After reassembly+decrypt we recompute SHA-256 over
  the plaintext and `sodium_memcmp` it against the END frame's value. A grafted-but-validly-
  encrypted chunk from another transfer is caught here (`ERR_HASH_MISMATCH`).
- **CIPHERTEXT fingerprint (NFT ANCHOR, verify-before-decrypt).** `ciphertext_fingerprint()`
  computes SHA-256 over the concatenated DATA-frame ciphertext payloads in seq order
  (order-independent over the input frame vector). This is what the MINT path puts on-chain as
  the ZSLP `document_hash` (`CONTENT_MODEL.md` §2.6 — "the anchor is over CIPHERTEXT"), so the
  public token cryptographically commits to the private bytes, and ANY node can verify the
  received frames match the on-chain anchor BEFORE possessing the key. A flipped ciphertext
  byte changes the anchor (tamper visible pre-decrypt; tested).
- **Header CRC-32 (TRANSPORT ONLY).** Detects corruption / foreign data so we can cheaply
  ignore non-ZDC1 memos. **It is NOT security** — an attacker who edits a payload simply
  recomputes the CRC. The test deliberately fixes the CRC after tampering and confirms the
  AEAD layer still rejects it.

### 4.4 AAD binds the frame's role
The AEAD associated data = the 32-byte header with `crc32` and `payload_len` zeroed (so
encoder and decoder compute it identically). This binds version/type/transfer_id/seq/
chunk_count/flags/cipher. A reordered or relabelled frame (e.g. DATA seq 0 rewritten to claim
seq 1) decrypts under the wrong nonce-counter + wrong AAD and fails (`ERR_AEAD_FAIL`, tested).

### 4.5 Key-reveal ordering (seal then reveal)
A transfer can be *structurally complete but sealed*: `is_complete()==true` while
`have_key()==false`. `assemble()` returns `ERR_NO_KEY` and never yields plaintext until the
KEY frame arrives (or `set_key()` is called out-of-band). A wrong key fails AEAD, never
returns garbage. All tested.

### 4.6 Reassembly robustness (the chain is unordered)
`mapWallet` iterates by txid hash, not block order, so the decoder is seq-keyed and order-
independent. Tested: out-of-order delivery, duplicates (first wins), missing chunks
(`missing_chunks()` + `ERR_INCOMPLETE`), truncated buffers (`ERR_TRUNCATED`), and ordinary
text / `0xF6` memos (`ERR_BAD_MAGIC` = "not for me, ignore").

### 4.7 Size caps (responsibility, not just performance)
`MAX_CHUNK_COUNT = 65535` (≈29 MB structural ceiling) bounds a hostile START's allocation;
oversize transfers are rejected with `ERR_OVERSIZE`. Callers MUST impose far tighter limits
(the as-built daemon caps a transfer at 40000 bytes; see `NATIVE_NFT_GUIDE.md §3.3`). Every memo is stored by every full node
**forever** — the cap is about not bloating a 200 KB-block chain.

---

## 5. The codec API (`src/datachannel/zdc.h`)

Pure logic. Depends ONLY on libsodium + the C++11 std lib. No daemon, chain, Qt, or globals.
Builds standalone for tests AND inside the daemon (C++11 `-noext`, libsodium already linked —
`configure.ac:68,783`).

```cpp
// --- L3 AEAD primitives ---
zdc::ZdcAead::generate_key(key);                 // 32 CSPRNG bytes, per transfer
zdc::ZdcAead::sha256(data, len, out32);          // plaintext content hash

// --- NFT on-chain anchor (verify-before-decrypt; over CIPHERTEXT) ---
zdc::ciphertext_fingerprint(frames, out32);      // ZSLP document_hash = this

// --- encode: plaintext -> a list of 512-byte memo frames ---
zdc::Encoder::encode(transfer_id, key, plaintext, meta,
                     include_key_frame, frames_out);   // START,DATA*,END[,KEY]
zdc::Encoder::encode_key_frame(transfer_id, key, chunk_count, frame_out); // reveal-later

// --- decode: feed memos in any order, then assemble ---
zdc::Decoder d;
for (each decrypted 512B memo) d.add_frame(memo);  // BAD_MAGIC => ordinary memo, skip
d.is_complete();                                   // START+END+all DATA (key not required)
d.have_key();                                      // sealed vs openable
d.set_key(key_out_of_band);                        // OR an on-chain KEY frame supplies it
d.assemble(out_plaintext, out_meta);               // AEAD + content-hash verified
```

Status codes are explicit (`zdc::Status`, `status_str()`); `OK==0`, all failures negative.

---

## 6. Honest privacy limits (do not oversell)

Hidden (strong, consensus-backed):
- **Memo contents** — Sapling-encrypted to `ivk` (L1) AND app-AEAD'd (L3).
- **Sender, recipient, amount** — zk-SNARK shielded (L0).
- **File metadata** (name, type, size, hashes) — inside the encrypted START/END frames.

Observable (the leakage — state it plainly):
- **Number of outputs/txs => approximate transfer size.** A burst of 21 tiny shielded txs ≈
  "~1 MB transfer." Large transfers are conspicuous (many outputs).
- **Timing** — a burst of tiny shielded txs across consecutive blocks is a distinct signature.
- **Existence** — "a shielded tx occurred" and "these outputs all carry max-size memos" is
  visible; an all-max-memo pattern hints "data channel" vs ordinary payment.
- **Fee-source linkage** — funding from a transparent address deanonymizes the *sender*. Fund
  from shielded inputs; use a single-use recipient address per transfer.

Permanence: **every memo is stored by every full node forever.** Encrypted, but undeletable.
This is a governance/liability surface (illicit-content storage, unbounded growth on a small
chain). Hence: default-OFF, opt-in consent, hard 40000-byte per-file cap (`ZDC_MAX_FILE_BYTES`),
single shielded tx per transfer, an inflight cap (`ZDC_MAX_INFLIGHT = 256`) + 72h TTL, and a
basic rate guard.

**No consensus enforces any of this.** It is wallet/application policy. `"Private"` means
*confidential*, not *undetectable*.

---

## 7. Daemon + GUI wiring (designed; not implemented here)

**Daemon (`/home/rhett/github/zclassic`):**
- The send path already accepts raw binary memos as hex — `get_memo_from_hex_string`
  (`src/wallet/asyncrpcoperation_sendmany.cpp:1321-1343`) copies bytes verbatim; no builder
  change. Each `zdc::Encoder` frame becomes one recipient `{address, 0.00001, memo=hex(frame)}`.
- `z_listreceivedbyaddress` already emits the full memo as a hex string
  (`HexStr(...)`, `src/wallet/rpcwallet.cpp:3374,3388`). The receive path hex-decodes each
  memo to 512 raw bytes and calls `zdc::Decoder::add_frame`. `ERR_BAD_MAGIC` => ordinary memo.
- RPCs (built, default-OFF behind `-datachannel`): `z_senddatafile` / `z_listdatatransfers` /
  `z_getdatatransfer`, enforcing the caps above. (There is no `z_receivedatafile` — receive is
  folded into `z_listdatatransfers` + `z_getdatatransfer`.)

**GUI (`/home/rhett/github/zcl-qt-wallet`) — the binary-safe read path (design only):**
The current code at `src/rpc.cpp` (~756-790) is **lossy** for ZDC1: it does
`QString::fromStdString(memo_hex)`, then for non-`f600` memos
`QString(QByteArray::fromHex(...))`. Routing binary frame bytes through `QString` corrupts
them (invalid UTF-8 => replacement chars), and the `startsWith("f600")` guard also drops the
empty-memo marker. **Design:** keep the decoded bytes as a `QByteArray` and branch BEFORE any
`QString` conversion:

```cpp
QByteArray raw = QByteArray::fromHex(QByteArray::fromStdString(i["memo"].get<json::string_t>()));
if (raw.size() == 512 && (quint8)raw[0]==0x5A && (quint8)raw[1]==0x44
                      && (quint8)raw[2]==0x43 && (quint8)raw[3]==0x31) {   // "ZDC1"
    // binary-safe path: hand raw.constData()/raw.size() to the ZDC1 receive handler.
    routeDataChannelFrame(zaddr, raw);
} else {
    // existing text path, unchanged:
    QString memo(raw);
    if (!memo.trimmed().isEmpty()) memos[zaddr + txid] = memo;
}
```

This adds a parallel binary path without touching the text inbox behaviour. (C++14-only
features are banned in the GUI — `gui-cpp14-constraint`; the snippet uses none.)

---

## 8. Private NFT, end to end

1. **Mint:** pick a `transfer_id` (a random 64-bit id, or the ZSLP `token_id`). `generate_key`.
   `Encoder::encode(...)` the asset bytes -> frames. Set the ZSLP genesis `document_hash` =
   `ciphertext_fingerprint(frames)` so the public token commits to the private CIPHERTEXT
   (verify-before-decrypt anchor; `CONTENT_MODEL.md` §2.6). Broadcast frames as shielded
   outputs to the owner zaddr (`z_sendmany`).
2. **Hold/own:** ownership = holding the 32-byte key (+ the ZSLP UTXO for public provenance).
   The recipient `Decoder`s the memos; `assemble()` verifies AEAD + content hash before any
   bytes are trusted.
3. **Seal-then-reveal:** mint with `include_key_frame=false`; the asset is on-chain but
   unopenable until you broadcast the KEY frame (or hand the key over out-of-band).
4. **Selective disclosure:** share the Sapling *incoming viewing key* to let an auditor read
   the memos (prove contents/receipt) without granting spend authority.
5. **Transfer:** re-deliver the key to the new owner (out-of-band = instant/free; or a single
   KEY-frame tx). Honest limit: pure key-possession cannot stop a prior holder keeping a copy
   — the chain proves the fingerprint and (via ZSLP UTXO conservation) who holds the 1-of-1
   token, never the pixels. **No DRM, no anti-copy.** State this in the UI.

---

## 9. Files

- `src/datachannel/zdc.h` — codec API + full security-model header doc.
- `src/datachannel/zdc.cpp` — implementation (C++11, libsodium only).
- `src/datachannel/test/zdc_test.cpp` — standalone harness, 260 checks (no gtest).
- `doc/nft/ZDC1_CODEC_SPEC.md` — codec wire + crypto spec.
- `doc/nft/CONTENT_MODEL.md` — content-addressing / fingerprint anchor for any-size files.
