# ZClassic Private NFTs & Shielded Data Channel

> **READ FIRST — honesty banner (2026-06-06).** This doc predates the build and oversells in places. As-built truth: (1) **NFT ownership is ALWAYS transparent/public** — the token rides a transparent dust UTXO, so who holds an NFT is on-chain and visible. "Private" here means only the data-channel **file contents** are confidential (encrypted), and even those are stored **permanently as public ciphertext on every full node**. There is **no "shielded ownership."** (2) The single-tx file cap is **40000 bytes** (not 64 KB). (3) **"Seal-then-reveal", `z_revealkey`, and `zslp_mint_private` are NOT built.** (4) Cross-wallet/cross-node receive does **not** work yet (the per-transfer key is sender-session-local — see task #117). Authoritative as-built contract: `NATIVE_NFT_GUIDE.md §3.3`; whole-feature status: `NFT_FINAL_REVIEW.md`.

**Status:** Codec BUILT + TESTED **and compiled into the daemon** (`src/Makefile.am:247,294`;
25 daemon gtests in `test_zdc.cpp`). The daemon RPCs `z_senddatafile` / `z_listdatatransfers`
/ `z_getdatatransfer` are **BUILT** (`src/rpc/datachannel.cpp:597-599`), **default-OFF** behind
`-datachannel` (the current daemon gate; `-experimentalfeatures` is NOT required by the as-built code — adding that second gate is a logged hardening option). The GUI binary-safe read path and native UX are still
DESIGNED here, not yet wired. Ships **default-OFF / opt-in** on its own experimental track,
decoupled from the beta release pipeline. *(NOTE: the as-built RPC surface differs from the
original design in §3 — there is no `z_revealkey`/`keymode` and no single `zslp_mint_private`
RPC; the as-built daemon always includes the KEY frame and returns the per-transfer key to the
sender, and the as-built per-file cap is 40000 bytes. The authoritative as-built contract is
`NATIVE_NFT_GUIDE.md §3.3`. §3 below is kept as the original design.)*

**Rides UNCHANGED consensus.** Every byte below sits on top of the Sapling
shielded pool and 512-byte encrypted memos that ZClassic consensus *already*
enforces. No soft fork, no hard fork, no new opcode, no builder change. The send
path already accepts a raw binary memo as hex (`get_memo_from_hex_string`,
`src/wallet/asyncrpcoperation_sendmany.cpp:1321`); we only choose what bytes go
in it.

This is the single canonical design. It supersedes and consolidates the four
working notes (`PRIVACY_STACK.md`, `ZDC1_CODEC_SPEC.md`, `PRIVACY_UX.md`, and the
API-surface design). Where those differ, **this document is authoritative**.

---

## Table of contents

1. [What privacy tech we enable — the 4-layer stack](#1-what-privacy-tech-we-enable)
2. [The ZDC1 codec spec](#2-the-zdc1-codec-spec)
3. [API — codec, daemon RPCs, GUI binary-safe memo path](#3-api)
4. [Native privacy UX](#4-native-privacy-ux)
5. [Honest privacy limits](#5-honest-privacy-limits)
6. [Build/test plan + implementation order](#6-buildtest-plan--implementation-order)

---

## 1. What privacy tech we enable

### 1.1 Plain language

ZClassic already moves money privately: a shielded (Sapling) transaction hides
**who sent**, **who received**, and **how much**, and it can carry a small
**private note** (a "memo") that **only the recipient can read**.

This feature turns that private-note capability into a general-purpose
**confidential delivery system**:

- **Private messages** — send a note up to ~4 KB in one transaction; only the
  recipient can decrypt it.
- **Private files** — send a file up to ~64 KB on-chain; bigger files go
  off-chain with a tiny on-chain encrypted fingerprint so the recipient can
  prove they got the right bytes.
- **Seal now, reveal later** — publish the encrypted content today and send the
  decryption key whenever you choose. Until you reveal the key, **even the
  recipient cannot open it**.
- **Private NFTs** — a publicly-trackable 1-of-1 ZSLP token whose *image/asset
  bytes are encrypted and delivered privately*. Anyone can see the token exists
  and changes hands; only a key-holder can see what it actually is.

Honest framing, in every screen: **confidential, not undetectable.** Observers
can still see *that* a private transfer happened, roughly *when*, and roughly
*how big*. And it is **permanent** — every full node stores every memo forever.

### 1.2 The 4-layer stack (technical)

The privacy is a stack. The bottom two layers are consensus-enforced and free;
the top two are the new codec (`src/datachannel/zdc.{h,cpp}`).

| Layer | What | Where | Enforced by |
|------|------|-------|-------------|
| **L0** | Sapling shielded pool — zk-SNARKs hide sender/recipient/amount | consensus | ZClassic consensus (NOT this code) |
| **L1** | Per-output 512-byte memo, ChaCha20-Poly1305-encrypted to recipient ivk | consensus | ZClassic consensus (NOT this code) |
| **L2** | **ZDC1 transport** — framing + chunking + reassembly across many memos | `zdc.{h,cpp}` | wallet/app policy |
| **L3** | **ZDC1 application AEAD** — independent ChaCha20-Poly1305 IETF under a per-transfer 32-byte key, per-chunk Poly1305 tag | `zdc.{h,cpp}` | wallet/app policy |

**Why two encryption layers (L1 and L3) and not one?** Three concrete wins:

1. **Seal-then-reveal.** L1 always encrypts to the recipient's ivk, so an ivk
   holder could open the memo the instant it lands. L3 adds an *independent*
   per-transfer key so the content stays sealed until the **KEY frame** (or an
   out-of-band key) arrives — even from the recipient.
2. **Layer isolation.** A break or key-compromise in one layer does not cascade
   into the other.
3. **One ciphertext, N recipients.** The same L3 ciphertext can be opened by
   several recipients, each handed the key via a separate KEY frame / channel,
   without re-encrypting the payload.

### 1.3 User capabilities (mapped to the stack)

- **Private message ≤ 4 KB, 1 tx** — L0+L1 carry the frames; L2 chunks; L3 seals.
- **Private file ≤ 64 KB on-chain** (responsible default cap; structural ceiling
  ~29 MB but DO NOT approach it — see §5). Larger = off-chain ciphertext + an
  on-chain encrypted fingerprint (`ciphertext_fingerprint`) per
  `CONTENT_MODEL.md`.
- **Seal-then-reveal-key** — encode with `include_key_frame=false`; broadcast or
  hand over the KEY frame later.
- **Private NFT** — encrypted asset bytes over ZDC1; ownership shielded; the
  public ZSLP 1-of-1 token commits to the private bytes via
  `document_hash = ciphertext_fingerprint(frames)` (verify-before-decrypt).
- **Selective disclosure** — share the Sapling **incoming viewing key** to let a
  third party prove contents/receipt **without spend authority**.

---

## 2. The ZDC1 codec spec

The codec is **pure logic**: libsodium + C++11 standard library only. No daemon,
no chain, no Qt, no globals, no exceptions across the boundary (only compile-time
`static_assert`s against libsodium's constants). It compiles standalone for unit
tests *and* into the daemon (`-std=c++11 -noext`, `-lsodium` already linked;
`configure.ac:68,783`).

> **One frame = one Sapling memo = 512 bytes.** Chain many tiny (0.00001 ZCL)
> shielded outputs, one frame each, to move an arbitrary encrypted byte stream.

### 2.1 Frame layout (frozen wire format)

512 bytes total = **32-byte header + 480-byte payload**. All multi-byte fields
are **big-endian**.

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0  | 4 | `magic` | `0x5A444331` = "ZDC1" |
| 4  | 1 | `version` | `0x01` |
| 5  | 1 | `type` | `START=0x01`, `DATA=0x02`, `END=0x03`, `KEY=0x04` |
| 6  | 1 | `flags` | bit0 `FL_CIPHERTEXT` = payload is L3 ciphertext |
| 7  | 1 | `cipher_id` | `0=NONE`, `1=ChaCha20-Poly1305-IETF` |
| 8  | 8 | `transfer_id` | u64; random or = ZSLP token_id |
| 16 | 4 | `seq` | u32; DATA index 0..N-1; END seq = chunk_count |
| 20 | 4 | `chunk_count` | u32; authoritative count of DATA frames |
| 24 | 2 | `payload_len` | u16, 0..480 |
| 26 | 4 | `crc32` | over the full 480-byte payload field — **TRANSPORT ONLY, NOT security** |
| 30 | 2 | `reserved` | must be 0 |

Constants (from `zdc.h`, asserted against sodium in `zdc.cpp`):
`MEMO_SIZE=512`, `HEADER_SIZE=32`, `FRAME_PAYLOAD=480`,
`AEAD_KEYBYTES=32`, `AEAD_NPUBBYTES=12`, `AEAD_ABYTES=16` (tag),
`CONTENT_HASH_LEN=32`.

**Usable plaintext per DATA frame** = `480 − 16 (tag)` = **464 bytes**
(`DATA_PLAINTEXT_PER_FRAME`).

### 2.2 Frame types & ordering

Order: `START, DATA*N, END[, KEY]`.

- **START** (`type=0x01`, `seq=0`): encrypted `TransferMeta` blob
  `{u64 total_plaintext_size, u32 chunk_count, u16 filename_len, filename,
  u16 content_type_len, content_type}` — must fit in 464 B.
- **DATA** (`type=0x02`, `seq=i`): one AEAD-sealed plaintext chunk, ≤464 B.
  Each chunk is sealed **independently** (no chaining) so out-of-order,
  partial, and per-chunk verification all work.
- **END** (`type=0x03`, `seq=chunk_count`): encrypted **SHA-256 of the full
  plaintext** — verified after reassembly (binds the stream).
- **KEY** (`type=0x04`, `seq=SEQ_KEY=0xFFFFFFFF`): the **raw 32-byte key**,
  `cipher_id=NONE`. *Not* L3-encrypted — its on-chain confidentiality is the L1
  Sapling-to-ivk encryption. A distinct type makes seal-then-reveal first-class
  and the key matters only at `assemble()` time.

`chunk_count = ceil(plaintext_len / 464)`. A zero-length payload is valid (0
DATA frames; START+END only).

### 2.3 AEAD, key, nonce, AAD — the security core

**This is the part that "tested" matters for.**

**Cipher:** `crypto_aead_chacha20poly1305_ietf` (combined mode,
ciphertext = plaintext ‖ 16-byte tag).

**Key:** 32 bytes from `randombytes_buf()`, **fresh per transfer**, never reused
across transfers, never logged.

**Nonce (12 B) — the non-negotiable.**
```
nonce = transfer_id(8 BE)  ‖  nonce_ctr(4 BE)
```
`nonce_ctr` is a **per-frame counter unique within the transfer**, and it is
**NOT the wire `seq`**:

| frame | nonce_ctr |
|-------|-----------|
| DATA chunk *i* | `i` (0 .. chunk_count-1, ≤ 65534) |
| START | `0xFFFFFFFF` (`NONCE_CTR_START`) |
| END   | `0xFFFFFFFE` (`NONCE_CTR_END`) |
| KEY   | (not L3-encrypted; consumes no counter) |

> **Why not `seq`?** A catastrophic nonce-reuse bug existed in an early draft:
> START used `seq=0` and DATA[0] used `seq=0`, so deriving the nonce from `seq`
> made them **share `(key, nonce)`** under one key — ChaCha20-Poly1305 nonce
> reuse leaks the plaintext XOR and breaks Poly1305 one-time authentication. The
> fix is the reserved-counter band above. Because the key is fresh per transfer
> and every counter within a transfer is distinct, **every `(key, nonce)` pair
> is unique by construction.** This is locked by `test_nonce_uniqueness` — keep
> that test as a **permanent CI regression gate** on any protocol change.

**AAD:** the 32-byte header **with `crc32` and `payload_len` zeroed**. It binds
`magic/version/type/flags/cipher_id/transfer_id/seq/chunk_count`, so a
reordered, retyped, or cross-transfer-grafted frame fails the Poly1305 check.

**Three distinct integrity mechanisms — do not conflate them:**

1. **Per-chunk Poly1305 tag** — the actual **security** check (tamper / wrong
   key / wrong AAD ⇒ `ERR_AEAD_FAIL`).
2. **Content binding** — END plaintext SHA-256 (internal, over **plaintext**)
   *and* `ciphertext_fingerprint` (on-chain anchor, over **ciphertext**). These
   are **two different hashes** for two different jobs (see §2.6).
3. **`crc32`** — **transport corruption detection only**, attacker-forgeable;
   any caller treating it as integrity is wrong. Tests prove this: a tampered
   ciphertext byte **with the crc re-fixed** still fails AEAD.

### 2.4 Reassembly (Decoder)

One `Decoder` == one transfer. Caller routes frames by `(zaddr, transfer_id)`.

- `add_frame()` accepts frames in **any order**; duplicates are ignored
  (first-wins). Non-ZDC1 memos return `ERR_BAD_MAGIC` so the caller treats them
  as ordinary text memos. The first valid frame **locks `transfer_id`**; a
  foreign id returns `ERR_BAD_STATE`.
- DATA frames stored in `map<seq, ciphertext>`.
- `is_complete()` ⇔ START + END + all DATA seqs in `[0, chunk_count)`. **Does not
  require the key** — you can be *complete-but-sealed*.
- `assemble()` requires complete **and** key. It decrypts START meta, concatenates
  and decrypts DATA in seq order, and verifies the END SHA-256 == sha256(plaintext)
  and the size cross-check.
- The codec holds **no clock and does no GC**. The **caller must** TTL-expire
  incomplete `(zaddr, transfer_id)` entries and impose a per-sender quota.

### 2.5 Size caps

- `MAX_CHUNK_COUNT = 65535` (`parse_header` rejects above ⇒ `ERR_OVERSIZE`).
- `MAX_TRANSFER_BYTES = 65535 × 464 ≈ 29 MB` — a **structural ceiling only** to
  stop a hostile START from allocating forever. **Callers MUST set a far tighter
  policy cap (64 KB default).** Do not raise the policy cap toward the ceiling
  without revisiting the all-node-permanent-storage governance question (§5).

### 2.6 NFT fingerprint anchor (`ciphertext_fingerprint`)

`ciphertext_fingerprint(frames, out32)` = SHA-256 over the concatenated **DATA
ciphertext** payloads (payload_len bytes each, in seq order). This is the
on-chain ZSLP `document_hash` anchor, per `CONTENT_MODEL.md §2.6`:

- **Over ciphertext, not plaintext**, so it is **key-independent** and stable
  before/after key reveal.
- Lets any node **verify-before-decrypt**: prove the received frames are exactly
  the committed bytes *without* possessing the key or revealing the plaintext.
- **Implementers must use `ciphertext_fingerprint()` for the ZSLP
  `document_hash`** — NOT the END plaintext hash. They are different by design;
  the END hash re-verifies plaintext integrity *after* key reveal.

### 2.7 Error taxonomy

14 stable codes via `status_str()` (never logs key material):
`OK=0`, `ERR_TRUNCATED`, `ERR_BAD_MAGIC`, `ERR_BAD_VERSION`, `ERR_BAD_TYPE`,
`ERR_BAD_PAYLOAD_LEN`, `ERR_BAD_CRC`, `ERR_BAD_CIPHER`, `ERR_AEAD_FAIL`,
`ERR_OVERSIZE`, `ERR_INCOMPLETE`, `ERR_HASH_MISMATCH`, `ERR_NO_KEY`,
`ERR_BAD_STATE`, `ERR_INTERNAL`.

---

## 3. API

Three layers, one composable core. The codec is the foundation that the daemon
RPCs, the GUI read path, and the private-NFT mint all call.

### 3.1 Codec public API (`src/datachannel/zdc.h`, namespace `zdc`)

Exact signatures from the live header:

```cpp
// --- L3 AEAD (low level, public + testable) ---
ZdcAead::generate_key(std::vector<uint8_t>& key /*out 32B*/) -> Status;
ZdcAead::derive_nonce(uint64_t transfer_id, uint32_t nonce_ctr,
                      uint8_t out_nonce[12]);
ZdcAead::encrypt(key, transfer_id, seq, aad, aad_len, plaintext, ct&) -> Status;
ZdcAead::decrypt(key, transfer_id, seq, aad, aad_len, ct, plaintext&) -> Status;
ZdcAead::sha256(const uint8_t* data, size_t len, uint8_t out[32]) -> Status;

// --- header / transport ---
crc32(const uint8_t* data, size_t len) -> uint32_t;          // transport only
serialize_header(const FrameHeader&, uint8_t out[32]);
parse_header(const uint8_t in[32], FrameHeader& out) -> Status;

// --- encode (bytes + meta -> frames) ---
Encoder::encode(uint64_t transfer_id, const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& plaintext, const TransferMeta& meta,
                bool include_key_frame,
                std::vector<std::vector<uint8_t>>& frames_out) -> Status;
Encoder::encode_key_frame(uint64_t transfer_id, const std::vector<uint8_t>& key,
                          uint32_t chunk_count,
                          std::vector<uint8_t>& frame_out) -> Status;

// --- decode / reassemble (one Decoder == one transfer) ---
Decoder::add_frame(const uint8_t* memo, size_t len) -> Status;   // any order, dup-safe
Decoder::add_frame(const std::vector<uint8_t>& memo) -> Status;
Decoder::set_key(const std::vector<uint8_t>& key) -> Status;     // out-of-band key
Decoder::is_complete() const -> bool;   // START+END+all DATA, key NOT required
Decoder::have_start()/have_end()/have_key() const -> bool;
Decoder::transfer_id()/chunk_count()/received_chunks() const;
Decoder::missing_chunks() const -> std::vector<uint32_t>;
Decoder::assemble(std::vector<uint8_t>& out, TransferMeta& meta) const -> Status;

// --- on-chain NFT anchor ---
ciphertext_fingerprint(const std::vector<std::vector<uint8_t>>& frames,
                       uint8_t out[32]) -> Status;   // = ZSLP document_hash
status_str(Status) -> const char*;
```

**Seal-then-reveal contract:** `include_key_frame=false` ⇒ `is_complete()` can be
true while `assemble()` returns `ERR_NO_KEY` until a KEY frame is accumulated or
`set_key()` supplies the key out-of-band.

### 3.2 Daemon RPCs (designed; default-OFF behind an opt-in flag)

These ride the existing `z_sendmany` binary-memo path **unchanged** — each
`encode()` frame becomes one shielded output's memo (0.00001 ZCL dust),
batched at the per-tx output budget. Keys are generated and held in the daemon;
the GUI never links libsodium.

- **`z_senddatafile(fromaddr, toaddr, datahex|filepath, opts)`**
  → `{transfer_id, key(hex — only for out-of-band/reveal-later), opids[]}`.
  `opts = {keymode: "inband"|"reveal-later"|"out-of-band", cap, metafilename,
  metamime}`. Validates `from` is shielded (sender privacy), `size ≤ cap`
  (default 64 KB; hard typed-override ceiling 256 KB), generates key via
  `ZdcAead::generate_key` and a CSPRNG `transfer_id`, calls `Encoder::encode`,
  maps frames → `z_sendmany` memos.
- **`z_revealkey(fromaddr, toaddr, transfer_id, keyhex)`** → `{opid}`.
  Builds one `Encoder::encode_key_frame` and sends it as a final memo — the
  seal-then-reveal trigger.
- **`z_listdatatransfers(zaddr?)`** → `[{transfer_id, complete, sealed,
  received/chunk_count, filename, mime, firstseen}]`. Scans decrypted memos
  (`z_listreceivedbyaddress`, on-demand decrypt), routes by
  `(zaddr, transfer_id)` into one `Decoder` each, reports
  `is_complete()`/`have_key()`/`missing_chunks().size()`.
- **`z_getdatafile(transfer_id, outpath?, keyhex?)`** → `{bytes|written, sha256,
  filename, mime}` via `Decoder::assemble`. `keyhex` for out-of-band mode.

**Private-NFT RPCs (ZSLP + ZDC1, combined):**

- **`zslp_mint_private({name, ticker, decimals:0, quantity:1,
  asset:datahex|filepath, documenturl?})`** — encrypts the asset, sets ZSLP
  genesis `document_hash = ciphertext_fingerprint(frames)`, broadcasts the ZSLP
  genesis `OP_RETURN` tx (`slp_build_genesis`, **unchanged**) **plus** a ZDC1
  transfer with `transfer_id = token_id`. Ownership = the ZSLP UTXO
  (public/transferable); content access = key possession (revealed on transfer).
  Validates: encoded script ≤ 223 B, `document_hash` exactly 32 B, asset ≤ cap.

Every send RPC enforces: shielded-funding (don't deanonymize the sender via a
transparent fee input), the 64 KB policy cap, a local rate limit, and TTL GC of
incomplete inbound transfers.

### 3.3 GUI binary-safe memo read path (design only)

**Confirmed bug** at `zcl-qt-wallet/src/rpc.cpp:755-758`:

```cpp
QString memo(QByteArray::fromHex(
                QByteArray::fromStdString(i["memo"].get<json::string_t>())));
```

Routing raw memo bytes through `QString` UTF-8-coerces them and **destroys any
non-UTF-8 / binary ZDC1 frame** (the `f600` empty-marker is the only special
case today).

**Fix (additive, binary-lossless, C++14-safe — no `std::optional`/`string_view`,
GUI is `c++14`-constrained):**

```cpp
QByteArray raw = QByteArray::fromHex(
        QByteArray::fromStdString(i["memo"].get<json::string_t>()));
// Sniff the 4-byte magic on RAW bytes, BEFORE any QString conversion.
static const char ZDC1_MAGIC[4] = {0x5A, 0x44, 0x43, 0x31};
if (raw.size() == 512 && memcmp(raw.constData(), ZDC1_MAGIC, 4) == 0) {
    // route raw bytes to the data-channel handler (feeds the daemon RPCs above)
} else {
    // existing text path, on a copy — never trim()/toUtf8 the binary branch
    if (!QString::fromStdString(i["memo"].get<json::string_t>())
             .startsWith("f600")) { /* ... unchanged ... */ }
}
```

**Recommended split (Option A): keys stay in the daemon.** The GUI only *detects*
the magic and routes; reassembly/decryption happens in the daemon via the §3.2
RPCs, so the GUI links no libsodium and never holds key material. The **text
inbox and the data-channel inbox stay separate surfaces.**

---

## 4. Native privacy UX

Don't-make-me-think, vocabulary-locked to `NATIVE_UX.md` ("sealed", "reveal the
key", "note" — never "memo"/"ivk"/"z-addr"). Reuse the existing delegate, the
green **Private** pill, and the image-match badge — **add no new visual
vocabulary.**

### 4.1 Send a private file / message

1. Pick recipient → attach file or type message.
2. A **live consequence table** maps size → outputs:
   `notes = ceil(size / 464) + 2` (START + DATA*N + END) → flat fee →
   balance-after.
3. Choose delivery: **Send the key with it** (inband) or **Seal it — reveal the
   key later** (reveal-later) or **I'll share the key myself** (out-of-band).
4. **The one non-negotiable honesty line, verbatim on the send screen:**
   > *Hidden: who it's from, who it's to, the amount, and the contents.
   > Visible: that a private transfer happened, roughly when, and roughly how
   > big. It is permanent.*

### 4.2 Receive

Three calm states, driven by `is_complete()` + `have_key()`:

- **Arriving** — frames still landing (`received/chunk_count`,
  `missing_chunks()`).
- **Waiting for the key** — complete but sealed (`ERR_NO_KEY` is the *calm* face
  of seal-then-reveal, never an error tone).
- **Ready** — `assemble()` succeeded; show file / message / NFT.

### 4.3 Reveal the key

One tap → `z_revealkey` → `encode_key_frame` → one tiny output. Plus an **"I have
a key"** paste field → `set_key` for out-of-band delivery.

### 4.4 Private NFT in the gallery & private mint

- **Gallery:** same green **Private** pill; same image-match badge via a local
  `assemble()` + the existing content engine. The fingerprint anchors the
  **ciphertext** (`CONTENT_MODEL.md`); the END frame binds the **plaintext** hash
  after key reveal.
- **Mint (NATIVE_UX tile A):** `transfer_id = ZSLP token_id`, so the public token
  commits to the sealed bytes. Default key delivery = **reveal-later or
  out-of-band** for anything sensitive.

### 4.5 Consent gate

Everything is **default-OFF**. First use shows a **one-time permanence +
metadata-leak consent dialog** stating §5 in plain words. No DRM, no anti-copy,
no consensus enforcement — say so.

---

## 5. Honest privacy limits

State these everywhere; never oversell. The codec **cannot** fix any of them.

- **Metadata leaks.** The **number of outputs ≈ transfer size**; the **timing**
  of the burst is a signature; the **existence of a shielded tx** is observable.
  An all-max-memo output run hints at a data channel. This is a
  **confidentiality** channel, **not steganographic / not undetectable**.
- **Sender deanonymization via fees.** A transparent fee input can deanonymize
  the sender even when the recipient is shielded → RPCs **enforce shielded
  funding**.
- **Permanence.** Every memo is stored by **every full node forever**,
  encrypted-but-undeletable. Size caps are about *responsibility*, not just
  performance.
- **KEY-frame caveat.** The in-band KEY frame ships the raw 32-byte key in
  cleartext at L3; its on-chain confidentiality relies **entirely on L1 Sapling
  encryption to the recipient's ivk**. A compromised ivk exposes the key, and
  in-band reveal commits the key on-chain at send time. **Out-of-band /
  reveal-later is the safer default** for sensitive content.
- **`crc32` is not security.** Transport corruption detection only,
  attacker-forgeable.
- **"Private" ≠ undetectable; no consensus enforces any of this.** It is all
  wallet/application policy, default-OFF, opt-in.
- **Abuse / governance surface.** Arbitrary encrypted bytes stored by every node
  forever is a real governance question. Caps + opt-in mitigate but do **not**
  remove it.

---

## 6. Build/test plan + implementation order

### 6.1 Current state (DONE)

- `src/datachannel/zdc.h` (337 lines — API + full security-model header doc).
- `src/datachannel/zdc.cpp` (C++11, libsodium only).
- `src/datachannel/test/zdc_test.cpp` — one canonical self-contained harness
  (no gtest dependency, so it runs anywhere).

**Reproduce the green build (no proot, no zclbuild, no daemon build):**

```sh
g++ -std=c++11 -pedantic -Wall -Wextra \
    src/datachannel/zdc.cpp src/datachannel/test/zdc_test.cpp -lsodium \
    -o /tmp/zdc_test && /tmp/zdc_test
# => 260 checks, 0 failures   RESULT: PASS
```

Also clean under `-pedantic-errors -Wshadow -Wconversion` (daemon-mode object)
and under `-fsanitize=address,undefined`.

**Test coverage:** header round-trip + endianness + rejects; CRC vector
`0xCBF43926` for `"123456789"`; AEAD round-trip; **nonce uniqueness** (incl.
START vs DATA[0] domain separation and the empty-transfer case); AAD
reorder/retype/cross-transfer rejection; per-byte tamper of
ciphertext/tag/AAD/key (crc re-fixed, proving crc ≠ security); truncation;
duplicate/reorder/missing reassembly; foreign-transfer-id rejection; empty and
maximal payloads; seal-then-reveal (`ERR_NO_KEY` then KEY frame); out-of-band
key; wrong-key; non-ZDC1/`f600` passthrough; size caps;
`ciphertext_fingerprint` determinism / order-independence / tamper-visibility.

### 6.2 Implementation order

1. **Land + CI-gate the codec — DONE.** `src/datachannel/*` is in `src/Makefile.am`
   (`:247,294`); daemon gtests in `test_zdc.cpp`. **Keep
   `test_nonce_uniqueness` as a mandatory CI gate** — it catches the single most
   dangerous failure mode and it already regressed once.
2. **Daemon send path — DONE.** `z_senddatafile` is built (`src/rpc/datachannel.cpp`),
   feeding `Encoder` frames into Sapling memos (no builder change); enforces shielded
   funding + the 40000-byte per-file cap + acknowledge_permanent. *(There is no
   `z_revealkey` in the as-built surface — the daemon always includes the KEY frame and
   returns the per-transfer key to the sender; seal-then-reveal is a designed, not-built
   option.)*
3. **Daemon receive path — DONE.** `z_listdatatransfers` + `z_getdatatransfer` are built,
   feeding the on-chain memos into `zdc::Decoder` with verify-before-decrypt; inflight GC
   via the 72h TTL + `ZDC_MAX_INFLIGHT=256` cap (the codec does no GC).
4. **GUI binary-safe read path** (§3.3) — sniff the 4-byte magic on the raw
   `QByteArray` before any `QString` conversion; route to a separate
   data-channel inbox; leave the text inbox untouched. Do this **after** the
   in-flight GUI build settles. C++14-safe.
5. **Native UX** (§4) — Send-Private-File, Private-Files inbox, reveal-key,
   private-NFT gallery + mint, reusing existing delegate/pill/badge.
6. **Private NFTs** — set ZSLP genesis
   `document_hash = ciphertext_fingerprint(frames)`; default to out-of-band /
   reveal-later key delivery.
7. **Consent gate** — default-OFF behind a one-time permanence + metadata-leak
   consent dialog.

### 6.3 Guardrails

- **Do NOT raise the policy cap toward the 29 MB structural ceiling** without
  revisiting the all-node permanent-storage governance question. **Do not enable
  multi-MB transfers.**
- Keep the feature on its own experimental track, **decoupled from the beta
  release pipeline**.
- **Do NOT edit `src/zslp/*` or any GUI source while the content-engine build is
  in flight** — those edits in `git status` are pre-existing, untouched here.
  Only `src/datachannel/*` and `doc/nft/*` are owned by this work.
- Keep the honest framing (§5) in **all** UI copy: confidential, not
  undetectable; permanent; no DRM; no consensus enforcement.
