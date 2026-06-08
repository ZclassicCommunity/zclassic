# ZDC1 Codec — Implementation-Ready Specification

> **REMOVED — HISTORICAL DOCUMENT.** The ZDC1 shielded data-channel codec and its RPCs
> (`z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer`, the `-datachannel` option) have
> been **removed entirely** from the ZClassic daemon. ZClassic deliberately provides **no wallet
> path to store arbitrary files on-chain**. This spec is retained for historical traceability
> only; it does not describe any shipping feature.

**Scope:** the exact, byte-level format and crypto the implementer codes to for the
ZClassic Shielded Data Channel (ZDC1). This is the **codec** only: pure logic, no
daemon/chain/Qt dependency, depends only on **libsodium + C++11**. It lives at
`src/datachannel/zdc.{h,cpp}` and compiles both standalone (`g++ -std=c++11
... -lsodium`) for unit tests and unchanged into the daemon (which already builds
`-std=c++11 -noext` and links `-lsodium`; `configure.ac:68,783`).

Refines, does not contradict, `PRIVACY_STACK.md` (and `CONTENT_MODEL.md`). Read those for the
throughput/cost/governance analysis; this file is the wire + crypto contract.

> **NON-CONSENSUS.** Rides the existing Sapling shielded pool + 512-byte encrypted
> memo (`ZC_MEMO_SIZE`, `src/zcash/Zcash.h:17`) with no validation, builder, or
> opcode change. The send path already accepts raw binary memo bytes
> (`get_memo_from_hex_string`, `asyncrpcoperation_sendmany.cpp:1321-1343`).

---

## 0. Layer model (what is whose job)

```
  L0  Sapling shielded pool       consensus zk-SNARK privacy            NOT this code
  L1  Sapling per-output memo      512B, ChaCha20-Poly1305 to ivk       NOT this code
  L2  ZDC1 transport               framing + reassembly + ordering      this codec
  L3  ZDC1 application AEAD         per-transfer key, per-chunk Poly1305 this codec
```

L0/L1 already guarantee only the recipient (holder of the incoming viewing key)
can read a memo at all. ZDC1 adds an **independent** application-layer AEAD so that
(a) ciphertext can be published now and the key revealed later, (b) a break in one
layer does not cascade, (c) one ciphertext can be opened by N recipients.

---

## 1. The frame — 32-byte header + 480-byte payload (512 = one memo)

All multi-byte fields **big-endian** (network order). One memo = exactly one frame.

```
 off  len  field         notes
  0    4    magic         0x5A444331  "ZDC1"
  4    1    version       0x01
  5    1    type          0x01 START | 0x02 DATA | 0x03 END | 0x04 KEY
  6    1    flags         bit0 = payload_is_ciphertext (L3-AEAD); rest reserved 0
  7    1    cipher_id     0x00 none | 0x01 ChaCha20-Poly1305-IETF
  8    8    transfer_id   random 64-bit; separates concurrent transfers
 16    4    seq           chunk index; START=0, DATA=0..N-1, END=chunk_count
 20    4    chunk_count   total DATA chunks; authoritative in START and END
 24    2    payload_len   0..480 valid bytes in this frame's payload
 26    4    crc32         CRC-32/IEEE over the FULL 480-byte payload field
 30    2    reserved      0 (rejected if non-zero)
 32  480    payload       data, zero-padded past payload_len
```

Usable payload = **480 B/frame**. After the L3 16-byte AEAD tag, usable
**plaintext per DATA chunk = 464 B** (`DATA_PLAINTEXT_PER_FRAME`). Header overhead
= 32/512 = 6.25%; with the tag, plaintext efficiency = 464/512 = 90.6%.

`crc32` is **transport integrity only** — corruption / foreign-data detection. It
is **NOT a MAC** and provides **no tamper-evidence**; the L3 Poly1305 tag is the
security check. The crc covers the whole padded 480-byte field so a flipped pad
byte is still caught at transport.

### 1.1 Frame semantics

| type | payload (plaintext, before L3) | seq | nonce_ctr | cipher |
|---|---|---|---|---|
| **START** 0x01 | `TransferMeta` blob (below) | 0 | `0xFFFFFFFF` | ChaCha20P |
| **DATA** 0x02 | up to 464 B of content | `i` (0..N-1) | `i` | ChaCha20P |
| **END** 0x03 | `SHA-256(full plaintext)` 32 B | `chunk_count` | `0xFFFFFFFE` | ChaCha20P |
| **KEY** 0x04 | the raw 32-byte transfer key | 0 | — | NONE (L1 protects it) |

`TransferMeta` blob (the START plaintext, big-endian, bounds-checked parse):

```
 off  len  field
  0    8    total_plaintext_size  u64 (exact reassembled byte length)
  8    4    chunk_count           u32
 12    2    filename_len          u16
 14   ...   filename              (filename_len bytes, may be 0)
 ..    2    content_type_len      u16
 ..   ...   content_type          (content_type_len bytes, may be 0)
```
Total must fit `DATA_PLAINTEXT_PER_FRAME` (464 B) or `encode` returns `ERR_OVERSIZE`.

---

## 2. Chunking

`chunk_count = ceil(len / 464)`. A **zero-length** payload is valid: 0 DATA frames,
producing `START, END[, KEY]`. DATA chunk `i` carries `plaintext[i*464 .. )`, the
last possibly short. Each chunk is independently AEAD-sealed (no cross-chunk
chaining) so out-of-order arrival, partial fetch, and per-chunk verification all
work without holding the whole transfer.

---

## 3. AEAD — ChaCha20-Poly1305 IETF (libsodium)

- **Primitive:** `crypto_aead_chacha20poly1305_ietf_{encrypt,decrypt}`. Key 32 B,
  nonce 12 B, tag 16 B. Ciphertext layout = `plaintext || tag` (combined mode).
- **Key:** per-transfer, 32 bytes from `randombytes_buf` (CSPRNG).
  **Never reused across transfers. Never logged.** `ZdcAead::generate_key`.

### 3.1 Nonce — guaranteed unique per chunk (the catastrophic-if-wrong part)

ChaCha20-Poly1305 nonce reuse under one key is catastrophic: the keystream repeats
(XOR of two plaintexts leaks) **and** the one-time Poly1305 key repeats (forgery).
AAD does **not** change the keystream, so binding different AAD does **not** rescue
a reused (key, nonce).

The key is fresh per transfer, so uniqueness reduces to: every L3-sealed frame in
one transfer uses a distinct 12-byte nonce. We derive it **deterministically**:

```
  nonce[12] = transfer_id (8 B, big-endian) || nonce_ctr (4 B, big-endian)
```

`nonce_ctr` is a **per-frame counter unique within the transfer**, and is **NOT**
the wire `seq` (START seq 0 and DATA[0] seq 0 would collide). The role→counter map
reserves the top of the 32-bit range for the singleton control frames:

```
  DATA chunk i  ->  nonce_ctr = i            (0 .. chunk_count-1, <= 65534)
  START         ->  nonce_ctr = 0xFFFFFFFF
  END           ->  nonce_ctr = 0xFFFFFFFE
  KEY           ->  (not L3-encrypted; consumes no counter)
```

Collision-free **by construction**: DATA counters are bounded by
`MAX_CHUNK_COUNT = 65535`, far below the reserved band. **Why deterministic and
not random per-chunk:** (a) saves no payload bytes carrying a nonce; (b) uniqueness
is *provable* and unit-testable rather than probabilistic; (c) a 96-bit random
nonce only has ~birthday-bound safety, unnecessary when we already have a unique
counter. Proven by `test_nonce_uniqueness` (across sizes incl. the 1-chunk case
where the naive `seq` scheme reuses counter 0).

### 3.2 AAD — header binding

AAD for every L3 op = the 32-byte serialized header **with `crc32` and `payload_len`
zeroed** (crc is computed after sealing; the AEAD tag already covers ciphertext
length). This binds `version | type | transfer_id | seq | chunk_count | flags |
cipher_id | reserved` — everything that defines the frame's **role** — so a
**reordered** (changed seq), **retyped** (DATA↔START), or **cross-transfer**
(changed transfer_id) frame fails the tag. Tested in `test_aead_tamper_and_aad`.

### 3.3 Integrity, three independent checks

1. **Per-chunk Poly1305 tag** (security) — any flipped ciphertext/tag/AAD byte ⇒
   `ERR_AEAD_FAIL`. Even if an attacker re-fixes the transport crc, the tag catches
   it (`test_tamper_in_transit_detected`).
2. **Overall content hash** — END carries `SHA-256(full plaintext)`; after
   reassembly+decrypt the decoder recomputes and compares ⇒ `ERR_HASH_MISMATCH` on
   mismatch. Also cross-checks `total_plaintext_size`.
3. **Transport crc32** — corruption detection at the frame boundary, before any
   crypto (`ERR_BAD_CRC`). NOT security.

### 3.4 NFT fingerprint anchor (over CIPHERTEXT)

`doc/nft/CONTENT_MODEL.md` commits the on-chain anchor to **ciphertext** (verify-
before-decrypt). The END plaintext hash above is an internal integrity check; the
**on-chain `document_hash`** is computed by `ciphertext_fingerprint(frames)` =
`SHA-256` over the concatenated DATA-frame ciphertext payloads, in seq order. This
lets the MINT path set `document_hash = ciphertext_fingerprint(...)` so the public
ZSLP token cryptographically commits to the private bytes, and lets any node verify
the committed bytes **without the key**. Tested in `test_ciphertext_fingerprint`.

---

## 4. KEY frame + reveal modes

The KEY frame's payload is the **raw 32-byte key**, `cipher_id = NONE`. Its on-chain
confidentiality is the **Sapling memo encryption (L1)** to the recipient's ivk — it
is not double-sealed under itself (that would be circular). It is a distinct frame
type so reveal-later is first-class and the decoder can show "key seen / sealed".

- **(a) In-band, same/next tx** — KEY as another shielded output now. Atomic.
- **(b) Reveal-later** — broadcast START/DATA/END now; send KEY after N confirms.
  Content is **undecryptable even by the recipient** until KEY arrives
  (`assemble` returns `ERR_NO_KEY` while content-complete-but-sealed;
  `test_seal_then_reveal`).
- **(c) Out-of-band** — deliver the key via Signal/QR/PGP; `Decoder::set_key`.
  Nothing key-related on chain (`test_oob_key`).

---

## 5. Reassembly, ordering, integrity (decoder)

Frames arrive in **arbitrary order** — `mapWallet` iterates by txid hash, never
block/insertion order, so chain order is **never trusted**. The `Decoder`:

1. `add_frame(memo, 512)` → `parse_header`. Non-ZDC1 ⇒ `ERR_BAD_MAGIC` (caller
   routes it to the text inbox). Then verify transport crc (`ERR_BAD_CRC`).
2. **Transfer lock:** first valid frame fixes `transfer_id`; a differing
   `transfer_id` ⇒ `ERR_BAD_STATE`. One `Decoder` == one transfer.
3. **Store by seq.** DATA in `map<seq, ciphertext>`. **Duplicate seq:** first wins,
   dup ignored (replay / multi-address delivery). **DATA seq ≥ chunk_count** ⇒
   `ERR_BAD_STATE`.
4. **Complete** = START present AND END present AND every `seq ∈ [0, chunk_count)`
   present. `missing_chunks()` lists gaps for UI. Complete does NOT require the key.
5. **`assemble`** (needs complete + key): decrypt START meta, decrypt DATA in seq
   order, recompute + compare END hash, cross-check size. Returns the exact original
   bytes + meta, or a precise error. Idempotent, side-effect-free on stored frames.
6. **GC (caller's job):** expire incomplete `(zaddr, transfer_id)` after a TTL to bound
   memory against START-spam. **As built, the daemon uses a 72h TTL** and an inflight cap
   `ZDC_MAX_INFLIGHT = 256` (`src/rpc/datachannel.cpp:88-89`).

---

## 6. Size caps (responsibility, not just perf)

- `MAX_CHUNK_COUNT = 65535` DATA frames (codec structural ceiling so a hostile
  START cannot make the decoder allocate forever). `parse_header` rejects a
  `chunk_count` above this ⇒ `ERR_OVERSIZE`.
- `MAX_TRANSFER_BYTES = 65535 * 464 ≈ 29 MB` absolute ceiling. **Callers MUST set a
  far tighter policy cap** (the as-built daemon caps a transfer at 40000 bytes; see
  `NATIVE_NFT_GUIDE.md §3.3`); the codec ceiling only prevents pathological allocation.
- **Honest permanence:** every memo is stored by every full node FOREVER. Large
  transfers are conspicuous (many outputs ⇒ approximate size leaks). This is a
  confidentiality channel, not a steganographic or scalable file-transfer one.

---

## 7. Error taxonomy (`zdc::Status`)

| code | value | meaning | who raises |
|---|---|---|---|
| `OK` | 0 | success | — |
| `ERR_TRUNCATED` | -1 | memo < 512 B | add_frame |
| `ERR_BAD_MAGIC` | -2 | not a ZDC1 frame (ordinary text memo) | parse_header |
| `ERR_BAD_VERSION` | -3 | magic ok, version unknown | parse_header |
| `ERR_BAD_TYPE` | -4 | type not START/DATA/END/KEY | parse_header |
| `ERR_BAD_PAYLOAD_LEN` | -5 | payload_len > 480 | parse_header |
| `ERR_BAD_CRC` | -6 | transport corruption | add_frame |
| `ERR_BAD_CIPHER` | -7 | unsupported cipher_id | (reserved) |
| `ERR_AEAD_FAIL` | -8 | Poly1305 fail: tamper / wrong key / wrong AAD | decrypt |
| `ERR_OVERSIZE` | -9 | chunk_count / transfer over cap; meta too big | encode/parse |
| `ERR_INCOMPLETE` | -10 | missing START/END/DATA seq | assemble |
| `ERR_HASH_MISMATCH` | -11 | reassembled hash/size ≠ END | assemble |
| `ERR_NO_KEY` | -12 | complete but sealed (no key yet) | assemble |
| `ERR_BAD_STATE` | -13 | protocol misuse / foreign transfer_id | add_frame |
| `ERR_INTERNAL` | -14 | libsodium / invariant failure | any |

`status_str(Status)` returns a human string and **never logs key material**.

---

## 8. Public API (`src/datachannel/zdc.h`)

```cpp
namespace zdc {
  // transport
  uint32_t crc32(const uint8_t* data, size_t len);
  void   serialize_header(const FrameHeader& h, uint8_t* out /*>=32*/);
  Status parse_header(const uint8_t* in /*>=512*/, FrameHeader& out);

  // L3 AEAD (also usable directly)
  struct ZdcAead {
    static Status generate_key(std::vector<uint8_t>& key /*out 32B*/);
    static void   derive_nonce(uint64_t tid, uint32_t nonce_ctr, uint8_t out[12]);
    static Status encrypt(key, tid, nonce_ctr, aad, aad_len, pt, ct /*out*/);
    static Status decrypt(key, tid, nonce_ctr, aad, aad_len, ct, pt /*out*/);
    static Status sha256(const uint8_t* d, size_t n, uint8_t out[32]);
  };

  // encode a whole transfer -> ordered 512B frames (START,DATA*,END[,KEY])
  struct Encoder {
    static Status encode(uint64_t tid, const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& plaintext,
                         const TransferMeta& meta, bool include_key_frame,
                         std::vector<std::vector<uint8_t>>& frames_out);
    static Status encode_key_frame(uint64_t tid, const std::vector<uint8_t>& key,
                                   uint32_t chunk_count,
                                   std::vector<uint8_t>& frame_out);
  };

  // stateful reassembly (one Decoder == one transfer)
  class Decoder {
    Status add_frame(const uint8_t* memo, size_t len);  // any order, dups ok
    Status add_frame(const std::vector<uint8_t>& memo);
    Status set_key(const std::vector<uint8_t>& key);    // out-of-band key
    bool   is_complete() const;                          // START+END+all DATA
    bool   have_key() const;
    std::vector<uint32_t> missing_chunks() const;
    Status assemble(std::vector<uint8_t>& out_pt, TransferMeta& out_meta) const;
    uint64_t transfer_id() const;
  };

  // on-chain NFT anchor (SHA-256 over DATA ciphertext, key-independent)
  Status ciphertext_fingerprint(const std::vector<std::vector<uint8_t>>& frames,
                                uint8_t out[32]);
  const char* status_str(Status s);
}
```

### 8.1 Daemon integration points (no change to the codec)

- **Send:** chunk the (already L3-sealed) frames; each frame's 512 bytes go out as a
  Sapling output memo (the send path accepts raw binary up to `ZC_MEMO_SIZE` —
  `asyncrpcoperation_sendmany.cpp:1321-1343`). **As built, the whole transfer rides ONE
  shielded tx** (not a multi-tx fan-out): the daemon caps a transfer at
  `ZDC_MAX_FRAMES_PER_TX = 90` frames and `ZDC_MAX_FILE_BYTES = 40000` bytes
  (`src/rpc/datachannel.cpp:86-87`); larger files are rejected, not split across txs.
  No builder/consensus change.
- **Receive:** the decrypted memo bytes from `z_listreceivedbyaddress`
  (`rpcwallet.cpp:3338-3427`) feed `Decoder::add_frame`. NFT mint path sets ZSLP
  `document_hash = ciphertext_fingerprint(frames)`.

---

## 9. GUI binary-safe read path (design — DO NOT implement here)

**The bug** (`zcl-qt-wallet/src/rpc.cpp ~756-790`): memos are read as
`QString memo(QByteArray::fromHex(hexMemo))`, which **UTF-8-decodes** the bytes and
**loses** any non-UTF-8 byte. ZDC1 frames are binary; this silently corrupts them.

**Fix — a parallel binary-safe path, leaving the text inbox unchanged:**

1. Keep the **raw** memo as a `QByteArray`, do not coerce to `QString`:
   ```cpp
   QByteArray rawMemo = QByteArray::fromHex(
       QByteArray::fromStdString(i["memo"].get<json::string_t>()));
   ```
2. **Sniff the magic on the raw bytes** before any text handling:
   ```cpp
   static const char ZDC1_MAGIC[4] = {0x5A,0x44,0x43,0x31}; // "ZDC1"
   bool isZdc = rawMemo.size() == 512 && memcmp(rawMemo.constData(), ZDC1_MAGIC, 4) == 0;
   ```
3. **Route:** if `isZdc`, hand `rawMemo` (512 bytes) to the data-channel handler
   (which feeds `zdc::Decoder::add_frame`) and do **not** add it to the text memo
   map. Otherwise, keep today's behavior: skip `f600`, trim, store as text.
4. The data-channel handler keys `Decoder`s by `(zaddr, transfer_id)` (transfer_id
   = header bytes 8..15, big-endian), surfaces `is_complete()/missing_chunks()` as
   a progress UI, and gates "open" on `have_key()`.

This is **additive and binary-lossless**: ordinary text memos are untouched, ZDC1
frames are no longer mangled, and the codec (this spec) is the single source of
truth for parsing/decrypting them. The GUI is **C++14**; keep to that repo's
constraints (no `std::optional`/`string_view`; the codec header is C++11 so it links
into either).

---

## 10. Build & test

```
g++ -std=c++11 -Wall -Wextra src/datachannel/zdc.cpp \
    src/datachannel/test/zdc_test.cpp -lsodium -o /tmp/zdc_test && /tmp/zdc_test
```

Tiny self-contained CHECK harness (no gtest needed). **260 checks, 0 failures**;
clean under `-pedantic-errors -Wshadow -Wconversion` and under
`-fsanitize=address,undefined`. Coverage: header round-trip + endianness +
rejects, CRC vectors, AEAD round-trip, **nonce uniqueness** (incl. the 1-chunk
collision case), AAD binding (reorder/retype/cross-transfer fail), tamper
(ciphertext/tag/AAD/key) detection, transport-crc rejection, truncation, dup +
reorder + missing reassembly, foreign-transfer-id rejection, empty + maximal
payloads, seal-then-reveal, out-of-band key, size caps, frame-size invariant,
and the ciphertext fingerprint (deterministic, order-independent, verify-before-
decrypt, tamper-visible).
