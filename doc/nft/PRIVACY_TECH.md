# Privacy Technology in the ZClassic NFT Feature

> **REMOVED — HISTORICAL DOCUMENT.** The shielded data-channel / arbitrary-file-transfer
> capability described here (`z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer`, the
> `-datachannel` option, the ZDC1 codec) has been **removed entirely** from the daemon. ZClassic
> deliberately provides **no wallet path to store arbitrary files on-chain**. NFT content is
> always off-chain, bound to the token only by a `document_hash` fingerprint. This doc is retained
> for historical traceability only.

*What privacy technology are we enabling, and exactly what does it protect?*

This document is the canonical answer. It describes **one** privacy technology — the
**ZDC1 shielded data-channel** — and is scrupulously honest about what it does, what
it does **not** do, and what is built versus merely designed.

The coin is **ZClassic (ZCL)**. Every fee, dust output, and balance referenced here is
denominated in **ZCL**. (Some code identifiers carry their upstream Sapling/zk lineage
— `zclassicd`, `z_sendmany`, `.zcash-params`, `Sapling`, `ivk` — but the money a user
holds, sends, or sells for is always ZCL.)

Capability honesty tags used throughout:

| Tag | Meaning |
|-----|---------|
| **BUILT+TESTED** | Implemented and covered by automated tests. |
| **BUILT-CLI-ONLY** | Implemented and reachable from `zclassic-cli`, but no GUI and no automated end-to-end test. |
| **DESIGNED-NOT-BUILT** | Specified in design docs; no working code path today. |
| **FUTURE-IDEA** | Direction only; not specified or scheduled. |

---

## 1. What is private, and what is NOT (read this first)

There are exactly two things to keep separate. Do not let them blur.

### 1a. NFT ownership is PUBLIC. Always. No exceptions.

A ZSLP NFT is a token that rides on an ordinary **transparent dust UTXO**
(0.00001 ZCL). Consequently:

- **Who owns which NFT is fully visible on-chain.**
- **Every transfer of an NFT is fully visible on-chain** — the sending address, the
  receiving address, the token id, the time, all of it.
- Provenance (the complete chain of past owners) is public and permanent.

The data-channel described in this document does **not** shield ownership, does **not**
shield transfers, and does **not** anonymize who-holds-what. There is no
private/confidential/anonymous mode for NFT ownership in this feature, and there is no
plan to claim one. If anyone tells you ZSLP NFT ownership is private, they are wrong.

### 1b. The file CONTENT (the bytes) can be PRIVATE.

What the privacy technology actually protects is the **content of a file or message** —
the asset bytes behind an NFT, or any arbitrary payload you choose to send. Those bytes
are encrypted and can only be opened by a holder of the per-transfer key. This is
**BUILT+TESTED** at the codec layer.

So the one-sentence truth is:

> **The token says, in public, "this exists and this address owns it."
> The data-channel keeps the file's *bytes* confidential — and nothing else.**

### 1c. A subtlety you must not miss: the ciphertext is public forever

"Private content" means **encrypted content that nobody without the key can read**. It
does **not** mean the content is hidden from existence or deletable. The encrypted bytes
(the ciphertext) are stored by **every full node, permanently, undeletably**. Privacy
here is confidentiality of the plaintext, guaranteed by encryption — not erasure, not
unobservability, not deniability. See §4 for the metadata that still leaks.

---

## 2. How ZDC1 works, end to end

ZDC1 ("ZClassic Data Channel, version 1") moves an encrypted byte stream across many
**512-byte Sapling shielded memos**, one ZDC1 frame per memo. The codec lives in
`src/datachannel/zdc.{h,cpp}` and is pure logic (depends only on libsodium + the C++
standard library; no chain, no globals, no Qt).

### 2.1 The four-layer stack

ZDC1 deliberately stacks two independent encryption layers on top of the Sapling pool:

| Layer | What it is | Whose code | Crypto |
|-------|-----------|-----------|--------|
| **L0** | Sapling shielded pool | consensus (NOT this code) | zk-SNARKs hide sender/recipient/amount |
| **L1** | Per-output 512-byte memo | consensus (NOT this code) | ChaCha20-Poly1305 to the recipient's `ivk` |
| **L2** | ZDC1 transport | this code | framing / chunking / reassembly |
| **L3** | ZDC1 application AEAD | this code | ChaCha20-Poly1305 IETF, per-transfer 32-byte key |

Two encryption layers (L1 and L3) are intentional. They enable seal-then-reveal
(publish ciphertext now, hand out the key later), layer isolation (a break in one layer
does not cascade into the other), and one-ciphertext-to-many-recipients fan-out.

### 2.2 The crypto, named (BUILT+TESTED — 25 gtests in `src/gtest/test_zdc.cpp`)

- **AEAD cipher:** libsodium `crypto_aead_chacha20poly1305_ietf` in combined mode
  (ciphertext = plaintext ‖ 16-byte Poly1305 tag). Its size constants are
  `static_assert`ed against sodium at compile time (`zdc.cpp:22-25`). It is the *only*
  cipher implemented (`CIPHER_CHACHA20POLY1305 = 0x01`).
- **Per-transfer key:** 32 bytes from `randombytes_buf()`, fresh for every transfer,
  never reused, never logged (`ZdcAead::generate_key`). The decoder zeroizes it with
  `sodium_memzero` on destruct and on replace; the RPC registry wipes keys on
  TTL-expire.
- **Key derivation:** there is **no KDF**. The key is raw CSPRNG bytes, not derived from
  any wallet secret. This keeps L3 fully independent of the L1 Sapling `ivk` by design.
- **Nonce (the security-critical part):** 12 bytes = `transfer_id(8 BE) ‖ counter(4 BE)`.
  The counter is a per-frame value distinct from the wire `seq`: DATA chunk *i* → *i*;
  START → `0xFFFFFFFF`; END → `0xFFFFFFFE`; the KEY frame is not L3-encrypted and
  consumes no counter. Fresh-per-transfer key + a unique counter ⇒ every `(key, nonce)`
  pair is unique by construction. The reserved-counter band fixes a real prior
  nonce-reuse bug (START `seq` 0 vs DATA[0] `seq` 0 would otherwise collide). Locked by
  `TEST(ZDC, NonceUniqueness)`.
- **AAD:** the 32-byte frame header with `crc32` and `payload_len` zeroed. This binds
  magic/version/type/flags/cipher/`transfer_id`/`seq`/`chunk_count`, so a reordered,
  retyped, or cross-transfer-grafted frame fails Poly1305.

**Three integrity mechanisms — do not conflate them:**

1. **Per-chunk Poly1305 tag** — the *real* security check. Tamper or wrong key ⇒ fail.
2. **Content binding via two different hashes** — the END frame carries a SHA-256 over
   the **plaintext** (re-verified after decrypt), and the `ciphertext_fingerprint` is a
   SHA-256 over the concatenated **DATA ciphertexts** in `seq` order. The latter is the
   key-independent on-chain anchor (the ZSLP `document_hash`).
3. **`crc32`** — transport-corruption detection only. It is attacker-forgeable and is
   **not** security; tests prove a CRC-refixed tampered byte still fails the AEAD.

**The document_hash / ciphertext fingerprint anchor** (`ciphertext_fingerprint`,
`zdc.cpp:523`) hashes only the DATA frames' ciphertext in ascending `seq` order. It is
deterministic, order-independent, and **key-independent** — stable before and after the
key is revealed. This is what a ZSLP NFT `document_hash` commits to: it cryptographically
binds the **public** token to the **private** bytes without revealing them.

### 2.3 Send path (encrypt → frame → Sapling memos → on-chain)

A single dedicated async operation, `AsyncRPCOperation_senddatafile`
(`src/wallet/asyncrpcoperation_senddatafile.{h,cpp}`), does the whole send:

1. **Encode + encrypt.** The plaintext is chunked and each DATA chunk is AEAD-encrypted
   under the per-transfer L3 key (464 usable plaintext bytes per DATA frame: 480 payload
   − 16 tag). Frame order is START, DATA×N, END, then KEY.
2. **Frame → memo.** Each 512-byte ZDC1 frame becomes exactly one Sapling output memo
   (`512 == ZC_MEMO_SIZE`): a 32-byte header + 480-byte payload.
3. **One shielded transaction.** All N same-recipient Sapling outputs are emitted in a
   *single* shielded tx. (This needs the dedicated op because `z_sendmany`'s RPC layer
   rejects duplicate recipients; the underlying `TransactionBuilder` does not.) Each
   output carries 0.00001 ZCL dust; change returns shielded to the from-address. The
   tx is signed with the wallet's Sapling spending key — used only to spend and sign,
   **never exported**.
4. **Random transfer id.** The 8-byte `transfer_id` is random (libsodium), in-flight
   collision-checked. It is **not** the txid and **not** a token id.

### 2.4 Receive path (reconstruct → verify-before-decrypt)

A recipient wallet reconstructs the transfer **from the chain alone**, even with no
local session record (`datachannel.cpp:560-600`):

1. `GetFilteredNotes(requireSpendingKey=false)` lets a viewing-key-only wallet (one
   holding just an `ivk`) read its frames.
2. The `ivk` decrypts the L1 Sapling memos, exposing the ZDC1 frames.
3. The on-chain KEY frame populates the L3 key in the decoder.
4. **Verify before decrypt** gates the open (see §2.5).

**No `ivk` and no spending key ever leaves the wallet.** (Historical note: older docs —
`NFT_FINAL_REVIEW.md` and the honesty banner in `PRIVACY.md` — say cross-wallet receive
is "structurally impossible (#117)." That described a prior revision that hard-threw
"transfer not found in registry." The current code has applied the exact recommended
fix — a registry-free reconstruct path — so cross-wallet verify-then-open now works via
the recipient `ivk`. **The docs are stale on this point; the code is ahead of them.**
The remaining caveat is key *delivery*: the in-band KEY frame works today; out-of-band /
reveal-later is **DESIGNED-NOT-BUILT**.)

### 2.5 Verify-before-decrypt (the safety property) — and its honest failure modes

`z_getdatatransfer` recomputes the ciphertext fingerprint over the received DATA frames
and compares it to the expected anchor **before any decrypt happens**. It never returns
plaintext on failure (`datachannel.cpp:622-692`). The distinct, honest error codes:

| Error | Meaning |
|-------|---------|
| `ERR_HASH_MISMATCH` | On-chain ciphertext fingerprint ≠ expected anchor (caller's `verify_fingerprint`, or the recorded anchor). Refuses to decrypt; returns no plaintext. Also raised post-decrypt if the END plaintext SHA-256 cross-check fails. |
| `ERR_NO_KEY` | Frames complete, but no KEY frame is visible to this wallet (the caller is not the recipient, or the transfer is sealed). |
| `ERR_AEAD_FAIL` | Poly1305 failed — tamper or wrong key. |
| `ERR_INCOMPLETE` | Frames are still missing. |

### 2.6 End-to-end maturity

The **codec** (AEAD, nonce domain, AAD, fingerprint, reassembly, error taxonomy) is
**BUILT+TESTED**. The **end-to-end send/receive over a live chain** is **BUILT-CLI-ONLY**:
it works from `zclassic-cli`, but there is no GUI and no automated cross-RPC / regtest
seam test yet (`qa/` contains zero `z_senddatafile` usage). Treat live end-to-end as
working-but-unproven-by-automation.

---

## 3. RPC API reference (BUILT-CLI-ONLY)

All three RPCs are registered **only** when the daemon runs with `-datachannel`. When the
flag is off (the default — see §4), the RPCs are not registered at all, so the dispatcher
returns `RPC_METHOD_NOT_FOUND (-32601)` — indistinguishable from a method that never
existed (registration gate `datachannel.cpp:713-722`). `-experimentalfeatures` is **not** required by the
as-built code (adding a second gate is a logged hardening option).

CLI argument mapping (so `zclassic-cli` sends a JSON object, not a raw string) lives at
`src/rpc/client.cpp:138-139`.

### z_senddatafile  *(async — returns immediately; poll with `z_getoperationresult`)*

Defined at `datachannel.cpp:215`.

**Params** — a single object:

| Field | Type | Notes |
|-------|------|-------|
| `fromaddress` | string | Sapling z-address; spending key must be in this wallet (no watch-only send). |
| `toaddress` | string | Sapling z-address (the recipient). |
| `filepath` *or* `hexdata` | string | Exactly one. The payload, ≤ 40000 bytes. |
| `acknowledge_permanent` | bool | **Required, must be `true`.** Daemon refuses otherwise. |
| `filename` | string | Optional metadata. |
| `content_type` | string | Optional metadata. |

**Returns** (the immediate object):

| Field | Notes |
|-------|-------|
| `operationid` | Poll this with `z_getoperationresult`. |
| `transfer_id` | 16-hex random id. |
| `fingerprint` | 64-hex ciphertext anchor — the same value an NFT `document_hash` commits to. |
| `frames` | Number of Sapling outputs emitted. |
| `key` | Hex per-transfer L3 key, returned to the sender for selective disclosure. |

The async result later yields `{txid, transfer_id, fingerprint, frames}`.

**Enforces:** permanence ack; Sapling from-address with spending key in wallet; shielded
change; the 40000-byte cap; and a 90-frame single-tx guard. The cap is *derived*, not
wished: a transfer is one shielded tx, each frame is a 948-byte Sapling
`OutputDescription`, and consensus `MAX_TX_SIZE_AFTER_SAPLING = 102000` ⇒ ≤ 90 frames
(`ZDC_MAX_FRAMES_PER_TX`) = 87 DATA × 464 = 40368, advertised as 40000. Oversize is
rejected up front before any proving; a second guard in the async op re-projects the real
serialized size (including the actual spend count) so an unusual UTXO set never hits a
late `bad-txns-oversize`.

**Errors:** `RPC_INVALID_PARAMETER` (missing/false `acknowledge_permanent`, oversize
payload, both/neither of `filepath`/`hexdata`, encode failure); address/key errors for a
non-Sapling or watch-only from-address; `RPC_METHOD_NOT_FOUND (-32601)` when
`-datachannel` is off.

### z_listdatatransfers  *(okSafeMode)*

Defined at `datachannel.cpp:430`.

**Params:** none.

**Returns:** an array of `{transfer_id, fingerprint, direction ("sent"), frames, status
("recorded"), fromaddress, toaddress, filename}`.

**Scope caveat:** this is **session / in-memory only**. It lists what *this* node sent
*this session*; the registry is not persisted and entries expire on a 72-hour TTL. It is
**not** a chain query and **not** a list of what you have received.

### z_getdatatransfer  *(okSafeMode — reassemble + verify-before-decrypt)*

Defined at `datachannel.cpp:471`.

**Params** — a single object:

| Field | Type | Notes |
|-------|------|-------|
| `transfer_id` *or* `fingerprint` | string | 16-hex id, or 64-hex anchor. Identifies the transfer. |
| `address` | string | Optional. The z-address that received it; defaults to the recorded `toaddress`, else scans all viewable addresses. |
| `verify_fingerprint` | string | Optional 64-hex out-of-band anchor. If given, the on-chain ciphertext **must** hash to it or the call refuses. |

**Returns:**

| Field | Notes |
|-------|-------|
| `transfer_id`, `fingerprint` | Identity. |
| `verified` | bool — anchor matched. |
| `complete` | bool — all frames present. |
| `frames_received` | count |
| `onchain_fingerprint`, `expected_fingerprint` | Present for mismatch diagnosis. |
| `hexdata` | The plaintext — returned **only** if verified and decrypted. |
| `size`, `filename`, `content_type` | Payload metadata. |
| `error` | The honest codec error, if any (see §2.5). |

**Errors:** the §2.5 taxonomy (`ERR_HASH_MISMATCH`, `ERR_NO_KEY`, `ERR_AEAD_FAIL`,
`ERR_INCOMPLETE`); `RPC_METHOD_NOT_FOUND (-32601)` when `-datachannel` is off.

---

## 4. Guarantees, limits, threat model, and what still leaks

### Guarantees

- **Plaintext confidentiality** of file/message bytes, under a fresh per-transfer AEAD
  key (BUILT+TESTED).
- **Tamper-evidence** via per-chunk Poly1305 over header-bound AAD (BUILT+TESTED).
- **Verify-before-decrypt:** plaintext is never returned unless the on-chain ciphertext
  fingerprint matches the expected anchor (BUILT-CLI-ONLY).
- **Keys never leave the wallet:** the only secret returned to a caller is the
  per-transfer L3 key it asked the daemon to create. No `ivk` or spending key is exported.

### Limits / caps (policy, not consensus)

- **40000-byte file cap** per transfer (`ZDC_MAX_FILE_BYTES`). The structural codec
  ceiling is ~29 MB (`MAX_CHUNK_COUNT = 65535`) but must never be approached, for
  governance and permanence reasons.
- **256** max in-flight tracked transfers; **72-hour** in-flight TTL; a basic rate guard
  (~4 calls/sec).
- **Default OFF** behind `-datachannel` (`init.cpp:527`, default `0`).
- **Permanence consent enforced at the daemon** (`datachannel.cpp:269-271`), not the GUI:
  `z_senddatafile` refuses unless `acknowledge_permanent=true` (*"Refusing: the encrypted bytes
  are PERMANENT and public-ciphertext on-chain forever. Pass acknowledge_permanent=true to
  proceed."*).

### Non-consensus overlay (why this is safe to ship)

ZDC1 frames ride inside ordinary Sapling output memos. **Old, unmodified nodes relay and
mine these transactions unchanged** — no validation, PoW, or consensus rule is touched, so
there is **no consensus fork**. Security comes from the application layer: every honest
wallet deterministically re-validates confirmed history (verify-before-decrypt over the
key-independent on-chain anchor). There is **no DRM, no anti-copy, and no consensus
enforcement** — it is pure wallet/application policy.

### Threat model and what STILL leaks

This is a **confidentiality** channel, **not** a steganographic or undetectable one.
*"Private" ≠ "undetectable."* Even with perfect L3 encryption, the following metadata is
observable on-chain (`zdc.h:30-37`):

- **Transfer size (approximate):** the number of Sapling outputs ≈ the transfer size.
- **Timing:** the burst of outputs is observable.
- **Existence:** that *a* shielded tx occurred is observable.
- **Fingerprinting:** a run of all-max-size memos in one tx hints "data channel here."
- **Permanence:** the ciphertext is stored by every full node **forever** — encrypted but
  undeletable. Caps exist for responsibility, not just performance.

**KEY-frame caveat (important).** The in-band KEY frame ships the raw 32-byte L3 key in
cleartext *at L3*; its on-chain confidentiality rests entirely on the L1 Sapling
encryption to the recipient `ivk`. A compromised `ivk` therefore exposes the key, and
in-band reveal commits the key on-chain at send time. The as-built daemon **always**
includes the KEY frame (`datachannel.cpp:346`, `include_key_frame=true`) and also returns
the key to the sender. Out-of-band / reveal-later key delivery is **DESIGNED-NOT-BUILT**.

**Selective disclosure via viewing-key export — known gap.** The design (`PRIVACY.md §1.3`)
envisions selective disclosure by sharing the Sapling `ivk` so a third party can prove
content/receipt without spend authority. **That Sapling path is not implemented.**
`z_exportviewingkey` (`src/wallet/rpcdump.cpp:830`) carries a `// TODO: Add Sapling
support` and throws *"Currently, only Sprout zaddrs are supported"* for any non-Sprout
address. Since the data channel is Sapling-only, `z_exportviewingkey` **cannot export the
`ivk` for a data-channel z-address today** — so tag ivk-export selective disclosure as
**DESIGNED-NOT-BUILT**. Disclosure *does* work in practice the as-built way: share the
per-transfer L3 `key` returned by `z_senddatafile` together with `verify_fingerprint`.

---

## 5. GUI / UX plan for private send + receive (DESIGNED-NOT-BUILT)

There is no GUI surface for the data-channel today; the entire send/receive UX below is
**DESIGNED-NOT-BUILT**. The principles it must honor:

### 5.1 Be honest in the label about what is private

The UI must never imply the NFT or its ownership is private. The framing is:

> "Your NFT and its owner are public on the blockchain. This option keeps the **file's
> contents** private — only someone you give the key to can open it."

### 5.2 Consent for permanence, in plain language

The daemon already refuses without `acknowledge_permanent=true`; the GUI must earn that
consent honestly, not bury it. Required copy, blunt:

> "This sends the encrypted file onto the blockchain **forever**. It cannot be deleted or
> recalled. The encrypted bytes will be **public ciphertext stored by every node, for
> all time** — private only as long as the key stays private. Continue?"

A user cannot proceed until they actively confirm this. No pre-checked boxes.

### 5.3 Private send flow

1. Pick the Sapling from-address (must hold the spending key) and the recipient Sapling
   z-address.
2. Choose the file (≤ 40000 bytes; the UI enforces and explains the cap up front).
3. Show the permanence consent (§5.2).
4. On send, surface the `transfer_id`, `fingerprint` (= NFT `document_hash`), frame count,
   and — clearly marked as the secret to safeguard/share for disclosure — the per-transfer
   `key`.

### 5.4 Private receive flow

1. The recipient wallet reconstructs from chain (binary-safe memo read — a path that is
   **DESIGNED-NOT-BUILT** in the GUI; the CLI does it).
2. Run verify-before-decrypt; show `verified` and `complete` plainly.
3. On success, present the file. On failure, surface the honest codec error (§2.5)
   verbatim-in-spirit, never a fake "try again."

### 5.5 The framing to repeat everywhere

Public token, private bytes, permanent ciphertext. If a screen can only show one
sentence, it is:

> "Anyone can see you own this NFT. Only key-holders can open its file. The encrypted
> file lives on-chain forever."

---

## 6. Built-vs-designed summary

| Capability | Status |
|-----------|--------|
| ZDC1 codec — AEAD, nonce domain, AAD, fingerprint, reassembly, error taxonomy | **BUILT+TESTED** (25 gtests, `src/gtest/test_zdc.cpp`; standalone harness `src/datachannel/test/zdc_test.cpp`; compiled into the daemon) |
| `z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer` incl. cross-wallet verify-then-open via recipient `ivk` and `verify_fingerprint` gating | **BUILT-CLI-ONLY** (no GUI, no automated E2E) |
| Seal-then-reveal / out-of-band key (`z_revealkey`, `keymode`) | **DESIGNED-NOT-BUILT** |
| `zslp_mint_private` single RPC | **DESIGNED-NOT-BUILT** |
| GUI binary-safe memo read + native SHIELD/receive UX (`PRIVACY.md §3.3/§4`) | **DESIGNED-NOT-BUILT** |
| Sapling `z_exportviewingkey` for selective disclosure | **DESIGNED-NOT-BUILT** (Sprout-only TODO, `rpcdump.cpp:830`) |
| Off-chain ciphertext + on-chain fingerprint for files > 40000 bytes | **FUTURE-IDEA** |
| One-ciphertext-N-recipients key fan-out | **FUTURE-IDEA** |

---

## 7. Source files

- `src/datachannel/zdc.h`, `src/datachannel/zdc.cpp` — the ZDC1 codec (crypto, framing, fingerprint).
- `src/rpc/datachannel.cpp` — the three RPCs, safety gates, verify-before-decrypt.
- `src/wallet/asyncrpcoperation_senddatafile.{h,cpp}` — single-tx multi-output shielded send.
- `src/gtest/test_zdc.cpp` (25 tests); `src/datachannel/test/zdc_test.cpp` (standalone harness).
- `src/wallet/rpcdump.cpp:832` — `z_exportviewingkey` Sprout-only gap.
- `src/rpc/client.cpp:138-139` — CLI arg mapping; `src/init.cpp:527` — `-datachannel` default-off.
- `doc/nft/PRIVACY.md`, `doc/nft/NFT_FINAL_REVIEW.md` — design docs (stale on cross-wallet #117; this doc is current).
