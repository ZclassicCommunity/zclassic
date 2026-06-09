# ZSLP Canonical Validation Spec (determinism-critical)

This is the SINGLE source of truth every honest observer (the `-zslpindex`
indexer, any compatible wallet/explorer) MUST implement **bit-identically**.
Disagreement on any rule here forks the token ledger and is a critical
DoS/grief vector (see `THREATS_DOS_SPAM_GRIEF.md` §2). All rules are stated so
that two independent implementations compute the identical ledger over the same
consensus-ordered confirmed block history.

Token id is the genesis txid (little-endian internal / big-endian display),
unique because consensus makes txids unique. The overlay is NON-consensus: an
on-chain tx that violates a rule is interpreted as **crediting nobody / burning
its token inputs**; it is never "rejected" (consensus already confirmed it).

References below cite current code; where the code diverges from the canonical
rule it is flagged **MUST FIX**.

---

## R1 — The SLP message lives at vout[0] ONLY  (closes T1, T2)

- Parse the SLP message from `tx.vout[0].scriptPubKey` and **nowhere else**.
- If `tx.vout[0]` is not a `TX_NULL_DATA` output, or does not parse as a valid
  SLP Token-Type-1 message, the tx is **non-SLP**: it creates no token outputs;
  it still burns any token UTXO it spends (R7).
- OP_RETURNs at vout ≥ 1 are **ignored entirely**. Multiple OP_RETURNs cannot
  change the result.

**MUST FIX:** `zslpindexer.cpp:211` currently scans every vout
(`for (size_t vo = 0; vo < tx.vout.size(); ++vo) ... if (msgPresent) break;`)
taking the first vout that parses. Replace with a vout[0]-only check. The header
already declares the correct rule (`slp.h:5,7`).

---

## R2 — Canonical OP_RETURN / push grammar

- The script MUST begin with `0x6a` (OP_RETURN) (`slp.c:44`).
- Each field is a single canonical data push read by `read_push`
  (`op_return_push.h:24-46`): direct push `0x01..0x4b`, `OP_PUSHDATA1` (0x4c),
  `OP_PUSHDATA2` (0x4d). Any other opcode ⇒ parse fail ⇒ non-SLP. (Note: SLP
  upstream additionally requires *minimally-encoded* pushes; the canonical rule
  for this overlay is "exactly what `read_push` accepts" — pin it and test it so a
  second implementation matches, including the empty-push encoding `0x4c 0x00`,
  `op_return_push.h:74-79`.)
- lokad_id field MUST be exactly the 4 bytes `"SLP\0"` (`slp.c:50`); else non-SLP.
- token_type MUST be 1, encoded in 1–2 bytes (`slp.c:54-57`); else non-SLP.
- A push that runs past end-of-script ⇒ parse fail ⇒ non-SLP
  (`op_return_push.h:43`).

---

## R3 — GENESIS

- tx_type push == `"GENESIS"` (7 bytes) (`slp.c:63`).
- Fields, in order (`slp.c:66-114`): ticker, name, document_url, document_hash
  (0 or 32 bytes; 32 ⇒ recorded), decimals (exactly 1 byte, value 0–9, else
  non-SLP), mint_baton_vout (0 or 1 byte; if present MUST be ≥ 2, else non-SLP),
  initial_token_mint_quantity (exactly 8 bytes, big-endian).
- token id := this tx's txid (`zslpindexer.cpp:229`, `zslpstore.cpp:453`).
- **First-genesis-wins:** if a token row for this id already exists, do not
  overwrite (`zslpstore.cpp:457`). (Txids are unique, so this only matters under
  re-delivery; keep it.)
- Mint output: `initial_quantity` is created at **vout[1]** iff `voutCount > 1`
  (`zslpstore.cpp:474-477`). If vout[1] doesn't exist, the quantity is **not**
  created (effectively burned). Canonical.
- Baton: created at `mint_baton_vout` iff `2 ≤ mint_baton_vout < voutCount`
  (`zslpstore.cpp:463-466,479-483`). Out-of-range baton vout ⇒ **no baton**
  (token mints a fixed supply). Canonical.
- Metadata strings (`ticker`/`name`/`document_url`) are clamped to the parser's
  fixed buffers (`slp.h:44-46`: 63/127/255 usable bytes). A field longer than the
  buffer is **dropped to empty** (`slp.c:69,77,85` only copy when `len < sizeof`).
  This length-clamp behavior is determinism-critical (a 255-vs-256 byte name must
  resolve identically everywhere) — pin and test it. Treat all three as untrusted
  display text (R10 / T5).

---

## R4 — MINT

- tx_type push == `"MINT"` (`slp.c:118`); token_id (32 bytes, `slp.c:122-124`);
  mint_baton_vout (0/1 byte, ≥2 if present); additional_quantity (8 bytes BE).
- VALID iff (a) the token id is a **known** token (`zslpstore.cpp:490`) AND (b) a
  **mint baton UTXO for that token id is on a spent input**
  (`zslpstore.cpp:441-442,493`). Missing either ⇒ INVALID: create nothing;
  consumed inputs stay burned. (gtest `MintWithoutBatonRejected`.)
- On valid MINT: `totalMinted += additional_quantity` (overflow-guarded, else the
  add is skipped — `zslpstore.cpp:497-506`); additional_quantity created at
  **vout[1]** iff `voutCount > 1`; baton continues at `mint_baton_vout` iff in
  range, else baton ends (`zslpstore.cpp:508-528`).

---

## R5 — SEND (the highest-risk arithmetic; closes T3)

- tx_type push == `"SEND"` (`slp.c:141`); token_id (32 bytes); then 1..N output
  quantity pushes, **each exactly 8 bytes big-endian**.
- **Canonical output count cap = 19** SEND outputs (mapping to vout[1..19]). The
  parser stops at 19 (`slp.c:151`). **MUST FIX consistency:** the bridge/store
  clamp to **20** (`zslpindexer.cpp:267`, `zslpstore.cpp:542`,
  `zslpstore.h:207` array `[20]`). Pick ONE number (19 recommended, matching the
  parser and SLP) and use it in parser, bridge, store, and the array bound, with a
  test that a 20th 8-byte push is treated identically by all layers. As written,
  the parser never emits a 20th, so the store clamp is dead — but a second
  implementation MUST be told the canonical cap is 19, or it diverges.
- **Quantity domain:** quantities are uint64 on the wire (`slp.c:158`). The store
  casts to int64 (`zslpstore.cpp:270,544`). Canonical rule to pin: **any output
  quantity with the high bit set (≥ 2^63) ⇒ the SEND is INVALID** (the store
  already treats the resulting negative int64 as overflow, `zslpstore.cpp:545`).
  Declare this explicitly so a uint64-native implementation matches.
- **Sum:** `requiredOut = Σ outputQuantities`, computed with an overflow guard;
  on overflow the SEND is **INVALID** (`zslpstore.cpp:537-550,567`).
- **Available:** `availIn = Σ amount of spent input UTXOs whose tokenId ==
  msg.tokenId` (batons contribute 0; non-token / unknown inputs contribute 0 via
  the `readUtxo` miss `continue`, `zslpstore.cpp:437-446`). This is the canonical
  "input not a recognized token UTXO ⇒ ZERO" rule.
- **Validity:** SEND is VALID iff `!overflow && availIn >= requiredOut`
  (`zslpstore.cpp:552`). INVALID ⇒ create nothing; all that-token inputs already
  burned. (gtest `OverSendBurnsInputsNoOutputs`, `ForgeSendWithoutInputCredits-
  Nobody`.)
- **Output mapping (positional, zero-preserving):** quantity j (0-based) maps to
  **vout[1+j]** (`zslpstore.cpp:559`). A zero-qty output consumes its slot but
  creates nothing (`zslpstore.cpp:557`). If `1+j >= voutCount`, that quantity is
  **burned** (skipped), remaining outputs still applied (`zslpstore.cpp:560-561`).
  Pin "out-of-range output index ⇒ that quantity burned, SEND otherwise valid".
- **Implicit burn:** `availIn - requiredOut` (the change the SEND chose not to
  re-emit) is burned (`zslpstore.cpp:565`). Canonical.

---

## R6 — Token-id byte order

- On-chain token_id bytes (display / big-endian) are reversed to the daemon's
  internal little-endian uint256 for MINT/SEND (`TokenIdToUint256`,
  `zslpindexer.cpp:147-153`); GENESIS uses the computed txid directly
  (`zslpindexer.cpp:229`). A second implementation MUST apply the identical
  reversal or it will look up the wrong token. Pin + test with a known
  genesis-txid round-trip.

---

## R7 — Every tx burns the token UTXOs it spends (non-SLP included)

- Before dispatching on the message, ALL token UTXOs referenced by `tx.vin` are
  consumed/erased (`zslpstore.cpp:432-446`). A non-SLP tx (msg == NULL) therefore
  burns any token dust it spends (gtest `NonSlpSpendBurnsUtxo`). This is the rule
  that makes T6 (wallet burn) real and is canonical — the wallet, not the
  indexer, is responsible for not spending tokens (R9 / §requirements).

---

## R8 — Bounded, streaming read APIs (closes the T4 amplification)

- All list RPCs MUST bound BOTH the returned slice AND the work performed.
  `count` is clamped to `ZSLP_LIST_MAX = 1000` (`zslpstore.h:49`,
  `rpc/zslp.cpp:124,162`). ✔ for the slice.
- **MUST FIX:** `ListTransfers` gathers the **entire** transfer set for a token
  into `all` then reverses (`zslpstore.cpp:777-799`) — unbounded by `count`.
  Re-implement to iterate the token's transfer keyspace and early-stop, or to
  seek from the high end, so peak memory/CPU is O(count+from), not O(total
  transfers for the token). A spammed token must not let one RPC allocate
  millions of rows.
- `GetTokensForAddress` is a full 'b'-keyspace scan (`zslpstore.cpp:810-822`) run
  once per wallet key by `zslp_listmytokens` (`rpc/zslp.cpp:222`). Either add an
  address-keyed index, or cap total scanned records and document it as
  best-effort, so a wallet with many keys × a flooded balance table cannot wedge
  the RPC thread.

---

## R9 — Wallet token-safety (closes T6) — fail CLOSED

- The wallet MUST treat a UTXO as **token-bearing** if the index reports a
  `(txid,vout)` token UTXO (`GetUtxo`, `zslpstore.h:357`) OR if the index is not
  yet synced past that UTXO's height (unknown ⇒ assume possibly-token ⇒ warn).
- Token-bearing UTXOs MUST be excluded from automatic coin selection and shown in
  coin-control. A deliberate token transfer MUST emit the canonical SEND at
  vout[0] (R1/R5) or warn that the token will burn.

---

## R10 — Untrusted-content handling (closes T5/T7 presentation)

- `ticker`/`name`/`document_url`/`document_hash` are attacker-controlled. Display
  rules (canonical for any compliant wallet/explorer): treat as plain text (no
  markup/HTML), strip control characters, length-clamp on display, NEVER
  auto-fetch or render `document_url` or any media, and always show the
  genesis-txid fingerprint alongside the name. Identity/verification is
  out-of-band, not a chain fact.

---

## R11 — Idempotence / crash-resume / reorg determinism

- A connect re-delivered for the current tip is a no-op (`zslpindexer.cpp:180-183`).
- The tip marker + version stamp drive crash-resume and version-migration wipe
  (`zslpindexer.cpp:62-89,99-126`). Index is fully derivable; a wipe+rebuild is a
  valid migration.
- DisconnectBlock MUST restore the byte-identical pre-connect state via the undo
  log (`zslpstore.cpp:591-731`; gtests `ReorgGenesisRoundTrip`,
  `ReorgMintRoundTrip`). Any divergence here is a self-inflicted ledger fork.

---

## R12 — Published test vectors (the agreement mechanism)

There is no consensus to fall back on, so cross-implementation agreement MUST be
proven by a shared, versioned set of **input→ledger** test vectors covering every
rule above (especially R1–R6). Ship them in-tree and treat them as the
interoperability contract. See `REQUIREMENTS_DOS_SPAM_GRIEF.md` for the exact
required cases.
