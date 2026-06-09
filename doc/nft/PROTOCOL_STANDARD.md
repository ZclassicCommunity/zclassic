# ZSLP Overlay Protocol — Implementation Standard

**Status: NORMATIVE.** This is the single canonical description of *how* a protocol feature
is designed, encoded, validated, versioned, tested, and documented in this codebase. Every
ZSLP-family overlay feature — fungible tokens, NFTs, **collections (group/child)**, and the NFT
sell/offer mechanism — MUST follow it. If a feature
cannot satisfy every hard invariant in §1, it does not ship; the design changes instead.

> **Removed:** the former ZDC1 shielded data-channel / arbitrary-file-transfer capability has
> been removed entirely. ZClassic provides **no wallet path to store arbitrary files on-chain**;
> NFTs reference off-chain content only by a `document_hash` fingerprint.

This document standardizes the *process*. The **what** lives in three companion normative
docs, and this standard says when/how to touch each:
- [`SECURITY_MODEL.md`](SECURITY_MODEL.md) — threat table + bit-exact validation rules (R-*).
- [`zslp-determinism-spec.md`](zslp-determinism-spec.md) — the deterministic parse/validate rules.
- [`NFT_API_REFERENCE.md`](NFT_API_REFERENCE.md) — the per-RPC call-shape reference.

The coin is **ZClassic (ZCL)**, never ZEC/Zcash, in all user-facing strings and docs.

---

## 1. The five hard invariants (the constitution)

Non-negotiable. A reviewer rejects any diff that violates one. Each is independently
verifiable from the diff alone.

- **I1 — Never affect consensus.** No edits under `src/consensus/`, `src/pow.cpp`, the
  script-verify paths, or `main.cpp`'s `ConnectBlock`/`CheckBlock`/`CheckInputs`/
  `AcceptToMemoryPool`. An overlay tx is an *ordinary* transaction that old, unmodified nodes
  relay and mine. Verify: `git diff` on those paths is empty.
- **I2 — Never put files / arbitrary data on-chain.** The only on-chain bytes a feature may
  add are small **fixed-length** fields and **32-byte hashes/ids**. File/media bytes live
  off-chain; the chain stores at most their fingerprint. The whole `OP_RETURN` is hard-capped
  at `MAX_OP_RETURN_RELAY = 223` bytes (`src/script/standard.h:34`); never raise it, never
  touch `-datacarriersize`/`nMaxDatacarrierBytes`. Verify: no new variable-length-from-user
  push; `git diff` on the data-carrier limits is empty.
- **I3 — Security is deterministic re-validation, not chain rejection.** A forgery *can* be
  mined; it must **credit nobody**. Correctness = every honest indexer computes the same
  ledger from the confirmed chain. (`SECURITY_MODEL.md` one-liner model.)
- **I4 — UTXO-bound + conservation.** Ownership and authority are functions of *spending a
  real coin*. Supply is conserved (created only by GENESIS/MINT; SEND conserves exactly).
  New authority (e.g. collection membership) reduces to "you spent a coin you controlled,"
  i.e. the scriptSig check consensus already enforces.
- **I5 — Confirmed-chain only.** The indexer acts on connected blocks under `cs_main`; there
  is **no mempool / 0-conf authority path**. Membership/ownership facts exist only after a
  confirmed connect.
- **I6 — Backward-compatible, append-only.** Existing on-chain tokens must parse
  byte-identically after the change. New wire fields are **optional trailing pushes**; new
  stored fields are **appended** to serialization. A clean reindex (not a migration) is how
  new columns populate.

> If a feature needs more than a fixed small field on-chain (e.g. real media), it goes
> **off-chain with an on-chain 32-byte fingerprint** (the content-fingerprint pattern, see
> `contentfingerprint.{h,cpp}` and `CONTENT_MODEL.md`). That is the only sanctioned way to
> "attach" arbitrary content.

---

## 2. On-chain message format standard

Every ZSLP message is a single `OP_RETURN` script at **`vout[0]` with value 0**, followed by
the token-carrying 546-sat ("dust") outputs at `vout[1..N]` and ZEC change **last**. The
deterministic-layout builder (`BuildAndCommitZSLP`) is mandatory — never `CreateTransaction`'s
random change insertion.

`OP_RETURN` layout (see `src/zslp/slp.c`):

```
OP_RETURN(0x6a)
  push "SLP\0"            LOKAD id   (SLP_LOKAD_ID 0x00504c53, exactly 4 bytes)
  push <token_type>       must be SLP_TOKEN_TYPE_1 (=1) for the current family
  push "<TX_TYPE>"        "GENESIS" | "MINT" | "SEND"
  ... type-specific fields, each a script PUSH ...
```

**Field rules (enforced in the parser, fail-closed):**
- **Fixed-length fields are length-gated.** A `document_hash`/`group_id`/`token_id` push MUST
  be *exactly* 0 or 32 bytes; any other length rejects the whole message. (Mirror the
  `document_hash` gate — this is how I2 is enforced structurally: there is no field that
  accepts arbitrary-length user bytes.)
- **Full consumption.** After the last defined field the parser requires `p == end`
  (`slp.c`): no trailing junk is tolerated.
- **Append-only new fields = optional trailing push.** A new field is read *after* the last
  existing field and *before* the `p == end` check, gated on "is there another push?". A
  legacy message (no trailing push) parses identically (I6). The new field, if present, is
  still length-gated.
- **Byte order.** `token_id` / `group_id` / hashes are stored on-chain in display
  (big-endian) order; convert to/from the daemon `uint256` with `TokenIdToUint256` (which
  reverses), exactly as existing fields do. Raw hex dumps (`zslp_decode`) use the on-chain
  order without reversal.
- **Byte budget.** Compute the worst-case size and assert it stays ≤ 223. The bridge already
  fails closed over the cap (`ZSLPBuild* → empty → RPC error`); never bypass it. Output-count
  caps (e.g. `ZSLP_MAX_SEND_OUTPUTS = 19`) are *wallet-construction* bounds chosen so the
  message also fits the byte cap — keep the count cap and the byte cap mutually consistent and
  `static_assert`ed across the parser/bridge/store copies.

---

## 3. Versioning standard

Two independent version numbers; bump the right one(s) and republish vectors.

| Version | Where | Bump WHEN | Effect |
|---|---|---|---|
| **`ZSLP_SPEC_VERSION`** (wire/accept-set) | spec docs (+ a macro if one exists) | the on-chain message format changes such that a strict *previous-version* parser would reject a *new* message (e.g. a new trailing field, a new token_type) | Documented feature gate. Republish R-VECTORS. Strict third-party parsers must upgrade to read the new feature; **unaffected messages stay cross-compatible**. |
| **`ZSLP_INDEX_VERSION`** (store schema) | `src/zslp/zslpstore.h` (currently `3`) | the indexed/serialized state changes (new `CZSLPToken` field, new secondary index) | On a lower stamp, `Init()` **wipes + reindexes** from genesis (`zslpindexer.cpp`), so the new column/index populates deterministically. No in-place migration. |

Rule of thumb: a new optional on-chain field bumps **both** (wire accept-set *and* stored
column). A pure read-RPC or help-text change bumps **neither**.

---

## 4. The implementation pipeline (mandatory layer order)

A feature flows through these layers in this order. Each has one responsibility; don't smear
logic across layers. (File homes in parentheses.)

1. **Parser** (`slp.h`/`slp.c`) — pure C, no daemon deps. Decode/encode the bytes; enforce
   the length/consumption gates (§2). Add the field to `struct slp_message` and to
   `slp_build_*`. **No I/O, no chain access.**
2. **Bridge** (`zslpmsg.{h,cpp}`) — translate the C `slp_message` ↔ the C++ `ZSLPMessage`;
   thread the new field through `ZSLPParseScript` / `ZSLPBuild*`; enforce the 223 cap.
3. **Indexer parse** (`zslpindexer.cpp::ParseTx`) — turn a confirmed `CTransaction` into a
   `CZSLPParsedMsg`; resolve byte-order (`TokenIdToUint256`); gather the spent-input facts
   (`availByToken`, `batonInputPresent`) the apply step needs. **Reads only confirmed data.**
4. **Store apply + undo** (`zslpstore.{h,cpp}::ApplyTransaction` / DisconnectBlock) — the
   ledger mutation. Mandatory rules:
   - **Consume-before-create ordering** (R-BURN-*): spent token inputs are burned/recorded
     *before* dispatch, so authority derived from a spent coin is already accounted for.
   - **Undo symmetry:** every write (token row, balance, UTXO, secondary index) has an undo so
     `DisconnectBlock` restores byte-identical pre-state on reorg. New secondary indexes need
     their undo too (or be derivable from the disconnected row). No new undo-op kind unless
     genuinely needed.
   - **Deterministic:** the result is a pure function of confirmed bytes + the existing UTXO
     set. Two store instances replaying the same blocks must agree bit-for-bit.
5. **Wallet builder + self-validate** (`wallet/zslpwallet.cpp`) — build the tx with the
   deterministic layout; pin intended token inputs in `req.tokenInputs`; respect **anti-burn**
   (`ZSLPIsProtectedTokenOutpoint` — never spend a token/baton UTXO as fee; the only
   token/authority inputs spent are the *intended* pinned ones). Before broadcast, **re-parse
   the final signed tx through the real `CZSLPIndexer::ParseTx` + `CZSLPStore::WouldBeValid`**
   and refuse to send if it wouldn't be valid. The wallet must never broadcast a burn it
   didn't intend.
6. **RPC** (`rpc/zslp.cpp`, `rpc/nftoffer.cpp`) — thin. Read RPCs are
   `okSafeMode=true` and registered unconditionally; write RPCs are `ENABLE_WALLET`-gated.
   **Fail closed:** with `-zslpindex` off, every `zslp_*`/`nft_*` throws `RPC_MISC_ERROR`.
   Every new RPC gets full help (params, result, errors, CLI + JSON-RPC examples).
7. **GUI** (separate repo) — never reimplements protocol logic; it calls the RPCs. Any
   client-side algorithm that an integrator also needs (e.g. the content fingerprint) MUST be
   exposed as a daemon RPC so there is one canonical implementation.

---

## 5. Determinism & forgery-safety standard

For any feature that asserts an ownership/authority/membership fact:

- **The fact is a pure function of confirmed bytes + the UTXO set.** No wall-clock, no
  randomness, no mempool, no node-local config. State it as one rule (e.g. "child C is an
  authorized member of group G iff …").
- **Authority = spending a real coin.** Reduce every "X is allowed to do Y" to "X spent a
  UTXO only X controlled," so it inherits consensus' own scriptSig guarantee with zero
  consensus change (I4). Avoid self-asserted on-chain claims as authority; if a self-asserted
  field exists (e.g. a "claimed" tag), it is **recorded but NEVER surfaced as the fact** —
  queries return only the authorized set.
- **The four-attack checklist** every such feature's design + tests must answer explicitly:
  (a) can a non-owner forge the fact? (b) can the parent/source be spoofed? (c) can an
  unauthorized actor create the fact? (d) can two honest indexers disagree? Each must be
  "no," with the cited rule/line that makes it so. (a)/(c) "no" come from §I4; (d) "no" comes
  from §4.4 determinism.

---

## 6. Test & review gates (a feature is not done until all pass)

- **R-VECTORS** — wire round-trip vectors (build→parse equals input) **and** rejection vectors
  (malformed/over-length/wrong-length pushes reject). Republish on any `ZSLP_SPEC_VERSION`
  bump.
- **gtests** (`src/gtest/test_zslp*.cpp`, registered in `Makefile.gtest.include`):
  - parser round-trip + length-gate rejection,
  - indexer determinism (two instances agree),
  - reorg undo (connect→disconnect restores byte-identical state),
  - **legacy parses byte-identical** (backward-compat, I6),
  - the **forgery-safety cases** from §5's checklist (one test per attack),
  - **no-fork standardness** (`IsStandardTx == true` for the carrier on mainnet params, cap
    tied to `MAX_OP_RETURN_RELAY`, mutation-proven),
  - anti-burn (the carrier UTXO is never spent as fee; intended inputs are).
- **regtest** (`qa/zslp/*.sh`) — a live end-to-end script (mint → use → query → an attack
  attempt that must fail), independently re-runnable with fresh txids.
- **Adversarial reviews** — (1) a design-stage forgery-safety review *before* coding a
  protocol-level change; (2) a diff-stage review against §1 (consensus-safe + no-files) +
  correctness *before* it's considered landable. Reviews try to *break* the invariants, not
  rubber-stamp.
- **Build** — proot glibc-2.31 (`zclassicd` links clean; `zcash-gtest` green). See
  [`../../`](../../) build harness notes.

---

## 7. Documentation standard

Each feature updates, in lockstep with the code:
- **`SECURITY_MODEL.md`** — add/resolve the threat (T*) and the validation rule (R*).
- **`zslp-determinism-spec.md`** — the deterministic rule (§5).
- **`NFT_API_REFERENCE.md`** — every new/changed RPC (params, result, errors, examples).
- A **feature section** in the relevant guide. Mark anything designed-but-not-built clearly as
  NOT BUILT. Keep `file:line` citations honest (they drift — re-verify before publishing).

---

## 8. The repeatable recipe (do these, in order)

> This is the standardized process. Following it is what makes each protocol feature
> predictable instead of ad-hoc.

1. **Frame** the feature against §1. If it can't satisfy all five invariants, redesign (e.g.
   move content off-chain behind a 32-byte fingerprint).
2. **Design** the on-chain encoding (§2), the determinism/forgery rule (§5), and the
   versioning impact (§3). For any protocol-level (wire) change, run a **design-stage
   adversarial forgery review** and get the on-chain format **owner-approved before coding**
   (the format is permanent).
3. **Implement** down the pipeline in order (§4): parser → bridge → indexer → store(+undo) →
   wallet(+self-validate, anti-burn) → RPC → (GUI later).
4. **Bump versions** (§3) and **write tests** (§6) — including one test per forgery attack.
5. **Build + gtest + regtest** (proot). Iterate to green.
6. **Adversarial diff review** against §1 + correctness. Fix blockers/majors.
7. **Document** (§7).
8. **Hold for the owner.** Nothing merges to `master` or ships without explicit go; protocol
   changes especially.

---

## 9. Worked example — collections (group/child), the C-hybrid format

Collections are the reference application of this standard:

- **§1:** non-consensus overlay (I1); the only new on-chain byte-field is a fixed **32-byte
  `group_id`** (I2 — no files); membership is deterministic (I3) and authority is a spent coin
  (I4); confirmed-only (I5); optional trailing push + appended store column (I6).
- **§2:** `group_id` is one optional 32-byte push appended to GENESIS after `initial_quantity`,
  length-gated to exactly 32, behind the `p==end` consumption check (+33 wire bytes, well
  under 223).
- **§3:** bumps `ZSLP_INDEX_VERSION` (2→3, new `CZSLPToken` columns + the `'g'` member index)
  **and** `ZSLP_SPEC_VERSION` (1→2, new wire field).
- **§4:** parser/bridge thread `group_id`; the store sets `groupAuthorized` in the GENESIS
  apply branch using the consume-step facts (`readToken(G)` + a spent parent-token/baton of G);
  the `'g'` index + undo make member queries O(members) and reorg-exact; the wallet builder
  pins+burns one parent authority coin. **Because a child is a GENESIS it cannot return parent-
  token change, so the spent outpoint is burned IN FULL** — the builder therefore requires a
  **single-unit** authority output (`amount==1`; decimals are 0) so each card burns exactly one
  unit (one unit = one card) and the baton/openness is preserved. A multi-unit authority output
  is refused (it would over-burn; split into single units first); the baton may be spent only
  with `allow_baton` and burning it SEALS the collection.
- **§5:** **child C is an authorized member of G iff** C's GENESIS names `group_id==G`, G
  exists, and C's tx spent a live parent-token/baton UTXO of G. A non-owner cannot spend G's
  coin → cannot create an authorized member (a/c fail); `group_id` is unique-by-txid (b fails);
  the rule is a pure function of confirmed state (d fails). A "claimed-but-unauthorized" token
  is stored but **never** returned by `zslp_listcollectionmembers`.
- **§6:** the ten forgery/determinism/reorg/legacy gtests + a members regtest.
- **§7:** resolves `T12`/`R-NFT1` in `SECURITY_MODEL.md`; documents the new RPCs in
  `NFT_API_REFERENCE.md`.

That mapping is the template: for the next protocol feature, fill in the same nine headings.
