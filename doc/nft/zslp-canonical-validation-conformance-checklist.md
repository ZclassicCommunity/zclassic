# ZSLP Canonical Validation — Conformance Checklist

Testable requirements the UTXO-bound conservation rewrite (`src/zslp/*`) MUST
satisfy to close the forgery-conservation threat class. Each item is a
concrete, automatable assertion. Companion to
`zslp-forgery-conservation-threat-model.md` (§5 R-* rules).

Legend: **[DONE]** verified present in current code (`src/zslp/*`,
`src/gtest/test_zslp*.cpp`); **[GAP]** not yet enforced / not yet tested;
file:line cites the relevant code.

---

## A. Conservation core (economic) — mostly DONE

- **C-1 [DONE]** Forged SEND with no token input of that token id credits
  nobody and creates no UTXO. (`zslpstore.cpp:552,567`; test
  `ForgeSendWithoutInputCreditsNobody`.)
- **C-2 [DONE]** SEND with `Σ outputs > availIn` is INVALID: creates nothing,
  burns the spent inputs. (`zslpstore.cpp:552`; test
  `OverSendBurnsInputsNoOutputs`.)
- **C-3 [DONE]** MINT without a baton input of that token id issues nothing;
  spent inputs stay burned. (`zslpstore.cpp:493`; test
  `MintWithoutBatonRejected`.)
- **C-4 [DONE]** MINT of an unknown token id issues nothing.
  (`zslpstore.cpp:490`.) *Add an explicit test.*
- **C-5 [DONE]** An NFT (qty 1, decimals 0, no baton) cannot be duplicated by
  a forged SEND. (test `NftCannotBeDuplicated`.)
- **C-6 [DONE]** A non-SLP tx that spends a token UTXO burns it (balance
  drops, UTXO erased). (`zslpstore.cpp:449-450`; test `NonSlpSpendBurnsUtxo`.)
- **C-7 [DONE]** Unknown input contributes ZERO (readUtxo miss → continue).
  (`zslpstore.cpp:439`.) *Add a test: SEND quoting tokenId X while spending a
  non-token dust input asserts availIn==0 and nothing created.*
- **C-8 [DONE]** Output index out of range burns that quantity, creates no
  UTXO. (`zslpstore.cpp:560-561`.) *Add a test: SEND with 3 amounts but tx has
  only vout[0..1] — the amount(s) targeting vout≥voutCount are burned.*
- **C-9 [DONE]** Σ-output overflow ⇒ SEND INVALID. (`zslpstore.cpp:543-550`.)
  *Add a test: two amounts each `0xFFFFFFFFFFFFFFFF` ⇒ create nothing, inputs
  burned.*
- **C-10 [DONE]** totalMinted overflow guarded. (`zslpstore.cpp:497-499`.)
  *Add a test.*
- **C-11 [DONE]** Genesis first-wins / replay idempotent. (`zslpstore.cpp:457`.)
  *Add a test: re-deliver the same genesis tx (idempotence guard,
  `zslpindexer.cpp:182`) and a second genesis attempt cannot overwrite metadata.*
- **C-12 [DONE]** Baton authority continuation: MINT moves the baton only if
  `mint_baton_vout ∈ [2,voutCount)`; otherwise the baton ends (token becomes
  fixed-supply). (`zslpstore.cpp:508-528`; tests `MintAccounting`,
  `ReorgMintRoundTrip`.)
- **C-13 [DONE]** Baton bears no quantity (isMintBaton ⇒ amount 0, never in
  availIn). (`zslpstore.cpp:303,315`, `zslpstore.h:118`.)

## B. Parse determinism — the live fork risk — mostly GAP

- **P-1 [GAP] (R-LOC-1, threat D1).** The SLP message MUST be taken from
  **vout[0] only.** Current code scans every vout for the first parsable SLP
  OP_RETURN (`zslpindexer.cpp:211-279`).
  - **Test (fork-proof):** tx with a non-SLP `OP_RETURN` at vout[0] and a
    valid SLP SEND `OP_RETURN` at vout[1], spending a token UTXO ⇒ result MUST
    be "no SLP message": inputs burned, NO outputs created. (Today this
    indexer would honor the vout[1] SEND.)
  - **Test:** valid SLP at vout[0] ⇒ honored normally.
  - **Test:** vout[0] OP_RETURN present but not SLP, vout[1] also not SLP ⇒ no
    message, inputs burned.

- **P-2 [GAP] (R-PARSE-2, threat D2).** Reject `OP_PUSHDATA4` (0x4e), `OP_0`
  (0x00), `OP_1NEGATE`, `OP_RESERVED`, `OP_1`..`OP_16` as SLP fields. Do NOT
  gate solely on `Solver==TX_NULL_DATA` (that accepts all of these via
  `IsPushOnly`, `script/script.cpp:239`).
  - **Test:** a script encoding the SLP grammar but with one field pushed via
    `OP_PUSHDATA4` ⇒ parse fails (not SLP). `read_push` already rejects 0x4e
    (`op_return_push.h:39`); add the assertion so a future "optimization" can't
    regress it.
  - **Test:** a field encoded as `OP_1` (0x51) where data was expected ⇒ not
    SLP.
  - **Test:** confirm the gate and parser AGREE: any script the gate
    (`TX_NULL_DATA`) lets through but the parser rejects must end as "not SLP"
    (it already does, via `continue`/`return false` — but with P-1's vout[0]
    rule a vout[0] gate-pass/parse-fail MUST be "no message", not "scan on").

- **P-3 [GAP] (R-PARSE-3, threat D3).** Reject non-minimal pushes. A 4-byte
  payload pushed as `OP_PUSHDATA1 0x04 ...` ⇒ not SLP.
  - **Test:** build a valid SEND, re-encode one field non-minimally, assert
    `slp_parse` returns false. (Current `read_push` ACCEPTS it,
    `op_return_push.h:32-38` — this is a GAP that must be fixed or the rule
    explicitly waived and frozen as repo-canonical with a published note.)

- **P-4 [GAP] (R-PARSE-4, threat D2 note).** Pin the zero-length-field
  encoding to exactly ONE byte sequence. Repo currently emits/accepts
  `OP_PUSHDATA1 0x00` (`op_return_push.h:74`).
  - **Test:** assert the canonical empty-field bytes round-trip and that the
    *other* common form (`OP_0`) is treated per the frozen decision
    (accept-as-equivalent OR reject — pick one, test it).

- **P-5 [DONE] (R-PARSE-5).** Push length past end-of-script ⇒ not SLP.
  (`op_return_push.h:43`; test `ParseTruncatedGenesis`.) *Add a targeted test
  for each field boundary.*

- **P-6 [GAP] (R-PARSE-6, threat D6).** Validity independent of
  `-datacarrier`/`-datacarriersize`/mempool/wallet/clock.
  - **Test:** index a block with the daemon configured at two different
    `-datacarriersize` values ⇒ identical ledger. (Or a code-review assertion:
    the parse path never reads these globals — it does not today.)

- **P-7 [GAP] (R-SEND-1, threat D5).** Freeze SEND amount-list semantics:
  each amount push exactly 8 bytes; pin whether a malformed amount push means
  "honor the valid prefix" (repo, `slp.c:151-160`) or "whole tx not SLP".
  - **Test:** SEND with two valid 8-byte amounts then a 7-byte push ⇒ assert
    the frozen behavior exactly. (Today the repo honors the 2-amount prefix.)
  - **Test:** SEND with a single 9-byte amount ⇒ frozen behavior.
  - **Test:** max 19 amounts accepted, a 20th makes the result per the frozen
    rule (parser caps at 19, `slp.c:151`).

- **P-8 [GAP] (R-GEN-1).** GENESIS field-length validity: document_hash ∈
  {0,32}; decimals == 1 byte 0–9; mint_baton_vout ∈ {0-len, 1-byte ≥2};
  initial_qty == 8 bytes. (`slp.c:91-114` enforces these — add explicit
  negative tests: decimals=10 ⇒ not SLP; baton_vout=1 ⇒ not SLP;
  document_hash len=16 ⇒ field ignored vs not-SLP — **pin which**, the code
  currently *ignores* a non-32 hash, `slp.c:93`, rather than failing.)

## C. Token-id determinism

- **I-1 [GAP] (R-ID-1, threat D4).** GENESIS↔MINT/SEND token-id coincidence.
  - **Test (must add):** GENESIS a token (id = txid); then construct a MINT
    and a SEND whose on-chain 32-byte token_id field is the **display-hex
    bytes** of that txid; assert `TokenIdToUint256` of that field == the
    GENESIS `tokenId`, and that the SEND resolves the GENESIS's vout[1] UTXO.
    This is the one test that proves the two endianness paths
    (`zslpindexer.cpp:229` direct vs `:256/:264` reversed) agree.

## D. Ordering / reorg determinism — DONE, extend

- **O-1 [DONE]** In-block ordering: a later tx spends an earlier tx's created
  UTXO. (`zslpindexer.cpp:186`, `zslpstore.cpp:422`; test `IntraBlockSpend`.)
- **O-2 [DONE]** Disconnect restores byte-identical pre-state. (tests
  `ReorgGenesisRoundTrip`, `ReorgMintRoundTrip`, `DisconnectEmptyBlock`.)
  - **Extend:** a reorg that REPLACES a genesis+send chain with a different
    chain ⇒ ledger equals fresh recompute over the new chain.
- **O-3 [DONE]** Connect idempotence guard prevents double-count on
  re-delivered tip. (`zslpindexer.cpp:182`.) *Add a test that re-delivers a
  connect for the current tip and asserts balances unchanged.*

## E. Cross-implementation conformance (agreement is the property)

- **X-1 [GAP]** Publish a **canonical test-vector file**: a list of
  `{raw_op_return_hex, expected_parse_result}` and
  `{block_of_txs, expected_ledger_snapshot}` pairs that ANY implementation
  (wallet, explorer, alt indexer) must reproduce exactly. Include every D1–D6
  edge case above. This is the artifact that turns "we hope they agree" into
  "they pass the same vectors."
- **X-2 [GAP]** A `zslp_validate`/dump RPC (read-only) that emits the full
  `'u'` UTXO set + `'t'`/`'b'` snapshot for a given height, so two nodes can be
  diffed for bit-exact agreement in CI.
- **X-3 [GAP]** Version-stamp coupling: any change to a frozen R-* rule MUST
  bump `ZSLP_INDEX_VERSION` (`zslpstore.h:54`) AND the published test vectors,
  because it changes the canonical ledger function. (Migration wipe+reindex is
  already wired, `zslpindexer.cpp:74-85`.)

---

## Priority for the conservation rewrite

1. **P-1 (vout[0]-only)** — highest fork risk, smallest fix (gate on vout[0]
   instead of scanning), directly named in the briefing.
2. **P-2 / P-3 (push opcode set + minimality)** — silent dual-encoding fork
   risk; align parser to ONE canonical push rule and stop relying on
   `TX_NULL_DATA`'s looser `IsPushOnly`.
3. **I-1 (token-id round-trip test)** — cheap, proves the endianness invariant.
4. **P-7 / P-8 (freeze field/amount edge semantics)** — write the rule down
   and test the exact current behavior so a third party can match it.
5. **X-1 (canonical test vectors)** — the deliverable that makes agreement
   verifiable rather than assumed.
