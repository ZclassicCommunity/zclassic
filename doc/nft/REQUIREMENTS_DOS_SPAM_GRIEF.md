# Requirements Checklist — DoS / Spam / Grief

Concrete, testable acceptance bar for the conservation rewrite (`src/zslp/*`) and
the wallet/GUI work. Each item is verifiable by a gtest, an RPC probe, or a
manual GUI check. IDs map to threats in `THREATS_DOS_SPAM_GRIEF.md` and rules in
`CANONICAL_VALIDATION_SPEC.md`. "MUST" = blocking; "SHOULD" = strong.

## A. Parse determinism (blocking — these are the ledger-fork class)

- **A1 (T1/R1, MUST):** The indexer parses the SLP message from `tx.vout[0]`
  ONLY. A tx with a valid SLP OP_RETURN at vout[1] (vout[0] a normal payment) is
  treated as non-SLP. Replace the `for (vo ...)` scan at `zslpindexer.cpp:211`.
  *Test:* gtest — build a tx with payment@vout0 + SLP-SEND@vout1; assert no token
  UTXO created and the spent token input is burned.
- **A2 (T2/R1, MUST):** A mined tx with two OP_RETURNs (vout0 + vout1, both
  parseable SLP, different messages) produces the result of vout[0] alone.
  *Test:* gtest with two OP_RETURNs; assert vout[1]'s message has zero effect.
- **A3 (R5, MUST):** The output-count cap is a SINGLE constant used by parser,
  bridge, store, and the `outputQuantities` array bound. Reconcile `slp.c:151`
  (19) with `zslpindexer.cpp:267` / `zslpstore.cpp:542` / `zslpstore.h:207` (20).
  *Test:* a SEND with the maximum + one extra 8-byte push parses/applies
  identically at every layer.
- **A4 (R5, MUST):** Output quantity ≥ 2^63 ⇒ SEND INVALID (nothing created,
  inputs burned). *Test:* gtest with `outputQuantities[0] = 0x8000...0`.
- **A5 (R5, MUST):** Output-sum overflow ⇒ SEND INVALID. *Test:* two outputs each
  near INT64_MAX. (Extends existing arithmetic; assert burn + no outputs.)
- **A6 (R5, MUST):** Output index past `voutCount` burns only that quantity; lower
  in-range outputs are still created. *Test:* SEND with 3 quantities but
  voutCount=2 → vout1 created, the rest burned, SEND otherwise valid.
- **A7 (R5/R7, MUST):** Input that is not a recognized token UTXO contributes 0;
  a SEND whose `availIn` (from real token inputs) < `requiredOut` is INVALID and
  burns its token inputs. *(Covered by `OverSendBurnsInputs`/`ForgeSend...`; keep
  them green under the rewrite.)*
- **A8 (R2, MUST):** Non-canonical pushes and a push that overruns the script are
  non-SLP. *Test:* truncated PUSHDATA2, unknown opcode after OP_RETURN.
- **A9 (R3, MUST):** decimals outside 0–9, or a baton vout < 2, make the GENESIS
  non-SLP; a metadata field longer than its buffer is dropped to empty
  deterministically. *Test:* per-field gtest.
- **A10 (R6, MUST):** token_id byte-order round-trips: a MINT/SEND quoting a
  genesis-txid in display order resolves to the same token the GENESIS created.
  *Test:* genesis then SEND quoting its txid; assert the SEND finds the token.
- **A11 (R12, MUST):** A versioned `input→ledger` test-vector file covering
  A1–A10 is committed in-tree and run in CI, declared the interoperability
  contract for any second implementation.

## B. Resource / amplification bounds (blocking where noted)

- **B1 (T4/R8, MUST):** `ListTransfers` peak memory/CPU is O(count+from), NOT
  O(total transfers for the token). Re-implement `zslpstore.cpp:777-799` to
  early-stop; do not materialize the full set. *Test:* insert >ZSLP_LIST_MAX
  transfers for one token; assert the call allocates/returns ≤ count and stops
  early (instrument or bound-check).
- **B2 (T4/R8, MUST):** Every list RPC clamps `count` to `ZSLP_LIST_MAX` at the
  store boundary (not just the RPC layer) so a direct store caller is also
  bounded. *(RPC clamp present `rpc/zslp.cpp:124,162`; push the bound into
  `ListTokens`/`ListTransfers` themselves — `ListTokens` already does
  `zslpstore.cpp:741`; make `ListTransfers` match.)*
- **B3 (T4/R8, SHOULD):** `zslp_listmytokens` / `GetTokensForAddress` cannot be
  driven to an unbounded full-table scan per call. Add an address-keyed view OR a
  documented scan cap + the existing `ZSLP_LIST_MAX` response cap
  (`rpc/zslp.cpp:242`). *Test:* many wallet keys × a large 'b' table returns
  within a bounded record-scan budget.
- **B4 (T4, MUST):** The index remains fully derivable and disposable: a version
  bump wipes + rebuilds (`zslpindexer.cpp:74-85`); no path makes index size
  super-linear in chain size. *Test:* catch-up over a block stuffed with many
  genesis/dust-send txs completes in O(total outputs) with no quadratic blowup.
- **B5 (T8, MUST):** A reorg's disconnect cost is O(undo ops for the block) and
  yields byte-identical pre-state. *(Keep `ReorgGenesisRoundTrip`/`ReorgMint-
  RoundTrip`; add a multi-tx-block reorg case.)*
- **B6 (T9, MUST):** A re-delivered connect for the current tip is a no-op (no
  double-credit). *(Guard at `zslpindexer.cpp:180-183`; add a regression test
  that re-delivers the tip and asserts balances unchanged.)*

## C. Wallet anti-burn (blocking — prevents user/asset loss)

- **C1 (T6/R9, MUST):** Wallet coin selection EXCLUDES UTXOs the index reports as
  token-bearing (`GetUtxo`). *Test:* fund a wallet with a token dust UTXO + normal
  coins; a plain ZCL send must not select the token UTXO. (Wallet has 0 zslp refs
  today — `grep -rin zslp src/wallet/` = 0; this is net-new.)
- **C2 (T6/R9, MUST):** Token UTXOs are visible/selectable in coin-control so a
  user can spend them only deliberately.
- **C3 (T6/R9, MUST):** Fail CLOSED — if the index is not synced past a UTXO's
  height, treat that UTXO as possibly-token and warn before spending it in a
  non-SLP tx. *Test:* with `-zslpindex` behind tip, a send touching unindexed
  dust warns.
- **C4 (T6/R5, MUST):** A deliberate token transfer emits the canonical SEND
  OP_RETURN at vout[0] with correct positional quantities (R5); otherwise the UI
  blocks/loudly warns "this will burn the token".
- **C5 (T6, SHOULD):** Auto-shield / consolidation / sweep features never sweep a
  token-bearing UTXO without explicit consent. (Cross-check the auto-shield path
  noted in repo memory.)

## D. UX honesty / anti-grief presentation (blocking for the grief class)

- **D1 (T5/R10, MUST):** Unsolicited / unverified tokens are hidden by default;
  user opts in per token or per issuer (allowlist).
- **D2 (T5/R10, MUST):** `document_url` and any media are NEVER auto-fetched or
  auto-rendered; resolving a URL requires explicit user action + a warning.
- **D3 (T5/R10, MUST):** `ticker`/`name` rendered as plain text — no markup/HTML,
  control chars stripped, length-clamped — and always shown with the genesis-txid
  fingerprint.
- **D4 (T7/R10, MUST):** Token identity in the GUI is the genesis-txid, never the
  name alone; impersonation is surfaced (e.g. "N other tokens use this name"),
  not hidden behind a false uniqueness claim.
- **D5 (honesty, MUST):** The GUI states plainly that on-chain bytes (spam, abusive
  names, unsolicited tokens) are permanent and only hideable, and that no chain
  rule enforces a "real" issuer. (See `THREATS...` §5.)

## E. Non-negotiable invariants (regression guards)

- **E1 (MUST):** The overlay NEVER touches consensus/validation/PoW/mempool
  acceptance. *Check:* `src/zslp/*` includes no validation mutation; indexer only
  reads the validation-signal bus (`zslpindexer.cpp` `RegisterValidationInterface`
  observer). Keep it behind `-zslpindex`.
- **E2 (MUST):** Forgery remains impossible at the ledger: a SEND with no funding
  input, an over-send, a baton-less MINT, and a duplicate-NFT GENESIS all credit
  nobody / burn. *(Keep `ForgeSendWithoutInputCreditsNobody`,
  `OverSendBurnsInputsNoOutputs`, `MintWithoutBatonRejected`,
  `NftCannotBeDuplicated` green.)*
- **E3 (MUST):** All determinism rules (R1–R12) have at least one gtest each, and
  the A11 test-vector file is the canonical agreement contract.

---

### Quick verification map (file:line cited above)

- vout-scan bug to fix: `src/zslp/zslpindexer.cpp:211`
- output-cap mismatch: `src/zslp/slp.c:151` vs `zslpindexer.cpp:267` /
  `zslpstore.cpp:542` / `zslpstore.h:207`
- SEND arithmetic / validity: `src/zslp/zslpstore.cpp:531-569`
- burn-on-spend (all txs): `src/zslp/zslpstore.cpp:432-446`
- unbounded ListTransfers: `src/zslp/zslpstore.cpp:777-799`
- full-scan listmytokens: `src/zslp/zslpstore.cpp:810-822`, `src/rpc/zslp.cpp:222`
- ZSLP_LIST_MAX: `src/zslp/zslpstore.h:49`
- wallet has zero ZSLP awareness: `grep -rin zslp src/wallet/` → 0
- consensus can't help: `src/script/standard.cpp:65-72`, `src/main.cpp:758-779`,
  `src/script/standard.h:34`
