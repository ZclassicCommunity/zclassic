# ZSLP Reorg & Confirmation Safety — Security Model + Canonical Validation Spec

**Threat class:** `reorg-confirmation` — token ownership undone by a chain reorg; an
apparent receipt at 0-conf that later vanishes; cross-implementation ledger forks
that let an attacker show conflicting "ownership" to two parties.

**Status:** security model + requirements checklist. This document does **not** edit
`src/zslp/*`. A concurrent workflow owns the UTXO-bound conservation rewrite; this
spec is the contract that rewrite (and the wallet + GUI) must satisfy.

**Scope of authority:** every claim that touches behavior cites `file:line` in this
tree (ZClassic = Zcash 2.x fork, Bitcoin Core 0.11–0.12 lineage). Where the code is
**already correct**, it is credited so the rewrite does not regress it. Where it is
**wrong or missing**, it is a numbered requirement.

---

## 0. The one-sentence threat

> Base consensus relays and mines **any** standard transaction, including an
> `OP_RETURN` that encodes a **forged** token SEND or a token transfer that a reorg
> will later orphan. We can never make consensus reject these. Therefore token
> safety is **not** "the chain refuses the bad tx" — it is **"every honest observer
> deterministically computes the identical ledger over the consensus-ordered,
> confirmed block history, and never shows ownership as final before it is
> reorg-safe."**

Two distinct failure modes live in this threat class, and they have different
defenses:

| Failure | What the attacker does | The defense layer |
|---|---|---|
| **Reorg undo** | Get a token tx confirmed, let the counterparty act, then have the block orphaned (natural reorg or a self-mined short fork). | Deterministic byte-exact undo + a **confirmation-depth gate** before the GUI says "final". |
| **0-conf vanish** | Show a payee an unconfirmed token receipt that never confirms (double-spend the dust, or the OP_RETURN never makes a block). | Index **confirmed blocks only**; GUI shows **pending until N confirmations**. |
| **Ledger fork** | Craft an edge-case tx (push-encoding, vout placement, overflow) that implementation A reads as a valid transfer and implementation B reads as invalid/burn → present each party "their" version of ownership. | **One canonical parse + apply spec, bit-exact, with cross-impl test vectors.** |

The first two are *time* problems (don't trust too early). The third is an
*agreement* problem (everyone must compute the same thing). This document hardens
all three.

---

## 1. What base consensus does and does NOT do (the hard constraint)

`-zslpindex` is a pure **observer**. It registers on the validation signal bus only
to *read* connected/disconnected blocks; it never votes on validity, never affects
PoW, mempool acceptance, or wallet spends. Disabling it changes nothing about
consensus. (`src/zslp/zslpindexer.h:1-9`, init default-on at
`src/init.cpp:3271-3273`, help text `src/init.cpp:526`.)

Consequences that **cannot** be engineered away:

- A miner can include a tx whose `OP_RETURN` claims to SEND a token the sender does
  not own. Consensus mines it. **Defense:** the overlay interprets it as crediting
  **nobody** and **burning** any token UTXOs it actually spent — see §3 SEND rule.
  The forgery is on-chain but moves no honest observer's ledger.
- A reorg can orphan a block that carried a valid token transfer. Consensus *will*
  do this (up to the node's reorg bound). **Defense:** deterministic undo (§4) +
  confirmation-depth gate (§5).
- Anyone can mint a *different* token reusing a name/ticker/image. **Defense:** none
  at the protocol layer — uniqueness is at the token-id (genesis txid) level only;
  impersonation is a social/identity problem, surfaced honestly in the GUI (§6).

---

## 2. The existing reorg machinery this spec ties into (do NOT re-derive it)

The indexer is **already** correctly bound to confirmed blocks, and the store
**already** has a byte-exact undo log. This section credits the existing work so the
conservation rewrite preserves it; the requirements in §3–§6 sit *on top* of it.

### 2.1 Confirmed-block binding (already correct)

`CZSLPIndexer` overrides **only** `ChainTip(...)` and nothing else
(`src/zslp/zslpindexer.h:49-51`; the class subscribes to no other signal). It does
**not** override `SyncTransaction` — so it **never sees mempool / 0-conf
transactions at all**. `added=true` → `ConnectBlock`, `added=false` →
`DisconnectBlock` (`src/zslp/zslpindexer.cpp:157-166`).

`ChainTip` is emitted **only** from two sites, both under `cs_main`, both on a
*confirmed* block:

- connect: `src/main.cpp:3440`, inside `ConnectTip`, **after** `view.Flush()`
  (`:3412`) and `FlushStateToDisk` (`:3417`) — i.e. after the chainstate is durable.
- disconnect: `src/main.cpp:3049`, inside `DisconnectTip`, after `UpdateTip`.

**Property A (load-bearing): the ZSLP ledger is a deterministic function of the
consensus-ordered, confirmed block history. There is no 0-conf code path into the
store.** The rewrite MUST NOT add one (no `SyncTransaction` override, no mempool
peeking). See requirement R1.

### 2.2 Byte-exact undo log (already present; the model to preserve)

Per block, every mutation appends a typed undo op under key `'r' + blockHash +
BE(seq)` (schema `src/zslp/zslpstore.h:226`, kinds `:249-257`). `ConnectBlockBegin`
resets the running seq (`src/zslp/zslpstore.cpp:407-411`); `DisconnectBlock` reads
the block's ops in ascending seq and **replays them in reverse**
(`src/zslp/zslpstore.cpp:591-731`), restoring consumed UTXOs, erasing created ones,
reversing balance / `totalMinted` / baton changes, deleting transfer + token rows,
then moving the tip marker back (`:727-728`).

The undo replay is written to be **idempotent across same-block sibling ops**: it
accumulates per-token / per-balance / per-utxo changes in memory and writes each
record exactly once (`:622-720`), because `readToken`/`readBalance`/`readUtxo` see
only committed data, not the pending batch (comment `:615-621`). A same-block
create-then-consume nets to *erase* because reverse-order replay sees CONSUME first
(stages a write) then CREATE (stages an erase), last-writer-per-key wins, and CREATE
has the lower seq so it is processed later in the reverse loop (comment `:675-682`).

**Property B (load-bearing): DisconnectBlock yields the byte-identical pre-connect
store state.** This is asserted by the design but is **only as true as its tests**.
See requirement R2 (round-trip determinism test is mandatory, not optional).

### 2.3 Crash-resume / idempotent re-delivery (already present)

`ConnectBlock` skips a block whose hash already equals the stored tip
(`src/zslp/zslpindexer.cpp:180-183`) so a re-delivered connect for the current tip
cannot double-count. `CatchUp()` resumes one past the stored tip
(`src/zslp/zslpindexer.cpp:99-126`). The version stamp is written **before**
reindexing so a crash mid-reindex resumes from the per-block tip rather than
re-wiping (`src/zslp/zslpindexer.cpp:82-84`). These must be preserved (R3).

### 2.4 The node's own reorg bounds (free finalization the gate can lean on)

Consensus already bounds how deep a reorg the node will follow:

- Auto-finalization depth `DEFAULT_MAX_REORG_DEPTH = 10` (`src/main.h:116`); a block
  ~10 deep is finalized and a reorg before it is rejected (`FindBlockToFinalize`
  `src/main.cpp:3206-3234`, `IsBlockFinalized` gate at `:1985`, `:3072`).
- Hard reorg ceiling `MAX_REORG_LENGTH = COINBASE_MATURITY - 1 = 99`
  (`src/main.h:58`, `src/consensus/consensus.h:29`); a reorg deeper than that **shuts
  the node down** rather than reorging (`src/main.cpp:3643-3654`).

**Implication for the confirmation gate (§5):** the deepest reorg the *local node
will ever apply on its own* is bounded, so the ZSLP DisconnectBlock path will never
be asked to undo more than `MAX_REORG_LENGTH` blocks in one ActivateBestChain pass.
This does **not** make a transfer safe at <10 confirmations (a 9-deep reorg is
allowed and *will* fire DisconnectBlock); it means a finite, testable upper bound
exists for undo, and that a confirmation gate of N≥`DEFAULT_MAX_REORG_DEPTH` aligns
the GUI's "final" with the node's own finalization point. See R8.

---

## 3. CANONICAL VALIDATION SPEC (the agreement contract — bit-exact)

This is THE spec every compatible implementation (this daemon, any wallet, any
explorer) must compute identically. **Any divergence forks the ledger.** Each rule
is normative; the "current code" note flags where the in-tree code already matches or
**diverges** (a divergence is a numbered requirement).

### 3.1 Per-transaction order of operations (normative)

For each tx, in **block order**, the observer MUST:

1. **Consume inputs first, unconditionally.** For every `vin[k].prevout` that is a
   recognized token UTXO, remove it and (for a quantity UTXO) debit its derived
   balance. This happens for **every** tx, SLP or not — a non-SLP tx that spends a
   token dust UTXO **burns** it. *(Current code: correct —
   `src/zslp/zslpstore.cpp:432-446`; gathered for every tx at
   `src/zslp/zslpindexer.cpp:199-203`.)*
2. **Parse at most one SLP message** from the transaction (§3.2).
3. **Apply the message's creates** only as far as the consumed inputs (or, for
   GENESIS, the genesis itself) permit (§3.4–3.6).

Order matters for determinism: consume-before-create lets a later tx in the same
block spend a UTXO an earlier tx created (per-tx batch commit,
`src/zslp/zslpstore.cpp:421-424`), and makes "spent-but-not-reassigned ⇒ burned"
fall out automatically.

### 3.2 Which output carries the SLP message — **CANONICAL: vout[0] ONLY**

**Normative rule:** the SLP `OP_RETURN` MUST be at **`vout[0]`**. If `vout[0]` is not
a parseable SLP message, the transaction **is not an SLP transaction** (it still
burns any token inputs it spends, per §3.1.1). An `OP_RETURN` at any other index is
**ignored**.

This matches the canonical SLP specification and the in-tree header comment
(`src/zslp/slp.h:5` "Tokens are encoded in OP_RETURN outputs (vout[0])").

> **DIVERGENCE — must fix (R4, determinism-critical).** The current indexer scans
> **every** vout for the *first* parseable `OP_RETURN` and accepts it:
> `for (vo = 0; vo < tx.vout.size(); ++vo) { ... if (msgPresent) break; }`
> (`src/zslp/zslpindexer.cpp:211-279`, especially the loop start `:211` and the
> "first valid OP_RETURN wins" break `:277-278`). A tx with a junk/non-SLP `vout[0]`
> and a valid SLP `OP_RETURN` at `vout[5]` would be treated as SLP by this code but
> as **not-SLP** by any strict-vout[0] implementation → **ledger fork**. The
> conservation rewrite MUST restrict the scan to `vout[0]` only (parse
> `tx.vout[0].scriptPubKey`; if it is not `TX_NULL_DATA` or `slp_parse` fails, treat
> the tx as carrying no SLP message). The order of token-id byte conversion
> (`TokenIdToUint256`, `src/zslp/zslpindexer.cpp:147-153`) is unaffected.

### 3.3 Push-encoding canonicalization — **must be pinned (R5)**

`slp_parse` reads pushes via `read_push` (`src/zslp/op_return_push.h:24-46`), which
accepts direct pushes `0x01..0x4b`, `OP_PUSHDATA1` (`0x4c`), and `OP_PUSHDATA2`
(`0x4d`); it rejects anything else (`:39-41`). Canonical SLP additionally requires:

- **Field 0 (lokad)** = exactly `"SLP\0"`, 4 bytes (`src/zslp/slp.c:48-51`). ✓
- **token_type** = 1, encoded in 1–2 bytes (`src/zslp/slp.c:53-57`). ✓
- A token_type push of length 0 or >2 ⇒ not SLP. ✓ (the `len < 1 || len > 2` guard).

**Open determinism question to pin in tests (R5):** canonical SLP (BCH) mandates
*minimal* push encoding and treats a non-minimal push (e.g. value pushed via
`OP_PUSHDATA1` when a direct push would do) as **making the whole tx invalid SLP**.
The current `read_push` is **lenient** — it accepts `OP_PUSHDATA1`/`2` for any
length, including lengths that a minimal encoder would have done with a direct push.
Two valid options, but the choice MUST be made once and locked with vectors:

- **(a) Strict-minimal (recommended, matches BCH SLP):** reject non-minimal pushes
  in the parse path used by the indexer. Lowest fork risk against external SLP
  tooling.
- **(b) Lenient (current behavior):** document that ZSLP intentionally accepts
  non-minimal pushes. Acceptable *only if* it is the single canonical rule and every
  compatible implementation copies `read_push` byte-for-byte.

Either way: **the same bytes must decide SLP-or-not on every implementation.** R5
requires a decision + a frozen vector set (§7) covering minimal vs. non-minimal
encodings of each field.

### 3.4 GENESIS (normative)

- token_id := **the genesis txid** (canonical; globally unique because consensus
  txids are unique). *(Current: `parsed.tokenId = txid`,
  `src/zslp/zslpindexer.cpp:229`, `:453`.)* ✓
- **First-genesis-wins:** if a token row for that id already exists, do not overwrite.
  *(Current: `if (... && !readToken(tokenId, existing))`,
  `src/zslp/zslpstore.cpp:457`.)* ✓ — note this can only collide on a real txid
  reuse, which consensus forbids, so it is belt-and-suspenders, but it MUST stay for
  determinism under reindex.
- `decimals` MUST be 0–9 (`src/zslp/slp.c:99-101`). ✓ **For an NFT: decimals == 0.**
- `mint_baton_vout`: emitted only when ≥ 2; 0/1 mean no baton (`src/zslp/slp.c:103-109`).
  A baton is *issued* only if `2 ≤ mint_baton_vout < voutCount`
  (`src/zslp/zslpstore.cpp:463-466`). ✓
- Initial quantity is created at **`vout[1]`** only if `initialQuantity > 0 &&
  voutCount > 1` (`src/zslp/zslpstore.cpp:474-477`). ✓ If `voutCount <= 1` the
  quantity is **not created** (effectively burned at genesis). This edge MUST be in
  the vector set (R6).
- **NFT definition (normative):** baton-less GENESIS, `decimals == 0`,
  `initialQuantity == 1`. The store does not special-case NFTs; an NFT is just this
  parameterization. The GUI/wallet classify by reading these fields (R7, R11).

### 3.5 MINT (normative)

- Valid **iff** a mint baton for that exact token_id was on a spent input
  (`batonInputPresent[tokenId]`, `src/zslp/zslpstore.cpp:492-494`). No baton ⇒ create
  nothing; consumed inputs stay burned. ✓
- MINT of an unknown token ⇒ invalid, no outputs (`readToken` fails ⇒ break,
  `src/zslp/zslpstore.cpp:489-491`). ✓
- `totalMinted += additionalQuantity`, overflow-guarded against
  `int64_t` max (`src/zslp/zslpstore.cpp:497-506`). ✓ — see R9 on the uint64↔int64
  boundary.
- New quantity at `vout[1]`; baton continues at its declared vout iff
  `2 ≤ mint_baton_vout < voutCount` (`src/zslp/zslpstore.cpp:508-528`). ✓

### 3.6 SEND (normative) — the conservation core

- `tokenId` := the message's token_id (display-order bytes reversed to internal,
  `TokenIdToUint256`). ✓
- `availIn` := Σ amounts of spent input UTXOs of **that token_id only**
  (`availByToken[tokenId]`, `src/zslp/zslpstore.cpp:533-535`). Batons contribute 0
  (they carry no quantity, invariant `src/zslp/zslpstore.h:117-119`,
  `src/zslp/zslpstore.cpp:441-444`). ✓
- `requiredOut` := Σ `outputQuantities[j]`, computed with **overflow → INVALID** and
  **any negative qty → INVALID** (`src/zslp/zslpstore.cpp:537-550`). ✓
- **Validity:** `(!overflow && availIn >= requiredOut)`. If INVALID (under-funded or
  overflow): **create nothing**; all that-token inputs already burned in §3.1.1
  (`src/zslp/zslpstore.cpp:552`, `:567-569`). ✓ — this is the anti-forgery property:
  a forged/over-budget SEND credits nobody.
- **Positional mapping (normative):** `outputQuantities[j]` → **`vout[1+j]`**. A
  zero-qty output **consumes a slot but creates nothing** (the positional mapping is
  preserved across zero-qty outputs — `qty <= 0 ⇒ continue` *without* shifting the
  index, `src/zslp/zslpstore.cpp:553-558`). ✓ This is determinism-critical: an
  implementation that *skips* zero-qty slots instead of preserving position would
  assign later quantities to the wrong vout → ledger fork. Lock with a vector (R6).
- **Output index out of range:** if `1+j >= voutCount`, that quantity is **burned**
  (the create is skipped, `src/zslp/zslpstore.cpp:559-561`). ✓
- **More outputQuantities than the spec cap:** the parser caps at 19 SEND outputs
  (`src/zslp/slp.c:151` `while (num_outputs < 19)`); the message struct holds 20
  (`src/zslp/zslpmsg.h:47`); the indexer re-clamps to 20
  (`src/zslp/zslpindexer.cpp:265-268`) and the store re-clamps `n` to `[0,20]`
  (`src/zslp/zslpstore.cpp:540-542`). The **two clamp limits differ (19 vs 20)** —
  harmless today because the parser never emits >19, but it is a latent
  divergence-by-construction. R10: pin a single cap (19, per parser) everywhere and
  test the boundary.
- **"Input not a recognized token UTXO ⇒ contributes ZERO":** `readUtxo` miss ⇒
  `continue` (`src/zslp/zslpstore.cpp:438-440`). ✓ A SEND that lists a token_id for
  which no input UTXO exists has `availIn == 0`, so any positive `requiredOut` is
  INVALID. ✓

### 3.7 Determinism-critical edge cases — the checklist this spec freezes

Every row MUST behave identically across implementations and MUST have a frozen test
vector (R6):

| # | Edge case | Canonical outcome | Current code |
|---|---|---|---|
| E1 | OP_RETURN not at vout[0] | tx is **not SLP** (inputs still burned) | **DIVERGES — R4** (scans all vouts) |
| E2 | Non-minimal push encoding | one rule, locked (§3.3) | **UNPINNED — R5** (lenient) |
| E3 | SEND output index ≥ voutCount | that qty burned | ✓ `:559-561` |
| E4 | SEND zero-qty output | slot consumed, nothing created, position preserved | ✓ `:553-558` |
| E5 | Σ outputQuantities overflows int64 | INVALID (create nothing) | ✓ `:546-550` |
| E6 | SEND availIn < requiredOut | INVALID (inputs burned) | ✓ `:552,567` |
| E7 | input not a token UTXO | contributes 0 | ✓ `:438-440` |
| E8 | MINT without baton input | create nothing | ✓ `:492-494` |
| E9 | GENESIS with voutCount ≤ 1 | quantity burned (not created) | ✓ `:474` (guard) |
| E10 | baton vout ≥ voutCount or < 2 | no baton issued | ✓ `:463-466,508-509` |
| E11 | qty parsed as uint64 ≥ 2^63 | see R9 (uint64→int64 boundary) | **NEEDS PROOF — R9** |
| E12 | duplicate genesis txid (reindex) | first-genesis-wins | ✓ `:457` |
| E13 | >19 SEND outputs | capped consistently | **two caps 19/20 — R10** |

---

## 4. Reorg / undo requirements (tie to existing machinery, don't rewrite it)

The undo log (§2.2) is the right design. The hardening is to make its **byte-exact**
claim **proven**, and to make the conservation rewrite preserve it.

- The store records, per block, *exactly* the UTXO creates/consumes + derived deltas
  applied, so DisconnectBlock reverses them precisely
  (`src/zslp/zslpstore.h:236-353`, impl `:591-731`).
- The reverse-replay nets same-block sibling ops in memory and writes each record
  once (`src/zslp/zslpstore.cpp:615-720`).

The **risk** is not the algorithm; it is that the conservation rewrite touches the
same mutation sites (`createUtxo`/`consumeUtxo`/`recordBalanceDelta`/`flushBalances`,
`src/zslp/zslpstore.cpp:289-403`) and could add a mutation that has **no matching
undo op** — silently breaking byte-exactness in a way only a reorg reveals. Hence R2
(every mutation site MUST append a paired undo op, asserted by a connect→disconnect
round-trip test that compares the **full DB dump** before/after).

---

## 5. Confirmation-depth gate (the missing layer) — requirements

There is **no confirmation/depth concept anywhere in the ZSLP code today** (verified:
no `confirm`/`depth`/`mature` references in `src/zslp/*` or `src/rpc/zslp.cpp`). The
store records `height` per UTXO/transfer/token, so depth is derivable as
`chainActive.Height() - record.height + 1`, but nothing surfaces it and nothing gates
on it.

Because the indexer is confirmed-block-only (§2.1), a record in the store is always
≥ 1 confirmation. But **1 confirmation is not reorg-safe**: the node itself will apply
reorgs up to `MAX_REORG_LENGTH = 99` and only auto-finalizes at depth
`DEFAULT_MAX_REORG_DEPTH = 10` (§2.4). So a token "received" at 1–9 confirmations can
still be undone by DisconnectBlock.

**Requirements:**

- **R12 (depth is a first-class, read-side field):** the read RPCs MUST expose the
  confirmation depth of each token UTXO / transfer (`confirmations =
  tipHeight - height + 1`) so the wallet/GUI can gate on it. This is a read-side
  computation against `chainActive.Height()` under `cs_main`; it does **not** change
  the stored ledger.
- **R13 (GUI "pending until N"):** the GUI MUST show ownership/authenticity as
  **pending** until a record reaches **N confirmations**, and only then render it as
  **final**. Recommended default **N = `DEFAULT_MAX_REORG_DEPTH` (10)** so "final" in
  the UI aligns with the node's own finalization point; the value MUST be a single
  named constant, not scattered literals. High-value transfers MAY use a larger N.
- **R14 (0-conf is never "received"):** a token transfer that is only in the mempool
  MUST never be shown as received/owned. (The indexer structurally cannot show it —
  it has no mempool path — but the GUI MUST NOT invent a 0-conf view by reading the
  mempool separately. If a "pending send broadcast" indicator is desired, it MUST be
  labeled *unconfirmed / not yet final*, visually distinct from owned.)
- **R15 (reorg demotion is visible):** if a reorg orphans a transfer, the GUI MUST
  demote it from "owned" back to absent/pending on the next ChainTip — i.e. the GUI
  reads live store state each tip, never caches an "owned" flag across blocks.

---

## 6. Honest impersonation / uniqueness presentation — requirements

Uniqueness is **only** at the token-id (genesis txid) level. Anyone can mint a
*different* token reusing a name/ticker/image-hash. This is unforgeable to *confuse a
careful verifier* (the token-id differs) but trivial to *fool a casual viewer*.

- **R16 (token-id is the identity, shown):** any UI that renders a token MUST surface
  its token-id (genesis txid) and MUST NOT present ticker/name as if unique. The RPC
  already returns `tokenid` (`src/rpc/zslp.cpp:43`); the GUI must show a
  fingerprint, not just the name.
- **R17 (image authenticity ≠ uniqueness):** `documentHash` proves the bytes match
  what genesis committed to (`src/zslp/zslpindexer.cpp:238-246`,
  RPC `src/rpc/zslp.cpp:47-48`), **not** that this is "the" token. The GUI MUST phrase
  authenticity as "matches the issuer's committed hash," never "genuine/the original."
- **R18 (no consensus-uniqueness claim):** docs and UI MUST NOT imply the chain
  enforces token uniqueness. Impersonation is defeated socially (issuer identity /
  genesis-txid fingerprint / signed attestations), as already stated in the
  enablement doc's honest ceiling (`doc/nft/ENABLEMENT.md`).

---

## 7. Cross-implementation test-vector requirement (the agreement guarantee)

Bit-exact agreement is THE security property; there is no consensus fallback. So the
spec is only real if it ships with **frozen vectors** that any implementation can run.

- **R19 (vector corpus):** a committed corpus of `(raw OP_RETURN bytes, tx shape) →
  expected ledger delta` covering every row of §3.7 (E1–E13), plus a multi-tx
  in-block ordering case (tx2 spends tx1's output) and a GENESIS→MINT→SEND→burn
  chain. The corpus is the canonical oracle; a second implementation passes iff it
  reproduces every delta.
- **R20 (reorg round-trip vector):** for at least one non-trivial block, a
  connect→disconnect cycle MUST restore a **byte-identical full DB dump** (proves
  Property B). And a 2-block reorg (disconnect B, disconnect A, connect A', connect
  B') MUST converge to the same ledger two ways: replay-from-scratch vs.
  incremental-undo/redo.
- **R21 (parse-determinism fuzz):** fuzz `slp_parse` / `read_push` against the chosen
  push-encoding rule (R5); every input must yield a single deterministic
  SLP-or-not + identical field decode. No input may crash or read out of bounds
  (note `read_push` bounds-checks `p + *len > end`, `src/zslp/op_return_push.h:43`).

---

## 8. Requirements checklist (consolidated, testable)

See `REORG_CONFIRMATION_REQUIREMENTS.md` for the flat checklist the conservation
rewrite + wallet + GUI must satisfy, each mapped to a verification method.
