# ZSLP Reorg/Confirmation — Requirements Checklist

Flat, testable checklist for the `reorg-confirmation` threat class. Companion to
`REORG_CONFIRMATION_SAFETY.md` (the security model + canonical spec). Each item has a
**verification method** so "done" is observable, not asserted.

Legend: **[INDEXER]** = the conservation rewrite (`src/zslp/*`); **[WALLET]** =
`src/wallet/*`; **[GUI]** = `zcl-qt-wallet`; **[RPC]** = `src/rpc/zslp.cpp`;
**[TEST]** = test/vector deliverable. This doc edits nothing under `src/`.

---

## A. Confirmed-block-only invariant (no 0-conf into the ledger)

- **R1 [INDEXER]** The store is mutated **only** from `ChainTip` connect/disconnect.
  The indexer MUST NOT override `SyncTransaction` or read the mempool. *(Today: only
  `ChainTip` is overridden, `src/zslp/zslpindexer.h:49-51`; `ChainTip` fires only on
  confirmed blocks, `src/main.cpp:3440`/`:3049`.)*
  **Verify:** grep the rewrite for `SyncTransaction`, `mempool`, `mapTx` → none in
  the store/indexer write path; unit test that a tx only in the mempool produces no
  store record.

## B. Deterministic, byte-exact reorg/undo

- **R2 [INDEXER][TEST]** Every connect-side mutation appends a paired undo op, and
  `DisconnectBlock` restores the **byte-identical** pre-connect DB.
  **Verify:** connect a block, dump the full DB; connect, then disconnect, dump
  again; assert the dumps are identical (covers token/utxo/balance/transfer/undo/tip
  records). Add a same-block create-then-consume case
  (`src/zslp/zslpstore.cpp:675-682`) and a multi-delta-same-address case.
- **R3 [INDEXER]** Crash-resume + re-delivery idempotence preserved: connect skips a
  block already at the stored tip (`src/zslp/zslpindexer.cpp:180-183`); CatchUp
  resumes one past stored tip (`:99-126`); version stamp written before reindex
  (`:82-84`).
  **Verify:** deliver the same connect twice → no double count; kill mid-reindex,
  restart → resumes, final ledger equals replay-from-scratch.
- **R20 [TEST]** Reorg round-trip + 2-block reorg converge to one ledger
  (incremental undo/redo == replay-from-scratch).
  **Verify:** scripted regtest reorg; compare full DB dumps.

## C. Canonical parse/apply determinism (close the ledger-fork class)

- **R4 [INDEXER]** **SLP message is read from `vout[0]` ONLY.** If `vout[0]` is not a
  parseable SLP `OP_RETURN`, the tx carries no SLP message (inputs still burn).
  *(Today DIVERGES: scans all vouts, `src/zslp/zslpindexer.cpp:211-279`.)*
  **Verify:** vector E1 — tx with junk vout[0] + valid SLP at vout[5] ⇒ not SLP.
- **R5 [INDEXER][TEST]** Pin ONE push-encoding rule (strict-minimal recommended) and
  freeze it with vectors. `read_push` is currently lenient
  (`src/zslp/op_return_push.h:24-46`).
  **Verify:** vector E2 — minimal vs non-minimal encoding of the same field decide
  SLP-or-not identically on every impl.
- **R6 [TEST]** Frozen vectors for E1–E13 (table in `REORG_CONFIRMATION_SAFETY.md`
  §3.7): vout placement, zero-qty slot positionality, output-index-out-of-range
  burn, Σ-overflow INVALID, under-funded INVALID, non-token input = 0, MINT w/o
  baton, GENESIS voutCount≤1, baton bounds, duplicate genesis, >19 outputs.
  **Verify:** corpus runs green; documented expected ledger delta per vector.
- **R9 [INDEXER][TEST]** uint64→int64 boundary is defined. SLP quantities are uint64
  on the wire (`src/zslp/slp.h:51,55,60`) but stored/summed as int64
  (`src/zslp/zslpstore.cpp:497-550`). A wire qty ≥ 2^63 becomes a negative int64.
  Define the canonical outcome (recommend: treat qty ≥ 2^63 as INVALID at parse, or
  clamp deterministically) and lock it.
  **Verify:** vector E11 — qty = 2^63 and 2^64-1; identical outcome everywhere; no
  signed overflow UB.
- **R10 [INDEXER]** Single SEND-output cap. Parser caps at 19
  (`src/zslp/slp.c:151`); indexer/store clamp at 20
  (`src/zslp/zslpindexer.cpp:265-268`, `src/zslp/zslpstore.cpp:540-542`). Unify to 19
  everywhere.
  **Verify:** vector E13 — exactly 19 and an attempted 20th decode identically.
- **R19 [TEST]** Ship the vector corpus as the canonical oracle + a multi-tx in-block
  ordering case (tx2 spends tx1's created output within one block) and a full
  GENESIS→MINT→SEND→burn lifecycle.
- **R21 [TEST]** Fuzz `slp_parse`/`read_push`: deterministic SLP-or-not, no OOB read
  (bounds check `src/zslp/op_return_push.h:43`), no crash.

## D. Confirmation-depth gate (don't show "final" too early)

- **R12 [RPC]** Read RPCs expose `confirmations = chainActive.Height() - height + 1`
  per UTXO/transfer/token (read-side, under `cs_main`; ledger unchanged). Today no
  depth is surfaced (no `confirm`/`depth` refs in `src/zslp/*` or
  `src/rpc/zslp.cpp`).
  **Verify:** RPC returns a `confirmations` field that increments per block.
- **R13 [GUI]** Ownership/authenticity shown **pending** until **N confirmations**,
  then **final**. Default `N = DEFAULT_MAX_REORG_DEPTH = 10` (`src/main.h:116`) so UI
  "final" == node finalization point. Single named constant.
  **Verify:** GUI snapshot at 1..9 conf = pending; at ≥10 = final.
- **R14 [GUI]** A mempool-only transfer is never "received/owned." Any pending-send
  indicator is labeled *unconfirmed / not yet final*.
  **Verify:** broadcast a token send; recipient GUI shows nothing owned until
  confirmed.
- **R15 [GUI]** Reorg demotion: GUI reads live store state on each ChainTip and never
  caches an "owned" flag across blocks; an orphaned transfer disappears.
  **Verify:** regtest reorg that orphans a transfer → GUI demotes within one tip.
- **R8 [INDEXER]** Undo is bounded: the node never applies a reorg deeper than
  `MAX_REORG_LENGTH = 99` (`src/main.h:58`, shutdown at `src/main.cpp:3643-3654`), so
  DisconnectBlock is never asked to undo more than that in one pass.
  **Verify:** documented invariant; reorg-depth test stays within bound.

## E. Wallet anti-burn (holder protection — token UTXOs must not be spent as fee/change)

The wallet has **ZERO** ZSLP awareness today (verified: no zslp refs in
`src/wallet/`). An ordinary send can spend a token-carrying dust UTXO as
fee/change and **BURN** the token/NFT (§3.1: any token UTXO a tx spends is consumed,
and a non-SLP tx reassigns nothing → permanent burn).

- **R22 [WALLET]** Coin selection MUST identify token-carrying UTXOs (via the store:
  `GetUtxo(txid, vout)`, `src/zslp/zslpstore.h:357`) and **exclude** them from normal
  fee/change selection so a routine ZCL send can never consume a token UTXO.
  **Verify:** with a token UTXO in the wallet, repeatedly `sendtoaddress` ZCL until
  change is forced; assert the token UTXO is never selected (store UtxoCount
  unchanged; `zslp_listmytokens` balance unchanged).
- **R23 [WALLET]** A token UTXO is spendable **only** through an explicit token-send
  path (or explicit coin-control opt-in), never implicitly.
  **Verify:** no implicit code path reaches a token UTXO; only the typed send / coin
  control can.
- **R24 [WALLET/GUI]** Token UTXOs are surfaced in coin-control, labeled as
  token-bearing (so a user who *does* select one is warned it carries a token).
  **Verify:** coin-control lists the UTXO with a token tag + a burn warning.
- **R25 [WALLET]** Burn is acknowledged, never silent: any path that *would* spend a
  token UTXO outside a token-send requires explicit confirmation describing the burn.
  **Verify:** attempting it raises a confirmation that names the token + "will be
  destroyed."

## F. Honest impersonation/uniqueness UX

- **R16 [GUI]** Token-id (genesis txid) is shown as the identity; ticker/name never
  presented as unique. RPC already returns `tokenid` (`src/rpc/zslp.cpp:43`).
  **Verify:** UI shows a genesis-txid fingerprint alongside the name.
- **R17 [GUI]** `documentHash` framed as "matches the issuer's committed hash," not
  "genuine/original." (`src/zslp/zslpindexer.cpp:238-246`, RPC `:47-48`.)
  **Verify:** copy review; no "genuine"/"the original" wording.
- **R18 [GUI/DOC]** No claim that consensus enforces token uniqueness; impersonation
  is a social/identity layer (consistent with `doc/nft/ENABLEMENT.md` honest ceiling).
  **Verify:** doc/UI copy review.
- **R7 / R11 [GUI]** NFT classification (baton-less GENESIS, decimals==0, qty==1) is
  computed on the read side from token fields; the store does not special-case NFTs.
  **Verify:** an NFT genesis renders as 1-of-1; a decimals>0 / qty>1 token does not.

---

## G. What this checklist deliberately does NOT promise

- It does **not** make consensus reject forgeries — impossible by the hard constraint
  (§1 of the model). Forgeries appear on-chain and are neutralized by *interpretation*
  (credit nobody / burn), not by rejection.
- It does **not** prevent a *different* token reusing a name/image — only the token-id
  is unique; the rest is honest UX (Section F).
- It does **not** protect a counterparty who acts on **< N** confirmations — that is
  exactly why R13 exists; sub-finalization receipts are inherently reorg-revocable.
