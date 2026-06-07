# ZSLP NFT — Non-Consensus Security Model & Canonical Validation Spec

Status: NORMATIVE. Spec version `ZSLP_SPEC_VERSION = 1` (see §8).
Scope: the ZSLP (SLP Token Type 1) overlay for ZClassic — `src/zslp/{slp.h,slp.c,op_return_push.h,zslpmsg.*,zslpstore.*,zslpindexer.*}`, `src/rpc/zslp.cpp`, plus the wallet anti-burn and GUI honesty requirements in `src/wallet/` and the Qt wallet.
This document defines the SECURITY MODEL and the BIT-EXACT CANONICAL VALIDATION RULES. It edits no source. The concurrent UTXO-conservation rewrite of the store+indexer, the wallet, and the GUI MUST satisfy the requirements checklist in §7.

This is a synthesis of six independent threat reviews (determinism-fork, forgery-conservation, holder-anti-burn, impersonation-uniqueness, reorg-confirmation, dos-spam-grief). Every code citation below was re-verified against the working tree on branch `feature/zslp-nft-indexer` (the branch that carries the ZSLP source the R-* rules cite).

---

## 1. The Security Model In One Page

### 1.1 The hard constraint

We CANNOT change ZClassic consensus. Minters and users run EXISTING, unchanged consensus nodes. **Base consensus does not know about ZSLP/SLP at all.** A push-only `OP_RETURN` is classified `TX_NULL_DATA` by `Solver()` (`src/script/standard.cpp`) and relayed/mined like any standard data-carrier output. Consensus will therefore relay and mine an `OP_RETURN` that encodes a **forged** token GENESIS, MINT, or SEND. We can never make consensus reject an invalid token transaction.

Corollary: **token uniqueness and ownership cannot be enforced by the chain refusing forgeries.** They must be enforced some other way.

### 1.2 What actually secures tokens: deterministic re-validation

The token ledger is a **pure, deterministic function** computed by an observer (our `-zslpindex` indexer `CZSLPIndexer`/`CZSLPStore`, and any compatible wallet or explorer) over the **consensus-ordered, confirmed** block history:

```
ledger = F( [block_0, block_1, ..., block_tip] )   // confirmed blocks, in consensus order
```

A transaction's token effect is VALID only if it follows the overlay rules. An on-chain transaction that breaks them is interpreted as **crediting nobody and/or burning its token inputs**. A forgery can therefore land on-chain yet change no honest observer's ledger.

> **The precise statement: forgery on-chain != forgery in the ledger.**
> An attacker can place any bytes on-chain. They cannot make `F` credit a forgery. `F` is computed independently by every observer, so the only thing the attacker controls is the input to `F` (the confirmed history), never `F` itself.

### 1.3 Why agreement is the whole game

Because there is no consensus over the overlay, the SOLE security property is:

> **SECURITY = DETERMINISM + AGREEMENT.**
> Every honest observer running the same canonical rules MUST compute the BIT-IDENTICAL ledger from the same confirmed history.

If two compatible implementations disagree on ANY edge case, the token ledger **forks**: the attacker presents one "ownership truth" to victim A (running implementation X) and a contradicting one to victim B (running implementation Y), with no tiebreaker — there is no consensus to fall back on. Cross-implementation bit-exact agreement is therefore not a nice-to-have; it IS the security property. Every divergence in §3 is a real exploit, not a style nit.

### 1.4 The trust boundary, stated honestly

The overlay guarantees, over confirmed history:

- **Token-id uniqueness** — `tokenId == genesis txid`, globally unique because txids are unique under consensus.
- **Conservation** — the single NFT unit (and any token quantity) cannot be inflated or duplicated; a forged SEND/MINT credits nobody.
- **Determinism** — every observer computes the same ledger (IFF the canonical rules below are followed bit-for-bit).

The overlay does NOT and CANNOT guarantee:

- **Name/ticker/image uniqueness** — anyone can mint a DIFFERENT token (new genesis txid) reusing any metadata. Defeated socially, not on-chain (§5).
- **Issuer identity** — GENESIS has no input requirement and no signed issuer field. Identity is an out-of-band attestation layer (§5).
- **That a holder's own wallet won't burn the token** — a token rides ordinary transparent dust; consensus lets any wallet spend it. Prevented wallet-side only (§4).
- **Finality below the node's reorg horizon** — see §6.

### 1.5 The overlay's place in the system

`CZSLPIndexer` is behind `-zslpindex`, derived and disposable. It MUST NEVER touch consensus, validation, PoW, or mempool acceptance. Verified: the indexer overrides only `ChainTip` (`src/zslp/zslpindexer.h:49`) and never `SyncTransaction`, so there is **no mempool / 0-conf path** into the ledger — a record exists only after a confirmed block connect under `cs_main` post-flush. This is a structural strength and MUST be preserved (R-1).

---

## 2. Canonical Validation Rules (bit-exact)

These rules are NORMATIVE. Any implementation that follows them computes the identical ledger. Each rule is keyed `R-<AREA>-<n>` and cross-referenced from the checklist in §7. Code citations mark whether the current tree already complies (OK) or requires a change (FIX).

### 2.0 Integer model (governs all of §2)

- **R-INT-1.** On-chain quantity fields are 8-byte big-endian **uint64**. The canonical internal arithmetic model is **signed int64 with explicit overflow guards** (matches the current store, which decodes uint64 into int64). Any quantity whose uint64 value has the high bit set (`>= 2^63`) is **INVALID for the entire message** (creates nothing; still burns inputs). Applied identically to GENESIS initial_quantity, MINT additional_quantity, and EVERY SEND output quantity.
  - Status: SEND guards this (`if (q < 0)` after the int64 cast, `zslpstore.cpp` SEND branch). GENESIS/MINT cast `(int64_t)msg.initialQuantity` / `additionalQuantity` with **no high-bit check** — FIX.
  - This removes the signed/unsigned boundary at `2^63` as a fork surface and prevents a negative-amount UTXO from corrupting derived balances.
- **R-INT-2.** `be_to_u64` is the canonical big-endian decoder. Quantity pushes MUST be EXACTLY 8 bytes; the genesis/mint/send field readers already enforce `len != 8 => reject`. The 1..8-byte leniency inside `be_to_u64` (`slp.c:16`) is unreachable for quantities because the callers length-gate first; it MUST stay that way (no caller may pass a non-8-byte quantity). Status: OK, pin by test.

### 2.1 Message location and gating (parse)

- **R-PARSE-1 (BLOCKER).** The SLP message is parsed from **`tx.vout[0].scriptPubKey` ONLY**. A tx is an SLP candidate IFF `vout[0]` begins `OP_RETURN` and parses as a valid SLP message. No other vout is ever examined for a message.
  - Status: **FIX (CRITICAL).** `zslpindexer.cpp:211` loops `for (size_t vo = 0; vo < tx.vout.size(); ++vo)` and breaks on the "first valid OP_RETURN wins" (the `break` after `msgPresent`). This contradicts the file's own header (`slp.h:5`: "OP_RETURN outputs (vout[0])"). Replace the all-vout scan with a single `vout[0]` check.
  - Rationale: this is the single largest live ledger-fork bug. A vout[0]-strict wallet says "not SLP, inputs burned"; this indexer credits a SEND placed at vout[1]. Attacker shows each victim a different ledger.
- **R-PARSE-2.** If `vout[0]` is not a valid SLP message, the tx has **no SLP message** (`msgPresent = false`). Token inputs the tx spends are STILL burned (R-BURN-1). Additional `OP_RETURN`s at vout >= 1 are irrelevant by construction (defeats the multi-OP_RETURN fork, even for self-mined non-standard txs).
- **R-PARSE-3.** The coinbase transaction (`vtx[0]`) is SKIPPED for SLP message parsing. A coinbase whose vout[0] begins `OP_RETURN` is ignored.
- **R-PARSE-4 (no policy dependence).** Ledger validity depends ONLY on confirmed transaction bytes. NEVER consult `-datacarrier`/`-datacarriersize`, relay policy, mempool, wallet state, or the clock. The parser already operates on raw script and does not read these globals (OK); MUST stay decoupled — in particular, do NOT gate SLP parsing behind `TX_NULL_DATA`'s datacarrier size check.

### 2.2 Push grammar (script)

- **R-SCRIPT-1.** ZSLP fields use ONLY: direct push `0x01..0x4b`, `OP_PUSHDATA1` (`0x4c`), and `OP_PUSHDATA2` (`0x4d`). The reader MUST reject `OP_PUSHDATA4` (`0x4e`), `OP_0`, `OP_1NEGATE`, `OP_RESERVED`, and `OP_1..OP_16`.
  - Status: OK. `read_push` (`op_return_push.h:31-42`) accepts exactly `{0x01..0x4b, 0x4c, 0x4d}` and returns NULL otherwise. Do NOT gate solely on `TX_NULL_DATA`/`IsPushOnly`, which is looser (accepts `OP_0..OP_16`, `OP_PUSHDATA4`) and would fork the ledger if relied upon.
- **R-SCRIPT-2 (dual-encoding accepted, frozen).** A short value pushed via direct push and the same value via `OP_PUSHDATA1`/`OP_PUSHDATA2` MUST parse to the IDENTICAL message. There is NO minimal-push requirement in this canonical spec; the current lenient behavior is FROZEN as canonical (this differs from BCH SLP's minimal-push rule — deliberate, and pinned here so no implementation re-introduces a minimality check and forks). Status: OK, freeze by test vector.
- **R-SCRIPT-3 (Lokad + type).** Lokad prefix MUST be exactly `"SLP\x00"` and token_type exactly `1`. Any deviation => not SLP. Status: OK.
- **R-SCRIPT-4 (empty-field encoding).** Zero-length text fields (`ticker`/`name`/`document_url`) are accepted when pushed as a zero-length push. Oversize text (`len >= sizeof(buffer)`) is deterministically dropped to empty WITHOUT rejecting the message (current behavior, frozen). Status: OK (`slp.c:69,77,85`), freeze by test.
- **R-SCRIPT-5 (FIX — no trailing data for GENESIS/MINT).** After the last required field of GENESIS and MINT, the parser MUST verify the script is fully consumed (`p == end`); any trailing push => reject the entire message.
  - Status: FIX. `slp.c` returns `true` immediately after `initial_quantity`/`additional_quantity` and ignores trailing bytes. A strict parser rejects; this one accepts => fork.
- **R-SCRIPT-6 (field-length validity).**
  - `document_hash` push length MUST be exactly `0` or exactly `32`. Any other length => **reject the whole GENESIS**. Status: FIX — `slp.c:91-96` sets `has_document_hash` only at len==32 and otherwise silently treats it as "no hash" without rejecting.
  - `decimals` MUST be a 1-byte push with value `0..9`. Status: OK (`slp.c:101`).
  - `mint_baton_vout` push MUST be length 0 (no baton), OR length 1 with value `>= 2`. Length 1 with value `0/1` => reject (OK). **Length > 1 => reject** the whole message. Status: FIX — `slp.c:104-109` only special-cases `len == 1` and silently ignores `len > 1`.
  - Quantities MUST be exactly 8 bytes (R-INT-2). `token_id` MUST be exactly 32 bytes. Status: OK.

### 2.3 Token-id endianness

- **R-ID-1.** `tokenId` is the genesis txid as the node's internal `uint256` (little-endian internal bytes). GENESIS stores `tokenId = tx.GetHash()` directly (`zslpindexer.cpp` GENESIS branch). MINT/SEND read the 32-byte on-chain `token_id` field in display byte order and **byte-reverse** it via `TokenIdToUint256` so that a MINT/SEND quoting a genesis txid's display-hex resolves to the GENESIS's UTXOs. These MUST coincide (they do, because `GetHex()` prints reversed internal bytes). Status: OK but invariant is silent — pin with a GENESIS->MINT/SEND round-trip test.

### 2.4 GENESIS validity

- **R-GEN-1.** `tokenId == genesis txid`. The token row is inserted ONLY if absent (first-genesis-wins, idempotent under reorg-replay). Status: OK (`readToken` miss => `writeTokenBatch`).
- **R-GEN-2.** Initial quantity (R-INT-1 valid) is created as a token UTXO at **`vout[1]` only**, and only if `vout[1]` exists (`voutCount > 1`). Status: OK.
- **R-GEN-3 (FIX).** `totalMinted` counts ONLY quantity ACTUALLY created as a UTXO (overflow-guarded), NOT declared-but-uncreated. Status: FIX — GENESIS sets `token.totalMinted = msg->initialQuantity` UNCONDITIONALLY, before the `voutCount > 1` creation gate. A GENESIS with no vout[1] then reports a non-zero supply that an impl counting created UTXOs reports as zero => RPC supply fork.
- **R-GEN-4.** A mint baton is issued IFF `mint_baton_vout >= 2 AND mint_baton_vout < voutCount`, as a baton UTXO (amount 0, isBaton true) at that vout. Out-of-range baton vout => no baton. Status: OK.

### 2.5 MINT validity

- **R-MINT-1.** MINT is valid IFF the token is known (`readToken` hit) AND a live mint baton UTXO of that tokenId was on a spent input (`batonInputPresent`). Otherwise: create nothing; consumed inputs stay burned. Status: OK.
- **R-MINT-2.** Additional quantity (R-INT-1 valid) is created at `vout[1]` only, if it exists. Baton continues IFF a new `mint_baton_vout >= 2 AND < voutCount` is declared; not re-declaring the baton permanently ends minting for that token. Status: OK.
- **R-MINT-3 (FIX).** `totalMinted += additionalQuantity` only for quantity ACTUALLY created (R-GEN-3 logic). Overflow-guarded (OK). Status: align with R-GEN-3.

### 2.6 SEND validity, conservation, and transitive validity

- **R-SEND-1.** SEND quantity list MUST be **exactly 1..19** entries, each an exactly-8-byte push. A 20th 8-byte push makes the message **INVALID** (reject) — NOT "first 19 win".
  - Status: FIX (cap mismatch). Parser caps at 19 (`slp.c:151 while (num_outputs < 19)`, then `num_outputs < 1 => reject`), but the bridge/store clamp to 20 (`zslpindexer.cpp` `if (n > 20) n = 20` and `zslpstore.cpp` SEND branch `if (n > 20) n = 20`). Reconcile to a SINGLE constant `ZSLP_SEND_MAX_OUTPUTS = 19` used by parser, bridge, store, AND the `outputQuantities`/array bounds; `> 19` quantities => INVALID, not truncated.
- **R-SEND-2 (transitive validity / availIn).** `availIn(T)` = sum of the **token UTXO amounts of tokenId T** consumed on this tx's inputs. An input that is NOT a recognized token UTXO of T contributes **ZERO**. Batons contribute 0 to availIn. This is the transitive-validity anchor: a token UTXO only enters availIn because it is an actual spent prevout the store recognizes, which transitively traces back to a GENESIS over confirmed blocks; consensus' own scriptSig check guarantees the spender actually owns the carrying dust. Status: OK (`readUtxo` per input; unknown => `continue`).
- **R-SEND-3 (budget + overflow).** `requiredOut` = sum of output quantities with an explicit int64 overflow guard; overflow => SEND INVALID. SEND is valid IFF `availIn(T) >= requiredOut`; surplus (`availIn - requiredOut`) is BURNED (never created). Status: OK.
- **R-SEND-4 (output-index bounds — PIN to "burn-that-quantity").** Output quantity `j` maps positionally to `vout[1 + j]`; a zero-quantity output consumes a slot but creates nothing. **The budget check (R-SEND-3) runs FIRST over all declared quantities.** Then, when creating, a positive quantity whose target `vout[1+j] >= voutCount` is BURNED (that quantity only); in-range outputs are still created.
  - **NOTE — this is the one rule where the six reviews split.** Two readings exist:
    - **Reading A (current code, PINNED CANONICAL):** out-of-range positive quantity burns only that quantity; other outputs apply. (`zslpstore.cpp` SEND branch: `if (voutIdx >= voutCount) continue;`.)
    - **Reading B (rejected):** any positive quantity to a nonexistent vout makes the WHOLE SEND invalid.
  - **Decision: PIN Reading A** (matches the current store and the dos-spam-grief review's R5; the determinism/forgery reviews proposed B but Reading A is equally deterministic, is already implemented, and never inflates — it only ever burns). Both are safe; what matters is that ALL implementations pick the SAME one. This spec freezes **Reading A** at version 1. The published test vector (§8) makes the choice unambiguous. Status: OK under Reading A.
- **R-SEND-5 (NFT non-duplication, derived).** Because availIn for a qty-1 NFT is at most 1, any SEND requesting > 1 (or by a non-holder, availIn 0) is INVALID and creates nothing (over-claim burns the single UTXO). A baton-less GENESIS means no MINT can ever add a second unit. Status: OK (gtest `NftCannotBeDuplicated`).

### 2.7 Burn rules (apply to EVERY tx)

- **R-BURN-1.** Every transaction — SLP or not, valid or not — CONSUMES every spent live token UTXO. Any consumed token UTXO not validly re-created by a valid SLP message of its tokenId is thereby BURNED. Status: OK (consume step (a) runs for every tx before dispatch).
- **R-BURN-2.** A spent prevout that is not a recognized token UTXO contributes nothing (no effect). Consume happens BEFORE create within a tx. Status: OK.
- **R-BURN-3 (intra-block ordering).** Transactions are applied strictly in `block.vtx` order, each tx's writes visible to the next tx's reads (per-tx batch commit). A GENESIS in tx1 and a SEND spending it in tx2 of the SAME block both apply correctly. Status: OK.

### 2.8 Read/RPC ordering and balances (observable surface)

- **R-RPC-1.** `zslp_listtokens` is ordered by raw-byte `tokenId` key order (leveldb key order). NORMATIVE so an alternate-store impl reproduces it.
- **R-RPC-2.** `zslp_listtransfers` is height-ascending then reversed to newest-first, tie-broken by txid then BE(vout). NORMATIVE.
- **R-RPC-3.** `balance(token, addr) == sum over live non-baton token UTXOs of that token at that address`. This invariant MUST hold after every block (checked by an after-each-block invariant test).
- **R-RPC-4 (confirmations).** Read-side RPC exposes `confirmations = chainActive.Height() - record.height + 1` per token/UTXO/transfer (computed under `cs_main`; ledger unchanged). No depth concept exists in the store today — this is read-side only.

### 2.9 Reorg / determinism over reorgs

- **R-REORG-1.** State is mutated ONLY from `ChainTip` connect/disconnect, never from the mempool/write path. Status: OK.
- **R-REORG-2.** Every connect-side mutation appends a paired typed undo op; `DisconnectBlock` replays the undo log in reverse to restore **byte-identical** pre-connect state (incl. same-block create-then-consume netting). Status: OK by design; MUST be locked by a connect/dump vs connect+disconnect/dump equality test.
- **R-REORG-3.** Post-reorg incremental ledger EQUALS a from-scratch reindex of the winning chain. Crash-resume (resume one past stored tip) and a re-delivered connect for the current tip are no-ops. Status: OK (idempotence guard `zslpindexer.cpp:180-183`); lock by tests.
- **R-REORG-4.** Undo is bounded by consensus: no reorg deeper than `MAX_REORG_LENGTH = COINBASE_MATURITY - 1` (= 99; `main.h:58`, hard shutdown) is ever applied; auto-finalization at `DEFAULT_MAX_REORG_DEPTH = 10` (`main.h:116`). No superlinear undo cost. Status: OK.

---

## 3. Threat Table

Severity: CRITICAL (active ledger fork or guaranteed holder loss) / HIGH / MEDIUM / LOW / INFO (already neutralized).

| # | Attack | Why on-chain unstoppable | Overlay defense (canonical rule) | Residual risk | Severity |
|---|--------|--------------------------|----------------------------------|---------------|----------|
| T1 | **Message-position fork**: payment at vout[0], SLP SEND at vout[1+]. This indexer credits it; a vout[0]-strict impl burns. Two ledgers. | `TX_NULL_DATA` has no positional constraint; multi-output tx with OP_RETURN at any index is standard and confirmable. | R-PARSE-1/2: parse vout[0] ONLY; non-vout[0] => not SLP, inputs still burned. | NONE once the all-vout scan (`zslpindexer.cpp:211`) is deleted and tested. **HIGHEST-severity live bug.** | CRITICAL |
| T2 | **Multi-OP_RETURN fork**: two SLP messages at low vouts; observers key on different ones. | `nDataOut>1` rejected only by relay policy; a self-mined block carrying it is consensus-valid. | R-PARSE-2: vout >= 1 OP_RETURNs are ignored by construction. | NONE once R-PARSE-1 lands. | CRITICAL |
| T3 | **Holder self-burn**: ordinary send/auto-shield/sweep picks a token dust UTXO as fee/change; the non-SLP tx burns the NFT. | Token rides ordinary t-dust; consensus sees only ZCL value and spends it. Dust threshold ~100 sats (`DEFAULT_MIN_RELAY_TX_FEE=100`, `main.h:64`) dwarfs a 1-sat NFT, so dust-to-fee fold burns it silently. | NOT a determinism issue — the burn is the deterministically-correct interpretation. Wallet-side only: R-WALLET-1..6. | HIGH until wallet coin-selection consults the token store. Document prominently. | CRITICAL |
| T4 | **Forged SEND / over-send / MINT-without-baton / unknown-token MINT / NFT-dup**. | Any OP_RETURN naming any token/quantity is a standard tx; consensus does no token math. | R-SEND-2/3 (availIn; unknown input = 0; under-funded => INVALID+burn), R-MINT-1 (baton input required), R-GEN-1 (id==txid). Tested: ForgedSendCreditsNobody, OverSendBurnsInputsNoOutputs, MintWithoutBatonRejected, NftCannotBeDuplicated. | None ECONOMICALLY, PROVIDED every impl computes availIn/requiredOut identically (depends on T5-T9). | INFO |
| T5 | **uint64 high-bit / overflow fork**: quantity `>= 2^63` (GENESIS/MINT cast int64 with no guard), or output-sum overflow. | 8-byte `0xFFFF...` is valid script data; consensus never sums. | R-INT-1 (high-bit => whole message INVALID, all three types), R-SEND-3 (sum overflow => INVALID). | GENESIS/MINT need the high-bit check added (SEND already has it). | HIGH |
| T6 | **Trailing-data / field-length fork**: extra push after GENESIS/MINT last field; non-{0,32} document_hash; baton push len>1. | Extra pushes keep the script push-only => still `TX_NULL_DATA`, confirms. | R-SCRIPT-5 (p==end for GENESIS/MINT), R-SCRIPT-6 (doc_hash {0,32}; baton len {0,1}). | Parser changes required (`slp.c`). | HIGH |
| T7 | **SEND cap fork**: 20th quantity; parser caps 19, store clamps 20. | Quantity-list length is independent of tx output count. | R-SEND-1: single `ZSLP_SEND_MAX_OUTPUTS=19`; > 19 => INVALID. | Reconcile parser/bridge/store to one constant. | HIGH |
| T8 | **Out-of-range output fork** (Reading A vs B). | Declared quantities independent of `tx.vout` count. | R-SEND-4: PIN Reading A (burn that quantity, apply in-range; budget-checked first). | NONE once the pinned reading is published as a test vector and both impls match. | HIGH |
| T9 | **totalMinted supply fork**: GENESIS/MINT with no vout[1] still bumps `totalMinted`. | A GENESIS/MINT tx with only the OP_RETURN output is confirmable. | R-GEN-3/R-MINT-3: count ONLY created quantity. | RPC supply diverges; FIX required in store. | MEDIUM |
| T10 | **RPC/list ordering fork** across alternate stores. | Ordering is observer presentation; consensus uninvolved. | R-RPC-1/2/3: orderings + balance invariant NORMATIVE. | Lower: divergence is presentation/pagination, not core UTXO truth. | MEDIUM |
| T11 | **Impersonation/clone token**: new genesis txid reusing victim's ticker/name/url/image-hash. | GENESIS imposes no metadata uniqueness/auth; consensus has no SLP notion. | NOT neutralizable on-chain — both are legitimately distinct tokens (different tokenIds). UX-honesty only: R-UX-1..5 + R-ATTEST-1/2. | Inherent and permanent; reduced to a social-trust problem. | MEDIUM (HIGH if GUI implies authenticity) |
| T12 | **Set/collection spoof**: children claiming a set's name with no cryptographic tie. | Set membership by name is unauthenticated. | Convert to a baton-input problem via NFT1 group/child (child spends a real group input) — REQUIRES adding the group/child rule to the spec with tests before any "verified set" UI claim. | Until specified+tested, membership is issuer-claimed and spoofable by name. | MEDIUM |
| T13 | **Confirmed-vs-unconfirmed / shallow-conf**: victim acts on an unconfirmed or 1-9-conf receipt; double-spend or reorg (depth < 10) orphans it. | Mempool/shallow txs are replaceable/reorgable; consensus promises nothing below finalization. | R-REORG-1 (no mempool path into ledger), R-RPC-4 (expose confirmations), R-UX-6/7 (pending-until-N, N=10; live read each ChainTip). | UI must enforce the split; high-value transfers may want N>10. | HIGH |
| T14 | **Reorg replay divergence**: two nodes compute different post-reorg ledgers. | Overlay keeps its own auxiliary store; a buggy disconnect could miss a paired undo. | R-REORG-2/3: byte-exact undo; incremental == from-scratch reindex. | Only as true as its tests; a new mutation site without a paired undo silently breaks — locked by the round-trip property test. | MEDIUM |
| T15 | **RPC DoS amplification**: spam thousands of tiny tokens/transfers; `ListTransfers` materializes the ENTIRE set then reverses (`zslpstore.cpp:777-799`); `GetTokensForAddress` full keyspace scan per wallet key. | Each genesis/send is a normal fee-paying standard tx. | Index is derived/disposable (bounded by chain size). FIX amplification: stream + early-stop `ListTransfers` at `from+count`; clamp `count` at the store boundary; address-keyed view or documented scan cap. | On-chain bloat itself is unpreventable (index mirrors chain); only the one-cheap-tx-to-expensive-RPC amplification is closeable. | HIGH |
| T16 | **Abusive/unsolicited token content**: offensive name/url airdropped to a victim; persists on-chain forever. | Paying an address is the chain's core function. | Presentation only: default-hide unsolicited/unverified; never auto-fetch document_url/media; render name/ticker as plain text (markup-stripped, length-clamped) with the genesis-txid fingerprint. | Bytes remain on-chain/in-index permanently; GUI can hide but not erase. State honestly. | MEDIUM |
| T17 | **Image-hash authenticity confusion**: a clone reusing the same image shows the same "match" badge; user reads it as "authentic". | `document_hash` proves bytes match SOME genesis, never WHICH is original; consensus records no issuer. | UX copy: badge means "matches THIS token's recorded fingerprint" only; never authentic/official/original. | Social engineering against users who ignore the tokenId; honest copy bounds but cannot eliminate. | HIGH (UX) |

---

## 4. Holder Anti-Burn Requirement (wallet must lock token UTXOs)

**Confirmed: the wallet has ZERO ZSLP awareness today** (`grep -ril zslp src/wallet/` is empty). A ZSLP token (and NFT) rides a transparent dust UTXO whose ownership lives only in the overlay ledger keyed by `(txid,vout)`. The single coin enumerator `CWallet::AvailableCoins` filters only spent/not-mine/locked/`nValue>0` — no token filter — so EVERY spend path (sendtoaddress, sendmany, z_sendmany `find_utxos`, z_shieldcoinbase, z_mergetoaddress, fundrawtransaction, GUI send/shield/send-max) can select a token UTXO. The sharpest edge is the dust-to-fee fold in `CreateTransaction` (`nFeeRet += nChange`, change dropped): with the ~100-sat dust threshold, a 1-sat NFT output is virtually always classified dust and folded into the miner fee — silently burning the token.

The overlay can only RECORD the burn (it is forbidden to touch validation/mempool); it can NEVER prevent it. **Anti-burn is a wallet property.** The store already exposes the exact primitive needed: `CZSLPStore::GetUtxo(txid,vout,out)`.

Requirements (see R-WALLET-* in §7):

- **Identify** token UTXOs and mint batons via the local zslp store (a read-only RPC mapping `(txid,vout) -> {tokenId,amount,isBaton,decimals}`, delegating to `GetUtxo`; batch classification so `AvailableCoins` does one store traversal).
- **Exclude** them from ALL automatic coin selection (fee/change/normal send/auto-shield/`shield all`/merge/send-max/dust consolidation) by default, at the same chokepoint that honors `IsLockedCoin`. Belt-and-suspenders: assert no selected input is a token UTXO before signing, so the dust-to-fee fold can never consume one.
- **Surface** them in coin control and `listunspent`, labeled `{tokenId, ticker, amount, isBaton}` with a "spending outside a token SEND BURNS it" warning, listed but unchecked by default.
- **Spend deliberately only**: a token UTXO is spendable solely via an explicit token-transfer flow or explicit coin-control opt-in, behind an acknowledged warning naming the token and its irreversibility.
- **Conserving SEND builder**: places the canonical SLP OP_RETURN at vout[0], recipients at vout[1..], adds a token CHANGE output for surplus, includes only intended token inputs, and **self-validates the constructed tx against this canonical spec before broadcast**.
- **Baton protection**: treat a mint baton like a token UTXO; never auto-spend it; explicit MINT keeps it alive unless the user ends minting.
- **Fail-safe when `-zslpindex` is off/unreachable**: do NOT fail open into a burn — refuse to auto-spend sub-threshold transparent dust (or block with an "enable -zslpindex" message), and degrade send-max/sweep conservatively. A wallet that sources balances independently MUST use the SAME canonical rules as the daemon and pass the published test vectors.

---

## 5. Impersonation Defense + the Honest Uniqueness Statement

Uniqueness exists ONLY at the token-id (genesis-txid) level (`tokenId == genesis txid`, collision-free because txids are unique under consensus). Anyone can mint a DIFFERENT token (new genesis txid) reusing any ticker/name/document_url/document_hash — even pointing document_hash at the genuine image. Both are legitimately, deterministically distinct tokens. **This cannot be neutralized on-chain or by the overlay**; it is a valid-by-design use of an open protocol.

Defense is layered and explicitly OFF-consensus:

- **Identity = tokenId.** All value actions (send/buy/gift) resolve the target by tokenId, never by user-typed name. A name search may aid discovery but the user MUST confirm the tokenId before any value action.
- **Issuer attestation (optional, off-chain).** Define a canonical byte-exact attestation string binding `tokenId <-> address/pubkey`, signed with the genesis funding key or a published brand key via the existing `signmessage`/`verifymessage`. Verify path: `(tokenId, address/pubkey, signature) -> valid/invalid`. No consensus, no new on-chain data.
- **Verified-issuer list keyed BY TOKENID ONLY** (never name/ticker), versioned, provenance shown. The badge means "on a list maintained by <named party>", never "protocol-guaranteed authenticity".
- **Image-hash badge** means ONLY "these bytes match THIS token's recorded fingerprint" — never authentic/official/original.
- **Lookalike indicator** fires when distinct tokenIds share a name/ticker/image-hash, instead of silently resolving to one.
- **Set membership** is shown as issuer-claimed until the NFT1 group/child rule (T12) is specified+tested.

### The HONEST uniqueness statement for the GUI

> **What "unique" / "authentic" actually means here.** This token is identified by its **genesis transaction id (tokenId)**, which is globally unique — there is exactly one genesis on the ZClassic chain with this id, and the overlay guarantees its quantity (for an NFT, the single 1-of-1 unit) can never be duplicated, inflated, or forged into someone else's wallet, as long as you and your counterparty compute the ledger by the same published rules. **What it does NOT mean:** it does NOT mean the name, ticker, image, or description is unique — anyone can create a *different* token (a different tokenId) that reuses this exact name and image. A matching image hash proves the picture's bytes match what this tokenId committed to; it does NOT prove this tokenId is "the original", "official", or made by any particular person. The chain does not record or verify who an issuer is. Trust an issuer only via their tokenId fingerprint and an out-of-band signed attestation (or a verified-issuer list naming its maintainer) — never via a name, a green check, or an image. And remember: **this is a non-consensus overlay** — ZClassic's consensus rules do not enforce any of this; safety comes from every honest wallet/explorer recomputing the identical ledger, not from the network rejecting bad token transactions.

---

## 6. Reorg / Confirmation Safety

Strong properties to PRESERVE (verified): (1) the indexer overrides only `ChainTip` and never `SyncTransaction` — no mempool/0-conf path; a record exists only after a confirmed block connect under `cs_main` post-flush. (2) A typed per-block undo log replays in reverse for byte-identical pre-state, with correct same-block create-then-consume netting. (3) Crash-resume + re-delivery idempotence. (4) Node bounds reorgs: auto-finalize at depth 10, hard shutdown at 99.

Gaps to close:

- **No confirmation-depth concept exists** anywhere in `src/zslp/*` or `src/rpc/zslp.cpp` (verified by grep). Records are always >= 1 conf, but **1-9 confs are NOT reorg-safe** (node applies reorgs up to 99 deep, finalizes at 10). The RPC MUST expose `confirmations = tipHeight - height + 1` (R-RPC-4); the GUI MUST show ownership/authenticity as **PENDING until N confirmations**, then FINAL, with `N = DEFAULT_MAX_REORG_DEPTH = 10` via a single named constant so UI-final aligns with node finalization (high-value transfers may warrant N > 10).
- The GUI MUST read live store state on every `ChainTip` and never cache an "owned" flag across blocks, so a reorg that orphans a transfer demotes it within one tip.
- A mempool-only transfer MUST NEVER be shown as received/owned; any pending-send indicator is explicitly labeled unconfirmed/not-final and visually distinct from owned.
- Lock byte-exactness: a connect/dump vs connect+disconnect/dump equality property test; a two-branch reorg vs full-reindex equality test; idempotent re-delivery and crash-resume tests; a multi-tx-in-block reorg case (tx2 spends tx1's created output).

---

## 7. Requirements Checklist (each item testable)

Legend: **BLOCKER** = must land before any token can be safely held/transferred. Status reflects the working tree.

### Indexer / store (the conservation rewrite must satisfy)

- [ ] **R-1 (BLOCKER)** Mutate the store ONLY from `ChainTip` connect/disconnect; never override `SyncTransaction` or read the mempool in the write path. *Test:* a mempool-only tx produces no store record. (Today: OK.)
- [ ] **R-2 (BLOCKER, FIX)** Parse the SLP message from `tx.vout[0]` ONLY; delete the all-vout scan at `zslpindexer.cpp:211` ("first valid OP_RETURN wins"). *Test:* payment at vout[0] + valid SLP SEND at vout[1] spending a token UTXO => create nothing, burn inputs. (R-PARSE-1/2)
- [ ] **R-3** Skip the coinbase for SLP parsing. *Test:* coinbase with OP_RETURN at vout[0] ignored. (R-PARSE-3)
- [ ] **R-4** Two parseable OP_RETURNs (vout0+vout1) yield vout[0]'s result alone. *Test:* vout[1] message has zero effect. (R-PARSE-2)
- [ ] **R-5** Push grammar = `{0x01..0x4b, 0x4c, 0x4d}` only; reject `0x4e/OP_0/OP_1NEGATE/OP_1..OP_16`; do not gate on `IsPushOnly`. *Test per case.* (R-SCRIPT-1) (Today: OK.)
- [ ] **R-6** Dual-encoding (direct vs PUSHDATA1/2) parses identically; lenient non-minimal pushes FROZEN as canonical. *Test:* token_type 1 via both encodings yields equal parse. (R-SCRIPT-2)
- [ ] **R-7 (FIX)** GENESIS/MINT require `p == end` after the last field; trailing push => reject. *Test:* GENESIS + one appended push => not SLP. (R-SCRIPT-5)
- [ ] **R-8 (FIX)** `document_hash` length exactly 0 or 32; baton push length 0 or (1 and value>=2), len>1 => reject; decimals 1 byte 0..9; quantities exactly 8 bytes; token_id exactly 32. *Tests:* 31-byte hash, baton len 2, baton value 1, decimals 10, 7-byte quantity => all not SLP. (R-SCRIPT-6, R-INT-2)
- [ ] **R-9** token_id endianness: a MINT/SEND quoting the genesis txid's display-hex resolves the GENESIS's UTXOs. *Test:* round-trip. (R-ID-1)
- [ ] **R-10 (FIX)** Any quantity with the high bit set (`>= 2^63`) => whole message INVALID for GENESIS, MINT, and every SEND output. *Tests:* `2^63` and `2^64-1` for all three types. (R-INT-1)
- [ ] **R-11** SEND `requiredOut` overflow-guarded => INVALID; valid IFF `availIn >= requiredOut`; surplus burned; unknown/non-token/baton inputs contribute 0. *Tests:* sum at int64-max valid, +1 invalid; forge-send credits nobody; over-send burns. (R-SEND-2/3)
- [ ] **R-12 (FIX)** Single constant `ZSLP_SEND_MAX_OUTPUTS = 19` in parser, bridge, store, and array bounds; > 19 quantities => INVALID (not truncated to 20); 0 quantities => INVALID. *Tests:* 0/19/20 outputs. (R-SEND-1) — reconciles `slp.c:151` (19) vs `zslpindexer.cpp`/`zslpstore.cpp` (clamp 20).
- [ ] **R-13** Out-of-range positive output index => that quantity burned, in-range outputs still created (PIN Reading A); budget-checked first. *Test:* 3 quantities on a 2-output tx => vout[1] created, the rest burned. (R-SEND-4)
- [ ] **R-14** Every tx burns spent token UTXOs not validly re-created; consume-before-create; non-token input = 0. *Tests:* non-SLP tx spending a token UTXO burns it; invalid SEND burns inputs. (R-BURN-1/2)
- [ ] **R-15** Block.vtx order respected; tx2 can spend tx1's created output in the same block. *Test:* same-block genesis + send. (R-BURN-3)
- [ ] **R-16** GENESIS: `tokenId == txid`; first-genesis-wins INSERT-only (idempotent). *Test:* re-applying the same genesis block is a no-op. (R-GEN-1)
- [ ] **R-17 (FIX)** `totalMinted` counts ONLY quantity actually created as a UTXO (overflow-guarded), GENESIS and MINT. *Test:* GENESIS/MINT with no vout[1] => totalMinted unchanged, no UTXO. (R-GEN-3/R-MINT-3)
- [ ] **R-18** Baton issued/continued IFF `2 <= mint_baton_vout < voutCount`; MINT valid IFF a live baton input of that token; not re-declaring the baton ends minting. *Tests:* baton vout >= voutCount => no baton; MINT without baton => create nothing; MINT not re-declaring baton ends it. (R-GEN-4, R-MINT-1/2)
- [ ] **R-19** Unknown-token MINT issues nothing. *Test:* MINT of a never-genesised id => no token, no UTXO. (R-MINT-1)
- [ ] **R-20** Reorg: connect/dump == connect+disconnect/dump (byte-identical), incl. same-block create-then-consume and multi-delta-same-address. (R-REORG-2)
- [ ] **R-21** Post-reorg incremental ledger == from-scratch reindex of the winning chain; re-delivered tip + crash-resume are no-ops. *Tests:* two-branch reorg vs reindex equality; idempotent re-delivery. (R-REORG-3)
- [ ] **R-22** Undo never asked to exceed `MAX_REORG_LENGTH = 99`. (R-REORG-4)
- [ ] **R-23** `balance(token,addr) == sum of live non-baton token UTXOs` — after-each-block invariant test. (R-RPC-3)
- [ ] **R-24 (FIX)** `ListTransfers` peak memory/CPU is O(from+count), not O(total); clamp `count` at the store boundary; bound `GetTokensForAddress`. *Test:* > `ZSLP_LIST_MAX` transfers for one token. (T15)
- [ ] **R-25** RPC list orderings normative (R-RPC-1/2); `confirmations` exposed (R-RPC-4). *Test:* ordering + a confirmations value matching `tipHeight - height + 1`.

### Wallet (holder anti-burn)

- [ ] **R-WALLET-1 (BLOCKER)** Read-only RPC + in-process batch classification mapping `(txid,vout) -> {tokenId,amount,isBaton,decimals}` via `GetUtxo`; no ledger logic in the wallet. *Test:* NFT outpoint reports qty 1/baton false; random outpoint not-a-token; 1000-UTXO wallet classified in one pass.
- [ ] **R-WALLET-2 (BLOCKER)** `AvailableCoins` excludes token UTXOs and batons from default selection (alongside `IsLockedCoin`) when `-zslpindex` is on. *Test:* 1000 randomized sends never select the NFT outpoint.
- [ ] **R-WALLET-3 (BLOCKER)** Dust-to-fee fold and change construction can never consume a token UTXO; assert no selected input is a token UTXO before signing. *Test:* a tx that would route an NFT to fee makes `CreateTransaction` fail with a token-protection error, not a burn.
- [ ] **R-WALLET-4** z_sendmany `find_utxos`, z_mergetoaddress, z_shieldcoinbase inherit the exclusion; shield/merge-ALL skip token UTXOs even on "*". *Test:* `z_shieldcoinbase "*"` / merge leave the NFT untouched.
- [ ] **R-WALLET-5** Send-max / empty-wallet compute spendable EXCLUDING token UTXO values. *Test:* NFT + 10 ZCL => send-max sends ~10 ZCL minus fee, NFT unspent.
- [ ] **R-WALLET-6** Fail-safe with `-zslpindex` off/unreachable: refuse/route-around sub-threshold dust with a warning; never fail open. *Test:* index off => sub-threshold-dust send blocked or routed around, no silent burn.
- [ ] **R-WALLET-7** `listunspent` + coin control annotate token UTXOs `{tokenId,amount,isBaton,ticker,name}` + "do not spend as fee" flag, unchecked by default. *Test:* token object emitted; coin-control row badged + unchecked.
- [ ] **R-WALLET-8** Spending a token UTXO requires explicit coin-control selection or the dedicated token-transfer flow, behind an acknowledged irreversibility warning naming the token. *Test:* spend outside the token flow rejected; inside it user sees name + confirm gate.
- [ ] **R-WALLET-9** Token SEND builder: OP_RETURN at vout[0], recipients vout[1..], token change output for surplus, only intended token inputs, and self-validates the built tx against this spec before broadcast. *Test:* NFT transfer yields SLP SEND at vout[0], qty 1 to recipient, supply unchanged, sender no longer owns it.
- [ ] **R-WALLET-10** Baton treated as a token UTXO for anti-burn; never auto-spent; explicit MINT keeps it alive unless the user ends minting. *Test:* ordinary send never selects the baton.
- [ ] **R-WALLET-11** CI anti-burn regression suite: ordinary send, dust-to-fee, shield/merge, send-max, index-off fail-safe, conserving transfer, baton protection.

### GUI (honesty + confirmation safety)

- [ ] **R-UX-1** Identify tokens primarily by tokenId (genesis txid); copyable. *Test:* two same-name tokens show distinct tokenIds + a "name not unique" cue.
- [ ] **R-UX-2** No on-chain-derived "verified" badge. Verified-issuer badge (if any) names its maintainer and is visually distinct from the image-match badge; absence reads "Unverified issuer", never "fake". *Test:* UI copy review.
- [ ] **R-UX-3** Image-match badge copy = "matches its on-chain fingerprint" ONLY; never authentic/official/original. *Test:* copy review; clone reusing the image is not implied genuine.
- [ ] **R-UX-4** Issuer identity only via out-of-band signed attestation (R-ATTEST) or a tokenId-keyed verified list; labeled social/external. *Test:* no "verified by network" wording.
- [ ] **R-UX-5** Lookalike/collision indicator when distinct tokenIds share a name/ticker/image-hash; value actions resolve by tokenId, confirmed before sending. *Test:* collision surfaced; name search requires id confirmation.
- [ ] **R-UX-6** Ownership/authenticity shown PENDING until N confirmations, then FINAL; `N = DEFAULT_MAX_REORG_DEPTH = 10` via one named constant. *Test:* a 5-conf receipt shows pending; a 10-conf shows final.
- [ ] **R-UX-7** Read live store state each ChainTip (no cached owned flag); a mempool-only transfer never shown as owned, any pending-send labeled not-final and visually distinct. *Test:* reorg demotes an orphaned item within one tip.
- [ ] **R-UX-8** Default-hide unsolicited/unverified tokens (per-token/per-issuer opt-in); never auto-fetch/render `document_url` or media; render ticker/name as plain text (markup-stripped, control-chars stripped, length-clamped) with the tokenId. *Test:* unsolicited token hidden; URL not fetched without explicit action.
- [ ] **R-UX-9** State plainly that on-chain bytes are permanent (hideable, not erasable), that consensus enforces no token rules, and that burn loss is irreversible (the overlay only records it). With `-zslpindex` off, provenance/verify degrade to a calm "can't verify — token index is off", never a false green or crash. *Test:* dialog/copy review.

### Attestation + interop

- [ ] **R-ATTEST-1** Canonical byte-exact attestation string binding `tokenId <-> address/pubkey` with sign (genesis funding key or published brand key via `signmessage`) and verify paths. No consensus, no new on-chain data.
- [ ] **R-ATTEST-2** Verified-issuer list keyed by tokenId only, versioned, provenance shown, source configurable/signed.
- [ ] **R-NFT1** (DEFERRED, before any "verified set" UI) NFT1 group/child membership rule (child proves membership by spending a real group baton/quantity input) added to this spec WITH determinism tests; until then membership is "issuer-claimed".

### Closure criterion (the threat class stays OPEN until this passes)

- [ ] **R-VECTORS** Publish a VERSIONED file `{raw_op_return_hex -> expected parse result}` and `{block_of_txs -> expected ledger snapshot (UTXO set / balances / token rows)}` covering EVERY adversarial vector above: vout[1] message, two OP_RETURNs, PUSHDATA2/4 + OP_N fields, dual encoding, trailing byte (GENESIS/MINT), 31-byte hash, baton len>1, decimals 10, `2^63`/`2^64-1` quantities (all three types), 19/20/0 SEND outputs, out-of-range output index, sum overflow, unknown-token MINT, MINT-without-baton, no-vout[1] GENESIS/MINT, same-block genesis+send, two-branch reorg, re-delivered tip, crash-resume.
- [ ] **R-DIFF** A SECOND independent implementation of `F`, fed the identical history including all of R-VECTORS, produces a BIT-IDENTICAL token ledger AND RPC output (verified via a read-only dump/validate RPC emitting the full token-UTXO set + balances at a height, diffable in CI). The threat class stays OPEN until this differential test exists and passes.

---

## 8. Versioning Note

Because security IS cross-implementation bit-exact agreement, the canonical rules are a contract that external wallets and explorers must implement identically. Therefore:

- This document is the NORMATIVE spec at **`ZSLP_SPEC_VERSION = 1`**. It is published (committed in-tree under `doc/nft/`) so any third party can implement `F` and prove agreement.
- The published test-vector corpus (R-VECTORS) is part of the versioned contract and is the authoritative tiebreaker for any ambiguity in prose.
- ANY change to a frozen `R-*` rule changes the ledger function. Such a change MUST: (a) bump `ZSLP_SPEC_VERSION`; (b) bump the on-disk `ZSLP_INDEX_VERSION` (`zslpstore.h`), which already triggers a wipe + reindex; and (c) update the published test vectors. The two version numbers move together so a node never silently computes a different ledger than its stored index version implies.
- Until R-DIFF passes against a second implementation, treat the overlay as EXPERIMENTAL and gate any "uniqueness/authenticity" UX claim behind the honesty statement in §5.

---

*Synthesized from six independent threat reviews (determinism-fork, forgery-conservation, holder-anti-burn, impersonation-uniqueness, reorg-confirmation, dos-spam-grief). All code citations re-verified against the working tree. No source under `src/` was edited by this workflow.*
