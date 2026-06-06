# ZSLP Forgery / Conservation Threat Model

Threat class: **forgery-conservation** — direct token forgery and inflation.

Scope: the NON-consensus ZSLP (SLP Token Type 1) overlay in this repo
(`src/zslp/*`, `src/rpc/zslp.cpp`), behind `-zslpindex`, in `CZSLPIndexer` /
`CZSLPStore`. This document is the **security model + canonical validation
spec + requirements checklist**. It edits no source under `src/`.

---

## 0. The unavoidable starting point

We **cannot change ZClassic consensus.** Minters and users run existing,
unchanged consensus nodes. Base consensus does not know ZSLP/SLP exists: it
relays and mines ANY standard transaction, including an `OP_RETURN` that
encodes a *forged* token SEND with no token inputs, a MINT with no baton, a
SEND quoting a token id you have never owned, output indices past the end of
the tx, or quantities that sum past 2^64.

Therefore **token validity is never enforced by the chain refusing the tx.**
Every forgery in this threat class CAN be mined and CAN sit in the confirmed
block history forever. The on-chain transaction is real. What is NOT real is
its *token effect*.

Security here is exactly two properties:

1. **DETERMINISM** — the token ledger is a pure function of the
   consensus-ordered, confirmed block history. Given the same blocks, every
   honest observer computes the identical ledger.
2. **AGREEMENT** — every compatible implementation (this `-zslpindex`, a
   wallet, an explorer) computes that *identical* ledger, bit for bit, on
   every edge case. There is no consensus to fall back on; if two
   implementations disagree on one edge case, the ledger FORKS and an attacker
   shows conflicting "ownership" to two parties. **Cross-implementation
   bit-exact agreement IS the security property.**

A forgery is neutralized when the canonical rules interpret it as
**crediting nobody** — i.e. it creates no token UTXO and changes no honest
observer's balances — and any token UTXOs it spent are **burned** (consumed,
not re-created). This is the design the store already implements
(`zslpstore.cpp` header comment, lines 8–20).

---

## 1. The conservation model (what makes forgery a no-op)

The ledger is **UTXO-bound**. The source of truth is a map

```
(txid, vout) -> { tokenId, amount, isMintBaton, address, height }
```

persisted under the `'u'` key (`CZSLPTokenUtxo`, `zslpstore.h:121`). Per-
address balances under `'b'` are a **derived view**, kept correct by signed
deltas (`zslpstore.cpp:367` `recordBalanceDelta`, `:386` `flushBalances`).
The token row under `'t'` (`CZSLPToken`) holds genesis metadata + issued
`totalMinted` + a baton display-mirror.

Every transaction — SLP or not — runs `ApplyTransaction`
(`zslpstore.cpp:413`). The order is the whole defense:

1. **CONSUME first.** For every `vin` prevout that is a known token UTXO,
   the store erases the `'u'` record and reverses its balance credit
   (`zslpstore.cpp:437-446`, `consumeUtxo` `:342`). Quantity inputs are summed
   into `availByToken[tokenId]`; a baton input sets
   `batonInputPresent[tokenId]`. **An input that is not a recognized token
   UTXO contributes ZERO** (`readUtxo` miss → `continue`, `:439`). This is the
   "unknown input = zero" rule, and it is the foundation of conservation.
2. **CREATE only as far as inputs permit.** Then dispatch on the parsed
   message; create new `'u'` records only up to what step 1 made available.
   Anything not re-assigned by a valid message of its token id is left
   consumed — i.e. **burned**.

This makes every member of the forgery-conservation class a no-op or a burn.
The exact rule each relies on is enumerated in §3.

---

## 2. The trust chain: transitive validity back to genesis

The store does NOT re-walk history per transaction; it keeps a *materialized*
UTXO set. But the materialized set is itself the fixed point of a transitive
rule, and the security argument is transitive:

- A token UTXO exists in `'u'` **iff** some prior `ApplyTransaction` created
  it via `createUtxo` (`zslpstore.cpp:295`), and `createUtxo` is reached only
  from a **valid** GENESIS, MINT, or SEND branch.
- A SEND output exists iff `availIn >= requiredOut` for that token, and
  `availIn` came only from consumed UTXOs that themselves existed by the same
  rule — back to a GENESIS (`token id == genesis txid`) or a baton-authorized
  MINT.
- Therefore every live token UTXO is **transitively valid back to a genesis
  over confirmed blocks**. A forged SEND that quotes a token id for which the
  spender holds no input UTXO finds `availIn = 0`, requires `> 0`, and creates
  nothing. The "ownership" it claims never enters `'u'`, so no observer ever
  sees it.

**Pin (TR-1):** the canonical ledger is the unique fixed point of "consume
known inputs; create outputs only within consumed availability; unknown input
= zero" applied in consensus tx order over confirmed blocks. Any
implementation that computes a *different* fixed point has forked.

---

## 3. Forgery-conservation threats, neutralization, and the exact rule

(Full structured detail is in the StructuredOutput payload. Summary table.)

| # | Attack | Overlay defense | Exact rule (file:line) |
|---|--------|-----------------|------------------------|
| F1 | Forged SEND, no/insufficient token inputs | `availIn < requiredOut` → create nothing; inputs already burned | `zslpstore.cpp:552`, `:567` |
| F2 | SEND spending token UTXOs you don't control | a UTXO is only consumable as a real tx `vin`; spending requires the prevout's scriptPubKey to be satisfiable under consensus (you must own the dust). Indexer never credits a spender it can't prove spent the input. | `zslpindexer.cpp:200-204`, `zslpstore.cpp:437-446` |
| F3 | MINT without the baton | `!batonInputPresent.count(tokenId)` → issue nothing | `zslpstore.cpp:493` |
| F4 | MINT of an unknown token | `!readToken` → break, nothing issued | `zslpstore.cpp:490` |
| F5 | Output index out of range / more quantities than vouts | `voutIdx >= voutCount` → that qty burned, no UTXO | `zslpstore.cpp:560-561` |
| F6 | Sum overflow (Σ outputs > int64 max) | overflow flag → INVALID, create nothing, burn inputs | `zslpstore.cpp:543-550`, `:552` |
| F7 | totalMinted overflow | guarded add, skip on overflow | `zslpstore.cpp:497-499` |
| F8 | Genesis-txid replay (re-declare an existing token) | first-genesis-wins: token row INSERTed only if absent | `zslpstore.cpp:457` |
| F9 | NFT duplication via forged SEND | qty-1 UTXO is single; a SEND can't exceed availIn; over-claim burns | tests `NftCannotBeDuplicated`, `zslpstore.cpp:552` |
| F10 | Double-create at vout[1] for GENESIS+MINT in same tx | only one SLP message per tx is honored (first valid OP_RETURN wins) | `zslpindexer.cpp:277-278` |

The economic-conservation half of this class (F1, F3–F9) is **already
implemented and unit-tested** (`src/gtest/test_zslp_indexer.cpp`:
`ForgeSendWithoutInputCreditsNobody`, `OverSendBurnsInputsNoOutputs`,
`MintWithoutBatonRejected`, `NftCannotBeDuplicated`, `NonSlpSpendBurnsUtxo`).
The residual risk in this class is **NOT economic — it is determinism**: two
implementations that PARSE the same tx differently will *create different
UTXOs*, which forks the very `'u'` map the conservation proof rests on. §4 is
where the live exposure is.

---

## 4. Determinism exposures found in the current code (the real risk)

These do not let an attacker mint free tokens against *this* node, but they
let an attacker craft a transaction that **this `-zslpindex` and a different
compatible implementation interpret differently**, forking the ledger and
defeating §1–§3. Each must be pinned to ONE canonical rule (§5).

### D1 — "first OP_RETURN at ANY vout" vs canonical "SLP must be vout[0]" (HIGH)

`zslpindexer.cpp:211` iterates **all** vouts looking for the first
`TX_NULL_DATA` that parses as SLP (`for (size_t vo = 0; vo < tx.vout.size();
...)`, with `continue` on a non-SLP nulldata). Canonical SLP (BCH spec, echoed
in `slp.h:5` "vout[0]") requires the SLP `OP_RETURN` to be **scriptPubKey of
vout[0]**; if vout[0] is not a valid SLP message the transaction is "not SLP"
and contributes no message (its inputs are still burned).

Attack: a minter puts a junk/non-SLP `OP_RETURN` at vout[0] and a valid SLP
SEND `OP_RETURN` at vout[1]. A canonical (vout[0]-only) implementation sees
"not SLP" → the spent token inputs are **burned, nothing created**. This
indexer scans on and **honors the vout[1] SEND → creates UTXOs**. The two
ledgers now disagree on who owns the tokens. **Ledger fork.** This is the
exact risk the briefing flagged.

### D2 — push-opcode acceptance set disagrees between the gate and the parser (HIGH)

The indexer gate is `Solver(spk, whichType, ...) == TX_NULL_DATA`
(`zslpindexer.cpp:215`). `TX_NULL_DATA` is `spk[0]==OP_RETURN &&
spk.IsPushOnly(begin()+1)` (`script/standard.cpp:71`). `IsPushOnly` accepts
**every opcode `<= OP_16`** (`script/script.cpp:239-256`): that includes
`OP_0`/`OP_FALSE` (0x00), `OP_1NEGATE` (0x4f), `OP_1`..`OP_16`
(0x51..0x60), **and `OP_PUSHDATA4`** (0x4e).

The raw parser `slp_parse` (`slp.c`) / `read_push`
(`op_return_push.h:24`) accepts **only** direct pushes 0x01–0x4b,
`OP_PUSHDATA1` (0x4c), `OP_PUSHDATA2` (0x4d). It rejects `OP_PUSHDATA4`,
`OP_0`, and `OP_1`..`OP_16` (returns NULL → parse fails → "not SLP").

So the gate and *this* parser already disagree with each other on what is a
"push", and a *different* implementation that uses `IsPushOnly` semantics (or
that, conversely, follows the strict canonical SLP rule below) will disagree
with this one. Canonical SLP is **stricter than both**:

- The SLP field separators MUST be data pushes; `OP_0`/`OP_1`..`OP_16`/
  `OP_1NEGATE`/`OP_RESERVED` as a "field" make the tx **not SLP**.
- A zero-length field MUST be `OP_0` (0x4c 0x00 is NOT minimal in BCH SLP —
  see D3). **NOTE:** this repo's `slp.c` emits empty fields as
  `OP_PUSHDATA1 0x00` (`op_return_push.h:74` `push_empty`) and *parses* a
  zero-length field only via `read_push` lengths (it never special-cases
  `OP_0`). This is a self-consistent but **non-canonical** empty-field
  encoding — pin it explicitly (§5 R-PARSE-4) or align to BCH SLP, but it
  must be ONE rule everywhere.

### D3 — non-minimal pushes are silently accepted (MEDIUM)

`read_push` (`op_return_push.h:24`) accepts a length expressible in a shorter
form: e.g. a 4-byte payload pushed with `OP_PUSHDATA1 0x04` (2-byte prefix)
instead of the minimal `0x04`. Canonical SLP requires **minimal push
encoding**; a non-minimal push makes the tx "not SLP". An attacker can encode
the same logical SEND two ways; a minimal-only implementation rejects the
non-minimal form (burn, nothing created) while this parser honors it.
**Ledger fork.** Pin minimality (§5 R-PARSE-3).

### D4 — GENESIS token-id endianness asymmetry is correct-but-unpinned (MEDIUM)

GENESIS stores `tokenId = txid = tx.GetHash()` **directly**
(`zslpindexer.cpp:229,233`; `zslpstore.cpp:453`). MINT/SEND read the on-chain
32-byte `token_id` field — documented big-endian *display* order
(`zslpmsg.h:42`) — and **byte-reverse** it via `TokenIdToUint256`
(`zslpindexer.cpp:147-153,256,264`). These match **iff** a minter copying the
genesis txid's `GetHex()` display string into the SEND `token_id` field, then
reversed, equals `GetHash()`. It does (GetHex prints reversed internal
bytes), so this is **correct** — but it is a silent invariant. Any
implementation that gets the endianness of *either* path wrong will look up a
different `'t'`/`'u'` key and fork. Pin it (§5 R-ID-1) and add a
GENESIS→SEND round-trip test asserting the SEND finds the GENESIS UTXO by id.

### D5 — quantity field width / `num_outputs` cap edge (LOW, pin anyway)

`slp_parse` SEND loop reads pushes of **exactly 8 bytes**, 1..19 of them
(`slp.c:151-160`); a 0-byte or non-8-byte amount push ends the list. The
indexer then clamps `numOutputs` to `[0,20]` (`zslpindexer.cpp:265-268`) and
the store re-clamps to `[0,20]` (`zslpstore.cpp:540-542`). Canonical SLP
requires each amount to be **exactly 8 bytes** and at least one amount; a
SEND with a malformed amount push is "not SLP" entirely (burn inputs), NOT
"truncate at the bad push and honor the prefix". Confirm `slp.c`'s
"break on non-8-byte then require ≥1" matches the canonical "any malformed
amount ⇒ whole tx not SLP" rule, or pin this repo's prefix-honoring behavior
as canonical and write it down. Also pin the **maximum** output count: the
parser caps at 19 (`slp.c:151`), the structs hold 20 (`zslpmsg.h:47`,
`zslpstore.h:207`); the canonical max is 19 SLP amounts (vout[1..19]).

### D6 — `-datacarriersize` / relay limits do not bound the *ledger* (INFO)

`MAX_OP_RETURN_RELAY = 223` and `-datacarriersize` (`init.cpp:1833`) are
**relay/mine policy**, not consensus and not ledger rules. A miner can include
a larger OP_RETURN. The ledger function MUST depend ONLY on the confirmed tx
bytes, never on the local node's relay policy, or two nodes with different
`-datacarriersize` fork. The parser already operates on the raw script with no
relay-size dependence; keep it that way (§5 R-PARSE-6). Canonical SLP itself
imposes no 223-byte cap on validity.

---

## 5. Canonical validation spec (the single rule each implementation must follow)

This is the normative spec the conservation rewrite (and any wallet/explorer)
MUST match bit-for-bit.

### Message location
- **R-LOC-1.** An SLP message is taken from **vout[0].scriptPubKey ONLY.**
  If vout[0] does not parse as a valid SLP message, the transaction has **no
  SLP message** (it may still burn token inputs). Do NOT scan other vouts.

### Script / push decoding
- **R-PARSE-1.** scriptPubKey must begin with `OP_RETURN` (0x6a).
- **R-PARSE-2.** Every field after `OP_RETURN` must be a **data push** using
  a direct push (0x01–0x4b), `OP_PUSHDATA1` (0x4c), or `OP_PUSHDATA2` (0x4d).
  `OP_PUSHDATA4` (0x4e), `OP_0`, `OP_1NEGATE`, `OP_RESERVED`, and
  `OP_1`..`OP_16` make the tx **not SLP**. (This is *stricter* than
  consensus `IsPushOnly`; do not gate solely on `TX_NULL_DATA`.)
- **R-PARSE-3.** Pushes MUST be **minimal** (shortest opcode for the length).
  A non-minimal push ⇒ not SLP.
- **R-PARSE-4.** Empty/zero-length field encoding MUST be ONE fixed form
  across all implementations. Pin the repo's current `push_empty` =
  `OP_PUSHDATA1 0x00` form **or** migrate to BCH SLP's `OP_0`; whichever is
  chosen, parser and builder and every peer implementation use exactly that
  byte sequence. (Resolve the D2 note before any third party implements.)
- **R-PARSE-5.** A push whose declared length runs past end-of-script ⇒ not
  SLP (already enforced, `op_return_push.h:43`).
- **R-PARSE-6.** Validity depends ONLY on the confirmed transaction bytes.
  Never consult `-datacarrier`, `-datacarriersize`, mempool state, wallet
  state, or wall-clock.

### Field grammar (Token Type 1)
- **R-FLD-1.** lokad_id field == exactly 4 bytes `53 4c 50 00` ("SLP\0").
- **R-FLD-2.** token_type field decodes to **1** (1 or 2 bytes big-endian);
  any other value ⇒ not SLP (Type-1 indexer).
- **R-FLD-3.** tx_type field ∈ {"GENESIS"(7B), "MINT"(4B), "SEND"(4B)}.
  ("BURN" is implicit — under-spending — never an on-chain tx_type.)
- **R-GEN-1.** GENESIS: ticker/name/document_url are opaque label bytes,
  length-bounded for *storage* but NEVER affect validity (truncation in
  `slp.c:69` is display-only). document_hash field length ∈ {0, 32}; any other
  length ⇒ not SLP. decimals field == 1 byte, value 0–9
  (`slp.c:98-101`). mint_baton_vout field length ∈ {0, 1}; if 1 byte, value
  **≥ 2** (`slp.c:106-108`). initial_qty field == exactly 8 bytes BE.
- **R-MINT-1.** MINT: token_id == exactly 32 bytes. mint_baton_vout same rule
  as R-GEN-1. additional_qty == exactly 8 bytes BE.
- **R-SEND-1.** SEND: token_id == exactly 32 bytes. Then 1..19 amount pushes,
  **each exactly 8 bytes BE.** A malformed amount push terminates the list;
  pin whether this means "honor the valid prefix" (repo behavior,
  `slp.c:151-160`) or "whole tx not SLP" (stricter). **This is a live
  fork-risk; choose one and freeze it.**

### Token id
- **R-ID-1.** `tokenId` (internal, the `'t'`/`'u'`/`'b'` key) for a GENESIS
  is `tx.GetHash()` (internal little-endian). For MINT/SEND it is the on-chain
  32-byte token_id field **byte-reversed** (`TokenIdToUint256`). These MUST
  coincide for a token's own GENESIS; a conformance test MUST assert a SEND of
  a just-minted token resolves to the GENESIS's UTXOs.

### Conservation (the economic core — already implemented; pin it)
- **R-CONS-1 (unknown input = zero).** A tx input that is not a known token
  UTXO contributes 0 to availIn and never a baton. (`zslpstore.cpp:439`)
- **R-CONS-2 (consume-then-create).** Burn every spent token UTXO first; then
  create outputs only within consumed availability. Inputs not re-assigned by
  a valid message of their token id remain burned. (`:437-446`)
- **R-CONS-3 (SEND budget).** Valid iff `Σ outputs (no overflow) ≤ availIn`
  for the SEND's token id; else create nothing (inputs already burned).
  (`:552`, `:567`)
- **R-CONS-4 (positional outputs).** outputQuantities[j] → vout[1+j]; a
  zero-qty output consumes a slot and creates nothing; `voutIdx >= voutCount`
  ⇒ that quantity is burned. (`:555-563`)
- **R-CONS-5 (MINT authority).** MINT valid iff the token is known AND a baton
  UTXO of that token id was on a spent input; else issue nothing. New quantity
  at vout[1]; baton continues only if `mint_baton_vout ∈ [2, voutCount)`.
  (`:490`, `:493`, `:508-528`)
- **R-CONS-6 (GENESIS authority + replay).** First GENESIS for a txid wins;
  the token row is INSERTed only if absent. Quantity at vout[1]; baton at its
  declared vout iff `∈ [2, voutCount)`. Because token id == txid and txids are
  unique under consensus, a *replay* of the same token id is impossible from a
  different tx; a duplicate-id collision can only come from the same txid and
  is idempotent. (`:457`, `:463-483`)
- **R-CONS-7 (overflow).** Σ outputs, totalMinted, and balance accumulation
  are int64 overflow-guarded; an overflowing SEND is INVALID (burn), an
  overflowing MINT/balance add is skipped. (`:497`, `:543-550`, `:395`)
- **R-CONS-8 (one message per tx).** Exactly the vout[0] message is applied;
  no second OP_RETURN is ever honored. (Follows from R-LOC-1; replaces the
  current "first valid wins across vouts", `zslpindexer.cpp:277`.)

### Ordering / reorg determinism
- **R-ORD-1.** Transactions are applied in **block order, then in-block vtx
  order** (`zslpindexer.cpp:186`). An earlier tx's created UTXO is visible to a
  later tx in the same block (per-tx batch commit, `zslpstore.cpp:422-424`).
- **R-ORD-2.** A disconnect restores the store byte-for-byte to its
  pre-connect state (undo log, `zslpstore.cpp:591`). The ledger after a reorg
  equals the ledger computed fresh over the new confirmed chain.

---

## 6. Why this closes the class (and what it does not)

With R-* pinned and the conservation core as implemented, every
forgery-conservation attack reduces to **"creates nothing and/or burns the
inputs it touched."** No on-chain transaction can credit token value the
spender did not transitively receive from a genesis. The chain still *carries*
the forged bytes; honest observers simply compute a ledger in which those
bytes moved nothing.

What this model **cannot** stop, by construction:
- The forged tx existing on-chain and being visible in a block explorer's raw
  view. (Out of scope — not a ledger effect.)
- A holder **burning their own** token by spending its dust UTXO in an
  ordinary send (the wallet has zero ZSLP awareness today — see the wallet
  anti-burn requirements doc). That is self-inflicted, not forgery, but it is
  a real loss and is addressed separately.
- **Impersonation by genesis reuse.** Anyone can GENESIS a *different* token
  (different txid ⇒ different token id) with the same ticker/name/image. This
  is not forgery of an existing token; it is a new token that lies socially.
  Defeated by issuer identity / genesis-txid fingerprint / signed
  attestations, surfaced honestly in the GUI — never claimed to be prevented
  by consensus.

See also:
- `doc/nft/zslp-canonical-validation-conformance-checklist.md` — the testable
  checklist the conservation rewrite must pass.
- `doc/nft/zslp-wallet-antiburn-ux-honesty.md` — holder anti-burn + UX honesty.
