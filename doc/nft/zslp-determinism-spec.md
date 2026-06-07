# ZSLP Canonical Validation Spec (determinism-fork hardening)

Status: SPEC. This document does not change `src/`. It is the single
normative reference the UTXO-bound conservation rewrite (zslpstore + indexer)
MUST satisfy bit-for-bit. Every compatible wallet / explorer / indexer that
computes a ZSLP ledger MUST produce the IDENTICAL result on the identical
consensus-ordered confirmed block history. Any divergence is a ledger fork.

## 0. Security model (why determinism IS the security property)

We cannot change ZClassic consensus. Existing, unchanged nodes relay and mine
ANY standard transaction, including an OP_RETURN that encodes a FORGED token
SEND/MINT/GENESIS. Consensus does not know SLP exists; it will never reject a
token forgery. Therefore:

- Token ownership is NOT enforced by the chain. It is a DETERMINISTIC FUNCTION
  `Ledger = f(confirmed, consensus-ordered block history)` computed by an
  observer (`-zslpindex` / `CZSLPIndexer` / any compatible implementation).
- A forged or rule-breaking transaction can be confirmed on-chain yet credit
  NOBODY: `f` interprets it as "creates nothing, burns its token inputs."
- SECURITY = DETERMINISM + AGREEMENT. If two implementations of `f` disagree on
  ANY edge case, the ledger FORKS: the attacker shows ledger A ("I own NFT X")
  to a buyer running implementation A, and the conflicting ledger B to a buyer
  running implementation B. There is no consensus to break the tie. So
  cross-implementation bit-exact agreement is the entire defense.

Consequence for this spec: every rule below is written as a TOTAL function with
NO undefined / implementation-defined behavior. "Reject ambiguous, don't guess"
is the default. Where two readings exist, the spec PINS one and the other is an
explicit fork bug.

## 1. Scope of the ledger function

Inputs to `f`, in order:

1. Confirmed blocks `B[0..tip]` in consensus order (`chainActive`).
2. Within a block, transactions in their in-block order `block.vtx[0..]`
   (coinbase = `vtx[0]`).
3. Within a transaction, `tx.vin` order and `tx.vout` order as serialized.

`f` MUST NOT depend on: mempool / unconfirmed state, wall-clock time, peer
order, local config, RPC call order, map iteration order of any in-memory
container that is not explicitly sorted by a spec-defined key, or floating
point. Output: per-(tokenId) token metadata, the live token-UTXO set
`(txid,vout) -> {tokenId, amount, isBaton}`, and the derived per-(token,address)
balances.

ONLY confirmed history feeds the ledger. The wallet/GUI MAY show an
"unconfirmed/pending" view but it MUST be visually and semantically distinct
from confirmed ownership (see §10). Confirmed-vs-unconfirmed conflation is a
fork vector: two parties at different confirmation depths must never be shown
contradictory "confirmed" ownership.

## 2. Transaction-level parse: which output carries the SLP message

This is the single highest-risk determinism rule and TODAY THE CODE IS WRONG.

`src/zslp/zslpindexer.cpp` IndexTransaction (~line 211) loops over ALL vouts and
takes the FIRST one that `Solver()` calls `TX_NULL_DATA` and that parses as SLP:

```c
for (size_t vo = 0; vo < tx.vout.size(); ++vo) { ... first valid wins ... }
```

Canonical SLP requires the SLP OP_RETURN to be at **vout[0]**. Anything else is
"not an SLP transaction." The scan-any-vout behavior diverges from every
reference SLP implementation and from any wallet that follows the spec: an
attacker crafts a tx whose vout[0] is a normal payment and vout[1] is an SLP
SEND. A vout[0]-strict validator says "not SLP -> token inputs burned"; the
scan-any validator says "valid SEND." => ledger fork.

CANONICAL RULE (R-PARSE-1): A transaction is an SLP-candidate IFF `tx.vout`
is non-empty AND `tx.vout[0].scriptPubKey` begins with `OP_RETURN` (0x6a) AND
the SLP parser (§3) accepts `tx.vout[0].scriptPubKey`. No other output is ever
examined for an SLP message. If vout[0] is not a valid SLP message, the
transaction has NO SLP message (msgPresent = false). Its spent token inputs are
still consumed/burned per §6.

R-PARSE-2: At most one SLP message per transaction, and it is exactly the
vout[0] message. The "first valid OP_RETURN at any index wins" loop MUST be
deleted.

R-PARSE-3: Coinbase transactions are never SLP. (Defensive: a coinbase vout[0]
that happens to start with OP_RETURN must still be ignored; the indexer should
skip `vtx[0]` for message parsing. It MUST still process coinbase inputs as
token inputs? No — coinbase has a single null prevout that can never reference a
token UTXO, so this is a no-op, but the skip must be explicit and tested.)

## 3. Script -> SLP message parse (byte-exact)

The parser is `slp_parse()` (`src/zslp/slp.c`) via `ZSLPParseScript`. Every
branch below is a TOTAL accept/reject decision. "reject" => not an SLP message.

R-SCRIPT-1 (push grammar, the load-bearing one): The script after OP_RETURN is
a sequence of data pushes read by `read_push` (`op_return_push.h`). Canonical
SLP permits ONLY these push encodings for SLP fields:
  - direct push 0x01..0x4b (length = opcode), and
  - OP_PUSHDATA1 (0x4c) with an explicit 1-byte length.
SLP does NOT use OP_PUSHDATA2/4, and does NOT treat OP_0/OP_1NEGATE/OP_1..OP_16
as data pushes. TODAY `read_push` ALSO accepts OP_PUSHDATA2 (0x4d). This is a
latent fork/availability risk: a field encoded with 0x4d would be parsed by this
indexer but rejected by a strict reference parser (which would say "not SLP").
DECISION REQUIRED + PINNED: reject 0x4d (and anything not in {0x01..0x4c}) as
"not SLP." `read_push` MUST return NULL for opcode 0x4d when used for ZSLP.
(R-SCRIPT-1a) Also reject OP_0 (0x00) and OP_1..OP_16 (0x51..0x60) — they
already return NULL in `read_push`; KEEP that and pin it with a test.

R-SCRIPT-2 (no minimal-push requirement, but pin it explicitly): SLP does NOT
require BIP62 minimal pushes. A 1-byte value MAY be pushed via 0x01 or via 0x4c
0x01. Both are valid and MUST parse identically. Pin with a test that the same
field via direct-push and via PUSHDATA1 yields the same parsed message. (This is
the one place where two encodings are deliberately allowed; everything else is
single-encoding.)

R-SCRIPT-3 (lokad + version): vout[0] must be
`OP_RETURN <4: "SLP\0"> <1-2: token_type>`. token_type MUST equal 1
(big-endian, 1 or 2 bytes). Any other token_type => not SLP (we implement only
Type 1; an unknown type is "not our ledger" and must credit nobody, NOT throw).

R-SCRIPT-4 (transaction_type): next push is exactly the ASCII bytes "GENESIS"
(7), "MINT" (4), or "SEND" (4). Any other => reject. Case-sensitive, exact
length.

R-SCRIPT-5 (trailing data): After the last field a tx-type requires, canonical
SLP requires NO trailing pushes for GENESIS/MINT (fixed field count). For SEND,
the trailing pushes ARE the output-quantity list (§5). Today GENESIS/MINT parse
`return true` immediately after the last required field and IGNORE any trailing
bytes; SLP treats trailing data after a fixed-arity message as INVALID (not
SLP). PIN: after reading the final required field of GENESIS/MINT, the parser
MUST verify `p == end` (script fully consumed); otherwise reject. Otherwise an
attacker appends a byte and one parser accepts while a strict one rejects.

R-SCRIPT-6 (field-length rules, per SLP Type 1), all reject-on-violation:
  - GENESIS ticker/name/document_url: any length 0..uint (PUSHDATA1 max 255);
    purely metadata, never affects ledger arithmetic. Over-long is truncated
    into the fixed buffers TODAY (`if (len > 0 && len < sizeof(...))`); that is
    a metadata-display divergence, NOT a ledger fork (amounts unaffected), but
    PIN it: store the FULL bytes (or a deterministic truncation) identically
    across implementations, and never let ticker/name length change accept/
    reject. Recommended: do not truncate silently — store full bytes; if a
    fixed buffer is kept, the truncation length is part of the spec and tested.
  - document_hash: push length MUST be exactly 0 or exactly 32. Any other
    length => reject the whole message (today only `len==32` sets the flag but a
    non-{0,32} length does NOT reject — it silently means "no hash"; PIN to
    reject so a 31-byte hash can't parse two ways).
  - decimals: exactly 1 byte, value 0..9. Else reject. (NFT requires 0.)
  - mint_baton_vout (GENESIS/MINT): push length 0 (no baton) or exactly 1 byte
    with value >= 2. A 1-byte value 0 or 1 => reject the message. Any length >1
    => reject. (Matches current code; pin it.)
  - initial_quantity (GENESIS) / additional_quantity (MINT): exactly 8 bytes,
    big-endian uint64. Else reject.

R-SCRIPT-7 (integer endianness): ALL multi-byte SLP integers are big-endian.
token_type is BE (1-2 bytes). Quantities are BE uint64 (exactly 8 bytes).
`be_to_u64` is the canonical decoder; pin it with vectors including 0,
0xFFFFFFFFFFFFFFFF.

R-SCRIPT-8 (token_id byte order): On chain, token_id in MINT/SEND is 32 bytes
in DISPLAY (big-endian txid) order. The indexer reverses it to the daemon's
internal little-endian uint256 (`TokenIdToUint256`). GENESIS sets tokenId =
genesis txid directly. PIN: a MINT/SEND that names a token MUST resolve to the
SAME uint256 the GENESIS produced, verified by a round-trip test
(genesis txid -> on-chain BE bytes -> TokenIdToUint256 == genesis uint256).

## 4. SLP quantity domain and overflow (determinism-critical)

SLP quantities are unsigned 64-bit (uint64). The store uses int64_t internally.
The boundary 2^63..2^64-1 is a real fork surface.

R-QTY-1 (domain): A parsed quantity is uint64 in [0, 2^64-1]. The store casts to
int64_t. A quantity with the high bit set (>= 2^63) becomes NEGATIVE int64_t.
Today: GENESIS/MINT cast `(int64_t)msg->initialQuantity`; SEND output qty is
checked `if (q < 0) overflow=true`. PIN one rule and apply it EVERYWHERE:
  - DECISION: treat any quantity >= 2^63 as INVALID for the whole message
    (because the rest of the pipeline is signed int64 and a negative amount is
    nonsense). I.e. GENESIS initial_quantity, MINT additional_quantity, and
    EVERY SEND output_quantity with the high bit set => the message creates
    NOTHING (and for SEND/MINT/GENESIS still burns consumed inputs).
  - This must be enforced at parse OR at apply, but identically; currently SEND
    catches it (q<0) while GENESIS/MINT do NOT (a 2^63 initial_quantity would
    be stored as a negative totalMinted and create a negative-amount UTXO).
    => REQUIRED FIX: GENESIS/MINT must reject (create nothing) when the
    quantity, read as uint64, has the high bit set.

R-QTY-2 (SEND output-sum overflow): `requiredOut = Σ outputQuantities` must be
computed with an explicit overflow guard; on overflow the SEND is INVALID
(create nothing, burn inputs). Current code does this for int64 max. Because
R-QTY-1 already bans >=2^63 per-output, the sum guard is against int64 overflow
across up to 19 positive outputs — keep it, and pin with a vector that sums to
exactly int64 max and one that overflows by 1.

R-QTY-3 (input availability): `availIn = Σ amount of spent token UTXOs of this
tokenId`. Batons contribute 0 (R-BATON). SEND is VALID iff `availIn >=
requiredOut` AND not overflow. Strict `>=` (equal is valid; equal-with-change-0
is valid). The surplus `availIn - requiredOut` is BURNED (never re-created).

R-QTY-4 (no implicit widening / no float): all comparisons in int64. No double.

## 5. SEND output mapping (positional, deterministic)

R-SEND-1: `output_quantities[j]` maps to `vout[1 + j]` (1-indexed; vout[0] is the
OP_RETURN). The mapping is POSITIONAL and preserved across zero-quantity
outputs (a zero-qty slot is consumed and creates nothing). Current code: correct
(`voutIdx = 1 + j`, zero-qty `continue` without skipping the index).

R-SEND-2 (count bounds): The SEND quantity list is 1..19 entries. Today
`slp_parse` reads up to 19; the store clamps `n` to [0,20]. PIN to [1,19]: a
SEND with 0 entries => reject (already: `num_outputs < 1 => return false`). A
list of >19 pushes: the parser stops at 19 and (per R-SCRIPT-5) MUST then verify
the script is fully consumed; if there is a 20th 8-byte push, that is trailing
data => reject the message. PIN: a 20-quantity SEND is INVALID (not "first 19
win"), because "stop at 19 and ignore the rest" vs "reject" is a fork.

R-SEND-3 (more quantities than tx outputs): If `1 + j >= voutCount` (the named
output index does not exist in the tx), that quantity is BURNED (the output
can't receive tokens) BUT the SEND as a whole may still be valid for the outputs
that DO exist, PROVIDED conservation still holds over ALL declared quantities.
PIN the exact rule, because there are two defensible readings and they fork:
  - READING A (current code): validity uses `requiredOut = Σ ALL declared
    quantities` (including those pointing at nonexistent vouts); if availIn >=
    that sum, create UTXOs only for existing vouts, burn the rest. Inputs are
    fully covered; surplus burned.
  - READING B (some references): a SEND that names a quantity for a
    nonexistent output is INVALID as a whole.
  - DECISION (PINNED): READING B — if any declared output_quantity j>0 maps to
    a vout index `1+j >= voutCount`, the entire SEND is INVALID (create nothing,
    burn inputs). Rationale: it is the strictest, removes the "partial-create"
    ambiguity entirely, and matches "a message that can't be fully honored
    credits nobody." THIS IS A REQUIRED CHANGE: current code uses Reading A
    (it `continue`s past out-of-range vouts inside the valid branch). The store
    must, BEFORE creating anything, verify every positive-qty output index is in
    range; if not, treat the SEND as invalid.
  - Zero-qty outputs pointing past voutCount are harmless (create nothing) and
    do NOT invalidate, since they move no tokens.

## 6. Input consumption / burn (runs for EVERY tx)

R-BURN-1: For EVERY transaction (SLP or not, valid or not), every spent prevout
that is a live token UTXO is CONSUMED (removed from the UTXO set) and its
balance credit reversed. A non-SLP tx, an invalid SLP message, a SEND that
fails conservation, a MINT without a baton, a GENESIS — all still burn the token
UTXOs they spend that they do not validly re-create. Current code: correct
(consume loop in `ApplyTransaction` step (a) runs before dispatch).

R-BURN-2 ("input not a recognized token UTXO contributes ZERO"): A spent prevout
that is not in the token-UTXO set contributes nothing and is a no-op. Current:
`readUtxo` miss => `continue`. Pin.

R-BURN-3 (ordering within a tx): consume-then-create. A tx cannot "spend its own
output": prevouts always reference earlier txids/outputs, so the consume set is
disjoint from the create set within one tx. Pin that creates use this tx's txid
and consumes use prevout txids.

R-BURN-4 (same-block dependency ordering): A later tx in a block may spend a
token UTXO an earlier tx in the SAME block created. Therefore txs MUST be
applied strictly in `block.vtx` order, and each tx's writes MUST be visible to
the next tx's reads. Current: each tx commits its own batch before the next
(documented in ApplyTransaction). Pin with a two-tx-in-one-block test
(genesis in tx1, send of it in tx2, same block).

## 7. GENESIS rules

R-GEN-1 (token id): tokenId == genesis txid (consensus-unique). Pin.

R-GEN-2 (first-genesis-wins): A token row is INSERTED only if absent. Since
tokenId == txid and txids are unique under consensus, a duplicate tokenId is
impossible in honest history; the `!readToken` guard is belt-and-suspenders and
MUST remain (a reorg-replay must not double-insert). Pin: re-applying the same
genesis block is idempotent.

R-GEN-3 (mint output): initial_quantity (if > 0 AND in-domain per R-QTY-1) is
created at vout[1] IFF vout[1] exists. If voutCount <= 1, the quantity is burned
(token row still created, totalMinted reflects declared initial_quantity?).
PIN the totalMinted semantics: totalMinted = sum of GENESIS + MINT DECLARED
quantities that were ACTUALLY CREATED, OR declared regardless of creation?
  - DECISION (PINNED): totalMinted counts only quantity that was actually
    created as a UTXO. If vout[1] doesn't exist, nothing is created and
    totalMinted contribution is 0. Rationale: totalMinted should equal the sum
    of live + burned token quantity that ever existed AS tokens; a quantity that
    was never created never existed. CURRENT CODE sets
    `token.totalMinted = msg->initialQuantity` unconditionally even if no UTXO
    is created — REQUIRED FIX to make totalMinted == actually-created.
    (This is a display value, but it is RPC-visible and therefore part of the
    deterministic surface; two implementations disagreeing on totalMinted is a
    fork of the observable ledger.)

R-GEN-4 (baton): baton issued IFF mint_baton_vout >= 2 AND < voutCount. Baton
UTXO created at that vout with amount 0, isBaton true. The display mirror
`token.mintBatonVout` reflects the live baton. Pin: a baton vout that is >=
voutCount => no baton (decl ignored), token row still created.

R-GEN-5 (NFT): NFT = baton-less GENESIS (mint_baton_vout absent), decimals == 0,
initial_quantity == 1. This is a CONVENTION over the same rules, not a separate
type. Uniqueness of the NFT is uniqueness of its tokenId (genesis txid). There
is no consensus-level "one of a kind"; see §9.

## 8. MINT rules

R-MINT-1: MINT of an unknown tokenId (no token row) => invalid, create nothing
(inputs still burned). Pin.

R-MINT-2: MINT is VALID iff a live BATON UTXO of this tokenId was on a spent
input. No baton input => create nothing (inputs burned). Current: correct.

R-MINT-3: additional_quantity (if >0 and in-domain) created at vout[1] iff
exists; totalMinted += actually-created amount (same R-GEN-3 fix:
overflow-guarded, and counts only created quantity).

R-MINT-4 (baton continuation): new baton at mint_baton_vout iff >=2 and
<voutCount; else the baton ENDS (token.mintBatonVout = 0). The spent baton is
consumed in step (a) regardless; a MINT that re-declares the baton creates a new
baton UTXO. Pin: minting without re-declaring a baton permanently ends minting.

## 9. Uniqueness, impersonation, and honesty (NOT a determinism bug, but a
       fork-adjacent UX hazard)

R-UNIQ-1: Uniqueness is at tokenId == genesis-txid granularity ONLY. Anyone can
GENESIS a different token with the same ticker/name/document_url/document_hash.
The overlay does NOT and CANNOT prevent it. There is exactly one canonical
fingerprint per token: its genesis txid.

R-UNIQ-2 (display honesty, see also §10 / GUI doc): Any UI MUST identify a token
primarily by tokenId, MUST treat ticker/name/image as untrusted attacker-chosen
strings, and MUST NOT present "verified"/"official" status from on-chain data
alone. Issuer authenticity is a SOCIAL layer (signed attestation binding an
identity to a genesis txid), out of band of consensus.

## 10. Confirmed-only ledger; reorg determinism

R-CONF-1: The ledger reflects only confirmed blocks. Wallet "pending" views are
separate and labeled (§ wallet doc). Never show unconfirmed token receipt as
owned.

R-CONF-2 (reorg exactness): DisconnectBlock MUST restore the store byte-for-byte
to its pre-connect state: restore consumed UTXOs, erase created ones, reverse
balance/totalMinted/baton deltas, delete transfer/token rows, rewind tip.
Connect(B) then Disconnect(B) is the identity. The undo log + reverse replay
implements this. Pin with a property test: random block of mixed ops, snapshot,
connect, disconnect, assert byte-identical DB.

R-CONF-3 (reorg = disconnect-to-fork-point then connect-new-branch): The ledger
after a reorg MUST equal `f` recomputed from genesis over the new active chain.
Pin with a test that builds two branches, reorgs, and compares the indexer's
incremental result to a from-scratch reindex of the winning branch.

R-CONF-4 (idempotent re-delivery): A re-delivered connect for the current tip is
a no-op (tip-hash guard). Crash-resume from the stored tip yields the same
ledger as continuous operation. Pin.

## 11. Determinism of the read/RPC surface (observable ledger)

The RPC output is part of the observable ledger; two implementations must agree.

R-RPC-1 (ordering): `listtokens` is ordered by the leveldb key order of
`'t'+tokenId` (uint256 raw-byte order). `listtransfers` is height-ascending then
reversed to newest-first; WITHIN equal height the tiebreak is the key order
`txid then BE(vout)`. PIN these orders explicitly — any list whose order is
"map/iterator order" without a spec'd key is a latent fork. (Current code uses
leveldb key order, which is deterministic; document it as normative so an
alternate impl reproduces it.)

R-RPC-2 (totals): totalMinted, balances, and "hasmintbaton" derive only from the
rules above; no separate code path may compute them differently from the UTXO
truth. Balance(token,addr) MUST always equal Σ amount of live non-baton token
UTXOs of that token at that address. Pin with an invariant check after each
block: derived balances == recomputed-from-UTXO-set.

## 12. Required deletions / changes summary (for the conservation rewrite)

1. R-PARSE-1/2: parse ONLY vout[0]; delete the all-vouts loop. (BLOCKER)
2. R-SCRIPT-1: reject OP_PUSHDATA2 (0x4d) for ZSLP fields. (fork risk)
3. R-SCRIPT-5: require full-script consumption for GENESIS/MINT (no trailing
   data); for SEND reject a 20th quantity push. (fork risk)
4. R-SCRIPT-6: reject non-{0,32} document_hash length. (fork risk)
5. R-QTY-1: GENESIS/MINT must reject quantities with the high bit set (>=2^63),
   matching SEND. (fork + negative-amount corruption)
6. R-SEND-3: PINNED Reading B — a SEND naming any positive quantity for a
   nonexistent output index is INVALID as a whole. Pre-validate output indices
   before creating. (fork risk; current code uses Reading A)
7. R-GEN-3/R-MINT-3: totalMinted counts only ACTUALLY-CREATED quantity, not
   declared-but-burned. (observable-ledger fork)
8. R-PARSE-3: explicitly skip coinbase for message parsing. (defensive)
9. R-RPC-1: document list orderings as normative.

Each item above MUST have a gtest vector that a second, independent
implementation could run to prove agreement.
