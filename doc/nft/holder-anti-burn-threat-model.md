# Holder Anti-Burn Threat Model (ZSLP / SLP overlay)

Status: ANALYSIS — wallet has ZERO token awareness today. This document is the
security model + canonical validation requirements for the holder-anti-burn
threat class. It does NOT edit `src/zslp/*` (a concurrent workflow owns the
conservation rewrite); it specifies what that rewrite and the wallet must
satisfy.

Scope: NON-consensus token overlay. We CANNOT change ZClassic consensus. Base
nodes relay/mine ANY standard tx, including an OP_RETURN that encodes a forged
token SEND, and including an ordinary payment that spends a token-carrying dust
UTXO as fee or change. Consensus offers NO protection. Holder safety is
therefore a WALLET property, and ledger integrity is a DETERMINISM property.

--------------------------------------------------------------------------------
## 1. The core hazard, grounded in code

A ZSLP token (and an NFT in particular) "rides" a tiny transparent dust UTXO.
The token's existence and ownership live ONLY in the overlay ledger, keyed by
the UTXO outpoint `(txid, vout)` — see `src/zslp/zslpstore.h:114-128`
("Persisted token-carrying UTXO record — THE SOURCE OF TRUTH for ownership.
Keyed by (txid, vout)."). Consensus sees an ordinary, low-value t-output.

The wallet has NO idea that UTXO is special. Verified:

- No ZSLP/SLP reference exists anywhere under `src/wallet/` (grep returns
  nothing). Coin selection, change, and fee logic are token-blind.

- `CWallet::AvailableCoins` (`src/wallet/wallet.cpp:3151`) is the single
  enumerator feeding ALL spend paths. Its only per-UTXO exclusions are:
  `IsSpent`, not-mine, `IsLockedCoin`, and `nValue > 0` / zero-value flag
  (line 3178-3183). There is NO token filter. A token dust UTXO with
  `nValue > 0` is returned as ordinary spendable change material.

- `CWallet::SelectCoins` / `SelectCoinsMinConf`
  (`src/wallet/wallet.cpp:3235, 3336`) run a randomized subset-sum over those
  coins. A token UTXO is eligible to be picked as an input to fund ANY
  ordinary send. Once picked and not reproduced as an output, the overlay
  treats its token as BURNED (inputs consumed, no conserving SEND output).

- The change/dust path is the sharpest edge. In `CreateTransaction`
  (`src/wallet/wallet.cpp:3471`), when computed change is below the dust
  threshold the wallet FOLDS IT INTO THE FEE and drops the output:
  `src/wallet/wallet.cpp:3672-3675`
  ```
  if (newTxOut.IsDust(::minRelayTxFee))
  {
      nFeeRet += nChange;          // <-- token-carrying value silently burned to miners
      reservekey.ReturnKey();
  ```
  An NFT rides a 1-sat (or similar) dust output. The dust threshold with the
  default min-relay fee (`DEFAULT_MIN_RELAY_TX_FEE = 100`,
  `src/main.h:64`; threshold = `3 * minRelayTxFee.GetFee(nSize)`,
  `src/primitives/transaction.h:452-467`) is on the order of ~100 sats, FAR
  above a 1-sat NFT dust output. So a token UTXO swept as change is essentially
  guaranteed to be classified as dust and burned into the fee, with no output
  and no warning.

- The async (shielded) paths are equally blind. `z_sendmany`'s
  `find_utxos` (`src/wallet/asyncrpcoperation_sendmany.cpp:988`) calls
  `pwalletMain->AvailableCoins(vecOutputs, false, NULL, true, fAcceptCoinbase)`
  with NO coin-control and NO token filter; `asyncrpcoperation_mergetoaddress`
  and `asyncrpcoperation_shieldcoinbase` likewise sweep `AvailableCoins`.
  A "shield all my transparent funds" or "merge" operation will hoover up token
  dust into a z-address — token irrecoverably burned (z-outputs carry no
  overlay SEND).

NET: ANY of `sendtoaddress`, `sendmany`, `z_sendmany` (from t), `z_shieldcoinbase`,
`z_mergetoaddress`, fund-raw-transaction, and the GUI "send"/"shield"/"send max"
buttons can today destroy an NFT with a single ordinary action by the holder.

--------------------------------------------------------------------------------
## 2. Why base consensus cannot stop this

Consensus validates scripts, PoW, supply, and standardness. It has no concept of
SLP/ZSLP — `src/zslp/*` lives entirely behind `-zslpindex` in `CZSLPIndexer`
and is forbidden to touch validation/mempool acceptance. A transaction that
spends a token dust UTXO as fee/change is a perfectly valid standard tx;
consensus relays and mines it. There is nothing to reject. The burn is real on
the only ledger that consensus enforces (the coin ledger); only the OVERLAY
ledger "knows" a token died, and it can only RECORD the burn, never prevent it.

Therefore: anti-burn is enforced exclusively in the spending software (wallet),
and "ownership" is enforced exclusively by every honest observer computing the
SAME overlay ledger from the SAME confirmed history.

--------------------------------------------------------------------------------
## 3. Security model: determinism + agreement (no consensus fallback)

The overlay ledger is a pure deterministic function of consensus-ordered,
confirmed block history. Security rests on TWO properties:

1. DETERMINISM — given the same block history, an implementation always computes
   the same ledger (same token UTXO set, same balances, same burns).
2. AGREEMENT — every honest implementation (our `-zslpindex`, any compatible
   wallet/explorer) computes the BIT-IDENTICAL ledger.

If two implementations disagree on ANY edge case, the ledger FORKS: an attacker
can show conflicting "ownership"/"validity" to different counterparties (e.g.
a marketplace that uses implementation A vs a buyer using implementation B).
There is no consensus to break the tie. Cross-implementation bit-exact agreement
IS the security property.

A forged or malformed token tx is NOT "rejected" — it is INTERPRETED. The
canonical rule set must assign it ONE deterministic meaning (credit nobody /
burn inputs). The danger is not that forgeries land on-chain (they always can);
it is that two implementations interpret the SAME forgery differently.

--------------------------------------------------------------------------------
## 4. Determinism-critical edge cases (each is a potential ledger fork)

These must be pinned to ONE canonical rule. Verified against current code where
cited; the conservation rewrite MUST satisfy these.

### 4.1 OP_RETURN position — CONFIRMED DIVERGENCE (must fix)

Canonical SLP requires the SLP OP_RETURN to be `vout[0]`. The repo's own header
states this: `src/zslp/slp.h:5` ("Tokens are encoded in OP_RETURN outputs
(vout[0]).").

But the indexer SCANS ALL vouts and accepts the FIRST that parses:
`src/zslp/zslpindexer.cpp:205-224, 277-278`
```
for (size_t vo = 0; vo < tx.vout.size(); ++vo) {
    ...
    if (!ZSLPParseScript(...)) continue; // not an SLP message; keep scanning other vouts
    ...
}
... break; // one SLP message per tx (first valid OP_RETURN wins)
```
This is a ledger fork against any canonical-SLP implementation: a tx whose
`vout[0]` is a payment and whose `vout[3]` is an SLP-looking OP_RETURN is
"not SLP" canonically but "SLP" here. CANONICAL RULE: an SLP message is
recognized ONLY at `vout[0]`; if `vout[0]` is not a parseable SLP OP_RETURN, the
tx is non-SLP (and still burns any token inputs it spends). The scan loop must
be replaced with a single `vout[0]` check.

### 4.2 SEND output-quantity array bounds

`output_quantities` is sized 20 in `slp.h:60` and `zslpmsg.h:47`, with a comment
"vout[1]..vout[19] + 1 extra". The indexer clamps `n` to `[0,20]`
(`zslpindexer.cpp:266-267`). Canonical SLP caps a SEND at 19 token outputs
(vout[1..19]); index 20 maps to no real vout. CANONICAL RULE: a SEND with more
than 19 output quantities is INVALID (entire token effect void, inputs burned),
not silently truncated. Pin the exact cap and the invalid-vs-truncate decision;
both implementations must agree.

### 4.3 num_outputs greater than tx.vout count

If a SEND lists more output quantities than the tx has real outputs, canonical
SLP makes the tx INVALID (inputs burned), it does NOT credit only the existing
outputs. The store is handed `voutCount` for exactly this bounds check
(`zslpstore.h:333, 341`). Pin: too-many-quantities => INVALID, deterministic.

### 4.4 Output-sum overflow (uint64)

Quantities are uint64 (`slp.h:60`). Summing output quantities or input token
amounts can overflow. CANONICAL RULE: any arithmetic overflow in summing
outputs (or inputs) makes the tx INVALID (burn), computed with explicit
overflow checks, NOT wrapping. Both implementations must detect overflow at the
same boundary.

### 4.5 "Input not a recognized token UTXO contributes ZERO"

A SEND's validity is `sum(input token UTXOs of tokenId) >= sum(outputQuantities)`.
Inputs that are not recorded token UTXOs of THIS tokenId contribute zero (they
do not borrow from another token, and a non-token input is just dust). The store
already keys truth by `(txid,vout)` and exposes `GetUtxo` (`zslpstore.h:356-357`).
Pin: only UTXOs recorded for the SAME tokenId count; mixing tokenIds does not
combine; shortfall => INVALID/burn (NOT partial credit).

### 4.6 Quantity field length / encoding

`be_to_u64` reads 1..8 big-endian bytes (`slp.c:16-21`) but canonical SLP
quantity pushes are EXACTLY 8 bytes. Pin: a quantity push whose length != 8 is
a parse failure => non-SLP (or INVALID where required), identically in both
implementations. Genesis/mint already require exactly 8 (`slp.c:113, 134`);
the SEND path must enforce the same.

### 4.7 GENESIS quantity location and baton

Genesis creates `initial_quantity` at `vout[1]`; the mint baton (if any) at
`mint_baton_vout` (>= 2). NFT = baton-less genesis, decimals 0, qty 1. Pin the
exact vout, the baton-present/absent decision, and that `mint_baton_vout` in
{0,1} means "no baton" (`slp.h:50,76`). MINT requires spending the live baton
UTXO as an input; no baton input => MINT INVALID.

### 4.8 Lokad ID / token-type / parse strictness

Lokad must be exactly `SLP\0` (`slp.h:23-24`) and token type exactly 1. Any
deviation => non-SLP. Pin every "is this an SLP message at all" gate so the two
implementations classify identically (a tx classified SLP by one and non-SLP by
the other forks the ledger AND can flip a burn into a non-burn).

Each edge case above needs a NAMED canonical rule + a cross-implementation test
vector (see the requirements checklist).

--------------------------------------------------------------------------------
## 5. What "ownership" means, honestly (impersonation is social)

Token id == genesis txid (`zslpindexer.cpp:229`), globally unique because txids
are unique under consensus. Uniqueness is at the TOKEN-ID level ONLY. Anyone can
mint a DIFFERENT token reusing a name, ticker, or image-hash. The overlay does
NOT and CANNOT prevent that — there is no consensus to reject a duplicate-named
genesis. Impersonation is defeated SOCIALLY: issuer identity, the genesis-txid
fingerprint, and (optionally) signed attestations — never by the chain. The GUI
MUST present this honestly (see UX-honesty requirements doc).

--------------------------------------------------------------------------------
## 6. The fix surface (minimal, non-consensus)

The store already has the primitive the wallet needs:
`CZSLPStore::GetUtxo(txid, vout, out)` (`zslpstore.h:356-357`) answers
"is this outpoint a token UTXO, and what token/amount/baton is it?" — the SOURCE
OF TRUTH. Today NO RPC exposes it and the wallet never consults it. The minimal
safe design (detailed in the anti-burn requirements doc) is:

1. Expose per-outpoint token status over RPC (read-only, behind `-zslpindex`).
2. Teach `AvailableCoins` to EXCLUDE token UTXOs from default coin selection
   (the same chokepoint that already honors `IsLockedCoin`).
3. NEVER fold a token UTXO into fee/change; never let the dust-to-fee path
   (`wallet.cpp:3672-3675`) touch one.
4. Surface token UTXOs in coin-control / `listunspent` with a token tag.
5. Require explicit opt-in + a clear warning to deliberately spend a token UTXO,
   and emit a conserving SEND when transferring it (not a bare spend).

This is wallet-only + one read-RPC. It touches no consensus, no validation, no
mempool, no PoW. It is fail-safe: if the index is unavailable, the wallet must
DEGRADE TO REFUSING to auto-spend low-value t-dust rather than risk a burn
(see requirements R8).
