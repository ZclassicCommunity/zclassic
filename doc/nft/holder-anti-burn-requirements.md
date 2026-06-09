# Holder Anti-Burn: Wallet Requirements + UX Honesty Checklist

Companion to `holder-anti-burn-threat-model.md`. Concrete, testable requirements
the implementation MUST meet to close the holder-anti-burn threat class. All are
NON-consensus (wallet + one read-only RPC). No edits to `src/zslp/*` are made by
this workflow; the RPC surface below is the contract the conservation rewrite
must expose.

Legend: [R#] requirement, each with an acceptance test.

--------------------------------------------------------------------------------
## A. Token-awareness plumbing (read-only)

[R1] EXPOSE per-outpoint token status over RPC.
Add a read-only RPC (behind `-zslpindex`) that, given `(txid, vout)`, returns
whether it is a token UTXO and its `{tokenId, amount, isBaton, decimals}`.
It MUST delegate to `CZSLPStore::GetUtxo` (`src/zslp/zslpstore.h:356-357`) — the
source of truth — and add NO new ledger logic in the wallet.
TEST: mint an NFT; the RPC reports its dust outpoint as a token UTXO with qty 1,
baton false; a random non-token outpoint reports not-a-token.

[R2] BATCH lookup for coin selection.
Provide a batched form (set of outpoints -> token status) so `AvailableCoins`
can classify all candidate coins in one pass without N RPC round-trips (in-process
call against the indexer, NOT an external RPC, when `-zslpindex` is on).
TEST: a wallet with 1000 UTXOs classifies all in a single store traversal; no
per-coin lock churn.

--------------------------------------------------------------------------------
## B. Exclude token UTXOs from normal spending (the core anti-burn)

[R3] EXCLUDE token UTXOs from default `AvailableCoins`.
At `src/wallet/wallet.cpp:3151` `AvailableCoins`, add a token-exclusion check
alongside the existing `IsLockedCoin` check (line 3181). When `-zslpindex` is on,
a UTXO that is a token UTXO (or a mint baton) is NOT returned for default coin
selection. This single chokepoint protects sendtoaddress/sendmany/z_sendmany/
shieldcoinbase/mergetoaddress/fundrawtransaction simultaneously, because they
all enumerate through `AvailableCoins`.
TEST: hold an NFT + ordinary funds; `sendtoaddress` to a third party never
selects the NFT outpoint as an input across 1000 randomized runs (defeats the
randomized subset-sum in `SelectCoinsMinConf`).

[R4] NEVER fold a token UTXO into fee/change.
Independently of R3, guarantee the dust-to-fee path
(`src/wallet/wallet.cpp:3672-3675`, `nFeeRet += nChange`) and the change-output
construction can NEVER consume a token UTXO's value. Since R3 keeps token UTXOs
out of inputs, this is belt-and-suspenders: assert no selected input is a token
UTXO before signing.
TEST: construct a transaction by hand that would route an NFT's value to fee;
`CreateTransaction` refuses (returns false with a token-protection error) rather
than burning it.

[R5] EXCLUDE token UTXOs from the shielded/merge sweeps.
`z_sendmany` `find_utxos` (`src/wallet/asyncrpcoperation_sendmany.cpp:988`),
`asyncrpcoperation_mergetoaddress`, and `asyncrpcoperation_shieldcoinbase` must
inherit the R3 exclusion (they call the same `AvailableCoins`). Additionally,
"shield/merge ALL transparent" operations MUST skip token UTXOs even when the
user expresses "all".
TEST: with an NFT held on a t-address, `z_shieldcoinbase "*"` and
`z_mergetoaddress` leave the NFT outpoint untouched; balances/notes reflect only
non-token funds.

[R6] "Send max" / sweep-all UX never empties a token UTXO.
The GUI "send max" and any "empty wallet" path compute the spendable maximum
EXCLUDING token UTXO values, and never select them.
TEST: NFT + 10 ZCL; "send max" sends ~10 ZCL minus fee, NFT outpoint remains
unspent.

--------------------------------------------------------------------------------
## C. Surface token UTXOs (coin-control + listunspent)

[R7] TAG token UTXOs in `listunspent` and coin-control.
`listunspent` (`src/wallet/rpcwallet.cpp:2335`) and the GUI coin-control picker
MUST annotate each token-carrying UTXO with `{tokenId, amount, isBaton, ticker,
name}` and a clear "TOKEN — do not spend as fee" flag. They are listed but
visually/structurally distinct and NOT selected by default.
TEST: `listunspent` output for an NFT outpoint includes a `token` object; the GUI
coin-control row shows the token badge and is unchecked by default.

--------------------------------------------------------------------------------
## D. Deliberate spend = explicit, warned, and CONSERVING

[R8] FAIL-SAFE when the index is unavailable.
If `-zslpindex` is OFF or the store cannot be consulted, the wallet MUST NOT
silently treat dust as ordinary. It must either (a) refuse to auto-spend
low-value transparent dust (configurable threshold) and warn, or (b) refuse the
operation with a clear "token protection unavailable — enable -zslpindex"
message. NEVER fail OPEN into a burn.
TEST: with `-zslpindex` off, a send that would otherwise pick a sub-threshold
dust UTXO is blocked or routes around it with a warning; no silent burn.

[R9] Deliberate token spend requires EXPLICIT opt-in + warning.
To spend a token UTXO at all (e.g. to transfer the NFT), the user must select it
explicitly via coin-control (`CCoinControl::Select`, `src/coincontrol.h:41`) or a
dedicated token-transfer RPC, AND acknowledge a warning naming the token and the
irreversibility of a mistaken spend.
TEST: spending a token outpoint without the explicit token-transfer flow is
rejected; with it, the user sees the token name + a confirm gate.

[R10] Token transfer emits a CONSERVING SEND, not a bare spend.
A deliberate NFT/token transfer MUST construct a tx that (a) puts a canonical SLP
OP_RETURN at `vout[0]`, (b) recreates the token quantity at the correct output
vout for the recipient, and (c) conserves `sum(inputs) == sum(outputs)` for that
tokenId. A bare spend (no conserving OP_RETURN) is a BURN and must be refused
unless the user explicitly chose "BURN this token" with a separate, louder gate.
TEST: transferring an NFT yields a tx with SLP SEND at vout[0], qty 1 at the
recipient vout; the overlay ledger shows the recipient now owns the NFT and the
sender does not; supply unchanged.

[R11] Baton protection.
A mint baton UTXO is treated like a token UTXO for anti-burn (R3-R10). Spending
it outside an explicit MINT flow (which must recreate the baton if continuation
is desired) warns that the mint capability will be destroyed.
TEST: an ordinary send never selects the baton outpoint; an explicit MINT keeps
the baton alive unless the user opts to end minting.

--------------------------------------------------------------------------------
## E. Determinism / canonical-spec requirements (the conservation rewrite MUST satisfy)

These bind the indexer/store rewrite so wallet anti-burn rests on a ledger that
every implementation computes identically. Cross-implementation bit-exact
agreement is the security property; each rule needs a shared test vector.

[R12] OP_RETURN at vout[0] ONLY (fix the confirmed divergence).
Replace the all-vout scan (`src/zslp/zslpindexer.cpp:205-224, 277-278`) with a
single `vout[0]` SLP check. If `vout[0]` is not a parseable SLP OP_RETURN, the tx
is non-SLP (and still burns any token inputs it spends).
TEST VECTOR: tx with payment at vout[0] and SLP-looking OP_RETURN at vout[3] =>
classified non-SLP by BOTH our indexer and a reference canonical-SLP parser.

[R13] SEND output cap = 19, too-many => INVALID.
Pin the SEND cap to 19 token outputs (vout[1..19]); a SEND with >19 quantities is
INVALID (token effect void, inputs burned), not truncated. Fix the 20-clamp
(`zslpindexer.cpp:266-267`) and the 20-sized arrays' off-by-one
(`slp.h:60`, `zslpmsg.h:47`) to a single agreed rule.
TEST VECTOR: a 20-quantity SEND => INVALID identically in both implementations.

[R14] num_outputs > tx.vout count => INVALID.
Using `voutCount` (`zslpstore.h:333`), a SEND that references more outputs than
exist is INVALID (burn), not partial-credit.
TEST VECTOR: SEND with 3 quantities on a 2-output tx => INVALID in both.

[R15] uint64 overflow on input/output sums => INVALID.
Explicit overflow detection when summing input token amounts and output
quantities; overflow => INVALID (burn). No wrapping.
TEST VECTOR: quantities chosen to overflow at the same byte boundary => INVALID
in both.

[R16] Non-token / wrong-token inputs contribute ZERO.
A SEND's available amount is the sum over inputs that are recorded token UTXOs of
THE SAME tokenId (via `GetUtxo`, `zslpstore.h:356-357`). Other inputs (non-token,
or a different token) contribute zero; shortfall => INVALID/burn, never partial.
TEST VECTOR: SEND of token A spending one A-UTXO + one B-UTXO credits only A's
amount; if that is short of outputs => INVALID, identically in both.

[R17] Quantity push length EXACTLY 8 bytes.
Enforce on the SEND path the same exact-8 rule genesis/mint already use
(`slp.c:113,134`); fix `be_to_u64`'s 1..8 leniency (`slp.c:16-21`) so a non-8
quantity push is a parse failure. Identical classification in both.
TEST VECTOR: a 4-byte quantity push => non-SLP/INVALID in both.

[R18] GENESIS/MINT/baton rules pinned.
Genesis qty at vout[1]; baton at `mint_baton_vout` (>=2), {0,1} = no baton
(`slp.h:50,76`); MINT requires spending the live baton UTXO; NFT = baton-less,
decimals 0, qty 1. MINT without a baton input => INVALID.
TEST VECTOR: MINT with no baton input => INVALID; genesis with mint_baton_vout=1
=> no baton, identically in both.

[R19] Lokad/token-type strictness pinned.
Lokad exactly `SLP\0` (`slp.h:23-24`), token type exactly 1; any deviation =>
non-SLP. A tx classified SLP by one impl and non-SLP by the other (which can flip
a burn into a non-burn) is a fork.
TEST VECTOR: wrong Lokad / type 2 => non-SLP in both.

[R20] Burn-on-spend is recorded deterministically.
For EVERY tx (SLP or not), token inputs it consumes are burned/transferred per
the rules (`ApplyTransaction` "Runs for EVERY tx", `zslpstore.h:322-325`); the
resulting UTXO set + balances are bit-identical across implementations and across
a disconnect/reconnect (reorg) round-trip.
TEST VECTOR: a cross-implementation golden ledger hash over a fixed block range
matches; a reorg replay yields the byte-identical pre-state
(`zslpstore.h:345-352`).

--------------------------------------------------------------------------------
## F. UX honesty (impersonation is social, never consensus-enforced)

[R21] Token id is the fingerprint of identity.
The GUI MUST display the genesis-txid (tokenId) as the authoritative identity and
make clear that ticker/name/image are NOT unique and NOT verified by the chain.
TEST: two tokens with identical name/ticker show distinct tokenIds and a
"name not unique" cue; neither is presented as "verified".

[R22] No false "verified" / "official" claims.
The wallet MUST NOT imply chain-level authenticity. Trust cues are limited to
issuer identity / genesis-txid match / (optional) signed attestations, each
labeled as social/external trust, not consensus.
TEST: UI copy review confirms no "verified by network" wording; impersonation
risk is surfaced.

[R23] Burn/irreversibility honesty.
Any flow that can destroy a token (deliberate burn, baton spend) states plainly
that consensus cannot undo it and the overlay can only RECORD the loss.
TEST: burn/baton-spend confirm dialogs state irreversibility explicitly.

--------------------------------------------------------------------------------
## G. Regression guards

[R24] Anti-burn regression suite.
Automated tests cover: ordinary send (R3), dust-to-fee (R4), shield/merge (R5),
send-max (R6), index-off fail-safe (R8), deliberate conserving transfer (R10),
and baton protection (R11). These run in CI on the wallet build.

[R25] Cross-implementation determinism vectors.
The R12-R20 test vectors are stored as shared golden files so any compatible
implementation can prove bit-exact agreement; a divergence FAILS the build.
