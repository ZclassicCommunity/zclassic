# ZSLP Security Model + Wallet Anti-Burn / UX-Honesty Requirements

Companion to `zslp-determinism-spec.md`. This doc states the trust model, the
determinism-fork threat class, and the wallet/GUI requirements that keep honest
holders from destroying their own tokens and keep users from being socially
defrauded.

## A. Trust model (one paragraph)

ZClassic consensus is unchanged and SLP-unaware. It will confirm any standard
tx, including a token forgery. The token ledger is a pure function of confirmed,
consensus-ordered history computed identically by every honest observer. A
forgery confirms on-chain but credits nobody. The ONLY thing that can break this
model is two honest observers disagreeing (a determinism fork) — then the
attacker presents conflicting ownership to two victims with no tiebreaker. So
the security target is: bit-exact agreement of the ledger function across all
implementations, plus a wallet that (1) never accidentally burns tokens and
(2) never lies to the user about what on-chain data can and cannot prove.

## B. What base consensus CANNOT do (and why the overlay must)

- Cannot reject a forged SEND/MINT/GENESIS OP_RETURN. (It's a standard tx.)
- Cannot make token UTXOs unspendable-as-coins. The token rides a normal
  transparent dust output; consensus sees only ZCL value and will happily let
  any wallet spend it as fee/change. => the BURN risk (§C) is unavoidable at the
  consensus layer and MUST be handled in the wallet.
- Cannot enforce token-id uniqueness beyond txid uniqueness. => impersonation is
  a social problem (§D).

The deterministic overlay's defense is uniform: a rule-breaking on-chain action
is interpreted as "creates nothing / burns inputs," so it changes no honest
observer's ledger — PROVIDED all observers apply the identical rules.

## C. Holder anti-burn (wallet) — REQUIRED

FACT (verified): `src/wallet/` has ZERO ZSLP awareness (`grep -rli zslp
src/wallet/` returns nothing). An ordinary `sendtoaddress` / `z_sendmany` /
fee/change selection can pick a token-carrying dust UTXO as an input and BURN
the token (per R-BURN-1 the indexer will dutifully record the burn — correctly,
but the user lost their NFT).

R-WALLET-1 (exclude token UTXOs from automatic coin selection): The wallet MUST
identify token-carrying UTXOs (via the local `-zslpindex` store: a prevout that
`GetUtxo(txid,vout)` resolves to a token UTXO or baton) and EXCLUDE them from
all automatic input selection (fee, change, normal sends). This requires the
wallet to consult the ZSLP store (or an equivalent local view) during coin
selection. Default: token UTXOs are unspendable-by-accident.

R-WALLET-2 (coin control surfacing): Token UTXOs (and batons) MUST be visible
and selectable in coin control, clearly labeled with tokenId/ticker/amount and a
"this output carries a token; spending it outside a token SEND BURNS it"
warning. Deliberate spend requires explicit selection.

R-WALLET-3 (token SEND construction): When building a token SEND, the wallet
MUST include exactly the intended token input UTXO(s) of the target token, place
the SLP OP_RETURN at vout[0], place recipient(s) at vout[1..], and add a token
CHANGE output for any surplus (availIn - sent) so surplus is not burned (R-QTY-3
burns surplus). The wallet's own constructed tx MUST validate under the §3-§8
canonical rules BEFORE broadcast (self-check against the same parser/conservation
the indexer uses).

R-WALLET-4 (no shielding of token dust): Token UTXOs are transparent. Auto-shield
/ "shield all" MUST exclude token UTXOs (shielding them = burning them and
leaking value into a z-addr). Tie into R-WALLET-1.

R-WALLET-5 (dust/fee interaction): The token dust output's ZCL value is below
normal spend thresholds; the wallet must not "consolidate dust" across token
UTXOs. Exclusion (R-WALLET-1) covers this; pin it for the dust-consolidation
path specifically.

## D. Impersonation / social honesty (GUI) — REQUIRED

R-UX-1 (identify by tokenId): Every token is shown with its full tokenId
(genesis txid) as the canonical identifier; ticker/name/image are secondary and
explicitly attacker-controllable. Two tokens with the same ticker MUST be
visually distinguishable by tokenId/fingerprint.

R-UX-2 (no false trust): The GUI MUST NOT render any "verified," "official," or
checkmark status derived solely from on-chain metadata. document_url and
document_hash are issuer claims, not proofs.

R-UX-3 (image/hash honesty): If an NFT image is shown, the GUI MUST verify it
against document_hash when it has the bytes, and show "image matches on-chain
hash" vs "unverified" — never imply authenticity of the ISSUER from a matching
hash (anyone can mint a token pointing at someone else's image).

R-UX-4 (issuer attestation is out-of-band): Any "this token is from issuer X"
claim MUST come from a signed attestation binding an identity to a genesis txid,
presented as a separate, clearly-sourced trust signal — never inferred from
on-chain strings.

## E. Confirmed-vs-unconfirmed honesty — REQUIRED

R-UX-5: Ownership/balance shown as "confirmed" MUST derive only from the
confirmed-history ledger (§ spec §1, §10). Unconfirmed token receipts/sends are
shown in a visually distinct "pending" state and are NEVER counted as owned for
the purpose of "I can prove I own this." This prevents an attacker from using a
just-broadcast (and later double-spent/reorged) tx to convince a victim of
ownership.

## F. Determinism-fork threat class — the residual that this work closes

The structured findings (returned to the orchestrator) enumerate each
nondeterminism source. The closure criterion for the whole class: a SECOND,
independent implementation of `f`, fed the identical block history including
adversarial edge-case txs (vout[1] SLP message, PUSHDATA2 field, trailing byte,
31-byte hash, 2^63 quantity, 20-quantity SEND, out-of-range output index,
same-block genesis+send, reorg), produces a BIT-IDENTICAL ledger and RPC output.
Until that cross-impl differential test exists and passes, the threat class is
OPEN regardless of how clean the single implementation looks.
