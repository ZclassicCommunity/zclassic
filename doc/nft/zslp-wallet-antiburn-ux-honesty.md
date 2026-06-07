# ZSLP Wallet Anti-Burn + UX-Honesty Requirements

Companion to `zslp-forgery-conservation-threat-model.md`. The conservation
model makes *forgery* a no-op, but it does NOTHING to stop a holder from
**burning their own** token, and it does NOTHING to stop social
**impersonation**. Both are real losses/deceptions that the wallet (GUI, a
separate repo) and the daemon coin-selection must address. These are
requirements, not edits to `src/zslp/*`.

---

## 1. The burn hazard (verified)

ZSLP rides **transparent dust UTXOs**: a token quantity or a mint baton lives
at exactly one `(txid, vout)` whose scriptPubKey pays an ordinary t-address
(`CZSLPTokenUtxo.address`, `zslpstore.h:127`; created at `vout[1]` etc.,
`zslpstore.cpp:474-483`). The amount on that output is plain dust (a few
zatoshi) — **the token value is metadata, invisible to consensus and to a
ZSLP-unaware wallet.**

The wallet today has **ZERO ZSLP awareness** — verified: `grep -rli
"zslp\|slp" src/wallet/` returns nothing. So ordinary coin selection will
happily pick a token-carrying dust UTXO as a fee/change input in a normal
ZCL send. The moment that UTXO is spent by a non-SLP tx (or an SLP tx that
doesn't re-assign it), **R-CONS-2 burns the token**
(`zslpstore.cpp:449-450`; test `NonSlpSpendBurnsUtxo`). An NFT spent this way
is gone forever — there is no recovery, because token id == genesis txid and
the qty-1 UTXO that carried it is consumed.

This is the single most likely way a user loses a token, and it is entirely
preventable in the wallet.

## 2. Anti-burn requirements (daemon coin-selection + wallet)

- **W-1.** The wallet MUST be able to identify token-carrying UTXOs. With
  `-zslpindex` enabled, cross-reference each candidate `(txid, vout)` against
  the token UTXO set. Expose a daemon read API the wallet can call cheaply:
  `GetUtxo(txid, vout)` already exists (`zslpstore.cpp:230`); add a batch
  "is-token-utxo" / "annotate my unspents" RPC so the wallet doesn't do N
  round-trips. (Pure read; no consensus impact.)
- **W-2.** Normal coin selection (fee + change for ordinary sends, autoshield,
  sweep, send-max) MUST **exclude** token-carrying UTXOs by default. A
  token/baton UTXO is *never* auto-selected as an incidental input.
- **W-3.** Coin-control MUST **surface** token UTXOs distinctly (labeled with
  ticker/name/qty/"mint baton"/"NFT") so a user can knowingly include one only
  when they mean to (e.g. building an actual SLP SEND).
- **W-4.** If a user action WOULD spend a token UTXO without a valid SLP
  message re-assigning it, the wallet MUST **block + warn** with an explicit
  "this will permanently BURN <token>" confirmation — never silent.
- **W-5.** Building an SLP SEND, the wallet MUST honor the positional output
  mapping (R-CONS-4: amount[j] → vout[1+j]) and MUST place the SLP OP_RETURN
  at **vout[0]** (R-LOC-1). It MUST select enough token inputs that
  `Σ amounts ≤ availIn` (R-CONS-3) or the SEND burns. Change tokens MUST be an
  explicit additional output, or they are burned implicitly
  (`zslpstore.cpp:565`).
- **W-6.** Mint-baton handling: the wallet MUST treat the baton UTXO as
  precious (losing it = token permanently fixed-supply, R-CONS-5) and never
  auto-spend it; continuing the baton requires `mint_baton_vout ∈ [2,
  voutCount)`.
- **W-7.** Dust-limit interaction: a token output is dust by ZCL value.
  The wallet MUST NOT let a dust-consolidation / "clean up small UTXOs" or
  "discard dust below threshold" feature sweep token UTXOs. Audit every place
  the wallet filters by amount.

## 3. UX-honesty requirements (impersonation is social, not consensus)

Uniqueness is at the **token-id (genesis txid)** level only. Anyone can
GENESIS a *different* token (different txid ⇒ different `tokenId`) reusing a
ticker, name, document_url, or image hash. The overlay does NOT and CANNOT
prevent this (it's a new, valid token, not a forgery of an existing one). The
GUI must present this honestly:

- **U-1.** NEVER present ticker/name/image as proof of identity. The
  **genesis-txid (token id)** is the only unique identifier. Show a short,
  copyable token-id fingerprint everywhere a token is named.
- **U-2.** Show the **document_hash** when present and let the user verify it
  against the actual image bytes (the NFT image-hash binding,
  `genesisMeta.documentHash`, `zslpindexer.cpp:238-246`). A matching hash
  proves the *bytes* are the ones the genesis committed to — NOT that the
  issuer is legitimate.
- **U-3.** Warn on look-alikes: if a token's ticker/name collides with a
  previously-seen different token id, flag "another token uses this name —
  verify the token id."
- **U-4.** Issuer trust is OUT of the protocol. Support (don't fake) social
  attestation: issuer-published token-id lists, signed messages, known-issuer
  registries. The GUI may *display* such attestations but MUST label them as
  third-party claims, never as protocol guarantees.
- **U-5.** Never imply consensus enforces token rules. Token balances are
  "as computed by the ZSLP index over confirmed blocks"; if `-zslpindex` is
  off, the wallet shows no token data (it does not silently guess).
- **U-6.** Make burn risk legible: any screen that lists token UTXOs should
  note they ride tiny transparent outputs that must not be spent as ordinary
  funds.

## 4. Determinism honesty (tie-back to the security model)

- **U-7.** The wallet's token balances MUST come from the SAME canonical rules
  as the daemon index (ideally by *reading the daemon index*, not by
  re-parsing independently). If the wallet ever parses SLP itself, it MUST
  pass the canonical test vectors (X-1 in the conformance checklist) — an
  independently-parsing wallet that disagrees on a D1–D6 edge case shows the
  user a balance no one else agrees with. Reading the daemon's `'u'`/`'b'` view
  is the safe default.

---

## Summary of what each property buys

| Loss vector | Stopped by | Where |
|-------------|-----------|-------|
| Token forgery / inflation | conservation model (this is a no-op/burn) | `src/zslp/*` (threat model doc) |
| Holder burns own token via incidental spend | wallet anti-burn W-1..W-7 | wallet repo + daemon read RPC |
| Look-alike / name-reuse impersonation | UX honesty U-1..U-6 (social, not consensus) | wallet repo |
| Two implementations disagree → ledger fork | canonical spec + test vectors | conformance checklist doc |
