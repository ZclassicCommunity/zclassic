# ZSLP Impersonation & Uniqueness — Security Model, Canonical Validation Spec, and Requirements

Threat class: **impersonation-uniqueness**. Scope: what "unique" / "authentic"
actually means for a ZClassic ZSLP token (and an NFT in particular), which
impersonation attacks are unstoppable on unchanged consensus, which the
deterministic overlay neutralizes, and the social/cryptographic defenses that
need **zero consensus change**.

This document is **spec + requirements only**. It edits no source. It grounds
every claim in the real tree (`src/zslp/*`, `src/rpc/zslp.cpp`,
`src/script/standard.cpp`) and tells the in-flight conservation rewrite and the
wallet/GUI exactly what they must satisfy.

---

## 0. The one-paragraph threat model

ZSLP is a **metaprotocol overlay**: a deterministic function computed by an
observer (`-zslpindex` → `CZSLPIndexer` → `CZSLPStore`) over the
consensus-ordered, confirmed block history. Base consensus knows nothing about
SLP — it relays and mines **any** standard transaction, including an OP_RETURN
that encodes a forged GENESIS or SEND. We can **never** make consensus reject a
token forgery. Therefore token security is not "the chain refuses bad txs"; it
is **determinism + agreement**: an on-chain tx that breaks the overlay rules is
simply *interpreted as crediting nobody (and burning its inputs)*, and **every**
honest observer running the **same canonical rules** computes the **identical**
ledger. The entire attack surface of this threat class is: (a) things the
overlay *cannot* stop because they are valid-by-design uses of an open protocol
(name/ticker/image reuse), which must be defended **socially** and surfaced
**honestly**; and (b) things the overlay *must* stop bit-exactly, where any
cross-implementation disagreement forks the ledger and lets an attacker show
two parties contradictory "ownership."

---

## 1. What "unique" / "authentic" actually guarantees

Verified against `src/zslp/slp.c`, `src/zslp/zslpindexer.cpp`,
`src/zslp/zslpstore.cpp`.

### 1.1 What IS guaranteed (cryptographic / deterministic)

1. **Token-id uniqueness.** `token id == genesis txid`
   (`zslpindexer.cpp:229` `parsed.tokenId = txid;`,
   `zslpstore.cpp:453` `const uint256 tokenId = txid;`). Txids are globally
   unique under consensus, so **a token id can never collide**. Two genesis
   transactions are two different tokens, full stop, even if every visible field
   (ticker, name, document_url, document_hash, decimals) is byte-identical.

2. **First-genesis-wins per id is structurally trivial.** Because the id *is*
   the txid, a second tx can never re-issue an existing id — it would need to
   reproduce a txid, i.e. a hash preimage collision. The `!readToken(tokenId,…)`
   guard at `zslpstore.cpp:457` is belt-and-suspenders, not the actual defense.

3. **Single-unit uncopyability (the NFT property).** An NFT is a baton-less
   GENESIS with `decimals=0, qty=1`. The lone unit lives at exactly one token
   UTXO `(txid,vout)` (`CZSLPTokenUtxo`, the store's "SOURCE OF TRUTH",
   `zslpstore.h:113`). A SEND can only move tokens carried by **spent inputs**
   (`availByToken`, `zslpstore.cpp:437-446`), and `availIn >= requiredOut`
   gates creation (`zslpstore.cpp:552`). So **the one unit cannot be duplicated,
   forged into existence, or moved by anyone but the current UTXO holder.**
   Confirmed by `ForgedSendCreditsNobody`
   (`test_zslp_indexer.cpp:477-491`) and `OverSendBurnsInputsNoOutputs`.

4. **Image-bytes provability.** GENESIS carries an optional 32-byte
   `document_hash` (`slp.c:90-96`). Anyone holding the bytes can recompute the
   hash and prove "**these exact bytes are the ones recorded at genesis.**" This
   binds *content* to *id*. (The on-chain field is opaque 32 bytes; the
   convention SHA-256(image) is overlay/UI policy, not consensus.)

### 1.2 What is NOT guaranteed (this is the whole threat class)

1. **Name / ticker / document_url are NOT unique and NOT authenticated.**
   GENESIS imposes **no constraint** on `ticker`/`name`/`document_url`
   (`slp.c:66-89` copies whatever is pushed). Anyone can mint a *different*
   token (new id) whose name/ticker/image-hash exactly reuse a victim
   collection's. The overlay accepts it as a perfectly valid, distinct token.

2. **Issuer identity is NOT on-chain.** A GENESIS has **no input requirement**
   and no signed issuer field — it is valid even with `vin` of unrelated coins.
   "Who minted this" is only "which key(s) signed the funding inputs," which the
   overlay does not record, does not verify, and which an impersonator can make
   look like anything (any address can fund any genesis).

3. **Same image, different token, is fully legal.** `document_hash` proves the
   *bytes* match; it says **nothing** about *who* is entitled to mint those
   bytes. An impersonator can mint a new token that reuses the victim's exact
   image hash — and the wallet's image-verify badge would (naively) go green,
   because the bytes *do* match the (forged) genesis. The green check answers
   "do these bytes match THIS token's recorded fingerprint?" — never "is this
   the authentic/original token."

**Bottom line:** uniqueness is at the **token-id (genesis-txid) level only**.
Authenticity of *name/brand/issuer* is a **social** problem with no trustless
on-chain answer on unchanged consensus. The defenses are issuer-identity
conventions and honest UI — Sections 4–6.

---

## 2. Why base consensus cannot stop any of this

`Solver()` classifies *any* `OP_RETURN <push-only…>` as `TX_NULL_DATA` and
returns true (`script/standard.cpp:71-73`); `IsStandard` accepts it as long as
it is ≤ `nMaxDatacarrierBytes` (223) and `-datacarrier` is on
(`standard.cpp:197-200`). Consensus has **no notion** of SLP fields, token ids,
issuers, batons, or conservation. It will relay and mine:

- a GENESIS reusing any name/ticker/image hash,
- a SEND/MINT OP_RETURN that the overlay will deem invalid,
- a transaction that spends and **burns** a token UTXO as ordinary dust.

None of these can be rejected by a node we do not control (and we have a HARD
CONSTRAINT not to touch consensus). Security must therefore be **interpretive**:
the forgery lands on-chain but **changes no honest observer's ledger** — *if and
only if* every observer computes the same canonical function. That "if" is
Section 3.

---

## 3. CANONICAL VALIDATION SPEC (the agreement contract)

This is the normative spec the conservation rewrite (and any third-party
indexer/wallet/explorer) MUST implement **bit-exactly**. Any divergence on any
clause **forks the ledger** and lets an attacker present conflicting ownership
to two parties — the core impersonation payoff. Each clause is testable.

### 3.1 SLP-message location and recognition

- **C-LOC-1 (vout[0] only — NORMATIVE, currently VIOLATED).** A transaction is
  an SLP transaction **iff its `vout[0]` scriptPubKey parses as a valid SLP
  message.** Canonical SLP pins the message to output index 0; an SLP-looking
  OP_RETURN at any other index does **not** make the tx SLP.
  **Current code violates this:** `zslpindexer.cpp:211` scans
  `for (vo = 0; vo < tx.vout.size(); ++vo)` and takes the *first* vout that
  both is `TX_NULL_DATA` and parses (`:215`, `:223`, "first valid OP_RETURN
  wins" `:278`). A tx whose vout[0] is an ordinary payment and whose vout[3] is
  an SLP OP_RETURN would be treated as SLP by this indexer but as **non-SLP**
  by a canonical implementation → **ledger fork**. **MUST change to: parse only
  `vout[0]`; if vout[0] is not a valid SLP message, the tx is non-SLP (inputs
  still burn per C-CONS-1).**

- **C-LOC-2 (one message per tx).** Exactly the vout[0] message governs. No
  scanning of later outputs for a "second" message.

- **C-REC-1 (recognition gate).** vout[0] is a valid SLP message iff, in order:
  starts with `OP_RETURN` (0x6a); field0 is a 4-byte push equal to `"SLP\0"`;
  field1 (token_type) is a 1–2 byte push decoding to exactly 1; field2 is the
  ASCII tx-type token (`"GENESIS"`/`"MINT"`/`"SEND"`); and all
  type-specific fields parse per `slp.c`. Any failure ⇒ **not SLP** (return
  false, `slp.c:34-166`). The push grammar is `read_push`
  (`op_return_push.h:24-46`): only opcodes `0x01..0x4b`, `0x4c` (PUSHDATA1),
  `0x4d` (PUSHDATA2) — **anything else (incl. `0x4e` PUSHDATA4, OP_0/OP_1..16,
  minimal-push violations) ⇒ not SLP.** This grammar is part of the contract;
  do not "fix" it to accept more.

### 3.2 Field-parse determinism (exact byte rules)

These mirror `slp.c` and MUST be reproduced exactly:

- **C-FLD-1 token_type:** push len 1–2, big-endian, must equal 1 else not-SLP
  (`slp.c:54-57`).
- **C-FLD-2 GENESIS decimals:** push len exactly 1, value `0..9` else not-SLP
  (`slp.c:99-101`).
- **C-FLD-3 GENESIS mint_baton_vout:** push len 0 (no baton) or 1; if 1 the
  value MUST be `>= 2` else **not-SLP** (`slp.c:104-109`). Values 0/1 are only
  valid as the *empty* push (no baton).
- **C-FLD-4 quantities are 8-byte pushes, big-endian, uint64**
  (`slp.c:111-114, 134-137, 149-159`). A quantity push of any length other than
  8 ⇒ not-SLP (GENESIS/MINT) or terminates the SEND list (SEND, see C-SEND-1).
- **C-FLD-5 token_id (MINT/SEND):** push len exactly 32 else not-SLP
  (`slp.c:121-124, 144-147`). On-chain bytes are **display/big-endian** and MUST
  be reversed to the daemon's internal little-endian uint256
  (`TokenIdToUint256`, `zslpindexer.cpp:147-153`). GENESIS id is the txid,
  taken directly (already internal order).
- **C-FLD-6 document_hash:** present iff its push len is exactly 32; any other
  length ⇒ treated as absent (`slp.c:91-96`). (For RPC/display the 32 bytes are
  reversed, `zslpindexer.cpp:242-245`; this is a display detail, but MUST be
  consistent so two implementations show the same hex.)
- **C-FLD-7 oversize text fields:** ticker/name/document_url longer than the
  buffer are silently **dropped to empty** (the `len < sizeof(...)` guards,
  `slp.c:69, 77, 85`) but the message still parses. This is a determinism trap:
  the rule is "store empty if it does not fit," and the buffer sizes
  (ticker 64, name 128, document_url 256, `slp.h:44-46`) are part of the
  contract. **Pin these sizes; never silently widen them.**

### 3.3 SEND quantity-list and output mapping

- **C-SEND-1 list termination.** Read 8-byte quantity pushes for outputs
  `vout[1], vout[2], …` until a non-8-byte push or end-of-script; **at least 1
  output quantity is required** else not-SLP (`slp.c:149-160`). The parser caps
  at 19 (`< 19`, `slp.c:151`); the indexer/store clamp `n` to `[0,20]`
  (`zslpindexer.cpp:265-268`, `zslpstore.cpp:540-542`). **The canonical cap and
  the clamp MUST agree** — a SEND with more quantities than the cap must be
  handled identically everywhere (current code: parser stops at 19; store would
  never see >19 because `numOutputs` is bounded). Pin one number.
- **C-SEND-2 positional mapping.** `outputQuantities[j]` maps to **`vout[1+j]`**
  (`zslpstore.cpp:559` `int32_t voutIdx = 1 + j;`). A zero-quantity output
  **consumes a slot but creates nothing** (`zslpstore.cpp:557-558`) — the
  mapping does NOT compact across zeros. This positional semantics is normative.
- **C-SEND-3 output-index out of range ⇒ that quantity is BURNED.** If
  `1+j >= voutCount` the quantity is silently dropped (no UTXO created),
  `zslpstore.cpp:560-561`. NOT an invalidation of the whole SEND.
- **C-SEND-4 conservation gate.** Compute `requiredOut = Σ outputQuantities`
  with **overflow ⇒ INVALID whole SEND** (`zslpstore.cpp:543-550`), and a
  **negative quantity (high-bit-set uint64 read as int64 < 0) ⇒ INVALID**
  (`:545`). SEND is valid iff `!overflow && availIn >= requiredOut`
  (`:552`). If invalid: create nothing; **all that-token inputs already burned**
  (input consume in 3.5 ran regardless). `(availIn - requiredOut)` on a valid
  SEND is **burned implicitly** (`:565`).
- **C-SEND-5 unknown-token / no-input ⇒ availIn = 0.** A SEND naming a token
  with no token UTXO among the spent inputs has `availIn = 0`
  (`zslpstore.cpp:533-535`), so any positive `requiredOut` is invalid ⇒ creates
  nothing. This is the forged-SEND defense (`test:477-491`).

### 3.4 GENESIS and MINT determinism

- **C-GEN-1 mint output at vout[1].** Initial quantity is created at **vout[1]**
  only, and only if `initialQuantity > 0 && voutCount > 1`
  (`zslpstore.cpp:474-477`). Hardcoded index 1 is normative.
- **C-GEN-2 baton at declared vout.** A baton is issued iff
  `mintBatonVout >= 2 && mintBatonVout < voutCount`
  (`zslpstore.cpp:463-466, 479-483`). Out-of-range declared baton ⇒ **no
  baton** (and `token.mintBatonVout` display-mirror stays 0).
- **C-MINT-1 baton-input requirement.** A MINT is valid iff a **mint-baton
  token UTXO of that token id was on a spent input**
  (`batonInputPresent`, `zslpstore.cpp:441-442, 493-494`). No baton input ⇒
  create nothing, inputs stay burned (`test:524-544`). MINT of an unknown token
  ⇒ nothing (`zslpstore.cpp:490-491`).
- **C-MINT-2 baton continuation.** New baton at `mintBatonVout` iff
  `>=2 && < voutCount` else the baton ends (`zslpstore.cpp:508-510`). Mint
  output at vout[1] as in C-GEN-1.
- **C-SUPPLY-1 totalMinted is issued supply, not circulating.** `totalMinted`
  is the running sum of genesis+mint quantities (`zslpstore.h:78`,
  `:497-500`); it is **not** decreased by burns. Display must not call it
  "supply" without the "issued" qualifier (a burned NFT still shows
  totalMinted=1). Overflow-guarded add (`:497-499`).

### 3.5 Universal input-burn and ordering

- **C-CONS-1 every tx burns the token UTXOs it spends.** For **every** tx (SLP
  or not), each spent input that is a known token UTXO is consumed/erased first
  (`zslpstore.cpp:437-446`). A non-SLP tx (or an invalid SLP tx) that spends a
  token UTXO **burns it** — this is the wallet anti-burn motivation (Section 5).
- **C-ORD-1 intra-block ordering.** Txs are applied in **block order**
  (`zslpindexer.cpp:186-187`), each committing its own batch so a later tx in
  the same block can spend a UTXO an earlier tx created
  (`test:638-644`, store header note `zslpstore.h:313-318`). The undo seq runs
  across the whole block (`:243-244`).
- **C-ORD-2 idempotence.** A re-delivered connect for the current tip is a
  no-op (`zslpindexer.cpp:180-183`). Catch-up resumes one past the stored tip
  (`:99-104`). These keep replay deterministic across restarts/reorgs.
- **C-REORG-1 byte-exact reversal.** DisconnectBlock replays the undo log in
  reverse, restoring consumed UTXOs, erasing created ones, reversing
  balance/totalMinted/baton changes, yielding a byte-identical pre-state
  (`zslpstore.cpp:591-731`, header `:345-352`). Reorg determinism is part of the
  agreement contract: two nodes that see the same reorg MUST land on the same
  ledger.

### 3.6 Address/derived-view determinism

- **C-ADDR-1.** A token UTXO's owner address is `ExtractDestination` of its
  scriptPubKey, encoded; non-standard/undecodable ⇒ `""`
  (`zslpindexer.cpp:132-142`). A `""`-address UTXO still exists and is still
  spendable/burnable (it just has no derived per-address balance row,
  `zslpstore.cpp:371` skips empty addresses). The UTXO map — not the balance
  view — is the source of truth, so a `""` owner does not lose the token.
- **C-BAL-1.** Per-(token,address) balance is a **derived** view maintained by
  signed deltas (`zslpstore.cpp:367-403`); it must always equal the sum of live
  token UTXO amounts for that (token,address). Tests must assert this invariant.

> **Determinism test obligation:** every clause above needs a gtest that pins
> the exact behavior, **especially C-LOC-1** (vout[0]-only), which the current
> indexer violates. A cross-implementation "ledger digest" test (hash of the
> full token/UTXO/balance set at a height) is the strongest agreement check.

---

## 4. Issuer identity & authenticity — defenses that need NO consensus

None of these change consensus. They establish "**who** minted this and **is it
the brand I trust**," which the chain cannot answer.

### 4.1 Genesis-txid fingerprint (the primary identity)

The only trustless, collision-free identity is the **token id = genesis txid**.
A creator publishes their token id out-of-band, against a source the user
already trusts (the brand's own https site, a signed social post, a printed
card). The user/wallet then verifies the on-chain token *is that exact id*.
This is centralized **only** in "you must already trust where you got the id" —
there is no trustless way around that, and pretending otherwise is the core
dishonesty to avoid.

### 4.2 Signed issuer attestations (cryptographic, off-chain)

A creator proves control of an identity by **signing a message** that binds the
token id to a public identity, using either:

- **the genesis funding key** — sign `"ZSLP-ISSUER:" + tokenid` with the
  private key of an input that funded the genesis (or any address the creator
  publicly claims). ZClassic already has `signmessage`/`verifymessage`
  (transparent ECDSA message signing in the wallet/RPC). The attestation is:
  *"address A, which I publicly own, signed this token id."* It is only as
  strong as the public's belief that A belongs to the brand — but it is a real,
  verifiable cryptographic statement and needs no consensus.
- **a published brand key** — the brand publishes a long-lived pubkey on its
  trusted channel and signs each legitimate token id with it. Now the user
  verifies one well-known key instead of trusting an id in isolation.

Requirements: define a **canonical attestation string format** (exact bytes,
so signatures are portable) and a **verify path** in the wallet/RPC that takes
(tokenid, address/pubkey, signature) → valid/invalid. This is pure
sign/verify; no consensus, no new on-chain data required (the attestation can
live entirely off-chain or, optionally, in a later GENESIS document_url).

### 4.3 Verified-issuer / allowlist (curated, explicitly centralized)

A wallet ships (or fetches from a configurable, signed source) a **curated map
`{tokenid → display name, verified bool}`**. A token id in the list earns a
"Verified issuer" badge; everything else is "Unverified." This is **honest
centralization**: the badge means "this id is on a list maintained by <named
party>," never "the protocol guarantees authenticity." The list MUST be:
keyed by token id (never by name/ticker), versioned, and its provenance shown
to the user. ENABLEMENT.md already states this is the only answer and is
centralized (`doc/nft/ENABLEMENT.md:85, 133`).

### 4.4 NFT1 group/child for set authenticity

Set membership ("is this card part of the official Curio set?") is **not**
on-chain-authenticated by name. The defense is the **NFT1 group/child**
pattern: a single **group genesis** (its token id is the set's identity), and
each child mint is tied to the group by spending a **group baton/quantity input**
— so a child's membership is provable via the same UTXO-conservation the overlay
already enforces (C-MINT-1 / C-CONS-1). A child that merely *claims* the group
name without spending a real group input is, by conservation, **not a member**.
This converts "set authenticity" from an unforgeable-name problem (impossible)
into a baton-input problem (already solved deterministically). **Requirement:**
the group/child binding rule must be added to the canonical spec (Section 3)
with its own determinism tests **before** the GUI shows any "part of set X"
claim as authoritative; until then the GUI must label set membership as
issuer-asserted, not verified.

---

## 5. Wallet anti-burn requirements (holder-side, non-consensus)

Verified: **the wallet has ZERO ZSLP awareness today** — `grep -ril zslp
src/wallet/` returns nothing. Consequence: ordinary coin selection can spend a
token-carrying dust UTXO as a fee or change input and **silently BURN the NFT**
(C-CONS-1 burns any spent token UTXO). This is the single highest-severity
*holder-side* loss in this threat class and it has nothing to do with
attackers — the holder's own wallet destroys the asset.

Requirements (all non-consensus, wallet-local):

- **W-ANTIBURN-1.** Coin selection MUST identify token-carrying UTXOs (query
  the store by `(txid,vout)` via `GetUtxo`, or an exported set) and **exclude
  them from normal/auto coin selection** for ordinary ZCL sends, change, and
  fee funding. A token UTXO is spent only by an explicit token operation.
- **W-ANTIBURN-2.** Token UTXOs MUST be surfaced in **coin control** so the
  user can see and (with an explicit, warned action) spend them.
- **W-ANTIBURN-3.** Any path that *would* spend a token UTXO (manual coin
  control, sweep, "send max") MUST show a **burn warning** naming the token and
  requiring explicit confirm. Default-deny.
- **W-ANTIBURN-4.** The exclusion MUST be robust when `-zslpindex` is **off**:
  if the wallet cannot consult the store, it MUST fall back to a conservative
  rule (e.g. treat protocol-dust outputs of the wallet's own token txs as
  unspendable-by-default, or refuse "send max" with a calm "token index off —
  cannot guarantee your collectibles are protected" note) rather than silently
  risking a burn.
- **W-ANTIBURN-5.** Sending an NFT MUST construct the SLP SEND with vout[0] =
  the OP_RETURN (per C-LOC-1) and the unit's quantity at the correct positional
  output (C-SEND-2), so the wallet never accidentally produces a tx the
  canonical indexer reads as non-SLP (which would burn the unit).

---

## 6. GUI honesty requirements (presentation of uniqueness/authenticity)

The GUI is where impersonation is won or lost socially. NATIVE_UX.md already
defines a verify badge and a banned-jargon list; these requirements pin the
**honesty semantics** for the impersonation-uniqueness threat class
specifically.

- **G-HONEST-1 (the green check's exact meaning).** The image "Genuine" badge
  (NATIVE_UX.md §2.2) means **only** "these bytes match the fingerprint recorded
  in THIS token's genesis." It MUST NOT be presented as "authentic," "official,"
  or "the original." Two different tokens can both show green for the same image.
  Copy MUST be "matches its on-chain fingerprint," never "authentic."
- **G-HONEST-2 (identity is the id, never the name).** Every NFT/collection
  detail MUST show the **token id (genesis txid)** as the identity, copyable,
  and MUST state that name/ticker are **not unique** — "anyone can create a
  collectible with this name." (Mirrors ENABLEMENT.md:98,133.)
- **G-HONEST-3 (impersonation warning on lookalikes).** When the wallet sees
  two distinct token ids sharing a name/ticker/image-hash, it MUST surface a
  **collision indicator** ("Another collectible uses this name/image") rather
  than silently picking one. Never resolve a name to a single token implicitly.
- **G-HONEST-4 (verified-issuer badge is explicitly sourced).** A "Verified
  issuer" badge (Section 4.3) MUST name its source and MUST be visually distinct
  from the image-match badge (they answer different questions). Absence of the
  badge MUST read "Unverified issuer," never "fake."
- **G-HONEST-5 (no name-based search-to-action).** Send/buy flows MUST resolve
  the target by **token id**, not by user-typed name. A name search MAY help
  discovery but the user MUST confirm the **id** before any value action.
- **G-HONEST-6 (set membership honesty).** Until NFT1 group/child verification
  (Section 4.4) is in the canonical spec + tested, "part of set X" MUST be shown
  as **issuer-claimed**, not verified.
- **G-HONEST-7 (index-off honesty).** With `-zslpindex` off, provenance/verify
  fields MUST degrade to a calm "can't verify right now — token index is off,"
  never a false green or a crash (matches NATIVE_UX index-off states). A
  wallet-local cached fingerprint MAY be checked, but the badge MUST indicate it
  was not cross-checked against the live ledger.

---

## 7. Severity-ranked threat table (summary)

| # | Attack | Overlay verdict | Severity |
|---|--------|-----------------|----------|
| T1 | Forged SEND/MINT crediting attacker without holding the token/baton input | **Neutralized** — credits nobody, burns inputs (C-SEND-5, C-MINT-1; `test:477-544`) | info (already solved) |
| T2 | **vout[0]-position parse divergence** — indexer scans any vout, not vout[0] (`zslpindexer.cpp:211`) | **NOT yet neutralized** — cross-impl ledger fork → conflicting ownership | **critical** |
| T3 | Impersonation token reusing victim name/ticker/image-hash (new id) | **Cannot be neutralized on-chain** (valid by design) → must be defended socially + UI (Sec 4,6) | high |
| T4 | Wallet burns a token UTXO as fee/change (zero wallet awareness) | **Not neutralized by overlay** (C-CONS-1 burns it) → wallet anti-burn required (Sec 5) | **critical** (holder loss) |
| T5 | Determinism edge cases: overflow, neg qty, out-of-range vout, >cap outputs, oversize fields, token_type≠1, baton<2, push-grammar | **Neutralized iff bit-exact** across implementations (Sec 3.2-3.4) | high (each is a fork risk) |
| T6 | "Same image ⇒ authentic" confusion in UI | Mitigated only by honest copy (G-HONEST-1) | high (social) |
| T7 | Name-resolves-to-one-token UI shortcut → silent impersonation | Mitigated by id-not-name actions (G-HONEST-3/5) | high (social) |
| T8 | Set/group spoof by name | Mitigated by NFT1 group/child + tests (Sec 4.4); honest label until then (G-HONEST-6) | medium |
| T9 | Reorg replay divergence between nodes | Neutralized iff byte-exact reversal (C-REORG-1) | medium (fork risk) |

---

## 8. Requirements checklist (testable)

**Canonical spec / conservation rewrite MUST satisfy:**

- [ ] **R1 (fixes T2, critical):** SLP message parsed from **vout[0] ONLY**;
  vout[0] not-SLP ⇒ tx is non-SLP (inputs still burn). gtest: SLP OP_RETURN at
  vout[3] with a payment at vout[0] ⇒ token effect = NONE.
- [ ] **R2:** token_type must equal 1; push-grammar limited to 0x01..0x4b /
  0x4c / 0x4d; reject 0x4e/opcodes/non-minimal as not-SLP. gtest per case.
- [ ] **R3:** GENESIS decimals ∈ 0..9 (len 1); baton push len 0 or 1-with-value≥2;
  else not-SLP. gtest both rejections.
- [ ] **R4:** quantities are 8-byte BE uint64; SEND list terminates on
  non-8-byte push; ≥1 quantity required; cap pinned and identical in parser +
  store. gtest >cap and 0-quantity-list.
- [ ] **R5:** SEND conservation: `requiredOut` overflow ⇒ invalid; negative qty
  ⇒ invalid; valid iff `availIn>=requiredOut`; surplus burned; positional
  `j→vout[1+j]`; out-of-range output qty burned (not whole-tx invalid). gtests
  for each (extend `OverSendBurnsInputsNoOutputs`).
- [ ] **R6:** GENESIS mint at vout[1] only; baton iff `2≤vout<voutCount`;
  first-genesis-wins (trivially via txid). gtest out-of-range baton ⇒ no baton.
- [ ] **R7:** MINT requires baton-input of that token id; unknown token ⇒
  nothing; baton continuation rule. gtest (extend `MintWithoutBatonRejected`).
- [ ] **R8:** every tx (incl. non-SLP) burns spent token UTXOs (C-CONS-1).
- [ ] **R9:** token_id endianness reversal (display↔internal) consistent;
  document_hash present iff 32 bytes; display-order consistent.
- [ ] **R10:** reorg yields byte-identical pre-state; intra-block later-tx
  spends earlier-tx UTXO; idempotent re-connect (extend existing reorg tests).
- [ ] **R11:** derived balance == Σ live UTXO amounts per (token,address)
  invariant asserted in tests.
- [ ] **R12 (agreement):** a cross-height **ledger-digest** test (stable hash of
  token+UTXO+balance set) to detect any future determinism drift.

**Issuer-identity layer (non-consensus) MUST provide:**

- [ ] **R13:** canonical, byte-exact issuer-attestation string format binding
  tokenid↔address/pubkey, plus a sign (genesis/published key) + verify path.
- [ ] **R14:** verified-issuer list keyed **by token id only**, versioned,
  provenance-shown, configurable/signed source.
- [ ] **R15:** NFT1 group/child membership rule added to the canonical spec with
  determinism tests **before** any "verified set membership" UI claim.

**Wallet anti-burn MUST provide:**

- [ ] **R16:** exclude token UTXOs from normal/auto coin selection, change, fee.
- [ ] **R17:** surface token UTXOs in coin control; explicit warned spend only.
- [ ] **R18:** burn warning (default-deny) on any path that would spend a token
  UTXO, incl. send-max/sweep.
- [ ] **R19:** safe degradation when `-zslpindex` is off (conservative protect,
  not silent burn).
- [ ] **R20:** NFT SEND constructed with OP_RETURN at vout[0] and correct
  positional quantity output (so the canonical indexer never reads it as
  non-SLP).

**GUI honesty MUST provide:**

- [ ] **R21:** image badge copy = "matches its on-chain fingerprint" only; never
  "authentic/official/original" (G-HONEST-1).
- [ ] **R22:** identity shown as token id; name/ticker labeled non-unique
  (G-HONEST-2).
- [ ] **R23:** lookalike/collision indicator on shared name/ticker/image-hash
  across distinct ids (G-HONEST-3).
- [ ] **R24:** verified-issuer badge names its source and is visually distinct
  from the image-match badge; absence reads "Unverified," not "fake"
  (G-HONEST-4).
- [ ] **R25:** value actions resolve by token id, not by user-typed name
  (G-HONEST-5).
- [ ] **R26:** set membership shown as issuer-claimed until R15 lands
  (G-HONEST-6).
- [ ] **R27:** index-off degrades to honest "can't verify," never a false green
  or crash (G-HONEST-7).

---

## 9. Cross-references

- `doc/nft/ENABLEMENT.md` §1, §4 — non-goals and the "identity is the genesis
  txid + minting address, never the name" framing this doc formalizes.
- `doc/nft/NATIVE_UX.md` §2.2 (verify badge), §3 (per-screen index-off states),
  §7 (honesty ledger) — the UI surface these honesty requirements bind.
- `src/zslp/slp.c`, `src/zslp/zslpindexer.cpp`, `src/zslp/zslpstore.cpp` — the
  implementation the canonical spec (Section 3) governs.
- `src/gtest/test_zslp_indexer.cpp` — existing forgery/conservation tests to
  extend per Section 8.
