# ZSLP Threat Model — DoS / Spam / Griefing (non-consensus overlay)

Threat class: **dos-spam-grief**
Scope: ZClassic ZSLP token overlay (`-zslpindex`, `CZSLPIndexer`, `CZSLPStore`),
RPC reads in `src/rpc/zslp.cpp`, and the (not-yet-written) wallet integration.
Status: ANALYSIS + SPEC. This document does **not** edit `src/zslp/*`. It is the
security model and acceptance bar the conservation rewrite + wallet work must hit.

---

## 0. The hard constraint (why most of this can't be "fixed")

We CANNOT change ZClassic consensus. Minters and users run **existing, unchanged**
nodes. Base consensus does not know ZSLP exists: it relays/mines any standard
transaction, including an OP_RETURN that encodes a forged or abusive token op.

Verified in-tree:
- `src/script/standard.cpp:65-72` — a `TX_NULL_DATA` output is standard as long
  as it starts with `OP_RETURN` and the rest is push-only. The chain neither
  parses nor rejects ZSLP content.
- `src/script/standard.h:34` — `MAX_OP_RETURN_RELAY = 223` bytes; one OP_RETURN
  per **relayed** tx is the policy ceiling.
- `src/main.cpp:758-779` — `IsStandardTx` rejects a tx with `nDataOut > 1`
  ("multi-op-return") **for relay only**. A cooperating/self-mining party can
  still place a non-standard, multi-OP_RETURN tx in a block, and once mined it is
  a normal confirmed tx that every indexer must process. Standardness is a relay
  policy, **not** a consensus rule.
- `src/init.cpp:552-553,1833` — `-datacarrier` / `-datacarriersize` are
  node-local relay knobs; they do not bind miners or other nodes.

**Consequence for this threat class:** we can never stop an attacker from getting
spam/dust/abusive-token bytes confirmed on-chain. Every defense below is
indexer-side (bound the damage to our resources + the canonical ledger) or
wallet-side (don't burn the user's tokens, don't auto-display hostile content,
tell the truth). Be honest in the GUI about what is unpreventable.

---

## 1. What an attacker can put on-chain (the raw primitives)

1. **OP_RETURN spam:** up to 223 bytes of arbitrary data per relayed output; via
   self-mined non-standard txs, multiple OP_RETURNs and larger payloads per tx.
   Each looks like a normal tx to consensus.
2. **Dust outputs:** ZSLP "rides" transparent dust — token quantity lives at a
   real pay-to-address vout (`zslp_listmytokens` help text, `src/rpc/zslp.cpp:204`).
   An attacker can pay 1 satoshi (or the dust floor) to **any** address and attach
   a token to it.
3. **Unsolicited token sends:** a valid SEND whose output vout pays the victim's
   address creates a real token UTXO the victim now "owns" in the index
   (`CZSLPStore::ApplyTransaction` SEND branch, `zslpstore.cpp:531-569`).
4. **Abusive metadata:** GENESIS `ticker`/`name`/`document_url`/`document_hash`
   are attacker-controlled free text/URL/hash (`slp.c:63-114`). `document_url`
   can point at hostile content; the hash can claim to be any image.
5. **Fake collections / impersonation:** anyone can GENESIS a token reusing a
   famous name/ticker/image. Uniqueness is only at token-id = genesis-txid level
   (`zslpindexer.cpp:229`, `zslpstore.cpp:453`).

---

## 2. The security property we are actually defending

SECURITY = **DETERMINISM + AGREEMENT**. There is no consensus to fall back on, so
the only thing protecting "who owns what" is that every honest observer running
the canonical rules computes the **bit-identical** ledger. Therefore in this
threat class a *determinism divergence is itself a critical DoS/grief vector*: an
attacker who finds an input two implementations parse differently can present
conflicting ownership to a marketplace vs. a wallet (ledger fork). I treat parse
non-determinism as the most severe item here, above resource exhaustion.

---

## 3. Threats (each: attack -> why consensus can't stop it -> overlay defense -> residual)

### T1 — Parse non-determinism: OP_RETURN at non-zero vout (CRITICAL, ledger fork)

**Attack.** Construct a tx whose vout[0] is a normal payment and whose vout[1] (or
later) is the SLP OP_RETURN. Canonical SLP requires the SLP message to be at
**vout[0]**; a tx with a non-zero-position OP_RETURN is simply "not SLP". An
implementation that scans *any* vout will credit/move tokens that a canonical
implementation ignores (and vice-versa) → two ledgers, conflicting ownership.

**Why unchanged consensus can't stop it.** The tx is standard either way; the
chain has no opinion on which vout "should" carry the data.

**Current code is WRONG here.** `zslpindexer.cpp:211` loops
`for (size_t vo = 0; vo < tx.vout.size(); ++vo)` and takes the **first vout that
parses as SLP**, not vout[0]. The header comment `slp.h:5` and `slp.h:7` already
*state* the canonical rule ("vout[0]"), so the implementation contradicts its own
spec. There is no gtest asserting vout-position behavior
(`src/gtest/test_zslp_indexer.cpp` has no nulldata-position test).

**Overlay defense (required).** Pin ONE canonical rule and make every observer
obey it: the SLP message MUST be parsed from **vout[0] only**. If vout[0] is not a
parseable SLP `TX_NULL_DATA`, the tx is non-SLP (inputs still burn, nothing
created). No "scan for first match". See `CANONICAL_VALIDATION_SPEC.md` §R1.

**Residual.** None once pinned + tested; this is fully closeable.

---

### T2 — Parse non-determinism: multiple OP_RETURNs in one (mined) tx (CRITICAL, ledger fork)

**Attack.** Self-mine a non-standard tx with two OP_RETURNs, both at low vouts,
each a *different* valid SLP message (e.g. vout[0] = junk-but-parseable, vout[1] =
the "real" SEND), betting that observer A keys on the first and observer B on
another.

**Why unchanged consensus can't stop it.** "multi-op-return" is relay policy only
(`main.cpp:778`); a mined block carrying it is valid and must be indexed.

**Overlay defense (required).** The canonical rule (vout[0]-only) already
disambiguates: only vout[0] is ever consulted, so additional OP_RETURNs at vout≥1
are irrelevant by construction. Spec §R1 + a gtest with a two-OP_RETURN tx.

**Residual.** None once §R1 is enforced and tested.

---

### T3 — Quantity/index edge-case divergence (HIGH, ledger fork)

**Attack.** Craft a SEND whose `outputQuantities` (a) sum-overflow int64/uint64,
(b) reference an output index beyond `tx.vout.size()`, (c) supply more quantities
than there are outputs, (d) include a quantity that overflows when added to the
running input total, or a GENESIS/MINT with a baton vout out of range. Each is a
spot where two implementations can silently disagree (one burns, one creates).

**Why unchanged consensus can't stop it.** All such txs are standard bytes.

**Overlay defense (mostly present, must be pinned + tested).** Current store
behavior to canonicalize:
- Output-sum overflow → whole SEND INVALID, inputs burned
  (`zslpstore.cpp:543-550,567`). ✔ matches a sane spec.
- Output index ≥ voutCount → that quantity is **burned**, others still applied
  (`zslpstore.cpp:560-561`). Must be the canonical rule, not an error.
- num_outputs clamp to ≤ 20 in two places (`slp.c:151` caps at 19 on parse;
  `zslpindexer.cpp:267` and `zslpstore.cpp:542` clamp to 20). **The clamp value
  must be ONE number across parser/bridge/store** or a 20th output diverges.
- "Input not a recognized token UTXO ⇒ contributes ZERO" — `readUtxo` miss is a
  `continue` (`zslpstore.cpp:439`). ✔ canonical.
- uint64→int64 cast: amounts are parsed as uint64 (`slp.c:158`) then stored int64
  (`zslpstore.cpp:230,270`). A quantity with the high bit set becomes **negative**
  int64; the SEND loop treats `q < 0` as overflow→INVALID (`zslpstore.cpp:545`).
  This is *a* deterministic rule but it must be the **declared** one (see spec
  §R5): "any output quantity ≥ 2^63 ⇒ SEND invalid".

**Residual.** None if the spec fixes each rule and gtests assert them. Risk is
purely "second implementation guesses differently" — closed by a published spec +
test vectors.

---

### T4 — Index resource exhaustion via cheap genesis/UTXO flooding (HIGH)

**Attack.** Mint thousands of tiny tokens, or fan a token into thousands of dust
UTXOs, to bloat the `-zslpindex` LevelDB ('t', 'u', 'x', 'b' records) and slow
catch-up/reorg replay. Cost to attacker = on-chain fees only; cost to every
indexing node = unbounded disk + CPU at `CatchUp` and on each `ConnectBlock`.

**Why unchanged consensus can't stop it.** Each genesis/send is a normal,
fee-paying tx.

**Overlay defense (partial; needs explicit bounds).**
- The index is **derived and disposable**: behind `-zslpindex`, fully rebuildable,
  wiped on version bump (`zslpindexer.cpp:74-85`). So worst case is bounded by the
  chain's own size, not amplified.
- Per-tx work is O(vin + vout) with a small constant; reorg replay is O(undo ops
  for the block). No superlinear blowup found.
- **Gaps:** (1) `TokenCount()`/`UtxoCount()` and `ListTransfers` build full
  in-memory vectors (`zslpstore.cpp:255-279,777-799`) — `ListTransfers` gathers
  **all** transfers for a token then reverses (`zslpstore.cpp:777,796`),
  unbounded by `count`. A token spammed with millions of transfers makes one RPC
  call allocate the whole set. (2) `GetTokensForAddress` scans the **entire** 'b'
  keyspace for every address (`zslpstore.cpp:810-822`), and `zslp_listmytokens`
  calls it once per wallet key (`rpc/zslp.cpp:222-236`) → O(keys × total_balances)
  full-table scan per RPC.

**Overlay defense (required).** Bound list RPCs at the **store** layer
(stream + early-stop at `count+from`, never materialize the full set);
the `ZSLP_LIST_MAX = 1000` cap (`zslpstore.h:49`) currently bounds the *returned*
slice but **not** the gathered set in `ListTransfers`. Make `GetTokensForAddress`
seek by an address-keyed view or accept that it is a full scan and rate-limit/cap
it. See spec §R8.

**Residual.** On-chain bloat itself is unpreventable; the index merely mirrors the
chain. We close the *amplification* (one cheap tx → expensive RPC / OOM), not the
base growth.

---

### T5 — Unsolicited / abusive token sends to a victim's address (MEDIUM, grief)

**Attack.** Send a valid token (offensive name, or a "scam airdrop") to a
victim's t-address. The index correctly records the victim as owner
(`zslpstore.cpp:562`); `zslp_listmytokens` will surface it
(`rpc/zslp.cpp:185-261`). The victim cannot refuse receipt.

**Why unchanged consensus can't stop it.** Paying someone is the chain's whole
purpose; a token-carrying dust payment is indistinguishable to consensus.

**Overlay defense (wallet/GUI, required).** Cannot be neutralized at the ledger
(the tokens are genuinely there). Defense is **presentation**:
- Default-hide unsolicited / unverified tokens; require explicit "show" per token
  or per issuer (allowlist).
- **Never auto-fetch or auto-render** `document_url` content or any media; never
  resolve the URL without an explicit user click + warning.
- Treat `name`/`ticker` as untrusted text: no HTML/markup, length-clamp on
  display, strip control chars; show the token-id fingerprint, not just the name.

**Residual.** The bytes (including an abusive name) remain on-chain and in the
index forever; we can hide but not erase. Be explicit about this in the GUI.

---

### T6 — Token-burn griefing via the ZSLP-unaware wallet (HIGH, user fund/asset loss)

**Attack.** Not even an external attacker is needed: the **user's own wallet**
will destroy tokens. The wallet has ZERO ZSLP awareness today (verified: `grep
-rin zslp src/wallet/` = 0 hits). A token quantity rides a transparent dust UTXO;
ordinary coin selection will happily spend that dust as fee/change in a normal
ZCL send, and `ApplyTransaction` then **burns** it (a non-SLP tx consuming a token
UTXO creates nothing — `zslpstore.cpp:432-446`, gtest
`NonSlpSpendBurnsUtxo`). An NFT (qty 1) is gone permanently. An attacker can
*induce* this by sending the victim tokens on tiny dust the wallet will
opportunistically sweep.

**Why unchanged consensus can't stop it.** The wallet builds a perfectly valid tx;
nothing on-chain marks the dust as "special".

**Overlay defense (wallet, required).**
- The wallet MUST identify token-carrying UTXOs (query the index by
  `(txid,vout)` → `GetUtxo`) and **exclude** them from automatic coin selection.
- Surface them in **coin-control** so the user can spend them only deliberately.
- A deliberate token spend must go through a ZSLP-aware path that emits the
  correct SEND OP_RETURN at vout[0], or warn loudly that the token will burn.

**Residual.** A user who force-spends a token via coin-control can still burn it
intentionally; that is acceptable with a clear warning. A wallet that hasn't yet
synced the index could mis-classify — must fail **closed** (treat unknown dust as
possibly-token and warn) per spec §R9.

---

### T7 — Impersonation / fake-collection flooding (MEDIUM, social grief)

**Attack.** GENESIS many tokens cloning a real project's `ticker`, `name`,
`document_url`, and `document_hash` to confuse buyers; flood `zslp_listtokens`
with look-alikes.

**Why unchanged consensus can't stop it.** Names are free-text bytes; there is no
on-chain registry.

**Overlay defense (presentation only).** Uniqueness exists **only** at token-id =
genesis-txid (`zslpstore.cpp:453`, `NftCannotBeDuplicated` gtest). The GUI must:
- Identify a token by its **genesis-txid fingerprint**, never by name alone.
- Mark everything unverified by default; verification is an out-of-band,
  social/attestation layer (issuer-signed statements, curated allowlists), NOT a
  chain guarantee.
- Make impersonation visible (e.g. "3 other tokens use this name") rather than
  pretending uniqueness.

**Residual.** Impersonation is **inherent** and unpreventable; honesty is the only
mitigation. State this plainly in the UX.

---

### T8 — Reorg / disconnect amplification (LOW–MEDIUM)

**Attack.** Drive deep reorgs (or feed a node many competing tips) so the indexer
replays large undo logs.

**Why unchanged consensus can't stop it.** Reorgs are normal consensus behavior.

**Overlay defense (present).** Disconnect is O(undo ops for the block), accumulates
per-record in memory, writes each once (`zslpstore.cpp:591-731`), and yields a
byte-identical pre-state (gtests `ReorgGenesisRoundTrip`, `ReorgMintRoundTrip`).
The undo log is bounded by the block's own ZSLP activity. No unbounded
amplification found.

**Residual.** Bounded by chain reorg depth, which consensus already limits in
practice. Acceptable.

---

### T9 — Catch-up / re-delivery double-count (LOW, integrity not DoS, noted)

The connect path has an idempotence guard (`zslpindexer.cpp:180-183`) and
crash-resume via the tip marker. Relevant here only because a broken guard would
let a replay double-credit, which is a (self-inflicted) ledger divergence. Keep
the guard + a test; not an external DoS lever.

---

## 4. Severity ranking (this threat class)

| ID | Threat | Severity | Closeable on overlay? |
|----|--------|----------|------------------------|
| T1 | OP_RETURN non-vout[0] parse divergence | **critical** | Yes — pin vout[0]-only |
| T2 | Multiple-OP_RETURN parse divergence | **critical** | Yes — implied by T1 fix |
| T3 | Quantity/index edge-case divergence | high | Yes — spec + vectors |
| T6 | Wallet burns tokens (own + induced) | high | Yes — coin-control exclude |
| T4 | Index resource exhaustion / RPC OOM | high | Partly — bound RPCs; base growth inherent |
| T5 | Unsolicited / abusive sends | medium | No (ledger); hide in GUI |
| T7 | Impersonation / fake collections | medium | No; honesty only |
| T8 | Reorg amplification | low | Already bounded |
| T9 | Replay double-count | low | Guard present; keep tested |

---

## 5. Honest "cannot be prevented" list (put this in the GUI, not the footnotes)

- On-chain **bytes are permanent**: spam OP_RETURNs, abusive names, dust, and
  unsolicited tokens cannot be deleted, only hidden in our views.
- **Anyone can clone** any token's name/ticker/image; only the genesis-txid is
  unique. There is no chain-enforced "real" issuer.
- We cannot stop a user from being **sent** a token; we can only choose not to
  surface it.
- A confirmed forged/abusive tx is a **valid** ZClassic tx; consensus will keep
  relaying and mining such transactions. The overlay's only power is to credit
  nobody / burn / hide — never to make the chain reject it.

See `CANONICAL_VALIDATION_SPEC.md` for the exact rules and
`REQUIREMENTS_DOS_SPAM_GRIEF.md` for the testable acceptance checklist the
conservation rewrite + wallet work must satisfy.
