# ZCL Decentralized Platform — beta7 Blueprint

## 1. Executive Summary

ZClassic becomes a privacy-first platform where **the chain is the source of truth for human-readable names** and **Tor is the source of truth for where to reach you** — two clients of one consensus-free overlay, never two networks. The whole design obeys one separation: **WHAT** (names, tokens, NFTs) lives on-chain as deterministic OP_RETURN records; **WHERE** (self-authenticating .onion v3 keys) lives on Tor, which the chain points at but never has to trust a server to resolve. The single headline feature of beta7 is **on-chain names (ZNAM) that resolve in the C++ daemon and the Qt wallet** — nothing more, because the red-team review made it unambiguous that the seven-workstream "do it all" plan was three releases of work disguised as one. We adopt the proven ZSLP non-consensus pattern verbatim: a `CValidationInterface` observer parses `vout[0]` OP_RETURN records, builds a reorg-safe indexer with undo deltas, and never touches consensus, PoW, mempool acceptance, or spends. Ownership of a name is bound to a **holding UTXO at output index 1** — owner = whoever can spend it — which makes TRANSFER/RENEW/expiry implementable with zero new crypto, but the review proved this rule is a latent divergence and privacy hazard, so it is now pinned as a strict total function and the GUI must warn that a name publicly clusters the coins used to fund it. **Names are ASCII-only `[a-z0-9-]`, reject-don't-normalize**, eliminating the homoglyph fork surface for v1; IDNA/punycode is an explicit v2 behind a version byte. The wire bytes are **PERMANENT and require the owner's byte-level sign-off on `znam-determinism-spec.md` BEFORE any code is written** — every constant (DURATION, grace, dust floor, length caps) is frozen, not "e.g." We make four decisive cuts based on the review: **marketplace, BIP155 ADDRv2, the multi-coin/CONTENT target types as live features, and the three-codebase Tor soak all move to beta8.** The C++ daemon is the authoritative indexer and the beta7 spine; zclassic23 is recast from "rival reimplementation" to a beta8 Tier-C web/power node whose `znam.c` is a *client of the spec*, not the canonical authority — the spec, not any code (especially not the private `zclassic-c` repo), is the single source of truth. We are honest that beta7 has real residual central points: discovery still bootstraps from operator seeds + `-addnode` (fixed only by beta8 BIP155), light wallets must resolve against a node the user runs (never a project-default remote RPC), and Tor inherits its own directory authorities. The result is a believable single release: **freeze the spec, port a 4-command/3-target ZNAM indexer + RPC into `zclassicd`, ship a Names tab in Qt, prove it with single-codebase regtest gtests.**

## 2. The Integrated Architecture

The platform is **three tiers over one chain**, with a clean role split and no overlap.

**Layer 1 — Shared on-chain overlay (the contract).** Every overlay protocol is a NON-consensus OP_RETURN record in `vout[0]`, value 0, parsed by a deterministic observer — the proven ZSLP 7-layer pipeline (parser → bridge → indexer → store → wallet anti-burn → self-validate → RPC). Two lokad families ship/extend the framework: `SLP\0` (tokens/NFTs, shipping) and `ZNAM` (names, new in beta7). **The bytes are the spec; the deterministic indexing rules are the spec.** A single shared total function in `op_return_push.h` reads the lokad tag first and routes to EXACTLY ONE family parser; any tag not in the set is inert for all overlays, so the SLP parser and the ZNAM parser can never produce cross-protocol ghost records.

**Layer 2 — Tor identity/transport (where, not what).** Chain records POINT to .onion targets; Tor publishes/reaches them. Embedded Tor T2 (node .onion via `ADD_ONION`, DEANON guard) is proven. The resolution model is: *chain says `name → onion/zaddr/taddr`; Tor says `onion → live host`.* The chain stores the **32-byte ed25519 key**, not the base32 string, so connecting cryptographically proves you reached the keyholder — no trusted resolver in the loop. **The keystone networking deliverable, T3 BIP155 ADDRv2 gossip, is a beta8 item** (it has no bearing on a beta7 Qt user, who resolves names via RPC and never needs onion gossip).

**Layer 3 — Node tiers:**
- **Tier A — Light/Qt GUI wallet (the beta7 audience).** Consumes the overlay via RPC; new Names tab; never an onion server. Resolves names ONLY against a node the user runs.
- **Tier B — Full node = shipping C++ `zclassicd`.** Authoritative indexer for SLP/NFT + ZNAM; publishes its P2P .onion; resolves names. **This is the beta7 spine.**
- **Tier C — Power/Web node = zclassic23 (beta8).** A full node that ALSO runs MVC-over-.onion + block explorer + zcl-browser. Web hosting is Tier C only; the C++ daemon stays P2P-onion-only (the no-SOCKS webserver was correctly rejected).

**End-to-end composition (the beta7-real path):** A Qt user (Tier A) registers `alice → ONION` via their own Tier-B daemon. Any Tier-B node ingests the same `vout[0]` bytes, derives the same owner from the holding UTXO, and `name_resolve("alice")` returns the 32-byte key. **Resolution is a pure local-index lookup that performs ZERO outbound network I/O** — it returns the target only; any connection is a separate, explicit user action. In beta8, the SAME chain record powers onion-reach for the daemon and a browsable `alice.zcl` site in the zcl-browser: one record, three tiers, one chain. The NFT/marketplace composition (`Listed by alice.zcl`, offer gossip, ZSLP atomic-swap settlement) is a **beta8 demo** — beta7 ships names only.

## 3. ZNAM On-Chain Protocol

NON-consensus name overlay, OP_RETURN at `vout[0]` value 0, same push family as ZSLP, whole record ≤223 bytes, total-function parsing. **Wire bytes are PERMANENT — owner byte-level sign-off on `znam-determinism-spec.md` is required BEFORE any code.** Every numeric below is a frozen v1-immutable constant; changing ANY of them requires a new version byte, never a v1 reinterpretation.

### 3.1 Record layout (canonical minimal push via `op_return_push.h`)
```
push  lokad     "ZNAM" = 0x5a4e414d           (4 bytes)
push  version   0x01                           (1 byte)
push  command   1 byte:
        REGISTER=1 UPDATE/SET_RECORD=2 TRANSFER=3 RENEW=4
push  name      1..32 bytes (hard cap 32; ASCII-canonical-or-drop)
push  command-specific fields (fixed per-type lengths; see §3.4)
```
**Recognition rule (frozen, total):** A ZNAM record is recognized ONLY at `vout[0]`, ONLY if `vout[0]` is OP_RETURN with `nValue==0`. **At most ONE ZNAM record per transaction.** If `vout[0]` is not a value-0 OP_RETURN the tx carries no ZNAM record even if a later output is one. A second OP_RETURN anywhere is irrelevant.

**Push encoding (frozen):** each field uses the minimal canonical single-byte length-prefixed direct push (all fields are <76 bytes). `OP_PUSHDATA1/2/4` and `OP_1..OP_16` numeric pushes are FORBIDDEN; any non-canonical push opcode ⇒ record IGNORED. This closes script malleability as a divergence vector.

**Length invariant (frozen):** the ≤223 limit is measured on the **full serialized `vout[0]` scriptPubKey byte length, including push-opcode/length-prefix bytes**, enforced BEFORE parse. A worked byte-budget table per command proving the max case ≤223 is part of the spec.

Any deviation / over-length / unknown-version / leftover-bytes / wrong-per-type-length ⇒ **record IGNORED** (never invalid, never throws, never forks — forward-compatible by construction).

**Indexing key:** `namehash = SHA256("ZNAM" || name_bytes)` over the canonical ASCII name **WITHOUT the version byte**, so a name's identity is version-independent (a future v2/IDNA record references the SAME name slot, not a parallel namespace). The indexer **MUST persist the raw canonical name bytes in the value** (not just the key) so `name_list`/`info` are deterministic and reversible. The recomputed namehash of a record's name MUST equal its key context or the record is dropped (string is authoritative, hash is merely an index).

### 3.2 Name canonicalization — REJECT, don't normalize
A name must already be canonical or the record is dropped — normalization on ingest is itself a fork surface. Canonical is a pure byte predicate, identical in both impls:
- each byte in `[a-z]`, `[0-9]`, or `-` (0x2d)
- does not start or end with `-`; no `--`
- length 1..32
- **NO unicode, NO uppercase, NO punycode** (ASCII-only eliminates the homoglyph class for v1; IDNA/punycode is a v2 extension behind a version bump, with its own determinism spec).

### 3.3 Ownership — HOLDING-UTXO at output index 1 (total function)
**Owner of a name = whoever can spend the holding UTXO**, fixed as the output at **index 1** of the registering tx. This binds the name to a real spendable coin, requires zero new crypto (pure UTXO bookkeeping the indexer already does for ZSLP), is reorg-clean, and collapses ownership + TRANSFER + UPDATE + RENEW into one rule. The red team proved the lifecycle was underspecified; the following total-function predicate is FROZEN and applies UNIFORMLY to all commands:

**Holding-output validity predicate `H(tx)`:** output index 1 is a valid holding iff ALL hold, else the record is dropped/orphans per below:
- output index 1 **EXISTS** (a tx with only `vout[0]` ⇒ record IGNORED).
- it is a **transparent, standard, spendable script** from a frozen enum: P2PKH or P2SH only. A shielded (Sapling/Sprout) output, an OP_RETURN, bare multisig, or any non-standard script ⇒ record IGNORED. (Shielded holders cannot be tracked in the transparent UTXO set the indexer follows.)
- `nValue >= DUST_FLOOR` (the exact integer is frozen in the spec; written as a constant, not "546 mirrors ZSLP").

**Mutation / owner-continuity (frozen):** any UPDATE/TRANSFER/RENEW is valid ONLY if its tx **spends the name's current holding UTXO AND re-emits a valid holding output at index 1** (passing `H`). The spend test is defined PURELY over confirmed-chain outpoints `(txid:vout)` the indexer already tracks, evaluated in `(height, txindex)` order.

**Orphaning (frozen):** if the holding UTXO is spent by ANY tx — a non-ZNAM wallet spend, a consolidation, a coinjoin, OR a ZNAM tx that fails to re-emit a valid holding output — the name becomes **ORPHANED and is treated as EXPIRED-immediately** (publicly re-REGISTERable, no grace), with an undo delta recorded. This is the only choice that is deterministic from blocks alone and prevents a name pinned to a coin the owner can never recover. Self-transfer (same script at index 1) is a valid no-op rebind.

### 3.4 Commands (v1 = 4 commands, 3 live target types)
- **REGISTER(name):** claims the name; owner = holding output at index 1; sets `expiryHeight = height + DURATION`. **No inline first target** — REGISTER claims the name only; a target requires a following UPDATE. (This removes a variable-length parsing branch and the "leftover bytes vs optional field" contradiction.)
- **UPDATE / SET_RECORD(name, target_type, target_payload):** owner-continuity spend; sets/replaces ONE `(type, payload)` per record. `target_type` for v1: **ONION=1** (32-byte v3 ed25519 pubkey), **ZADDR=2**, **TADDR=3**. **Fixed per-type payload length; wrong length ⇒ record IGNORED.** A name holds AT MOST ONE current target per type (last-valid-wins by confirmed `(height, txindex)` order). **CLEAR semantics:** an all-zero payload of the type's fixed length is the canonical "cleared" sentinel; resolution OMITS a type whose current value is the sentinel (lets an owner deterministically retract a leaked onion key). For ONION, the indexer accepts ANY 32 bytes (validity is the resolver's concern — a non-decodable key resolves to "unreachable," never an indexer drop).
- **TRANSFER(name):** owner spends the holding UTXO; new owner = the holding output of the TRANSFER tx (must pass `H`, else the name orphans per §3.3). Distinct command so the GUI can show "you gave away rhett.zcl."
- **RENEW(name, periods):** owner-continuity spend; `expiryHeight += periods*DURATION`. `periods` is 1..RENEW_CAP (frozen, e.g. 10); `periods==0` or `>CAP` ⇒ record IGNORED (never clamped — clamping is a divergence trap).

**Reserved-for-beta8 (byte codes frozen now, NON-RESOLVABLE in beta7):** target types **BTC=4, LTC=5, DOGE=6, CONTENT=7** and command **SET_TEXT** are reserved in the v1 byte table so the codes are permanent, but the indexer parses them as opaque and the resolver returns "no target of that kind." (See §7 for why SET_TEXT and CONTENT are deliberately not shipped live.)

### 3.5 First-claim-wins ordering (total function)
A name is owned by the FIRST valid REGISTER in **confirmed order: (block height ASC, tx-index-in-block ASC)** — there is NO vout tiebreaker (the record is always `vout[0]`; the misleading "vout-index" component is deleted). Mempool/unconfirmed NEVER grants ownership. A later REGISTER of a live, unexpired name is dropped. Reorgs replay deterministically.

### 3.6 Expiry & grace — one pure-height predicate, no sweep
ONE predicate, used identically for resolution and registration: **`EXPIRED(name, H) := H > expiryHeight`** (at `H == expiryHeight` the name is alive and not yet re-registerable). There is NO background sweep thread (a timer is non-deterministic). A name is RESOLVABLE iff `NOT EXPIRED`. Public re-REGISTER is valid only when EXPIRED past the grace window.

**Grace (frozen):** during `[expiryHeight+1 .. expiryHeight+G]`, a REGISTER by anyone OTHER than the current-holding script is IGNORED **regardless of txindex** (grace-priority overrides ordering); only RENEW/REGISTER by the holding script is valid. **If the holding UTXO was already spent (orphaned), there is no grace** — the name is immediately publicly REGISTERable. Same-block contention at the boundary resolves by fee-priority (txindex), and this is an accepted, documented, deterministic property.

### 3.7 Anti-squat v1 (pure total functions; no central surface)
Per the red team, the privacy-toxic and under-specified economics are CUT for v1:
- **DROPPED:** the "must spend a ≥DUST confirmed-owned input" rule (negligible squat resistance, forces common-input clustering — see §4).
- **DROPPED for v1:** min-burn length tiers (consensus-adjacent economics that require the indexer to read output values as money; deferred to v2 behind a version byte, where exact integer tiers + a provably-unspendable burn output would be specified).
- **KEPT for v1:** the holding-dust deposit + tx fee + expiry recirculation + the 32-byte length cap + no-unicode. The GUI shows a **client-side confusable/brand-collision warning** (advisory, never a consensus blocklist).

The owner must consciously decide whether weak v1 anti-squat is acceptable for one release (see §9) — the value-skewed burn is the real fix and is a v2 lever.

### 3.8 Determinism contract (the signed spec) — TWO LAYERS
**(A) CANONICAL REGISTRY** — deterministic, conformance-pinned, byte-identical on every node, NEVER filtered. **(B) LOCAL RESOLUTION VIEW** — what `name_resolve`/GUI surfaces, which MAY apply a per-operator advisory denylist that suppresses *presentation only* without mutating layer A. The conformance vector pins ONLY layer A; every takedown/denylist affordance lives entirely in layer B.

The frozen rules:
1. ASCII-canonical-or-drop, no transform (§3.2).
2. Confirmed-only, ordered by (height, txindex); no mempool.
3. Ownership = holding output at index 1 per the `H` predicate; mutation = must-spend-current-holding + re-emit-valid-holding; spent-holding ⇒ orphan-as-expired.
4. Fixed per-type payload lengths; wrong length / non-canonical push / over-223 (measured on full `vout[0]` scriptPubKey) ⇒ drop.
5. ONE `EXPIRED(name,H) := H > expiryHeight`; grace-priority overrides txindex; orphaned ⇒ no grace.
6. **Determinism is specified over OBSERVABLE STATE, not mechanism:** after processing any chain to tip `(hash X, height H)`, both impls MUST yield the identical canonical registry, regardless of path (linear sync, reorg-and-replay, or cold reindex). Undo is strict LIFO (disconnect blocks reverse-height, within-block reverse-txindex). `name_resolve/list/info` are served only from settled state under the connect/disconnect lock (never a half-applied reorg).
7. The version byte gates all future changes; v1 bytes frozen; v2 = a new version byte, never a reinterpretation of v1.
8. No floats, no locale, no wall-clock, no mempool/network state; integers fixed-width; ≤223 enforced before parse.
9. **Protocol Constants table** (frozen, shared header / shared fixture): DURATION, grace G, RENEW_CAP, DUST_FLOOR, name min/max (1/32), the ≤223 cap, per-type payload lengths, the namehash preimage (`"ZNAM" || name`, no version byte), and the canonical-dump grammar. Both `CZNAMIndexer` and any `znam.c` include this table; the conformance SHA256 only matches if both use identical constants.

**Canonical dump grammar (frozen):** sort by namehash ASC; for each name emit fixed-field-order raw bytes: `namehash || raw_name_len || raw_name || owner_script_hash || expiryHeight || (per-type targets, type-ASC, RAW payloads not rendered .onion)`. Expired-below-tip names are ABSENT (matches resolution semantics). No map-iteration-order dependence.

### 3.9 Resolution
`name_resolve("alice")` at tip H: validate canonical → look up namehash → if `EXPIRED(state,H)` ⇒ "not found / available"; else return owner + current per-type targets (all-zero sentinels omitted). ONION = the 32-byte key, rendered to the .onion v3 string by the resolver. **No mempool resolution. ZERO outbound network I/O — pure O(1) local-index lookup.** The GUI calls this RPC and never parses chain data locally — determinism stays in one place. **When `-embeddedtor` is OFF the GUI MUST refuse to auto-connect to ONION targets** (no Tor route) and warn, rather than leak via a clearnet fallback.

## 4. Privacy & Decentralization Model

**No NEW load-bearing central point — but we name the residual ones honestly** (the review proved the absolutist "no central point" copy was false for beta7).

- **WHAT on-chain / WHERE on Tor.** Names live on-chain; locations are self-authenticating .onion v3 keys; the chain never stores a network location it must trust a server to resolve.
- **Resolution privacy depends on WHO you query.** A Tier-A wallet calling `name_resolve` over RPC hands that node a query log. **Invariant (frozen in §2/§5):** the Qt wallet resolves names ONLY against a node the user runs (embedded/built-in node or a user-configured local daemon over loopback), **NEVER a project-operated default remote RPC endpoint.** Resolving via a foreign node is a deanonymization point and the UI must say so.
- **Holding-UTXO clustering is a permanent, unfixable-after-ship deanon.** A human name is a strong real-identity anchor; binding it to a coin lineage lets chain analysis build `name ↔ UTXO ↔ funding inputs/change`. Therefore: (1) the spec and GUI MUST state bluntly that the holding UTXO and its funding inputs are PUBLIC and PERMANENTLY tied to the name; (2) the GUI SHOULD auto-fund REGISTER from a freshly-derived, never-reused address on a name-dedicated derivation path isolated from spending funds; (3) the GUI MUST warn that funding a name from a shielded (ZADDR) source requires a de-shield that links the shielded pool to the name. We DROPPED the "must co-spend a confirmed-owned input" anti-squat rule precisely because it forced common-input clustering.
- **Published targets are permanent public linkage.** Publishing a ZADDR target makes a shielded address publicly name-attributable; the GUI must warn and steer toward ONION (self-authenticating, no standing chain↔wallet linkage) as the canonical privacy-preserving target, and recommend a dedicated diversified address per published name. This is also why SET_TEXT (email/url) and cross-chain BTC/LTC/DOGE targets are NOT live in beta7.
- **DEANON guard is a first-class deliverable, not assumed-proven.** A node that publishes/advertises an onion identity MUST NOT simultaneously advertise or accept inbound clearnet connections under the same node identity (services/nonce/tip fingerprint) — onion-only or clearnet-only, never both correlatable. (This guard is fully realized only with T3 in beta8, when ADDRv2 gossip must be checked to never emit a self-address pairing onion with clearnet.)
- **Tx-origin deanon:** broadcasting a name-bearing REGISTER over clearnet reveals the originating IP. The GUI SHOULD broadcast ZNAM txs over Tor when `-embeddedtor` is enabled and warn otherwise.
- **Residual / inherited central points (named, not hidden):** beta7 onion/overlay discovery bootstraps from a fixed/operator seed set + manual `-addnode` — **this IS a load-bearing central point, removed in beta8 by T3 BIP155 gossip + a ZNAM-ONION peer-discovery substrate**; we ship ≥3 independently-operated seeds with documented hand-off so no single operator is load-bearing. Tor's ~9 directory authorities are an inherited (out-of-ZCL-scope) dependency of the WHERE layer — the precise claim is "no NEW load-bearing central point introduced by ZCL." Non-onion targets (ZADDR/TADDR) stay first-class so payment degrades gracefully when Tor is unavailable. Spec governance (one owner-signed permanent byte spec) is a deliberate one-time centralized act; after freeze the BYTES — not the signer — are the authority, and we anchor SHA256 of the frozen spec on-chain so the sign-off is itself verifiable. Software distribution/updates remain conventionally centralized; the decentralization claim is scoped to the runtime overlay + Tor-reached identity.

## 5. Anti-Abuse

- **ZNAM (beta7):** holding-dust deposit + tx fee + expiry recirculation + 32-byte length cap + reject-unicode + a client-side confusable/brand-collision warning. The value-skewed burn (the real squat fix) is a **v2** lever behind the version byte (exact length→satoshi tiers, enforced via a provably-unspendable burn output the indexer reads deterministically — NOT fee, which miners reclaim). The owner must accept that v1 squat resistance is weak-but-honest for one release (§9).
- **Index-bloat / replay amplification:** every record permanently adds a fixed-width entry the indexer must re-ingest on reindex. v1 mitigations: (a) **deterministic cache-eviction** — a name EXPIRED beyond grace and never re-registered MAY be dropped from the live store (reconstructible from blocks on reindex; the eviction predicate is deterministic so all nodes agree on `name_list`); (b) cap honored UPDATE records per name per N blocks at the indexer level so a name can't be a rolling write-amplification channel; (c) document the per-node growth model for Tier-B/C operators. (This is why SET_TEXT — an arbitrary-string write channel — is NOT shipped in v1.)
- **RPC-side DoS:** cap and paginate `name_list` result size; rate-limit `name_*` like other expensive RPCs; `name_resolve` is O(1) namehash lookup, no mempool, not amplifiable.
- **Marketplace anti-abuse (beta8, when ZMARKET ships):** the doc-only PoW claim (#143) is **deleted from docs now** to end doc-vs-code drift. v1 marketplace anti-spam = per-originator caps on simultaneous live offers + mandatory short offer TTL so the RAM pool self-drains + per-peer token-bucket + ban-score + originate from a fresh, name-UNLINKED confirmed UTXO (never the holding UTXO). "Tor reduces operator identifiability; it does NOT change the legal nature of relaying" — the "dissolves the legal surface" framing is struck everywhere. Relay stays default-OFF; the beta8 default-ON flip is gated on offers gossiping over the embedded onion (gated on T3 BIP155) and on a one-time operator consent gate. The node never custodies, matches, escrows, or takes a fee — settlement is the existing ZSLP atomic-swap SEND.
- **Onion inbound resource DoS (beta8 Tier-B/C):** cap inbound onion connection slots separately from clearnet with tight idle/handshake timeouts; since IP-banning is useless over Tor, add connection-establishment PoW/token-bucket and per-circuit request-rate caps; CONTENT fetches size-bounded and cached. `-embeddedtor` default-OFF is itself the beta7 mitigation (most beta7 users are Tier-A and never host an onion).

## 6. Codebase Roles

**They are ONE platform with a clean tier split, not two products — and the SPEC, not any code, is the authority.**

- **C++ daemon (`zclassicd`)** = THE shipping reference full node and authoritative overlay indexer (SLP/NFT + ZNAM) + P2P-onion transport. The beta7 spine. New beta7 code = `znam.c` (pure C, modeled on `slp.c`) + `CZNAMIndexer` (modeled on the ZSLP indexer: UTXO-bound, ownership/orphan-checked, reorg-safe LIFO undo, leveldb store keyed by namehash, raw name persisted) wired as a `CValidationInterface` observer behind `-znamindex`; wallet builder for the 4 commands; `name_register/update/transfer/renew/resolve/list/info` RPC for the **3 live target types only** (ONION/ZADDR/TADDR). Embedded Tor T2 already here.
- **Qt GUI** = THE user surface (separate C++14 repo; **NO std::optional/string_view** — empty-QString sentinels, header-declared signature types). New **Names tab only** for beta7 (register/renew/transfer/set-target + resolve box with green/red availability; My Names; accept `rhett.zcl` in Send/Receive with a mandatory "resolves to …" confirm and no remembered-trust shortcut). The RPC JSON contract is **frozen before GUI work starts** so the GUI builds against a stable interface. ZCL/ZClassic copy, never ZEC/Zcash.
- **zclassic23 (C23)** = recast from "rival reimplementation" to a **beta8 Tier-C web/power node + reference C indexer**. It is NOT a rival network: it indexes the SAME OP_RETURN bytes by the SAME determinism spec. **It is a client of the SPEC, not of any "canonical parser."** The private `github.com/RhettCreighton/zclassic-c` `znam.c` (Apache-2.0, attribute Rhett Creighton) is a one-time seed for the C++ port; after that the public, reviewable `CZNAMIndexer` + the public frozen spec are authoritative. No shipping correctness claim depends on a private repo.

**Harvest, don't merge.** We PORT the pure-C parser as a seed and the design taxonomy. We explicitly **REJECT** zclassic23's SQLite local-RPC registry (the exact thing that makes nodes disagree), its no-SOCKS MVC webserver on the C++ daemon (unauth HTTP, OOB-read), and a second full-node consensus. The `op_return_push.h` comment already names "ZSLP, ZNAM" — the framework was built to absorb this, but a header comment binds only the C++ side and is not a cross-codebase contract.

## 7. Threat Model Summary

**Consensus-safety (all NON-fork; the risk is node-disagreement/determinism):**
- *Holding-UTXO is a latent consensus-equivalent coupling.* FIX: the frozen `H` predicate (§3.3) — exists, transparent P2PKH/P2SH only, ≥DUST_FLOOR, else drop; spent-holding ⇒ orphan-as-expired; spend test over confirmed outpoints in (height,txindex) order. The conformance suite MUST include chained-mutation + reorg-across-a-transfer.
- *Lokad dispatch ambiguity.* FIX: single shared total function routes by tag; cross-protocol records cleanly rejected; conformance feeds every protocol's records to every other parser.
- *Push malleability.* FIX: minimal-push REQUIRED; `OP_PUSHDATA*`/numeric pushes forbidden ⇒ drop (§3.1).
- *Constants drift.* FIX: every "e.g." replaced by a frozen integer in the §3.8 Protocol Constants table.
- *Relay policy vs ≤223.* FIX: verify ZClassic's `MAX_OP_RETURN_RELAY`/`-datacarriersize` actually relays the record size shipped; keep records within the relayable cap or ship the wallet to set `-datacarriersize` for self-broadcast and document third-party-relay requirements (policy, not consensus).

**Privacy-deanon (critical):**
- *Holding-UTXO clusters wallet ↔ human name* and *"Listed by rhett.zcl" deanonymizes both parties via public settlement.* FIX: §4 funding/warning rules; **decouple the marketplace trust badge from the holding UTXO** — prove name↔offer binding by SIGNING the offer with the key controlling the holding UTXO, never by co-locating coins; default offers pseudonymous; "Listed by" opt-in with a deanon warning (beta8).
- *Onion-target resolution as a deanon oracle.* FIX: resolve is pure local lookup, zero network I/O; no auto-connect/auto-fetch when Tor is off; beta8 ZNAM-sourced peers contacted only over Tor, rate-limited, never gossip own clearnet address back.
- *DEANON guard split-brain (dual-stack node).* FIX: onion-only-or-clearnet-only invariant; ADDRv2 gossip must never pair self onion+clearnet (beta8 first-class gtest).
- *SET_TEXT/cross-chain targets = permanent public linkage.* FIX: not shipped live in beta7; reserved codes only; strong GUI warnings when they land.
- *Light-wallet resolver leak.* FIX: resolve only against a user-run node; forbid a default remote RPC resolver.

**Decentralization (critical):**
- *beta7 discovery is a load-bearing operator-seed set* and *marketplace has no decentralized discovery in beta7.* FIX: stop overclaiming — name discovery is honest about seeds; ship ≥3 independent seeds; marketplace is cut from beta7 entirely (no crippled "decentralized marketplace" copy).
- *CONTENT(7) has no content-routing layer = de-facto central host.* FIX: CONTENT byte reserved but NON-RESOLVABLE in beta7; the daemon never fetches it; a real DHT/replication routing layer is an unsolved beta8 design item.
- *GUI default node could become a central resolver.* FIX: the user-run-node invariant (§4/§5), enforced by a soak-test assertion.

**Legal-surface (critical):**
- *Daemon as name→illegal-content resolver* and *relay liability mischaracterized as "dissolved."* FIX: beta7 `name_resolve` returns connection endpoints ONLY (ONION/ZADDR/TADDR); CONTENT is parse-and-index-only opaque, never fetched/rendered by the daemon. The two-layer model (§3.8) gives a **layer-B per-operator advisory denylist** (namehash / content-hash / seller-namehash / offer-anchor) that suppresses LOCAL resolution without mutating the conformance-pinned layer A — a notice-and-takedown affordance that preserves conduit framing. Strike "dissolves the legal surface" everywhere. No clearnet-relay-on-for-soak. One-time operator consent gate before enabling relay/CONTENT-resolution/embedded-Tor-default. No custody/matching/fee. Explicit "no trademark adjudication" disclosure; the layer-B denylist also serves brand/phishing notices; mandatory "resolves to …" confirm in Send.

**DoS/spam/squat (critical):** near-free registration → §5 (v1 weak-but-honest; burn is a v2 lever the owner must sign off on); index-bloat → deterministic eviction + per-name UPDATE rate cap; marketplace flood, onion inbound DoS → beta8 caps/TTL/circuit-PoW (§5).

**Protocol-correctness / codebase-coherence (critical):** the conformance artifact is **redefined from a single golden SHA256 to an adversarial differential test SUITE** that diffs the full canonical registry dump across impls and includes named drop-vectors for every edge above (no-`vout[1]`, sub-dust holding, holding-spent-by-non-ZNAM-tx, double-OP_RETURN, non-canonical push, duplicate-type-last-wins, clear-via-zero, expiry/grace boundary H values, periods==0/>CAP, multi-block reorg, max-length record) plus a fuzzer. **For beta7 the C++ daemon's correctness gate is its OWN gtest vectors against the SPEC** — the cross-codebase differential suite is a **beta8** deliverable so the C++ release is not blocked on a separate codebase's convergence.

## 8. Phased Build Plan

### beta7 (one release; ONE headline: on-chain names in the daemon + Qt)
1. **`znam-determinism-spec.md` FROZEN with owner byte-level sign-off — BEFORE any code.** Exact lokad/version/command/name bytes; ASCII-canonical-or-drop ≤32; minimal-push-only; ≤223 measured on full `vout[0]` scriptPubKey + worked byte budget; holding-output `H` predicate (index 1, P2PKH/P2SH, ≥DUST_FLOOR) + orphan-as-expired; (height,txindex) ordering; single `EXPIRED` + grace-priority; namehash = `SHA256("ZNAM"||name)` (no version byte) + raw-name persisted; LIFO reorg-undo over observable state; the §3.8 two-layer model + canonical-dump grammar; the Protocol Constants table (DURATION, G, RENEW_CAP, DUST_FLOOR, caps, per-type lengths). Anchor SHA256 of the frozen spec on-chain.
2. **ZNAM port into `zclassicd`:** `znam.c` (modeled on `slp.c`) + `CZNAMIndexer` (ZSLP-modeled, behind `-znamindex`) — 4 commands (REGISTER/UPDATE/TRANSFER/RENEW), **3 live target types (ONION/ZADDR/TADDR)**; reserved codes (BTC/LTC/DOGE/CONTENT/SET_TEXT) parsed-as-opaque, non-resolvable. Wallet builder for the 4 commands. `name_*` RPC; `name_resolve` returns endpoints only, zero network I/O; `name_list` paginated + rate-limited. Deterministic expired-name eviction + per-name UPDATE rate cap.
3. **C++ correctness gate = own gtest suite against the SPEC** (the authority is the spec, not a second codebase): parse/canonicalize, ownership + `H` drop-vectors, orphan-as-expired, expiry/grace boundary H values, periods edge, duplicate-type-last-wins, clear-via-zero, non-canonical-push drop, double-OP_RETURN, multi-block reorg == cold-reindex. Plus regtest `register → resolve → update-target → transfer → expire → reorg-undo` with a small regtest DURATION.
4. **Qt Names tab only** (RPC contract frozen first): register/renew/transfer/set-target + resolve box (green/red availability, debounced/coalesced against the user's OWN local node); My Names; Send/Receive `rhett.zcl` acceptance with mandatory "resolves to …" confirm. Privacy warnings: holding-UTXO/funding is public and name-linked (auto-fund from a fresh name-dedicated address); ZADDR target reduces shielded privacy; refuse onion auto-connect when Tor is off. Confusable/brand-collision warning. ZCL never ZEC.
5. **Headless E2E** (like the existing `nft-gui-e2e` harness): Qt Names tab drives the RPCs end-to-end offscreen; full daemon gtest stays green.
6. **Doc hygiene:** delete the doc-only marketplace PoW claim; strike "dissolves the legal surface"; ship the operator-facing legal-posture doc stub and the layer-B denylist scaffolding (resolution-view filter, no consensus impact).

### beta8+
- **T3 BIP155 ADDRv2** (the headline of beta8): version-gated `CNetAddr/CService/CAddress` torv3 serializer, `peers.dat` v1→v2 migration, `sendaddrv2` negotiation, DEANON-guard ADDRv2 self-address check as a first-class gtest. Onion peers gossip/persist.
- **Cross-implementation conformance differential SUITE** vs zclassic23 `znam.c` (full-dump diff + fuzzer) — makes "unified codebases" real once both parts exist.
- **Marketplace (ZMARKET):** publish RPCs (`nft_publishoffer/unpublish/browse/getoffer/offerpoolinfo`) over `g_offerPool + NftVerify + RelayNftOfferInv`; bridge `nft_makeoffer`'s json store into the RAM offerpool; SIGNED name↔offer binding (no coin co-location); pseudonymous default + opt-in "Listed by"; per-originator caps + offer TTL + token-bucket + ban-score; Market tab; relay default-ON gated on T3 + onion gossip + operator consent; no custody/matching/fee.
- **Embedded Tor default-ON flip** (rebase ALPHA→STABLE first), onion inbound resource caps + circuit-establishment PoW.
- **Tier-C decentralized web:** harden zclassic23 MVC-over-.onion + zcl-browser; client-side render policy + layer-B denylist; ONLY then make CONTENT(7) resolvable, with a content-routing/replication layer so no author-node is load-bearing.
- **ZNAM v2 (version byte):** value-skewed burn anti-squat tiers; IDNA/punycode + homoglyph policy with its own spec; SET_TEXT with a fixed low-risk key allowlist + tight caps + printable-ASCII-only values, gated on the emergency-redaction break-glass design; multi-coin/CONTENT live UX with permanent-linkage warnings.
- **ZNAM-ONION as a peer-discovery substrate** (removes remaining fixed-seed reliance), Tor-only, rate-limited, untrusted.
- **Emergency-redaction coordination** for any user-supplied on-chain strings.

## 9. Open Decisions for the Owner

- **Permanent ZNAM wire bytes — the gating sign-off.** Exact lokad/version/command/name encoding, minimal-push-only rule, and per-type payload lengths. **Recommendation:** approve the §3.1 layout as written; these bytes are permanent and block all code.
- **DUST_FLOOR (holding-output minimum).** **Recommendation:** write an exact integer (do not say "546 mirrors ZSLP"); pick the ZClassic transparent dust relay threshold as a HARD constant so it never diverges per-chain.
- **DURATION and grace window G.** ~262,800 blocks ≈ 1yr at 150s, with a grace of e.g. a few thousand blocks. **Recommendation:** freeze both now (changing later = v2, acceptable); validate the full expiry/grace/re-register/reorg state machine on regtest with a tiny DURATION so the frozen value isn't shipped untested.
- **RENEW_CAP.** **Recommendation:** freeze at 10 (`periods` 1..10; 0 or >10 ⇒ drop, never clamp).
- **v1 anti-squat strength.** **Recommendation:** accept weak-but-honest v1 (dust + fee + expiry + length cap + client-side warning); commit the value-skewed burn (steep length-tiered, provably-unspendable burn output, RENEW charged the same) as the v2 headline. Decide now ONLY whether to *reserve* a burn-output convention so v2 doesn't need to reshape the record.
- **Reserve vs defer the unused byte codes (BTC/LTC/DOGE/CONTENT, SET_TEXT).** **Recommendation:** RESERVE the codes in the v1 table (permanent, non-resolvable) but ship NO live handling — adding them later is purely additive behind the version byte, while reserving keeps the namespace clean. The owner must accept that reserving CONTENT/SET_TEXT codes commits their meaning even though they're inert.
- **namehash preimage includes the version byte? — NO.** **Recommendation:** `SHA256("ZNAM" || name)` WITHOUT the version byte, so v2/IDNA references the same name slot rather than forking a parallel namespace. This is a permanent choice; confirm explicitly.
- **Relay-policy reality check.** **Recommendation:** before freeze, confirm ZClassic's default `-datacarriersize` relays the largest beta7 ZNAM record; if not, cap record size or ship the wallet's `-datacarriersize` setting + document it.
- **Spec-as-authority, not the private `zclassic-c` parser.** **Recommendation:** the frozen public spec is canonical; the private `znam.c` is a one-time porting seed only — confirm no shipping correctness claim depends on a private repo.
- **Layer-B per-operator denylist for legal/takedown.** **Recommendation:** approve the §3.8 two-layer model so an operator can suppress LOCAL resolution of a specific name/content/offer without touching the conformance-pinned canonical registry — this preserves both unification and a notice-and-takedown posture.
- **Scope confirmation (the biggest call).** **Recommendation:** APPROVE cutting marketplace, BIP155, multi-coin/CONTENT live features, and the three-codebase Tor soak to beta8; ship beta7 as names-only (daemon + Qt) verified by single-codebase gtests. This is the difference between a believable release and an indefinitely-slipping one.