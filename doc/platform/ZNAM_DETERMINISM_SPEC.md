# ZNAM — ZClassic Name Service: Protocol & Determinism Spec (v1)

**STATUS: authoritative for the beta7 build. These wire bytes are PERMANENT once mainnet ships.**
The indexer / RPC / wallet / GUI are coded against THIS document. Companion to
`doc/platform/DECENTRALIZED_PLATFORM_BLUEPRINT.md`. Coin is **ZClassic / ZCL** (never ZEC/Zcash) in
all user-facing strings.

This spec documents the **exact bytes produced and accepted by the ported parser** at
`src/znam/znam.{c,h}` (ported from `github.com/RhettCreighton/zclassic-c` `lib/znam`, Apache-2.0,
Rhett Creighton). The parser is the authoritative encoder/decoder; this document is its written
contract and the indexer's acceptance-rule reference. Where this spec and `znam.c` ever disagree,
**that is a bug to be reconciled, not a license to diverge** — they ship together.

> **Constants still pending owner sign-off** are the time/economics knobs in §12 marked **(SIGN-OFF)**
> — `REGISTRATION_DURATION`, `GRACE`, `MAX_REGISTRATION`, `RESERVE_BURN`. They are non-consensus
> indexer policy, freely tunable on regtest/testnet and right up to the mainnet ZNAM activation
> height; they do NOT change the wire bytes. Everything else (lokad, version, commands, types, field
> order, length caps) is frozen by the ported parser.

---

## 0. Invariants (why this document is shaped the way it is)

ZNAM is a **NON-consensus overlay**: an `OP_RETURN` record interpreted by a `CValidationInterface`
observer (the indexer), exactly like ZSLP/NFT. It NEVER touches consensus, PoW, block/tx validity,
mempool acceptance, or wallet spends. A forged/squatted name CAN be mined; "correct" means **it binds
nobody and resolves to nothing**.

Because there is no consensus to break a tie, **determinism IS security**:

- **I1 — Total function.** Every transaction maps to exactly one outcome (`apply` | `ignore`). There
  is no error path two implementations could resolve differently. Malformed → *ignored*, never
  *rejected-and-maybe-handled-elsewhere*.
- **I2 — No implementation-defined behavior.** No locale, no float, no platform endianness in the
  rules, no unicode. Names and text are ASCII-only (§2, §6).
- **I3 — No policy-dependent values.** The rules MUST NOT read any node policy knob that can differ
  between honest nodes (`-minrelaytxfee`, `-datacarriersize`, mempool state). Every threshold is a
  **frozen protocol constant** (§12). *Consequence: the optional reserve burn uses a fixed
  `RESERVE_BURN_ZATS`, NOT `GetDustThreshold(minRelayTxFee)`.*
- **I4 — Confirmed-chain authority only.** Ordering is by confirmed `(height, txindex)`. There is NO
  mempool / 0-conf authority for ownership or first-claim. (vout index never participates in ordering
  — the record is a single `vout[0]`.)
- **I5 — Bounded data only.** Every field is tightly length-capped (§12) and the whole record's
  `scriptPubKey` is `<= 223` bytes (`MAX_OP_RETURN_RELAY`); the wallet builder fails closed above it.
- **I6 — Permanent bytes.** The lokad id, version, command codes, target-type codes, field order, and
  length caps cannot change without a hard incompatibility. v2 is gated behind the version byte and is
  purely additive.
- **I7 — Decoded-value semantics (Postel).** Acceptance and all registry effects key on the
  *decoded* field values, never on raw push framing. Two transactions that decode to the same
  `(command, name, …)` are semantically identical and resolved by first-claim ordering (I4). This is
  why non-minimal push encodings and trailing bytes after the last field cannot fork the registry
  (§1.1) — every node decodes identical bytes to identical values.

---

## 1. Record layout (PERMANENT — matches `znam_parse`)

The ZNAM record is an `OP_RETURN` output whose `scriptPubKey` is:

```
OP_RETURN (0x6a)
PUSH "ZNAM"        4 bytes, lokad id = 0x5A 0x4E 0x41 0x4D  ("ZNAM")
PUSH <version>     1 byte, must == 0x01
PUSH <command>     1 byte, 0x01..0x06 (§3)
PUSH <name>        1..63 bytes, ASCII, validated (§2)
PUSH <...command-specific fields...>   (§3)
```

The indexer scans the transaction's outputs and interprets the **first** output whose `scriptPubKey`
`znam_parse()`-accepts as the transaction's ZNAM record (§5 — canonical-output rule). At most one
ZNAM record per transaction is honored.

### 1.1 Push encoding & framing (matches the ported `read_push`)

`read_push` (`src/zslp/op_return_push.h`, shared verbatim with `slp.c`) accepts direct pushes
(`0x01..0x4b`), `OP_PUSHDATA1` (`0x4c`), and `OP_PUSHDATA2` (`0x4d`). It is **liberal**: it does not
require minimal encoding, and `znam_parse` does not require the script to end after the last field.
Per **I7** this is safe — the decoded field values are identical regardless of push framing or
trailing bytes, so all nodes compute the identical registry effect. **The wallet builder always emits
the shortest (canonical minimal) push** (`push_data`), so honest traffic is canonical; the parser's
liberality only affects which adversarial re-encodings are *also* accepted as the same logical
message (and first-claim ordering then makes the later ones no-ops).

A record whose total `scriptPubKey` exceeds 223 bytes is still *parseable*, but the wallet refuses to
build it and standard relay will not propagate it; the indexer applies no special cap (it never needs
to — every individual field is capped in §12, and an over-cap record simply won't be relayed/mined in
practice). The indexer MUST NOT reject on total length (that would be a policy-dependent value, I3).

---

## 2. Name validation — REJECT, don't normalize (matches `znam_validate_name`)

A name is valid iff ALL hold:

1. length `1..63` bytes (`ZNAM_NAME_MAX = 63`);
2. every byte is `a`–`z` (0x61–0x7a), `0`–`9` (0x30–0x39), or `-` (0x2d);
3. first byte is not `-` and last byte is not `-`.

There is **no normalization** — no lowercasing, no NFC, no punycode, no homoglyph folding. A name with
any byte outside the allowlist (including any byte `>= 0x80`, any uppercase, `.`, `_`, space, or an
embedded NUL) is **invalid → the whole record is ignored** (I1). This kills the unicode/homoglyph fork
surface at the door; internationalized names, if ever wanted, are a v2 feature behind the version byte.

> Double-hyphen (`a--b`) is **allowed** (the reference does not forbid it). This is deliberate parity
> with the ported parser; punycode-style `xn--` prefixes carry no special meaning in v1.

---

## 3. Commands & command-specific fields (PERMANENT)

`command` byte, then the fields below. Field numbers continue from the shared header (name = field 3).

| code | command      | extra fields (in order)                                  |
|------|--------------|----------------------------------------------------------|
| 0x01 | `REGISTER`   | `target_type` (1 B, §3.1), `target_value` (1..128 B)     |
| 0x02 | `UPDATE`     | `target_type` (1 B), `target_value` (1..128 B)           |
| 0x03 | `TRANSFER`   | `new_owner` (1..63 B, address string, §4.3)              |
| 0x04 | `RENEW`      | *(none)*                                                 |
| 0x05 | `SET_RECORD` | `target_type` (1 B), `target_value` (1..128 B)           |
| 0x06 | `SET_TEXT`   | `text_key` (1..32 B), `text_value` (0..128 B)            |

A `command` byte outside `0x01..0x06` ⇒ record ignored.

### 3.1 Target types (PERMANENT)

| code | type      | resolvable in v1 | meaning                                   |
|------|-----------|------------------|-------------------------------------------|
| 0x01 | `ONION`   | yes              | v3 `.onion` hidden-service address        |
| 0x02 | `ZADDR`   | yes              | ZCL shielded z-address                    |
| 0x03 | `TADDR`   | yes              | ZCL transparent t-address                 |
| 0x04 | `BTC`     | yes (opaque)     | Bitcoin address                           |
| 0x05 | `LTC`     | yes (opaque)     | Litecoin address                          |
| 0x06 | `DOGE`    | yes (opaque)     | Dogecoin address                          |
| 0x07 | `CONTENT` | yes (opaque)     | content hash (e.g. file-market root hash) |

A `target_type` outside `0x01..0x07` ⇒ record ignored. `target_value` is stored and resolved **as
raw bytes**; the indexer does NOT validate that a `BTC`/`LTC`/`DOGE`/`CONTENT` value is a well-formed
address/hash (it has no canonical cross-chain validator — that would be implementation-defined, I2).
`ONION`/`ZADDR`/`TADDR` values SHOULD be syntactically checked by the **wallet at build time** for UX,
but the indexer stores whatever validly-framed bytes it sees (resolution consumers decide trust).

---

## 4. Ownership model — vin[0] P2PKH signer, first-in-first-served (PERMANENT)

ZNAM uses the reference design: ownership is the **address that authorized the transaction's first
input**, FIFS like ENS's `FIFSRegistrar`. There is no holding-UTXO.

### 4.1 Owner identity — total-function rule (hardening, I1)

The **owner address** of a ZNAM transaction is derived deterministically from `vin[0]`:

- Resolve `vin[0].prevout` against the chain's UTXO view to get its `scriptPubKey`.
- If that `scriptPubKey` is **exactly a standard P2PKH** (`OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY
  OP_CHECKSIG`), the owner address is its base58check P2PKH address.
- Otherwise (P2SH, multisig, non-standard, coinbase, or an unresolvable prevout) the transaction has
  **no ZNAM owner → the record is ignored** (P2PKH-or-drop).

This is a total function of the confirmed chain (the prevout is always resolvable during ConnectBlock).
It deliberately excludes multisig/P2SH owners in v1: a single canonical signer address is required so
ownership comparison is an exact string equality with no ambiguity.

### 4.2 Per-command authorization

| command      | precondition (else IGNORED)                                                              |
|--------------|------------------------------------------------------------------------------------------|
| `REGISTER`   | `name` is **free** (never registered, or expired past grace, §7). Claims it for owner.    |
| `UPDATE`     | `name` exists, not expired, and `owner == current owner`. Replaces the primary target.    |
| `SET_RECORD` | same as UPDATE. Sets/overwrites the record for that `target_type`.                         |
| `SET_TEXT`   | same as UPDATE. Sets/overwrites (or deletes, §6) the text record for `text_key`.           |
| `RENEW`      | `name` exists (active or within grace) and `owner == current owner`. Extends expiry (§7). |
| `TRANSFER`   | `name` exists, not expired, and `owner == current owner`. Sets owner = `new_owner` (§4.3).|

"Current owner" is the owner recorded by the most recent applied REGISTER/TRANSFER (by `(height,
txindex)`). A command failing its precondition is a **no-op that is still recorded in the undo log as
"no change"** so reorg accounting stays exact (§8).

### 4.3 TRANSFER target validation (hardening, I1)

`new_owner` is the 1..63-byte address string carried in the TRANSFER record. The indexer MUST decode
it as a **valid ZCL transparent P2PKH base58check address for the active network**. If it does not
decode to a P2PKH address, the **TRANSFER is ignored** (owner unchanged) — a name can never be
transferred into an unspendable/garbage owner that would silently burn it. (Intentional burns are a
v2 concern; v1 has no burn command.)

### 4.4 Why signer-address, and the privacy caveat (honest)

The reference chose signer-address FIFS for simplicity (no special holding coin to track or
accidentally spend). The cost: managing a name requires **reusing the same P2PKH owner address**
across REGISTER/UPDATE/TRANSFER/RENEW, which clusters every coin spent from that address to the
public human name. Mitigations (NOT consensus — client behavior):
- the wallet derives owner addresses on a **dedicated `names` derivation path**, isolated from the
  spending wallet, and the GUI states plainly that the owner address is publicly linked to the name;
- marketplace "listed by alice.zcl" binding is proven by a **signature** from the owner key, never by
  co-locating coins (§11) — so a listing does not deanonymize the seller's spending wallet.

---

## 5. Canonical-output & per-tx rules (determinism)

- The indexer interprets the **first** output (lowest vout index) whose `scriptPubKey`
  `znam_parse()`-accepts. Any later ZNAM-looking outputs in the same tx are ignored. (One record per
  tx; deterministic selection independent of how many OP_RETURNs exist.)
- The owner is `vin[0]` per §4.1 regardless of which vout carried the record.
- Coinbase transactions are skipped entirely (mirrors ZSLP: the indexer loops `vtx[1..]`).

---

## 6. SET_TEXT records — ASCII allowlist (hardening)

`text_key` (1..32 B) and `text_value` (0..128 B) carry arbitrary user data, the only free-form bytes
in ZNAM. To bound legal/redaction exposure and keep resolution unambiguous, the indexer applies a
**printable-ASCII allowlist** as an acceptance rule:

- `text_key`: every byte in `0x21..0x7e` (printable, no space/control). Else the SET_TEXT is ignored.
- `text_value`: every byte in `0x20..0x7e` (printable incl. space). Else the SET_TEXT is ignored.
- An empty `text_value` (length 0) is the **record deletion** for `text_key` (removes it). It is
  encoded as the canonical empty push `0x4c 0x00` (`OP_PUSHDATA1` length 0), never a bare `0x00`
  (`OP_0`), so it round-trips through `read_push` (which accepts `0x01..0x4b`/`0x4c`/`0x4d` only).

This is a *semantic* acceptance check layered above the byte-faithful parser (the C parser stores raw
bytes; the indexer drops non-conforming SET_TEXT). It also closes the embedded-NUL ambiguity (a value
with a `0x00` byte is non-printable → ignored), so `text_value` is always a clean C/utf-safe string.
`text_key` is case-sensitive and stored verbatim (no normalization, I2).

---

## 7. Expiry, grace, and RENEW (PERMANENT semantics, SIGN-OFF constants)

Names are **time-bounded** to make squatting reclaimable without any consensus rent:

- A REGISTER at height `h` sets `expiry = h + REGISTRATION_DURATION`.
- `name` is **active** for resolution while `currentHeight < expiry`.
- `[expiry, expiry + GRACE)` is the **grace window**: the name does not resolve and cannot be claimed
  by anyone else, but the **current owner** may RENEW it.
- At `currentHeight >= expiry + GRACE` the name is **free**: a REGISTER by anyone (including the old
  owner) starts a fresh registration, resetting owner + all records.
- `RENEW` sets `expiry = min( max(current_expiry, currentHeight) + REGISTRATION_DURATION,
  currentHeight + MAX_REGISTRATION )`. The `min` caps how far ownership can be pinned in one stroke
  (anti-indefinite-squat); the `max` lets a renew during grace re-anchor from "now".

Expiry is a pure function of height — every node agrees on active/grace/free at any height (I4). No
wall-clock, ever.

### 7.1 Optional reserve burn (anti-squat, SIGN-OFF amount)

If `RESERVE_BURN_ZATS > 0`, a REGISTER is only honored when the same transaction contains an output
sending `>= RESERVE_BURN_ZATS` to the **canonical burn sink** (a provably-unspendable
`OP_RETURN`-prefixed script `burn_marker`, fixed in §12) — raising the cost of mass squatting without
requiring any particular *input* (so it does not force coin clustering, unlike a "spend a dust input"
rule, which the red-team rejected). With `RESERVE_BURN_ZATS == 0` (v1 default) registration is free
(tx fee only). The amount is a non-consensus knob (tunable until mainnet activation); the *mechanism*
is specified now so the indexer ships with it wired and gated by the constant.

---

## 8. Reorg safety — LIFO undo (matches the ZSLP store pattern)

The store records a per-block undo log (ascending sequence) of every mutation a block applied:
owner set, record set/cleared, text set/cleared, expiry change, registration create. On
`DisconnectBlock` the ops are replayed in **reverse** (LIFO) to restore the exact prior state,
including no-op records (§4.2) so the tip marker and per-name history stay consistent across a reorg
that straddles a REGISTER/TRANSFER/expiry boundary. The store keeps a tip marker `(height, hash)` for
crash-resume and an index-version stamp for wipe-and-reindex on format bumps — identical discipline to
`CZSLPStore`.

---

## 9. Resolution semantics (read path)

`name_resolve(name)` returns, for an **active** name (not expired, not in grace):
- the **primary target** (`target_type`, `target_value`) from the latest REGISTER/UPDATE;
- additional address records keyed by `target_type` from SET_RECORD;
- text records keyed by `text_key` from SET_TEXT (printable-ASCII, §6).

A name that is unregistered, expired (past grace), or in grace resolves to **nothing** (NXDOMAIN-like)
— callers MUST NOT fall through to a stale target. The cohesion bridge "alice.zcl → onion" reads the
`ONION` record of the active name only.

---

## 10. Index storage schema (implementation, leveldb — mirrors `CZSLPStore`)

`blocks/znam/` `CDBWrapper`. Keys (`name` is the validated ≤63-byte ASCII string, used directly — no
namehash needed, it is already a bounded canonical key):

- `'n' + name` → `CZNAMName { ownerAddr, registeredHeight, expiryHeight, primaryType, primaryValue }`
- `'r' + name + type` → `value`  (SET_RECORD address records)
- `'x' + name + textKey` → `textValue`  (SET_TEXT records)
- `'h' + name + BE(height) + txid` → command history (audit / `name_history`)
- `'o' + ownerAddr + name` → (empty)  (reverse index for `name_listmine` / owner enumeration)
- `'u' + blockHash + BE(seq)` → `CZNAMUndoOp`  (reorg undo log, §8)
- `'T'` → `(height, blockHash)`  (tip marker)
- `'V'` → `uint32`  (index format version)

---

## 11. Marketplace binding — signature, not co-location (hardening; cohesion)

To display "listed by alice.zcl" on a marketplace offer without deanonymizing the seller:
- the offer carries a signature over `H("ZNAM-offer-v1" || name || offerId || expiry)` made with the
  **private key of the name's current owner P2PKH address**;
- a verifier resolves `name`'s owner address (§4) and checks the signature against it;
- this proves control of the name **without** anchoring the offer to any on-chain coin of the seller,
  so the listing leaks nothing about the seller's wallet (the red-team's deanon finding).

The signature scheme reuses the daemon's existing `signmessage`/`verifymessage` (Bitcoin
message-signing) over the owner P2PKH key.

---

## 12. PERMANENT CONSTANTS

Frozen by the ported parser (cannot change without a hard fork of the overlay):

| constant                | value                          | source                        |
|-------------------------|--------------------------------|-------------------------------|
| lokad id                | `"ZNAM"` = `0x5A4E414D`        | `ZNAM_LOKAD_BYTES`            |
| version                 | `0x01`                         | `znam_parse`                  |
| commands                | `0x01..0x06`                   | §3                            |
| target types            | `0x01..0x07`                   | §3.1                          |
| `ZNAM_NAME_MAX`         | `63`                           | `znam.h`                      |
| `ZNAM_VALUE_MAX`        | `128`                          | `znam.h`                      |
| `ZNAM_TEXT_KEY_MAX`     | `32`                           | `znam.h`                      |
| `ZNAM_TEXT_VAL_MAX`     | `128`                          | `znam.h`                      |
| `new_owner` max         | `63`                           | `znam_parse` (TRANSFER)       |
| canonical record output | first `znam_parse`-accepted vout | §5                          |
| `MAX_OP_RETURN_RELAY`   | `223` (wallet build cap)       | `script/standard.h`           |

Non-consensus indexer policy — **(SIGN-OFF)** before mainnet activation, free to tune on test nets:

| constant                  | proposed default              | rationale                                   |
|---------------------------|-------------------------------|---------------------------------------------|
| `REGISTRATION_DURATION`   | `210000` blocks (~1 yr @150s) | ENS-like annual term                        |
| `GRACE`                   | `52500` blocks (~91 days)     | ENS 90-day grace; owner-only re-claim       |
| `MAX_REGISTRATION`        | `2100000` blocks (~10 yr)     | renew cap, anti-indefinite-squat            |
| `RESERVE_BURN_ZATS`       | `0` (free in v1)              | mechanism wired; raise later if squatted    |
| `burn_marker`             | `OP_RETURN "ZNAM-BURN"`       | canonical unspendable sink (if burn > 0)    |
| ZNAM activation height    | TBD (mainnet)                 | indexer ignores ZNAM records below it       |

---

## 13. Conformance vectors (must be gtests before mainnet)

1. **Round-trip**: every command builds → parses → identical decoded fields (✅ `test_znam.cpp`).
2. **Reject**: bad lokad / version / command / target_type / invalid name / truncation (✅).
3. **FIFS**: REGISTER `alice`; a second REGISTER `alice` by a different signer is a no-op; owner
   unchanged.
4. **Auth**: UPDATE/TRANSFER/RENEW by a non-owner signer is a no-op.
5. **Transfer**: TRANSFER to a valid t-addr moves ownership; subsequent UPDATE by the new owner
   succeeds and by the old owner is a no-op; TRANSFER to a non-P2PKH string is a no-op.
6. **Expiry**: name resolves before `expiry`, NXDOMAIN in grace, re-REGISTER by a stranger succeeds
   only at `expiry + GRACE`.
7. **Reorg-across-transfer**: a block containing TRANSFER(alice→bob) disconnected restores owner=alice
   exactly (LIFO undo), and a competing branch that instead expires alice yields the branch-correct
   owner after reorg.
8. **SET_TEXT allowlist**: non-printable key/value ignored; empty value deletes; printable round-trips.
9. **P2PKH-or-drop**: a REGISTER whose `vin[0]` spends a P2SH output is a no-op.
```
