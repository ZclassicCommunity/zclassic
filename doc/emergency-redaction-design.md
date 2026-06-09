# Emergency Data-Redaction Capability — Design Note

**Status: CONCEPT / FUTURE — target v2.1.2-beta8.** Not built. Not in beta7 (beta7 is strictly
non-consensus). This is a *consensus-level* protocol capability and must get its own careful, fully
red-teamed design + review cycle before any implementation.

Coin is **ZClassic / ZCL**, never ZEC/Zcash.

---

## 1. Purpose

A **dormant, network-wide "break-glass" capability**: a mechanism, built into the protocol but **inactive
by default**, that would let the network — *if it ever needed to* — efficiently remove specific illegal data
that someone maliciously stored on-chain (e.g. in Sapling memos, OP_RETURN, or script fields), in a way that
every node, including nodes syncing in the future, honors.

This is the **last-resort backstop**, above the day-to-day, already-planned defenses:

- **Prevention** (relay/standardness hardening — tight OP_RETURN, `-permitbaremultisig=0`, fail-closed ZSLP
  grammar) — makes casual data-stuffing non-standard. *Non-consensus, ships in beta7.*
- **Operator non-hosting denylist** (refuse to relay / serve / surface flagged txids/hashes) — what real
  operators do; needs no fork. *Non-consensus, ships in beta7.*
- **Emergency redaction (this doc)** — the only thing that achieves true *network-wide* removal, and the only
  thing that requires a consensus change. *Future, beta8+.*

## 2. Why true removal must be a consensus change

Memo/script bytes are committed into the transaction id → the block merkle root → the PoW-signed header. A
single node cannot alter those bytes and still have the block validate or be accepted by peers (the recomputed
txid/merkle root won't match, so peers reject it). Therefore *network-wide* zeroing that new syncing nodes
also accept can only work if **all nodes agree on a rule that accepts the redacted form as valid** — i.e. a
consensus change. (A per-operator, local-only "zero my own disk" version was explicitly **rejected** as
confusing: it can't serve those blocks, can't reindex them, and doesn't remove the data anywhere else.)

## 3. The efficient mechanism (no re-mine, no reorg)

The chain's integrity does **not** depend on the redactable bytes themselves:

- The **merkle root is built from txids** (each leaf = hash of the full tx). A node needs only the 32-byte
  **txid** — not the full transaction bytes — to recompute the merkle root and verify PoW. So: **drop the
  flagged bytes, keep the txid**, and PoW + merkle roots stay byte-for-byte identical. No history rewrite.
- **Below a checkpoint**, nodes already skip re-verifying signatures/proofs. So a freshly-syncing node does
  not need the redacted bytes to accept buried history — it trusts the checkpoint. Every activated redaction
  is therefore **paired with a checkpoint** above the affected region.

**The consensus change is exactly:** define a *"redacted block / transaction" wire format* plus a rule that
every node **accepts it as valid**, verifying through the preserved txid (and the covering checkpoint).
Without that shared rule only PoW/merkle survive locally; with it, the redacted form is serveable and accepted
network-wide, including by future syncs.

## 4. Redactable surface (only non-validation-critical data)

May be redacted (not needed to maintain the UTXO / note-commitment set):

- **Sapling memos** (inside an output's `encCiphertext`; consensus needs the note commitment `cmu`, not the
  ciphertext) — the cleanest target.
- **OP_RETURN** outputs (provably unspendable; never in the UTXO set).
- `scriptPubKey` of already-**spent** transparent outputs, and `scriptSig` of buried transactions.

Must **never** be redacted: an **unspent** output's `scriptPubKey` (would break the ability to spend it), or
any amount/structure a node needs to maintain the UTXO set.

## 5. Dormant by default + activation / governance

- The redaction set is **empty** by default — nothing is ever removed unless an emergency arises.
- **Activation = a coordinated software release** that (a) ships the specific set of data hashes to redact and
  (b) places a checkpoint above the affected region. Nodes / miners / exchanges adopt it like any upgrade.
- **No standing "delete key."** The safeguard is the same social consensus as any hard fork — there is no
  permanent, centralized trapdoor anyone can pull quietly. (A standing on-chain authorization key/multisig was
  **rejected**: it would be a permanent censorship lever — the "redactable blockchain" anti-pattern.)

## 6. Honest tradeoffs (state these plainly)

- It **is** a consensus change — a hard fork to *introduce* the capability, even while it lies dormant.
- It deliberately places a small, **governed hole in immutability**. That is the entire point of "break
  glass," but it is a real philosophical cost and must be communicated honestly.
- Mild data-availability effect: a redacted block is served only in redacted form, so the original bytes
  become unfetchable network-wide once activated — which, for genuinely illegal content, is the intended
  outcome.

## 7. What a full beta8 design must still produce

This note captures the idea; a complete design (workflow + grounded review) must specify:

1. The exact **redacted-block / redacted-tx serialization** and how `ReadBlockFromDisk` / block relay /
   `ProcessGetData` handle it.
2. The **activation mechanism** (checkpoint coupling, the on-disk/compiled redaction set format, the
   activation height/version gate).
3. **Sync / IBD behavior** for a node that has the original bytes vs. one that only ever sees the redacted
   form; reindex behavior; bootstrap-snapshot interaction.
4. A **consensus-neutrality proof** (a redacting-capable node and the chain agree on the same valid history)
   and an **adversarial red-team** (censorship abuse, false-positive redaction, partition/IBD harm, governance
   capture).
5. **Tests**: gtest + multi-node regtest (activate a redaction → chain stays valid → redacted form syncs to a
   fresh node → tip identical to a non-redacting node).

## 8. Related

- Day-to-day defenses (prevention + non-hosting denylist) — see the content-defense layers in the beta7 plan;
  they need none of this.
- The arbitrary-file wallet path (`z_senddatafile` / ZDC1) was **removed** so the wallet offers no way to put
  files on-chain in the first place.
