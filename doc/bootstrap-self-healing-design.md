# Design: Self-healing, low-maintenance P2P bootstrap (option B)

Status: **implemented, EXPERIMENTAL (off by default).** Tracks the evolution of
native P2P bootstrap (see [bootstrap-snapshots.md](bootstrap-snapshots.md)) from a
hand-maintained, single-anchor model toward one that needs no ongoing operator
work and repairs itself.

## Implementation status (this branch)

Phase B is implemented behind off-by-default flags; the compiled-anchor swarm is
unchanged when they are not set:

- **Server self-snapshot:** `-bootstrapserve=auto` freezes the node's own live
  chainstate at its current tip on an interval (`-bootstrapservefreezeinterval`,
  default 6h) and serves it as a **version-2 manifest** carrying the snapshot's
  real height/hash and a UTXO-set commitment. v1 (compiled-anchor) manifests are
  byte-for-byte unchanged. (`FreezeLiveChainstateForServe`, `GetBootstrapSnapshotManifest`.)
- **Client trustless accept:** `-bootstrapmode=trustless` accepts a v2 self-snapshot
  via a cheap provisional gate (chainstate digest == advertised commitment, tip on
  a PoW/checkpoint-consistent header chain), then hands off to background validation.
  (`ProvisionalAcceptTrustlessSnapshot`.)
- **Background validation + auto-reindex:** a thread re-derives the UTXO set from
  genesis to the snapshot height into a private scratch chainstate and compares
  `hash_serialized` to the value captured at import. Match → durable `validated`
  latch; mismatch → discard chainstate and reindex from local blocks (the existing,
  tested reindex path). The background replay connects into a private scratch
  chainstate only (`ConnectBlock(..., fScratchView=true)` suppresses live txindex
  writes, block-index mutation, and wallet signals). State is persisted in the
  block-tree DB and resumes after a restart. Trustless mode is refused together
  with `-prune` (a pruned node cannot re-derive, so it could never validate); an
  already-pruned node that somehow holds a provisional snapshot stays
  `provisional` rather than auto-reindexing. (`src/bootstrapvalidation.{h,cpp}`.)
- **Status:** `getblockchaininfo` reports a `bootstrap_validation` object
  (`disabled`/`provisional`/`provisional_pruned`/`validated`/`failed` + progress).

Verified on a two-node regtest swarm: a self-snapshotting server, a trustless
client that fast-syncs and latches `validated`, and a forced-failure run that
discards and reindexes back to the correct chain. The compiled-anchor path and its
manifest wire format remain unchanged (regression-tested).

## 1. Why

The shipped model is trustless but **maintenance-bound**:

- A single fast-sync anchor (height + block hash + SHA-256/SHA3 digests +
  UTXO-set commitment) is **compiled into the binary**. Trust comes from that
  compiled constant.
- Because it is compiled, keeping fast-sync useful is a treadmill: regenerate a
  snapshot at a new height → recompute the commitment/digests → add a checkpoint
  → ship a new binary → everyone rebuilds. The served snapshot and the compiled
  anchor must stay in lockstep or clients download gigabytes and then reject the
  result (this exact failure happened in production: snapshot at 3126937 vs
  compiled anchor 2879438).
- Serving is effectively centralized: a server must expose an immutable snapshot
  *at the compiled anchor height*, so in practice one operator runs it.

The correctness floor is already self-healing: any failure (server down, hacked,
stale, corrupt) degrades to a full validated sync from genesis — nobody is ever
stuck or defrauded. What is *not* self-healing is keeping the **fast** path fast
and available without a human in the loop.

### Goals

1. **No release treadmill** — adding/serving snapshots must not require compiling
   new constants or coordinating client rebuilds.
2. **Self-healing** — bad snapshots are detected and discarded automatically;
   missing servers just slow things down; the serving set reseeds as nodes join
   and leave.
3. **Truly P2P** — any node can serve to any other; no special, operator-run
   node is required.
4. No consensus change. (A header-committed UTXO set — "option C" — is the
   eventual gold standard but is a soft-fork and out of scope here.)

### Non-goals

- Changing block/transaction consensus rules.
- Eliminating the *temporary* trust window described in §4 (that is the price of
  avoiding both a compiled constant and a consensus change).

## 2. Core idea

Replace "trust a value compiled into the binary" with "trust nothing permanently;
verify in the background." Two mechanics:

1. **Self-snapshotting servers.** Any node can periodically freeze a consistent
   copy of its own chainstate at a recent height and serve *that*. No global
   pinned height; each server advertises whatever height it froze.
2. **Background full validation on the client.** A bootstrapping node accepts a
   downloaded snapshot *provisionally* (only that its tip is a real, PoW-valid,
   checkpoint-consistent block), starts operating immediately, and then
   re-derives the UTXO set from genesis in a background thread. If the
   background result disagrees with the imported chainstate, the snapshot is
   discarded and the node falls back to a normal sync. If it agrees, the node
   "latches" fully validated.

This removes the compiled anchor entirely. Trust no longer comes from the binary;
it comes from work the node does itself, exactly as a from-genesis sync would —
just deferred so the node is usable sooner.

## 3. Server side: self-snapshotting

A node opts in with `-bootstrapserve=auto`.

- **Consistency.** A live LevelDB chainstate is mutating; it cannot be served
  directly. The node freezes a copy at a quiescent point: `FlushStateToDisk`,
  record the current tip (height + hash), then clone `blocks/` + `chainstate/`
  into a serve directory. Cloning uses a copy-on-write reflink where the
  filesystem supports it (APFS/Btrfs/ZFS — near-free) and a plain recursive copy
  otherwise (disk cost ≈ chain size; opt-in covers that choice).
- **Cadence.** Re-freeze on an interval (e.g. every N blocks / T hours) so served
  snapshots track the tip. Old freeze is replaced atomically. A node that does
  not want the disk cost simply does not enable `auto`.
- **Advertisement.** While a valid frozen snapshot exists, advertise
  `NODE_BOOTSTRAP` and serve it via the existing manifest/chunk protocol. The
  manifest carries the frozen snapshot's own height + block hash (not a compiled
  anchor).

This is a strict generalization of the current serve path, which is hardcoded to
serve one immutable dir at the compiled anchor height.

## 4. Client side: provisional accept + background validation

1. **Discover & fetch.** Use the existing `NODE_BOOTSTRAP` discovery to find
   servers, pick one (or several), download its snapshot at whatever height it
   advertises, verifying per-file hashes from the manifest (transport integrity).
2. **Provisional acceptance gate (cheap, no compiled per-height secret).** As
   implemented (`ProvisionalAcceptTrustlessSnapshot`), the gate is deliberately
   weak — it is only a pre-filter to reject an obviously-bogus import before the
   node spends time on it, **not** a proof of honesty:
   - *integrity*: the imported chainstate's `hashSerialized` equals the manifest's
     advertised commitment, and the active tip matches the advertised height/hash;
   - *checkpoints*: the imported chain agrees with every compiled checkpoint at a
     height `> 0` and `<=` the tip;
   - *proof of work*: the tip header satisfies its own target.

   Note the integrity check is **circular** against a malicious server (it
   authored both the UTXO set and the commitment), and the PoW check covers only
   the single tip header, not cumulative chain work. So a forged-but-self-
   consistent UTXO set whose tip is above the highest compiled checkpoint *passes
   the gate*. That is by design: the gate is not the security boundary — step 3
   is. (Full per-block PoW/Equihash is re-checked there for every block.)
3. **Background full validation.** A low-priority thread re-derives the UTXO set
   from genesis using the block data, and compares the result to the imported
   chainstate (a final `hashSerialized` equality via the existing
   `CCoinsViewDB::GetStats`). On success: latch validated (durable). On mismatch:
   log loudly, discard the imported chainstate, and reindex from block data (which
   the node already has) — i.e. fall back to a real sync with no operator
   involvement. **This re-derivation is the entire trust basis of trustless mode**;
   if it cannot run (a pruned node — see below), the snapshot is never verified.
4. **Trust-window policy.** Between provisional accept and the validated latch the
   node is using an unverified UTXO set, for as long as a full genesis→H
   re-derivation takes (≈ a full sync). As implemented:
   - the window is surfaced loudly: a startup `InitWarning` explicitly states that
     balances are unverified and funds should not be spent until validated, and
     `getblockchaininfo.bootstrap_validation` reports the live state/progress;
   - **pruned nodes are refused** at init (`-bootstrapmode=trustless` + `-prune` is
     an error), because a pruned node can never run the re-derivation and would
     therefore trust the snapshot forever with no backstop.
   - *Not yet implemented (planned):* `-bootstrapsafe=1`, which would defer wallet
     spends of coins that exist only in the unvalidated deep chainstate until the
     latch, removing the economic risk of the window for cautious operators. Until
     it exists, the window's economic risk is mitigated only by the warning above
     — which is why trustless mode is EXPERIMENTAL and off by default.

This is the assumeutxo model, minus the compiled snapshot hash — trust is the
background validation itself, so there is nothing to maintain per release.

## 5. Self-healing properties

| Failure | Automatic recovery |
|---|---|
| Server offline | Client discovers other `NODE_BOOTSTRAP` peers; if none, full sync from genesis. |
| Server hacked / serves forged UTXO set | Provisional accept lets it start, background validation detects the divergence, discards, and reindexes. No forged coins survive. |
| Corrupt chunk in transit | Per-file SHA-256 mismatch → re-request / different peer. |
| Snapshot stale (behind tip) | Irrelevant — client just does slightly more IBD after import; nothing to bump. |
| Whole serving set disappears | Network falls back to from-genesis sync; reseeds automatically as nodes re-enable `auto`. |
| Operator does nothing, ever | System keeps working; no anchor to regenerate, no release to ship. |

## 6. Security analysis

- **Forged chainstate** is caught by background validation; the only exposure is
  the trust window (§4.4), bounded by validation time. The window will be
  removable per-node with `-bootstrapsafe` once that is implemented (deferring
  wallet spends of deep unvalidated coins); until then it is mitigated only by a
  loud warning, so an operator who transacts during the window can in principle be
  defrauded — this is the main reason trustless mode is EXPERIMENTAL/off by
  default. After the latch it is as strong as a full sync (stronger than "trust
  the binary's compiled hash," which is never independently checked).
- **Eclipse.** Snapshot peers are still just peers; normal IBD/header validation
  from other connections applies. Do not pin a snapshot peer as a permanent
  `addnode` after bootstrap (close the existing TODO).
- **DoS / sybil serving.** Reuse the shipped per-IP quota, throttle, burst-serve
  backpressure, and `Misbehaving` bans. A flood of fake `NODE_BOOTSTRAP`
  advertisers wastes a client's discovery dials but cannot feed bad data (§4).
- **Resource use.** Background validation eventually costs ~one full validation;
  it is spread over time at low priority, and is the same work a from-genesis
  node does. Net: later, cheaper-feeling, same total.

## 7. Migration / phasing

- **Phase A (now, implemented separately):** `-bootstrapserve=auto` — a node that
  has the snapshot at the *current compiled anchor* retains an immutable copy and
  serves it, advertising `NODE_BOOTSTRAP`. Combined with discovery this removes
  the single-server availability SPOF immediately, while still using the
  compiled-anchor trust model. Stepping stone; no new trust assumptions.
- **Phase B (this doc):** add background validation and let servers self-snapshot
  at arbitrary recent heights; relax the client from "manifest must equal the
  compiled anchor" to "provisional accept + background validate." The compiled
  anchor degrades to an *optional* fast-path/checkpoint hint, not a requirement;
  manual anchor bumps stop being necessary.
- **Phase C (future, optional):** commit the UTXO set in block headers
  (soft-fork) so the provisional-accept gate becomes fully trustless with no
  background validation needed. Out of scope; noted as the end state.

## 8. Open questions

- Self-snapshot cadence and disk policy defaults (interval; reflink detection;
  refuse-if-low-disk threshold).
- Background validation scheduling: continuous low-priority vs. opportunistic;
  interaction with pruning (a pruned node cannot re-derive from genesis — such
  nodes keep using the provisional state and rely on PoW headers + peers, or
  decline `auto`).
- Whether to keep a compiled checkpoint at a recent height purely as the
  provisional-accept anchor (cheap, occasional, far less frequent than today's
  snapshot/commitment regen).
- Exact `-bootstrapsafe` wallet semantics (which coins are "deep unvalidated").

## 9. Summary

Phase A makes serving a swarm and kills the single-server SPOF with no new trust.
Phase B removes the compiled-anchor maintenance treadmill by trusting background
validation instead of a shipped constant — self-healing, low-maintenance, and
genuinely peer-to-peer without a consensus change. Phase C (header commitments)
is the eventual zero-trust-window end state if the project chooses to soft-fork.
