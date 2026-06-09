# Security hardening — June 2026

This document records the security work integrated via the merge of
`feature/parkdeepreorg-ibd-gate` into `master`. It covers one fix, one
reviewed behaviour change, one hardening commit, and the status of the
remaining items from the June-2026 upstream-parity audit.

Scope of the merge (commits, newest first):

| Commit | Summary |
|--------|---------|
| `28382a7cd` | Fix use-after-free in `ConnectBlock` check-queue lifetime (CVE-2024-52911 parity) |
| `dcbdf14e5` | Deep-reorg parking: skip during IBD/reindex (fixes from-genesis reindex stall) |
| `fb585fd29` | docs: TVSP proposal (v2) Markdown source |
| `b2da5f69f` | docs: Transparent-Value Shielded Pool (TVSP) proposal (v2) |
| `bbea3177e` | Harden ZIP-209 pool accounting: checked `CAmount` delta arithmetic |

---

## 1. ConnectBlock use-after-free — FIXED (`28382a7cd`)

**Class:** memory-safety use-after-free. Bitcoin **CVE-2024-52911** /
Zcash **GHSA-fqr9-fxpx-rfpf** parity.

### Root cause
In `ConnectBlock` (`src/main.cpp`):

- Queued script checks (`CScriptCheck`) hold a **raw**
  `PrecomputedTransactionData*` into a local `txdata` vector
  (`CScriptCheck::txdata`, `src/main.h`).
- `~CCheckQueueControl()` calls `Wait()` on **every** return — including
  early returns — and `Wait()` drains any still-queued checks **on the
  calling thread** (the "master" in `CCheckQueue::Loop`).
- `control` was declared **before** `txdata`. C++ destroys locals in reverse
  declaration order, so on an early return `txdata` was destroyed **first**,
  then `~control`'s `Wait()` ran the queued checks that dereferenced the
  freed `txdata` → **heap-use-after-free**.

### Reachability and impact
Reachable in normal operation: `-par>=2` (default) and a block above the last
checkpoint (i.e. live blocks near tip). An attacker mines a valid-PoW block
crafted to fail **late** — e.g. coinbase overpay (`main.cpp:~2758`) or bad
Sapling root (`main.cpp:~2745`) — after script checks are queued but before the
explicit `control.Wait()`. The control destructor then drains those checks
against freed memory. **Impact: remote DoS (node crash).** RCE is theoretically
in the UAF class but not demonstrated.

### Fix
Declare `txdata` (and its `reserve()`) **before** `control`, so reverse-order
destruction always runs `~control`'s `Wait()` before `txdata` is destroyed, on
every return path. One-line move; `reserve()` still precedes the first
`emplace_back`, preserving pointer stability. See the inline comment at the
declaration site in `ConnectBlock`.

### Verification
- **gtest** (`src/gtest/test_validation.cpp`):
  `Validation.CheckQueueControlDrainsQueuedCheckBeforeTxdataDestroyed`.
  Deterministic (no worker threads → the queued check runs inside `~control`'s
  `Wait()` on the calling thread). `EXPECT_TRUE(ran)` guards the
  drain-before-destroy contract without needing a sanitizer; under
  AddressSanitizer the buggy declaration order reports `heap-use-after-free`.
  Compiles and passes.
- **AddressSanitizer proof** (standalone reproducer, throwaway, using the real
  `CCheckQueue`/`CCheckQueueControl`): buggy declaration order →
  `heap-use-after-free` in `~CCheckQueueControl → Wait → Loop → check()`;
  fixed order → clean exit. Both observed.
  Note: `--enable-asan` is unusable under Apple clang (`-static-libasan`
  unsupported); the proof used `clang -fsanitize=address` directly.

---

## 2. Deep-reorg parking IBD gate — REVIEWED, SAFE (`dcbdf14e5`)

### What it changes
Gates the deep-reorg park in `AcceptBlock` behind `!IsInitialBlockDownload()`:

```cpp
if (GetBoolArg("-parkdeepreorg", true) && !IsInitialBlockDownload()) { ... }
```

### Why
During `-reindex`, blocks are loaded from `blk*.dat` out of height order, so
`chainActive.FindFork(pindex)` sees spurious deep forks (`fork depth > 1`) and
parks large swaths of the chain — the stall that forced `-parkdeepreorg=0` on a
from-genesis reindex (observed at height ~478543/478544).

### Review conclusion: safe
The "Deep Reorg Protection" feature (`d57bf7a5e`) has **three** layers; this
commit relaxes only the softest, and the two harder layers remain active during
the skip window:

| Layer | Behaviour | During the IBD skip window |
|-------|-----------|----------------------------|
| Parking (this commit) | Preemptively parks deep-fork blocks; unparks at 2× work | **Skipped during IBD** |
| Auto-finalization, depth `-maxreorgdepth` (default 10) | Finalizes a block 10 deep; conflicting forks rejected (`bad-fork-prior-finalized`, `main.cpp:3089`) | **Still active** (`main.cpp:~3253`) |
| `MAX_REORG_LENGTH = COINBASE_MATURITY-1 = 99` | Node shuts down on any reorg > 99 blocks (`main.cpp:3667`) | **Always active** |

Key safety property: `IsInitialBlockDownload()` **latches to false permanently**
after first catch-up. So after a node first reaches tip, parking is **always
on** again and cannot be forced off by an attacker staling the tip
(eclipse/partition). At-tip behaviour is therefore unchanged — the 51%/deep-reorg
defense is intact at tip. Parking is skipped only during `fReindex`/`fImporting`
or a node's genuine first sync.

### Residual nuance (informational, not a blocker)
The latch resets on process restart. A node restarted after being offline
> `nMaxTipAge` (~24h) re-enters `IBD=true` until it catches the backlog, so
parking is skipped during that catch-up. Finalization (depth 10) and the 99-block
cap still apply, and a visibly-catching-up node should not be trusted for
confirmations. Exposure is bounded and acceptable.

---

## 3. ZIP-209 checked arithmetic — included (`bbea3177e`)

Overflow-safe `CAmount` delta arithmetic for the shielded-pool value tracking
(`CheckedAdd`/`CheckedAddTo`). Hardening of pool accounting; no behavioural
change for in-range values.

---

## Audit items still OPEN (not in this merge)

From the June-2026 upstream-parity audit. Priority order:

1. **#2 — checkpoint hash not enforced at header acceptance (High).**
   `GetLastCheckpoint` only finds checkpoints already in `mapBlockIndex`;
   `ContextualCheckBlockHeader` (`main.cpp:4434`) rejects only forks **below**
   the last checkpoint height, never a header **at** checkpoint height with the
   wrong hash. Upstream's `CheckIndexAgainstCheckpoint` is absent. Fix first —
   #3's "checkpoint validates correctness" rationale depends on it.

2. **#3 — reindex size band-aids loosen live consensus (High).**
   `GENEROUS_BLOCK_SIZE_LIMIT = 2MB` (`main.cpp:4364`) vs `MAX_BLOCK_SIZE =
   200000` (`consensus.h:22`); `GENEROUS_TX_SIZE_LIMIT = 2MB` non-contextual
   (`main.cpp:1230`) with the tight `MAX_TX_SIZE_AFTER_SAPLING = 102000` enforced
   only **pre-Sapling** (`main.cpp:1039`) → post-Sapling tx size effectively
   unbounded to 2MB for live blocks. These are local patches, not an intentional
   hardfork. **Load-bearing for reindex** (confirmed: real canonical tx at height
   478544 is 125,811 B; another 122,415 B at 478596 — both exceed 102000). Fix:
   keep the non-contextual bounds generous (so historical reindex passes) and add
   the tight limits in `ContextualCheckTransaction`/`ContextualCheckBlock` gated
   on a future activation height (coordinated soft fork).

3. **#4 — header-DoS hardening gap (Medium, unproven).** No modern
   `nMinimumChainWork`/headers-presync staging. Has `MAX_HEADERS_RESULTS=160` +
   checkpoint fork-rejection. Hardening gap, not a demonstrated exploit.

4. **#5 — timestamp adjustment (Low).** Raw `nTime - GetTime()` (`main.cpp:6208`).
   Self-limiting (200-sample freeze; protective per the in-code issue-#4521
   note). Signed-overflow hardening only.

### Confirmed sound (no action)
Value conservation / no-inflation path: coinbase overpay rejected
(`main.cpp:~2758`), input/value conservation (`main.cpp:~2088`), ZIP-209
negative-pool checks (`main.cpp:~2589`), Sapling/JoinSplit verification
(`main.cpp:~951`). Duplicate-input protection (`1336`), CVE-2012-2459 merkle
malleability (`4340`), Overwinter non-overwintered-tx rejection (`1023`). No
NU5/Orchard code in this fork. Structural block checks **do** run at
`AcceptBlock` (`CheckBlock` default `fCheckSizeLimits=true`, `main.cpp:4587`) —
only the redundant `ConnectBlock` re-check skips them below checkpoint.
