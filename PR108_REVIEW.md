I have all the structured data needed to write the final review. Let me synthesize it into the report.

# PR #108 — Native P2P Bootstrap Sync — Final Review Report

## 1. Verdict

**MERGE-WITH-FIXES**

The two prior consensus blockers (SEC-1 null-commitment, SEC-2 difficulty-retarget) are genuinely fixed and wired on all three import paths, and the default anchor mode introduces no consensus-rule change: content trust binds to the compiled binary, never to a peer-supplied hash, and the gossip path is server-only and cannot be flipped into trusting a peer. No high-severity consensus, trust, memory-safety, or crash-safety defect was confirmed. One confirmed medium DoS-amplification issue (unbounded aggregate serve bandwidth) and one confirmed medium performance gap (single-peer, no fan-out) should be addressed before merge; the remaining items are low/info, several of them documentation honesty about the experimental trustless mode.

## 2. Scorecard

- **Low operator maintenance:** At-risk — the treadmill-free promise applies only to the *experimental, off-by-default* trustless mode; the shipped default still requires a per-release anchor bump (DEC-1).
- **No central trust:** Strong — default-mode ledger state is verified against a compiled UTXO commitment (highest checkpoint, hash-stapled), not the peer; forged/unreachable peer falls back to full validation; gossip path is server-only and cannot be remotely flipped (SEC-A4, SEC-A5). Residual is availability centralization on two project IPs, not trust (DEC-2).
- **New-user performance:** Adequate — fast time-to-provisionally-usable via a pipelined 16-deep chunk window, but single-peer sourcing caps throughput and creates a single-server dependency for the whole transfer (PERF-1); trustless mode costs roughly a second full verifying IBD to reach *trusted* (PERF-3).
- **Security:** Strong — no consensus change in default mode; DoS surface is carefully bounded (chunk-range validation, double-capped manifest, free-space precheck, per-IP /64-collapsed quota, slow-loris watchdog, consistent Misbehaving scoring). Residual is operator-side bandwidth amplification (DOS-A1), not crash/RCE/eclipse.
- **Code quality:** Strong — dedicated thread handle with interrupt+join before DB free, fail-closed state machines, lock-free atomic mirror to dodge lock inversion, genuine dedup, comprehensive tests (39 cases). Only minor latent items remain.

## 3. Blockers

The verification confirmed **no high-severity defect**. The two previously-identified consensus blockers are confirmed FIXED:

- **SEC-A1 (confirmed, info):** null anchor UTXO commitment refuses startup — `checkpoints.cpp:129-135`, invoked at `init.cpp:1074-1078`. Fixed and wired.
- **SEC-A2 (confirmed, info):** difficulty retarget re-enforced via `ContextualCheckBlockHeader` (`main.cpp:2825`) above the last checkpoint on all three import paths — trustless validator (`bootstrapvalidation.cpp:557-562`), v3 forward-connect (`main.cpp:3320-3336`), from-genesis serve build (`bootstrap.cpp:2070-2077`). Fixed and consistent.

There are **no remaining must-fix-before-merge blockers** and **no uncertain findings awaiting author confirmation** in the verified data. The two confirmed **medium** items below are strongly recommended pre-merge but are amplification/performance, not correctness:

**DOS-A1 — Serving has no inbound/whitelist gate and only a per-peer rate limit; aggregate upload scales with connection count** (confirmed, medium)
- Files: `src/main.cpp:6172,6234` (GETBSCHK/GETBSPCHK dispatch, gated only by `fBootstrapManifestSent`); `src/bootstrap.cpp:3859-3943` (per-address-group quota), `3955-4046` (per-peer burst serve).
- Why it matters: All accounting is keyed per address group (`BootstrapServeQuotaKey`, IPv4 full / IPv6 /64). There is no global byte-served counter and no max-concurrent-serving-peers cap. An IPv6 attacker presenting 100+ distinct /64s each gets an independent 100 GiB/day budget and burst, so the operator's upload + snapshot read-IO scale linearly with source-address count (capped only by `-maxconnections`). Undercuts the "DoS-resistant serving" / low-operator-cost goals.
- Fix: Add a global aggregate serve-bandwidth ceiling and/or a max-concurrent-serving-peers cap, preferring whitelisted/inbound peers when over budget, so worst-case upload is operator-tunable independent of attacker address count.

**PERF-1 — Single-peer download, no multi-peer fan-out** (confirmed, medium)
- Files: `src/bootstrap.cpp:2484` (BootstrapFromPeer: one socket, one peer), `909-1156` (DownloadBootstrapSnapshot strictly sequential over that socket), `init.cpp:1968-1977` (peers tried strictly sequentially).
- Why it matters: The entire snapshot is fetched from exactly one peer over one socket; aggregate throughput can never exceed a single server's rate, and time-to-usable is hostage to the chosen server. (Verification noted the loop is even more serial than originally claimed — no intra-socket pipelining deque exists.) Directly impacts CDN-competitiveness (goal 3) and no-single-point-of-failure-during-sync (goal 2). Each chunk is already addressed by (fileIndex, offset) and independently hash-verified, so disjoint-range striping is feasible.
- Fix: Stripe the chunk request space across several connected NODE_BOOTSTRAP peers (disjoint (file,offset) ranges; reassign on timeout/abort).

## 4. Non-blocking findings

**Security & Consensus**
- **SEC-A8 (confirmed, low):** Imported-tip finalization hold can persist indefinitely for an honest low-connectivity / inbound-only / partitioned node (`bootstrapvalidation.cpp:97-104, 247-301`; `main.cpp:3058-3120`). Safe direction (node stays a longest-chain follower; only auto-finalization pauses). Recommend recording a `tip_hold_since` timestamp (`g_finalizationHeldSince` already exists for the peer gate but isn't wired to the imported-tip hold) and documenting the `-finalizationminpeers` / `-finalizationrequirepeers=0` / re-bootstrap escape in `getblockchaininfo` help.

**P2P / DoS**
- **PERF-2 / DOS-related throttle (confirmed, info/low):** Per-IP serve throttle (~1 MiB/s) engages only after a 100 GiB/day cap; never trips a normal first sync. Shared-NAT / shared-/64 cohorts share one bucket and can collectively trip it (`bootstrap.cpp:3837-3909`). Intended DoS guard; document the shared-bucket behavior; ties to PERF-1 failover.

**Performance**
- **PERF-3 (confirmed, low):** Trustless background validation re-runs an IBD-grade ConnectBlock replay genesis..H (`bootstrapvalidation.cpp:386-641`), so time-to-*trusted* ≈ a second verifying IBD. Non-blocking (80ms cs_main batches, flush off-lock, interruption points) and script checks already parallelized. Inherent cost of genuine trustlessness; document the expectation; optionally round-robin CPU against concurrent IBD-to-tip.
- **PERF-4 (confirmed, low):** Throughput-floor watchdog (32 KiB/s over 60s) hard-aborts a slow-but-progressing link and `remove_all(staging)` discards all partial work — no resume (`bootstrap.cpp:136-151, 1084, 2535`). Recommend preserving staging + resuming remaining chunks from another peer (`.part` + per-file SHA-256 already make this safe), and/or an adaptive floor.
- **PERF-5 (confirmed, low):** Server re-opens/fstats/seeks/reads/closes the backing file per 1-MiB chunk (`bootstrap.cpp:3485-3531, 3533-3588`). Deliberate fd-robustness tradeoff (mtime/size recheck catches swaps; SHA cache reused off-lock). Consider a small open-FILE* LRU or mmap to improve many-downloader scaling.

**Decentralization / Operator burden**
- **DEC-1 (confirmed, low):** Treadmill-free / self-healing promise is delivered only by experimental trustless mode; default anchor mode retains the per-release anchor-bump obligation (`init.cpp:1946` default "anchor"; `bootstrap.h:173` `fTrustlessAllowed=false`). Documentation/positioning fix: state plainly the promise applies only to trustless mode; define graduation criteria (notably the planned `-bootstrapsafe` wallet-spend gate).
- **DEC-2 (confirmed, low):** Two hardcoded project IPs (`chainparams.cpp:235-236`: 74.50.74.102, 205.209.104.118) are the deterministic first dial on every bare startup; `DiscoverBootstrapPeers` runs only as fallback. Availability/observability centralization, not ledger trust. Consider shuffling the compiled list / interleaving one discovered NODE_BOOTSTRAP peer; document IPs as availability seeds, not trust roots.
- **DEC-3 (confirmed, low):** Post-bootstrap `-addnode` injection iterates the *entire* compiled peer list, not the single peer used, and is never removed for the process lifetime (`init.cpp:2011-2022` loop + TODO). Code/doc divergence (doc says singular "the bootstrap peer"). Restrict to the actually-used peer or reconcile the doc; implement the CConnman drop hook once IBD latches false.
- **DEC-4 (confirmed, low):** Trustless self-healing on a forged snapshot completes only across a restart (FAILED → reindex sentinel → shutdown → next-start reindex; `bootstrapvalidation.cpp` RequestReindexAndShutdown / ConsumeReindexRequest, `init.cpp` consume path). Self-healing only under a restart supervisor. Document the `Restart=always` requirement next to "no operator action" / "operator does nothing, ever" claims.

**Code Quality / Concurrency**
- **QUAL-3 (confirmed, low):** `InstallStagedBootstrapChainData` half-install (blocks/ present, chainstate/ absent) is not restart-idempotent if both the chainstate rename and the catch's `remove_all(blocks_dir)` throw (`bootstrap.cpp:826-865`); `IsBootstrapFreshChainDatadir` (`718-754`) then refuses re-bootstrap. Double-fault, narrow window. Add an install-complete marker checked on restart, or treat lone blocks/ with no chainstate/ as recoverable.
- **QUAL-4 (confirmed, low):** `BootstrapMetricsScreenActive()` (`bootstrap.cpp:53-59`) hand-duplicates init.cpp's metrics-screen predicate with no compile-time link; documented rationale (test link), but silent drift → progress flicker/wrong sink. Extract to a header-only inline helper or add a unit test pinning the two predicates.
- **QUAL-5 (confirmed, info):** `ClearBootstrapSnapshotCacheLocked()` (`bootstrap.cpp:2787-2793`) enforces its cs_bootstrap_snapshot contract by comment only; no present-day race. Add `AssertLockHeld(cs_bootstrap_snapshot);` to match the discipline in bootstrapvalidation.cpp.

## 5. Refuted / non-issues (verified and cleared)

- **SEC-A3** — Alleged fScratchView consensus-rule change does not exist; fScratchView gates only persistence/notification side effects, all consensus validations run unconditionally (`main.cpp:2505-2790`). Earlier "verifier swap" claim was a misread.
- **SEC-A9** — No dead/redundant code defect in `ValidateBootstrapSnapshotManifest`; the four version branches are mutually exclusive with materially different follow-on checks, not collapsible duplication (`bootstrap.cpp:3590-3691`).
- **DOS-B1** — getbsman/getbspman DO call `Misbehaving(20)` on trailing bytes (`main.cpp:6104,6192`); scoring is present and consistent. Only residual is cheap cold-cache polling (fAllowBuild=false), bounded log/CPU noise.
- **DOS-C1 / DOS-D1 / DOS-E1** — Confirmed *correct* defenses, not defects: slow-loris watchdog cannot be reset by trickling a byte; disk-fill closed by manifest caps + free-space precheck + strict per-chunk match + per-file SHA-256; per-IP quota correctly collapses IPv6 to /64 and hard-bounds the tracked map at 16384 with eviction.
- **DEC-5** — Refuted as written: cited file/lines and supporting doc were wrong, and the throttle/quota constants are currently *unreferenced* (dead defines) rather than enforced generous defaults; serving is genuinely opt-in (`-bootstrapserve` default false). Note byproduct: the throttle/quota are not actually enforced today.
- **QUAL-1** — No FILE* leak (always closed post-loop); dangling `.part` is deterministically reaped by caller `remove_all(staging)`. Self-containment style preference only.
- **QUAL-2** — Unsigned-add overflow in disk preflight is unreachable: `nSnapshotBytes` is never populated (JSON path never sets it; defaults to 0). Latent byproduct noted: the disk preflight only ever requires ~2 GiB regardless of real snapshot size — a separate latent issue, not an overflow.

## 6. Key risks & open questions for the maintainer

1. **DOS-A1 aggregate serve bandwidth (medium):** Confirm whether bounding worst-case upload to an attacker-controlled address-count is required for the "every node a server" vision, or whether `-maxconnections` capping is deemed sufficient. A global ceiling / concurrent-serving-peers cap is the recommended pre-merge fix.
2. **DEC-5 byproduct — throttle/quota are dead defines:** Verification found `BOOTSTRAP_SERVE_DEFAULT_THROTTLE_KBPS` / `MAX_BYTES_PER_DAY_PER_IP` referenced only at their own `#define`. Several DoS findings assume these are *enforced*. Confirm whether the per-IP quota/throttle is actually wired into the live serve path or is currently inert — this directly affects DOS-A1's real exposure.
3. **QUAL-2 byproduct — disk preflight may be inert:** `manifest.nSnapshotBytes` appears never populated, so the free-space precheck may only ever require the 2 GiB margin regardless of real snapshot size. Confirm the preflight actually reflects snapshot size before relying on it as a disk-fill guard.
4. **Trustless mode positioning (DEC-1, DEC-4, PERF-3):** Confirm the documentation honestly scopes "maintenance-free / no central trust / no operator action" to the experimental, off-by-default, `-prune`-refused trustless mode, and that the restart-supervisor requirement on the failure path is foregrounded. Define the graduation criteria (notably the `-bootstrapsafe` wallet-spend gate) before advertising the treadmill as gone.
5. **Default-mode anchor treadmill (DEC-1):** The shipped default still requires per-release anchor regeneration + checkpoint + lockstep adoption — the exact treadmill that already broke in production (snapshot 3126937 vs compiled anchor 2879438). Confirm this is an accepted operator obligation for the default mode.