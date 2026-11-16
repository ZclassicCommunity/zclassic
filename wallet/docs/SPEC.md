# ZClassic Wallet — North-Star Specification (SPEC.md)

## Vision

A single-file, privacy-first ZClassic wallet (Qt 5.15 static GUI embedding `zclassicd`) that is **fast, modern, secure, and "just works."** The everyday user opens it on a friendly Home dashboard, sees their **private (shielded) balance** as the headline number, receives to a shielded Sapling address with zero extra steps, and sends privately by default. Balances feel **instant** (cached paint on startup, sub-500 ms push-driven updates) without ever moving a viewing/spending key out of the daemon. Fresh installs never hang: bootstrap fast-sync, peer-of-last-resort pins, hash-verified peer-fetched params, and bounded self-heal keep first-run progress visible and recoverable. The single hard constraint that shapes the whole architecture: **viewing/incoming-viewing/spending keys never cross the `wallet.dat` process boundary** — which is why a separate C indexer was rejected and all acceleration lives inside `CWallet` (Plan A) with a key-free localhost notify trigger (Plan B).

This spec deduplicates five source dimensions (Performance, Privacy, Security/Key-boundary, UX, Reliability/Self-heal). Where dimensions overlapped, one canonical requirement is kept and the duplicates are cross-referenced inline.

---

## 1. Security & Key Boundary (the hard constraint)

- **KEY-1 — Keys never cross the wallet.dat process boundary (P0, partial)**: No spending key, full/incoming viewing key (Sapling/Sprout/transparent WIF/seed) is ever serialized into, returned by, or derivable from any RPC/IPC/notify channel the GUI fast-path consumes (`getwalletsummary`, `waitwalletchange`, the localhost notify socket, `listsinceblock` delta). Export RPCs (`dumpprivkey`, `z_exportkey`, `z_exportviewingkey`, `z_exportwallet`) stay gated behind explicit user action + RPC auth and are NEVER on a timer/notify/long-poll path. This is the north-star constraint; decryption stays in-process (`wallet.cpp` GetFilteredNotes) and only aggregates egress. *(Canonical for PERF-7, PRIV-20, NOTIFY-4.)*
- **KEY-2 — Rejected separate-indexer stays rejected (P0, done)**: Build MUST NOT (re)introduce a standalone indexer/process/socket that receives ivk/FVK/spending-key material. A CI denylist grep fails the build if a key-bearing egress RPC/IPC reappears. *(Canonical for PERF-15. Rationale: the C indexer needs ivk across the boundary = permanent de-anon surface AND zero speedup since decrypt is already a compiled native loop.)*
- **CONF-1 — rpcpassword is CSPRNG with ≥128 bits (P0, todo)**: `createZClassicConf` MUST generate `rpcpassword` from `QRandomGenerator::system()` (≥128 bits). The current `randomPassword()` (connection.cpp:209) uses `rand()%len` over 10 chars (~59.5 bits, time-seeded, predictable) and MUST be replaced. (Verified: still `rand()`.)
- **CONF-2 — conf + notify-token file are 0600 owner-only (P0, todo)**: `zclassic.conf` (holds rpcpassword + notify token) and any `QLocalServer` socket MUST be created 0600 atomically, never world/group-readable for any instant. `createZClassicConf` currently never calls `setPermissions`. (Verified: no perms call.)
- **CONF-3 — secrets never logged (P0, todo)**: No GUI log, qDebug, status message, crash dump, or captured daemon stderr may contain rpcpassword, the Basic-auth header, full conf contents, or the notify token. Audit existing `notify:` / `Authentication failed` lines.
- **CONF-4 — daemon RPC stays loopback-bound (P1, done)**: GUI-created conf and launch args MUST NOT contain `rpcallowip`/`rpcbind`; daemon default 127.0.0.1/::1 bind preserved. (Verified: conf has no addnode/rpcallowip/rpcbind.)
- **AUTH-1 — new RPCs use the standard authenticated path (P1, partial)**: `getwalletsummary`/`waitwalletchange` MUST be normal authenticated RPCs (TimingResistantEqual + 250 ms wrong-password penalty), never on an unauthenticated endpoint or the notify socket.
- **AUTH-2 — waitwalletchange cannot exhaust RPC workers (P2, todo)**: Concurrent long-polls bounded so they cannot starve `getinfo`/`getwalletsummary`; server-side timeout enforced regardless of client behavior (slow-loris reaped).
- **ATREST-1 — encrypted-wallet at-rest semantics preserved (P0, partial)**: `getwalletsummary`/`waitwalletchange` MUST work on an encrypted-but-locked wallet WITHOUT the passphrase and WITHOUT decrypting spending keys (aggregates from already-decrypted note-value cache). The cache MUST NOT be flushed as plaintext to a disk sidecar.
- **ATREST-2 — note-value cache invalidates correctly (P0, todo)**: The in-CWallet running-aggregate cache (Plan A) MUST recompute on every balance-affecting change (new note, spend, reorg, conflict, rescan); a miss/inconsistency MUST fail safe by recomputing, never return a stale aggregate that hides a spend.

## 2. Privacy by Default

### Receive (private at rest)
- **PRIV-1 / UX-9 — Shielded-by-default receive resting state (P0, done)**: Receive comes to rest showing ONLY a shielded Sapling z-address: green "Private" badge visible, "Other address types (advanced)" disclosure collapsed, t-Addr/Sprout radios hidden, shown address passes `isSaplingAddress()`. No PUBLIC caption at rest. *(Canonical; UX-9 is the same requirement.)*
- **PRIV-2 — Collapsing advanced always returns to private (P0, done)**: `setReceiveAdvancedExpanded(false)` re-selects Sapling, restores the badge, clears the PUBLIC warning.
- **PRIV-3 / UX-10 — No new Sprout address can ever be minted (P0, done)**: New-Address button disabled under the Sprout radio; no UI path calls `newZaddr(false)`/`z_getnewaddress sprout`. *(Canonical; UX-10 identical.)*
- **PRIV-4 — Legacy Sprout view hidden unless funds held (P1, done)**: Sprout radio visible only when `walletHasLegacySprout()`; falls back to Sapling if Sprout funds vanish while selected.
- **PRIV-5 — Transparent receive flagged PUBLIC (P0, done)**: Selecting t-Addr shows a warning containing "PUBLIC" stating the balance is permanently visible.
- **PRIV-6 — Fresh t-Addr on every transparent receive (P1, done)**: Each t-Addr selection mints a new address (no reuse across consecutive selections).
- **PRIV-7 — Receive 'previously used' signalling (P2, done)**: Used address → "Address has been previously used" tooltip; unused → "Address is unused".

### Send (private by default)
- **PRIV-8 — Send From defaults to a shielded source (P0, done)**: `setDefaultPayFrom()` selects the largest-balance z-address; falls back to a t-address only when zero spendable z-balance exists.
- **PRIV-9 — getAutoShield default is ON (P0, todo)**: `getAutoShield()` MUST default TRUE when `options/autoshield` is unset, asserted by a canary test. **Currently returns `false`** (settings.cpp:252, verified) — this is the privacy-by-default flip. *(See gap: scope of "auto-shield".)*
- **PRIV-10 — Auto-shield fail-open: change always shielded (P0, todo)**: With auto-shield ON and transparent change, `createTxFromSendPage()` routes change to Sapling; if NO Sapling address exists it MUST auto-create one (`newZaddr(true)`), never silently leave transparent change. **Current code returns false instead of creating one** (sendtab.cpp:515, verified). *(See gap: synchronous newZaddr latency / first-run provisioning.)*
- **PRIV-11 / UX-12 — Four-way from-aware send classification (P0, partial)**: `confirmTx()` MUST classify into z→z (private/green, no warning), t→z (shielding/neutral), z→t (DE-SHIELD/red, strongest warning naming public + sender-linkage), t→t (public/amber), exposed via a test-readable category accessor — not merely the binary `isPublicTx`. **Today only `isPublicTx` exists** (sendtab.cpp:581, verified). *(Canonical for UX-12.)*
- **PRIV-12 — De-shield (z→t) requires explicit acknowledgement (P1, todo)**: A z→t send MUST require a non-default-accept acknowledgement before `executeTransaction`; t→t/t→z/z→z MUST NOT add this friction.
- **PRIV-27 — Sprout send never gets a privacy-degrading change route (P2, partial)**: For a Sprout recipient, Sapling-change is suppressed (gate at sendtab.cpp:495) AND the wallet MUST surface the constraint rather than silently leave transparent change.
- **PRIV-26 — Composite: defaults yield a fully-private z→z tx with zero extra steps (P0, partial)**: With auto-shield ON + z-balance, recipient+amount only → From shielded, every output (incl. change) shielded, category PRIVATE, no de-shield prompt. *(Composite of PRIV-8/9/10/11/12.)*

### Badges, guidance, framing
- **PRIV-13 / UX-11 — Privacy-badge classification correct, never mislabels (P0, todo-test)**: `classify()` maps Sapling→Private, Sprout→PrivateLegacy, other-z→Private, t→Public, "(Shielded)"→Private, empty→None; `classifyForIndex()` returns Deshield only for a Public recipient on a row whose Type contains send/sent. No t→Private, no z→Public ever. *Logic exists (privacybadgedelegate.cpp, verified) but has NO unit test — status reflects the missing test.* *(Canonical for UX-11.)*
- **PRIV-14 — Badge color tokens match qss (P1, todo)**: `colorFor()` → green `#1f7a1f` (Private/Legacy), amber `#d9822b` (Public), red `#c0392b` (Deshield); `labelFor()` → Private/Private (legacy)/PUBLIC/De-shield; guard test greps `dark.qss` for the same hex tokens.
- **PRIV-22 — Activity de-shield rows flagged red (P1, done)**: A send to a transparent recipient renders the red "De-shield" badge; shielded receive green; public receive amber; delegate reads the sibling Type cell.
- **PRIV-21 / UX-6 — Private balance is the visual lead (P2/P0, done)**: Home hero presents shielded balance as the dominant green figure, Total as a smaller dimmed "Total" line; hero mirrors `balSheilded`/`balTotal` so they can never disagree. *(Canonical merges PRIV-21 + UX-6.)*
- **PRIV-17 / UX-8 — Amber 'Shield public funds' card iff transparent>0 (P1/P0, done)**: Card visible (naming the exact PUBLIC amount) when transparent > 1e-7 ZCL; hidden at zero/dust; never for an all-shielded wallet. *(Canonical merges PRIV-17 + UX-8.)*
- **PRIV-18 — Shield action actually shields, not just navigates (P1, partial)**: The guidance MUST produce a t→(default Sapling z) shielding tx. Context-menu "Shield balance to Sapling" path is done; the Home fix-it button only `setCurrentIndex(1)` (verified) — partial.
- **PRIV-19 — Default Sapling resolution prefers a real shielded address (P1, partial)**: `getDefaultSaplingAddress()` returns the first `isSaplingAddress()` or empty; callers MUST auto-create on empty rather than degrade to Sprout/transparent.

### Memo, history, nags
- **PRIV-15 — Memo reply-to one-time consent (P1, done)**: First "Insert From" shows a consent dialog (default No) explaining it reveals the sender's z-address; persists `memo/replyToWarned`; never nags after acceptance; programmatic path inserts only the user's own z-address.
- **PRIV-16 — Memo offered only for shielded recipients (P2, done)**: Memo button enabled only for z-recipients; disabled with tooltip for t-recipients; `memoButtonClicked` rejects non-z.
- **PRIV-23 — History opt-out doesn't weaken privacy or instant balance (P2, done)**: `getSaveZtxs=false` MUST NOT change address-type defaults nor disable cached-balance paint; written history files are 0600.
- **PRIV-24 / UX-14 — Backup nag is one-shot, dismissible, silent after backup (P2/P0, done/partial)**: `promptWalletBackup()` shows at most until `options/walletbackedup`; then returns with NO modal; never re-nags on refresh. UX-14 extends: first-run text states "no seed phrase," offers Back Up Now / Export Private Keys / Maybe later, sets the flag only on confirmed save (F1/F4 extensions are partial).
- **PRIV-25 — E2E fresh-empty receive lands private (P1, partial)**: L2 bundle run resting Receive shows a z-address + "Private", no "PUBLIC". Blocked on a deterministic mocked `z_getnewaddress` (see gap).

## 3. Performance & Instant Update

### Instant first paint (shipped)
- **PERF-1 / UX-21 — Cached-balance instant paint on startup (P0, done)**: Before any RPC, Home hero + balance labels paint last-known balances from QSettings (when `getShowCachedBalance` ON) with a "Last known balance … (refreshing…)" tooltip; live RPC overwrites instantly. App opens on Home (index 0), overriding the .ui default. *(UX-21 is the same requirement.)*
- **PERF-2 — Cached paint is correct-by-disclosure (P1, done)**: Stale tooltip present until first live refresh; suppressed when `getShowCachedBalance` OFF; cache lives only in QSettings, never in wallet.dat.
- **PERF-10 — No model rebuild/repaint on unchanged poll (P0, done)**: SHA1 content fingerprint (folding in confirmations) early-outs with zero dataChanged/layoutChanged on identical data; a pending→confirmed transition still repaints.
- **PERF-11 — Batch RPC completion is counter-driven, zero dead-poll (P1, done)**: `doBatchRPC` fires its callback exactly once via a completion counter (every terminal path counts); no 100 ms completion poll; N=0 fires once.
- **PERF-19 — Adaptive poll cadence while syncing (P2, done)**: Fallback poll 5 s while syncing, 20 s synced; interval changed only when it differs (no needless restart).
- **PERF-20 — Refresh skipped on unchanged height unless forced (P1, done)**: Heavy fan-out only when block height changed OR `force==true` (rpc.cpp:697).

### Push architecture — Plan B (GUI-only, ships first; all todo)
- **PERF-3 / UX-20 — Warm update latency via push (P0, todo)**: A wallet-relevant on-chain event → repainted balance within **500 ms p95** (200 ms debounce + one RPC round trip) measured notify-fire → repaint, independent of the 20 s/5 s QTimer. *(Canonical merges PERF-3 + UX-20.)*
- **PERF-4 — Debounced single refresh per notify burst (P0, todo)**: N notifies within the 200 ms window coalesce to exactly ONE refresh; timer re-started per notify, fires once on quiescence. *(See KEY-boundary security analogue NOTIFY-5/sec under §1-adjacent.)*
- **PERF-5 — GUI stops fixed-interval polling once push healthy (P0, todo)**: 20 s/5 s balance QTimer stopped or extended to ≥120 s keepalive heartbeat when push healthy; active polling auto-resumes if the notify channel is detected dead.
- **NOTIFY-SRV — Localhost-only, token-gated notify listener (P0, todo)**: GUI writes `-walletnotify`/`-blocknotify` into the GUI-owned conf pointing at a `QTcpServer`/`QLocalServer` bound to 127.0.0.1/::1 (or 0600 unix socket) ONLY, with a per-session ≥128-bit CSPRNG path token (NOT `rand()`/`qrand()`). Wrong/absent token dropped before any refresh; constant-time + length-checked compare (TimingResistantEqual-equivalent); non-loopback connections refused before token check; payload validated `^[0-9a-f]{64}$` before use (no shell/file/RPC injection); reads bounded (≤4 KiB) and idle-reaped; server torn down + token invalidated at session end, fresh token on relaunch; a successful notify grants NO data (the refresh is an authenticated RPC; socket peer gets only "OK"). *(Canonical merges PERF-6, NOTIFY-1/2/3/4/5/6/7 (security), NOTIFY-1 (reliability), INJ-1.)*
- **PERF-8 — listsinceblock<cursor> delta replaces full fan-out (P1, todo)**: On a wallet event the GUI fetches only the delta via `listsinceblock(cursor)`, persisting and advancing a block-hash cursor; not the full `listtransactions` + per-zaddr fan-out. (Verified: GUI never calls listsinceblock.)
- **PERF-9 / DELTA-1 — Reorg-safe cursor resync (depth==-1 returns ALL) (P0/P1, todo)**: When the cursor block is off-chain, the daemon returns ALL txns (rpcwallet.cpp:1690); the GUI detects this and rebuilds from the full set (no dup/double-count), re-anchors the cursor, and never permanently skips a reorged tx. *(Canonical merges PERF-9 + DELTA-1 + NOTIFY-3/reliability.)*
- **PERF-21 — Eliminate per-zaddr fan-out for balances (P1, todo)**: Balance display MUST NOT issue one `z_listreceivedbyaddress` per z-addr; replaced by a single summary call (B minimal / A `getwalletsummary`). Per-zaddr detail confined to Activity.
- **PERF-24 / NOTIFY-2(rel) — Notify-channel failure falls back safely (P0, todo)**: If notify never fires/dies/absent (external daemon, e.g. systemd peer #1), the GUI still converges via the fallback heartbeat within one `updateSpeed` interval and never hangs on a long-poll/notify that will never arrive. For a foreign node no notify wiring is attempted; the heartbeat alone runs (no double-refresh on owned nodes). *(Canonical merges PERF-24 + NOTIFY-2 reliability.)*

### Plan A — daemon in-CWallet index (ships after B; all todo)
- **PERF-12 / EGR-1 — O(1) getwalletsummary (P1, todo)**: Daemon exposes `getwalletsummary` returning transparent/shielded(sapling)/sprout/total confirmed+unconfirmed in O(1)/O(changed-notes) from a maintained note-value index (CAmount cached at first decrypt), NOT a re-walk of mapWallet. Fixed closed schema `{shielded_total, transparent_total, unconfirmed, immature, note_count, address_count, cursor_height, cursor_hash, content_fingerprint}`; NO per-note plaintext/memo/nullifier/rseed/diversifier. (Verified: no such RPC.) *(Canonical merges PERF-12 + EGR-1.)*
- **PERF-13 — No full re-decrypt on unchanged poll (P1, todo)**: Repeated summary queries with no change perform ZERO decryptions; each note decrypted at most once.
- **PERF-14 / EGR-2 — waitwalletchange long-poll, single round-trip (P1, todo)**: Daemon blocks (bounded timeout) until the aggregate fingerprint changes, returning ONLY `{changed, fingerprint, cursor_height, cursor_hash}` — no contents; cancellable on shutdown without holding cs_wallet. GUI blocks then issues ONE `getwalletsummary`. *(Canonical merges PERF-14 + EGR-2.)*
- **EGR-3 — Aggregate fingerprint is non-invertible (P2, todo)**: Fixed-width hash or monotonic change-counter (counter preferred — no correlation oracle); MUST NOT encode per-note values/addresses/memos.

### Perf budgets & guardrails (mostly todo — no harness yet)
- **PERF-16 — No UI jank / main-thread stall during sync (P1, partial)**: No synchronous RPC on the GUI thread; no model update >16 ms p95 / 50 ms p100 for ≤10k txns; large-delta rebuild must stay within frame budget (currently unmeasured).
- **PERF-17 — Startup-to-first-paint <1500 ms (P1, partial)**: First usable painted window <1500 ms independent of daemon, with `downloadParams()` having zero live callers (verified: dead code, no startup caller).
- **PERF-18 — Send-to-feedback <300 ms optimistic pending (P1, partial)**: Acknowledgment/pending row within 300 ms of accept, before the next poll tick; txTimer escalates to 1 s while pending.
- **PERF-22 — Cold vs warm latency measured (P1, todo)**: Harness reports COLD (first balance, one-time prime, p95 <3 s) and WARM (post-event, p95 <500 ms B / <300 ms A) distinctly.
- **PERF-23 — Keyscan/decrypt throughput floor (P2, todo)**: Document notes/sec floor; assert no >10% regression vs baseline; each note decrypted exactly once per scan (no quadratic re-decrypt).
- **PERF-25 — Idle CPU/wakeups (P2, todo)**: Synced+idle with push healthy → ~zero balance/tx RPCs, only ≥120 s heartbeat + 1 hr price refresh; no per-second timer when nothing pending.

## 4. Modern UX & Ease of Use

- **UX-1 — Single source-of-truth type scale (P0, done)**: Base ≥13pt, secondary balances ≥14pt, `balTotal` ≥19pt, `homeHeroPrivate` ≥28pt; scale lives only in `dark.qss` + `main.cpp` base font.
- **UX-2 — Bundled Ubuntu font on every platform (P1, done)**: Load `Ubuntu-R.ttf` via QFontDatabase on all 3 platforms; fall back to sans-serif at the same sizes on load failure.
- **UX-3 — Modern dark theme app-wide (Fusion + central QSS) (P0, done)**: `setStyle('Fusion')` + dark palette + `dark.qss` so every surface is dark; no native light-palette leakage (Xvfb luminance <0.25).
- **UX-4 — Left nav rail is primary IA; tab bar hidden (P0, done)**: Rail = Home/Send/Receive/Activity + demoted Advanced gear (id 1000); QTabWidget tab strip hidden; exactly one rail item highlighted, synced to code-driven page changes.
- **UX-5 — Advanced gear graceful when node-stats absent (P1, done)**: Resolves the zclassicd page index dynamically; safe no-op when absent; switches + checks when present.
- **UX-7 — Home quick actions: prominent Send + Receive (P0, done)**: Send (primary green) → index 1, Receive (secondary) → index 2; hit height ≥40px; pointing-hand cursor.
- **UX-13 — First-run onboarding card, once (P0, partial)**: First launch only shows a friendly 3-step card (security files → starting → catching up) + honest time expectation; persists `ez/onboardingShown`; never shows again. (L2 first-run lane partial.)
- **UX-15 — Sync status self-explains (P0, done)**: Distinct green "Synced — Ready", amber indeterminate "Starting your node…" (with live height), determinate %+ETA while syncing; never-frozen text; % rounded + clamped 0..100.
- **UX-16 — Startup/connection errors self-explain with an action (P0, done)**: Plain-language actionable errors for no-connect/no-start/low-disk/already-running + always-reachable "Repair / Re-download blockchain…" in Help; dead param pre-download off the boot path.
- **UX-17 — Hit-targets ≥40px (P1, partial)**: Primary controls effective ≥40px (target 44px); rail buttons fill the 168px width. (Polish pass partial.)
- **UX-18 — WCAG AA contrast for the token set (P0, todo)**: `#e6e6e6`/`#15171c` ≥4.5, `#e6e6e6`/`#1d2027` ≥4.5, dim `#9aa0a6` ≥3.0 (large/non-essential only), white/`#1f7a1f` ≥4.5, pills ≥3.0 — pure-logic contrast helper asserts each pair.
- **UX-19 — Dangerous/advanced actions demoted + confirmed (P1, partial)**: Import/Export keys, node-stats, turnstile, debug, repair NOT on rail/Home; reachable via Advanced gear / menus; destructive actions (repair, key export, deshield) require explicit confirm.
- **UX-22 — Friendly empty/zero states (P2, todo)**: Zero balance → hero "0.00" with private framing + "Receive to get started"; empty Activity → "No transactions yet"; no blank void.
- **UX-23 — Modals never trap the user (P1, done)**: Every modal has a safe exit; connect splash is app-modal but uses deferred `done()`+`deleteLater` (no UAF/deadlock on quit); at most one modal on the connect path.
- **UX-24 — Address copy + QR, never silent truncation (P2, partial)**: One-click copy of the exact active address; QR tracks the selected address; address + hero are `TextSelectableByMouse`.
- **UX-25 — Visual-regression / layout-integrity L2 guard (P2, partial)**: Booted-bundle Xvfb run asserts rail (~168px) present, dark background, hero present, captures home/balances/receive screenshots for golden diff.

## 5. Reliability, Self-Heal & Cross-Platform

### Single-file packaging & daemon resolution
- **XPLAT-1 — Embedded daemon extraction verified/atomic/never-hangs (P0, done)**: Footer `[bytes][sha256:32][len:8 LE][magic ZQWDMON1:8]`; verify SHA-256, atomic rename, exec bit, content-addressed cache; reject corrupt/zero/>512 MiB length within <2 s and fall back to a sibling.
- **XPLAT-2 — Sibling-first then runtime-extract, clear error on total failure (P0, done)**: Try sibling (`zqw-zclassicd`→`zclassicd`), then extract on Linux/Win; explicit error (not a silent spinner) if none found.
- **XPLAT-3 — macOS never runtime-extracts; signed sibling in .app (P0, partial)**: `ensureDaemonExtracted` returns "" under Q_OS_DARWIN; exec the signed sibling; `.app` passes Gatekeeper/hardened runtime. (No automated test; dmg stale — see gap re notarization.)
- **XPLAT-4 — glibc-2.31 floor on Linux (P1, done)**: Both binaries' max GLIBC symbol ≤2.31; proot 20.04 builder is source of truth.

### Never-stuck startup
- **STUCK-1 — getbootstrapinfo answers during warmup (P0, done)**: Warmup-exempt, read-only, structured status (phase/percent/bytes/mbps/streams/peers/attempt/mode/verify_pending/validation_state/tip_hold); all other RPCs still RPC_IN_WARMUP.
- **STUCK-2 — Throughput watchdog aborts a stalled peer (P0, done)**: Abort if <32 KiB/s averaged over a full 60 s window; allow ramp-up; reset window on a healthy window.
- **STUCK-3 — Per-peer retry+backoff, graceful fallback to normal P2P (P0, done)**: 3 attempts × 3 s per peer, iterate full list, transition to `normal_sync` (recording reason) on total failure unless `-bootstrappeer` pinned; each retry emits a warmup InitMessage.
- **STUCK-4 — Abandoned-stub recovery gated by the 64 MiB cap (P0, done)**: Stub only when chainstate ≤64 MiB AND blocks ≤128 MiB AND best block non-null≠genesis; decision ignores the (possibly foreign-fork) block index; real/corrupt/genesis-only datadirs left untouched.
- **STUCK-5 — Stub recovery churn-guarded (≤3/6h), fail-closed (P0, done)**: Bounded by a durable sibling marker; anchor-height change resets the counter; attempt stamped before any backup; skip if the marker can't be durably written.
- **STUCK-6 — Genesis/stub re-bootstrap backs up (never deletes) + restores on failure (P0, done)**: Existing blocks/chainstate MOVED to a timestamped backup; restored on failure; retained on success with the marker cleared.
- **STUCK-7 — Bootstrap peers pinned as -addnode every start (P1, partial)**: Compiled peers injected into the P2P addnode list (unless `-connect`); ThreadDNSAddressSeed relaxed so pins aren't self-suppressed.
- **STUCK-8 — Healthy seed infrastructure (P0, partial)**: Non-empty `vFixedSeeds`; DNS seeds + the two bootstrap peers reachable on the P2P port; fresh-install soak reaches connections>0 within 60 s in ≥95% of trials. *(Operational, not code — see gap re seed commitment + canonical P2P port.)*
- **STUCK-9 — Foreign stuck node surfaces an actionable dialog once (P1, done)**: For a not-owned daemon peerless/not-syncing ≥36 polls (~3 min), `showForeignNodeStuck` fires exactly once; never kills/mutates the foreign node; owned/has-peers/syncing nodes never trigger it.
- **STUCK-10 — Active download not mistaken for an abandoned stub (P0, done)**: When `phase==active`, show real progress and SKIP stub-heal/wipe; an in-flight multi-GB snapshot is never wiped.

### Params & fast-sync integrity
- **PARAM-1 — Params peer-fetched over P2P, hash-verified, never z.cash (P0, done)**: Missing/invalid params fetched from a bootstrap peer, each verified against its compiled SHA-256 before install; mismatches rejected; GUI never pre-downloads; `downloadParams` stays dead (verified: no live caller).
- **PARAM-2 — Single source of truth for param hashes (P0, done)**: `InitSanityCheck` validates against the SAME `GetZcashParamSpecs` table as fetch; a still-missing/invalid param yields a clear InitError naming the dir + remedy.
- **FASTSYNC-1 — Anchor-mode snapshot verified vs compiled anchor (P0, done)**: Manifest validated against compiled anchor (height+hash+UTXO commitment); gossip path always `fTrustlessAllowed=false`; non-matching tip rejected; null-commitment anchor fails startup.
- **FASTSYNC-2 — Trustless self-snapshot provisional, background-revalidated, reindex on mismatch (P1, done)**: Imported snapshot starts PROVISIONAL; background thread re-derives UTXO from genesis and compares; latches VALIDATED durably on match, FAILED→reindex on mismatch; GUI shows "Verifying — don't spend yet".
- **FASTSYNC-3 — Above-checkpoint tip holds finalization until corroborated (P1, done)**: `ArmBootstrapTipHold` pauses auto-finalization (durable, re-armed) until the live network corroborates; pure-anchor tip==checkpoint arms no hold; releases on corroboration or reorg.
- **FASTSYNC-4 — Untrusted manifest can't exhaust disk (P1, done)**: Reject >200 GiB total / >32 GiB per file / wrong chunk size; require free space ≥ total + 1 GiB.
- **FASTSYNC-5 — Durable verify-pending markers gate the forgery check across a crash (P1, done)**: Marker fsync'd BEFORE chainstate install; `verify_pending` derives from on-disk markers, not an in-memory bool.
- **FASTSYNC-6 — Parallel-stream download correct, degrades to single (P1, done)**: `-bootstrapstreams` (default 4, max 16, 1=legacy); N-stream reassembly byte-identical + per-file SHA-256; works against a server advertising a smaller chunk size.
- **FASTSYNC-7 — Serve-side per-IP quota, aggregate caps, rate floor (P2, done)**: Per-IP daily quota (100 GiB) with throttle/stop; aggregate Kbit/s + concurrent caps; per-IP keyed (v4/v6 separate); warn below the single-chunk floor; whitelisted bypass.
- **FASTSYNC-8 — Auto-serve only for the current compiled anchor (P2, done)**: `-bootstrapserve=auto` serves only a copy matching the compiled anchor; stale copies removed; clear reason if never bootstrapped.

### Shutdown, crash, fresh-install
- **SHUTDOWN-1 — Graceful stop with a 30 s hard cap, never wedges Quit (P0, done)**: Graceful RPC stop (ignore RPC_IN_WARMUP / refused without a tx-error box), poll exit at 150 ms, wait dialog only >700 ms, hard-cap 30 s; external daemon never waited on.
- **SHUTDOWN-2 — Clean restart no dirty reindex; unclean kill recovers safely (P1, partial)**: Clean stop → no dirty-reindex; unclean kill → WAL replay or bounded reindex-chainstate, no data loss; the strict "best block not in index" path surfaced as clear status; `-reindex`/`-reindex-chainstate` mutually exclusive; one-shot flags stripped on crash-restart. *(See gap: harden clean-shutdown flush vs surface-as-status for beta5.)*
- **SHUTDOWN-3 — Background validation thread joined before DB free (P1, done)**: `InterruptBootstrapValidation` runs in `Shutdown()` before pblocktree/pcoinsTip freed, on normal + init-failure paths; no-op if never started (ASan-clean).
- **CRASH-1 — Runtime crash auto-restart capped at 3, strips one-shot flags (P0, done)**: Relaunch same process ≤3×; cap resets on a successful getinfo; strip `-reindex*`; tray-resident → silent restart + tray notice, no unseen modal.
- **CRASH-2 — Warmup-corruption failsafe (P1, done)**: A node dying during warmup is detected (process exited, never came online) → repair/redownload dialog, not an eternal spinner.
- **FRESH-1 — Clear monotonic first-sync progress, never stuck 0 (P0, done)**: Param fetch → bootstrap download (real %/bytes/mbps) → chain sync (headers-aware %, 96% invariant); syncing + 0 peers → "waiting for the network" after a ~15 s (3-poll) debounce.
- **FRESH-2 — Conf creation failure surfaced (P1, done)**: Unwritable conf → explicit permissions/disk error (verified), not a silent spinner; conf has server=1 + random rpcpassword + no addnode (with `-tor` → proxy line).
- **FRESH-3 — Disk-space preflight before large writes (P1, partial)**: Extraction needs len+16 MiB; snapshot needs manifest total + 1 GiB; refuse with a clear message, no junk half-writes. (Some paths checked, not all.)
- **SELFTEST-1 — Self-heal scenarios run headless in L0/L1/L2 + daemon-gtest (P1, partial)**: Every never-stuck/self-heal case has a named automated regression in the fast parallel runner; P0/P1 traceability has no gaps. (Daemon side green; GUI push cases not yet built.)

---

## Build Sequence

**Phase 0 — Privacy default flip + send classification (GUI-only, no daemon rebuild).** Lowest-risk, highest user-visible privacy win and unblocks the composite tests.
1. PRIV-9 flip `getAutoShield` default → ON (canary test first).
2. PRIV-10 fail-open auto-create Sapling change (+ PRIV-19 caller hardening).
3. PRIV-11/UX-12 four-way from-aware classification accessor; PRIV-12 z→t acknowledgement; PRIV-27 Sprout-change surface.
4. PRIV-13/14 badge unit tests (logic already shipped); UX-18 contrast helper.
5. PRIV-18 wire the Home fix-it button to the real shield flow; UX-22 empty states; UX-19 confirms.

**Phase 1 — Plan B push (GUI-only).** Ships the instant-feel without touching the daemon.
1. CONF-1/2/3 harden secrets (CSPRNG rpcpassword + token, 0600, no-log) — prerequisite for the listener.
2. NOTIFY-SRV localhost-only token-gated listener + conf `-walletnotify`/`-blocknotify` (PERF-6, INJ-1, all NOTIFY security/reliability reqs).
3. PERF-4 debouncer (200 ms named constant); PERF-3/UX-20 push refresh; PERF-5 stop the fixed poll; PERF-24 fallback heartbeat (foreign nodes).
4. PERF-8/9 `listsinceblock<cursor>` delta + reorg resync; PERF-21 drop per-zaddr balance fan-out.
5. Build the perf-harness; close PERF-16/17/18/22/25 measurements; SELFTEST-1 GUI lanes.

**Phase 2 — Plan A daemon index (rebuild + re-embed + soak).** Supersedes B's chatty path where available.
1. PERF-12/EGR-1 in-CWallet note-value index + `getwalletsummary` (ATREST-1/2 invariants).
2. PERF-13 no-re-decrypt; PERF-14/EGR-2 `waitwalletchange`; EGR-3 non-invertible fingerprint.
3. AUTH-1/2 auth + worker-pool bounds; KEY-1/PRIV-20 re-verified as explicit daemon-gtests the moment A lands.
4. GUI capability-negotiates: probe for `getwalletsummary`; fall back to the Phase-1 B path on older daemons.
5. PERF-23 keyscan throughput floor; finalize PERF-22 A targets.

**Cross-cutting / ongoing.** STUCK-7/8 seed health + addnode pins; XPLAT-3 macOS notarization; SHUTDOWN-2 clean-flush decision; PRIV-25 E2E mocked `z_getnewaddress`.

## Out of Scope / Rejected

- **Separate standalone fast-C indexer — REJECTED (KEY-2, PERF-15).** It would require an incoming-viewing key to cross the `wallet.dat` process boundary (a permanent de-anonymization exfil surface) AND yields ZERO speedup, because note decryption is already a compiled native loop inside the daemon. All acceleration MUST live inside `CWallet` (Plan A). A CI denylist grep fails the build if any key-bearing egress RPC/IPC reappears.
- **Light theme / per-user font scale** — not in scope; the single bundled 13pt dark scale is the intended final state unless an accessibility decision reopens it.
- **z.cash param pre-download** — dead code, must never return to the boot path.
