# ZClassic Wallet — Acceptance Test Matrix (TEST_MATRIX.md)

One row per unique (deduplicated) requirement. This is the checklist that gates handing the wallet to the user. Cross-referenced source IDs are noted in the Requirement cell.

| ID | Requirement | Acceptance test | Layer | Priority | Status |
|----|-------------|-----------------|-------|----------|--------|
| KEY-1 | Keys never cross the wallet.dat boundary (≡PERF-7, PRIV-20, NOTIFY-4) | Grep summary/waitwalletchange schema = aggregates only; byte-scan response for known ivk/ask/nsk/ovk/seed = NOT FOUND; static-assert no export RPC on timer/notify/long-poll path | daemon-gtest | P0 | partial |
| KEY-2 | Rejected separate-indexer stays rejected (≡PERF-15) | CI denylist grep: a stub `getivk` RPC turns the guard RED; match-count == export-RPCs baseline | L0 | P0 | done |
| CONF-1 | rpcpassword CSPRNG ≥128 bits | Assert QRandomGenerator::system(); 100k passwords zero-dup + chi-square; not reproducible from time() | L0 | P0 | todo |
| CONF-2 | conf + notify-token file 0600 owner-only | stat conf == 0600, owner==uid, no 0644 window; second-user read == EACCES | L0 | P0 | todo |
| CONF-3 | secrets never logged | Drive connect+refresh+notify with sentinel password/token; grep log+stderr+crash artifact = NOT FOUND | L0 | P0 | todo |
| CONF-4 | daemon RPC stays loopback-bound | Parse conf+launchArgs: no rpcallowip/rpcbind; ss shows RPC bound only 127.0.0.1/::1 | L0 | P1 | done |
| AUTH-1 | New RPCs use standard authenticated path | getwalletsummary no-auth→401; wrong pass→401 after ~250ms; in dispatch table with auth wrapper | daemon-gtest | P1 | partial |
| AUTH-2 | waitwalletchange can't exhaust workers | (pool+4) long-polls + concurrent getinfo returns <2s; server reaps a never-read poll at timeout | daemon-gtest | P2 | todo |
| ATREST-1 | Encrypted-locked summary works without unlock | Lock wallet, call getwalletsummary: correct aggregates, unlock-counter==0, ask bytes absent from heap; no plaintext aggregate sidecar | daemon-gtest | P0 | partial |
| ATREST-2 | Note-value cache invalidates correctly | 1000 random receive/spend/reorg seqs: summary == fresh GetFilteredNotes sum each time (zero divergence) | daemon-gtest | P0 | todo |
| PRIV-1 | Shielded-by-default receive resting state (≡UX-9) | Switch to Receive: badge shown, advanced collapsed (RightArrow, panel hidden), rdioTAddr hidden, address passes isSaplingAddress | L1 | P0 | done |
| PRIV-2 | Collapsing advanced returns to private | After t-Addr select, setReceiveAdvancedExpanded(false): rdioZSAddr checked, badge shown, lblSproutWarning hidden | L1 | P0 | done |
| PRIV-3 | No new Sprout address can ever be minted (≡UX-10) | rdioZAddr selected → btnRecieveNewAddr disabled; grep: no newZaddr(false)/{"sprout"} from any handler | L1 | P0 | done |
| PRIV-4 | Sprout view hidden unless funds held | Only-Sapling fixture → rdioZAddr hidden; one Sprout addr → visible | L1 | P1 | done |
| PRIV-5 | Transparent receive flagged PUBLIC | Expand+check rdioTAddr → lblSproutWarning visible + text contains "PUBLIC" | L1 | P0 | done |
| PRIV-6 | Fresh t-Addr on every transparent receive | Two consecutive t-Addr selects yield distinct addresses, both isTAddress | L1 | P1 | done |
| PRIV-7 | Receive previously-used signalling | usedAddresses[a]=true → "Address has been previously used"; fresh → "Address is unused" | L1 | P2 | done |
| PRIV-8 | Send From defaults to shielded source | {z_hi:10,z_lo:1,t:100} → currentText==z_hi (isZAddress); {t:100} only → isTAddress | L1 | P0 | done |
| PRIV-9 | getAutoShield default ON | remove options/autoshield → getAutoShield()==true (canary; FAILS on current false) | L0 | P0 | todo |
| PRIV-10 | Auto-shield fail-open change to Sapling | autoshield ON, t-from + EMPTY zaddresses, change>0 → tx has Sapling change AND newZaddr(true) invoked; OFF → none | L1 | P0 | todo |
| PRIV-11 | Four-way from-aware classification (≡UX-12) | 4 (from,to) shapes → category accessor: z→z PRIVATE/hidden; t→z SHIELDING; z→t DESHIELD red (text: public + linkage); t→t PUBLIC | L1 | P0 | partial |
| PRIV-12 | De-shield requires explicit ack | z→t: extra ack appears, default button==reject; z→z: no extra ack | L1 | P1 | todo |
| PRIV-13 | Badge classify never mislabels (≡UX-11) | Table-driven {zs,zc-sprout,t,(Shielded),'',label} × send/receive sibling → expected Kind; no t→Private, no z→Public | L0 | P0 | todo |
| PRIV-14 | Badge color tokens match qss | colorFor(Private)==#1f7a1f, Public==#d9822b, Deshield==#c0392b; labelFor(Public)=="PUBLIC"; grep dark.qss for same hex | L0 | P1 | todo |
| PRIV-15 | Memo reply-to one-time consent | Clear flag→click→question dialog default No, reject→no insert; accept→inserts own z-addr + flag true; third click→silent | L1 | P1 | done |
| PRIV-16 | Memo only for shielded recipients | t-addr → MemoBtn disabled + tooltip "z-address"; zs-addr → enabled; memoButtonClicked rejects t | L1 | P2 | done |
| PRIV-17 | Shield-public-funds card iff transparent>0 (≡UX-8) | updateHomeFixIt(12.345)→card visible + "PUBLIC" + amount; (0.0)/(5e-8 dust)→hidden | L1 | P1 | done |
| PRIV-18 | Shield action shields, not just navigates | Invoke shield for a t-addr → tx fromAddr t-addr, single toAddr == getDefaultSaplingAddress (Sapling) | L1 | P1 | partial |
| PRIV-19 | Default Sapling resolution prefers real shielded | [sprout,sapling]→returns sapling; [sprout] only→QString() and callers auto-create (never return Sprout) | L1 | P1 | partial |
| PRIV-21 | Private balance is the visual lead (≡UX-6) | Set balSheilded/balTotal, updateHomeFixIt → homeHeroPrivate==balSheilded, homeHeroTotal contains "Total"+balTotal; hero 28pt | L1 | P0 | done |
| PRIV-22 | Activity de-shield rows flagged red | Row {Type=send, t-addr}→Deshield; {receive, t-addr}→Public; {(Shielded)}→Private | L0 | P1 | done |
| PRIV-23 | History opt-out doesn't weaken privacy/instant | savesenttx=false → getShowCachedBalance()==true, autoshield/default-from unaffected; store file 0600 | L0 | P2 | done |
| PRIV-24 | Backup nag one-shot, silent after backup (≡UX-14) | walletbackedup=true → promptWalletBackup() returns sync, activeModalWidget==nullptr; F1/F4 text+flag-on-save extensions | L1 | P0 | partial |
| PRIV-25 | E2E fresh-empty receive lands private | mocke2e fresh-empty: Receive address matches ^z/Sapling regex; "Private" present, no "PUBLIC" at rest | L2 | P1 | partial |
| PRIV-26 | Composite defaults → fully-private z→z | autoshield ON + z-balance, recipient+amount only → fromAddr Sapling, all outputs shielded, category PRIVATE, no de-shield prompt | L1 | P0 | partial |
| PRIV-27 | Sprout send no degrading change route | autoshield ON, Sprout recipient, t-from change>0 → no Sapling change appended AND user informed (no silent t-change) | L1 | P2 | partial |
| PERF-1 | Cached-balance instant paint (≡UX-21) | Seed cache, construct MainWindow with RPC not answering → balTotal==12.5 + "Last known" tooltip; live 9.0 flips label, drops prefix; opens on Home index 0 | L1 | P0 | done |
| PERF-2 | Cached paint correct-by-disclosure | getShowCachedBalance=false → empty/0.00 + no tooltip; grep: only QSettings writes cache/bal*; stale tooltip on all 3 labels | L1 | P1 | done |
| PERF-3 | Warm push update <500ms p95 (≡UX-20) | Fire walletnotify on synthetic event; p95(notify→repaint) <500ms over 50 iters AND updates with 20s/5s QTimer disabled | perf-harness | P0 | todo |
| PERF-4 | Debounced single refresh per burst | 10 notifies 20ms apart → refresh counter==1; 2 notifies 400ms apart → ==2 | L1 | P0 | todo |
| PERF-5 | GUI stops fixed poll once push healthy | Advance 60s with no notify → refresh counter unchanged; kill notify channel → fallback re-arms ≤updateSpeed | L1 | P0 | todo |
| NOTIFY-SRV | Localhost token-gated notify listener (≡PERF-6, NOTIFY-1/2/3/4/5/6/7-sec, NOTIFY-1-rel, INJ-1) | serverAddress==LocalHost, conf token ≥128-bit unique/session; wrong/absent/truncated token → 0 refresh; correct → 1 debounced refresh; constant-time+length compare; payload `^[0-9a-f]{64}$` else dropped (no shell exec of "aa..;touch /tmp/pwned"); ≤4KiB read bound, idle-reaped; token invalidated at session end; non-loopback refused; socket peer gets only "OK" | L1 | P0 | todo |
| PERF-8 | listsinceblock delta replaces fan-out | 5000-tx wallet, cursor N-1, one block notify → exactly one listsinceblock(cursor), no full listtransactions; cursor advances to lastblock | L2 | P1 | todo |
| PERF-9 | Reorg-safe cursor resync depth==-1 (≡DELTA-1, NOTIFY-3-rel) | Orphaned cursor → mock returns full set (depth==-1); model row count == full set (no dup), balance correct; 3-block reorg keeps tx visible | L2 | P0 | todo |
| PERF-10 | No rebuild/repaint on unchanged poll | setNewData identical twice → 0 dataChanged on 2nd, ≥1 on 1st; confirmations 0→1 → dataChanged fires | L1 | P0 | done |
| PERF-11 | Batch RPC zero dead-poll, counter-driven | N=5 all-1ms → cb <30ms same loop turn; inject 1 error → cb once, map owned; N=0 → cb once empty, no leak | L1 | P1 | done |
| PERF-12 | O(1) getwalletsummary (≡EGR-1) | K decrypted notes: prime once + 100 calls → decrypt invocations after prime==0, <5ms total; totals byte-match z_gettotalbalance; schema key-set == whitelist; memo "LEAKCANARY" absent | daemon-gtest | P1 | todo |
| PERF-13 | No re-decrypt on unchanged poll | 50 summary queries static tip → decrypt delta==0; add one note → delta==1 | daemon-gtest | P1 | todo |
| PERF-14 | waitwalletchange single round-trip (≡EGR-2) | Idle 1s-timeout → changed:false within 1s±200ms same fingerprint; inject note → changed:true new fingerprint <250ms; key-set=={changed,fingerprint,cursor_height,cursor_hash}; no deadlock vs concurrent z_gettotalbalance | daemon-gtest | P1 | todo |
| PERF-16 | No main-thread stall during sync | QElapsedTimer around setNewData on 10k-tx delta → no call >16ms p95 / >50ms p100; Xvfb singleShot fires <50ms throughout | perf-harness | P1 | partial |
| PERF-17 | Startup-to-first-paint <1500ms | main()→first paintEvent <1500ms with daemon unreachable; grep: downloadParams zero live callers | perf-harness | P1 | partial |
| PERF-18 | Send-to-feedback <300ms optimistic | Submit send returning opid → pending indicator <300ms before next tick, txTimer==1s; resolve → pending clears, tx in model within one 1s tick | L1 | P1 | partial |
| PERF-19 | Adaptive poll cadence while syncing | isSyncing=true getinfo → interval==5000; false → 20000; unchanged → start NOT called again (guard) | L1 | P2 | done |
| PERF-20 | Refresh skipped on unchanged height | Two getinfo blocks=N force=false → refreshBalances counter==1; blocks=N+1 → ==2; refresh(force) at N+1 → increments | L1 | P1 | done |
| PERF-21 | Eliminate per-zaddr balance fan-out | 50-zaddr fixture, one balance refresh → z_listreceivedbyaddress count==0 (A) / doesn't scale with addr count; daemon decrypt bounded by changed-notes | perf-harness | P1 | todo |
| PERF-22 | Cold vs warm latency measured | COLD connect→first balance p95 <3s; WARM event→repaint p95 <500ms (B) / record <300ms (A) over 50 iters | perf-harness | P1 | todo |
| PERF-23 | Keyscan/decrypt throughput floor | Full GetFilteredNotes scan of M notes → notes/sec ≥ baseline*0.9; total decrypts == M (no quadratic) | daemon-gtest | P2 | todo |
| PERF-24 | Notify failure falls back safely (≡NOTIFY-2-rel) | No notify configured + advance one updateSpeed → exactly one fallback refresh, balances correct; foreign node → no notify wiring, heartbeat only, no double-refresh; stub waitwalletchange never-returns → times out, never blocks UI | L1 | P0 | todo |
| PERF-25 | Idle CPU/wakeups | Synced+idle 5min, push healthy → 0 balance/tx RPCs, ≤1 price/hr, only heartbeat; no timer faster than keepalive | perf-harness | P2 | todo |
| EGR-3 | Fingerprint non-invertible | Two notes V1,V2 → fingerprints fixed-width; code-inspect no CAmount fed to hash (or counter-based); brute-force 10k (V1,V2) → no unique recovery | daemon-gtest | P2 | todo |
| UX-1 | Single source-of-truth type scale | Grep dark.qss: base 13pt, balTotal 19pt, balSheilded/balTransparent 14pt, homeHeroPrivate 28pt; qApp font ≥13; no Home content label <13pt | L1 | P0 | done |
| UX-2 | Bundled font on every platform | QFontDatabase has 'Ubuntu' + qApp font resolves to it; load-fail → base ≥13pt; .qrc references Ubuntu-R.ttf | L1 | P1 | done |
| UX-3 | Modern dark theme (Fusion + QSS) | style=='fusion', styleSheet non-empty contains #15171c, Window lightness <60; Xvfb central bg luminance <0.25 | L2 | P0 | done |
| UX-4 | Left nav rail primary, tab bar hidden | tabBar hidden; navRailGroup exclusive ids 0..3 Home/Send/Receive/Activity + Advanced id 1000; setCurrentIndex(2) syncs rail | L1 | P0 | done |
| UX-5 | Advanced gear graceful when absent | No zclassicd tab → advBtn slot leaves index unchanged, no crash; inject tab → switches + checks | L1 | P1 | done |
| UX-7 | Home quick actions Send+Receive | homeSendBtn (homeaction=='primary', ≥40px) → index 1; homeReceiveBtn → index 2; QSS bg #1f7a1f padding ≥12px | L1 | P0 | done |
| UX-13 | First-run onboarding card once | onboardingShown unset → ezCard visible with Step 1/2/3, flag set; set → ezCard hidden | L1 | P0 | partial |
| UX-15 | Sync status self-explains | setSyncStatus(false,h,h,1.0)→"Synced"+green #1f7a1f; (true,0,-1,-1)→indeterminate "Starting your node…"; (true,500,1000,0.996)→value==100 + ETA; height>0 indeterminate → includes block number | L1 | P0 | done |
| UX-16 | Startup errors self-explain w/ action | showError strings for no-connect/no-start/low-disk/already-running each have an action verb + no raw errno; downloadParams not on doAutoConnect; "Repair…" QAction under menuHelp enabled post-latch | L1 | P0 | done |
| UX-17 | Hit-targets ≥40px | Each rail button sizeHint h≥40, w≥150; homeSendBtn/homeReceiveBtn h≥40; QSS primary padding ≥8px | L1 | P1 | partial |
| UX-18 | WCAG AA contrast tokens | Contrast helper: e6e6e6/15171c≥4.5, e6e6e6/1d2027≥4.5, 9aa0a6/15171c≥3.0, ffffff/1f7a1f≥4.5, fixit-text/amber≥3.0, pills≥3.0 | L0 | P0 | todo |
| UX-19 | Dangerous actions demoted + confirmed | Rail/Home reference no Import/Export/turnstile/repair; reachable via menus/gear; Repair raises a confirm (wallet untouched, backup first) before acting | L1 | P1 | partial |
| UX-22 | Friendly empty/zero states | Zero fixtures → hero "0.00…" not empty, card hidden; empty model → Activity "No transactions yet"; Xvfb hero label non-empty | L1 | P2 | todo |
| UX-23 | Modals never trap the user | promptWalletBackup backed-up → activeModalWidget==nullptr; confirmTx exactly one modal, reject() no hang; mocke2e WM_DELETE exits <CLOSE_TIMEOUT_S | L2 | P1 | done |
| UX-24 | Address copy + QR, no truncation | qrcodelabel updates on address change; copy puts EXACT address on clipboard; hero + receive widget TextSelectableByMouse | L1 | P2 | partial |
| UX-25 | Visual-regression L2 guard | Funded-synced fixture after READY: ~168px rail column, central bg luminance <0.25, capture home/balances/receive.png; golden diff within tolerance | L2 | P2 | partial |
| XPLAT-1 | Embedded extraction verified/atomic | Extracted daemon size==len + sha256==footer + exec bit; flip a byte/len=0/600MiB → return "" <2s + "failed verification", fall back; re-launch fast-path no .part | L2 | P0 | done |
| XPLAT-2 | Sibling-first then extract, clear error | Sibling chosen over extraction (log names abs path); no sibling on single-file → extraction; both corrupt → error dialog within connect window | manual | P0 | done |
| XPLAT-3 | macOS signed sibling, never extract | grep Q_OS_DARWIN body first stmt == return QString(); spctl accepted; codesign hardened+Developer ID; quarantined launch → getinfo answers | manual | P0 | partial |
| XPLAT-4 | glibc-2.31 floor | objdump -T max GLIBC ≤2.31 for both binaries; smoke-launch on clean Ubuntu 20.04 → getinfo | manual | P1 | done |
| STUCK-1 | getbootstrapinfo during warmup | Mid-bootstrap: getbootstrapinfo 200+phase while getbalance==RPC_IN_WARMUP; two calls leave datadir mtimes unchanged | daemon-gtest | P0 | done |
| STUCK-2 | Throughput watchdog | BootstrapDownloadTooSlow: 59999ms→false; 60000ms+1MB→true; +2MB→false advance; sub-floor trickle aborts, ≥32KiB/s never | daemon-gtest | P0 | done |
| STUCK-3 | Per-peer retry + graceful fallback | Dead -bootstrappeer → 3 attempts ~3s gaps; no explicit peer → phase normal_sync + opens DBs; explicit peer fail → InitError; InitMessage updates per attempt | daemon-gtest | P0 | done |
| STUCK-4 | Stub recovery 64 MiB gate | chainstate 70MiB→false; 10/20MiB best≠genesis→true; torn→false; genesis→false; blocks 200MiB→false; foreign-fork index <64MiB→true (index ignored) | daemon-gtest | P0 | done |
| STUCK-5 | Stub recovery churn-guard fail-closed | attempts=3→false "max"; attempts=1 last 1h ago→false "cooldown"; anchor changed→allowed; read-only datadir → marker write fails, recovery skipped | daemon-gtest | P0 | done |
| STUCK-6 | Genesis/stub backup not delete + restore | Force import fail → blocks/chainstate restored byte-identical, no orphan backup; success → timestamped backup kept + marker cleared | daemon-gtest | P0 | done |
| STUCK-7 | Bootstrap peers pinned as -addnode | Empty peers.dat + dead DNS + no -connect → getpeerinfo shows outbound to a compiled peer; -connect=x → not injected; log line only in addnode case | manual | P1 | partial |
| STUCK-8 | Healthy seed infrastructure | ARRAYLEN(pnSeed6_main)>0; dig DNS seeds ≥1 A; TCP+handshake to both bootstrap peers <10s; soak connections>0 <60s in ≥95% trials | manual | P0 | partial |
| STUCK-9 | Foreign stuck node dialog once | Foreign node connections==0 + syncing ≥36 polls → showForeignNodeStuck once, no stop/kill; connections>0 → never; embedded → never | L1 | P1 | done |
| STUCK-10 | Active download not stub-wiped | phase=active percent=40 connections==0 → setSyncStatusBootstrapSnapshot called, maybeAutoHealStubChain NOT; flip to normal_sync <1GiB → heal eligible | L1 | P0 | done |
| PARAM-1 | Params peer-fetched hash-verified, never z.cash | Empty params + mock peer → all 5 files land matching GetZcashParamSpecs; flipped byte → rejected; grep GUI downloadParams zero callers | daemon-gtest | P0 | done |
| PARAM-2 | Single source of truth for param hashes | Corrupt one param → InitSanityCheck false naming file; delete one -bootstrap=0 → InitError names dir + fetch-params.sh; sizes pinned test passes | daemon-gtest | P0 | done |
| FASTSYNC-1 | Anchor snapshot verified vs compiled anchor | v1/v2 manifest==anchor validates; self-snapshot rejected unless fTrustlessAllowed; tampered commitment/height/hash rejected; null-commitment anchor fails | daemon-gtest | P0 | done |
| FASTSYNC-2 | Trustless provisional + background revalidate | Import → provisional + durable record; matching re-derive → validated persists restart; corrupted → FAILED + reindex queued; GUI banner provisional→cleared | daemon-gtest | P1 | done |
| FASTSYNC-3 | Above-checkpoint tip holds finalization | Arm hold at (H,hash) → BootstrapValidationHoldsFinalization true persists restart; corroboration clears; tip==checkpoint → no hold | daemon-gtest | P1 | done |
| FASTSYNC-4 | Untrusted manifest can't exhaust disk | 300GiB total→reject; 40GiB file→reject; wrong chunk size→reject; < total+1GiB free→refuse up front | daemon-gtest | P1 | done |
| FASTSYNC-5 | Durable verify-pending markers | Write anchor-pending marker, exit before verify, restart → verify_pending true + verify runs; success clears; v3 grown-bundle tip vs v1 anchor returned | daemon-gtest | P1 | done |
| FASTSYNC-6 | Parallel-stream correct, degrades to single | streams=1 and =4 reassemble identical + matching hashes; smaller server chunk size still completes; clamp [1,16] | daemon-gtest | P1 | done |
| FASTSYNC-7 | Serve quota/aggregate caps/rate floor | IP over cap throttled/stopped at deterministic now_ms; aggregate cap defers but first chunk through; 24h rollover resets; v4/v6 tracked separately; sub-floor → RateCapBelowFloor | daemon-gtest | P2 | done |
| FASTSYNC-8 | Auto-serve only matching compiled anchor | Matching marker → serve activates; stale anchor → false + copy removed; no serve dir → false+reason; prepared snapshot no-anchor → false+warning | daemon-gtest | P2 | done |
| SHUTDOWN-1 | Graceful stop, 30s hard cap | Synced quit → clean exit (no leftover LOCK, no dirty reindex next start), no flash dialog; warmup quit → no tx-error box; ignoring-stop daemon → quits ~30s; external → no wait | L2 | P0 | done |
| SHUTDOWN-2 | Clean restart no dirty reindex | 5 clean restarts → no reindex/"best block not in index"; SIGKILL mid-write → WAL replay or bounded reindex to prior tip, no orphaned funds; -reindex/-reindex-chainstate mutually exclusive; one-shot flags stripped on crash | daemon-gtest | P1 | partial |
| SHUTDOWN-3 | Validation thread joined before DB free | ASan: shutdown mid-validation → no UAF on pcoinsTip/pblocktree, thread joined before teardown; no-op when none running; init-failure path same | daemon-gtest | P1 | done |
| CRASH-1 | Crash auto-restart capped at 3, strip flags | Kill once → one restart, getinfo resets count; kill 4x → terminal dialog/tray notice no further restart; -reindex crash → restarted args have no -reindex*; hidden → tray notify silent | L2 | P0 | done |
| CRASH-2 | Warmup-corruption failsafe | Corrupt chainstate so daemon InitError-exits during warmup → log "exited and did not come online" + repair dialog within connect window; repair → redownloadChain with guards | L2 | P1 | done |
| FRESH-1 | Clear monotonic first-sync, never stuck 0 | fresh-empty → banner cycles download→sync, no literal stuck "0%" while connections==0 (waiting-for-network after ≥3 polls); syncing 0.9635 → ~96%; funded → Synced; monotonic per phase | L2 | P0 | done |
| FRESH-2 | Conf creation failure surfaced | Read-only conf dir → showError mentions permissions+disk, no hang; conf has server=1+rpcuser+random rpcpassword+no addnode; -tor → proxy=127.0.0.1:9050 | L2 | P1 | done |
| FRESH-3 | Disk-space preflight before large writes | < (len+16MiB) free → extraction "insufficient disk" returns "" no .part; manifest > free-1GiB → refused; user-readable message each case | L2 | P1 | partial |
| SELFTEST-1 | Self-heal scenarios run headless | Parallel runner: test_bitcoin bootstrap (55) + zcash-gtest + GUI L0(74)/L1(9)/L2 all pass; every P0/P1 req maps to ≥1 named test (no traceability gap) | daemon-gtest | P1 | partial |
