# Pinned Decisions — gap resolutions for SPEC.md (2026-06-03)

The north-star spec ([SPEC.md](SPEC.md)) surfaced 24 open decisions. These are pinned with sensible defaults to unblock the build; each can be revisited if proven wrong. IDs reference SPEC.md requirements.

1. **Auto-shield scope (PRIV-9/10):** option (a) — shield *change* to Sapling + keep a shielded default From. NOT full output-shielding (sending to a t-recipient the user explicitly chose stays allowed, with the de-shield warning).
2. **Fail-open provisioning (new PRIV-28):** eagerly provision ONE Sapling z-address at first run / first funding so the send path never blocks on key generation; a synchronous `newZaddr(true)` mid-send remains only as a last-resort fallback.
3. **Debounce window:** single named constant `kNotifyDebounceMs = 200`. Not user-configurable.
4. **Fallback heartbeat:** 120 s while the push channel is healthy; re-arm to `updateSpeed` (20 s / 5 s syncing) within one interval on channel death.
5. **Perf-harness fixture:** synthetic 10k tx / 5k Sapling notes / 50 z-addrs at a fixed chain height; reference machine = this dev box; all p95 thresholds measured there and recorded in the harness.
6. **B/A coexistence:** keep Plan B permanently as the older-daemon fallback. The GUI capability-probes `getwalletsummary`; if absent it uses the B notify+delta path. Both are permanent.
7. **listsinceblock shielded coverage (PERF-8/9):** `listsinceblock` is transparent-oriented; shielded receives still need a parallel z-side delta (cursor-gated `z_listreceivedbyaddress`). B keeps a z-delta alongside the transparent delta.
8. **Cursor persistence:** lives in QSettings per-GUI (like the balance cache), keyed by a wallet fingerprint; invalidated on wallet switch or best-block-hash mismatch.
9. **getwalletsummary semantics:** match `z_gettotalbalance minconf=0` exactly (including immature coinbase) so the displayed total is identical pre/post-A.
10. **Note-value cache persistence:** persisted INSIDE the encrypted `wallet.dat` envelope (`CWalletDB`), never a plaintext sidecar; a miss/inconsistency fails safe by full recompute.
11. **Change fingerprint (EGR-3):** monotonic `uint64` change-counter (epoch). The GUI treats any backwards/reset value (e.g. daemon restart) as "force full refresh."
12. **Notify transport:** `QLocalServer` (unix domain socket, 0600) on Linux/macOS; loopback `QTcpServer` (127.0.0.1, ephemeral port) on Windows. Token-gated either way.
13. **Notify connector (no external dep):** the GUI binary is its own connector — daemon conf gets `-walletnotify`/`-blocknotify` invoking `<self> --notify <token> %s`, a tiny mode that connects to the socket, sends token+id, exits. No reliance on curl/nc being present.
14. **Threat model:** a hostile co-resident local user IS in scope (cheap to defend; the conf already holds full-authority creds) → 0600 + timing-safe token compare.
15. **Canonical P2P port:** 8033 (ZClassic mainnet). The 8034 bootstrap special-case was dropped (aaa748e98); 8033 references are correct.
16. **Seeds (STUCK-8, operational):** commit to ≥3 reachable seeds — peer#1 (74.50.74.102) + rhett2.dev (205.209.104.118) + a third to stand up. Ops follow-up, not code-blocking.
17. **SHUTDOWN-2:** for this milestone, surface-as-clear-status is sufficient; hardening clean-shutdown flush (single-WAL discipline) is a post-milestone follow-up (matches the dirty-DB "minor-nits" finding).
18. **macOS notarization (XPLAT-3):** dev-owned signing identity; out of scope for this code work.
19. **PRIV-25 E2E:** update the mock fresh-empty fixture to return a deterministic Sapling `z_getnewaddress`, unblocking the L2 receive-privacy assertion.
20. **Give-up policy (CRASH-1 + STUCK-5):** documented jointly; a node both crash-looping AND stub-stuck → the crash cap (3) wins → repair dialog, no infinite loop.
21. **First-sync SLA (FRESH-1):** target — a fresh install reaches "Synced" within ~20 min via bootstrap fast-sync on typical broadband; the 32 KiB/s watchdog floor stays.
22. **PRIV-11/12 enforcement locus:** GUI confirm dialog for this milestone; daemon-side `z_sendmany` dry-run enforcement (covers headless/programmatic sends) is a follow-up.
23. **Memo length side-channel:** NON-ISSUE — the Zcash/ZClassic memo field is protocol-fixed at 512 bytes on-chain, so there is no memo-length oracle; no padding requirement needed.
24. **Send-side reuse guard (new PRIV-29, P2):** the wallet should not auto-consolidate into / repeatedly auto-select one transparent From across sessions (send-side analogue of the PRIV-6 receive-reuse guard).
