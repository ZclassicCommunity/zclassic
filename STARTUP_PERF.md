# Cold-start performance — measured, ranked, logged

Always-on per-phase instrumentation (`src/startuptimer.{h,cpp}`, `g_startupTimer.mark()` in
`src/init.cpp`) prints a `[startup]` table on every "Done loading". This file is the running
before/after log. **Rule: never quote a saving we have not measured** — estimates are labelled.

## Measurement methodology (read before trusting numbers)

The first instrumented run used an alt-port, no-net, *fresh/stub* datadir. That made
`BootstrapDatadirEligible` return true, so the node **fast-synced from a bootstrap peer during
"startup"** — i.e. the run measured a *fresh-install bootstrap*, not a *synced-user reopen*.

Consequences:
- The coarse **`network+bootstrap` = 42.7 s is a harness artifact** (an actual fast-sync download +
  install ran). On a genuinely synced datadir this span is the cheap ineligible path (~0 ms).
- `loadblockindex-db` (24.3 s) + `rewindblockindex` (9.6 s) are the freshly-installed chain being
  loaded — real, but their magnitude scales with chain size.

**To measure a true synced restart:** point the alt-datadir at an already-synced multi-GiB
chainstate (so eligibility returns false). The new finer marks below split every coarse span.

## Measured baseline (fresh-install bootstrap run; ~86 s total)

| phase | ms | note |
|---|---|---|
| setup+flags(1-3) | 0.8 | |
| **ecc+sodium+sanity** | **8889.6** | param SHA-256 hash (now split: `ecc-start` / `param-hash-loop` / `sanity-tail`) |
| datadir-lock+threads | 0.6 | |
| zk-snark params | 680.9 | already deduped (single hash pass) |
| rpc/http servers | 0.4 | |
| wallet db verify | 1.4 | |
| **network+bootstrap** | **42681.9** | harness artifact — real fast-sync ran (see methodology) |
| **.loadblockindex-db** | **24348.3** | leveldb scan + ~1344-byte nSolution decode dominate |
| **.rewindblockindex** | **9584.3** | |
| .verifydb | 17.8 | |

## Applied wins (this pass — provably safe / verified)

| # | change | file | expected | confidence |
|---|---|---|---|---|
| 1 | param hash read buffer 1 KiB → **256 KiB** (kills ~1.65M proot-taxed `read()` syscalls; byte-identical SHA-256) | `init.cpp check_file_hash` | ~6 s (proot); bounded by syscall-fraction of ~3 s bare-metal | high |
| 2 | drop the **redundant 2nd per-record header rehash** in `LoadBlockIndexGuts` (recompute-vs-recompute of identical inputs — can never fail); **`CheckProofOfWork` kept verbatim** | `txdb.cpp` | ~5 s est (likely smaller — scan/decode dominate) | high |
| 3 | network sub-marks `.net-setup` / `.pre-bootstrap-snapshot`, re-scoped `network+bootstrap` | `init.cpp` | 0 (instrumentation) | — |
| 4 | param-hash attribution marks `ecc-start` / `param-hash-loop` / `sanity-tail` | `init.cpp` | 0 (instrumentation) | — |
| 5 | **param self-heal fix**: `check_file_hash` no longer calls `StartShutdown()` on failure; caller (`InitSanityCheck` self-heal loop) owns the abort, so a corrupted-but-healable param re-fetches + re-verifies + **continues** instead of heals-then-exits | `init.cpp` | correctness | high |

**Expected total ≈ 11 s** (estimates; to be replaced with measured deltas on a synced datadir).

## ✅ MEASURED — verified-params cache (params-verify.cache) — biggest relaunch win

Cache helpers + verification-loop rewrite in `init.cpp` (compiled-hash-gated; skip a re-hash only when
file size == **compiled** size AND a cached record's (size,mtime) match AND the record's verified hash
== the **compiled** `spec.sha256hex`; `0600` owner-only cache in the datadir with an on-read fstat
owner/mode gate; epoch = SHA-256 of the whole compiled name|hash|size table; `-noparamcache` escape
hatch; **fail-closed** — any doubt → full hash; self-heal path preserved). Designed + adversarially
attacked by workflow `whvhpm792` (verdict: implement-cache; chose cache over SHA-NI because SHA-NI
touches the consensus `SHA256Compress`).

Measured on an isolated empty datadir (alt ports, `-bootstrap=0`, peer #1 untouched):

| run | log line | `param-hash-loop` |
|---|---|---|
| **COLD** (no cache) | `param-cache: 0 skipped, 5 hashed` + cache file written `0600` | **4946.5 ms** |
| **WARM** (unchanged) | `param-cache: 5 skipped, 0 hashed` | **0.1 ms** |

→ **~4.95 s → 0.1 ms** on every relaunch with unchanged params; both runs reached "Done loading".
Known accepted residual: bit-rot preserving BOTH size+mtime is skipped — but zk params are firewalled
from consensus (a corrupt param makes a shielded proof fail/**reject**, never forge/fork; self-heals via
re-fetch); `-noparamcache` forces today's full hash.

## Rejected (do NOT retry without the stated precondition)

- **Skip the terminal `FLUSH_STATE_ALWAYS` in `RewindBlockIndex`** — measure-first/REFUTED. The
  chainstate flush is an async non-durable `WriteBatch` (default `fSync=false`); the stated
  mechanism is contradicted by source and the root cause of the 9.6 s is unmeasured. Precondition
  to revisit: the `.rewind-scan` / `.rewind-prewrite` / `.rewind-flush` marks must positively
  attribute the cost first.
- **Use the raw leveldb key as the block hash** (skip the single recompute) — would change map-key
  derivation; self-rejected by author + verdict.

## Pending (next measurement run)

Add the remaining finer marks (rewind scan/flush, txdb post-loop + record count, main.cpp
post-processing), point at a **synced** datadir, rebuild once, and record measured before/after
here. Then decide whether the `network+bootstrap` span and the rewind flush hide further wins.
