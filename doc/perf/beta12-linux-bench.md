# Beta 12 Linux baseline bench (Rust-backed build)

Scope: where block-connection time goes in the current Rust-backed `zclassicd`, measured on one Linux host, so later speed work can be ranked by data. Two 15-minute windows from genesis were run, one with `-disablewallet` and one with the wallet enabled (empty wallet). No above-checkpoint window was run (see "Not run").

Every number below comes from `debug.log` (`-debug=bench`) or from `uptime`/`/proc/loadavg` samples taken during the run. Aggregation is `agg.awk` (in `doc/perf/bench-scripts/`).

## Machine and host (shared)

- Host: `z23-r2` (rhett2.dev), AMD Ryzen 9 7950X3D, 16 cores / 32 threads, 93 GiB RAM, Ubuntu 24.04.3 LTS, gcc 14.2.0.
- The host is shared and busy during the bench: about 30 to 36 logged-in users, and other `fuzz_*` processes at about 99 % CPU each. The bench node was allotted 8 CPU and 8 GiB by the devbuild broker (`--project z23 --class normal`). Load averages are reported per window below. Timing numbers are therefore noisy and are not a clean microbenchmark; they are relative data for ranking.
- Disk: `/home` on NVMe, 886 GiB free at start. The 25 GB cap was never reached (peak datadir 290 MB).

## Build under test

- Path: `~/work/zclassic-c23-rust-removal/src/zclassicd` (read only, not modified).
- SHA-256: `104ff98c3bd9f73656430fa2c4d841deb14b72c8603f066c1682eb27b5fa5981`.
- Reported version: `ZClassic Daemon version v2.1.2-beta11-f53b1232d`. The string says beta11 while the bench assignment called it beta 12 master; the reported commit is `f53b1232d`. Recorded as found.
- Built 2026-11-16 18:29 (Rust-backed, librustzcash in `depends`).

## Exact commands

Daemon configuration written by `window.sh` into a fresh datadir (`~/work/zc23-p0-data/<mode>/zclassic.conf`, password generated per run, file removed at the end of each window):

```
rpcuser=p0bench
rpcpassword=<random per run>
rpcport=28232
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
server=1
port=28033
listen=0
bootstrap=0
debug=bench
debuglogfile=1
```

Daemon launch (mode `nowallet` adds `-disablewallet`; mode `wallet` adds nothing):

```
zclassicd -datadir=$HOME/work/zc23-p0-data/<mode> -conf=$HOME/work/zc23-p0-data/<mode>/zclassic.conf [-disablewallet]
```

Submission, one window at a time, each under the broker:

```
devbuild --wait --project z23 --class normal ./window.sh nowallet 900
devbuild --wait --project z23 --class normal ./window.sh wallet 900
```

`window.sh` samples `/proc/loadavg` and datadir size every 60 s, runs `zclassic-cli ... getblockcount`, then `zclassic-cli ... stop`, waits for the exact PID, and copies `debug.log`. Aggregation:

```
awk -v WINDOW=900 -f agg.awk debug.log
```

Notes on the configuration:

- `bootstrap=0` is required. A fresh datadir otherwise starts a bootstrap snapshot download (observed: "Bootstrap snapshot: 0% 0.00 / 10.43 GB, 4 streams"), which measures snapshot import rather than block connection. The production node uses the same `-bootstrap=0`.
- There is no `-nofastsync` option in this build. `zclassicd -help` lists only `-bootstrap*` options, so a plain `bootstrap=0` datadir is the from-genesis full-validation path.
- `debuglogfile=1` is required. Without it the build writes no `debug.log` (the default is off), and daemon-mode stdout is empty.
- The ports 18232 and 18033 are in use on this host by another node, so the bench uses 28232 and 28033.

## Runs

| Run | Mode | Start (UTC) | End (UTC) | Load 1 min at start / end | Mean load (1 min, 15 samples) | Blocks connected | Heights | Tip at stop | Stop | Peak datadir |
|---|---|---|---|---|---|---|---|---|---|---|
| A | `-disablewallet` | 18:53:32 | 19:08:33 | 23.99 / 13.99 | 26.85 | 34,575 | 0 to 34,574 | 34,574 | clean, 1 s | 259 MB |
| B | wallet enabled, empty | 19:08:33 | 19:23:35 | 13.11 / 28.18 | 19.14 | 39,618 | 0 to 39,617 | 39,616 | clean, 2 s | 290 MB |

Both windows exited through `zclassic-cli stop`. Neither hit the 25 GB cap or an early daemon exit.

## Stage table (mean and total milliseconds per stage)

`Connect block` is the per-block total the code logs as `nTime6 - nTime1` in `ConnectTip`. `Connect total` is `ConnectBlock` plus the signal, finalize and erase steps (`main.cpp:3319` to `3412`). Two rows are cumulative from the start of `ConnectBlock` (`main.cpp:2620`): `Connect transactions` and `Verify txins`. Their percentage column therefore overlaps and is not additive.

Run A, `-disablewallet`, heights 0 to 34,574 (34,575 blocks):

| Stage | Samples | Mean ms | Total ms | % of Connect block |
|---|---:|---:|---:|---:|
| Load block from disk | 34,575 | 0.225 | 7,776.1 | 1.03 |
| Connect total | 34,575 | 21.504 | 743,513.0 | 98.83 |
| Connect transactions (cumulative) | 34,574 | 0.107 | 3,711.9 | 0.49 |
| Verify txins (cumulative) | 34,574 | 0.189 | 6,545.7 | 0.87 |
| Index writing | 34,574 | 0.052 | 1,806.3 | 0.24 |
| Callbacks | 34,574 | 0.007 | 229.7 | 0.03 |
| Flush | 34,575 | 0.008 | 286.7 | 0.04 |
| Writing chainstate | 34,575 | 0.002 | 85.4 | 0.01 |
| Connect postprocess | 34,575 | 0.017 | 591.4 | 0.08 |
| Connect block | 34,575 | 21.760 | 752,337.6 | 100.00 |

Run B, wallet enabled (empty), heights 0 to 39,617 (39,618 blocks):

| Stage | Samples | Mean ms | Total ms | % of Connect block |
|---|---:|---:|---:|---:|
| Load block from disk | 39,618 | 0.202 | 8,006.0 | 1.06 |
| Connect total | 39,618 | 18.809 | 745,165.0 | 98.75 |
| Connect transactions (cumulative) | 39,617 | 0.093 | 3,695.8 | 0.49 |
| Verify txins (cumulative) | 39,617 | 0.228 | 9,042.1 | 1.20 |
| Index writing | 39,617 | 0.048 | 1,911.1 | 0.25 |
| Callbacks | 39,617 | 0.007 | 266.6 | 0.04 |
| Flush | 39,618 | 0.007 | 293.1 | 0.04 |
| Writing chainstate | 39,618 | 0.001 | 51.4 | 0.01 |
| Connect postprocess | 39,618 | 0.025 | 980.3 | 0.13 |
| Connect block | 39,618 | 19.047 | 754,611.3 | 100.00 |

Blocks per second:

| Run | Blocks over 900 s window | Blocks/s over window | Blocks/s over Connect-block time only |
|---|---:|---:|---:|
| A, `-disablewallet` | 34,575 | 38.42 | 45.96 |
| B, wallet | 39,618 | 44.02 | 52.50 |

Derived values (computed from the table above, not logged):

- Verify phase alone, `Verify txins` minus `Connect transactions`: A 0.082 ms/block, B 0.135 ms/block.
- Connect-total residual not covered by any logged sub-stage (`Connect total` minus `Connect transactions`, `Verify` phase, `Index writing`, `Callbacks`): A 21.256 ms/block (98.9 % of Connect total), B 18.526 ms/block (98.5 %).
- `Connect block` consumed 83.6 % of the 900 s window in run A (752,338 ms of 900,000 ms) and 83.8 % in run B (754,611 ms of 900,000 ms).

## Ranking

These are ranks by measured share of connect time. Read them with the caveats below.

1. **Uninstrumented remainder of `Connect total` (about 98.5 to 98.9 %).** The logged sub-stages sum to about 0.25 to 0.28 ms per block, against 18.8 to 21.5 ms of `Connect total`. The time is inside `ConnectBlock` before the first timer (`main.cpp:2528` to `2620`), in the `BlockChecked` signal dispatch, or in `FindBlockToFinalize`/`FinalizeBlockInternal` (`main.cpp:3400` to `3412`). These logs cannot split it. This is the first gap to close, by adding timers in those three regions, before any optimisation is ranked.
2. **Verify phase (script and signature verification, cumulative to `main.cpp:2750`).** 0.082 ms (A) and 0.135 ms (B) per block, about 0.4 % and 0.7 % of Connect block.
3. **Load block from disk.** 0.225 ms (A) and 0.202 ms (B), about 1.0 % of Connect block. Blocks come from the block index and flat files.
4. **Index writing.** 0.052 ms and 0.048 ms, about 0.25 %.
5. **Connect transactions (tx loop, cumulative).** 0.107 ms and 0.093 ms, about 0.5 %.
6. **Connect postprocess, Flush, Callbacks, Writing chainstate.** Each at or under 0.03 ms, about 0.16 % combined in A.

Caveats for the ranking:

- **The Rust-backed work is not timed here.** The bench timers sit only in `ConnectBlock` (`main.cpp:2739` to `2810`), `DisconnectBlock` (`:3005`) and `ConnectTip` (`:3334` to `3448`), confirmed by grep of the `LogPrint("bench"` calls. Block checks (`CheckBlock`, `CheckBlockHeader`, `CheckTransaction`) and `AcceptBlock` run on the path before `ConnectTip` and have no bench line. Where the Sprout and Sapling proof verification runs (through librustzcash) was not traced in this unit, so its cost is not in these numbers, and whether it sits on that path is unverified.
- **The window is early chain.** Heights 0 to about 39,600 are early blocks; the sampled blocks are dated from 2016 (height 1265 is dated 2016-11-07), and I did not check the dates at the top of the range. I did not check how many of these blocks contain shielded transactions. Proof-heavy tip blocks are not represented; the tip-region cost would need an above-checkpoint window.
- **The wallet delta cannot be isolated.** Run B has a lower per-block `Connect total` (18.8 vs 21.5 ms), but it also covers a different height range (39.6k vs 34.6k blocks) and a lower mean host load (19.1 vs 26.9). The wallet's `BlockChecked` cost sits inside the uninstrumented remainder and is not separated here.

## Not run

- **Above-checkpoint window (above height 3,126,937).** Not run. Reaching the tip needs the bootstrap snapshot path (`-bootstrappeer` or `-bootstrapdiscover`), which measures snapshot import rather than block connection, and this bench has no trusted bootstrap peer address for this build. A snapshot download is also a 10.43 GB transfer. The window needs a decided bootstrap policy before it can run.
- **Clean, quiet-host numbers.** Not possible on this shared host (see Machine).
- **Per-stage numbers for the Rust proof verification.** Not measured; the timers do not reach `CheckTransaction`.
- **A wallet-versus-no-wallet delta at the same heights.** Not measured; the two windows cover different ranges.
- **Two-run repeat.** Each configuration was run once.

## Incidents during the bench (disclosed)

- A first `devbuild --help` call queued a z23 job that failed with exit 127 and left a retained scratch directory. I removed that job's scratch (`~/.cache/development-builds/z23/job.2CyqZlJB`).
- The first submission used the default project, which resolved to `exclusive/exclusive` (28 CPU, 64 GiB, 9 I/O tokens). It was admitted about 127 s after queueing and held for a short time (a few minutes at most) before I killed the driver. The cancelled run's daemon was no longer running afterwards and produced no bench data; it appears to have been reaped when the job scope ended. This may have taken capacity from other users on the shared host. All later runs used `--project z23 --class normal`.
- Port 18232 was already held on the host by another z23 node's RPC (`ss -ltnp` showed pid 987845). My cli calls (`getblockcount`, `stop`) reached that RPC with my own password and were rejected ("incorrect rpcuser or rpcpassword"). Nothing was stopped or changed there. The bench moved to 28232 and 28033.
- Several of my `pgrep -f` and `pkill -f` pattern matches matched my own remote shells and ended those ssh sessions with exit 255. Only processes this bench started were signalled, and the final `ps` checks found none left.
- A first daemon run in each mode did not write `debug.log` (missing `debuglogfile=1`). Those runs were stopped and discarded; the reported runs are the second and final pair.

## Evidence

- Raw logs (not copied locally, 31 MB and 35 MB): `~/work/zc23-p0-bench/nowallet/debug.log` and `~/work/zc23-p0-bench/wallet/debug.log` on z23-r2.
- Per-window samples, stop records, host load and aggregated tables: `~/work/zc23-p0-bench/<mode>/{sampler.txt,host-start.txt,host-end.txt,stop.txt,agg.tsv}` on z23-r2.
- Scripts: `doc/perf/bench-scripts/window.sh`, `doc/perf/bench-scripts/driver.sh`, `doc/perf/bench-scripts/agg.awk` (the copies on z23-r2 are identical).
- The chain datadir `~/work/zc23-p0-data` was deleted after the second window.
