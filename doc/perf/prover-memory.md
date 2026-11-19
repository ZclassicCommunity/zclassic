# Sapling prover memory (Linux x86-64)

Scope: where the daemon's memory goes during `z_sendmany`, what this branch changes, and what
waits for Z23. Host `z23-r2` (shared; load average 12 to 55 during the runs, so times are good to
about +-15 %, memory is exact). Measurement: `VmHWM` of the daemon after `echo 5 > /proc/<pid>/clear_refs`,
read right after `z_sendmany` completes; idle RSS read before, right after and 5 s after.
Regtest, temporary datadirs, one recipient unless stated. Script: `qa/rpc-tests/wallet_matrix_lib.sh`
helpers plus a `VmHWM` sampler: `qa/rpc-tests/prover_memory_bench.sh`.

## Where the memory goes

Massif of one spend proof (standalone harness, 1 thread, heap peak 247 MB):

| component of one spend proof              | before  | after (this branch) | after Z23 patch 1 | scales with |
|-------------------------------------------|---------|---------------------|-------------------|-------------|
| raw sapling-spend/output params           | 51.6 MB | 51.6 MB             | 51.6 MB           | fixed (process) |
| parsed proving key (`groth16_pk_read`)    | 71.9 MB | 71.9 MB, once per send | 71.9 MB, once per send | per proof -> shared |
| stored linear combinations (terms)        | 86.9 MB | 86.9 MB             | 25.0 MB           | proofs in flight |
| `constraints[]` (3 x 32 B, capacity 2^17) | 12.6 MB | 12.6 MB             | 12.6 MB           | proofs in flight |
| constraint-system witness                 | 4.2 MB  | 4.2 MB              | 4.2 MB            | proofs in flight |
| QAP a, b, c (3 x 2^17 x 32 B), then h     | 12.6 MB | 12.6 MB             | 12.6 MB           | proofs in flight |
| MSM scalars, index, window buckets        | <= 10 MB | <= 10 MB           | <= 10 MB          | proofs in flight, transient |

The output key parses to 5.4 MB. Sprout parameters are streamed through BLAKE2b at start and not
kept. glibc arenas are not the cause: `MALLOC_ARENA_MAX=2` leaves the peak at 828 MB and the
retained size after the send at 832 MB; `MALLOC_MMAP_THRESHOLD_=1 MiB` lowers what is retained
(369 MB to 258 MB) without touching the peak. Per-proof state in the transaction builder
(witness bytes, descriptions, a 100-byte context per worker) is a few KB.

## What changed

- The proving keys are parsed once per send and shared by every proof (`librustzcash_compat.c`),
  freed with the last proving context, and the heap is returned to the system then
  (`malloc_trim`, `malloc_zone_pressure_relief`).
- Left automatic, a send makes at most as many proofs at once as fit in about 340 MB or an eighth
  of physical memory (`ProverWorkerLimit`; four since Z23 3e680284b6 was re-vendored, see the last section).
  An explicit `-proverthreads` lifts the cap.
- Z23 patches (`z23-provermem-patch`): constraints stored at exact size (86.9 MB to 25 MB of terms
  per proof in flight) and a parsed-key API. See the lane description.

## z_sendmany peak RSS (MB) and wall time (s)

Default settings (`-proverthreads` not given; 8 threads here), host quiet, 2 rounds interleaved:

| notes / recipients | before            | this branch        | + Z23 patch re-vendored |
|--------------------|-------------------|--------------------|-------------------------|
| 20 / 1             | 847 MB, 8.2-8.3 s | 403 MB, 9.1-9.9 s  | 386 MB, 7.0-7.8 s       |
| 40 / 1             | 859-869 MB, 16.3-16.5 s | 405-408 MB, 17.5-19.2 s | 417 MB, 12.9-15.7 s |
| 40 / 10            | 848 MB, 16.4 s    | 405 MB, 15.3 s     | 386 MB, 14.9 s          |

Explicit `-proverthreads` (workers = threads / 2, no cap), peak RSS in MB (time in s), 1 recipient:

| threads | notes | before        | this branch (4 workers) | + Z23 patch |
|---------|-------|---------------|-------------------------|-------------|
| 1       | 1     | 267 (5.1)     | 270 (4.2)               | 204 (4.1)   |
| 1       | 20    | 274 (60.8)    | 277 (55.6)              | 208 (51.4)  |
| 1       | 40    | 276 (120.5)   | 279 (100.1)             | 209 (119.4) |
| 4       | 5     | 468 (6.1)     | 412 (4.4)               | 289 (5.1)   |
| 4       | 20    | 470 (22.4)    | 416 (14.9)              | 296 (18.2)  |
| 4       | 40    | 471 (31.3)    | 423 (28.2)              | 289 (32.3)  |
| 8       | 5     | 848 (3.0)     | 655 (4.2)               | 397 (4.1)   |
| 8       | 20    | 868 (12.3)    | 672 (10.2)              | 419 (10.1)  |
| 8       | 40    | 922 (19.3)    | 675 (23.4)              | 419 (20.3)  |

(Times in these two tables come from different hours on a busy host; compare within a table.)

Idle footprint (RSS) after the first send of a fresh node, 1 note: before 82 MB, after the send
171 MB and it stays (275 to 370 MB after more sends); this branch 91 MB; with the Z23 patch 83 MB.

Standalone harness (`kat_bench`, one proof per process, peak RSS / median time):

| proof  | threads | before        | this branch   | + Z23 patch   |
|--------|---------|---------------|---------------|---------------|
| spend  | 1       | 241 MB, 2.65 s | 237 MB, 2.82 s | 176 MB, 2.24 s |
| spend  | 4       | 242 MB, 0.95 s | 238 MB, 0.83 s | 178 MB, 0.76 s |
| spend  | 8       | 248 MB, 0.68 s | 243 MB, 0.58 s | 183 MB, 0.52 s |
| output | 1 / 4 / 8 | 69 / 68 / 68 MB | 68 / 67 / 68 MB | 63 / 62 / 62 MB |

A single proof gains nothing from key sharing (it parses once either way); the gain is for sends
with several proofs, which is why the daemon numbers move and these barely do.

## Not done here

See the Z23 lane description: coefficient table for constraint terms, exact `constraints[]`
capacity, MSM over affine key points, and mapping the 52 MB of raw parameter bytes instead of
holding them (idle RSS near 30 MB).

## After the re-vendor (Z23 3e680284b6)

The vendored Z23 now stores constraint terms at exact size and offers
`sapling_create_{spend,output}_proof_parsed`. The glue calls those two functions with the
parsed key it keeps (the raw keys it verified at init are the glue's own, not Z23 params_init's, so
the parsed copy stays in `librustzcash_compat.c`: parsed once on the first proof, freed with the
last proving context). The glue no longer carries its own copy of the proof assembly
(synthesize, `groth16_prove`, proof serialization), and a key that cannot be parsed still falls
back to the per-proof functions. Proof bytes and verification results are unchanged (golden
corpus, below).

`kProverWorkerBytes` is measured, not assumed. Peak RSS of the daemon over `z_sendmany` of 20
notes, explicit `-proverthreads` (workers = threads / 2, no cap), regtest, `z23-r2`:

| threads | proofs in flight | before (15ef1f004) | after | per further proof |
|---------|------------------|--------------------|-------|-------------------|
| 2       | 1                | 266 MB             | 202 MB | |
| 4       | 2                | 391 MB             | 266 MB | 63 MB (was 125) |
| 8       | 4                | 631 MB             | 381 MB | 58 MB (was 120) |
| 16      | 8                | 1110 MB            | 612 MB | 58 MB (was 120) |

`kProverWorkerBytes` goes from 120 MB to 60 MB, so the automatic limit rises from two proofs at
once to four (an eighth of 2 GiB of RAM: two). Default settings (8 prover threads here), median of
three runs, peak RSS in MB (wall time in s), one recipient:

| notes | before (15ef1f004, 2 proofs) | re-vendored, limit still 2 | re-vendored, limit 4 (final) |
|-------|------------------------------|----------------------------|------------------------------|
| 1     | 268 (1.0)                    | 207 (0.9)                  | 206 (0.9)                    |
| 5     | 398 (2.8)                    | 284 (2.6)                  | 374 (2.9)                    |
| 20    | 400 (9.7)                    | 284 (9.5)                  | 396 (8.2)                    |
| 40    | 407 (19.0)                   | 286 (18.8)                 | 395 (16.3)                   |

The limit-4 column spends the same ceiling the earlier branch did (a default send near 400 MB)
for more parallel proofs, and is faster at 20 and 40 notes; the limit-2 column shows what the
exact-size storage alone saves. Times are good to about +-15 % on this shared host.

## Lazy proving parameters

Since the raw Sapling bytes went into the table above as "fixed (process)", the default mode no
longer keeps them (`ZCL_PARAMS_VERIFY`, see `doc/c23-build.md`): init hashes the 51.6 MB Sapling
pair and frees it at once, and only checks the size of `sprout-groth16.params` instead of
streaming its 692 MiB through BLAKE2b. The first proof of a send reads and re-verifies the pair
before parsing it; `ZCL_PARAMS_VERIFY=boot` restores the old behaviour.

Host `z23-r1` (shared, load average 9 to 35), regtest, fresh datadir, `-nuparams` for Sapling at
height 1, warm page cache, two rounds each (both shown). `rchar` is read from `/proc/<pid>/io` from
exec until the log line "Loaded Sapling parameters"; the first start has an empty verified-params
cache, so `init.cpp`'s SHA-256 gate also reads every file; the second start finds the cache warm.
Idle RSS is read 5 s after RPC answers. A send is `z_sendmany` from a transparent address to one
Sapling address (output proofs only), `execution_secs` of the operation.

| | base 8ee9727e7 | this change, lazy (default) | this change, `ZCL_PARAMS_VERIFY=boot` |
|---|---|---|---|
| read to "Loaded Sapling parameters", cold cache | 1554 MB | 829 MB | 1554 MB |
| read to "Loaded Sapling parameters", warm cache | 777 MB | 51.7 MB | 777 MB |
| time to that line, warm cache | 707-741 ms | 93-115 ms | 706 ms |
| shim init ("Loaded Sapling parameters in") | 0.66-0.68 s | 0.058-0.059 s | 0.66 s |
| idle RSS after start | 81.3-82.2 MB | 30.2-30.9 MB | 81.8-81.9 MB |
| RSS after a send | 84.2-84.5 MB | 32.3-33.3 MB | 84.0-84.7 MB |
| first send of the process | 0.133-0.161 s | 0.220-0.244 s | 0.145 s |
| second send | 0.115-0.128 s | 0.195-0.199 s | 0.102 s |
| first send after a restart | 0.145-0.165 s | 0.227-0.234 s | 0.135 s |

So start-up reads 725 MB less per start, the shim's part of start-up falls from 0.67 s to 0.06 s,
an idle node holds about 51 MB less, and each send pays 60 to 100 ms to read, hash and parse the
Sapling pair again (every send, because the parsed keys are released with the send's last proving
context, as before). The first Sprout proof of a process additionally hashes the Sprout file once
(about 0.6 s here, what the boot-mode init spent on it). In the standalone shim smoke (`compat_smoke`, warm cache) init went from 703 ms
to 62 ms and the first spend proof from 531 ms to 599 ms.
