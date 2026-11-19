# Building zclassicd on the C23 crypto core

zclassicd no longer links `librustzcash.a`. The Sapling and Sprout-Groth16
functions it calls (`librustzcash_*`, 31 of them) come from `src/c23`, built
into `src/libzcl_c23.a` by `src/Makefile.am`. No Rust toolchain or Rust
library takes part in the link.

## What is built

| archive | contents | language |
|---|---|---|
| `libzcl_c23.a` | `c23/vendor` (Z23, verbatim), `c23/glue`, `c23/compat` (the ABI shim), `c23/sprout_prover` | C |
| `libzcl_c23_seam.a` | `c23/glue/zcl_c23_log.cpp`: `LogPrintStr`, `-debug=zc23`, network id | C++ |
| `libzcl_tokenguard.a` | `c23/services`: Z23's SLP wire parser (verbatim) and the wallet token-guard glue; part of `$(LIBBITCOIN_WALLET)`. Own pin and manifest `c23/services/Z23_SOURCE.tsv`; same language level and symbol-prefix scheme as the core (`glue/zcl_tokenguard_symbol_prefix.h`) | C |
| `libzcl_tor.a` | `c23/tor`: the daemon's own C code (owner-only key files; with embedded Tor the launcher and the in-process/child runner). Not vendored Z23. Globals are `zcl_tor_*`/`zcl_keyfile_*`. Listed as `$(ZCL_TOR_LIBS)` right after `libbitcoin_server.a`, with libtor and its helper archives when embedded Tor is built | C |

Both are listed as `$(LIBZCL_C23)`, after every library that calls
`librustzcash_*` and before `-lsodium -lcrypto`. `zclassic-cli` does not link them.

Embedded Tor itself (`libtor.a` and three helper archives) comes from depends and keeps Tor's own
global names; `make check-c23-tor-symbols TOR_LIBDIR=<depends prefix>/lib` proves no other
archive of the daemon defines one. `make check-c23-vendor` verifies both vendored manifests
(`c23/Z23_SOURCE.tsv` and `c23/services/Z23_SOURCE.tsv`).

## Rules the Makefile enforces

- **Header.** `-I$(srcdir)/c23/compat` is first in `AM_CPPFLAGS`, so
  `#include "librustzcash.h"` is the shim header.
- **Include isolation.** The Z23 include directories are given to the C objects
  only, and Automake's `-I.` is removed for them. Z23 has `chainparams.h`,
  `crypto/sha256.h`, `crypto/sha512.h`, `uint256.h`; so does zclassicd.
- **Symbol prefix.** Every object of `libzcl_c23.a` is compiled with
  `-include c23/glue/zcl_c23_symbol_prefix.h`, which renames each internal
  global to `zc23_<name>`. Z23 and libsodium both export `blake2b_init`,
  `blake2b_update`, `blake2b_final`, `blake2b` (different state layouts); a
  static link either fails with "multiple definition" or binds one library's
  callers to the other's function. `c23-symbols.stamp` runs
  `c23/tools/symbol-prefix.sh check` on the archive and every program that
  links it depends on that stamp. After re-vendoring, if the check names a new
  symbol: `sh src/c23/tools/symbol-prefix.sh gen nm src/libzcl_c23.a
  src/c23/glue/zcl_c23_symbol_prefix.h`, rebuild, commit the header.
- **Language level.** configure compiles a C23 probe with `-std=c23
  -D_GNU_SOURCE`. If it works that is used; otherwise `-std=gnu17` (the
  force-included `c23/glue/zcl_c23_compat.h` supplies the C23 spellings).
  `-D_GNU_SOURCE` is passed in both modes (glibc needs it for the Sprout
  prover's `sched_getaffinity`). Override: `./configure ZCL_C23_STD=-std=gnu17`.
  GCC 14.2 takes the C23 path. mingw-w64 GCC 13 has no `-std=c23` and takes
  gnu17 (the core compiles there with no diagnostics; that was a standalone
  cross compile, a full mingw configure run needs a mingw `depends` prefix).
- **Optimisation.** The C23 objects always end with `-O3`, whatever `CFLAGS`
  says. Release `CFLAGS`/`CXXFLAGS` from `depends` are `-O3` on Linux, Windows
  and macOS. A prefix built before
  this change has `-O2` in `share/config.site` of the depends prefix (from `depends/config.site.in`); rebuild `depends` or the <!-- doc-path-ok -->
  daemon's C++ stays at `-O2`.
- **No `-march`.** Nothing in the release flags selects an instruction set.
  The core picks ADX/BMI2, AVX2, AVX-512 and SHA-NI code at run time
  (`simd_dispatch.c`); those functions carry `target` attributes.
  `-fomit-frame-pointer` is required by the ADX inline assembly.
- **Hardening** is unchanged and now covers the C objects too:
  `-fstack-protector-all`, `-D_FORTIFY_SOURCE=2`, `-fPIE`/`-pie`, RELRO, BIND_NOW.

## Checks

```sh
make -C src check-c23-no-rust     # 31 librustzcash_* from the shim, 0 Rust symbols, per binary
make -C src check-c23-vendor      # vendored files match Z23_SOURCE.tsv
make -C src check-tools-vendor    # zcutil/tools/vendor (jsonq) matches zcutil/tools/Z23_SOURCE.tsv
sh src/c23/test/run.sh --out <dir> --linked src/libzcl_c23.a --deps <depends prefix> \
    --golden <c23_golden>         # KAT replay + mutations + threads against the linked archive
sh src/c23/test/regtest-smoke.sh --bin src --work <empty dir> [--peer-bin <other build>/src]
sh src/c23/test/params-smoke.sh --bin src --work <empty dir>
ZCL_MAINNET_BLK_FILES=<copy of blkNNNNN.dat>[:...] ZCL_MAINNET_BLK_THREADS=8 \
    src/zcash-gtest --gtest_filter='MainnetBlocks.*'
```

## Parameters at startup

`init.cpp` is unchanged: its SHA-256 gate runs first, then
`librustzcash_init_zksnark_params` (now the shim) checks the three Groth16
parameter files against the same BLAKE2b-512 digests as before and aborts with
librustzcash's wording, prefixed `librustzcash (C23):` instead of Rust's
`thread '<unnamed>' panicked at`.

The verifying keys are compiled in, so the files matter only for proving, and
how much init reads depends on the environment variable `ZCL_PARAMS_VERIFY`
(`src/c23/compat/zcl_params_lazy.h`):

- unset or anything but `boot` (lazy, the default): init hashes the Sapling
  spend and output files (51.6 MB) and keeps none of their bytes, and checks
  only that `sprout-groth16.params` opens and has its canonical size. A missing,
  unreadable or wrong Sapling file and a missing or wrong-size Sprout file still
  abort at start-up. The log says
  `zc23: zk params: verify mode lazy (Sprout and Sapling proving bytes are verified at first proof)`.
  The first Sapling proof of a send reads both Sapling files again, requires the
  init-time digest, parses them and frees the raw bytes; the parsed keys are
  shared by the send and released with its last proving context. A file that
  changed since start-up refuses the proof (the send fails with "Spend proof
  failed" or "Output proof failed", logged once as "Sapling proving parameters
  changed on disk since start-up; refusing to prove"). Before the first Sprout
  proof `zcl_c23_sprout_params_ready` hashes `sprout-groth16.params` once (again
  only if its device, inode, size or times change). The Sprout prover has no
  failure value, so a wrong file aborts the node there with the same advice as
  the boot-time check (`src/zcash/JoinSplit.cpp` is consensus-sealed, so turning
  this into an RPC error is left for a sealed change or a wallet-side caller).
- `boot`: exactly the old behaviour: all three files hashed at init (the 692 MiB
  Sprout file on a second thread), any mismatch aborts, and the raw Sapling
  bytes stay resident for the life of the process.

Measurements are in [perf/prover-memory.md](perf/prover-memory.md).

## LTO: measured, not enabled

`libzcl_c23_a_CFLAGS` ends with `$(ZCL_C23_LTO_CFLAGS)`, empty by default.
Measured on x86_64 Linux, GCC 14.2, `-O3` against `-O3 -flto` for the whole
core and its test driver (`kat_bench`, same golden inputs, median per call):

| op | -O3 | -O3 -flto |
|---|---|---|
| check_spend | 2.86 ms | 3.06 ms |
| check_output | 2.66 ms | 2.82 ms |
| sprout_verify | 2.67 ms | 2.83 ms |
| merkle_hash | 43.2 us | 45.4 us |
| final_check | 252 us | 269 us |

That is the quietest of three interleaved rounds: LTO was 5-7% slower on every
verification op. The other two rounds ran under heavy host load and went
either way (one LTO-slower, one LTO-faster), so no gain was demonstrated. On
Linux both variants were bit-for-bit reproducible when rebuilt in the same
directory. With the mingw-w64 GCC 13 cross compiler the core compiles and
links with `-flto`, but reproducibility there is unproven: the test link
differed between two builds with and without LTO alike (the PE timestamp was
not pinned). With no measured gain, LTO stays off.
To try it again (untested through Automake):
`make ZCL_C23_LTO_CFLAGS="-flto -ffat-lto-objects" AR=gcc-ar RANLIB=gcc-ranlib`.

## Performance against the Rust build

Same host, same golden inputs, interleaved runs of `c23/test/kat_bench` linked
against `libzcl_c23.a` and against `librustzcash.a` (median per call, the
quietest of three rounds; the host was shared and loaded):

| op | Rust | C23 |
|---|---|---|
| check_spend | 3.75 ms | 3.03 ms |
| check_output | 3.42 ms | 2.82 ms |
| sprout_verify (Groth16) | 3.77 ms | 2.82 ms |
| final_check | 200 us | 267 us |
| merkle_hash | 21.5 us | 45.5 us |
| compute_cm | 191 us | 257 us |
| ivk_to_pkd | 90 us | 102 us |
| ka_agree | 88 us | 104 us |
| spend_proof | 0.47 s | 8.97 s |
| output_proof | 0.11 s | 1.32 s |

Groth16 verification is about 20% faster than librustzcash. The
Jubjub/Pedersen operations are 13% to 2.1x slower; `merkle_hash` is what the
note commitment tree calls for every append and root. Proof creation is 8x
to 19x slower across the rounds (`zcbenchmark createsaplingspend`: 8.65 s
against 0.45-0.83 s): `groth16_prover.c` loads the proving key again for every
proof and prints `Proving key loaded: ...` to stdout each time.

## Wallet trial decryption

Every Sapling output a wallet sees (each block it connects, each mempool
transaction, each `-rescan` / key import) is trial-decrypted against every
incoming viewing key. The cost per (key, output) pair is one Jubjub scalar
multiplication, so it grows with keys x outputs; `ka_agree` above is that
operation, about 70-110 us.

`c23/glue/zcl_c23_sapling_scan.c` (zclassicd glue, not vendored; a candidate
to upstream into Z23, which trial-decrypts one key at a time) does the work
for one output against many keys at once: the output's `epk` is decompressed
once (no inversion, square root with precomputed roots of unity), a signed
radix-16 comb of affine multiples of `[8] epk` is built once, each key costs 64
mixed additions plus a few doublings (none with many keys), and the results
share one inversion. `SaplingNotePlaintext::decryptWithFirstMatchingIvk` then
runs the unchanged KDF, AEAD and note validation in key order, so the first
matching key wins exactly as before. `CWallet::TrialDecryptSaplingOutput`
uses it, which covers block connect, mempool and the parallel rescan. The
core is constant time in the key, like `jub_scalar_mul`, and checks itself
against the vendored primitives at first use; if that fails the one-at-a-time
path is used.

Per (key, output), best of 7 per output on a shared host (`SaplingScanBatch.
PerOutputCostBreakdown` in `zcash-gtest`):

| keys | one at a time | batched |
|---|---|---|
| 1 | 68-77 us | 56 us |
| 3 | | 31 us |
| 10 | | 17 us |
| 50 | | 11 us |
| 200 | | 9 us |

Real mainnet blocks (the last five `blk*.dat` files, 691,020 blocks,
46,229 Sapling outputs, about 0.07 outputs per block; trial decryption only,
`SaplingScanBatch.MainnetOutputsAgreeAndTiming`):

| keys | one at a time | batched |
|---|---|---|
| 1 | 78 us/pair, 192k blocks/s | 63 us/pair, 236k blocks/s |
| 20 | 83 us/pair, 9.0k blocks/s | 17 us/pair, 44k blocks/s |

Regtest wallet rescan, 2581 blocks, 4800 outputs sent to the wallet's keys
and to foreign keys, `-par=1` (CPU seconds of the whole process, startup
included; the identical notes and balances are checked by hash):

| keys | before | after |
|---|---|---|
| 10 | 6.6 s | 3.3 s |
| 50 | 21.7 s | 6.1 s |
| 200 | 68 s | 17 s |

Tests: `src/gtest/test_sapling_scan_batch.cpp` compares the batched path with
`librustzcash_sapling_ka_agree` and with the serial `decrypt` loop on random
and edge inputs, replays the 2028 Rust-oracle golden `ka_agree` records
(`ZCL_C23_GOLDEN_DIR`) and compares every epk of real mainnet blocks
(`ZCL_MAINNET_BLK_FILES`, read from copies). `c23/test/kat_threads.c` replays
the golden records through the batched core from 16 threads (clean under
`-fsanitize=thread`, run with `setarch x86_64 -R`).
