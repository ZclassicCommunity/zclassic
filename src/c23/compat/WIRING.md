# Build wiring for the librustzcash C ABI shim (unit U3)

Nothing here is applied by unit U3. `configure.ac` and `Makefile*.am` are untouched.
Paths are relative to `src/`. Read together with `c23/glue/WIRING.md` (units U1/U2),
which defines `libzcl_c23.a`, its CPPFLAGS/CFLAGS and the link order. The Automake text
below is UNTESTED until the build-switch unit (U7) runs autogen.

## 1. Add the shim to libzcl_c23.a

```make
libzcl_c23_a_SOURCES += \
  c23/compat/librustzcash_compat.c \
  c23/compat/witness_codec.c \
  c23/compat/zip32_codec.c

# The shim includes its own headers by quote; vendored headers come from the
# libzcl_c23 -I set already listed in c23/glue/WIRING.md.
libzcl_c23_a_CPPFLAGS += -I$(srcdir)/c23/compat
```

Same `libzcl_c23_a_CFLAGS` as the vendored set (`-std=gnu17 -O3 -include
c23/glue/zcl_c23_compat.h -fomit-frame-pointer -fno-strict-aliasing
-fvisibility=hidden ...`). Never define `ZCL_TESTING`.

`-fvisibility=hidden` is fine: `librustzcash_compat.c` wraps its `#include
"librustzcash.h"` in `#pragma GCC visibility push(default)`, so the 31 `librustzcash_*`
symbols and the `zcl_c23_*` extras keep default visibility (ELF). Static linking does
not depend on it either way.

## 2. Put the replacement header on the C++ include path

All existing call sites say `#include "librustzcash.h"` or `<librustzcash.h>` and must
compile unchanged. Add to the C++ preprocessor flags of every target that compiled
against the Rust header (libbitcoin_server, libbitcoin_wallet, libbitcoin_common,
libzcash, zcash-gtest, test_bitcoin, the zcbenchmarks object in zclassicd):

```make
AM_CPPFLAGS += -I$(srcdir)/c23/compat
```

and remove the depends `include/librustzcash.h` (it disappears with U9; while both
exist, `-I$(srcdir)/c23/compat` must come BEFORE the depends include dir). Only
`c23/compat` goes on the C++ path. Never add `c23/glue/chain` or any `c23/vendor/...`
include dir to C++ targets: their header names (`chainparams.h`, `crypto/sha256.h`,
`uint256.h`) collide with zclassicd's.

The header is C and C++ (it has its own `extern "C"` guard, `<stdbool.h>` for C).
`codeunit` is `uint16_t` when `WIN32` or `_WIN32` is defined, `uint8_t` otherwise;
`init.cpp`, `gtest/main.cpp` and `test/test_bitcoin.cpp` keep their
`static_assert(sizeof(path::value_type) == sizeof(codeunit))`, verified by
`compat/test/abi_cxx_check.cpp`.

## 3. Sprout prover symbol (separately linked)

`librustzcash_sprout_prove` forwards to `zc23_sprout_prove(...)` and init calls
`zc23_sprout_prover_set_params_path(utf8_path)`. Both are ordinary external symbols
defined by `c23/sprout_prover/sprout_prove.c` (another unit). The daemon build must
add that unit's sources to `libzcl_c23_a_SOURCES` (see its own WIRING notes); until
then the link fails with an undefined `zc23_sprout_prove`, which is the intended
loud failure. No weak symbol is used (weak undefined symbols are unreliable on PE/COFF).

`librustzcash_compat.c` includes `../sprout_prover/sprout_prover.h` when it exists
(`__has_include`), so a signature change there is a compile error here. If the header
is absent it declares the two prototypes itself.

TEST-ONLY: `compat/test/sprout_prove_stub_test.c` defines both symbols (the path is
recorded, proving aborts with a clear message). It is linked only by
`compat/test/build-smoke.sh`. Never add it to any Makefile.

## 4. Startup sequence in the daemon

No call-site change. `librustzcash_init_zksnark_params` (init.cpp `ZC_LoadParams`)
does what librustzcash does (rustzcash.rs:191-280):

1. warms every lazily initialised vendored constant and the CPU dispatch (Montgomery
   multiply pointers, `FR_JUB_D`, fixed generators, Pedersen tables) before any
   validation thread runs;
2. checks that the three hash strings are valid UTF-8, then opens the three files in
   Rust's order (any file names, any directories);
3. reads every byte of all three files through BLAKE2b-512 (the 692 MiB Sprout file on
   a second thread while the Sapling pair is read) and compares each lowercase-hex
   digest with the caller's string, spend, output, Sprout; a read error or a mismatch
   aborts with librustzcash's message. The C23 build then also requires the caller's
   digests to be the canonical ones (it carries the canonical verifying keys compiled
   in); zclassicd always passes those;
4. installs the compiled-in verifying keys (`sapling_install_embedded_vks`, SHA-256
   pinned; they are the leading bytes of the files just verified); failure aborts;
5. keeps the verified bytes of `sapling-spend.params` and `sapling-output.params`
   (51 MB) resident as the proving keys for the life of the process, as Rust keeps its
   parsed `Parameters`, and hands the `sprout-groth16.params` path (UTF-8) to the
   Sprout prover.

   The parsed form of those keys (about 77 MB of curve points) is not kept: the first proof of
   a send parses it once, every proof of every proving context reads that copy, and the last
   proving context to be freed releases it and returns the heap to the system. Left
   automatic, a send also limits the proofs it makes at once (`ProverWorkerLimit`); see
   `doc/perf/prover-memory.md`.

Measured on Windows (gcc 16, warm page cache): init 0.84 s. Proving never reads a file
again, so the first spend proof of a send costs the same as any other.

Logging: call `zcl_c23_log_refresh()` after argument parsing (c23/glue/WIRING.md).

## 5. Platform notes

- Windows: init opens the UTF-16 paths directly (`CreateFileW` with Rust's share mode
  and `FILE_FLAG_BACKUP_SEMANTICS`, then `ReadFile`), so non-ASCII profile paths need no
  code-page or 8.3 handling. The Sprout path is converted to UTF-8 for the Sprout
  prover; a path with a lone surrogate aborts there. Link needs only kernel32
  (CreateFileW, ReadFile, CloseHandle, WideCharToMultiByte) and winpthread, already in
  every mingw link.
- POSIX: paths are bytes, as in Rust. `_POSIX_C_SOURCE` is defined inside the shim
  source only when the build did not define it (needed for `open` under strict
  `-std=c23`; the production `-std=gnu17` does not need it).

## 6. What to run after wiring

- `nm -g zclassicd | grep -c ' T librustzcash_'` must print 31 (32 Rust names minus
  the never-called `eh_isvalid`), and no `librustzcash` archive may be on the link line.
- The standalone proof: `sh src/c23/compat/test/build-smoke.sh <cc> -std=gnu17 <out> <cxx>`,
  then `<out>/compat_smoke <params-dir>` (122 checks) and
  `sh src/c23/compat/test/run-abort-cases.sh <out>/compat_smoke <params-dir>` (10 cases).
