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
-fvisibility=hidden ...`). Never define `ZCL_C23_COMPAT_TESTING` (it compiles in a
test hook that forces the Windows full-set loader) and never define `ZCL_TESTING`.

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
now:

1. warms every lazily initialised vendored constant and the CPU dispatch (Montgomery
   multiply pointers, `FR_JUB_D`, fixed generators, Pedersen tables) before any
   validation thread runs;
2. checks the three hash strings (valid UTF-8, equal to the canonical BLAKE2b
   digests), opens the three files and checks their exact sizes; any failure aborts
   with librustzcash's message;
3. installs the compiled-in verifying keys (`sapling_install_embedded_vks`, SHA-256
   pinned); failure aborts;
4. notes the parameter directory for on-demand Sapling proving, and hands the
   `sprout-groth16.params` path (UTF-8) to the Sprout prover.

Nothing reads the 777 MB of parameter files at startup any more. The Sapling pair
(51 MB) is read, SHA-512 pinned and self-tested on the first spend/output proof of a
send, and released when the last proving context of that send is freed.

Logging: call `zcl_c23_log_refresh()` after argument parsing (c23/glue/WIRING.md).
The shim's own rare operator notes (proving refused, with a static reason code) go
through `zcl_log_emit_at` unconditionally.

## 5. Platform notes

- Windows: init converts the UTF-16 paths. The Z23 pair loader uses narrow `stat()`
  (ANSI code page) and UTF-8 `_wopen`; the shim hands it the directory as ASCII, its
  ASCII 8.3 short name, or UTF-8 when `GetACP() == CP_UTF8`. When none exists (8.3
  names disabled on a non-ASCII profile path), the first proof uses the full-set loader
  (`sapling_init_params`, UTF-8 only), which reads and pins all four files once and
  keeps the proving keys for the process. Link needs only kernel32 (CreateFileW,
  GetFileSizeEx, GetShortPathNameW, GetACP, WideCharToMultiByte), already in every
  mingw link.
- POSIX: paths are bytes, as in Rust. `_POSIX_C_SOURCE` is defined inside the shim
  source only when the build did not define it (needed for `open`/`fstat` under strict
  `-std=c23`; the production `-std=gnu17` does not need it).

## 6. What to run after wiring

- `nm -g zclassicd | grep -c ' T librustzcash_'` must print 31 (32 Rust names minus
  the never-called `eh_isvalid`), and no `librustzcash` archive may be on the link line.
- The standalone proof: `sh src/c23/compat/test/build-smoke.sh <cc> -std=gnu17 <out> <cxx>`,
  then `<out>/compat_smoke <params-dir>` (111 checks) and
  `sh src/c23/compat/test/run-abort-cases.sh <out>/compat_smoke <params-dir>` (10 cases).
