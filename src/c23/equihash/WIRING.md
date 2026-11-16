# Build wiring for the C23 Equihash verifier and the Equihash memo (unit p1-equihash)

Branch `unit/p1-equihash` already carries these lines; this file lists them so the
build-wiring unit (U7) can apply them to the shared tree exactly.

## src/Makefile.am

1. Library variable, next to `LIBZCASH=libzcash.a`:

       LIBZC23_EQUIHASH=libzc23_equihash.a

2. Append `$(LIBZC23_EQUIHASH)` to `EXTRA_LIBRARIES` (after `$(LIBZCASH)`).

3. `BITCOIN_CORE_H`: add `equihashmemo.h`.
   `libbitcoin_server_a_SOURCES`: add `equihashmemo.cpp`.

4. `zclassicd_LDADD`: add `$(LIBZC23_EQUIHASH)` after `$(LIBZCASH)` (any position
   after `$(LIBBITCOIN_SERVER)` works; only `pow.cpp` references it).

5. The library itself (C, not C++):

       libzc23_equihash_a_SOURCES = \
         c23/equihash/zc23_equihash.c \
         c23/equihash/zc23_equihash.h \
         c23/equihash/glue/util/log_macros.h \
         c23/equihash/glue/util/safe_alloc.h \
         c23/equihash/glue/zc23_eh_namespace.h \
         c23/equihash/vendor/core/modules/crypto/include/crypto/blake2b.h \
         c23/equihash/vendor/core/modules/crypto/include/crypto/equihash.h \
         c23/equihash/vendor/core/modules/crypto/include/crypto/simd_dispatch.h \
         c23/equihash/vendor/core/modules/crypto/src/blake2b.c \
         c23/equihash/vendor/core/modules/crypto/src/blake2b_avx2.c \
         c23/equihash/vendor/core/modules/crypto/src/equihash.c \
         c23/equihash/vendor/core/modules/crypto/src/simd_dispatch.c
       libzc23_equihash_a_CPPFLAGS = $(AM_CPPFLAGS) \
         -include $(srcdir)/c23/equihash/glue/zc23_eh_namespace.h \
         -iquote $(srcdir)/c23/equihash/glue \
         -iquote $(srcdir)/c23/equihash/vendor/core/modules/crypto/include \
         -iquote $(srcdir)/c23/equihash
       libzc23_equihash_a_CFLAGS = -std=gnu17 -fno-strict-aliasing $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) $(PIE_FLAGS)

   Why each flag:
   - `-iquote` (not `-I`): automake puts `-I. -I$(srcdir)` (= `src/`) first, so with `-I`
     the vendored `#include "crypto/equihash.h"` would pick up zclassicd's C++
     `src/crypto/equihash.h`. `-iquote` directories are searched before `-I` ones for
     quoted includes.
   - `-include .../zc23_eh_namespace.h`: **libsodium exports unprefixed `blake2b_init`,
     `blake2b_init_param`, `blake2b_init_salt_personal`, `blake2b_init_key`,
     `blake2b_update`, `blake2b_final` and `blake2b`** (its internal reference BLAKE2b,
     different signatures). Without the rename the zclassicd link fails with "multiple
     definition" (observed on z23-r2). The header renames every symbol the vendored
     files define into `zc23eh_*` without editing a vendored byte.
     `check-vendor.sh <lib>` fails if any exported symbol is unprefixed.
     The same collision will hit U1/U3 when they vendor `blake2b.c` for Sapling
     (report 02 section 5.3 assumed libsodium is prefixed; it is not for these names).
   - `-std=gnu17`: the release toolchains (GCC 9.4, mingw 9.3) have no `-std=c23`.
     The vendored Equihash files need only `<stdatomic.h>`, `<stdbool.h>`, GNU
     `__attribute__((target(...)))` and `__builtin_bswap32`; no `__VA_OPT__` reaches
     them (the glue `log_macros.h` uses `, ##__VA_ARGS__`).

## src/Makefile.test.include

    BITCOIN_TESTS += test/equihashmemo_tests.cpp        (in the list)
    test_test_bitcoin_LDADD += $(LIBZC23_EQUIHASH)      (after the existing LDADD lines)

## src/Makefile.gtest.include

    zcash_gtest_SOURCES += gtest/test_equihash_c23.cpp  (in the list)
    zcash_gtest_LDADD += $(LIBZC23_EQUIHASH)            (after the existing LDADD lines)

`gtest/test_equihash_c23.cpp` includes `gtest/data/equihash_mainnet_192_7.inc` (real
mainnet headers). Add it to `EXTRA_DIST` if `make dist` is used.

## Files this unit adds or changes

- `src/pow.cpp`, `src/pow.h`: verifier selection, differential mode, memo wrapper.
- `src/main.cpp`: `CheckBlockHeader` and `ReadBlockFromDisk(CBlock&, const CDiskBlockPos&, bool)`
  call `CheckEquihashSolutionMemo` instead of `CheckEquihashSolution` (2 lines).
- `src/equihashmemo.{h,cpp}`: the bounded positive-result memo.
- `src/c23/equihash/**`: vendored Z23 files (`Z23_SOURCE.tsv`), glue, bridge, `check-vendor.sh`,
  `test/eh_headers_check.c` (standalone C check, not built by automake).
- `src/test/equihashmemo_tests.cpp`, `src/gtest/test_equihash_c23.cpp`,
  `src/gtest/data/equihash_mainnet_192_7.inc`.

## Optional (not owned by this unit)

- `src/init.cpp`: call `InitEquihashOptions()` right after `ParseParameters` /
  `ReadConfigFile` so the three hidden options are read on the init thread rather than
  lazily by the first header check, and list them under `-help-debug`:
  `-equihashimpl=<cpp|c23>`, `-equihashdifferential`, `-equihashmemo` (default 1).
  Without this the options still work (read once, under `std::call_once`, on the first
  Equihash check, which in practice is the genesis check during `InitBlockIndex`).

## Interaction with other units

- U1 vendors `core/modules/crypto/src/blake2b.c` and `simd_dispatch.c` (and their
  headers) for Sapling. They are the same blobs as here (see `Z23_SOURCE.tsv`). Because
  this library renames its copies to `zc23eh_*`, both copies can link side by side; once
  U1's copy is also namespaced, U7 may drop the duplicates here and point this library at
  U1's tree instead, re-running `check-vendor.sh`.
- Windows/MinGW: `blake2b_avx2.c` uses `__attribute__((target("avx2"/"avx512f")))` with
  256/512-bit locals. GCC on Windows x64 does not realign the stack for 32/64-byte
  spills (GCC bug 54412). Checked: `test/eh_headers_check.c` built with msys64 UCRT
  GCC 16.2 and clang 22 at -O2 runs clean on an AVX2 Windows host (i9-9900K) over
  68,436 real mainnet headers, scalar and AVX2 tiers. NOT checked: the release
  toolchain (mingw-w64 GCC 9.3 from depends). Run the same check with that toolchain
  on Windows before shipping a Windows build; if it fails, build Windows with
  `-equihashimpl` defaulting to cpp (one-line change of DEFAULT_EQUIHASH_IMPL under
  `#ifdef WIN32`), or compile `blake2b_avx2.c` with `-mno-avx` style tier removal.
