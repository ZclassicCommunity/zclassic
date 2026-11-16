# Build wiring for libzcl_c23.a (for the later build-switch unit)

APPLIED by the build switch. This file is the original plan; `doc/c23-build.md`
describes the build as it is. Where they differ, the build is right:

- the C objects are compiled with Automake's `-I.` removed (it shadowed Z23's
  `crypto/sha512.h`), and with `c23/glue/zcl_c23_symbol_prefix.h` force-included
  (every internal global is `zc23_<name>`; libsodium.a exports `blake2b_init` etc.);
- the language level is chosen by configure (`-std=c23 -D_GNU_SOURCE` or `-std=gnu17`);
- `zcl_c23_log.cpp` lives in its own `libzcl_c23_seam.a`, listed right after
  `libzcl_c23.a`, not in `libbitcoin_util.a` (it needs `Params()` from common).

Nothing here is applied by unit U1/U2. `configure.ac` and `Makefile*.am` are untouched.
All paths are relative to `src/`. Everything below was proven with the standalone
`tools/build-check.sh` (see README.md); the Automake text itself is UNTESTED until
the build-switch unit runs autogen.

## configure.ac

1. Add `AC_PROG_CC` right after `AC_PROG_CXX` (line 56). Today the C compiler only
   appears through `LT_INIT`.
2. Add a 64-bit and `__int128` check that errors out with a clear message:
   `AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
   _Static_assert(sizeof(void*)==8 && sizeof(unsigned __int128)==16, "need 64-bit");
   ]])],,[AC_MSG_ERROR([the C23 crypto core needs a 64-bit target with __int128 (no i686)])])`
   (the force-included `zcl_c23_compat.h` already enforces this at compile time, little-endian too).
3. Remove `RUST_LIBS`, its `-ldl` addition and `$RUST_LIBS` in `LIBZCASH_LIBS` (later unit).
4. Do NOT add any `-march`/`-mavx*`/`-mbmi*` flag. ADX/BMI2/AVX2 dispatch is at run time.

## src/Makefile.am

```make
noinst_LIBRARIES += libzcl_c23.a
LIBZCL_C23 = libzcl_c23.a

libzcl_c23_a_SOURCES = \
  c23/glue/zcl_c23_glue.c \
  c23/glue/zcl_c23_stubs.c \
  c23/glue/zcl_c23_tree_selftest.c \
  c23/vendor/core/modules/crypto/src/aes256.c \
  c23/vendor/core/modules/crypto/src/blake2b.c \
  c23/vendor/core/modules/crypto/src/blake2s.c \
  c23/vendor/core/modules/crypto/src/random_secret.c \
  c23/vendor/core/modules/crypto/src/sha256.c \
  c23/vendor/core/modules/crypto/src/sha512.c \
  c23/vendor/core/modules/crypto/src/simd_dispatch.c \
  c23/vendor/core/modules/sapling/src/bls12_381.c \
  c23/vendor/core/modules/sapling/src/bn254.c \
  c23/vendor/core/modules/sapling/src/bn254_accel.c \
  c23/vendor/core/modules/sapling/src/circuit_bits.c \
  c23/vendor/core/modules/sapling/src/circuit_gadgets.c \
  c23/vendor/core/modules/sapling/src/circuit_merkle.c \
  c23/vendor/core/modules/sapling/src/circuit_pedersen.c \
  c23/vendor/core/modules/sapling/src/circuit_spend.c \
  c23/vendor/core/modules/sapling/src/ff1.c \
  c23/vendor/core/modules/sapling/src/fr.c \
  c23/vendor/core/modules/sapling/src/fr_avx512.c \
  c23/vendor/core/modules/sapling/src/groth16_prover.c \
  c23/vendor/core/modules/sapling/src/jubjub.c \
  c23/vendor/core/modules/sapling/src/msm_parallel.c \
  c23/vendor/core/modules/sapling/src/params_init.c \
  c23/vendor/core/modules/sapling/src/params_vk_embedded.c \
  c23/vendor/core/modules/sapling/src/pedersen_hash.c \
  c23/vendor/core/modules/sapling/src/sapling.c \
  c23/vendor/core/modules/sapling/src/sapling_circuit.c \
  c23/vendor/core/modules/sapling/src/sapling_prover_c23.c \
  c23/vendor/core/modules/sapling/src/sapling_prover_native.c \
  c23/vendor/core/modules/sapling/src/sprout.c \
  c23/vendor/core/modules/sapling/src/zip32.c \
  c23/vendor/platform/modules/base/src/safe_alloc.c \
  c23/vendor/platform/modules/encoding/src/utilstrencodings.c \
  c23/vendor/platform/modules/platform/src/file_stream.c \
  c23/vendor/platform/modules/util/src/file_io.c
# + the compat adapters of unit U3 (c23/compat/librustzcash_compat.c)

# Include ORDER matters only in that glue comes first (its chain/chainparams.h and
# zcl_c23_compat.h must win). Z23 header names (crypto/sha256.h, core/uint256.h, ...)
# collide with zclassicd's own, so this -I set is for the C library ONLY and must
# never reach C++ targets. C++ code includes only c23/compat/librustzcash.h.
libzcl_c23_a_CPPFLAGS = \
  -I$(srcdir)/c23/glue -I$(srcdir)/c23/glue/chain \
  -I$(srcdir)/c23/vendor/core/modules/sapling/include \
  -I$(srcdir)/c23/vendor/core/modules/sapling/src \
  -I$(srcdir)/c23/vendor/core/modules/crypto/include \
  -I$(srcdir)/c23/vendor/core/modules/core/include \
  -I$(srcdir)/c23/vendor/core/math/include \
  -I$(srcdir)/c23/vendor/platform/modules/base/include \
  -I$(srcdir)/c23/vendor/platform/modules/util/include \
  -I$(srcdir)/c23/vendor/platform/modules/support/include \
  -I$(srcdir)/c23/vendor/platform/modules/platform/include \
  -I$(srcdir)/c23/vendor/platform/modules/encoding/include

# -O3 per the owner's performance instruction. -std=gnu17 + the force-include is the
# one spelling that works on GCC 9.4, mingw-w64 9.3 and Apple clang (no -std=c23
# there). -fomit-frame-pointer is required by the ADX inline asm (mont_adx.h needs a
# spare GPR; with a frame pointer reserved it fails to compile). Never -DZCL_TESTING.
# Never define ZCL_FUZZ_QUIET_LOG_MACROS. $(PIC_FLAGS)/$(PIE_FLAGS)/$(HARDENED_*) as libzcash_a.
libzcl_c23_a_CFLAGS = -std=gnu17 -O3 -include $(srcdir)/c23/glue/zcl_c23_compat.h \
  -fomit-frame-pointer -fno-strict-aliasing -fvisibility=hidden \
  $(PIC_FLAGS) $(PIE_FLAGS) $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS)

# The adapter symbols that C++ calls (librustzcash_*) must NOT be hidden: mark them
# with __attribute__((visibility("default"))) in librustzcash_compat.c (unit U3).
```

Notes:

- `-O3` last-wins: Automake places `$(CFLAGS)` (depends supplies `-O2`) AFTER per-target
  `_CFLAGS`, so `-O2` would override. Either have the build-switch unit filter `-O2` out
  of the CFLAGS used for this target (preferred: `libzcl_c23_a_CFLAGS` ends with `-O3`
  and use `$(subst -O2,,$(CFLAGS))`-style override), or confirm the final command line.
  UNVERIFIED until the first real build.
- `-Wall -Wextra` is NOT in the stanza: vendored code is warning-free at `-Wall -Wextra`
  on gcc 9.5/13/14/16 and clang 18/19/22 (proof in README.md). Add them only if the project
  wants the gate in CI; never add `-Werror` on third-party compilers not tested here.
- Do not pass `-D_POSIX_C_SOURCE`: unneeded at gnu17 (verified) and it hides BSD
  declarations on Darwin.
- Standalone Windows tests use `c23/glue/zcl_c23_test_glue.c` INSTEAD of
  `zcl_c23_glue.c`. Never link both.

## C++ seam

`c23/glue/zcl_c23_log.cpp` needs `util.h` and `chainparams.h`. Add it to
`libbitcoin_util_a_SOURCES` (so every consumer of libzcl_c23 that already links util
resolves `zcl_c23_log_sink`, `zcl_c23_log_category_enabled`, `zcl_c23_network_id`).
Compiles clean as `g++ -std=gnu++17 -fsyntax-only -DHAVE_CONFIG_H` (verified on z23-r2).
`zcl_c23_log.cpp` finds `zcl_c23_glue.h` beside itself (quote include), so no extra -I
is needed; do NOT put `-I c23/glue/chain` on C++ targets (it would shadow `chainparams.h`).

After argument parsing (and after `SelectParams`), call `zcl_c23_log_refresh()` once
(declare via `c23/glue/zcl_c23_glue.h`, `extern "C"`) so that `-debug=zc23` takes effect.
Without it vendored `LOG_FAIL` lines stay off. Before that the level is OFF.

## Link order (every consumer that carries `$(LIBZCASH_LIBS)`)

zclassicd (`Makefile.am` ~478), zclassic-cli / zclassic-tx (~501, ~523),
`Makefile.test.include:126`, `Makefile.gtest.include:66`:

```
... $(LIBZCASH) $(LIBZCL_C23) ... -lsodium -lcrypto -lz (+ pthread) (+ -lbcrypt on mingw)
```

`$(LIBZCL_C23)` must precede `-lsodium -lcrypto` (it consumes `randombytes_buf`,
`sodium_init`, `OPENSSL_cleanse`) and must come after the C++ libraries that define
`zcl_c23_*` only if those libraries are listed after it (static archive order). Put
`libbitcoin_util.a` after `$(LIBZCL_C23)` or list util twice.
mingw: `file_stream.c` uses MultiByteToWideChar/_wopen (kernel32, ucrt); `pthread` is
winpthreads (already static in the release job). No bcrypt needed in production glue.

## Source-identity gate

Add a check target (not part of `make all`):

```make
check-c23-vendor:
	sh $(srcdir)/c23/tools/check-vendor.sh
```

and run it in CI. `.gitattributes` in `c23/vendor/` (`* -text`) keeps git from
rewriting line endings on Windows; do not delete it, a CRLF conversion changes the
blob and `check-vendor.sh` will (correctly) fail.

## Symbol-collision audit (do in the build-switch unit)

Z23 exports generic C names (`blake2b_init`, `sha256_init`, `fr_add`, `group_hash`,
`g1_msm`, ...). `-fvisibility=hidden` keeps them private in shared objects; for the
static link run `nm -g build/src/zclassicd | sort | uniq -d` and fail on duplicates.
The vendored sha256/sha512 (`sha256_init`...) vs zclassicd's `crypto/sha256.cpp` are
C++-mangled on the zclassicd side, so no clash is expected; this is not machine-checked
here (needs a full daemon link).
