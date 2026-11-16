# Build wiring for libzcl_c23.a (for the later build-switch unit)

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

## Hash acceleration (unit p4-hash): APPLIED, unlike the rest of this file

`CSHA256` (`crypto/sha256.{h,cpp}`) now runs on the vendored Z23
`vendor/core/modules/crypto/src/sha256.c`. The C++ class interface is unchanged; every
SHA-256 consumer (CHash256, CHash160, CHMAC_SHA256, SHA256Compress, HashFileSHA256,
txid/header/merkle hashing) gets the backend without a call-site change.

```
crypto/sha256.cpp ──> c23/glue/zcl_c23_sha256.h (extern "C" seam; the only header C++ sees)
                      c23/glue/zcl_c23_sha256.c (forwarders, layout static asserts; #includes the
                        vendored sha256.c below so no object is written under vendor/)
                      c23/vendor/core/modules/crypto/src/sha256.c (portable C, SHA-NI, ARMv8 SHA)
                      c23/glue/zcl_c23_hash_log.c (zcl_log_level_get / zcl_log_emit_at -> stderr)
```

Built as `libzcl_c23_hash.a` (and as the libtool convenience library
`libzcl_c23_hash_pic.la` for `libzcashconsensus`, which compiles `crypto/sha256.cpp`
itself). `LIBBITCOIN_CRYPTO` expands to `crypto/libbitcoin_crypto.a libzcl_c23_hash.a`, so
every existing link line carries it in the right order.

- **Include path is `-iquote`, not `-I`.** Automake emits `-I.` (zclassicd `src/`) before
  per-target flags, so with `-I` the vendored `sha256.c` picked up zclassicd's C++
  `crypto/sha256.h` (first build failed on `#include <string>`). `-iquote` directories are
  searched before every `-I`. The `libzcl_c23_a_CPPFLAGS` stanza above has the same
  problem for `crypto/sha256.h`, `crypto/common.h`, `crypto/sha512.h`: use `-iquote` there too.
- **No `-march`, `-msha`, `-msse4` anywhere.** The SHA-NI and ARMv8 transforms carry
  `__attribute__((target(...)))`; the object is x86-64 baseline and the transform is
  chosen from CPUID at run time, after a known-answer comparison with the portable code.
- **Dispatch.** The backend flag is an `_Atomic int` probed on first use (benign race: every
  thread computes the same value). `crypto/sha256.cpp` also probes in a static initialiser
  and `AppInit2` calls `SHA256AutoDetect()` before any thread starts and logs
  `Using the '<name>' SHA256 implementation`.
- **Linux aarch64 stays portable.** The pinned Z23 `sha256.c` only enables the ARMv8
  transform on Apple (`sysctl hw.optional.arm.FEAT_SHA256`); on other arm64 systems
  `detect_sha_arm()` returns "unavailable". That is upstream behaviour at this pin, not a
  glue choice; a `getauxval(AT_HWCAP)` probe belongs in Z23 and arrives by re-vendoring.
- **Private symbol names.** `glue/zcl_c23_hash_names.h` (included first in both glue C
  files) renames the vendored externals to `zcl_c23h_sha256_*` and the two log entry points
  to `zcl_c23h_log_*`. This was forced by a real clash: zclassicd's `src/sha256.cpp` (the
  helper behind `SHA256::hashString`) defines `sha256_init` and `sha256_finalize` as
  `extern "C"` with other signatures, and the first zclassicd link failed with "multiple
  definition". The "Symbol-collision audit" section above assumed the zclassicd names are
  C++-mangled; for these two they are not, so `libzcl_c23.a` needs the same treatment.
- **When `libzcl_c23.a` is added:** thanks to the renaming both libraries can be linked
  into one program without duplicate symbols (two private copies of SHA-256, about 16 KB).
  To share one copy instead, point `libzcl_c23.a` at the `zcl_c23h_` names and drop
  `sha256.c` from its source list.
- **Test hooks.** `SHA256SelectBackendForTesting("portable"|"hardware"|"auto")`;
  `ZCL_SHA256_BACKEND=portable|hardware` forces a backend for a whole `zcash-gtest` or
  `test_bitcoin` run; `ZCL_SHA256_REQUIRE_HARDWARE=1` makes the differential test fail
  instead of silently running portable twice on a host that should have SHA-NI.
- **Proofs.** `gtest/test_sha256_differential.cpp` (reference: the former C++ code in
  `gtest/sha256_reference.h`), `c23/test/sha256-diff-sanitize.sh` (ASan+UBSan),
  `c23/bench/hash/build.sh` (before/after numbers), `make check-c23-vendor`.

Not replaced, on measurement: RIPEMD160 (Z23 portable equals the C++ one), single-stream
BLAKE2b (libsodium's AVX2 compress is 12 to 17 percent faster than Z23's scalar code).
Equihash 4-way/8-way BLAKE2b is a separate unit (`vendor-equihash-pending/`).
