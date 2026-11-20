# C23 Equihash verifier (unit p1-equihash, folded into libzcl_c23.a)

The verifier is part of `libzcl_c23.a`; there is no separate Equihash library.

- Vendored Z23 files (byte-identical, listed in `src/c23/Z23_SOURCE.tsv`, checked by
  `src/c23/tools/check-vendor.sh`): `crypto/equihash.{c,h}`, `crypto/blake2b_avx2.c` (under `src/c23/vendor/core/modules/crypto/src/`). <!-- doc-path-ok -->
  `blake2b.{c,h}` and `simd_dispatch.{c,h}` are the copies the Sapling code already
  uses (same blobs); nothing is compiled twice.
- `zc23_equihash.{c,h}`: the C ABI between zclassicd (`pow.cpp`) and the verifier.
  Only `zc23_equihash.h` is included from C++.
- `zc23_equihash_vendor.c`: compiles the vendored `equihash.c` with the two policy
  overrides in `util/` (out-of-memory aborts instead of becoming an "invalid
  solution"; reject lines go to the sink `pow.cpp` installs). Those overrides apply to
  that one translation unit only; `equihash.c` is not listed in the Makefile sources.
- Symbol hygiene: libsodium exports unprefixed `blake2b_*`. Every global of the
  vendored files is renamed to `zc23_<name>` by the generated, force-included
  `glue/zcl_c23_symbol_prefix.h`, and `c23-symbols.stamp` (`tools/symbol-prefix.sh
  check`) fails the build if the archive exports anything else. After re-vendoring run
  `tools/symbol-prefix.sh gen` and rebuild.
- `-equihashimpl=<cpp|c23>`, `-equihashdifferential`, `-equihashmemo` (default 1)
  are read in `pow.cpp`; the memo is `src/equihashmemo.{h,cpp}`.
- `test/eh_headers_check.c`: standalone check (not built by automake). Build it from
  `src/c23` with the same force-includes as the library:
      cc -std=gnu17 -O2 -include glue/zcl_c23_compat.h -include glue/zcl_c23_symbol_prefix.h \
         -iquote equihash -Ivendor/core/modules/crypto/include \
         equihash/test/eh_headers_check.c equihash/zc23_equihash.c equihash/zc23_equihash_vendor.c \
         vendor/core/modules/crypto/src/{blake2b,blake2b_avx2,simd_dispatch}.c ...
  (the library needs the other glue objects for logging when linked as a whole).

Windows/MinGW: `blake2b_avx2.c` uses `__attribute__((target("avx2"/"avx512f")))` with
256/512-bit locals; GCC on Windows x64 does not realign the stack for 32/64-byte
spills (GCC bug 54412). Run `eh_headers_check` with the release mingw-w64 toolchain
before shipping a Windows build.
