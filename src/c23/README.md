# src/c23: the C23 core that replaces librustzcash

Status: wired. `src/Makefile.am` builds everything below into `libzcl_c23.a`, which
`zclassicd`, `zclassic-tx`, `zcash-gtest` and `test_bitcoin` link instead of
`librustzcash.a`. How it is built, checked and tuned: `doc/c23-build.md`.
`CSHA256` runs on the vendored SHA-256 through `libzcl_c23_hash.a` (`glue/WIRING.md`, "Hashacceleration"); Equihash verification is part of `libzcl_c23.a` (`equihash/WIRING.md`). Botharchives are held to the symbol-prefix check by `c23-symbols.stamp`.

```
vendor/                  VERBATIM Z23 files at the pin in Z23_SOURCE.tsv. Never edit.
                         Z23 relative paths are preserved (vendor/core/..., vendor/platform/...).
glue/                    zclassicd-owned: compat header, logging/RNG/cleanse/chain-params
                         glue, fail-closed note-encryption stubs, single-leaf tree shim,
                         test-only glue, WIRING.md.
tools/                   check-vendor.sh, revendor.sh, derive-closure.sh, vendor-seeds.txt,
                         build-check.sh, tree-shim-diff.sh, tree_shim_check.c.
vendor-equihash-pending/ empty on purpose (README only); nothing links it.
Z23_SOURCE.tsv           one row per vendored file: zclassicd path, Z23 path, 40-hex git blob,
                         Z23 commit, core/MANIFEST.sha3 SHA3-256 (or "unsealed").
LICENSE.z23, NOTICE      Apache-2.0 text and notice for the vendored subtree.
```

## Pin

`aa9eed8322b686cf9ee5443adfe9bb6063d985e7` (Z23 origin/main, 2026-11-16). `revendor.sh`
and `check-vendor.sh` (with `Z23_REPO=<path>`) refuse any pin that does not contain
`55245e2bd` ("reject non-canonical Fr encodings as zclassicd does"). Without it the
verifier would accept `cm >= q`, `anchor >= q` and `y = q` point encodings that
librustzcash rejects (consensus fork).

The closure (82 files: 34 `.c`, 48 headers, plus LICENSE) is derived from
`tools/vendor-seeds.txt` by following quoted includes (`tools/derive-closure.sh`). It
contains the verifier, prover, ZIP-32/FF1, Sprout Groth16 verify, embedded verifying keys,
and (params-loader Option B) `params_init.c` with its SHA-512 pins, bn254 (only to parse
the PHGR13 verifying key), sha256/sha512, file_io, file_stream, utilstrencodings.
Replaced by glue instead of vendored: `log_level.c`, `cleanse.c`, `random.c`,
`incremental_merkle_tree.c`, `note_encryption.c`.

## Re-vendoring

```sh
sh src/c23/tools/revendor.sh <z23-repo> <commit>     # rewrites vendor/ and Z23_SOURCE.tsv
sh src/c23/tools/check-vendor.sh                      # must print OK
```

Then re-run the known-answer and differential tests. Re-vendoring is a deliberate act.

## Proofs and how to re-run them

```sh
sh src/c23/tools/check-vendor.sh                              # blobs, unlisted files, SHA3 vs MANIFEST.sha3
sh src/c23/tools/build-check.sh <cc> -std=gnu17|-std=c23 <outdir>   # zero-warning -O3 -Wall -Wextra build + link
sh src/c23/tools/tree-shim-diff.sh <cc> <z23-repo> <commit> <outdir> # tree shim vs Z23's real tree + zclassicd vectors
```

Recorded results are in the unit report (REPORT.md of unit u1-u2-vendor-glue).

## Design notes

- **One portable binary.** No `-march` flags. ADX/BMI2 (`fr_avx512.c`, `bn254_accel.c`)
  and AVX2 / SHA-NI paths dispatch at run time through `simd_dispatch.c`.
- **Platform contract** (`glue/zcl_c23_compat.h`, enforced by `_Static_assert`/`#error`):
  8-bit bytes, 64-bit pointers/`size_t`, `unsigned __int128`, little-endian.
- **Logging.** Vendored `LOG_FAIL`/`LOG_WARN` sites call `zcl_log_emit_at`. Production glue
  routes them to `LogPrintStr` but keeps them OFF unless `-debug=zc23` (adversarial
  transactions would otherwise write `debug.log` on every reject). Call
  `zcl_c23_log_refresh()` after argument parsing.
- **RNG.** `GetRandBytes` -> libsodium `randombytes_buf`; `sodium_init()` is ensured on the
  first call; failure aborts. `ZCL_TESTING` is never defined so the test RNG hooks stay
  compiled out.
- **Note encryption** (`sapling_kdf`, `sapling_prf_ock`, `sapling_note_encrypt`,
  `sapling_out_encrypt`) return false. zclassicd never reaches them (libsodium
  NoteEncryption). Unit U3 must add a test proving there is no caller.
- **Tree shim** supports exactly the self-test in `sapling_prover_native.c`: one leaf at
  position 0, depth 32. A second append makes `merkle_path` fail (fail closed).
- **Known pinned quirk, not fixed here:** Z23's Groth16 point decode accepts the point at
  infinity; librustzcash rejects it. The unit U3 shim must reject bit 0x40 in bytes
  0, 48 and 144 of every 192-byte proof (plan, headline 2). Editing vendor/ is not the
  fix.
