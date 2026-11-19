# src/c23 agent rules

Imports the root contract: [../../AGENTS.md](../../AGENTS.md). Design and pin: [README.md](README.md), [../../doc/c23-build.md](../../doc/c23-build.md).

## Vendored code is byte-identical

- `vendor/**` and `services/vendor/**` are verbatim Z23 files at the pin in `Z23_SOURCE.tsv` (one row per file: path, Z23 path, git blob, commit, MANIFEST.sha3 digest or `unsealed`). Never edit one, never add one by hand, never reformat one. `.gitattributes` there says `-text` so line endings stay as vendored.
- Change them only with the matching tool, then check:
  - `sh src/c23/tools/revendor.sh <z23-repo> <commit>` then `sh src/c23/tools/check-vendor.sh`;
  - services: `sh src/c23/services/tools/revendor.sh ...` then `sh src/c23/services/tools/check-vendor.sh src/c23/services`;
  - zcutil helpers: `sh zcutil/tools/revendor.sh <z23-repo> <commit>` then `sh src/c23/tools/check-vendor.sh zcutil/tools/Z23_SOURCE.tsv`.
- The pin must contain `55245e2bd` (canonical Fr encodings, a consensus matter). `revendor.sh` refuses a pin that does not; `Z23_REPO=<path> check-vendor.sh` re-proves it.
- A vendored root needs `LICENSE.z23` and `NOTICE` beside its manifest and a line in `THIRD-PARTY-LICENSES`. A file we change is not vendored: move it to `glue/` (or the owning directory) with a header `derived from Z23 <path>@<commit>, changed` (Apache-2.0 section 4(b)).
- Fix a bug in vendored code in Z23 first, then re-vendor. If zclassicd must differ from Z23, put the difference in `glue/` and say why in `glue/WIRING.md`.

## Language level

Release builds use GCC 9, which compiles C as gnu17. Everything linked into the daemon or wallet compiles as gnu17 with zero warnings, and also as `-std=c23` where the tree supports it. Check with `sh src/c23/tools/build-check.sh <cc> -std=gnu17 <outdir>` (and `-std=c23`). Do not use `nullptr`, `constexpr`, attributes, `typeof`, `_BitInt` or `#embed` in anything that can be linked. The platform contract (64-bit, `unsigned __int128`, little endian) is enforced in `glue/zcl_c23_compat.h`.

On MinGW, C code needs `-D__USE_MINGW_ANSI_STDIO=1` for `%zu` and friends; `src/Makefile.am` sets it for `libzcl_c23.a`.

## Symbol prefix

Every internal global in `libzcl_c23.a` is prefixed `zc23_` through the force-included `glue/zcl_c23_symbol_prefix.h` (libsodium and OpenSSL export colliding names). `sh src/c23/tools/symbol-prefix.sh check <nm> <archive>` fails on an unprefixed export; `... gen <nm> <archive> <header>` regenerates the header. A new vendored file or function usually needs a regeneration and a rebuild.

## Golden corpus and known-answer tests

- `sh src/c23/test/run.sh --out <dir> [--linked <libzcl_c23.a> --deps <prefix>] [--golden <dir>]` builds and runs the replay, mutation, thread and scan suites against the C23 core; `--linked` tests the archive the daemon links. CI step `c23-run-linked`.
- The golden corpus (default `src/test/data/c23_golden`, or `ZCL_CI_GOLDEN`) is generated evidence: never hand-edit it, never regenerate it to make a failing test pass.
- Sprout/Sapling/Groth16 behaviour equals zclassicd's (accept and reject identically). A change that alters any verifier outcome is a consensus change and is out of scope.
- Other proofs: `src/c23/test/regtest-smoke.sh`, `src/c23/tools/tree-shim-diff.sh`, `make -C src check-c23-vendor check-c23-no-rust`.
