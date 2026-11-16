# Wiring the C23 Sprout prover into the zclassicd build

This directory replaces `librustzcash_sprout_prove`. Nothing here edits
`configure.ac` or `Makefile*.am`; this file lists what the build owner must add.

## 1. Sources to compile (C, `-std=gnu2x`, plus `-pthread`)

    src/c23/sprout_prover/sprout_circuit.c
    src/c23/sprout_prover/sprout_par.c
    src/c23/sprout_prover/sprout_prove.c

Put them in the same static library as the rest of `src/c23` (the U3
`librustzcash_compat.c` shim), so it builds into `zclassicd`, `zcash-gtest`,
`test_bitcoin` and `zclassic-tx` wherever `librustzcash.a` is linked today.

Include paths: every `src/c23/vendor/**/include` directory (the same list the
vendor build uses) and `src/c23/sprout_prover`.

## 2. Vendored Z23 objects the prover links

Measured from a link map of `test_sprout_prover` (an archive link, so only
referenced members are pulled):

    core/modules/sapling/src/{bls12_381,fr,fr_avx512,groth16_prover,
                              circuit_bits,circuit_gadgets,params_vk_embedded}.c
    core/modules/crypto/src/{blake2b,random_secret,simd_dispatch}.c
    platform/modules/base/src/safe_alloc.c

(`sprout.c` is pulled only by the test's verifier call; `msm_parallel.c` only
by `test_fft_parity`.) All of these are already in the U1/U2 vendor set. The
glue must provide `memory_cleanse`, `GetRandBytes` (abort on failure),
`zcl_log_level_get` and `zcl_log_emit_at`. `src/c23/glue/zcl_c23_glue.c` does,
and `test/test_glue.c` does for standalone tests only. Never link `test_glue.c`
into the daemon.

## 3. Shim changes (U3, `src/c23/compat/librustzcash_compat.c`)

- `librustzcash_sprout_prove(...)` forwards its 22 arguments unchanged to
  `zc23_sprout_prove(...)` (`sprout_prover.h`). It is a drop-in with the same
  argument order and sizes.
- `librustzcash_init_zksnark_params(...)`: after the existing work, convert the
  Sprout Groth16 path to UTF-8. On Windows it arrives as UTF-16 (`const
  codeunit*` with a length). Then call `zc23_sprout_prover_set_params_path(utf8)`.
  If that returns false, `abort()`, as Rust does on a bad path. The prover
  opens the file with `_wfopen` on Windows, so non-ASCII profile paths work.
- `JoinSplit.cpp`, `asyncrpcoperation_*` and every other caller stay as they are.

## 4. Tests to register

| program | needs | gate |
|---|---|---|
| `test_sprout_circuit` | nothing | always (about 12 s): 1,989,085 constraints, satisfied, nf/cm/mac KAT, mutations |
| `test_fft_parity` | nothing | always (about 10 s) |
| `test_sprout_prover <sprout-groth16.params> [<other .params>]` | params | when `~/.zcash-params/sprout-groth16.params` exists (about 1 min) |

For a standalone build, `sh src/c23/sprout_prover/test/build.sh <out-dir>`
compiles all three with `CC`, `AR`, `OPT` and `ARCH`. A Makefile rule can
call it, or list the same sources.

## 5. What can then leave the build

Once U3 forwards to this prover, nothing in zclassicd calls Rust for Sprout
proving. `sprout-groth16.params` is still required at proving time, and the
prover reads it on every call, as Rust does. The startup BLAKE2b gate for that
file belongs to U3/init, not here. The prover also compares the file's
1,828-byte verifying-key prefix with the compiled-in key on every call, and
verifies every proof before it returns it.
