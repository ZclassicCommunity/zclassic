# Removing the Rust build dependency

Target: replace `librustzcash` with verified Z23-derived C23 implementations,
then remove its linker entry and pinned Rust toolchain from `depends`.
The existing Rust implementation remains a test oracle during migration.

The source inventory currently finds 31 distinct `librustzcash_*` entry points
across production code and tests. Root memoization alone does not remove that
library. This branch begins with the canonical uncommitted-leaf constant, adapted
from Z23 `pedersen_hash.c`, with a byte-for-byte Rust comparison. It is a small
dependency-boundary change, not a claimed sync-speed improvement.

| Area | Existing Rust entry points (prefix omitted) | C23 candidate |
|---|---|---|
| Tree hashing | tree_uncommitted, merkle_hash | Z23 pedersen_hash.c, fr.c, fr_avx512.c |
| Key derivation | ask_to_ak, nsk_to_nk, crh_ivk, ivk_to_pkd, check_diversifier, to_scalar | Z23 Sapling/Jubjub field and key operations |
| ZIP32 | zip32_xsk_master, zip32_xsk_derive, zip32_xfvk_derive, zip32_xfvk_address | Z23 ZIP32; compare encoded keys, addresses and failure results |
| Note operations | sapling_generate_r, sapling_compute_cm, sapling_compute_nf, sapling_ka_agree, sapling_ka_derivepublic | Z23 note, key-agreement and randomness implementations |
| Sapling validation | sapling_verification_ctx_init/free, sapling_check_spend/output, sapling_final_check | Z23 verification context and proof/signature checks |
| Sapling spending | sapling_proving_ctx_init/free, sapling_spend_proof, sapling_output_proof, sapling_spend_sig, sapling_binding_sig | Z23 proving-context interfaces; ABI adaptation required |
| Sprout and setup | init_zksnark_params, sprout_prove, sprout_verify | Z23 parameter loading and Sprout Groth16 paths |

These are candidates, not declarations of interchangeability. For example,
Z23's spend-proof API takes an explicit witness buffer length; simply renaming
symbols would not preserve the legacy ABI. CPU dispatch, initialization races,
allocation failures, secret handling and constant-time behavior must be reviewed
alongside mathematical output parity.

Each replacement requires existing known-answer vectors, Rust differential
tests (valid and invalid inputs), serialization compatibility, and platform
build checks. Verification replacements also require historical-chain and
reorg tests; proving replacements require round-trip proofs and spend tests in
isolated wallets. Never test spends with a user's live wallet.

The final Rust-removal gate must show that production binaries have no unresolved
Rust FFI calls, build without the Rust toolchain, and preserve all shielded
wallet operations. Do not remove proof checks, parameter validation or wallet
functionality to make that gate pass. No consensus constants, activation heights,
acceptance predicates or wallet formats are to change.

Beta11 packaging work proceeds separately so this migration cannot silently
replace a tested release backend with an unfinished cryptographic port.

## Scalar-reduction candidate

`src/zcash/jubjub_scalar.c` imports Z23's shifted-accumulator reducer, source
blob `67c21700e4b8904fe58690cd2d24bff27dcc85c4`. Only its include path and public
symbol prefix are adapted. The algorithm runs a fixed 512 rounds and avoids
secret-dependent indexing. C23 `_BitInt(128)` is used where supported, with the
upstream `unsigned __int128` fallback for legacy compilers.

It is compiled and tested but **not yet selected by production key derivation**.
Tests compare Rust and independent arbitrary-precision integer remainders for
zero, all-one, single-bit, complemented single-bit, modulus-boundary and 2,048
deterministic pseudorandom inputs, including overlapping input/output buffers.
The suite reports Rust/C23 timing without weakening a correctness assertion to
meet a performance target. Cross-platform timing/side-channel review and the
differential gate are required before switching the two production callers.
