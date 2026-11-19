# src/crypto: hash functions and the Equihash solver

The hash primitives (SHA-1, SHA-256, SHA-512, SHA-3, RIPEMD-160, HMAC) and the C++ Equihash verifier and reference solver that proof of work and header checks call.

## What lives here

- `sha256.cpp`, `sha512.cpp`, `sha1.cpp`, `ripemd160.cpp`, `sha3.cpp`: the hash classes (`CSHA256`, `CSHA512`, `CSHA1`, `CRIPEMD160`, `SHA3_256`) with `Write` and `Finalize`.
- `hmac_sha256.cpp`, `hmac_sha512.cpp`: `CHMAC_SHA256`, `CHMAC_SHA512`.
- `equihash.cpp`, `equihash.h`, `equihash.tcc`: `Equihash<N,K>`, `ExpandArray`, `CompressArray`, `GetIndicesFromMinimal`, `GetMinimalFromIndices`, `EhSolverCancelledException`.
- `common.h`: byte-order helpers shared by the hashes.

The Equihash verification of received headers is memoised by `src/equihashmemo.h` (positive results only) and pre-warmed on worker threads by `src/headerprecheck.cpp`.

## Traps

- This directory is consensus-path code: a hash or a verifier that accepts or rejects differently forks the chain. A speedup is proven identical on the same inputs, not argued; see [../consensus/AGENTS.md](../consensus/AGENTS.md).
- The Sprout, Sapling and Groth16 verifiers are not here; they come from the C23 core in `src/c23/`.
- A new SHA-256 backend must pass the differential cases in `src/gtest/test_sha256_differential.cpp`.

## Tests

Boost suites `crypto_tests`, `hash_tests`, `sha256compress_tests`, `equihash_tests`, `equihashmemo_tests`, `headerprecheck_tests`; gtest `equihash_tests`, `EquihashC23`, `Sha256Backend`, `Sha256Differential`. List them with `zcutil/bin/zcl-dev t-list`.

## Related

Rules: [../consensus/AGENTS.md](../consensus/AGENTS.md). Facts: `zcutil/bin/zcl-dev know positive-only-memo`, `zcutil/bin/zcl-dev know header-precheck`.
