# libsecp256k1 with the GLV endomorphism

Scope: why `configure.ac` passes `--enable-endomorphism` to the bundled `src/secp256k1`, what it
speeds up, and how the change is proven not to move an accept/reject decision.

## What changed

`configure.ac` hands one argument list to the `src/secp256k1` sub-configure (the
`ac_configure_args` line before `AC_CONFIG_SUBDIRS`). It now ends in `--enable-endomorphism`,
which defines `USE_ENDOMORPHISM` in the generated `src/secp256k1/src/libsecp256k1-config.h`.
Linux, the mingw-w64 cross build and macOS all take this one path; `depends/` does not build
secp256k1 on its own. The vendored tree under `src/secp256k1` is not edited.

With the define, `secp256k1_ecmult` (the `a*P + b*G` step inside ECDSA verification and public-key
recovery) splits each 256-bit scalar into two halves of about 128 bits with the curve
endomorphism `lambda*(x, y) = (beta*x, y)` and evaluates both halves together, roughly halving the
doublings. It computes the same group element. Signing (`secp256k1_ecmult_gen` and its static
table), key and signature parsing, DER and low-S handling in `CPubKey::Verify` are unchanged.

Upstream kept the option off by default because of the GLV patent, which expired in 2020;
upstream libsecp256k1 later made the endomorphism unconditional. Z23 links a modern
libsecp256k1, so it always uses it (Z23 `docs/quality/NEON_CRYPTO_MATRIX.md`, secp256k1 row) and <!-- doc-path-ok -->
pins verification under a 50 us ceiling (Z23 `tools/crypto_perf_baseline.csv`, <!-- doc-path-ok -->
`secp256k1-ecdsa-verify`).

## Measurement

Host `z23-r1` (AMD Ryzen 9 7950X3D, 32 threads, shared; load average about 3.4 during the runs),
2026-11-19. Two throwaway copies of `src/secp256k1` configured with the daemon's flags
(`--disable-shared --with-pic --with-bignum=no --enable-module-recovery`) plus
`--enable-benchmark`, one of them also with `--enable-endomorphism`; runs interleaved off/on.
(`bench_recover` in this vendored version does not compile, so recovery is covered by the parity
test rather than a benchmark.)

| benchmark (avg of 10 x 20000) | without | with endomorphism | change |
|-------------------------------|---------|-------------------|--------|
| `bench_verify` run 1          | 49.4 us | 36.8 us           |        |
| `bench_verify` run 2          | 48.7 us | 37.0 us           |        |
| `bench_verify` run 3          | 49.2 us | 36.8 us           |        |
| `bench_verify` run 4          | 48.8 us | 36.1 us           |        |
| `bench_verify` run 5          | 49.1 us | 36.6 us           |        |
| `bench_verify` mean           | 49.0 us | 36.7 us           | -25 %  |
| `bench_sign`                  | 27.4 us | 27.9 us           | noise  |

In the daemon's own code path the same shows up end to end: `Secp256k1VerifyParity.EcdsaCorpus`
(about 300000 `CPubKey::Verify` calls, more than 100000 of them reaching the multiplication,
80000 `RecoverCompact` calls and 40000 signatures) took 11375 ms and
10765 ms on the build without the flag and 8977 ms and 8406 ms with it.

Every transparent signature check that is not skipped by a checkpoint gets this saving: block
connect, mempool acceptance, `-reindex` and `verifymessage`.

## Result identity

`src/gtest/test_secp256k1_verify_parity.cpp` (`Secp256k1VerifyParity`) folds every input and every
outcome of a fixed corpus into a SHA-256 digest and compares it with a golden value:

- `EcdsaCorpus`: 20000 keys from a fixed 64-bit LCG (compressed and uncompressed; every 5000th
  key is zero, so 19996 are used). For each: the valid DER signature, its high-S twin, one-bit
  flips of r, s, the hash and the public key, r or s set to 0, n, n + 1 and 2^256 - 1, the
  signature checked against the previous case's key, and `SignCompact`/`RecoverCompact` round
  trips plus recovery from a flipped hash and a flipped recovery id.
- `ScriptJsonCorpus`: every row of `src/test/data/script_valid.json` (589) and
  `script_invalid.json` (473) through `VerifyScript` under each network upgrade's branch id; the
  result and the script error are folded. `sighash.json` holds no signatures to verify, so it is
  not used.

The golden digests were recorded on the build without the flag (base `8ee9727e7`) and committed
before the flag changed. Both builds reproduce them:

| build                  | `EcdsaCorpus` digest | `ScriptJsonCorpus` digest |
|------------------------|----------------------|---------------------------|
| without endomorphism   | `0807f5dc888c55016e20c9c5cdab2ee870b5f174b0daee3baae9635c6cb06d7a` | `38706f04d0dcca7432ec1216fb5532378a17513c7d6aeab343a88418143ba0e6` |
| with endomorphism      | `0807f5dc888c55016e20c9c5cdab2ee870b5f174b0daee3baae9635c6cb06d7a` | `38706f04d0dcca7432ec1216fb5532378a17513c7d6aeab343a88418143ba0e6` |

Upstream's own `make -C src/secp256k1 check` (run by `make check` through
`src/Makefile.test.include`) exercises the endomorphism split directly. A digest mismatch is a
divergence: drop the flag, never regenerate the golden.

Check a build: `grep USE_ENDOMORPHISM src/secp256k1/src/libsecp256k1-config.h` after configure,
then `src/zcash-gtest --gtest_filter='Secp256k1VerifyParity.*'`.
