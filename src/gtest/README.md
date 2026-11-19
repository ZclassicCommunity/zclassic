# src/gtest: zcash-gtest cases

The Google Test binary `zcash-gtest`: shielded-crypto, transaction-builder, validation and wallet-adjacent cases inherited from Zcash, plus differential and mainnet-block cases that pin consensus behaviour.

## What lives here

- `main.cpp`: the entry; it loads the Sprout and Sapling parameter files from the params directory and fails when one is missing.
- `test_*.cpp`: one `TEST(Suite, Case)` or `TEST_F` per behaviour, listed in `src/Makefile.gtest.include`.
- `utils.cpp`, `json_test_vectors.cpp`, `data/`: helpers and generated evidence.
- Wallet cases live in `src/wallet/gtest/`.

## Traps

- The binary needs the zk-SNARK parameters (`zcutil/fetch-params.sh`); a missing file is a failure, not a skip.
- `test_mainnet_blocks.cpp`, `test_sha256_differential.cpp` and `test_equihash_c23.cpp` pin consensus; a failure is a divergence.
- Data under `data/` and the JSON vectors are generated evidence; never edit or regenerate them to make a case pass.
- Never run the whole binary while iterating; pass a filter.

## Run

```sh
src/zcash-gtest --gtest_list_tests
src/zcash-gtest --gtest_filter='Validation.*'
```

The full binary is the `zcash-gtest-full` CI step. A new file needs a row in `zcutil/dev/impact.rules`.

## Related

Rules: [AGENTS.md](AGENTS.md). Boost suites: [../test/README.md](../test/README.md). Facts: `zcutil/bin/zcl-dev know pinned-consensus-vectors`, `zcutil/bin/zcl-dev know zk-params-present`.
