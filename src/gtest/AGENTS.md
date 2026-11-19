# src/gtest agent rules

Imports the root contract: [../../AGENTS.md](../../AGENTS.md). Sources are listed in [../Makefile.gtest.include](../Makefile.gtest.include); the binary is `zcash-gtest` (`main.cpp` is its entry). The wallet cases live in `src/wallet/gtest/`.

- `main.cpp` loads the Sprout and Sapling parameter files from the params directory, so the binary needs them (`zcutil/fetch-params.sh`); a missing file is a failure, not a reason to skip.
- One `TEST(Suite, Case)` or `TEST_F` per behaviour; add the file to `Makefile.gtest.include` and to `zcutil/dev/impact.rules`.
- Data under `data/` and the `json_test_vectors` inputs are generated evidence; never hand-edit or regenerate them to make a case pass.
- Cases that touch disk use a temporary directory, never a real datadir. Never loosen an assertion to pass.
- Run a filter, never the whole binary, while iterating: `src/zcash-gtest --gtest_filter='Suite.*'` (`--gtest_list_tests` lists them). The full binary is the `zcash-gtest-full` CI step.
- Differential and mainnet-block cases (`test_mainnet_blocks.cpp`, `test_sha256_differential.cpp`, `test_equihash_c23.cpp`) pin consensus behaviour; a failure there is a divergence, not a flaky test.

Tests: `src/zcash-gtest --gtest_filter='<Suite>.*'`, then `zcutil/local-ci.sh --commit <sha> --only zcash-gtest-full test <outdir>`.
