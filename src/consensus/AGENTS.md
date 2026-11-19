# consensus, script, primitives, pow, zcash agent rules

Imports the root contract: [../../AGENTS.md](../../AGENTS.md). Also governs `src/script/`, `src/primitives/`, `src/pow/`, `src/zcash/`, `src/crypto/`, `src/pow.cpp`, `src/main.cpp`, `src/chain.cpp`, `src/coins.cpp`, `src/checkpoints.cpp`, `src/chainparams.cpp` (those directories have no guide of their own, so `zcl-dev guide` shows this one only for `src/consensus/`).

- zclassicd is the reference and Z23 matches it bug-for-bug. There are no rule changes here: no rule, checkpoint, activation height, limit or acceptance predicate is altered, even to fix an apparent bug. A divergence is fixed in the other implementation to match this one.
- A refactor or speedup on these paths is proven accept/reject-identical on the same inputs (differential and golden tests) before and after, not argued.
- `oversize_grandfather.cpp`, `z23/oversize_grandfather_table.inc` and `doc/oversize-grandfather.md` reproduce 413 historical mainnet transactions. Never edit the table or loosen the rule; it applies only inside block validation.
- `src/zcash/tree_root.c` is C and is built with the C23 core flags; Sprout/Sapling/Groth16 verifiers come from `src/c23/` and must accept and reject exactly as before ([../c23/AGENTS.md](../c23/AGENTS.md)).
- `src/pow/tromp/` is third-party solver code; do not reformat it.
- Every file here maps to `ALL` in `zcutil/dev/impact.rules`: a change runs the full test set.

Tests: `src/test/test_bitcoin --run_test=<suite>` for the suites the file owns (`script_tests`, `transaction_tests`, `checkblock_tests`, `pow_tests`, `sighash_tests`, `coins_tests`), `src/zcash-gtest --gtest_filter=<Case>.*`, then `zcutil/local-ci.sh --commit <sha> --only test_bitcoin-full,zcash-gtest-full,c23-run-linked,regtest-smoke test <outdir>`.
Table proof: `sh contrib/devtools/check-oversize-grandfather.sh`.
Read first: [doc/oversize-grandfather.md](../../doc/oversize-grandfather.md), [doc/agent/TRAPS.md](../../doc/agent/TRAPS.md) section 1.
