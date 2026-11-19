# src agent rules

Imports the root contract: [../AGENTS.md](../AGENTS.md). Build and unit-test layout: [Makefile.am](Makefile.am), [Makefile.test.include](Makefile.test.include), [Makefile.gtest.include](Makefile.gtest.include).

- Consensus-path files (`script/`, `primitives/`, `pow/`, `zcash/`, `crypto/`, `pow.cpp`, `main.cpp`, `chain.cpp`, `coins.cpp`) follow [consensus/AGENTS.md](consensus/AGENTS.md): zclassicd is the reference, no rule changes.
- Other areas with their own guide: `wallet/`, `rpc/`, `test/`, `gtest/`, `zslp/` (covers `znam/` too), `c23/`. This directory holds the daemon, `zclassic-cli`, `zclassic-tx` and their unit tests.
- `leveldb/`, `secp256k1/`, `univalue/` and `pow/tromp/` are third-party trees: do not edit or reformat them.
- A new source or test file is listed in `Makefile.am`, `Makefile.test.include` or `Makefile.gtest.include` and needs a rule in `zcutil/dev/impact.rules`; `zcutil/bin/zcl-dev check-rules` fails otherwise.
- Locks: `cs_main` before `cs_wallet` before `mempool.cs`; never the reverse. `-DDEBUG_LOCKORDER` reports violations ([doc/developer-notes.md](../doc/developer-notes.md)).
- Anything linked into the daemon builds on Linux, macOS arm64 and the mingw cross-compiler with the release GCC 9; C in here compiles as gnu17 (no `nullptr`, `constexpr`, attributes, `typeof`).
- Do not run `src/test/test_bitcoin` or `src/zcash-gtest` bare as a quick check; each runs for a long time. Pass a suite or filter (see `test/AGENTS.md` and `gtest/AGENTS.md`).

Tests: `zcutil/bin/zcl-dev select` names the CI steps for your diff; run `zcutil/local-ci.sh --commit <sha> --only <steps> test <outdir>`. Focused suites: `zcutil/bin/zcl-dev t-fast` once the test tool lands, else the commands in `test/AGENTS.md`.
