# src/test agent rules

Imports the root contract: [../../AGENTS.md](../../AGENTS.md). Naming and layout: [README.md](README.md). The Boost.Test binary is `test_bitcoin`; its sources are listed in [../Makefile.test.include](../Makefile.test.include).

- One file per unit under test, `<name>_tests.cpp`, one `BOOST_FIXTURE_TEST_SUITE(<name>_tests, ...)`; add the file to `Makefile.test.include` and a rule to `zcutil/dev/impact.rules`.
- `TestingSetup` (`test_bitcoin.cpp`) builds a temporary datadir under the system temp path. A test never reads or writes a real datadir, wallet or home directory.
- Fixtures in `data/` (JSON vectors, `c23_golden/`, `token_name_rules.txt`, `oversize_grandfather_txids.txt`) are evidence from the reference node or from Z23. Never hand-edit or regenerate one to make a test pass; `rust_oracle/README.md` documents how the golden corpus was captured.
- Never loosen an assertion, tolerance or timeout to pass; a failing consensus vector means the code is wrong.
- Run a suite, never the whole binary, while iterating: `src/test/test_bitcoin --run_test=<suite>` (`--list_content` lists suites). `zcutil/build.sh` builds it unless `--disable-tests` is passed; rebuild one binary with `make -C src test/test_bitcoin`.
- The `.c` test here (`tree_root_c_tests.c`) is C compiled as gnu17 and also runs in the `tree-root-asan` CI step.

Tests: `src/test/test_bitcoin --run_test=<suite>`, then `zcutil/local-ci.sh --commit <sha> --only test_bitcoin-full test <outdir>` (see [doc/unit-tests.md](../../doc/unit-tests.md)).
