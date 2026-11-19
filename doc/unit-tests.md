# Unit tests

zclassicd has two C++ unit-test binaries and a set of shell regression tests. Run focused tests while you work and let local CI run the full sets.

| Binary | Framework | Sources | Run one part |
| --- | --- | --- | --- |
| `src/test/test_bitcoin` | Boost.Test | `src/test/*_tests.cpp`, `src/wallet/test/` | `src/test/test_bitcoin --run_test=<suite>` (`--list_content` lists suites) |
| `src/zcash-gtest` | googletest | `src/gtest/`, `src/wallet/gtest/` | `src/zcash-gtest --gtest_filter='<Suite>.*'` (`--gtest_list_tests`) |
| `qa/rpc-tests/*.sh` | POSIX `sh` | isolated regtest nodes | `sh qa/rpc-tests/<script>.sh <dir-with-zclassicd>` |

`zcutil/build.sh` builds both binaries unless it is given `--disable-tests`. To rebuild one: `make -C src test/test_bitcoin` or `make -C src zcash-gtest`. The gtest binary needs the Sprout and Sapling parameter files (`zcutil/fetch-params.sh`).

A bare `test_bitcoin` or `zcash-gtest` runs everything and takes a long time; use it only through local CI:

```sh
zcutil/bin/zcl-dev select                                         # which steps your diff needs
zcutil/local-ci.sh --commit <sha> --only test_bitcoin-full,zcash-gtest-full test <outdir>
```

Rules for tests and where the layout is explained:

- `src/test/AGENTS.md` and `src/gtest/AGENTS.md` for the two binaries, `qa/AGENTS.md` for the shell tests, `wallet/docs/TESTING.md` for the Qt wallet.
- The agent-oriented testing guide is `doc/agent/TESTING.md` (a separate work unit; until it exists, use the files above and `zcutil/bin/zcl-dev guide <path>`). <!-- doc-path-ok -->
- Naming and the Boost pattern: `src/test/README.md`. Add a new file to `src/Makefile.test.include` or `src/Makefile.gtest.include` and to `zcutil/dev/impact.rules`.
