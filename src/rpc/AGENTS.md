# rpc agent rules

Imports the root contract: [../../AGENTS.md](../../AGENTS.md), and [../AGENTS.md](../AGENTS.md) for `src/`. Commands are registered through [register.h](register.h) and the table in `server.cpp`.

- RPC names, parameters and result fields are a public interface (scripts, the Qt wallet and exchanges call them). Do not rename, remove or retype one; add an optional parameter or a new command instead.
- A new command is registered in its `Register*RPCCommands` function; a string-typed argument that must be parsed as JSON also needs a row in `vRPCConvertParams` in `client.cpp`, or `zclassic-cli` sends it as a string.
- Every command throws its full usage text (summary, arguments, result, `HelpExampleCli`, `HelpExampleRpc`) when called with wrong arguments; keep the text true when behaviour changes.
- Wallet-bearing commands (`src/wallet/rpc*.cpp`) are custody code: never log or echo key material, and add no second send path ([../wallet/AGENTS.md](../wallet/AGENTS.md)).
- `zslp.cpp` and `znam.cpp` commands answer "disabled" unless `-zslpindex=1` or `-znamindex=1`; keep that behaviour ([../zslp/AGENTS.md](../zslp/AGENTS.md)).
- Take `cs_main` before `cs_wallet`, never the reverse, and never hold a lock while waiting on another thread.

Tests: `src/test/test_bitcoin --run_test=rpc_tests,rpc_wallet_tests`, `src/zcash-gtest --gtest_filter='rpc.*:HTTPRPC.*'`, the qa scripts `zcutil/bin/zcl-dev guide <file>` lists, then `zcutil/local-ci.sh --commit <sha> --only test_bitcoin-full,zcash-gtest-full,regtest-smoke,zclassic-tx-util test <outdir>`.
