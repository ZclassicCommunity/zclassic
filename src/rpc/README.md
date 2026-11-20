# src/rpc: JSON-RPC commands

The JSON-RPC command tables of the daemon, one file per area, plus the call-statistics code behind `getrpcinfo`.

## What lives here

- `server.cpp`, `server.h`: `CRPCTable` (`tableRPC`), `CRPCCommand`, `StartRPC`, `StopRPC`, `RPCRunLater` and the control commands, including `getrpcinfo`.
- `blockchain.cpp`, `net.cpp`, `misc.cpp`, `mining.cpp`, `rawtransaction.cpp`: the core command groups, each with a `Register*RPCCommands` function declared in `register.h`.
- `zslp.cpp`, `znam.cpp`: token and name index commands; they answer a disabled error unless `-zslpindex=1` or `-znamindex=1`.
- `client.cpp`: `vRPCConvertParams`, the argument types `zclassic-cli` converts to JSON.
- `rpcstats.cpp`, `rpcstats.h`: `RpcCallScope`, `RpcCallBegin`, `RpcCallEnd`; a table of 128 in-flight calls and per-method aggregates (names and durations only).
- `protocol.cpp`, `protocol.h`: HTTP status codes and JSON-RPC error codes. The HTTP transport is `src/httpserver.cpp` and `src/httprpc.cpp`.

## Traps

- Names, parameters and result fields are a public interface; add an optional parameter or a new command instead of changing one.
- A string argument that must be JSON needs a `vRPCConvertParams` row.
- A full work queue answers HTTP 503; out-of-range `-rpcthreads`, `-rpcworkqueue` or `-rpcservertimeout` stops start-up instead of being clamped.
- Take `cs_main` before `cs_wallet`; `getconnectioncount` and `getpeerinfo` take only `cs_vNodes` so a long `verifychain` does not block them.
- Wallet commands live in `src/wallet/rpc*.cpp` and are custody code; never log key material.

## Tests

Boost suites `rpc_tests`, `rpc_wallet_tests`, `rpcstats_tests`, `httpserver_tests`; gtest `rpc` and `HTTPRPC`; qa scripts `qa/rpc-tests/getrpcinfo.sh`, `qa/rpc-tests/rpc_busy.sh`, `qa/rpc-tests/rpc_bind_conflict.sh`. List them with `zcutil/bin/zcl-dev t-list`.

## Related

Rules: [AGENTS.md](AGENTS.md). Payment API: [doc/payment-api.md](../../doc/payment-api.md). Facts: `zcutil/bin/zcl-dev know getrpcinfo`, `zcutil/bin/zcl-dev know http-503-overload`.
