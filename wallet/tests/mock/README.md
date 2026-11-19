# tests/mock — localhost JSON-RPC stand-in for zclassicd

A single-file C23 program (`mockrpc.c`, no dependencies, one request at a time) that answers the wallet's JSON-RPC calls from
canned per-scenario fixtures, with **zero product-code changes**. It is the
shared backend for the L1 widget tests (point the real `RPC` at it via
`rpc->setConnection()`) and the L2 Xvfb E2E (`--no-embedded` bundle against it).

Why this works: the wallet's only network primitive is `Connection::doRPC`,
which POSTs HTTP/Basic-auth JSON-RPC 1.0 and reads `parsed["result"]` off the
reply (`src/connection.cpp:2476`). The mock ignores Basic auth and wraps each
fixture in `{"result": …, "error": null, "id": …}`.

## Build and run

```sh
cc -std=c2x -O2 -Wall -Wextra -o tests/mock/mockrpc tests/mock/mockrpc.c
MOCK_PORT=18232 MOCK_SCENARIO=funded-synced MOCK_LOG=/tmp/mockrpc.requests.log \
  tests/mock/mockrpc
```

In the proot chroot build it the same way (gcc 9 accepts `-std=c2x`):

```sh
/home/rhett/zclbuild/prun bash -c \
  'cd /src/wallet/tests/mock && cc -std=c2x -O2 -o /tmp/mockrpc mockrpc.c && \
   MOCK_PORT=18232 MOCK_SCENARIO=funded-synced MOCK_FIXTURES=/src/wallet/tests/mock/fixtures \
   MOCK_LOG=/tmp/mockrpc.requests.log /tmp/mockrpc'
```

`sh tests/mock/test-mockrpc.sh` builds it and checks every behaviour below; the local CI
(`zcutil/local-ci.sh test`) runs it.

### Env vars
| var | default | meaning |
|-----|---------|---------|
| `MOCK_PORT` | `18232` | TCP port on `127.0.0.1` |
| `MOCK_SCENARIO` | `funded-synced` | dir under `fixtures/` |
| `MOCK_LOG` | `mockrpc.requests.log` next to the binary | one compact request body per line |
| `MOCK_FIXTURES` | `fixtures` next to the binary | directory holding the scenario dirs |

### Control / health (GET — the wallet never uses these)
- `GET /` → `{ok, scenario, port, log}`
- `GET /__shutdown` → graceful stop (also responds to SIGTERM/SIGINT)

## Scenarios
- **funded-synced** — synced, nonzero shielded (100) + transparent (12.345)
  balance; a Sapling `zs…`, a Sprout `zc…`, and a `t1…` address; receive+send
  transparent txs + a received shielded note with a memo.
- **fresh-empty** — synced, zero balance, exactly one Sapling addr, no txs.
- **syncing** — `blocks` (850000) far below `headers` (1700000) → ~50%, with
  `verificationprogress` pinned at the misleading ~0.9635 ("96%-stuck") value
  the headers-based sync logic must ignore.

## Per-method resolution (first hit wins)
1. `fixtures/<scenario>/<method>.json` — the bare **result** value (not enveloped).
2. a built-in default in `DEFAULTS` (`mockrpc.c`) — key dumps, imports,
   `z_getnewaddress`/`getnewaddress`, `z_getoperationstatus`, `z_sendmany` opid,
   `stop`, `getnetworksolps`, empty `z_listreceivedbyaddress`.
3. JSON-RPC `-32601 Method not found` — mirrors a real daemon.

Malformed request JSON → `-32700 Parse error` (exercises the wallet error path).

## Methods answered
`getinfo`, `getblockchaininfo`, `getbootstrapinfo`, `getnetworksolps`,
`z_gettotalbalance`, `getaddressesbyaccount`, `z_listaddresses`,
`listunspent`, `z_listunspent`, `listtransactions`, `gettransaction`,
`z_listreceivedbyaddress`, `z_getoperationstatus`, `z_sendmany`,
`getnewaddress`, `z_getnewaddress`, `dumpprivkey`, `z_exportkey`,
`importprivkey`, `z_importkey`, `stop`.

## Asserting a request payload (e.g. z_sendmany change routing)
Every request body is appended to `MOCK_LOG` as a compact single line. A test
can grep the log for the `z_sendmany` call and parse `params` to assert the
change recipient is a `zs…` (auto-shield on) vs a `t…` (off).
