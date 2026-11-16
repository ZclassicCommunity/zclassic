# tests/mock — localhost JSON-RPC stand-in for zclassicd

A ~200-line `python3 http.server` that answers the wallet's JSON-RPC calls from
canned per-scenario fixtures, with **zero product-code changes**. It is the
shared backend for the L1 widget tests (point the real `RPC` at it via
`rpc->setConnection()`) and the L2 Xvfb E2E (`--no-embedded` bundle against it).

Why this works: the wallet's only network primitive is `Connection::doRPC`,
which POSTs HTTP/Basic-auth JSON-RPC 1.0 and reads `parsed["result"]` off the
reply (`src/connection.cpp:2476`). The mock ignores Basic auth and wraps each
fixture in `{"result": …, "error": null, "id": …}`.

## Run

```sh
MOCK_PORT=18232 MOCK_SCENARIO=funded-synced MOCK_LOG=/tmp/mockrpc.requests.log \
  python3 tests/mock/mockrpc.py
```

In the proot chroot (python3 is present there too):

```sh
/home/rhett/zclbuild/prun bash -c \
  'MOCK_PORT=18232 MOCK_SCENARIO=funded-synced MOCK_LOG=/tmp/mockrpc.requests.log \
   python3 /src/wallet/tests/mock/mockrpc.py'
```

### Env vars
| var | default | meaning |
|-----|---------|---------|
| `MOCK_PORT` | `18232` | TCP port on `127.0.0.1` |
| `MOCK_SCENARIO` | `funded-synced` | dir under `fixtures/` |
| `MOCK_LOG` | `tests/mock/mockrpc.requests.log` | one request body per line |

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
2. a built-in default in `DEFAULTS` (`mockrpc.py`) — key dumps, imports,
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
