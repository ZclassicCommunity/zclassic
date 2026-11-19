# qa: regtest scenarios and test isolation

End-to-end scenarios that start real `zclassicd` nodes on regtest in throw-away datadirs, plus the libraries that keep them from colliding on ports or leaving daemons behind.

## What lives here

- `rpc-tests/`: one POSIX `sh` scenario per file (crash and restart, wallet consistency, RPC overload, indexes, bootstrap); the index is [rpc-tests/README.md](rpc-tests/README.md).
- `lib/`: `isolation.sh` (leased ports through `zcutil/dev/zcl-port.c`, a process group per node) and `iso-reaper.sh` (kills everything tagged by the run when the script ends by any means); see [lib/README.md](lib/README.md).
- `key1-guard.c`, `key1-guard.sh`, `key1-walletdb-baseline.txt`: the wallet secrecy guard, CI step `key1-guard`.
- `zslp/`, `zcash/`: token fixtures with a mainnet cross-check, and inherited helper scripts (some retired).
- `bootstrap-resume/`: snapshot resume tests (owned by the bootstrap work; read them, do not change them here).

## Run one

```sh
sh qa/rpc-tests/getrpcinfo.sh --bin <dir-with-zclassicd> --work <empty-dir>
```

Most scripts take `--bin`, `--work` and optional `--base` (a leased port base). Add a new script to `zcutil/dev/impact.rules` and to a `step` in `zcutil/local-ci.sh`; `zcutil/bin/zcl-dev check-rules` fails otherwise.

## Traps

- Never derive ports from the PID; two parallel runs collide. Use the lease helper or an explicit base.
- A node killed before its first chainstate flush restarts from height 0; wait for the re-sync before reading wallet state after a hard kill.
- `-testcrashpoint` and the other `-test*` options are accepted on regtest only.
- Never loosen an assertion, tolerance or timeout to turn a run green; `zcl-lint wallclock` flags assertions decided by elapsed time.
- The Python test framework is gone and must not return; `zcutil/check-no-python.sh` fails when it does.

## Related

Rules: [AGENTS.md](AGENTS.md). Isolation lint: `zcl-lint testiso` in [zcutil/lint/README.md](../zcutil/lint/README.md). Facts: `zcutil/bin/zcl-dev know leased-ports`, `zcutil/bin/zcl-dev know orphaned-test-daemons`.
