# qa agent rules

Imports the root contract: [../AGENTS.md](../AGENTS.md). Index of scripts: [rpc-tests/README.md](rpc-tests/README.md).

## How a test script is built

- POSIX `sh`, one scenario per file in `qa/rpc-tests/`, a header comment naming its environment variables and what it proves. Run: `sh qa/rpc-tests/<script>.sh <dir-with-zclassicd-and-zclassic-cli>`.
- It starts regtest nodes in a fresh `mktemp -d` datadir, drives them with `zclassic-cli`, and removes everything on exit (trap on EXIT/INT/TERM). It never touches a real datadir, wallet or home directory.
- Shared helpers live in `wallet_matrix_lib.sh` (start, `kill9`, `sync_to`, `wait_height`); reuse them before writing new ones. `jq` is an allowed test dependency (the focal CI rootfs installs it); a new script must still run where only `jq`, `sh` and the build tools exist.
- Assertions print a named line and the script exits non-zero on the first unexplained failure. Never loosen an assertion, a tolerance or a timeout to make a run pass; find the cause.
- Add a new gate script to `zcutil/dev/impact.rules` and to a `step` in `zcutil/local-ci.sh`; `zcl-dev check-rules` fails otherwise.

## Peer binaries

Scripts that cross-check versions take a second binary directory (`--peer-bin`, `--alt-bin`, or `ZCL_CI_PREV_BIN` through CI): a previous release's `zclassicd` and `zclassic-cli`. Use the peer for the behaviour under test (cross-version wallet and encryption tests); do not substitute the build under test for it.

## Crash points and kills

`-testcrashpoint=<name>[:<n>]` (regtest only, rejected elsewhere in `src/init.cpp`) makes the node `_exit(77)` at the nth wallet or chain-state write point (`any` matches all). Use it for deterministic crash tests; use `kill -9` only where the scenario is an unclean external kill. After a hard kill a node that never flushed its chainstate restarts from height 0: wait for it to re-sync from the peer before you read state (`wallet_platform_checks.sh`, `wallet_reaccept_bound.sh`).

## Ports

Use the port helper; never derive ports from the PID. `$((20000 + ($$ % 20000)))` collides when two scripts run in parallel (the test stage, `--base`, and a developer run all do). Until the helper lands, take an explicit base (`--base` or `--port-base`; the CI steps pass one), give each node `base + 2*i` for RPC and p2p, and fail fast when a port is already bound. `git grep -n '\$\$ %' qa` lists the scripts that still derive ports from the PID; they are the known collision sources.

## Other trees

`qa/zslp/` holds token fixtures and a mainnet cross-check, `qa/bootstrap-resume/` the snapshot resume tests, `qa/zcash/` inherited helper scripts (some are retired). The Python test framework is gone and must not return.
