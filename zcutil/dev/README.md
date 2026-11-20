# zcutil/dev: the zcl-dev developer tool

The `zcl-dev` dispatcher, its built-in commands and the discovered `zcl-dev-<cmd>` tools, plus the port-lease helper `zcl-port`; plain C with libc only.

## Layout

- `zcl-dev.c`: the dispatcher and the built-in commands `guide`, `select`, `check-rules`, `check-docs`, `receipt`, `help`.
- `impact.rules`: which CI steps and qa scripts a path selects (`ALL` for consensus, chain state, the daemon wallet and the build); `tests.rules` maps paths to focused tests.
- `wiki/`: `wiki`, `read`, `lessons` and `know` (one program that acts by its name); see [doc/agent/WIKI.md](../../doc/agent/WIKI.md).
- `code/` (`zcl-dev code`), `tests/` (`t-list`, `t-fast`, `tests`, `check-tests`), `verify/`, `doctor/`, `gen/` (generated RPC and argument references, parity gates), `hooks/`.
- `lib/`: shared scanners (`gitfiles`, `cxxscan`, `incgraph`, `automake`).
- `zcl-port.c`, `zcl-port-selftest.sh`, `zcl-port-stress.c`: port leases used by `qa/lib/isolation.sh`.
- `test/`: fixtures and the dispatch and receipt tests that `make -C zcutil/dev check` runs.

## Build and check

```sh
make -C zcutil                 # every tool into zcutil/bin
make -C zcutil/dev check       # dispatcher fixtures, port selftest, check-rules, check-docs
zcutil/bin/zcl-dev help        # built-in and discovered subcommands
```

## Traps

- A new test file needs a row in `impact.rules`; a path with no rule selects every CI step, and `check-rules` fails on an unmapped tracked file under `src/`, `qa/` or `zcutil/`.
- A subcommand is its own binary `zcl-dev-<cmd>`; add its directory to `SUBDIRS` in `zcutil/Makefile`.
- Tools use `-std=gnu17`, no C23-only syntax, no bash, and build with the mingw cross compiler; `zcl-lint` itself is POSIX only.
- Never edit `zcutil/tools/vendor`; re-vendor from Z23 instead.
- Leases live in a shared directory regardless of `TMPDIR`; do not give a script a fixed port.

## Related

Rules: [../AGENTS.md](../AGENTS.md). Local CI: [doc/local-ci.md](../../doc/local-ci.md). Lint gates: [../lint/README.md](../lint/README.md). Facts: `zcutil/bin/zcl-dev know zcl-dev-tooling`.
