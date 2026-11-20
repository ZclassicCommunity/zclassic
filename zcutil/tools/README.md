# zcutil/tools: developer tools built from vendored Z23 code

`jsonq` is a small JSON path query tool (no jq, no Python, libc only). Its sources under `vendor/` are
copied byte for byte from the Z23 repository at the commit recorded in `Z23_SOURCE.tsv`
(`jsonq.c`, `jsonq_standalone.c`, `multicall.h`, the `zjsonp` pull parser and the `zutf8` validator).
The licence is Apache-2.0 (`LICENSE.z23`, `NOTICE`); never edit anything under `vendor/`.

```sh
make -C zcutil/tools          # builds zcutil/bin/jsonq (host cc, -std=gnu17)
make -C zcutil/tools check    # fixture test (test-jsonq.sh)
make -C zcutil/tools CC=x86_64-w64-mingw32-gcc EXEEXT=.exe    # Windows cross build
sh src/c23/tools/check-vendor.sh zcutil/tools/Z23_SOURCE.tsv  # source identity (make -C src check-tools-vendor)
```

```sh
printf '%s' "$json" | zcutil/bin/jsonq get result.items[1].id    # value; exit 1 if missing, 2 if malformed
printf '%s' "$json" | zcutil/bin/jsonq count result              # elements or keys
```

The shell tests use it through `qa/rpc-tests/jsonq_lib.sh` (`jget`, `jgetd`, `jlen`, `jraw`, `jhas`), which builds
it on first use. Filters that need select, sort_by, arithmetic or string interpolation still use jq.

To move to a newer Z23 commit run `sh zcutil/tools/revendor.sh <z23-repo> <commit>` (fails unless the commit contains `55245e2bd`; rewrites `vendor/`, `LICENSE.z23` and `Z23_SOURCE.tsv` from `vendor-files.txt`),
then run the checker and `make -C zcutil check`. Add a file to `vendor-files.txt` and re-run `revendor.sh` to vendor another Z23 file; `make -C zcutil/tools vendor-compile` proves every vendored C file builds under `-Werror` as gnu17 and c2x.

## Vendored for later tools (pin `9a191ef7b`)

Besides jsonq: `platform/modules/json/{json.h,json.c}` (the JSON reader/writer), `platform/modules/base/{safe_alloc,cleanse,hex}`
and `tools/mcp/{mcp_rpc.h,mcp_rpc.c}` (the MCP JSON-RPC server core). They are not linked by anything yet; the agent guard,
the MCP server and the other `zcl-dev-<cmd>` tools build against them, never against edited copies.

## Layout of `zcutil/`

`make -C zcutil` builds every tool into `zcutil/bin/` (git-ignored); `make -C zcutil check` runs every tool's selftest;
generated documents go to `zcutil/gen/` (git-ignored). `make -C zcutil CC=x86_64-w64-mingw32-gcc EXEEXT=.exe` cross builds
`zcl-dev`, `zcl-port` and `jsonq` (`zcl-lint` is POSIX-only). A tool lives in `zcutil/dev/<module>/` (a `zcl-dev-<cmd>` subcommand),
`zcutil/lint/` (a gate rule in `rules/`), `zcutil/agent/` or `zcutil/githooks/`, and adds one directory name to `SUBDIRS` in `zcutil/Makefile`.
`zcl-dev <cmd>` runs `zcl-dev-<cmd>` from the directory of `zcl-dev` (or `zcutil/bin`), starting in the repository root with
`ZCL_DEV_PREFIX` set to the caller's directory relative to the root; `zcl-dev help` lists built-in and discovered subcommands
using each binary's `--purpose` line.
