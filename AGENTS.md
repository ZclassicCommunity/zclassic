# zclassicd agent contract

Shared by every coding agent (Claude Code, Codex, others). `CLAUDE.md` imports this file.

zclassicd is the ZClassic full node (C++, a Zcash-derived fork), its command-line tools, and the Qt GUI wallet that embeds the daemon. The cryptographic core is C23 code vendored byte-identical from the Z23 node. This file is a contract, not a build guide: the build guide is [doc/building-quickstart.md](doc/building-quickstart.md).

## Layout

- `src/` the daemon (`zclassicd`, `zclassic-cli`, `zclassic-tx`) and its unit tests (`src/test/`, `src/gtest/`).
- `src/c23/` the C23 core that replaced librustzcash. `vendor/` and `services/vendor/` are verbatim Z23 files; the rest (`glue/`, `compat/`, `test/`, `tools/`) is owned here. See [src/c23/AGENTS.md](src/c23/AGENTS.md).
- `wallet/` the Qt GUI wallet (custody-bearing). See [wallet/AGENTS.md](wallet/AGENTS.md).
- `qa/` shell regression tests that start isolated regtest nodes. See [qa/AGENTS.md](qa/AGENTS.md).
- `zcutil/` build, release and local CI scripts; `zcutil/dev/` the `zcl-dev` developer tool; `zcutil/tools/` vendored Z23 helper code.
- `depends/` pinned third-party build system. `doc/` manuals. `contrib/` helper scripts.
- `.claude/` agents and skills for Claude Code.

## Commands

```sh
./zcutil/build.sh -j"$(getconf _NPROCESSORS_ONLN)"         # dev build into src/ (HOST is an env var, never an argument)
./zcutil/build-release.sh linux|win64 -j"$(getconf _NPROCESSORS_ONLN)"
make -C zcutil && zcutil/bin/zcl-dev guide <paths>      # brief for the files you will touch
zcutil/bin/zcl-dev select [base-ref]                        # which CI steps your diff needs
zcutil/local-ci.sh --commit <sha> --only <steps> test <outdir>   # own-machine CI, focused
zcutil/local-ci.sh --commit <sha> test-changed <outdir>          # steps chosen by zcl-dev select
zcutil/local-ci.sh --commit <sha> all <outdir>              # full candidate; macOS: zcutil/local-ci-macos.sh
make -C zcutil check                                        # every developer tool's selftest (zcutil/bin/zcl-dev help lists subcommands)
zcutil/bin/zcl-dev doctor                                   # what this host lacks to build and test, with the fix for each gap
zcutil/bin/zcl-dev verify [--base ref]                      # one trip for committed changes: select, focused tests when built (needs the zcl-dev-t-fast alias), zcl-lint all, test-changed hint (no `tests`, `t-fast --changed` or `hooks install` line yet: they land with their tools; zcl-lint has no `fast`, so verify runs `all`); on Windows lint is UNAVAILABLE (exit 2), run it on a POSIX host
zcutil/bin/zcl-dev code map|owner|impact|file|sym|refs ...  # code intelligence: navigate before searching
zcutil/bin/zcl-dev wiki [topic]                             # walk the docs and source trees one topic at a time
zcutil/bin/zcl-dev lessons find <words>                     # search lessons, traps and facts (add: lessons add)
zcutil/bin/zcl-dev know <term>                              # closed FACTS table answer, UNKNOWN when no row; know --check validates it
zcutil/bin/zcl-dev gen --check rpc-parity                   # also: gen --check flags, gen rpc-reference|args-reference|inventory
zcutil/bin/zcl-lint all                                     # every lint rule and ratchet; zcl-lint kpi prints the tree-health floor
zcutil/bin/zcl-dev verify --gates                           # the check-dev-tools gates after `make -C zcutil check`: zcl-lint all, check-tests (when built), know, rpc-parity, flags; stops at the first failure
```

Run a single qa script by the form its usage line gives: most take `sh qa/rpc-tests/<script>.sh --bin <dir-with-zclassicd> --work <empty dir> [--base <port>]` (add `--peer-bin <previous release>` where its header asks for one); `token_name_rules`, `wallet_tokenguard`, `znam_index`, `zslp_*`, `startup_bad_home` and `zclassic_tx_util` take one positional `<dir>` holding the binaries. Ports are leased automatically (qa/lib/README.md), so no port needs choosing. Unit tests: `src/test/test_bitcoin --run_test=<suite>` after a `--enable-tests` build ([doc/unit-tests.md](doc/unit-tests.md)). Where the host has a build broker (for example `devbuild --wait`), run heavy commands behind it.

Before editing, run `zcutil/bin/zcl-dev guide <paths>`: nearest rules, CI steps, lessons and traps in one brief.

## Hard rules

- **Consensus does not change.** zclassicd is the reference. Never alter a rule, checkpoint, activation height or acceptance predicate. A speedup or refactor on a consensus path must be proven accept/reject-identical against the old code. A divergence is fixed to match zclassicd bug-for-bug.
- **Vendored code is verbatim.** `src/c23/vendor/**`, `src/c23/services/vendor/**` and `zcutil/tools/vendor/**` are Z23 files, changed only by the matching `revendor.sh` and verified by `check-vendor.sh`. Never hand-edit them; derived files carry a header `derived from Z23 <path>@<commit>, changed`.
- **No Python, no Rust, no GitHub CI.** New tooling is C23 or small POSIX sh. CI runs on our own machines: `zcutil/local-ci.sh` (macOS: `zcutil/local-ci-macos.sh`). Never add or dispatch GitHub Actions.
- **Custody.** The wallet holds keys. Never spend funds, export keys or touch a real datadir, wallet file or profile. Tests use isolated datadirs, isolated profiles and leased ports; never derive a port from the PID.
- **Portability.** Anything linked into the daemon or wallet must build on Linux, macOS arm64 and the mingw cross-compiler. Release builds use GCC 9: C compiles as gnu17 (no `nullptr`, `constexpr`, attributes, `typeof`, `_BitInt`, `#embed`); developer tools avoid C23-only syntax too.
- **Review.** Every change is reviewed by someone other than its author before merge. Commits are authored by the repository owner; an AI-written commit ends with a `Co-Authored-By:` trailer naming the model.
- **Preserve unrelated work.** Never reset, overwrite or commit other people's dirty files. Never rewrite shared history.
- **Production.** Do not restart, deploy to or edit a production service or its datadir without being asked; never restart one twice in quick succession.

## Verify, do not trust

Run the test and read the log: an exit status behind a pipe, a hash, a green summary line or a doc are each only a claim. Re-derive counts from the tree. Before repairing something that looks wrong, check [doc/agent/TRAPS.md](doc/agent/TRAPS.md): it may be intentional. Record what you learned in [doc/agent/LESSONS.md](doc/agent/LESSONS.md) as one line: `OPEN|DONE <tracked-path> — <measured failure and the invariant>`; `zcl-dev check-docs` validates the paths.

## Where detail lives

- Build, release, platforms: [doc/building-quickstart.md](doc/building-quickstart.md), [doc/building-daemon-from-source.md](doc/building-daemon-from-source.md), [wallet/docs/BUILDING.md](wallet/docs/BUILDING.md).
- Local CI, step names, receipts: [doc/local-ci.md](doc/local-ci.md).
- Agent documents: [doc/agent/README.md](doc/agent/README.md) (index), [doc/agent/WIKI.md](doc/agent/WIKI.md) (walking the docs), [doc/agent/KPI.md](doc/agent/KPI.md) (tree-health floor), [zcutil/lint/README.md](zcutil/lint/README.md) (lint rules and ratchets). The MCP server for agents is `zcutil/agent/mcp/` (`zcutil/bin/zcl-mcp`).
- C23 core and vendoring: [src/c23/README.md](src/c23/README.md), [doc/c23-build.md](doc/c23-build.md).
- Wallet durability: [doc/wallet-crash-consistency.md](doc/wallet-crash-consistency.md). Wallet tests: [wallet/docs/TESTING.md](wallet/docs/TESTING.md).
- Tests: [doc/unit-tests.md](doc/unit-tests.md), [qa/rpc-tests/README.md](qa/rpc-tests/README.md).
- Release notes: [doc/release-notes.md](doc/release-notes.md).
- Nested `AGENTS.md` files in `wallet/`, `src/c23/` and `qa/` add area rules; nested `CLAUDE.md` files are not needed.
