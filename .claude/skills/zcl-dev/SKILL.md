---
name: zcl-dev
description: Use when changing zclassicd (daemon, C23 core, qa scripts, local CI) or the Qt wallet. Routes the task to the contract, the area rules, the traps and lessons, and the CI steps, instead of copying them.
---

# zcl-dev

Start with the contract: `AGENTS.md` (hard rules: no consensus change, verbatim vendored code, no Python/Rust/GitHub CI, custody, gnu17 portability, review).

1. Brief for your files: `make -C zcutil && zcutil/bin/zcl-dev guide <paths>`.
   Navigate with `zcl-dev code map|owner|impact|file|sym|refs`, `zcl-dev wiki`, `zcl-dev lessons find`, `zcl-dev know <term>`; `zcl-dev doctor` lists what the host lacks.
2. Pick the area document:
   - wallet or GUI: `wallet/AGENTS.md`, `wallet/docs/TESTING.md`
   - `src/c23/**`, vendoring, golden corpus: `src/c23/AGENTS.md`, `src/c23/README.md`
   - `qa/**`, tests, ports, crash points: `qa/AGENTS.md`, `qa/rpc-tests/README.md`
   - build, release, toolchains: `doc/building-quickstart.md`
   - CI, receipts, step names: `doc/local-ci.md`
3. Before repairing odd-looking behaviour: `doc/agent/TRAPS.md`. After learning something measured: add a line to `doc/agent/LESSONS.md` and run `zcl-dev check-docs`.
4. Choose the proof: `zcl-dev select [base]` lists CI steps and qa scripts for your diff; run them with `zcutil/local-ci.sh --commit <sha> --only <steps> test <outdir>` (or `test-changed`). Read the log and `receipts.jsonl`; a green summary is a claim.
5. A new source or test file needs a rule in `zcutil/dev/impact.rules`; `zcl-dev check-rules` enforces it.
6. Before landing: `zcutil/bin/zcl-dev verify` (select, focused tests when built, `zcl-lint all`, then the `test-changed` hint), and `zcutil/local-ci.sh --commit <sha> dev-tools <outdir>` for the `check-dev-tools` step with a receipt. Agents can read the same tools over MCP (`zcutil/bin/zcl-mcp`).

This skill grants no consensus, custody, datadir or deployment authority.
