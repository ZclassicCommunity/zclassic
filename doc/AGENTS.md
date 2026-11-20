# doc agent rules

Imports the root contract: [../AGENTS.md](../AGENTS.md). Index of agent documents: [agent/TRAPS.md](agent/TRAPS.md), [agent/LESSONS.md](agent/LESSONS.md); release notes: [release-notes.md](release-notes.md).

- A document states what the code does today. Re-read the code before you write or keep a claim; a stale sentence is worse than none. Paths, command names, step names and flags you cite must exist.
- Relative links must resolve and `#anchors` must match a heading; `zcutil/bin/zcl-lint md-links` counts broken ones against a shrink-only baseline.
- `doc/agent/LESSONS.md` lines are `OPEN|DONE <tracked-path> — <measured failure and the invariant>`; `doc/agent/TRAPS.md` sections carry a `Paths:` line. `zcutil/bin/zcl-dev check-docs` validates both.
- `doc/history/` and the old `release-notes-beta*.md` files are a record; do not rewrite them. Release notes record shipped behaviour, not plans.
- Consensus and custody documents (`oversize-grandfather.md`, `wallet-crash-consistency.md`, `wallet-backup.md`) change only together with the code they describe.
- Never put keys, seeds, passphrases or real datadir paths of an operator in a document or example.
- Generated references (API, capability) are never tracked here; they are written to `zcutil/gen/` (ignored).

Tests: `zcutil/bin/zcl-dev check-docs`, `zcutil/bin/zcl-lint md-links`, `zcutil/local-ci.sh --commit <sha> --only check-dev-tools test <outdir>`.
