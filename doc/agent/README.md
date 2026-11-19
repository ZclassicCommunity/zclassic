# Agent documents

Guardrails and navigation for coding agents working in zclassicd: lessons learned, traps to avoid, a closed table of facts about the tree, and the wiki that finds them. Every item names a tracked path and is checked by a tool, so a line that stops being true is found rather than trusted.

Commands: `zcl-dev guide <paths>`, `zcl-dev lessons find <query>`, `zcl-dev know <term>`, `zcl-dev know --check`, `zcl-dev check-docs`, `zcl-dev wiki`

- [LESSONS.md](LESSONS.md): one measured failure and its invariant per line, `OPEN` or `DONE`. Add one with `zcl-dev lessons add OPEN <tracked-path> "<text>"`.
- [TRAPS.md](TRAPS.md): what not to do, why, and where, grouped by the paths that trigger each section.
- [FACTS.tsv](FACTS.tsv): subject, relation, object, context, confidence and why, over a closed vocabulary. `zcl-dev know <term>` answers from it, or says `UNKNOWN`.
- [WIKI.md](WIKI.md): how `zcl-dev wiki`, `zcl-dev read`, `zcl-dev lessons` and `zcl-dev know` behave.
- [CODEBASE_MAP.md](CODEBASE_MAP.md): every top-level directory, every `src/` subdirectory and the major files, each with its purpose, test suites and owning `AGENTS.md`; claim markers keep the load-bearing paths checked.
