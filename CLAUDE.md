@AGENTS.md

Claude Code notes:

- Skill: `.claude/skills/zcl-dev` routes a task to the documents above. It grants no extra consensus, custody, datadir or deployment authority.
- Do not read `doc/building-daemon-from-source.md` or `wallet/docs/BUILDING.md` whole; `grep -n '^#' <file>` and open the section you need.
- Never use Python, even for a one-off; use `sh`, `awk`, `sed` or a small C program.
