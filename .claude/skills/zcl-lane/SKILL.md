---
name: zcl-lane
description: Use when splitting zclassicd work into parallel units. Keeps file ownership pairwise disjoint, derives the base by full sha, makes worktrees on the build host and returns immutable commit ids.
---

# zcl-lane

Contract first: `AGENTS.md`. This skill adds only the parallel-assignment routine.

1. Split into units whose file sets are pairwise disjoint. List each unit's owned paths; no path in two units. Prefer a new file per unit over edits to a shared one.
2. Shared one-row tables are the usual collision points. A unit may add exactly its own row and nothing else; a second unit editing the same table is a conflict to serialize or merge by hand:
   - `zcutil/Makefile` `SUBDIRS` (one directory per unit)
   - `zcutil/lint/rules.def`
   - `zcutil/dev/impact.rules` and `zcutil/dev/tests.rules`
   - `src/Makefile.am` and the other `src/Makefile*.am` source and test lists
   Also shared: `AGENTS.md` and `doc/agent/*.md` (touch only the line you own).
3. Base: the current tip of the integration branch, as a full 40-hex sha (`git rev-parse <branch>`), never a branch name or abbreviation. Every unit and reviewer is given that sha.
4. Worktrees on the build host: `git -C <bare-or-main> worktree add <dir>/<unit> -b <branch>/<unit> <BASE-sha>`. Use absolute paths, build the node out of tree, and prefix heavy commands with the host broker (`devbuild --wait`) when it exists. Never touch another checkout, a datadir or a running node.
5. Check the lane with `zcutil/bin/zcl-dev select <base>` for the CI steps, `zcl-dev check-rules` for rule rows, and `zcl-dev check-docs`.
6. Return immutable commit ids: the branch name AND the full tip sha, plus the `BASE..TIP` range. Do not rewrite a returned range; fix forward with a new commit. Pass the range to the reviewer (see `.claude/skills/zcl-review/SKILL.md`).

Agents: `.claude/agents/zcl-scout.md` (premise check), `.claude/agents/zcl-unit-haiku.md` (well-specified units), `.claude/agents/zcl-implement.md` (harder units), `.claude/agents/zcl-review.md` (independent review).

This skill grants no consensus, custody, datadir or deployment authority.
