---
name: zcl-review
description: Use when a zclassicd commit range needs its independent review. Spawns the read-only zcl-review agent with a worktree, BASE..TIP and the unit spec, and records the verdict.
---

# zcl-review

Every unit needs one reviewer who is not its author, of any model. Review a range that is finished and committed.

1. Gather: the worktree path, `BASE..TIP` with both as full shas, and the unit spec (contract, owned files, acceptance commands and their results).
2. Check authorship first: `git -C <worktree> log --format="%H %an %s%n%b" BASE..TIP`. The reviewer must not be an author or `Co-Authored-By` of any commit in the range; if the model is, use a different one.
3. Spawn the `zcl-review` agent (`.claude/agents/zcl-review.md`) with those three items. It is read-only and replies with `ACCEPT`, `ACCEPT-WITH-FIXES` or `REJECT` on the first line, numbered findings with file:line and a failing input, and a final `review record` line.
4. Record the verdict, when zcutil/bin/zcl-dev-review is built: run the line the reviewer ended with, `zcutil/bin/zcl-dev review record --reviewer <model> --verdict <token> BASE..TIP`. Until it is built, keep the verdict line in the unit report. The reviewer never records or commits itself.
5. `ACCEPT-WITH-FIXES` and `REJECT`: the implementer fixes forward with new commits, then a delta review of `ACCEPTED..TIP` or a fresh review of the new range. Do not amend a reviewed range.

This skill grants no consensus, custody, datadir or deployment authority.
