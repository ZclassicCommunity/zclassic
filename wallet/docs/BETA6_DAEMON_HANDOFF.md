# beta6 — daemon handoff (dev-owned)

The GUI side of beta6 is done (version bumped, Send form merged, all tests green). The **one
blocker only the daemon owner can clear** is making the embedded daemon **reproducible + tagged**.

## The problem
The RC bundle embeds a daemon built as `v2.1.2-beta5-03c27eb43-DIRTY` — from an **untagged**
branch tip (`feature/bootstrap-param-parallel`) with **~16 uncommitted changes**
(`bootstrap.cpp/.h`, `init.cpp`, `txdb.cpp`, untracked `mapport.cpp/.h`, `startuptimer.*`,
`test_param_presence.cpp`, `Makefile.am`/`Makefile.gtest`). It cannot be rebuilt from any commit,
so the shipped binary doesn't match any source — a non-starter for a signed release.

## The fix (recipe)
1. **Pin the daemon to `be6f0031d`** — the commit that completes `getwalletsummary` (instant
   balance) but is **before** the two parallel-Sapling-rescan commits (`00b7568b6`/`03c27eb43`).
   The rescan engine is explicitly *not yet bundled* (memory `parallel-rescan-engine.md`); it only
   helps cold restore/import and expands the regression surface for zero steady-state benefit, so
   it's **deferred to a later release**. Drop it from the beta6 daemon.
2. **Commit the embedded-daemon changes that beta6 actually depends on** on top of `be6f0031d` —
   the NAT-PMP `mapport.cpp/.h` (the GUI panel drives `-natpmp=1`) and `startuptimer.*` if the
   GUI's startup-timing log expects it. Leave out the bootstrap-param-parallel experiment unless
   beta6 needs it.
3. **Bump the version:** `configure.ac` `define(_CLIENT_VERSION_BUILD, 4)` → `5`. The macro maps
   `build < 25 → beta(N+1)`, so build `5` yields **beta6** (matches the GUI's `APP_VERSION`).
4. **Tag it:** `git tag v2.1.2-beta6 <commit>` and push. Then the embedded-daemon footer reads a
   clean tag, not `…-DIRTY`.
5. **Merge to daemon master** so the published source equals the shipped binary.

## Verify
- `./src/zclassicd --version` shows `v2.1.2-beta6` (no `-dirty`).
- `git describe --tags` on the build commit is clean.
- The GUI's `getwalletsummary` instant-balance lights up (the capability probe latches off and
  falls back to `z_gettotalbalance` only on an *older* daemon — confirm the new daemon answers it).

Once this daemon is tagged, the GUI release builder embeds it and we cut the 3-platform beta6
bundles. Until then the GUI bundle uses the existing (functionally-correct) embedded daemon, so
**this blocks the signed release, not testing.**
