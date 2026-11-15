# ZClassic Wallet v2.1.2-beta7 — release candidate

This release is being validated. Download links continue to point to beta6
until reviewed beta7 artifacts are published.

- Windows portable builds include GCC, C++ and pthread runtimes; missing-DLL
  errors are caught by checks on both the GUI and its embedded daemon.
- Sync uses the daemon's existing database-cache defaults and user settings
  instead of forcing a smaller cache. No validation checks are removed.
- Windows notification messages avoid unnecessary write waits.
- Private sent-history and notification-token files use atomic writes and
  owner-only permissions, including protected Windows ACLs.
- Damaged sent history is preserved, and fresh-profile logging works reliably.
- Cached embedded nodes are hash-checked before reuse; extraction uses private,
  atomic writes and rejects malformed payloads without replacing a prior file.
- Retained node stderr is bounded to 64 KiB, and unused stdout is discarded to
  avoid accumulating console output throughout long-running node sessions.
- Native platform tests cover the GUI, private file access, notification
  round trips and packaging failures.

Consensus rules, transaction construction and the embedded daemon are unchanged.
End-to-end sync performance must be measured before advertising a speedup.

## Release gates

- Windows static build, isolated native tests and dependency checks.
- Linux and macOS native builds/tests, plus portable release packaging checks.
- Fresh-profile startup, embedded-daemon extraction, shutdown and sync checks
  using isolated data and consenting peers.
- Reviewed source commit, artifact checksums and platform signing verification.

CI test builds alone are not portable user releases. Do not publish artifacts
from a newer Linux build host without checking the intended glibc floor.
