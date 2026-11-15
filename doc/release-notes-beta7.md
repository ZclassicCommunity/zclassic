# ZClassic Wallet 2.1.2-beta7

Release preparation: binaries are candidates until validation and publication
finish. This release brings the Qt desktop wallet source into this repository
under `wallet/`, imported from `ZclassicCommunity/zcl-qt-wallet` commit
`0589e5badacb3e12740ab6e84fe2eebb4832c61e`. Its license is retained in
`wallet/LICENSE`. The bundled node remains the reviewed beta6 daemon; its
reported node version is intentionally beta6. There are no consensus changes.

## Improvements

- **Windows portability:** statically link GCC's exception runtime, the C++
  runtime and pthreads. Beta6 requested `libgcc_s_seh-1.dll`; inspection also
  found missing `libstdc++-6.dll` and `libwinpthread-1.dll` dependencies.
  Packaging now rejects non-system DLL dependencies in both GUI and daemon.
- **Sync configuration:** stop forcing a 450 MiB database cache. The existing
  64-bit daemon defaults (1024 MiB, or 2048 MiB during a rebuild) and explicit
  user settings now take effect. No verification checks are removed. This can
  reduce database flush pressure; full-chain speedups have not been measured.
- **Node integrity:** hash cached node executables before reuse, check footer
  lengths, reject symbolic-link output files, and publish extracted binaries
  atomically with private access permissions. Same-size corruption is repaired
  from a verified payload; a bad payload cannot replace the previous cache.
- **Long-running stability:** bound retained node stderr to 64 KiB. Unused
  stdout is discarded instead of accumulating in memory. The default daemon
  logging destination remains `debug.log`; explicit `printtoconsole` output is
  discarded by the GUI launcher.
- **Private local files:** save notification tokens and sent-history files
  atomically, with real owner-only Windows ACLs and private POSIX permissions.
  Preserve unreadable or malformed history instead of overwriting it.
- **Notifications:** avoid unnecessary named-pipe write waits on Windows;
  verify actual notification round trips in native tests.
- **Fresh profiles:** create the logging directory when missing and handle
  log-open failures without repeated invalid writes.
- **Release reliability:** test shadow builds and platform permissions, isolate
  tests from real user profiles, reject oversized embedded payloads and existing
  packaging outputs, and snapshot the daemon before hashing/packaging so a
  concurrent rebuild cannot produce inconsistent footer data.

## Validation and release status

The imported source passed native builds and tests on Windows, Linux and macOS.
Windows: 105 logic and 48 widget passes; Linux/macOS: 106 logic and 47 widget
passes each. There were no failures. Windows skips one POSIX-only test; all
platforms retain one previously deferred widget latency test.

Windows packaging regression tests and a Windows-only-PATH startup passed. The
actual packaged executable was extracted with production code into a temporary
cache, its daemon hash was checked against beta6, and `--version` completed.
Independent source review found two test integration issues, both corrected.

Portable Linux/macOS artifacts, signing checks and isolated full-chain sync
measurement are still release gates. No funds were spent, keys exported,
canonical datadirs changed, or transaction-construction code modified. Z23's
storage read-ahead design is being evaluated separately; no unvalidated Z23
consensus or storage implementation has been substituted into this release.

Published binaries must include SHA256SUMS.txt and platform requirements.
Windows candidates are unsigned; macOS ad-hoc signing is not notarization.
