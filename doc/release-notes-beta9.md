# ZClassic Wallet 2.1.2-beta9

Beta9 addresses the Windows upgrade failure that beta8 repaired only partially.
An older data folder can grant its owner access without passing that access to
new files. The configuration may then become readable while the node still
cannot open its lock file or blockchain folders.

## Startup recovery

- Check wallet and parameter folder access in the background before starting the
  embedded node. The window stays responsive and the check can be stopped.
- Offer **Repair access and continue** in the main window, with the exact folders
  listed. One action repairs recognized blocked files throughout those folders
  and restores inheritance so new files do not encounter the same failure.
- Repair only files owned by the current account with empty access lists, and
  the narrowly recognized owner-private directory policy lacking inheritance.
  Preserve custom policies, skip links, and never change file contents. A custom
  data directory discovered afterward is checked and authorized separately.
- Keep the explanation and action visible through disconnected polling. Retry a
  failed check or stopped node without closing and reopening the application.
- Cancel obsolete file checks when a newer connection attempt replaces them.
- Report a confirmed node exit immediately rather than showing “Almost ready”
  for the remainder of a two-minute startup timeout.
- Recognize access-denied errors before generic “probably already running” lock
  messages. Such errors do not trigger blockchain repair or re-download.

## Validation and limits

Windows regressions reproduce blocked configuration, lock, wallet, parameter,
and nested blockchain files. They verify unchanged bytes, preserved custom
permissions, readable newly created files, cancellation, visible recovery,
and replacement of an in-flight check. The real-node release helper supports
`--repair-fixture`: it repairs an isolated broken folder, starts the bundled node
with wallets and peers disabled, authenticates with its RPC cookie, then checks
clean shutdown. It never modifies the user's wallet or blockchain directory.

Windows validation: 106 logic tests and 55 widget tests passed,
with one pre-existing platform/latency skip in each suite. System-only DLL import
checks, final-bundle extraction/hash/cache checks, verified HTTPS, and real-node
startup from the repaired fixture passed. The recovery screen was also captured
and inspected. Linux/macOS native tests, release builds, and independent host startup checks passed.

The native directory-relative Windows access pattern is adapted from Z23's C23
platform code with Apache-2.0 attribution. The legacy GUI remains C++; no Z23
consensus code is imported. The bundled beta6 node and consensus are unchanged.

Windows remains a portable executable without separate compiler, Qt or OpenSSL
DLL downloads. This change does not sign the executable or eliminate SmartScreen.
Linux retains its glibc 2.31+ and X11/XCB requirements; macOS requires Apple Silicon
and macOS 15+, with ad-hoc signing rather than Apple notarization. No measured
full-chain sync speedup or MMB snapshot support is claimed.

Released from merge 62e0cd07c4f6b9294ec5e3e10609fde3cf138711 (PR #146). Its source tree is identical to the independently reviewed and tested build source ac0bc3bb8d9393534e762363bb3fcbe8bc8e257d.
See [beta8](release-notes-beta8.md) and [beta7](release-notes-beta7.md) for retained
packaging and configuration improvements.

## Downloads

- Windows x86_64: zclwallet-v2.1.2-beta9-win64.exe
- Linux x86_64: zclwallet-v2.1.2-beta9-linux-x86_64
- macOS 15+ Apple Silicon: zclwallet-v2.1.2-beta9-macos-arm64.dmg

Verify SHA256SUMS.txt before running. BUILDINFO.txt records source identity and validation. Retain your existing data directory; do not delete or reindex it for an access error. The standalone command-line node release remains beta6.
