# ZClassic Wallet 2.1.2-beta7

This release brings the Qt desktop wallet source into this repository
under `wallet/`, imported from `ZclassicCommunity/zcl-qt-wallet` commit
`0589e5badacb3e12740ab6e84fe2eebb4832c61e`. Its license is retained in
`wallet/LICENSE`. The bundled node remains the reviewed beta6 daemon; its
reported node version is intentionally beta6. There are no consensus changes.
The old Hugo documentation-site theme and a stale prebuilt GUI executable are
excluded; the public website remains in `zclassicorg.github.io`. The theme's
Tachyons CSS references were unrelated to blockchain protocol code.

## Improvements

- **Windows portability:** statically link GCC's exception runtime, the C++
  runtime and pthreads. Beta6 requested `libgcc_s_seh-1.dll`; inspection also
  found missing `libstdc++-6.dll` and `libwinpthread-1.dll` dependencies.
  Packaging now rejects non-system DLL dependencies in both GUI and daemon.
  Windows HTTPS uses native Schannel, restoring certificate-verified update
  requests without adding OpenSSL DLL requirements. Linux GUI candidates use
  Qt 5.15.19 and statically linked OpenSSL 3.5.9; the node's libraries are unchanged.
- **Sync configuration:** stop forcing a 450 MiB database cache. The existing
  64-bit daemon defaults (1024 MiB, or 2048 MiB during a rebuild) and explicit
  user settings now take effect. No verification checks are removed. This can
  reduce database flush pressure; full-chain speedups have not been measured.
- **Node integrity:** hash cached node executables before reuse, check footer
  lengths, reject symbolic-link output files, and publish extracted binaries
  atomically with private access permissions. Same-size corruption is repaired
  from a verified payload; a bad payload cannot replace the previous cache.
- **Long-running stability:** bound retained node stderr to 64K characters. Unused
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
- **Canonical releases:** the wallet's update checker and download links now use
  `ZclassicCommunity/zclassic`, alongside the node and unified release notes.
  Version comparisons distinguish beta6, beta7, release candidates and final
  releases instead of treating every 2.1.2 prerelease as the same version.
- **macOS packaging:** include transitive Brotli and WebP libraries missed by Qt's deploy
  tool, check all bundled library references, and set the minimum macOS version
  from the actual deployed libraries and static objects before signing.
- **Release reliability:** test shadow builds and platform permissions, isolate
  tests from real user profiles, reject oversized embedded payloads and existing
  packaging outputs, and snapshot the daemon before hashing/packaging so a
  concurrent rebuild cannot produce inconsistent footer data.

## Validation and release status

The imported source passed native builds and tests on Windows, Linux and macOS.
Windows: 106 logic and 48 widget passes; Linux/macOS: 107 logic and 47 widget
passes each. There were no failures. Windows skips one POSIX-only test; all
platforms retain one previously deferred widget latency test.

Windows packaging regression tests and a Windows-only-PATH startup passed. The
actual packaged executable was extracted with production code into a temporary
cache, its daemon hash was checked against beta6, and `--version` completed.
Independent source review found two test integration issues, both corrected.

Windows HTTPS was tested with certificate verification and Windows-only PATH.
The macOS DMG passed library closure checks, ad-hoc signature verification and
mounted-image GUI/node startup on a separate Mac. It requires macOS 15 or newer
on Apple Silicon. Windows candidates are unsigned; macOS is not notarized.

The Linux candidate passed the glibc/C++ runtime floors, dependency checks,
production payload extraction, cache reuse and verified HTTPS. Its downloaded
binary also started on a separate Linux host. Full-chain sync speed has not been
benchmarked, so this release makes no measured speedup claim. No funds were spent, keys exported,
canonical datadirs changed, or transaction-construction code modified. Z23's
storage read-ahead and MMB designs are being evaluated separately; no unvalidated
Z23 consensus or storage implementation has been substituted into this release.
MMB snapshot sync is not enabled: ZClassic headers do not commit an MMB or UTXO
root, so an auxiliary peer proof cannot replace full historical validation.

Published binaries must include SHA256SUMS.txt and platform requirements.
Windows candidates are unsigned; macOS ad-hoc signing is not notarization.

## Downloads and requirements

- Windows x86_64: `zclwallet-v2.1.2-beta7-win64.exe`. No GCC, Qt, pthread or
  OpenSSL DLL installation is needed.
- macOS 15+ Apple Silicon: `zclwallet-v2.1.2-beta7-macos-arm64.dmg`. Drag the app
  to Applications. It is ad-hoc signed, not Apple-notarized; use the system's
  Privacy & Security approval flow if Gatekeeper blocks it.
- Linux x86_64: `zclwallet-v2.1.2-beta7-linux-x86_64`. Built on Ubuntu 20.04;
  requires glibc 2.31+, the system C++ runtime and X11/XCB desktop libraries.
  Qt and OpenSSL are statically included. Run `chmod +x` on the downloaded file.

On minimal Ubuntu/Debian installations, the X11/XCB runtime packages are:

```sh
sudo apt-get install libx11-xcb1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
  libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-sync1 libxcb-xfixes0 \
  libxcb-xinerama0 libxcb-xkb1 libxkbcommon-x11-0 libstdc++6 ca-certificates
```

Verify downloads against `SHA256SUMS.txt`. Back up your wallet before upgrading.
Replace the application; do not delete or reindex your existing data directory
as part of this upgrade. Standalone daemon downloads remain beta6 because its
implementation is unchanged. No transaction or consensus migration is required.
