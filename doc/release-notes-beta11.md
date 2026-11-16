# ZClassic 2.1.2-beta11 candidate

This release is being built and tested. Published beta10 downloads remain the
current wallet release until backend validation and platform packaging finish.

Unlike beta7–beta10, beta11 rebuilds **zclassicd itself**, as well as the wallet.
The new C23-compatible root-calculation module is adapted from Z23. It reuses
unchanged shielded-tree roots using exact tree-state comparisons and per-thread
caches. Existing consensus hashes and all block/proof checks are retained.

Wallet scanning avoids copying viewing keys for transactions without shielded
outputs and avoids redundant discovery-map copies. Transparent ownership and
shielded spend/nullifier checks are unchanged. Existing parallel rescanning is
retained; it is not a new feature of this release.

No consensus parameters, wallet file formats or chain-state formats change.
Rust cryptography remains linked; the root cache avoids redundant Rust calls
but does not replace cryptographic implementations.

Release builds now use portable `-O2` optimization. The Windows GUI destroys
its windows before Qt shuts down, fixing an exit-time platform crash.

Interrupted snapshot transfers retry with completed files retained within the
current attempt. Completed files are rehashed against the same manifest before
reuse; incomplete files are downloaded again. Reconnects use one stream if a
parallel transfer fails. The existing compiled checkpoint at height 3,126,937
and full imported-chainstate commitment check remain mandatory. Initial chain
replay honors shutdown requests between completed validation batches.

Isolated Windows and Linux tests have imported and verified the full state at
that checkpoint and continued ordinary block validation above it. This does
not yet provide automatic migration of an existing partially synced wallet.
The new retry code still requires its full regression and final build checks.
No wallet data should be removed to enable fast sync.

## Release gates

- Full daemon build, Sprout/Sapling root vectors and differential root tests.
- Wallet scan, viewing-key discovery, reorg, witness and serialization tests.
- C23 address/undefined-behavior checks and legacy Windows compiler checks.
- New backend version and SHA256 verification before GUI bundling; no fallback
  to the old beta6 daemon. CI bundles must match the daemon source commit exactly.
- Windows system-DLL-only import checks, Linux glibc compatibility checks, and
  final embedded-daemon extraction and startup tests.
- macOS native backend build and dependency verification before publishing a
  macOS bundle. The new Linux/Windows daemon workflow does not produce that build.

Timing benchmarks are included in the backend tests. Full-chain speedup has not
yet been measured. This candidate must not be announced as a completed release.
