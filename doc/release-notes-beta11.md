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
