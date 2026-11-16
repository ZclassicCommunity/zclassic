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

Catch-up now keeps an in-memory index of parked blocks, avoiding repeated scans
of the entire block index and full ancestor walks when out-of-order blocks become
usable. Parking rules, accumulated-work requirements and validation checks are
unchanged. The index is rebuilt on load and maintained through reorgs and cleanup.
Differential tests compare its flag changes and side effects with the old traversal;
Windows regtest exercises fork handling and parked-state recovery after restart.

A short Windows comparison from the same saved height and using the same three
Z23 peers measured about 141 blocks/second before and 183 after this optimization.
This is one network-dependent catch-up sample, not a guaranteed sync rate or a
measurement of the full download and wallet-rescan time.

Blockchain re-download repair now preserves earlier backups and uses a unique
backup directory for each attempt. Failed moves restore what they can and retain
any data that cannot be restored, with the recovery paths shown in the error.
Repair stops instead of restarting the node when a move fails. Older backups
are no longer deleted automatically; they continue to occupy disk space.

Repair now selects the configured data directory, network and wallet filename,
including configuration comments, duplicate-setting precedence and negative
boolean options. It no longer guesses testnet from folders present on disk.
Relative paths are refused when the daemon's working directory is unknown.
Wallet backup and blockchain moves now hold the daemon-compatible native data
directory lock. A node using custom ports still blocks repair, and another node
cannot open the databases during those moves. The lock file is never deleted.
Blockchain moves now record a recovery journal first. After an interrupted
process, the GUI restores the previous chain under the data-directory lock;
the daemon refuses to open databases while recovery is pending. Conflicting
files and malformed journals stop recovery without deleting either copy.
Pending snapshot-verification markers, recovery-attempt state and verification
scratch data move with the old chain and are restored together after interruption.
The imported-tip hold and validation records already reside in the moved block
index. Recovery rejects legacy journals that would strand newer verification
metadata. Abrupt-exit tests cover all seven move boundaries.
Repair now checks the journal's native file flush before moving components.
POSIX directory changes are flushed destination-first; Windows moves request
write-through completion. A completed journal is archived with the backup.
Flush failures stop the transition without starting the node. Fault-injection
tests cover publication, move barriers, recovery retries and completion conflicts.
These are checked persistence requests and tested process-interruption recovery,
not a guarantee against power loss or faulty storage. End-to-end wallet migration
still needs qualification before announcing an existing-wallet fast-sync release.

Isolated Windows and Linux tests have imported and verified the full state at
that checkpoint and continued ordinary block validation above it. This does
not yet provide automatic migration of an existing partially synced wallet.
The consolidated backend passed full debug CI and isolated Windows packaging,
extraction, startup and shutdown checks. Final release qualification is ongoing.
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
