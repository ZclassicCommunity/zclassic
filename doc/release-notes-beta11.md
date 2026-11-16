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

The GUI now reads RPC settings with the same case-sensitive, first-value-wins
configuration rules as the daemon, including comments and section prefixes.
This fixes connection failures caused by conflicting duplicate settings or
comments being treated as part of a port or password. Testnet and regtest both
use the correct default RPC port. Malformed configuration is preserved and
reported rather than interpreted using guessed settings.

Native macOS build preparation fixes invalid Make variable assignments, uses
the selected Xcode SDK for native dependency tools, and identifies Apple Silicon
as 64-bit ARM. Native dependency, linking, cryptographic and package validation passed on
Apple Silicon macOS 26. The audited deployment minimum is macOS 15; this is
not a claim of native runtime testing on macOS 15.
Boost now selects the configured compiler and retains its SDK and deployment
flags; the daemon's rebuilt Boost archives report macOS 15 rather than inheriting
macOS 26 from the build host. A checksum-pinned static Qt 5.15.19 toolchain uses
Apple's Secure Transport and avoids optional Homebrew runtime libraries.
Mac packaging checks static archive requirements as well as final executables,
rejects a minimum OS above 15, verifies the daemon against its audited build,
and tests certificate-verified HTTPS access before creating the DMG. Final native package qualification passed, including a mounted-DMG permission
and signature check and extracted node-archive checksums.
The Mac package also normalizes public application file permissions and verifies
them after signing, avoiding owner-only bundles inherited from a private build
account's umask.

Interrupted snapshot transfers retry with completed files retained within the
current attempt. Completed files are rehashed against the same manifest before
reuse; incomplete files are downloaded again. Reconnects use one stream if a
parallel transfer fails. The existing compiled checkpoint at height 3,126,937
and full imported-chainstate commitment check remain mandatory. Initial chain
replay honors shutdown requests between completed validation batches.

Cancelling a startup download now stops before database initialization or rewind,
including cancellation while genesis activation is in progress. This fixes an
empty-candidate assertion observed when closing an isolated Windows test during
download. Transfer byte counts and rates refresh between whole-percent changes,
so a slow download no longer needs to receive over 100 MB before reporting motion.
Failed initialization also interrupts and joins worker threads before destroying
the scheduler and shared state. Isolated Windows and Linux startup-failure tests
exercise this teardown, including failure after workers have started.

Parameter-file integrity checks use the backend's existing SHA-256 implementation
on Linux/Windows and Apple's system SHA-256 acceleration on macOS, retaining the
same mandatory digests and bounded read buffers. The Mac path adds no third-party
runtime dependency. Native standard-vector, legacy boundary-parity and read-error
tests passed, as did all six real-backend wallet protection checks on Windows and
macOS. The Mac checks retain their existing startup time limits.
On the native Apple Silicon test host, fresh isolated regtest initialization
with all five parameter files present fell from about 31 seconds to 5.9 seconds.
Parameter digests were checked in both runs; this measures startup, not chain
synchronization or a guarantee for other machines.
Read errors fail verification instead of repeatedly reading a failed stream.
Boundary-vector and read-error tests cover this file-hashing path; block, proof
and transaction hashing are unchanged.

Default snapshot endpoints now explicitly use port 8035, where the project's
legacy snapshot services run. Previously they used port 8033, whose ordinary
P2P nodes do not provide this snapshot protocol. Normal block synchronization
still uses port 8033; checkpoint commitments and validation rules are unchanged.

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
not a guarantee against power loss or faulty storage. Public-endpoint migration
still needs qualification before announcing an existing-wallet fast-sync release.

Repair no longer force-kills a node that is still stopping; it waits for a later
attempt after shutdown finishes. An isolated Windows regtest migration retained
wallet bytes during chain set-aside, then restored the same chain height, wallet
transaction count, test balance and address ownership through the real backend's
snapshot-import path. The original chain backup remained available.

An isolated Linux production-GUI mainnet test also preserved a disposable
wallet through chain set-aside and checkpoint import, verified the checkpoint
commitment, validated bundled post-anchor blocks through height 3,172,671 and
retained ownership of the existing address. The GUI became usable in about
3.5 minutes using a local snapshot server. This is not an internet-download
benchmark, a funded-mainnet wallet rescan benchmark, or proof of default public
endpoint availability. The imported-tip corroboration hold remained enabled.

The repair safety copy is now owner-only before any wallet bytes are written,
streamed and hash-checked, explicitly flushed, and published without replacing
an earlier backup. A missing, unreadable or invalid configured wallet stops repair
instead of silently proceeding. Backup failures show their actual cause.

Isolated Windows and Linux tests have imported and verified the full state at
that checkpoint and continued ordinary block validation above it. This does
not by itself prove the complete public-endpoint GUI migration path.
The consolidated backend passed full debug CI and isolated Windows packaging,
extraction, startup and shutdown checks. Final release qualification is ongoing.
No wallet data should be removed to enable fast sync.

A wallet-disabled Windows public-network run downloaded and verified the compiled
checkpoint, validated the bundled post-anchor blocks, and caught up to live height
3,321,378 with the imported-tip hold released. The earlier RC11 backend candidate then
restarted that isolated chain, connected to both Z23 peers and shut down cleanly.
Download/bootstrap took about 27 minutes under the shared snapshot-server bandwidth
cap; startup including bundled replay took about 61 minutes before live-peer
catch-up. These are observed timings, not a guarantee or a wallet-rescan benchmark.
Both default public snapshot endpoints have now served data to the Windows
candidate. The second mirror also completed checkpoint verification and live
catch-up, and is configured to start automatically after reboot.

Native macOS testing exposed a notification-burst fixture that could spread its
messages beyond the debounce window under load. It now connects clients first,
queues the burst without intervening waits, verifies all four notifications and
retains the exact one-refresh assertion. Twenty focused repetitions passed on
both Windows and macOS; the full native Mac widget suite passed with its existing
deferred warm-latency case. Production debounce timing is unchanged.

## Final-source qualification

Source `b00a3442f6a429a9cc3c913e53ef69f76e2fa100` passed full backend CI,
Linux/macOS wallet platform tests, and Linux/Windows daemon release builds.
Native Mac final-source tests passed 149 logic cases, 58 widget cases and both
parameter-hash cases. Two child-only logic cases and one existing deferred
widget-latency case were skipped. Native backend cryptographic validation passed
63 Boost cases with 1,467,179 assertions and 63 gtests.

The final Windows wallet and standalone node ZIP passed system-DLL import checks,
production embedded extraction/hash/version/cache checks, all six real-backend
wallet protection checks, and default-endpoint download/cancellation/restart and
post-worker initialization-failure checks. The ZIP was extracted and each file
matched its manifest. The Linux node archive passed architecture, runtime-library
compatibility and extracted-file checks. Downloaded Mac and Linux archives were
rehashed after transfer. The full public snapshot run above used earlier
candidates; final artifact startup tests do not repeat that entire download.

The final Linux GUI package passed GLIBC compatibility, production extraction,
backend hash/version/cache and certificate-verified HTTPS checks. All six final
artifacts were hashed locally and are covered by one checksum manifest.
Publication remains pending collaborator approval and merge; the website must
only be updated after the corresponding release links are available.
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

Windows candidates are not Authenticode-signed, so Windows SmartScreen may still
show a reputation warning. Eliminating missing runtime DLLs does not remove that
warning. Mac candidates use ad-hoc signatures and are not Apple-notarized.
