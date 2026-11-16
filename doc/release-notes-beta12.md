# ZClassic Wallet 2.1.2-beta12

Existing wallets far below the compiled checkpoint previously resumed slow
block-by-block sync after upgrading: the backend intentionally refuses to replace
an existing chain directory during automatic bootstrap. Beta12 makes the GUI
handle that transition automatically instead of requiring a repair-menu choice.

For a GUI-owned mainnet node more than 100,000 blocks below checkpoint 3,126,937,
the wallet detects that bootstrap was skipped because existing chain files are
present. It stops its node, makes a private verified wallet backup, preserves the
old chain through the existing journaled move, and restarts into verified
checkpoint download. No repair-choice dialog or extra button is required.

External nodes, test networks, explicit bootstrap opt-outs, active downloads,
pending verification and nearly caught-up chains are not migrated. The transition
requires sufficient free disk space and records an attempt for that data directory
to prevent repeated chain replacements. Quit or connection changes during shutdown
cancel the transition before any files move. Cancelled pre-move attempts can retry
on a later launch.

This is a wallet orchestration change; the beta11 backend remains unchanged.
Checkpoint commitments, subsequent block validation, wallet formats and production
cryptography are unchanged. The snapshot still requires downloading and verification,
followed by later-block validation and wallet scanning. No instant-sync claim is made.

Windows qualification passed 149 logic cases (three existing skips) and 66 UI
cases (one existing deferred latency skip), with zero failures. The automatic
migration tests use isolated wallet/chain fixtures and an owned child process to
exercise the actual shutdown wait: normal migration, quit, failed replacement
connection and competing requests. They verify retained wallet bytes, preserved
chain backups, cancellation before movement and release of the operation guard.
The replacement test also exposed and now covers a shutdown null-pointer crash;
shutdown waits for its original process even if a replacement clears RPC state.

Beta12 is published for Windows x86_64, Linux x86_64 and macOS Apple Silicon in
[one release](https://github.com/ZclassicCommunity/zclassic/releases/tag/v2.1.2-beta12),
with checksums and BUILDINFO. The three unchanged standalone beta11 node archives
are included with their original versioned filenames. Source a7367ab1b was merged
through PR158 as 448f65b18 with an identical source tree.

Windows isolated regtest transactions passed: transparent sends and confirmations,
coinbase shielding, shielded sends with memo round trips, unshielding, and exact
balance/fee accounting. These use disposable wallets and do not establish an
end-to-end funded public-mainnet migration.

Production Windows packaging, system-DLL imports and embedded extraction/hash/version/cache
checks passed. Linux wallet release run 43918732284 passed at the release commit,
including glibc/dependency checks, embedded daemon verification and verified HTTPS.
Linux requires glibc 2.31+ and system X11/XCB/font libraries; Qt and OpenSSL are bundled.

Hosted Mac jobs did not obtain a runner, so the Mac package was built and tested
natively on macOS 26, targeting macOS 15+. Logic tests passed 150 cases (two existing
skips). An initial UI run had one debounce timing failure; 20 unchanged focused
repetitions and the complete rerun passed (62 cases, one existing deferred skip).
No assertion or timeout was weakened. Read-only DMG mounting verified version metadata,
permissions, signatures and the bundled backend hash against the published beta11 node.

Windows executables are unsigned; Mac apps are ad-hoc signed, not Apple-notarized.
Operating-system security prompts may still appear. Check SHA256SUMS.txt before opening.