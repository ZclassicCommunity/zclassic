# ZClassic Wallet 2.1.2-beta12 candidate

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

These tests do not establish an end-to-end funded public-mainnet migration.
Release packaging and cross-platform qualification remain pending. Do not replace
a published beta11 artifact with this candidate.
