# ZClassic Wallet and Node 2.1.2-beta13

Beta13 is a new wallet **and** a new node (both v2.1.2-beta13). The shielded cryptography no longer uses Rust or libsnark: it is the C23 core in `src/c23`. Start-up and balance queries are faster, shielded sends use less memory, wallet state survives hard kills and chain reorganisations with correct balances, and syncing from block 0 works again.

**No consensus rule, checkpoint, activation height or the IBD proof-skip is changed.** One owner-approved consensus-adjacent change: the 413 historical oversize transactions are admitted by an explicit allowlist (the same table Z23 uses), which is what makes a sync from block 0 possible.

## What is new
- **No Rust, no libsnark.** Sapling, Sprout (Groth16 and PHGR13) and Equihash verification are C23, checked against a manifest. `sprout-proving.key`, libgmp and OpenMP are no longer needed. New Sprout PHGR13 proofs can no longer be created (they only existed before Sapling); they are still verified.
- **Faster.** Proof verification about 2x; Equihash checked once per block; start-up of a full mainnet node about 24 s to 8 s; `z_getbalance` with 3,252 notes 1.29 s to 0.012 s; note scanning up to 4x faster with many addresses.
- **Less memory.** Peak for a 20-40 note shielded send about 850 MB to about 390 MB.
- **Wallet reliability.** A hard kill can no longer leave a spent shielded note counted as unspent. A reorganisation no longer aborts the daemon, and after a reorganisation or `-reindex` the wallet's own unmined sends are offered to the mempool again, so the running wallet shows the same balance as after a restart. Shielded sends check their anchors and witnesses before proving. `backupwallet` now copies to a temporary file, syncs, compares SHA-256 and only then renames into place; it works without `-exportdir`.
- **Node reliability.** Sync from block 0 works. `-reindex` no longer silently drops blocks after a stale record header; `invalidateblock` is reliable across restarts. Peer address selection no longer stalls, and a fresh node holds its outbound peers. Interrupted snapshot downloads resume, with every kept file re-verified. New `-mempoolmaxbytes` (default 300 MB).
- **Tor (off by default).** Optional embedded Tor (`-embeddedtor=1`) with fixed onion v3 handling.
- **Updated components.** OpenSSL 3.5.9.
- **Windows.** Non-ASCII data directories work, and the node shuts down cleanly when its console is closed.
- `debug.log` is off by default; use `-debuglogfile` to enable it.

## Upgrading
Close your old wallet normally, keep your wallet and data directory, and open the new one. A wallet backup first is recommended; do not delete or reindex your data directory. Beta13 reads existing `wallet.dat` files.

## Downloads
- **Windows x86_64 wallet:** `zclwallet-v2.1.2-beta13-win64.exe`, a single file with the node embedded. No installer; run it.
- **Linux x86_64 wallet:** `zclwallet-v2.1.2-beta13-linux-x86_64` (glibc 2.31+, system X11/XCB/font libraries).
- **macOS Apple Silicon wallet:** `zclwallet-v2.1.2-beta13-macos-arm64.dmg` (macOS 14 or later; tested natively on macOS 26). Intel Macs are not supplied.
- **Command-line node** (`zclassicd`, `zclassic-cli`, `zclassic-tx`): `zclassicd-v2.1.2-beta13-win64.zip`, `zclassicd-v2.1.2-beta13-linux-x86_64.tar.gz`, `zclassicd-v2.1.2-beta13-macos-arm64.tar.gz`.

Verify a download against `SHA256SUMS.txt` (for example `sha256sum -c SHA256SUMS.txt --ignore-missing`, or `Get-FileHash` on Windows). `BUILDINFO.txt` records the source commit, toolchains and checks for each file.

## Unsigned builds
These builds were made on our own machines, not on GitHub Actions, and are **not code-signed**. Windows SmartScreen may warn: choose "More info", then "Run anyway". The macOS wallet and node are ad-hoc signed, not Apple-notarized: Gatekeeper may refuse the first launch; right-click the app and choose Open, or allow it under System Settings, Privacy & Security.

## Known issues
- A node killed while a downloaded snapshot is being installed can refuse the next start ("requires a fresh chain datadir"). Workaround: remove the partial `blocks` and `chainstate` folders the install created and start again. A fix is coming.
- A pruned node cannot reorganise onto a reconsidered fork that is more than 288 blocks heavier (the undo data is gone).
- New Sprout PHGR13 proofs can no longer be created (see above); existing ones are still verified.
- Windows 7 and Windows 10 older than 1903 are untested; 32-bit targets no longer build.
- Tor is pinned to the `RhettCreighton/tor` fork with patches carried in `depends`; it stays off by default.

## Verification
Built from source commit `bb43dd9f0bcc3fce907df9ec582de8d2d9aedb82`, whose tree is identical to the release commit (merge of [PR161](https://github.com/ZclassicCommunity/zclassic/pull/161)). On Linux, macOS arm64 and real Windows, the PR records: unit suites, golden corpus, real mainnet block replay (3,327,490 blocks, 0 failures), kill-and-verify cycles with no spent-note mismatches, reorganisation and `invalidateblock` tests, and a node synced from block 0 identical to a snapshot-synced node (same best block and UTXO-set hash at height 3,321,763). A fresh node followed the mainnet tip in a 3-hour soak with flat memory.

For these release files: each node binary was hardening-checked (PIE/RELRO/NX/canary on Linux, DYNAMIC_BASE/NX_COMPAT/HIGH_ENTROPY_VA on Windows, PIE on macOS); the Windows wallet imports only Windows system DLLs and passed the embedded-daemon extraction check against the node hash; the macOS wallet passed 176 logic tests (0 failed, 6 skipped), its disk image verified and mounted read-only with a valid ad-hoc signature, and the Linux wallet passed extraction and HTTPS checks. No funded public-mainnet send test and no universal sync-time claim is made.
