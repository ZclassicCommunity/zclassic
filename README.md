# ZClassic Wallet and Node

**Beta13 is a new wallet and a new command-line node (both v2.1.2-beta13) for Windows, Linux and macOS.**
There is no Rust and no libsnark any more: the shielded cryptography is the C23 core in `src/c23`.
Start-up and balance queries are faster, shielded sends use less memory, wallet state survives
hard kills and chain reorganisations with correct balances, and syncing from genesis works again.
No consensus rule, checkpoint, activation height or the IBD proof-skip is changed. One owner-approved
consensus-adjacent change: the 413 historical oversize transactions are admitted by an explicit
allowlist (the same table Z23 uses), which is what makes a sync from block 0 possible.
The wallet source lives in [wallet/](wallet/).

ZClassic is an Equihash-based proof-of-work implementation of the Zerocash protocol. It offers privacy through shielded transactions using zero-knowledge proofs that preserve transaction confidentiality. Based on Bitcoin's code and derived from Zcash, ZClassic builds three main binaries: **zclassicd** (daemon), **zclassic-cli** (RPC client), and **zclassic-tx** (transaction utility).

**Mainnet:** P2P port `8033`, RPC port `8023`

## What is ZClassic?

[ZClassic](https://zclassic.org/) implements the "Zerocash" protocol, offering far higher privacy than Bitcoin through a zero-knowledge proving scheme that preserves the confidentiality of transaction metadata. For technical details, see the [Protocol Specification](https://github.com/zcash/zips/raw/master/protocol/protocol.pdf).

This software is the ZClassic client. It downloads and validates the chain, with an optional compiled-checkpoint bootstrap for fresh nodes.

**Security Warning:** ZClassic is experimental and a work-in-progress. Use at your own risk. To report a security vulnerability, do not open a public issue: use [private vulnerability reporting](https://github.com/ZclassicCommunity/zclassic/security/advisories/new) as described in [SECURITY.md](SECURITY.md).

**Deprecation Policy:** A release is considered deprecated approximately 70 weeks after its release; an automatic shutdown then halts the node at a block height past that point. Keep your node updated.

---

## Quick Start

### Release Binaries

Pre-built release binaries are published on **[GitHub Releases](https://github.com/ZclassicCommunity/zclassic/releases)**. Download the bundle for your platform and verify it against the checksums published alongside it before running. If you prefer to build it yourself, see [Build from Source](#build-from-source) below.

| Desktop wallets | Download |
|---|---|
| Windows x86_64, beta13 single executable (node embedded) | [Windows wallet](https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta13/zclwallet-v2.1.2-beta13-win64.exe) |
| Linux x86_64, glibc 2.31+ and X11/XCB libraries | [Linux wallet](https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta13/zclwallet-v2.1.2-beta13-linux-x86_64) |
| macOS 14+, Apple Silicon | [macOS wallet](https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta13/zclwallet-v2.1.2-beta13-macos-arm64.dmg) |

Close your older wallet normally, keep your existing wallet and data directory, and open the beta13 wallet.

What beta13 changes for users (details in the [beta13 notes](doc/release-notes-beta13.md)):
- No Rust or libsnark; `sprout-proving.key`, libgmp and OpenMP are no longer needed. New Sprout proofs can no longer be created; existing ones are still verified.
- Proof verification about 2x faster; start-up of a full mainnet node about 24 s to 8 s; `z_getbalance` with 3,252 notes 1.29 s to 0.012 s.
- Peak memory for a 20-40 note shielded send about 850 MB to about 390 MB.
- A hard kill no longer leaves a spent shielded note counted as unspent; a reorganisation no longer aborts the daemon and the wallet shows the same balance as after a restart; `backupwallet` verifies its copy before renaming it into place.
- Sync from genesis works; `-reindex` and `invalidateblock` are reliable; peer selection is better; interrupted snapshot downloads resume.
- Faster peer connections: a fresh node dials several addresses at once and uses its fixed seeds early (measured on a Windows home PC: 3 peers in 0.75 s instead of 8.6 s, median of 5 fresh starts).
- Fast sync uses every snapshot server it knows at once and still verifies every byte against the trusted snapshot manifest; a node killed during the snapshot install recovers by itself on the next start. `getbootstrapinfo` shows `servers` and `servers_in_use`.
- Wallet: witnesses of long-spent notes are retired (smaller wallet file, less work per block); `z_sendmany` accepts an `idempotency_key` and a durable send journal (`z_listsendjournal`) keeps a retried send from paying twice; `getwalletinfo` reports `health`, and the wallet shows a notice only when something needs attention.
- Node: `getrpcinfo` and a slow-RPC warning (`-rpcslowlog`), HTTP 503 with an explanation when the RPC server is overloaded, a cache of verified shielded transactions, parallel header Equihash checks, a shorter start-up check after a clean shutdown, and LevelDB open files sized from the system limit.
- Embedded Tor is optional (`-embeddedtor=1`) and off by default. `debug.log` is off by default (`-debuglogfile`).

Known issue: a pruned node cannot reorganise onto a reconsidered fork more than 288 blocks heavier. Going back to an older wallet after this version has spent many shielded notes has one limit, described in the [beta13 notes](doc/release-notes-beta13.md). Earlier changes: [beta12 notes](doc/release-notes-beta12.md) and [beta11 notes](doc/release-notes-beta11.md).

For developers: the source tree has no Python and no hosted CI; the developer tools (`zcl-dev`, `zcl-lint` and others) are written in C. See `AGENTS.md` and `doc/agent/`.

The Windows wallet is one file: run `zclwallet-v2.1.2-beta13-win64.exe`; no installer, no extra DLLs. Windows binaries are unsigned and may trigger SmartScreen ("More info", then "Run anyway"). The Mac wallet and node are ad-hoc signed, not Apple-notarized; they were tested natively on macOS 26 only.

| Command-line node beta13 | Download |
|---|---|
| Windows x86_64 | [Windows node ZIP](https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta13/zclassicd-v2.1.2-beta13-win64.zip) |
| Linux x86_64, glibc 2.31+ | [Linux node archive](https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta13/zclassicd-v2.1.2-beta13-linux-x86_64.tar.gz) |
| macOS Apple Silicon | [Mac node archive](https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta13/zclassicd-v2.1.2-beta13-macos-arm64.tar.gz) |

See the [release notes](doc/release-notes-beta13.md),
[checksums](https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta13/SHA256SUMS.txt),
[build record](https://github.com/ZclassicCommunity/zclassic/releases/download/v2.1.2-beta13/BUILDINFO.txt) and [wallet instructions](wallet/README.md). Each node archive contains
`zclassicd`, `zclassic-cli` and `zclassic-tx`.
Back up your wallet before upgrading; do not delete or reindex your data directory.

---

## Build from Source

For comprehensive build instructions, cross-compilation, and troubleshooting, see [BUILD.md](BUILD.md).

### Quick Build (Ubuntu/Debian)

```bash
# Clone
git clone https://github.com/ZclassicCommunity/zclassic.git
cd zclassic

# Install build dependencies
./zcutil/install-deps.sh

# Build (dev binaries land in src/)
./zcutil/build.sh -j$(nproc)
```

Release candidates are built and tested on the project's own machines with `zcutil/local-ci.sh` (see [doc/local-ci.md](doc/local-ci.md)); the GitHub workflows run only when started by hand.

### Release Build (stripped binaries)

`build-release.sh` builds depends and a stripped binary set for a target, written to `release/<host-triple>/`.

```bash
# Native build for the current host (Linux on a Linux box, macOS on a Mac)
./zcutil/build-release.sh linux -j$(nproc)

# Windows (Win64) cross-build — needs the mingw-w64 toolchain
./zcutil/install-deps.sh --mingw
./zcutil/build-release.sh win64 -j$(nproc)
```

To produce macOS binaries, run the native build on macOS (Apple Silicon arm64 build support is included). Cross-building to macOS from another host is not provided by these scripts.

### First Run: Fetch the zk-SNARK Parameters

Before running `zclassicd`, obtain the zk-SNARK parameters (about 780 MB; the 910 MB `sprout-proving.key` is no longer needed):

```bash
./zcutil/fetch-params.sh
```

---

## Running ZClassic

### Default: Auto Fast-Sync (Recommended for Fresh Nodes)

On a fresh data directory, the node automatically fast-syncs from a compiled-in default bootstrap peer over parallel streams (4 by default). The downloaded snapshot's tip is verified against a compiled fast-sync anchor commitment, and every block after the anchor is forward-validated. This existing snapshot mode relies on that anchor; it is not full historical validation. Sync time depends on peers, hardware and network conditions. It does not remove the checkpoint trust assumption or guarantee a sync time.

```bash
./src/zclassicd
```

Uses `~/.zclassic` as the data directory.

### Custom Peer or Parallel Streams

```bash
# Fast-sync from a specific peer (default port 8033)
./src/zclassicd -bootstrappeer=192.0.2.10

# Adjust parallel download connections (1–16, default 4)
./src/zclassicd -bootstrapstreams=8
```

When the node knows several snapshot servers (the compiled-in list, or `-bootstrappeer` given more than once), the download spreads its streams over all of them, takes identical files from whichever server has them, and carries on if one goes away. Every byte is still checked against the trusted snapshot manifest. `getbootstrapinfo` reports `servers` and `servers_in_use`.

### Full Validation from Genesis (No Fast-Sync)

For complete trustlessness, disable fast-sync and validate the entire chain from genesis:

```bash
./src/zclassicd -bootstrap=0
```

The node then performs normal P2P sync, validating every block. Beta13 syncs from block 0 again (the 413 historical oversize transactions are admitted by an explicit allowlist).

### Serve Bootstrap Snapshots to Other Nodes

Auto-serve: the node retains a copy of the snapshot it fast-syncs and serves it to peers (uses extra disk).

```bash
./src/zclassicd -bootstrapserve=auto
```

Or serve a prepared snapshot directory:

```bash
./src/zclassicd -bootstrapserve -bootstrapsourcedir=/path/to/prepared-snapshot
```

### Bootstrap Flags Reference

| Flag | Purpose |
|------|---------|
| `-bootstrap=0` | Disable fast-sync; validate from genesis (full validation mode). Default is `1`. |
| `-bootstrappeer=<host>` | Download the snapshot from a specific peer (default port 8033). |
| `-bootstrapstreams=<n>` | Parallel connections for the snapshot download (default 4, max 16; `1` = legacy single stream). More streams improve throughput on lossy/distant links. |
| `-bootstrapserve` | Serve snapshots to peers. Requires `-bootstrapsourcedir=<dir>`. |
| `-bootstrapserve=auto` | Auto-retain and serve the snapshot this node fast-syncs (no `-bootstrapsourcedir` needed; uses extra disk). |
| `-bootstrapsourcedir=<dir>` | Prepared snapshot directory (`blocks/` + `chainstate/`) to serve. |
| `-bootstrapdatadir=<dir>` | Import a snapshot from a local prepared directory at startup, before the databases open. |
| `-bootstrapforce` | Force import into a non-empty data directory (overwrites existing chain data). |

For the full set of bootstrap options (serving rate limits, peer caps, freeze interval, trustless mode), run `./src/zclassicd -help | grep bootstrap`.

---

## Configuration

Create `zclassic.conf` in your data directory (e.g. `~/.zclassic/zclassic.conf`):

```ini
txindex=1
gen=0
rpcuser=yourusername
rpcpassword=yourpassword
port=8033
rpcport=8023
```

`debug.log` is off by default; start with `-debuglogfile` to write it. Embedded Tor is optional and off by default (`-embeddedtor=1`); see `zclassicd -help` for its options.

---

## RPC and CLI

Interact with the running daemon via JSON-RPC:

```bash
./src/zclassic-cli getblockchaininfo
./src/zclassic-cli gettransaction <txid>
```

`getblockchaininfo` reports overall sync progress in `verificationprogress`. When the node is running with the experimental trustless bootstrap mode, its `bootstrap_validation` object reports the background re-validation state; in the default anchor-pinned fast-sync mode that object reports `state: disabled`.

---

## Advanced: Bootstrap Snapshots

See [doc/bootstrap-snapshots.md](doc/bootstrap-snapshots.md) for:
- Full validation vs. fast-sync trust models (anchor mode vs. experimental trustless mode)
- Preparing and serving snapshots, including serving bandwidth/peer limits
- Local snapshot import (`-bootstrapdatadir`) and its requirements

---

## Getting Help

- **Build Issues:** see [BUILD.md](BUILD.md) for troubleshooting.
- **Bug Reports:** [github.com/ZclassicCommunity/zclassic/issues](https://github.com/ZclassicCommunity/zclassic/issues).

---

## License

For license information, see [COPYING](COPYING).

---

## Contributing

Contributions are welcome. Fork the repository, create a feature branch, make your changes, and open a pull request.
