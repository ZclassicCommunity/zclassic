# ZClassic 2.1.2-beta2

ZClassic is an Equihash-based proof-of-work implementation of the Zerocash protocol. It offers privacy through shielded transactions using zero-knowledge proofs that preserve transaction confidentiality. Based on Bitcoin's code and derived from Zcash, ZClassic builds three main binaries: **zclassicd** (daemon), **zclassic-cli** (RPC client), and **zclassic-tx** (transaction utility).

**Mainnet:** P2P port `8033`, RPC port `8023`

## What is ZClassic?

[ZClassic](https://zclassic.org/) implements the "Zerocash" protocol, offering far higher privacy than Bitcoin through a zero-knowledge proving scheme that preserves the confidentiality of transaction metadata. For technical details, see the [Protocol Specification](https://github.com/zcash/zips/raw/master/protocol/protocol.pdf).

This software is the ZClassic client. It synchronizes the entire blockchain history to your computer.

**Security Warning:** ZClassic is experimental and a work-in-progress. Use at your own risk. See the [Security Information page](https://z.cash/support/security/) for important security details.

**Deprecation Policy:** A release is considered deprecated approximately 70 weeks after its release; an automatic shutdown then halts the node at a block height past that point. Keep your node updated.

---

## Quick Start

### Release Binaries

Pre-built release binaries are published on **[GitHub Releases](https://github.com/ZclassicCommunity/zclassic/releases)**. Download the bundle for your platform and verify it against the checksums published alongside it before running. If you prefer to build it yourself, see [Build from Source](#build-from-source) below.

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

### First Run: Fetch ZCash Parameters

Before running `zclassicd`, obtain the ZCash proving parameters (~1.6 GB):

```bash
./zcutil/fetch-params.sh
```

---

## Running ZClassic

### Default: Auto Fast-Sync (Recommended for Fresh Nodes)

On a fresh data directory, the node automatically fast-syncs from a compiled-in default bootstrap peer over parallel streams (4 by default), turning a multi-day initial sync into minutes. The downloaded snapshot's tip is verified against a compiled fast-sync anchor commitment, and every block after the anchor is forward-validated.

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

### Full Validation from Genesis (No Fast-Sync)

For complete trustlessness, disable fast-sync and validate the entire chain from genesis:

```bash
./src/zclassicd -bootstrap=0
```

The node then performs normal P2P sync, validating every block.

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
