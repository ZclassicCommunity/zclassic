ZClassic 2.1.2

## Getting Started

### Building from Source

For comprehensive build instructions, troubleshooting, and advanced options, see [BUILD.md](BUILD.md).

#### Quick Start (Ubuntu/Debian)

```bash
# Clone the repository
git clone https://github.com/ZclassicCommunity/zclassic.git
cd zclassic

# Install dependencies
./zcutil/install-deps.sh

# Build ZClassic
./zcutil/build.sh -j$(nproc)
```

The compiled binaries will be in the `src/` directory.

#### First Run - Fast Sync

On first run, `zclassicd` will automatically:
- Download ZCash cryptographic parameters (~1.6 GB)
- Download initial blockchain state from Arweave (~8.8 GB)
- Create a default configuration file

This fast-sync feature saves hours compared to syncing from genesis.

### Running ZClassic

```bash
# Start the daemon (uses ~/.zclassic as data directory)
./src/zclassicd

# Use custom data directory and ports
./src/zclassicd -datadir=/path/to/datadir -port=8033 -rpcport=8023
```

#### Configuration

You can create a configuration file `zclassic.conf` in `~/.zclassic` to customize settings:

```
txindex=1
gen=0
rpcuser=yourusername
rpcpassword=yourpassword
```
## What is ZClassic?

<p align="center">
<img width="669" alt="image" src="https://github.com/user-attachments/assets/20d00ef7-13f9-4811-8973-2c5d4b288eee" />
</p>

[ZClassic](https://zclassic.org/) is an implementation of the "Zerocash" protocol.
Based on Bitcoin's code, it intends to offer a far higher standard of privacy
through a sophisticated zero-knowledge proving scheme that preserves
confidentiality of transaction metadata. Technical details are available
in our [Protocol Specification](https://github.com/zcash/zips/raw/master/protocol/protocol.pdf).

This software is the ZClassic client. It downloads and stores the entire history
of ZClassic transactions; depending on the speed of your computer and network
connection, the synchronization process could take a day or more once the
blockchain has reached a significant size.

#### :lock: Security Warnings

See important security warnings on the
[Security Information page](https://z.cash/support/security/).

**ZClassic is experimental and a work-in-progress.** Use at your own risk.

#### :ledger: Deprecation Policy

This release is considered deprecated 16 weeks after the release day. There
is an automatic deprecation shutdown feature which will halt the node some
time after this 16 week time period. The automatic feature is based on block
height.


Currently only Linux is officially supported.

## License

For license information see the file [COPYING](COPYING).
