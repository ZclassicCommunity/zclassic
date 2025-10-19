# Building ZClassic from Source

This guide will help you build `zclassicd` (ZClassic daemon) from source code.

## System Requirements

- **Operating System**: Ubuntu 20.04+, Debian 11+, or compatible Linux distribution
- **Memory**: At least 4 GB RAM recommended
- **Disk Space**: 20 GB free space (for build files and blockchain data)
- **Compiler**: GCC 9+ or Clang 10+

## Quick Start

For Ubuntu/Debian users, the fastest way to build is:

```bash
# 1. Install dependencies
./zcutil/install-deps.sh

# 2. Build ZClassic
./zcutil/build.sh -j$(nproc)
```

The compiled binaries will be in `src/`:
- `zclassicd` - ZClassic daemon
- `zclassic-cli` - Command-line interface
- `zclassic-tx` - Transaction utility

## Manual Installation

### 1. Install Build Dependencies

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential pkg-config libc6-dev m4 g++-multilib \
    autoconf libtool automake \
    libgmp-dev libdb++-dev libsodium-dev libcurl4-openssl-dev \
    git python3 wget curl \
    zlib1g-dev libssl-dev libevent-dev
```

#### Other Distributions

Install equivalent packages for your distribution. The key dependencies are:
- Standard build tools (gcc, g++, make, autoconf, libtool, automake)
- **libgmp-dev** - GNU Multiple Precision library
- **libdb++-dev** - Berkeley DB (for wallet support)
- **libsodium-dev** - Cryptography library
- **libcurl4-openssl-dev** - HTTP client library

### 2. Build Process

```bash
# Clone the repository (if you haven't already)
git clone https://github.com/ZclassicCommunity/zclassic.git
cd zclassic

# Run the build script
./zcutil/build.sh -j$(nproc)
```

The build script will:
1. Download and build required dependencies (Boost, etc.)
2. Download Rust libraries for zero-knowledge proofs
3. Configure the build system
4. Compile all components

**Note**: The first build will take 30-60 minutes depending on your system.

### 3. Build Without Wallet Support

If you don't need wallet functionality:

```bash
./autogen.sh
./configure --disable-wallet --disable-tests
make -j$(nproc)
```

## First Run and Fast Sync

When you first run `zclassicd`, it will automatically:

1. **Download ZCash Parameters** (~1.6 GB) - Required cryptographic parameters
2. **Download Initial Blockchain State** (~8.8 GB) - Fast-sync from Arweave
3. **Create default configuration** - Basic `zclassic.conf` file

This "fast sync" feature downloads a recent blockchain snapshot instead of syncing from genesis, saving hours of initial sync time.

### Running ZClassic

```bash
# Default run (uses ~/.zclassic as data directory)
./src/zclassicd

# Custom data directory and ports
./src/zclassicd \
    -datadir=/path/to/datadir \
    -port=8033 \
    -rpcport=8023
```

## Troubleshooting

### Build Errors

**Error: "UINT64_C was not declared"**
- Solution: This should be fixed in the latest code. If you still see it, ensure you're using GCC 9+.

**Error: "std::this_thread has not been declared"**
- Solution: This should be fixed in the latest code. Update your source code to the latest version.

**Error: "cannot find -lprocps"**
- Solution: This should be fixed by the build system automatically. If not, install `libprocps-dev`.

**Error: "gtest/gtest.h: No such file or directory"**
- Solution: Build with tests disabled: `./configure --disable-tests`

### Build Hangs or is Very Slow

The snark (zero-knowledge proof library) compilation is CPU-intensive. You can:
- Reduce parallel jobs: use `-j4` instead of `-j$(nproc)`
- Build on a machine with more CPU cores
- Be patient - this step can take 15-30 minutes

### Download Failures

If Arweave downloads fail during first run:
- Check your internet connection
- The daemon will retry automatically
- You can delete partial downloads and restart

## Advanced Build Options

### Building Dependencies Separately

```bash
# Build only the dependencies
make -C depends -j$(nproc)

# Then configure with the dependencies
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-unknown-linux-gnu/share/config.site ./configure
make -j$(nproc)
```

### Cross-Compilation

See `depends/README.md` for cross-compilation instructions for:
- Windows (x86_64-w64-mingw32)
- macOS (x86_64-apple-darwin)
- ARM (aarch64-linux-gnu)

### Debug Build

```bash
./configure --enable-debug
make -j$(nproc)
```

## Getting Help

- **Documentation**: See [README.md](README.md) for general information
- **Issues**: Report build problems on [GitHub Issues](https://github.com/ZclassicCommunity/zclassic/issues)
- **Community**: Join the ZClassic community channels

## Contributing

If you've improved the build process or documentation:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Thank you for building ZClassic!
