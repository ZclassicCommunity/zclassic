# Zclassic v2.1.2 - ARM64 macOS Support & Security Improvements

## Overview

This release adds native ARM64 (Apple Silicon) support for macOS and includes important security improvements.

## Security Improvements

### Critical: SSL Certificate Verification Enabled

- **Issue**: SSL certificate verification was disabled for CURL operations, allowing potential MITM attacks when downloading blockchain snapshots and cryptographic parameters from Arweave
- **Fix**: Enabled `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` in `src/init.cpp`
- **Impact**: Downloads are now protected against man-in-the-middle attacks

### High: Increased Key Derivation Iterations

- **Issue**: Wallet encryption used only 25,000 KDF iterations, which is vulnerable to brute-force attacks on modern hardware
- **Fix**: Increased to 200,000 iterations in `src/wallet/crypter.h` (OWASP recommendation)
- **Impact**: Significantly improved resistance to passphrase brute-forcing
- **Note**: Existing wallets retain their original iteration count; only new wallet encryptions use the higher count

### Medium: Randomized Default RPC Credentials

- **Issue**: Default RPC credentials were hardcoded as `zcluser:zclpass`
- **Fix**: Auto-generates random credentials on first run in `src/bitcoind.cpp`
- **Impact**: Prevents use of well-known default credentials

## Build System Changes

### ARM64 macOS Support

Added native support for Apple Silicon (M1/M2/M3) processors:

- **Rust Toolchain**: Upgraded from 1.32.0 to 1.75.0 with `aarch64-apple-darwin` target
- **New Dependencies**: Added `brotli` (1.1.0) and `zstd` (1.5.6) packages with ARM64 architecture flags
- **libcurl**: Updated to link against brotli and zstd for compression support

### Dependency Updates

| Package | Purpose |
|---------|---------|
| brotli 1.1.0 | HTTP compression support |
| zstd 1.5.6 | Zstandard compression support |
| Rust 1.75.0 | ARM64 macOS toolchain |

### Build Fixes

- Fixed ZeroMQ struct initialization warning in `proxy.cpp`
- Updated package registry in `depends/packages/packages.mk`
- Added ARM64 architecture flags to cmake-based dependencies

## Files Changed

### Security Fixes
- `src/init.cpp` - SSL verification
- `src/wallet/crypter.h` - KDF iterations
- `src/bitcoind.cpp` - Random RPC credentials

### Build System
- `depends/packages/brotli.mk` (new)
- `depends/packages/zstd.mk` (new)
- `depends/packages/packages.mk`
- `depends/packages/libcurl.mk`
- `depends/packages/rust.mk`

## Upgrade Notes

### For Users

- **Wallet compatibility**: Existing encrypted wallets will continue to work. The higher KDF iteration count only applies to newly encrypted wallets
- **Configuration**: If upgrading from a previous version with default RPC credentials, your existing `zclassic.conf` will be preserved

### For Developers

- macOS ARM64 builds require Xcode Command Line Tools and Homebrew dependencies
- See `doc/build-macos-arm64.md` for detailed build instructions

## Checksums

```
[To be filled after release]
```

## Contributors

- Security audit and ARM64 build support
