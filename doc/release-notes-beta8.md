# ZClassic Wallet 2.1.2-beta8

Beta8 fixes a Windows upgrade failure where an unreadable existing configuration
was treated as missing, setup attempted to replace it, and the wallet was left at
"No Connection". It retains beta7's static Windows runtime packaging and security
improvements. The bundled node remains beta6; consensus rules are unchanged.

## Startup and configuration fixes

- Distinguish an unreadable existing configuration from a missing file. Preserve
  existing contents and show the actual failure instead of starting setup again.
- On Windows, offer a consent-gated repair only when the configuration belongs to
  the current user and its access list is empty. Restore access for that user
  only. Reject reparse points, directories, different owners and ordinary ACLs.
  This changes permissions only, not wallet, blockchain or configuration bytes.
- Use the directory-relative native-open and ownership-checking pattern from
  Z23's C23 platform code, adapted to the Qt wallet. The Apache-2.0 attribution
  and license are retained. No Z23 consensus implementation is imported.
- Create complete private configurations without replacing an existing file.
  Cancelling setup creates no configuration. Legacy cookie-auth migration uses
  a private atomic save instead of truncating the working configuration first.
- Keep actionable startup errors visible through ordinary RPC polling. An error
  no longer disappears into a generic "No Connection" screen after dismissal.

## Dependencies and validation

The Windows GUI and bundled daemon must import only Windows system DLLs. Users
do not install GCC, libgcc, GMP, MPC, ISL, Qt or OpenSSL DLLs. Windows HTTPS uses
native Schannel. Compiler DLL errors during development are build-tool issues;
the compiler is not shipped in the wallet.

Regression tests exercise actual Windows empty-DACL denial and repair, config
preservation, private creation, and error persistence across RPC refreshes.
The `check-node-startup` release helper starts a real node in an isolated regtest
directory, disables wallets and peer connections, authenticates with its cookie,
and verifies clean RPC shutdown. It requires already installed proving parameters
and never accesses a canonical wallet or blockchain data directory.

Release artifacts include `SHA256SUMS.txt` and `BUILDINFO.txt` with validation
results. Windows is unsigned; macOS is ad-hoc signed, not notarized. These changes
do not remove Windows SmartScreen or Apple Gatekeeper reputation prompts.

## Platforms and upgrading

- Windows x86_64: `zclwallet-v2.1.2-beta8-win64.exe`.
- Linux x86_64: `zclwallet-v2.1.2-beta8-linux-x86_64`, glibc 2.31+ with system C++
  and X11/XCB libraries; Qt/OpenSSL are static.
- macOS 15+ Apple Silicon: `zclwallet-v2.1.2-beta8-macos-arm64.dmg`.

Back up the wallet before upgrading and verify the download checksum. Replace the
application and retain the existing data directory. A configuration-access error
does not require deleting or re-downloading blockchain data. Standalone daemon
downloads remain beta6. MMB snapshot sync is not enabled, and no measured
full-chain sync speedup is claimed. See also the [beta7 notes](release-notes-beta7.md).
