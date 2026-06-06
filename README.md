# ZClassic 2.1.2-beta6

ZClassic is an Equihash-based proof-of-work implementation of the Zerocash protocol. It offers privacy through shielded transactions using zero-knowledge proofs that preserve transaction confidentiality. Based on Bitcoin's code and derived from Zcash, ZClassic builds three main binaries: **zclassicd** (daemon), **zclassic-cli** (RPC client), and **zclassic-tx** (transaction utility).

**Mainnet:** P2P port `8033`, RPC port `8023`

## What is ZClassic?

[ZClassic](https://zclassic.org/) implements the "Zerocash" protocol, offering far higher privacy than Bitcoin through a zero-knowledge proving scheme that preserves the confidentiality of transaction metadata. For technical details, see the [Protocol Specification](https://github.com/zcash/zips/raw/master/protocol/protocol.pdf).

This software is the ZClassic client. It synchronizes the entire blockchain history to your computer.

**Security Warning:** ZClassic is experimental and a work-in-progress. Use at your own risk. For a security issue, please [open an issue](https://github.com/ZclassicCommunity/zclassic/issues); see also the [upstream Zcash security background](https://z.cash/support/security/).

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

## NFTs / Collectibles (ZSLP) — dev/testnet stage

ZClassic can carry **NFTs and tokens** as a **non-consensus overlay** called ZSLP (an SLP Token Type 1 message in a single `OP_RETURN`). An NFT is a 1-of-1 token: a baton-less GENESIS with `decimals=0`, `quantity=1`. The token id is the genesis transaction id. The file itself never goes on-chain — only a 32-byte fingerprint (`document_hash`, a SHA-256 of the file) is recorded, so anyone can verify that a given file matches what was minted.

**Security model, in one paragraph.** ZClassic consensus does not know NFTs exist — it never changes for this feature. Instead, every node that runs the indexer re-derives the same token ledger as a deterministic function of the confirmed chain: it reads each `OP_RETURN`, debits the spent token inputs, credits the outputs, and enforces conservation (a transfer is valid only if tokens-in ≥ tokens-out). The consequence, stated honestly: a forged token message **can be mined, but it credits nobody** and every honest node agrees it is invalid. Security here is *agreement*, not chain rejection — so treat ZSLP as **dev/testnet-stage**, not mainnet-ready.

**The index is ON by default.** The `zslp_*` RPCs need the read-only ZSLP index, which defaults **on** (`-zslpindex`, default `1`). It does a one-time catch-up scan in the background. Opt out with `-zslpindex=0`.

### CLI walkthrough (mint → inspect → transfer → list)

All arguments are **positional**. (`zslp_genesis` takes one JSON object; the rest take plain positional args.)

```bash
# 1. Compute the file fingerprint (32-byte SHA-256, lowercase hex)
HASH=$(sha256sum my-art.png | cut -d' ' -f1)

# 2. Mint a 1-of-1 NFT (nft:true forces decimals 0, quantity 1, no re-issue baton)
./src/zclassic-cli zslp_genesis "{\"nft\":true,\"name\":\"My Photo #1\",\"document_url\":\"\",\"document_hash\":\"$HASH\"}"
#   -> { "txid": "<hex>", "tokenid": "<hex>" }     (tokenid == txid == the NFT's identity)

# 3. Inspect the token you just minted
./src/zclassic-cli zslp_gettoken "<tokenid>"
#   -> name, document_hash, decimals 0, totalMinted 1, hasMintBaton false  (a real 1-of-1)

# 4. Transfer / gift it to someone (positional: tokenid, recipient, amount[, change_addr])
./src/zclassic-cli zslp_send "<tokenid>" "t1RecipientAddress..." 1
#   -> { "txid": "<hex>" }

# 5. List the NFTs/tokens this wallet holds
./src/zclassic-cli zslp_listmytokens
```

> **Honest limits.** A transfer is public and irreversible (a send to the wrong address cannot be undone). The name and image are **not** unique — anyone can mint another token reusing them; only the token id (genesis txid) is one of a kind. The fingerprint proves *which bytes* were minted, never that a creator is "genuine" or "official." ZSLP is a non-consensus overlay (dev/testnet-stage).

### Private files / private NFTs (shielded data channel) — dev/testnet, default-OFF

You can also send a **private file or message** over the shielded pool: the bytes are encrypted, framed into Sapling memos, and carried in one shielded transaction. This is **default-OFF** and experimental — start `zclassicd` with `-experimentalfeatures -datachannel` to enable it (the RPCs return `-32601` when off).

```bash
# SENDER (both addresses must be Sapling z-addrs in your wallet; acknowledge_permanent is REQUIRED)
./src/zclassic-cli z_senddatafile '{"fromaddress":"zs1...","toaddress":"zs1...","filepath":"/path/to/secret.png","acknowledge_permanent":true}'
#   -> { "operationid", "transfer_id", "fingerprint", "frames", "key" }
#      "fingerprint" is the 32-byte ciphertext anchor (= an NFT's document_hash); "key" is yours to disclose selectively.

# List the transfers this node knows about (sent this session)
./src/zclassic-cli z_listdatatransfers

# RECIPIENT: reassemble + verify-before-decrypt, then decrypt
./src/zclassic-cli z_getdatatransfer '{"transfer_id":"<16hex>"}'
#   -> { "verified", "complete", "frames_received", "hexdata", "filename", "content_type", ... }
```

> **What this protects / does not.** Hidden: who it's from, who it's to, the amount, the contents. Visible: *that* a private transfer happened, roughly *when*, and roughly *how big*. It is **permanent** on every full node forever and **not deletable** — private ≠ undetectable. Keep files small (per-file cap ~40000 bytes). The recipient verifies the on-chain ciphertext fingerprint **before** decrypting; selectively disclose by handing over the returned `key`, or `z_exportviewingkey` for the receiving z-addr (read/prove only, never spend).

### Sell an NFT for ZCL (atomic swap) — dev/testnet

You can sell a transparent NFT for transparent ZCL in a single `ALL|ANYONECANPAY` atomic swap.

```bash
# SELLER: build a signed offer for the NFT
OFFER=$(./src/zclassic-cli nft_makeoffer '{"tokenId":"<txid>","priceZat":"100000000","buyerNftAddr":"t1Buyer...","payoutAddr":"t1Seller..."}')
#   -> { "offerBlob": "znftoffer:..." }   (hand this blob to the buyer)

# BUYER (mandatory): verify the offer BEFORE taking it
./src/zclassic-cli nft_verifyoffer '{"offerBlob":"znftoffer:..."}'
#   -> { "ok": true, "priceZat": ..., ... }

# BUYER: take the offer (appends funding, broadcasts the single atomic tx)
./src/zclassic-cli nft_takeoffer '{"offerBlob":"znftoffer:..."}'
```

> **Honest limit.** The single-tx swap makes the **coin** legs consensus-atomic, but token attribution is an indexer convention — so this is **trust-minimized, not trustless**. Always run `nft_verifyoffer` before `nft_takeoffer`. No shielded leg can be atomic. (Other SELL RPCs: `nft_listoffers`, `nft_canceloffer`, `nft_requestbuy`.)

For the full design — mint/transfer write path, anti-burn protection, content addressing, the private data channel, and the NFT→ZCL sell design — see [doc/nft/README.md](doc/nft/README.md) (start with `NATIVE_NFT_GUIDE.md`). Runnable end-to-end proofs live in `qa/zslp/` (`zslp-nft-regtest.sh`, `nft-sell-regtest.sh`; see `qa/zslp/README.md`).

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
