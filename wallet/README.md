# ZClassic Wallet

A private, single-file ZClassic wallet — with a full ZClassic node built right in. One download, no setup, no command line. For **Windows, macOS, and Linux**.

> **New here?** Download the file for your computer below and open it. The wallet shows setup and sync progress. If Windows blocks access to existing wallet files, use **Repair access and continue**; **Details** shows the affected locations.

![ZclWallet — your balance, shielded and transparent](docs/screenshot-wallet.png?raw=true)
![Friendly first-run setup](docs/screenshot-firstrun.png?raw=true)

## Download & run

**Windows, Linux and macOS: [v2.1.2-beta13](https://github.com/ZclassicCommunity/zclassic/releases/tag/v2.1.2-beta13).**

Download the **one** file for your computer and open it:

| Your computer | Download | First-time open |
|---|---|---|
| **Windows** | `zclwallet-v2.1.2-beta13-win64.exe` | Double-click. If you see **"Windows protected your PC"**, click **More info → Run anyway**. |
| **macOS 14+** (Apple Silicon) | `zclwallet-v2.1.2-beta13-macos-arm64.dmg` | Open the `.dmg` and drag **ZclWallet** to Applications. On first launch macOS says **"Apple could not verify … is free from malware"** — that's expected (the app is signed but not yet notarized). See **[Opening on macOS](#opening-on-macos)** just below. |
| **Linux** | `zclwallet-v2.1.2-beta13-linux-x86_64` | `chmod +x zclwallet-v2.1.2-beta13-linux-x86_64 && ./zclwallet-v2.1.2-beta13-linux-x86_64` — or right-click → Properties → *Allow executing as program*, then double-click. _(glibc ≥ 2.31; system X11/XCB libraries required; no Qt or OpenSSL install needed.)_ |

### Opening on macOS

The beta13 app targets **macOS 14 or newer on Apple Silicon** and was tested natively on macOS 26. It is ad-hoc signed, not Apple-notarized. Verify its checksum first. If Gatekeeper blocks it, use **System Settings → Privacy & Security → Open Anyway** for the verified app.

## What happens on first launch

The wallet starts its built-in node, which automatically downloads its security files and a compiled-checkpoint snapshot (about 11.2 GB in the tested release) from the network — all checked for integrity, with a progress bar. Depending on your connection, this can take a little while. When it finishes, your wallet opens. **That is the entire setup** — there's nothing to download or configure by hand.

Your private keys and wallet state are stored in `wallet.dat`, which the node updates during normal operation. Back up your wallet before upgrading. Keep your existing data directory.

## Your privacy

ZClassic supports **shielded z-addresses**, which keep your balances and transfers private.

- The **Receive** tab gives you a shielded **z-Sapling** address by default.
- The **Balance** tab shows your **Shielded** and **Transparent** funds separately, plus the **Total** — so you always know what's private and what's public.

The tabs are: **Balance · Send · Receive · Transactions · zclassicd**.

## Beta13: new wallet and node

Beta13 is a new wallet and a new node (both v2.1.2-beta13). The shielded cryptography is now C23 (no Rust, no libsnark), start-up and balance queries are faster, and wallet state survives hard kills and reorganisations with correct balances. Close your older wallet normally, keep your data directory and open beta13; back up your wallet first.

- **Fast sync** uses every snapshot server at once, checks every byte against the trusted snapshot manifest, and the download screen shows how many servers are in use. A kill during the snapshot install no longer needs manual cleanup.
- **Faster connections:** a fresh wallet finds its first peers in a fraction of the time (measured on a Windows home PC: 3 peers in 0.75 s instead of 8.6 s, median of 5 fresh starts).
- **Wallet health:** the status bar shows "Wallet needs attention" only when something needs it (hover for details). A healthy wallet shows nothing.
- **Retried sends cannot pay twice:** `z_sendmany` accepts an `idempotency_key` and the node keeps a durable send journal (`z_listsendjournal`); spent notes are retired from per-block work, so the wallet file is smaller.
- No consensus rule, checkpoint or activation height changed. See the [beta13 release notes](../doc/release-notes-beta13.md) for the full list and known issues.

## Beta12: automatic checkpoint sync

Close your older wallet normally and open beta12 with the existing data directory.
Eligible wallets far behind the compiled checkpoint switch automatically: the app
waits for its node to save the wallet, verifies a private backup, preserves the old
chain, and downloads the checkpoint. No repair menu is needed. Keep at least
15 GiB free for the additional copy. Downloads and validation still take time.
See [eligibility, test results and limits](../doc/release-notes-beta12.md).

## Beta11 backend improvements

Beta11 rebuilds the wallet and its node backend. Verified checkpoint downloads
connect to the correct service, retry interrupted transfers and show byte-level
progress. Z23-derived root caching, less wallet-scanning copying and indexed
block catch-up reduce redundant work. The compiled checkpoint at block 3,126,937,
its complete state commitment and subsequent block validation remain mandatory.
Consensus rules and wallet formats are unchanged; Rust cryptography remains.

Repair holds the native data-directory lock, makes private verified wallet
backups, retains earlier backups and journals blockchain moves for recovery after
an interrupted process. Startup cancellation and shutdown are safer, and balance
layout remains readable at large display scales. No misleading sync ETA is shown.

Windows needs no separate GCC, GMP, MPC, ISL, Qt or OpenSSL runtime DLLs. Mac uses
a pinned static Qt toolchain with native system TLS. Initial downloads and wallet
scanning still take time; see the [release notes](../doc/release-notes-beta11.md)
for observed timings, test coverage and limitations.
## Verify your download

Each release includes `SHA256SUMS.txt`. To check a file matches:

- **Linux:** `sha256sum <file>`
- **macOS:** `shasum -a 256 <file>`
- **Windows:** `certutil -hashfile <file> SHA256`

Compare the result against the matching line in `SHA256SUMS.txt`.

## Run a node only

The wallet runs its own embedded `zclassicd` automatically — most people never think about it. If you already run a ZClassic node, the wallet connects to that instead.

To run a **node only** (no GUI, e.g. on a server), download `zclassicd` from the [beta13 release](https://github.com/ZclassicCommunity/zclassic/releases/tag/v2.1.2-beta13) and run it — **no flags or config needed**. It fetches the params and a snapshot and syncs by itself.

_(To run the wallet itself without the GUI, pass `--headless`.)_

## Build from source

This wallet is **C++14 + Qt 5.15**. Full, copy-pasteable instructions for all three platforms (native + cross-compile, single-file packaging, code-signing) are in:

- **`docs/BUILDING.md`** — the wallet (GUI + single-file).
- **`AGENTS.md`** — the cross-repo build quickstart (also in the [zclassic](https://github.com/ZclassicCommunity/zclassic) node repo, alongside `doc/building-daemon-from-source.md`).

Quick Linux dev build:

```
git clone https://github.com/ZclassicCommunity/zclassic.git
cd zclassic/wallet
/path/to/qt5/bin/qmake zcl-qt-wallet.pro CONFIG+=release && make -j$(nproc)
```

Building from source produces the GUI without an embedded node by default — run an external `zclassicd`, or use `contrib/make-allinone.sh` to embed one. See `docs/BUILDING.md`.

## Help

[File an issue](https://github.com/ZclassicCommunity/zclassic/issues) for support or bug reports.

_ZclWallet is a community wallet and is not affiliated with the Electric Coin Company._
