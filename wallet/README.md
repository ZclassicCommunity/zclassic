# ZClassic Wallet

A private, single-file ZClassic wallet — with a full ZClassic node built right in. One download, no setup, no command line. For **Windows, macOS, and Linux**.

> **New here?** Download the file for your computer below and open it. The wallet shows setup and sync progress. If Windows blocks access to existing wallet files, use **Repair access and continue**; **Details** shows the affected locations.

![ZclWallet — your balance, shielded and transparent](docs/screenshot-wallet.png?raw=true)
![Friendly first-run setup](docs/screenshot-firstrun.png?raw=true)

## Download & run

**Current desktop prerelease: v2.1.2-beta9**:
**https://github.com/ZclassicCommunity/zclassic/releases/tag/v2.1.2-beta9**

Download the **one** file for your computer and open it:

| Your computer | Download | First-time open |
|---|---|---|
| **Windows** | `zclwallet-v2.1.2-beta9-win64.exe` | Double-click. If you see **"Windows protected your PC"**, click **More info → Run anyway**. |
| **macOS 15+** (Apple Silicon) | `zclwallet-v2.1.2-beta9-macos-arm64.dmg` | Open the `.dmg` and drag **ZclWallet** to Applications. On first launch macOS says **"Apple could not verify … is free from malware"** — that's expected (the app is signed but not yet notarized). See **[Opening on macOS](#opening-on-macos)** just below. |
| **Linux** | `zclwallet-v2.1.2-beta9-linux-x86_64` | `chmod +x zclwallet-v2.1.2-beta9-linux-x86_64 && ./zclwallet-v2.1.2-beta9-linux-x86_64` — or right-click → Properties → *Allow executing as program*, then double-click. _(glibc ≥ 2.31; system X11/XCB libraries required; no Qt or OpenSSL install needed.)_ |

### Opening on macOS

The beta9 app requires **macOS 15 or newer on Apple Silicon**. It is ad-hoc signed, not Apple-notarized. Verify its checksum first. If Gatekeeper blocks it, use **System Settings → Privacy & Security → Open Anyway** for the verified app.

## What happens on first launch

The wallet starts its built-in node, which automatically downloads its security files and a recent copy of the blockchain (a few GB) from the network — all checked for integrity, with a progress bar. Depending on your connection, this can take a little while. When it finishes, your wallet opens. **That is the entire setup** — there's nothing to download or configure by hand.

Your private keys and wallet state are stored in `wallet.dat`, which the node updates during normal operation. Back up your wallet before upgrading. Keep your existing data directory.

## Your privacy

ZClassic supports **shielded z-addresses**, which keep your balances and transfers private.

- The **Receive** tab gives you a shielded **z-Sapling** address by default.
- The **Balance** tab shows your **Shielded** and **Transparent** funds separately, plus the **Total** — so you always know what's private and what's public.

The tabs are: **Balance · Send · Receive · Transactions · zclassicd**.

## Beta9 improvements

Windows requires no separate GCC, Qt, pthread or OpenSSL DLLs. The release adds verified daemon extraction and cache reuse, owner-only metadata permissions, atomic file writes and verified HTTPS. It retains the beta6 daemon and unchanged consensus rules. See [release notes and platform requirements](../doc/release-notes-beta9.md). Full-chain sync speed has not been benchmarked.

## Verify your download

Each release includes `SHA256SUMS.txt`. To check a file matches:

- **Linux:** `sha256sum <file>`
- **macOS:** `shasum -a 256 <file>`
- **Windows:** `certutil -hashfile <file> SHA256`

Compare the result against the matching line in `SHA256SUMS.txt`.

## Run a node only

The wallet runs its own embedded `zclassicd` automatically — most people never think about it. If you already run a ZClassic node, the wallet connects to that instead.

To run a **node only** (no GUI, e.g. on a server), download `zclassicd` from the [beta6 node release](https://github.com/ZclassicCommunity/zclassic/releases/tag/v2.1.2-beta6) and run it — **no flags or config needed**. It fetches the params and a snapshot and syncs by itself.

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
