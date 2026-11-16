# ZClassic Wallet v2.1.2-beta6

A single file. Double-click it — the wallet and a full ZClassic node start together, with
nothing to install or configure. This release is about making that "just works" promise real
on every machine, and making your money safe and your privacy clear.

## ⭐ Highlights

### It starts everywhere now
- **Fixed the startup crash on modern Linux** (Fedora 39+, Arch, and other recent distros). The
  app could segfault right after launch; it now opens reliably to "Payment UI ready."

### It connects itself
- **Zero-config sign-in.** The wallet now signs in to your node automatically — including nodes
  running in cookie-auth mode (no `rpcpassword` set) and nodes you started yourself. No more
  "Authentication failed / fix it in Settings" dead-ends.

### Your money is safe and your sends go through
- **Fixed "Not enough funds" when shielding your whole balance.** A rounding bug could falsely
  block a max shield even when both numbers read the same (e.g. "send 0.12, but you only hold
  0.12"). All amount math is now exact (integer zatoshis).
- **Fixed auto-shield for mined (coinbase) funds**, which previously failed with a false
  insufficient-funds error.
- **Closed a privacy leak in auto-shield.** In a narrow timing window, change could have been
  sent as a *public* transparent output instead of staying shielded. The wallet now re-checks
  and refuses to send rather than ever leak your change.

### Clearer, calmer, private-by-default
- A modern dark theme, a privacy-first Home dashboard, and **shielded (private) by default**.
- **Instant balance** display (single round-trip via the node's wallet summary, with a safe
  fallback on older nodes) and live balance updates.
- A friendlier Receive screen (private address front-and-center), a one-button **backup** flow,
  honest sync status, and **stays in the tray** for instant re-open.
- Readable transaction history on the dark theme; the "Clear saved history" Cancel button no
  longer deletes anything.

### Opt-in: help the network
- An optional **NAT-PMP** panel ("you're helping the network") with honest reachability — off by
  default, never UPnP.

## 🔒 Safety notes
- The shielded-send / auto-shield money paths are covered by the L0/L1 test suites and an
  independent source-level review against the node. As with any wallet release, **back up your
  wallet** before upgrading.

## 📦 Downloads
- **Linux** — `zclwallet-v2.1.2-beta6-linux-x86_64` (glibc 2.31+; `chmod +x` and run).
- **Windows** — `zclwallet-v2.1.2-beta6-win64.exe`.
- **macOS** — `zclwallet-v2.1.2-beta6-macos-arm64.dmg` (Apple Silicon; see **Opening on macOS** below).

Verify your download against `SHA256SUMS.txt` first if you like.

## 🍎 Opening on macOS (please read)
On first launch macOS will say **"Apple could not verify "ZclWallet" is free from malware."**
This is **expected** — the app is signed but not yet *notarized* (no Apple Developer ID yet). The
download is fine; here's how to open it (once):

- **macOS 14 Sonoma / 15 Sequoia:** double-click → click **Done** → open
  **System Settings → Privacy & Security**, scroll to *Security*, click **Open Anyway** next to the
  ZclWallet message → authenticate.
- **macOS 13 and earlier:** **right-click (Control-click) the app → Open → Open.**
- **Any version (Terminal):** `xattr -dr com.apple.quarantine /Applications/ZclWallet.app`

(We plan to notarize a future build so this prompt goes away entirely.)

## Upgrading
Just replace the old file with the new one. Your wallet data is untouched.

---
*This is a pre-release (beta). The money paths are tested and reviewed but, as always, start
with a small amount you can afford to test.*
