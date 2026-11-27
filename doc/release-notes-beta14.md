# ZClassic Wallet and Node 2.1.2-beta14

Beta14 is a wallet update: a recovery phrase, a new look, and a wallet that stays fast and keeps your balance on screen. The node and the wallet are both v2.1.2-beta14.

**No consensus rule, checkpoint, activation height or the IBD proof-skip is changed.** The node changes are in the wallet code only (key derivation, three new RPCs, the restore).

## What is new

- **24-word recovery phrase.** The wallet's HD seed can be written down as 24 words (the BIP39 English list and checksum). The Backup page shows them, asks for three of them to check that they were written down, and can restore from them.
  - The words are the 32-byte seed itself: there is no PBKDF2 step and no passphrase. An existing wallet therefore keeps its seed and its Sapling addresses are covered at once. It also means the phrase is not a standard BIP39 seed phrase: **it works in the ZClassic wallet only**; other wallet apps derive different keys from the same words.
  - New transparent addresses and transparent change now come from the seed too (BIP44 path `m/44'/147'/0'/0/i`), so one phrase covers every address the wallet makes from now on. At start-up the key pool drops keys that do not come from the seed (the keys stay in the wallet) and refills from it, once per wallet.
  - **Not covered:** keys made before this release, imported keys and Sprout keys. The Backup page lists the ones that hold money and fills in a send to a new address for you to review; Sprout money goes through the existing Sprout migration. A copy of `wallet.dat` still keeps every key, and the Home backup reminder stays while money sits on an address the phrase does not cover.
  - New RPCs: `z_getphraseinfo` (which addresses the phrase does not cover), `z_getrecoveryphrase` and `z_restorefromphrase "phrase" ( startheight )`. A restore makes the phrase the wallet's seed, keeps every key already in the wallet, rescans the whole chain from `startheight` and derives more addresses while the newest ones turn out used. The previous seed stays in the wallet file as a `retiredseed` record. A restore needs an unencrypted wallet and holds the wallet for the length of the rescan.
  - An older release still opens a wallet that beta14 has used or restored.
- **New look and navigation.** A side menu instead of tabs, with Home, Send, Receive, Activity, Backup, Address book, Settings, Node and More. Receive has Private and Transparent tabs, the QR next to the full address, and a list of your addresses with search and paging. Settings and Address book are pages. Start-up shows its progress in the main window; the pages that need the node open once it answers. Icons load with a transparent background on every desktop.
- **Your balance stays on screen.** When the node drops or restarts, Home keeps the last known balance, greyed and dated, instead of replacing it with a dash. A dash appears only when the wallet has never recorded a balance.
- **Activity lists older transparent transactions.** The wallet asked the node without a count and got the 10 latest only; it now asks for the latest 1000.
- **Transparent addresses are not reused.** The Transparent tab offers an address the node says was never paid, instead of making a new key on every visit; **New address** still always makes one.
- **Fast in old wallets.** A wallet from the years when the GUI made a transparent key about every block can hold tens of thousands of transparent addresses. Measured with 53,766 of them: opening Receive took 970 ms the first time and 465 ms after that, and now takes 7 ms and 2 ms. The per-block address refresh no longer checks every address's checksum, and the Backup page counts only the older addresses that hold money.
- **Time format.** Settings has 24-hour, 12-hour or "5m ago" times for Activity; the CSV export keeps its fixed date format.

## Upgrading

Close your older wallet normally, keep your existing wallet and data directory, and open the beta14 wallet. Nothing is downloaded again. Back up `wallet.dat` first, as before any upgrade.

After the upgrade, open **Backup**, write the 24 words on paper and do the three-word check.

## Known limits

- `z_getphraseinfo` takes about a second in a wallet with tens of thousands of old addresses; the wallet asks it a moment after connecting so it does not delay the first balance.
- A restore started while the node is still syncing only finds what the node has seen so far; restore after the sync has finished.
- The limits listed in the [beta13 notes](release-notes-beta13.md) still apply.
