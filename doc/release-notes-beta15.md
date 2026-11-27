# ZClassic Wallet and Node 2.1.2-beta15

Beta15 is a wallet update: the Node page is rebuilt to show what your node sees. The node and the wallet are both v2.1.2-beta15.

**No consensus rule, checkpoint, activation height or the IBD proof-skip is changed.** The node's source is the same as in beta14 apart from its version label.

## What is new

- **A Node page that shows the node.** It was a logo and three bare rows. It now has:
  - four tiles: block height with the age of the last block and "Synced" or how many blocks are left, peers split into outgoing and incoming, network hashrate, difficulty;
  - the network hashrate over the last 24 hours, as a chart;
  - the latest six blocks (height, age, transactions, size and the whole hash with a copy button) and a lookup by block height or hash;
  - facts read from your own node: the block reward, the next halving, the recent block time against the 75-second target, how much ZCL is held in private addresses, waiting transactions, how long the chain has run, and the node version;
  - the "helping the network" panel as its own card.
  - It asks the node only while the page is shown, with read-only calls.
- **It fits every window.** The page rearranges itself with the window: four tiles in a row or two by two, the facts beside the chart or under it, a block's hash on one line or as two halves. It scrolls down, never sideways, from a 640-pixel-wide window to a 2560-pixel one.
- **Send and Receive tidied.** On Send, "Add Recipient" sits at the left under the fields it adds to. On Receive, the two request fields read "Amount (optional)" and "Note (optional)" (the longer texts were cut off), and the address list no longer says to back up again after making new addresses: new addresses come from the recovery phrase.

## Upgrading

Close your older wallet normally, keep your existing wallet and data directory, and open the beta15 wallet. Nothing is downloaded again. Back up `wallet.dat` first, as before any upgrade.

## Known limits

- The hashrate chart covers the last 24 hours only, and the block lookup shows one block; there is no transaction lookup.
- The limits listed in the [beta14 notes](release-notes-beta14.md) still apply.
