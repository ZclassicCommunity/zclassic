# Wallet persistence and crash consistency

What the wallet writes to `wallet.dat`, when, and how the start-up logic checks
it against the chain. The write timing is the same in beta12 and in the
performance work after it (that work changed how the in-memory witness state is
updated per block, not what is written or when).

## What is written, and when

| State | Written to `wallet.dat` | Not written |
| --- | --- | --- |
| Wallet transactions without note data (transparent) | `AddToWallet`, at once (Berkeley DB auto-commit, log written, not fsynced) | |
| Wallet transactions with Sprout or Sapling note data | `AddToWallet` at once, **with whatever note data is in memory at that moment** (a new note has no witness and no nullifier yet); and again, **all of them**, in every `SetBestChain` checkpoint | per block |
| Sapling nullifier, Sprout nullifier | inside the note-transaction record (above) | |
| Witness cache and `witnessHeight` of every note | inside the note-transaction record (above); updated in memory for every connected block | per block |
| `nWitnessCacheSize` | `SetBestChain` | |
| Best-block locator | `SetBestChain` | |
| Spent-ness (`mapTxNullifiers`, `mapSaplingNullifiersToNotes`, ...) | not stored: rebuilt from the transactions and nullifiers when the wallet is loaded | |

`SetBestChain` (`SetBestChainINTERNAL`) writes the note transactions, the cache size
and the locator in one Berkeley DB transaction, locator last. It runs

* at the end of a start-up rescan (`init.cpp`),
* from `FlushStateToDisk` in `PERIODIC` or `ALWAYS` mode, at most every
  `DATABASE_WRITE_INTERVAL` (one hour; `-testsetchaininterval=<s>` overrides it for tests),
  which may be before the coin database is flushed, so the locator can be ahead of the
  chain state that survives a crash,
* **at shutdown, after the final chain-state flush** (new): the checkpoint and the chain
  state now describe the same tip after every clean stop.

The chain state (coin database, block index) is flushed when the coin cache is full, every
24 hours, and at shutdown. After a crash the chain is rolled back to the last flush.

## What start-up does with it

1. Load `wallet.dat`; rebuild the spent-ness maps from the transactions.
2. Take the fork of the stored locator with the active chain as the rescan start.
3. **`CWallet::ReconcileNoteState`** (new) checks every note's witness cache and nullifier
   against the active chain before it is trusted:
   * a cache ahead of the chain tip (the chain state was rolled back behind the wallet) is
     cut back to the tip if the cache reaches that far, and dropped if it does not;
   * a cache whose root is not what the chain committed to at that height (another branch
     won after the crash) is dropped, and the rescan starts at the block that holds the note;
   * a cache that ends before the locator (a record written while blocks were being
     reconnected) lowers the rescan start to where it ends;
   * a confirmed note without any witness lowers the rescan start to its block;
   * a Sapling nullifier that is missing next to its witness is derived again (a note whose
     nullifier is missing reads as unspent, which is how a spent note came back as balance).
   Only cached witness data is ever dropped; no transaction or key is.
4. Rescan from the (possibly lowered) start, then write one checkpoint.

## What re-adding a transaction does

`AddToWallet` merges a transaction that is already in the wallet (a block reconnected after
a rollback, a reindex, a transaction announced again after a disconnect). The merge keeps the
old witnesses and their height, and now keeps the old nullifier with them. Before, the
nullifier was dropped, the record written to disk had a witness but no nullifier, and the
note read as unspent after the next restart because the locator was already past its block.

## `-zapwallettxes`

`-zapwallettxes` erases every wallet transaction, one auto-committed erase at a time, and only
the `-rescan` it implies finds them again. The locator is now set to an empty locator before the
first erase (the write reaches the log first), so a process that dies before that rescan has
ended rescans from genesis on its next plain start instead of trusting a locator that promises
transactions which are no longer in the file. Older releases read an empty locator the same way.
`qa/rpc-tests/wallet_zap_interrupt.sh` covers it.

## Test hooks

`-testcrashpoint=<name>[:<n>]` exits the process with status 77 (like `kill -9` at that
spot) the n-th time the named point is reached; `any` matches every point. Points:
`addtowallet-after-write`, `chaintip-before`, `chaintip-after`, `connect-after-updatetip`,
`connect-between-sync-and-chaintip`, `disconnect-between-sync-and-chaintip`,
`flush-after-coins`, `flush-before-setbestchain`, `setbestchain-begin`,
`setbestchain-after-txs`, `setbestchain-after-locator`, `setbestchain-after-commit`,
`init-after-rescan`. The option does nothing unless it is given, and both it and
`-testsetchaininterval` stop the node at start-up with an error on any network but regtest. The regression test is
`qa/rpc-tests/wallet_crash_consistency.sh`; unit tests are in
`src/wallet/gtest/test_wallet_note_state.cpp`.
