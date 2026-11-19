# Wallet persistence and crash consistency

What the wallet writes to `wallet.dat`, when, and how the start-up logic checks
it against the chain. The write timing is the same in beta12 and in the
performance work after it (that work changed how the in-memory witness state is
updated per block, not what is written or when).

## What is written, and when

| State | Written to `wallet.dat` | Not written |
| --- | --- | --- |
| Wallet transactions without note data (transparent) | `AddToWallet`, at once (Berkeley DB auto-commit, log written, not fsynced) | |
| Wallet transactions with Sprout or Sapling note data | `AddToWallet` at once, **with whatever note data is in memory at that moment** (a new note has no witness and no nullifier yet); and again, in a `SetBestChain` checkpoint **when their note data changed since they were last written** (see "Retired notes and the dirty set") | per block |
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
`init-after-rescan`, `rebuild-before-scan`, `rebuild-after-scan`. The option does nothing unless it is given, and both it and
`-testsetchaininterval` stop the node at start-up with an error on any network but regtest. The regression test is
`qa/rpc-tests/wallet_crash_consistency.sh`; unit tests are in
`src/wallet/gtest/test_wallet_note_state.cpp`.

## Witnesses a reorg could not roll back (`fNoteWitnessesLost`)

A block disconnect rolls each note's witness cache back by one block (`DecrementNoteWitnesses`).
When a cache does not reach that far (a deep `invalidateblock`, more than `WITNESS_CACHE_SIZE`
blocks), the wallet no longer asserts: it clamps `nWitnessCacheSize` at zero, leaves the note
without a witness (never a wrong one) and sets the memory-only flag `fNoteWitnessesLost`. The
rebuild (clear every witness, rescan the active chain from genesis) runs once, at the first of

* the next connected block (`ChainTip`, `added`),
* the next `SetBestChain`, which includes the periodic write, the write `invalidateblock`,
  `parkblock` and `finalizeblock` trigger when they finish.

Rule: **`SetBestChain` never writes the note records, the cache size or the locator while the
flag is set.** Outside shutdown it runs the rebuild first and writes the rebuilt state. Once
shutdown has been requested (the shutdown checkpoint, or a periodic write during shutdown) it
does not rebuild, because the rebuild is a rescan from genesis that can take minutes on a large
wallet; it writes nothing and logs `wallet witness rebuild pending at shutdown`. `wallet.dat`
then keeps its last consistent checkpoint, from before the unwind, while the chain state is
flushed at the lowered tip, and the next start repairs it (below).

A process that dies between the unwind and the rebuild (kill -9), or stops with the rebuild
pending, has persisted only the checkpoint written before the unwind: the old locator, whose
fork with the chain is at or below the unwind point, and witness caches that are ahead of (or
beyond) the chain tip. `ReconcileNoteState` handles exactly that: caches ahead of the tip are
cut back to it when they reach that far and dropped otherwise, with the rescan starting at the
block that holds the note; notes whose records were rewritten without witnesses (the
transaction was re-synced after the disconnect) get `witnessHeight` -1 and the same rescan. So
the on-disk state after a crash or a stop in the lost-witness window is repaired by the next
start, without `-rescan`. `qa/rpc-tests/wallet_deep_unwind.sh` checks the result against a
`-rescan` reference for the kill, the crash points, the clean stop, and (variant 6) the state a
stop with the rebuild pending leaves: chain state at the lowered tip, wallet checkpoint from
before the unwind.

`rebuild-before-scan` and `rebuild-after-scan` are test crash points inside the rebuild.

## Retired notes and the dirty set

**Retired notes.** A note whose nullifier is spent by a wallet transaction buried deeper than
`WITNESS_CACHE_SIZE` (100) blocks cannot be un-spent by any reorg the node accepts: it refuses
to disconnect more than `MAX_REORG_LENGTH` (99) blocks (`ActivateBestChainStep`, `RewindBlockIndex`;
a parked chain is only unparked when it has twice the work, and the reorg it then asks for is
subject to the same limit, so the node shuts down instead of disconnecting). Such a note keeps no
witness: `CWallet::RetireSpentNotes` clears its witness list and sets `witnessHeight` to -1 once,
marks it retired in memory (`fRetired`, never serialized), and the per-block updates
(`IncrementNoteWitnesses`, `DecrementNoteWitnesses`, the append path) skip it. A transaction whose
notes are all retired leaves `setNoteTxIndex` for `setNoteTxRetired`, so the cost of a block follows
the unspent notes. Retiring runs at start-up (`ReconcileNoteState`) and every
`RETIRE_SWEEP_INTERVAL` (10) blocks from the block update; the nullifier stays in the record (it is
what keeps the note spent) and `UpdateSaplingNullifierNoteMapWithTx` leaves a retired note alone.

On disk a retired note is `witnesses = {}`, `witnessHeight = -1`, nullifier kept: the form every
older binary accepts (it asserts `witnessHeight == -1 || witnessHeight == tip - 1` only when it
copies a witness, and a note without witnesses is never copied). An older binary that runs on such a
wallet moves the height of every note to the tip, retired or not (`UpdateWitnessHeights`);
the next start of this build normalises that record again (witnesses empty, height -1) without a
rescan. `ReconcileNoteState` exempts retired notes from the rule that a confirmed note without a
witness needs a rescan; a note that the chain at start-up does not show as deeply spent is not
retired, and then the same rule rescans from its block.

An operator `invalidateblock`/`parkblock`/`finalizeblock` is not limited by `MAX_REORG_LENGTH`. When
such an unwind disconnects the block of a spend that retired notes (`DecrementNoteWitnesses` calls
`UnretireNotesSpentFrom`), those notes are live again, they have no witness, and
`fNoteWitnessesLost` is armed: the rebuild above (rescan from genesis, one rescan for the whole
unwind) restores their witnesses at the next tip or checkpoint, and until then a spend of them
fails cleanly. A wallet transaction that leaves the wallet (`EraseFromWallet`) brings back the notes
it retired in the same way.

**The dirty set.** `SetBestChainINTERNAL` used to copy and write every note transaction at every
checkpoint. It now writes, by reference and in txid order, only the transactions in
`setNoteTxDirty`: the ones whose note data was touched since the last checkpoint that wrote them.
`CWallet::MarkNoteTxDirty` is the one helper; the writers of a note record that call it are
`IncrementNoteWitnesses` and `DecrementNoteWitnesses` (every live note transaction),
`RetireSpentNotes` and `UnretireNotesSpentFrom`, `AddToWallet` (new and merged transactions),
`UpdateSaplingNullifierNoteMapWithTx`, `ReconcileNoteState` (every record it repairs),
`ClearNoteWitnessCache` (all), and `SyncMetaData`. What `LoadWallet` reads is clean. The set is
cleared only after the database transaction commits, so a failed write or commit leaves the
transactions marked; the cache size and the locator are written at every checkpoint, in the same
single transaction and order as before, so every property above holds unchanged. If a writer ever
missed a mark, the record would reach `wallet.dat` only through another rewrite, and the next start
would find the stale witness exactly as it finds one after a crash (`ReconcileNoteState` checks
every cache against the chain and rescans from where it ends).
