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
`WITNESS_CACHE_SIZE` (100) blocks needs no witness and no per-block update. One reorganisation step
cannot undo such a spend: the node refuses to disconnect more than `MAX_REORG_LENGTH` (99) blocks in
a step (`ActivateBestChainStep`, `RewindBlockIndex`). That limit is per step, not per spend: chained
reorganisations, an operator `invalidateblock`/`parkblock`/`finalizeblock`, and a chain that is
rewound at start-up can unwind further. What keeps a retired note correct is the un-retire below:
every disconnect that reaches the height of a recorded spend brings the notes back.

`CWallet::RetireSpentNotes` marks such a note retired in memory (`fRetired`, never serialized) and
stores it in the retired form (below), and the per-block updates (`IncrementNoteWitnesses`,
`DecrementNoteWitnesses`, the append path) skip it. A transaction whose notes are all retired leaves
`setNoteTxIndex` for `setNoteTxRetired`, so the cost of a block follows the unspent notes. Retiring
runs at start-up (`ReconcileNoteState`) and every `RETIRE_SWEEP_INTERVAL` (10) blocks from the block
update; the nullifier stays in the record (it is what keeps the note spent) and
`UpdateSaplingNullifierNoteMapWithTx` leaves a retired note alone.

**The retired form on disk.** `witnessHeight = -1`, nullifier kept, and for a Sapling note up to FOUR
frozen witnesses (`RETIRED_WITNESSES_KEPT`, the newest ones; about 0.78 KiB each): the record layout is unchanged. Sprout notes
and the notes retired by test builds keep no witness (an empty list), the notes retired by the one-witness build keep one; all forms
are recognised at load, by `ReconcileNoteState`, by un-retire and by the health report
(`witnesses_held_spent` counts the frozen ones).

Why witnesses and not none. Released binaries (v2.1.2-beta12 and before) move the height of a note
without a witness to the tip with every block (`UpdateWitnessHeights`), so a later rescan that starts
below the note (`importprivkey`, `z_importkey`, `z_importviewingkey`, `importwallet` with rescan)
makes `WitnessNoteIfMine` skip it, and `UpdateSaplingNullifierNoteMapWithTx` erases the nullifier of a
note whose witness list is empty: the spent note then reads as unspent, and that is saved
(64.5451 instead of 16.5451 ZCL in the reviewer's reproduction). With a witness the same function
derives the nullifier again from the witness position, which never changes. What the old code does
with a retired record, from the beta12 source:

- connect: `CopyPreviousWitnesses` accepts height -1, copies the frozen witness once per block (the
  list grows by one per block up to `WITNESS_CACHE_SIZE`, `nWitnessCacheSize` is at least that big),
  `AppendNoteCommitment` appends to it, `UpdateWitnessHeights` moves the height to the tip. The
  witness is no longer a valid witness, but the note is spent, the nullifier is derived from the
  position, and nothing ever spends it;
- disconnect: `DecrementNoteWitnesses` accepts -1 and the tip height and pops one entry per block;
- rescan and import with rescan: a note whose height is at the tip is skipped (witness and
  nullifier stay); a note still at -1 is witnessed again from its own block (the log line
  "Inconsistent witness cache state" appears, the cache is replaced): a normal live note, correct
  and heavier;
- `-rescan`, `-zapwallettxes`, `-salvagewallet`, backup/restore, restart: the record is read and
  written like any other; `ClearNoteWitnessCache` clears it, and the rescan rebuilds it.

None of these paths asserts on or aborts for such a record (`wallet_witness_retire.sh` scenario 5
runs them on the previous release and on the parent commit's build: blocks mined, an
invalidate/reconsider, `importprivkey` and `z_importkey` with rescan, a restart, a spend of an
unrelated note; balances and note counts equal the -rescan reference, and this build reads the
result back equal to a -rescan of the same wallet.dat).

How many (`RETIRED_WITNESSES_KEPT` = 4). An older binary adds one witness per block it connects
(`CopyPreviousWitnesses`, at most 100) and removes one per block it disconnects
(`DecrementNoteWitnesses`), so a record with W witnesses survives W - 1 disconnects that come before
any connect, and one witness survived none. Checked in the beta12 source for four entries at height -1:
`CopyPreviousWitnesses` and `UpdateWitnessHeights` assert only `nWitnessCacheSize >= witnesses.size()`
(a sweep retires a Sapling note only when it holds four witnesses, so the cache size written with the
wallet is at least four) and `witnessHeight == -1 || == tip - 1`; `DecrementNoteWitnesses` asserts
`witnessHeight == -1 || == tip` and `nWitnessCacheSize - 1 >= witnesses.size()` after the pop, which
holds because the cache size drops by one with every pop; `WitnessNoteIfMine` replaces the list of a
note still at -1 when a rescan meets its block; zap and `-rescan` clear the cache. Nothing else reads
the list's length. The cost is 3 more witnesses per retired note: a retired record weighs about
4.7 KiB (a live one 77 KiB).

**The stated limit.** An older binary whose first events after the downgrade are FOUR or more block
disconnects (an orphaned tip, `invalidateblock`), followed by a rescan from below the note
(`z_importkey` or `importwallet` with rescan), has no witness left, the rescan erases the nullifier,
and it counts those spent notes as unspent (347 notes instead of 107 in the test wallet) until it
runs with `-rescan` or this build opens the wallet again: this build finds confirmed notes without a
witness and rescans from their height. Nothing is spent twice and nothing can be sent from those
notes (the older binary fails with "Missing witness"). One, two and three disconnects first, then the
rescan, leave the older binaries correct (`wallet_witness_retire.sh` scenario 5, previous release and
parent commit); so does any number of disconnects after a block was connected, because each connect
adds a witness.

**The stored cache size and the frozen list.** Older binaries assert, at every block, that
`nWitnessCacheSize` (stored with the wallet) is at least the witness count of every note, retired ones
included. Every disconnect lowers the cache size by one, and a retired note is skipped by the per-block
updates, so this build cuts the frozen witnesses of every retired note to the new cache size at each
disconnect (`DecrementNoteWitnesses`; the records are marked and written at the next checkpoint),
raises the cache size at start-up to cover every note including the retired ones
(`ReconcileNoteState`), and resets both together in `ClearNoteWitnessCache`. Without this, 97 to 99
disconnects that reach no retired spend (an operator `invalidateblock` 97 deep) followed by a
checkpoint stored a cache size of 3 next to four-witness records, and beta12 aborted with
`Assertion 'nWitnessCacheSize >= nd->witnesses.size()'` at its first block and at every restart (only
`-rescan` on the old binary recovered). Consequence for the stated limit: after such a deep unwind the
frozen list is shorter than four (3 after 97 disconnects), so an older binary then survives fewer
disconnects-first than three; the notes are restored to four only when they are retired again. A
100-block unwind that reaches no retired spend does not bring the notes back: they stay retired and
spent, with the cache size at zero and the frozen lists trimmed to nothing. An empty record is the form
that loses the nullifier on a released binary after an import with rescan, and with no live note whose
cache could run out nothing else would trigger a rebuild, so the trim that empties a frozen list sets
`fNoteWitnessesLost` itself: the rebuild (above) runs before the next write and gives every such note
its witnesses back (the sweep freezes the spent ones again). The gtest `AnUnwindThatEmptiesTheFrozenWitnessesOfEveryNoteArmsTheRebuild`
covers it. `wallet_witness_retire.sh` scenario 5 runs the
97-block unwind with this build and then starts the previous release and the parent build on the
result: they start, mine blocks, restart, and balances and notes stay equal.

`ClearNoteWitnessCache` (`-rescan`, `-zapwallettxes`, the rebuild after an unwind) clears the retired
state with the witnesses: a note that stayed retired would be skipped by the rebuild and be stored
with no witness at all, which is the form older binaries lose track of. And a Sapling note with fewer than
four witnesses is not retired by a sweep (there is too little to freeze; a rescan has not reached its block
yet); a record already stored in the retired form is recognised at start-up.

A note that the chain at start-up does not show as deeply spent is not retired by the sweep. At
start-up a note that is already stored in the retired form and is spent by a mined wallet
transaction is retired at any depth: after a crash the chain can begin below the last wallet
checkpoint (the checkpoint is written without a full flush of the coins), and the spends are then
fewer than 101 blocks deep, but the note still needs no witness and no rescan from its own height.
If that spend is ever disconnected, un-retire handles it as for any other.

An unwind that disconnects the block of a spend that retired notes (`DecrementNoteWitnesses` calls
`UnretireNotesSpentFrom`) makes those notes live again: the frozen witness is dropped, they are
unspent, they have no witness, and `fNoteWitnessesLost` is armed. The rebuild above (rescan from
genesis, one rescan for the whole unwind) restores their witnesses at the next tip or checkpoint, and
until then a spend of them fails cleanly. A wallet transaction that leaves the wallet
(`EraseFromWallet`) brings back the notes it retired in the same way.

**The dirty set.** `SetBestChainINTERNAL` used to copy and write every note transaction at every
checkpoint. It now writes, by reference and in txid order, only the transactions in
`setNoteTxDirty`: the ones whose note data was touched since the last checkpoint that wrote them.
`CWallet::MarkNoteTxDirty` is the one helper; the writers of a note record that call it are
`IncrementNoteWitnesses` and `DecrementNoteWitnesses` (every live note transaction),
`RetireSpentNotes` and `UnretireNotesSpentFrom`, `AddToWallet` (new and merged transactions),
`UpdateSaplingNullifierNoteMapWithTx`, `UpdateNullifierNoteMap` (Sprout nullifiers),
`ReconcileNoteState` (every record it repairs), `ClearNoteWitnessCache` (all), and `SyncMetaData`.
What `LoadWallet` reads is clean. The set is cleared only after the database transaction commits, so a
failed write or commit leaves the transactions marked; the cache size and the locator are written at
every checkpoint, in the same single transaction and order as before, so every property above holds
unchanged. If a writer ever missed a mark, the record would reach `wallet.dat` only through another
rewrite, and the next start would find the stale witness exactly as it finds one after a crash
(`ReconcileNoteState` checks every cache against the chain and rescans from where it ends).

**What it saves.** Every live note transaction is still rewritten at the first checkpoint after each
block (its witness moved); the saving in normal running is the retired share of the wallet, which is
neither updated per block nor rewritten. `WalletPerf` bench (2000 Sapling notes, 90% spent and
buried, 13800 wallet transactions, a shared and loaded host): per foreign block the witness update
plus the chain-tip handling is 9.9 ms with the spends under 100 deep and 6.7 ms once they are
retired. The checkpoint one block after a block (200 live notes with 77 KiB of witnesses each dominate
what is written) is dominated by disk speed on this host and did not give a stable figure: in three
runs the previous release's way of writing took 3810, 1582 and 2941 ms and this build 2605, 1222 and
3683 ms. A checkpoint with no block in between (a clean stop, a second checkpoint) goes from 686 ms to
6 ms, and the checkpoint after a block with nothing live from 631 ms to 9 ms: those two are not the
per-block case. A retired note record weighs 4.60 KiB (four frozen witnesses, 0.78 KiB each) against
77 KiB for a live one, 1.57 KiB with no witness at all.
