# Historical oversize transactions

Owner-authorised consensus change: zclassicd accepts the 413 mainnet transactions
that are larger than `MAX_TX_SIZE_AFTER_SAPLING` (102,000 bytes) and are already in
the chain, so a node can validate the chain from genesis. Nothing else about
consensus changes.

## Why

Commit 8d6d05e63 (v2.1.1-58, 2023) lowered `MAX_TX_SIZE_AFTER_SAPLING` from
2,000,000 (the then `MAX_BLOCK_SIZE`) to 102,000 with no height gate. The chain
holds 413 post-Sapling transactions above 102,000 bytes in 171 blocks (heights
478,544 to 1,968,856, the largest 1,922,197 bytes). `CheckTransaction` rejected
them with `bad-txns-oversize`, so a from-genesis sync stopped at block 478,543.
No transaction after height 1,968,856 exceeds 102,000 bytes.

## The rule

Same rule as Z23 (`core/consensus/src/tx_structural.c`,
`core/consensus/src/oversize_grandfather_table.inc`):

A transaction whose serialized size is greater than `MAX_TX_SIZE_AFTER_SAPLING` is
still rejected with `bad-txns-oversize`, except when all of these hold:

1. it is being validated as part of a block (`CheckBlock`, which `ProcessNewBlock`,
   `AcceptBlock`, `ConnectBlock`, `TestBlockValidity`, `VerifyDB` and, through
   `ProcessNewBlock`, `LoadExternalBlockFile` reach);
2. its serialized size is at most 2,000,000 (`MAX_TX_SIZE_GRANDFATHER_CEILING`,
   Z23's `MAX_BLOCK_SIZE`);
3. its txid (double SHA-256 of its serialization, `CTransaction::GetHash()`,
   compared as the 32 internal bytes) and its exact serialized size are one of the
   413 `(txid, size)` pairs of the table. A listed txid with any other size is
   rejected.

There is no height test and no network test: the rule is the same on mainnet,
testnet and regtest, and the listed txids do not occur on the test networks.
`AcceptToMemoryPool`, relay, wallet, `sendrawtransaction` and
`createrawtransaction` call `CheckTransaction` without the block flag and keep the
102,000 byte limit. Block size rules (`GENEROUS_BLOCK_SIZE_LIMIT` 2,000,000),
sigops, checkpoints, activation heights and the IBD proof skip are untouched.

Code: `src/consensus/oversize_grandfather.{h,cpp}`, `CheckTransaction` and
`CheckTransactionWithoutProofVerification` (`fInBlock`) and `CheckBlock` in
`src/main.cpp`.

## Provenance of the table

`src/consensus/z23/oversize_grandfather_table.inc` is a byte-for-byte copy of the
Z23 file (Apache License 2.0, Copyright 2026 Rhett Creighton; licence text in
`src/c23/LICENSE.z23`, notice in `src/c23/NOTICE`):

| | |
|---|---|
| Z23 path | `core/consensus/src/oversize_grandfather_table.inc` |
| Z23 commit | `03a8b1d4c9ff43f47215c5d493585641cf86c3d0` (same blob at Z23 `origin/main` 76ffcc4885843f63df1f69fc8c531911ba5f1181) |
| git blob | `1deee007953f53931b5736498c13b1436d64fde3` |
| sha3-256 | `443a7deeae3a1239bce85df59e19cb374529cbaaa9895e0ebdda21777f509d35` (Z23 `core/MANIFEST.sha3`) |

`src/test/data/oversize_grandfather_txids.txt` is Z23's
`tools/data/oversize_grandfather_txids.txt` (blob
`641f7ffdc7544a868f31bf250df8bd63c9570bd0`, same commit): the committed
`height txid size` list the table was generated from.
`src/test/data/oversize_tx_478544.hex` is the raw first oversize transaction
(txid `e3eeb123...c79700`, 125,811 bytes, block 478,544), extracted from Z23's
`tests/harness/src/fixture_tx_oversize_478544.c` (blob
`c66545824fb653a2d737798ee69ff0d583c34bcf`); its double SHA-256 is the txid above.

Do not edit the `.inc`. To refresh it, copy the new Z23 file, update the blob
hashes in `contrib/devtools/check-oversize-grandfather.sh` and this page, and
run:

    contrib/devtools/check-oversize-grandfather.sh [chain-scan-file]

It checks the blobs, 413 entries, strictly ascending internal txid order, no
duplicates, each byte array equal to the reversal of its display txid, equality
with the Z23 list, and, given a file of `height size` lines from a chain scan,
equality with that scan. The gtests `oversize_grandfather_tests.*` repeat the
count, order, list equality and the predicate.

## Other size limits a historical oversize transaction meets

Checked against the real chain (all 3,321,764 height-ordered blocks scanned by the gtest
`oversize_grandfather_tests.real_chain_all_413`, which needs `ZCL_ORDERED_BLK_DIR`):

- `GENEROUS_BLOCK_SIZE_LIMIT` in `CheckBlock` (2,000,000): the largest block of the chain is
  1,999,599 bytes; every block over 102,000 bytes (2,364 of them, including the 171 that hold
  an oversize transaction) passes `CheckBlock`.
- `MAX_PROTOCOL_MESSAGE_LENGTH` (2 MiB = 2,097,152) and `MAX_SIZE` (32 MiB): a block message is at
  most 1,999,599 bytes plus its 24 byte header.
- `MAX_BLOCK_SIGOPS` (20,000), `ContextualCheckTransaction` (its 100,000 byte limit applies only
  before Sapling) and the serialization limits: the 171 blocks pass `CheckBlock`; the chain was also imported through height 700,000
  with `submitblock` and synced from 478,544 over loopback P2P without a rejection.

Not changed: `LoadExternalBlockFile` (`-loadblock`, `-reindex`) skips a record whose size is above
`MAX_BLOCK_SIZE` (200,000 bytes in `consensus/consensus.h`). 1,272 blocks of the chain
(the first at height 6,587) are larger, so those two import paths already skip them today and
this change does not alter that. Syncing over P2P and `submitblock` are unaffected.
