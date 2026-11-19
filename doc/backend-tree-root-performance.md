# C23 shielded-tree root reuse (candidate)

The backend repeatedly computes the same Sprout/Sapling tree root when connecting
blocks without new shielded commitments. Each full Sapling calculation traverses
32 levels using the existing Pedersen hash implementation. More download peers
or script-verification threads do not remove this repeated serial work.

`src/zcash/tree_root.c` adapts the full-root fold and memoization from Z23's
`core/modules/sapling/src/incremental_merkle_tree.c` (in the Z23 source tree, not this repository), function <!-- doc-path-ok -->
`incremental_tree_root`, source baseline
`cf51aaa573b1b7d2457ba85f180684da829cf84c`. Attribution and Apache-2.0 license are
retained. This is C23-compatible C, also compiled in C11 mode for existing Windows
release toolchains. It does not require a runtime library or compiler upgrade.

The C++ adapter supplies the existing SHA256Compress/Pedersen hash operations and
empty roots. The original C++ fold remains in use for witness paths and serves as
an independent comparison in tests. No consensus parameter, validity predicate,
proof check, serialization, or on-disk format is changed.

Unlike Z23's per-object mutable memo, this integration stores one bounded cache
per thread and template specialization. Its key compares the complete frontier:
depth, occupied leaves, parent count, occupancy and every occupied parent hash.
It does not use a collision-prone short fingerprint, height, or caller-provided
validity flag. Copies, deserialization and reorgs are ordinary cache misses when
their contents differ. Concurrent const readers cannot race over cache writes.

The cache contains only public commitment-tree data. A hit performs zero hash
operations; a miss performs the original full fold. Memory is bounded to roughly
2.3 KiB per instantiated tree type per calling thread, plus a temporary frontier.

Validation includes exact root/wire vectors, comparison to the original witness
root calculation after appends, copies and deserialization, interleaved different
trees, concurrent readers, and standalone C cache-key mutation/bounds tests.
The C tests run in C23 mode with address/undefined-behavior sanitizers on Linux,
and in C11 mode with the Windows release compiler.

This is not yet a released backend. Full-node builds and root parity tests must
pass before landing. A full-chain sync speedup has not yet been measured; the
amount saved depends on how often unchanged trees are revisited. MMB snapshot
activation is unrelated and remains unchanged.

## Wallet scanning

Transactions without Sapling outputs now return an empty discovery result before
locking the key store or copying its incoming viewing keys. Transactions without
Sprout JoinSplits similarly avoid unnecessary scan setup. Spend/nullifier and
transparent ownership checks still run through their original caller paths.

The apply path uses references to discovery results instead of copying their
maps. Write ordering, serialization and the crash-recovery cursor are unchanged.
The defensive transaction copy during rescan persistence is retained: the legacy
serializer mutates its metadata map, so removing that copy requires a separate
serializer correction with byte-parity and exception-safety tests.

The existing parallel Sapling rescan implementation is retained; it is not a new
feature of this change. Wallet tests, including scan parity, viewing-key discovery,
reorg and witness coverage, are included in the native validation gate. The Rust
cryptographic dependency is retained; avoiding unnecessary calls is separate from
replacing a cryptographic implementation.
