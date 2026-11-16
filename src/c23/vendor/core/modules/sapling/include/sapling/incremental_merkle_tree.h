/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Incremental Merkle tree for Sprout (SHA256Compress) and Sapling (Pedersen). */

#ifndef ZCL_SAPLING_INCREMENTAL_MERKLE_TREE_H
#define ZCL_SAPLING_INCREMENTAL_MERKLE_TREE_H

#include "core/uint256.h"
#include "core/serialize.h"
#include "sapling/constants.h"
#include <stdbool.h>
#include <stddef.h>

/* Hash combine functions — the parent = combine(left, right, depth) rule
 * for each pool. The Sprout SHA256Compress variant IGNORES `depth` (every
 * level uses the same compression); the Sapling Pedersen variant
 * (pedersen_combine, wired internally) KEYS on `depth` so a hash at one
 * level cannot be replayed at another. `uncommitted` is the leaf-level
 * "empty" value (all-zero for Sprout). Callers normally use the function
 * pointers stored on the tree by *_tree_init rather than these directly. */
void sha256_compress_combine(const struct uint256 *a,
                              const struct uint256 *b,
                              size_t depth,
                              struct uint256 *out);

void sha256_compress_uncommitted(struct uint256 *out);

/* Incremental Merkle Tree — runtime-parameterized depth.
 * Each node in parents[] is either present or absent (optional). */
#define MAX_TREE_DEPTH 32

struct incremental_merkle_tree {
    size_t depth;
    bool has_left;
    struct uint256 left;
    bool has_right;
    struct uint256 right;
    bool has_parent[MAX_TREE_DEPTH];
    struct uint256 parents[MAX_TREE_DEPTH];
    size_t num_parents;

    /* Function pointers for hash operations (SHA256 or Pedersen) */
    void (*combine)(const struct uint256 *a, const struct uint256 *b,
                    size_t depth, struct uint256 *out);
    void (*uncommitted)(struct uint256 *out);

    /* Runtime-only memo of incremental_tree_root(): valid iff root_cached.
     * NEVER serialized (the wire/checkpoint formats are unchanged) and
     * invalidated by every mutator (init/append/deserialize). A value copy
     * of the struct carries content + memo together, so copies stay
     * consistent; invalidation is per-instance and conservative.
     * Threading: the memo is written inside the const root() via a const
     * cast. This adds no new synchronization requirement — concurrent
     * root-vs-append on one instance was already a data race on the
     * content fields, so callers must serialize mutation vs reads exactly
     * as before. Concurrent root-vs-root writes identical bytes. */
    bool root_cached;
    struct uint256 cached_root;
};

/* Initialize an empty tree with the protocol-specific depth + hash:
 *   sprout_tree_init   — depth 29, SHA256Compress  (Sprout pool)
 *   sapling_tree_init  — depth 32, Pedersen        (Sapling pool; consensus)
 *   sapling_testing_tree_init — depth 4, Pedersen  (tests only)
 * The depth fixes the maximum leaf count (2^depth) and the root height. */
void sprout_tree_init(struct incremental_merkle_tree *t);
void sapling_tree_init(struct incremental_merkle_tree *t);
void sapling_testing_tree_init(struct incremental_merkle_tree *t);

/* Append one leaf (a note commitment) at the next free position.
 * Leaves are added strictly left-to-right and are NEVER removed or
 * reordered — the tree is append-only, so a leaf's position (its index,
 * == the value passed to sapling_compute_nf) is fixed at insertion and an
 * earlier root is always a prefix-consistent ancestor of every later root.
 * Storage is O(depth): only the frontier (left/right buffer + one optional
 * hash per level in parents[]) is kept, not every leaf. Appending past
 * 2^depth leaves is a caller error (the frontier loop has no room). */
void incremental_tree_append(struct incremental_merkle_tree *t,
                              const struct uint256 *obj);

/* Compute the current Merkle root: the frontier is folded up to `depth`,
 * substituting the precomputed empty-subtree root for every absent branch.
 * The result is exactly the `anchor` a spend proves membership against.
 * The root changes with every append; a spend's anchor must equal the root
 * at (or after) the time its note was appended.
 *
 * Memoized: the result is cached in the tree (root_cached/cached_root) and
 * recomputed only after a mutator ran. The cached bytes are always exactly
 * what a fresh fold would produce — caching changes cost, never output. */
void incremental_tree_root(const struct incremental_merkle_tree *t,
                            struct uint256 *out);

/* Number of leaves appended so far (0..2^depth). Equals the index that the
 * next incremental_tree_append will occupy. */
size_t incremental_tree_size(const struct incremental_merkle_tree *t);

/* True iff the tree is completely full (2^depth leaves). Used as the
 * subtree-complete signal by the witness append loop; not an error path. */
bool incremental_tree_is_complete(const struct incremental_merkle_tree *t);

/* Root of a fully-empty tree of this depth (all leaves = uncommitted).
 * Deterministic from depth + hash function; the Pedersen empties are
 * cached after first computation. */
void incremental_tree_empty_root(const struct incremental_merkle_tree *t,
                                  struct uint256 *out);

/* Serialization (wire-compatible with C++ boost::optional encoding) */
bool incremental_tree_serialize(const struct incremental_merkle_tree *t,
                                 struct byte_stream *s);
bool incremental_tree_deserialize(struct incremental_merkle_tree *t,
                                   struct byte_stream *s);

/* ── Flat-file checkpoint ───────────────────────────────
 *
 * Dedicated on-disk checkpoint that lives independently of the
 * SQLite-backed `node_state` table. Used by boot to skip the
 * 2.6M-block replay path when a recent checkpoint is available;
 * the rebuild path falls back to full replay if the file is
 * missing, corrupt, or its embedded root doesn't match the
 * deserialized tree.
 *
 * File format (little-endian, self-describing):
 *   4  bytes  magic      = "SPLT"
 *   4  bytes  version    = 2
 *   8  bytes  height     (last block included in the tree)
 *  32  bytes  root       (root hash at this height)
 *  32  bytes  block_hash (block hash at `height`; all-zero if the writer
 *                         did not know it — see sapling_ckpt_verify_binding)
 *   4  bytes  tree_size  (leaf count — informational)
 *   4  bytes  blob_len
 *  blob_len bytes        (incremental_tree_serialize output)
 *  32  bytes  sha3_256(everything above)
 *
 * The checkpoint is keyed by {height, block_hash, root}: the caller binds
 * it to the authoritative header chain at load time via
 * sapling_ckpt_verify_binding() before trusting it. `block_hash` may be
 * NULL on flush (written as all-zero) and `block_hash_out` may be NULL on
 * load. Both entry points return false on any I/O / format / integrity
 * failure; load also restores `*height_out`, `block_hash_out`, and the
 * tree state only on success. A prior-version file fails the version
 * check and is treated as absent (fail-closed → full replay). */
bool sapling_tree_flush_checkpoint(const struct incremental_merkle_tree *t,
                                   int64_t height,
                                   const uint8_t block_hash[32],
                                   const char *path);
bool sapling_tree_load_checkpoint(struct incremental_merkle_tree *t,
                                  int64_t *height_out,
                                  uint8_t block_hash_out[32],
                                  const char *path);

/* Fail-closed verify-then-trust decision for a loaded flat-file checkpoint.
 * Pure function (no I/O) so it is unit-testable without a live chain: given
 * the checkpoint's own {height, root, block_hash} and the authoritative
 * header-chain values at that height, it decides whether the cached frontier
 * may be trusted as a replay resume point. Anything but SAPLING_CKPT_OK means
 * the caller must discard (delete) the checkpoint and fall back to a full
 * replay — the cache is never trusted unverified. */
enum sapling_ckpt_verdict {
    SAPLING_CKPT_OK = 0,          /* trust: resume replay from height+1 */
    SAPLING_CKPT_STALE_ABOVE_TIP, /* height > current tip (reorg/rollback) */
    SAPLING_CKPT_REORG,           /* block hash at height no longer matches */
    SAPLING_CKPT_ROOT_MISMATCH,   /* root != header hashFinalSaplingRoot at H */
    SAPLING_CKPT_ROOT_UNKNOWN,    /* header binding at H is absent — cannot verify */
};

enum sapling_ckpt_verdict sapling_ckpt_verify_binding(
    int64_t ckpt_height, const struct uint256 *ckpt_root,
    const uint8_t ckpt_block_hash[32],
    int64_t tip_height,
    const uint8_t expected_block_hash[32], bool expected_hash_known,
    const struct uint256 *expected_root, bool expected_root_known);

/* Human-readable verdict label (for logs + diagnostics). Never NULL. */
const char *sapling_ckpt_verdict_str(enum sapling_ckpt_verdict v);

/* Incremental witness — tracks a path to a specific leaf.
 * filled[] stores roots of completed subtrees in the authentication path.
 * For a depth-32 tree, max fills = 32. Use 64 for safety margin. */
#define MAX_WITNESS_FILLS 64
struct incremental_witness {
    struct incremental_merkle_tree tree;
    struct uint256 filled[MAX_WITNESS_FILLS];
    size_t num_filled;
    bool has_cursor;
    struct incremental_merkle_tree cursor;
    size_t cursor_depth;
};

/* Begin tracking the authentication path for the LAST leaf that was
 * appended to `tree` at the moment of this call. The witness snapshots the
 * tree's frontier; from here, every subsequent leaf added to the global
 * tree must be replayed into THIS witness via incremental_witness_append so
 * the path stays current. The tracked leaf's position is fixed for the life
 * of the witness. */
void incremental_witness_init(struct incremental_witness *w,
                               const struct incremental_merkle_tree *tree);

/* Replay one later leaf into the witness so the authentication path keeps
 * pace with the growing tree. Call once per leaf appended to the global
 * tree AFTER the witnessed leaf. Completed sibling subtrees are folded into
 * filled[] (the auth path); a partial subtree lives in the cursor. The
 * witnessed leaf itself is never re-supplied. */
void incremental_witness_append(struct incremental_witness *w,
                                 const struct uint256 *obj);

/* Root of the tree as reconstructed FROM this witness. Invariant: this
 * equals incremental_tree_root of the underlying tree at the same leaf
 * count — i.e. the witness's auth path hashes up to the same anchor the
 * spend proof is checked against. This is what makes the witnessed path a
 * valid membership proof for the tracked leaf. */
void incremental_witness_root(const struct incremental_witness *w,
                               struct uint256 *out);

bool incremental_witness_serialize(const struct incremental_witness *w,
                                    struct byte_stream *s);
bool incremental_witness_deserialize(struct incremental_witness *w,
                                      struct byte_stream *s,
                                      size_t depth,
                                      void (*combine)(const struct uint256 *,
                                                      const struct uint256 *,
                                                      size_t, struct uint256 *),
                                      void (*uncommitted)(struct uint256 *));

/* Extract the Merkle authentication path for the witnessed leaf, in the
 * Sapling wire format the spend prover consumes. The path is the `depth`
 * sibling hashes from leaf to root; hashing the leaf up against them must
 * reproduce incremental_witness_root (the anchor). Each level carries a
 * position_bit: 0 = witnessed leaf is the LEFT child at that level (sibling
 * on the right), 1 = leaf is the RIGHT child (sibling on the left). Absent
 * siblings are filled with the empty-subtree root for that level.
 * Output: compact_size(depth) || depth × (32-byte sibling || 1-byte position_bit)
 * path_out must have space for at least 1 + depth*33 bytes.
 * Returns false (and logs) if the tree is empty (no leaf to authenticate). */
bool incremental_witness_merkle_path(const struct incremental_witness *w,
                                      uint8_t *path_out, size_t *path_len);

#endif
