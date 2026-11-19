/* zclassicd-owned. The five incremental-tree symbols that vendor
 * sapling_prover_native.c needs for its one-leaf proving self-test, WITHOUT
 * vendoring incremental_merkle_tree.c (which drags sha3, positioned_file and
 * private_file). Semantics are exactly Z23's for a depth-32 Pedersen tree
 * holding at most ONE leaf at position 0:
 *   E_0 = sapling_uncommitted(); E_{d+1} = pedersen_merkle_hash(d, E_d, E_d)
 *   root = fold over d=0..31 of cur = pedersen_merkle_hash(d, cur, E_d)
 *   path = 32 x (E_d || 0x00), prefixed by the length byte 32 (1057 bytes).
 * A second append poisons the tree (depth 0): root is all-zero and
 * merkle_path returns false, so the self-test fails closed. Differential
 * test against the real Z23 implementation: see README.md (tests section). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sapling/incremental_merkle_tree.h"
#include "sapling/pedersen_hash.h"

#define ZT_DEPTH SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH

static void zt_combine(const struct uint256 *a, const struct uint256 *b,
                       size_t depth, struct uint256 *out)
{
    pedersen_merkle_hash(depth, a->data, b->data, out->data);
}

static void zt_uncommitted(struct uint256 *out)
{
    sapling_uncommitted(out->data);
}

static void zt_empty_roots(struct uint256 e[ZT_DEPTH])
{
    zt_uncommitted(&e[0]);
    for (size_t d = 0; d + 1 < ZT_DEPTH; d++)
        zt_combine(&e[d], &e[d], d, &e[d + 1]);
}

void sapling_tree_init(struct incremental_merkle_tree *t)
{
    if (!t)
        return;
    memset(t, 0, sizeof(*t));
    t->depth = ZT_DEPTH;
    t->combine = zt_combine;
    t->uncommitted = zt_uncommitted;
}

void incremental_tree_append(struct incremental_merkle_tree *t, const struct uint256 *obj)
{
    if (!t || !obj)
        return;
    if (t->depth == ZT_DEPTH && !t->has_left && !t->has_right) {
        t->left = *obj;
        t->has_left = true;
        return;
    }
    t->depth = 0; /* poisoned: more than one leaf is outside this shim's contract */
}

void incremental_witness_init(struct incremental_witness *w,
                              const struct incremental_merkle_tree *t)
{
    if (!w)
        return;
    memset(w, 0, sizeof(*w));
    if (t)
        w->tree = *t;
    else
        w->tree.depth = 0;
}

static bool zt_single_leaf(const struct incremental_witness *w)
{
    const struct incremental_merkle_tree *t = &w->tree;
    return t->depth == ZT_DEPTH && t->has_left && !t->has_right &&
           t->num_parents == 0 && w->num_filled == 0 && !w->has_cursor;
}

void incremental_witness_root(const struct incremental_witness *w, struct uint256 *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!w || !zt_single_leaf(w))
        return;
    struct uint256 e[ZT_DEPTH], cur = w->tree.left, next;
    zt_empty_roots(e);
    for (size_t d = 0; d < ZT_DEPTH; d++) {
        zt_combine(&cur, &e[d], d, &next);
        cur = next;
    }
    *out = cur;
}

bool incremental_witness_merkle_path(const struct incremental_witness *w, uint8_t *path_out,
                                     size_t *path_len)
{
    if (!w || !path_out || !path_len || !zt_single_leaf(w))
        return false;
    struct uint256 e[ZT_DEPTH];
    zt_empty_roots(e);
    size_t off = 0;
    path_out[off++] = (uint8_t)ZT_DEPTH;
    for (size_t d = 0; d < ZT_DEPTH; d++) {
        memcpy(path_out + off, e[d].data, 32);
        off += 32;
        path_out[off++] = 0;
    }
    *path_len = off;
    return true;
}
