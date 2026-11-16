/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "zcash/tree_root.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned calls;
/* Deliberately asymmetric test hash, not a consensus hash. */
static void combine(const uint8_t *a, const uint8_t *b, size_t d, uint8_t *out)
{
    ++calls;
    for (size_t i = 0; i < 32; ++i)
        out[i] = (uint8_t)(a[i] * 17u + b[(i + 1) % 32] * 3u + d);
}
static void empty(size_t d, uint8_t *out)
{
    for (size_t i = 0; i < 32; ++i) out[i] = (uint8_t)(d * 7 + i);
}
static void check(struct zcl_tree_frontier *tree, struct zcl_tree_root_cache *warm)
{
    struct zcl_tree_root_cache cold = {0};
    uint8_t actual[32], expected[32];
    assert(zcl_tree_root(tree, &cold, combine, empty, expected));
    assert(zcl_tree_root(tree, warm, combine, empty, actual));
    assert(memcmp(expected, actual, 32) == 0);
    calls = 0;
    assert(zcl_tree_root(tree, warm, combine, empty, actual));
    assert(calls == 0);
    assert(memcmp(expected, actual, 32) == 0);
}
int main(void)
{
    struct zcl_tree_frontier tree = {0};
    struct zcl_tree_root_cache cache = {0};
    uint8_t out[32];
    tree.depth = 32;
    check(&tree, &cache);
    tree.has_left = 1; check(&tree, &cache);
    tree.has_right = 1; check(&tree, &cache);
    for (size_t i = 0; i < 32; ++i) {
        ++tree.left[i]; check(&tree, &cache);
        ++tree.right[i]; check(&tree, &cache);
    }
    for (size_t p = 0; p < 31; ++p) {
        tree.parents_len = p + 1; check(&tree, &cache);
        tree.has_parent[p] = 1; check(&tree, &cache);
        for (size_t i = 0; i < 32; ++i) {
            ++tree.parents[p][i]; check(&tree, &cache);
        }
        tree.has_parent[p] = 0; check(&tree, &cache);
    }
    tree.depth = 64; check(&tree, &cache);
    tree.parents_len = 63; check(&tree, &cache);
    tree.depth = 0;
    assert(!zcl_tree_root(&tree, &cache, combine, empty, out));
    tree.depth = 65;
    assert(!zcl_tree_root(&tree, &cache, combine, empty, out));
    tree.depth = 32;
    assert(!zcl_tree_root(&tree, &cache, combine, empty, out));
    assert(!zcl_tree_root(NULL, &cache, combine, empty, out));
    puts("PASS: exact frontier cache keys, warm hits, bounds and null input");
    return 0;
}
