/* Check/dump program for the single-leaf tree self-test shim.
 *
 *   tree_shim_check <merkle_commitments_sapling.json> <merkle_roots_sapling.json>
 *                   <merkle_roots_empty_sapling.json>
 *
 * 1. VECTORS (zclassicd src/test/data): the empty-subtree roots E_0..E_31 that
 *    the shim computes equal merkle_roots_empty_sapling.json, and the depth-4
 *    fold of commitment[0] (the formula the shim uses at depth 32) equals
 *    merkle_roots_sapling.json[0]. Byte order: JSON roots are raw byte order,
 *    JSON commitments are uint256S big-endian text (reversed to bytes).
 * 2. DUMP: for 4 leaves, prints depth-32 witness root and the 1057-byte compact
 *    path obtained through sapling_tree_init/incremental_tree_append/
 *    incremental_witness_init/_root/_merkle_path. Link this program once with
 *    the shim and once with Z23's real incremental_merkle_tree.c and diff the
 *    two outputs (tools/tree-shim-diff.sh).
 * 3. POISON (shim only; skipped with -DREAL_TREE): a second append must make
 *    merkle_path fail. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sapling/incremental_merkle_tree.h"
#include "sapling/pedersen_hash.h"

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *b = NULL;
    size_t cap = 0, len = 0;
    for (;;) {
        if (len + 4096 + 1 > cap) {
            char *nb = realloc(b, cap = cap ? cap * 2 : 8192);
            if (!nb) {
                free(b);
                fclose(f);
                return NULL;
            }
            b = nb;
        }
        size_t r = fread(b + len, 1, 4096, f);
        len += r;
        if (r == 0)
            break;
    }
    b[len] = 0;
    fclose(f);
    return b;
}

/* i-th 64-hex-digit quoted string in a flat JSON array; 0 on success. */
static int nth_hex(const char *json, size_t n, uint8_t out[32])
{
    const char *p = json;
    for (;;) {
        p = strchr(p, '"');
        if (!p)
            return -1;
        const char *q = strchr(p + 1, '"');
        if (!q)
            return -1;
        if ((size_t)(q - p - 1) == 64) {
            if (n-- == 0) {
                for (int i = 0; i < 32; i++) {
                    unsigned v;
                    if (sscanf(p + 1 + 2 * i, "%2x", &v) != 1)
                        return -1;
                    out[i] = (uint8_t)v;
                }
                return 0;
            }
        }
        p = q + 1;
    }
}

static void hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
}

int main(int argc, char **argv)
{
    int bad = 0;
    if (argc == 4) {
        char *cm = slurp(argv[1]), *rt = slurp(argv[2]), *em = slurp(argv[3]);
        if (!cm || !rt || !em) {
            fprintf(stderr, "cannot read vector files\n");
            return 2;
        }
        uint8_t e[32][32], want[32], leaf[32], raw[32];
        sapling_uncommitted(e[0]);
        for (size_t d = 0; d + 1 < 32; d++)
            pedersen_merkle_hash(d, e[d], e[d], e[d + 1]);
        for (size_t d = 0; d < 32; d++) {
            if (nth_hex(em, d, want) || memcmp(want, e[d], 32)) {
                printf("MISMATCH empty root depth %zu\n", d);
                bad = 1;
            }
        }
        if (nth_hex(cm, 0, raw) || nth_hex(rt, 0, want)) {
            fprintf(stderr, "vector parse\n");
            return 2;
        }
        for (int i = 0; i < 32; i++)
            leaf[i] = raw[31 - i]; /* uint256S is big-endian text */
        uint8_t cur[32], nxt[32];
        memcpy(cur, leaf, 32);
        for (size_t d = 0; d < 4; d++) { /* depth-4 testing tree */
            pedersen_merkle_hash(d, cur, e[d], nxt);
            memcpy(cur, nxt, 32);
        }
        if (memcmp(cur, want, 32)) {
            printf("MISMATCH depth-4 single-leaf root vs merkle_roots_sapling.json[0]\n");
            bad = 1;
        }
        printf("vectors: empty roots E_0..E_31 and depth-4 position-0 root %s\n",
               bad ? "FAIL" : "match zclassicd");
        free(cm);
        free(rt);
        free(em);
    }

    static const uint8_t seed[4][32] = {
        {1}, {2, 3}, {0x55, 0x6f, 0x3a, 0xf9, 0x42}, {0xde, 0xad, 0xbe, 0xef}};
    for (int k = 0; k < 4; k++) {
        struct incremental_merkle_tree t;
        struct incremental_witness w;
        struct uint256 leaf, root;
        uint8_t path[1100];
        size_t plen = 0;
        memcpy(leaf.data, seed[k], 32);
        sapling_tree_init(&t);
        incremental_tree_append(&t, &leaf);
        incremental_witness_init(&w, &t);
        incremental_witness_root(&w, &root);
        bool ok = incremental_witness_merkle_path(&w, path, &plen);
        printf("leaf%d ok=%d len=%zu root=", k, ok, plen);
        hex(root.data, 32);
        printf(" path=");
        hex(path, ok ? plen : 0);
        printf("\n");
        if (!ok || plen != 1057)
            bad = 1;
    }
#ifndef REAL_TREE
    {
        struct incremental_merkle_tree t;
        struct incremental_witness w;
        struct uint256 leaf = {{9}}, root;
        uint8_t path[1100];
        size_t plen = 0;
        sapling_tree_init(&t);
        incremental_tree_append(&t, &leaf);
        incremental_tree_append(&t, &leaf);
        incremental_witness_init(&w, &t);
        incremental_witness_root(&w, &root);
        bool ok = incremental_witness_merkle_path(&w, path, &plen);
        printf("poison: second append => merkle_path %s\n", ok ? "SUCCEEDED (BAD)" : "refused");
        if (ok)
            bad = 1;
    }
#endif
    return bad;
}
