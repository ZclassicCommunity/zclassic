/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY. Large-scale differential test of the batched Sapling key
 * agreement (c23/glue/zcl_c23_sapling_scan.c) against the one-at-a-time
 * librustzcash_sapling_ka_agree, over adversarial inputs, with a fixed seed:
 *
 *   epk: honest prime-order points; every small-order (torsion) point found as
 *        [r]Q, with both sign bits (x = 0 with the sign bit set included);
 *        honest + torsion (not in the prime subgroup); non-canonical y + q;
 *        random 255-bit y with a random sign (decodable or not); random bytes.
 *   ivk: random < 2^251 (real ivks), random 256-bit (mostly >= r, rejected),
 *        0, 1, 2, r-1, r, r+1, 2^251-1, 2^251, 2^252-1, 2^256-1, digit-carry
 *        patterns, and duplicates, mixed in one batch so rejected keys sit
 *        between accepted ones inside a chunk.
 *   batch: n in 1..300, table width chosen from an expected count that is
 *        n, 1 or up to 5000 (so every comb width is used with every n), and
 *        the same context reused for a second agree() call.
 *
 * usage: kat_scan [--pairs N] [--seed S] [--threads T]
 * Exit 0 when every (epk, ivk) pair matches (ok flag and, when ok, the 32
 * output bytes), 1 on any mismatch, 2 on a setup error. */
#include "kat_common.h"
#include "kat_jub.h"
#include "zcl_c23_sapling_scan.h"
#include "sapling/fr.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static uint64_t sm64(uint64_t *s)
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void rnd(uint64_t *s, uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        b[i] = (uint8_t)sm64(s);
}

#define MAX_EPK 4096
static uint8_t g_epk[MAX_EPK][32];
static const char *g_epk_kind[MAX_EPK];
static size_t g_nepk;

static void add_epk(const uint8_t e[32], const char *kind)
{
    if (g_nepk < MAX_EPK) {
        memcpy(g_epk[g_nepk], e, 32);
        g_epk_kind[g_nepk++] = kind;
    }
}

#define MAX_EDGE 32
static uint8_t g_edge[MAX_EDGE][32];
static size_t g_nedge;

static void edge_add(const uint8_t s[32])
{
    memcpy(g_edge[g_nedge++], s, 32);
}

static void build_edges(void)
{
    uint8_t s[32];
    memset(s, 0, 32); edge_add(s);                       /* 0 */
    s[0] = 1; edge_add(s);                               /* 1 */
    s[0] = 2; edge_add(s);                               /* 2 */
    memcpy(s, KAT_R_LE, 32); s[0] -= 1; edge_add(s);     /* r-1 (r is odd) */
    memcpy(s, KAT_R_LE, 32); edge_add(s);                /* r */
    s[0] += 1; edge_add(s);                              /* r+1 */
    memset(s, 0xff, 32); s[31] = 0x07; edge_add(s);      /* 2^251-1 */
    memset(s, 0, 32); s[31] = 0x08; edge_add(s);         /* 2^251 */
    memset(s, 0xff, 32); s[31] = 0x0f; edge_add(s);      /* 2^252-1 */
    memset(s, 0xff, 32); edge_add(s);                    /* 2^256-1 */
    memset(s, 0x88, 32); s[31] = 0x08; edge_add(s);      /* all digits 8 */
    memset(s, 0x77, 32); edge_add(s);
    memset(s, 0x99, 32); s[31] = 0x09; edge_add(s);
    memset(s, 0xf8, 32); s[31] = 0x08; edge_add(s);      /* -8 digits, carries */
}

static int build_epks(uint64_t seed)
{
    uint64_t s = seed ^ 0x5eedULL;
    uint8_t e[32], k[32], h[64][32];
    /* honest points [k]G, k < 2^251 */
    for (int i = 0; i < 64; i++) {
        rnd(&s, k, 32);
        k[31] &= 0x07;
        kat_gen_mul(KAT_GEN_SPEND_AUTH, k, h[i]);
        add_epk(h[i], "honest");
    }
    /* torsion: [r]Q for random curve points Q */
    uint8_t tors[16][32];
    size_t nt = 0;
    for (int tries = 0; tries < 4000 && nt < 8; tries++) {
        rnd(&s, e, 32);
        e[31] &= 0x7f;
        struct jub_point q, t;
        if (!jub_from_bytes(&q, e))
            continue;
        jub_scalar_mul(&t, &q, KAT_R_LE);
        uint8_t te[32];
        jub_to_bytes(te, &t);
        bool seen = false;
        for (size_t j = 0; j < nt; j++)
            seen = seen || memcmp(tors[j], te, 32) == 0;
        if (!seen)
            memcpy(tors[nt++], te, 32);
    }
    if (nt != 8) {
        fprintf(stderr, "kat_scan: found %zu distinct torsion points, want 8\n", nt);
        return 2;
    }
    for (size_t j = 0; j < nt; j++) {
        add_epk(tors[j], "torsion");
        memcpy(e, tors[j], 32);
        e[31] ^= 0x80;                       /* other sign bit */
        add_epk(e, "torsion-signflip");
        uint8_t nc[32];
        if (kat_enc_y_plus_q(tors[j], nc))
            add_epk(nc, "torsion-noncanon");
        for (int i = 0; i < 16; i++) {
            if (kat_point_add(h[i], tors[j], e))
                add_epk(e, "honest+torsion");
        }
    }
    for (int i = 0; i < 64; i++) {
        uint8_t nc[32];
        if (kat_enc_y_plus_q(h[i], nc))
            add_epk(nc, "noncanon");
    }
    for (int i = 0; i < 512; i++) {
        rnd(&s, e, 32);
        if (i & 1)
            e[31] &= 0x7f, e[31] |= (uint8_t)((i >> 1) & 1) << 7;
        add_epk(e, (i & 1) ? "random-y" : "random-bytes");
    }
    return 0;
}

static atomic_ullong g_pairs, g_ok_pairs, g_mism, g_items;
static unsigned long long g_target;
static uint64_t g_seed;

static void gen_ivk(uint64_t *s, uint8_t out[32], uint8_t (*prev)[32], size_t nprev)
{
    unsigned c = (unsigned)(sm64(s) % 16);
    if (c < 9) {                         /* real ivk shape */
        rnd(s, out, 32);
        out[31] &= 0x07;
    } else if (c < 11) {
        rnd(s, out, 32);                 /* mostly >= r */
    } else if (c < 13 && nprev) {
        memcpy(out, prev[sm64(s) % nprev], 32); /* duplicate */
    } else {
        memcpy(out, g_edge[sm64(s) % g_nedge], 32);
    }
}

static void *worker(void *arg)
{
    uint64_t s = g_seed * 1000003ULL + (uint64_t)(uintptr_t)arg;
    enum { NMAX = 300 };
    static _Thread_local uint8_t ivk[NMAX][32], dh[NMAX][32], ref[NMAX][32];
    static _Thread_local uint8_t ok[NMAX], rok[NMAX];
    while (atomic_load(&g_pairs) < g_target) {
        const uint8_t *epk;
        uint8_t fresh[32];
        const char *kind;
        if (sm64(&s) % 4 == 0) {          /* a fresh honest epk */
            uint8_t k[32];
            rnd(&s, k, 32);
            k[31] &= 0x07;
            kat_gen_mul(KAT_GEN_SPEND_AUTH, k, fresh);
            epk = fresh;
            kind = "fresh-honest";
        } else {
            size_t i = (size_t)(sm64(&s) % g_nepk);
            epk = g_epk[i];
            kind = g_epk_kind[i];
        }
        size_t n;
        uint64_t r = sm64(&s) % 10;
        n = r < 4 ? 1 + (size_t)(sm64(&s) % 8) : r < 8 ? 1 + (size_t)(sm64(&s) % 70) : 1 + (size_t)(sm64(&s) % NMAX);
        for (size_t i = 0; i < n; i++)
            gen_ivk(&s, ivk[i], ivk, i);
        size_t expected;
        r = sm64(&s) % 3;
        expected = r == 0 ? n : r == 1 ? 1 + (size_t)(sm64(&s) % 8) : 1 + (size_t)(sm64(&s) % 5000);

        for (size_t i = 0; i < n; i++)
            rok[i] = librustzcash_sapling_ka_agree(epk, ivk[i], ref[i]) ? 1 : 0;

        zcl_c23_sapling_scan_ctx *ctx = zcl_c23_sapling_scan_begin(epk, expected);
        if (!ctx) {
            fprintf(stderr, "kat_scan: fast path unavailable (NULL context)\n");
            atomic_fetch_add(&g_mism, 1);
            return NULL;
        }
        /* two calls on the same context: a prefix, then the rest */
        size_t cut = (size_t)(sm64(&s) % (n + 1));
        memset(ok, 7, n);
        zcl_c23_sapling_scan_agree(ctx, &ivk[0][0], cut, &dh[0][0], ok);
        zcl_c23_sapling_scan_agree(ctx, &ivk[cut][0], n - cut, &dh[cut][0], ok + cut);
        zcl_c23_sapling_scan_end(ctx);

        unsigned long long okc = 0;
        for (size_t i = 0; i < n; i++) {
            bool bad = (ok[i] != 0) != (rok[i] != 0) || (ok[i] > 1) ||
                       (rok[i] && memcmp(dh[i], ref[i], 32) != 0);
            okc += rok[i];
            if (bad) {
                if (atomic_fetch_add(&g_mism, 1) < 20) {
                    char he[65], hi[65];
                    for (int b = 0; b < 32; b++) {
                        sprintf(he + 2 * b, "%02x", epk[b]);
                        sprintf(hi + 2 * b, "%02x", ivk[i][b]);
                    }
                    fprintf(stderr, "MISMATCH kind=%s epk=%s ivk=%s n=%zu expected=%zu ref_ok=%d ok=%d\n",
                            kind, he, hi, n, expected, rok[i], ok[i]);
                }
            }
        }
        atomic_fetch_add(&g_pairs, n);
        atomic_fetch_add(&g_ok_pairs, okc);
        atomic_fetch_add(&g_items, 1);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    unsigned long long pairs = 200000;
    unsigned long long seed = 20261117;
    int threads = 1;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--pairs"))
            pairs = strtoull(argv[i + 1], NULL, 10);
        else if (!strcmp(argv[i], "--seed"))
            seed = strtoull(argv[i + 1], NULL, 10);
        else if (!strcmp(argv[i], "--threads"))
            threads = atoi(argv[i + 1]);
        else {
            fprintf(stderr, "usage: kat_scan [--pairs N] [--seed S] [--threads T]\n");
            return 2;
        }
    }
    if (threads < 1 || threads > 256)
        return 2;
    g_target = pairs;
    g_seed = seed;
    kat_jub_init();
    build_edges();
    if (build_epks(seed) != 0)
        return 2;
    size_t counts[8] = {0};
    const char *names[] = {"honest", "torsion", "torsion-signflip", "torsion-noncanon",
                           "honest+torsion", "noncanon", "random-y", "random-bytes"};
    for (size_t i = 0; i < g_nepk; i++)
        for (int k = 0; k < 8; k++)
            if (!strcmp(g_epk_kind[i], names[k]))
                counts[k]++;
    printf("epk pool %zu:", g_nepk);
    for (int k = 0; k < 8; k++)
        printf(" %s=%zu", names[k], counts[k]);
    printf("\n");

    pthread_t th[256];
    for (int i = 0; i < threads; i++)
        if (pthread_create(&th[i], NULL, worker, (void *)(uintptr_t)i) != 0)
            return 2;
    for (int i = 0; i < threads; i++)
        pthread_join(th[i], NULL);
    unsigned long long m = atomic_load(&g_mism);
    printf("RESULT kat_scan seed=%llu threads=%d outputs=%llu pairs=%llu accepted_pairs=%llu mismatches=%llu\n",
           seed, threads, (unsigned long long)atomic_load(&g_items), (unsigned long long)atomic_load(&g_pairs),
           (unsigned long long)atomic_load(&g_ok_pairs), m);
    return m == 0 ? 0 : 1;
}
