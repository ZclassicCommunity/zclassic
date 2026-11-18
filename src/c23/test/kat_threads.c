/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). kat_threads: concurrency check of the librustzcash
 * ABI, meant to run under -fsanitize=thread as well as plainly.
 *
 *   kat_threads --dir <c23_golden> --params <dir> [--threads 16] [--rounds 2]
 *
 * Phase 1 (cold): before init, N threads call merkle_hash and ka_agree
 *   concurrently (these need no parameters in Rust); this exercises the lazy
 *   warm-up of the C23 constants from many threads at once.
 * Phase 2: after librustzcash_init_zksnark_params, N threads run
 *   check_spend, check_output (each with its own context) and merkle_hash over
 *   golden records, every thread starting at a different offset, and compare
 *   every verdict and output with the golden value. */
#include "kat_common.h"
#include "zcl_c23_sapling_scan.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* K_KB: the same ka_agree records through the batched scan core */
enum kind { K_SPEND, K_OUTPUT, K_MERKLE, K_KA, K_KB };
typedef struct {
    enum kind kind;
    unsigned char b[512];
    uint64_t depth;
    bool want;
    unsigned char out[32];
    unsigned long lineno;
} Item;

static Item *g_items;
static size_t g_n, g_cap;
static atomic_ulong g_bad, g_calls;
static int g_rounds = 2;

static Item *push(void)
{
    if (g_n == g_cap) {
        g_cap = g_cap ? 2 * g_cap : 256;
        Item *ni = realloc(g_items, g_cap * sizeof(Item));
        if (!ni) {
            fprintf(stderr, "out of memory\n");
            exit(2);
        }
        g_items = ni;
    }
    memset(&g_items[g_n], 0, sizeof(Item));
    return &g_items[g_n++];
}

/* Loads up to max_t records with verdict T and max_f with F (or OK). */
static void load(const char *dir, const char *file, enum kind kind, int vcol, size_t max_t, size_t max_f)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, file);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    kat_cur_file = file;
    char *line = NULL;
    size_t cap = 0, nt = 0, nf = 0;
    unsigned long ln = 0;
    while (kat_read_line(f, &line, &cap)) {
        ln++;
        if (line[0] != 'C')
            continue;
        KatToks k;
        kat_tokenize(line, ln, &k);
        bool t = kat_is(&k, vcol, "T") || kat_is(&k, vcol, "OK");
        bool fl = kat_is(&k, vcol, "F");
        if ((!t && !fl) || (t && nt >= max_t) || (fl && nf >= max_f) ||
            (kind == K_MERKLE && kat_u64(&k, 3) >= 63)) {
            kat_toks_free(&k);
            continue;
        }
        Item *it = push();
        it->kind = kind;
        it->want = t;
        it->lineno = ln;
        switch (kind) {
        case K_SPEND:
            kat_hexn(&k, 3, it->b, 32);
            kat_hexn(&k, 4, it->b + 32, 32);
            kat_hexn(&k, 5, it->b + 64, 32);
            kat_hexn(&k, 6, it->b + 96, 32);
            kat_hexn(&k, 7, it->b + 128, 192);
            kat_hexn(&k, 8, it->b + 320, 64);
            kat_hexn(&k, 9, it->b + 384, 32);
            break;
        case K_OUTPUT:
            kat_hexn(&k, 3, it->b, 32);
            kat_hexn(&k, 4, it->b + 32, 32);
            kat_hexn(&k, 5, it->b + 64, 32);
            kat_hexn(&k, 6, it->b + 96, 192);
            break;
        case K_MERKLE:
            it->depth = kat_u64(&k, 3);
            kat_hexn(&k, 4, it->b, 32);
            kat_hexn(&k, 5, it->b + 32, 32);
            kat_hexn(&k, 7, it->out, 32);
            break;
        case K_KA:
        case K_KB:
            kat_hexn(&k, 3, it->b, 32);
            kat_hexn(&k, 4, it->b + 32, 32);
            if (t)
                kat_hexn(&k, 6, it->out, 32);
            break;
        }
        if (t)
            nt++;
        else
            nf++;
        kat_toks_free(&k);
    }
    free(line);
    fclose(f);
}

static bool run_item(const Item *it)
{
    unsigned char o[32];
    switch (it->kind) {
    case K_SPEND: {
        void *ctx = librustzcash_sapling_verification_ctx_init();
        bool ok = librustzcash_sapling_check_spend(ctx, it->b, it->b + 32, it->b + 64, it->b + 96, it->b + 128,
                                                   it->b + 320, it->b + 384);
        librustzcash_sapling_verification_ctx_free(ctx);
        return ok == it->want;
    }
    case K_OUTPUT: {
        void *ctx = librustzcash_sapling_verification_ctx_init();
        bool ok = librustzcash_sapling_check_output(ctx, it->b, it->b + 32, it->b + 64, it->b + 96);
        librustzcash_sapling_verification_ctx_free(ctx);
        return ok == it->want;
    }
    case K_MERKLE:
        librustzcash_merkle_hash((size_t)it->depth, it->b, it->b + 32, o);
        return memcmp(o, it->out, 32) == 0;
    case K_KA: {
        bool ok = librustzcash_sapling_ka_agree(it->b, it->b + 32, o);
        return ok == it->want && (!ok || memcmp(o, it->out, 32) == 0);
    }
    case K_KB: {
        /* batched core; table width varies with the record so every comb
         * shape is exercised, from many threads at once */
        unsigned char dh[32] = {0}, okb = 7;
        zcl_c23_sapling_scan_ctx *ctx = zcl_c23_sapling_scan_begin(it->b, 1 + (size_t)(it->lineno % 70));
        if (!ctx)
            return false;
        zcl_c23_sapling_scan_agree(ctx, it->b + 32, 1, dh, &okb);
        zcl_c23_sapling_scan_end(ctx);
        return (okb != 0) == it->want && (!okb || memcmp(dh, it->out, 32) == 0);
    }
    }
    return false;
}

struct targ {
    size_t start, from, to;
    int id;
};
static void *worker(void *p)
{
    struct targ *a = p;
    size_t span = a->to - a->from;
    for (int r = 0; r < g_rounds; r++)
        for (size_t j = 0; j < span; j++) {
            const Item *it = &g_items[a->from + (a->start + j) % span];
            atomic_fetch_add(&g_calls, 1);
            if (!run_item(it)) {
                unsigned long b = atomic_fetch_add(&g_bad, 1);
                if (b < 20)
                    fprintf(stderr, "thread %d: MISMATCH kind=%d golden line %lu\n", a->id, (int)it->kind,
                            it->lineno);
            }
        }
    return NULL;
}

static int run_threads(int nthreads, size_t from, size_t to, const char *phase)
{
    pthread_t th[64];
    struct targ ta[64];
    unsigned long bad0 = atomic_load(&g_bad), calls0 = atomic_load(&g_calls);
    double t0 = kat_now();
    for (int i = 0; i < nthreads; i++) {
        ta[i].start = (size_t)i * 7919u;
        ta[i].from = from;
        ta[i].to = to;
        ta[i].id = i;
        if (pthread_create(&th[i], NULL, worker, &ta[i]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            exit(2);
        }
    }
    for (int i = 0; i < nthreads; i++)
        pthread_join(th[i], NULL);
    unsigned long bad = atomic_load(&g_bad) - bad0, calls = atomic_load(&g_calls) - calls0;
    printf("%s: threads=%d items=%zu calls=%lu mismatches=%lu time=%.1fs\n", phase, nthreads, to - from, calls, bad,
           kat_now() - t0);
    fflush(stdout);
    return bad ? 1 : 0;
}

int main(int argc, char **argv)
{
    const char *dir = NULL, *params = NULL;
    int nthreads = 16;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dir") && i + 1 < argc)
            dir = argv[++i];
        else if (!strcmp(argv[i], "--params") && i + 1 < argc)
            params = argv[++i];
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc)
            nthreads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rounds") && i + 1 < argc)
            g_rounds = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: kat_threads --dir <c23_golden> --params <dir> [--threads N] [--rounds R]\n");
            return 2;
        }
    }
    if (!dir || !params || nthreads < 1 || nthreads > 64 || g_rounds < 1) {
        fprintf(stderr, "usage: kat_threads --dir <c23_golden> --params <dir> [--threads N] [--rounds R]\n");
        return 2;
    }
    /* phase 1 items: merkle + ka_agree, before init */
    load(dir, "merkle_hash.golden", K_MERKLE, 6, 300, 0);
    load(dir, "sapling_ka_agree.golden", K_KA, 5, 60, 40);
    load(dir, "sapling_ka_agree.golden", K_KB, 5, 120, 80);
    size_t cold_end = g_n;
    int rc = run_threads(nthreads, 0, cold_end, "cold (before init): merkle_hash+ka_agree");

    kat_init_canonical(params);
    load(dir, "sapling_check_spend.golden", K_SPEND, 10, 64, 60);
    load(dir, "sapling_check_output.golden", K_OUTPUT, 7, 64, 40);
    rc |= run_threads(nthreads, 0, g_n, "after init: check_spend+check_output+merkle_hash+ka_agree");
    printf("RESULT threads %s\n", rc ? "FAIL" : "PASS");
    free(g_items);
    return rc;
}
