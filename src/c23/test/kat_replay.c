/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). kat_replay: replays EVERY record of the Rust golden
 * corpus (src/test/data/c23_golden, FORMAT.md) through the C23 librustzcash
 * shim. Written independently of src/test/rust_oracle/golden_replay.c, and
 * portable (Windows re-executes itself for ABORT records instead of fork).
 *
 *   kat_replay --dir <c23_golden> --params <dir> [--prove] [--file <name>]
 *              [--emit <cases> --emit-expect <expect>] [--no-batch] [--max-print N]
 *
 * Deterministic records: verdict and every output byte must match.
 * ABORT records: the call runs in a child process that must die from abort().
 * Randomized records (FORMAT.md "Nondeterministic functions"):
 *   generate_r   C23 output < r; 2000 outputs pairwise distinct.
 *   spend_sig    verdict; a C23 signature verifies under the Rust-derived rk
 *                with Rust's cofactored RedJubjub equation (and so does Rust's).
 *   spend_proof / output_proof / sprout_prove / prove bundles
 *                verdict; with --prove the C23 prover is fed the recorded
 *                inputs and its proof must be accepted by the C23 verifier with
 *                Rust's verdict; --emit writes those C23-made descriptions as a
 *                kat_cases file so the Rust verifier can check them too.
 *                Rust-made proofs are always re-verified by the C23 verifier.
 * The zcl_c23_batch_* extra API is also checked against every single
 * check_spend / check_output record (verdict-exact claim), unless --no-batch.
 *
 * Exit: 0 all match, 1 mismatches, 2 usage/I-O/corrupt input. */
#include "kat_common.h"
#include "kat_jub.h"

#include <stdlib.h>
#include <string.h>

#if defined(KAT_C23_HEADER)
#define KAT_HAVE_BATCH 1
#endif

static const char *g_dir, *g_params, *g_only;
static bool g_prove, g_batch = true;
static FILE *g_emit, *g_emit_expect;
static unsigned long g_emit_id;
static unsigned long g_records, g_mismatch, g_skipped, g_batch_checked, g_batch_mismatch;
static unsigned long g_max_print = 200;
static FILE *g_mlog;

/* mismatch: function, record, what, rust (golden) value, c23 value */
static void mism(const KatToks *k, const char *what, const char *rust, const char *c23)
{
    g_mismatch++;
    const char *id = k->n > 1 ? k->t[1] : "?";
    const char *label = k->n > 2 ? k->t[2] : "?";
    if (g_mismatch <= g_max_print)
        fprintf(stdout, "MISMATCH %s:%lu id=%s label=%s %s rust=%s c23=%s\n", kat_cur_file, k->lineno, id, label, what,
                rust ? rust : "?", c23 ? c23 : "?");
    if (g_mlog)
        fprintf(g_mlog, "%s\t%lu\t%s\t%s\t%s\t%s\t%s\n", kat_cur_file, k->lineno, id, label, what, rust ? rust : "?",
                c23 ? c23 : "?");
}

static void cmp_hex(const KatToks *k, int col, const unsigned char *b, size_t n, const char *what)
{
    if (kat_eqhex(k, col, b, n))
        return;
    char *h = kat_xmalloc(2 * n + 1);
    kat_tohex(h, b, n);
    mism(k, what, col < k->n ? k->t[col] : "?", h);
    free(h);
}

static bool cmp_verdict(const KatToks *k, int col, bool got, const char *what)
{
    if (kat_is(k, col, kat_tf(got)))
        return true;
    mism(k, what, col < k->n ? k->t[col] : "?", kat_tf(got));
    return false;
}

/* ---------------------------------------------------------------- ABORT */

typedef void (*rec_fn)(const KatToks *k, bool cmp);
struct abort_arg {
    rec_fn fn;
    const KatToks *k;
};
static void abort_trampoline(void *p)
{
    struct abort_arg *a = p;
    a->fn(a->k, false);
}
static void expect_abort(const KatToks *k, rec_fn fn)
{
    struct abort_arg a = {fn, k};
    long detail = 0;
    enum kat_child c = kat_isolate(kat_cur_file, k->lineno, abort_trampoline, &a, &detail);
    if (c == KAT_CHILD_ABORTED)
        return;
    char buf[64];
    snprintf(buf, sizeof buf, "%s(%ld)", kat_child_str(c), detail);
    mism(k, "verdict", "ABORT", buf);
}

/* --------------------------------------------------- stateless functions */

static void h_to_scalar(const KatToks *k, bool cmp)
{
    unsigned char in[64], o[32];
    kat_hexn(k, 3, in, 64);
    librustzcash_to_scalar(in, o);
    if (cmp) {
        if (!kat_is(k, 4, "OK"))
            mism(k, "verdict", k->t[4], "OK");
        cmp_hex(k, 5, o, 32, "to_scalar");
    }
}
static void h_ask_to_ak(const KatToks *k, bool cmp)
{
    unsigned char in[32], o[32];
    kat_hexn(k, 3, in, 32);
    librustzcash_ask_to_ak(in, o);
    if (cmp) {
        if (!kat_is(k, 4, "OK"))
            mism(k, "verdict", k->t[4], "OK");
        cmp_hex(k, 5, o, 32, "ask_to_ak");
    }
}
static void h_nsk_to_nk(const KatToks *k, bool cmp)
{
    unsigned char in[32], o[32];
    kat_hexn(k, 3, in, 32);
    librustzcash_nsk_to_nk(in, o);
    if (cmp) {
        if (!kat_is(k, 4, "OK"))
            mism(k, "verdict", k->t[4], "OK");
        cmp_hex(k, 5, o, 32, "nsk_to_nk");
    }
}
static void h_crh_ivk(const KatToks *k, bool cmp)
{
    unsigned char a[32], n[32], o[32];
    kat_hexn(k, 3, a, 32);
    kat_hexn(k, 4, n, 32);
    librustzcash_crh_ivk(a, n, o);
    if (cmp) {
        if (!kat_is(k, 5, "OK"))
            mism(k, "verdict", k->t[5], "OK");
        cmp_hex(k, 6, o, 32, "crh_ivk");
    }
}
static void h_check_diversifier(const KatToks *k, bool cmp)
{
    unsigned char d[11];
    kat_hexn(k, 3, d, 11);
    bool ok = librustzcash_check_diversifier(d);
    if (cmp)
        cmp_verdict(k, 4, ok, "verdict");
}
static void h_ivk_to_pkd(const KatToks *k, bool cmp)
{
    unsigned char ivk[32], d[11], o[32];
    kat_hexn(k, 3, ivk, 32);
    kat_hexn(k, 4, d, 11);
    bool ok = librustzcash_ivk_to_pkd(ivk, d, o);
    if (cmp && cmp_verdict(k, 5, ok, "verdict") && ok)
        cmp_hex(k, 6, o, 32, "pk_d");
}
static void h_tree_uncommitted(const KatToks *k, bool cmp)
{
    unsigned char o[32];
    librustzcash_tree_uncommitted(o);
    if (cmp)
        cmp_hex(k, 4, o, 32, "uncommitted");
}
static void h_merkle_hash(const KatToks *k, bool cmp)
{
    unsigned char a[32], b[32], o[32];
    kat_hexn(k, 4, a, 32);
    kat_hexn(k, 5, b, 32);
    librustzcash_merkle_hash((size_t)kat_u64(k, 3), a, b, o);
    if (cmp) {
        if (!kat_is(k, 6, "OK"))
            mism(k, "verdict", k->t[6], "OK");
        cmp_hex(k, 7, o, 32, "merkle_hash");
    }
}
static void h_compute_cm(const KatToks *k, bool cmp)
{
    unsigned char d[11], p[32], r[32], o[32];
    kat_hexn(k, 3, d, 11);
    kat_hexn(k, 4, p, 32);
    kat_hexn(k, 6, r, 32);
    bool ok = librustzcash_sapling_compute_cm(d, p, kat_u64(k, 5), r, o);
    if (cmp && cmp_verdict(k, 7, ok, "verdict") && ok)
        cmp_hex(k, 8, o, 32, "cm");
}
static void h_compute_nf(const KatToks *k, bool cmp)
{
    unsigned char d[11], p[32], r[32], ak[32], nk[32], o[32];
    kat_hexn(k, 3, d, 11);
    kat_hexn(k, 4, p, 32);
    kat_hexn(k, 6, r, 32);
    kat_hexn(k, 7, ak, 32);
    kat_hexn(k, 8, nk, 32);
    bool ok = librustzcash_sapling_compute_nf(d, p, kat_u64(k, 5), r, ak, nk, kat_u64(k, 9), o);
    if (cmp && cmp_verdict(k, 10, ok, "verdict") && ok)
        cmp_hex(k, 11, o, 32, "nf");
}
static void h_ka_agree(const KatToks *k, bool cmp)
{
    unsigned char p[32], s[32], o[32];
    kat_hexn(k, 3, p, 32);
    kat_hexn(k, 4, s, 32);
    bool ok = librustzcash_sapling_ka_agree(p, s, o);
    if (cmp && cmp_verdict(k, 5, ok, "verdict") && ok)
        cmp_hex(k, 6, o, 32, "ka_agree");
}
static void h_ka_derivepublic(const KatToks *k, bool cmp)
{
    unsigned char d[11], s[32], o[32];
    kat_hexn(k, 3, d, 11);
    kat_hexn(k, 4, s, 32);
    bool ok = librustzcash_sapling_ka_derivepublic(d, s, o);
    if (cmp && cmp_verdict(k, 5, ok, "verdict") && ok)
        cmp_hex(k, 6, o, 32, "ka_derivepublic");
}

static unsigned char (*g_genr)[32];
static size_t g_genr_n, g_genr_cap;
static bool lt_r(const unsigned char *x)
{
    for (int i = 31; i >= 0; i--) {
        if (x[i] < KAT_R_LE[i])
            return true;
        if (x[i] > KAT_R_LE[i])
            return false;
    }
    return false;
}
static void h_generate_r(const KatToks *k, bool cmp)
{
    unsigned char o[32], rec[32];
    librustzcash_sapling_generate_r(o);
    if (!cmp)
        return;
    kat_hexn(k, 4, rec, 32);
    if (!kat_is(k, 3, "OK") || !lt_r(rec) || !kat_is(k, 5, "T"))
        mism(k, "golden record itself out of range", k->t[4], "-");
    if (!lt_r(o)) {
        char h[65];
        kat_tohex(h, o, 32);
        mism(k, "generate_r output >= r", "<r", h);
    }
    if (g_genr_n == g_genr_cap) {
        g_genr_cap = g_genr_cap ? 2 * g_genr_cap : 1024;
        void *nb = realloc(g_genr, g_genr_cap * 32);
        if (!nb) {
            fprintf(stderr, "out of memory\n");
            exit(2);
        }
        g_genr = nb;
    }
    memcpy(g_genr[g_genr_n++], o, 32);
}
static int cmp32(const void *a, const void *b) { return memcmp(a, b, 32); }
static void generate_r_finish(void)
{
    if (g_genr_n < 2)
        return;
    qsort(g_genr, g_genr_n, 32, cmp32);
    for (size_t i = 1; i < g_genr_n; i++)
        if (memcmp(g_genr[i - 1], g_genr[i], 32) == 0) {
            KatToks k = {{0}, 0, 0, NULL};
            mism(&k, "generate_r repeated an output", "distinct", "repeat");
            break;
        }
    free(g_genr);
    g_genr = NULL;
    g_genr_n = g_genr_cap = 0;
}

static void h_spend_sig(const KatToks *k, bool cmp)
{
    unsigned char ask[32], ar[32], sh[32], o[64];
    kat_hexn(k, 3, ask, 32);
    kat_hexn(k, 4, ar, 32);
    kat_hexn(k, 5, sh, 32);
    bool ok = librustzcash_sapling_spend_sig(ask, ar, sh, o);
    if (!cmp || !cmp_verdict(k, 6, ok, "verdict") || !ok)
        return;
    unsigned char rk[32], msg[64], rsig[64];
    kat_hexn(k, 8, rk, 32);
    kat_hexn(k, 7, rsig, 64);
    memcpy(msg, rk, 32);
    memcpy(msg + 32, sh, 32);
    if (!kat_rj_verify(rk, msg, rsig, KAT_GEN_SPEND_AUTH))
        mism(k, "test helper rejects Rust's own signature (helper bug)", "verifies", "rejected");
    if (!kat_rj_verify(rk, msg, o, KAT_GEN_SPEND_AUTH)) {
        char h[129];
        kat_tohex(h, o, 64);
        mism(k, "C23 spend_auth_sig does not verify under rk", "verifies", h);
    }
}

static void h_xsk_master(const KatToks *k, bool cmp)
{
    size_t n = (size_t)kat_u64(k, 3);
    unsigned char *seed = kat_xmalloc(n), o[169];
    if (n)
        kat_hexn(k, 4, seed, n);
    else if (!kat_is(k, 4, "~"))
        mism(k, "empty seed must be ~", "~", k->t[4]);
    librustzcash_zip32_xsk_master(seed, n, o);
    free(seed);
    if (cmp)
        cmp_hex(k, 6, o, 169, "xsk_master");
}
static void h_xsk_derive(const KatToks *k, bool cmp)
{
    unsigned char p[169], o[169];
    kat_hexn(k, 3, p, 169);
    librustzcash_zip32_xsk_derive(p, (uint32_t)kat_u64(k, 4), o);
    if (cmp) {
        if (!kat_is(k, 5, "OK"))
            mism(k, "verdict", k->t[5], "OK");
        cmp_hex(k, 6, o, 169, "xsk");
    }
}
static void h_xfvk_derive(const KatToks *k, bool cmp)
{
    unsigned char p[169], o[169];
    kat_hexn(k, 3, p, 169);
    bool ok = librustzcash_zip32_xfvk_derive(p, (uint32_t)kat_u64(k, 4), o);
    if (cmp && cmp_verdict(k, 5, ok, "verdict") && ok)
        cmp_hex(k, 6, o, 169, "xfvk");
}
static void h_xfvk_address(const KatToks *k, bool cmp)
{
    unsigned char x[169], j[11], jr[11], a[43];
    kat_hexn(k, 3, x, 169);
    kat_hexn(k, 4, j, 11);
    bool ok = librustzcash_zip32_xfvk_address(x, j, jr, a);
    if (cmp && cmp_verdict(k, 5, ok, "verdict") && ok) {
        cmp_hex(k, 6, jr, 11, "j_ret");
        cmp_hex(k, 7, a, 43, "addr");
    }
}

/* init records: run before the canonical init (see main). */
static void h_init(const KatToks *k, bool cmp)
{
    (void)cmp;
    kat_init_params(g_params, k->t[3], k->t[4], k->t[5], k->t[6], k->t[7], k->t[8]);
}

static void h_ctx(const KatToks *k, bool cmp)
{
    (void)cmp;
    const char *label = k->t[2];
    if (strcmp(kat_cur_file, "sapling_proving_ctx_init.golden") == 0) {
        int reps = strcmp(label, "init_free_x1000") == 0 ? 1000 : 1;
        bool nonnull = true;
        for (int i = 0; i < reps; i++) {
            void *c = librustzcash_sapling_proving_ctx_init();
            nonnull = nonnull && c != NULL;
            if (c)
                librustzcash_sapling_proving_ctx_free(c);
        }
        cmp_verdict(k, 4, nonnull, "non_null");
    } else if (strcmp(kat_cur_file, "sapling_verification_ctx_init.golden") == 0) {
        void *c = librustzcash_sapling_verification_ctx_init();
        if (strcmp(label, "empty_ctx_final_vb0_zero_sig") == 0) {
            unsigned char sig[64] = {0}, sh[32] = {0};
            bool ok = c && librustzcash_sapling_final_check(c, 0, sig, sh);
            cmp_verdict(k, 4, ok, "final_check(empty ctx, vb 0, zero sig)");
        } else {
            cmp_verdict(k, 4, c != NULL, "non_null");
        }
        if (c)
            librustzcash_sapling_verification_ctx_free(c);
    } else if (strcmp(kat_cur_file, "sapling_proving_ctx_free.golden") == 0) {
        librustzcash_sapling_proving_ctx_free(librustzcash_sapling_proving_ctx_init());
    } else {
        librustzcash_sapling_verification_ctx_free(librustzcash_sapling_verification_ctx_init());
    }
}

/* --------------------------------------------------------- verification */

static void ld_spend(const KatToks *k, int i, unsigned char cv[32], unsigned char an[32], unsigned char nf[32],
                     unsigned char rk[32], unsigned char pr[192], unsigned char sig[64], unsigned char sh[32])
{
    kat_hexn(k, i, cv, 32);
    kat_hexn(k, i + 1, an, 32);
    kat_hexn(k, i + 2, nf, 32);
    kat_hexn(k, i + 3, rk, 32);
    kat_hexn(k, i + 4, pr, 192);
    kat_hexn(k, i + 5, sig, 64);
    kat_hexn(k, i + 6, sh, 32);
}

static void batch_check_spend(const KatToks *k, const unsigned char *cv, const unsigned char *an,
                              const unsigned char *nf, const unsigned char *rk, const unsigned char *pr,
                              const unsigned char *sig, const unsigned char *sh, bool want)
{
#ifdef KAT_HAVE_BATCH
    if (!g_batch)
        return;
    zcl_c23_batch *b = zcl_c23_batch_new(1, 1);
    void *ctx = librustzcash_sapling_verification_ctx_init();
    if (!b || !ctx) {
        fprintf(stderr, "batch allocation failed\n");
        exit(2);
    }
    enum zcl_c23_item_status st = zcl_c23_batch_add_spend(b, ctx, cv, an, nf, rk, pr, sig, sh);
    bool got = st == ZCL_C23_ITEM_QUEUED && zcl_c23_batch_verify_each(b, NULL, NULL);
    bool got2 = st == ZCL_C23_ITEM_QUEUED && zcl_c23_batch_verify(b, NULL, NULL);
    g_batch_checked++;
    if (got != want || got2 != want) {
        g_batch_mismatch++;
        char c[32];
        snprintf(c, sizeof c, "each=%s combined=%s", kat_tf(got), kat_tf(got2));
        mism(k, "zcl_c23_batch spend verdict (C23 extra API)", kat_tf(want), c);
    }
    librustzcash_sapling_verification_ctx_free(ctx);
    zcl_c23_batch_free(b);
#else
    (void)k, (void)cv, (void)an, (void)nf, (void)rk, (void)pr, (void)sig, (void)sh, (void)want;
#endif
}

static void batch_check_output(const KatToks *k, const unsigned char *cv, const unsigned char *cm,
                               const unsigned char *epk, const unsigned char *pr, bool want)
{
#ifdef KAT_HAVE_BATCH
    if (!g_batch)
        return;
    zcl_c23_batch *b = zcl_c23_batch_new(1, 1);
    void *ctx = librustzcash_sapling_verification_ctx_init();
    if (!b || !ctx) {
        fprintf(stderr, "batch allocation failed\n");
        exit(2);
    }
    enum zcl_c23_item_status st = zcl_c23_batch_add_output(b, ctx, cv, cm, epk, pr);
    bool got = st == ZCL_C23_ITEM_QUEUED && zcl_c23_batch_verify_each(b, NULL, NULL);
    bool got2 = st == ZCL_C23_ITEM_QUEUED && zcl_c23_batch_verify(b, NULL, NULL);
    g_batch_checked++;
    if (got != want || got2 != want) {
        g_batch_mismatch++;
        char c[32];
        snprintf(c, sizeof c, "each=%s combined=%s", kat_tf(got), kat_tf(got2));
        mism(k, "zcl_c23_batch output verdict (C23 extra API)", kat_tf(want), c);
    }
    librustzcash_sapling_verification_ctx_free(ctx);
    zcl_c23_batch_free(b);
#else
    (void)k, (void)cv, (void)cm, (void)epk, (void)pr, (void)want;
#endif
}

static void h_check_spend(const KatToks *k, bool cmp)
{
    unsigned char cv[32], an[32], nf[32], rk[32], pr[192], sig[64], sh[32];
    ld_spend(k, 3, cv, an, nf, rk, pr, sig, sh);
    void *ctx = librustzcash_sapling_verification_ctx_init();
    bool ok = librustzcash_sapling_check_spend(ctx, cv, an, nf, rk, pr, sig, sh);
    librustzcash_sapling_verification_ctx_free(ctx);
    if (cmp) {
        cmp_verdict(k, 10, ok, "verdict");
        batch_check_spend(k, cv, an, nf, rk, pr, sig, sh, kat_is(k, 10, "T"));
    }
}
static void h_check_output(const KatToks *k, bool cmp)
{
    unsigned char cv[32], cm[32], epk[32], pr[192];
    kat_hexn(k, 3, cv, 32);
    kat_hexn(k, 4, cm, 32);
    kat_hexn(k, 5, epk, 32);
    kat_hexn(k, 6, pr, 192);
    void *ctx = librustzcash_sapling_verification_ctx_init();
    bool ok = librustzcash_sapling_check_output(ctx, cv, cm, epk, pr);
    librustzcash_sapling_verification_ctx_free(ctx);
    if (cmp) {
        cmp_verdict(k, 7, ok, "verdict");
        batch_check_output(k, cv, cm, epk, pr, kat_is(k, 7, "T"));
    }
}
static void h_sprout_verify(const KatToks *k, bool cmp)
{
    unsigned char pr[192], f[8][32];
    kat_hexn(k, 3, pr, 192);
    for (int j = 0; j < 8; j++)
        kat_hexn(k, 4 + j, f[j], 32);
    bool ok = librustzcash_sprout_verify(pr, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], kat_u64(k, 12),
                                         kat_u64(k, 13));
    if (cmp)
        cmp_verdict(k, 14, ok, "verdict");
}

/* ------------------------------------------------------- emit for Rust */

static void emit_hex(const unsigned char *b, size_t n)
{
    char *h = kat_xmalloc(2 * n + 1);
    kat_tohex(h, b, n);
    fputc(' ', g_emit);
    fputs(h, g_emit);
    free(h);
}
static void emit_head(const char *fn, const char *label, const char *src_label, const char *expect)
{
    ++g_emit_id;
    fprintf(g_emit, "%lu - %s c23made:%s:%s", g_emit_id, fn, label, src_label);
    fprintf(g_emit_expect, "%lu %s\n", g_emit_id, expect);
}
static void emit_check_spend(const char *label, const char *src, const unsigned char *cv, const unsigned char *an,
                             const unsigned char *nf, const unsigned char *rk, const unsigned char *pr,
                             const unsigned char *sig, const unsigned char *sh, const char *expect)
{
    if (!g_emit)
        return;
    emit_head("check_spend", label, src, expect);
    emit_hex(cv, 32);
    emit_hex(an, 32);
    emit_hex(nf, 32);
    emit_hex(rk, 32);
    emit_hex(pr, 192);
    emit_hex(sig, 64);
    emit_hex(sh, 32);
    fputc('\n', g_emit);
}
static void emit_check_output(const char *label, const char *src, const unsigned char *cv, const unsigned char *cm,
                              const unsigned char *epk, const unsigned char *pr, const char *expect)
{
    if (!g_emit)
        return;
    emit_head("check_output", label, src, expect);
    emit_hex(cv, 32);
    emit_hex(cm, 32);
    emit_hex(epk, 32);
    emit_hex(pr, 192);
    fputc('\n', g_emit);
}

/* --------------------------------------------------------------- provers */

static bool spend_proof_call(const KatToks *k, unsigned char cv[32], unsigned char rk[32], unsigned char pr[192])
{
    unsigned char ak[32], nsk[32], d[11], rcm[32], ar[32], an[32], w[1065];
    kat_hexn(k, 3, ak, 32);
    kat_hexn(k, 4, nsk, 32);
    kat_hexn(k, 5, d, 11);
    kat_hexn(k, 6, rcm, 32);
    kat_hexn(k, 7, ar, 32);
    kat_hexn(k, 9, an, 32);
    kat_hexn(k, 10, w, 1065);
    void *ctx = librustzcash_sapling_proving_ctx_init();
    if (!ctx) {
        fprintf(stderr, "proving_ctx_init returned NULL\n");
        exit(2);
    }
    bool ok = librustzcash_sapling_spend_proof(ctx, ak, nsk, d, rcm, ar, kat_u64(k, 8), an, w, cv, rk, pr);
    librustzcash_sapling_proving_ctx_free(ctx);
    return ok;
}
static void h_spend_proof(const KatToks *k, bool cmp)
{
    unsigned char cv[32], rk[32], pr[192];
    if (!cmp) {
        (void)spend_proof_call(k, cv, rk, pr);
        return;
    }
    bool golden_t = kat_is(k, 11, "T");
    if (golden_t && !kat_is(k, 18, "-")) {
        /* Rust-made proof through the C23 verifier. */
        unsigned char gcv[32], an[32], nf[32], grk[32], gpr[192], sig[64], sh[32];
        kat_hexn(k, 12, gcv, 32);
        kat_hexn(k, 9, an, 32);
        kat_hexn(k, 15, nf, 32);
        kat_hexn(k, 13, grk, 32);
        kat_hexn(k, 14, gpr, 192);
        kat_hexn(k, 17, sig, 64);
        kat_hexn(k, 16, sh, 32);
        void *v = librustzcash_sapling_verification_ctx_init();
        bool ok = librustzcash_sapling_check_spend(v, gcv, an, nf, grk, gpr, sig, sh);
        librustzcash_sapling_verification_ctx_free(v);
        cmp_verdict(k, 18, ok, "C23 check_spend of the Rust-made spend proof");
    }
    if (golden_t && !g_prove) {
        g_skipped++;
        return;
    }
    bool ok = spend_proof_call(k, cv, rk, pr);
    if (!cmp_verdict(k, 11, ok, "spend_proof verdict") || !ok)
        return;
    cmp_hex(k, 13, rk, 32, "rk (deterministic)");
    if (kat_is(k, 18, "-"))
        return;
    unsigned char an[32], nf[32], sig[64], sh[32];
    kat_hexn(k, 9, an, 32);
    kat_hexn(k, 15, nf, 32);
    kat_hexn(k, 17, sig, 64);
    kat_hexn(k, 16, sh, 32);
    void *v = librustzcash_sapling_verification_ctx_init();
    bool vok = librustzcash_sapling_check_spend(v, cv, an, nf, rk, pr, sig, sh);
    librustzcash_sapling_verification_ctx_free(v);
    cmp_verdict(k, 18, vok, "C23 check_spend of the C23-made spend proof");
    emit_check_spend("spend_proof", k->t[2], cv, an, nf, rk, pr, sig, sh, k->t[18]);
}

static bool output_proof_call(const KatToks *k, unsigned char cv[32], unsigned char pr[192])
{
    unsigned char esk[32], d[11], pkd[32], rcm[32];
    kat_hexn(k, 3, esk, 32);
    kat_hexn(k, 4, d, 11);
    kat_hexn(k, 5, pkd, 32);
    kat_hexn(k, 6, rcm, 32);
    void *ctx = librustzcash_sapling_proving_ctx_init();
    if (!ctx) {
        fprintf(stderr, "proving_ctx_init returned NULL\n");
        exit(2);
    }
    bool ok = librustzcash_sapling_output_proof(ctx, esk, d, pkd, rcm, kat_u64(k, 7), cv, pr);
    librustzcash_sapling_proving_ctx_free(ctx);
    return ok;
}
static void h_output_proof(const KatToks *k, bool cmp)
{
    unsigned char cv[32], pr[192];
    if (!cmp) {
        (void)output_proof_call(k, cv, pr);
        return;
    }
    bool golden_t = kat_is(k, 8, "T");
    if (golden_t && !kat_is(k, 13, "-")) {
        unsigned char gcv[32], gpr[192], cm[32], epk[32];
        kat_hexn(k, 9, gcv, 32);
        kat_hexn(k, 10, gpr, 192);
        kat_hexn(k, 11, cm, 32);
        kat_hexn(k, 12, epk, 32);
        void *v = librustzcash_sapling_verification_ctx_init();
        bool ok = librustzcash_sapling_check_output(v, gcv, cm, epk, gpr);
        librustzcash_sapling_verification_ctx_free(v);
        cmp_verdict(k, 13, ok, "C23 check_output of the Rust-made output proof");
    }
    if (golden_t && !g_prove) {
        g_skipped++;
        return;
    }
    bool ok = output_proof_call(k, cv, pr);
    if (!cmp_verdict(k, 8, ok, "output_proof verdict") || !ok || kat_is(k, 13, "-"))
        return;
    unsigned char cm[32], epk[32];
    kat_hexn(k, 11, cm, 32);
    kat_hexn(k, 12, epk, 32);
    void *v = librustzcash_sapling_verification_ctx_init();
    bool vok = librustzcash_sapling_check_output(v, cv, cm, epk, pr);
    librustzcash_sapling_verification_ctx_free(v);
    cmp_verdict(k, 13, vok, "C23 check_output of the C23-made output proof");
    emit_check_output("output_proof", k->t[2], cv, cm, epk, pr, k->t[13]);
}

static void sprout_prove_call(const KatToks *k, unsigned char *proof)
{
    unsigned char phi[32], rt[32], hs[32], sk1[32], rho1[32], r1[32], a1[966], sk2[32], rho2[32], r2[32], a2[966];
    unsigned char pk1[32], or1[32], pk2[32], or2[32];
    kat_hexn(k, 3, phi, 32);
    kat_hexn(k, 4, rt, 32);
    kat_hexn(k, 5, hs, 32);
    kat_hexn(k, 6, sk1, 32);
    kat_hexn(k, 8, rho1, 32);
    kat_hexn(k, 9, r1, 32);
    kat_hexn(k, 10, a1, 966);
    kat_hexn(k, 11, sk2, 32);
    kat_hexn(k, 13, rho2, 32);
    kat_hexn(k, 14, r2, 32);
    kat_hexn(k, 15, a2, 966);
    kat_hexn(k, 16, pk1, 32);
    kat_hexn(k, 18, or1, 32);
    kat_hexn(k, 19, pk2, 32);
    kat_hexn(k, 21, or2, 32);
    librustzcash_sprout_prove(proof, phi, rt, hs, sk1, kat_u64(k, 7), rho1, r1, a1, sk2, kat_u64(k, 12), rho2, r2, a2,
                              pk1, kat_u64(k, 17), or1, pk2, kat_u64(k, 20), or2, kat_u64(k, 22), kat_u64(k, 23));
}
static bool sprout_verify_derived(const KatToks *k, const unsigned char pr[192])
{
    unsigned char rt[32], hs[32], f[6][32];
    kat_hexn(k, 4, rt, 32);
    kat_hexn(k, 5, hs, 32);
    for (int j = 0; j < 6; j++)
        kat_hexn(k, 26 + j, f[j], 32);
    /* derived order nf1 nf2 mac1 mac2 cm1 cm2; ABI order mac1 mac2 nf1 nf2 cm1 cm2 */
    return librustzcash_sprout_verify(pr, rt, hs, f[2], f[3], f[0], f[1], f[4], f[5], kat_u64(k, 22), kat_u64(k, 23));
}
static void h_sprout_prove(const KatToks *k, bool cmp)
{
    unsigned char pr[192];
    if (!cmp) {
        sprout_prove_call(k, pr);
        return;
    }
    if (!kat_is(k, 24, "OK"))
        mism(k, "verdict", k->t[24], "OK");
    unsigned char gpr[192];
    kat_hexn(k, 25, gpr, 192);
    cmp_verdict(k, 32, sprout_verify_derived(k, gpr), "C23 sprout_verify of the Rust-made proof");
    if (!g_prove) {
        g_skipped++;
        return;
    }
    memset(pr, 0xa5, sizeof pr);
    sprout_prove_call(k, pr);
    cmp_verdict(k, 32, sprout_verify_derived(k, pr), "C23 sprout_verify of the C23-made proof");
    if (g_emit) {
        emit_head("sprout_verify", "sprout_prove", k->t[2], k->t[32]);
        emit_hex(pr, 192);
        unsigned char b[32];
        kat_hexn(k, 4, b, 32);
        emit_hex(b, 32);
        kat_hexn(k, 5, b, 32);
        emit_hex(b, 32);
        static const int order[6] = {28, 29, 26, 27, 30, 31}; /* mac1 mac2 nf1 nf2 cm1 cm2 */
        for (int j = 0; j < 6; j++) {
            kat_hexn(k, order[j], b, 32);
            emit_hex(b, 32);
        }
        fprintf(g_emit, " %s %s\n", k->t[22], k->t[23]);
    }
}

/* --------------------------------------------------------------- bundles */

typedef struct {
    KatToks *lines;
    size_t n, cap;
} Bundle;

static void vbundle(const Bundle *b)
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    for (size_t i = 1; i + 1 < b->n; i++) {
        const KatToks *k = &b->lines[i];
        bool ok;
        int vi;
        if (kat_is(k, 0, "S")) {
            unsigned char cv[32], an[32], nf[32], rk[32], pr[192], sig[64], sh[32];
            ld_spend(k, 1, cv, an, nf, rk, pr, sig, sh);
            ok = librustzcash_sapling_check_spend(ctx, cv, an, nf, rk, pr, sig, sh);
            vi = 8;
        } else if (kat_is(k, 0, "O")) {
            unsigned char cv[32], cm[32], epk[32], pr[192];
            kat_hexn(k, 1, cv, 32);
            kat_hexn(k, 2, cm, 32);
            kat_hexn(k, 3, epk, 32);
            kat_hexn(k, 4, pr, 192);
            ok = librustzcash_sapling_check_output(ctx, cv, cm, epk, pr);
            vi = 5;
        } else if (kat_is(k, 0, "F")) {
            unsigned char sig[64], sh[32];
            kat_hexn(k, 2, sig, 64);
            kat_hexn(k, 3, sh, 32);
            ok = librustzcash_sapling_final_check(ctx, kat_i64(k, 1), sig, sh);
            vi = 4;
        } else {
            fprintf(stderr, "%s:%lu: unknown bundle line\n", kat_cur_file, k->lineno);
            exit(2);
        }
        if (!kat_is(k, vi, kat_tf(ok))) {
            KatToks h = b->lines[0];
            h.lineno = k->lineno;
            char what[64];
            snprintf(what, sizeof what, "bundle step %c (line %lu)", k->t[0][0], k->lineno);
            mism(&h, what, k->t[vi], kat_tf(ok));
        }
    }
    librustzcash_sapling_verification_ctx_free(ctx);
}

enum { MAXD = 8 };
static void pbundle(const Bundle *b)
{
    const KatToks *hd = &b->lines[0];
    if (!g_prove) {
        g_skipped++;
        return;
    }
    void *ctx = librustzcash_sapling_proving_ctx_init();
    if (!ctx) {
        fprintf(stderr, "proving_ctx_init returned NULL\n");
        exit(2);
    }
    unsigned char scv[MAXD][32], srk[MAXD][32], spr[MAXD][192], san[MAXD][32], snf[MAXD][32], ssig[MAXD][64];
    unsigned char ocv[MAXD][32], opr[MAXD][192], ocm[MAXD][32], oepk[MAXD][32], sh[32] = {0}, bsig[64];
    int ns = 0, no = 0, nss = 0;
    bool all = true;
    int64_t vb = 0;
    const KatToks *vline = NULL;
    for (size_t i = 1; i + 1 < b->n; i++) {
        const KatToks *k = &b->lines[i];
        KatToks h = *hd;
        h.lineno = k->lineno;
        if (kat_is(k, 0, "PS") && ns < MAXD) {
            unsigned char ak[32], nsk[32], d[11], rcm[32], ar[32], w[1065], nk[32], ivk[32], pkd[32];
            kat_hexn(k, 1, ak, 32);
            kat_hexn(k, 2, nsk, 32);
            kat_hexn(k, 3, d, 11);
            kat_hexn(k, 4, rcm, 32);
            kat_hexn(k, 5, ar, 32);
            kat_hexn(k, 7, san[ns], 32);
            kat_hexn(k, 8, w, 1065);
            bool ok = librustzcash_sapling_spend_proof(ctx, ak, nsk, d, rcm, ar, kat_u64(k, 6), san[ns], w, scv[ns],
                                                       srk[ns], spr[ns]);
            if (!kat_is(k, 9, kat_tf(ok)))
                mism(&h, "PS verdict", k->t[9], kat_tf(ok));
            all = all && ok;
            if (ok) {
                if (!kat_eqhex(k, 11, srk[ns], 32))
                    mism(&h, "PS rk (deterministic)", k->t[11], "differs");
                uint64_t pos = 0;
                for (int j = 0; j < 8; j++)
                    pos |= (uint64_t)w[1057 + j] << (8 * j);
                librustzcash_nsk_to_nk(nsk, nk);
                librustzcash_crh_ivk(ak, nk, ivk);
                if (!librustzcash_ivk_to_pkd(ivk, d, pkd) ||
                    !librustzcash_sapling_compute_nf(d, pkd, kat_u64(k, 6), rcm, ak, nk, pos, snf[ns]))
                    mism(&h, "nf recompute", "T", "F");
            }
            ns++;
        } else if (kat_is(k, 0, "PO") && no < MAXD) {
            unsigned char esk[32], d[11], pkd[32], rcm[32];
            kat_hexn(k, 1, esk, 32);
            kat_hexn(k, 2, d, 11);
            kat_hexn(k, 3, pkd, 32);
            kat_hexn(k, 4, rcm, 32);
            bool ok = librustzcash_sapling_output_proof(ctx, esk, d, pkd, rcm, kat_u64(k, 5), ocv[no], opr[no]);
            if (!kat_is(k, 6, kat_tf(ok)))
                mism(&h, "PO verdict", k->t[6], kat_tf(ok));
            all = all && ok;
            if (ok && (!librustzcash_sapling_compute_cm(d, pkd, kat_u64(k, 5), rcm, ocm[no]) ||
                       !librustzcash_sapling_ka_derivepublic(d, esk, oepk[no])))
                mism(&h, "cm/epk recompute", "T", "F");
            no++;
        } else if (kat_is(k, 0, "SS") && nss < MAXD) {
            unsigned char ask[32], ar[32];
            kat_hexn(k, 1, ask, 32);
            kat_hexn(k, 2, ar, 32);
            kat_hexn(k, 3, sh, 32);
            bool ok = librustzcash_sapling_spend_sig(ask, ar, sh, ssig[nss]);
            if (!kat_is(k, 4, kat_tf(ok)))
                mism(&h, "SS verdict", k->t[4], kat_tf(ok));
            all = all && ok;
            nss++;
        } else if (kat_is(k, 0, "PB")) {
            vb = kat_i64(k, 1);
            kat_hexn(k, 2, sh, 32);
            bool ok = librustzcash_sapling_binding_sig(ctx, vb, sh, bsig);
            if (!kat_is(k, 3, kat_tf(ok)))
                mism(&h, "PB verdict", k->t[3], kat_tf(ok));
            all = all && ok;
        } else if (kat_is(k, 0, "V")) {
            vline = k;
        } else {
            fprintf(stderr, "%s:%lu: unknown prove-bundle line or too many descriptions\n", kat_cur_file, k->lineno);
            exit(2);
        }
    }
    librustzcash_sapling_proving_ctx_free(ctx);
    if (!vline)
        return;
    KatToks h = *hd;
    h.lineno = vline->lineno;
    if (!all) {
        if (!kat_is(vline, 1, "-"))
            mism(&h, "V should be '-' after a failed step", vline->t[1], "-");
        return;
    }
    void *v = librustzcash_sapling_verification_ctx_init();
    bool vok = true;
    for (int i = 0; i < ns; i++)
        vok = librustzcash_sapling_check_spend(v, scv[i], san[i], snf[i], srk[i], spr[i], ssig[i], sh) && vok;
    for (int i = 0; i < no; i++)
        vok = librustzcash_sapling_check_output(v, ocv[i], ocm[i], oepk[i], opr[i]) && vok;
    vok = librustzcash_sapling_final_check(v, vb, bsig, sh) && vok;
    librustzcash_sapling_verification_ctx_free(v);
    if (!kat_is(vline, 1, kat_tf(vok)))
        mism(&h, "V verdict (C23-made bundle, C23 verifier)", vline->t[1], kat_tf(vok));
    if (g_emit) {
        emit_head("vbundle", "binding_sig", hd->t[2], vline->t[1]);
        fprintf(g_emit, " %d\n", ns + no + 1);
        for (int i = 0; i < ns; i++) {
            fputs("S", g_emit);
            emit_hex(scv[i], 32);
            emit_hex(san[i], 32);
            emit_hex(snf[i], 32);
            emit_hex(srk[i], 32);
            emit_hex(spr[i], 192);
            emit_hex(ssig[i], 64);
            emit_hex(sh, 32);
            fputc('\n', g_emit);
        }
        for (int i = 0; i < no; i++) {
            fputs("O", g_emit);
            emit_hex(ocv[i], 32);
            emit_hex(ocm[i], 32);
            emit_hex(oepk[i], 32);
            emit_hex(opr[i], 192);
            fputc('\n', g_emit);
        }
        fprintf(g_emit, "F %lld", (long long)vb);
        emit_hex(bsig, 64);
        emit_hex(sh, 32);
        fputc('\n', g_emit);
        /* expectation is the AND of the steps (kat_cases prints "AND:steps") */
    }
}

/* --------------------------------------------------------------- driver */

struct filedef {
    const char *file;
    rec_fn fn;
    int verdict_col; /* column holding the verdict for ABORT detection, or 0 */
    int bundle;      /* 0 single, 1 verification bundles, 2 prove bundles */
};

static const struct filedef FILES[] = {
    {"init_zksnark_params.golden", h_init, 9, 0},
    {"to_scalar.golden", h_to_scalar, 4, 0},
    {"ask_to_ak.golden", h_ask_to_ak, 4, 0},
    {"nsk_to_nk.golden", h_nsk_to_nk, 4, 0},
    {"crh_ivk.golden", h_crh_ivk, 5, 0},
    {"check_diversifier.golden", h_check_diversifier, 4, 0},
    {"ivk_to_pkd.golden", h_ivk_to_pkd, 5, 0},
    {"tree_uncommitted.golden", h_tree_uncommitted, 3, 0},
    {"merkle_hash.golden", h_merkle_hash, 6, 0},
    {"sapling_compute_cm.golden", h_compute_cm, 7, 0},
    {"sapling_compute_nf.golden", h_compute_nf, 10, 0},
    {"sapling_ka_agree.golden", h_ka_agree, 5, 0},
    {"sapling_ka_derivepublic.golden", h_ka_derivepublic, 5, 0},
    {"sapling_generate_r.golden", h_generate_r, 3, 0},
    {"sapling_spend_sig.golden", h_spend_sig, 6, 0},
    {"zip32_xsk_master.golden", h_xsk_master, 5, 0},
    {"zip32_xsk_derive.golden", h_xsk_derive, 5, 0},
    {"zip32_xfvk_derive.golden", h_xfvk_derive, 5, 0},
    {"zip32_xfvk_address.golden", h_xfvk_address, 5, 0},
    {"sapling_proving_ctx_init.golden", h_ctx, 3, 0},
    {"sapling_proving_ctx_free.golden", h_ctx, 3, 0},
    {"sapling_verification_ctx_init.golden", h_ctx, 3, 0},
    {"sapling_verification_ctx_free.golden", h_ctx, 3, 0},
    {"sapling_check_spend.golden", h_check_spend, 10, 0},
    {"sapling_check_output.golden", h_check_output, 7, 0},
    {"sapling_final_check.golden", NULL, 0, 1},
    {"sprout_verify.golden", h_sprout_verify, 14, 0},
    {"sapling_spend_proof.golden", h_spend_proof, 11, 0},
    {"sapling_output_proof.golden", h_output_proof, 8, 0},
    {"sapling_binding_sig.golden", NULL, 0, 2},
    {"sprout_prove.golden", h_sprout_prove, 24, 0},
};

static int replay_file(const struct filedef *fd)
{
    char path[4096];
    if (snprintf(path, sizeof path, "%s/%s", g_dir, fd->file) >= (int)sizeof path)
        return 2;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        return 2;
    }
    kat_cur_file = fd->file;
    unsigned long before = g_mismatch, recs = 0, lineno = 0;
    char *line = NULL;
    size_t cap = 0;
    Bundle b = {NULL, 0, 0};
    double t0 = kat_now();
    while (kat_read_line(f, &line, &cap)) {
        lineno++;
        if (line[0] == '#' || line[0] == '@' || line[0] == '\n' || line[0] == '\r')
            continue;
        if (kat_in_child() && fd->bundle == 0 && lineno != kat_child_line())
            continue;
        KatToks k;
        kat_tokenize(line, lineno, &k);
        if (k.n == 0) {
            kat_toks_free(&k);
            continue;
        }
        if (fd->bundle == 0) {
            if (!kat_is(&k, 0, "C")) {
                fprintf(stderr, "%s:%lu: expected a C record\n", fd->file, lineno);
                exit(2);
            }
            if (fd->verdict_col && kat_is(&k, fd->verdict_col, "ABORT"))
                expect_abort(&k, fd->fn);
            else if (kat_in_child())
                fd->fn(&k, false); /* not reached: children only run ABORT records */
            else if (fd->fn == h_init && kat_is(&k, 9, "OK"))
                ; /* the canonical init is performed by main() right after this file */
            else
                fd->fn(&k, true);
            recs++;
            kat_toks_free(&k);
            continue;
        }
        if (b.n == b.cap) {
            b.cap = b.cap ? 2 * b.cap : 16;
            KatToks *nl = realloc(b.lines, b.cap * sizeof(KatToks));
            if (!nl) {
                fprintf(stderr, "out of memory\n");
                exit(2);
            }
            b.lines = nl;
        }
        b.lines[b.n++] = k;
        if (kat_is(&k, 0, "E")) {
            if (!kat_is(&b.lines[0], 0, "B")) {
                fprintf(stderr, "%s:%lu: bundle without B\n", fd->file, lineno);
                exit(2);
            }
            for (size_t i = 0; i < b.n; i++)
                for (int j = 0; j < b.lines[i].n; j++)
                    if (strcmp(b.lines[i].t[j], "ABORT") == 0) {
                        fprintf(stderr, "%s:%lu: bundle with an ABORT step is not supported\n", fd->file, lineno);
                        exit(2);
                    }
            if (fd->bundle == 1)
                vbundle(&b);
            else
                pbundle(&b);
            recs++;
            for (size_t i = 0; i < b.n; i++)
                kat_toks_free(&b.lines[i]);
            b.n = 0;
        }
    }
    free(line);
    free(b.lines);
    bool rerr = ferror(f);
    fclose(f);
    if (rerr) {
        fprintf(stderr, "read error on %s\n", path);
        return 2;
    }
    if (fd->fn == h_generate_r)
        generate_r_finish();
    g_records += recs;
    printf("%-40s %6lu records %8.2fs %s\n", fd->file, recs, kat_now() - t0,
           g_mismatch == before ? "ok" : "MISMATCH");
    fflush(stdout);
    return 0;
}

static void usage(void)
{
    fprintf(stderr, "usage: kat_replay --dir <c23_golden> --params <dir> [--prove] [--file <name>]\n"
                    "                  [--emit <cases> --emit-expect <expect>] [--mismatch-log <tsv>]\n"
                    "                  [--no-batch] [--max-print N]\n");
    exit(2);
}

int main(int argc, char **argv)
{
    kat_isolation_setup(argc, argv);
    const char *emit = NULL, *emit_expect = NULL, *mlog = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dir") && i + 1 < argc)
            g_dir = argv[++i];
        else if (!strcmp(argv[i], "--params") && i + 1 < argc)
            g_params = argv[++i];
        else if (!strcmp(argv[i], "--file") && i + 1 < argc)
            g_only = argv[++i];
        else if (!strcmp(argv[i], "--emit") && i + 1 < argc)
            emit = argv[++i];
        else if (!strcmp(argv[i], "--emit-expect") && i + 1 < argc)
            emit_expect = argv[++i];
        else if (!strcmp(argv[i], "--mismatch-log") && i + 1 < argc)
            mlog = argv[++i];
        else if (!strcmp(argv[i], "--max-print") && i + 1 < argc)
            g_max_print = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--prove"))
            g_prove = true;
        else if (!strcmp(argv[i], "--no-batch"))
            g_batch = false;
        else
            usage();
    }
    if (!g_dir || !g_params || (!emit) != (!emit_expect))
        usage();
    kat_jub_init();

    if (kat_in_child()) {
        /* Windows child: run exactly one ABORT record and exit. */
        const char *cf = kat_child_file();
        if (strcmp(cf, "init_zksnark_params.golden") != 0)
            kat_init_canonical(g_params);
        for (size_t i = 0; i < sizeof FILES / sizeof FILES[0]; i++)
            if (!strcmp(FILES[i].file, cf)) {
                replay_file(&FILES[i]);
                fprintf(stderr, "child: record %s:%lu not found or not an ABORT record\n", cf, kat_child_line());
                return 99;
            }
        return 99;
    }

    if (emit && !g_prove) {
        fprintf(stderr, "--emit needs --prove (it writes C23-made proofs)\n");
        return 2;
    }
    if (emit) {
        g_emit = fopen(emit, "wb");
        g_emit_expect = fopen(emit_expect, "wb");
        if (!g_emit || !g_emit_expect) {
            fprintf(stderr, "cannot open emit files\n");
            return 2;
        }
        fprintf(g_emit, "# kat_cases v1: C23-made proofs, signatures and bundles for the Rust verifier\n");
    }
    if (mlog) {
        g_mlog = fopen(mlog, "wb");
        if (!g_mlog) {
            fprintf(stderr, "cannot open %s\n", mlog);
            return 2;
        }
    }
    double t0 = kat_now();
    /* 1. init records (ABORT ones in children, before this process inits). */
    if (!g_only || !strcmp(g_only, FILES[0].file))
        if (replay_file(&FILES[0]) != 0)
            return 2;
    /* 2. the canonical init (the golden's OK record). */
    double ti = kat_now();
    kat_init_canonical(g_params);
    printf("canonical init_zksnark_params: %.3fs\n", kat_now() - ti);
    for (size_t i = 1; i < sizeof FILES / sizeof FILES[0]; i++) {
        if (g_only && strcmp(g_only, FILES[i].file) != 0)
            continue;
        if (replay_file(&FILES[i]) != 0)
            return 2;
    }
    if (g_emit) {
        fclose(g_emit);
        fclose(g_emit_expect);
    }
    if (g_mlog)
        fclose(g_mlog);
    printf("RESULT records=%lu mismatches=%lu skipped=%lu batch_checked=%lu batch_mismatch=%lu prove=%d emitted=%lu "
           "time=%.1fs\n",
           g_records, g_mismatch, g_skipped, g_batch_checked, g_batch_mismatch, g_prove ? 1 : 0, g_emit_id,
           kat_now() - t0);
    return g_mismatch ? 1 : 0;
}
