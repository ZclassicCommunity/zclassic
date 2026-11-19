/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). kat_bench: times the librustzcash ABI on fixed golden
 * inputs. The same source is linked with the C23 shim (kat_bench) and with the
 * Rust librustzcash.a (kat_bench_rust), so both run identical inputs on the
 * same host. Timing is reported, never asserted.
 *
 *   kat_bench --dir <c23_golden> --params <dir> [--runs 21] [--only <op>] [--label <s>]
 *             [--threads <n>]   (C23 build only: prover thread budget, 0 = default)
 *
 * Each op runs --runs times; each run performs `inner` calls (fixed per op,
 * identical for both libraries) and yields one per-call time. Reported: the
 * median, min and max per-call time over the runs. Every call's result is
 * checked against the golden value; a wrong result aborts the benchmark. */
#include "kat_common.h"

#include <stdlib.h>
#include <string.h>

static const char *g_dir;

#ifndef KAT_RUST
/* Vendored Z23 prover thread budget (sapling/groth16_prover.h); 0 = its default. */
void groth16_prover_set_threads(unsigned n);
#endif

/* Finds the first C record in <file> whose column vcol equals want and (when
 * label is non-NULL) whose label equals label. */
static bool find_rec(const char *file, int vcol, const char *want, const char *label, KatToks *k)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", g_dir, file);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    kat_cur_file = file;
    char *line = NULL;
    size_t cap = 0;
    unsigned long ln = 0;
    bool found = false;
    while (!found && kat_read_line(f, &line, &cap)) {
        ln++;
        if (line[0] != 'C')
            continue;
        kat_tokenize(line, ln, k);
        if (kat_is(k, vcol, want) && (!label || kat_is(k, 2, label)))
            found = true;
        else
            kat_toks_free(k);
    }
    free(line);
    fclose(f);
    if (!found) {
        fprintf(stderr, "kat_bench: no record in %s with col %d = %s label %s\n", file, vcol, want,
                label ? label : "*");
        exit(2);
    }
    return true;
}

static void die_wrong(const char *op)
{
    fprintf(stderr, "kat_bench: %s returned a wrong result\n", op);
    exit(1);
}

/* ---- inputs ---- */
static unsigned char mh_a[32], mh_b[32], mh_o[32];
static size_t mh_depth;
static unsigned char cs[7][192]; /* cv an nf rk proof sig sh */
static unsigned char co[4][192]; /* cv cm epk proof */
static unsigned char sv_p[192], sv_f[8][32];
static uint64_t sv_vo, sv_vn;
static unsigned char cm_d[11], cm_pk[32], cm_r[32], cm_o[32];
static uint64_t cm_v;
static unsigned char ip_ivk[32], ip_d[11], ip_o[32];
static unsigned char ka_p[32], ka_s[32], ka_o[32];
/* sprout_prove: the golden record, as the token vector */
static KatToks spv_k;
static unsigned char sp_ak[32], sp_nsk[32], sp_d[11], sp_rcm[32], sp_ar[32], sp_an[32], sp_w[1065];
static uint64_t sp_v;
static unsigned char op_esk[32], op_d[11], op_pk[32], op_rcm[32];
static uint64_t op_v;
static void *fc_ctx;
static int64_t fc_vb;
static unsigned char fc_sig[64], fc_sh[32];

static void load_inputs(void)
{
    KatToks k;
    find_rec("merkle_hash.golden", 2, "vec:pedersen", NULL, &k);
    mh_depth = (size_t)kat_u64(&k, 3);
    kat_hexn(&k, 4, mh_a, 32);
    kat_hexn(&k, 5, mh_b, 32);
    kat_hexn(&k, 7, mh_o, 32);
    kat_toks_free(&k);

    find_rec("sapling_check_spend.golden", 10, "T", NULL, &k);
    kat_hexn(&k, 3, cs[0], 32);
    kat_hexn(&k, 4, cs[1], 32);
    kat_hexn(&k, 5, cs[2], 32);
    kat_hexn(&k, 6, cs[3], 32);
    kat_hexn(&k, 7, cs[4], 192);
    kat_hexn(&k, 8, cs[5], 64);
    kat_hexn(&k, 9, cs[6], 32);
    printf("# check_spend input: %s line %lu (%s)\n", kat_cur_file, k.lineno, k.t[2]);
    kat_toks_free(&k);

    find_rec("sapling_check_output.golden", 7, "T", NULL, &k);
    kat_hexn(&k, 3, co[0], 32);
    kat_hexn(&k, 4, co[1], 32);
    kat_hexn(&k, 5, co[2], 32);
    kat_hexn(&k, 6, co[3], 192);
    printf("# check_output input: %s line %lu (%s)\n", kat_cur_file, k.lineno, k.t[2]);
    kat_toks_free(&k);

    find_rec("sprout_verify.golden", 14, "T", NULL, &k);
    kat_hexn(&k, 3, sv_p, 192);
    for (int j = 0; j < 8; j++)
        kat_hexn(&k, 4 + j, sv_f[j], 32);
    sv_vo = kat_u64(&k, 12);
    sv_vn = kat_u64(&k, 13);
    printf("# sprout_verify input: %s line %lu (%s)\n", kat_cur_file, k.lineno, k.t[2]);
    kat_toks_free(&k);

    find_rec("sapling_compute_cm.golden", 7, "T", NULL, &k);
    kat_hexn(&k, 3, cm_d, 11);
    kat_hexn(&k, 4, cm_pk, 32);
    cm_v = kat_u64(&k, 5);
    kat_hexn(&k, 6, cm_r, 32);
    kat_hexn(&k, 8, cm_o, 32);
    kat_toks_free(&k);

    find_rec("ivk_to_pkd.golden", 5, "T", NULL, &k);
    kat_hexn(&k, 3, ip_ivk, 32);
    kat_hexn(&k, 4, ip_d, 11);
    kat_hexn(&k, 6, ip_o, 32);
    kat_toks_free(&k);

    find_rec("sapling_ka_agree.golden", 5, "T", NULL, &k);
    kat_hexn(&k, 3, ka_p, 32);
    kat_hexn(&k, 4, ka_s, 32);
    kat_hexn(&k, 6, ka_o, 32);
    kat_toks_free(&k);

    find_rec("sprout_prove.golden", 24, "OK", "valid:input_with_path", &spv_k); /* kept for op_sprout_prove */

    find_rec("sapling_spend_proof.golden", 2, "valid:0", NULL, &k);
    kat_hexn(&k, 3, sp_ak, 32);
    kat_hexn(&k, 4, sp_nsk, 32);
    kat_hexn(&k, 5, sp_d, 11);
    kat_hexn(&k, 6, sp_rcm, 32);
    kat_hexn(&k, 7, sp_ar, 32);
    sp_v = kat_u64(&k, 8);
    kat_hexn(&k, 9, sp_an, 32);
    kat_hexn(&k, 10, sp_w, 1065);
    kat_toks_free(&k);

    find_rec("sapling_output_proof.golden", 2, "valid:0", NULL, &k);
    kat_hexn(&k, 3, op_esk, 32);
    kat_hexn(&k, 4, op_d, 11);
    kat_hexn(&k, 5, op_pk, 32);
    kat_hexn(&k, 6, op_rcm, 32);
    op_v = kat_u64(&k, 7);
    kat_toks_free(&k);

    /* final_check: the Rust-made 1-spend 1-output bundle "rustmade:1s1o". */
    char path[4096];
    snprintf(path, sizeof path, "%s/sapling_final_check.golden", g_dir);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    kat_cur_file = "sapling_final_check.golden";
    char *line = NULL;
    size_t cap = 0;
    unsigned long ln = 0;
    bool in = false, done = false;
    fc_ctx = librustzcash_sapling_verification_ctx_init();
    while (!done && kat_read_line(f, &line, &cap)) {
        ln++;
        kat_tokenize(line, ln, &k);
        if (kat_is(&k, 0, "B"))
            in = kat_is(&k, 2, "rustmade:1s1o");
        else if (in && kat_is(&k, 0, "S")) {
            unsigned char b[7][192];
            kat_hexn(&k, 1, b[0], 32);
            kat_hexn(&k, 2, b[1], 32);
            kat_hexn(&k, 3, b[2], 32);
            kat_hexn(&k, 4, b[3], 32);
            kat_hexn(&k, 5, b[4], 192);
            kat_hexn(&k, 6, b[5], 64);
            kat_hexn(&k, 7, b[6], 32);
            if (!librustzcash_sapling_check_spend(fc_ctx, b[0], b[1], b[2], b[3], b[4], b[5], b[6]))
                die_wrong("final_check setup (spend)");
        } else if (in && kat_is(&k, 0, "O")) {
            unsigned char b[4][192];
            kat_hexn(&k, 1, b[0], 32);
            kat_hexn(&k, 2, b[1], 32);
            kat_hexn(&k, 3, b[2], 32);
            kat_hexn(&k, 4, b[3], 192);
            if (!librustzcash_sapling_check_output(fc_ctx, b[0], b[1], b[2], b[3]))
                die_wrong("final_check setup (output)");
        } else if (in && kat_is(&k, 0, "F")) {
            fc_vb = kat_i64(&k, 1);
            kat_hexn(&k, 2, fc_sig, 64);
            kat_hexn(&k, 3, fc_sh, 32);
            done = true;
        }
        kat_toks_free(&k);
    }
    free(line);
    fclose(f);
    if (!done) {
        fprintf(stderr, "kat_bench: bundle rustmade:1s1o not found\n");
        exit(2);
    }
}

/* ---- ops ---- */
static void op_merkle(void)
{
    unsigned char o[32];
    librustzcash_merkle_hash(mh_depth, mh_a, mh_b, o);
    if (memcmp(o, mh_o, 32))
        die_wrong("merkle_hash");
}
static void op_check_spend(void)
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    bool ok = librustzcash_sapling_check_spend(ctx, cs[0], cs[1], cs[2], cs[3], cs[4], cs[5], cs[6]);
    librustzcash_sapling_verification_ctx_free(ctx);
    if (!ok)
        die_wrong("check_spend");
}
static void op_check_output(void)
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    bool ok = librustzcash_sapling_check_output(ctx, co[0], co[1], co[2], co[3]);
    librustzcash_sapling_verification_ctx_free(ctx);
    if (!ok)
        die_wrong("check_output");
}
static void op_final_check(void)
{
    if (!librustzcash_sapling_final_check(fc_ctx, fc_vb, fc_sig, fc_sh))
        die_wrong("final_check");
}
static void op_sprout_verify(void)
{
    if (!librustzcash_sprout_verify(sv_p, sv_f[0], sv_f[1], sv_f[2], sv_f[3], sv_f[4], sv_f[5], sv_f[6], sv_f[7], sv_vo,
                                    sv_vn))
        die_wrong("sprout_verify");
}
static void op_compute_cm(void)
{
    unsigned char o[32];
    if (!librustzcash_sapling_compute_cm(cm_d, cm_pk, cm_v, cm_r, o) || memcmp(o, cm_o, 32))
        die_wrong("compute_cm");
}
static void op_ivk_to_pkd(void)
{
    unsigned char o[32];
    if (!librustzcash_ivk_to_pkd(ip_ivk, ip_d, o) || memcmp(o, ip_o, 32))
        die_wrong("ivk_to_pkd");
}
static void op_ka_agree(void)
{
    unsigned char o[32];
    if (!librustzcash_sapling_ka_agree(ka_p, ka_s, o) || memcmp(o, ka_o, 32))
        die_wrong("ka_agree");
}
static void op_sprout_prove(void)
{
    const KatToks *k = &spv_k;
    unsigned char pr[192], phi[32], rt[32], hs[32], sk1[32], rho1[32], r1[32], a1[966], sk2[32], rho2[32], r2[32], a2[966];
    unsigned char pk1[32], or1[32], pk2[32], or2[32], f[6][32];
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
    for (int j = 0; j < 6; j++)
        kat_hexn(k, 26 + j, f[j], 32);
    librustzcash_sprout_prove(pr, phi, rt, hs, sk1, kat_u64(k, 7), rho1, r1, a1, sk2, kat_u64(k, 12), rho2, r2, a2, pk1,
                              kat_u64(k, 17), or1, pk2, kat_u64(k, 20), or2, kat_u64(k, 22), kat_u64(k, 23));
    /* derived order nf1 nf2 mac1 mac2 cm1 cm2; ABI order mac1 mac2 nf1 nf2 cm1 cm2 */
    if (!librustzcash_sprout_verify(pr, rt, hs, f[2], f[3], f[0], f[1], f[4], f[5], kat_u64(k, 22), kat_u64(k, 23)))
        die_wrong("sprout_prove");
}
static void op_spend_proof(void)
{
    unsigned char cv[32], rk[32], pr[192];
    void *ctx = librustzcash_sapling_proving_ctx_init();
    bool ok = librustzcash_sapling_spend_proof(ctx, sp_ak, sp_nsk, sp_d, sp_rcm, sp_ar, sp_v, sp_an, sp_w, cv, rk, pr);
    librustzcash_sapling_proving_ctx_free(ctx);
    if (!ok)
        die_wrong("spend_proof");
}
static void op_output_proof(void)
{
    unsigned char cv[32], pr[192];
    void *ctx = librustzcash_sapling_proving_ctx_init();
    bool ok = librustzcash_sapling_output_proof(ctx, op_esk, op_d, op_pk, op_rcm, op_v, cv, pr);
    librustzcash_sapling_proving_ctx_free(ctx);
    if (!ok)
        die_wrong("output_proof");
}

static const struct {
    const char *name;
    void (*fn)(void);
    int inner;
} OPS[] = {
    {"merkle_hash", op_merkle, 200},       {"check_spend", op_check_spend, 10},
    {"check_output", op_check_output, 10}, {"final_check", op_final_check, 20},
    {"sprout_verify", op_sprout_verify, 10}, {"compute_cm", op_compute_cm, 50},
    {"ivk_to_pkd", op_ivk_to_pkd, 50},     {"ka_agree", op_ka_agree, 50},
    {"sprout_prove", op_sprout_prove, 1},
    {"spend_proof", op_spend_proof, 1},    {"output_proof", op_output_proof, 1},
};

static int cmpd(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void loadavg(const char *when)
{
#if defined(__linux__)
    FILE *f = fopen("/proc/loadavg", "r");
    char buf[128] = "";
    if (f) {
        if (!fgets(buf, sizeof buf, f))
            buf[0] = 0;
        fclose(f);
    }
    size_t n = strlen(buf);
    if (n && buf[n - 1] == '\n')
        buf[n - 1] = 0;
    printf("# loadavg %s: %s\n", when, buf);
#else
    (void)when;
#endif
}

int main(int argc, char **argv)
{
    const char *params = NULL, *only = NULL, *label =
#ifdef KAT_RUST
                                                  "rust";
#else
                                                  "c23";
#endif
    int runs = 21;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dir") && i + 1 < argc)
            g_dir = argv[++i];
        else if (!strcmp(argv[i], "--params") && i + 1 < argc)
            params = argv[++i];
        else if (!strcmp(argv[i], "--runs") && i + 1 < argc)
            runs = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--only") && i + 1 < argc)
            only = argv[++i];
#ifndef KAT_RUST
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc)
            groth16_prover_set_threads((unsigned)atoi(argv[++i]));
#endif
        else if (!strcmp(argv[i], "--label") && i + 1 < argc)
            label = argv[++i];
        else {
            fprintf(stderr, "usage: kat_bench --dir <c23_golden> --params <dir> [--runs N] [--only op[,op]]\n");
            return 2;
        }
    }
    if (!g_dir || !params || runs < 1 || runs > 1000) {
        fprintf(stderr, "usage: kat_bench --dir <c23_golden> --params <dir> [--runs N] [--only op[,op]]\n");
        return 2;
    }
    double t0 = kat_now();
    kat_init_canonical(params);
    printf("# %s init_zksnark_params %.3f s\n", label, kat_now() - t0);
    load_inputs();
    loadavg("start");
    printf("# lib op median_us min_us max_us runs inner\n");
    double *v = kat_xmalloc((size_t)runs * sizeof(double));
    for (size_t o = 0; o < sizeof OPS / sizeof OPS[0]; o++) {
        if (only) {
            const char *p = strstr(only, OPS[o].name);
            size_t nl = strlen(OPS[o].name);
            if (!p || (p != only && p[-1] != ',') || (p[nl] != 0 && p[nl] != ','))
                continue;
        }
        OPS[o].fn(); /* warm-up (first proof loads keys) */
        for (int r = 0; r < runs; r++) {
            double s = kat_now();
            for (int i = 0; i < OPS[o].inner; i++)
                OPS[o].fn();
            v[r] = (kat_now() - s) / OPS[o].inner;
        }
        qsort(v, (size_t)runs, sizeof(double), cmpd);
        printf("%s %s %.1f %.1f %.1f %d %d\n", label, OPS[o].name, v[runs / 2] * 1e6, v[0] * 1e6, v[runs - 1] * 1e6,
               runs, OPS[o].inner);
        fflush(stdout);
    }
    loadavg("end");
    free(v);
    librustzcash_sapling_verification_ctx_free(fc_ctx);
    return 0;
}
