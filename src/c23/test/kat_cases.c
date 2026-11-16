/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). kat_cases: runs a case file through whichever
 * librustzcash ABI it is linked with and prints one result per case. Built
 * twice from this one source:
 *   kat_cases       linked with the C23 shim (src/c23/compat)
 *   kat_cases_rust  linked with the Rust librustzcash.a (build host only)
 * so the Rust output is the expected output of the C23 run.
 *
 *   kat_cases --cases <file> --params <dir> [--pdir <dir>]      run, print results
 *   kat_cases --compare <cases> <expected> <actual>              diff two result files
 *
 * Case file (one case per line; '#' comments):
 *   <id> <mode> <fn> <label> <args...>
 * mode: '-' in this process after init; 'x' in a child process after init;
 *       'n' in a child process WITHOUT init (pre-init and init cases).
 * A child that dies from abort() prints "ABORT"; another signal "CRASH:<n>".
 * Bundles: "<id> <mode> vbundle <label> <n>" or "... pbundle <label> <n>",
 * followed by exactly n step lines (S/O/F for vbundle, PS/PO/SS/PB for
 * pbundle) in the column order of src/test/data/c23_golden/FORMAT.md.
 * Results: "<id> <result>". Byte outputs of deterministic functions are part
 * of the result; randomized functions print verdicts (and deterministic
 * by-products) only. */
#include "kat_common.h"

#include <stdlib.h>
#include <string.h>

static const char *g_params, *g_pdir;

typedef struct {
    char **lines;
    size_t n;
} Lines;

static Lines load_lines(const char *path)
{
    Lines L = {NULL, 0};
    size_t cap = 0;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    char *buf = NULL;
    size_t bcap = 0;
    while (kat_read_line(f, &buf, &bcap)) {
        if (L.n == cap) {
            cap = cap ? 2 * cap : 256;
            char **nl = realloc(L.lines, cap * sizeof(char *));
            if (!nl) {
                fprintf(stderr, "out of memory\n");
                exit(2);
            }
            L.lines = nl;
        }
        size_t len = strlen(buf);
        L.lines[L.n] = kat_xmalloc(len + 1);
        memcpy(L.lines[L.n], buf, len + 1);
        L.n++;
    }
    free(buf);
    if (ferror(f)) {
        fprintf(stderr, "read error on %s\n", path);
        exit(2);
    }
    fclose(f);
    return L;
}

static void free_lines(Lines *L)
{
    for (size_t i = 0; i < L->n; i++)
        free(L->lines[i]);
    free(L->lines);
    L->lines = NULL;
    L->n = 0;
}

static bool skip_line(const char *s) { return s[0] == '#' || s[0] == '\n' || s[0] == '\r' || s[0] == 0; }

/* --------------------------------------------------------------- output */

static char g_out[4096];
static size_t g_outn;
static void out_reset(void)
{
    g_outn = 0;
    g_out[0] = 0;
}
static void out_s(const char *s)
{
    size_t n = strlen(s);
    if (g_outn + n + 2 >= sizeof g_out) {
        fprintf(stderr, "result too long\n");
        exit(2);
    }
    if (g_outn)
        g_out[g_outn++] = ' ';
    memcpy(g_out + g_outn, s, n + 1);
    g_outn += n;
}
static void out_hex(const unsigned char *b, size_t n)
{
    char h[2 * 256 + 1];
    if (n > 256) {
        fprintf(stderr, "out_hex too long\n");
        exit(2);
    }
    kat_tohex(h, b, n);
    out_s(h);
}
static void out_cat(const char *s) /* append without a separating space */
{
    size_t n = strlen(s);
    if (g_outn + n + 1 >= sizeof g_out) {
        fprintf(stderr, "result too long\n");
        exit(2);
    }
    memcpy(g_out + g_outn, s, n + 1);
    g_outn += n;
}

/* --------------------------------------------------------------- calls */

#define A 4 /* first argument column */

static void hash_arg(const KatToks *k, int i, char *out, size_t cap)
{
    const char *s = k->t[i];
    if (strncmp(s, "hex:", 4) == 0) {
        size_t n = strlen(s + 4) / 2;
        if (n + 1 > cap || !kat_parse_hex(s + 4, (unsigned char *)out, n)) {
            fprintf(stderr, "%s:%lu: bad hex: hash\n", kat_cur_file, k->lineno);
            exit(2);
        }
        out[n] = 0;
    } else {
        if (strlen(s) + 1 > cap) {
            fprintf(stderr, "hash too long\n");
            exit(2);
        }
        strcpy(out, s);
    }
}

static const char *name_arg(const KatToks *k, int i) { return strcmp(k->t[i], "~") == 0 ? "" : k->t[i]; }

static bool run_single(const KatToks *k)
{
    const char *fn = k->t[2];
    unsigned char a[1100], b[1100], c[64], d[64], e[64], f[64], g[192], h[64], o[256], o2[64];
#define IS(x) (strcmp(fn, x) == 0)
    if (IS("to_scalar")) {
        kat_hexn(k, A, a, 64);
        librustzcash_to_scalar(a, o);
        out_s("OK");
        out_hex(o, 32);
    } else if (IS("ask_to_ak") || IS("nsk_to_nk")) {
        kat_hexn(k, A, a, 32);
        if (IS("ask_to_ak"))
            librustzcash_ask_to_ak(a, o);
        else
            librustzcash_nsk_to_nk(a, o);
        out_s("OK");
        out_hex(o, 32);
    } else if (IS("crh_ivk")) {
        kat_hexn(k, A, a, 32);
        kat_hexn(k, A + 1, b, 32);
        librustzcash_crh_ivk(a, b, o);
        out_s("OK");
        out_hex(o, 32);
    } else if (IS("check_diversifier")) {
        kat_hexn(k, A, a, 11);
        out_s(kat_tf(librustzcash_check_diversifier(a)));
    } else if (IS("ivk_to_pkd")) {
        kat_hexn(k, A, a, 32);
        kat_hexn(k, A + 1, b, 11);
        bool ok = librustzcash_ivk_to_pkd(a, b, o);
        out_s(kat_tf(ok));
        if (ok)
            out_hex(o, 32);
    } else if (IS("tree_uncommitted")) {
        librustzcash_tree_uncommitted(o);
        out_s("OK");
        out_hex(o, 32);
    } else if (IS("merkle_hash")) {
        kat_hexn(k, A + 1, a, 32);
        kat_hexn(k, A + 2, b, 32);
        librustzcash_merkle_hash((size_t)kat_u64(k, A), a, b, o);
        out_s("OK");
        out_hex(o, 32);
    } else if (IS("compute_cm")) {
        kat_hexn(k, A, a, 11);
        kat_hexn(k, A + 1, b, 32);
        kat_hexn(k, A + 3, c, 32);
        bool ok = librustzcash_sapling_compute_cm(a, b, kat_u64(k, A + 2), c, o);
        out_s(kat_tf(ok));
        if (ok)
            out_hex(o, 32);
    } else if (IS("compute_nf")) {
        kat_hexn(k, A, a, 11);
        kat_hexn(k, A + 1, b, 32);
        kat_hexn(k, A + 3, c, 32);
        kat_hexn(k, A + 4, d, 32);
        kat_hexn(k, A + 5, e, 32);
        bool ok = librustzcash_sapling_compute_nf(a, b, kat_u64(k, A + 2), c, d, e, kat_u64(k, A + 6), o);
        out_s(kat_tf(ok));
        if (ok)
            out_hex(o, 32);
    } else if (IS("ka_agree")) {
        kat_hexn(k, A, a, 32);
        kat_hexn(k, A + 1, b, 32);
        bool ok = librustzcash_sapling_ka_agree(a, b, o);
        out_s(kat_tf(ok));
        if (ok)
            out_hex(o, 32);
    } else if (IS("ka_derivepublic")) {
        kat_hexn(k, A, a, 11);
        kat_hexn(k, A + 1, b, 32);
        bool ok = librustzcash_sapling_ka_derivepublic(a, b, o);
        out_s(kat_tf(ok));
        if (ok)
            out_hex(o, 32);
    } else if (IS("xsk_master")) {
        size_t n = (size_t)kat_u64(k, A);
        if (n > sizeof a) {
            fprintf(stderr, "seed too long\n");
            exit(2);
        }
        if (n)
            kat_hexn(k, A + 1, a, n);
        librustzcash_zip32_xsk_master(a, n, o);
        out_s("OK");
        out_hex(o, 169);
    } else if (IS("xsk_derive") || IS("xfvk_derive")) {
        kat_hexn(k, A, a, 169);
        uint32_t i = (uint32_t)kat_u64(k, A + 1);
        if (IS("xsk_derive")) {
            librustzcash_zip32_xsk_derive(a, i, o);
            out_s("OK");
            out_hex(o, 169);
        } else {
            bool ok = librustzcash_zip32_xfvk_derive(a, i, o);
            out_s(kat_tf(ok));
            if (ok)
                out_hex(o, 169);
        }
    } else if (IS("xfvk_address")) {
        kat_hexn(k, A, a, 169);
        kat_hexn(k, A + 1, b, 11);
        bool ok = librustzcash_zip32_xfvk_address(a, b, o2, o);
        out_s(kat_tf(ok));
        if (ok) {
            out_hex(o2, 11);
            out_hex(o, 43);
        }
    } else if (IS("spend_sig")) {
        kat_hexn(k, A, a, 32);
        kat_hexn(k, A + 1, b, 32);
        kat_hexn(k, A + 2, c, 32);
        out_s(kat_tf(librustzcash_sapling_spend_sig(a, b, c, o)));
    } else if (IS("check_spend")) {
        kat_hexn(k, A, a, 32);
        kat_hexn(k, A + 1, b, 32);
        kat_hexn(k, A + 2, c, 32);
        kat_hexn(k, A + 3, d, 32);
        kat_hexn(k, A + 4, g, 192);
        kat_hexn(k, A + 5, h, 64);
        kat_hexn(k, A + 6, e, 32);
        void *ctx = librustzcash_sapling_verification_ctx_init();
        out_s(kat_tf(librustzcash_sapling_check_spend(ctx, a, b, c, d, g, h, e)));
        librustzcash_sapling_verification_ctx_free(ctx);
    } else if (IS("check_output")) {
        kat_hexn(k, A, a, 32);
        kat_hexn(k, A + 1, b, 32);
        kat_hexn(k, A + 2, c, 32);
        kat_hexn(k, A + 3, g, 192);
        void *ctx = librustzcash_sapling_verification_ctx_init();
        out_s(kat_tf(librustzcash_sapling_check_output(ctx, a, b, c, g)));
        librustzcash_sapling_verification_ctx_free(ctx);
    } else if (IS("sprout_verify")) {
        unsigned char f8[8][32];
        kat_hexn(k, A, g, 192);
        for (int j = 0; j < 8; j++)
            kat_hexn(k, A + 1 + j, f8[j], 32);
        out_s(kat_tf(librustzcash_sprout_verify(g, f8[0], f8[1], f8[2], f8[3], f8[4], f8[5], f8[6], f8[7],
                                                kat_u64(k, A + 9), kat_u64(k, A + 10))));
    } else if (IS("final_check_fresh")) {
        kat_hexn(k, A + 1, h, 64);
        kat_hexn(k, A + 2, e, 32);
        void *ctx = librustzcash_sapling_verification_ctx_init();
        out_s(kat_tf(librustzcash_sapling_final_check(ctx, kat_i64(k, A), h, e)));
        librustzcash_sapling_verification_ctx_free(ctx);
    } else if (IS("generate_r")) {
        librustzcash_sapling_generate_r(o);
        static const unsigned char R[32] = {0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8,
                                            0xcc, 0x93, 0x20, 0x68, 0xa6, 0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b,
                                            0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e};
        bool lt = false;
        for (int i = 31; i >= 0; i--)
            if (o[i] != R[i]) {
                lt = o[i] < R[i];
                break;
            }
        out_s("OK");
        out_s(kat_tf(lt));
    } else if (IS("init")) {
        char sh[256], oh[256], gh[256];
        hash_arg(k, A + 1, sh, sizeof sh);
        hash_arg(k, A + 3, oh, sizeof oh);
        hash_arg(k, A + 5, gh, sizeof gh);
        kat_init_params(g_pdir, name_arg(k, A), sh, name_arg(k, A + 2), oh, name_arg(k, A + 4), gh);
        out_s("OK");
    } else if (IS("output_proof") || IS("init_prove_output")) {
        int B = A;
        if (IS("init_prove_output")) {
            /* init from the 6 init columns, then one output proof */
            char sh[256], oh[256], gh[256];
            hash_arg(k, A + 1, sh, sizeof sh);
            hash_arg(k, A + 3, oh, sizeof oh);
            hash_arg(k, A + 5, gh, sizeof gh);
            kat_init_params(g_pdir, name_arg(k, A), sh, name_arg(k, A + 2), oh, name_arg(k, A + 4), gh);
            out_s("OK");
            B = A + 6;
        }
        kat_hexn(k, B, a, 32);
        kat_hexn(k, B + 1, b, 11);
        kat_hexn(k, B + 2, c, 32);
        kat_hexn(k, B + 3, d, 32);
        uint64_t v = kat_u64(k, B + 4);
        void *ctx = librustzcash_sapling_proving_ctx_init();
        bool ok = librustzcash_sapling_output_proof(ctx, a, b, c, d, v, e, g);
        librustzcash_sapling_proving_ctx_free(ctx);
        out_s(kat_tf(ok));
        if (ok) {
            unsigned char cm[32], epk[32];
            bool dv = librustzcash_sapling_compute_cm(b, c, v, d, cm) && librustzcash_sapling_ka_derivepublic(b, a, epk);
            void *vc = librustzcash_sapling_verification_ctx_init();
            bool vok = dv && librustzcash_sapling_check_output(vc, e, cm, epk, g);
            librustzcash_sapling_verification_ctx_free(vc);
            out_cat(":");
            out_cat(kat_tf(vok));
        }
    } else if (IS("spend_proof")) {
        unsigned char w[1065], rk[32];
        kat_hexn(k, A, a, 32);
        kat_hexn(k, A + 1, b, 32);
        kat_hexn(k, A + 2, c, 11);
        kat_hexn(k, A + 3, d, 32);
        kat_hexn(k, A + 4, e, 32);
        kat_hexn(k, A + 6, f, 32);
        kat_hexn(k, A + 7, w, 1065);
        void *ctx = librustzcash_sapling_proving_ctx_init();
        bool ok = librustzcash_sapling_spend_proof(ctx, a, b, c, d, e, kat_u64(k, A + 5), f, w, h, rk, g);
        librustzcash_sapling_proving_ctx_free(ctx);
        out_s(kat_tf(ok));
        if (ok)
            out_hex(rk, 32);
    } else {
        return false;
    }
#undef IS
    return true;
}

static void run_vbundle(const KatToks *hd, const KatToks *steps, int n)
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    char s[128];
    int m = 0;
    bool all = true;
    for (int i = 0; i < n; i++) {
        const KatToks *k = &steps[i];
        bool ok;
        if (kat_is(k, 0, "S")) {
            unsigned char cv[32], an[32], nf[32], rk[32], pr[192], sig[64], sh[32];
            kat_hexn(k, 1, cv, 32);
            kat_hexn(k, 2, an, 32);
            kat_hexn(k, 3, nf, 32);
            kat_hexn(k, 4, rk, 32);
            kat_hexn(k, 5, pr, 192);
            kat_hexn(k, 6, sig, 64);
            kat_hexn(k, 7, sh, 32);
            ok = librustzcash_sapling_check_spend(ctx, cv, an, nf, rk, pr, sig, sh);
        } else if (kat_is(k, 0, "O")) {
            unsigned char cv[32], cm[32], epk[32], pr[192];
            kat_hexn(k, 1, cv, 32);
            kat_hexn(k, 2, cm, 32);
            kat_hexn(k, 3, epk, 32);
            kat_hexn(k, 4, pr, 192);
            ok = librustzcash_sapling_check_output(ctx, cv, cm, epk, pr);
        } else if (kat_is(k, 0, "F")) {
            unsigned char sig[64], sh[32];
            kat_hexn(k, 2, sig, 64);
            kat_hexn(k, 3, sh, 32);
            ok = librustzcash_sapling_final_check(ctx, kat_i64(k, 1), sig, sh);
        } else {
            fprintf(stderr, "%s:%lu: bad vbundle step\n", kat_cur_file, k->lineno);
            exit(2);
        }
        all = all && ok;
        if (m < (int)sizeof s - 1)
            s[m++] = ok ? 'T' : 'F';
    }
    s[m] = 0;
    librustzcash_sapling_verification_ctx_free(ctx);
    (void)hd;
    out_s(kat_tf(all));
    out_cat(":");
    out_cat(s);
}

enum { MAXD = 8 };
static void run_pbundle(const KatToks *hd, const KatToks *steps, int n)
{
    (void)hd;
    void *ctx = librustzcash_sapling_proving_ctx_init();
    unsigned char scv[MAXD][32], srk[MAXD][32], spr[MAXD][192], san[MAXD][32], snf[MAXD][32], ssig[MAXD][64];
    unsigned char ocv[MAXD][32], opr[MAXD][192], ocm[MAXD][32], oepk[MAXD][32], sh[32] = {0}, bsig[64];
    int ns = 0, no = 0, nss = 0, m = 0;
    bool all = true, have_b = false;
    int64_t vb = 0;
    char s[128];
    for (int i = 0; i < n; i++) {
        const KatToks *k = &steps[i];
        bool ok;
        if (kat_is(k, 0, "PS") && ns < MAXD) {
            unsigned char ak[32], nsk[32], dd[11], rcm[32], ar[32], w[1065], nk[32], ivk[32], pkd[32];
            kat_hexn(k, 1, ak, 32);
            kat_hexn(k, 2, nsk, 32);
            kat_hexn(k, 3, dd, 11);
            kat_hexn(k, 4, rcm, 32);
            kat_hexn(k, 5, ar, 32);
            kat_hexn(k, 7, san[ns], 32);
            kat_hexn(k, 8, w, 1065);
            ok = librustzcash_sapling_spend_proof(ctx, ak, nsk, dd, rcm, ar, kat_u64(k, 6), san[ns], w, scv[ns],
                                                  srk[ns], spr[ns]);
            if (ok) {
                uint64_t pos = 0;
                for (int j = 0; j < 8; j++)
                    pos |= (uint64_t)w[1057 + j] << (8 * j);
                librustzcash_nsk_to_nk(nsk, nk);
                librustzcash_crh_ivk(ak, nk, ivk);
                if (!librustzcash_ivk_to_pkd(ivk, dd, pkd) ||
                    !librustzcash_sapling_compute_nf(dd, pkd, kat_u64(k, 6), rcm, ak, nk, pos, snf[ns]))
                    memset(snf[ns], 0, 32);
            }
            ns++;
        } else if (kat_is(k, 0, "PO") && no < MAXD) {
            unsigned char esk[32], dd[11], pkd[32], rcm[32];
            kat_hexn(k, 1, esk, 32);
            kat_hexn(k, 2, dd, 11);
            kat_hexn(k, 3, pkd, 32);
            kat_hexn(k, 4, rcm, 32);
            ok = librustzcash_sapling_output_proof(ctx, esk, dd, pkd, rcm, kat_u64(k, 5), ocv[no], opr[no]);
            if (ok && (!librustzcash_sapling_compute_cm(dd, pkd, kat_u64(k, 5), rcm, ocm[no]) ||
                       !librustzcash_sapling_ka_derivepublic(dd, esk, oepk[no])))
                memset(ocm[no], 0, 32);
            no++;
        } else if (kat_is(k, 0, "SS") && nss < MAXD) {
            unsigned char ask[32], ar[32];
            kat_hexn(k, 1, ask, 32);
            kat_hexn(k, 2, ar, 32);
            kat_hexn(k, 3, sh, 32);
            ok = librustzcash_sapling_spend_sig(ask, ar, sh, ssig[nss]);
            nss++;
        } else if (kat_is(k, 0, "PB")) {
            vb = kat_i64(k, 1);
            kat_hexn(k, 2, sh, 32);
            ok = librustzcash_sapling_binding_sig(ctx, vb, sh, bsig);
            have_b = have_b || ok;
        } else {
            fprintf(stderr, "%s:%lu: bad pbundle step\n", kat_cur_file, k->lineno);
            exit(2);
        }
        all = all && ok;
        if (m < (int)sizeof s - 1)
            s[m++] = ok ? 'T' : 'F';
    }
    s[m] = 0;
    librustzcash_sapling_proving_ctx_free(ctx);
    out_s(s);
    if (!all || !have_b || nss != ns) {
        out_cat(":-");
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
    out_cat(":");
    out_cat(kat_tf(vok));
}

/* ---------------------------------------------------------------- driver */

static Lines g_L;
struct case_arg {
    size_t idx; /* index of the header line in g_L */
    bool init;  /* child must init first (mode x) */
};

static void run_case(size_t idx)
{
    KatToks k;
    kat_tokenize(g_L.lines[idx], idx + 1, &k);
    out_reset();
    if (kat_is(&k, 2, "vbundle") || kat_is(&k, 2, "pbundle")) {
        int n = (int)kat_u64(&k, 4);
        if (n < 1 || n > 64 || idx + (size_t)n >= g_L.n) {
            fprintf(stderr, "%s:%zu: bad bundle step count\n", kat_cur_file, idx + 1);
            exit(2);
        }
        KatToks steps[64];
        for (int i = 0; i < n; i++)
            kat_tokenize(g_L.lines[idx + 1 + (size_t)i], idx + 2 + (size_t)i, &steps[i]);
        if (kat_is(&k, 2, "vbundle"))
            run_vbundle(&k, steps, n);
        else
            run_pbundle(&k, steps, n);
        for (int i = 0; i < n; i++)
            kat_toks_free(&steps[i]);
    } else if (!run_single(&k)) {
        fprintf(stderr, "%s:%zu: unknown function %s\n", kat_cur_file, idx + 1, k.t[2]);
        exit(2);
    }
    printf("%s %s\n", k.t[0], g_out);
    fflush(stdout);
    kat_toks_free(&k);
}

static void child_trampoline(void *p)
{
    struct case_arg *a = p;
    if (a->init)
        kat_init_canonical(g_params);
    run_case(a->idx);
}

static int run_cases(const char *path)
{
    kat_cur_file = path;
    g_L = load_lines(path);
    bool inited = false;
    if (kat_in_child()) {
        size_t idx = kat_child_line() - 1;
        if (idx >= g_L.n)
            return 99;
        KatToks k;
        kat_tokenize(g_L.lines[idx], idx + 1, &k);
        struct case_arg a = {idx, kat_is(&k, 1, "x")};
        kat_toks_free(&k);
        long det;
        kat_isolate(path, idx + 1, child_trampoline, &a, &det); /* runs and exits */
        return 99;
    }
    double t0 = kat_now();
    unsigned long ncases = 0;
    for (size_t i = 0; i < g_L.n; i++) {
        if (skip_line(g_L.lines[i]))
            continue;
        KatToks k;
        kat_tokenize(g_L.lines[i], i + 1, &k);
        if (k.n < 4) {
            fprintf(stderr, "%s:%zu: short case line\n", path, i + 1);
            exit(2);
        }
        size_t nsteps = 0;
        if (kat_is(&k, 2, "vbundle") || kat_is(&k, 2, "pbundle"))
            nsteps = (size_t)kat_u64(&k, 4);
        ncases++;
        if (kat_is(&k, 1, "-")) {
            if (!inited) {
                kat_init_canonical(g_params);
                inited = true;
            }
            run_case(i);
        } else if (kat_is(&k, 1, "x") || kat_is(&k, 1, "n")) {
            struct case_arg a = {i, kat_is(&k, 1, "x") && !inited};
#if defined(_WIN32)
            a.init = kat_is(&k, 1, "x");
#else
            /* fork inherits this process's init state: an 'n' case needs a
             * process that never initialized, so 'n' cases must come first. */
            if (kat_is(&k, 1, "n") && inited) {
                fprintf(stderr, "%s:%zu: mode n after an initialized case (put n cases first)\n", path, i + 1);
                exit(2);
            }
#endif
            long det = 0;
            enum kat_child c = kat_isolate(path, i + 1, child_trampoline, &a, &det);
            if (c == KAT_CHILD_ABORTED)
                printf("%s ABORT\n", k.t[0]);
            else if (c == KAT_CHILD_CRASHED)
                printf("%s CRASH:%ld\n", k.t[0], det);
            else if (c == KAT_CHILD_ERROR)
                printf("%s CHILDERR:%ld\n", k.t[0], det);
            fflush(stdout);
        } else {
            fprintf(stderr, "%s:%zu: bad mode %s\n", path, i + 1, k.t[1]);
            exit(2);
        }
        kat_toks_free(&k);
        i += nsteps;
    }
    fprintf(stderr, "kat_cases: %lu cases in %.1fs\n", ncases, kat_now() - t0);
    free_lines(&g_L);
    return 0;
}

/* ---------------------------------------------------------------- compare */

typedef struct {
    char *id, *val;
} KV;
static int load_results(const char *path, KV **out, Lines *keep)
{
    Lines L = load_lines(path);
    *keep = L;
    KV *kv = kat_xmalloc((L.n + 1) * sizeof(KV));
    int n = 0;
    for (size_t i = 0; i < L.n; i++) {
        char *s = L.lines[i];
        size_t len = strlen(s);
        while (len && (s[len - 1] == '\n' || s[len - 1] == '\r'))
            s[--len] = 0;
        if (skip_line(s))
            continue;
        char *sp = strchr(s, ' ');
        if (!sp) {
            fprintf(stderr, "%s:%zu: malformed result line\n", path, i + 1);
            exit(2);
        }
        *sp = 0;
        kv[n].id = s;
        kv[n].val = sp + 1;
        n++;
    }
    *out = kv;
    return n;
}
static const char *find(KV *kv, int n, const char *id)
{
    for (int i = 0; i < n; i++)
        if (!strcmp(kv[i].id, id))
            return kv[i].val;
    return NULL;
}
static bool val_eq(const char *exp, const char *act)
{
    if (!strcmp(exp, act))
        return true;
    /* "T" expected against "T:steps" (an AND verdict) */
    const char *colon = strchr(act, ':');
    if (!strchr(exp, ':') && colon && strlen(exp) == (size_t)(colon - act) && !strncmp(exp, act, (size_t)(colon - act)))
        return true;
    return false;
}

static int compare(const char *cases, const char *expected, const char *actual)
{
    Lines C = load_lines(cases);
    KV *e, *a;
    Lines le, la;
    int ne = load_results(expected, &e, &le), na = load_results(actual, &a, &la);
    int mism = 0, match = 0;
    for (size_t i = 0; i < C.n; i++) {
        if (skip_line(C.lines[i]))
            continue;
        KatToks k;
        kat_tokenize(C.lines[i], i + 1, &k);
        if (k.n < 4) {
            kat_toks_free(&k);
            continue;
        }
        size_t nsteps = (kat_is(&k, 2, "vbundle") || kat_is(&k, 2, "pbundle")) ? (size_t)kat_u64(&k, 4) : 0;
        const char *ev = find(e, ne, k.t[0]), *av = find(a, na, k.t[0]);
        if (!ev) {
            fprintf(stderr, "no expected result for case %s\n", k.t[0]);
            exit(2);
        }
        if (av && val_eq(ev, av)) {
            match++;
        } else {
            mism++;
            char in[160] = "";
            for (int j = 4; j < k.n && strlen(in) < 100; j++) {
                strncat(in, k.t[j], 40);
                if (strlen(k.t[j]) > 40)
                    strcat(in, "..");
                strcat(in, " ");
            }
            printf("MISMATCH id=%s fn=%s label=%s input=[%s] expected(rust)=%s actual(c23)=%s\n", k.t[0], k.t[2],
                   k.t[3], in, ev, av ? av : "(missing)");
        }
        kat_toks_free(&k);
        i += nsteps;
    }
    printf("COMPARE cases=%d match=%d mismatch=%d\n", match + mism, match, mism);
    free_lines(&C);
    free_lines(&le);
    free_lines(&la);
    free(e);
    free(a);
    return mism ? 1 : 0;
}

int main(int argc, char **argv)
{
    kat_isolation_setup(argc, argv);
    const char *cases = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--compare") && i + 3 < argc)
            return compare(argv[i + 1], argv[i + 2], argv[i + 3]);
        else if (!strcmp(argv[i], "--cases") && i + 1 < argc)
            cases = argv[++i];
        else if (!strcmp(argv[i], "--params") && i + 1 < argc)
            g_params = argv[++i];
        else if (!strcmp(argv[i], "--pdir") && i + 1 < argc)
            g_pdir = argv[++i];
        else {
            fprintf(stderr, "usage: kat_cases --cases <file> --params <dir> [--pdir <dir>]\n"
                            "       kat_cases --compare <cases> <expected> <actual>\n");
            return 2;
        }
    }
    if (!cases || !g_params) {
        fprintf(stderr, "usage: kat_cases --cases <file> --params <dir> [--pdir <dir>]\n");
        return 2;
    }
    if (!g_pdir)
        g_pdir = g_params;
    return run_cases(cases);
}
