/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). kat_mutgen: writes vectors/mutations.cases, the
 * mutation cases that are NOT in the Rust golden corpus. They were derived
 * independently from rustzcash.rs (and the sapling-crypto / bellman / pairing
 * sources it calls) at librustzcash 06da3b9a; the expected result of every case
 * is whatever the real Rust library returns (kat_cases_rust on the build host,
 * stored as vectors/mutations.rust.out), never a value reasoned out here.
 *
 *   kat_mutgen --golden <c23_golden> --out <file>
 *
 * Output is deterministic (no randomness): nonces come from to_scalar of fixed
 * byte strings. Groups (see the label prefix of each case):
 *   preinit:  calls before librustzcash_init_zksnark_params (mode n)
 *   init:     parameter files with right size but wrong content, truncated
 *             files, invalid UTF-8 hash strings, empty path, directory path
 *   rjsig:    spend_auth_sig re-signed with the real rsk of a Rust-made spend,
 *             with R = [n]G + torsion, R = torsion, R = x0s1 identity, R with a
 *             non-canonical y+q encoding (cofactored-verification and
 *             point-decoding rules of redjubjub.rs + edwards.rs)
 *   bsig:     binding signatures on an empty context (bvk = identity, bsk = 0),
 *             same R variants
 *   xp:       Groth16 proof points with a non-canonical x+p coordinate encoding
 *             (pairing ec.rs from_compressed: Fq::from_repr must fail) in slot
 *             A, B.c1, B.c0 and C of every valid Sapling spend/output and Sprout
 *             proof in the corpus
 *   yq:       Jubjub points cv/rk/epk of every valid description, and ka_agree
 *             / compute_nf / xfvk inputs, re-encoded with y+q (edwards.rs read:
 *             Fr::from_repr must fail)
 *   order:    final_check twice, final_check before the descriptions, binding_sig
 *             twice, spend_sig with rsk = 0, compute_nf with large positions,
 *             output_proof with value 2^64-1 */
#include "kat_common.h"
#include "kat_jub.h"

#include <stdlib.h>
#include <string.h>

static const char *g_golden;
static FILE *O;
static unsigned g_id;

/* ------------------------------------------------------------ golden I/O */

typedef struct {
    char *name;
    KatToks *t;
    size_t n;
} GFile;
static GFile g_files[16];
static size_t g_nfiles;

static GFile *gfile(const char *name)
{
    for (size_t i = 0; i < g_nfiles; i++)
        if (!strcmp(g_files[i].name, name))
            return &g_files[i];
    if (g_nfiles == sizeof g_files / sizeof g_files[0]) {
        fprintf(stderr, "too many golden files\n");
        exit(2);
    }
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", g_golden, name);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    GFile *g = &g_files[g_nfiles++];
    size_t nm = strlen(name) + 1;
    g->name = kat_xmalloc(nm);
    memcpy(g->name, name, nm);
    g->t = NULL;
    g->n = 0;
    size_t cap = 0, bcap = 0;
    char *buf = NULL;
    unsigned long ln = 0;
    kat_cur_file = name;
    while (kat_read_line(f, &buf, &bcap)) {
        ln++;
        if (buf[0] == '#' || buf[0] == '@' || buf[0] == '\n')
            continue;
        if (g->n == cap) {
            cap = cap ? 2 * cap : 1024;
            KatToks *nt = realloc(g->t, cap * sizeof(KatToks));
            if (!nt) {
                fprintf(stderr, "out of memory\n");
                exit(2);
            }
            g->t = nt;
        }
        kat_tokenize(buf, ln, &g->t[g->n++]);
    }
    free(buf);
    fclose(f);
    return g;
}

static const KatToks *rec_by_label(const char *file, const char *label)
{
    GFile *g = gfile(file);
    for (size_t i = 0; i < g->n; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 2, label))
            return &g->t[i];
    fprintf(stderr, "kat_mutgen: %s has no record %s\n", file, label);
    exit(2);
}

/* Bundle lines [B ... E] with the given label; returns index of B. */
static size_t bundle_by_label(const char *file, const char *label, GFile **out)
{
    GFile *g = gfile(file);
    for (size_t i = 0; i < g->n; i++)
        if (kat_is(&g->t[i], 0, "B") && kat_is(&g->t[i], 2, label)) {
            *out = g;
            return i;
        }
    fprintf(stderr, "kat_mutgen: %s has no bundle %s\n", file, label);
    exit(2);
}

/* ----------------------------------------------------------------- output */

static void head(const char *mode, const char *fn, const char *label)
{
    fprintf(O, "%u %s %s %s", ++g_id, mode, fn, label);
}
static void hx(const unsigned char *b, size_t n)
{
    char *h = kat_xmalloc(2 * n + 1);
    kat_tohex(h, b, n);
    fprintf(O, " %s", h);
    free(h);
}
static void tok(const char *s) { fprintf(O, " %s", s); }
static void endl(void) { fputc('\n', O); }

/* deterministic nonce scalar < r */
static void nonce(unsigned tag, unsigned char n[32])
{
    unsigned char in[64];
    for (int i = 0; i < 64; i++)
        in[i] = (unsigned char)(tag * 131u + (unsigned)i * 29u + 7u);
    librustzcash_to_scalar(in, n);
}

static void must(bool ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "kat_mutgen: %s\n", what);
        exit(2);
    }
}

/* ------------------------------------------------------------ base data */

static unsigned char TOR[8][32]; /* torsion points from the golden labels */

static void load_torsion(void)
{
    for (int k = 0; k < 8; k++) {
        char lab[96];
        snprintf(lab, sizeof lab, "testnet:abbd823c:spend0:mut:sig:R:tor%d", k);
        const KatToks *r = rec_by_label("sapling_check_spend.golden", lab);
        unsigned char sig[64];
        kat_hexn(r, 8, sig, 64);
        memcpy(TOR[k], sig, 32);
    }
}

/* rustmade:1s1o: the Rust-made spend with its real ask/ar from the prove bundle. */
static unsigned char S_cv[32], S_an[32], S_nf[32], S_rk[32], S_pr[192], S_sig[64], S_sh[32], S_rsk[32];
static unsigned char O_cv[32], O_cm[32], O_epk[32], O_pr[192];
static int64_t F_vb;
static unsigned char F_sig[64], F_sh[32];

static void load_rustmade(void)
{
    GFile *g;
    size_t b = bundle_by_label("sapling_final_check.golden", "rustmade:1s1o", &g);
    for (size_t i = b + 1; !kat_is(&g->t[i], 0, "E"); i++) {
        const KatToks *k = &g->t[i];
        if (kat_is(k, 0, "S")) {
            kat_hexn(k, 1, S_cv, 32);
            kat_hexn(k, 2, S_an, 32);
            kat_hexn(k, 3, S_nf, 32);
            kat_hexn(k, 4, S_rk, 32);
            kat_hexn(k, 5, S_pr, 192);
            kat_hexn(k, 6, S_sig, 64);
            kat_hexn(k, 7, S_sh, 32);
        } else if (kat_is(k, 0, "O")) {
            kat_hexn(k, 1, O_cv, 32);
            kat_hexn(k, 2, O_cm, 32);
            kat_hexn(k, 3, O_epk, 32);
            kat_hexn(k, 4, O_pr, 192);
        } else if (kat_is(k, 0, "F")) {
            F_vb = kat_i64(k, 1);
            kat_hexn(k, 2, F_sig, 64);
            kat_hexn(k, 3, F_sh, 32);
        }
    }
    size_t p = bundle_by_label("sapling_binding_sig.golden", "1s1o", &g);
    unsigned char ask[32], ar[32];
    bool have = false;
    for (size_t i = p + 1; !kat_is(&g->t[i], 0, "E"); i++)
        if (kat_is(&g->t[i], 0, "SS")) {
            kat_hexn(&g->t[i], 1, ask, 32);
            kat_hexn(&g->t[i], 2, ar, 32);
            have = true;
        }
    must(have, "1s1o prove bundle has no SS line");
    kat_fs_add(ask, ar, S_rsk);
    unsigned char rk[32];
    kat_gen_mul(KAT_GEN_SPEND_AUTH, S_rsk, rk);
    must(memcmp(rk, S_rk, 32) == 0, "[ask+ar]G != rk of rustmade:1s1o");
    unsigned char msg[64];
    memcpy(msg, S_rk, 32);
    memcpy(msg + 32, S_sh, 32);
    must(kat_rj_verify(S_rk, msg, S_sig, KAT_GEN_SPEND_AUTH), "rustmade:1s1o spend sig does not verify (helper)");
}

static void spend_case(const char *mode, const char *label, const unsigned char *cv, const unsigned char *rk,
                       const unsigned char *pr, const unsigned char *sig)
{
    head(mode, "check_spend", label);
    hx(cv, 32);
    hx(S_an, 32);
    hx(S_nf, 32);
    hx(rk, 32);
    hx(pr, 192);
    hx(sig, 64);
    hx(S_sh, 32);
    endl();
}

/* --------------------------------------------------------------- groups */

static void group_preinit(void)
{
    unsigned char bad[32];
    memset(bad, 0xff, 32);
    bad[31] = 0x7f; /* y = 2^255-1 > q: does not decode */
    spend_case("n", "preinit:check_spend:valid", S_cv, S_rk, S_pr, S_sig);
    spend_case("n", "preinit:check_spend:cv_undecodable", bad, S_rk, S_pr, S_sig);
    spend_case("n", "preinit:check_spend:cv_small_order", TOR[4], S_rk, S_pr, S_sig);
    {
        unsigned char rkbad[32];
        memcpy(rkbad, S_rk, 32);
        rkbad[0] ^= 1;
        spend_case("n", "preinit:check_spend:rk_flip", S_cv, rkbad, S_pr, S_sig);
        unsigned char pr0[192];
        memcpy(pr0, S_pr, 192);
        pr0[0] &= 0x7f; /* no compression flag */
        spend_case("n", "preinit:check_spend:proof_nocomp", S_cv, S_rk, pr0, S_sig);
    }
    head("n", "check_output", "preinit:check_output:valid");
    hx(O_cv, 32), hx(O_cm, 32), hx(O_epk, 32), hx(O_pr, 192), endl();
    head("n", "check_output", "preinit:check_output:cv_undecodable");
    hx(bad, 32), hx(O_cm, 32), hx(O_epk, 32), hx(O_pr, 192), endl();
    head("n", "check_output", "preinit:check_output:epk_small_order");
    hx(O_cv, 32), hx(O_cm, 32), hx(TOR[1], 32), hx(O_pr, 192), endl();

    /* Sprout: a valid mainnet JoinSplit, and the same with a broken proof encoding. */
    GFile *g = gfile("sprout_verify.golden");
    for (size_t i = 0; i < g->n; i++) {
        const KatToks *k = &g->t[i];
        if (!kat_is(k, 14, "T"))
            continue;
        for (int v = 0; v < 2; v++) {
            unsigned char pr[192];
            kat_hexn(k, 3, pr, 192);
            if (v)
                pr[0] &= 0x7f;
            head("n", "sprout_verify", v ? "preinit:sprout_verify:proof_nocomp" : "preinit:sprout_verify:valid");
            hx(pr, 192);
            for (int j = 4; j < 14; j++)
                tok(k->t[j]);
            endl();
        }
        break;
    }
    {
        unsigned char z[64] = {0};
        head("n", "final_check_fresh", "preinit:final_check:empty_vb0_zero_sig");
        tok("0"), hx(z, 64), hx(z, 32), endl();
    }
    const KatToks *r = rec_by_label("merkle_hash.golden", "vec:pedersen");
    head("n", "merkle_hash", "preinit:merkle_hash");
    tok(r->t[3]), tok(r->t[4]), tok(r->t[5]), endl();
    r = rec_by_label("sapling_compute_cm.golden", "vec:keycomp:0");
    head("n", "compute_cm", "preinit:compute_cm");
    for (int j = 3; j < 7; j++)
        tok(r->t[j]);
    endl();
    r = rec_by_label("ivk_to_pkd.golden", "vec:keycomp:0");
    head("n", "ivk_to_pkd", "preinit:ivk_to_pkd");
    tok(r->t[3]), tok(r->t[4]), endl();
    r = rec_by_label("sapling_spend_sig.golden", "mut:ask=0");
    head("n", "spend_sig", "preinit:spend_sig");
    tok(r->t[3]), tok(r->t[4]), tok(r->t[5]), endl();
    head("n", "generate_r", "preinit:generate_r"), endl();
    r = rec_by_label("zip32_xsk_master.golden", "vec:zip32");
    head("n", "xsk_master", "preinit:xsk_master");
    tok(r->t[3]), tok(r->t[4]), endl();

    r = rec_by_label("sapling_output_proof.golden", "valid:0");
    head("n", "output_proof", "preinit:output_proof:valid");
    for (int j = 3; j < 8; j++)
        tok(r->t[j]);
    endl();
    r = rec_by_label("sapling_output_proof.golden", "mut:esk=r");
    head("n", "output_proof", "preinit:output_proof:esk=r");
    for (int j = 3; j < 8; j++)
        tok(r->t[j]);
    endl();
    r = rec_by_label("sapling_spend_proof.golden", "valid:0");
    head("n", "spend_proof", "preinit:spend_proof:valid");
    for (int j = 3; j < 11; j++)
        tok(r->t[j]);
    endl();
    r = rec_by_label("sapling_spend_proof.golden", "mut:ak:offcurve");
    head("n", "spend_proof", "preinit:spend_proof:ak_offcurve");
    for (int j = 3; j < 11; j++)
        tok(r->t[j]);
    endl();
    r = rec_by_label("sapling_spend_proof.golden", "mut:nsk=r");
    head("n", "spend_proof", "preinit:spend_proof:nsk=r");
    for (int j = 3; j < 11; j++)
        tok(r->t[j]);
    endl();
    {
        unsigned char sh[32];
        memset(sh, 0x5a, 32);
        head("n", "pbundle", "preinit:binding_sig:empty_ctx_vb0"), tok("1"), endl();
        fprintf(O, "PB 0"), hx(sh, 32), endl();
    }
}

static void group_init(void)
{
    const char *S = "sapling-spend.params", *Op = "sapling-output.params", *G = "sprout-groth16.params";
    struct {
        const char *label, *s, *sh, *o, *oh, *g, *gh;
    } cases[] = {
        {"init:canonical_in_pdir", S, KAT_SPEND_HASH, Op, KAT_OUTPUT_HASH, G, KAT_SPROUT_HASH},
        {"init:spend_copy_other_name", "spend-copy.params", KAT_SPEND_HASH, Op, KAT_OUTPUT_HASH, G, KAT_SPROUT_HASH},
        {"init:output_content_corrupt_same_size", S, KAT_SPEND_HASH, "output-corrupt.params", KAT_OUTPUT_HASH, G,
         KAT_SPROUT_HASH},
        {"init:spend_content_corrupt_same_size", "spend-corrupt.params", KAT_SPEND_HASH, Op, KAT_OUTPUT_HASH, G,
         KAT_SPROUT_HASH},
        {"init:output_truncated", S, KAT_SPEND_HASH, "output-trunc.params", KAT_OUTPUT_HASH, G, KAT_SPROUT_HASH},
        {"init:output_extended", S, KAT_SPEND_HASH, "output-long.params", KAT_OUTPUT_HASH, G, KAT_SPROUT_HASH},
        {"init:spend_path_empty", "~", KAT_SPEND_HASH, Op, KAT_OUTPUT_HASH, G, KAT_SPROUT_HASH},
        {"init:spend_path_directory", "subdir", KAT_SPEND_HASH, Op, KAT_OUTPUT_HASH, G, KAT_SPROUT_HASH},
        {"init:sprout_missing", S, KAT_SPEND_HASH, Op, KAT_OUTPUT_HASH, "no-such-sprout.params", KAT_SPROUT_HASH},
        {"init:output_missing", S, KAT_SPEND_HASH, "no-such-output.params", KAT_OUTPUT_HASH, G, KAT_SPROUT_HASH},
        /* canonical names in one directory, one file with one flipped byte */
        {"init:canonical_names:output_content_corrupt", "c-output/sapling-spend.params", KAT_SPEND_HASH,
         "c-output/sapling-output.params", KAT_OUTPUT_HASH, "c-output/sprout-groth16.params", KAT_SPROUT_HASH},
        {"init:canonical_names:spend_content_corrupt", "c-spend/sapling-spend.params", KAT_SPEND_HASH,
         "c-spend/sapling-output.params", KAT_OUTPUT_HASH, "c-spend/sprout-groth16.params", KAT_SPROUT_HASH},
        {"init:canonical_names:sprout_content_corrupt", "c-sprout/sapling-spend.params", KAT_SPEND_HASH,
         "c-sprout/sapling-output.params", KAT_OUTPUT_HASH, "c-sprout/sprout-groth16.params", KAT_SPROUT_HASH},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        head("n", "init", cases[i].label);
        tok(cases[i].s), tok(cases[i].sh), tok(cases[i].o), tok(cases[i].oh), tok(cases[i].g), tok(cases[i].gh);
        endl();
    }
    /* init, then the first output proof of a send */
    const KatToks *op = rec_by_label("sapling_output_proof.golden", "valid:0");
    const char *dirs[] = {"", "c-output/"};
    for (int d = 0; d < 2; d++) {
        char a[128], b[128], c[128];
        snprintf(a, sizeof a, "%s%s", dirs[d], S);
        snprintf(b, sizeof b, "%s%s", dirs[d], Op);
        snprintf(c, sizeof c, "%s%s", dirs[d], G);
        head("n", "init_prove_output", d ? "init:canonical_names:output_content_corrupt:then_output_proof"
                                         : "init:canonical:then_output_proof");
        tok(a), tok(KAT_SPEND_HASH), tok(b), tok(KAT_OUTPUT_HASH), tok(c), tok(KAT_SPROUT_HASH);
        for (int j = 3; j < 8; j++)
            tok(op->t[j]);
        endl();
    }
    /* hash strings: invalid UTF-8, trailing garbage, empty */
    char badutf[300];
    snprintf(badutf, sizeof badutf, "hex:ff");
    for (size_t j = 0; j < strlen(KAT_SPEND_HASH) && strlen(badutf) < 260; j++) {
        char two[3];
        snprintf(two, sizeof two, "%02x", (unsigned char)KAT_SPEND_HASH[j]);
        strcat(badutf, two);
    }
    head("n", "init", "init:spend_hash_invalid_utf8"), tok(S), tok(badutf), tok(Op), tok(KAT_OUTPUT_HASH), tok(G),
        tok(KAT_SPROUT_HASH), endl();
    char longer[200];
    snprintf(longer, sizeof longer, "%s0", KAT_OUTPUT_HASH);
    head("n", "init", "init:output_hash_trailing_char"), tok(S), tok(KAT_SPEND_HASH), tok(Op), tok(longer), tok(G),
        tok(KAT_SPROUT_HASH), endl();
    char sprout_hex[300];
    snprintf(sprout_hex, sizeof sprout_hex, "hex:");
    for (size_t j = 0; j < strlen(KAT_SPROUT_HASH) - 1; j++) {
        char two[3];
        snprintf(two, sizeof two, "%02x", (unsigned char)KAT_SPROUT_HASH[j]);
        strcat(sprout_hex, two);
    }
    strcat(sprout_hex, "c0"); /* last byte invalid UTF-8 lead */
    head("n", "init", "init:sprout_hash_invalid_utf8_tail"), tok(S), tok(KAT_SPEND_HASH), tok(Op),
        tok(KAT_OUTPUT_HASH), tok(G), tok(sprout_hex), endl();
}

/* R variants for a crafted RedJubjub signature. Writes rbar, and the nonce n
 * such that the R decodes to [n]G + torsion (n used in S). */
typedef struct {
    char label[64];
    unsigned char rbar[32], n[32];
} RVar;

static size_t r_variants(enum kat_gen gen, RVar *v)
{
    size_t m = 0;
    unsigned char n[32], R[32];
    nonce(1 + (unsigned)gen, n);
    kat_gen_mul(gen, n, R);
    snprintf(v[m].label, sizeof v[m].label, "R=nG");
    memcpy(v[m].rbar, R, 32), memcpy(v[m].n, n, 32), m++;
    for (int k = 1; k < 8; k++) {
        unsigned char RT[32];
        must(kat_point_add(R, TOR[k], RT), "R + torsion");
        snprintf(v[m].label, sizeof v[m].label, "R=nG+tor%d", k);
        memcpy(v[m].rbar, RT, 32), memcpy(v[m].n, n, 32), m++;
    }
    unsigned char zero[32] = {0};
    for (int k = 0; k < 8; k++) {
        snprintf(v[m].label, sizeof v[m].label, "R=tor%d", k);
        memcpy(v[m].rbar, TOR[k], 32), memcpy(v[m].n, zero, 32), m++;
    }
    /* identity with the sign bit set (x = 0, sign 1), and (0,-1) with sign 1 */
    unsigned char id_s1[32] = {1};
    id_s1[31] = 0x80;
    snprintf(v[m].label, sizeof v[m].label, "R=x0s1:id");
    memcpy(v[m].rbar, id_s1, 32), memcpy(v[m].n, zero, 32), m++;
    unsigned char m1_s1[32];
    memcpy(m1_s1, TOR[4], 32);
    m1_s1[31] |= 0x80;
    snprintf(v[m].label, sizeof v[m].label, "R=x0s1:m1");
    memcpy(v[m].rbar, m1_s1, 32), memcpy(v[m].n, zero, 32), m++;
    /* [n]G with y+q: search a nonce whose R has a small enough y. */
    for (unsigned t = 100; t < 400; t++) {
        unsigned char nn[32], RR[32], RQ[32];
        nonce(t + 1000u * (unsigned)gen, nn);
        kat_gen_mul(gen, nn, RR);
        if (kat_enc_y_plus_q(RR, RQ)) {
            snprintf(v[m].label, sizeof v[m].label, "R=nG:y+q");
            memcpy(v[m].rbar, RQ, 32), memcpy(v[m].n, nn, 32), m++;
            snprintf(v[m].label, sizeof v[m].label, "R=nG:canonical_of_y+q_case");
            memcpy(v[m].rbar, RR, 32), memcpy(v[m].n, nn, 32), m++;
            break;
        }
    }
    /* identity / order-2 with y+q (y = 1 + q, y = q-1+q does not fit) */
    unsigned char idq[32];
    if (kat_enc_y_plus_q(TOR[0], idq)) {
        snprintf(v[m].label, sizeof v[m].label, "R=tor0:y+q");
        memcpy(v[m].rbar, idq, 32), memcpy(v[m].n, zero, 32), m++;
    }
    return m;
}

static void group_rjsig(void)
{
    RVar v[40];
    size_t m = r_variants(KAT_GEN_SPEND_AUTH, v);
    unsigned char msg[64];
    memcpy(msg, S_rk, 32);
    memcpy(msg + 32, S_sh, 32);
    for (size_t i = 0; i < m; i++) {
        unsigned char sig[64];
        kat_rj_sign_with(S_rsk, msg, v[i].rbar, v[i].n, sig);
        char lab[128];
        snprintf(lab, sizeof lab, "rjsig:rustmade:1s1o:spend_auth:%.63s", v[i].label);
        spend_case("-", lab, S_cv, S_rk, S_pr, sig);
        /* the same inside the whole bundle (cv accumulation, output, binding sig) */
        snprintf(lab, sizeof lab, "rjsig:rustmade:1s1o:bundle:%.63s", v[i].label);
        head("-", "vbundle", lab), tok("3"), endl();
        fputs("S", O), hx(S_cv, 32), hx(S_an, 32), hx(S_nf, 32), hx(S_rk, 32), hx(S_pr, 192), hx(sig, 64), hx(S_sh, 32),
            endl();
        fputs("O", O), hx(O_cv, 32), hx(O_cm, 32), hx(O_epk, 32), hx(O_pr, 192), endl();
        fprintf(O, "F %lld", (long long)F_vb), hx(F_sig, 64), hx(F_sh, 32), endl();
    }
    /* S + r on a re-signed signature with torsion R (non-canonical S) */
    unsigned char sig[64];
    kat_rj_sign_with(S_rsk, msg, v[1].rbar, v[1].n, sig);
    unsigned carry = 0;
    for (int j = 0; j < 32; j++) {
        unsigned x = (unsigned)sig[32 + j] + KAT_R_LE[j] + carry;
        sig[32 + j] = (unsigned char)x;
        carry = x >> 8;
    }
    if (!carry)
        spend_case("-", "rjsig:rustmade:1s1o:spend_auth:R=nG+tor1:S+r", S_cv, S_rk, S_pr, sig);
}

static void group_bsig(void)
{
    RVar v[40];
    size_t m = r_variants(KAT_GEN_VALUE_RAND, v);
    unsigned char zero[32] = {0}, sh[32];
    memset(sh, 0x3c, 32);
    unsigned char ident[32];
    memcpy(ident, TOR[0], 32); /* bvk of an empty context: identity */
    unsigned char msg[64];
    memcpy(msg, ident, 32);
    memcpy(msg + 32, sh, 32);
    for (size_t i = 0; i < m; i++) {
        unsigned char sig[64];
        kat_rj_sign_with(zero, msg, v[i].rbar, v[i].n, sig);
        char lab[128];
        snprintf(lab, sizeof lab, "bsig:empty_ctx:vb0:%.63s", v[i].label);
        head("-", "final_check_fresh", lab), tok("0"), hx(sig, 64), hx(sh, 32), endl();
    }
    /* vb != 0 with the same signatures must fail; vb = 0 with S = r - n */
    unsigned char sig[64];
    kat_rj_sign_with(zero, msg, v[0].rbar, v[0].n, sig);
    head("-", "final_check_fresh", "bsig:empty_ctx:vb1:R=nG"), tok("1"), hx(sig, 64), hx(sh, 32), endl();
    head("-", "final_check_fresh", "bsig:empty_ctx:vb-1:R=nG"), tok("-1"), hx(sig, 64), hx(sh, 32), endl();
}

static void xp_variants(const char *fn, const char *base_label, const KatToks *k, int proof_col, int nfields)
{
    unsigned char pr[192];
    kat_hexn(k, proof_col, pr, 192);
    static const struct {
        const char *slot;
        int off;
        bool flags;
    } S[] = {{"A", 0, true}, {"B.c1", 48, true}, {"B.c0", 96, false}, {"C", 144, true}};
    for (int s = 0; s < 4; s++) {
        unsigned char m[192];
        memcpy(m, pr, 192);
        bool ok;
        if (S[s].flags) {
            ok = kat_bls_x_plus_p(pr + S[s].off, m + S[s].off);
        } else {
            unsigned carry = 0;
            for (int j = 47; j >= 0; j--) {
                unsigned x = (unsigned)pr[S[s].off + j] + KAT_P_BE[j] + carry;
                m[S[s].off + j] = (unsigned char)x;
                carry = x >> 8;
            }
            ok = carry == 0;
        }
        if (!ok)
            continue;
        char lab[200];
        snprintf(lab, sizeof lab, "xp:%s:%s:x+p", base_label, S[s].slot);
        head("-", fn, lab);
        for (int j = 3; j < 3 + nfields; j++) {
            if (j == proof_col)
                hx(m, 192);
            else
                tok(k->t[j]);
        }
        endl();
    }
}

static void group_xp(void)
{
    GFile *g = gfile("sapling_check_spend.golden");
    for (size_t i = 0; i < g->n; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 10, "T"))
            xp_variants("check_spend", g->t[i].t[2], &g->t[i], 7, 7);
    g = gfile("sapling_check_output.golden");
    for (size_t i = 0; i < g->n; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 7, "T"))
            xp_variants("check_output", g->t[i].t[2], &g->t[i], 6, 4);
    g = gfile("sprout_verify.golden");
    for (size_t i = 0; i < g->n; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 14, "T"))
            xp_variants("sprout_verify", g->t[i].t[2], &g->t[i], 3, 11);
}

static void yq_field(const char *fn, const char *base, const char *field, const KatToks *k, int col, int nfields)
{
    unsigned char e[32], q[32];
    kat_hexn(k, col, e, 32);
    if (!kat_enc_y_plus_q(e, q))
        return;
    char lab[200];
    snprintf(lab, sizeof lab, "yq:%s:%s:y+q", base, field);
    head(strcmp(fn, "xfvk_derive") == 0 || strcmp(fn, "xfvk_address") == 0 ? "x" : "-", fn, lab);
    for (int j = 3; j < 3 + nfields; j++) {
        if (j == col)
            hx(q, 32);
        else
            tok(k->t[j]);
    }
    endl();
}

static void group_yq(void)
{
    GFile *g = gfile("sapling_check_spend.golden");
    for (size_t i = 0; i < g->n; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 10, "T")) {
            yq_field("check_spend", g->t[i].t[2], "cv", &g->t[i], 3, 7);
            yq_field("check_spend", g->t[i].t[2], "rk", &g->t[i], 6, 7);
        }
    g = gfile("sapling_check_output.golden");
    for (size_t i = 0; i < g->n; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 7, "T")) {
            yq_field("check_output", g->t[i].t[2], "cv", &g->t[i], 3, 4);
            yq_field("check_output", g->t[i].t[2], "epk", &g->t[i], 5, 4);
        }
    unsigned nka = 0, nnf = 0, ncm = 0;
    g = gfile("sapling_ka_agree.golden");
    for (size_t i = 0; i < g->n && nka < 6; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 5, "T")) {
            unsigned char e[32], q[32];
            kat_hexn(&g->t[i], 3, e, 32);
            if (kat_enc_y_plus_q(e, q)) {
                yq_field("ka_agree", g->t[i].t[2], "p", &g->t[i], 3, 2);
                nka++;
            }
        }
    g = gfile("sapling_compute_nf.golden");
    for (size_t i = 0; i < g->n && nnf < 9; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 10, "T")) {
            unsigned before = g_id;
            yq_field("compute_nf", g->t[i].t[2], "pk_d", &g->t[i], 4, 7);
            yq_field("compute_nf", g->t[i].t[2], "ak", &g->t[i], 7, 7);
            yq_field("compute_nf", g->t[i].t[2], "nk", &g->t[i], 8, 7);
            nnf += g_id - before;
        }
    g = gfile("sapling_compute_cm.golden");
    for (size_t i = 0; i < g->n && ncm < 3; i++)
        if (kat_is(&g->t[i], 0, "C") && kat_is(&g->t[i], 7, "T")) {
            unsigned before = g_id;
            yq_field("compute_cm", g->t[i].t[2], "pk_d", &g->t[i], 4, 4);
            ncm += g_id - before;
        }
    /* xfvk: ak at bytes 41..72, nk at 73..104 of the 169-byte encoding */
    g = gfile("zip32_xfvk_derive.golden");
    unsigned nx = 0;
    for (size_t i = 0; i < g->n && nx < 4; i++) {
        const KatToks *k = &g->t[i];
        if (!kat_is(k, 0, "C") || !kat_is(k, 5, "T"))
            continue;
        unsigned char x[169];
        kat_hexn(k, 3, x, 169);
        for (int f = 0; f < 2; f++) {
            unsigned char q[32], m[169];
            if (!kat_enc_y_plus_q(x + 41 + 32 * f, q))
                continue;
            memcpy(m, x, 169);
            memcpy(m + 41 + 32 * f, q, 32);
            char lab[200];
            snprintf(lab, sizeof lab, "yq:%s:xfvk_%s:y+q", k->t[2], f ? "nk" : "ak");
            head("x", "xfvk_derive", lab), hx(m, 169), tok(k->t[4]), endl();
            unsigned char j[11] = {0};
            snprintf(lab, sizeof lab, "yq:%s:xfvk_%s:y+q:address", k->t[2], f ? "nk" : "ak");
            head("x", "xfvk_address", lab), hx(m, 169), hx(j, 11), endl();
            nx++;
        }
    }
}

static void group_order(void)
{
    /* final_check twice; final_check before any description; check after final */
    head("-", "vbundle", "order:rustmade:1s1o:final_twice"), tok("4"), endl();
    fputs("S", O), hx(S_cv, 32), hx(S_an, 32), hx(S_nf, 32), hx(S_rk, 32), hx(S_pr, 192), hx(S_sig, 64), hx(S_sh, 32),
        endl();
    fputs("O", O), hx(O_cv, 32), hx(O_cm, 32), hx(O_epk, 32), hx(O_pr, 192), endl();
    fprintf(O, "F %lld", (long long)F_vb), hx(F_sig, 64), hx(F_sh, 32), endl();
    fprintf(O, "F %lld", (long long)F_vb), hx(F_sig, 64), hx(F_sh, 32), endl();
    head("-", "vbundle", "order:rustmade:1s1o:final_first"), tok("4"), endl();
    fprintf(O, "F %lld", (long long)F_vb), hx(F_sig, 64), hx(F_sh, 32), endl();
    fputs("S", O), hx(S_cv, 32), hx(S_an, 32), hx(S_nf, 32), hx(S_rk, 32), hx(S_pr, 192), hx(S_sig, 64), hx(S_sh, 32),
        endl();
    fputs("O", O), hx(O_cv, 32), hx(O_cm, 32), hx(O_epk, 32), hx(O_pr, 192), endl();
    fprintf(O, "F %lld", (long long)F_vb), hx(F_sig, 64), hx(F_sh, 32), endl();
    head("-", "vbundle", "order:rustmade:1s1o:spend_twice"), tok("4"), endl();
    for (int r = 0; r < 2; r++)
        fputs("S", O), hx(S_cv, 32), hx(S_an, 32), hx(S_nf, 32), hx(S_rk, 32), hx(S_pr, 192), hx(S_sig, 64),
            hx(S_sh, 32), endl();
    fputs("O", O), hx(O_cv, 32), hx(O_cm, 32), hx(O_epk, 32), hx(O_pr, 192), endl();
    fprintf(O, "F %lld", (long long)F_vb), hx(F_sig, 64), hx(F_sh, 32), endl();

    /* binding_sig twice after one output; binding_sig on an empty context */
    GFile *g;
    size_t b = bundle_by_label("sapling_binding_sig.golden", "0s1o", &g);
    const KatToks *po = NULL, *pb = NULL;
    for (size_t i = b + 1; !kat_is(&g->t[i], 0, "E"); i++) {
        if (kat_is(&g->t[i], 0, "PO"))
            po = &g->t[i];
        if (kat_is(&g->t[i], 0, "PB"))
            pb = &g->t[i];
    }
    must(po && pb, "0s1o bundle lines");
    head("-", "pbundle", "order:0s1o:binding_sig_twice"), tok("3"), endl();
    fputs("PO", O);
    for (int j = 1; j <= 5; j++)
        tok(po->t[j]);
    endl();
    for (int r = 0; r < 2; r++)
        fputs("PB", O), tok(pb->t[1]), tok(pb->t[2]), endl();
    head("-", "pbundle", "order:0s1o:binding_sig_wrong_then_right"), tok("3"), endl();
    fputs("PO", O);
    for (int j = 1; j <= 5; j++)
        tok(po->t[j]);
    endl();
    fprintf(O, "PB %lld %s\n", (long long)kat_i64(pb, 1) + 1, pb->t[2]);
    fputs("PB", O), tok(pb->t[1]), tok(pb->t[2]), endl();
    {
        unsigned char sh[32];
        memset(sh, 0x77, 32);
        head("-", "pbundle", "order:0s0o:binding_sig_vb0"), tok("1"), endl();
        fprintf(O, "PB 0"), hx(sh, 32), endl();
    }

    /* spend_sig with rsk = ask + ar = 0, and ask + ar = 1 */
    const KatToks *r = rec_by_label("sapling_spend_sig.golden", "mut:ask=r-1");
    unsigned char ask[32], ar[32];
    kat_hexn(r, 3, ask, 32);
    kat_fs_negate(ask, ar);
    head("-", "spend_sig", "order:spend_sig:rsk=0"), hx(ask, 32), hx(ar, 32), tok(r->t[5]), endl();
    unsigned char one[32] = {1}, ar1[32];
    kat_fs_add(ar, one, ar1);
    head("-", "spend_sig", "order:spend_sig:rsk=1"), hx(ask, 32), hx(ar1, 32), tok(r->t[5]), endl();

    /* compute_nf with large positions (Rust uses all 64 bits for rho) */
    r = rec_by_label("sapling_compute_nf.golden", "vec:keycomp:0");
    const char *pos[] = {"4294967296", "9223372036854775808", "18446744073709551615", "4294967295"};
    for (size_t i = 0; i < sizeof pos / sizeof pos[0]; i++) {
        char lab[64];
        snprintf(lab, sizeof lab, "order:compute_nf:position=%s", pos[i]);
        head("-", "compute_nf", lab);
        for (int j = 3; j < 9; j++)
            tok(r->t[j]);
        tok(pos[i]);
        endl();
    }
    /* compute_cm / output_proof with value 2^64-1 */
    r = rec_by_label("sapling_compute_cm.golden", "vec:keycomp:0");
    head("-", "compute_cm", "order:compute_cm:value=2^64-1"), tok(r->t[3]), tok(r->t[4]), tok("18446744073709551615"),
        tok(r->t[6]), endl();
    r = rec_by_label("sapling_output_proof.golden", "valid:0");
    head("-", "output_proof", "order:output_proof:value=2^64-1");
    for (int j = 3; j < 7; j++)
        tok(r->t[j]);
    tok("18446744073709551615");
    endl();
    /* merkle_hash at the deepest allowed depth with the largest inputs */
    unsigned char mx[32];
    memset(mx, 0xff, 32);
    head("-", "merkle_hash", "order:merkle_hash:depth62:max"), tok("62"), hx(mx, 32), hx(mx, 32), endl();
    head("-", "merkle_hash", "order:merkle_hash:depth0:q"), tok("0"), hx(KAT_Q_LE, 32), hx(KAT_Q_LE, 32), endl();
}

int main(int argc, char **argv)
{
    const char *out = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--golden") && i + 1 < argc)
            g_golden = argv[++i];
        else if (!strcmp(argv[i], "--out") && i + 1 < argc)
            out = argv[++i];
        else {
            fprintf(stderr, "usage: kat_mutgen --golden <c23_golden> --out <file>\n");
            return 2;
        }
    }
    if (!g_golden || !out) {
        fprintf(stderr, "usage: kat_mutgen --golden <c23_golden> --out <file>\n");
        return 2;
    }
    kat_jub_init();
    O = fopen(out, "wb");
    if (!O) {
        fprintf(stderr, "cannot open %s\n", out);
        return 2;
    }
    fprintf(O, "# kat_cases v1: U4 mutation cases (generated by kat_mutgen; do not edit)\n");
    fprintf(O, "# mode n cases come first (POSIX fork isolation needs an uninitialized parent)\n");
    load_torsion();
    load_rustmade();
    group_preinit();
    group_init();
    group_rjsig();
    group_bsig();
    group_xp();
    group_yq();
    group_order();
    if (fclose(O) != 0) {
        fprintf(stderr, "write error on %s\n", out);
        return 2;
    }
    printf("kat_mutgen: %u cases\n", g_id);
    for (size_t i = 0; i < g_nfiles; i++) {
        for (size_t j = 0; j < g_files[i].n; j++)
            kat_toks_free(&g_files[i].t[j]);
        free(g_files[i].t);
        free(g_files[i].name);
    }
    return 0;
}
