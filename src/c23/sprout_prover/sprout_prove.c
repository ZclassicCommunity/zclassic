/* Copyright 2026 The Zclassic developers - MIT License
 *
 * Streaming Groth16 prover for the Sprout JoinSplit circuit (see
 * sprout_prover.h for the contract).
 *
 * The math is bellman's create_proof (groth16/prover.rs at 06da3b9a), the
 * same steps the vendored Z23 groth16_prove() performs:
 *   A   = alpha + sum_i w_i * a_i + r * delta          (G1)
 *   B   = beta  + sum_i w_i * b_i + s * delta          (G2, and G1 for C)
 *   C   = sum h_j * H_j + sum_aux w_k * L_k + s*A + r*B1 - r*s*delta
 * with h(x) = (a(x) b(x) - c(x)) / z(x) evaluated on the coset 7*<omega>.
 *
 * What differs from groth16_prove() is WHEN the proving key is read: the
 * witness is fully known before any query point is needed, so the parameter
 * file is consumed section by section in bounded chunks and each chunk is
 * folded into its multi-scalar sum immediately. The 725 MB file is never
 * resident, and nothing is cached between calls.
 *
 * Side channels. Every auxiliary variable of this circuit is a bit, so the
 * L, A and B sums are computed as "always add, then constant-time select"
 * over every point, starting from a public non-identity offset so no early
 * identity shortcut fires; the bit values never choose a branch or an index.
 * The H sum (2^21 - 1 dense scalars derived from the witness) uses the
 * vendored variable-time Pippenger g1_msm, exactly as bellman and Z23's own
 * Sapling prover do; see REPORT. r and s multiply through the vendored
 * cmov ladder g1_scalar_mul and a local cmov ladder for G2. */

#include "sprout_prover.h"
#include "sprout_circuit.h"
#include "sprout_par.h"

#include "sapling/bls12_381.h"
#include "sapling/fr.h"
#include "sapling/groth16_prover.h"
#include "sapling/params_vk_embedded.h"
#include "crypto/random_secret.h"
#include "support/cleanse.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define SP_G1_RAW 96u
#define SP_G2_RAW 192u
#define SP_VK_PREFIX 1828u   /* 864 fixed + 4 + 10 * 96 */
#define SP_MAX_THREADS 64u
#define SP_CHUNK_BYTES ((size_t)192 << 20) /* raw read buffer: 192 MiB */

/* ── small utilities ──────────────────────────────────────────────── */

static double sp_now(void)
{
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC)
        return 0.0;
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static pthread_mutex_t g_path_mu = PTHREAD_MUTEX_INITIALIZER;
static char *g_params_path = NULL;
static unsigned g_test_threads = 0;

#ifdef SPROUT_PROVER_TESTING
static zc23_sprout_test_rng_fn g_test_rng = NULL;
static void *g_test_rng_user = NULL;
void zc23_sprout_set_test_rng(zc23_sprout_test_rng_fn fn, void *user)
{
    g_test_rng = fn;
    g_test_rng_user = user;
}
void zc23_sprout_set_test_threads(unsigned n) { g_test_threads = n; }
#endif

bool zc23_sprout_prover_set_params_path(const char *utf8_path)
{
    if (!utf8_path || !utf8_path[0])
        return false;
    size_t n = strlen(utf8_path);
    char *copy = malloc(n + 1);
    if (!copy)
        return false;
    memcpy(copy, utf8_path, n + 1);
    pthread_mutex_lock(&g_path_mu);
    free(g_params_path);
    g_params_path = copy;
    pthread_mutex_unlock(&g_path_mu);
    return true;
}

static char *sp_params_path_dup(void)
{
    char *out = NULL;
    pthread_mutex_lock(&g_path_mu);
    if (g_params_path) {
        size_t n = strlen(g_params_path);
        out = malloc(n + 1);
        if (out)
            memcpy(out, g_params_path, n + 1);
    }
    pthread_mutex_unlock(&g_path_mu);
    return out;
}

static FILE *sp_fopen(const char *path)
{
#ifdef _WIN32
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (n <= 0)
        return NULL;
    wchar_t *w = malloc((size_t)n * sizeof *w);
    if (!w)
        return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, w, n) != n) {
        free(w);
        return NULL;
    }
    FILE *f = _wfopen(w, L"rb");
    free(w);
    return f;
#else
    return fopen(path, "rb");
#endif
}

static unsigned sp_thread_count(void)
{
    if (g_test_threads)
        return g_test_threads > SP_MAX_THREADS ? SP_MAX_THREADS : g_test_threads;
    return sprout_cpu_count();
}

#define sp_parallel_for sprout_parallel_for

static void sp_fr_pow(struct fr *r, const struct fr *base, uint64_t e)
{
    struct fr acc, b = *base;
    fr_one(&acc);
    while (e) {
        if (e & 1u)
            fr_mul(&acc, &acc, &b);
        fr_sq(&b, &b);
        e >>= 1;
    }
    *r = acc;
}

static void sp_fr_raw(uint64_t raw[4], const struct fr *a)
{
    uint8_t b[32];
    fr_to_bytes(b, a);
    for (size_t i = 0; i < 4; i++) {
        raw[i] = 0;
        for (size_t j = 0; j < 8; j++)
            raw[i] |= (uint64_t)b[8 * i + j] << (8 * j);
    }
    memory_cleanse(b, sizeof b);
}

static void sp_cmov_words(uint64_t *dst, const uint64_t *src, size_t n,
                          uint64_t mask)
{
    for (size_t i = 0; i < n; i++)
        dst[i] ^= mask & (dst[i] ^ src[i]);
}

static void sp_g1_cmov(struct g1_point *d, const struct g1_point *s, uint64_t m)
{
    sp_cmov_words(d->x.d, s->x.d, 6, m);
    sp_cmov_words(d->y.d, s->y.d, 6, m);
    sp_cmov_words(d->z.d, s->z.d, 6, m);
}

static void sp_fp2_cmov(struct fp2 *d, const struct fp2 *s, uint64_t m)
{
    sp_cmov_words(d->c0.d, s->c0.d, 6, m);
    sp_cmov_words(d->c1.d, s->c1.d, 6, m);
}

static void sp_g2_cmov(struct g2_point *d, const struct g2_point *s, uint64_t m)
{
    sp_fp2_cmov(&d->x, &s->x, m);
    sp_fp2_cmov(&d->y, &s->y, m);
    sp_fp2_cmov(&d->z, &s->z, m);
}

/* Constant-time double-and-add-always over G2 (mirror of g1_scalar_mul). */
static void sp_g2_mul_ct(struct g2_point *r, const struct g2_point *p,
                         const uint64_t k[4])
{
    struct g2_point acc, base = *p, sum;
    g2_identity(&acc);
    for (size_t i = 0; i < 4; i++) {
        for (size_t bit = 0; bit < 64; bit++) {
            g2_add(&sum, &acc, &base);
            sp_g2_cmov(&acc, &sum, (uint64_t)0 - ((k[i] >> bit) & 1u));
            g2_double(&base, &base);
        }
    }
    *r = acc;
}

/* Uniform non-zero r, s by rejection sampling on 255-bit strings. */
static bool sp_random_fr(struct fr *out, const char *label)
{
    uint8_t b[32];
    for (int tries = 0; tries < 128; tries++) {
        bool ok;
#ifdef SPROUT_PROVER_TESTING
        if (g_test_rng)
            ok = g_test_rng(g_test_rng_user, b, sizeof b);
        else
#endif
            ok = zcl_random_secret_bytes(b, sizeof b, label);
        if (!ok) {
            memory_cleanse(b, sizeof b);
            return false;
        }
        b[31] &= 0x7f;
        bool canon = fr_from_bytes(out, b);
        memory_cleanse(b, sizeof b);
        if (canon && !fr_is_zero(out))
            return true;
    }
    return false;
}

/* bellman / pairing compressed encodings. */
static void sp_g1_compress(uint8_t out[48], const struct g1_point *p)
{
    if (g1_is_identity(p)) {
        memset(out, 0, 48);
        out[0] = 0xc0;
        return;
    }
    struct fp x, y;
    g1_to_affine(&x, &y, p);
    fp_to_bytes(out, &x);
    out[0] = (uint8_t)((out[0] & 0x1f) | 0x80);
    if (fp_lexicographically_largest(&y))
        out[0] |= 0x20;
}

static void sp_g2_compress(uint8_t out[96], const struct g2_point *p)
{
    if (g2_is_identity(p)) {
        memset(out, 0, 96);
        out[0] = 0xc0;
        return;
    }
    struct fp2 x, y;
    g2_to_affine(&x, &y, p);
    fp_to_bytes(out, &x.c1);
    fp_to_bytes(out + 48, &x.c0);
    out[0] = (uint8_t)((out[0] & 0x1f) | 0x80);
    if (fp2_lexicographically_largest(&y))
        out[0] |= 0x20;
}

static const struct zcl_embedded_vk *sp_embedded_vk(void)
{
    for (size_t i = 0; i < ZCL_EMBEDDED_VK_COUNT; i++)
        if (strcmp(zcl_embedded_vks[i].name, "sprout-groth16") == 0 &&
            zcl_embedded_vks[i].len == SP_VK_PREFIX)
            return &zcl_embedded_vks[i];
    return NULL;
}

/* ── QAP: densities, a/b/c evaluations, h(x) ─────────────────────── */

/* ── QAP: a/b/c evaluations (with the satisfaction check), densities,
 *    h(x) ─────────────────────────────────────────────────────────── */

struct sp_qap {
    size_t num_in, num_aux, domain;
    struct fr *a, *b, *c;   /* domain entries; h ends up in a */
    uint8_t *a_aux_dense;   /* per aux: appears in some A */
    uint8_t *b_in_dense;    /* per input (incl. ONE): appears in some B */
    uint8_t *b_aux_dense;
    size_t a_aux_total, b_in_total, b_aux_total;
};

struct sp_eval_ctx {
    const struct constraint_system *cs;
    struct fr *a, *b, *c;
    size_t first_bad[SPROUT_MAX_THREADS];
};

/* Evaluate A, B, C of every row and check A*B == C in the same pass (this is
 * cs_is_satisfied, parallel, without a second walk over the rows). */
static void sp_eval_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    struct sp_eval_ctx *e = p;
    size_t bad = SIZE_MAX;
    for (size_t i = lo; i < hi; i++) {
        lc_evaluate(&e->a[i], &e->cs->constraints[i].a, e->cs->witness);
        lc_evaluate(&e->b[i], &e->cs->constraints[i].b, e->cs->witness);
        lc_evaluate(&e->c[i], &e->cs->constraints[i].c, e->cs->witness);
        struct fr ab;
        fr_mul(&ab, &e->a[i], &e->b[i]);
        if (bad == SIZE_MAX && !fr_eq(&ab, &e->c[i]))
            bad = i;
    }
    e->first_bad[tid] = bad;
}

struct sp_h_ctx {
    struct fr *a;
    const struct fr *b, *c;
    struct fr zinv;
};

static void sp_h_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct sp_h_ctx *h = p;
    for (size_t i = lo; i < hi; i++) {
        struct fr ab;
        fr_mul(&ab, &h->a[i], &h->b[i]);
        fr_sub(&ab, &ab, &h->c[i]);
        fr_mul(&h->a[i], &ab, &h->zinv);
    }
}

static void sp_free_vec(struct fr **v, size_t n)
{
    if (*v) {
        memory_cleanse(*v, n * sizeof **v);
        free(*v);
        *v = NULL;
    }
}

static void sp_free_qap(struct sp_qap *q)
{
    sp_free_vec(&q->a, q->domain);
    sp_free_vec(&q->b, q->domain);
    sp_free_vec(&q->c, q->domain);
    free(q->a_aux_dense);
    free(q->b_in_dense);
    free(q->b_aux_dense);
    memset(q, 0, sizeof *q);
}

static void sp_free_constraints(struct constraint_system *cs)
{
    for (size_t i = 0; i < cs->num_constraints; i++) {
        lc_free(&cs->constraints[i].a);
        lc_free(&cs->constraints[i].b);
        lc_free(&cs->constraints[i].c);
    }
    free(cs->constraints);
    cs->constraints = NULL;
    cs->num_constraints = 0;
    cs->cap_constraints = 0;
}

/* Stage 1: evaluations + satisfaction + densities, then release the rows
 * (the witness stays). UNSATISFIED is decided here, before any params I/O. */
static enum zc23_sprout_status sp_qap_eval(struct constraint_system *cs,
                                           struct sp_qap *q, unsigned T)
{
    memset(q, 0, sizeof *q);
    size_t n_con = cs->num_constraints;
    q->num_in = cs->num_inputs + 1;
    q->num_aux = cs->num_vars - q->num_in;
    size_t rows = n_con + q->num_in;
    q->domain = 1;
    while (q->domain < rows)
        q->domain <<= 1;

    q->a = calloc(q->domain, sizeof(struct fr));
    q->b = calloc(q->domain, sizeof(struct fr));
    q->c = calloc(q->domain, sizeof(struct fr));
    q->a_aux_dense = calloc(q->num_aux ? q->num_aux : 1, 1);
    q->b_in_dense = calloc(q->num_in, 1);
    q->b_aux_dense = calloc(q->num_aux ? q->num_aux : 1, 1);
    if (!q->a || !q->b || !q->c || !q->a_aux_dense || !q->b_in_dense ||
        !q->b_aux_dense)
        return ZC23_SPROUT_OOM;

    struct sp_eval_ctx ec;
    memset(&ec, 0, sizeof ec);
    ec.cs = cs;
    ec.a = q->a;
    ec.b = q->b;
    ec.c = q->c;
    for (unsigned t = 0; t < SPROUT_MAX_THREADS; t++)
        ec.first_bad[t] = SIZE_MAX;
    sp_parallel_for(T, n_con, sp_eval_rows, &ec);
    for (unsigned t = 0; t < SPROUT_MAX_THREADS; t++)
        if (ec.first_bad[t] != SIZE_MAX)
            return ZC23_SPROUT_UNSATISFIED;

    /* The `Input(i) * 0 = 0` rows bellman appends after synthesis. */
    for (size_t i = 0; i < q->num_in; i++)
        q->a[n_con + i] = cs->witness[i];

    /* Density = syntactic appearance (bellman DensityTracker::inc). */
    for (size_t i = 0; i < n_con; i++) {
        const struct linear_combination *la = &cs->constraints[i].a;
        for (size_t t = 0; t < la->num_terms; t++) {
            size_t v = la->terms[t].var;
            if (v >= q->num_in)
                q->a_aux_dense[v - q->num_in] = 1;
        }
        const struct linear_combination *lb = &cs->constraints[i].b;
        for (size_t t = 0; t < lb->num_terms; t++) {
            size_t v = lb->terms[t].var;
            if (v < q->num_in)
                q->b_in_dense[v] = 1;
            else
                q->b_aux_dense[v - q->num_in] = 1;
        }
    }
    for (size_t i = 0; i < q->num_aux; i++) {
        q->a_aux_total += q->a_aux_dense[i];
        q->b_aux_total += q->b_aux_dense[i];
    }
    for (size_t i = 0; i < q->num_in; i++)
        q->b_in_total += q->b_in_dense[i];

    sp_free_constraints(cs);
    return ZC23_SPROUT_OK;
}

/* Stage 2: h(x) = (a b - c) / z on the coset 7<omega>, back to
 * coefficients (bellman: ifft, coset_fft, divide_by_z_on_coset, icoset_fft).
 * Leaves h in q->a and frees b, c. */
static enum zc23_sprout_status sp_qap_h(struct sp_qap *q, unsigned T)
{
    uint8_t gb[32] = { 7 }; /* Fr::multiplicative_generator */
    struct fr g, ginv, one;
    fr_from_bytes(&g, gb);
    fr_inv(&ginv, &g);
    fr_one(&one);

    struct fr *v[3] = { q->a, q->b, q->c };
    for (size_t i = 0; i < 3; i++) {
        if (!sprout_fft(v[i], q->domain, true, T))
            return ZC23_SPROUT_OOM;
        sprout_distribute_powers(v[i], q->domain, &g, T);
        if (!sprout_fft(v[i], q->domain, false, T))
            return ZC23_SPROUT_OOM;
    }
    struct sp_h_ctx hc = { q->a, q->b, q->c, { { 0 } } };
    sp_fr_pow(&hc.zinv, &g, (uint64_t)q->domain);
    fr_sub(&hc.zinv, &hc.zinv, &one);
    fr_inv(&hc.zinv, &hc.zinv);
    sp_parallel_for(T, q->domain, sp_h_rows, &hc);
    sp_free_vec(&q->b, q->domain);
    sp_free_vec(&q->c, q->domain);
    if (!sprout_fft(q->a, q->domain, true, T))
        return ZC23_SPROUT_OOM;
    sprout_distribute_powers(q->a, q->domain, &ginv, T);
    return ZC23_SPROUT_OK;
}

/* ── G1 mixed addition and the dense H sum ───────────────────────── */

/* r = a + (x2, y2), a Jacobian (X/Z^2, Y/Z^3, identity Z = 0), (x2, y2)
 * affine and on the curve (madd-2007-bl). r may alias a. The special cases
 * (a = identity, a = +-P) branch; on the bit-sum path a starts from a public
 * offset so they do not occur except with negligible probability. */
static void sp_g1_madd(struct g1_point *r, const struct g1_point *a,
                       const struct fp *x2, const struct fp *y2)
{
    if (g1_is_identity(a)) {
        r->x = *x2;
        r->y = *y2;
        fp_one(&r->z);
        return;
    }
    struct fp z1z1, u2, s2, h, hh, i, j, rr, v, t, x3, y3, z3;
    fp_sq(&z1z1, &a->z);
    fp_mul(&u2, x2, &z1z1);
    fp_mul(&s2, y2, &a->z);
    fp_mul(&s2, &s2, &z1z1);
    fp_sub(&h, &u2, &a->x);
    fp_sub(&rr, &s2, &a->y);
    if (fp_is_zero(&h)) {
        if (fp_is_zero(&rr)) {
            struct g1_point p;
            p.x = *x2;
            p.y = *y2;
            fp_one(&p.z);
            g1_double(r, &p);
        } else {
            g1_identity(r);
        }
        return;
    }
    fp_add(&rr, &rr, &rr);
    fp_sq(&hh, &h);
    fp_add(&i, &hh, &hh);
    fp_add(&i, &i, &i);
    fp_mul(&j, &h, &i);
    fp_mul(&v, &a->x, &i);
    fp_sq(&x3, &rr);
    fp_sub(&x3, &x3, &j);
    fp_sub(&x3, &x3, &v);
    fp_sub(&x3, &x3, &v);
    fp_sub(&t, &v, &x3);
    fp_mul(&y3, &rr, &t);
    fp_mul(&t, &a->y, &j);
    fp_add(&t, &t, &t);
    fp_sub(&y3, &y3, &t);
    fp_add(&z3, &a->z, &h);
    fp_sq(&z3, &z3);
    fp_sub(&z3, &z3, &z1z1);
    fp_sub(&z3, &z3, &hh);
    r->x = x3;
    r->y = y3;
    r->z = z3;
}

struct sp_aff {
    struct fp x, y;
};

/* Window-parallel Pippenger over affine points: one thread per window, all
 * n points per window, so a window pays n mixed adds + 2^(c+1) bucket adds.
 * Variable-time in the scalars (as bellman's multiexp and the vendored
 * g1_msm); used only for the H query. */
#define SP_DENSE_C 16u

struct sp_dense_ctx {
    const struct sp_aff *pts;
    const uint8_t *inf;          /* 1 = point at infinity, skip */
    const uint64_t (*k)[4];      /* canonical scalar limbs */
    const uint8_t *raw;          /* decode input */
    const struct fr *sc;
    struct sp_aff *out_pts;
    uint8_t *out_inf;
    uint64_t (*out_k)[4];
    size_t n;
    struct g1_point win[32];
    int err[SPROUT_MAX_THREADS];
};

static void sp_dense_decode_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    struct sp_dense_ctx *c = p;
    for (size_t i = lo; i < hi; i++) {
        struct g1_point q;
        if (!g1_from_uncompressed(&q, c->raw + i * SP_G1_RAW)) {
            c->err[tid] = 1;
            return;
        }
        c->out_inf[i] = g1_is_identity(&q);
        c->out_pts[i].x = q.x; /* z = 1 after decode */
        c->out_pts[i].y = q.y;
        sp_fr_raw(c->out_k[i], &c->sc[i]);
    }
}

static void sp_dense_window_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    struct sp_dense_ctx *c = p;
    const size_t nb = ((size_t)1 << SP_DENSE_C) - 1;
    struct g1_point *bk = malloc(nb * sizeof *bk);
    if (!bk) {
        c->err[tid] = 2;
        return;
    }
    for (size_t w = lo; w < hi; w++) {
        for (size_t b = 0; b < nb; b++)
            g1_identity(&bk[b]);
        unsigned off = (unsigned)w * SP_DENSE_C;
        unsigned word = off / 64, bit = off % 64;
        for (size_t i = 0; i < c->n; i++) {
            if (c->inf[i])
                continue;
            uint64_t d = c->k[i][word] >> bit;
            if (bit + SP_DENSE_C > 64 && word + 1 < 4)
                d |= c->k[i][word + 1] << (64 - bit);
            d &= ((uint64_t)1 << SP_DENSE_C) - 1;
            if (d)
                sp_g1_madd(&bk[d - 1], &bk[d - 1], &c->pts[i].x, &c->pts[i].y);
        }
        struct g1_point run, sum;
        g1_identity(&run);
        g1_identity(&sum);
        for (size_t b = nb; b > 0; b--) {
            g1_add(&run, &run, &bk[b - 1]);
            g1_add(&sum, &sum, &run);
        }
        c->win[w] = sum;
    }
    free(bk);
}

#define SP_DENSE_WINDOWS ((255u + SP_DENSE_C - 1u) / SP_DENSE_C)

struct sp_win_arg {
    struct sp_dense_ctx *c;
    size_t w;
};

static void *sp_window_thread(void *p)
{
    struct sp_win_arg *a = p;
    sp_dense_window_rows(a->c, a->w, a->w + 1, (unsigned)a->w);
    return NULL;
}

/* sum_i sc[i] * P_i over n uncompressed G1 points in raw[]. */
static enum zc23_sprout_status sp_msm_g1_dense(const uint8_t *raw,
                                               const struct fr *sc, size_t n,
                                               unsigned T, struct g1_point *out)
{
    struct sp_dense_ctx *c = calloc(1, sizeof *c);
    if (!c)
        return ZC23_SPROUT_OOM;
    c->n = n;
    c->raw = raw;
    c->sc = sc;
    c->out_pts = malloc(n * sizeof *c->out_pts);
    c->out_inf = malloc(n ? n : 1);
    c->out_k = malloc(n * sizeof *c->out_k);
    enum zc23_sprout_status st = ZC23_SPROUT_OK;
    if (!c->out_pts || !c->out_inf || !c->out_k) {
        st = ZC23_SPROUT_OOM;
        goto done;
    }
    sp_parallel_for(T, n, sp_dense_decode_rows, c);
    for (unsigned t = 0; t < SPROUT_MAX_THREADS; t++)
        if (c->err[t])
            st = ZC23_SPROUT_PARAMS_FORMAT;
    if (st != ZC23_SPROUT_OK)
        goto done;
    c->pts = c->out_pts;
    c->inf = c->out_inf;
    c->k = (const uint64_t(*)[4])c->out_k;
    /* One thread per window (16 windows of 16 bits). With T == 1 the
     * windows run inline, one after another. */
    size_t windows = (255 + SP_DENSE_C - 1) / SP_DENSE_C;
    pthread_t th[SP_DENSE_WINDOWS];
    bool started[SP_DENSE_WINDOWS];
    struct sp_win_arg wa[SP_DENSE_WINDOWS];
    for (size_t w = 0; w < windows; w++) {
        wa[w].c = c;
        wa[w].w = w;
        started[w] = w != 0 && T > 1 &&
                     pthread_create(&th[w], NULL, sp_window_thread, &wa[w]) == 0;
    }
    for (size_t w = 0; w < windows; w++)
        if (!started[w])
            sp_window_thread(&wa[w]);
    for (size_t w = 0; w < windows; w++)
        if (started[w])
            pthread_join(th[w], NULL);
    for (unsigned t = 0; t < SPROUT_MAX_THREADS; t++)
        if (c->err[t])
            st = ZC23_SPROUT_OOM;
    if (st != ZC23_SPROUT_OK)
        goto done;
    struct g1_point acc;
    g1_identity(&acc);
    for (size_t w = windows; w > 0; w--) {
        for (unsigned d = 0; d < SP_DENSE_C; d++)
            g1_double(&acc, &acc);
        g1_add(&acc, &acc, &c->win[w - 1]);
    }
    *out = acc;
done:
    if (c->out_k) {
        memory_cleanse(c->out_k, n * sizeof *c->out_k);
        free(c->out_k);
    }
    free(c->out_pts);
    free(c->out_inf);
    memory_cleanse(c, sizeof *c);
    free(c);
    return st;
}

/* ── streaming multi-scalar sums ──────────────────────────────────── */

/* One section of the parameter file: `count` points; the first `n_full`
 * carry full scalars `full[]` (public inputs, or the dense h coefficients),
 * the rest carry bits `bits[i - n_full]`. */
struct sp_section {
    bool g2;
    size_t count;
    size_t n_full;
    const struct fr *full;
    const uint8_t *bits;
};

struct sp_worker {
    const struct sp_section *sec;
    const uint8_t *raw; /* chunk */
    size_t base;        /* section index of raw's first point */
    struct g1_point acc1, off1, full1;
    struct g2_point acc2, off2, full2;
    struct g1_point *tmp1;
    struct g2_point *tmp2;
    size_t tmp_cap;
    bool used_bits;
    int err; /* 0 ok, 1 decode, 2 oom */
};

struct sp_stream_ctx {
    struct sp_worker *w;
};

static void sp_stream_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    struct sp_stream_ctx *sc = p;
    struct sp_worker *w = &sc->w[tid];
    const struct sp_section *s = w->sec;
    size_t psz = s->g2 ? SP_G2_RAW : SP_G1_RAW;
    if (w->err)
        return;

    /* full-scalar prefix of this range: decode then Pippenger. */
    size_t full_hi = hi;
    if (w->base + full_hi > s->n_full)
        full_hi = s->n_full > w->base ? s->n_full - w->base : 0;
    if (full_hi < lo)
        full_hi = lo;
    size_t nf = full_hi - lo;
    if (nf) {
        if (nf > w->tmp_cap) {
            free(w->tmp1);
            free(w->tmp2);
            w->tmp1 = NULL;
            w->tmp2 = NULL;
            if (s->g2)
                w->tmp2 = malloc(nf * sizeof *w->tmp2);
            else
                w->tmp1 = malloc(nf * sizeof *w->tmp1);
            if ((s->g2 && !w->tmp2) || (!s->g2 && !w->tmp1)) {
                w->tmp_cap = 0;
                w->err = 2;
                return;
            }
            w->tmp_cap = nf;
        }
        for (size_t j = 0; j < nf; j++) {
            const uint8_t *pp = w->raw + (lo + j) * psz;
            bool ok = s->g2 ? g2_from_uncompressed(&w->tmp2[j], pp)
                            : g1_from_uncompressed(&w->tmp1[j], pp);
            if (!ok) {
                w->err = 1;
                return;
            }
        }
        const struct fr *sc_full = s->full + w->base + lo;
        if (s->g2) {
            struct g2_point part;
            g2_msm(&part, w->tmp2, sc_full, nf);
            g2_add(&w->full2, &w->full2, &part);
        } else {
            struct g1_point part;
            g1_msm(&part, w->tmp1, sc_full, nf);
            g1_add(&w->full1, &w->full1, &part);
        }
    }

    /* bit-scalar remainder: add every point, keep it by mask. */
    if (full_hi < hi)
        w->used_bits = true;
    for (size_t j = full_hi; j < hi; j++) {
        const uint8_t *pp = w->raw + j * psz;
        uint64_t m = (uint64_t)0 - (uint64_t)(s->bits[w->base + j - s->n_full] & 1u);
        if (s->g2) {
            struct g2_point pt, sum;
            if (!g2_from_uncompressed(&pt, pp)) {
                w->err = 1;
                return;
            }
            g2_add(&sum, &w->acc2, &pt);
            sp_g2_cmov(&w->acc2, &sum, m);
        } else {
            struct g1_point pt, sum;
            if (!g1_from_uncompressed(&pt, pp)) {
                w->err = 1;
                return;
            }
            if (g1_is_identity(&pt))
                continue; /* public key data; adding O changes nothing */
            sp_g1_madd(&sum, &w->acc1, &pt.x, &pt.y); /* pt.z == 1 */
            sp_g1_cmov(&w->acc1, &sum, m);
        }
    }
}

static bool sp_read_exact(FILE *f, void *buf, size_t n)
{
    return fread(buf, 1, n, f) == n;
}

static bool sp_read_u32be(FILE *f, uint32_t *out)
{
    uint8_t b[4];
    if (!sp_read_exact(f, b, 4))
        return false;
    *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
    return true;
}

/* Stream one section (its u32 length must already have been consumed). */
static enum zc23_sprout_status sp_stream_section(
    FILE *f, const struct sp_section *s, uint8_t *buf, size_t buf_bytes,
    unsigned T, const struct g1_point *off1, const struct g2_point *off2,
    struct g1_point *out1, struct g2_point *out2)
{
    size_t psz = s->g2 ? SP_G2_RAW : SP_G1_RAW;
    size_t per_chunk = buf_bytes / psz;
    struct sp_worker w[SP_MAX_THREADS];
    memset(w, 0, sizeof w);
    for (unsigned t = 0; t < T; t++) {
        w[t].sec = s;
        if (s->g2) {
            w[t].acc2 = *off2;
            g2_identity(&w[t].full2);
        } else {
            w[t].acc1 = *off1;
            g1_identity(&w[t].full1);
        }
    }
    enum zc23_sprout_status st = ZC23_SPROUT_OK;
    for (size_t done = 0; done < s->count && st == ZC23_SPROUT_OK;) {
        size_t n = s->count - done;
        if (n > per_chunk)
            n = per_chunk;
        if (!sp_read_exact(f, buf, n * psz)) {
            st = ZC23_SPROUT_PARAMS_IO;
            break;
        }
        for (unsigned t = 0; t < T; t++) {
            w[t].raw = buf;
            w[t].base = done;
        }
        struct sp_stream_ctx sc = { w };
        unsigned TT = (n < (size_t)T * 2u) ? 1u : T;
        sp_parallel_for(TT, n, sp_stream_rows, &sc);
        for (unsigned t = 0; t < T; t++) {
            if (w[t].err == 1)
                st = ZC23_SPROUT_PARAMS_FORMAT;
            else if (w[t].err == 2 && st == ZC23_SPROUT_OK)
                st = ZC23_SPROUT_OOM;
        }
        done += n;
    }
    if (st == ZC23_SPROUT_OK) {
        if (s->g2) {
            struct g2_point neg, sum;
            g2_neg(&neg, off2);
            g2_identity(&sum);
            for (unsigned t = 0; t < T; t++) {
                g2_add(&sum, &sum, &w[t].full2);
                if (w[t].used_bits) { /* structural, not secret */
                    g2_add(&sum, &sum, &w[t].acc2);
                    g2_add(&sum, &sum, &neg);
                }
            }
            *out2 = sum;
        } else {
            struct g1_point neg, sum;
            g1_neg(&neg, off1);
            g1_identity(&sum);
            for (unsigned t = 0; t < T; t++) {
                g1_add(&sum, &sum, &w[t].full1);
                if (w[t].used_bits) {
                    g1_add(&sum, &sum, &w[t].acc1);
                    g1_add(&sum, &sum, &neg);
                }
            }
            *out1 = sum;
        }
    }
    for (unsigned t = 0; t < T; t++) {
        free(w[t].tmp1);
        free(w[t].tmp2);
    }
    memory_cleanse(w, sizeof w);
    return st;
}

/* Witness → bit array; fails if any aux value is not 0/1. Branch-free over
 * the values (the only data-dependent outcome is the validity verdict). */
static bool sp_aux_bits(const struct fr *wit, size_t n, uint8_t *bits)
{
    uint8_t bad = 0;
    uint8_t b[32];
    for (size_t k = 0; k < n; k++) {
        fr_to_bytes(b, &wit[k]);
        uint8_t hi = (uint8_t)(b[0] >> 1);
        for (size_t j = 1; j < 32; j++)
            hi |= b[j];
        bad |= hi;
        bits[k] = (uint8_t)(b[0] & 1u);
    }
    memory_cleanse(b, sizeof b);
    return bad == 0;
}

/* ── the prover ───────────────────────────────────────────────────── */

const char *zc23_sprout_status_str(enum zc23_sprout_status s)
{
    switch (s) {
    case ZC23_SPROUT_OK: return "ok";
    case ZC23_SPROUT_BAD_AUTH: return "malformed auth path";
    case ZC23_SPROUT_NO_PARAMS: return "sprout-groth16.params path not set";
    case ZC23_SPROUT_PARAMS_IO: return "cannot read sprout-groth16.params";
    case ZC23_SPROUT_PARAMS_FORMAT: return "sprout-groth16.params does not match the Sprout circuit";
    case ZC23_SPROUT_UNSATISFIED: return "witness does not satisfy the JoinSplit circuit";
    case ZC23_SPROUT_OOM: return "out of memory";
    case ZC23_SPROUT_RNG: return "OS RNG failure";
    case ZC23_SPROUT_INTERNAL: return "internal prover failure";
    case ZC23_SPROUT_SELFVERIFY: return "produced proof failed verification";
    }
    return "unknown";
}

struct sp_job {
    struct sprout_js_witness w;
    struct sprout_js_public pub;
    struct constraint_system cs;
    bool cs_live;
    struct sp_qap q;
    uint8_t *aux_bits, *a_bits, *b_bits;
    struct fr *b_in_w;
    uint8_t *buf;
    FILE *f;
    char *path;
    struct groth16_vk vk;
    bool vk_live;
    struct fr r, s;
};

static void sp_job_free(struct sp_job *j)
{
    if (j->cs_live)
        cs_free(&j->cs); /* cleanses the witness */
    /* The bit arrays are copies of the secret witness: cleanse them with the
     * sizes from q BEFORE sp_free_qap zeroes q. Sizes match the mallocs in
     * sp_prove_job (n ? n : 1). */
    if (j->aux_bits) {
        memory_cleanse(j->aux_bits, j->q.num_aux ? j->q.num_aux : 1);
        free(j->aux_bits);
    }
    if (j->a_bits) {
        memory_cleanse(j->a_bits, j->q.a_aux_total ? j->q.a_aux_total : 1);
        free(j->a_bits);
    }
    if (j->b_bits) {
        memory_cleanse(j->b_bits, j->q.b_aux_total ? j->q.b_aux_total : 1);
        free(j->b_bits);
    }
    free(j->b_in_w); /* public inputs (packed values and ONE) */
    sp_free_qap(&j->q);
    free(j->buf);
    if (j->f)
        fclose(j->f);
    free(j->path);
    if (j->vk_live) {
        free(j->vk.ic);
        groth16_vk_free_combs(&j->vk);
    }
    memory_cleanse(j, sizeof *j);
}

static enum zc23_sprout_status sp_prove_job(struct sp_job *j,
                                            uint8_t proof_out[192],
                                            const char *params_path,
                                            struct zc23_sprout_prove_stats *st)
{
    unsigned T = sp_thread_count();
    st->threads = T;
    double t0 = sp_now();

    /* 1. synthesize and check every row. */
    cs_init(&j->cs);
    j->cs_live = true;
    if (!j->cs.witness || !j->cs.constraints)
        return ZC23_SPROUT_OOM;
    if (!sprout_synthesize(&j->cs, &j->w))
        return j->cs.oom_error ? ZC23_SPROUT_OOM : ZC23_SPROUT_INTERNAL;
    st->num_constraints = j->cs.num_constraints;
    st->num_inputs = j->cs.num_inputs;
    st->num_aux = j->cs.num_vars - j->cs.num_inputs - 1;
    if (j->cs.num_constraints != SPROUT_NUM_CONSTRAINTS ||
        j->cs.num_inputs != SPROUT_NUM_INPUTS)
        return ZC23_SPROUT_INTERNAL;
    /* every A*B=C row is checked inside the parallel evaluation */
    enum zc23_sprout_status s = sp_qap_eval(&j->cs, &j->q, T);
    if (s != ZC23_SPROUT_OK)
        return s;
    double t1 = sp_now();
    st->synth_s = t1 - t0;

    /* 2. open the params and check the VK prefix before the heavy work. */
    const struct zcl_embedded_vk *evk = sp_embedded_vk();
    if (!evk)
        return ZC23_SPROUT_INTERNAL;
    if (params_path) {
        size_t n = strlen(params_path);
        j->path = malloc(n + 1);
        if (!j->path)
            return ZC23_SPROUT_OOM;
        memcpy(j->path, params_path, n + 1);
    } else {
        j->path = sp_params_path_dup();
    }
    if (!j->path)
        return ZC23_SPROUT_NO_PARAMS;
    j->f = sp_fopen(j->path);
    if (!j->f)
        return ZC23_SPROUT_PARAMS_IO;
    uint8_t vkraw[SP_VK_PREFIX];
    if (!sp_read_exact(j->f, vkraw, sizeof vkraw))
        return ZC23_SPROUT_PARAMS_IO;
    if (memcmp(vkraw, evk->bytes, SP_VK_PREFIX) != 0)
        return ZC23_SPROUT_PARAMS_FORMAT;
    memset(&j->vk, 0, sizeof j->vk);
    if (!groth16_vk_read_raw(&j->vk, evk->bytes, evk->len))
        return ZC23_SPROUT_INTERNAL;
    j->vk_live = true;
    struct g1_point alpha1, beta1, delta1;
    struct g2_point beta2, gamma2, delta2;
    if (!g1_from_uncompressed(&alpha1, vkraw) ||
        !g1_from_uncompressed(&beta1, vkraw + 96) ||
        !g2_from_uncompressed(&beta2, vkraw + 192) ||
        !g2_from_uncompressed(&gamma2, vkraw + 384) ||
        !g1_from_uncompressed(&delta1, vkraw + 576) ||
        !g2_from_uncompressed(&delta2, vkraw + 672))
        return ZC23_SPROUT_PARAMS_FORMAT;
    (void)gamma2;

    /* 3. h(x). */
    s = sp_qap_h(&j->q, T);
    if (s != ZC23_SPROUT_OK)
        return s;
    double t2 = sp_now();
    st->qap_s = t2 - t1;

    struct sp_qap *q = &j->q;
    const struct fr *wit = j->cs.witness;
    j->aux_bits = malloc(q->num_aux ? q->num_aux : 1);
    j->a_bits = malloc(q->a_aux_total ? q->a_aux_total : 1);
    j->b_bits = malloc(q->b_aux_total ? q->b_aux_total : 1);
    j->b_in_w = calloc(q->b_in_total ? q->b_in_total : 1, sizeof(struct fr));
    if (!j->aux_bits || !j->a_bits || !j->b_bits || !j->b_in_w)
        return ZC23_SPROUT_OOM;
    if (!sp_aux_bits(wit + q->num_in, q->num_aux, j->aux_bits))
        return ZC23_SPROUT_INTERNAL; /* every Sprout aux wire is a bit */
    size_t ka = 0, kb = 0, ki = 0;
    for (size_t i = 0; i < q->num_aux; i++) {
        if (q->a_aux_dense[i])
            j->a_bits[ka++] = j->aux_bits[i];
        if (q->b_aux_dense[i])
            j->b_bits[kb++] = j->aux_bits[i];
    }
    for (size_t i = 0; i < q->num_in; i++)
        if (q->b_in_dense[i])
            j->b_in_w[ki++] = wit[i];

    if (!sp_random_fr(&j->r, "sprout_groth16_r") ||
        !sp_random_fr(&j->s, "sprout_groth16_s"))
        return ZC23_SPROUT_RNG;

    j->buf = malloc(SP_CHUNK_BYTES);
    if (!j->buf)
        return ZC23_SPROUT_OOM;

    /* 4. stream H, L, A, B_G1, B_G2. Offsets for the bit sums are public
     * non-identity points of the key itself. */
    uint32_t len;
    struct g1_point H, L, Aq, B1q;
    struct g2_point B2q, unused2;
    struct g1_point unused1;
    struct sp_section sec;

    if (!sp_read_u32be(j->f, &len))
        return ZC23_SPROUT_PARAMS_IO;
    st->h_len = len;
    double th0 = sp_now();
    if ((size_t)len != q->domain - 1)
        return ZC23_SPROUT_PARAMS_FORMAT;
    if ((size_t)len * SP_G1_RAW <= SP_CHUNK_BYTES) {
        /* H fits the read buffer (2^21 - 1 points = 192 MiB): one read,
         * window-parallel Pippenger. */
        if (!sp_read_exact(j->f, j->buf, (size_t)len * SP_G1_RAW))
            return ZC23_SPROUT_PARAMS_IO;
        s = sp_msm_g1_dense(j->buf, q->a, len, T, &H);
    } else {
        sec = (struct sp_section){ false, len, len, q->a, NULL };
        s = sp_stream_section(j->f, &sec, j->buf, SP_CHUNK_BYTES, T, &alpha1,
                              &beta2, &H, &unused2);
    }
    if (s != ZC23_SPROUT_OK)
        return s;

    if (!sp_read_u32be(j->f, &len))
        return ZC23_SPROUT_PARAMS_IO;
    st->h_s = sp_now() - th0;
    st->l_len = len;
    if ((size_t)len != q->num_aux)
        return ZC23_SPROUT_PARAMS_FORMAT;
    sec = (struct sp_section){ false, len, 0, NULL, j->aux_bits };
    s = sp_stream_section(j->f, &sec, j->buf, SP_CHUNK_BYTES, T, &alpha1,
                          &beta2, &L, &unused2);
    if (s != ZC23_SPROUT_OK)
        return s;

    if (!sp_read_u32be(j->f, &len))
        return ZC23_SPROUT_PARAMS_IO;
    st->a_len = len;
    if ((size_t)len != q->num_in + q->a_aux_total)
        return ZC23_SPROUT_PARAMS_FORMAT;
    sec = (struct sp_section){ false, len, q->num_in, wit, j->a_bits };
    s = sp_stream_section(j->f, &sec, j->buf, SP_CHUNK_BYTES, T, &alpha1,
                          &beta2, &Aq, &unused2);
    if (s != ZC23_SPROUT_OK)
        return s;

    if (!sp_read_u32be(j->f, &len))
        return ZC23_SPROUT_PARAMS_IO;
    st->b_len = len;
    if ((size_t)len != q->b_in_total + q->b_aux_total)
        return ZC23_SPROUT_PARAMS_FORMAT;
    sec = (struct sp_section){ false, len, q->b_in_total, j->b_in_w, j->b_bits };
    s = sp_stream_section(j->f, &sec, j->buf, SP_CHUNK_BYTES, T, &alpha1,
                          &beta2, &B1q, &unused2);
    if (s != ZC23_SPROUT_OK)
        return s;

    if (!sp_read_u32be(j->f, &len))
        return ZC23_SPROUT_PARAMS_IO;
    if ((size_t)len != q->b_in_total + q->b_aux_total)
        return ZC23_SPROUT_PARAMS_FORMAT;
    sec = (struct sp_section){ true, len, q->b_in_total, j->b_in_w, j->b_bits };
    s = sp_stream_section(j->f, &sec, j->buf, SP_CHUNK_BYTES, T, &alpha1,
                          &beta2, &unused1, &B2q);
    if (s != ZC23_SPROUT_OK)
        return s;
    fclose(j->f);
    j->f = NULL;

    /* 5. assemble. */
    uint64_t r_raw[4], s_raw[4], rs_raw[4];
    struct fr rs;
    fr_mul(&rs, &j->r, &j->s);
    sp_fr_raw(r_raw, &j->r);
    sp_fr_raw(s_raw, &j->s);
    sp_fr_raw(rs_raw, &rs);

    struct groth16_proof pf;
    struct g1_point tmp1;
    struct g2_point tmp2;

    pf.a = alpha1;                        /* A */
    g1_add(&pf.a, &pf.a, &Aq);
    g1_scalar_mul(&tmp1, &delta1, r_raw);
    g1_add(&pf.a, &pf.a, &tmp1);

    pf.b = beta2;                         /* B in G2 */
    g2_add(&pf.b, &pf.b, &B2q);
    sp_g2_mul_ct(&tmp2, &delta2, s_raw);
    g2_add(&pf.b, &pf.b, &tmp2);

    struct g1_point b1 = beta1;           /* B in G1 */
    g1_add(&b1, &b1, &B1q);
    g1_scalar_mul(&tmp1, &delta1, s_raw);
    g1_add(&b1, &b1, &tmp1);

    g1_add(&pf.c, &H, &L);                /* C */
    g1_scalar_mul(&tmp1, &pf.a, s_raw);
    g1_add(&pf.c, &pf.c, &tmp1);
    g1_scalar_mul(&tmp1, &b1, r_raw);
    g1_add(&pf.c, &pf.c, &tmp1);
    g1_scalar_mul(&tmp1, &delta1, rs_raw);
    g1_neg(&tmp1, &tmp1);
    g1_add(&pf.c, &pf.c, &tmp1);

    memory_cleanse(r_raw, sizeof r_raw);
    memory_cleanse(s_raw, sizeof s_raw);
    memory_cleanse(rs_raw, sizeof rs_raw);
    memory_cleanse(&rs, sizeof rs);
    memory_cleanse(&b1, sizeof b1);
    memory_cleanse(&tmp1, sizeof tmp1);
    memory_cleanse(&tmp2, sizeof tmp2);

    uint8_t out[192];
    sp_g1_compress(out, &pf.a);
    sp_g2_compress(out + 48, &pf.b);
    sp_g1_compress(out + 144, &pf.c);
    double t3 = sp_now();
    st->msm_s = t3 - t2;

    /* 6. self-verify under the compiled-in key. */
    struct groth16_proof chk;
    uint8_t in[272];
    memcpy(in, j->w.rt, 32);
    memcpy(in + 32, j->w.h_sig, 32);
    memcpy(in + 64, j->pub.nf[0], 32);
    memcpy(in + 96, j->pub.mac[0], 32);
    memcpy(in + 128, j->pub.nf[1], 32);
    memcpy(in + 160, j->pub.mac[1], 32);
    memcpy(in + 192, j->pub.cm[0], 32);
    memcpy(in + 224, j->pub.cm[1], 32);
    for (size_t i = 0; i < 8; i++) {
        in[256 + i] = (uint8_t)(j->w.vpub_old >> (8 * i));
        in[264 + i] = (uint8_t)(j->w.vpub_new >> (8 * i));
    }
    uint64_t packed[16][4];
    size_t npk = 0;
    multipack_bytes_to_fr_be(packed, &npk, in, sizeof in);
    bool verified = npk == j->vk.ic_len - 1 && groth16_proof_read(&chk, out) &&
                    groth16_verify(&j->vk, &chk, (const uint64_t(*)[4])packed, npk);
    st->verify_s = sp_now() - t3;
    if (!verified)
        return ZC23_SPROUT_SELFVERIFY;
    memcpy(proof_out, out, 192);
    return ZC23_SPROUT_OK;
}

enum zc23_sprout_status zc23_sprout_prove_status(
    unsigned char *proof_out,
    const unsigned char *phi, const unsigned char *rt,
    const unsigned char *h_sig,
    const unsigned char *in_sk1, uint64_t in_value1,
    const unsigned char *in_rho1, const unsigned char *in_r1,
    const unsigned char *in_auth1,
    const unsigned char *in_sk2, uint64_t in_value2,
    const unsigned char *in_rho2, const unsigned char *in_r2,
    const unsigned char *in_auth2,
    const unsigned char *out_pk1, uint64_t out_value1,
    const unsigned char *out_r1,
    const unsigned char *out_pk2, uint64_t out_value2,
    const unsigned char *out_r2,
    uint64_t vpub_old, uint64_t vpub_new,
    const char *params_path, struct zc23_sprout_prove_stats *stats)
{
    struct zc23_sprout_prove_stats local;
    struct zc23_sprout_prove_stats *st = stats ? stats : &local;
    memset(st, 0, sizeof *st);
    if (!proof_out)
        return ZC23_SPROUT_INTERNAL;
    memset(proof_out, 0, 192);

    struct sp_job *j = calloc(1, sizeof *j);
    if (!j)
        return ZC23_SPROUT_OOM;
    double t0 = sp_now();

    struct sprout_js_witness *w = &j->w;
    memcpy(w->phi, phi, 32);
    memcpy(w->rt, rt, 32);
    memcpy(w->h_sig, h_sig, 32);
    const unsigned char *sk[2] = { in_sk1, in_sk2 };
    const unsigned char *rho[2] = { in_rho1, in_rho2 };
    const unsigned char *rr[2] = { in_r1, in_r2 };
    const unsigned char *auth[2] = { in_auth1, in_auth2 };
    uint64_t val[2] = { in_value1, in_value2 };
    enum zc23_sprout_status s = ZC23_SPROUT_OK;
    for (size_t i = 0; i < 2; i++) {
        memcpy(w->in[i].a_sk, sk[i], 32);
        memcpy(w->in[i].rho, rho[i], 32);
        memcpy(w->in[i].r, rr[i], 32);
        w->in[i].value = val[i];
        if (!sprout_parse_auth(auth[i], &w->in[i]))
            s = ZC23_SPROUT_BAD_AUTH;
    }
    memcpy(w->out[0].a_pk, out_pk1, 32);
    memcpy(w->out[0].r, out_r1, 32);
    w->out[0].value = out_value1;
    memcpy(w->out[1].a_pk, out_pk2, 32);
    memcpy(w->out[1].r, out_r2, 32);
    w->out[1].value = out_value2;
    w->vpub_old = vpub_old;
    w->vpub_new = vpub_new;

    if (s == ZC23_SPROUT_OK) {
        sprout_compute_public(w, &j->pub);
        s = sp_prove_job(j, proof_out, params_path, st);
    }
    if (s != ZC23_SPROUT_OK)
        memset(proof_out, 0, 192);
    st->total_s = sp_now() - t0;
    sp_job_free(j);
    free(j);
    return s;
}

void zc23_sprout_prove(
    unsigned char *proof_out,
    const unsigned char *phi, const unsigned char *rt,
    const unsigned char *h_sig,
    const unsigned char *in_sk1, uint64_t in_value1,
    const unsigned char *in_rho1, const unsigned char *in_r1,
    const unsigned char *in_auth1,
    const unsigned char *in_sk2, uint64_t in_value2,
    const unsigned char *in_rho2, const unsigned char *in_r2,
    const unsigned char *in_auth2,
    const unsigned char *out_pk1, uint64_t out_value1,
    const unsigned char *out_r1,
    const unsigned char *out_pk2, uint64_t out_value2,
    const unsigned char *out_r2,
    uint64_t vpub_old, uint64_t vpub_new)
{
    enum zc23_sprout_status s = zc23_sprout_prove_status(
        proof_out, phi, rt, h_sig, in_sk1, in_value1, in_rho1, in_r1, in_auth1,
        in_sk2, in_value2, in_rho2, in_r2, in_auth2, out_pk1, out_value1,
        out_r1, out_pk2, out_value2, out_r2, vpub_old, vpub_new, NULL, NULL);
    switch (s) {
    case ZC23_SPROUT_OK:
        return;
    case ZC23_SPROUT_UNSATISFIED:
    case ZC23_SPROUT_SELFVERIFY:
        /* proof_out is all zero; the caller's JSDescription::Verify fails. */
        fprintf(stderr, "zc23_sprout_prove: %s; no proof emitted\n",
                zc23_sprout_status_str(s));
        return;
    default:
        /* Rust panics here (assert_eq!/expect); a panic across the FFI
         * boundary aborts the process. */
        fprintf(stderr, "zc23_sprout_prove: %s; aborting\n",
                zc23_sprout_status_str(s));
        abort();
    }
}
