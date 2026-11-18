/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Groth16 prover — pure C23 implementation.
 * Implements R1CS constraint system, FFT over Fr,
 * multi-scalar multiplication (Pippenger), bellman proving key parsing,
 * and the Groth16 prove algorithm. */

#include "sapling/groth16_prover.h"
#include "core/random.h"
#include "crypto/random_secret.h"
#include "support/cleanse.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

/* ── test hook: failing-realloc injector ───────────────────── */

/* When non-NULL, the three CS-building helpers call this instead of
 * zcl_realloc. Returning NULL simulates OOM. File-scope so the hook
 * influences only this translation unit (no effect on zcl_realloc
 * calls elsewhere, nor on pk reads / MSM / FFT buffers). */
static void *(*g_groth16_realloc_hook)(void *, size_t) = NULL;

void groth16_prover_test_set_realloc_hook(void *(*hook)(void *, size_t))
{
    g_groth16_realloc_hook = hook;
}

#ifdef ZCL_TESTING
/* ── Test-ONLY deterministic RNG hook for the blinding factors r, s
 *    (see groth16_prover.h). Compiled ONLY under -DZCL_TESTING; the
 *    production node binary has neither this symbol nor the branch in
 *    groth16_prove below, so r, s ALWAYS come from zcl_random_secret_bytes
 *    there. Defaults to NULL even in a ZCL_TESTING build. ────────────── */
#include <stdatomic.h>
static _Atomic(groth16_test_rng_fn) g_groth16_test_rng_fn = NULL;
static void *g_groth16_test_rng_user = NULL;
void groth16_set_test_rng_hook(groth16_test_rng_fn fn, void *user)
{
    /* Publish user before fn so a reader that observes non-NULL fn also
     * observes the matching user pointer (mirrors sapling_set_test_rng_hook). */
    g_groth16_test_rng_user = user;
    atomic_store_explicit(&g_groth16_test_rng_fn, fn, memory_order_release);
}

/* Fill n bytes of blinding randomness: the test hook when installed, else
 * the production CSPRNG. Byte-identical to zcl_random_secret_bytes when no
 * hook is set. */
static bool groth16_blind_bytes(uint8_t *out, size_t n, const char *label)
{
    groth16_test_rng_fn hook =
        atomic_load_explicit(&g_groth16_test_rng_fn, memory_order_acquire);
    if (hook)
        return hook(g_groth16_test_rng_user, out, n);
    return zcl_random_secret_bytes(out, n, label);
}
#else
static inline bool groth16_blind_bytes(uint8_t *out, size_t n, const char *label)
{
    return zcl_random_secret_bytes(out, n, label);
}
#endif /* ZCL_TESTING */

static inline void *g_cs_realloc(void *ptr, size_t size, const char *label)
{
    if (g_groth16_realloc_hook)
        return g_groth16_realloc_hook(ptr, size);
    return zcl_realloc(ptr, size, label);
}

/* ── test hook: force non-pow-2 FFT domain in groth16_prove ── */

/* When non-zero, overrides the computed domain size in groth16_prove
 * so tests can exercise the fr_fft / fr_fft_parallel non-pow-2 branch
 * through the real prover call path. File-scope; never set outside
 * tests. */
static size_t g_force_domain = 0;

void groth16_prover_test_set_force_domain(size_t forced)
{
    g_force_domain = forced;
}

/* ── R1CS Constraint System ─────────────────────────────────────── */

void lc_init(struct linear_combination *lc)
{
    lc->terms = NULL;
    lc->num_terms = 0;
    lc->cap = 0;
    lc->oom_error = false;
}

void lc_free(struct linear_combination *lc)
{
    free(lc->terms);
    lc->terms = NULL;
    lc->num_terms = 0;
    lc->cap = 0;
}

bool lc_add_term(struct linear_combination *lc, size_t var,
                   const struct fr *coeff)
{
    if (lc->num_terms >= lc->cap) {
        size_t new_cap = lc->cap ? lc->cap * 2 : 8;
        size_t bytes = new_cap * sizeof(struct lc_term);
        struct lc_term *new_terms = g_cs_realloc(lc->terms, bytes, "lc_terms");
        if (!new_terms) {
            lc->oom_error = true;
            LOG_FAIL("groth16",
                     "lc_add_term: realloc failed (new_cap=%zu bytes=%zu); "
                     "term dropped, LC marked oom_error",
                     new_cap, bytes);
        }
        lc->terms = new_terms;
        lc->cap = new_cap;
    }
    lc->terms[lc->num_terms].var = var;
    lc->terms[lc->num_terms].coeff = *coeff;
    lc->num_terms++;
    return true;
}

void lc_evaluate(struct fr *result, const struct linear_combination *lc,
                   const struct fr *witness)
{
    fr_zero(result);
    for (size_t i = 0; i < lc->num_terms; i++) {
        struct fr term;
        fr_mul(&term, &lc->terms[i].coeff, &witness[lc->terms[i].var]);
        fr_add(result, result, &term);
    }
}

bool cs_is_satisfied(const struct constraint_system *cs, size_t *bad_index_out)
{
    if (bad_index_out)
        *bad_index_out = SIZE_MAX;
    if (!cs || !cs->witness)
        return false;
    for (size_t i = 0; i < cs->num_constraints; i++) {
        struct fr av, bv, cv, ab;
        lc_evaluate(&av, &cs->constraints[i].a, cs->witness);
        lc_evaluate(&bv, &cs->constraints[i].b, cs->witness);
        lc_evaluate(&cv, &cs->constraints[i].c, cs->witness);
        fr_mul(&ab, &av, &bv);
        if (!fr_eq(&ab, &cv)) {
            if (bad_index_out)
                *bad_index_out = i;
            return false;
        }
    }
    return true;
}

void cs_init(struct constraint_system *cs)
{
    memset(cs, 0, sizeof(*cs));

    /* Variable 0 is always ONE */
    cs->cap_vars = 256;
    cs->witness = zcl_calloc(cs->cap_vars, sizeof(struct fr), "cs_witness");
    fr_one(&cs->witness[0]);
    cs->num_vars = 1;
    cs->num_inputs = 0;

    cs->cap_constraints = 256;
    cs->constraints = zcl_calloc(cs->cap_constraints,
                              sizeof(struct r1cs_constraint), "cs_constraints");
    cs->num_constraints = 0;
}

void cs_free(struct constraint_system *cs)
{
    for (size_t i = 0; i < cs->num_constraints; i++) {
        lc_free(&cs->constraints[i].a);
        lc_free(&cs->constraints[i].b);
        lc_free(&cs->constraints[i].c);
    }
    free(cs->constraints);
    if (cs->witness)
        memory_cleanse(cs->witness, cs->cap_vars * sizeof(struct fr));
    free(cs->witness);
    memset(cs, 0, sizeof(*cs));
}

static size_t cs_alloc_var(struct constraint_system *cs, const struct fr *value)
{
    if (cs->num_vars >= cs->cap_vars) {
        size_t new_cap = cs->cap_vars * 2;
        /* Grow by hand instead of realloc: the witness holds secret field
         * assignments, so the old buffer must be cleansed before release —
         * realloc would free it with the secret elements intact. */
        /* Allocate the new buffer through g_cs_realloc(NULL, ...) so the
         * test realloc hook (OOM injection) still fires. */
        struct fr *new_w = g_cs_realloc(NULL, new_cap * sizeof(struct fr),
                                        "cs_witness");
        if (!new_w) {
            cs->oom_error = true;
            LOG_RETURN(0, "groth16",
                       "cs_alloc_var: alloc failed (new_cap=%zu); "
                       "returning 0 which aliases CS_ONE, CS marked oom_error",
                       new_cap);
        }
        memcpy(new_w, cs->witness, cs->num_vars * sizeof(struct fr));
        memory_cleanse(cs->witness, cs->cap_vars * sizeof(struct fr));
        free(cs->witness);
        cs->witness = new_w;
        cs->cap_vars = new_cap;
    }
    size_t idx = cs->num_vars++;
    cs->witness[idx] = *value;
    return idx;
}

size_t cs_alloc_input(struct constraint_system *cs, const struct fr *value)
{
    size_t idx = cs_alloc_var(cs, value);
    cs->num_inputs++;
    return idx;
}

size_t cs_alloc_aux(struct constraint_system *cs, const struct fr *value)
{
    return cs_alloc_var(cs, value);
}

/* Stores a copy of src in dst in an allocation of exactly src->num_terms
 * entries. A constraint is written once and never appended to, so the
 * doubling capacity (first allocation 8 terms) lc_add_term gives a gadget's
 * scratch combination is pure waste there: most combinations hold one to three
 * terms and a spend circuit stores about 3 x 100,000 of them. Same terms in
 * the same order, so every proof is unchanged. */
static bool lc_copy_exact(struct linear_combination *dst,
                          const struct linear_combination *src)
{
    lc_init(dst);
    if (src->num_terms == 0)
        return true;
    if (src->num_terms > SIZE_MAX / sizeof(struct lc_term)) {
        dst->oom_error = true;
        LOG_FAIL("groth16", "lc_copy_exact: term count overflow (%zu)",
                 src->num_terms);
    }
    size_t bytes = src->num_terms * sizeof(struct lc_term);
    struct lc_term *terms = g_cs_realloc(NULL, bytes, "lc_terms");
    if (!terms) {
        dst->oom_error = true;
        LOG_FAIL("groth16",
                 "lc_copy_exact: alloc failed (terms=%zu bytes=%zu); "
                 "constraint dropped, LC marked oom_error",
                 src->num_terms, bytes);
    }
    memcpy(terms, src->terms, bytes);
    dst->terms = terms;
    dst->num_terms = src->num_terms;
    dst->cap = src->num_terms;
    return true;
}

bool cs_enforce(struct constraint_system *cs,
                const struct linear_combination *a,
                const struct linear_combination *b,
                const struct linear_combination *c)
{
    /* Propagate any caller-local LC OOM: a gadget may have ignored a
     * bool return from lc_add_term and handed us a truncated LC. */
    if (a->oom_error || b->oom_error || c->oom_error) {
        cs->oom_error = true;
        LOG_FAIL("groth16",
                 "cs_enforce: input LC has oom_error set "
                 "(a=%d b=%d c=%d); constraint dropped, CS marked oom_error",
                 (int)a->oom_error, (int)b->oom_error, (int)c->oom_error);
    }

    if (cs->num_constraints >= cs->cap_constraints) {
        size_t new_cap = cs->cap_constraints * 2;
        size_t bytes = new_cap * sizeof(struct r1cs_constraint);
        struct r1cs_constraint *new_c = g_cs_realloc(cs->constraints, bytes,
                                                     "cs_constraints");
        if (!new_c) {
            cs->oom_error = true;
            LOG_FAIL("groth16",
                     "cs_enforce: realloc failed (new_cap=%zu bytes=%zu); "
                     "constraint dropped, CS marked oom_error",
                     new_cap, bytes);
        }
        cs->constraints = new_c;
        cs->cap_constraints = new_cap;
    }

    /* Build the constraint into scratch LCs first; only bump
     * num_constraints after every internal lc_add_term succeeds. */
    struct r1cs_constraint *con = &cs->constraints[cs->num_constraints];
    lc_init(&con->a);
    lc_init(&con->b);
    lc_init(&con->c);

    if (!lc_copy_exact(&con->a, a) || !lc_copy_exact(&con->b, b) ||
        !lc_copy_exact(&con->c, c)) {
        cs->oom_error = true;
        lc_free(&con->a); lc_free(&con->b); lc_free(&con->c);
        LOG_FAIL("groth16", "cs_enforce: constraint copy failed "
                 "(a=%zu b=%zu c=%zu terms); CS marked oom_error",
                 a->num_terms, b->num_terms, c->num_terms);
    }
    cs->num_constraints++;
    return true;
}

/* ── Fr helpers ─────────────────────────────────────────────────── */

static void fr_to_raw(uint64_t raw[4], const struct fr *a)
{
    uint8_t bytes[32];
    fr_to_bytes(bytes, a);
    memcpy(raw, bytes, 32);
}

/* ── Fr helpers shared with the FFT (msm_parallel.c) ────────────── */

void fr_pow_u64(struct fr *r, const struct fr *base, uint64_t exp)
{
    struct fr result, b;
    fr_one(&result);
    b = *base;
    while (exp > 0) {
        if (exp & 1)
            fr_mul(&result, &result, &b);
        fr_sq(&b, &b);
        exp >>= 1;
    }
    *r = result;
}

/* ── Bellman Parameters file reader ─────────────────────────────── */

/* bellman Parameters format (all multi-byte integers are big-endian):
 *
 * VK section:
 *   alpha_g1     (G1 uncompressed, 96 bytes)
 *   beta_g1      (G1 uncompressed, 96 bytes)
 *   beta_g2      (G2 uncompressed, 192 bytes)
 *   gamma_g2     (G2 uncompressed, 192 bytes)
 *   delta_g1     (G1 uncompressed, 96 bytes)
 *   delta_g2     (G2 uncompressed, 192 bytes)
 *   ic_len       (u32 BE)
 *   ic[0..ic_len-1] (G1 uncompressed, 96 bytes each)
 *
 * PK arrays:
 *   h_len        (u32 BE)
 *   h[0..h_len-1]   (G1 uncompressed)
 *   l_len        (u32 BE)
 *   l[0..l_len-1]   (G1 uncompressed)
 *   a_len        (u32 BE)
 *   a[0..a_len-1]   (G1 uncompressed)
 *   b_g1_len     (u32 BE)
 *   b_g1[0..len-1]  (G1 uncompressed)
 *   b_g2_len     (u32 BE)
 *   b_g2[0..len-1]  (G2 uncompressed)
 *
 * Trailing:
 *   contributions hash (variable length)
 */

struct pk_reader {
    const uint8_t *data;
    size_t len;
    size_t pos;
};

static bool pkr_read(struct pk_reader *r, void *out, size_t n)
{
    if (r->pos + n > r->len)
        LOG_FAIL("groth16_pk",
                 "pkr_read: out of bounds: pos=%zu+need=%zu > len=%zu",
                 r->pos, n, r->len);
    memcpy(out, r->data + r->pos, n);
    r->pos += n;
    return true;
}

static bool pkr_u32_be(struct pk_reader *r, uint32_t *out)
{
    uint8_t buf[4];
    if (!pkr_read(r, buf, 4))
        LOG_FAIL("groth16_pk", "pkr_u32_be: underlying pkr_read failed");
    *out = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | buf[3];
    return true;
}

static bool pkr_g1(struct pk_reader *r, struct g1_point *p)
{
    if (r->pos + 96 > r->len)
        LOG_FAIL("groth16_pk",
                 "pkr_g1: out of bounds: pos=%zu need=96 len=%zu",
                 r->pos, r->len);
    bool ok = g1_from_uncompressed(p, r->data + r->pos);
    r->pos += 96;
    return ok;
}

static bool pkr_g2(struct pk_reader *r, struct g2_point *p)
{
    if (r->pos + 192 > r->len)
        LOG_FAIL("groth16_pk",
                 "pkr_g2: out of bounds: pos=%zu need=192 len=%zu",
                 r->pos, r->len);
    bool ok = g2_from_uncompressed(p, r->data + r->pos);
    r->pos += 192;
    return ok;
}

/* A proving-key query is hundreds of thousands of points, each checked to be
 * on the curve, so the arrays are decoded on the prover's thread budget. */
struct pk_array_job {
    const uint8_t *data;
    struct g1_point *g1;
    struct g2_point *g2;
    atomic_bool bad;
};

static void pk_array_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct pk_array_job *j = ctx;
    bool ok = true;
    for (size_t i = lo; i < hi && ok; i++)
        ok = j->g1 ? g1_from_uncompressed(&j->g1[i], j->data + i * 96)
                   : g2_from_uncompressed(&j->g2[i], j->data + i * 192);
    if (!ok)
        atomic_store(&j->bad, true);
}

/* Decodes count points of point_len bytes each into a new array of elem_size
 * structs; NULL when the section is truncated, a point is invalid or the
 * allocation fails. */
static void *pkr_point_array(struct pk_reader *r, uint32_t count,
                             size_t point_len, size_t elem_size)
{
    if ((r->len - r->pos) / point_len < count)
        LOG_NULL("groth16_pk",
                 "pkr_point_array: out of bounds: pos=%zu need=%u x %zu len=%zu",
                 r->pos, count, point_len, r->len);
    void *arr = zcl_calloc(count, elem_size, "pk_point_array");
    if (!arr)
        LOG_NULL("groth16_pk", "pkr_point_array: zcl_calloc failed (count=%u)",
                 count);
    struct pk_array_job job = { .data = r->data + r->pos };
    if (point_len == 96)
        job.g1 = arr;
    else
        job.g2 = arr;
    groth16_parallel_for(groth16_prover_threads(), count, 2048, pk_array_range,
                         &job);
    if (atomic_load(&job.bad)) {
        free(arr);
        LOG_NULL("groth16_pk",
                 "pkr_point_array: invalid point among %u at pos=%zu", count,
                 r->pos);
    }
    r->pos += (size_t)count * point_len;
    return arr;
}

static struct g1_point *pkr_g1_array(struct pk_reader *r, uint32_t count)
{
    return pkr_point_array(r, count, 96, sizeof(struct g1_point));
}

static struct g2_point *pkr_g2_array(struct pk_reader *r, uint32_t count)
{
    return pkr_point_array(r, count, 192, sizeof(struct g2_point));
}

/* Reads the VK section and the IC array of the proving key. */
static bool groth16_pk_read_vk_ic(struct groth16_pk *pk, struct pk_reader *r)
{
    /* Read VK */
    if (!pkr_g1(r, &pk->alpha_g1)) {
        LOG_ERROR_IN("groth16_pk_read", "groth16_pk", "pk_read: alpha_g1 parse failed");
        return false;
    }
    if (!pkr_g1(r, &pk->beta_g1)) {
        LOG_ERROR_IN("groth16_pk_read", "groth16_pk", "pk_read: beta_g1 parse failed");
        return false;
    }
    if (!pkr_g2(r, &pk->beta_g2)) {
        LOG_ERROR_IN("groth16_pk_read", "groth16_pk", "pk_read: beta_g2 parse failed");
        return false;
    }
    if (!pkr_g2(r, &pk->gamma_g2)) {
        LOG_ERROR_IN("groth16_pk_read", "groth16_pk", "pk_read: gamma_g2 parse failed");
        return false;
    }
    if (!pkr_g1(r, &pk->delta_g1)) {
        LOG_ERROR_IN("groth16_pk_read", "groth16_pk", "pk_read: delta_g1 parse failed");
        return false;
    }
    if (!pkr_g2(r, &pk->delta_g2)) {
        LOG_ERROR_IN("groth16_pk_read", "groth16_pk", "pk_read: delta_g2 parse failed");
        return false;
    }

    /* Copy to VK struct for verification */
    pk->vk.alpha_g1 = pk->alpha_g1;
    pk->vk.beta_g2 = pk->beta_g2;
    pk->vk.gamma_g2 = pk->gamma_g2;
    pk->vk.delta_g2 = pk->delta_g2;

    /* IC points */
    uint32_t ic_len;
    if (!pkr_u32_be(r, &ic_len)) {
        LOG_ERROR_IN("groth16_pk_read", "groth16_pk", "pk_read: ic_len u32 parse failed");
        return false;
    }
    pk->vk.ic_len = ic_len;
    pk->num_inputs = ic_len - 1;
    pk->vk.ic = pkr_g1_array(r, ic_len);
    if (!pk->vk.ic) {
        groth16_pk_free(pk);
        LOG_ERROR_IN("groth16_pk_read", "groth16_pk", "pk_read: ic[] parse failed (ic_len=%u)", ic_len);
        return false;
    }
    return true;
}

bool groth16_pk_read(struct groth16_pk *pk, const uint8_t *data, size_t len)
{
    memset(pk, 0, sizeof(*pk));
    struct pk_reader r = { data, len, 0 };

    if (!groth16_pk_read_vk_ic(pk, &r))
        return false;

    /* H query */
    uint32_t h_len;
    if (!pkr_u32_be(&r, &h_len)) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: h_len u32 parse failed");
    }
    pk->h_len = h_len;
    pk->h_g1 = pkr_g1_array(&r, h_len);
    if (!pk->h_g1) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: h_g1[] parse failed (h_len=%u)", h_len);
    }

    /* L query */
    uint32_t l_len;
    if (!pkr_u32_be(&r, &l_len)) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: l_len u32 parse failed");
    }
    pk->l_len = l_len;
    pk->l_g1 = pkr_g1_array(&r, l_len);
    if (!pk->l_g1) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: l_g1[] parse failed (l_len=%u)", l_len);
    }

    /* A query */
    uint32_t a_len;
    if (!pkr_u32_be(&r, &a_len)) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: a_len u32 parse failed");
    }
    pk->a_len = a_len;
    pk->a_g1 = pkr_g1_array(&r, a_len);
    if (!pk->a_g1) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: a_g1[] parse failed (a_len=%u)", a_len);
    }

    /* B G1 query */
    uint32_t b_g1_len;
    if (!pkr_u32_be(&r, &b_g1_len)) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: b_g1_len u32 parse failed");
    }
    pk->b_len = b_g1_len;
    pk->b_g1 = pkr_g1_array(&r, b_g1_len);
    if (!pk->b_g1) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: b_g1[] parse failed (b_g1_len=%u)", b_g1_len);
    }

    /* B G2 query */
    uint32_t b_g2_len;
    if (!pkr_u32_be(&r, &b_g2_len)) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: b_g2_len u32 parse failed");
    }
    if (b_g2_len != b_g1_len) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk",
                 "pk_read: b_g1_len=%u != b_g2_len=%u (malformed key)",
                 b_g1_len, b_g2_len);
    }
    pk->b_g2 = pkr_g2_array(&r, b_g2_len);
    if (!pk->b_g2) {
        groth16_pk_free(pk);
        LOG_FAIL("groth16_pk", "pk_read: b_g2[] parse failed (b_g2_len=%u)", b_g2_len);
    }

    return true;
}

void groth16_pk_free(struct groth16_pk *pk)
{
    free(pk->h_g1);
    free(pk->l_g1);
    free(pk->a_g1);
    free(pk->b_g1);
    free(pk->b_g2);
    free(pk->vk.ic);
    memset(pk, 0, sizeof(*pk));
}

/* ── Groth16 Prover ─────────────────────────────────────────────── */

/* The Groth16 proving algorithm computes proof elements (A, B, C):
 *
 *   A = alpha_g1 + sum(w[i] * a_g1[i], i=0..m) + r * delta_g1
 *
 *   B_g2 = beta_g2 + sum(w[i] * b_g2[i], i=0..m) + s * delta_g2
 *   B_g1 = beta_g1 + sum(w[i] * b_g1[i], i=0..m) + s * delta_g1
 *
 *   C = sum(h[i] * h_g1[i])                 (quotient polynomial)
 *     + sum(w[l+1..m] * l_g1[i])            (private inputs)
 *     + s * A + r * B_g1 - r*s * delta_g1   (blinding)
 *
 * Where:
 *   w[0] = 1, w[1..l] = public inputs, w[l+1..m] = private witness
 *   r, s are random blinding scalars
 *   h(x) = (A(x)*B(x) - C(x)) / z_H(x) is the quotient polynomial */

/* Per-proof compacted query state: density maps, their totals and the
 * compacted witness scalars. */
struct groth16_prove_dense {
    bool *a_aux_dense;
    bool *b_in_dense;
    bool *b_aux_dense;
    size_t a_aux_total;
    size_t b_in_total;
    size_t b_aux_total;
    struct fr *a_aux_w;
    struct fr *b_in_w;
    struct fr *b_aux_w;
};

/* Domain size: smallest power of 2 >= n_rows (EvaluationDomain::from_coeffs). */
static size_t groth16_prove_domain_for_rows(size_t n_rows)
{
    size_t domain = 1;
    while (domain < n_rows)
        domain <<= 1;

    /* test hook: force a non-pow-2 domain to exercise the fr_fft
     * failure-propagation path. Never set outside tests. */
    if (g_force_domain)
        domain = g_force_domain;
    return domain;
}

/* Fill adapters for fr_sample_uniform: each rejected candidate is a fresh
 * draw from the same source under the same label. */
static bool groth16_fill_r_blind(void *user, uint8_t *out, size_t n)
{
    (void)user;
    return groth16_blind_bytes(out, n, "groth16_r_blind");
}

static bool groth16_fill_s_blind(void *user, uint8_t *out, size_t n)
{
    (void)user;
    return groth16_blind_bytes(out, n, "groth16_s_blind");
}

/* r and s are uniform in [0, r) by rejection sampling (bellman Fr::random),
 * never a raw 256-bit value: that was biased and tier-dependent. */
static bool groth16_prove_draw_blinds(struct fr *r_blind, struct fr *s_blind)
{
    if (!fr_sample_uniform(r_blind, groth16_fill_r_blind, NULL))
        LOG_FAIL("groth16", "prove: could not draw an unbiased r blind");
    if (!fr_sample_uniform(s_blind, groth16_fill_s_blind, NULL))
        LOG_FAIL("groth16", "prove: could not draw an unbiased s blind");
    return true;
}

/* ── Step 1 and 2: the quotient polynomial h ── */

/* The QAP vectors a, b, c over the evaluation domain. h is computed in a. */
struct groth16_abc {
    const struct constraint_system *cs;
    struct fr *v[3];
    size_t domain;
};

static void groth16_abc_free(struct groth16_abc *abc)
{
    for (int k = 0; k < 3; k++) {
        if (abc->v[k])
            memory_cleanse(abc->v[k], abc->domain * sizeof(struct fr));
        free(abc->v[k]);
        abc->v[k] = NULL;
    }
}

/* Rows [lo, hi) of a, b, c: each constraint's linear combinations evaluated
 * at the witness. */
static void groth16_abc_fill_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    const struct groth16_abc *abc = ctx;
    const struct constraint_system *cs = abc->cs;
    for (size_t i = lo; i < hi; i++) {
        lc_evaluate(&abc->v[0][i], &cs->constraints[i].a, cs->witness);
        lc_evaluate(&abc->v[1][i], &cs->constraints[i].b, cs->witness);
        lc_evaluate(&abc->v[2][i], &cs->constraints[i].c, cs->witness);
    }
}

/* a[i] = a[i] * b[i] - c[i]. */
static void groth16_abc_pointwise_range(void *ctx, size_t lo, size_t hi,
                                        unsigned tid)
{
    (void)tid;
    const struct groth16_abc *abc = ctx;
    for (size_t i = lo; i < hi; i++) {
        fr_mul(&abc->v[0][i], &abc->v[0][i], &abc->v[1][i]);
        fr_sub(&abc->v[0][i], &abc->v[0][i], &abc->v[2][i]);
    }
}

/* v[k][i] *= scale * g^i over the first `count` vectors. */
struct groth16_powers {
    struct fr *const *v;
    size_t count;
    struct fr g, scale;
};

static void groth16_powers_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    const struct groth16_powers *p = ctx;
    struct fr g_pow;
    fr_pow_u64(&g_pow, &p->g, lo);
    fr_mul(&g_pow, &g_pow, &p->scale);
    for (size_t i = lo; i < hi; i++) {
        for (size_t k = 0; k < p->count; k++)
            fr_mul(&p->v[k][i], &p->v[k][i], &g_pow);
        fr_mul(&g_pow, &g_pow, &p->g);
    }
}

/* The three transforms behind h, leaving a*b - c in abc->v[0], in coefficient
 * form and still on the coset. False when an FFT refuses.
 *
 * a/b/c hold the QAP polynomials' EVALUATIONS at the domain points, so
 * bellman interpolates first (ifft) and only then evaluates on the coset
 * (distribute powers of g, then fft). Skipping the ifft coset-evaluates the
 * wrong polynomial and yields an h that no verifier accepts.
 *
 * fr_fft refuses non-pow-2 domains (returns false). Silent-dropping there
 * would emit a mathematically invalid proof: A/B/C computed from
 * un-transformed coefficients do not satisfy the Groth16 verifier's pairing
 * check, and the prover would still return true. */
static bool groth16_abc_transform(struct groth16_abc *abc,
                                  const struct fr *g_coset, unsigned threads)
{
    size_t domain = abc->domain;
    struct groth16_powers shift = { .v = abc->v, .count = 3, .g = *g_coset };
    fr_one(&shift.scale);

    if (!fr_fft_many(abc->v, 3, domain, true, threads))
        return false;
    groth16_parallel_for(threads, domain, 4096, groth16_powers_range, &shift);
    if (!fr_fft_many(abc->v, 3, domain, false, threads))
        return false;
    groth16_parallel_for(threads, domain, 4096, groth16_abc_pointwise_range,
                         abc);
    return fr_fft_many(abc->v, 1, domain, true, threads);
}

/* Computes h(x) = (a(x)*b(x) - c(x)) / z_H(x) via a coset FFT and returns its
 * `domain` coefficients, or NULL (logged) on an allocation or FFT failure. */
static struct fr *groth16_prove_quotient(const struct constraint_system *cs,
                                         size_t domain, size_t num_in,
                                         unsigned threads)
{
    struct groth16_abc abc = { .cs = cs, .domain = domain };
    for (int k = 0; k < 3; k++)
        abc.v[k] = zcl_calloc(domain, sizeof(struct fr), "groth16_abc_eval");
    if (!abc.v[0] || !abc.v[1] || !abc.v[2]) {
        groth16_abc_free(&abc);
        LOG_NULL("groth16",
                 "prove: OOM allocating a/b/c eval buffers (domain=%zu x 3 x %zu)",
                 domain, sizeof(struct fr));
    }

    size_t n_con = cs->num_constraints < domain ? cs->num_constraints : domain;
    groth16_parallel_for(threads, n_con, 1024, groth16_abc_fill_range, &abc);
    /* The appended `Input(i) * 0 = 0` rows: A = w[i], B = C = 0. */
    for (size_t i = 0; i < num_in && n_con + i < domain; i++)
        abc.v[0][n_con + i] = cs->witness[i];

    /* Coset generator g = Fr::multiplicative_generator = 7 in bellman.
     * Multiplying coefficient i by g^i shifts evaluation to the coset
     * {g*w^i}, where z_H(g*w^i) = g^domain - 1 is a nonzero constant. */
    struct fr g_coset;
    uint8_t g_bytes[32] = {7};
    fr_from_bytes(&g_coset, g_bytes);
    if (!groth16_abc_transform(&abc, &g_coset, threads)) {
        groth16_abc_free(&abc);
        LOG_NULL("groth16", "prove: fr_fft failed on a/b/c (domain=%zu)",
                 domain);
    }

    /* Divide by z_H and undo the coset shift, as the one factor
     * (g^domain - 1)^-1 * g^-i on coefficient i. */
    struct groth16_powers unshift = { .v = abc.v, .count = 1 };
    struct fr one_val;
    fr_one(&one_val);
    fr_pow_u64(&unshift.scale, &g_coset, (uint64_t)domain);
    fr_sub(&unshift.scale, &unshift.scale, &one_val);
    fr_inv(&unshift.scale, &unshift.scale);
    fr_inv(&unshift.g, &g_coset);
    groth16_parallel_for(threads, domain, 4096, groth16_powers_range, &unshift);

    struct fr *h = abc.v[0];
    abc.v[0] = NULL;
    groth16_abc_free(&abc);
    return h;
}

static bool groth16_prove_alloc_dense(struct groth16_prove_dense *d,
                                      size_t num_in, size_t num_aux)
{
    d->a_aux_dense = zcl_calloc(num_aux ? num_aux : 1, 1, "groth16_a_dense");
    d->b_in_dense  = zcl_calloc(num_in ? num_in : 1, 1, "groth16_b_in_dense");
    d->b_aux_dense = zcl_calloc(num_aux ? num_aux : 1, 1, "groth16_b_dense");
    if (!d->a_aux_dense || !d->b_in_dense || !d->b_aux_dense) {
        free(d->a_aux_dense); free(d->b_in_dense); free(d->b_aux_dense);
        return false;
    }
    return true;
}

static void groth16_prove_mark_dense(const struct constraint_system *cs,
                                     struct groth16_prove_dense *d,
                                     size_t num_in, size_t num_aux)
{
    size_t n_con = cs->num_constraints;
    for (size_t i = 0; i < n_con; i++) {
        const struct linear_combination *la = &cs->constraints[i].a;
        for (size_t t = 0; t < la->num_terms; t++) {
            size_t v = la->terms[t].var;
            if (v >= num_in && v - num_in < num_aux)
                d->a_aux_dense[v - num_in] = true;
        }
        const struct linear_combination *lb = &cs->constraints[i].b;
        for (size_t t = 0; t < lb->num_terms; t++) {
            size_t v = lb->terms[t].var;
            if (v < num_in)
                d->b_in_dense[v] = true;
            else if (v - num_in < num_aux)
                d->b_aux_dense[v - num_in] = true;
        }
    }
}

static void groth16_prove_count_dense(struct groth16_prove_dense *d,
                                      size_t num_in, size_t num_aux)
{
    size_t a_aux_total = 0, b_in_total = 0, b_aux_total = 0;
    for (size_t i = 0; i < num_aux; i++) {
        if (d->a_aux_dense[i]) a_aux_total++;
        if (d->b_aux_dense[i]) b_aux_total++;
    }
    for (size_t i = 0; i < num_in; i++)
        if (d->b_in_dense[i]) b_in_total++;
    d->a_aux_total = a_aux_total;
    d->b_in_total = b_in_total;
    d->b_aux_total = b_aux_total;
}

static void groth16_prove_free_dense(struct groth16_prove_dense *d)
{
    free(d->a_aux_dense);
    free(d->b_in_dense);
    free(d->b_aux_dense);
}

/* True when the proving key has the query shape this circuit generates. */
static bool groth16_prove_key_shape_ok(const struct groth16_pk *pk, size_t l,
                                       size_t num_in, size_t num_aux,
                                       size_t domain,
                                       const struct groth16_prove_dense *d)
{
    return !(pk->num_inputs != l || pk->l_len != num_aux ||
             pk->h_len != domain - 1 ||
             pk->a_len != num_in + d->a_aux_total ||
             pk->b_len != d->b_in_total + d->b_aux_total);
}

static bool groth16_prove_alloc_compact(struct groth16_prove_dense *d)
{
    d->a_aux_w = zcl_calloc(d->a_aux_total ? d->a_aux_total : 1,
                            sizeof(struct fr), "groth16_a_aux_w");
    d->b_in_w  = zcl_calloc(d->b_in_total ? d->b_in_total : 1,
                            sizeof(struct fr), "groth16_b_in_w");
    d->b_aux_w = zcl_calloc(d->b_aux_total ? d->b_aux_total : 1,
                            sizeof(struct fr), "groth16_b_aux_w");
    if (!d->a_aux_w || !d->b_in_w || !d->b_aux_w) {
        free(d->a_aux_w); free(d->b_in_w); free(d->b_aux_w);
        return false;
    }
    return true;
}

static void groth16_prove_fill_compact(const struct constraint_system *cs,
                                       struct groth16_prove_dense *d,
                                       size_t num_in, size_t num_aux)
{
    size_t ka = 0, kb = 0;
    for (size_t i = 0; i < num_aux; i++) {
        if (d->a_aux_dense[i]) d->a_aux_w[ka++] = cs->witness[num_in + i];
        if (d->b_aux_dense[i]) d->b_aux_w[kb++] = cs->witness[num_in + i];
    }
    size_t ki = 0;
    for (size_t i = 0; i < num_in; i++)
        if (d->b_in_dense[i]) d->b_in_w[ki++] = cs->witness[i];
}

/* result += scalar * p, in constant time in the scalar. */
static void groth16_prove_add_mul(struct g1_point *result,
                                  const struct g1_point *p,
                                  const struct fr *scalar)
{
    uint64_t raw[4];
    fr_to_raw(raw, scalar);
    struct g1_point term;
    g1_scalar_mul(&term, p, raw);
    g1_add(result, result, &term);
    memory_cleanse(raw, sizeof(raw));
    memory_cleanse(&term, sizeof(term));
}

/* ── Step 3: Compute proof element A ── */
static bool groth16_prove_element_a(struct g1_point *A,
                                    const struct groth16_pk *pk,
                                    const struct constraint_system *cs,
                                    size_t num_in,
                                    const struct groth16_prove_dense *d,
                                    const struct fr *r_blind, unsigned threads)
{
    /* A = alpha + sum(w[i] * a_g1[i]) + r * delta_g1 */
    struct g1_point a_aux_sum;
    if (!groth16_g1_msm(A, pk->a_g1, cs->witness, num_in, threads) ||
        !groth16_g1_msm(&a_aux_sum, pk->a_g1 + num_in, d->a_aux_w,
                        d->a_aux_total, threads))
        return false;
    g1_add(A, A, &a_aux_sum);
    g1_add(A, A, &pk->alpha_g1);
    groth16_prove_add_mul(A, &pk->delta_g1, r_blind);
    return true;
}

/* ── Step 4: Compute proof element B (G2) ── */
static bool groth16_prove_element_b_g2(struct g2_point *B_g2,
                                       const struct groth16_pk *pk,
                                       const struct groth16_prove_dense *d,
                                       const struct fr *s_blind,
                                       unsigned threads)
{
    /* B = beta + sum(w[i] * b_g2[i]) + s * delta_g2; there is no G2 scalar
     * multiply, so s * delta_g2 is a one-term MSM. */
    struct g2_point b_aux_sum, s_delta;
    if (!groth16_g2_msm(B_g2, pk->b_g2, d->b_in_w, d->b_in_total, threads) ||
        !groth16_g2_msm(&b_aux_sum, pk->b_g2 + d->b_in_total, d->b_aux_w,
                        d->b_aux_total, threads) ||
        !groth16_g2_msm(&s_delta, &pk->delta_g2, s_blind, 1, 1))
        return false;
    g2_add(B_g2, B_g2, &b_aux_sum);
    g2_add(B_g2, B_g2, &pk->beta_g2);
    g2_add(B_g2, B_g2, &s_delta);
    return true;
}

/* ── Step 5: Compute B_g1 (needed for C) ── */
static bool groth16_prove_element_b_g1(struct g1_point *B_g1,
                                       const struct groth16_pk *pk,
                                       const struct groth16_prove_dense *d,
                                       const struct fr *s_blind,
                                       unsigned threads)
{
    struct g1_point b_aux_sum;
    if (!groth16_g1_msm(B_g1, pk->b_g1, d->b_in_w, d->b_in_total, threads) ||
        !groth16_g1_msm(&b_aux_sum, pk->b_g1 + d->b_in_total, d->b_aux_w,
                        d->b_aux_total, threads))
        return false;
    g1_add(B_g1, B_g1, &b_aux_sum);
    g1_add(B_g1, B_g1, &pk->beta_g1);
    groth16_prove_add_mul(B_g1, &pk->delta_g1, s_blind);
    return true;
}

/* ── Step 6: Compute proof element C ── */
static bool groth16_prove_element_c(struct g1_point *C,
                                    const struct groth16_pk *pk,
                                    const struct constraint_system *cs,
                                    size_t domain, const struct fr *h_eval,
                                    const struct g1_point *A,
                                    const struct g1_point *B_g1,
                                    const struct fr *r_blind,
                                    const struct fr *s_blind, unsigned threads)
{
    size_t num_in = cs->num_inputs + 1;
    size_t num_aux = (cs->num_vars > num_in) ? cs->num_vars - num_in : 0;

    /* H polynomial contribution: sum(h[i] * h_g1[i]) */
    size_t h_msm_len = domain - 1;
    if (h_msm_len > pk->h_len) h_msm_len = pk->h_len;

    /* Private variable contribution: sum(w[num_in..m] * l_g1[i]). The L
     * query is FullDensity by construction — the setup rejects a key with
     * an unconstrained variable — so it is indexed by aux number directly. */
    struct g1_point L_contrib;
    if (!groth16_g1_msm(C, pk->h_g1, h_eval, h_msm_len, threads) ||
        !groth16_g1_msm(&L_contrib, pk->l_g1, &cs->witness[num_in], num_aux,
                        threads))
        return false;
    g1_add(C, C, &L_contrib);

    /* Blinding: + s*A + r*B_g1 - r*s*delta_g1 */
    groth16_prove_add_mul(C, A, s_blind);
    groth16_prove_add_mul(C, B_g1, r_blind);
    struct fr rs;
    fr_mul(&rs, r_blind, s_blind);
    fr_neg(&rs, &rs);
    groth16_prove_add_mul(C, &pk->delta_g1, &rs);
    memory_cleanse(&rs, sizeof(rs));
    return true;
}

static void groth16_prove_release_compact(struct groth16_prove_dense *d)
{
    memory_cleanse(d->a_aux_w, (d->a_aux_total ? d->a_aux_total : 1) * sizeof(struct fr));
    memory_cleanse(d->b_in_w, (d->b_in_total ? d->b_in_total : 1) * sizeof(struct fr));
    memory_cleanse(d->b_aux_w, (d->b_aux_total ? d->b_aux_total : 1) * sizeof(struct fr));
    free(d->a_aux_w);
    free(d->b_in_w);
    free(d->b_aux_w);
}

/* Steps 2b to 6: densities, the key-shape check and the three proof elements.
 * False (logged) on a shape mismatch or an allocation failure. */
static bool groth16_prove_elements(const struct groth16_pk *pk,
                                   const struct constraint_system *cs,
                                   size_t domain, const struct fr *h_eval,
                                   const struct fr *r_blind,
                                   const struct fr *s_blind, unsigned threads,
                                   struct groth16_proof *proof_out)
{
    size_t l = cs->num_inputs;
    size_t num_in = l + 1;
    size_t num_aux = (cs->num_vars > num_in) ? cs->num_vars - num_in : 0;

    /* ── Step 2b: query densities ──
     *
     * The trusted setup drops every query point whose polynomial is empty, so
     * a_g1/b_g1/b_g2 are COMPACTED: a_g1 is [all inputs][aux that appear in
     * some A], b_* is [inputs that appear in some B][aux that appear in some
     * B]. Indexing them by raw variable number pairs witness values with the
     * wrong group elements. Density is syntactic appearance in a linear
     * combination (bellman's DensityTracker::inc / KeypairAssembly's per-
     * variable term list), not "has a nonzero summed coefficient". */
    struct groth16_prove_dense dense;
    if (!groth16_prove_alloc_dense(&dense, num_in, num_aux))
        LOG_FAIL("groth16", "prove: OOM allocating density maps (aux=%zu)",
                 num_aux);
    groth16_prove_mark_dense(cs, &dense, num_in, num_aux);
    groth16_prove_count_dense(&dense, num_in, num_aux);

    /* Refuse rather than emit a proof against a key whose query shape is not
     * the one this circuit generates — that is a silent wrong-circuit proof. */
    if (!groth16_prove_key_shape_ok(pk, l, num_in, num_aux, domain, &dense)) {
        groth16_prove_free_dense(&dense);
        LOG_FAIL("groth16",
                 "prove: proving-key shape does not match this circuit — "
                 "key(inputs=%zu l=%zu h=%zu a=%zu b=%zu) vs "
                 "circuit(inputs=%zu aux=%zu h=%zu a=%zu b=%zu)",
                 pk->num_inputs, pk->l_len, pk->h_len, pk->a_len, pk->b_len,
                 l, num_aux, domain - 1,
                 num_in + dense.a_aux_total,
                 dense.b_in_total + dense.b_aux_total);
    }

    if (!groth16_prove_alloc_compact(&dense)) {
        groth16_prove_free_dense(&dense);
        LOG_FAIL("groth16", "prove: OOM allocating compacted query scalars");
    }
    groth16_prove_fill_compact(cs, &dense, num_in, num_aux);
    groth16_prove_free_dense(&dense);

    struct g1_point A, B_g1, C;
    struct g2_point B_g2;
    bool ok =
        groth16_prove_element_a(&A, pk, cs, num_in, &dense, r_blind, threads) &&
        groth16_prove_element_b_g2(&B_g2, pk, &dense, s_blind, threads) &&
        groth16_prove_element_b_g1(&B_g1, pk, &dense, s_blind, threads) &&
        groth16_prove_element_c(&C, pk, cs, domain, h_eval, &A, &B_g1, r_blind,
                                s_blind, threads);
    groth16_prove_release_compact(&dense);
    if (!ok)
        LOG_FAIL("groth16", "prove: multi-scalar multiplication failed");

    proof_out->a = A;
    proof_out->b = B_g2;
    proof_out->c = C;
    return true;
}

bool groth16_prove(const struct groth16_pk *pk,
                   const struct constraint_system *cs,
                   struct groth16_proof *proof_out)
{
    /* refuse to prove if CS construction hit OOM. Otherwise the
     * witness / constraints / public-input indices are silently wrong
     * and we'd emit a valid-looking proof for the wrong circuit. */
    if (cs->oom_error) {
        memset(proof_out, 0, sizeof(*proof_out));
        LOG_FAIL("groth16",
                 "prove: refusing — cs->oom_error is set "
                 "(realloc failed during CS construction; circuit is "
                 "silently wrong, proof would not match verifier's "
                 "expected circuit)");
    }

    /* bellman's input_assignment holds ONE at index 0 followed by the public
     * inputs, so its length is l + 1 and Index::Input(i) is our variable i. */
    size_t num_in = cs->num_inputs + 1;

    /* create_proof appends one `Input(i) * 0 = 0` row per input AFTER
     * synthesize (that is what makes the IC query fully dense), and the trusted
     * setup was generated over the same padded system. Leaving them out shifts
     * every QAP polynomial. */
    size_t domain = groth16_prove_domain_for_rows(cs->num_constraints + num_in);
    unsigned threads = groth16_prover_threads();

    /* Generate random blinding factors */
    struct fr r_blind, s_blind;
    if (!groth16_prove_draw_blinds(&r_blind, &s_blind))
        return false;

    bool ok = false;
    struct fr *h_eval = groth16_prove_quotient(cs, domain, num_in, threads);
    if (h_eval) {
        ok = groth16_prove_elements(pk, cs, domain, h_eval, &r_blind, &s_blind,
                                    threads, proof_out);
        memory_cleanse(h_eval, domain * sizeof(struct fr));
        free(h_eval);
    }
    memory_cleanse(&r_blind, sizeof(r_blind));
    memory_cleanse(&s_blind, sizeof(s_blind));
    if (!ok) {
        memset(proof_out, 0, sizeof(*proof_out));
        LOG_FAIL("groth16", "prove: failed (domain=%zu); proof_out zeroed",
                 domain);
    }
    return true;
}
