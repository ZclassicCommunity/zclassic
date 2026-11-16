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

    for (size_t i = 0; i < a->num_terms; i++) {
        if (!lc_add_term(&con->a, a->terms[i].var, &a->terms[i].coeff)) {
            cs->oom_error = true;
            lc_free(&con->a); lc_free(&con->b); lc_free(&con->c);
            LOG_FAIL("groth16",
                     "cs_enforce: deep-copy a[%zu/%zu] lc_add_term failed",
                     i, a->num_terms);
        }
    }
    for (size_t i = 0; i < b->num_terms; i++) {
        if (!lc_add_term(&con->b, b->terms[i].var, &b->terms[i].coeff)) {
            cs->oom_error = true;
            lc_free(&con->a); lc_free(&con->b); lc_free(&con->c);
            LOG_FAIL("groth16",
                     "cs_enforce: deep-copy b[%zu/%zu] lc_add_term failed",
                     i, b->num_terms);
        }
    }
    for (size_t i = 0; i < c->num_terms; i++) {
        if (!lc_add_term(&con->c, c->terms[i].var, &c->terms[i].coeff)) {
            cs->oom_error = true;
            lc_free(&con->a); lc_free(&con->b); lc_free(&con->c);
            LOG_FAIL("groth16",
                     "cs_enforce: deep-copy c[%zu/%zu] lc_add_term failed",
                     i, c->num_terms);
        }
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

/* ── FFT over Fr ────────────────────────────────────────────────── */

/* BLS12-381 Fr supports FFT domains up to 2^32.
 * Root of unity: omega = 5^((r-1)/2^32) mod r */

static void fr_pow_u64(struct fr *r, const struct fr *base, uint64_t exp)
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

/* Canonical (non-Montgomery) encoding of pairing::bls12_381::Fr's published
 * 2^32-th ROOT_OF_UNITY. The upstream limb literal is already in Montgomery
 * form; feeding those limbs to fr_from_bytes applies R a second time and
 * selects a different domain. That error preserves FFT round-trips but changes
 * the QAP evaluation points, so every generated Groth16 proof is rejected by
 * the production verifying key. */
static const uint64_t ROOT_OF_UNITY_RAW[4] = {
    0x3829971f439f0d2bULL, 0xb63683508c2280b9ULL,
    0xd09b681922c813b4ULL, 0x16a2a19edfe81f20ULL
};

static void fr_get_root_of_unity(struct fr *omega, unsigned int log_n)
{
    if (log_n > 32) { fr_zero(omega); return; }

    /* Start with 2^32-th root, square (32 - log_n) times */
    uint8_t root_bytes[32];
    memcpy(root_bytes, ROOT_OF_UNITY_RAW, 32);
    fr_from_bytes(omega, root_bytes);

    for (unsigned int i = log_n; i < 32; i++)
        fr_sq(omega, omega);
}

bool fr_fft(struct fr *coeffs, size_t n, bool inverse)
{
    if (n <= 1) return true;

    unsigned int log_n = fr_log2_ceil(n);
    if ((size_t)1 << log_n != n)
        LOG_FAIL("groth16",
                 "fr_fft: n=%zu is not a power of 2 (fr_log2_ceil=%u, "
                 "2^log_n=%zu); refusing to transform — caller would "
                 "silently receive un-FFT'd data",
                 n, log_n, (size_t)1 << log_n);

    bit_reverse(coeffs, n, log_n);

    struct fr omega;
    fr_get_root_of_unity(&omega, log_n);
    if (inverse)
        fr_inv(&omega, &omega);

    for (unsigned int s = 1; s <= log_n; s++) {
        size_t m = (size_t)1 << s;
        size_t half = m >> 1;

        struct fr omega_m;
        fr_pow_u64(&omega_m, &omega, n / m);

        for (size_t k = 0; k < n; k += m) {
            struct fr w;
            fr_one(&w);
            for (size_t j = 0; j < half; j++) {
                struct fr t, u;
                fr_mul(&t, &w, &coeffs[k + j + half]);
                u = coeffs[k + j];
                fr_add(&coeffs[k + j], &u, &t);
                fr_sub(&coeffs[k + j + half], &u, &t);
                fr_mul(&w, &w, &omega_m);
            }
        }
    }

    if (inverse) {
        struct fr n_inv;
        fr_one(&n_inv);
        struct fr n_fr;
        fr_zero(&n_fr);
        /* Build n as Fr element: add 1 n times (slow but correct for init) */
        struct fr one_val;
        fr_one(&one_val);
        fr_zero(&n_fr);
        for (size_t i = 0; i < n; i++)
            fr_add(&n_fr, &n_fr, &one_val);
        fr_inv(&n_inv, &n_fr);
        for (size_t i = 0; i < n; i++)
            fr_mul(&coeffs[i], &coeffs[i], &n_inv);
    }
    return true;
}

/* ── Multi-scalar multiplication (Pippenger's) ──────────────────── */

/* Window size: c ≈ log2(n), clamped to [4, 16] */
static unsigned int msm_window_bits(size_t n)
{
    unsigned int c = 1;
    { size_t v = n; while (v > 1) { c++; v >>= 1; } }
    if (c > 16) c = 16;
    if (c < 4 && n > 16) c = 4;
    return c;
}

/* The c-bit digit of one raw scalar at bit_offset (0 when past the top word). */
static uint64_t msm_window_digit(const uint64_t raw[4], unsigned int bit_offset,
                                 unsigned int c)
{
    unsigned int word = bit_offset / 64;
    unsigned int bit = bit_offset % 64;
    if (word >= 4) return 0;
    uint64_t val = raw[word] >> bit;
    if (bit + c > 64 && word + 1 < 4)
        val |= raw[word + 1] << (64 - bit);
    val &= ((uint64_t)1 << c) - 1;
    return val;
}

static void g1_msm_reduce_buckets(struct g1_point *window_sum,
                                  const struct g1_point *buckets,
                                  size_t num_buckets)
{
    struct g1_point running_sum;
    g1_identity(&running_sum);
    g1_identity(window_sum);
    for (size_t b = num_buckets; b > 0; b--) {
        g1_add(&running_sum, &running_sum, &buckets[b - 1]);
        g1_add(window_sum, window_sum, &running_sum);
    }
}

static void g2_msm_reduce_buckets(struct g2_point *window_sum,
                                  const struct g2_point *buckets,
                                  size_t num_buckets)
{
    struct g2_point running_sum;
    g2_identity(&running_sum);
    g2_identity(window_sum);
    size_t remaining = num_buckets;
    while (remaining > 0) {
        remaining--;
        g2_add(&running_sum, &running_sum, &buckets[remaining]);
        g2_add(window_sum, window_sum, &running_sum);
    }
}

void g1_msm(struct g1_point *result,
            const struct g1_point *points, const struct fr *scalars,
            size_t n)
{
    if (n == 0) { g1_identity(result); return; }

    unsigned int c = msm_window_bits(n);

    size_t num_buckets = ((size_t)1 << c) - 1;
    struct g1_point *buckets = zcl_calloc(num_buckets, sizeof(struct g1_point), "g1_msm_buckets");
    if (!buckets) { g1_identity(result); return; }

    uint64_t (*raw_scalars)[4] = zcl_calloc(n, sizeof(uint64_t[4]), "g1_msm_scalars");
    if (!raw_scalars) { free(buckets); g1_identity(result); return; }

    for (size_t i = 0; i < n; i++)
        fr_to_raw(raw_scalars[i], &scalars[i]);

    g1_identity(result);
    unsigned int num_windows = (255 + c - 1) / c;

    for (int w = (int)num_windows - 1; w >= 0; w--) {
        for (unsigned int d = 0; d < c; d++)
            g1_double(result, result);

        for (size_t b = 0; b < num_buckets; b++)
            g1_identity(&buckets[b]);

        unsigned int bit_offset = (unsigned int)w * c;
        for (size_t i = 0; i < n; i++) {
            uint64_t val = msm_window_digit(raw_scalars[i], bit_offset, c);
            if (val == 0) continue;
            g1_add(&buckets[val - 1], &buckets[val - 1], &points[i]);
        }

        struct g1_point window_sum;
        g1_msm_reduce_buckets(&window_sum, buckets, num_buckets);
        g1_add(result, result, &window_sum);
    }

    memory_cleanse(raw_scalars, n * sizeof(uint64_t[4]));
    free(raw_scalars);
    free(buckets);
}

void g2_msm(struct g2_point *result,
            const struct g2_point *points, const struct fr *scalars,
            size_t n)
{
    if (n == 0) { g2_identity(result); return; }

    unsigned int c = msm_window_bits(n);

    size_t num_buckets = ((size_t)1 << c) - 1;
    struct g2_point *buckets = zcl_calloc(num_buckets, sizeof(struct g2_point), "g2_msm_buckets");
    if (!buckets) { g2_identity(result); return; }

    uint64_t (*raw_scalars)[4] = zcl_calloc(n, sizeof(uint64_t[4]), "g2_msm_scalars");
    if (!raw_scalars) { free(buckets); g2_identity(result); return; }

    for (size_t i = 0; i < n; i++)
        fr_to_raw(raw_scalars[i], &scalars[i]);

    g2_identity(result);
    unsigned int num_windows = (255 + c - 1) / c;

    for (int w = (int)num_windows - 1; w >= 0; w--) {
        for (unsigned int d = 0; d < c; d++)
            g2_double(result, result);

        for (size_t b = 0; b < num_buckets; b++)
            g2_identity(&buckets[b]);

        unsigned int bit_offset = (unsigned int)w * c;
        for (size_t i = 0; i < n; i++) {
            uint64_t val = msm_window_digit(raw_scalars[i], bit_offset, c);
            if (val == 0) continue;
            g2_add(&buckets[val - 1], &buckets[val - 1], &points[i]);
        }

        struct g2_point window_sum;
        g2_msm_reduce_buckets(&window_sum, buckets, num_buckets);
        g2_add(result, result, &window_sum);
    }

    memory_cleanse(raw_scalars, n * sizeof(uint64_t[4]));
    free(raw_scalars);
    free(buckets);
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

static struct g1_point *pkr_g1_array(struct pk_reader *r, uint32_t count)
{
    struct g1_point *arr = zcl_calloc(count, sizeof(struct g1_point), "pk_g1_array");
    if (!arr)
        LOG_NULL("groth16_pk", "pkr_g1_array: zcl_calloc failed (count=%u)", count);
    for (uint32_t i = 0; i < count; i++) {
        if (!pkr_g1(r, &arr[i])) {
            free(arr);
            LOG_NULL("groth16_pk",
                     "pkr_g1_array: pkr_g1 failed at index %u/%u", i, count);
        }
    }
    return arr;
}

static struct g2_point *pkr_g2_array(struct pk_reader *r, uint32_t count)
{
    struct g2_point *arr = zcl_calloc(count, sizeof(struct g2_point), "pk_g2_array");
    if (!arr)
        LOG_NULL("groth16_pk", "pkr_g2_array: zcl_calloc failed (count=%u)", count);
    for (uint32_t i = 0; i < count; i++) {
        if (!pkr_g2(r, &arr[i])) {
            free(arr);
            LOG_NULL("groth16_pk",
                     "pkr_g2_array: pkr_g2 failed at index %u/%u", i, count);
        }
    }
    return arr;
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

    printf("Proving key loaded: h=%zu l=%zu a=%zu b=%zu inputs=%zu\n",
           pk->h_len, pk->l_len, pk->a_len, pk->b_len, pk->num_inputs);

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

static bool groth16_prove_draw_blinds(struct fr *r_blind, struct fr *s_blind)
{
    uint8_t rb[32];
    if (!groth16_blind_bytes(rb, 32, "groth16_r_blind"))
        return false;
    fr_from_bytes(r_blind, rb);
    if (!groth16_blind_bytes(rb, 32, "groth16_s_blind")) {
        memory_cleanse(rb, 32);
        return false;
    }
    fr_from_bytes(s_blind, rb);
    memory_cleanse(rb, 32);
    return true;
}

static bool groth16_prove_alloc_abc(size_t domain, struct fr **a_eval,
                                    struct fr **b_eval, struct fr **c_eval)
{
    *a_eval = zcl_calloc(domain, sizeof(struct fr), "groth16_a_eval");
    *b_eval = zcl_calloc(domain, sizeof(struct fr), "groth16_b_eval");
    *c_eval = zcl_calloc(domain, sizeof(struct fr), "groth16_c_eval");
    if (!*a_eval || !*b_eval || !*c_eval) {
        free(*a_eval); free(*b_eval); free(*c_eval);
        return false;
    }
    return true;
}

static void groth16_prove_fill_abc(const struct constraint_system *cs,
                                   struct fr *a_eval, struct fr *b_eval,
                                   struct fr *c_eval, size_t domain,
                                   size_t num_in)
{
    size_t n_con = cs->num_constraints;
    for (size_t i = 0; i < n_con; i++) {
        lc_evaluate(&a_eval[i], &cs->constraints[i].a, cs->witness);
        lc_evaluate(&b_eval[i], &cs->constraints[i].b, cs->witness);
        lc_evaluate(&c_eval[i], &cs->constraints[i].c, cs->witness);
    }
    /* The appended `Input(i) * 0 = 0` rows: A = w[i], B = C = 0. */
    for (size_t i = 0; i < num_in && n_con + i < domain; i++)
        a_eval[n_con + i] = cs->witness[i];
}

static bool groth16_prove_fft_abc(struct fr *a_eval, struct fr *b_eval,
                                  struct fr *c_eval, size_t domain, bool inverse)
{
    return fr_fft(a_eval, domain, inverse) &&
           fr_fft(b_eval, domain, inverse) &&
           fr_fft(c_eval, domain, inverse);
}

/* Failure tail shared by the fft failure paths: scrub and free the evaluation
 * buffers (h_eval may be NULL), zero proof_out and scrub the blinding factors. */
static void groth16_prove_abort_eval(struct fr *a_eval, struct fr *b_eval,
                                     struct fr *c_eval, struct fr *h_eval,
                                     size_t domain,
                                     struct groth16_proof *proof_out,
                                     struct fr *r_blind, struct fr *s_blind)
{
    memory_cleanse(a_eval, domain * sizeof(struct fr));
    memory_cleanse(b_eval, domain * sizeof(struct fr));
    memory_cleanse(c_eval, domain * sizeof(struct fr));
    if (h_eval)
        memory_cleanse(h_eval, domain * sizeof(struct fr));
    free(a_eval); free(b_eval); free(c_eval);
    if (h_eval)
        free(h_eval);
    memset(proof_out, 0, sizeof(*proof_out));
    memory_cleanse(r_blind, sizeof(*r_blind));
    memory_cleanse(s_blind, sizeof(*s_blind));
}

/* Failure tail once only h_eval is live: scrub and free it, zero proof_out and
 * scrub the blinding factors. */
static void groth16_prove_abort_h(struct fr *h_eval, size_t domain,
                                  struct groth16_proof *proof_out,
                                  struct fr *r_blind, struct fr *s_blind)
{
    memory_cleanse(h_eval, domain * sizeof(struct fr));
    free(h_eval);
    memset(proof_out, 0, sizeof(*proof_out));
    memory_cleanse(r_blind, sizeof(*r_blind));
    memory_cleanse(s_blind, sizeof(*s_blind));
}

static void groth16_prove_coset_generator(struct fr *g_coset)
{
    uint8_t g_bytes[32] = {0};
    g_bytes[0] = 7; /* Fr multiplicative generator = 7 (little-endian) */
    fr_from_bytes(g_coset, g_bytes);
}

static void groth16_prove_coset_shift(struct fr *a_eval, struct fr *b_eval,
                                      struct fr *c_eval, size_t domain,
                                      const struct fr *g_coset)
{
    struct fr g_pow;
    fr_one(&g_pow);
    for (size_t i = 0; i < domain; i++) {
        fr_mul(&a_eval[i], &a_eval[i], &g_pow);
        fr_mul(&b_eval[i], &b_eval[i], &g_pow);
        fr_mul(&c_eval[i], &c_eval[i], &g_pow);
        fr_mul(&g_pow, &g_pow, g_coset);
    }
}

static void groth16_prove_release_abc(struct fr *a_eval, struct fr *b_eval,
                                      struct fr *c_eval, size_t domain)
{
    memory_cleanse(a_eval, domain * sizeof(struct fr));
    memory_cleanse(b_eval, domain * sizeof(struct fr));
    memory_cleanse(c_eval, domain * sizeof(struct fr));
    free(a_eval);
    free(b_eval);
    free(c_eval);
}

static void groth16_prove_h_pointwise(struct fr *h_eval, const struct fr *a_eval,
                                      const struct fr *b_eval,
                                      const struct fr *c_eval, size_t domain)
{
    for (size_t i = 0; i < domain; i++) {
        struct fr ab;
        fr_mul(&ab, &a_eval[i], &b_eval[i]);
        fr_sub(&h_eval[i], &ab, &c_eval[i]);
    }
}

static void groth16_prove_h_divide_zh(struct fr *h_eval, size_t domain,
                                      const struct fr *g_coset)
{
    struct fr z_h_coset;
    fr_pow_u64(&z_h_coset, g_coset, (uint64_t)domain);
    struct fr one_val;
    fr_one(&one_val);
    fr_sub(&z_h_coset, &z_h_coset, &one_val);
    struct fr z_h_inv;
    fr_inv(&z_h_inv, &z_h_coset);
    for (size_t i = 0; i < domain; i++)
        fr_mul(&h_eval[i], &h_eval[i], &z_h_inv);
}

static void groth16_prove_h_unshift(struct fr *h_eval, size_t domain,
                                    const struct fr *g_coset)
{
    struct fr g_inv;
    fr_inv(&g_inv, g_coset);
    struct fr g_inv_pow;
    fr_one(&g_inv_pow);
    for (size_t i = 0; i < domain; i++) {
        fr_mul(&h_eval[i], &h_eval[i], &g_inv_pow);
        fr_mul(&g_inv_pow, &g_inv_pow, &g_inv);
    }
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

/* ── Step 3: Compute proof element A ── */
static void groth16_prove_element_a(struct g1_point *A,
                                    const struct groth16_pk *pk,
                                    const struct constraint_system *cs,
                                    size_t num_in,
                                    const struct groth16_prove_dense *d,
                                    const struct fr *r_blind)
{
    /* A = alpha + sum(w[i] * a_g1[i]) + r * delta_g1 */
    struct g1_point a_aux_sum;
    g1_msm(A, pk->a_g1, cs->witness, num_in);
    g1_msm(&a_aux_sum, pk->a_g1 + num_in, d->a_aux_w, d->a_aux_total);
    g1_add(A, A, &a_aux_sum);
    g1_add(A, A, &pk->alpha_g1);

    uint64_t r_raw[4];
    fr_to_raw(r_raw, r_blind);
    struct g1_point r_delta;
    g1_scalar_mul(&r_delta, &pk->delta_g1, r_raw);
    g1_add(A, A, &r_delta);
}

/* ── Step 4: Compute proof element B (G2) ── */
static void groth16_prove_element_b_g2(struct g2_point *B_g2,
                                       const struct groth16_pk *pk,
                                       const struct groth16_prove_dense *d,
                                       const struct fr *s_blind)
{
    struct g2_point b_aux_sum;
    g2_msm(B_g2, pk->b_g2, d->b_in_w, d->b_in_total);
    g2_msm(&b_aux_sum, pk->b_g2 + d->b_in_total, d->b_aux_w, d->b_aux_total);
    g2_add(B_g2, B_g2, &b_aux_sum);
    g2_add(B_g2, B_g2, &pk->beta_g2);

    /* + s * delta_g2 */
    /* (need g2_scalar_mul — use MSM with 1 point as workaround) */
    struct g2_point s_delta;
    g2_msm(&s_delta, &pk->delta_g2, s_blind, 1);
    g2_add(B_g2, B_g2, &s_delta);
}

/* ── Step 5: Compute B_g1 (needed for C) ── */
static void groth16_prove_element_b_g1(struct g1_point *B_g1,
                                       const struct groth16_pk *pk,
                                       const struct groth16_prove_dense *d,
                                       const struct fr *s_blind)
{
    struct g1_point b_aux_sum;
    g1_msm(B_g1, pk->b_g1, d->b_in_w, d->b_in_total);
    g1_msm(&b_aux_sum, pk->b_g1 + d->b_in_total, d->b_aux_w, d->b_aux_total);
    g1_add(B_g1, B_g1, &b_aux_sum);
    g1_add(B_g1, B_g1, &pk->beta_g1);

    uint64_t s_raw[4];
    fr_to_raw(s_raw, s_blind);
    struct g1_point s_delta;
    g1_scalar_mul(&s_delta, &pk->delta_g1, s_raw);
    g1_add(B_g1, B_g1, &s_delta);
}

/* ── Step 6: Compute proof element C ── */
static void groth16_prove_element_c(struct g1_point *C,
                                    const struct groth16_pk *pk,
                                    const struct constraint_system *cs,
                                    size_t num_in, size_t num_aux, size_t domain,
                                    const struct fr *h_eval,
                                    const struct g1_point *A,
                                    const struct g1_point *B_g1,
                                    const struct fr *r_blind,
                                    const struct fr *s_blind)
{
    /* H polynomial contribution: sum(h[i] * h_g1[i]) */
    size_t h_msm_len = domain - 1;
    if (h_msm_len > pk->h_len) h_msm_len = pk->h_len;
    struct g1_point H_contrib;
    g1_msm(&H_contrib, pk->h_g1, h_eval, h_msm_len);

    /* Private variable contribution: sum(w[num_in..m] * l_g1[i]). The L
     * query is FullDensity by construction — the setup rejects a key with
     * an unconstrained variable — so it is indexed by aux number directly. */
    struct g1_point L_contrib;
    g1_msm(&L_contrib, pk->l_g1, &cs->witness[num_in], num_aux);

    g1_add(C, &H_contrib, &L_contrib);

    /* Blinding: + s*A */
    {
        uint64_t s_raw[4];
        fr_to_raw(s_raw, s_blind);
        struct g1_point sA;
        g1_scalar_mul(&sA, A, s_raw);
        g1_add(C, C, &sA);
    }

    /* + r*B_g1 */
    {
        uint64_t r_raw[4];
        fr_to_raw(r_raw, r_blind);
        struct g1_point rB;
        g1_scalar_mul(&rB, B_g1, r_raw);
        g1_add(C, C, &rB);
    }

    /* - r*s*delta_g1 */
    {
        struct fr rs;
        fr_mul(&rs, r_blind, s_blind);
        uint64_t rs_raw[4];
        fr_to_raw(rs_raw, &rs);
        struct g1_point rs_delta;
        g1_scalar_mul(&rs_delta, &pk->delta_g1, rs_raw);
        struct g1_point neg_rs_delta;
        g1_neg(&neg_rs_delta, &rs_delta);
        g1_add(C, C, &neg_rs_delta);
    }
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

    size_t m = cs->num_vars;
    size_t l = cs->num_inputs;
    size_t n_con = cs->num_constraints;

    /* bellman's input_assignment holds ONE at index 0 followed by the public
     * inputs, so its length is l + 1 and Index::Input(i) is our variable i. */
    size_t num_in = l + 1;
    size_t num_aux = (m > num_in) ? m - num_in : 0;

    /* create_proof appends one `Input(i) * 0 = 0` row per input AFTER
     * synthesize (that is what makes the IC query fully dense), and the trusted
     * setup was generated over the same padded system. Leaving them out shifts
     * every QAP polynomial. */
    size_t n_rows = n_con + num_in;

    size_t domain = groth16_prove_domain_for_rows(n_rows);

    /* Generate random blinding factors */
    struct fr r_blind, s_blind;
    if (!groth16_prove_draw_blinds(&r_blind, &s_blind))
        return false;

    /* ── Step 1: Evaluate constraints to get a[], b[], c[] coefficient vectors ── */
    struct fr *a_eval, *b_eval, *c_eval;
    if (!groth16_prove_alloc_abc(domain, &a_eval, &b_eval, &c_eval)) {
        LOG_FAIL("groth16",
                 "prove: OOM allocating a/b/c eval buffers (domain=%zu x 3 x %zu)",
                 domain, sizeof(struct fr));
    }

    groth16_prove_fill_abc(cs, a_eval, b_eval, c_eval, domain, num_in);

    /* ── Step 2: Compute h(x) = (a(x)*b(x) - c(x)) / z_H(x) via coset FFT ──
     *
     * a/b/c hold the QAP polynomials' EVALUATIONS at the domain points, so
     * bellman interpolates first (ifft) and only then evaluates on the coset
     * (distribute powers of g, then fft). Skipping the ifft coset-evaluates the
     * wrong polynomial and yields an h that no verifier accepts. */
    if (!groth16_prove_fft_abc(a_eval, b_eval, c_eval, domain, true)) {
        groth16_prove_abort_eval(a_eval, b_eval, c_eval, NULL, domain,
                                 proof_out, &r_blind, &s_blind);
        LOG_FAIL("groth16",
                 "prove: interpolating fr_fft failed on a/b/c_eval "
                 "(domain=%zu); proof_out zeroed", domain);
    }

    /* Coset generator g = Fr::multiplicative_generator = 7 in bellman.
     * Multiply coefficients by g^i to shift evaluation to coset {g*ω^i}.
     * z_H(g*ω^i) = (g*ω^i)^domain - 1 = g^domain - 1 ≠ 0 on the coset. */
    struct fr g_coset;
    groth16_prove_coset_generator(&g_coset);

    /* Apply coset shift: coeff[i] *= g^i */
    groth16_prove_coset_shift(a_eval, b_eval, c_eval, domain, &g_coset);

    /* FFT → evaluations at coset points g*ω^i.
     * fr_fft refuses non-pow-2 domains (returns false). Silent-
     * dropping here would emit a mathematically invalid proof: A/B/C
     * computed from un-transformed coefficients do not satisfy the
     * Groth16 verifier's pairing check, and the prover would still
     * return true. Bail immediately, free buffers, zero proof_out. */
    if (!groth16_prove_fft_abc(a_eval, b_eval, c_eval, domain, false)) {
        groth16_prove_abort_eval(a_eval, b_eval, c_eval, NULL, domain,
                                 proof_out, &r_blind, &s_blind);
        LOG_FAIL("groth16",
                 "prove: forward fr_fft failed on a/b/c_eval "
                 "(domain=%zu); proof_out zeroed", domain);
    }

    /* Compute (a*b - c) pointwise on coset */
    struct fr *h_eval = zcl_calloc(domain, sizeof(struct fr), "groth16_h_eval");
    if (!h_eval) {
        groth16_prove_release_abc(a_eval, b_eval, c_eval, domain);
        LOG_FAIL("groth16",
                 "prove: OOM allocating h eval buffer (domain=%zu x %zu)",
                 domain, sizeof(struct fr));
    }

    groth16_prove_h_pointwise(h_eval, a_eval, b_eval, c_eval, domain);

    /* Divide by z_H on coset: z_H(g*ω^i) = g^domain - 1 (constant) */
    groth16_prove_h_divide_zh(h_eval, domain, &g_coset);

    /* IFFT back to coefficient form.
     * same refuse-on-non-pow-2 contract. If we reached here the
     * three forward FFTs already succeeded, so a failure now is
     * anomalous — but the guard is cheap and keeps the call sites
     * symmetric. */
    if (!fr_fft(h_eval, domain, true)) {
        groth16_prove_abort_eval(a_eval, b_eval, c_eval, h_eval, domain,
                                 proof_out, &r_blind, &s_blind);
        LOG_FAIL("groth16",
                 "prove: inverse fr_fft failed on h_eval "
                 "(domain=%zu); proof_out zeroed", domain);
    }

    /* Undo coset shift: coeff[i] *= g^{-i} */
    groth16_prove_h_unshift(h_eval, domain, &g_coset);

    groth16_prove_release_abc(a_eval, b_eval, c_eval, domain);

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
    if (!groth16_prove_alloc_dense(&dense, num_in, num_aux)) {
        groth16_prove_abort_h(h_eval, domain, proof_out, &r_blind, &s_blind);
        LOG_FAIL("groth16", "prove: OOM allocating density maps (aux=%zu)",
                 num_aux);
    }
    groth16_prove_mark_dense(cs, &dense, num_in, num_aux);
    groth16_prove_count_dense(&dense, num_in, num_aux);

    /* Refuse rather than emit a proof against a key whose query shape is not
     * the one this circuit generates — that is a silent wrong-circuit proof. */
    if (!groth16_prove_key_shape_ok(pk, l, num_in, num_aux, domain, &dense)) {
        groth16_prove_free_dense(&dense);
        groth16_prove_abort_h(h_eval, domain, proof_out, &r_blind, &s_blind);
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
        groth16_prove_abort_h(h_eval, domain, proof_out, &r_blind, &s_blind);
        LOG_FAIL("groth16", "prove: OOM allocating compacted query scalars");
    }
    groth16_prove_fill_compact(cs, &dense, num_in, num_aux);
    groth16_prove_free_dense(&dense);

    struct g1_point A;
    groth16_prove_element_a(&A, pk, cs, num_in, &dense, &r_blind);

    struct g2_point B_g2;
    groth16_prove_element_b_g2(&B_g2, pk, &dense, &s_blind);

    struct g1_point B_g1;
    groth16_prove_element_b_g1(&B_g1, pk, &dense, &s_blind);

    struct g1_point C;
    groth16_prove_element_c(&C, pk, cs, num_in, num_aux, domain, h_eval, &A,
                            &B_g1, &r_blind, &s_blind);

    memory_cleanse(h_eval, domain * sizeof(struct fr));
    free(h_eval);
    groth16_prove_release_compact(&dense);

    proof_out->a = A;
    proof_out->b = B_g2;
    proof_out->c = C;

    memory_cleanse(&r_blind, sizeof(r_blind));
    memory_cleanse(&s_blind, sizeof(s_blind));

    return true;
}
