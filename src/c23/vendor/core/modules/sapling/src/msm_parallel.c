/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The parallel pieces of the Groth16 prover: a bounded thread fan-out, the
 * radix-2 FFT over Fr, and Pippenger multi-scalar multiplication.
 *
 * Threads exist only inside one groth16_parallel_for() call: they are created,
 * run and joined there, so nothing outlives a proof. The budget is
 * groth16_prover_threads(); a caller that shares the machine with other work
 * (a node that is also validating) lowers it with groth16_prover_set_threads().
 *
 * Everything here is exact field and group arithmetic, so the thread count
 * changes neither an FFT output nor the group element an MSM returns. */

#include "sapling/groth16_prover.h"
#include "sapling/bls12_381.h"
#include "sapling/fr.h"
#include "base/serialize_le.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/* ── Thread budget ──────────────────────────────────────────────── */

/* With no budget set, use the online processors up to this many. */
#define GROTH16_AUTO_THREADS 8u

static _Atomic unsigned g_prover_threads; /* 0 = automatic */

void groth16_prover_set_threads(unsigned n)
{
    atomic_store(&g_prover_threads,
                 n > GROTH16_MAX_THREADS ? GROTH16_MAX_THREADS : n);
}

/* Online processors, or 0 when the platform cannot say. mingw-w64 has no
 * sysconf(_SC_NPROCESSORS_ONLN), so Windows asks the OS directly: the active
 * processor count across all groups, falling back to GetSystemInfo. */
static long groth16_online_cpus(void)
{
#if defined(_WIN32)
    DWORD active = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (active > 0)
        return (long)active;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (long)si.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_ONLN)
    return sysconf(_SC_NPROCESSORS_ONLN);
#else
    return 0;
#endif
}

unsigned groth16_prover_threads(void)
{
    unsigned n = atomic_load(&g_prover_threads);
    if (n)
        return n;
    long online = groth16_online_cpus();
    if (online > 1)
        return online < (long)GROTH16_AUTO_THREADS ? (unsigned)online
                                                   : GROTH16_AUTO_THREADS;
    return 1;
}

/* ── Fan-out ────────────────────────────────────────────────────── */

struct par_run {
    groth16_range_fn fn;
    void *ctx;
    size_t n, grain;
    atomic_size_t next;
    atomic_uint tid;
};

/* Claims grain-sized ranges until none are left. */
static void *par_worker(void *arg)
{
    struct par_run *run = arg;
    unsigned tid = atomic_fetch_add(&run->tid, 1);
    for (;;) {
        size_t lo = atomic_fetch_add(&run->next, run->grain);
        if (lo >= run->n)
            break;
        size_t hi = run->n - lo > run->grain ? lo + run->grain : run->n;
        run->fn(run->ctx, lo, hi, tid);
    }
    return NULL;
}

void groth16_parallel_for(unsigned threads, size_t n, size_t grain,
                          groth16_range_fn fn, void *ctx)
{
    if (n == 0)
        return;
    if (grain == 0)
        grain = 1;
    struct par_run run = { .fn = fn, .ctx = ctx, .n = n, .grain = grain };
    size_t chunks = (n - 1) / grain + 1;
    if (threads > GROTH16_MAX_THREADS)
        threads = GROTH16_MAX_THREADS;
    if (threads > chunks)
        threads = (unsigned)chunks;

    /* The calling thread is one of the workers, so a thread that cannot be
     * started only costs speed: the ranges it would have claimed are claimed
     * by the others. */
    pthread_t started[GROTH16_MAX_THREADS];
    unsigned n_started = 0;
    for (unsigned t = 1; t < threads; t++) {
        /* raw-pthread-ok: short-burst-joined-immediately */
        if (pthread_create(&started[n_started], NULL, par_worker, &run) == 0)
            n_started++;
    }
    par_worker(&run);
    for (unsigned t = 0; t < n_started; t++)
        pthread_join(started[t], NULL);
}

/* ── FFT over Fr ────────────────────────────────────────────────── */

/* BLS12-381 Fr supports FFT domains up to 2^32.
 *
 * Canonical (non-Montgomery) encoding of pairing::bls12_381::Fr's published
 * 2^32-th ROOT_OF_UNITY. The upstream limb literal is already in Montgomery
 * form; feeding those limbs to fr_from_bytes applies R a second time and
 * selects a different domain. That error preserves FFT round-trips but changes
 * the QAP evaluation points, so every generated Groth16 proof is rejected by
 * the production verifying key. */
static const uint64_t ROOT_OF_UNITY_RAW[4] = {
    0x3829971f439f0d2bULL, 0xb63683508c2280b9ULL,
    0xd09b681922c813b4ULL, 0x16a2a19edfe81f20ULL
};

/* Stages up to this block size run block by block, so a block stays in cache
 * across all of them and whole blocks are handed to threads. */
#define FFT_BLOCK_LOG 12u

struct fft_job {
    struct fr **v;      /* count arrays of n elements */
    size_t count, n;
    unsigned log_n, block_log, stage;
    struct fr *tw;      /* tw[j] = omega^j for j < n/2 */
    struct fr omega, scale;
};

static inline void fft_butterfly(struct fr *lo, struct fr *hi,
                                 const struct fr *w)
{
    struct fr t;
    fr_mul(&t, w, hi);
    fr_sub(hi, lo, &t);
    fr_add(lo, lo, &t);
}

static void fft_twiddle_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct fft_job *j = ctx;
    struct fr w;
    fr_pow_u64(&w, &j->omega, lo);
    for (size_t i = lo; i < hi; i++) {
        j->tw[i] = w;
        fr_mul(&w, &w, &j->omega);
    }
}

static void fft_bit_reverse_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct fft_job *j = ctx;
    for (size_t c = lo; c < hi; c++)
        bit_reverse(j->v[c], j->n, j->log_n);
}

/* Stages 1..block_log of blocks [lo, hi), numbered across all arrays. */
static void fft_block_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    const struct fft_job *j = ctx;
    size_t block = (size_t)1 << j->block_log;
    size_t per_array = j->n >> j->block_log;
    for (size_t u = lo; u < hi; u++) {
        struct fr *a = j->v[u / per_array] + (u % per_array) * block;
        for (unsigned s = 1; s <= j->block_log; s++) {
            size_t half = (size_t)1 << (s - 1), stride = j->n >> s;
            for (size_t k = 0; k < block; k += 2 * half)
                for (size_t i = 0; i < half; i++)
                    fft_butterfly(&a[k + i], &a[k + i + half],
                                  &j->tw[i * stride]);
        }
    }
}

/* Butterflies [lo, hi) of one stage, numbered across all arrays. */
static void fft_stage_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    const struct fft_job *j = ctx;
    size_t half = (size_t)1 << (j->stage - 1), stride = j->n >> j->stage;
    for (size_t f = lo; f < hi; f++) {
        struct fr *a = j->v[f >> (j->log_n - 1)];
        size_t g = f & ((j->n >> 1) - 1);
        size_t i = g & (half - 1);
        size_t k = (g >> (j->stage - 1)) << j->stage;
        fft_butterfly(&a[k + i], &a[k + i + half], &j->tw[i * stride]);
    }
}

static void fft_scale_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    const struct fft_job *j = ctx;
    for (size_t f = lo; f < hi; f++) {
        struct fr *e = &j->v[f >> j->log_n][f & (j->n - 1)];
        fr_mul(e, e, &j->scale);
    }
}

static void fft_set_roots(struct fft_job *j, bool inverse)
{
    uint8_t bytes[32];
    memcpy(bytes, ROOT_OF_UNITY_RAW, 32);
    fr_from_bytes(&j->omega, bytes);
    /* Start with the 2^32-th root, square (32 - log_n) times. */
    for (unsigned i = j->log_n; i < 32; i++)
        fr_sq(&j->omega, &j->omega);
    if (!inverse)
        return;
    fr_inv(&j->omega, &j->omega);
    memset(bytes, 0, 32);
    zcl_write_u64_le(bytes, (uint64_t)j->n);
    fr_from_bytes(&j->scale, bytes);
    fr_inv(&j->scale, &j->scale);
}

bool fr_fft_many(struct fr **v, size_t count, size_t n, bool inverse,
                 unsigned threads)
{
    if (n <= 1 || count == 0)
        return true;

    unsigned log_n = fr_log2_ceil(n);
    if (log_n > 32 || (size_t)1 << log_n != n)
        LOG_FAIL("groth16",
                 "fr_fft: n=%zu is not a power of 2 up to 2^32 "
                 "(fr_log2_ceil=%u); refusing to transform — caller would "
                 "silently receive un-FFT'd data", n, log_n);

    struct fft_job j = { .v = v, .count = count, .n = n, .log_n = log_n };
    j.tw = zcl_calloc(n / 2, sizeof(struct fr), "fr_fft_twiddles");
    if (!j.tw)
        LOG_FAIL("groth16", "fr_fft: twiddle allocation failed (n=%zu)", n);
    fft_set_roots(&j, inverse);
    groth16_parallel_for(threads, n / 2, 4096, fft_twiddle_range, &j);
    groth16_parallel_for(threads, count, 1, fft_bit_reverse_range, &j);

    j.block_log = log_n < FFT_BLOCK_LOG ? log_n : FFT_BLOCK_LOG;
    groth16_parallel_for(threads, count * (n >> j.block_log), 1,
                         fft_block_range, &j);
    for (j.stage = j.block_log + 1; j.stage <= log_n; j.stage++)
        groth16_parallel_for(threads, count * (n / 2), 2048, fft_stage_range,
                             &j);
    if (inverse)
        groth16_parallel_for(threads, count * n, 4096, fft_scale_range, &j);

    free(j.tw);
    return true;
}

bool fr_fft(struct fr *coeffs, size_t n, bool inverse)
{
    return fr_fft_many(&coeffs, 1, n, inverse, 1);
}

bool fr_fft_parallel(struct fr *coeffs, size_t n, bool inverse, int num_threads)
{
    return fr_fft_many(&coeffs, 1, n, inverse,
                       num_threads > 1 ? (unsigned)num_threads : 1);
}

/* ── Multi-scalar multiplication (Pippenger) ────────────────────── */

/* Scalars are split three ways, as bellman's multiexp does: 0 contributes
 * nothing, 1 contributes its base by one addition, and only the rest go
 * through the bucket method. A Sapling witness is mostly boolean wires, so
 * most of every query but H is the first two cases.
 *
 * Bases are added with the mixed formula whenever they are normalised (z = 1),
 * which every proving-key point is.
 *
 * Variable time in the scalars, as the MSM here has always been (bucket index,
 * skipped zero digits) and as bellman's is. */

#define MSM_SCALAR_BITS 255u

/* r += b for a normalised b (z = 1): madd-2007-bl, 7M + 4S. */
#define MSM_DEFINE_MADD(NAME, POINT, FE, F, G)                                \
static void NAME(struct POINT *r, const struct POINT *b)                     \
{                                                                            \
    if (G##_is_identity(r)) {                                                \
        *r = *b;                                                             \
        return;                                                              \
    }                                                                        \
    struct FE z1z1, u2, s2, h, hh, i, j, rr, v, t;                           \
    F##_sq(&z1z1, &r->z);                                                    \
    F##_mul(&u2, &b->x, &z1z1);                                              \
    F##_mul(&s2, &b->y, &r->z);                                              \
    F##_mul(&s2, &s2, &z1z1);                                                \
    if (F##_eq(&u2, &r->x)) {                                                \
        if (F##_eq(&s2, &r->y))                                              \
            G##_double(r, r);                                                \
        else                                                                 \
            G##_identity(r);                                                 \
        return;                                                              \
    }                                                                        \
    F##_sub(&h, &u2, &r->x);                                                 \
    F##_sq(&hh, &h);                                                         \
    F##_add(&i, &hh, &hh);                                                   \
    F##_add(&i, &i, &i);                                                     \
    F##_mul(&j, &h, &i);                                                     \
    F##_sub(&rr, &s2, &r->y);                                                \
    F##_add(&rr, &rr, &rr);                                                  \
    F##_mul(&v, &r->x, &i);                                                  \
    F##_add(&t, &r->z, &h);                                                  \
    F##_sq(&t, &t);                                                          \
    F##_sub(&t, &t, &z1z1);                                                  \
    F##_sub(&r->z, &t, &hh);                                                 \
    F##_sq(&t, &rr);                                                         \
    F##_sub(&t, &t, &j);                                                     \
    F##_sub(&t, &t, &v);                                                     \
    F##_sub(&t, &t, &v);                                                     \
    F##_sub(&v, &v, &t);                                                     \
    F##_mul(&v, &v, &rr);                                                    \
    F##_mul(&j, &r->y, &j);                                                  \
    F##_add(&j, &j, &j);                                                     \
    F##_sub(&r->y, &v, &j);                                                  \
    r->x = t;                                                                \
}

MSM_DEFINE_MADD(g1_madd, g1_point, fp, fp, g1)
MSM_DEFINE_MADD(g2_madd, g2_point, fp2, fp2, g2)

/* One group behind untyped pointers, so G1 and G2 share the driver below. */
struct msm_group {
    size_t size;
    void (*identity)(void *p);
    void (*dbl)(void *p);
    void (*add)(void *acc, const void *p);  /* any p */
    void (*base)(void *acc, const void *p); /* mixed when p is normalised */
};

static void msm_g1_identity(void *p) { g1_identity(p); }
static void msm_g1_dbl(void *p) { g1_double(p, p); }
static void msm_g1_add(void *acc, const void *p) { g1_add(acc, acc, p); }
static void msm_g1_base(void *acc, const void *p)
{
    const struct g1_point *b = p;
    struct fp one;
    fp_one(&one);
    if (fp_eq(&b->z, &one))
        g1_madd(acc, b);
    else
        g1_add(acc, acc, b);
}

static void msm_g2_identity(void *p) { g2_identity(p); }
static void msm_g2_dbl(void *p) { g2_double(p, p); }
static void msm_g2_add(void *acc, const void *p) { g2_add(acc, acc, p); }
static void msm_g2_base(void *acc, const void *p)
{
    const struct g2_point *b = p;
    struct fp2 one;
    fp2_one(&one);
    if (fp2_eq(&b->z, &one))
        g2_madd(acc, b);
    else
        g2_add(acc, acc, b);
}

static const struct msm_group MSM_G1 = {
    sizeof(struct g1_point), msm_g1_identity, msm_g1_dbl, msm_g1_add,
    msm_g1_base
};
static const struct msm_group MSM_G2 = {
    sizeof(struct g2_point), msm_g2_identity, msm_g2_dbl, msm_g2_add,
    msm_g2_base
};

/* One MSM. Each task yields one point in `partial`: first one per window of
 * the bucket method, then one per chunk of the scalars equal to 1. */
struct msm_job {
    const struct msm_group *g;
    const unsigned char *points;
    uint64_t (*raw)[4];     /* the scalars that are neither 0 nor 1 */
    uint32_t *raw_idx;      /* and the index of each one's base */
    size_t raw_n;
    uint32_t *one_idx;      /* bases whose scalar is 1 */
    size_t one_n, one_chunk;
    unsigned c, windows;
    size_t tasks;
    unsigned char *partial;
    atomic_bool failed;
};

/* Window width minimising additions: per window, one per scalar plus two per
 * bucket, the latter between full Jacobian points and so about 1.5x dearer. */
static unsigned msm_window_bits(size_t n)
{
    unsigned best = 1;
    size_t best_cost = SIZE_MAX;
    for (unsigned c = 1; c <= 16; c++) {
        size_t windows = (MSM_SCALAR_BITS + c - 1) / c;
        size_t cost = windows * (n + ((size_t)3 << c));
        if (cost < best_cost) {
            best_cost = cost;
            best = c;
        }
    }
    return best;
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

/* out = sum over the scalars of digit_w(scalar) * base. */
static bool msm_window(const struct msm_job *j, unsigned w, void *out)
{
    const struct msm_group *g = j->g;
    size_t buckets = ((size_t)1 << j->c) - 1;
    unsigned char *b = zcl_calloc(buckets, g->size, "msm_buckets");
    if (!b)
        LOG_FAIL("groth16", "msm: bucket allocation failed (%zu x %zu)",
                 buckets, g->size);
    for (size_t k = 0; k < buckets; k++)
        g->identity(b + k * g->size);

    for (size_t i = 0; i < j->raw_n; i++) {
        uint64_t digit = msm_window_digit(j->raw[i], w * j->c, j->c);
        if (digit)
            g->base(b + (digit - 1) * g->size,
                    j->points + (size_t)j->raw_idx[i] * g->size);
    }

    /* sum(k * bucket[k]) as a running sum from the top bucket down. */
    union { struct g1_point g1; struct g2_point g2; } running;
    g->identity(&running);
    g->identity(out);
    for (size_t k = buckets; k-- > 0;) {
        g->add(&running, b + k * g->size);
        g->add(out, &running);
    }
    memory_cleanse(&running, sizeof(running));
    memory_cleanse(b, buckets * g->size);
    free(b);
    return true;
}

static void msm_task_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct msm_job *j = ctx;
    for (size_t t = lo; t < hi; t++) {
        void *out = j->partial + t * j->g->size;
        if (t < j->windows) {
            if (!msm_window(j, (unsigned)t, out))
                atomic_store(&j->failed, true);
            continue;
        }
        size_t first = (t - j->windows) * j->one_chunk;
        size_t end = j->one_n - first > j->one_chunk ? first + j->one_chunk
                                                     : j->one_n;
        j->g->identity(out);
        for (size_t i = first; i < end; i++)
            j->g->base(out, j->points + (size_t)j->one_idx[i] * j->g->size);
    }
}

static void msm_classify(struct msm_job *j, const struct fr *scalars, size_t n)
{
    uint8_t bytes[32];
    uint64_t raw[4];
    for (size_t i = 0; i < n; i++) {
        fr_to_bytes(bytes, &scalars[i]);
        for (int k = 0; k < 4; k++)
            raw[k] = zcl_read_u64_le(bytes + 8 * k);
        if ((raw[1] | raw[2] | raw[3]) == 0 && raw[0] <= 1) {
            if (raw[0])
                j->one_idx[j->one_n++] = (uint32_t)i;
            continue;
        }
        memcpy(j->raw[j->raw_n], raw, 32);
        j->raw_idx[j->raw_n++] = (uint32_t)i;
    }
    memory_cleanse(bytes, sizeof(bytes));
    memory_cleanse(raw, sizeof(raw));
}

/* Runs every task, then result = sum(2^(c*w) * window[w]) + sum(ones). */
static bool msm_reduce(struct msm_job *j, void *result, unsigned threads)
{
    const struct msm_group *g = j->g;
    if (j->raw_n) {
        j->c = msm_window_bits(j->raw_n);
        j->windows = (MSM_SCALAR_BITS + j->c - 1) / j->c;
    }
    if (j->one_n) {
        j->one_chunk = (j->one_n - 1) / (threads ? threads : 1) + 1;
        if (j->one_chunk < 64)
            j->one_chunk = 64;
    }
    j->tasks = j->windows + (j->one_n ? (j->one_n - 1) / j->one_chunk + 1 : 0);
    if (j->tasks == 0)
        return true;

    j->partial = zcl_calloc(j->tasks, g->size, "msm_partial");
    if (!j->partial)
        LOG_FAIL("groth16", "msm: partial-sum allocation failed (%zu tasks)",
                 j->tasks);
    groth16_parallel_for(threads, j->tasks, 1, msm_task_range, j);

    bool ok = !atomic_load(&j->failed);
    for (size_t w = j->windows; ok && w-- > 0;) {
        for (unsigned d = 0; d < j->c; d++)
            g->dbl(result);
        g->add(result, j->partial + w * g->size);
    }
    for (size_t t = j->windows; ok && t < j->tasks; t++)
        g->add(result, j->partial + t * g->size);
    memory_cleanse(j->partial, j->tasks * g->size);
    free(j->partial);
    return ok;
}

static bool msm_run(const struct msm_group *g, void *result, const void *points,
                    const struct fr *scalars, size_t n, unsigned threads)
{
    g->identity(result);
    if (n == 0)
        return true;
    if (n > UINT32_MAX)
        LOG_FAIL("groth16", "msm: %zu terms exceeds the 2^32 index range", n);

    struct msm_job j = { .g = g, .points = points };
    j.raw = zcl_calloc(n, sizeof(*j.raw), "msm_scalars");
    j.raw_idx = zcl_calloc(n, 2 * sizeof(*j.raw_idx), "msm_index");
    bool ok = j.raw && j.raw_idx;
    if (ok) {
        j.one_idx = j.raw_idx + n;
        msm_classify(&j, scalars, n);
        ok = msm_reduce(&j, result, threads);
    }
    if (j.raw)
        memory_cleanse(j.raw, n * sizeof(*j.raw));
    if (j.raw_idx)
        memory_cleanse(j.raw_idx, n * 2 * sizeof(*j.raw_idx));
    free(j.raw);
    free(j.raw_idx);
    if (!ok) {
        g->identity(result);
        LOG_FAIL("groth16", "msm: failed over %zu terms; result cleared", n);
    }
    return true;
}

bool groth16_g1_msm(struct g1_point *result, const struct g1_point *points,
                    const struct fr *scalars, size_t n, unsigned threads)
{
    return msm_run(&MSM_G1, result, points, scalars, n, threads);
}

bool groth16_g2_msm(struct g2_point *result, const struct g2_point *points,
                    const struct fr *scalars, size_t n, unsigned threads)
{
    return msm_run(&MSM_G2, result, points, scalars, n, threads);
}

void g1_msm(struct g1_point *result,
            const struct g1_point *points, const struct fr *scalars,
            size_t n)
{
    (void)groth16_g1_msm(result, points, scalars, n, 1);
}

void g2_msm(struct g2_point *result,
            const struct g2_point *points, const struct fr *scalars,
            size_t n)
{
    (void)groth16_g2_msm(result, points, scalars, n, 1);
}
