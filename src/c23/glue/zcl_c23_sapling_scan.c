/* zclassicd-owned glue (NOT vendored): batched Sapling incoming-viewing-key
 * key agreement for wallet trial decryption.
 *
 * What it replaces. Trial decryption of one Sapling output against N incoming
 * viewing keys used to call librustzcash_sapling_ka_agree() N times. Each call
 * decompressed the same epk (a field inversion and a Tonelli-Shanks square
 * root that recomputes its roots of unity every time), multiplied by the
 * cofactor, built a fresh 16-entry window table with 14 extended additions,
 * ran 256 doublings and 64 additions with a 16-entry masked lookup each, then
 * paid another field inversion to canonicalise the result.
 * About 80 us per (ivk, output).
 *
 * What it does instead, for ONE output and any number of ivks:
 *   - decompress epk without an inversion (x = sqrt(u v) / v, projective
 *     (s : y v : v : s y)) using a square root with precomputed roots of
 *     unity, and multiply by the cofactor once;
 *   - build, once, a signed radix-16 "comb" of tables for P8 = [8]epk:
 *     t tables, table b holding [1..8] * 16^(S*b) * P8 (S = 64 / t) as affine
 *     "niels" points. One shared inversion normalises every table entry AND
 *     resolves the sign of x of the decoded point (the entries are negated
 *     when needed: [k](-P) = -[k]P);
 *   - per ivk, recode the scalar into 64 signed base-16 digits and evaluate
 *     sum_j d_j 16^j P8 with 4*(S-1) doublings (T skipped where the next
 *     operation is a doubling) and 64 mixed additions (no doublings at all
 *     for t = 64), then
 *   - canonicalise all results of a chunk with ONE shared inversion
 *     (Montgomery's trick) and emit the same 32-byte encoding as jub_to_bytes.
 * t is chosen from the number of ivks by a small cost model: few ivks use a
 * small t (cheap table build), many ivks use a large t (no per-ivk doublings).
 *
 * Equivalence. The group element [ivk]([8]epk) and its canonical encoding are
 * mathematically fixed, and every formula used here (add-2008-hwcd-3 mixed
 * addition, the dedicated doubling, the unified/complete addition) is valid
 * for every pair of curve points, so the output bytes are bit-identical to
 * librustzcash_sapling_ka_agree(): same decode failure (non-canonical y, y
 * not on the curve), same scalar range check (ivk < Jubjub group order), same
 * encoding. The differential tests (src/gtest/test_sapling_scan_batch.cpp,
 * kat_threads under TSan) compare against the one-at-a-time primitives, the
 * Rust-oracle golden records and real mainnet epks. A self-check at first use
 * compares the derived constants, the niels conversion, the square root
 * tables and the decoder with the vendored primitives; if anything disagrees
 * the fast path disables itself and the caller falls back to the
 * one-at-a-time path.
 *
 * Constant time. The scalar (the ivk is secret) is processed exactly like the
 * vendored jub_scalar_mul: digit recoding is branch-free, every digit does a
 * full masked scan of its table and a branch-free conditional negation, and
 * the number of doublings and additions depends only on t (a function of the
 * public ivk count). The epk is public (it is on the chain), so the decoder
 * and the sign handling may branch on it.
 *
 * Thread safety: a context is owned by one thread; the shared state is a
 * set of constants initialised once under pthread_once. Candidate to upstream
 * into Z23's sapling module (Z23 trial-decrypts one ivk at a time in
 * wallet_sapling_decrypt.c). */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "sapling/fr.h"
#include "sapling/sapling.h"
#include "witness_codec.h"
#include "zcl_c23_sapling_scan.h"
#include "support/cleanse.h"

/* A Jubjub point in extended coordinates whose Z is known nonzero. */
#define SCAN_DIGITS 64
#define SCAN_ENTRIES 9   /* |digit| in 0..8 */
#define SCAN_CHUNK 64    /* ivks canonicalised per shared inversion */

struct zcl_c23_sapling_scan_ctx {
    bool epk_ok;                 /* epk decoded; otherwise every ivk fails */
    unsigned t, S;               /* tables, digits per table (t * S == 64) */
    struct jub_niels *tab;       /* t * SCAN_ENTRIES, entry 0 = identity */
};

static struct fr g_d2;           /* 2d, Montgomery form */
static struct jub_niels g_niels_identity;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static atomic_bool g_fast_ok;

/* --- constant-time helpers ------------------------------------------------- */

static inline uint64_t ct_eq_mask(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    uint32_t nz = (x | (0u - x)) >> 31;
    return (uint64_t)0 - (uint64_t)(1u - nz);
}

static inline void niels_cmov(struct jub_niels *dst, const struct jub_niels *src,
                              uint64_t mask)
{
    for (int i = 0; i < 4; i++) {
        dst->y_plus_x.d[i]  ^= (dst->y_plus_x.d[i]  ^ src->y_plus_x.d[i])  & mask;
        dst->y_minus_x.d[i] ^= (dst->y_minus_x.d[i] ^ src->y_minus_x.d[i]) & mask;
        dst->t2d.d[i]       ^= (dst->t2d.d[i]       ^ src->t2d.d[i])       & mask;
    }
}

/* --- shared constant ---------------------------------------------------------- */

static void fr_from_u32(struct fr *r, uint32_t v)
{
    uint8_t b[32] = {0};
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    (void)fr_from_bytes(r, b);
}

/* Montgomery batch inversion of vals[0..n): vals[i] <- 1/vals[i]. prefix is
 * caller scratch of n elements. Every input must be nonzero. */
static void batch_inv(struct fr *vals, struct fr *prefix, size_t n)
{
    if (n == 0)
        return;
    prefix[0] = vals[0];
    for (size_t i = 1; i < n; i++)
        fr_mul(&prefix[i], &prefix[i - 1], &vals[i]);
    struct fr inv;
    fr_inv(&inv, &prefix[n - 1]);
    for (size_t i = n; i-- > 1;) {
        struct fr zi;
        fr_mul(&zi, &inv, &prefix[i - 1]);
        fr_mul(&inv, &inv, &vals[i]);
        vals[i] = zi;
    }
    vals[0] = inv;
}

/* --- field helpers: fixed-exponent power and a square root with precomputed
 *     constants (the vendored fr_sqrt recomputes g^t on every call) --------- */

/* q, the BLS12-381 scalar field modulus (the Jubjub base field), 4 LE limbs. */
static const uint64_t FQ[4] = {
    0xffffffff00000001ULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL};

static struct fr g_d;                 /* the Jubjub curve constant d */
static uint8_t g_sqrt_exp[32];        /* (T - 1) / 2, T = (q - 1) / 2^32, LE */
static struct fr g_pw[32];            /* z0^(2^i), z0 = 5^T: primitive 2^32-th root of 1 */

/* r = base^e, e as 32 LE bytes, left-to-right 4-bit windows (e is public). */
static void fr_pow_w4(struct fr *r, const struct fr *base, const uint8_t e[32])
{
    struct fr tab[16];
    fr_one(&tab[0]);
    tab[1] = *base;
    for (int i = 2; i < 16; i++)
        fr_mul(&tab[i], &tab[i - 1], base);
    struct fr acc;
    fr_one(&acc);
    bool started = false;
    for (int i = 63; i >= 0; i--) {
        unsigned nib = (e[i >> 1] >> ((i & 1) * 4)) & 0xFu;
        if (started) {
            fr_sq(&acc, &acc);
            fr_sq(&acc, &acc);
            fr_sq(&acc, &acc);
            fr_sq(&acc, &acc);
        }
        if (nib) {
            if (started)
                fr_mul(&acc, &acc, &tab[nib]);
            else
                acc = tab[nib];
            started = true;
        }
    }
    *r = acc;
}

/* Square root in Fr (Tonelli-Shanks, q - 1 = 2^32 T) with the roots of unity
 * precomputed. false when a is not a square. Which root comes back is
 * arbitrary, exactly as with the vendored fr_sqrt; the only caller fixes the
 * sign afterwards. */
static bool sqrt_fast(struct fr *r, const struct fr *a)
{
    if (fr_is_zero(a)) {
        fr_zero(r);
        return true;
    }
    struct fr one, z, x, b;
    fr_one(&one);
    fr_pow_w4(&z, a, g_sqrt_exp);   /* a^((T-1)/2) */
    fr_mul(&x, a, &z);              /* a^((T+1)/2) */
    fr_mul(&b, &x, &z);             /* a^T */
    unsigned v = 32;
    for (;;) {
        struct fr t = b;
        unsigned m = 0;
        while (!fr_eq(&t, &one)) {
            fr_sq(&t, &t);
            m++;
            if (m >= v)
                return false;       /* a is a non-residue */
        }
        if (m == 0)
            break;
        fr_mul(&x, &x, &g_pw[32 - m - 1]);
        fr_mul(&b, &b, &g_pw[32 - m]);
        v = m;
    }
    struct fr chk;
    fr_sq(&chk, &x);
    if (!fr_eq(&chk, a))
        return false;
    *r = x;
    return true;
}

static void init_sqrt_constants(void)
{
    /* T = (q - 1) >> 32 ; e = (T - 1) >> 1 */
    uint64_t qm1[4] = {FQ[0] - 1, FQ[1], FQ[2], FQ[3]};
    uint64_t T[4];
    for (int i = 0; i < 4; i++)
        T[i] = (qm1[i] >> 32) | ((i < 3 ? qm1[i + 1] : 0) << 32);
    uint64_t e[4] = {T[0] - 1, T[1], T[2], T[3]}; /* T is odd: no borrow */
    for (int i = 0; i < 4; i++)
        e[i] = (e[i] >> 1) | ((i < 3 ? e[i + 1] : 0) << 63);
    for (int i = 0; i < 32; i++)
        g_sqrt_exp[i] = (uint8_t)(e[i >> 3] >> (8 * (i & 7)));

    uint8_t tb[32];
    for (int i = 0; i < 32; i++)
        tb[i] = (uint8_t)(T[i >> 3] >> (8 * (i & 7)));
    struct fr five;
    fr_from_u32(&five, 5);
    fr_pow_w4(&g_pw[0], &five, tb);
    for (int i = 1; i < 32; i++)
        fr_sq(&g_pw[i], &g_pw[i - 1]);
}

/* Decode a compressed Jubjub point without any inversion: with
 * x^2 = u / v (u = y^2 - 1, v = 1 + d y^2), s = sqrt(u v) gives
 * x = s / v, so (X : Y : Z : T) = (s : y v : v : s y). The sign of x cannot be
 * applied yet (it needs 1/v); the caller applies it once it holds 1/v.
 * Accepts exactly the encodings jub_from_bytes accepts: y canonical (< q) and
 * x^2 a square (v is never zero: -1/d is a non-residue). */
static bool decode_unsigned(struct jub_point *p, bool *x_sign, const uint8_t in[32])
{
    uint8_t yb[32];
    memcpy(yb, in, 32);
    *x_sign = ((yb[31] >> 7) & 1) != 0;
    yb[31] &= 0x7f;
    struct fr y, y2, one, u, v, uv, s;
    if (!fr_from_bytes(&y, yb))
        return false;
    fr_sq(&y2, &y);
    fr_one(&one);
    fr_sub(&u, &y2, &one);
    fr_mul(&v, &g_d, &y2);
    fr_add(&v, &one, &v);
    fr_mul(&uv, &u, &v);
    if (!sqrt_fast(&s, &uv))
        return false;
    p->x = s;
    fr_mul(&p->y, &y, &v);
    p->z = v;
    fr_mul(&p->t, &s, &y);
    return true;
}

/* Doubling that skips the T coordinate (saves a multiplication when the next
 * operation is another doubling, which reads only X, Y, Z). */
static inline void dbl_no_t(struct jub_point *r, const struct jub_point *a)
{
    struct fr A, B, C, D, E, F, G, H, t;
    fr_sq(&A, &a->x);
    fr_sq(&B, &a->y);
    fr_sq(&C, &a->z);
    fr_add(&C, &C, &C);
    fr_neg(&D, &A);
    fr_add(&t, &a->x, &a->y);
    fr_sq(&E, &t);
    fr_sub(&E, &E, &A);
    fr_sub(&E, &E, &B);
    fr_add(&G, &D, &B);
    fr_sub(&F, &G, &C);
    fr_sub(&H, &D, &B);
    fr_mul(&r->x, &E, &F);
    fr_mul(&r->y, &G, &H);
    fr_mul(&r->z, &F, &G);
}

/* Extended point -> niels, given 1/Z; negated (the niels form of -P) when
 * negate is set: -P swaps y+x with y-x and negates 2dxy. */
static void to_niels(struct jub_niels *out, const struct jub_point *p,
                     const struct fr *zi, bool negate)
{
    struct fr s, yp, ym, t2d;
    fr_add(&s, &p->y, &p->x);
    fr_mul(&yp, &s, zi);
    fr_sub(&s, &p->y, &p->x);
    fr_mul(&ym, &s, zi);
    fr_mul(&s, &p->t, zi);
    fr_mul(&t2d, &s, &g_d2);
    if (negate) {
        out->y_plus_x = ym;
        out->y_minus_x = yp;
        fr_neg(&out->t2d, &t2d);
    } else {
        out->y_plus_x = yp;
        out->y_minus_x = ym;
        out->t2d = t2d;
    }
}

static bool jub_points_equal(const struct jub_point *a, const struct jub_point *b)
{
    uint8_t ea[32], eb[32];
    jub_to_bytes(ea, a);
    jub_to_bytes(eb, b);
    return memcmp(ea, eb, 32) == 0;
}

static void init_once(void)
{
    /* The curve constant d = -10240/10241; the niels form needs 2d. */
    struct fr a, b, binv;
    fr_from_u32(&a, 10240);
    fr_from_u32(&b, 10241);
    fr_inv(&binv, &b);
    fr_mul(&g_d, &a, &binv);
    fr_neg(&g_d, &g_d);
    fr_add(&g_d2, &g_d, &g_d);

    fr_one(&g_niels_identity.y_plus_x);
    fr_one(&g_niels_identity.y_minus_x);
    fr_zero(&g_niels_identity.t2d);

    init_sqrt_constants();

    /* Probe against the vendored primitives on real curve points (the
     * SpendingKey generator multiples, as the shim's warm-up uses): niels form
     * and its negation, the root of unity table, the fast square root and the
     * inversion-free decompression. Any disagreement disables the fast path
     * (callers fall back to the one-at-a-time ka_agree). */
    struct fr minus_one, mo;
    fr_one(&mo);
    fr_neg(&minus_one, &mo);
    bool ok = fr_eq(&g_pw[31], &minus_one);   /* z0 has order exactly 2^32 */

    for (uint8_t k = 1; ok && k <= 6; k++) {
        uint8_t sk[32] = {k}, ak[32];
        sapling_ask_to_ak(sk, ak);
        struct jub_point p, q;
        bool xs;
        ok = jub_from_bytes(&p, ak) && decode_unsigned(&q, &xs, ak);
        if (!ok)
            break;

        struct jub_niels ref, mine, negref;
        struct fr zi;
        jub_to_niels_batch(&ref, &p, 1);
        fr_inv(&zi, &p.z);
        to_niels(&mine, &p, &zi, false);
        ok = fr_eq(&ref.y_plus_x, &mine.y_plus_x) &&
             fr_eq(&ref.y_minus_x, &mine.y_minus_x) &&
             fr_eq(&ref.t2d, &mine.t2d);
        struct jub_point np;
        jub_neg(&np, &p);
        jub_to_niels_batch(&negref, &np, 1);
        fr_inv(&zi, &p.z);
        to_niels(&mine, &p, &zi, true);   /* the negate flag must give niels(-P) */
        ok = ok && fr_eq(&negref.y_plus_x, &mine.y_plus_x) &&
             fr_eq(&negref.y_minus_x, &mine.y_minus_x) &&
             fr_eq(&negref.t2d, &mine.t2d);

        /* decode_unsigned gives P or -P as the same group element up to sign */
        struct jub_point qn;
        jub_neg(&qn, &q);
        ok = ok && (jub_points_equal(&p, &q) || jub_points_equal(&p, &qn));
    }
    atomic_store_explicit(&g_fast_ok, ok, memory_order_release);
}

/* --- context ------------------------------------------------------------------- */

/* Cost model in field multiplications (squarings counted as one): extended
 * doubling 8, extended addition 10, mixed addition 8, one inversion ~380. */
static unsigned choose_tables(size_t n)
{
    unsigned best_t = 1;
    uint64_t best = UINT64_MAX;
    for (unsigned t = 1; t <= 64; t <<= 1) {
        uint64_t S = 64 / t;
        uint64_t build = 8ull * 4 * S * (t - 1)      /* chain of base doublings */
                       + (uint64_t)t * (3 * 8 + 4 * 10) /* multiples 2..8 per table */
                       + 380 + (uint64_t)t * 8 * 7;  /* shared inversion + niels */
        uint64_t per = 8ull * 4 * (S - 1) + 64 * 8 + 64 * 4 /* masked lookups */;
        uint64_t total = build + (uint64_t)n * per;
        if (total < best) {
            best = total;
            best_t = t;
        }
    }
    return best_t;
}

zcl_c23_sapling_scan_ctx *zcl_c23_sapling_scan_begin(const uint8_t epk[32],
                                                     size_t expected_ivks)
{
    zcl_c23_compat_warm();
    (void)pthread_once(&g_once, init_once);
    if (!atomic_load_explicit(&g_fast_ok, memory_order_acquire))
        return NULL;

    zcl_c23_sapling_scan_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    /* Decompress without inverting: P' = +-P, the sign still unresolved. */
    struct jub_point p;
    bool x_sign;
    if (!decode_unsigned(&p, &x_sign, epk)) {
        ctx->epk_ok = false; /* ka_agree would return false for every ivk */
        return ctx;
    }
    ctx->epk_ok = true;

    /* [8] P' (the table is built for P'; the sign is fixed below when the
     * entries are converted, since [k](-P') = -[k]P' entrywise). */
    struct jub_point p8;
    jub_mul_by_cofactor(&p8, &p);

    ctx->t = choose_tables(expected_ivks ? expected_ivks : 1);
    ctx->S = 64 / ctx->t;
    const size_t nent = (size_t)ctx->t * 8; /* entries 1..8 per table */

    struct jub_point *ext = malloc(nent * sizeof(*ext));
    struct fr *zs = malloc((nent + 1) * sizeof(*zs));
    struct fr *prefix = malloc((nent + 1) * sizeof(*prefix));
    ctx->tab = malloc((size_t)ctx->t * SCAN_ENTRIES * sizeof(*ctx->tab));
    if (!ext || !zs || !prefix || !ctx->tab) {
        free(ext); free(zs); free(prefix);
        zcl_c23_sapling_scan_end(ctx);
        return NULL;
    }

    struct jub_point base = p8;
    for (unsigned b = 0; b < ctx->t; b++) {
        struct jub_point *e = ext + (size_t)b * 8; /* e[k-1] = k * base */
        e[0] = base;
        jub_double(&e[1], &e[0]);          /* 2B */
        jub_add(&e[2], &e[1], &e[0]);      /* 3B */
        jub_double(&e[3], &e[1]);          /* 4B */
        jub_add(&e[4], &e[3], &e[0]);      /* 5B */
        jub_double(&e[5], &e[2]);          /* 6B */
        jub_add(&e[6], &e[5], &e[0]);      /* 7B */
        jub_double(&e[7], &e[3]);          /* 8B */
        if (b + 1 < ctx->t) {
            /* next base = 16^S * base = 4*S doublings */
            struct jub_point nb = base;
            for (unsigned k = 0; k < 4 * ctx->S; k++)
                jub_double(&nb, &nb);
            base = nb;
        }
    }
    /* One inversion for everything: 1/Z of the decoded point (to resolve the
     * sign of x) and 1/Z of every table entry. */
    zs[0] = p.z;
    for (size_t i = 0; i < nent; i++)
        zs[i + 1] = ext[i].z;
    batch_inv(zs, prefix, nent + 1);
    struct fr xa;
    uint8_t xb[32];
    fr_mul(&xa, &p.x, &zs[0]);       /* affine x of P' */
    fr_to_bytes(xb, &xa);
    /* jub_from_bytes negates its root when the parity of x differs from the
     * encoded sign bit (a no-op for x = 0). P = -P' in exactly that case. */
    const bool negate = (((xb[0] & 1) != 0) != x_sign);
    for (unsigned b = 0; b < ctx->t; b++) {
        struct jub_niels *row = ctx->tab + (size_t)b * SCAN_ENTRIES;
        row[0] = g_niels_identity;
        for (unsigned k = 1; k <= 8; k++)
            to_niels(&row[k], &ext[(size_t)b * 8 + (k - 1)], &zs[(size_t)b * 8 + (k - 1) + 1], negate);
    }
    memset(xb, 0, sizeof(xb));
    free(ext);
    free(zs);
    free(prefix);
    return ctx;
}

void zcl_c23_sapling_scan_end(zcl_c23_sapling_scan_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->tab) {
        memset(ctx->tab, 0, (size_t)ctx->t * SCAN_ENTRIES * sizeof(*ctx->tab));
        free(ctx->tab);
    }
    free(ctx);
}

/* Signed radix-16 recoding of a scalar < 2^252: digits in [-8, 7], digit 63 in
 * {0, 1}. Branch-free. */
static void recode(int8_t d[SCAN_DIGITS], const uint8_t s[32])
{
    int carry = 0;
    for (int j = 0; j < SCAN_DIGITS; j++) {
        int nib = (s[j >> 1] >> ((j & 1) * 4)) & 0xF;
        int v = nib + carry;
        carry = (v + 8) >> 4;
        d[j] = (int8_t)(v - (carry << 4));
    }
}

static void mul_one(const zcl_c23_sapling_scan_ctx *ctx, struct jub_point *out,
                    const int8_t dig[SCAN_DIGITS])
{
    struct jub_point acc;
    jub_identity(&acc);
    for (unsigned a = ctx->S; a-- > 0;) {
        if (a + 1 != ctx->S) {
            dbl_no_t(&acc, &acc);   /* doubling reads only X, Y, Z */
            dbl_no_t(&acc, &acc);
            dbl_no_t(&acc, &acc);
            jub_double(&acc, &acc); /* the addition below needs T */
        }
        for (unsigned b = 0; b < ctx->t; b++) {
            int dg = dig[a + ctx->S * b];
            uint32_t neg = (uint32_t)(dg >> 7) & 1u;          /* dg < 0 */
            uint32_t mag = (uint32_t)((dg ^ -(int)neg) + (int)neg) & 0xFu; /* |dg| */
            const struct jub_niels *row = ctx->tab + (size_t)b * SCAN_ENTRIES;
            struct jub_niels sel = row[0];
            for (uint32_t k = 1; k < SCAN_ENTRIES; k++)
                niels_cmov(&sel, &row[k], ct_eq_mask(k, mag));
            jub_add_niels(&acc, &acc, &sel, neg != 0);
        }
    }
    *out = acc;
    memory_cleanse(&acc, sizeof(acc));
}

void zcl_c23_sapling_scan_agree(const zcl_c23_sapling_scan_ctx *ctx,
                                  const uint8_t *ivks, size_t n,
                                  uint8_t *dh, uint8_t *ok)
{
    if (!ctx)
        return;
    if (!ctx->epk_ok) {
        for (size_t i = 0; i < n; i++)
            ok[i] = 0;
        return;
    }
    size_t done = 0;
    while (done < n) {
        size_t m = n - done;
        if (m > SCAN_CHUNK)
            m = SCAN_CHUNK;
        struct jub_point pts[SCAN_CHUNK];
        struct fr zs[SCAN_CHUNK], prefix[SCAN_CHUNK];
        size_t idx[SCAN_CHUNK];
        size_t cnt = 0;
        for (size_t i = 0; i < m; i++) {
            const uint8_t *iv = ivks + 32 * (done + i);
            /* Fs::from_repr: the scalar must be below the group order. */
            if (!zcl_c23_lt_fs_modulus(iv)) {
                ok[done + i] = 0;
                continue;
            }
            int8_t dig[SCAN_DIGITS];
            recode(dig, iv);
            mul_one(ctx, &pts[cnt], dig);
            zs[cnt] = pts[cnt].z;
            idx[cnt++] = done + i;
            memory_cleanse(dig, sizeof(dig));
        }
        batch_inv(zs, prefix, cnt);
        for (size_t c = 0; c < cnt; c++) {
            struct fr x, y;
            uint8_t xb[32];
            fr_mul(&x, &pts[c].x, &zs[c]);
            fr_mul(&y, &pts[c].y, &zs[c]);
            uint8_t *out = dh + 32 * idx[c];
            fr_to_bytes(out, &y);
            fr_to_bytes(xb, &x);
            out[31] |= (uint8_t)((xb[0] & 1) << 7);
            ok[idx[c]] = 1;
        }
        memory_cleanse(pts, sizeof(pts));
        memory_cleanse(zs, sizeof(zs));
        memory_cleanse(prefix, sizeof(prefix));
        done += m;
    }

}
