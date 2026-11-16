/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BLS12-381 scalar field (Fr) and Jubjub curve — pure C23 implementation.
 * Montgomery multiplication with R = 2^256 for field arithmetic.
 * Extended twisted Edwards coordinates for Jubjub point operations.
 *
 * Note on `return false;` paths in this file: every one is an algorithmic
 * outcome, not a silent error. Specifically:
 *   - fr_gte-style helpers compare two field elements; `false` is "less
 *     than" or "not equal", not a failure.
 *   - fr_sqrt returns false when the input is not a quadratic residue,
 *     which happens for ~50% of random inputs in hash-to-curve retry
 *     loops (find_group_hash walks counters until a point decodes).
 *   - fr_from_bytes returns false when bytes don't encode a valid field
 *     element, also a routine miss during compressed-point parsing.
 *
 * Wrapping these with LOG_FAIL would flood stderr hundreds of times per
 * block verification. Do NOT add logging here without understanding
 * each call site's retry behavior. commit
 * ca139a5ad for the crypto-side close-out of the logging audit. */

#include "sapling/fr.h"
#include <string.h>

/* Runtime-dispatched Montgomery multiply (CPUID → BMI2+ADX or portable) */
extern void fr_mont_mul_accel(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
#define fr_mont_mul fr_mont_mul_accel

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

/* p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 */
static const uint64_t FR_P[4] = {
    0xffffffff00000001ULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL
};

/* FR_INV moved to fr_avx512.c (runtime dispatch) */

/* R mod p = 2^256 mod p (= 1 in Montgomery form) */
static const uint64_t FR_R[4] = {
    0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
    0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL
};

/* R^2 mod p */
static const uint64_t FR_R2[4] = {
    0xc999e990f3f29c6dULL, 0x2b6cedcb87925c23ULL,
    0x05d314967254398fULL, 0x0748d9d99f59ff11ULL
};

/* Jubjub curve parameter d = -(10240/10241) mod p, in Montgomery form */
static const uint64_t JUB_D[4] = {
    0x2a522455b974f6b0ULL, 0xfc6cc9ef0d9acab3ULL,
    0x7a08fb94c27628d1ULL, 0x57f8f6a8fe0e262eULL
};


/* --- Fr field arithmetic --- */

static bool fr_gte(const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true; /* equal */
}

static void fr_sub_noborrow(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 tmp = (unsigned __int128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)tmp;
        borrow = (tmp >> 127) & 1; /* borrow if negative */
    }
}

/* Montgomery multiply implementation is in fr_avx512.c (runtime dispatch) */

void fr_zero(struct fr *r) { memset(r->d, 0, 32); }

void fr_one(struct fr *r) { memcpy(r->d, FR_R, 32); }

bool fr_is_zero(const struct fr *a)
{
    return a->d[0] == 0 && a->d[1] == 0 && a->d[2] == 0 && a->d[3] == 0;
}

bool fr_eq(const struct fr *a, const struct fr *b)
{
    return a->d[0] == b->d[0] && a->d[1] == b->d[1] &&
           a->d[2] == b->d[2] && a->d[3] == b->d[3];
}

void fr_add(struct fr *r, const struct fr *a, const struct fr *b)
{
    unsigned __int128 carry = 0;
    uint64_t tmp[4];
    for (int i = 0; i < 4; i++) {
        unsigned __int128 sum = (unsigned __int128)a->d[i] + b->d[i] + carry;
        tmp[i] = (uint64_t)sum;
        carry = sum >> 64;
    }
    if (carry || fr_gte(tmp, FR_P))
        fr_sub_noborrow(r->d, tmp, FR_P);
    else
        memcpy(r->d, tmp, 32);
}

void fr_sub(struct fr *r, const struct fr *a, const struct fr *b)
{
    if (fr_gte(a->d, b->d)) {
        fr_sub_noborrow(r->d, a->d, b->d);
    } else {
        /* a - b + p */
        uint64_t tmp[4];
        unsigned __int128 carry = 0;
        for (int i = 0; i < 4; i++) {
            unsigned __int128 sum = (unsigned __int128)a->d[i] + FR_P[i] + carry;
            tmp[i] = (uint64_t)sum;
            carry = sum >> 64;
        }
        fr_sub_noborrow(r->d, tmp, b->d);
    }
}

void fr_neg(struct fr *r, const struct fr *a)
{
    if (fr_is_zero(a)) {
        fr_zero(r);
    } else {
        fr_sub_noborrow(r->d, FR_P, a->d);
    }
}

void fr_mul(struct fr *r, const struct fr *a, const struct fr *b)
{
    fr_mont_mul(r->d, a->d, b->d);
}

void fr_sq(struct fr *r, const struct fr *a)
{
    fr_mont_mul(r->d, a->d, a->d);
}

void fr_inv(struct fr *r, const struct fr *a)
{
    /* Fermat's little theorem: a^{-1} = a^{p-2} mod p */
    struct fr result;
    fr_one(&result);
    struct fr base = *a;

    /* p - 2 in bytes */
    uint8_t exp[32];
    for (int i = 0; i < 32; i++)
        exp[i] = ((const uint8_t *)FR_P)[i];
    /* Subtract 2 from p (little-endian) */
    if (exp[0] >= 2) {
        exp[0] -= 2;
    } else {
        exp[0] += 254; /* 0 - 2 + 256 */
        int i = 1;
        while (i < 32 && exp[i] == 0) { exp[i] = 0xff; i++; }
        if (i < 32) exp[i]--;
    }

    for (int i = 0; i < 256; i++) {
        if ((exp[i / 8] >> (i % 8)) & 1)
            fr_mul(&result, &result, &base);
        fr_sq(&base, &base);
    }
    *r = result;
}

bool fr_from_bytes(struct fr *r, const uint8_t s[32])
{
    /* Load raw little-endian bytes */
    uint64_t raw[4];
    for (int i = 0; i < 4; i++) {
        raw[i] = 0;
        for (int j = 0; j < 8; j++)
            raw[i] |= (uint64_t)s[i * 8 + j] << (j * 8);
    }

    /* Check < p strictly: an encoding equal to p is not canonical, and
     * zclassicd's Fr::from_repr rejects it (consensus parity). */
    bool ok = false;
    for (int i = 3; i >= 0; i--) {
        if (raw[i] > FR_P[i]) break;
        if (raw[i] < FR_P[i]) { ok = true; break; }
    }

    /* Convert to Montgomery form: r = raw * R^2 * R^{-1} = raw * R mod p */
    fr_mont_mul(r->d, raw, FR_R2);
    return ok;
}

void fr_to_bytes(uint8_t s[32], const struct fr *a)
{
    /* Convert from Montgomery form: raw = a * 1 * R^{-1} = a * R^{-1} mod p */
    uint64_t one[4] = {1, 0, 0, 0};
    uint64_t raw[4];
    fr_mont_mul(raw, a->d, one);

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            s[i * 8 + j] = (uint8_t)(raw[i] >> (j * 8));
}

/* --- Jubjub curve operations --- */
/* Twisted Edwards: -x^2 + y^2 = 1 + d*x^2*y^2
 * a = -1
 * Extended coordinates: (X : Y : Z : T) where x = X/Z, y = Y/Z, T = XY/Z */

static struct fr FR_JUB_D; /* d in Montgomery form */
static bool jub_params_init = false;

static void ensure_jub_params(void)
{
    if (jub_params_init) return;
    memcpy(FR_JUB_D.d, JUB_D, 32);
    /* JUB_D is already in Montgomery form (precomputed) */
    jub_params_init = true;
}

void jub_identity(struct jub_point *p)
{
    fr_zero(&p->x);
    fr_one(&p->y);
    fr_one(&p->z);
    fr_zero(&p->t);
}

bool jub_is_identity(const struct jub_point *p)
{
    return fr_is_zero(&p->x) && fr_eq(&p->y, &p->z);
}

void jub_neg(struct jub_point *r, const struct jub_point *p)
{
    fr_neg(&r->x, &p->x);
    r->y = p->y;
    r->z = p->z;
    fr_neg(&r->t, &p->t);
}

/* Complete addition for twisted Edwards with a=-1 */
void jub_add(struct jub_point *r, const struct jub_point *a, const struct jub_point *b)
{
    ensure_jub_params();

    struct fr A, B, C, D, E, F, G, H;

    /* A = a.X * b.X */
    fr_mul(&A, &a->x, &b->x);
    /* B = a.Y * b.Y */
    fr_mul(&B, &a->y, &b->y);
    /* C = a.T * d * b.T */
    fr_mul(&C, &a->t, &b->t);
    fr_mul(&C, &C, &FR_JUB_D);
    /* D = a.Z * b.Z */
    fr_mul(&D, &a->z, &b->z);

    /* E = (a.X + a.Y) * (b.X + b.Y) - A - B */
    struct fr t1, t2;
    fr_add(&t1, &a->x, &a->y);
    fr_add(&t2, &b->x, &b->y);
    fr_mul(&E, &t1, &t2);
    fr_sub(&E, &E, &A);
    fr_sub(&E, &E, &B);

    /* F = D - C */
    fr_sub(&F, &D, &C);
    /* G = D + C */
    fr_add(&G, &D, &C);
    /* H = B - a*A = B + A (since a = -1) */
    fr_add(&H, &B, &A);

    /* Result: X = E*F, Y = G*H, T = E*H, Z = F*G */
    fr_mul(&r->x, &E, &F);
    fr_mul(&r->y, &G, &H);
    fr_mul(&r->t, &E, &H);
    fr_mul(&r->z, &F, &G);
}

void jub_double(struct jub_point *r, const struct jub_point *a)
{
    struct fr A, B, C, D, E, G, F, H;

    /* A = a.X^2 */
    fr_sq(&A, &a->x);
    /* B = a.Y^2 */
    fr_sq(&B, &a->y);
    /* C = 2 * a.Z^2 */
    fr_sq(&C, &a->z);
    fr_add(&C, &C, &C);
    /* D = a * A = -A (since a = -1) */
    fr_neg(&D, &A);

    /* E = (a.X + a.Y)^2 - A - B */
    struct fr t1;
    fr_add(&t1, &a->x, &a->y);
    fr_sq(&E, &t1);
    fr_sub(&E, &E, &A);
    fr_sub(&E, &E, &B);

    /* G = D + B */
    fr_add(&G, &D, &B);
    /* F = G - C */
    fr_sub(&F, &G, &C);
    /* H = D - B */
    fr_sub(&H, &D, &B);

    /* Result: X = E*F, Y = G*H, T = E*H, Z = F*G */
    fr_mul(&r->x, &E, &F);
    fr_mul(&r->y, &G, &H);
    fr_mul(&r->t, &E, &H);
    fr_mul(&r->z, &F, &G);
}

/* Constant-time conditional copy: if mask == all-ones, dst = src;
 * if mask == 0, dst unchanged. No branches, no secret-dependent memory
 * access pattern. */
static inline void fr_cmov(struct fr *dst, const struct fr *src, uint64_t mask)
{
    for (int i = 0; i < 4; i++)
        dst->d[i] = (dst->d[i] & ~mask) | (src->d[i] & mask);
}

static inline void jub_cmov(struct jub_point *dst, const struct jub_point *src,
                            uint64_t mask)
{
    fr_cmov(&dst->x, &src->x, mask);
    fr_cmov(&dst->y, &src->y, mask);
    fr_cmov(&dst->z, &src->z, mask);
    fr_cmov(&dst->t, &src->t, mask);
}

/* Branchless nibble equality: returns 0xFF..FF if a == b (low 4 bits), else 0. */
static inline uint64_t ct_nibble_eq_mask(uint32_t a, uint32_t b)
{
    uint32_t x = (a ^ b) & 0xFu;          /* 0 iff equal */
    uint32_t nonzero = (x | (0u - x)) >> 31; /* 0 iff x == 0, else 1 */
    return (uint64_t)0 - (uint64_t)(1u - nonzero);
}

/* Constant-time lookup: copy table[idx] into *out by scanning every entry.
 * No secret-dependent branch or memory access. */
static void jub_ct_lookup(struct jub_point *out,
                          const struct jub_point table[16],
                          uint32_t idx)
{
    jub_identity(out);
    for (uint32_t i = 0; i < 16u; i++) {
        uint64_t mask = ct_nibble_eq_mask(i, idx);
        jub_cmov(out, &table[i], mask);
    }
}

/* Constant-time 4-bit windowed scalar multiplication.
 *
 * Threat model: callers pass secret scalars (ask, nsk, ivk, esk, bsk for
 * Sapling; ed25519/x25519 secrets elsewhere indirectly). A co-resident
 * attacker must not learn scalar bits from timing or cache-line probes.
 *
 * CT properties of this implementation:
 *   - Table lookup is a masked linear scan over all 16 entries — no
 *     secret-indexed load.
 *   - Per-nibble work is fixed: always 4 doubles and 1 add, regardless
 *     of the nibble value. Since table[0] = identity, the nibble-0 path
 *     adds identity, which is a mathematical no-op (the complete
 *     twisted-Edwards formula handles this branch-free in jub_add).
 *
 * Any future reviewer: do not reintroduce `if (nibble)` or indexed
 * `table[nibble]` without revisiting the side-channel threat model. */
void jub_scalar_mul(struct jub_point *r, const struct jub_point *p, const uint8_t scalar[32])
{
    struct jub_point table[16];
    jub_identity(&table[0]);
    table[1] = *p;
    for (int i = 2; i < 16; i++)
        jub_add(&table[i], &table[i - 1], p);

    struct jub_point acc;
    jub_identity(&acc);

    /* Process from most significant nibble down. 32 bytes × 2 nibbles. */
    for (int i = 63; i >= 0; i--) {
        jub_double(&acc, &acc);
        jub_double(&acc, &acc);
        jub_double(&acc, &acc);
        jub_double(&acc, &acc);

        uint32_t nibble = (uint32_t)((scalar[i / 2] >> ((i & 1) * 4)) & 0xFu);
        struct jub_point selected;
        jub_ct_lookup(&selected, table, nibble);
        jub_add(&acc, &acc, &selected);
    }
    *r = acc;
}

void jub_mul_by_cofactor(struct jub_point *r, const struct jub_point *p)
{
    struct jub_point t;
    jub_double(&t, p);
    jub_double(&t, &t);
    jub_double(r, &t);
}

/* Write (p - 1) >> 32 into t_bytes, little-endian. */
static void fr_sqrt_tonelli_t_bytes(uint8_t t_bytes[32])
{
    /* t = (p-1) >> 32 in bytes */
    uint64_t pm1[4];
    memcpy(pm1, FR_P, 32);
    /* p - 1: subtract 1 from p[0] */
    pm1[0]--;
    /* >> 32: shift right by 32 bits */
    for (int i = 0; i < 4; i++) {
        uint64_t hi = (i < 3) ? pm1[i + 1] : 0;
        pm1[i] = (pm1[i] >> 32) | (hi << 32);
    }
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            t_bytes[i * 8 + j] = (uint8_t)(pm1[i] >> (j * 8));
}

/* Square-and-multiply base_in into *r. exp is 32 little-endian bytes,
 * scanned from bit 0 through bit 255. */
static inline void fr_sqrt_pow_le(struct fr *r, const struct fr *base_in,
                                   const uint8_t exp[32])
{
    struct fr base = *base_in;
    fr_one(r);
    for (int i = 0; i < 256; i++) {
        if ((exp[i / 8] >> (i % 8)) & 1)
            fr_mul(r, r, &base);
        fr_sq(&base, &base);
    }
}

/* Subtract one from a 32-byte little-endian integer, then shift it right one bit. */
static void fr_sqrt_le_sub1_shr1(uint8_t t1h_bytes[32])
{
    /* (t-1)/2: subtract 1 then shift right by 1 */
    /* t is odd, so t-1 is even */
    if (t1h_bytes[0] >= 1) t1h_bytes[0]--;
    else { t1h_bytes[0] = 0xff; for (int i = 1; i < 32; i++) { if (t1h_bytes[i] > 0) { t1h_bytes[i]--; break; } t1h_bytes[i] = 0xff; } }
    /* >> 1 */
    for (int i = 0; i < 31; i++)
        t1h_bytes[i] = (t1h_bytes[i] >> 1) | ((t1h_bytes[i + 1] & 1) << 7);
    t1h_bytes[31] >>= 1;
}

/* Square root mod p using Tonelli-Shanks.
 * p - 1 = 2^32 * q where q = (p-1)/2^32
 * Returns false if no square root exists. */
bool fr_sqrt(struct fr *r, const struct fr *a)
{
    if (fr_is_zero(a)) { fr_zero(r); return true; }

    /* p - 1 = 2^32 * t where t is odd */
    /* Use the Tonelli-Shanks algorithm */
    /* For BLS12-381 Fr: s=32, t = (p-1) >> 32 */

    /* Precompute: find a non-residue. 5 is a non-residue for this field. */
    uint8_t five_bytes[32] = {5};
    struct fr g;
    fr_from_bytes(&g, five_bytes);

    /* Compute g^t (generator of 2-Sylow subgroup) */
    uint8_t t_bytes[32];
    fr_sqrt_tonelli_t_bytes(t_bytes);

    /* w = g^t */
    struct fr w;
    fr_sqrt_pow_le(&w, &g, t_bytes);

    /* x = a^((t-1)/2) */
    uint8_t t1h_bytes[32];
    memcpy(t1h_bytes, t_bytes, 32);
    fr_sqrt_le_sub1_shr1(t1h_bytes);

    struct fr x;
    fr_sqrt_pow_le(&x, a, t1h_bytes);

    /* b = a * x^2, y = a * x */
    struct fr b, y;
    fr_sq(&b, &x);
    fr_mul(&b, a, &b);
    fr_mul(&y, a, &x);

    /* Tonelli-Shanks main loop */
    struct fr ww = w;
    for (int v = 32; v > 1; ) {
        /* Find least k such that b^{2^k} = 1 */
        int k = 0;
        struct fr tmp = b;
        while (!fr_eq(&tmp, (const struct fr *)FR_R)) { /* FR_R = 1 in Montgomery */
            fr_sq(&tmp, &tmp);
            k++;
            if (k >= v) { return false; } /* Not a quadratic residue */
        }
        if (k == 0) break;

        /* w = w^{2^{v-k-1}} */
        struct fr ww2 = ww;
        for (int i = 0; i < v - k - 1; i++)
            fr_sq(&ww2, &ww2);

        v = k;
        fr_sq(&ww, &ww2);
        fr_mul(&b, &b, &ww);
        fr_mul(&y, &y, &ww2);
    }

    /* Verify: y^2 == a */
    struct fr check;
    fr_sq(&check, &y);
    if (!fr_eq(&check, a)) return false;

    *r = y;
    return true;
}

void jub_to_bytes(uint8_t out[32], const struct jub_point *p)
{
    /* Convert to affine: x = X/Z, y = Y/Z */
    struct fr z_inv, x_aff, y_aff;
    fr_inv(&z_inv, &p->z);
    fr_mul(&x_aff, &p->x, &z_inv);
    fr_mul(&y_aff, &p->y, &z_inv);

    /* Encode y, with sign bit of x in the top bit */
    fr_to_bytes(out, &y_aff);

    /* Get the sign of x (lowest bit of x when converted to bytes) */
    uint8_t x_bytes[32];
    fr_to_bytes(x_bytes, &x_aff);
    out[31] |= (x_bytes[0] & 1) << 7;
}

bool jub_from_bytes(struct jub_point *p, const uint8_t in[32])
{
    ensure_jub_params();

    uint8_t y_bytes[32];
    memcpy(y_bytes, in, 32);
    bool x_sign = (y_bytes[31] >> 7) & 1;
    y_bytes[31] &= 0x7f;

    struct fr y;
    if (!fr_from_bytes(&y, y_bytes)) return false;

    /* Compute x^2 from curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
     * x^2 * (-1 - d*y^2) = 1 - y^2
     * x^2 = (1 - y^2) / (-1 - d*y^2) = (y^2 - 1) / (1 + d*y^2) * (-1)
     * Actually: x^2 = (y^2 - 1) / (d*y^2 - 1) ... let me redo.
     * -x^2 + y^2 = 1 + d*x^2*y^2
     * y^2 - 1 = x^2 + d*x^2*y^2 = x^2(1 + d*y^2)
     * x^2 = (y^2 - 1) / (1 + d*y^2)
     * But a = -1, so: a*x^2 + y^2 = 1 + d*x^2*y^2
     * -x^2 + y^2 = 1 + d*x^2*y^2
     * y^2 - 1 = x^2(1 + d*y^2)
     * Wait, that's wrong. Let me be more careful:
     * -x^2 + y^2 = 1 + d*x^2*y^2
     * y^2 - 1 = x^2 + d*x^2*y^2 = x^2*(1 + d*y^2)
     * x^2 = (y^2 - 1) / (1 + d*y^2)
     * Hmm but with a=-1: a*x^2 = -x^2, so x^2 term is negative.
     * a*x^2 + y^2 = 1 + d*x^2*y^2
     * y^2 - 1 = -a*x^2 + d*x^2*y^2 = x^2(-a + d*y^2) = x^2(1 + d*y^2)
     * x^2 = (y^2 - 1) / (1 + d*y^2) ← This is correct for a = -1
     */

    struct fr y2, one_val, num, denom, x2, x;
    fr_sq(&y2, &y);
    fr_one(&one_val);

    /* num = y^2 - 1 */
    fr_sub(&num, &y2, &one_val);
    /* denom = 1 + d * y^2 */
    fr_mul(&denom, &FR_JUB_D, &y2);
    fr_add(&denom, &one_val, &denom);

    /* x^2 = num / denom */
    struct fr denom_inv;
    fr_inv(&denom_inv, &denom);
    fr_mul(&x2, &num, &denom_inv);

    /* x = sqrt(x^2) */
    if (!fr_sqrt(&x, &x2)) return false;

    /* Check sign */
    uint8_t x_bytes[32];
    fr_to_bytes(x_bytes, &x);
    if (((x_bytes[0] & 1) != 0) != x_sign)
        fr_neg(&x, &x);

    p->x = x;
    p->y = y;
    fr_one(&p->z);
    fr_mul(&p->t, &x, &y);

    return true;
}

void jub_get_x(struct fr *r, const struct jub_point *p)
{
    struct fr z_inv;
    fr_inv(&z_inv, &p->z);
    fr_mul(r, &p->x, &z_inv);
}

void jub_get_y(struct fr *r, const struct jub_point *p)
{
    struct fr z_inv;
    fr_inv(&z_inv, &p->z);
    fr_mul(r, &p->y, &z_inv);
}

/* --- Jubjub scalar field Fs --- */
/* s = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7 */
static const uint64_t FS_S[4] = {
    0xd0970e5ed6f72cb7ULL, 0xa6682093ccc81082ULL,
    0x06673b0101343b00ULL, 0x0e7db4ea6533afa9ULL
};

void fs_zero(struct fs *r) { memset(r->d, 0, 32); }

void fs_one(struct fs *r) { memset(r->d, 0, 32); r->d[0] = 1; }

bool fs_is_zero(const struct fs *a)
{
    return a->d[0] == 0 && a->d[1] == 0 && a->d[2] == 0 && a->d[3] == 0;
}

void fs_add(struct fs *r, const struct fs *a, const struct fs *b)
{
    unsigned __int128 carry = 0;
    uint64_t tmp[4];
    for (int i = 0; i < 4; i++) {
        unsigned __int128 sum = (unsigned __int128)a->d[i] + b->d[i] + carry;
        tmp[i] = (uint64_t)sum;
        carry = sum >> 64;
    }
    if (carry || fr_gte(tmp, FS_S)) {
        fr_sub_noborrow(r->d, tmp, FS_S);
    } else {
        memcpy(r->d, tmp, 32);
    }
}

void fs_neg(struct fs *r, const struct fs *a)
{
    if (fs_is_zero(a)) {
        fs_zero(r);
    } else {
        fr_sub_noborrow(r->d, FS_S, a->d);
    }
}

void fs_to_bytes(uint8_t s[32], const struct fs *a)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            s[i * 8 + j] = (uint8_t)(a->d[i] >> (j * 8));
}

bool fs_from_bytes(struct fs *r, const uint8_t s[32])
{
    for (int i = 0; i < 4; i++) {
        r->d[i] = 0;
        for (int j = 0; j < 8; j++)
            r->d[i] |= (uint64_t)s[i * 8 + j] << (j * 8);
    }
    return !fr_gte(r->d, FS_S);
}

/* Montgomery multiplication for Fs field */
static const uint64_t FS_INV = 0x1ba3a358ef788ef9ULL;
static const uint64_t FS_R2[4] = {
    0x67719aa495e57731ULL, 0x51b0cef09ce3fc26ULL,
    0x69dab7fac026e9a5ULL, 0x04f6547b8d127688ULL
};

static void fs_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t t[5] = {0};
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 prod = (unsigned __int128)a[j] * b[i] + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        t[4] = (uint64_t)carry;

        uint64_t m = t[0] * FS_INV;
        carry = 0;
        unsigned __int128 prod0 = (unsigned __int128)m * FS_S[0] + t[0];
        carry = prod0 >> 64;
        for (int j = 1; j < 4; j++) {
            unsigned __int128 prod = (unsigned __int128)m * FS_S[j] + t[j] + carry;
            t[j - 1] = (uint64_t)prod;
            carry = prod >> 64;
        }
        unsigned __int128 sum = (unsigned __int128)t[4] + carry;
        t[3] = (uint64_t)sum;
        t[4] = (uint64_t)(sum >> 64);
    }
    if (t[4] || fr_gte(t, FS_S))
        fr_sub_noborrow(r, t, FS_S);
    else
        memcpy(r, t, 32);
}

void fs_mul(struct fs *r, const struct fs *a, const struct fs *b)
{
    /* Convert a and b to Montgomery form, multiply, convert back.
     * Or: compute a*b*R^{-1} by converting both to Montgomery first.
     * Actually, since a and b are raw (not Montgomery), we need:
     * result = a * b mod s
     * = mont_mul(mont_mul(a, R2), b)  [convert a to Montgomery, then mul by b]
     * But that gives a*R * b * R^{-1} = a*b. Wait, no.
     * mont_mul(a, R2) = a * R^2 * R^{-1} = a * R = a in Montgomery form
     * mont_mul(a_mont, b) = a*R * b * R^{-1} = a * b
     * So the result is a*b in raw form. */
    uint64_t a_mont[4];
    fs_mont_mul(a_mont, a->d, FS_R2);
    fs_mont_mul(r->d, a_mont, b->d);
}

void fs_to_uniform(struct fs *r, const uint8_t digest[64])
{
    /* Interpret 64 LE bytes as 512-bit integer, reduce mod s.
     * Same as Rust's to_uniform: one.mul_bits(BitIterator(repr))
     * = double-and-add from MSB to LSB. */
    uint64_t repr[8];
    for (int i = 0; i < 8; i++) {
        repr[i] = 0;
        for (int j = 0; j < 8; j++)
            repr[i] |= (uint64_t)digest[i * 8 + j] << (j * 8);
    }

    struct fs res, one, tmp;
    fs_zero(&res);
    fs_one(&one);

    for (int word = 7; word >= 0; word--) {
        for (int bit = 63; bit >= 0; bit--) {
            fs_add(&tmp, &res, &res);
            res = tmp;
            if ((repr[word] >> bit) & 1) {
                fs_add(&tmp, &res, &one);
                res = tmp;
            }
        }
    }

    *r = res;
}

#pragma GCC diagnostic pop
