/* BN-254 (alt_bn128) pairing and PPZKSNARK (PHGR13) verification.
 * Pure C23 port — no external dependencies beyond standard library.
 *
 * Pairing algorithms (Miller loop, line functions, final exponentiation)
 * ported from libsnark by SCIPR Lab:
 *   Copyright (c) 2012-2014 SCIPR Lab and contributors
 *   (Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Shaul Kfir,
 *    Eran Tromer, Madars Virza, Sean Bowe, Daira Hopwood, et al.)
 *   MIT License — see libsnark LICENSE file
 *
 * Zcash integration and PPZKSNARK verification logic:
 *   Copyright (c) 2014-2017 The Zcash developers
 *   MIT License
 *
 * C23 implementation:
 *   Copyright 2026 Rhett Creighton
 *   MIT License
 *
 * Curve: y^2 = x^3 + 3, embedding degree 12.
 * q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
 * r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
 */

#include "sapling/bn254.h"
#include "sapling/bn254_accel.h"
#include <string.h>
#include <stdlib.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

/* ══════════════════════════════════════════════════════════════
 *  Fq: 254-bit prime field arithmetic (Montgomery form)
 * ══════════════════════════════════════════════════════════════ */

/* q = 21888242871839275222246405745257275088696311157297823662689037894645226208583 */
static const uint64_t FQ_Q[4] = {
    0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL,
    0xb85045b68181585dULL, 0x30644e72e131a029ULL
};

/* R = 2^256 mod q (Montgomery R) */
static const uint64_t FQ_R[4] = {
    0xd35d438dc58f0d9dULL, 0x0a78eb28f5c70b3dULL,
    0x666ea36f7879462cULL, 0x0e0a77c19a07df2fULL
};

/* R^2 mod q */
static const uint64_t FQ_R2[4] = {
    0xf32cfc5b538afa89ULL, 0xb5e71911d44501fbULL,
    0x47ab1eff0a417ff6ULL, 0x06d89f71cab8351fULL
};


static inline bool u256_ge(const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true; /* equal */
}

static inline uint64_t u256_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    __uint128_t c = 0;
    for (int i = 0; i < 4; i++) {
        c += (__uint128_t)a[i] + b[i];
        r[i] = (uint64_t)c;
        c >>= 64;
    }
    return (uint64_t)c;
}

static inline uint64_t u256_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    __int128_t c = 0;
    for (int i = 0; i < 4; i++) {
        c += (__int128_t)a[i] - b[i];
        r[i] = (uint64_t)c;
        c >>= 64;
    }
    return (uint64_t)(c < 0 ? 1 : 0); /* borrow */
}

/* Montgomery multiplication: r = a*b*R^{-1} mod q */
/* Runtime-dispatched (BMI2+ADX → portable) Montgomery multiply. The accel
 * paths are byte-identical to the historical portable schoolbook (proven by
 * test_bn254_accel), so this is a pure SPEED swap — no consensus effect. All
 * BN254 Fq/Fq2/Fq12 tower and G1/G2 point arithmetic funnels through here, so
 * every Sprout Groth16 proof verify is accelerated. */
static void bn_fq_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    bn_fq_mont_mul_accel(r, a, b);
}

void bn_fq_zero(struct bn_fq *r) { memset(r->d, 0, 32); }

void bn_fq_one(struct bn_fq *r) { memcpy(r->d, FQ_R, 32); }

bool bn_fq_is_zero(const struct bn_fq *a)
{
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

bool bn_fq_eq(const struct bn_fq *a, const struct bn_fq *b)
{
    return memcmp(a->d, b->d, 32) == 0;
}

void bn_fq_add(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b)
{
    u256_add(r->d, a->d, b->d);
    if (u256_ge(r->d, FQ_Q)) {
        uint64_t tmp[4];
        u256_sub(tmp, r->d, FQ_Q);
        memcpy(r->d, tmp, 32);
    }
}

void bn_fq_sub(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b)
{
    if (u256_sub(r->d, a->d, b->d)) {
        uint64_t tmp[4];
        u256_add(tmp, r->d, FQ_Q);
        memcpy(r->d, tmp, 32);
    }
}

void bn_fq_neg(struct bn_fq *r, const struct bn_fq *a)
{
    if (bn_fq_is_zero(a)) { bn_fq_zero(r); return; }
    u256_sub(r->d, FQ_Q, a->d);
}

void bn_fq_mul(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b)
{
    bn_fq_mont_mul(r->d, a->d, b->d);
}

void bn_fq_sq(struct bn_fq *r, const struct bn_fq *a)
{
    bn_fq_mont_mul(r->d, a->d, a->d);
}

/* Fermat's little theorem: a^{-1} = a^{q-2} mod q */
void bn_fq_inv(struct bn_fq *r, const struct bn_fq *a)
{
    /* q-2 in binary: compute via square-and-multiply */
    uint64_t exp[4];
    memcpy(exp, FQ_Q, 32);
    /* exp = q - 2 */
    __int128_t c = (__int128_t)exp[0] - 2;
    exp[0] = (uint64_t)c;
    for (int i = 1; i < 4 && c < 0; i++) {
        c = (__int128_t)exp[i] - 1;
        exp[i] = (uint64_t)c;
    }

    struct bn_fq base = *a;
    bn_fq_one(r);
    for (int i = 0; i < 4; i++) {
        for (int bit = 0; bit < 64; bit++) {
            if ((exp[i] >> bit) & 1)
                bn_fq_mul(r, r, &base);
            bn_fq_sq(&base, &base);
        }
    }
}

bool bn_fq_sqrt(struct bn_fq *r, const struct bn_fq *a)
{
    /* q mod 4 == 3, so sqrt(a) = a^{(q+1)/4} */
    uint64_t exp[4];
    /* (q+1)/4 */
    __uint128_t c = (__uint128_t)FQ_Q[0] + 1;
    exp[0] = (uint64_t)c;
    c >>= 64;
    for (int i = 1; i < 4; i++) {
        c += FQ_Q[i];
        exp[i] = (uint64_t)c;
        c >>= 64;
    }
    /* Right shift by 2 */
    for (int i = 0; i < 3; i++)
        exp[i] = (exp[i] >> 2) | (exp[i+1] << 62);
    exp[3] >>= 2;

    struct bn_fq base = *a;
    bn_fq_one(r);
    for (int i = 0; i < 4; i++) {
        for (int bit = 0; bit < 64; bit++) {
            if ((exp[i] >> bit) & 1)
                bn_fq_mul(r, r, &base);
            bn_fq_sq(&base, &base);
        }
    }

    /* Verify: r^2 == a */
    struct bn_fq check;
    bn_fq_sq(&check, r);
    return bn_fq_eq(&check, a);
}

bool bn_fq_from_bytes_be(struct bn_fq *r, const uint8_t s[32])
{
    uint64_t raw[4] = {0};
    for (int i = 0; i < 32; i++) {
        int limb = (31 - i) / 8;
        int shift = ((31 - i) % 8) * 8;
        raw[limb] |= (uint64_t)s[i] << shift;
    }
    /* Check < q */
    if (u256_ge(raw, FQ_Q) && memcmp(raw, FQ_Q, 32) != 0)
        return false;
    /* Convert to Montgomery form: r = raw * R^2 * R^{-1} = raw * R mod q */
    bn_fq_mont_mul(r->d, raw, FQ_R2);
    return true;
}

void bn_fq_to_bytes_be(uint8_t s[32], const struct bn_fq *a)
{
    /* Convert from Montgomery: raw = a * 1 = a * R^{-1} mod q */
    uint64_t one[4] = {1,0,0,0};
    uint64_t raw[4];
    bn_fq_mont_mul(raw, a->d, one);
    for (int i = 0; i < 32; i++) {
        int limb = (31 - i) / 8;
        int shift = ((31 - i) % 8) * 8;
        s[i] = (uint8_t)(raw[limb] >> shift);
    }
}

void bn_fq_from_u64(struct bn_fq *r, uint64_t v)
{
    uint64_t raw[4] = {v, 0, 0, 0};
    bn_fq_mont_mul(r->d, raw, FQ_R2);
}

/* ══════════════════════════════════════════════════════════════
 *  Fq2 = Fq[u] / (u^2 + 1)
 * ══════════════════════════════════════════════════════════════ */

void bn_fq2_zero(struct bn_fq2 *r) { bn_fq_zero(&r->c0); bn_fq_zero(&r->c1); }
void bn_fq2_one(struct bn_fq2 *r) { bn_fq_one(&r->c0); bn_fq_zero(&r->c1); }
bool bn_fq2_is_zero(const struct bn_fq2 *a) { return bn_fq_is_zero(&a->c0) && bn_fq_is_zero(&a->c1); }
bool bn_fq2_eq(const struct bn_fq2 *a, const struct bn_fq2 *b) { return bn_fq_eq(&a->c0, &b->c0) && bn_fq_eq(&a->c1, &b->c1); }

void bn_fq2_add(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b)
{
    bn_fq_add(&r->c0, &a->c0, &b->c0);
    bn_fq_add(&r->c1, &a->c1, &b->c1);
}

void bn_fq2_sub(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b)
{
    bn_fq_sub(&r->c0, &a->c0, &b->c0);
    bn_fq_sub(&r->c1, &a->c1, &b->c1);
}

void bn_fq2_neg(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    bn_fq_neg(&r->c0, &a->c0);
    bn_fq_neg(&r->c1, &a->c1);
}

/* (a0+a1*u)(b0+b1*u) = (a0*b0-a1*b1) + (a0*b1+a1*b0)*u  since u^2=-1 */
void bn_fq2_mul(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b)
{
    struct bn_fq t0, t1, t2, t3;
    bn_fq_mul(&t0, &a->c0, &b->c0);
    bn_fq_mul(&t1, &a->c1, &b->c1);
    bn_fq_add(&t2, &a->c0, &a->c1);
    bn_fq_add(&t3, &b->c0, &b->c1);
    bn_fq_sub(&r->c0, &t0, &t1);
    bn_fq_mul(&t2, &t2, &t3);
    bn_fq_sub(&t2, &t2, &t0);
    bn_fq_sub(&r->c1, &t2, &t1);
}

void bn_fq2_sq(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    struct bn_fq t0, t1;
    bn_fq_add(&t0, &a->c0, &a->c1);
    bn_fq_sub(&t1, &a->c0, &a->c1);
    struct bn_fq c1;
    bn_fq_mul(&c1, &a->c0, &a->c1);
    bn_fq_add(&r->c1, &c1, &c1);
    bn_fq_mul(&r->c0, &t0, &t1);
}

void bn_fq2_inv(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    /* 1/(a0+a1*u) = (a0-a1*u)/(a0^2+a1^2) */
    struct bn_fq t0, t1, inv;
    bn_fq_sq(&t0, &a->c0);
    bn_fq_sq(&t1, &a->c1);
    bn_fq_add(&t0, &t0, &t1);
    bn_fq_inv(&inv, &t0);
    bn_fq_mul(&r->c0, &a->c0, &inv);
    bn_fq_neg(&t0, &a->c1);
    bn_fq_mul(&r->c1, &t0, &inv);
}

/* Multiply by xi = 9 + u (non-residue for Fq6 construction) */
void bn_fq2_mul_by_nonresidue(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    /* (a0+a1*u)(9+u) = (9*a0-a1) + (a0+9*a1)*u */
    struct bn_fq nine;
    bn_fq_from_u64(&nine, 9);
    struct bn_fq t0, t1;
    bn_fq_mul(&t0, &a->c0, &nine);
    bn_fq_sub(&t0, &t0, &a->c1);
    bn_fq_mul(&t1, &a->c1, &nine);
    bn_fq_add(&r->c1, &a->c0, &t1);
    r->c0 = t0;
}

/* Fq2 Frobenius: conjugation (a + b*u → a - b*u) since u^p = -u for p ≡ 3 mod 4 */
static void bn_fq2_conj(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    r->c0 = a->c0;
    bn_fq_neg(&r->c1, &a->c1);
}

/* Fq2 norm: N(a) = a * conj(a) = a0^2 + a1^2 ∈ Fq */
static void bn_fq2_norm(struct bn_fq *r, const struct bn_fq2 *a)
{
    struct bn_fq t0, t1;
    bn_fq_sq(&t0, &a->c0);
    bn_fq_sq(&t1, &a->c1);
    bn_fq_add(r, &t0, &t1);
}

/* Fq2 exponentiation by 256-bit exponent (square-and-multiply, LSB first) */
static void bn_fq2_pow(struct bn_fq2 *r, const struct bn_fq2 *base, const uint64_t exp[4])
{
    struct bn_fq2 acc, b;
    bn_fq2_one(&acc);
    b = *base;
    for (int i = 0; i < 4; i++) {
        for (int bit = 0; bit < 64; bit++) {
            if ((exp[i] >> bit) & 1)
                bn_fq2_mul(&acc, &acc, &b);
            bn_fq2_sq(&b, &b);
        }
    }
    *r = acc;
}

/* Divide a 256-bit unsigned integer by a small divisor */
static void u256_div_small(uint64_t r[4], const uint64_t a[4], uint64_t d)
{
    __uint128_t carry = 0;
    for (int i = 3; i >= 0; i--) {
        carry = (carry << 64) | a[i];
        r[i] = (uint64_t)(carry / d);
        carry = carry % d;
    }
}

/* ══════════════════════════════════════════════════════════════
 *  Frobenius constants for BN-254
 *  Computed at first use from ξ = 9+u ∈ Fq2
 * ══════════════════════════════════════════════════════════════ */

static struct {
    bool initialized;
    /* p-Frobenius on Fq6: c_k *= w1_k */
    struct bn_fq2 w1_1;     /* ξ^{(p-1)/3} */
    struct bn_fq2 w1_2;     /* ξ^{2(p-1)/3} */
    /* p-Frobenius on Fq12: c1 *= w1_6 */
    struct bn_fq2 w1_6;     /* ξ^{(p-1)/6} */
    /* p²-Frobenius on Fq6 (in Fq, c1 component is 0) */
    struct bn_fq w2_1;      /* ξ^{(p²-1)/3} = N(w1_1) */
    struct bn_fq w2_2;      /* ξ^{2(p²-1)/3} = N(w1_2) */
    /* p²-Frobenius on Fq12 */
    struct bn_fq w2_6;      /* ξ^{(p²-1)/6} = N(w1_6) */
    /* p³-Frobenius on Fq6 */
    struct bn_fq2 w3_1;     /* ξ^{(p³-1)/3} */
    struct bn_fq2 w3_2;     /* ξ^{2(p³-1)/3} */
    /* p³-Frobenius on Fq12 */
    struct bn_fq2 w3_6;     /* ξ^{(p³-1)/6} */
    /* Twist Frobenius for G2 (used in Miller loop correction) */
    struct bn_fq2 twist_frob_x;  /* ξ^{(p-1)/3} = w1_1 */
    struct bn_fq2 twist_frob_y;  /* ξ^{(p-1)/2} = w1_1 * w1_6 */
} g_frob;

static void bn254_init_frobenius(void)
{
    if (g_frob.initialized) return;

    /* ξ = 9 + u in Fq2 */
    struct bn_fq2 xi;
    bn_fq_from_u64(&xi.c0, 9);
    bn_fq_one(&xi.c1);

    /* Compute exponents from p */
    uint64_t pm1[4];
    memcpy(pm1, FQ_Q, 32);
    /* pm1 = p - 1 */
    __int128_t c = (__int128_t)pm1[0] - 1;
    pm1[0] = (uint64_t)c;
    for (int i = 1; i < 4 && c < 0; i++) {
        c = (__int128_t)pm1[i] - 1;
        pm1[i] = (uint64_t)c;
    }

    uint64_t pm1_div3[4], pm1_div6[4];
    u256_div_small(pm1_div3, pm1, 3);
    u256_div_small(pm1_div6, pm1, 6);

    /* w1_1 = ξ^{(p-1)/3} */
    bn_fq2_pow(&g_frob.w1_1, &xi, pm1_div3);
    /* w1_2 = ξ^{2(p-1)/3} = w1_1² */
    bn_fq2_sq(&g_frob.w1_2, &g_frob.w1_1);
    /* w1_6 = ξ^{(p-1)/6} */
    bn_fq2_pow(&g_frob.w1_6, &xi, pm1_div6);

    /* p²-Frobenius constants via norm (live in Fq, not Fq2):
     * ξ^{(p²-1)/k} = N(ξ^{(p-1)/k}) since (p²-1)/k = (p-1)(p+1)/k
     * and a^{p+1} = a * a^p = a * conj(a) = N(a) for a ∈ Fq2 */
    bn_fq2_norm(&g_frob.w2_1, &g_frob.w1_1);
    bn_fq2_norm(&g_frob.w2_2, &g_frob.w1_2);
    bn_fq2_norm(&g_frob.w2_6, &g_frob.w1_6);

    /* p³-Frobenius: ξ^{(p³-1)/k} = ξ^{((p-1)/k)·(p²+p+1)}
     * Since ξ^{p²-1} = 1, we have (p²+p+1) mod (p²-1) = p+2
     * So ξ^{(p³-1)/k} = (ξ^{(p-1)/k})^{p+2} = conj(w)·w² (where w = ξ^{(p-1)/k}) */
    struct bn_fq2 t, conj_w;
    /* w3_1 */
    bn_fq2_conj(&conj_w, &g_frob.w1_1);
    bn_fq2_sq(&t, &g_frob.w1_1);
    bn_fq2_mul(&g_frob.w3_1, &conj_w, &t);
    /* w3_2 */
    bn_fq2_conj(&conj_w, &g_frob.w1_2);
    bn_fq2_sq(&t, &g_frob.w1_2);
    bn_fq2_mul(&g_frob.w3_2, &conj_w, &t);
    /* w3_6 */
    bn_fq2_conj(&conj_w, &g_frob.w1_6);
    bn_fq2_sq(&t, &g_frob.w1_6);
    bn_fq2_mul(&g_frob.w3_6, &conj_w, &t);

    /* Twist Frobenius for G2 (from libsnark alt_bn128_init.cpp):
     * twist_mul_by_q_X = ξ^{(p-1)/3}
     * twist_mul_by_q_Y = ξ^{(p-1)/2} (computed directly, not as product) */
    g_frob.twist_frob_x = g_frob.w1_1;  /* ξ^{(p-1)/3} */
    /* Compute ξ^{(p-1)/2} directly */
    uint64_t pm1_div2[4];
    u256_div_small(pm1_div2, pm1, 2);
    bn_fq2_pow(&g_frob.twist_frob_y, &xi, pm1_div2);

    g_frob.initialized = true;
}

/* ══════════════════════════════════════════════════════════════
 *  Fq6 = Fq2[v] / (v^3 - xi)  where xi = 9+u
 * ══════════════════════════════════════════════════════════════ */

void bn_fq6_zero(struct bn_fq6 *r) { bn_fq2_zero(&r->c0); bn_fq2_zero(&r->c1); bn_fq2_zero(&r->c2); }
void bn_fq6_one(struct bn_fq6 *r) { bn_fq2_one(&r->c0); bn_fq2_zero(&r->c1); bn_fq2_zero(&r->c2); }

void bn_fq6_add(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b)
{
    bn_fq2_add(&r->c0, &a->c0, &b->c0);
    bn_fq2_add(&r->c1, &a->c1, &b->c1);
    bn_fq2_add(&r->c2, &a->c2, &b->c2);
}

void bn_fq6_sub(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b)
{
    bn_fq2_sub(&r->c0, &a->c0, &b->c0);
    bn_fq2_sub(&r->c1, &a->c1, &b->c1);
    bn_fq2_sub(&r->c2, &a->c2, &b->c2);
}

void bn_fq6_neg(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    bn_fq2_neg(&r->c0, &a->c0);
    bn_fq2_neg(&r->c1, &a->c1);
    bn_fq2_neg(&r->c2, &a->c2);
}

/* v^3 = xi, so multiplying by v shifts and multiplies c2 by xi */
void bn_fq6_mul_by_nonresidue(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    struct bn_fq2 t;
    bn_fq2_mul_by_nonresidue(&t, &a->c2);
    r->c2 = a->c1;
    r->c1 = a->c0;
    r->c0 = t;
}

void bn_fq6_mul(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b)
{
    struct bn_fq2 t0, t1, t2, t3, t4, t5;
    struct bn_fq2 rc0, rc1, rc2; /* temporaries to handle r==a or r==b aliasing */

    bn_fq2_mul(&t0, &a->c0, &b->c0);
    bn_fq2_mul(&t1, &a->c1, &b->c1);
    bn_fq2_mul(&t2, &a->c2, &b->c2);

    /* c0 = t0 + xi*((a1+a2)(b1+b2) - t1 - t2) */
    bn_fq2_add(&t3, &a->c1, &a->c2);
    bn_fq2_add(&t4, &b->c1, &b->c2);
    bn_fq2_mul(&t5, &t3, &t4);
    bn_fq2_sub(&t5, &t5, &t1);
    bn_fq2_sub(&t5, &t5, &t2);
    bn_fq2_mul_by_nonresidue(&t5, &t5);
    bn_fq2_add(&rc0, &t0, &t5);

    /* c1 = (a0+a1)(b0+b1) - t0 - t1 + xi*t2 */
    bn_fq2_add(&t3, &a->c0, &a->c1);
    bn_fq2_add(&t4, &b->c0, &b->c1);
    bn_fq2_mul(&t5, &t3, &t4);
    bn_fq2_sub(&t5, &t5, &t0);
    bn_fq2_sub(&t5, &t5, &t1);
    bn_fq2_mul_by_nonresidue(&t3, &t2);
    bn_fq2_add(&rc1, &t5, &t3);

    /* c2 = (a0+a2)(b0+b2) - t0 - t2 + t1 */
    bn_fq2_add(&t3, &a->c0, &a->c2);
    bn_fq2_add(&t4, &b->c0, &b->c2);
    bn_fq2_mul(&t5, &t3, &t4);
    bn_fq2_sub(&t5, &t5, &t0);
    bn_fq2_sub(&t5, &t5, &t2);
    bn_fq2_add(&rc2, &t5, &t1);

    r->c0 = rc0;
    r->c1 = rc1;
    r->c2 = rc2;
}

void bn_fq6_sq(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    bn_fq6_mul(r, a, a);
}

void bn_fq6_inv(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    struct bn_fq2 t0, t1, t2, c0, c1, c2, t;

    bn_fq2_sq(&t0, &a->c0);
    bn_fq2_sq(&t1, &a->c1);
    bn_fq2_sq(&t2, &a->c2);

    struct bn_fq2 s01, s12, s02;
    bn_fq2_mul(&s01, &a->c0, &a->c1);
    bn_fq2_mul(&s02, &a->c0, &a->c2);
    bn_fq2_mul(&s12, &a->c1, &a->c2);

    /* c0 = t0 - xi*s12 */
    bn_fq2_mul_by_nonresidue(&t, &s12);
    bn_fq2_sub(&c0, &t0, &t);
    /* c1 = xi*t2 - s01 */
    bn_fq2_mul_by_nonresidue(&t, &t2);
    bn_fq2_sub(&c1, &t, &s01);
    /* c2 = t1 - s02 */
    bn_fq2_sub(&c2, &t1, &s02);

    /* det = a0*c0 + xi*(a2*c1 + a1*c2) */
    struct bn_fq2 det, tmp1, tmp2;
    bn_fq2_mul(&tmp1, &a->c2, &c1);
    bn_fq2_mul(&tmp2, &a->c1, &c2);
    bn_fq2_add(&tmp1, &tmp1, &tmp2);
    bn_fq2_mul_by_nonresidue(&tmp1, &tmp1);
    bn_fq2_mul(&det, &a->c0, &c0);
    bn_fq2_add(&det, &det, &tmp1);

    bn_fq2_inv(&det, &det);
    bn_fq2_mul(&r->c0, &c0, &det);
    bn_fq2_mul(&r->c1, &c1, &det);
    bn_fq2_mul(&r->c2, &c2, &det);
}

/* ══════════════════════════════════════════════════════════════
 *  Fq12 = Fq6[w] / (w^2 - v)
 * ══════════════════════════════════════════════════════════════ */

void bn_fq12_zero(struct bn_fq12 *r) { bn_fq6_zero(&r->c0); bn_fq6_zero(&r->c1); }
void bn_fq12_one(struct bn_fq12 *r) { bn_fq6_one(&r->c0); bn_fq6_zero(&r->c1); }

bool bn_fq12_eq(const struct bn_fq12 *a, const struct bn_fq12 *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

void bn_fq12_mul(struct bn_fq12 *r, const struct bn_fq12 *a, const struct bn_fq12 *b)
{
    struct bn_fq6 t0, t1, t2;
    bn_fq6_mul(&t0, &a->c0, &b->c0);
    bn_fq6_mul(&t1, &a->c1, &b->c1);
    bn_fq6_add(&t2, &a->c0, &a->c1);
    struct bn_fq6 t3;
    bn_fq6_add(&t3, &b->c0, &b->c1);
    bn_fq6_mul(&t2, &t2, &t3);
    bn_fq6_sub(&t2, &t2, &t0);
    bn_fq6_sub(&r->c1, &t2, &t1);
    bn_fq6_mul_by_nonresidue(&t1, &t1);
    bn_fq6_add(&r->c0, &t0, &t1);
}

void bn_fq12_sq(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    bn_fq12_mul(r, a, a);
}

void bn_fq12_inv(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    struct bn_fq6 t0, t1, det;
    bn_fq6_sq(&t0, &a->c0);
    bn_fq6_sq(&t1, &a->c1);
    bn_fq6_mul_by_nonresidue(&t1, &t1);
    bn_fq6_sub(&det, &t0, &t1);
    bn_fq6_inv(&det, &det);
    bn_fq6_mul(&r->c0, &a->c0, &det);
    bn_fq6_neg(&t0, &a->c1);
    bn_fq6_mul(&r->c1, &t0, &det);
}

void bn_fq12_conjugate(struct bn_fq12 *a)
{
    bn_fq6_neg(&a->c1, &a->c1);
}

/* Fq6 Frobenius p-map: apply p-Frobenius to each Fq2 coefficient, scale c1 and c2 */
static void bn_fq6_frobenius_p(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    bn254_init_frobenius();
    /* p-Frobenius on Fq2 is conjugation */
    bn_fq2_conj(&r->c0, &a->c0);
    struct bn_fq2 t;
    bn_fq2_conj(&t, &a->c1);
    bn_fq2_mul(&r->c1, &t, &g_frob.w1_1);
    bn_fq2_conj(&t, &a->c2);
    bn_fq2_mul(&r->c2, &t, &g_frob.w1_2);
}

/* Fq6 Frobenius p²-map: p²-Frobenius on Fq2 is identity, scale c1 and c2 */
static void bn_fq6_frobenius_p2(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    bn254_init_frobenius();
    r->c0 = a->c0;
    /* w2_1, w2_2 are in Fq (c1=0), so just multiply c0 component */
    struct bn_fq2 scale;
    bn_fq_zero(&scale.c1);
    scale.c0 = g_frob.w2_1;
    bn_fq2_mul(&r->c1, &a->c1, &scale);
    scale.c0 = g_frob.w2_2;
    bn_fq2_mul(&r->c2, &a->c2, &scale);
}

/* Fq6 Frobenius p³-map */
static void bn_fq6_frobenius_p3(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    bn254_init_frobenius();
    bn_fq2_conj(&r->c0, &a->c0);
    struct bn_fq2 t;
    bn_fq2_conj(&t, &a->c1);
    bn_fq2_mul(&r->c1, &t, &g_frob.w3_1);
    bn_fq2_conj(&t, &a->c2);
    bn_fq2_mul(&r->c2, &t, &g_frob.w3_2);
}

void bn_fq12_frobenius_map(struct bn_fq12 *r, const struct bn_fq12 *a, int power)
{
    bn254_init_frobenius();
    switch (power) {
    case 1: {
        bn_fq6_frobenius_p(&r->c0, &a->c0);
        struct bn_fq6 t;
        bn_fq6_frobenius_p(&t, &a->c1);
        /* Scale by ξ^{(p-1)/6} */
        bn_fq2_mul(&r->c1.c0, &t.c0, &g_frob.w1_6);
        bn_fq2_mul(&r->c1.c1, &t.c1, &g_frob.w1_6);
        bn_fq2_mul(&r->c1.c2, &t.c2, &g_frob.w1_6);
        break;
    }
    case 2: {
        bn_fq6_frobenius_p2(&r->c0, &a->c0);
        struct bn_fq6 t;
        bn_fq6_frobenius_p2(&t, &a->c1);
        struct bn_fq2 scale;
        bn_fq_zero(&scale.c1);
        scale.c0 = g_frob.w2_6;
        bn_fq2_mul(&r->c1.c0, &t.c0, &scale);
        bn_fq2_mul(&r->c1.c1, &t.c1, &scale);
        bn_fq2_mul(&r->c1.c2, &t.c2, &scale);
        break;
    }
    case 3: {
        bn_fq6_frobenius_p3(&r->c0, &a->c0);
        struct bn_fq6 t;
        bn_fq6_frobenius_p3(&t, &a->c1);
        bn_fq2_mul(&r->c1.c0, &t.c0, &g_frob.w3_6);
        bn_fq2_mul(&r->c1.c1, &t.c1, &g_frob.w3_6);
        bn_fq2_mul(&r->c1.c2, &t.c2, &g_frob.w3_6);
        break;
    }
    default:
        *r = *a;
        break;
    }
}

/* ══════════════════════════════════════════════════════════════
 *  G1: y^2 = x^3 + 3 over Fq (Jacobian coordinates)
 * ══════════════════════════════════════════════════════════════ */

void bn_g1_identity(struct bn_g1 *p)
{
    bn_fq_zero(&p->x);
    bn_fq_one(&p->y);
    bn_fq_zero(&p->z);
}

bool bn_g1_is_identity(const struct bn_g1 *p)
{
    return bn_fq_is_zero(&p->z);
}

void bn_g1_neg(struct bn_g1 *r, const struct bn_g1 *p)
{
    r->x = p->x;
    bn_fq_neg(&r->y, &p->y);
    r->z = p->z;
}

void bn_g1_double(struct bn_g1 *r, const struct bn_g1 *a)
{
    if (bn_g1_is_identity(a)) { *r = *a; return; }

    struct bn_fq A, B, C, D, E, F;
    bn_fq_sq(&A, &a->x);
    bn_fq_sq(&B, &a->y);
    bn_fq_sq(&C, &B);

    struct bn_fq t;
    bn_fq_add(&t, &a->x, &B);
    bn_fq_sq(&t, &t);
    bn_fq_sub(&t, &t, &A);
    bn_fq_sub(&t, &t, &C);
    bn_fq_add(&D, &t, &t);

    bn_fq_add(&E, &A, &A);
    bn_fq_add(&E, &E, &A);

    bn_fq_sq(&F, &E);

    /* Compute z BEFORE x,y to handle r==a aliasing safely.
     * r->z = 2 * a->y * a->z (must read a->y before it's overwritten) */
    bn_fq_mul(&r->z, &a->y, &a->z);
    bn_fq_add(&r->z, &r->z, &r->z);

    bn_fq_add(&t, &D, &D);
    bn_fq_sub(&r->x, &F, &t);

    bn_fq_sub(&t, &D, &r->x);
    bn_fq_mul(&t, &E, &t);
    struct bn_fq eight_c;
    bn_fq_add(&eight_c, &C, &C);
    bn_fq_add(&eight_c, &eight_c, &eight_c);
    bn_fq_add(&eight_c, &eight_c, &eight_c);
    bn_fq_sub(&r->y, &t, &eight_c);
}

void bn_g1_add(struct bn_g1 *r, const struct bn_g1 *a, const struct bn_g1 *b)
{
    if (bn_g1_is_identity(a)) { *r = *b; return; }
    if (bn_g1_is_identity(b)) { *r = *a; return; }

    struct bn_fq z1sq, z2sq, u1, u2, s1, s2, h, i, j, rr, v;
    bn_fq_sq(&z1sq, &a->z);
    bn_fq_sq(&z2sq, &b->z);
    bn_fq_mul(&u1, &a->x, &z2sq);
    bn_fq_mul(&u2, &b->x, &z1sq);
    bn_fq_mul(&s1, &a->y, &z2sq);
    bn_fq_mul(&s1, &s1, &b->z);
    bn_fq_mul(&s2, &b->y, &z1sq);
    bn_fq_mul(&s2, &s2, &a->z);

    if (bn_fq_eq(&u1, &u2)) {
        if (bn_fq_eq(&s1, &s2)) { bn_g1_double(r, a); return; }
        bn_g1_identity(r);
        return;
    }

    bn_fq_sub(&h, &u2, &u1);
    bn_fq_add(&i, &h, &h);
    bn_fq_sq(&i, &i);
    bn_fq_mul(&j, &h, &i);
    bn_fq_sub(&rr, &s2, &s1);
    bn_fq_add(&rr, &rr, &rr);
    bn_fq_mul(&v, &u1, &i);

    bn_fq_sq(&r->x, &rr);
    bn_fq_sub(&r->x, &r->x, &j);
    struct bn_fq v2;
    bn_fq_add(&v2, &v, &v);
    bn_fq_sub(&r->x, &r->x, &v2);

    bn_fq_sub(&r->y, &v, &r->x);
    bn_fq_mul(&r->y, &rr, &r->y);
    struct bn_fq s1j;
    bn_fq_mul(&s1j, &s1, &j);
    bn_fq_add(&s1j, &s1j, &s1j);
    bn_fq_sub(&r->y, &r->y, &s1j);

    bn_fq_add(&r->z, &a->z, &b->z);
    bn_fq_sq(&r->z, &r->z);
    bn_fq_sub(&r->z, &r->z, &z1sq);
    bn_fq_sub(&r->z, &r->z, &z2sq);
    bn_fq_mul(&r->z, &r->z, &h);
}

void bn_g1_to_affine(struct bn_fq *ax, struct bn_fq *ay, const struct bn_g1 *p)
{
    if (bn_g1_is_identity(p)) { bn_fq_zero(ax); bn_fq_zero(ay); return; }
    struct bn_fq zi, zi2, zi3;
    bn_fq_inv(&zi, &p->z);
    bn_fq_sq(&zi2, &zi);
    bn_fq_mul(&zi3, &zi2, &zi);
    bn_fq_mul(ax, &p->x, &zi2);
    bn_fq_mul(ay, &p->y, &zi3);
}

void bn_g1_scalar_mul(struct bn_g1 *r, const struct bn_g1 *p, const uint64_t scalar[4])
{
    struct bn_g1 acc;
    struct bn_g1 base = *p;
    bn_g1_identity(&acc);

    for (int i = 0; i < 4; i++) {
        for (int bit = 0; bit < 64; bit++) {
            if ((scalar[i] >> bit) & 1)
                bn_g1_add(&acc, &acc, &base);
            bn_g1_double(&base, &base);
        }
    }
    *r = acc;
}

bool bn_g1_decompress(struct bn_g1 *p, const uint8_t data[33])
{
    uint8_t flags = data[0];
    bool y_lsb = (flags & 0x01) != 0;

    /* Check for point at infinity */
    bool all_zero = true;
    for (int i = 1; i < 33; i++) if (data[i] != 0) { all_zero = false; break; }
    if (all_zero && (flags & 0x04)) { bn_g1_identity(p); return true; }

    if (!bn_fq_from_bytes_be(&p->x, data + 1))
        return false;

    /* y^2 = x^3 + 3 */
    struct bn_fq x3, b;
    bn_fq_sq(&x3, &p->x);
    bn_fq_mul(&x3, &x3, &p->x);
    bn_fq_from_u64(&b, 3);
    bn_fq_add(&x3, &x3, &b);

    if (!bn_fq_sqrt(&p->y, &x3))
        return false;

    /* Check parity */
    uint8_t ybuf[32];
    bn_fq_to_bytes_be(ybuf, &p->y);
    bool computed_lsb = (ybuf[31] & 1) != 0;
    if (computed_lsb != y_lsb)
        bn_fq_neg(&p->y, &p->y);

    bn_fq_one(&p->z);
    return true;
}

/* ══════════════════════════════════════════════════════════════
 *  G2: y^2 = x^3 + b' over Fq2 (Jacobian)
 *  b' = 3/(9+u) in Fq2
 * ══════════════════════════════════════════════════════════════ */

void bn_g2_identity(struct bn_g2 *p)
{
    bn_fq2_zero(&p->x);
    bn_fq2_one(&p->y);
    bn_fq2_zero(&p->z);
}

bool bn_g2_is_identity(const struct bn_g2 *p)
{
    return bn_fq2_is_zero(&p->z);
}

void bn_g2_neg(struct bn_g2 *r, const struct bn_g2 *p)
{
    r->x = p->x;
    bn_fq2_neg(&r->y, &p->y);
    r->z = p->z;
}

void bn_g2_double(struct bn_g2 *r, const struct bn_g2 *a)
{
    if (bn_g2_is_identity(a)) { *r = *a; return; }

    struct bn_fq2 A, B, C, D, E, F, t;
    bn_fq2_sq(&A, &a->x);
    bn_fq2_sq(&B, &a->y);
    bn_fq2_sq(&C, &B);

    bn_fq2_add(&t, &a->x, &B);
    bn_fq2_sq(&t, &t);
    bn_fq2_sub(&t, &t, &A);
    bn_fq2_sub(&t, &t, &C);
    bn_fq2_add(&D, &t, &t);

    bn_fq2_add(&E, &A, &A);
    bn_fq2_add(&E, &E, &A);

    bn_fq2_sq(&F, &E);

    /* Compute z BEFORE x,y to handle r==a aliasing safely */
    bn_fq2_mul(&r->z, &a->y, &a->z);
    bn_fq2_add(&r->z, &r->z, &r->z);

    bn_fq2_add(&t, &D, &D);
    bn_fq2_sub(&r->x, &F, &t);

    bn_fq2_sub(&t, &D, &r->x);
    bn_fq2_mul(&t, &E, &t);
    struct bn_fq2 eight_c;
    bn_fq2_add(&eight_c, &C, &C);
    bn_fq2_add(&eight_c, &eight_c, &eight_c);
    bn_fq2_add(&eight_c, &eight_c, &eight_c);
    bn_fq2_sub(&r->y, &t, &eight_c);
}

void bn_g2_add(struct bn_g2 *r, const struct bn_g2 *a, const struct bn_g2 *b)
{
    if (bn_g2_is_identity(a)) { *r = *b; return; }
    if (bn_g2_is_identity(b)) { *r = *a; return; }

    struct bn_fq2 z1sq, z2sq, u1, u2, s1, s2, h, i, j, rr, v;
    bn_fq2_sq(&z1sq, &a->z);
    bn_fq2_sq(&z2sq, &b->z);
    bn_fq2_mul(&u1, &a->x, &z2sq);
    bn_fq2_mul(&u2, &b->x, &z1sq);
    bn_fq2_mul(&s1, &a->y, &z2sq);
    bn_fq2_mul(&s1, &s1, &b->z);
    bn_fq2_mul(&s2, &b->y, &z1sq);
    bn_fq2_mul(&s2, &s2, &a->z);

    if (bn_fq2_eq(&u1, &u2)) {
        if (bn_fq2_eq(&s1, &s2)) { bn_g2_double(r, a); return; }
        bn_g2_identity(r);
        return;
    }

    bn_fq2_sub(&h, &u2, &u1);
    bn_fq2_add(&i, &h, &h);
    bn_fq2_sq(&i, &i);
    bn_fq2_mul(&j, &h, &i);
    bn_fq2_sub(&rr, &s2, &s1);
    bn_fq2_add(&rr, &rr, &rr);
    bn_fq2_mul(&v, &u1, &i);

    bn_fq2_sq(&r->x, &rr);
    bn_fq2_sub(&r->x, &r->x, &j);
    struct bn_fq2 v2;
    bn_fq2_add(&v2, &v, &v);
    bn_fq2_sub(&r->x, &r->x, &v2);

    bn_fq2_sub(&r->y, &v, &r->x);
    bn_fq2_mul(&r->y, &rr, &r->y);
    struct bn_fq2 s1j;
    bn_fq2_mul(&s1j, &s1, &j);
    bn_fq2_add(&s1j, &s1j, &s1j);
    bn_fq2_sub(&r->y, &r->y, &s1j);

    bn_fq2_add(&r->z, &a->z, &b->z);
    bn_fq2_sq(&r->z, &r->z);
    bn_fq2_sub(&r->z, &r->z, &z1sq);
    bn_fq2_sub(&r->z, &r->z, &z2sq);
    bn_fq2_mul(&r->z, &r->z, &h);
}

void bn_g2_to_affine(struct bn_fq2 *ax, struct bn_fq2 *ay, const struct bn_g2 *p)
{
    if (bn_g2_is_identity(p)) { bn_fq2_zero(ax); bn_fq2_zero(ay); return; }
    struct bn_fq2 zi, zi2, zi3;
    bn_fq2_inv(&zi, &p->z);
    bn_fq2_sq(&zi2, &zi);
    bn_fq2_mul(&zi3, &zi2, &zi);
    bn_fq2_mul(ax, &p->x, &zi2);
    bn_fq2_mul(ay, &p->y, &zi3);
}

/* ── FE2IP decoding for CompressedG2 ──────────────────────────────
 *
 * Zcash's CompressedG2 wire format encodes the Fq2 x-coordinate as
 * a single 512-bit big-endian integer: combined = c1*q + c0 (FE2IP).
 * To decode: c0 = combined mod q, c1 = combined div q, assert c1 < q.
 *
 * The previous code incorrectly read the 64 bytes as two independent
 * 32-byte big-endian Fq elements (c1 || c0), which is only correct
 * when c1*q < 2^256 — i.e. essentially never for real curve points.
 *
 * Reference: zclassic-cpp/src/zcash/Proof.cpp:85-96 (Fq2::to_libsnark_fq2).
 */

/* Divide a 512-bit unsigned integer by a 256-bit divisor.
 * Returns quotient (256-bit) and remainder (256-bit).
 * Uses binary long division — O(512) iterations. Correct for all inputs.
 * Not performance-critical: called once per G2 decompression. */
static void u512_divmod_u256(const uint64_t dividend[8],
                              const uint64_t divisor[4],
                              uint64_t quotient[4],
                              uint64_t remainder[4])
{
    /* Accumulator for remainder — needs 257 bits during processing. */
    uint64_t rem[5] = {0};
    memset(quotient, 0, 32);

    for (int i = 511; i >= 0; i--) {
        /* Left-shift remainder by 1 */
        rem[4] = (rem[4] << 1) | (rem[3] >> 63);
        rem[3] = (rem[3] << 1) | (rem[2] >> 63);
        rem[2] = (rem[2] << 1) | (rem[1] >> 63);
        rem[1] = (rem[1] << 1) | (rem[0] >> 63);
        rem[0] = rem[0] << 1;

        /* Bring down bit i of dividend */
        if (dividend[i / 64] & (1ULL << (i % 64)))
            rem[0] |= 1;

        /* Compare rem[4..0] >= divisor[3..0] */
        bool ge = false;
        if (rem[4] > 0) {
            ge = true;
        } else {
            ge = true;
            for (int j = 3; j >= 0; j--) {
                if (rem[j] > divisor[j]) break;
                if (rem[j] < divisor[j]) { ge = false; break; }
            }
        }

        if (ge) {
            /* Subtract divisor from rem */
            __int128_t borrow = 0;
            for (int j = 0; j < 4; j++) {
                borrow += (__int128_t)rem[j] - divisor[j];
                rem[j] = (uint64_t)borrow;
                borrow >>= 64;
            }
            rem[4] += (uint64_t)borrow;

            /* Set quotient bit (only bits 0..255 matter) */
            if (i < 256)
                quotient[i / 64] |= (1ULL << (i % 64));
        }
    }

    memcpy(remainder, rem, 32);
}

/* Decode a CompressedG2 Fq2 x-coordinate from 64-byte FE2IP encoding.
 * combined (512-bit BE) = c1*q + c0 where c0, c1 < q.
 * Returns false if c1 >= q (invalid encoding). */
bool fq2_decode_fe2ip(struct bn_fq *c0, struct bn_fq *c1,
                      const uint8_t data[64])
{
    /* Read 64 bytes big-endian into 8 uint64 limbs (little-endian order) */
    uint64_t combined[8] = {0};
    for (int i = 0; i < 64; i++) {
        int limb = (63 - i) / 8;
        int shift = ((63 - i) % 8) * 8;
        combined[limb] |= (uint64_t)data[i] << shift;
    }

    uint64_t q_raw[4], r_raw[4];
    u512_divmod_u256(combined, FQ_Q, q_raw, r_raw);

    /* c1 = quotient, must be < q */
    if (u256_ge(q_raw, FQ_Q) && memcmp(q_raw, FQ_Q, 32) != 0)
        return false;

    /* c0 = remainder (already < q by definition of mod) */
    /* Convert canonical → Montgomery form */
    bn_fq_mont_mul(c0->d, r_raw, FQ_R2);
    bn_fq_mont_mul(c1->d, q_raw, FQ_R2);
    return true;
}

bool bn_g2_decompress(struct bn_g2 *p, const uint8_t data[65])
{
    uint8_t flags = data[0];
    bool y_gt = (flags & 0x01) != 0;

    /* Check for point at infinity */
    bool all_zero = true;
    for (int i = 1; i < 65; i++) if (data[i] != 0) { all_zero = false; break; }
    if (all_zero && (flags & 0x04)) { bn_g2_identity(p); return true; }

    /* G2 x-coordinate: 64-byte FE2IP encoding → (c0, c1) in Fq2.
     * Previous code (WRONG): read as c1(32 BE) || c0(32 BE).
     * Correct: 64 bytes form a single 512-bit BE integer = c1*q + c0. */
    if (!fq2_decode_fe2ip(&p->x.c0, &p->x.c1, data + 1))
        return false;

    /* y^2 = x^3 + b_twist */
    struct bn_fq2 x3, b_twist;
    bn_fq2_sq(&x3, &p->x);
    bn_fq2_mul(&x3, &x3, &p->x);

    /* b_twist = 3 / (9+u). Pre-compute: */
    struct bn_fq2 three, xi;
    bn_fq_from_u64(&three.c0, 3);
    bn_fq_zero(&three.c1);
    bn_fq_from_u64(&xi.c0, 9);
    bn_fq_one(&xi.c1);
    bn_fq2_inv(&b_twist, &xi);
    bn_fq2_mul(&b_twist, &b_twist, &three);

    bn_fq2_add(&x3, &x3, &b_twist);

    /* sqrt in Fq2: try a^{(q^2+1)/4} since q^2 mod 4 == 1 for BN... */
    /* For BN-254: use Tonelli-Shanks or compute a^{(q^2+7)/16} and adjust.
     * Simplified: try Fq2 sqrt via the formula for p ≡ 3 mod 4 base field. */

    /* Fq2 sqrt: let a = a0 + a1*u.
     * alpha = a^{(q-1)/2} in Fq2
     * If alpha == -1, sqrt = u * a * (2a)^{(q-3)/4}
     * If alpha != -1, sqrt = a * (a*(1+alpha))^{-1} * ...
     * Simpler: compute candidate = a^{(q^2+1)/4} and verify */

    /* For the decompression of static VK points, we can use a brute-force
     * approach: compute y^2, then try sqrt. Since Fq2 sqrt is non-trivial,
     * use the Cipolla-like method via the base field. */

    /* Norm-based Fq2 sqrt:
     * norm(a) = a0^2 + a1^2 (since u^2 = -1)
     * If norm(a) is a QR in Fq, compute sqrt(norm) in Fq.
     * Then y = a * (norm(a))^{(q-3)/4} * (sqrt(norm)+a0)^{-1/2} ...
     * This is getting complex. Let me use the direct approach. */

    /* Direct Fq2 sqrt via Frobenius:
     * In Fq2 with q ≡ 3 mod 4:
     * sqrt(a) = a^{(q+1)/2} up to a factor from Fq.
     * But we're in Fq2, so we need a^{(q^2+1)/4}. */

    /* Compute a^{(q+1)/4} as a candidate (works when Fq2 element is in Fq image) */
    /* For general Fq2 elements, use: */

    /* Step 1: a1 = a^{(q-3)/4} */
    /* Step 2: a0 = a1 * a = a^{(q+1)/4} */
    /* Step 3: if a0^2 == a, done */
    /* Step 4: else a0 = a0 * sqrt(-1) = a0 * u (since u^2 = -1) */

    /* Actually, for BN-254, q ≡ 3 mod 4, so sqrt(-1) doesn't exist in Fq.
     * This means u is the sqrt of -1 in Fq2.
     * For Fq2 sqrt with q ≡ 3 mod 4:
     * - Compute t = a^q (Frobenius: conjugate = a0 - a1*u)
     * - Compute alpha = a * t = a * a^q = a^{q+1} = norm(a) in Fq
     * - Compute beta = alpha^{(q-3)/4} in Fq
     * - x = a * t * beta = a^{q+1} * a^{q*(q-3)/4} = ... complicated
     * Let me just use exponentiation. */

    /* Fq2 exponentiation by (q^2+1)/4 */
    /* q^2 + 1 is divisible by 4 for BN-254 */
    /* This would require huge-number exponentiation. Instead, use the
     * chain: sqrt(a) where a in Fq2, q ≡ 3 mod 4:
     *   t = a^{(q-1)/2}  (in Fq2)
     *   if t == 1:  sqrt(a) = a^{(q+1)/4}
     *   if t == -1: sqrt(a) = a^{(q+1)/4} * u^{(q-1)/2} = a^{(q+1)/4} * (-1)^{...}
     * Actually this doesn't work either. */

    /* PRACTICAL APPROACH: for VK loading, the points are stored in the verifying
     * key file uncompressed (x AND y). We only need decompression for proof
     * points. Let me implement bn_g2_from_uncompressed instead and handle
     * proof deserialization accordingly. For compressed G2 in PHGR13 proofs,
     * we need Fq2 sqrt. Let me implement it properly. */

    /* Tonnelli-Shanks for Fq2 using the norm map */
    struct bn_fq norm;
    struct bn_fq a0sq, a1sq;
    bn_fq_sq(&a0sq, &x3.c0);
    bn_fq_sq(&a1sq, &x3.c1);
    bn_fq_add(&norm, &a0sq, &a1sq);

    /* Check if norm is QR in Fq */
    /* norm^{(q-1)/2} should be 1 for QR */

    /* For Fq2 sqrt when q ≡ 3 mod 4:
     * Compute gamma = x3^{(q-1)/2} in Fq2
     * If gamma.c1 == 0 and gamma.c0 == 1: sqrt = x3^{(q+1)/4}
     * If gamma.c1 == 0 and gamma.c0 == -1: no sqrt exists
     * Otherwise: need more complex algorithm */

    /* Since this is getting very involved and the VK file stores points
     * uncompressed for the IC query, let me implement a simpler approach
     * for G2 decompression that works for the proof format: */

    /* BN-254 PHGR13 G2 compressed: just like G1 but in Fq2.
     * We need Fq2 sqrt. Use: for q ≡ 3 mod 4,
     * sqrt in Fq2 of (a0 + a1*u):
     *   If a1 == 0: sqrt(a0) in Fq (straightforward since q ≡ 3 mod 4)
     *   If a1 != 0:
     *     d = sqrt(a0^2 + a1^2) in Fq (norm must be QR)
     *     x0 = sqrt((a0 + d) / 2) or sqrt((a0 - d) / 2)
     *     x1 = a1 / (2 * x0)
     *     return x0 + x1 * u
     */

    struct bn_fq d;
    if (!bn_fq_sqrt(&d, &norm)) {
        /* Try negating */
        bn_fq_neg(&d, &norm);
        if (!bn_fq_sqrt(&d, &d))
            return false;
    }

    /* Try (a0 + d) / 2 */
    struct bn_fq half, sum, y0;
    bn_fq_from_u64(&half, 2);
    bn_fq_inv(&half, &half);

    bn_fq_add(&sum, &x3.c0, &d);
    bn_fq_mul(&sum, &sum, &half);

    if (bn_fq_sqrt(&y0, &sum)) {
        struct bn_fq two_y0, y1;
        bn_fq_add(&two_y0, &y0, &y0);
        bn_fq_inv(&two_y0, &two_y0);
        bn_fq_mul(&y1, &x3.c1, &two_y0);
        p->y.c0 = y0;
        p->y.c1 = y1;
    } else {
        /* Try (a0 - d) / 2 */
        bn_fq_sub(&sum, &x3.c0, &d);
        bn_fq_mul(&sum, &sum, &half);
        if (!bn_fq_sqrt(&y0, &sum))
            return false;
        struct bn_fq two_y0, y1;
        bn_fq_add(&two_y0, &y0, &y0);
        bn_fq_inv(&two_y0, &two_y0);
        bn_fq_mul(&y1, &x3.c1, &two_y0);
        p->y.c0 = y0;
        p->y.c1 = y1;
    }

    /* Verify y^2 == x^3 + b_twist */
    struct bn_fq2 y2;
    bn_fq2_sq(&y2, &p->y);
    if (!bn_fq2_eq(&y2, &x3))
        return false;

    /* Check sign convention: libsnark uses y_gt flag based on comparison */
    /* The y_gt bit means "y > -y" in lexicographic Fq2 ordering */
    uint8_t y1_buf[32];
    bn_fq_to_bytes_be(y1_buf, &p->y.c1);
    bool computed_gt;
    if (!bn_fq_is_zero(&p->y.c1)) {
        /* Compare c1 with q-c1 */
        struct bn_fq neg_c1;
        bn_fq_neg(&neg_c1, &p->y.c1);
        uint8_t neg_buf[32];
        bn_fq_to_bytes_be(neg_buf, &neg_c1);
        computed_gt = (memcmp(y1_buf, neg_buf, 32) > 0);
    } else {
        uint8_t y0_buf[32];
        bn_fq_to_bytes_be(y0_buf, &p->y.c0);
        struct bn_fq neg_c0;
        bn_fq_neg(&neg_c0, &p->y.c0);
        uint8_t neg_buf[32];
        bn_fq_to_bytes_be(neg_buf, &neg_c0);
        computed_gt = (memcmp(y0_buf, neg_buf, 32) > 0);
    }

    if (computed_gt != y_gt)
        bn_fq2_neg(&p->y, &p->y);

    bn_fq2_one(&p->z);
    return true;
}

/* ══════════════════════════════════════════════════════════════
 *  Optimal Ate Pairing on BN-254
 * ══════════════════════════════════════════════════════════════ */

/* BN parameter u = 4965661367192848881 (from libsnark alt_bn128_init.cpp)
 * 6u+2 = 29793968203157093288 = 0x19D797039BE763BA8 */
static const uint64_t ATE_LOOP[2] = {
    0x9D797039BE763BA8ULL,
    0x0000000000000001ULL
};
static const int ATE_LOOP_BITS = 65; /* Number of bits */
static const bool ATE_LOOP_NEG = false;

/* mul_by_024: multiply Fp12 by sparse element with non-zero at positions
 * z0 (c0.c0), z2 (c0.c2), z4 (c1.c1).
 * Uses naive approach (construct full Fp12 and multiply) for correctness. */
static void bn_fq12_mul_by_024(struct bn_fq12 *r,
                                const struct bn_fq2 *ell_0,
                                const struct bn_fq2 *ell_VW,
                                const struct bn_fq2 *ell_VV)
{
    /* Construct sparse Fp12: Fp12(Fp6(ell_0, 0, ell_VV), Fp6(0, ell_VW, 0)) */
    struct bn_fq12 sparse;
    bn_fq12_zero(&sparse);
    sparse.c0.c0 = *ell_0;
    sparse.c0.c2 = *ell_VV;
    sparse.c1.c1 = *ell_VW;

    struct bn_fq12 tmp = *r;
    bn_fq12_mul(r, &tmp, &sparse);
}

/* Doubling step for flipped Miller loop — direct port from libsnark.
 * Updates current point R (Jacobian on twist curve) and produces
 * line function coefficients ell_0, ell_VW, ell_VV. */
static void doubling_step(struct bn_g2 *current,
                          struct bn_fq2 *ell_0,
                          struct bn_fq2 *ell_VW,
                          struct bn_fq2 *ell_VV)
{
    struct bn_fq2 X = current->x, Y = current->y, Z = current->z;

    /* A = X*Y/2 (use inv(2) to avoid division) */
    struct bn_fq two_fq;
    bn_fq_from_u64(&two_fq, 2);
    struct bn_fq two_inv_fq;
    bn_fq_inv(&two_inv_fq, &two_fq);
    struct bn_fq2 two_inv;
    two_inv.c0 = two_inv_fq;
    bn_fq_zero(&two_inv.c1);

    struct bn_fq2 XY;
    bn_fq2_mul(&XY, &X, &Y);
    struct bn_fq2 A;
    bn_fq2_mul(&A, &two_inv, &XY);

    struct bn_fq2 B; bn_fq2_sq(&B, &Y);
    struct bn_fq2 C; bn_fq2_sq(&C, &Z);
    struct bn_fq2 D;
    bn_fq2_add(&D, &C, &C);
    bn_fq2_add(&D, &D, &C); /* D = 3C */

    /* E = twist_coeff_b * D = (3/xi)*D, but twist_coeff_b = b * inv(xi) = 3 * inv(9+u)
     * We can compute: E = (3/(9+u)) * D. Precompute twist_coeff_b. */
    struct bn_fq2 xi, three_fq2, twist_b, E;
    bn_fq_from_u64(&xi.c0, 9);
    bn_fq_one(&xi.c1);
    bn_fq2_inv(&twist_b, &xi);
    bn_fq_from_u64(&three_fq2.c0, 3);
    bn_fq_zero(&three_fq2.c1);
    bn_fq2_mul(&twist_b, &twist_b, &three_fq2);
    bn_fq2_mul(&E, &twist_b, &D);

    struct bn_fq2 F;
    bn_fq2_add(&F, &E, &E);
    bn_fq2_add(&F, &F, &E); /* F = 3E */

    struct bn_fq2 BpF;
    bn_fq2_add(&BpF, &B, &F);
    struct bn_fq2 G;
    bn_fq2_mul(&G, &two_inv, &BpF); /* G = (B+F)/2 */

    struct bn_fq2 YpZ, BpC, H;
    bn_fq2_add(&YpZ, &Y, &Z);
    bn_fq2_sq(&YpZ, &YpZ);
    bn_fq2_add(&BpC, &B, &C);
    bn_fq2_sub(&H, &YpZ, &BpC); /* H = (Y+Z)^2 - (B+C) */

    struct bn_fq2 I;
    bn_fq2_sub(&I, &E, &B); /* I = E - B */

    struct bn_fq2 J;
    bn_fq2_sq(&J, &X); /* J = X^2 */

    struct bn_fq2 E_sq;
    bn_fq2_sq(&E_sq, &E);

    /* Update current point */
    struct bn_fq2 BmF;
    bn_fq2_sub(&BmF, &B, &F);
    bn_fq2_mul(&current->x, &A, &BmF); /* X3 = A*(B-F) */

    struct bn_fq2 Gsq, three_Esq;
    bn_fq2_sq(&Gsq, &G);
    bn_fq2_add(&three_Esq, &E_sq, &E_sq);
    bn_fq2_add(&three_Esq, &three_Esq, &E_sq);
    bn_fq2_sub(&current->y, &Gsq, &three_Esq); /* Y3 = G^2 - 3*E^2 */

    bn_fq2_mul(&current->z, &B, &H); /* Z3 = B*H */

    /* Line function coefficients:
     * ell_0 = xi * I  (goes to z0 = c0.c0)
     * ell_VW = -H     (later scaled by yP, goes to z2 = c0.c2)
     * ell_VV = 3*J    (later scaled by xP, goes to z4 = c1.c1) */
    bn_fq2_mul_by_nonresidue(ell_0, &I); /* xi * I (mul_by_nonresidue IS xi*) */
    bn_fq2_neg(ell_VW, &H);
    bn_fq2_add(ell_VV, &J, &J);
    bn_fq2_add(ell_VV, ell_VV, &J); /* 3*J */
}

/* Mixed addition step — direct port from libsnark.
 * base is affine (on twist), current is Jacobian. */
static void mixed_addition_step(const struct bn_fq2 *base_x,
                                const struct bn_fq2 *base_y,
                                struct bn_g2 *current,
                                struct bn_fq2 *ell_0,
                                struct bn_fq2 *ell_VW,
                                struct bn_fq2 *ell_VV)
{
    struct bn_fq2 X1 = current->x, Y1 = current->y, Z1 = current->z;
    const struct bn_fq2 *x2 = base_x, *y2 = base_y;

    struct bn_fq2 D, E, F, G, H, I, J;
    struct bn_fq2 x2Z1;
    bn_fq2_mul(&x2Z1, x2, &Z1);
    bn_fq2_sub(&D, &X1, &x2Z1); /* D = X1 - x2*Z1 */

    struct bn_fq2 y2Z1;
    bn_fq2_mul(&y2Z1, y2, &Z1);
    bn_fq2_sub(&E, &Y1, &y2Z1); /* E = Y1 - y2*Z1 */

    bn_fq2_sq(&F, &D);          /* F = D^2 */
    bn_fq2_sq(&G, &E);          /* G = E^2 */
    bn_fq2_mul(&H, &D, &F);     /* H = D*F */

    bn_fq2_mul(&I, &X1, &F);    /* I = X1*F */

    struct bn_fq2 Z1G, twoI;
    bn_fq2_mul(&Z1G, &Z1, &G);
    bn_fq2_add(&twoI, &I, &I);
    bn_fq2_add(&J, &H, &Z1G);
    bn_fq2_sub(&J, &J, &twoI);  /* J = H + Z1*G - 2*I */

    bn_fq2_mul(&current->x, &D, &J); /* X3 = D*J */

    struct bn_fq2 ImJ, HY1;
    bn_fq2_sub(&ImJ, &I, &J);
    bn_fq2_mul(&ImJ, &E, &ImJ);
    bn_fq2_mul(&HY1, &H, &Y1);
    bn_fq2_sub(&current->y, &ImJ, &HY1); /* Y3 = E*(I-J) - H*Y1 */

    bn_fq2_mul(&current->z, &Z1, &H); /* Z3 = Z1*H */

    /* Line function coefficients */
    struct bn_fq2 Ex2, Dy2, t;
    bn_fq2_mul(&Ex2, &E, x2);
    bn_fq2_mul(&Dy2, &D, y2);
    bn_fq2_sub(&t, &Ex2, &Dy2);
    bn_fq2_mul_by_nonresidue(ell_0, &t); /* ell_0 = xi * (E*x2 - D*y2) */

    bn_fq2_neg(ell_VV, &E);              /* ell_VV = -E (later * xP) */
    *ell_VW = D;                          /* ell_VW = D  (later * yP) */
}

/* Line function double: f = f² · line, update T. */
static void line_func_double(struct bn_fq12 *f,
                              struct bn_g2 *t,
                              const struct bn_fq *px_a, const struct bn_fq *py_a)
{
    struct bn_fq2 ell_0, ell_VW, ell_VV;
    doubling_step(t, &ell_0, &ell_VW, &ell_VV);

    /* Scale by P: ell_VW *= yP, ell_VV *= xP */
    struct bn_fq2 scaled_VW, scaled_VV;
    bn_fq_mul(&scaled_VW.c0, &ell_VW.c0, py_a);
    bn_fq_mul(&scaled_VW.c1, &ell_VW.c1, py_a);
    bn_fq_mul(&scaled_VV.c0, &ell_VV.c0, px_a);
    bn_fq_mul(&scaled_VV.c1, &ell_VV.c1, px_a);

    struct bn_fq12 fsq;
    bn_fq12_sq(&fsq, f);
    *f = fsq;
    bn_fq12_mul_by_024(f, &ell_0, &scaled_VW, &scaled_VV);
}

/* Line function add: f *= line, update T. */
static void line_func_add(struct bn_fq12 *f,
                           struct bn_g2 *t,
                           const struct bn_fq2 *qx, const struct bn_fq2 *qy,
                           const struct bn_fq *px_a, const struct bn_fq *py_a)
{
    struct bn_fq2 ell_0, ell_VW, ell_VV;
    mixed_addition_step(qx, qy, t, &ell_0, &ell_VW, &ell_VV);

    struct bn_fq2 scaled_VW, scaled_VV;
    bn_fq_mul(&scaled_VW.c0, &ell_VW.c0, py_a);
    bn_fq_mul(&scaled_VW.c1, &ell_VW.c1, py_a);
    bn_fq_mul(&scaled_VV.c0, &ell_VV.c0, px_a);
    bn_fq_mul(&scaled_VV.c1, &ell_VV.c1, px_a);

    bn_fq12_mul_by_024(f, &ell_0, &scaled_VW, &scaled_VV);
}

/* exp_by_neg_z: compute elt^{-z} where z = 4965661367192848881.
 * Since z is positive (alt_bn128_final_exponent_is_z_neg = false),
 * this computes elt^z then takes conjugate (unitary inverse). */
static void bn_fq12_exp_by_neg_z(struct bn_fq12 *r, const struct bn_fq12 *f)
{
    const uint64_t z = 4965661367192848881ULL;
    struct bn_fq12 acc;
    bn_fq12_one(&acc);
    struct bn_fq12 base = *f;
    for (int i = 62; i >= 0; i--) {
        bn_fq12_sq(&acc, &acc);
        if ((z >> i) & 1)
            bn_fq12_mul(&acc, &acc, &base);
    }
    /* z is positive, so negate: unitary_inverse = conjugation */
    bn_fq12_conjugate(&acc);
    *r = acc;
}

/* BN-254 final exponentiation: f^{(p^12-1)/r}
 * Split as: easy_part * hard_part
 *   easy = (p^6 - 1)(p^2 + 1)
 *   hard = (p^4 - p^2 + 1)/r
 *
 * Hard part uses the BN u-chain + Frobenius decomposition from
 * "High-Speed Software Implementation of the Optimal Ate Pairing
 *  over Barreto-Naehrig Curves" (Beuchat et al., 2010) and
 * go-ethereum's bn256 implementation. */
static void bn254_final_exp(struct bn_fq12 *f)
{
    bn254_init_frobenius();

    /* ── Easy part step 1: f^{p^6 - 1} ──
     * f^{p^6} = conjugate(f) since Fq12 = Fq6[w]/(w^2-v) */
    struct bn_fq12 t0, t1;
    t0 = *f;
    bn_fq12_conjugate(&t0);         /* t0 = f^{p^6} = conj(f) */
    bn_fq12_inv(&t1, f);            /* t1 = f^{-1} */
    bn_fq12_mul(f, &t0, &t1);       /* f = f^{p^6 - 1} */

    /* ── Easy part step 2: f^{p^2 + 1} ── */
    bn_fq12_frobenius_map(&t0, f, 2);  /* t0 = f^{p^2} */
    bn_fq12_mul(f, &t0, f);             /* f = f^{p^2 + 1} */

    /* Now f = original_f^{(p^6-1)(p^2+1)}, in the cyclotomic subgroup. */

    /* ── Hard part: Fuentes-Castaneda et al. formula (from libsnark) ──
     * Computes elt^(2z(6z²+3z+1)(q⁴-q²+1)/r) using exp_by_neg_z. */
    struct bn_fq12 A, B, C, D, E, F2, G;
    struct bn_fq12 H, I, J, K, L, M, N, O, P, Q, R, S, T, U;

    bn_fq12_exp_by_neg_z(&A, f);       /* A = f^{-z} */
    bn_fq12_sq(&B, &A);                /* B = A² = f^{-2z} */
    bn_fq12_sq(&C, &B);                /* C = B² = f^{-4z} */
    bn_fq12_mul(&D, &C, &B);           /* D = C*B = f^{-6z} */
    bn_fq12_exp_by_neg_z(&E, &D);      /* E = D^{-z} = f^{6z²} */
    bn_fq12_sq(&F2, &E);               /* F = E² = f^{12z²} */
    bn_fq12_exp_by_neg_z(&G, &F2);     /* G = F^{-z} = f^{-12z³} */
    H = D; bn_fq12_conjugate(&H);      /* H = conj(D) = f^{6z} */
    I = G; bn_fq12_conjugate(&I);      /* I = conj(G) = f^{12z³} */
    bn_fq12_mul(&J, &I, &E);           /* J = I*E = f^{12z³+6z²} */
    bn_fq12_mul(&K, &J, &H);           /* K = J*H = f^{12z³+6z²+6z} */
    bn_fq12_mul(&L, &K, &B);           /* L = K*B = f^{12z³+6z²+4z} */
    bn_fq12_mul(&M, &K, &E);           /* M = K*E = f^{12z³+12z²+6z} */
    bn_fq12_mul(&N, &M, f);            /* N = M*f = f^{12z³+12z²+6z+1} */
    bn_fq12_frobenius_map(&O, &L, 1);  /* O = L^{p} */
    bn_fq12_mul(&P, &O, &N);           /* P = O*N */
    bn_fq12_frobenius_map(&Q, &K, 2);  /* Q = K^{p²} */
    bn_fq12_mul(&R, &Q, &P);           /* R = Q*P */
    S = *f; bn_fq12_conjugate(&S);     /* S = conj(f) = f^{-1} */
    bn_fq12_mul(&T, &S, &L);           /* T = S*L = f^{12z³+6z²+4z-1} */
    bn_fq12_frobenius_map(&U, &T, 3);  /* U = T^{p³} */
    bn_fq12_mul(f, &U, &R);            /* result = U*R */
}

/* Forward declaration — defined below after multi_pairing_check */
static void bn254_miller_loop(struct bn_fq12 *result,
                              const struct bn_g1 *p,
                              const struct bn_g2 *q);

void bn254_pairing(struct bn_fq12 *result,
                   const struct bn_g1 *p,
                   const struct bn_g2 *q)
{
    bn254_miller_loop(result, p, q);
    bn254_final_exp(result);
}

/* Compute Q.mul_by_q() — Frobenius on twist curve G2.
 * Maps (X, Y, Z) → (twist_mul_by_q_X * conj(X), twist_mul_by_q_Y * conj(Y), conj(Z))
 * Returns result in affine (Z=1). Input must be affine. */
static void g2_mul_by_q(struct bn_fq2 *rx, struct bn_fq2 *ry,
                         const struct bn_fq2 *qx, const struct bn_fq2 *qy)
{
    bn254_init_frobenius();
    /* Frobenius on Fq2 is conjugation */
    struct bn_fq2 cx, cy;
    bn_fq2_conj(&cx, qx);
    bn_fq2_conj(&cy, qy);
    /* Multiply by twist constants from libsnark alt_bn128_init.cpp */
    bn_fq2_mul(rx, &g_frob.twist_frob_x, &cx);
    bn_fq2_mul(ry, &g_frob.twist_frob_y, &cy);
}

/* Miller loop only (no final exponentiation) — for multi-pairing optimization.
 * Direct port of libsnark alt_bn128_ate_miller_loop. */
static void bn254_miller_loop(struct bn_fq12 *result,
                              const struct bn_g1 *p,
                              const struct bn_g2 *q)
{
    if (bn_g1_is_identity(p) || bn_g2_is_identity(q)) {
        bn_fq12_one(result);
        return;
    }

    struct bn_fq px_a, py_a;
    bn_g1_to_affine(&px_a, &py_a, p);

    struct bn_fq2 qx_a, qy_a;
    bn_g2_to_affine(&qx_a, &qy_a, q);

    /* R starts as Q in Jacobian */
    struct bn_g2 R;
    R.x = qx_a;
    R.y = qy_a;
    bn_fq2_one(&R.z);

    bn_fq12_one(result);

    /* Miller loop: MSB-to-LSB scan of ate_loop_count, skip leading 1 */
    bool found_one = false;
    for (int i = ATE_LOOP_BITS - 1; i >= 0; i--) {
        int bit_idx = i / 64;
        int bit_pos = i % 64;
        bool bit = (bit_idx < 2) && ((ATE_LOOP[bit_idx] >> bit_pos) & 1);

        if (!found_one) {
            found_one = bit;
            continue;
        }

        line_func_double(result, &R, &px_a, &py_a);
        if (bit)
            line_func_add(result, &R, &qx_a, &qy_a, &px_a, &py_a);
    }

    if (ATE_LOOP_NEG)
        bn_fq12_conjugate(result);

    /* Frobenius correction: Q1 = Q.mul_by_q(), Q2 = Q1.mul_by_q() with Q2.Y negated */
    struct bn_fq2 q1x, q1y;
    g2_mul_by_q(&q1x, &q1y, &qx_a, &qy_a);

    struct bn_fq2 q2x, q2y;
    g2_mul_by_q(&q2x, &q2y, &q1x, &q1y);
    bn_fq2_neg(&q2y, &q2y); /* Q2.Y = -Q2.Y */

    line_func_add(result, &R, &q1x, &q1y, &px_a, &py_a);
    line_func_add(result, &R, &q2x, &q2y, &px_a, &py_a);
}

/* Multi-pairing check: product of pairings == 1 in GT.
 * Computes product of Miller loops, then single final exponentiation.
 * This is both faster and more correct than separate pairings. */
bool bn254_multi_pairing_check(
    const struct bn_g1 *a_pts, const struct bn_g2 *b_pts,
    size_t n_pairs)
{
    struct bn_fq12 acc;
    bn_fq12_one(&acc);

    for (size_t i = 0; i < n_pairs; i++) {
        struct bn_fq12 ml;
        bn254_miller_loop(&ml, &a_pts[i], &b_pts[i]);
        bn_fq12_mul(&acc, &acc, &ml);
    }

    bn254_final_exp(&acc);

    struct bn_fq12 one;
    bn_fq12_one(&one);
    return bn_fq12_eq(&acc, &one);
}

/* ══════════════════════════════════════════════════════════════
 *  PPZKSNARK (PHGR13) Proof Verification
 * ══════════════════════════════════════════════════════════════ */

bool ppzksnark_proof_read(struct ppzksnark_proof *proof, const uint8_t data[296])
{
    size_t off = 0;
    /* 8 elements: g_A(33), g_A'(33), g_B(65), g_B'(33), g_C(33), g_C'(33), g_K(33), g_H(33) */
    if (!bn_g1_decompress(&proof->a, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_A) failed");
    off += 33;
    if (!bn_g1_decompress(&proof->a_prime, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_A') failed");
    off += 33;
    if (!bn_g2_decompress(&proof->b, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g2_decompress(g_B) failed");
    off += 65;
    if (!bn_g1_decompress(&proof->b_prime, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_B') failed");
    off += 33;
    if (!bn_g1_decompress(&proof->c, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_C) failed");
    off += 33;
    if (!bn_g1_decompress(&proof->c_prime, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_C') failed");
    off += 33;
    if (!bn_g1_decompress(&proof->k, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_K) failed");
    off += 33;
    if (!bn_g1_decompress(&proof->h, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_H) failed");
    off += 33;
    return (off == 296);
}

/* ── libsnark VK file parser ───────────────────────────────────
 *
 * The sprout-verifying.key file is in libsnark's native binary format,
 * NOT the flat big-endian concat the previous code assumed. The format:
 *
 *   - Fp values: 32 bytes, Montgomery-form limbs in native (LE) byte order
 *   - G1 points: X(Fp:32) + Y(Fp:32) = 64 bytes (affine, uncompressed)
 *   - G2 points: X.c0(32) + X.c1(32) + Y.c0(32) + Y.c1(32) = 128 bytes
 *   - '\n' (0x0A) separator between top-level VK fields
 *   - accumulation_vector: first(G1) + '\n' + sparse_vector + '\n'
 *   - sparse_vector: domain_size(decimal text + '\n') + count(decimal + '\n')
 *     + count indices (each decimal + '\n') + count G1 values (each binary + '\n')
 *
 * Total for ZCash PHGR13 (ic_len=10): 1449 bytes.
 *
 */

/* Read one Fp value from libsnark BINARY_OUTPUT format.
 * 32 bytes, 4 × uint64_t in LE byte order, Montgomery form.
 * Goes directly into bn_fq.d[] since our internal format is also Montgomery. */
static bool vk_read_fq_mont_le(struct bn_fq *r, const uint8_t *data,
                                 size_t len, size_t *off)
{
    if (*off + 32 > len) return false;
    for (int i = 0; i < 4; i++) {
        r->d[i] = 0;
        for (int j = 0; j < 8; j++)
            r->d[i] |= (uint64_t)data[*off + i * 8 + j] << (j * 8);
    }
    *off += 32;
    return true;
}

/* Read a decimal-encoded integer followed by '\n'.
 * In libsnark's sparse_vector, domain_size/count/indices are written via
 * `out << val << "\n"` (hardcoded newline, not OUTPUT_NEWLINE), so they
 * are always text even in BINARY_OUTPUT mode. */
static bool vk_read_text_int(uint64_t *out, const uint8_t *data,
                               size_t len, size_t *off)
{
    uint64_t val = 0;
    bool any = false;
    while (*off < len && data[*off] >= '0' && data[*off] <= '9') {
        val = val * 10 + (data[*off] - '0');
        (*off)++;
        any = true;
    }
    if (!any) return false;
    if (*off < len && data[*off] == '\n') (*off)++;
    *out = val;
    return true;
}

/* Read a G1 affine point in libsnark BINARY_OUTPUT + NO_PT_COMPRESSION format.
 * Layout: is_zero('0'/'1', 1 byte) + X(Fp, 32) + Y(Fp, 32) = 65 bytes.
 * OUTPUT_SEPARATOR = "" between fields (BINARY_OUTPUT mode). */
static bool vk_read_g1_libsnark(struct bn_g1 *pt, const uint8_t *data,
                                  size_t len, size_t *off)
{
    if (*off >= len) return false;
    uint8_t is_zero = data[*off] - '0';
    (*off)++;
    if (is_zero == 1) {
        /* Point at infinity */
        bn_fq_zero(&pt->x);
        bn_fq_zero(&pt->y);
        bn_fq_zero(&pt->z);
        /* Still consume 64 bytes of X,Y even for zero point */
        if (*off + 64 > len) return false;
        *off += 64;
        return true;
    }
    if (!vk_read_fq_mont_le(&pt->x, data, len, off)) return false;
    if (!vk_read_fq_mont_le(&pt->y, data, len, off)) return false;
    bn_fq_one(&pt->z);
    return true;
}

/* Read a G2 affine point in libsnark BINARY_OUTPUT + NO_PT_COMPRESSION format.
 * Layout: is_zero('0'/'1', 1 byte) + X(Fp2=c0+c1, 64) + Y(Fp2, 64) = 129 bytes.
 * Fp2 component order: c0 first, c1 second. */
static bool vk_read_g2_libsnark(struct bn_g2 *pt, const uint8_t *data,
                                  size_t len, size_t *off)
{
    if (*off >= len) return false;
    uint8_t is_zero = data[*off] - '0';
    (*off)++;
    if (is_zero == 1) {
        bn_fq_zero(&pt->x.c0); bn_fq_zero(&pt->x.c1);
        bn_fq_zero(&pt->y.c0); bn_fq_zero(&pt->y.c1);
        bn_fq_zero(&pt->z.c0); bn_fq_zero(&pt->z.c1);
        if (*off + 128 > len) return false;
        *off += 128;
        return true;
    }
    if (!vk_read_fq_mont_le(&pt->x.c0, data, len, off)) return false;
    if (!vk_read_fq_mont_le(&pt->x.c1, data, len, off)) return false;
    if (!vk_read_fq_mont_le(&pt->y.c0, data, len, off)) return false;
    if (!vk_read_fq_mont_le(&pt->y.c1, data, len, off)) return false;
    bn_fq2_one(&pt->z);
    return true;
}

/* Read the seven fixed VK curve points and the accumulation vector's first G1.
 * Returns 0 on success and -1 on failure. */
static int vk_read_libsnark_header(struct bn_g2 *alpha_a_g2,
                                   struct bn_g1 *alpha_b_g1,
                                   struct bn_g2 *alpha_c_g2,
                                   struct bn_g2 *gamma_g2,
                                   struct bn_g1 *gamma_beta_g1,
                                   struct bn_g2 *gamma_beta_g2,
                                   struct bn_g2 *rc_z_g2,
                                   struct bn_g1 *first,
                                   const uint8_t *data, size_t len,
                                   size_t *off)
{
    memset(alpha_a_g2, 0, sizeof(*alpha_a_g2));
    memset(alpha_b_g1, 0, sizeof(*alpha_b_g1));
    memset(alpha_c_g2, 0, sizeof(*alpha_c_g2));
    memset(gamma_g2, 0, sizeof(*gamma_g2));
    memset(gamma_beta_g1, 0, sizeof(*gamma_beta_g1));
    memset(gamma_beta_g2, 0, sizeof(*gamma_beta_g2));
    memset(rc_z_g2, 0, sizeof(*rc_z_g2));
    memset(first, 0, sizeof(*first));

    /* 7 VK fields — no separators (BINARY_OUTPUT) */
    if (!vk_read_g2_libsnark(alpha_a_g2, data, len, off)) return -1;
    if (!vk_read_g1_libsnark(alpha_b_g1, data, len, off)) return -1;
    if (!vk_read_g2_libsnark(alpha_c_g2, data, len, off)) return -1;
    if (!vk_read_g2_libsnark(gamma_g2, data, len, off)) return -1;
    if (!vk_read_g1_libsnark(gamma_beta_g1, data, len, off)) return -1;
    if (!vk_read_g2_libsnark(gamma_beta_g2, data, len, off)) return -1;
    if (!vk_read_g2_libsnark(rc_z_g2, data, len, off)) return -1;

    /* accumulation_vector<G1>: first(G1) + rest(sparse_vector) */
    if (!vk_read_g1_libsnark(first, data, len, off)) return -1;
    return 0;
}

/* Read domain_size, the index count, and the index list.
 * Returns 0 on success and -1 on failure. On failure *indices_out is NULL. */
static int vk_read_sparse_vector_indices(uint64_t *domain_size,
                                         uint64_t *idx_count,
                                         uint64_t **indices_out,
                                         const uint8_t *data, size_t len,
                                         size_t *off)
{
    *domain_size = 0;
    *idx_count = 0;
    *indices_out = NULL;

    if (!vk_read_text_int(domain_size, data, len, off)) return -1;
    if (!vk_read_text_int(idx_count, data, len, off)) return -1;
    if (*idx_count > 1000 || *idx_count > *domain_size) return -1;

    uint64_t *indices = zcl_calloc(*idx_count, sizeof(uint64_t), "phgr_vk_indices");
    if (!indices && *idx_count > 0) return -1;
    for (uint64_t i = 0; i < *idx_count; i++) {
        if (!vk_read_text_int(&indices[i], data, len, off)) {
            free(indices); return -1;
        }
    }
    *indices_out = indices;
    return 0;
}

/* Read values_count, set ic[0] to first, and place each G1 at ic[index + 1].
 * Frees indices. Returns 0 on success and -1 on failure. */
static int vk_read_sparse_vector_values(struct bn_g1 **ic_out,
                                        size_t *ic_len_out,
                                        const struct bn_g1 *first,
                                        uint64_t *indices,
                                        uint64_t domain_size,
                                        uint64_t idx_count,
                                        const uint8_t *data, size_t len,
                                        size_t *off)
{
    *ic_out = NULL;
    *ic_len_out = 0;

    /* values_count (same as idx_count for a well-formed sparse_vector) */
    uint64_t val_count;
    if (!vk_read_text_int(&val_count, data, len, off)) {
        free(indices); return -1;
    }
    if (val_count != idx_count) { free(indices); return -1; }

    /* Allocate IC: first + domain_size entries */
    uint32_t ic_len = (uint32_t)(domain_size + 1);
    *ic_out = zcl_calloc(ic_len, sizeof(struct bn_g1), "phgr_vk_ic");
    if (!*ic_out) { free(indices); return -1; }
    *ic_len_out = ic_len;
    struct bn_g1 *ic = *ic_out;
    ic[0] = *first;

    /* Read G1 values in order, placed at indices[i]+1 in ic[] */
    for (uint64_t i = 0; i < val_count; i++) {
        uint64_t idx = indices[i];
        if (idx + 1 >= ic_len) {
            free(indices); free(ic); *ic_out = NULL; return -1;
        }
        if (!vk_read_g1_libsnark(&ic[idx + 1], data, len, off)) {
            free(indices); free(ic); *ic_out = NULL; return -1;
        }
    }

    free(indices);
    return 0;
}

/* Parse sprout-verifying.key in libsnark BINARY_OUTPUT + NO_PT_COMPRESSION format.
 *
 * The zcash fork of libsnark uses -DBINARY_OUTPUT -DNO_PT_COMPRESSION:
 *   OUTPUT_NEWLINE = ""  (no separators between VK fields)
 *   OUTPUT_SEPARATOR = "" (no separators within fields)
 *   NO_PT_COMPRESSION:   affine (X, Y) for each point
 *   is_zero flag:         1-byte text ('0' or '1') before each point
 *
 * Layout: 7 curve points (G1=65 bytes, G2=129 bytes), concatenated,
 * followed by an accumulation_vector<G1>. The accumulation_vector has
 * a "first" G1 point then a sparse_vector<G1> whose integer fields
 * (domain_size, counts, indices) use hardcoded "\n" separators (not
 * OUTPUT_NEWLINE), so they're always text-encoded even in binary mode.
 *
 * Verified against the real 1449-byte sprout-verifying.key file:
 *   5×129 + 2×65 = 775 (VK points)
 *   + 65 (IC first) + 24 (text) + 9×65 (IC values) = 1449.
 *
 * Returns true on success. On failure, vk is zeroed. */
bool ppzksnark_vk_read(struct ppzksnark_vk *vk, const uint8_t *data, size_t len)
{
    memset(vk, 0, sizeof(*vk));
    size_t off = 0;

    struct bn_g1 first;
    if (vk_read_libsnark_header(&vk->alpha_a_g2, &vk->alpha_b_g1,
                                &vk->alpha_c_g2, &vk->gamma_g2,
                                &vk->gamma_beta_g1, &vk->gamma_beta_g2,
                                &vk->rc_z_g2, &first,
                                data, len, &off) != 0)
        return false;

    /* sparse_vector text fields: domain_size, indices_count, indices[],
     * values_count, then binary G1 values. */
    uint64_t domain_size = 0;
    uint64_t idx_count = 0;
    uint64_t *indices = NULL;
    if (vk_read_sparse_vector_indices(&domain_size, &idx_count, &indices,
                                      data, len, &off) != 0)
        return false;

    if (vk_read_sparse_vector_values(&vk->ic, &vk->ic_len, &first, indices,
                                     domain_size, idx_count, data, len, &off) != 0)
        return false;

    return true;
}

void ppzksnark_vk_free(struct ppzksnark_vk *vk)
{
    free(vk->ic);
    vk->ic = NULL;
    vk->ic_len = 0;
}

/* The canonical alt_bn128 (BN254) G2 generator = libsnark G2::one(), the
 * "G2_one" every PHGR13/BCTV14 pairing check pairs against. SINGLE SOURCE OF
 * TRUTH — bn254.c's verifier and the tests both build it here, so the constant
 * cannot drift independently. A corrupt generator silently false-rejects every
 * Sprout proof, so both verifier and tests must construct it from this one
 * place. The bytes are the canonical big-endian encodings,
 * independently verified on-curve:
 *   x = (10857046999023057135944570762232829481370756359578518086990519993285655852781,
 *        11559732032986387107991004021392285783925812861821192530917403151452391805634)
 *   y = (8495653923123431417604973247489272438418190587263600148770280649306958101930,
 *        4082367875863433681332203403145435568316851327593401208105741076214120093531)
 * bn_fq_from_bytes_be range-checks < q and converts to Montgomery. */
void bn254_g2_one(struct bn_g2 *out)
{
    static const uint8_t g2_x_c0[32] = {
        0x18,0x00,0xde,0xef,0x12,0x1f,0x1e,0x76,0x42,0x6a,0x00,0x66,0x5e,0x5c,0x44,0x79,
        0x67,0x43,0x22,0xd4,0xf7,0x5e,0xda,0xdd,0x46,0xde,0xbd,0x5c,0xd9,0x92,0xf6,0xed
    };
    static const uint8_t g2_x_c1[32] = {
        0x19,0x8e,0x93,0x93,0x92,0x0d,0x48,0x3a,0x72,0x60,0xbf,0xb7,0x31,0xfb,0x5d,0x25,
        0xf1,0xaa,0x49,0x33,0x35,0xa9,0xe7,0x12,0x97,0xe4,0x85,0xb7,0xae,0xf3,0x12,0xc2
    };
    static const uint8_t g2_y_c0[32] = {
        0x12,0xc8,0x5e,0xa5,0xdb,0x8c,0x6d,0xeb,0x4a,0xab,0x71,0x80,0x8d,0xcb,0x40,0x8f,
        0xe3,0xd1,0xe7,0x69,0x0c,0x43,0xd3,0x7b,0x4c,0xe6,0xcc,0x01,0x66,0xfa,0x7d,0xaa
    };
    static const uint8_t g2_y_c1[32] = {
        0x09,0x06,0x89,0xd0,0x58,0x5f,0xf0,0x75,0xec,0x9e,0x99,0xad,0x69,0x0c,0x33,0x95,
        0xbc,0x4b,0x31,0x33,0x70,0xb3,0x8e,0xf3,0x55,0xac,0xda,0xdc,0xd1,0x22,0x97,0x5b
    };
    bn_fq_from_bytes_be(&out->x.c0, g2_x_c0);
    bn_fq_from_bytes_be(&out->x.c1, g2_x_c1);
    bn_fq_from_bytes_be(&out->y.c0, g2_y_c0);
    bn_fq_from_bytes_be(&out->y.c1, g2_y_c1);
    bn_fq2_one(&out->z);
}

/* True iff the affine G2 point (z assumed normalized to 1) lies on the BN254
 * twist curve y^2 = x^3 + b', with b' = 3/(9+u). Used to guard the hardcoded
 * G2 generator ("G2_one") against constant corruption — a bad G2_one silently
 * false-rejects every pairing check. */
bool bn_g2_is_on_curve(const struct bn_g2 *p)
{
    struct bn_fq2 y2, x2, x3, xi, twist_b, three, rhs;
    bn_fq2_mul(&y2, &p->y, &p->y);
    bn_fq2_mul(&x2, &p->x, &p->x);
    bn_fq2_mul(&x3, &x2, &p->x);
    bn_fq_from_u64(&xi.c0, 9);
    bn_fq_one(&xi.c1);
    bn_fq2_inv(&twist_b, &xi);
    bn_fq_from_u64(&three.c0, 3);
    bn_fq_zero(&three.c1);
    bn_fq2_mul(&twist_b, &twist_b, &three);
    bn_fq2_add(&rhs, &x3, &twist_b);
    return bn_fq2_eq(&y2, &rhs);
}

/* PPZKSNARK verification: 5 pairing checks.
 *
 * 1. Knowledge of A:  e(g_A, alpha_A) == e(g_A', G2_one)
 * 2. Knowledge of B:  e(alpha_B, g_B) == e(g_B', G2_one)
 * 3. Knowledge of C:  e(g_C, alpha_C) == e(g_C', G2_one)
 * 4. QAP divisibility: e(g_A + acc, g_B) == e(g_H, rC_Z) * e(g_C, G2_one)
 * 5. Consistency:      e(g_K, gamma) == e(g_A+acc+g_C, gamma_beta_g2) * e(gamma_beta_g1, g_B)
 *
 * Each check can be written as: product of pairings == 1
 * by moving all terms to one side. */
bool ppzksnark_verify(const struct ppzksnark_vk *vk,
                      const struct ppzksnark_proof *proof,
                      const uint64_t (*public_inputs)[4],
                      size_t n_inputs)
{
    if (!vk)
        LOG_FAIL("phgr13", "verify: vk is NULL (params never loaded)");
    if (!proof)
        LOG_FAIL("phgr13", "verify: proof is NULL");
    if (n_inputs != vk->ic_len - 1)
        LOG_FAIL("phgr13",
                 "verify: public input count mismatch: n_inputs=%zu ic_len=%zu (want %zu)",
                 n_inputs, vk->ic_len, vk->ic_len - 1);

    /* Compute accumulator: acc = ic[0] + sum(input[i] * ic[i+1]) */
    struct bn_g1 acc = vk->ic[0];
    for (size_t i = 0; i < n_inputs; i++) {
        struct bn_g1 term;
        bn_g1_scalar_mul(&term, &vk->ic[i+1], public_inputs[i]);
        bn_g1_add(&acc, &acc, &term);
    }

    /* G2 generator ("G2_one" in the pairing checks). Single source of truth
     * (bn254_g2_one) shared with the tests so the constant can never silently
     * drift — a corrupt generator false-rejects every Sprout PHGR13 proof at
     * pairing check 1, and this verifier is also on the consensus path. The
     * on-curve guard makes any future drift fail LOUD. */
    struct bn_g2 g2_gen;
    bn254_g2_one(&g2_gen);
    if (!bn_g2_is_on_curve(&g2_gen)) {
        LOG_FAIL("phgr13", "verify: G2 generator off-curve — refusing "
                 "(corrupt g2_gen constant; would false-reject all proofs)");
        return false;
    }

    /* Check 1: Knowledge of A
     * e(g_A, alpha_A) * e(-g_A', G2_one) == 1 */
    {
        struct bn_g1 neg_ap;
        bn_g1_neg(&neg_ap, &proof->a_prime);
        struct bn_g1 pts1[2] = { proof->a, neg_ap };
        struct bn_g2 pts2[2] = { vk->alpha_a_g2, g2_gen };
        if (!bn254_multi_pairing_check(pts1, pts2, 2))
            LOG_FAIL("phgr13", "verify: check 1 (knowledge of A) pairing rejected");
    }

    /* Check 2: Knowledge of B
     * e(alpha_B, g_B) * e(-g_B', G2_one) == 1 */
    {
        struct bn_g1 neg_bp;
        bn_g1_neg(&neg_bp, &proof->b_prime);
        struct bn_g1 pts1[2] = { vk->alpha_b_g1, neg_bp };
        struct bn_g2 pts2[2] = { proof->b, g2_gen };
        if (!bn254_multi_pairing_check(pts1, pts2, 2))
            LOG_FAIL("phgr13", "verify: check 2 (knowledge of B) pairing rejected");
    }

    /* Check 3: Knowledge of C
     * e(g_C, alpha_C) * e(-g_C', G2_one) == 1 */
    {
        struct bn_g1 neg_cp;
        bn_g1_neg(&neg_cp, &proof->c_prime);
        struct bn_g1 pts1[2] = { proof->c, neg_cp };
        struct bn_g2 pts2[2] = { vk->alpha_c_g2, g2_gen };
        if (!bn254_multi_pairing_check(pts1, pts2, 2))
            LOG_FAIL("phgr13", "verify: check 3 (knowledge of C) pairing rejected");
    }

    /* Check 4: QAP divisibility
     * e(g_A + acc, g_B) * e(-g_H, rC_Z) * e(-g_C, G2_one) == 1 */
    {
        struct bn_g1 a_acc;
        bn_g1_add(&a_acc, &proof->a, &acc);
        struct bn_g1 neg_h, neg_c;
        bn_g1_neg(&neg_h, &proof->h);
        bn_g1_neg(&neg_c, &proof->c);
        struct bn_g1 pts1[3] = { a_acc, neg_h, neg_c };
        struct bn_g2 pts2[3] = { proof->b, vk->rc_z_g2, g2_gen };
        if (!bn254_multi_pairing_check(pts1, pts2, 3))
            LOG_FAIL("phgr13", "verify: check 4 (QAP divisibility) pairing rejected");
    }

    /* Check 5: Consistency
     * e(g_K, gamma) * e(-(g_A+acc+g_C), gamma_beta_g2) * e(-gamma_beta_g1, g_B) == 1 */
    {
        struct bn_g1 a_acc_c;
        bn_g1_add(&a_acc_c, &proof->a, &acc);
        bn_g1_add(&a_acc_c, &a_acc_c, &proof->c);
        struct bn_g1 neg_aac, neg_gb1;
        bn_g1_neg(&neg_aac, &a_acc_c);
        bn_g1_neg(&neg_gb1, &vk->gamma_beta_g1);
        struct bn_g1 pts1[3] = { proof->k, neg_aac, neg_gb1 };
        struct bn_g2 pts2[3] = { vk->gamma_g2, vk->gamma_beta_g2, proof->b };
        if (!bn254_multi_pairing_check(pts1, pts2, 3))
            LOG_FAIL("phgr13", "verify: check 5 (consistency) pairing rejected");
    }

    return true;
}

/* ══════════════════════════════════════════════════════════════
 *  Sprout PHGR13 High-Level API
 * ══════════════════════════════════════════════════════════════ */

static struct ppzksnark_vk *phgr_vk = NULL;

void sprout_phgr_set_vk(struct ppzksnark_vk *vk)
{
    phgr_vk = vk;
}

#ifdef ZCL_TESTING
const struct ppzksnark_vk *sprout_test_published_phgr_vk(void) { return phgr_vk; }
#endif
bool sprout_phgr_vk_loaded(void)
{
    return phgr_vk != NULL;
}

/* Pack bits (MSB-first) into Fr scalars (253 bits per scalar).
 * Matches libsnark's pack_bit_vector_into_field_element_vector
 * with big-endian bit ordering (Zcash Sprout convention). */
static void bn254_multipack_be(uint64_t (*out)[4], size_t *n_out,
                                const uint8_t *bytes, size_t n_bytes)
{
    size_t n_bits = n_bytes * 8;
    size_t n_scalars = (n_bits + 252) / 253;
    *n_out = n_scalars;

    for (size_t s = 0; s < n_scalars; s++) {
        memset(out[s], 0, 32);
        for (size_t b = 0; b < 253 && s * 253 + b < n_bits; b++) {
            size_t bit_idx = s * 253 + b;
            size_t byte_idx = bit_idx / 8;
            int bit_pos = 7 - (int)(bit_idx % 8); /* MSB first */
            if ((bytes[byte_idx] >> bit_pos) & 1) {
                /* Set bit b in the scalar (little-endian limb order) */
                int limb = (int)(b / 64);
                int lbit = (int)(b % 64);
                out[s][limb] |= (1ULL << lbit);
            }
        }
    }
}

bool sprout_verify_phgr13(const uint8_t proof[296],
                          const uint8_t rt[32],
                          const uint8_t h_sig[32],
                          const uint8_t mac1[32],
                          const uint8_t mac2[32],
                          const uint8_t nf1[32],
                          const uint8_t nf2[32],
                          const uint8_t cm1[32],
                          const uint8_t cm2[32],
                          uint64_t vpub_old,
                          uint64_t vpub_new)
{
    if (!phgr_vk)
        LOG_FAIL("phgr13",
                 "sprout_verify_phgr13: phgr_vk is NULL (sprout-verifying.key not loaded)");

    struct ppzksnark_proof gp;
    if (!ppzksnark_proof_read(&gp, proof))
        LOG_FAIL("phgr13", "sprout_verify_phgr13: ppzksnark_proof_read failed");

    /* Construct input bytes (same layout as Groth16):
     * rt || h_sig || nf1 || mac1 || nf2 || mac2 || cm1 || cm2 || vpub_old_le || vpub_new_le */
    uint8_t input[272];
    memcpy(input,       rt,    32);
    memcpy(input + 32,  h_sig, 32);
    memcpy(input + 64,  nf1,   32);
    memcpy(input + 96,  mac1,  32);
    memcpy(input + 128, nf2,   32);
    memcpy(input + 160, mac2,  32);
    memcpy(input + 192, cm1,   32);
    memcpy(input + 224, cm2,   32);
    for (int i = 0; i < 8; i++) {
        input[256 + i] = (uint8_t)(vpub_old >> (i * 8));
        input[264 + i] = (uint8_t)(vpub_new >> (i * 8));
    }

    uint64_t public_inputs[16][4];
    size_t n_inputs;
    bn254_multipack_be(public_inputs, &n_inputs, input, 272);

    if (n_inputs != phgr_vk->ic_len - 1)
        LOG_FAIL("phgr13",
                 "sprout_verify_phgr13: input count mismatch: got=%zu expected=%zu",
                 n_inputs, phgr_vk->ic_len - 1);

    return ppzksnark_verify(phgr_vk, &gp, public_inputs, n_inputs);
}
