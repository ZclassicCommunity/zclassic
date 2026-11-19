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
#if defined(__x86_64__) || defined(_M_X64)
#include "mont_adx.h"
#endif
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>
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
    /* Strict < q, as zclassicd's bigint::limit (Proof.cpp:74, bigint.tcc:211):
     * the value q itself is not a field element encoding. Letting it through
     * reduced it to 0. */
    if (u256_ge(raw, FQ_Q))
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
    /* Pre-multiplied products for the engine's Frobenius maps (exact field
     * products of the constants above; see bn254_engine.inc). */
    struct bn_fq2 k1_1, k1_2;    /* w1_1*w1_6, w1_2*w1_6 */
    struct bn_fq k2_1, k2_2;     /* w2_1*w2_6, w2_2*w2_6 */
    struct bn_fq2 k3_1, k3_2;    /* w3_1*w3_6, w3_2*w3_6 */
} g_frob;

/* Constants of the pairing engine (bn254_engine.inc), filled together with
 * g_frob under the same once-flag. */
static struct {
    struct bn_fq fq_zero, fq_one;
    struct bn_fq2 fq2_one;
    struct bn_fq12 fq12_one;
    struct bn_fq two_inv;     /* 1/2 */
    struct bn_fq three;
    struct bn_fq2 twist_b;    /* b' = 3/(9+u) */
} g_eng;

/* The table is filled exactly once (pthread_once) and then never written.
 * g_frob_ready is stored with release order after the last table write and
 * loaded with acquire order by every user, so a reader that sees true also
 * sees the whole table. On x86-64 an acquire load is the same single mov as a
 * relaxed one. It used to be a plain `bool initialized` inside the table:
 * concurrent first callers (parallel proof validation) both filled the table
 * while others already read it. */
static pthread_once_t g_frob_once = PTHREAD_ONCE_INIT;
static atomic_bool g_frob_ready = false;

static void bn254_init_frobenius_once(void)
{
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

    /* products for the engine's Frobenius maps */
    bn_fq2_mul(&g_frob.k1_1, &g_frob.w1_1, &g_frob.w1_6);
    bn_fq2_mul(&g_frob.k1_2, &g_frob.w1_2, &g_frob.w1_6);
    bn_fq_mul(&g_frob.k2_1, &g_frob.w2_1, &g_frob.w2_6);
    bn_fq_mul(&g_frob.k2_2, &g_frob.w2_2, &g_frob.w2_6);
    bn_fq2_mul(&g_frob.k3_1, &g_frob.w3_1, &g_frob.w3_6);
    bn_fq2_mul(&g_frob.k3_2, &g_frob.w3_2, &g_frob.w3_6);

    /* engine constants */
    bn_fq_zero(&g_eng.fq_zero);
    bn_fq_one(&g_eng.fq_one);
    bn_fq2_one(&g_eng.fq2_one);
    bn_fq12_one(&g_eng.fq12_one);
    struct bn_fq two;
    bn_fq_from_u64(&two, 2);
    bn_fq_inv(&g_eng.two_inv, &two);
    bn_fq_from_u64(&g_eng.three, 3);
    {
        /* b' = 3 / (9 + u) in Fq2, exactly as bn_g2_twist_b computes it */
        struct bn_fq2 three2;
        bn_fq_from_u64(&three2.c0, 3);
        bn_fq_zero(&three2.c1);
        bn_fq2_inv(&g_eng.twist_b, &xi);
        bn_fq2_mul(&g_eng.twist_b, &g_eng.twist_b, &three2);
    }

    atomic_store_explicit(&g_frob_ready, true, memory_order_release);
}

/* First-use path, out of line so the callers pay one load and one
 * predicted-not-taken branch. */
__attribute__((noinline, cold))
static void bn254_init_frobenius_first(void)
{
    pthread_once(&g_frob_once, bn254_init_frobenius_once);
}

static inline void bn254_init_frobenius(void)
{
    if (__builtin_expect(!atomic_load_explicit(&g_frob_ready, memory_order_acquire), 0))
        bn254_init_frobenius_first();
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
 * Returns the full quotient (512-bit) and the remainder (256-bit).
 * Uses binary long division — O(512) iterations. Correct for all inputs.
 * Not performance-critical: called once per G2 decompression. */
static void u512_divmod_u256(const uint64_t dividend[8],
                              const uint64_t divisor[4],
                              uint64_t quotient[8],
                              uint64_t remainder[4])
{
    /* Accumulator for remainder — needs 257 bits during processing. */
    uint64_t rem[5] = {0};
    memset(quotient, 0, 64);

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

            /* Every quotient bit is kept: the caller must see a quotient
             * that does not fit in 256 bits in order to refuse it. */
            quotient[i / 64] |= (1ULL << (i % 64));
        }
    }

    memcpy(remainder, rem, 32);
}

/* Decode a CompressedG2 Fq2 x-coordinate from 64-byte FE2IP encoding.
 * combined (512-bit BE) = c1*q + c0 where c0, c1 < q.
 *
 * zclassicd (Proof.cpp:86-96, bigint.tcc:194-216): div_qr gives a 5-limb
 * quotient, and shorten() throws unless its high limb is zero and the low four
 * limbs are strictly below q. So the accepted integers are exactly
 * 0 <= combined < q^2. The quotient is therefore kept in full here: dropping
 * its bits >= 2^256 made combined + 2^256*q decode like combined. */
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

    uint64_t q_raw[8], r_raw[4];
    u512_divmod_u256(combined, FQ_Q, q_raw, r_raw);

    /* c1 = quotient, must be < q (strict), with no bits above 2^256 */
    if ((q_raw[4] | q_raw[5] | q_raw[6] | q_raw[7]) != 0)
        return false;
    if (u256_ge(q_raw, FQ_Q))
        return false;

    /* c0 = remainder (already < q by definition of mod) */
    /* Convert canonical → Montgomery form */
    bn_fq_mont_mul(c0->d, r_raw, FQ_R2);
    bn_fq_mont_mul(c1->d, q_raw, FQ_R2);
    return true;
}

/* Compare two Fq2 elements as FE2IP integers c1*q + c0 (Proof.cpp:25-34):
 * c1 first, then c0, each as a canonical integer. */
static int bn_fq2_fe2ip_cmp(const struct bn_fq2 *a, const struct bn_fq2 *b)
{
    uint8_t x[32], y[32];
    bn_fq_to_bytes_be(x, &a->c1);
    bn_fq_to_bytes_be(y, &b->c1);
    int c = memcmp(x, y, 32);
    if (c != 0)
        return c;
    bn_fq_to_bytes_be(x, &a->c0);
    bn_fq_to_bytes_be(y, &b->c0);
    return memcmp(x, y, 32);
}


/* ══════════════════════════════════════════════════════════════
 *  Pairing engine (bn254_engine.inc), instantiated per multiplier
 * ══════════════════════════════════════════════════════════════ */

/* BN parameter u = 4965661367192848881 (from libsnark alt_bn128_init.cpp)
 * 6u+2 = 29793968203157093288 = 0x19D797039BE763BA8 */
static const uint64_t ATE_LOOP[2] = {
    0x9D797039BE763BA8ULL,
    0x0000000000000001ULL
};

#define BNE_U 4965661367192848881ULL
#define BNE_INV 0x87d20782e4866389ULL
/* q - 2 and (q + 1) / 4, little-endian limbs */
static const uint64_t BNE_QM2[4] = {
    0x3c208c16d87cfd45ULL, 0x97816a916871ca8dULL,
    0xb85045b68181585dULL, 0x30644e72e131a029ULL
};
static const uint64_t BNE_SQRT_EXP[4] = {
    0x4f082305b61f3f52ULL, 0x65e05aa45a1c72a3ULL,
    0x6e14116da0605617ULL, 0x0c19139cb84c680aULL
};

/* One line function of a G2 point's Miller loop (unscaled by P). The loop has
 * 64 doublings, 36 additions for the set bits of 6u+2, and 2 Frobenius
 * additions. */
#define BN_NLINES 102
struct bn_line {
    struct bn_fq2 e0, vw, vv;
};

/* One factor of a pairing product: the lines of Q and the affine P. */
struct bn_pair {
    const struct bn_line *lines; /* NULL: identity operand, factor 1 */
    const struct bn_fq *xp, *yp;
};

/* Per verifying key: the line tables of its fixed G2 elements and of the G2
 * generator, and Straus tables for the IC multi-scalar multiplication. Built
 * once from the key and immutable afterwards. */
#define BN_PREP_MAX_INPUTS 16
struct bn_tab_pt {
    struct bn_fq x, y;
    bool inf;
};
struct bn_phgr_prep {
    struct bn_line l_alpha_a[BN_NLINES], l_alpha_c[BN_NLINES], l_gamma[BN_NLINES];
    struct bn_line l_gamma_beta[BN_NLINES], l_rc_z[BN_NLINES], l_g2_one[BN_NLINES];
    bool have_alpha_a, have_alpha_c, have_gamma, have_gamma_beta, have_rc_z;
    bool have_g2_one, g2_one_ok, have_tables;
    struct bn_tab_pt tab[BN_PREP_MAX_INPUTS][15];
    /* the key this was built from (ic copied in full when it fits) */
    struct ppzksnark_vk vk;
    struct bn_g1 ic[BN_PREP_MAX_INPUTS + 1];
};

/* Portable instance: the dispatched multiply, byte-identical to the MULX one. */
#define BNE_ID portable
#define BNE_ATTR
#define BNE_MUL(r, a, b) bn254_accel_mont_mul_portable((r), (a), (b))
#include "bn254_engine.inc"
#undef BNE_ID
#undef BNE_ATTR
#undef BNE_MUL

#if defined(__x86_64__) || defined(_M_X64)
/* BMI2+ADX instance: the multiply of mont_adx.h inlined into every field op. */
#define BNE_ID adx
#define BNE_ASM_ADDSUB 1
#define BNE_ATTR __attribute__((target("bmi2,adx")))
#define BNE_MUL(r, a, b) mont_mul_adx4((r), (a), (b), FQ_Q, BNE_INV)
#include "bn254_engine.inc"
#undef BNE_ID
#undef BNE_ATTR
#undef BNE_MUL
#undef BNE_ASM_ADDSUB
#define BN_HAVE_ADX_ENGINE 1
#endif

struct bn_engine {
    const char *name;
    bool (*g1_decompress)(struct bn_g1 *, const uint8_t[33]);
    bool (*fq2_sqrt)(struct bn_fq2 *, const struct bn_fq2 *);
    bool (*g2_decompress)(struct bn_g2 *, const uint8_t[65]);
    bool (*g2_in_subgroup)(const struct bn_g2 *);
    void (*prep_build)(struct bn_phgr_prep *, const struct ppzksnark_vk *);
    int (*verify)(const struct ppzksnark_vk *, const struct bn_phgr_prep *,
                  const struct ppzksnark_proof *, const uint64_t (*)[4], size_t);
    void (*pairing_product)(struct bn_fq12 *, const struct bn_g1 *, const struct bn_g2 *, size_t);
    void (*pairing_full)(struct bn_fq12 *, const struct bn_g1 *, const struct bn_g2 *);
    bool (*multi_pairing_check)(const struct bn_g1 *, const struct bn_g2 *, size_t);
    void (*final_exp)(struct bn_fq12 *);
#ifdef ZCL_TESTING
    void (*t_fq12_mul)(struct bn_fq12 *, const struct bn_fq12 *, const struct bn_fq12 *);
    void (*t_fq12_sqr)(struct bn_fq12 *, const struct bn_fq12 *);
    void (*t_fq12_cyc_sqr)(struct bn_fq12 *, const struct bn_fq12 *);
    void (*t_fq12_inv)(struct bn_fq12 *, const struct bn_fq12 *);
    void (*t_fq12_frob1)(struct bn_fq12 *, const struct bn_fq12 *);
    void (*t_fq12_frob2)(struct bn_fq12 *, const struct bn_fq12 *);
    void (*t_fq12_frob3)(struct bn_fq12 *, const struct bn_fq12 *);
    void (*t_fq12_mul_by_024)(struct bn_fq12 *, const struct bn_fq2 *, const struct bn_fq2 *, const struct bn_fq2 *);
    void (*t_fq6_mul)(struct bn_fq6 *, const struct bn_fq6 *, const struct bn_fq6 *);
    void (*t_fq6_sqr)(struct bn_fq6 *, const struct bn_fq6 *);
    void (*t_fq_inv)(struct bn_fq *, const struct bn_fq *);
    bool (*t_fq_sqrt)(struct bn_fq *, const struct bn_fq *);
    void (*t_accumulate)(struct bn_g1 *, const struct bn_phgr_prep *, const struct ppzksnark_vk *,
                         const uint64_t (*)[4], size_t);
#endif
};

static const struct bn_engine g_engine_portable = {
    "portable",
    bne_portable_g1_decompress, bne_portable_fq2_sqrt, bne_portable_g2_decompress,
    bne_portable_g2_in_subgroup, bne_portable_prep_build, bne_portable_verify,
    bne_portable_pairing_product, bne_portable_pairing_full,
    bne_portable_multi_pairing_check, bne_portable_final_exp
#ifdef ZCL_TESTING
    , bne_portable_fq12_mul, bne_portable_fq12_sqr, bne_portable_fq12_cyc_sqr, bne_portable_fq12_inv,
    bne_portable_fq12_frob1, bne_portable_fq12_frob2, bne_portable_fq12_frob3, bne_portable_fq12_mul_by_024,
    bne_portable_fq6_mul, bne_portable_fq6_sqr, bne_portable_fq_inv, bne_portable_fq_sqrt, bne_portable_accumulate
#endif
};
#ifdef BN_HAVE_ADX_ENGINE
static const struct bn_engine g_engine_adx = {
    "adx",
    bne_adx_g1_decompress, bne_adx_fq2_sqrt, bne_adx_g2_decompress,
    bne_adx_g2_in_subgroup, bne_adx_prep_build, bne_adx_verify,
    bne_adx_pairing_product, bne_adx_pairing_full,
    bne_adx_multi_pairing_check, bne_adx_final_exp
#ifdef ZCL_TESTING
    , bne_adx_fq12_mul, bne_adx_fq12_sqr, bne_adx_fq12_cyc_sqr, bne_adx_fq12_inv,
    bne_adx_fq12_frob1, bne_adx_fq12_frob2, bne_adx_fq12_frob3, bne_adx_fq12_mul_by_024,
    bne_adx_fq6_mul, bne_adx_fq6_sqr, bne_adx_fq_inv, bne_adx_fq_sqrt, bne_adx_accumulate
#endif
};
#endif

/* The engine every public entry point uses. Selection is idempotent (every
 * racer stores the same pointer), so a relaxed atomic suffices. */
static _Atomic(const struct bn_engine *) g_engine_sel = NULL;

static const struct bn_engine *bn_eng(void)
{
    const struct bn_engine *e = atomic_load_explicit(&g_engine_sel, memory_order_relaxed);
    if (__builtin_expect(e == NULL, 0)) {
        e = &g_engine_portable;
#ifdef BN_HAVE_ADX_ENGINE
        if (bn254_accel_cpu_has_adx())
            e = &g_engine_adx;
#endif
        atomic_store_explicit(&g_engine_sel, e, memory_order_relaxed);
    }
    return e;
}

#ifdef ZCL_TESTING
/* Test hook: 0 = automatic, 1 = portable instance, 2 = BMI2+ADX instance.
 * Returns false (and changes nothing) when the instance is unavailable. Not
 * thread-safe against concurrent verifiers; for tests only. */
bool bn254_test_select_engine(int which)
{
    if (which == 0) {
        atomic_store_explicit(&g_engine_sel, NULL, memory_order_relaxed);
        return true;
    }
    if (which == 1) {
        atomic_store_explicit(&g_engine_sel, &g_engine_portable, memory_order_relaxed);
        return true;
    }
#ifdef BN_HAVE_ADX_ENGINE
    if (which == 2 && bn254_accel_cpu_has_adx()) {
        atomic_store_explicit(&g_engine_sel, &g_engine_adx, memory_order_relaxed);
        return true;
    }
#endif
    return false;
}

const char *bn254_test_engine_name(void) { return bn_eng()->name; }

void bn254_test_miller(struct bn_fq12 *r, const struct bn_g1 *p, const struct bn_g2 *q, size_t n)
{
    bn254_init_frobenius();
    bn_eng()->pairing_product(r, p, q, n);
}

void bn254_test_final_exp(struct bn_fq12 *f)
{
    bn254_init_frobenius();
    bn_eng()->final_exp(f);
}

bool bn254_test_g2_in_subgroup(const struct bn_g2 *p)
{
    bn254_init_frobenius();
    return bn_eng()->g2_in_subgroup(p);
}

void bn254_test_fq12_mul(struct bn_fq12 *r, const struct bn_fq12 *a, const struct bn_fq12 *b)
{ bn254_init_frobenius(); bn_eng()->t_fq12_mul(r, a, b); }
void bn254_test_fq12_sqr(struct bn_fq12 *r, const struct bn_fq12 *a)
{ bn254_init_frobenius(); bn_eng()->t_fq12_sqr(r, a); }
void bn254_test_fq12_cyc_sqr(struct bn_fq12 *r, const struct bn_fq12 *a)
{ bn254_init_frobenius(); bn_eng()->t_fq12_cyc_sqr(r, a); }
void bn254_test_fq12_inv(struct bn_fq12 *r, const struct bn_fq12 *a)
{ bn254_init_frobenius(); bn_eng()->t_fq12_inv(r, a); }
void bn254_test_fq12_frob(struct bn_fq12 *r, const struct bn_fq12 *a, int power)
{
    bn254_init_frobenius();
    if (power == 1) bn_eng()->t_fq12_frob1(r, a);
    else if (power == 2) bn_eng()->t_fq12_frob2(r, a);
    else bn_eng()->t_fq12_frob3(r, a);
}
void bn254_test_fq12_mul_by_024(struct bn_fq12 *f, const struct bn_fq2 *x0,
                                const struct bn_fq2 *x4, const struct bn_fq2 *x2)
{ bn254_init_frobenius(); bn_eng()->t_fq12_mul_by_024(f, x0, x4, x2); }
void bn254_test_fq6_mul(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b)
{ bn254_init_frobenius(); bn_eng()->t_fq6_mul(r, a, b); }
void bn254_test_fq6_sqr(struct bn_fq6 *r, const struct bn_fq6 *a)
{ bn254_init_frobenius(); bn_eng()->t_fq6_sqr(r, a); }
void bn254_test_fq_inv(struct bn_fq *r, const struct bn_fq *a)
{ bn254_init_frobenius(); bn_eng()->t_fq_inv(r, a); }
bool bn254_test_fq_sqrt(struct bn_fq *r, const struct bn_fq *a)
{ bn254_init_frobenius(); return bn_eng()->t_fq_sqrt(r, a); }

/* The IC accumulation the verifier uses (prepared tables or plain), for tests.
 * The prepared state is the verifier's own: this goes through bn_prep_get, so a
 * key that differs from the cached one is accumulated through a private copy. */
static const struct bn_phgr_prep *bn_prep_get(const struct bn_engine *e,
                                              const struct ppzksnark_vk *vk,
                                              struct bn_phgr_prep **tmp);
void bn254_test_msm(struct bn_g1 *acc, const struct ppzksnark_vk *vk,
                    const uint64_t (*in)[4], size_t n)
{
    bn254_init_frobenius();
    const struct bn_engine *e = bn_eng();
    struct bn_phgr_prep *tmp;
    const struct bn_phgr_prep *pp = bn_prep_get(e, vk, &tmp);
    if (pp)
        e->t_accumulate(acc, pp, vk, in, n);
    free(tmp);
}
#endif

bool bn_g1_decompress(struct bn_g1 *p, const uint8_t data[33])
{
    bn254_init_frobenius();
    return bn_eng()->g1_decompress(p, data);
}

bool bn_fq2_sqrt(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    bn254_init_frobenius();
    return bn_eng()->fq2_sqrt(r, a);
}

/* Decode a CompressedG2 exactly as zclassicd does (Proof.hpp:147-161,
 * Proof.cpp:147-171). Reject unless ALL of:
 *   - the lead byte is 0x0a or 0x0b (bit 0 is the y_gt flag). There is no
 *     encoding of the point at infinity;
 *   - the 64-byte FE2IP integer is below q^2;
 *   - x^3 + b' is a square in Fq2;
 *   - the point is in the order-r subgroup.
 * y is the root whose FE2IP integer is the larger of (y, -y) iff y_gt. */
bool bn_g2_decompress(struct bn_g2 *p, const uint8_t data[65])
{
    bn254_init_frobenius();
    return bn_eng()->g2_decompress(p, data);
}

/* Optimal ate pairing. Same function as before: the Miller loop with the same
 * line formulas and the same final exponentiation, so the result is the same
 * field element for any input. */
void bn254_pairing(struct bn_fq12 *result,
                   const struct bn_g1 *p,
                   const struct bn_g2 *q)
{
    bn254_init_frobenius();
    bn_eng()->pairing_full(result, p, q);
}

/* Multi-pairing check: product of pairings == 1 in GT, one final
 * exponentiation. */
bool bn254_multi_pairing_check(
    const struct bn_g1 *a_pts, const struct bn_g2 *b_pts,
    size_t n_pairs)
{
    bn254_init_frobenius();
    return bn_eng()->multi_pairing_check(a_pts, b_pts, n_pairs);
}

/* ══════════════════════════════════════════════════════════════
 *  PPZKSNARK (PHGR13) Proof Verification
 * ══════════════════════════════════════════════════════════════ */

bool ppzksnark_proof_read(struct ppzksnark_proof *proof, const uint8_t data[296])
{
    size_t off = 0;
    bn254_init_frobenius();
    const struct bn_engine *e = bn_eng();
    /* 8 elements: g_A(33), g_A'(33), g_B(65), g_B'(33), g_C(33), g_C'(33), g_K(33), g_H(33) */
    if (!e->g1_decompress(&proof->a, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_A) failed");
    off += 33;
    if (!e->g1_decompress(&proof->a_prime, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_A') failed");
    off += 33;
    if (!e->g2_decompress(&proof->b, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g2_decompress(g_B) failed");
    off += 65;
    if (!e->g1_decompress(&proof->b_prime, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_B') failed");
    off += 33;
    if (!e->g1_decompress(&proof->c, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_C) failed");
    off += 33;
    if (!e->g1_decompress(&proof->c_prime, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_C') failed");
    off += 33;
    if (!e->g1_decompress(&proof->k, data + off))
        LOG_FAIL("phgr13", "proof_read: bn_g1_decompress(g_K) failed");
    off += 33;
    if (!e->g1_decompress(&proof->h, data + off))
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

/* ── per-key preparation ──────────────────────────────────────
 *
 * The line tables and Straus tables depend only on the verifying key. They are
 * built once, from the first key a verification sees, into static storage (no
 * allocation on the consensus path), and published with a release store. A
 * caller whose key differs from the cached one (a test that edits a key, a
 * second key in the same process) gets a private heap copy instead, so the
 * cache can never make a verification use stale key material. Every verify
 * compares the key against the snapshot, so even an in-place edit of a key
 * that was cached is noticed. */

static pthread_mutex_t g_prep_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_prep_state; /* 0 empty, 1 published */
static struct bn_phgr_prep g_prep;

static bool bn_prep_matches(const struct bn_phgr_prep *pp, const struct ppzksnark_vk *vk)
{
    if (vk->ic_len != pp->vk.ic_len)
        return false;
    if (memcmp(&vk->alpha_a_g2, &pp->vk.alpha_a_g2, sizeof vk->alpha_a_g2) ||
        memcmp(&vk->alpha_b_g1, &pp->vk.alpha_b_g1, sizeof vk->alpha_b_g1) ||
        memcmp(&vk->alpha_c_g2, &pp->vk.alpha_c_g2, sizeof vk->alpha_c_g2) ||
        memcmp(&vk->gamma_g2, &pp->vk.gamma_g2, sizeof vk->gamma_g2) ||
        memcmp(&vk->gamma_beta_g1, &pp->vk.gamma_beta_g1, sizeof vk->gamma_beta_g1) ||
        memcmp(&vk->gamma_beta_g2, &pp->vk.gamma_beta_g2, sizeof vk->gamma_beta_g2) ||
        memcmp(&vk->rc_z_g2, &pp->vk.rc_z_g2, sizeof vk->rc_z_g2))
        return false;
    return memcmp(vk->ic, pp->ic, vk->ic_len * sizeof(struct bn_g1)) == 0;
}

static void bn_prep_snapshot(struct bn_phgr_prep *pp, const struct ppzksnark_vk *vk)
{
    pp->vk = *vk;
    pp->vk.ic = NULL;
    if (vk->ic_len >= 1 && vk->ic_len <= BN_PREP_MAX_INPUTS + 1)
        memcpy(pp->ic, vk->ic, vk->ic_len * sizeof(struct bn_g1));
}

/* Returns a prepared key for vk: the cached one, or a private copy in *tmp
 * that the caller frees. NULL only when that copy cannot be allocated. */
static const struct bn_phgr_prep *bn_prep_get(const struct bn_engine *e,
                                              const struct ppzksnark_vk *vk,
                                              struct bn_phgr_prep **tmp)
{
    *tmp = NULL;
    bool cacheable = vk->ic != NULL && vk->ic_len >= 1 && vk->ic_len <= BN_PREP_MAX_INPUTS + 1;
    if (cacheable) {
        if (atomic_load_explicit(&g_prep_state, memory_order_acquire) == 1 &&
            bn_prep_matches(&g_prep, vk))
            return &g_prep;
        pthread_mutex_lock(&g_prep_mu);
        if (atomic_load_explicit(&g_prep_state, memory_order_relaxed) == 0) {
            bn_prep_snapshot(&g_prep, vk);
            e->prep_build(&g_prep, vk);
            atomic_store_explicit(&g_prep_state, 1, memory_order_release);
        }
        pthread_mutex_unlock(&g_prep_mu);
        if (bn_prep_matches(&g_prep, vk))
            return &g_prep;
    }
    struct bn_phgr_prep *t = zcl_calloc(1, sizeof *t, "phgr_prep");
    if (!t)
        return NULL;
    bn_prep_snapshot(t, vk);
    e->prep_build(t, vk);
    *tmp = t;
    return t;
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
 * by moving all terms to one side. The five checks stay five separate
 * products (no random combination): a proof is accepted iff each one holds. */
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

    bn254_init_frobenius();
    const struct bn_engine *e = bn_eng();
    struct bn_phgr_prep *tmp;
    const struct bn_phgr_prep *pp = bn_prep_get(e, vk, &tmp);
    if (!pp)
        LOG_FAIL("phgr13", "verify: cannot allocate the verifying-key tables");
    int rc = e->verify(vk, pp, proof, public_inputs, n_inputs);
    free(tmp);

    switch (rc) {
    case 0:
        return true;
    case 1:
        LOG_FAIL("phgr13", "verify: check 1 (knowledge of A) pairing rejected");
    case 2:
        LOG_FAIL("phgr13", "verify: check 2 (knowledge of B) pairing rejected");
    case 3:
        LOG_FAIL("phgr13", "verify: check 3 (knowledge of C) pairing rejected");
    case 4:
        LOG_FAIL("phgr13", "verify: check 4 (QAP divisibility) pairing rejected");
    case 5:
        LOG_FAIL("phgr13", "verify: check 5 (consistency) pairing rejected");
    default:
        /* the G2 generator constant is off the twist curve: never expected */
        LOG_FAIL("phgr13", "verify: G2 generator off-curve — refusing "
                 "(corrupt g2_gen constant; would false-reject all proofs)");
    }
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
