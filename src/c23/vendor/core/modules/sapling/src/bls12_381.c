/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BLS12-381 pairing — pure C23 implementation.
 * 381-bit prime, 6 x 64-bit limbs, Montgomery multiplication.
 * Full tower: Fp -> Fp2 -> Fp6 -> Fp12, G1, G2, optimal Ate pairing. */

#include "sapling/bls12_381.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto/blake2b.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "bls12_381_fp_inline.h"

/* Runtime-dispatched Montgomery multiply (CPUID → BMI2+ADX or portable) */
extern void fp_mont_mul_accel(uint64_t r[6], const uint64_t a[6], const uint64_t b[6]);
#define fp_mont_mul fp_mont_mul_accel

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

/* ===== Fp constants ===== */

/* q = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab */
static const uint64_t FP_Q[6] = {
    0xb9feffffffffaaabULL, 0x1eabfffeb153ffffULL,
    0x6730d2a0f6b0f624ULL, 0x64774b84f38512bfULL,
    0x4b1ba7b6434bacd7ULL, 0x1a0111ea397fe69aULL
};

/* FP_INV moved to fr_avx512.c (runtime dispatch) */

/* R = 2^384 mod q */
static const uint64_t FP_R[6] = {
    0x760900000002fffdULL, 0xebf4000bc40c0002ULL,
    0x5f48985753c758baULL, 0x77ce585370525745ULL,
    0x5c071a97a256ec6dULL, 0x15f65ec3fa80e493ULL
};

/* R^2 mod q */
static const uint64_t FP_R2[6] = {
    0xf4df1f341c341746ULL, 0x0a76e6a609d104f1ULL,
    0x8de5476c4c95b6d5ULL, 0x67eb88a9939d83c0ULL,
    0x9a793e85b519952dULL, 0x11988fe592cae3aaULL
};

/* ===== Fp arithmetic ===== */


/* Montgomery multiply implementation is in fr_avx512.c (runtime dispatch) */

void fp_zero(struct fp *r) { memset(r->d, 0, 48); }

void fp_one(struct fp *r) { memcpy(r->d, FP_R, 48); }

bool fp_is_zero(const struct fp *a)
{
    for (int i = 0; i < 6; i++)
        if (a->d[i] != 0) return false;
    return true;
}

bool fp_eq(const struct fp *a, const struct fp *b)
{
    for (int i = 0; i < 6; i++)
        if (a->d[i] != b->d[i]) return false;
    return true;
}

void fp_add(struct fp *r, const struct fp *a, const struct fp *b)
{
    fpi_add(r->d, a->d, b->d, FP_Q);
}

void fp_sub(struct fp *r, const struct fp *a, const struct fp *b)
{
    fpi_sub(r->d, a->d, b->d, FP_Q);
}

void fp_neg(struct fp *r, const struct fp *a)
{
    fpi_neg(r->d, a->d, FP_Q);
}

void fp_mul(struct fp *r, const struct fp *a, const struct fp *b)
{
    fp_mont_mul(r->d, a->d, b->d);
}

void fp_sq(struct fp *r, const struct fp *a)
{
    fp_mont_mul(r->d, a->d, a->d);
}

/* fp_pow: a^exp where exp is an array of 6 uint64_t (little-endian limbs) */
static void fp_pow(struct fp *r, const struct fp *a, const uint64_t exp[6])
{
    struct fp result;
    fp_one(&result);
    struct fp base = *a;

    for (int i = 0; i < 6; i++) {
        for (int bit = 0; bit < 64; bit++) {
            if ((exp[i] >> bit) & 1)
                fp_mul(&result, &result, &base);
            fp_sq(&base, &base);
        }
    }
    *r = result;
}

void fp_inv(struct fp *r, const struct fp *a)
{
    /* q - 2 */
    uint64_t exp[6];
    memcpy(exp, FP_Q, 48);
    /* Subtract 2 from little-endian */
    exp[0] -= 2; /* FP_Q[0] ends in ...aaab, so no borrow */
    fp_pow(r, a, exp);
}

bool fp_sqrt(struct fp *r, const struct fp *a)
{
    /* q ≡ 3 (mod 4), so sqrt(a) = a^((q+1)/4) */
    /* (q+1)/4 */
    uint64_t exp[6];
    memcpy(exp, FP_Q, 48);
    /* q+1: add 1 to ...aaab -> ...aaac */
    unsigned __int128 carry = 1;
    for (int i = 0; i < 6; i++) {
        unsigned __int128 s = (unsigned __int128)exp[i] + carry;
        exp[i] = (uint64_t)s;
        carry = s >> 64;
    }
    /* Divide by 4: right shift by 2 */
    for (int i = 0; i < 5; i++)
        exp[i] = (exp[i] >> 2) | (exp[i + 1] << 62);
    exp[5] >>= 2;

    fp_pow(r, a, exp);

    /* Verify: r^2 == a */
    struct fp check;
    fp_sq(&check, r);
    return fp_eq(&check, a);
}

bool fp_lexicographically_largest(const struct fp *a)
{
    /* Convert from Montgomery to get raw value, then check > (q-1)/2 */
    uint64_t one[6] = {1, 0, 0, 0, 0, 0};
    uint64_t raw[6];
    fp_mont_mul(raw, a->d, one);

    /* (q-1)/2 */
    uint64_t half[6];
    for (int i = 0; i < 6; i++) half[i] = FP_Q[i];
    /* Right shift by 1 */
    for (int i = 0; i < 5; i++)
        half[i] = (half[i] >> 1) | (half[i + 1] << 63);
    half[5] >>= 1;

    /* raw > half means lexicographically largest */
    for (int i = 5; i >= 0; i--) {
        if (raw[i] > half[i]) return true;
        if (raw[i] < half[i]) return false;
    }
    return false;
}

bool fp_from_bytes(struct fp *r, const uint8_t s[48])
{
    uint64_t raw[6];
    for (int i = 0; i < 6; i++) {
        raw[5 - i] = 0;
        for (int j = 0; j < 8; j++)
            raw[5 - i] |= (uint64_t)s[i * 8 + j] << (8 * (7 - j));
    }

    bool ok = true;
    for (int i = 5; i >= 0; i--) {
        if (raw[i] > FP_Q[i]) { ok = false; break; }
        if (raw[i] < FP_Q[i]) break;
    }

    fp_mont_mul(r->d, raw, FP_R2);
    return ok;
}

void fp_to_bytes(uint8_t s[48], const struct fp *a)
{
    uint64_t one[6] = {1, 0, 0, 0, 0, 0};
    uint64_t raw[6];
    fp_mont_mul(raw, a->d, one);

    for (int i = 0; i < 6; i++)
        for (int j = 0; j < 8; j++)
            s[i * 8 + j] = (uint8_t)(raw[5 - i] >> (8 * (7 - j)));
}

/* ===== Fp2 = Fp[u] / (u^2 + 1) ===== */

void fp2_zero(struct fp2 *r) { fp_zero(&r->c0); fp_zero(&r->c1); }

void fp2_one(struct fp2 *r) { fp_one(&r->c0); fp_zero(&r->c1); }

bool fp2_is_zero(const struct fp2 *a) { return fp_is_zero(&a->c0) && fp_is_zero(&a->c1); }

bool fp2_eq(const struct fp2 *a, const struct fp2 *b)
{
    return fp_eq(&a->c0, &b->c0) && fp_eq(&a->c1, &b->c1);
}

void fp2_add(struct fp2 *r, const struct fp2 *a, const struct fp2 *b)
{
    fp_add(&r->c0, &a->c0, &b->c0);
    fp_add(&r->c1, &a->c1, &b->c1);
}

void fp2_sub(struct fp2 *r, const struct fp2 *a, const struct fp2 *b)
{
    fp_sub(&r->c0, &a->c0, &b->c0);
    fp_sub(&r->c1, &a->c1, &b->c1);
}

void fp2_neg(struct fp2 *r, const struct fp2 *a)
{
    fp_neg(&r->c0, &a->c0);
    fp_neg(&r->c1, &a->c1);
}

void fp2_mul(struct fp2 *r, const struct fp2 *a, const struct fp2 *b)
{
    struct fp t0, t1, t2, t3, rc0, rc1;
    fp_mul(&t0, &a->c0, &b->c0);
    fp_mul(&t1, &a->c1, &b->c1);
    fp_sub(&rc0, &t0, &t1);
    fp_add(&t2, &a->c0, &a->c1);
    fp_add(&t3, &b->c0, &b->c1);
    fp_mul(&rc1, &t2, &t3);
    fp_sub(&rc1, &rc1, &t0);
    fp_sub(&rc1, &rc1, &t1);
    r->c0 = rc0;
    r->c1 = rc1;
}

void fp2_sq(struct fp2 *r, const struct fp2 *a)
{
    struct fp t0, t1, rc0, rc1;
    fp_add(&t0, &a->c0, &a->c1);
    fp_sub(&t1, &a->c0, &a->c1);
    fp_mul(&rc0, &t0, &t1);
    fp_mul(&t0, &a->c0, &a->c1);
    fp_add(&rc1, &t0, &t0);
    r->c0 = rc0;
    r->c1 = rc1;
}

void fp2_inv(struct fp2 *r, const struct fp2 *a)
{
    struct fp t0, t1, inv;
    fp_sq(&t0, &a->c0);
    fp_sq(&t1, &a->c1);
    fp_add(&t0, &t0, &t1);
    fp_inv(&inv, &t0);
    fp_mul(&r->c0, &a->c0, &inv);
    fp_neg(&r->c1, &a->c1);
    fp_mul(&r->c1, &r->c1, &inv);
}

/* (a0 + a1*u) * (1 + u) = (a0 - a1) + (a0 + a1)*u */
void fp2_mul_by_nonresidue(struct fp2 *r, const struct fp2 *a)
{
    struct fp t0;
    fp_sub(&t0, &a->c0, &a->c1);
    fp_add(&r->c1, &a->c0, &a->c1);
    r->c0 = t0;
}

/* FROBENIUS_COEFF_FQ2_C1[1] = -1 in Montgomery form (q - R mod q) */
static const struct fp FP_NEGATIVE_ONE = {{
    0x43f5fffffffcaaaeULL, 0x32b7fff2ed47fffdULL,
    0x07e83a49a2e99d69ULL, 0xeca8f3318332bb7aULL,
    0xef148d1ea0f4c069ULL, 0x040ab3263eff0206ULL
}};

void fp2_frobenius_map(struct fp2 *a, int power)
{
    if (power % 2 != 0)
        fp_mul(&a->c1, &a->c1, &FP_NEGATIVE_ONE);
}

static void fp2_pow(struct fp2 *r, const struct fp2 *a, const uint64_t exp[6])
{
    struct fp2 result;
    fp2_one(&result);
    struct fp2 base = *a;

    for (int i = 0; i < 6; i++) {
        for (int bit = 0; bit < 64; bit++) {
            if ((exp[i] >> bit) & 1)
                fp2_mul(&result, &result, &base);
            fp2_sq(&base, &base);
        }
    }
    *r = result;
}

bool fp2_sqrt(struct fp2 *r, const struct fp2 *a)
{
    if (fp2_is_zero(a)) {
        fp2_zero(r);
        return true;
    }

    /* Algorithm 9, https://eprint.iacr.org/2012/685.pdf */
    /* a1 = a^((q - 3) / 4) */
    static const uint64_t QM3D4[6] = {
        0xee7fbfffffffeaaaULL, 0x07aaffffac54ffffULL,
        0xd9cc34a83dac3d89ULL, 0xd91dd2e13ce144afULL,
        0x92c6e9ed90d2eb35ULL, 0x0680447a8e5ff9a6ULL
    };
    struct fp2 a1;
    fp2_pow(&a1, a, QM3D4);

    struct fp2 alpha;
    fp2_sq(&alpha, &a1);
    fp2_mul(&alpha, &alpha, a);

    struct fp2 a0 = alpha;
    fp2_frobenius_map(&a0, 1);
    fp2_mul(&a0, &a0, &alpha);

    struct fp2 neg1;
    neg1.c0 = FP_NEGATIVE_ONE;
    fp_zero(&neg1.c1);

    if (fp2_eq(&a0, &neg1))
        return false;

    fp2_mul(&a1, &a1, a);

    if (fp2_eq(&alpha, &neg1)) {
        struct fp2 i_val;
        fp_zero(&i_val.c0);
        fp_one(&i_val.c1);
        fp2_mul(&a1, &a1, &i_val);
    } else {
        struct fp2 one_val;
        fp2_one(&one_val);
        fp2_add(&alpha, &alpha, &one_val);

        /* alpha = alpha^((q - 1) / 2) */
        static const uint64_t QM1D2[6] = {
            0xdcff7fffffffd555ULL, 0x0f55ffff58a9ffffULL,
            0xb39869507b587b12ULL, 0xb23ba5c279c2895fULL,
            0x258dd3db21a5d66bULL, 0x0d0088f51cbff34dULL
        };
        fp2_pow(&alpha, &alpha, QM1D2);
        fp2_mul(&a1, &a1, &alpha);
    }

    *r = a1;

    /* Verify */
    struct fp2 check;
    fp2_sq(&check, r);
    return fp2_eq(&check, a);
}

bool fp2_lexicographically_largest(const struct fp2 *a)
{
    /* Lexicographic order: compare c1 first, then c0 */
    if (!fp_is_zero(&a->c1))
        return fp_lexicographically_largest(&a->c1);
    return fp_lexicographically_largest(&a->c0);
}

/* ===== Frobenius coefficients for Fp6 and Fp12 ===== */

/* FROBENIUS_COEFF_FQ6_C1[i] — all in Montgomery form */
static const struct fp2 FROB_FQ6_C1[6] = {
    /* [0] = 1 */
    {{{0x760900000002fffdULL, 0xebf4000bc40c0002ULL,
       0x5f48985753c758baULL, 0x77ce585370525745ULL,
       0x5c071a97a256ec6dULL, 0x15f65ec3fa80e493ULL}},
     {{0,0,0,0,0,0}}},
    /* [1] */
    {{{0,0,0,0,0,0}},
     {{0xcd03c9e48671f071ULL, 0x5dab22461fcda5d2ULL,
       0x587042afd3851b95ULL, 0x8eb60ebe01bacb9eULL,
       0x03f97d6e83d050d2ULL, 0x18f0206554638741ULL}}},
    /* [2] */
    {{{0x30f1361b798a64e8ULL, 0xf3b8ddab7ece5a2aULL,
       0x16a8ca3ac61577f7ULL, 0xc26a2ff874fd029bULL,
       0x3636b76660701c6eULL, 0x051ba4ab241b6160ULL}},
     {{0,0,0,0,0,0}}},
    /* [3] */
    {{{0,0,0,0,0,0}},
     {{0x760900000002fffdULL, 0xebf4000bc40c0002ULL,
       0x5f48985753c758baULL, 0x77ce585370525745ULL,
       0x5c071a97a256ec6dULL, 0x15f65ec3fa80e493ULL}}},
    /* [4] */
    {{{0xcd03c9e48671f071ULL, 0x5dab22461fcda5d2ULL,
       0x587042afd3851b95ULL, 0x8eb60ebe01bacb9eULL,
       0x03f97d6e83d050d2ULL, 0x18f0206554638741ULL}},
     {{0,0,0,0,0,0}}},
    /* [5] */
    {{{0,0,0,0,0,0}},
     {{0x30f1361b798a64e8ULL, 0xf3b8ddab7ece5a2aULL,
       0x16a8ca3ac61577f7ULL, 0xc26a2ff874fd029bULL,
       0x3636b76660701c6eULL, 0x051ba4ab241b6160ULL}}}
};

static const struct fp2 FROB_FQ6_C2[6] = {
    /* [0] = 1 */
    {{{0x760900000002fffdULL, 0xebf4000bc40c0002ULL,
       0x5f48985753c758baULL, 0x77ce585370525745ULL,
       0x5c071a97a256ec6dULL, 0x15f65ec3fa80e493ULL}},
     {{0,0,0,0,0,0}}},
    /* [1] */
    {{{0x890dc9e4867545c3ULL, 0x2af322533285a5d5ULL,
       0x50880866309b7e2cULL, 0xa20d1b8c7e881024ULL,
       0x14e4f04fe2db9068ULL, 0x14e56d3f1564853aULL}},
     {{0,0,0,0,0,0}}},
    /* [2] */
    {{{0xcd03c9e48671f071ULL, 0x5dab22461fcda5d2ULL,
       0x587042afd3851b95ULL, 0x8eb60ebe01bacb9eULL,
       0x03f97d6e83d050d2ULL, 0x18f0206554638741ULL}},
     {{0,0,0,0,0,0}}},
    /* [3] */
    {{{0x43f5fffffffcaaaeULL, 0x32b7fff2ed47fffdULL,
       0x07e83a49a2e99d69ULL, 0xeca8f3318332bb7aULL,
       0xef148d1ea0f4c069ULL, 0x040ab3263eff0206ULL}},
     {{0,0,0,0,0,0}}},
    /* [4] */
    {{{0x30f1361b798a64e8ULL, 0xf3b8ddab7ece5a2aULL,
       0x16a8ca3ac61577f7ULL, 0xc26a2ff874fd029bULL,
       0x3636b76660701c6eULL, 0x051ba4ab241b6160ULL}},
     {{0,0,0,0,0,0}}},
    /* [5] */
    {{{0xecfb361b798dba3aULL, 0xc100ddb891865a2cULL,
       0x0ec08ff1232bda8eULL, 0xd5c13cc6f1ca4721ULL,
       0x47222a47bf7b5c04ULL, 0x0110f184e51c5f59ULL}},
     {{0,0,0,0,0,0}}}
};

static const struct fp2 FROB_FQ12_C1[12] = {
    /* [0] = 1 */
    {{{0x760900000002fffdULL, 0xebf4000bc40c0002ULL,
       0x5f48985753c758baULL, 0x77ce585370525745ULL,
       0x5c071a97a256ec6dULL, 0x15f65ec3fa80e493ULL}},
     {{0,0,0,0,0,0}}},
    /* [1] */
    {{{0x07089552b319d465ULL, 0xc6695f92b50a8313ULL,
       0x97e83cccd117228fULL, 0xa35baecab2dc29eeULL,
       0x1ce393ea5daace4dULL, 0x08f2220fb0fb66ebULL}},
     {{0xb2f66aad4ce5d646ULL, 0x5842a06bfc497cecULL,
       0xcf4895d42599d394ULL, 0xc11b9cba40a8e8d0ULL,
       0x2e3813cbe5a0de89ULL, 0x110eefda88847fafULL}}},
    /* [2] */
    {{{0xecfb361b798dba3aULL, 0xc100ddb891865a2cULL,
       0x0ec08ff1232bda8eULL, 0xd5c13cc6f1ca4721ULL,
       0x47222a47bf7b5c04ULL, 0x0110f184e51c5f59ULL}},
     {{0,0,0,0,0,0}}},
    /* [3] */
    {{{0x3e2f585da55c9ad1ULL, 0x4294213d86c18183ULL,
       0x382844c88b623732ULL, 0x92ad2afd19103e18ULL,
       0x1d794e4fac7cf0b9ULL, 0x0bd592fc7d825ec8ULL}},
     {{0x7bcfa7a25aa30fdaULL, 0xdc17dec12a927e7cULL,
       0x2f088dd86b4ebef1ULL, 0xd1ca2087da74d4a7ULL,
       0x2da2596696cebc1dULL, 0x0e2b7eedbbfd87d2ULL}}},
    /* [4] */
    {{{0x30f1361b798a64e8ULL, 0xf3b8ddab7ece5a2aULL,
       0x16a8ca3ac61577f7ULL, 0xc26a2ff874fd029bULL,
       0x3636b76660701c6eULL, 0x051ba4ab241b6160ULL}},
     {{0,0,0,0,0,0}}},
    /* [5] */
    {{{0x3726c30af242c66cULL, 0x7c2ac1aad1b6fe70ULL,
       0xa04007fbba4b14a2ULL, 0xef517c3266341429ULL,
       0x0095ba654ed2226bULL, 0x02e370eccc86f7ddULL}},
     {{0x82d83cf50dbce43fULL, 0xa2813e53df9d018fULL,
       0xc6f0caa53c65e181ULL, 0x7525cf528d50fe95ULL,
       0x4a85ed50f4798a6bULL, 0x171da0fd6cf8eebdULL}}},
    /* [6] = -1 */
    {{{0x43f5fffffffcaaaeULL, 0x32b7fff2ed47fffdULL,
       0x07e83a49a2e99d69ULL, 0xeca8f3318332bb7aULL,
       0xef148d1ea0f4c069ULL, 0x040ab3263eff0206ULL}},
     {{0,0,0,0,0,0}}},
    /* [7] */
    {{{0xb2f66aad4ce5d646ULL, 0x5842a06bfc497cecULL,
       0xcf4895d42599d394ULL, 0xc11b9cba40a8e8d0ULL,
       0x2e3813cbe5a0de89ULL, 0x110eefda88847fafULL}},
     {{0x07089552b319d465ULL, 0xc6695f92b50a8313ULL,
       0x97e83cccd117228fULL, 0xa35baecab2dc29eeULL,
       0x1ce393ea5daace4dULL, 0x08f2220fb0fb66ebULL}}},
    /* [8] */
    {{{0xcd03c9e48671f071ULL, 0x5dab22461fcda5d2ULL,
       0x587042afd3851b95ULL, 0x8eb60ebe01bacb9eULL,
       0x03f97d6e83d050d2ULL, 0x18f0206554638741ULL}},
     {{0,0,0,0,0,0}}},
    /* [9] */
    {{{0x7bcfa7a25aa30fdaULL, 0xdc17dec12a927e7cULL,
       0x2f088dd86b4ebef1ULL, 0xd1ca2087da74d4a7ULL,
       0x2da2596696cebc1dULL, 0x0e2b7eedbbfd87d2ULL}},
     {{0x3e2f585da55c9ad1ULL, 0x4294213d86c18183ULL,
       0x382844c88b623732ULL, 0x92ad2afd19103e18ULL,
       0x1d794e4fac7cf0b9ULL, 0x0bd592fc7d825ec8ULL}}},
    /* [10] */
    {{{0x890dc9e4867545c3ULL, 0x2af322533285a5d5ULL,
       0x50880866309b7e2cULL, 0xa20d1b8c7e881024ULL,
       0x14e4f04fe2db9068ULL, 0x14e56d3f1564853aULL}},
     {{0,0,0,0,0,0}}},
    /* [11] */
    {{{0x82d83cf50dbce43fULL, 0xa2813e53df9d018fULL,
       0xc6f0caa53c65e181ULL, 0x7525cf528d50fe95ULL,
       0x4a85ed50f4798a6bULL, 0x171da0fd6cf8eebdULL}},
     {{0x3726c30af242c66cULL, 0x7c2ac1aad1b6fe70ULL,
       0xa04007fbba4b14a2ULL, 0xef517c3266341429ULL,
       0x0095ba654ed2226bULL, 0x02e370eccc86f7ddULL}}}
};

/* ===== Fp6 = Fp2[v] / (v^3 - (u+1)) ===== */

void fp6_zero(struct fp6 *r) { fp2_zero(&r->c0); fp2_zero(&r->c1); fp2_zero(&r->c2); }
void fp6_one(struct fp6 *r) { fp2_one(&r->c0); fp2_zero(&r->c1); fp2_zero(&r->c2); }
bool fp6_is_zero(const struct fp6 *a) { return fp2_is_zero(&a->c0) && fp2_is_zero(&a->c1) && fp2_is_zero(&a->c2); }

void fp6_add(struct fp6 *r, const struct fp6 *a, const struct fp6 *b)
{
    fp2_add(&r->c0, &a->c0, &b->c0);
    fp2_add(&r->c1, &a->c1, &b->c1);
    fp2_add(&r->c2, &a->c2, &b->c2);
}

void fp6_sub(struct fp6 *r, const struct fp6 *a, const struct fp6 *b)
{
    fp2_sub(&r->c0, &a->c0, &b->c0);
    fp2_sub(&r->c1, &a->c1, &b->c1);
    fp2_sub(&r->c2, &a->c2, &b->c2);
}

void fp6_neg(struct fp6 *r, const struct fp6 *a)
{
    fp2_neg(&r->c0, &a->c0);
    fp2_neg(&r->c1, &a->c1);
    fp2_neg(&r->c2, &a->c2);
}

/* Multiply by v: (c0, c1, c2) -> (c2*beta, c0, c1) where beta = (1+u) */
void fp6_mul_by_nonresidue(struct fp6 *r, const struct fp6 *a)
{
    struct fp2 t = a->c2;
    fp2_mul_by_nonresidue(&t, &a->c2);
    r->c2 = a->c1;
    r->c1 = a->c0;
    r->c0 = t;
}

void fp6_mul(struct fp6 *r, const struct fp6 *a, const struct fp6 *b)
{
    struct fp2 aa, bb, cc;
    fp2_mul(&aa, &a->c0, &b->c0);
    fp2_mul(&bb, &a->c1, &b->c1);
    fp2_mul(&cc, &a->c2, &b->c2);

    /* t1 = ((b1+b2)*(a1+a2) - bb - cc) * beta + aa */
    struct fp2 t1, tmp;
    fp2_add(&t1, &b->c1, &b->c2);
    fp2_add(&tmp, &a->c1, &a->c2);
    fp2_mul(&t1, &t1, &tmp);
    fp2_sub(&t1, &t1, &bb);
    fp2_sub(&t1, &t1, &cc);
    fp2_mul_by_nonresidue(&t1, &t1);
    fp2_add(&t1, &t1, &aa);

    /* t3 = (b0+b2)*(a0+a2) - aa + bb - cc */
    struct fp2 t3;
    fp2_add(&t3, &b->c0, &b->c2);
    fp2_add(&tmp, &a->c0, &a->c2);
    fp2_mul(&t3, &t3, &tmp);
    fp2_sub(&t3, &t3, &aa);
    fp2_add(&t3, &t3, &bb);
    fp2_sub(&t3, &t3, &cc);

    /* t2 = (b0+b1)*(a0+a1) - aa - bb + cc*beta */
    struct fp2 t2;
    fp2_add(&t2, &b->c0, &b->c1);
    fp2_add(&tmp, &a->c0, &a->c1);
    fp2_mul(&t2, &t2, &tmp);
    fp2_sub(&t2, &t2, &aa);
    fp2_sub(&t2, &t2, &bb);
    struct fp2 cc_nr;
    fp2_mul_by_nonresidue(&cc_nr, &cc);
    fp2_add(&t2, &t2, &cc_nr);

    r->c0 = t1;
    r->c1 = t2;
    r->c2 = t3;
}

void fp6_sq(struct fp6 *r, const struct fp6 *a)
{
    struct fp2 s0, ab, s1, s2, bc, s3, s4;

    fp2_sq(&s0, &a->c0);
    fp2_mul(&ab, &a->c0, &a->c1);
    fp2_add(&s1, &ab, &ab);

    struct fp2 t;
    fp2_sub(&t, &a->c0, &a->c1);
    fp2_add(&s2, &t, &a->c2);
    fp2_sq(&s2, &s2);

    fp2_mul(&bc, &a->c1, &a->c2);
    fp2_add(&s3, &bc, &bc);

    fp2_sq(&s4, &a->c2);

    /* c0 = s3 * beta + s0 */
    fp2_mul_by_nonresidue(&r->c0, &s3);
    fp2_add(&r->c0, &r->c0, &s0);

    /* c1 = s4 * beta + s1 */
    fp2_mul_by_nonresidue(&r->c1, &s4);
    fp2_add(&r->c1, &r->c1, &s1);

    /* c2 = s1 + s2 + s3 - s0 - s4 */
    fp2_add(&r->c2, &s1, &s2);
    fp2_add(&r->c2, &r->c2, &s3);
    fp2_sub(&r->c2, &r->c2, &s0);
    fp2_sub(&r->c2, &r->c2, &s4);
}

void fp6_inv(struct fp6 *r, const struct fp6 *a)
{
    /* c0 = a2*a1*beta - a0^2, negated later */
    struct fp2 c0, c1, c2;

    /* c0 = a2*beta*a1, negated, + a0^2 */
    struct fp2 tmp;
    fp2_mul_by_nonresidue(&tmp, &a->c2);
    fp2_mul(&c0, &tmp, &a->c1);
    fp2_neg(&c0, &c0);
    struct fp2 a0s;
    fp2_sq(&a0s, &a->c0);
    fp2_add(&c0, &c0, &a0s);

    /* c1 = a2^2 * beta - a0*a1 */
    fp2_sq(&c1, &a->c2);
    fp2_mul_by_nonresidue(&c1, &c1);
    fp2_mul(&tmp, &a->c0, &a->c1);
    fp2_sub(&c1, &c1, &tmp);

    /* c2 = a1^2 - a0*a2 */
    fp2_sq(&c2, &a->c1);
    fp2_mul(&tmp, &a->c0, &a->c2);
    fp2_sub(&c2, &c2, &tmp);

    /* tmp1 = a2*c1 + a1*c2, tmp1 *= beta, tmp1 += a0*c0 */
    struct fp2 tmp1, tmp2;
    fp2_mul(&tmp1, &a->c2, &c1);
    fp2_mul(&tmp2, &a->c1, &c2);
    fp2_add(&tmp1, &tmp1, &tmp2);
    fp2_mul_by_nonresidue(&tmp1, &tmp1);
    fp2_mul(&tmp2, &a->c0, &c0);
    fp2_add(&tmp1, &tmp1, &tmp2);

    struct fp2 inv;
    fp2_inv(&inv, &tmp1);

    fp2_mul(&r->c0, &c0, &inv);
    fp2_mul(&r->c1, &c1, &inv);
    fp2_mul(&r->c2, &c2, &inv);
}

/* Multiply Fp6 element by (0, c1, 0) */
void fp6_mul_by_1(struct fp6 *r, const struct fp6 *a, const struct fp2 *c1)
{
    struct fp2 bb;
    fp2_mul(&bb, &a->c1, c1);

    struct fp2 t1, tmp;
    fp2_add(&tmp, &a->c1, &a->c2);
    fp2_mul(&t1, c1, &tmp);
    fp2_sub(&t1, &t1, &bb);
    fp2_mul_by_nonresidue(&t1, &t1);

    struct fp2 t2;
    fp2_add(&tmp, &a->c0, &a->c1);
    fp2_mul(&t2, c1, &tmp);
    fp2_sub(&t2, &t2, &bb);

    r->c0 = t1;
    r->c1 = t2;
    r->c2 = bb;
}

/* Multiply Fp6 element by (c0, c1, 0) */
void fp6_mul_by_01(struct fp6 *r, const struct fp6 *a, const struct fp2 *c0, const struct fp2 *c1)
{
    struct fp2 aa, bb;
    fp2_mul(&aa, &a->c0, c0);
    fp2_mul(&bb, &a->c1, c1);

    struct fp2 t1, tmp;
    fp2_add(&tmp, &a->c1, &a->c2);
    fp2_mul(&t1, c1, &tmp);
    fp2_sub(&t1, &t1, &bb);
    fp2_mul_by_nonresidue(&t1, &t1);
    fp2_add(&t1, &t1, &aa);

    struct fp2 t3;
    fp2_add(&tmp, &a->c0, &a->c2);
    fp2_mul(&t3, c0, &tmp);
    fp2_sub(&t3, &t3, &aa);
    fp2_add(&t3, &t3, &bb);

    struct fp2 t2, c01;
    fp2_add(&c01, c0, c1);
    fp2_add(&tmp, &a->c0, &a->c1);
    fp2_mul(&t2, &c01, &tmp);
    fp2_sub(&t2, &t2, &aa);
    fp2_sub(&t2, &t2, &bb);

    r->c0 = t1;
    r->c1 = t2;
    r->c2 = t3;
}

void fp6_frobenius_map(struct fp6 *a, int power)
{
    fp2_frobenius_map(&a->c0, power);
    fp2_frobenius_map(&a->c1, power);
    fp2_frobenius_map(&a->c2, power);

    fp2_mul(&a->c1, &a->c1, &FROB_FQ6_C1[power % 6]);
    fp2_mul(&a->c2, &a->c2, &FROB_FQ6_C2[power % 6]);
}

/* ===== Fp12 = Fp6[w] / (w^2 - v) ===== */

void fp12_zero(struct fp12 *r) { fp6_zero(&r->c0); fp6_zero(&r->c1); }
void fp12_one(struct fp12 *r) { fp6_one(&r->c0); fp6_zero(&r->c1); }
bool fp12_is_zero(const struct fp12 *a) { return fp6_is_zero(&a->c0) && fp6_is_zero(&a->c1); }

void fp12_add(struct fp12 *r, const struct fp12 *a, const struct fp12 *b)
{
    fp6_add(&r->c0, &a->c0, &b->c0);
    fp6_add(&r->c1, &a->c1, &b->c1);
}

void fp12_sub(struct fp12 *r, const struct fp12 *a, const struct fp12 *b)
{
    fp6_sub(&r->c0, &a->c0, &b->c0);
    fp6_sub(&r->c1, &a->c1, &b->c1);
}

void fp12_neg(struct fp12 *r, const struct fp12 *a)
{
    fp6_neg(&r->c0, &a->c0);
    fp6_neg(&r->c1, &a->c1);
}

void fp12_mul(struct fp12 *r, const struct fp12 *a, const struct fp12 *b)
{
    struct fp6 aa, bb;
    fp6_mul(&aa, &a->c0, &b->c0);
    fp6_mul(&bb, &a->c1, &b->c1);

    struct fp6 o;
    fp6_add(&o, &b->c0, &b->c1);

    struct fp6 c1_tmp;
    fp6_add(&c1_tmp, &a->c1, &a->c0);
    fp6_mul(&r->c1, &c1_tmp, &o);
    fp6_sub(&r->c1, &r->c1, &aa);
    fp6_sub(&r->c1, &r->c1, &bb);

    struct fp6 bb_nr;
    fp6_mul_by_nonresidue(&bb_nr, &bb);
    fp6_add(&r->c0, &bb_nr, &aa);
}

void fp12_sq(struct fp12 *r, const struct fp12 *a)
{
    struct fp6 ab;
    fp6_mul(&ab, &a->c0, &a->c1);

    struct fp6 c0c1;
    fp6_add(&c0c1, &a->c0, &a->c1);

    struct fp6 c0_tmp;
    fp6_mul_by_nonresidue(&c0_tmp, &a->c1);
    fp6_add(&c0_tmp, &c0_tmp, &a->c0);
    fp6_mul(&c0_tmp, &c0_tmp, &c0c1);
    fp6_sub(&c0_tmp, &c0_tmp, &ab);

    r->c1 = ab;
    fp6_add(&r->c1, &r->c1, &ab);

    struct fp6 ab_nr;
    fp6_mul_by_nonresidue(&ab_nr, &ab);
    fp6_sub(&r->c0, &c0_tmp, &ab_nr);
}

void fp12_inv(struct fp12 *r, const struct fp12 *a)
{
    struct fp6 c0s, c1s;
    fp6_sq(&c0s, &a->c0);
    fp6_sq(&c1s, &a->c1);
    fp6_mul_by_nonresidue(&c1s, &c1s);
    fp6_sub(&c0s, &c0s, &c1s);

    struct fp6 t;
    fp6_inv(&t, &c0s);

    fp6_mul(&r->c0, &a->c0, &t);
    fp6_mul(&r->c1, &a->c1, &t);
    fp6_neg(&r->c1, &r->c1);
}

void fp12_conjugate(struct fp12 *a)
{
    fp6_neg(&a->c1, &a->c1);
}

void fp12_frobenius_map(struct fp12 *a, int power)
{
    fp6_frobenius_map(&a->c0, power);
    fp6_frobenius_map(&a->c1, power);

    const struct fp2 *coeff = &FROB_FQ12_C1[power % 12];
    fp2_mul(&a->c1.c0, &a->c1.c0, coeff);
    fp2_mul(&a->c1.c1, &a->c1.c1, coeff);
    fp2_mul(&a->c1.c2, &a->c1.c2, coeff);
}

void fp12_mul_by_014(struct fp12 *f, const struct fp2 *c0, const struct fp2 *c1, const struct fp2 *c4)
{
    struct fp6 aa, bb;
    fp6_mul_by_01(&aa, &f->c0, c0, c1);
    fp6_mul_by_1(&bb, &f->c1, c4);

    struct fp2 o;
    fp2_add(&o, c1, c4);

    struct fp6 t;
    fp6_add(&t, &f->c1, &f->c0);
    fp6_mul_by_01(&t, &t, c0, &o);
    fp6_sub(&t, &t, &aa);
    fp6_sub(&t, &t, &bb);
    f->c1 = t;

    struct fp6 bb_nr;
    fp6_mul_by_nonresidue(&bb_nr, &bb);
    fp6_add(&f->c0, &bb_nr, &aa);
}

void fp12_pow_u64(struct fp12 *r, const struct fp12 *a, uint64_t exp)
{
    struct fp12 result;
    fp12_one(&result);
    struct fp12 base = *a;

    while (exp > 0) {
        if (exp & 1)
            fp12_mul(&result, &result, &base);
        fp12_sq(&base, &base);
        exp >>= 1;
    }
    *r = result;
}

/* Fp4 squaring helper for Granger-Scott: (a + b*s)^2 with s^2 = v-nonresidue. */
static void fp4_square(struct fp2 *c0, struct fp2 *c1, const struct fp2 *a, const struct fp2 *b)
{
    struct fp2 t0, t1, t2;
    fp2_sq(&t0, a);
    fp2_sq(&t1, b);
    fp2_mul_by_nonresidue(&t2, &t1);
    fp2_add(c0, &t2, &t0);
    fp2_add(&t2, a, b);
    fp2_sq(&t2, &t2);
    fp2_sub(&t2, &t2, &t0);
    fp2_sub(c1, &t2, &t1);
}

/* z = 3*t - 2*z (the "minus" lane) or 3*t + 2*z (the "plus" lane). */
static void gs_lane(struct fp2 *z, const struct fp2 *t, bool minus)
{
    struct fp2 u;
    if (minus)
        fp2_sub(&u, t, z);
    else
        fp2_add(&u, t, z);
    fp2_add(&u, &u, &u);
    fp2_add(z, &u, t);
}

/* Granger-Scott squaring. Valid ONLY for a in the cyclotomic subgroup
 * (norm to Fp6 is 1), where it equals fp12_sq(a). Public-constant callers
 * only: no secret-dependent control flow. */
void fp12_cyclotomic_sq(struct fp12 *r, const struct fp12 *a)
{
    struct fp2 z0 = a->c0.c0, z4 = a->c0.c1, z3 = a->c0.c2;
    struct fp2 z2 = a->c1.c0, z1 = a->c1.c1, z5 = a->c1.c2;
    struct fp2 t0, t1, t2, t3, t;

    fp4_square(&t0, &t1, &z0, &z1);
    gs_lane(&z0, &t0, true);
    gs_lane(&z1, &t1, false);

    fp4_square(&t0, &t1, &z2, &z3);
    fp4_square(&t2, &t3, &z4, &z5);
    gs_lane(&z4, &t0, true);
    gs_lane(&z5, &t1, false);

    fp2_mul_by_nonresidue(&t, &t3);
    gs_lane(&z2, &t, false);
    gs_lane(&z3, &t2, true);

    r->c0.c0 = z0; r->c0.c1 = z4; r->c0.c2 = z3;
    r->c1.c0 = z2; r->c1.c1 = z1; r->c1.c2 = z5;
}

/* a^BLS_X-style exponentiation for a in the cyclotomic subgroup: MSB-first
 * square-and-multiply with cyclotomic squaring. exp is a public constant. */
static void fp12_cyclotomic_exp(struct fp12 *r, const struct fp12 *a, uint64_t exp)
{
    struct fp12 acc = *a;
    for (int i = 62 - __builtin_clzll(exp); i >= 0; i--) {
        fp12_cyclotomic_sq(&acc, &acc);
        if ((exp >> i) & 1)
            fp12_mul(&acc, &acc, a);
    }
    *r = acc;
}

/* ===== G1 point operations (Jacobian, y^2 = x^3 + 4) ===== */

/* B coefficient = 4 in Montgomery form */
static const struct fp G1_B = {{
    0xaa270000000cfff3ULL, 0x53cc0032fc34000aULL,
    0x478fe97a6b0a807fULL, 0xb1d37ebee6ba24d7ULL,
    0x8ec9733bbf78ab2fULL, 0x09d645513d83de7eULL
}};

/* Generator of G1 in Montgomery form (used by g1_generator) */
const struct fp G1_GEN_X = {{
    0x5cb38790fd530c16ULL, 0x7817fc679976fff5ULL,
    0x154f95c7143ba1c1ULL, 0xf0ae6acdf3d0e747ULL,
    0xedce6ecc21dbf440ULL, 0x120177419e0bfb75ULL
}};
const struct fp G1_GEN_Y = {{
    0xbaac93d50ce72271ULL, 0x8c22631a7918fd8eULL,
    0xdd595f13570725ceULL, 0x51ac582950405194ULL,
    0x0e1c8c3fad0059c0ULL, 0x0bbc3efc5008a26aULL
}};

void g1_identity(struct g1_point *p)
{
    fp_zero(&p->x);
    fp_one(&p->y);
    fp_zero(&p->z);
}

bool g1_is_identity(const struct g1_point *p)
{
    return fp_is_zero(&p->z);
}

void g1_neg(struct g1_point *r, const struct g1_point *p)
{
    r->x = p->x;
    fp_neg(&r->y, &p->y);
    r->z = p->z;
}

void g1_double(struct g1_point *r, const struct g1_point *p)
{
    if (g1_is_identity(p)) { *r = *p; return; }

    struct fp a, b, c, d, e, f;
    fp_sq(&a, &p->x);
    fp_sq(&b, &p->y);
    fp_sq(&c, &b);

    fp_add(&d, &p->x, &b);
    fp_sq(&d, &d);
    fp_sub(&d, &d, &a);
    fp_sub(&d, &d, &c);
    fp_add(&d, &d, &d);

    fp_add(&e, &a, &a);
    fp_add(&e, &e, &a);

    fp_sq(&f, &e);

    fp_mul(&r->z, &p->y, &p->z);
    fp_add(&r->z, &r->z, &r->z);

    fp_sub(&r->x, &f, &d);
    fp_sub(&r->x, &r->x, &d);

    fp_sub(&r->y, &d, &r->x);
    fp_mul(&r->y, &r->y, &e);
    fp_add(&c, &c, &c);
    fp_add(&c, &c, &c);
    fp_add(&c, &c, &c);
    fp_sub(&r->y, &r->y, &c);
}

void g1_add(struct g1_point *r, const struct g1_point *a, const struct g1_point *b)
{
    if (g1_is_identity(a)) { *r = *b; return; }
    if (g1_is_identity(b)) { *r = *a; return; }

    struct fp z1z1, z2z2, u1, u2, s1, s2;
    fp_sq(&z1z1, &a->z);
    fp_sq(&z2z2, &b->z);
    fp_mul(&u1, &a->x, &z2z2);
    fp_mul(&u2, &b->x, &z1z1);
    fp_mul(&s1, &a->y, &b->z);
    fp_mul(&s1, &s1, &z2z2);
    fp_mul(&s2, &b->y, &a->z);
    fp_mul(&s2, &s2, &z1z1);

    if (fp_eq(&u1, &u2) && fp_eq(&s1, &s2)) {
        g1_double(r, a);
        return;
    }

    struct fp h, i, j, rr, v;
    fp_sub(&h, &u2, &u1);
    fp_add(&i, &h, &h);
    fp_sq(&i, &i);
    fp_mul(&j, &h, &i);
    fp_sub(&rr, &s2, &s1);
    fp_add(&rr, &rr, &rr);
    fp_mul(&v, &u1, &i);

    fp_sq(&r->x, &rr);
    fp_sub(&r->x, &r->x, &j);
    fp_sub(&r->x, &r->x, &v);
    fp_sub(&r->x, &r->x, &v);

    fp_sub(&r->y, &v, &r->x);
    fp_mul(&r->y, &r->y, &rr);
    fp_mul(&s1, &s1, &j);
    fp_add(&s1, &s1, &s1);
    fp_sub(&r->y, &r->y, &s1);

    fp_add(&r->z, &a->z, &b->z);
    fp_sq(&r->z, &r->z);
    fp_sub(&r->z, &r->z, &z1z1);
    fp_sub(&r->z, &r->z, &z2z2);
    fp_mul(&r->z, &r->z, &h);
}

void g1_to_affine(struct fp *ax, struct fp *ay, const struct g1_point *p)
{
    struct fp zinv;
    fp_inv(&zinv, &p->z);
    struct fp zinv2;
    fp_sq(&zinv2, &zinv);
    fp_mul(ax, &p->x, &zinv2);
    struct fp zinv3;
    fp_mul(&zinv3, &zinv2, &zinv);
    fp_mul(ay, &p->y, &zinv3);
}

bool g1_from_compressed(struct g1_point *p, const uint8_t in[48])
{
    uint8_t copy[48];
    memcpy(copy, in, 48);

    bool compressed = (copy[0] >> 7) & 1;
    bool infinity = (copy[0] >> 6) & 1;
    bool greatest = (copy[0] >> 5) & 1;
    copy[0] &= 0x1f;

    if (!compressed) return false;

    if (infinity) {
        g1_identity(p);
        return true;
    }

    struct fp x;
    if (!fp_from_bytes(&x, copy)) return false;

    /* y^2 = x^3 + 4 */
    struct fp x3b;
    fp_sq(&x3b, &x);
    fp_mul(&x3b, &x3b, &x);
    fp_add(&x3b, &x3b, &G1_B);

    struct fp y;
    if (!fp_sqrt(&y, &x3b)) return false;

    struct fp negy;
    fp_neg(&negy, &y);

    bool y_largest = fp_lexicographically_largest(&y);
    if (y_largest != greatest)
        y = negy;

    p->x = x;
    p->y = y;
    fp_one(&p->z);
    return true;
}

bool g1_from_uncompressed(struct g1_point *p, const uint8_t in[96])
{
    uint8_t copy[96];
    memcpy(copy, in, 96);

    bool compressed = (copy[0] >> 7) & 1;
    bool infinity = (copy[0] >> 6) & 1;
    copy[0] &= 0x1f;

    if (compressed) return false;

    if (infinity) {
        g1_identity(p);
        return true;
    }

    struct fp x, y;
    if (!fp_from_bytes(&x, copy)) return false;
    if (!fp_from_bytes(&y, copy + 48)) return false;

    /* Verify on curve: y^2 == x^3 + 4 */
    struct fp lhs, rhs;
    fp_sq(&lhs, &y);
    fp_sq(&rhs, &x);
    fp_mul(&rhs, &rhs, &x);
    fp_add(&rhs, &rhs, &G1_B);
    if (!fp_eq(&lhs, &rhs)) return false;

    p->x = x;
    p->y = y;
    fp_one(&p->z);
    return true;
}

/* ===== G2 point operations (Jacobian, y^2 = x^3 + 4(u+1)) ===== */

/* B coefficient for G2 = 4*(1+u) in Montgomery form */
static const struct fp2 G2_B = {
    {{0xaa270000000cfff3ULL, 0x53cc0032fc34000aULL,
      0x478fe97a6b0a807fULL, 0xb1d37ebee6ba24d7ULL,
      0x8ec9733bbf78ab2fULL, 0x09d645513d83de7eULL}},
    {{0xaa270000000cfff3ULL, 0x53cc0032fc34000aULL,
      0x478fe97a6b0a807fULL, 0xb1d37ebee6ba24d7ULL,
      0x8ec9733bbf78ab2fULL, 0x09d645513d83de7eULL}}
};

void g2_identity(struct g2_point *p)
{
    fp2_zero(&p->x);
    fp2_one(&p->y);
    fp2_zero(&p->z);
}

bool g2_is_identity(const struct g2_point *p)
{
    return fp2_is_zero(&p->z);
}

void g2_neg(struct g2_point *r, const struct g2_point *p)
{
    r->x = p->x;
    fp2_neg(&r->y, &p->y);
    r->z = p->z;
}

void g2_double(struct g2_point *r, const struct g2_point *p)
{
    if (g2_is_identity(p)) { *r = *p; return; }

    struct fp2 a, b, c, d, e, f;
    fp2_sq(&a, &p->x);
    fp2_sq(&b, &p->y);
    fp2_sq(&c, &b);

    fp2_add(&d, &p->x, &b);
    fp2_sq(&d, &d);
    fp2_sub(&d, &d, &a);
    fp2_sub(&d, &d, &c);
    fp2_add(&d, &d, &d);

    fp2_add(&e, &a, &a);
    fp2_add(&e, &e, &a);

    fp2_sq(&f, &e);

    fp2_mul(&r->z, &p->y, &p->z);
    fp2_add(&r->z, &r->z, &r->z);

    fp2_sub(&r->x, &f, &d);
    fp2_sub(&r->x, &r->x, &d);

    fp2_sub(&r->y, &d, &r->x);
    fp2_mul(&r->y, &r->y, &e);
    fp2_add(&c, &c, &c);
    fp2_add(&c, &c, &c);
    fp2_add(&c, &c, &c);
    fp2_sub(&r->y, &r->y, &c);
}

void g2_add(struct g2_point *r, const struct g2_point *a, const struct g2_point *b)
{
    if (g2_is_identity(a)) { *r = *b; return; }
    if (g2_is_identity(b)) { *r = *a; return; }

    struct fp2 z1z1, z2z2, u1, u2, s1, s2;
    fp2_sq(&z1z1, &a->z);
    fp2_sq(&z2z2, &b->z);
    fp2_mul(&u1, &a->x, &z2z2);
    fp2_mul(&u2, &b->x, &z1z1);
    fp2_mul(&s1, &a->y, &b->z);
    fp2_mul(&s1, &s1, &z2z2);
    fp2_mul(&s2, &b->y, &a->z);
    fp2_mul(&s2, &s2, &z1z1);

    if (fp2_eq(&u1, &u2) && fp2_eq(&s1, &s2)) {
        g2_double(r, a);
        return;
    }

    struct fp2 h, i, j, rr, v;
    fp2_sub(&h, &u2, &u1);
    fp2_add(&i, &h, &h);
    fp2_sq(&i, &i);
    fp2_mul(&j, &h, &i);
    fp2_sub(&rr, &s2, &s1);
    fp2_add(&rr, &rr, &rr);
    fp2_mul(&v, &u1, &i);

    fp2_sq(&r->x, &rr);
    fp2_sub(&r->x, &r->x, &j);
    fp2_sub(&r->x, &r->x, &v);
    fp2_sub(&r->x, &r->x, &v);

    fp2_sub(&r->y, &v, &r->x);
    fp2_mul(&r->y, &r->y, &rr);
    fp2_mul(&s1, &s1, &j);
    fp2_add(&s1, &s1, &s1);
    fp2_sub(&r->y, &r->y, &s1);

    fp2_add(&r->z, &a->z, &b->z);
    fp2_sq(&r->z, &r->z);
    fp2_sub(&r->z, &r->z, &z1z1);
    fp2_sub(&r->z, &r->z, &z2z2);
    fp2_mul(&r->z, &r->z, &h);
}

void g2_to_affine(struct fp2 *ax, struct fp2 *ay, const struct g2_point *p)
{
    struct fp2 zinv;
    fp2_inv(&zinv, &p->z);
    struct fp2 zinv2;
    fp2_sq(&zinv2, &zinv);
    fp2_mul(ax, &p->x, &zinv2);
    struct fp2 zinv3;
    fp2_mul(&zinv3, &zinv2, &zinv);
    fp2_mul(ay, &p->y, &zinv3);
}

bool g2_from_compressed(struct g2_point *p, const uint8_t in[96])
{
    uint8_t copy[96];
    memcpy(copy, in, 96);

    bool compressed = (copy[0] >> 7) & 1;
    bool infinity = (copy[0] >> 6) & 1;
    bool greatest = (copy[0] >> 5) & 1;
    copy[0] &= 0x1f;

    if (!compressed) return false;

    if (infinity) {
        g2_identity(p);
        return true;
    }

    /* Fp2 x: c1 is in first 48 bytes, c0 in next 48 bytes */
    struct fp2 x;
    if (!fp_from_bytes(&x.c1, copy)) return false;
    if (!fp_from_bytes(&x.c0, copy + 48)) return false;

    /* y^2 = x^3 + 4(1+u) */
    struct fp2 x3b;
    fp2_sq(&x3b, &x);
    fp2_mul(&x3b, &x3b, &x);
    fp2_add(&x3b, &x3b, &G2_B);

    struct fp2 y;
    if (!fp2_sqrt(&y, &x3b)) return false;

    struct fp2 negy;
    fp2_neg(&negy, &y);

    bool y_largest = fp2_lexicographically_largest(&y);
    if (y_largest != greatest)
        y = negy;

    p->x = x;
    p->y = y;
    fp2_one(&p->z);
    return true;
}

bool g2_from_uncompressed(struct g2_point *p, const uint8_t in[192])
{
    uint8_t copy[192];
    memcpy(copy, in, 192);

    bool compressed = (copy[0] >> 7) & 1;
    bool infinity = (copy[0] >> 6) & 1;
    copy[0] &= 0x1f;

    if (compressed) return false;

    if (infinity) {
        g2_identity(p);
        return true;
    }

    /* Fp2 x: c1 first 48 bytes, c0 next 48 */
    struct fp2 x, y;
    if (!fp_from_bytes(&x.c1, copy)) return false;
    if (!fp_from_bytes(&x.c0, copy + 48)) return false;
    if (!fp_from_bytes(&y.c1, copy + 96)) return false;
    if (!fp_from_bytes(&y.c0, copy + 144)) return false;

    /* Verify: y^2 == x^3 + 4(1+u) */
    struct fp2 lhs, rhs;
    fp2_sq(&lhs, &y);
    fp2_sq(&rhs, &x);
    fp2_mul(&rhs, &rhs, &x);
    fp2_add(&rhs, &rhs, &G2_B);
    if (!fp2_eq(&lhs, &rhs)) return false;

    p->x = x;
    p->y = y;
    fp2_one(&p->z);
    return true;
}

/* ===== Optimal Ate pairing ===== */

/* BLS parameter x = -0xd201000000010000 */
#define BLS_X 0xd201000000010000ULL

/* Fr modulus is 255-bit, so a BLS12-381 scalar safely holds 254 bits of
 * payload. Must be 254: 253 would mis-pack bit 253 of the nullifier into
 * the wrong packed scalar, breaking Sapling Groth16 verification. Used by
 * both multipack_bytes_to_fr variants. */
#define BLS12_381_FR_CAPACITY 254

/* Doubling step for Miller loop (Algorithm 26 from https://eprint.iacr.org/2010/354.pdf) */
static void doubling_step(struct g2_point *r, struct fp2 *c0, struct fp2 *c1, struct fp2 *c2)
{
    struct fp2 tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, zsquared;

    fp2_sq(&tmp0, &r->x);
    fp2_sq(&tmp1, &r->y);
    fp2_sq(&tmp2, &tmp1);

    fp2_add(&tmp3, &tmp1, &r->x);
    fp2_sq(&tmp3, &tmp3);
    fp2_sub(&tmp3, &tmp3, &tmp0);
    fp2_sub(&tmp3, &tmp3, &tmp2);
    fp2_add(&tmp3, &tmp3, &tmp3);

    fp2_add(&tmp4, &tmp0, &tmp0);
    fp2_add(&tmp4, &tmp4, &tmp0);

    fp2_add(&tmp6, &r->x, &tmp4);

    fp2_sq(&tmp5, &tmp4);

    fp2_sq(&zsquared, &r->z);

    r->x = tmp5;
    fp2_sub(&r->x, &r->x, &tmp3);
    fp2_sub(&r->x, &r->x, &tmp3);

    fp2_add(&r->z, &r->y, &r->z);
    fp2_sq(&r->z, &r->z);
    fp2_sub(&r->z, &r->z, &tmp1);
    fp2_sub(&r->z, &r->z, &zsquared);

    r->y = tmp3;
    fp2_sub(&r->y, &r->y, &r->x);
    fp2_mul(&r->y, &r->y, &tmp4);

    fp2_add(&tmp2, &tmp2, &tmp2);
    fp2_add(&tmp2, &tmp2, &tmp2);
    fp2_add(&tmp2, &tmp2, &tmp2);
    fp2_sub(&r->y, &r->y, &tmp2);

    fp2_mul(&tmp3, &tmp4, &zsquared);
    fp2_add(&tmp3, &tmp3, &tmp3);
    fp2_neg(&tmp3, &tmp3);

    fp2_sq(&tmp6, &tmp6);
    fp2_sub(&tmp6, &tmp6, &tmp0);
    fp2_sub(&tmp6, &tmp6, &tmp5);
    fp2_add(&tmp1, &tmp1, &tmp1);
    fp2_add(&tmp1, &tmp1, &tmp1);
    fp2_sub(&tmp6, &tmp6, &tmp1);

    fp2_mul(&tmp0, &r->z, &zsquared);
    fp2_add(&tmp0, &tmp0, &tmp0);

    *c0 = tmp0;
    *c1 = tmp3;
    *c2 = tmp6;
}

/* Addition step for Miller loop (Algorithm 27) */
static void addition_step(struct g2_point *r, const struct fp2 *qx, const struct fp2 *qy,
                           struct fp2 *c0, struct fp2 *c1, struct fp2 *c2)
{
    struct fp2 zsquared, ysquared, t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10;

    fp2_sq(&zsquared, &r->z);
    fp2_sq(&ysquared, qy);

    fp2_mul(&t0, &zsquared, qx);

    fp2_add(&t1, qy, &r->z);
    fp2_sq(&t1, &t1);
    fp2_sub(&t1, &t1, &ysquared);
    fp2_sub(&t1, &t1, &zsquared);
    fp2_mul(&t1, &t1, &zsquared);

    fp2_sub(&t2, &t0, &r->x);

    fp2_sq(&t3, &t2);

    fp2_add(&t4, &t3, &t3);
    fp2_add(&t4, &t4, &t4);

    fp2_mul(&t5, &t4, &t2);

    fp2_sub(&t6, &t1, &r->y);
    fp2_sub(&t6, &t6, &r->y);

    fp2_mul(&t9, &t6, qx);

    fp2_mul(&t7, &t4, &r->x);

    fp2_sq(&r->x, &t6);
    fp2_sub(&r->x, &r->x, &t5);
    fp2_sub(&r->x, &r->x, &t7);
    fp2_sub(&r->x, &r->x, &t7);

    fp2_add(&r->z, &r->z, &t2);
    fp2_sq(&r->z, &r->z);
    fp2_sub(&r->z, &r->z, &zsquared);
    fp2_sub(&r->z, &r->z, &t3);

    fp2_add(&t10, qy, &r->z);

    fp2_sub(&t8, &t7, &r->x);
    fp2_mul(&t8, &t8, &t6);

    fp2_mul(&t0, &r->y, &t5);
    fp2_add(&t0, &t0, &t0);

    r->y = t8;
    fp2_sub(&r->y, &r->y, &t0);

    fp2_sq(&t10, &t10);
    fp2_sub(&t10, &t10, &ysquared);
    struct fp2 ztsquared;
    fp2_sq(&ztsquared, &r->z);
    fp2_sub(&t10, &t10, &ztsquared);

    fp2_add(&t9, &t9, &t9);
    fp2_sub(&t9, &t9, &t10);

    struct fp2 t10_out;
    t10_out = r->z;
    fp2_add(&t10_out, &t10_out, &t10_out);

    fp2_neg(&t6, &t6);
    struct fp2 t1_out;
    fp2_add(&t1_out, &t6, &t6);

    *c0 = t10_out;
    *c1 = t1_out;
    *c2 = t9;
}

/* Twist: apply line function evaluation to G1 affine point */
static void ell(struct fp12 *f, const struct fp2 *c0_coeff, const struct fp2 *c1_coeff,
                const struct fp2 *c2_coeff, const struct fp *px, const struct fp *py)
{
    struct fp2 c0_eval = *c0_coeff;
    struct fp2 c1_eval = *c1_coeff;

    /* c0 *= py (both components) */
    fp_mul(&c0_eval.c0, &c0_eval.c0, py);
    fp_mul(&c0_eval.c1, &c0_eval.c1, py);

    /* c1 *= px (both components) */
    fp_mul(&c1_eval.c0, &c1_eval.c0, px);
    fp_mul(&c1_eval.c1, &c1_eval.c1, px);

    fp12_mul_by_014(f, c2_coeff, &c1_eval, &c0_eval);
}

/* Miller loop only (no final exponentiation).
 * Returns the Miller loop result f for pairing(P, Q). */
void bls12_381_miller_loop(struct fp12 *result, const struct g1_point *p, const struct g2_point *q)
{
    if (g1_is_identity(p) || g2_is_identity(q)) {
        fp12_one(result);
        return;
    }

    /* Convert P to affine */
    struct fp px, py;
    g1_to_affine(&px, &py, p);

    /* Convert Q to affine for addition steps */
    struct fp2 qx, qy;
    g2_to_affine(&qx, &qy, q);

    /* Miller loop R starts at Q */
    struct g2_point r_point;
    r_point.x = qx;
    r_point.y = qy;
    fp2_one(&r_point.z);

    struct fp12 f;
    fp12_one(&f);

    /* Iterate over bits of BLS_X >> 1 = 0x6900800000008000 */
    uint64_t x_half = BLS_X >> 1;
    bool found_one = false;

    for (int i = 63; i >= 0; i--) {
        bool bit = (x_half >> i) & 1;
        if (!found_one) {
            found_one = bit;
            continue;
        }

        struct fp2 c0, c1, c2;
        doubling_step(&r_point, &c0, &c1, &c2);
        ell(&f, &c0, &c1, &c2, &px, &py);

        if (bit) {
            addition_step(&r_point, &qx, &qy, &c0, &c1, &c2);
            ell(&f, &c0, &c1, &c2, &px, &py);
        }

        fp12_sq(&f, &f);
    }

    /* Final doubling step */
    {
        struct fp2 c0, c1, c2;
        doubling_step(&r_point, &c0, &c1, &c2);
        ell(&f, &c0, &c1, &c2, &px, &py);
    }

    /* BLS_X is negative, so conjugate */
    fp12_conjugate(&f);
    *result = f;
}

/* Final exponentiation: f^((q^12 - 1) / r) */
void bls12_381_final_exp(struct fp12 *result, const struct fp12 *f_in)
{
    struct fp12 f = *f_in;

    /* Final exponentiation */
    /* Easy part: f = f^(q^6-1) * f^(q^2+1) */
    struct fp12 f1 = f;
    fp12_conjugate(&f1);

    struct fp12 f2;
    fp12_inv(&f2, &f);
    fp12_mul(&f, &f1, &f2);
    f2 = f;
    fp12_frobenius_map(&f, 2);
    fp12_mul(&f, &f, &f2);

    /* Hard part */
    struct fp12 y0, y1, y2, y3;

    struct fp12 r_save = f;

    fp12_sq(&y0, &f);

    fp12_cyclotomic_exp(&y1, &y0, BLS_X);
    fp12_conjugate(&y1); /* exp_by_x conjugates since BLS_X_IS_NEGATIVE */

    fp12_cyclotomic_exp(&y2, &y1, BLS_X >> 1);
    fp12_conjugate(&y2);

    y3 = r_save;
    fp12_conjugate(&y3);
    fp12_mul(&y1, &y1, &y3);
    fp12_conjugate(&y1);
    fp12_mul(&y1, &y1, &y2);

    fp12_cyclotomic_exp(&y2, &y1, BLS_X);
    fp12_conjugate(&y2);

    fp12_cyclotomic_exp(&y3, &y2, BLS_X);
    fp12_conjugate(&y3);

    fp12_conjugate(&y1);
    fp12_mul(&y3, &y3, &y1);

    fp12_conjugate(&y1);
    fp12_frobenius_map(&y1, 3);

    fp12_frobenius_map(&y2, 2);
    fp12_mul(&y1, &y1, &y2);

    fp12_cyclotomic_exp(&y2, &y3, BLS_X);
    fp12_conjugate(&y2);
    fp12_mul(&y2, &y2, &y0);
    fp12_mul(&y2, &y2, &r_save);
    fp12_mul(&y1, &y1, &y2);

    y2 = y3;
    fp12_frobenius_map(&y2, 1);
    fp12_mul(&y1, &y1, &y2);

    *result = y1;
}

void bls12_381_pairing(struct fp12 *result, const struct g1_point *p, const struct g2_point *q)
{
    struct fp12 ml;
    bls12_381_miller_loop(&ml, p, q);
    bls12_381_final_exp(result, &ml);
}

/* Multi-pairing: product of Miller loops, single final exponentiation.
 * Checks if product of pairings equals 1 in GT.
 * This is both faster and more numerically robust than computing
 * individual pairings and multiplying in GT. */
bool bls12_381_multi_pairing_check(const struct g1_point *a_pts, const struct g2_point *b_pts,
                                    size_t n_pairs)
{
    struct fp12 acc;
    fp12_one(&acc);

    /* Accumulate Miller loop products (before final exponentiation) */
    for (size_t i = 0; i < n_pairs; i++) {
        if (g1_is_identity(&a_pts[i]) || g2_is_identity(&b_pts[i]))
            continue;

        struct fp12 ml;
        bls12_381_miller_loop(&ml, &a_pts[i], &b_pts[i]);
        fp12_mul(&acc, &acc, &ml);
    }

    /* Single final exponentiation over the accumulated product */
    struct fp12 result;
    bls12_381_final_exp(&result, &acc);

    struct fp12 one;
    fp12_one(&one);
    return memcmp(&result, &one, sizeof(struct fp12)) == 0;
}


/* ===== Shared-f multi-Miller loop with precomputed G2 lines ===== */

/* Line coefficients (c0,c1,c2) of one fixed G2 point, in Miller-loop order:
 * per bit of BLS_X>>1 below the leading one a doubling line then, on a set
 * bit, an addition line; then the final doubling line. These are exactly the
 * values doubling_step/addition_step hand to ell() for that point. */
/* 62 doublings + 5 additions (popcount(BLS_X>>1) - 1) + the final doubling. */
#define ML_MAX_LINES 68

struct g2_lines {
    size_t n;
    struct fp2 c[ML_MAX_LINES][3];
};

/* 62 loop doublings (leading bit is bit 62) + the final one + one addition per
 * remaining set bit: the table must hold them all or the build overruns it. */
static_assert(63 + __builtin_popcountll(BLS_X >> 1) - 1 <= ML_MAX_LINES,
              "g2_lines table too small for the Miller schedule");

struct g2_lines *bls12_381_g2_lines_new(const struct g2_point *q)
{
    if (!q)
        LOG_NULL("bls12_381", "g2_lines_new: NULL point");
    struct g2_lines *ln = zcl_calloc(1, sizeof(*ln), "bls12_381_g2_lines");
    if (!ln)
        LOG_NULL("bls12_381", "g2_lines_new: zcl_calloc failed (%zu bytes)",
                 sizeof(*ln));
    if (g2_is_identity(q))
        return ln;                      /* n == 0: pairs with it are skipped */

    struct fp2 qx, qy;
    g2_to_affine(&qx, &qy, q);
    struct g2_point r;
    r.x = qx;
    r.y = qy;
    fp2_one(&r.z);

    uint64_t x_half = BLS_X >> 1;
    bool found_one = false;
    for (int i = 63; i >= 0; i--) {
        bool bit = (x_half >> i) & 1;
        if (!found_one) {
            found_one = bit;
            continue;
        }
        doubling_step(&r, &ln->c[ln->n][0], &ln->c[ln->n][1], &ln->c[ln->n][2]);
        ln->n++;
        if (bit) {
            addition_step(&r, &qx, &qy, &ln->c[ln->n][0], &ln->c[ln->n][1],
                          &ln->c[ln->n][2]);
            ln->n++;
        }
    }
    doubling_step(&r, &ln->c[ln->n][0], &ln->c[ln->n][1], &ln->c[ln->n][2]);
    ln->n++;
    return ln;
}

void bls12_381_g2_lines_free(struct g2_lines *ln)
{
    free(ln);
}

#define ML_MAX_PAIRS 8

/* One live pair of the shared loop. lines != NULL reads the table, else the
 * point is stepped on the fly from r (starting at Q). */
struct ml_pair {
    struct fp px, py;
    const struct g2_lines *lines;
    struct g2_point r;
    struct fp2 qx, qy;
};

static void ml_pair_init(struct ml_pair *mp, const struct g1_point *p,
                         const struct g2_point *q, const struct g2_lines *lines)
{
    g1_to_affine(&mp->px, &mp->py, p);
    mp->lines = lines;
    if (lines)
        return;
    g2_to_affine(&mp->qx, &mp->qy, q);
    mp->r.x = mp->qx;
    mp->r.y = mp->qy;
    fp2_one(&mp->r.z);
}

/* Multiply the pair's step number idx (doubling or addition) into f. */
static void ml_pair_step(struct fp12 *f, struct ml_pair *mp, size_t idx, bool add)
{
    struct fp2 c0, c1, c2;
    if (mp->lines) {
        c0 = mp->lines->c[idx][0];
        c1 = mp->lines->c[idx][1];
        c2 = mp->lines->c[idx][2];
    } else if (add) {
        addition_step(&mp->r, &mp->qx, &mp->qy, &c0, &c1, &c2);
    } else {
        doubling_step(&mp->r, &c0, &c1, &c2);
    }
    ell(f, &c0, &c1, &c2, &mp->px, &mp->py);
}

/* Product over pairs of bls12_381_miller_loop, computed with ONE f. The
 * per-pair loop is f <- (f * l_dbl [* l_add])^2 ending with f * l_dbl, then a
 * conjugate; with f = prod f_i that recurrence factors exactly, and Fp12
 * arithmetic is exact, so the result equals the product of the separate loops
 * bit for bit. lines[i] may be NULL (step on the fly) or the table of q[i].
 * Pairs with an identity point are skipped as multi_pairing_check does. */
bool bls12_381_multi_miller_shared(struct fp12 *result, const struct g1_point *p,
                                   const struct g2_point *q,
                                   const struct g2_lines *const *lines, size_t n)
{
    if (n > ML_MAX_PAIRS)
        LOG_FAIL("bls12_381", "multi_miller_shared: %zu pairs > cap %d", n,
                 ML_MAX_PAIRS);
    struct ml_pair mp[ML_MAX_PAIRS];
    size_t live = 0;
    for (size_t i = 0; i < n; i++) {
        if (g1_is_identity(&p[i]) || g2_is_identity(&q[i]))
            continue;
        const struct g2_lines *ln = lines ? lines[i] : NULL;
        if (ln && ln->n == 0)
            ln = NULL;                  /* defensive: empty table, step live */
        ml_pair_init(&mp[live++], &p[i], &q[i], ln);
    }

    struct fp12 f;
    fp12_one(&f);
    uint64_t x_half = BLS_X >> 1;
    bool found_one = false;
    size_t idx = 0;
    for (int i = 63; i >= 0; i--) {
        bool bit = (x_half >> i) & 1;
        if (!found_one) {
            found_one = bit;
            continue;
        }
        for (size_t k = 0; k < live; k++)
            ml_pair_step(&f, &mp[k], idx, false);
        idx++;
        if (bit) {
            for (size_t k = 0; k < live; k++)
                ml_pair_step(&f, &mp[k], idx, true);
            idx++;
        }
        fp12_sq(&f, &f);
    }
    for (size_t k = 0; k < live; k++)
        ml_pair_step(&f, &mp[k], idx, false);

    fp12_conjugate(&f);
    *result = f;
    return true;
}

/* Pairing check through the shared loop; same verdict as
 * bls12_381_multi_pairing_check. */
static bool multi_pairing_check_shared(const struct g1_point *p,
                                       const struct g2_point *q,
                                       const struct g2_lines *const *lines,
                                       size_t n)
{
    struct fp12 ml, result, one;
    if (!bls12_381_multi_miller_shared(&ml, p, q, lines, n))
        return false;
    bls12_381_final_exp(&result, &ml);
    fp12_one(&one);
    return memcmp(&result, &one, sizeof(struct fp12)) == 0;
}
/* Constant-time conditional move for Fp.  If mask == all-ones,
 * dst = src; if mask == 0, dst is unchanged.  No branches, no
 * secret-dependent memory access. */
static inline void fp_cmov(struct fp *dst, const struct fp *src, uint64_t mask)
{
    for (int i = 0; i < 6; i++)
        dst->d[i] = (dst->d[i] & ~mask) | (src->d[i] & mask);
}

static inline void g1_cmov(struct g1_point *dst, const struct g1_point *src,
                           uint64_t mask)
{
    fp_cmov(&dst->x, &src->x, mask);
    fp_cmov(&dst->y, &src->y, mask);
    fp_cmov(&dst->z, &src->z, mask);
}

/* G1 scalar multiplication: r = scalar * p (double-and-add, 256 bits).
 *
 * Threat model: callers include Groth16 proving, where the scalar
 * is a secret blinding factor (r_blind, s_blind — groth16_prover.c:906,
 * 934).  An attacker measuring wall-time of the prover must not learn
 * the Hamming weight of the scalar.
 *
 * CT properties:
 *   - Every iteration unconditionally runs g1_add and g1_double, so the
 *     total number of field-arithmetic ops is fixed (256 adds, 256
 *     doubles) independent of scalar content.
 *   - The bit-dependent update of `result` is done via `g1_cmov` masked
 *     on the bit, not a branch.
 *
 * Any future reviewer: do not reintroduce `if (bit)` without revisiting
 * the side-channel threat model. */
void g1_scalar_mul(struct g1_point *r, const struct g1_point *p, const uint64_t scalar[4])
{
    struct g1_point result;
    g1_identity(&result);
    struct g1_point base = *p;

    for (int i = 0; i < 4; i++) {
        for (int bit = 0; bit < 64; bit++) {
            struct g1_point sum;
            g1_add(&sum, &result, &base);
            uint64_t mask = (uint64_t)0 - ((scalar[i] >> bit) & 1ULL);
            g1_cmov(&result, &sum, mask);
            g1_double(&base, &base);
        }
    }
    *r = result;
}

/* ===== Fixed-base windowed multiplication over the constant VK IC points =====
 *
 * The Groth16 public-input commitment is vk_x = IC[0] + sum(input[i]*IC[i+1]),
 * and every IC[] base is FIXED for the lifetime of a verifying key. The naive
 * path pays a full 256-bit constant-time double-and-add per non-zero input on
 * every single verify. Because the bases never change, we precompute — once, at
 * VK load — a windowed table per IC point, and the per-verify work becomes
 * G1_COMB_WINDOWS table lookups plus adds, with zero doublings.
 *
 * BEHAVIOR-PRESERVING. Windowing only regroups the same 256-bit integer
 * multiple: s*P = sum_k digit_k(s) * (2^{k*W} * P). g1_comb_mul(table, s)
 * therefore yields the same GROUP ELEMENT as g1_scalar_mul(P, s) for every
 * 256-bit scalar, including scalars at or beyond r (both paths interpret the
 * multiplier as a plain integer). g1_add returns the correct sum for any
 * Jacobian representatives, and bls12_381_miller_loop normalizes G1 to affine
 * before pairing, so the pairing input — and every accept/reject verdict — is
 * unchanged. This is the consensus invariant: the same checks run faster, the
 * set of accepted proofs is identical. Enforced by the frozen corpus in
 * tests/harness/differential (make check-groth16-parity), which replays every
 * verify/batch vector down BOTH paths, and by test_groth16_msm_parity.
 *
 * Side channels: unlike g1_scalar_mul — whose scalar can be a SECRET prover
 * blinding factor — these scalars are PUBLIC verifier inputs, so the
 * data-dependent lookup and zero-digit skip leak nothing. The surrounding
 * verify path is already data-dependent (g1_add branches, the zero-input
 * skip), so no constant-time property is given up here. */
#define G1_COMB_W        4                       /* window width in bits         */
#define G1_COMB_WINDOWS  (256 / G1_COMB_W)       /* 64 windows over a 256b scalar*/
#define G1_COMB_ENTRIES  (1u << G1_COMB_W)       /* 16 multiples per window      */

struct g1_comb {
    /* t[k][j] = (j * 2^{k*W}) * base. t[k][0] is the identity (skipped). */
    struct g1_point t[G1_COMB_WINDOWS][G1_COMB_ENTRIES];
};

/* Build the table for one fixed base. Uses the same g1_add/g1_double the naive
 * path uses, so every entry is exactly the multiple the naive path would reach
 * (g1_add routes the j=2 case through g1_double, so the doubling is correct). */
static void g1_comb_build(struct g1_comb *c, const struct g1_point *base)
{
    struct g1_point win_base = *base;            /* 2^{k*W} * base, k advances  */
    for (int k = 0; k < G1_COMB_WINDOWS; k++) {
        g1_identity(&c->t[k][0]);                /* j = 0 -> identity           */
        for (int j = 1; j < (int)G1_COMB_ENTRIES; j++)
            g1_add(&c->t[k][j], &c->t[k][j - 1], &win_base); /* j*win_base      */
        for (int b = 0; b < G1_COMB_W; b++)      /* win_base *= 2^W             */
            g1_double(&win_base, &win_base);
    }
}

/* r = scalar * base, same value as g1_scalar_mul(&r, base, scalar), from the
 * precomputed table. W divides 64, so every window lies wholly inside one
 * 64-bit limb — no cross-limb straddle to get wrong. */
static void g1_comb_mul(struct g1_point *r, const struct g1_comb *c,
                        const uint64_t scalar[4])
{
    struct g1_point acc;
    g1_identity(&acc);
    for (int k = 0; k < G1_COMB_WINDOWS; k++) {
        int bitpos = k * G1_COMB_W;
        uint64_t digit = (scalar[bitpos >> 6] >> (bitpos & 63)) &
                         (uint64_t)(G1_COMB_ENTRIES - 1);
        if (digit)                               /* adding identity is a no-op  */
            g1_add(&acc, &acc, &c->t[k][digit]);
    }
    *r = acc;
}

/* vk_x term for public input i: the precomputed table when the VK carries one,
 * else the naive double-and-add. Same value either way. */
static inline void groth16_ic_term(struct g1_point *term,
                                   const struct groth16_vk *vk, size_t i,
                                   const uint64_t scalar[4])
{
    if (vk->ic_combs)
        g1_comb_mul(term, &vk->ic_combs[i], scalar);
    else
        g1_scalar_mul(term, &vk->ic[i + 1], scalar);
}

static void groth16_vk_free_lines(struct groth16_vk *vk)
{
    for (int i = 0; i < 3; i++) {
        bls12_381_g2_lines_free(vk->g2_lines[i]);
        vk->g2_lines[i] = NULL;
    }
}

void groth16_vk_free_combs(struct groth16_vk *vk)
{
    if (!vk)
        return;
    free(vk->ic_combs);
    vk->ic_combs = NULL;
    groth16_vk_free_lines(vk);
}

/* Lines for beta, -gamma, -delta (the fixed G2 points of groth16_verify). */
static bool groth16_vk_build_lines(struct groth16_vk *vk)
{
    struct g2_point neg_gamma, neg_delta;
    g2_neg(&neg_gamma, &vk->gamma_g2);
    g2_neg(&neg_delta, &vk->delta_g2);
    const struct g2_point *fixed[3] = { &vk->beta_g2, &neg_gamma, &neg_delta };
    for (int i = 0; i < 3; i++) {
        vk->g2_lines[i] = bls12_381_g2_lines_new(fixed[i]);
        if (!vk->g2_lines[i]) {
            groth16_vk_free_lines(vk);
            LOG_FAIL("groth16_vk", "build_lines: line table %d alloc failed", i);
        }
    }
    return true;
}

bool groth16_vk_build_combs(struct groth16_vk *vk)
{
    if (!vk)
        LOG_FAIL("groth16_vk", "build_combs: NULL vk");
    /* Rebuild from scratch so a second call cannot leak or reuse tables built
     * over different bases. */
    groth16_vk_free_combs(vk);
    if (!groth16_vk_build_lines(vk))
        return false;
    if (vk->ic_len < 2 || !vk->ic)
        return true;                    /* no scalar-mul'd IC points -> nothing */

    size_t n = vk->ic_len - 1;          /* one table per ic[1..ic_len-1]        */
    struct g1_comb *combs =
        zcl_malloc(n * sizeof(struct g1_comb), "groth16_vk_ic_combs");
    if (!combs)
        LOG_FAIL("groth16_vk",
                 "build_combs: zcl_malloc failed (%zu tables, %zu bytes)",
                 n, n * sizeof(struct g1_comb));
    for (size_t i = 0; i < n; i++)
        g1_comb_build(&combs[i], &vk->ic[i + 1]);
    vk->ic_combs = combs;
    return true;
}

/* ===== Prime-order subgroup membership via the endomorphism tests =====
 *
 * G1/G2 have large cofactors, so an on-curve point can carry a torsion
 * (non-prime-order) component that the pairing accepts: a Groth16 soundness
 * gap. P lies in the order-r subgroup iff [r]P == O; for BLS12-381 there are
 * equivalent EXACT tests that need only 64-bit multiplications by the curve
 * parameter instead of a 255-bit one:
 *   Scott, "A note on group membership tests for G1, G2 and GT on BLS
 *   pairing-friendly curves", eprint 2021/1130 (section 4 G2, section 6 G1);
 *   proofs corrected in El Housni, Guillevic, Piellard, eprint 2022/352.
 * zkcrypto bls12_381 (>= 0.7, Zcash consensus) uses the same two tests as
 * is_torsion_free. Both are membership iff-tests for every curve point, so
 * the verdict equals [r]P == O on every input (tests/harness/src/
 * test_bls12_381_subgroup_parity.c checks it against the [r]P oracle).
 *
 * The parameter is x = -0xd201000000010000, so [x]P = -[|x|]P.
 *   G2: psi(P) == [x]P, psi the untwist-Frobenius-twist endomorphism
 *       psi(X,Y,Z) = (conj(X)*c_x, conj(Y)*c_y, conj(Z)) in Jacobian form,
 *       c_x = 1/(1+u)^((p-1)/3), c_y = 1/(1+u)^((p-1)/2), conj = fp2 Frobenius.
 *   G1: phi(P) == -[x^2]P = -[|x|]([|x|]P), phi(X,Y,Z) = (beta*X, Y, Z) with
 *       beta a primitive cube root of unity in Fp. Exactly one of the two
 *       (beta, beta^2) satisfies the relation on G1; it is
 *       beta = 2^((p-1)/3) = 0x5f19672f...fffefffe, chosen by checking the
 *       generator and multiples of it (the other root, ...aaac, fails).
 * The constants are re-derived from field arithmetic and compared in the test.
 *
 * Multiplication by |x| is variable-time double-and-add: the inputs are the
 * PUBLIC proof points, so a side channel reveals nothing (as the old
 * g2_scalar_mul). g1/g2_add handle a == b (doubling, lines "u1==u2 && s1==s2")
 * and a == -b (h == 0 so z3 = 0, the identity) correctly, which small-order
 * torsion inputs can hit inside the chain. The identity passes: psi(O) = O,
 * phi(O) = O, [|x|]O = O. */
static const uint64_t BLS_X_ABS = 0xd201000000010000ULL;

/* Canonical big-endian field encodings of the endomorphism constants. */
static const uint8_t ENDO_BETA_BE[48] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5f,0x19,0x67,0x2f,
    0xdf,0x76,0xce,0x51,0xba,0x69,0xc6,0x07,0x6a,0x0f,0x77,0xea,
    0xdd,0xb3,0xa9,0x3b,0xe6,0xf8,0x96,0x88,0xde,0x17,0xd8,0x13,
    0x62,0x0a,0x00,0x02,0x2e,0x01,0xff,0xff,0xff,0xfe,0xff,0xfe
};
static const uint8_t ENDO_CX_C1_BE[48] = {
    0x1a,0x01,0x11,0xea,0x39,0x7f,0xe6,0x99,0xec,0x02,0x40,0x86,
    0x63,0xd4,0xde,0x85,0xaa,0x0d,0x85,0x7d,0x89,0x75,0x9a,0xd4,
    0x89,0x7d,0x29,0x65,0x0f,0xb8,0x5f,0x9b,0x40,0x94,0x27,0xeb,
    0x4f,0x49,0xff,0xfd,0x8b,0xfd,0x00,0x00,0x00,0x00,0xaa,0xad
};
static const uint8_t ENDO_CY_C0_BE[48] = {
    0x13,0x52,0x03,0xe6,0x01,0x80,0xa6,0x8e,0xe2,0xe9,0xc4,0x48,
    0xd7,0x7a,0x2c,0xd9,0x1c,0x3d,0xed,0xd9,0x30,0xb1,0xcf,0x60,
    0xef,0x39,0x64,0x89,0xf6,0x1e,0xb4,0x5e,0x30,0x44,0x66,0xcf,
    0x3e,0x67,0xfa,0x0a,0xf1,0xee,0x7b,0x04,0x12,0x1b,0xde,0xa2
};
static const uint8_t ENDO_CY_C1_BE[48] = {
    0x06,0xaf,0x0e,0x04,0x37,0xff,0x40,0x0b,0x68,0x31,0xe3,0x6d,
    0x6b,0xd1,0x7f,0xfe,0x48,0x39,0x5d,0xab,0xc2,0xd3,0x43,0x5e,
    0x77,0xf7,0x6e,0x17,0x00,0x92,0x41,0xc5,0xee,0x67,0x99,0x2f,
    0x72,0xec,0x05,0xf4,0xc8,0x10,0x84,0xfb,0xed,0xe3,0xcc,0x09
};

struct endo_consts {
    struct fp beta;
    struct fp2 cx, cy;
};

static void endo_consts_load(struct endo_consts *k)
{
    /* All encodings are < q constants, so fp_from_bytes cannot fail. */
    (void)fp_from_bytes(&k->beta, ENDO_BETA_BE);
    fp2_zero(&k->cx);
    (void)fp_from_bytes(&k->cx.c1, ENDO_CX_C1_BE);
    (void)fp_from_bytes(&k->cy.c0, ENDO_CY_C0_BE);
    (void)fp_from_bytes(&k->cy.c1, ENDO_CY_C1_BE);
}

#ifdef ZCL_TESTING
void bls12_381_endo_consts_for_test(struct fp *beta, struct fp2 *cx,
                                    struct fp2 *cy)
{
    struct endo_consts k;
    endo_consts_load(&k);
    *beta = k.beta;
    *cx = k.cx;
    *cy = k.cy;
}
#endif

/* r = [|x|]p, variable-time MSB-first double-and-add over the public 64-bit
 * constant (top bit is bit 63). */
static void g1_mul_abs_x(struct g1_point *r, const struct g1_point *p)
{
    struct g1_point acc = *p;
    for (int bit = 62; bit >= 0; bit--) {
        g1_double(&acc, &acc);
        if ((BLS_X_ABS >> bit) & 1ULL)
            g1_add(&acc, &acc, p);
    }
    *r = acc;
}

static void g2_mul_abs_x(struct g2_point *r, const struct g2_point *p)
{
    struct g2_point acc = *p;
    for (int bit = 62; bit >= 0; bit--) {
        g2_double(&acc, &acc);
        if ((BLS_X_ABS >> bit) & 1ULL)
            g2_add(&acc, &acc, p);
    }
    *r = acc;
}

/* Jacobian equality without inversion: both identity, or neither and
 * X1*Z2^2 == X2*Z1^2 and Y1*Z2^3 == Y2*Z1^3. */
static bool g1_jac_eq(const struct g1_point *a, const struct g1_point *b)
{
    bool ia = g1_is_identity(a), ib = g1_is_identity(b);
    if (ia || ib)
        return ia && ib;
    struct fp z1z1, z2z2, l, r;
    fp_sq(&z1z1, &a->z);
    fp_sq(&z2z2, &b->z);
    fp_mul(&l, &a->x, &z2z2);
    fp_mul(&r, &b->x, &z1z1);
    if (!fp_eq(&l, &r))
        return false;
    fp_mul(&l, &a->y, &z2z2);
    fp_mul(&l, &l, &b->z);
    fp_mul(&r, &b->y, &z1z1);
    fp_mul(&r, &r, &a->z);
    return fp_eq(&l, &r);
}

static bool g2_jac_eq(const struct g2_point *a, const struct g2_point *b)
{
    bool ia = g2_is_identity(a), ib = g2_is_identity(b);
    if (ia || ib)
        return ia && ib;
    struct fp2 z1z1, z2z2, l, r;
    fp2_sq(&z1z1, &a->z);
    fp2_sq(&z2z2, &b->z);
    fp2_mul(&l, &a->x, &z2z2);
    fp2_mul(&r, &b->x, &z1z1);
    if (!fp2_eq(&l, &r))
        return false;
    fp2_mul(&l, &a->y, &z2z2);
    fp2_mul(&l, &l, &b->z);
    fp2_mul(&r, &b->y, &z1z1);
    fp2_mul(&r, &r, &a->z);
    return fp2_eq(&l, &r);
}

bool g1_in_subgroup(const struct g1_point *p)
{
    struct endo_consts k;
    endo_consts_load(&k);
    struct g1_point phi = *p;
    fp_mul(&phi.x, &p->x, &k.beta);                /* phi(P) = (beta*X, Y, Z) */
    struct g1_point t, rhs;
    g1_mul_abs_x(&t, p);
    g1_mul_abs_x(&rhs, &t);
    g1_neg(&rhs, &rhs);                            /* -[x^2]P                 */
    return g1_jac_eq(&phi, &rhs);
}

bool g2_in_subgroup(const struct g2_point *p)
{
    struct endo_consts k;
    endo_consts_load(&k);
    struct g2_point psi = *p;                      /* psi(P) = (conj(X)*c_x,  */
    fp2_frobenius_map(&psi.x, 1);                  /*  conj(Y)*c_y, conj(Z))  */
    fp2_frobenius_map(&psi.y, 1);
    fp2_frobenius_map(&psi.z, 1);
    fp2_mul(&psi.x, &psi.x, &k.cx);
    fp2_mul(&psi.y, &psi.y, &k.cy);
    struct g2_point rhs;
    g2_mul_abs_x(&rhs, p);
    g2_neg(&rhs, &rhs);                            /* [x]P = -[|x|]P          */
    return g2_jac_eq(&psi, &rhs);
}

/* Groth16 proof deserialization: A (G1, 48B) + B (G2, 96B) + C (G1, 48B) = 192B.
 *
 * Each point is checked for (1) on-curve (inside g{1,2}_from_compressed) AND
 * (2) prime-order subgroup membership.  Without (2), a malicious prover could
 * submit on-curve-but-torsion points that the pairing still accepts, breaking
 * Groth16 soundness on the consensus Sapling proof path. */
bool groth16_proof_read(struct groth16_proof *proof, const uint8_t data[192])
{
    if (!g1_from_compressed(&proof->a, data))
        LOG_FAIL("groth16", "proof_read: g1_from_compressed(A) failed");
    if (!g1_in_subgroup(&proof->a))
        LOG_FAIL("groth16", "proof_read: A not in G1 prime-order subgroup");
    if (!g2_from_compressed(&proof->b, data + 48))
        LOG_FAIL("groth16", "proof_read: g2_from_compressed(B) failed");
    if (!g2_in_subgroup(&proof->b))
        LOG_FAIL("groth16", "proof_read: B not in G2 prime-order subgroup");
    if (!g1_from_compressed(&proof->c, data + 144))
        LOG_FAIL("groth16", "proof_read: g1_from_compressed(C) failed");
    if (!g1_in_subgroup(&proof->c))
        LOG_FAIL("groth16", "proof_read: C not in G1 prime-order subgroup");
    return true;
}

/* Multipack: pack bytes into Fr scalars (253 bits per scalar, LE bit order) */
void multipack_bytes_to_fr(uint64_t (*out)[4], size_t *n_out,
                           const uint8_t *bytes, size_t n_bytes)
{
    const size_t capacity = BLS12_381_FR_CAPACITY;
    size_t n_bits = n_bytes * 8;
    size_t n_scalars = (n_bits + capacity - 1) / capacity;

    for (size_t s = 0; s < n_scalars; s++) {
        memset(out[s], 0, 32);
        uint64_t cur[4] = {0, 0, 0, 0};
        uint64_t coeff[4] = {1, 0, 0, 0};

        size_t bit_start = s * capacity;
        size_t bit_end = bit_start + capacity;
        if (bit_end > n_bits) bit_end = n_bits;

        for (size_t b = bit_start; b < bit_end; b++) {
            size_t byte_idx = b / 8;
            int bit_idx = b % 8;
            bool bit_val = (bytes[byte_idx] >> bit_idx) & 1;

            if (bit_val) {
                /* cur += coeff (simple 256-bit add, no modular reduction needed
                 * since we only accumulate 253 bits) */
                unsigned __int128 carry = 0;
                for (int i = 0; i < 4; i++) {
                    unsigned __int128 sum = (unsigned __int128)cur[i] + coeff[i] + carry;
                    cur[i] = (uint64_t)sum;
                    carry = sum >> 64;
                }
            }
            /* coeff *= 2 */
            uint64_t carry2 = 0;
            for (int i = 0; i < 4; i++) {
                uint64_t new_carry = coeff[i] >> 63;
                coeff[i] = (coeff[i] << 1) | carry2;
                carry2 = new_carry;
            }
        }
        memcpy(out[s], cur, 32);
    }
    *n_out = n_scalars;
}

/* Multipack: pack bytes into Fr scalars (253 bits per scalar, BE bit order).
 * Sprout uses MSB-first bit ordering (bytes_to_bits in Rust). */
void multipack_bytes_to_fr_be(uint64_t (*out)[4], size_t *n_out,
                               const uint8_t *bytes, size_t n_bytes)
{
    /* Sprout Groth16 uses BLS12-381, BE bit order. */
    const size_t capacity = BLS12_381_FR_CAPACITY;
    size_t n_bits = n_bytes * 8;
    size_t n_scalars = (n_bits + capacity - 1) / capacity;

    for (size_t s = 0; s < n_scalars; s++) {
        uint64_t cur[4] = {0, 0, 0, 0};
        uint64_t coeff[4] = {1, 0, 0, 0};

        size_t bit_start = s * capacity;
        size_t bit_end = bit_start + capacity;
        if (bit_end > n_bits) bit_end = n_bits;

        for (size_t b = bit_start; b < bit_end; b++) {
            /* BE bit order: bit b maps to byte b/8, bit (7 - b%8) */
            size_t byte_idx = b / 8;
            int bit_idx = 7 - (int)(b % 8);
            bool bit_val = (bytes[byte_idx] >> bit_idx) & 1;

            if (bit_val) {
                unsigned __int128 carry = 0;
                for (int i = 0; i < 4; i++) {
                    unsigned __int128 sum = (unsigned __int128)cur[i] + coeff[i] + carry;
                    cur[i] = (uint64_t)sum;
                    carry = sum >> 64;
                }
            }
            uint64_t carry2 = 0;
            for (int i = 0; i < 4; i++) {
                uint64_t new_carry = coeff[i] >> 63;
                coeff[i] = (coeff[i] << 1) | carry2;
                carry2 = new_carry;
            }
        }
        memcpy(out[s], cur, 32);
    }
    *n_out = n_scalars;
}

/* Groth16 verification:
 * e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
 * Rearranged: e(A, B) * e(vk_x, -gamma) * e(C, -delta) == e(alpha, beta) */
bool groth16_verify(const struct groth16_vk *vk,
                    const struct groth16_proof *proof,
                    const uint64_t (*public_inputs)[4],
                    size_t n_inputs)
{
    if (n_inputs + 1 != vk->ic_len)
        LOG_FAIL("groth16",
                 "verify: public input count mismatch: n_inputs=%zu ic_len=%zu (want %zu)",
                 n_inputs, vk->ic_len, vk->ic_len - 1);

    /* Compute vk_x = IC[0] + sum(IC[i+1] * input[i]) */
    struct g1_point vk_x = vk->ic[0];

    for (size_t i = 0; i < n_inputs; i++) {
        /* Skip zero inputs (optimization + avoids identity issues) */
        if (public_inputs[i][0] == 0 && public_inputs[i][1] == 0 &&
            public_inputs[i][2] == 0 && public_inputs[i][3] == 0)
            continue;
        struct g1_point term;
        groth16_ic_term(&term, vk, i, public_inputs[i]);
        g1_add(&vk_x, &vk_x, &term);
    }

    /* Negate gamma and delta for the pairing check */
    struct g2_point neg_gamma, neg_delta;
    g2_neg(&neg_gamma, &vk->gamma_g2);
    g2_neg(&neg_delta, &vk->delta_g2);

    /* Check: e(A, B) * e(vk_x, -gamma) * e(C, -delta) * e(-alpha, beta) == 1
     * Equivalent to: e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta) */
    struct g1_point neg_alpha;
    g1_neg(&neg_alpha, &vk->alpha_g1);

    struct g1_point pts[4] = { proof->a, vk_x, proof->c, neg_alpha };
    struct g2_point qts[4] = { proof->b, neg_gamma, neg_delta, vk->beta_g2 };

    /* Fixed-VK points carry precomputed lines when built: one shared Miller
     * loop, same GT value. Without them, the per-pair loops of old. */
    if (vk->g2_lines[0] && vk->g2_lines[1] && vk->g2_lines[2]) {
        const struct g2_lines *lines[4] = { NULL, vk->g2_lines[1],
                                            vk->g2_lines[2], vk->g2_lines[0] };
        return multi_pairing_check_shared(pts, qts, lines, 4);
    }
    return bls12_381_multi_pairing_check(pts, qts, 4);
}

/* Compute vk_x = IC[0] + sum(IC[i+1] * input[i]) — the per-proof aggregated
 * public-input commitment, identical to the loop inside groth16_verify. */
static void groth16_compute_vk_x(const struct groth16_vk *vk,
                                 const uint64_t (*public_inputs)[4],
                                 size_t n_inputs, struct g1_point *vk_x)
{
    *vk_x = vk->ic[0];
    for (size_t i = 0; i < n_inputs; i++) {
        if (public_inputs[i][0] == 0 && public_inputs[i][1] == 0 &&
            public_inputs[i][2] == 0 && public_inputs[i][3] == 0)
            continue;
        struct g1_point term;
        groth16_ic_term(&term, vk, i, public_inputs[i]);
        g1_add(vk_x, vk_x, &term);
    }
}

/* 256-bit little-endian add: acc += add (wrap at 2^256; a set large enough to
 * overflow 2^256 with 128-bit summands is not reached on any real block). */
static void u256_add(uint64_t acc[4], const uint64_t add[4])
{
    unsigned __int128 carry = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 s = (unsigned __int128)acc[i] + add[i] + carry;
        acc[i] = (uint64_t)s;
        carry = s >> 64;
    }
}

bool groth16_batch_verify(const struct groth16_vk *vk,
                          const struct groth16_proof *proofs,
                          const uint64_t (*public_inputs)[4],
                          size_t n_inputs, size_t n_proofs)
{
    if (n_proofs == 0)
        LOG_FAIL("groth16", "batch_verify: n_proofs == 0");
    if (n_inputs + 1 != vk->ic_len)
        LOG_FAIL("groth16",
                 "batch_verify: public input count mismatch: n_inputs=%zu ic_len=%zu",
                 n_inputs, vk->ic_len);

    /* Per-batch Fiat-Shamir seed: BLAKE2b over every proof's point bytes and
     * every public-input scalar. The random combining scalars r_j derive from
     * this seed, so a forger who chooses the proofs cannot predict r_j and
     * therefore cannot craft a set whose weighted product cancels to 1. A fixed
     * r would be unsound. */
    uint8_t seed[32];
    {
        struct blake2b_ctx bctx;
        if (blake2b_init(&bctx, sizeof(seed)) != 0)
            LOG_FAIL("groth16", "batch_verify: blake2b_init(seed) failed");
        static const uint8_t domain[] = "ZCL_Groth16_Batch_v1";
        blake2b_update(&bctx, domain, sizeof(domain));
        blake2b_update(&bctx, proofs, n_proofs * sizeof(struct groth16_proof));
        if (n_inputs > 0)
            blake2b_update(&bctx, public_inputs,
                           n_proofs * n_inputs * sizeof(public_inputs[0]));
        blake2b_final(&bctx, seed, sizeof(seed));
    }

    /* Accumulators shared across the batch:
     *   S_vkx = sum_j r_j * vk_x_j     (paired with -gamma, one Miller loop)
     *   S_c   = sum_j r_j * C_j        (paired with -delta, one Miller loop)
     *   sum_r = sum_j r_j              ((sum_r)*(-alpha) paired with beta) */
    struct g1_point S_vkx, S_c;
    g1_identity(&S_vkx);
    g1_identity(&S_c);
    uint64_t sum_r[4] = {0, 0, 0, 0};

    size_t n_terms = n_proofs + 3;
    struct g1_point *pts = zcl_calloc(n_terms, sizeof(struct g1_point),
                                      "groth16 batch pts");
    struct g2_point *qts = zcl_calloc(n_terms, sizeof(struct g2_point),
                                      "groth16 batch qts");
    if (!pts || !qts) {
        free(pts);
        free(qts);
        LOG_FAIL("groth16", "batch_verify: allocation failed (n_proofs=%zu)",
                 n_proofs);
    }

    for (size_t j = 0; j < n_proofs; j++) {
        /* r_j: 128-bit challenge from the seed (2^-128 soundness), never 0. */
        uint8_t rd[64];
        struct blake2b_ctx rctx;
        blake2b_init(&rctx, sizeof(rd));
        blake2b_update(&rctx, seed, sizeof(seed));
        uint64_t jj = (uint64_t)j;
        uint8_t jle[8];
        for (int b = 0; b < 8; b++) jle[b] = (uint8_t)(jj >> (8 * b));
        blake2b_update(&rctx, jle, sizeof(jle));
        blake2b_final(&rctx, rd, sizeof(rd));
        uint64_t r[4] = {0, 0, 0, 0};
        for (int b = 0; b < 8; b++) {
            r[0] |= (uint64_t)rd[b] << (8 * b);
            r[1] |= (uint64_t)rd[8 + b] << (8 * b);
        }
        if (r[0] == 0 && r[1] == 0)
            r[0] = 1;

        const uint64_t (*pi_j)[4] =
            n_inputs ? &public_inputs[j * n_inputs] : NULL;

        /* r_j * A_j  paired with  B_j (distinct per proof → own Miller loop) */
        g1_scalar_mul(&pts[j], &proofs[j].a, r);
        qts[j] = proofs[j].b;

        /* accumulate r_j * vk_x_j and r_j * C_j into the shared G2 terms */
        struct g1_point vk_x_j, tmp;
        groth16_compute_vk_x(vk, pi_j, n_inputs, &vk_x_j);
        g1_scalar_mul(&tmp, &vk_x_j, r);
        g1_add(&S_vkx, &S_vkx, &tmp);
        g1_scalar_mul(&tmp, &proofs[j].c, r);
        g1_add(&S_c, &S_c, &tmp);

        u256_add(sum_r, r);
    }

    struct g2_point neg_gamma, neg_delta;
    g2_neg(&neg_gamma, &vk->gamma_g2);
    g2_neg(&neg_delta, &vk->delta_g2);
    struct g1_point neg_alpha, sum_r_neg_alpha;
    g1_neg(&neg_alpha, &vk->alpha_g1);
    g1_scalar_mul(&sum_r_neg_alpha, &neg_alpha, sum_r);

    pts[n_proofs + 0] = S_vkx;         qts[n_proofs + 0] = neg_gamma;
    pts[n_proofs + 1] = S_c;           qts[n_proofs + 1] = neg_delta;
    pts[n_proofs + 2] = sum_r_neg_alpha; qts[n_proofs + 2] = vk->beta_g2;

    bool ok = bls12_381_multi_pairing_check(pts, qts, n_terms);
    free(pts);
    free(qts);
    return ok;
}

/* ===== VK reader (bellman format) ===== */

static bool read_g1_uncompressed(struct g1_point *p, const uint8_t **data, size_t *remaining)
{
    if (*remaining < 96)
        LOG_FAIL("groth16_vk",
                 "read_g1_uncompressed: short buffer (%zu < 96)", *remaining);
    if (!g1_from_uncompressed(p, *data))
        LOG_FAIL("groth16_vk", "read_g1_uncompressed: g1_from_uncompressed failed");
    *data += 96;
    *remaining -= 96;
    return true;
}

static bool read_g2_uncompressed(struct g2_point *p, const uint8_t **data, size_t *remaining)
{
    if (*remaining < 192)
        LOG_FAIL("groth16_vk",
                 "read_g2_uncompressed: short buffer (%zu < 192)", *remaining);
    if (!g2_from_uncompressed(p, *data))
        LOG_FAIL("groth16_vk", "read_g2_uncompressed: g2_from_uncompressed failed");
    *data += 192;
    *remaining -= 192;
    return true;
}

static uint32_t read_be32(const uint8_t **data, size_t *remaining)
{
    uint32_t v = ((uint32_t)(*data)[0] << 24) | ((uint32_t)(*data)[1] << 16) |
                 ((uint32_t)(*data)[2] << 8) | (*data)[3];
    *data += 4;
    *remaining -= 4;
    return v;
}

bool groth16_vk_read_raw(struct groth16_vk *vk, const uint8_t *data, size_t len)
{
    /* VK format: alpha_g1(96) beta_g1(96) beta_g2(192) gamma_g2(192)
     *            delta_g1(96) delta_g2(192) ic_len(4) ic[](96 each)
     * Minimum: 96+96+192+192+96+192+4 = 868 bytes */
    if (len < 868)
        LOG_FAIL("groth16_vk",
                 "vk_read_raw: buffer too small: len=%zu < 868 minimum", len);

    /* A parse installs new bases, so any table the caller's struct happens to
     * carry is stale and would multiply against the wrong points. Callers pass
     * a fresh struct (same contract as vk->ic, which is overwritten too), so
     * clear rather than free. Re-precompute with groth16_vk_build_combs. */
    vk->ic_combs = NULL;
    for (int i = 0; i < 3; i++)
        vk->g2_lines[i] = NULL;

    struct g1_point beta_g1, delta_g1;
    if (!read_g1_uncompressed(&vk->alpha_g1, &data, &len))
        LOG_FAIL("groth16_vk", "vk_read_raw: alpha_g1 parse failed");
    if (!read_g1_uncompressed(&beta_g1, &data, &len))  /* beta_g1 unused */
        LOG_FAIL("groth16_vk", "vk_read_raw: beta_g1 parse failed");
    if (!read_g2_uncompressed(&vk->beta_g2, &data, &len))
        LOG_FAIL("groth16_vk", "vk_read_raw: beta_g2 parse failed");
    if (!read_g2_uncompressed(&vk->gamma_g2, &data, &len))
        LOG_FAIL("groth16_vk", "vk_read_raw: gamma_g2 parse failed");
    if (!read_g1_uncompressed(&delta_g1, &data, &len))  /* delta_g1 unused */
        LOG_FAIL("groth16_vk", "vk_read_raw: delta_g1 parse failed");
    if (!read_g2_uncompressed(&vk->delta_g2, &data, &len))
        LOG_FAIL("groth16_vk", "vk_read_raw: delta_g2 parse failed");

    if (len < 4)
        LOG_FAIL("groth16_vk", "vk_read_raw: no room for ic_len u32 (remaining=%zu)", len);
    uint32_t ic_len = read_be32(&data, &len);
    if (ic_len > 1000000)
        LOG_FAIL("groth16_vk",
                 "vk_read_raw: ic_len=%u exceeds 1M sanity cap", ic_len);
    if (len < (size_t)ic_len * 96)
        LOG_FAIL("groth16_vk",
                 "vk_read_raw: short for ic array: remaining=%zu need=%u",
                 len, ic_len * 96);

    vk->ic = zcl_malloc(ic_len * sizeof(struct g1_point), "groth16_vk_ic");
    if (!vk->ic)
        LOG_FAIL("groth16_vk",
                 "vk_read_raw: zcl_malloc failed for ic[] (ic_len=%u)", ic_len);
    vk->ic_len = ic_len;

    for (uint32_t i = 0; i < ic_len; i++) {
        if (!read_g1_uncompressed(&vk->ic[i], &data, &len)) {
            free(vk->ic);
            vk->ic = NULL;
            LOG_FAIL("groth16_vk",
                     "vk_read_raw: ic[%u] parse failed (of %u)", i, ic_len);
        }
    }

    return true;
}

bool groth16_vk_read(struct groth16_vk *vk, const uint8_t *data, size_t len)
{
    /* Parameters file starts with VK, then proving key arrays.
     * We only need the VK portion. */
    return groth16_vk_read_raw(vk, data, len);
}

#pragma GCC diagnostic pop
