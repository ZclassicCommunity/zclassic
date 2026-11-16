/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Branch-free inline BLS12-381 base-field add / subtract / negate.
 *
 * Semantics are bit-for-bit those of the previous compare-then-conditional-
 * subtract code for EVERY 6-limb input, canonical or not:
 *   add: t = a + b (carry c out of limb 5); u = t - q (mod 2^384, borrow w);
 *        result = (c || !w) ? u : t.   (old: carry || t >= q -> t - q)
 *   sub: d = a - b (mod 2^384, borrow w); result = w ? d + q (mod 2^384) : d.
 *        (old: a >= b ? a - b : (a + q) - b, all mod 2^384; identical)
 *   neg: a == 0 ? 0 : q - a (mod 2^384).
 * Every operation runs the same instruction sequence regardless of data, so
 * there is no data-dependent branch to mispredict. Outputs may alias inputs. */
#ifndef BLS12_381_FP_INLINE_H
#define BLS12_381_FP_INLINE_H

#include <stdint.h>

__extension__ typedef unsigned __int128 fpi_u128;

#if defined(__x86_64__) && defined(__GNUC__)
#include <x86intrin.h>
#define FPI_ADC(c, x, y, out) _addcarry_u64((c), (x), (y), (unsigned long long *)(out))
#define FPI_SBB(c, x, y, out) _subborrow_u64((c), (x), (y), (unsigned long long *)(out))
#else
static inline unsigned char fpi_adc(unsigned char c, uint64_t x, uint64_t y, uint64_t *o)
{
    fpi_u128 s = (fpi_u128)x + y + c;
    *o = (uint64_t)s;
    return (unsigned char)(s >> 64);
}
static inline unsigned char fpi_sbb(unsigned char c, uint64_t x, uint64_t y, uint64_t *o)
{
    fpi_u128 d = (fpi_u128)x - y - c;
    *o = (uint64_t)d;
    return (unsigned char)((d >> 64) & 1);
}
#define FPI_ADC(c, x, y, out) fpi_adc((c), (x), (y), (out))
#define FPI_SBB(c, x, y, out) fpi_sbb((c), (x), (y), (out))
#endif

/* r = a + b, returns carry out.  Aliasing-safe. */
static inline uint64_t fpi_add_raw(uint64_t r[6], const uint64_t a[6],
                                   const uint64_t b[6])
{
    unsigned char c = 0;
    c = FPI_ADC(c, a[0], b[0], &r[0]);
    c = FPI_ADC(c, a[1], b[1], &r[1]);
    c = FPI_ADC(c, a[2], b[2], &r[2]);
    c = FPI_ADC(c, a[3], b[3], &r[3]);
    c = FPI_ADC(c, a[4], b[4], &r[4]);
    c = FPI_ADC(c, a[5], b[5], &r[5]);
    return c;
}

/* r = a - b mod 2^384, returns borrow out (0 or 1).  Aliasing-safe. */
static inline uint64_t fpi_sub_raw(uint64_t r[6], const uint64_t a[6],
                                   const uint64_t b[6])
{
    unsigned char c = 0;
    c = FPI_SBB(c, a[0], b[0], &r[0]);
    c = FPI_SBB(c, a[1], b[1], &r[1]);
    c = FPI_SBB(c, a[2], b[2], &r[2]);
    c = FPI_SBB(c, a[3], b[3], &r[3]);
    c = FPI_SBB(c, a[4], b[4], &r[4]);
    c = FPI_SBB(c, a[5], b[5], &r[5]);
    return c;
}

static inline void fpi_add(uint64_t r[6], const uint64_t a[6],
                           const uint64_t b[6], const uint64_t q[6])
{
    uint64_t t[6], u[6];
    uint64_t carry = fpi_add_raw(t, a, b);
    uint64_t borrow = fpi_sub_raw(u, t, q);
    uint64_t mask = -(carry | (borrow ^ 1));   /* all-ones: take t - q */
    for (int i = 0; i < 6; i++)
        r[i] = (t[i] & ~mask) | (u[i] & mask);
}

static inline void fpi_sub(uint64_t r[6], const uint64_t a[6],
                           const uint64_t b[6], const uint64_t q[6])
{
    uint64_t d[6], e[6];
    uint64_t borrow = fpi_sub_raw(d, a, b);
    uint64_t mask = -borrow;                   /* all-ones: add q back */
    uint64_t qm[6];
    for (int i = 0; i < 6; i++)
        qm[i] = q[i] & mask;
    (void)fpi_add_raw(e, d, qm);
    for (int i = 0; i < 6; i++)
        r[i] = e[i];
}

static inline void fpi_neg(uint64_t r[6], const uint64_t a[6],
                           const uint64_t q[6])
{
    uint64_t d[6];
    uint64_t any = a[0] | a[1] | a[2] | a[3] | a[4] | a[5];
    uint64_t mask = -(uint64_t)((any | -any) >> 63);  /* 0 iff a == 0 */
    (void)fpi_sub_raw(d, q, a);
    for (int i = 0; i < 6; i++)
        r[i] = d[i] & mask;
}

#endif /* BLS12_381_FP_INLINE_H */
