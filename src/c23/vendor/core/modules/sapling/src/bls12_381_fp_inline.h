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

/* r = a + b - q when a + b >= q (or the sum carries out of the top limb),
 * else a + b:  u = a + b - q, then q is added back when that subtraction
 * borrowed with no carry to absorb it.
 * r = a - b, plus q when the subtraction borrowed (all mod 2^(64N)).
 * r = -a is 0 - a under the same rule, which is 0 for a == 0.
 *
 * Every step is a carry chain; nothing is selected with a mask-and-or over limb
 * arrays. That form is what cost GCC its speed here: it vectorised the select
 * and reloaded limbs it had just stored through 16-byte SSE loads, a
 * store-forwarding stall on every call, and it materialised the carry with
 * SETC between ADCs whenever an AND sat inside the chain. On x86-64 the chains
 * are therefore written out as asm (ADD/ADC, SUB/SBB), so GCC and Clang emit
 * the same instructions; other targets use the C chains below. */
#if defined(__x86_64__) && defined(__GNUC__)

#define FPI_LD(I, OFF) "movq " OFF "(%[ap]), %[d" I "]\n\t"
#define FPI_OP(OP, OFF, P, I) OP " " OFF "(%[" P "]), %[d" I "]\n\t"
#define FPI_RR(OP, I) OP " %[q" I "], %[d" I "]\n\t"

#define FPI_DECL4 uint64_t d0, d1, d2, d3, m
#define FPI_LOAD4 FPI_LD("0", "0") FPI_LD("1", "8") FPI_LD("2", "16") FPI_LD("3", "24")
#define FPI_CHAIN4(OP1, OPN, P)                                               \
    FPI_OP(OP1, "0", P, "0") FPI_OP(OPN, "8", P, "1")                         \
    FPI_OP(OPN, "16", P, "2") FPI_OP(OPN, "24", P, "3")
#define FPI_BACK4 FPI_RR("addq", "0") FPI_RR("adcq", "1") FPI_RR("adcq", "2") FPI_RR("adcq", "3")
#define FPI_REGS4(K) [d0] K(d0), [d1] K(d1), [d2] K(d2), [d3] K(d3)
#define FPI_QM4 [q0] "r"(q[0] & m), [q1] "r"(q[1] & m), [q2] "r"(q[2] & m), [q3] "r"(q[3] & m)
#define FPI_STORE4 r[0] = d0; r[1] = d1; r[2] = d2; r[3] = d3

#define FPI_DECL6 uint64_t d0, d1, d2, d3, d4, d5, m
#define FPI_LOAD6 FPI_LOAD4 FPI_LD("4", "32") FPI_LD("5", "40")
#define FPI_CHAIN6(OP1, OPN, P)                                               \
    FPI_CHAIN4(OP1, OPN, P) FPI_OP(OPN, "32", P, "4") FPI_OP(OPN, "40", P, "5")
#define FPI_BACK6 FPI_BACK4 FPI_RR("adcq", "4") FPI_RR("adcq", "5")
#define FPI_REGS6(K) FPI_REGS4(K), [d4] K(d4), [d5] K(d5)
#define FPI_QM6 FPI_QM4, [q4] "r"(q[4] & m), [q5] "r"(q[5] & m)
#define FPI_STORE6 FPI_STORE4; r[4] = d4; r[5] = d5

/* d += q & m, then store. m is all-ones or zero. */
#define FPI_ADD_BACK(N)                                                       \
    __asm__(FPI_BACK##N : FPI_REGS##N("+&r") : FPI_QM##N : "cc");             \
    FPI_STORE##N;

/* d = a + b with the carry in m, then d -= q; m becomes carry - borrow, and
 * only -1 (borrowed, no carry) asks for q back. */
#define FPI_ADD_BODY(N)                                                       \
    FPI_DECL##N;                                                              \
    __asm__(FPI_LOAD##N FPI_CHAIN##N("addq", "adcq", "bp")                    \
            "movl $0, %k[m]\n\t" "adcq %[m], %[m]\n\t"                        \
            FPI_CHAIN##N("subq", "sbbq", "qp")                                \
            "sbbq $0, %[m]\n\t" "sarq $63, %[m]\n\t"                          \
            : FPI_REGS##N("=&r"), [m] "=&r"(m)                                \
            : [ap] "r"(a), [bp] "r"(b), [qp] "r"(q)                           \
            : "cc", "memory");                                                \
    FPI_ADD_BACK(N)

/* d = a - b; SBB m,m leaves m = -borrow. */
#define FPI_SUB_BODY(N)                                                       \
    FPI_DECL##N;                                                              \
    __asm__(FPI_LOAD##N FPI_CHAIN##N("subq", "sbbq", "bp")                    \
            "sbbq %[m], %[m]\n\t"                                             \
            : FPI_REGS##N("=&r"), [m] "=&r"(m)                                \
            : [ap] "r"(a), [bp] "r"(b)                                        \
            : "cc", "memory");                                                \
    FPI_ADD_BACK(N)

#else /* portable carry chains */

#define FPI_ADD_BODY(N)                                                       \
    uint64_t t[N], u[N];                                                      \
    unsigned char carry = 0, borrow = 0, c = 0;                               \
    for (int i = 0; i < (N); i++)                                             \
        carry = FPI_ADC(carry, a[i], b[i], &t[i]);                            \
    for (int i = 0; i < (N); i++)                                             \
        borrow = FPI_SBB(borrow, t[i], q[i], &u[i]);                          \
    uint64_t m = -(uint64_t)(borrow & (carry ^ 1));                           \
    for (int i = 0; i < (N); i++)                                             \
        c = FPI_ADC(c, u[i], q[i] & m, &r[i]);

#define FPI_SUB_BODY(N)                                                       \
    uint64_t d[N];                                                            \
    unsigned char borrow = 0, c = 0;                                          \
    for (int i = 0; i < (N); i++)                                             \
        borrow = FPI_SBB(borrow, a[i], b[i], &d[i]);                          \
    uint64_t m = -(uint64_t)borrow;                                           \
    for (int i = 0; i < (N); i++)                                             \
        c = FPI_ADC(c, d[i], q[i] & m, &r[i]);

#endif

static inline void fpi_add(uint64_t r[6], const uint64_t a[6],
                           const uint64_t b[6], const uint64_t q[6])
{
    FPI_ADD_BODY(6)
}

static inline void fpi_sub(uint64_t r[6], const uint64_t a[6],
                           const uint64_t b[6], const uint64_t q[6])
{
    FPI_SUB_BODY(6)
}

static inline void fpi_neg(uint64_t r[6], const uint64_t b[6],
                           const uint64_t q[6])
{
    static const uint64_t a[6] = {0};
    FPI_SUB_BODY(6)
}

/* The same three operations on 4 limbs (BLS12-381 Fr and Jubjub Fs moduli). */
static inline void fpi_add4(uint64_t r[4], const uint64_t a[4],
                            const uint64_t b[4], const uint64_t q[4])
{
    FPI_ADD_BODY(4)
}

static inline void fpi_sub4(uint64_t r[4], const uint64_t a[4],
                            const uint64_t b[4], const uint64_t q[4])
{
    FPI_SUB_BODY(4)
}

static inline void fpi_neg4(uint64_t r[4], const uint64_t b[4],
                            const uint64_t q[4])
{
    static const uint64_t a[4] = {0};
    FPI_SUB_BODY(4)
}

#endif /* BLS12_381_FP_INLINE_H */
