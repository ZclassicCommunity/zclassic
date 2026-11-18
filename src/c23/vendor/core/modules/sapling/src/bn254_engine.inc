/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BN254 pairing engine. NOT a standalone translation unit: bn254.c includes
 * this file twice, once per field-multiply flavour (see the bottom of the
 * includer for BNE_ID / BNE_MUL / BNE_ATTR), so that on a BMI2+ADX CPU the
 * whole Miller loop, final exponentiation and G2 arithmetic run with the MULX
 * multiply inlined (no indirect call per multiplication) while every other CPU
 * runs the byte-identical portable instance.
 *
 * WHAT IT IS. Faster implementations of EXACTLY the functions the original
 * bn254.c computed:
 *   - the Miller loop, with the G2 line functions (doubling_step /
 *     mixed_addition_step, the same formulas) computed once per G2 point
 *     instead of once per pairing, and a sparse multiply by each line;
 *   - the final exponentiation, same exponent and same addition chain, with
 *     Granger-Scott cyclotomic squarings;
 *   - the multi-scalar multiplication of the public inputs;
 *   - the G2 order-r subgroup test: psi(P) == [6u^2]P instead of [r]P == O.
 * Every Fq/Fq2/Fq6/Fq12 value is canonical (reduced) at every step, exactly as
 * before, so the pairing value before AND after the final exponentiation is the
 * same field element as the original code produced, for any input. The one
 * place a different formula is used is the subgroup test; its proof is in the
 * comment above E_(g2_in_subgroup).
 *
 * Constant time is NOT a goal: every input here is public. */

#ifndef BNE_ID
#error "bn254_engine.inc must be included by bn254.c"
#endif

#define BNE_CAT2(a, b) a##b
#define BNE_CAT(a, b) BNE_CAT2(a, b)
#define E_(n) BNE_CAT(BNE_CAT(bne_, BNE_ID), BNE_CAT(_, n))
#define BNE_FN static BNE_ATTR
#define BNE_INL static inline __attribute__((always_inline)) BNE_ATTR

/* ══════════════ Fq ══════════════ */

BNE_INL void E_(fq_mul)(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b)
{
    BNE_MUL(r->d, a->d, b->d);
}

BNE_INL void E_(fq_sqr)(struct bn_fq *r, const struct bn_fq *a)
{
    BNE_MUL(r->d, a->d, a->d);
}

#ifdef BNE_ASM_ADDSUB
/* x86-64 add/sub/neg in assembly: a + b < 2q < 2^255, so one conditional
 * subtraction of q finishes the sum; the C form below compiles to a long
 * mov/and/or sequence. Results are the same canonical residues. Operands are
 * base pointers (not "m" operands) so the block also allocates at -O0. */
BNE_INL void E_(fq_add)(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b)
{
    uint64_t t0, t1, t2, t3, d0, d1, d2, d3;
    __asm__(
        "movq  (%[ap]), %[t0]\n\t" "addq  (%[bp]), %[t0]\n\t"
        "movq 8(%[ap]), %[t1]\n\t" "adcq 8(%[bp]), %[t1]\n\t"
        "movq 16(%[ap]), %[t2]\n\t" "adcq 16(%[bp]), %[t2]\n\t"
        "movq 24(%[ap]), %[t3]\n\t" "adcq 24(%[bp]), %[t3]\n\t"
        "movq %[t0], %[d0]\n\t" "subq  (%[qp]), %[d0]\n\t"
        "movq %[t1], %[d1]\n\t" "sbbq 8(%[qp]), %[d1]\n\t"
        "movq %[t2], %[d2]\n\t" "sbbq 16(%[qp]), %[d2]\n\t"
        "movq %[t3], %[d3]\n\t" "sbbq 24(%[qp]), %[d3]\n\t"
        "cmovcq %[t0], %[d0]\n\t" "cmovcq %[t1], %[d1]\n\t"
        "cmovcq %[t2], %[d2]\n\t" "cmovcq %[t3], %[d3]\n\t"
        : [t0] "=&r"(t0), [t1] "=&r"(t1), [t2] "=&r"(t2), [t3] "=&r"(t3),
          [d0] "=&r"(d0), [d1] "=&r"(d1), [d2] "=&r"(d2), [d3] "=&r"(d3)
        : [ap] "r"(a->d), [bp] "r"(b->d), [qp] "r"(FQ_Q)
        : "cc", "memory");
    r->d[0] = d0; r->d[1] = d1; r->d[2] = d2; r->d[3] = d3;
}

BNE_INL void E_(fq_sub)(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b)
{
    uint64_t d0, d1, d2, d3, m, q0, q1, q2, q3;
    __asm__(
        "movq  (%[ap]), %[d0]\n\t" "subq  (%[bp]), %[d0]\n\t"
        "movq 8(%[ap]), %[d1]\n\t" "sbbq 8(%[bp]), %[d1]\n\t"
        "movq 16(%[ap]), %[d2]\n\t" "sbbq 16(%[bp]), %[d2]\n\t"
        "movq 24(%[ap]), %[d3]\n\t" "sbbq 24(%[bp]), %[d3]\n\t"
        "sbbq %[m], %[m]\n\t"
        "movq  (%[qp]), %[q0]\n\t" "andq %[m], %[q0]\n\t"
        "movq 8(%[qp]), %[q1]\n\t" "andq %[m], %[q1]\n\t"
        "movq 16(%[qp]), %[q2]\n\t" "andq %[m], %[q2]\n\t"
        "movq 24(%[qp]), %[q3]\n\t" "andq %[m], %[q3]\n\t"
        "addq %[q0], %[d0]\n\t" "adcq %[q1], %[d1]\n\t"
        "adcq %[q2], %[d2]\n\t" "adcq %[q3], %[d3]\n\t"
        : [d0] "=&r"(d0), [d1] "=&r"(d1), [d2] "=&r"(d2), [d3] "=&r"(d3), [m] "=&r"(m),
          [q0] "=&r"(q0), [q1] "=&r"(q1), [q2] "=&r"(q2), [q3] "=&r"(q3)
        : [ap] "r"(a->d), [bp] "r"(b->d), [qp] "r"(FQ_Q)
        : "cc", "memory");
    r->d[0] = d0; r->d[1] = d1; r->d[2] = d2; r->d[3] = d3;
}

/* r = (q - a) mod q: 0 for a == 0. */
BNE_INL void E_(fq_neg)(struct bn_fq *r, const struct bn_fq *a)
{
    uint64_t t0, t1, t2, t3, z, o;
    __asm__(
        "xorl %k[z], %k[z]\n\t"
        "movq  (%[qp]), %[t0]\n\t" "subq  (%[ap]), %[t0]\n\t"
        "movq 8(%[qp]), %[t1]\n\t" "sbbq 8(%[ap]), %[t1]\n\t"
        "movq 16(%[qp]), %[t2]\n\t" "sbbq 16(%[ap]), %[t2]\n\t"
        "movq 24(%[qp]), %[t3]\n\t" "sbbq 24(%[ap]), %[t3]\n\t"
        "movq  (%[ap]), %[o]\n\t" "orq 8(%[ap]), %[o]\n\t"
        "orq 16(%[ap]), %[o]\n\t" "orq 24(%[ap]), %[o]\n\t"
        "cmovzq %[z], %[t0]\n\t" "cmovzq %[z], %[t1]\n\t"
        "cmovzq %[z], %[t2]\n\t" "cmovzq %[z], %[t3]\n\t"
        : [t0] "=&r"(t0), [t1] "=&r"(t1), [t2] "=&r"(t2), [t3] "=&r"(t3),
          [z] "=&r"(z), [o] "=&r"(o)
        : [ap] "r"(a->d), [qp] "r"(FQ_Q)
        : "cc", "memory");
    r->d[0] = t0; r->d[1] = t1; r->d[2] = t2; r->d[3] = t3;
}
#else
BNE_INL void E_(fq_add)(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b)
{
    __uint128_t c;
    uint64_t s0, s1, s2, s3, t0, t1, t2, t3, bw;
    c = (__uint128_t)a->d[0] + b->d[0]; s0 = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->d[1] + b->d[1]; s1 = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->d[2] + b->d[2]; s2 = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->d[3] + b->d[3]; s3 = (uint64_t)c;
    /* a, b < q < 2^254, so s < 2^255: no carry out of 256 bits. */
    c = (__uint128_t)s0 - FQ_Q[0]; t0 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)s1 - FQ_Q[1] - bw; t1 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)s2 - FQ_Q[2] - bw; t2 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)s3 - FQ_Q[3] - bw; t3 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    uint64_t m = (uint64_t)0 - bw; /* all ones: s < q, keep s */
    r->d[0] = (t0 & ~m) | (s0 & m);
    r->d[1] = (t1 & ~m) | (s1 & m);
    r->d[2] = (t2 & ~m) | (s2 & m);
    r->d[3] = (t3 & ~m) | (s3 & m);
}

BNE_INL void E_(fq_sub)(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b)
{
    __uint128_t c;
    uint64_t t0, t1, t2, t3, bw;
    c = (__uint128_t)a->d[0] - b->d[0]; t0 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)a->d[1] - b->d[1] - bw; t1 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)a->d[2] - b->d[2] - bw; t2 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)a->d[3] - b->d[3] - bw; t3 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    uint64_t m = (uint64_t)0 - bw; /* borrow: add q back */
    c = (__uint128_t)t0 + (FQ_Q[0] & m); r->d[0] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)t1 + (FQ_Q[1] & m); r->d[1] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)t2 + (FQ_Q[2] & m); r->d[2] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)t3 + (FQ_Q[3] & m); r->d[3] = (uint64_t)c;
}

BNE_INL void E_(fq_neg)(struct bn_fq *r, const struct bn_fq *a)
{
    __uint128_t c;
    uint64_t t0, t1, t2, t3, bw;
    uint64_t nz = a->d[0] | a->d[1] | a->d[2] | a->d[3];
    uint64_t m = (uint64_t)0 - (uint64_t)(nz != 0);
    c = (__uint128_t)FQ_Q[0] - a->d[0]; t0 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)FQ_Q[1] - a->d[1] - bw; t1 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)FQ_Q[2] - a->d[2] - bw; t2 = (uint64_t)c; bw = (uint64_t)(c >> 64) & 1;
    c = (__uint128_t)FQ_Q[3] - a->d[3] - bw; t3 = (uint64_t)c;
    r->d[0] = t0 & m; r->d[1] = t1 & m; r->d[2] = t2 & m; r->d[3] = t3 & m;
}
#endif /* BNE_ASM_ADDSUB */


BNE_INL void E_(fq_dbl)(struct bn_fq *r, const struct bn_fq *a) { E_(fq_add)(r, a, a); }

BNE_INL bool E_(fq_is_zero)(const struct bn_fq *a)
{
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

BNE_INL bool E_(fq_eq)(const struct bn_fq *a, const struct bn_fq *b)
{
    return ((a->d[0] ^ b->d[0]) | (a->d[1] ^ b->d[1]) | (a->d[2] ^ b->d[2]) | (a->d[3] ^ b->d[3])) == 0;
}

/* r = a^e for a 256-bit exponent, fixed 4-bit windows, MSB first. a = 0 gives 0
 * for every e != 0 (the table holds powers of 0), the same as the original
 * square-and-multiply loop. */
BNE_FN void E_(fq_pow)(struct bn_fq *r, const struct bn_fq *a, const uint64_t e[4])
{
    struct bn_fq tab[16];
    tab[0] = g_eng.fq_one;
    tab[1] = *a;
    for (int i = 2; i < 16; i++)
        E_(fq_mul)(&tab[i], &tab[i - 1], a);
    struct bn_fq acc = tab[0];
    bool started = false;
    for (int w = 63; w >= 0; w--) {
        unsigned d = (unsigned)((e[w / 16] >> (4 * (w % 16))) & 15);
        if (started) {
            E_(fq_sqr)(&acc, &acc); E_(fq_sqr)(&acc, &acc);
            E_(fq_sqr)(&acc, &acc); E_(fq_sqr)(&acc, &acc);
            if (d) E_(fq_mul)(&acc, &acc, &tab[d]);
        } else if (d) {
            acc = tab[d];
            started = true;
        }
    }
    *r = acc;
}

/* a^(q-2); 0 maps to 0, as the original Fermat loop did. */
BNE_FN void E_(fq_inv)(struct bn_fq *r, const struct bn_fq *a)
{
    E_(fq_pow)(r, a, BNE_QM2);
}

/* a^((q+1)/4) and whether it squares back to a (q = 3 mod 4). */
BNE_FN bool E_(fq_sqrt)(struct bn_fq *r, const struct bn_fq *a)
{
    E_(fq_pow)(r, a, BNE_SQRT_EXP);
    struct bn_fq chk;
    E_(fq_sqr)(&chk, r);
    return E_(fq_eq)(&chk, a);
}

/* ══════════════ Fq2 = Fq[u]/(u^2+1) ══════════════ */

BNE_INL void E_(fq2_add)(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b)
{
    E_(fq_add)(&r->c0, &a->c0, &b->c0);
    E_(fq_add)(&r->c1, &a->c1, &b->c1);
}

BNE_INL void E_(fq2_sub)(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b)
{
    E_(fq_sub)(&r->c0, &a->c0, &b->c0);
    E_(fq_sub)(&r->c1, &a->c1, &b->c1);
}

BNE_INL void E_(fq2_neg)(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    E_(fq_neg)(&r->c0, &a->c0);
    E_(fq_neg)(&r->c1, &a->c1);
}

BNE_INL void E_(fq2_dbl)(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    E_(fq_add)(&r->c0, &a->c0, &a->c0);
    E_(fq_add)(&r->c1, &a->c1, &a->c1);
}

BNE_INL void E_(fq2_conj)(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    struct bn_fq t = a->c0;
    E_(fq_neg)(&r->c1, &a->c1);
    r->c0 = t;
}

BNE_INL bool E_(fq2_is_zero)(const struct bn_fq2 *a)
{
    return E_(fq_is_zero)(&a->c0) && E_(fq_is_zero)(&a->c1);
}

BNE_INL bool E_(fq2_eq)(const struct bn_fq2 *a, const struct bn_fq2 *b)
{
    return E_(fq_eq)(&a->c0, &b->c0) && E_(fq_eq)(&a->c1, &b->c1);
}

/* (a0+a1 u)(b0+b1 u) = (a0 b0 - a1 b1) + (a0 b1 + a1 b0) u. */
BNE_INL void E_(fq2_mul)(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b)
{
    struct bn_fq t0, t1, s, u, t2;
    E_(fq_mul)(&t0, &a->c0, &b->c0);
    E_(fq_mul)(&t1, &a->c1, &b->c1);
    E_(fq_add)(&s, &a->c0, &a->c1);
    E_(fq_add)(&u, &b->c0, &b->c1);
    E_(fq_mul)(&t2, &s, &u);
    E_(fq_sub)(&r->c0, &t0, &t1);
    E_(fq_sub)(&t2, &t2, &t0);
    E_(fq_sub)(&r->c1, &t2, &t1);
}

BNE_INL void E_(fq2_sqr)(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    struct bn_fq s, d, m;
    E_(fq_add)(&s, &a->c0, &a->c1);
    E_(fq_sub)(&d, &a->c0, &a->c1);
    E_(fq_mul)(&m, &a->c0, &a->c1);
    E_(fq_mul)(&r->c0, &s, &d);
    E_(fq_add)(&r->c1, &m, &m);
}

/* r = a * s for s in Fq. */
BNE_INL void E_(fq2_mul_fq)(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq *s)
{
    E_(fq_mul)(&r->c0, &a->c0, s);
    E_(fq_mul)(&r->c1, &a->c1, s);
}

/* r = a * xi, xi = 9 + u: (9 a0 - a1) + (a0 + 9 a1) u, as 8x + x by additions. */
BNE_INL void E_(fq2_mul_xi)(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    struct bn_fq t0, t1, u0, u1;
    E_(fq_add)(&t0, &a->c0, &a->c0);
    E_(fq_add)(&t1, &a->c1, &a->c1);
    E_(fq_add)(&t0, &t0, &t0);
    E_(fq_add)(&t1, &t1, &t1);
    E_(fq_add)(&t0, &t0, &t0);
    E_(fq_add)(&t1, &t1, &t1);
    E_(fq_add)(&u0, &t0, &a->c0);   /* 9 a0 */
    E_(fq_add)(&u1, &t1, &a->c1);   /* 9 a1 */
    struct bn_fq o0, o1;
    E_(fq_sub)(&o0, &u0, &a->c1);
    E_(fq_add)(&o1, &u1, &a->c0);
    r->c0 = o0;
    r->c1 = o1;
}

BNE_FN void E_(fq2_inv)(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    struct bn_fq t0, t1, inv, n;
    E_(fq_sqr)(&t0, &a->c0);
    E_(fq_sqr)(&t1, &a->c1);
    E_(fq_add)(&t0, &t0, &t1);
    E_(fq_inv)(&inv, &t0);
    E_(fq_mul)(&r->c0, &a->c0, &inv);
    E_(fq_neg)(&n, &a->c1);
    E_(fq_mul)(&r->c1, &n, &inv);
}

/* ══════════════ Fq6 = Fq2[v]/(v^3 - xi) ══════════════ */

BNE_INL void E_(fq6_add)(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b)
{
    E_(fq2_add)(&r->c0, &a->c0, &b->c0);
    E_(fq2_add)(&r->c1, &a->c1, &b->c1);
    E_(fq2_add)(&r->c2, &a->c2, &b->c2);
}

BNE_INL void E_(fq6_sub)(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b)
{
    E_(fq2_sub)(&r->c0, &a->c0, &b->c0);
    E_(fq2_sub)(&r->c1, &a->c1, &b->c1);
    E_(fq2_sub)(&r->c2, &a->c2, &b->c2);
}

BNE_INL void E_(fq6_neg)(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    E_(fq2_neg)(&r->c0, &a->c0);
    E_(fq2_neg)(&r->c1, &a->c1);
    E_(fq2_neg)(&r->c2, &a->c2);
}

/* r = a * v: (xi a2, a0, a1). */
BNE_INL void E_(fq6_mul_v)(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    struct bn_fq2 t;
    E_(fq2_mul_xi)(&t, &a->c2);
    r->c2 = a->c1;
    r->c1 = a->c0;
    r->c0 = t;
}

BNE_FN void E_(fq6_mul)(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b)
{
    struct bn_fq2 t0, t1, t2, s, u, m, rc0, rc1, rc2;
    E_(fq2_mul)(&t0, &a->c0, &b->c0);
    E_(fq2_mul)(&t1, &a->c1, &b->c1);
    E_(fq2_mul)(&t2, &a->c2, &b->c2);
    /* c0 = t0 + xi((a1+a2)(b1+b2) - t1 - t2) */
    E_(fq2_add)(&s, &a->c1, &a->c2);
    E_(fq2_add)(&u, &b->c1, &b->c2);
    E_(fq2_mul)(&m, &s, &u);
    E_(fq2_sub)(&m, &m, &t1);
    E_(fq2_sub)(&m, &m, &t2);
    E_(fq2_mul_xi)(&m, &m);
    E_(fq2_add)(&rc0, &t0, &m);
    /* c1 = (a0+a1)(b0+b1) - t0 - t1 + xi t2 */
    E_(fq2_add)(&s, &a->c0, &a->c1);
    E_(fq2_add)(&u, &b->c0, &b->c1);
    E_(fq2_mul)(&m, &s, &u);
    E_(fq2_sub)(&m, &m, &t0);
    E_(fq2_sub)(&m, &m, &t1);
    E_(fq2_mul_xi)(&s, &t2);
    E_(fq2_add)(&rc1, &m, &s);
    /* c2 = (a0+a2)(b0+b2) - t0 - t2 + t1 */
    E_(fq2_add)(&s, &a->c0, &a->c2);
    E_(fq2_add)(&u, &b->c0, &b->c2);
    E_(fq2_mul)(&m, &s, &u);
    E_(fq2_sub)(&m, &m, &t0);
    E_(fq2_sub)(&m, &m, &t2);
    E_(fq2_add)(&rc2, &m, &t1);
    r->c0 = rc0; r->c1 = rc1; r->c2 = rc2;
}

/* Chung-Hasan SQR2: 3 squarings + 2 multiplications in Fq2. */
BNE_FN void E_(fq6_sqr)(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    struct bn_fq2 s0, s1, s2, s3, s4, t, rc0, rc1, rc2;
    E_(fq2_sqr)(&s0, &a->c0);
    E_(fq2_mul)(&t, &a->c0, &a->c1);
    E_(fq2_dbl)(&s1, &t);
    E_(fq2_sub)(&t, &a->c0, &a->c1);
    E_(fq2_add)(&t, &t, &a->c2);
    E_(fq2_sqr)(&s2, &t);
    E_(fq2_mul)(&t, &a->c1, &a->c2);
    E_(fq2_dbl)(&s3, &t);
    E_(fq2_sqr)(&s4, &a->c2);
    E_(fq2_mul_xi)(&t, &s3);
    E_(fq2_add)(&rc0, &s0, &t);
    E_(fq2_mul_xi)(&t, &s4);
    E_(fq2_add)(&rc1, &s1, &t);
    E_(fq2_add)(&t, &s1, &s2);
    E_(fq2_add)(&t, &t, &s3);
    E_(fq2_sub)(&t, &t, &s0);
    E_(fq2_sub)(&rc2, &t, &s4);
    r->c0 = rc0; r->c1 = rc1; r->c2 = rc2;
}

BNE_FN void E_(fq6_inv)(struct bn_fq6 *r, const struct bn_fq6 *a)
{
    struct bn_fq2 t0, t1, t2, c0, c1, c2, t, s01, s02, s12, det, tmp1, tmp2;
    E_(fq2_sqr)(&t0, &a->c0);
    E_(fq2_sqr)(&t1, &a->c1);
    E_(fq2_sqr)(&t2, &a->c2);
    E_(fq2_mul)(&s01, &a->c0, &a->c1);
    E_(fq2_mul)(&s02, &a->c0, &a->c2);
    E_(fq2_mul)(&s12, &a->c1, &a->c2);
    E_(fq2_mul_xi)(&t, &s12);
    E_(fq2_sub)(&c0, &t0, &t);
    E_(fq2_mul_xi)(&t, &t2);
    E_(fq2_sub)(&c1, &t, &s01);
    E_(fq2_sub)(&c2, &t1, &s02);
    E_(fq2_mul)(&tmp1, &a->c2, &c1);
    E_(fq2_mul)(&tmp2, &a->c1, &c2);
    E_(fq2_add)(&tmp1, &tmp1, &tmp2);
    E_(fq2_mul_xi)(&tmp1, &tmp1);
    E_(fq2_mul)(&det, &a->c0, &c0);
    E_(fq2_add)(&det, &det, &tmp1);
    E_(fq2_inv)(&det, &det);
    E_(fq2_mul)(&r->c0, &c0, &det);
    E_(fq2_mul)(&r->c1, &c1, &det);
    E_(fq2_mul)(&r->c2, &c2, &det);
}

/* ══════════════ Fq12 = Fq6[w]/(w^2 - v) ══════════════ */

BNE_FN void E_(fq12_mul)(struct bn_fq12 *r, const struct bn_fq12 *a, const struct bn_fq12 *b)
{
    struct bn_fq6 t0, t1, s, u, c1;
    E_(fq6_mul)(&t0, &a->c0, &b->c0);
    E_(fq6_mul)(&t1, &a->c1, &b->c1);
    E_(fq6_add)(&s, &a->c0, &a->c1);
    E_(fq6_add)(&u, &b->c0, &b->c1);
    E_(fq6_mul)(&s, &s, &u);
    E_(fq6_sub)(&s, &s, &t0);
    E_(fq6_sub)(&c1, &s, &t1);
    E_(fq6_mul_v)(&t1, &t1);
    E_(fq6_add)(&r->c0, &t0, &t1);
    r->c1 = c1;
}

/* Complex squaring: (a0 + a1 w)^2 = a0^2 + v a1^2 + 2 a0 a1 w. */
BNE_FN void E_(fq12_sqr)(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    struct bn_fq6 v0, s, u, c0;
    E_(fq6_mul)(&v0, &a->c0, &a->c1);
    E_(fq6_add)(&s, &a->c0, &a->c1);
    E_(fq6_mul_v)(&u, &a->c1);
    E_(fq6_add)(&u, &a->c0, &u);
    E_(fq6_mul)(&s, &s, &u);
    E_(fq6_sub)(&s, &s, &v0);
    E_(fq6_mul_v)(&u, &v0);
    E_(fq6_sub)(&c0, &s, &u);
    E_(fq6_add)(&r->c1, &v0, &v0);
    r->c0 = c0;
}

BNE_INL void E_(fq12_conj)(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    r->c0 = a->c0;
    E_(fq6_neg)(&r->c1, &a->c1);
}

BNE_FN void E_(fq12_inv)(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    struct bn_fq6 t0, t1, det, c0, c1;
    E_(fq6_sqr)(&t0, &a->c0);
    E_(fq6_sqr)(&t1, &a->c1);
    E_(fq6_mul_v)(&t1, &t1);
    E_(fq6_sub)(&det, &t0, &t1);
    E_(fq6_inv)(&det, &det);
    E_(fq6_mul)(&c0, &a->c0, &det);
    E_(fq6_neg)(&t0, &a->c1);
    E_(fq6_mul)(&c1, &t0, &det);
    r->c0 = c0;
    r->c1 = c1;
}

/* f *= (e0 + vv*w^4 + vw*w^3): f.c0 gets (e0, 0, vv), f.c1 gets (0, vw, 0).
 * f*s = (f0 s0 + v f1 s1) + ((f0+f1)(s0+s1) - f0 s0 - f1 s1) w, with the three
 * Fq6 products done on the sparse shapes: 5 + 3 + 6 = 14 Fq2 multiplications. */
BNE_FN void E_(fq12_mul_by_024)(struct bn_fq12 *f, const struct bn_fq2 *x0,
                                const struct bn_fq2 *x4, const struct bn_fq2 *x2)
{
    const struct bn_fq2 *z0 = &f->c0.c0, *z1 = &f->c0.c1, *z2 = &f->c0.c2;
    const struct bn_fq2 *z3 = &f->c1.c0, *z4 = &f->c1.c1, *z5 = &f->c1.c2;
    struct bn_fq2 m1, m2, m3, m4, m5, s, u, A0, A1, A2, B0, B1, B2;

    /* A = f0 * (x0, 0, x2) */
    E_(fq2_mul)(&m1, z0, x0);
    E_(fq2_mul)(&m2, z1, x2);
    E_(fq2_mul)(&m3, z1, x0);
    E_(fq2_mul)(&m4, z2, x2);
    E_(fq2_add)(&s, z0, z2);
    E_(fq2_add)(&u, x0, x2);
    E_(fq2_mul)(&m5, &s, &u);
    E_(fq2_mul_xi)(&s, &m2);
    E_(fq2_add)(&A0, &m1, &s);
    E_(fq2_mul_xi)(&s, &m4);
    E_(fq2_add)(&A1, &m3, &s);
    E_(fq2_sub)(&A2, &m5, &m1);
    E_(fq2_sub)(&A2, &A2, &m4);

    /* B = f1 * (0, x4, 0) = (xi z5 x4, z3 x4, z4 x4) */
    E_(fq2_mul)(&B1, z3, x4);
    E_(fq2_mul)(&B2, z4, x4);
    E_(fq2_mul)(&s, z5, x4);
    E_(fq2_mul_xi)(&B0, &s);

    /* C = (f0 + f1) * (x0, x4, x2) */
    struct bn_fq2 g0, g1, g2, t0, t1, t2, C0, C1, C2;
    E_(fq2_add)(&g0, z0, z3);
    E_(fq2_add)(&g1, z1, z4);
    E_(fq2_add)(&g2, z2, z5);
    E_(fq2_mul)(&t0, &g0, x0);
    E_(fq2_mul)(&t1, &g1, x4);
    E_(fq2_mul)(&t2, &g2, x2);
    E_(fq2_add)(&s, &g1, &g2);
    E_(fq2_add)(&u, x4, x2);
    E_(fq2_mul)(&C0, &s, &u);
    E_(fq2_sub)(&C0, &C0, &t1);
    E_(fq2_sub)(&C0, &C0, &t2);
    E_(fq2_mul_xi)(&C0, &C0);
    E_(fq2_add)(&C0, &C0, &t0);
    E_(fq2_add)(&s, &g0, &g1);
    E_(fq2_add)(&u, x0, x4);
    E_(fq2_mul)(&C1, &s, &u);
    E_(fq2_sub)(&C1, &C1, &t0);
    E_(fq2_sub)(&C1, &C1, &t1);
    E_(fq2_mul_xi)(&s, &t2);
    E_(fq2_add)(&C1, &C1, &s);
    E_(fq2_add)(&s, &g0, &g2);
    E_(fq2_add)(&u, x0, x2);
    E_(fq2_mul)(&C2, &s, &u);
    E_(fq2_sub)(&C2, &C2, &t0);
    E_(fq2_sub)(&C2, &C2, &t2);
    E_(fq2_add)(&C2, &C2, &t1);

    /* c1 = C - A - B ; c0 = A + v B */
    E_(fq2_sub)(&f->c1.c0, &C0, &A0);
    E_(fq2_sub)(&f->c1.c0, &f->c1.c0, &B0);
    E_(fq2_sub)(&f->c1.c1, &C1, &A1);
    E_(fq2_sub)(&f->c1.c1, &f->c1.c1, &B1);
    E_(fq2_sub)(&f->c1.c2, &C2, &A2);
    E_(fq2_sub)(&f->c1.c2, &f->c1.c2, &B2);
    E_(fq2_mul_xi)(&s, &B2);
    E_(fq2_add)(&f->c0.c0, &A0, &s);
    E_(fq2_add)(&f->c0.c1, &A1, &B0);
    E_(fq2_add)(&f->c0.c2, &A2, &B1);
}

/* Granger-Scott squaring, valid only inside the cyclotomic subgroup (every
 * value after the easy part of the final exponentiation). */
BNE_FN void E_(fq12_cyc_sqr)(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    struct bn_fq2 z0 = a->c0.c0, z4 = a->c0.c1, z3 = a->c0.c2;
    struct bn_fq2 z2 = a->c1.c0, z1 = a->c1.c1, z5 = a->c1.c2;
    struct bn_fq2 t0, t1, t2, t3, t4, t5, s, A, B, C;

    /* (z0 + z1 y)^2 with y^2 = xi: t0 = z0^2 + xi z1^2, t1 = 2 z0 z1 */
    E_(fq2_sqr)(&A, &z0);
    E_(fq2_sqr)(&B, &z1);
    E_(fq2_add)(&s, &z0, &z1);
    E_(fq2_sqr)(&C, &s);
    E_(fq2_mul_xi)(&t0, &B);
    E_(fq2_add)(&t0, &t0, &A);
    E_(fq2_sub)(&t1, &C, &A);
    E_(fq2_sub)(&t1, &t1, &B);
    /* (z2 + z3 y)^2 */
    E_(fq2_sqr)(&A, &z2);
    E_(fq2_sqr)(&B, &z3);
    E_(fq2_add)(&s, &z2, &z3);
    E_(fq2_sqr)(&C, &s);
    E_(fq2_mul_xi)(&t2, &B);
    E_(fq2_add)(&t2, &t2, &A);
    E_(fq2_sub)(&t3, &C, &A);
    E_(fq2_sub)(&t3, &t3, &B);
    /* (z4 + z5 y)^2 */
    E_(fq2_sqr)(&A, &z4);
    E_(fq2_sqr)(&B, &z5);
    E_(fq2_add)(&s, &z4, &z5);
    E_(fq2_sqr)(&C, &s);
    E_(fq2_mul_xi)(&t4, &B);
    E_(fq2_add)(&t4, &t4, &A);
    E_(fq2_sub)(&t5, &C, &A);
    E_(fq2_sub)(&t5, &t5, &B);

    /* z0 = 3 t0 - 2 z0 */
    E_(fq2_sub)(&z0, &t0, &z0); E_(fq2_dbl)(&z0, &z0); E_(fq2_add)(&z0, &z0, &t0);
    /* z1 = 3 t1 + 2 z1 */
    E_(fq2_add)(&z1, &t1, &z1); E_(fq2_dbl)(&z1, &z1); E_(fq2_add)(&z1, &z1, &t1);
    /* z2 = 3 xi t5 + 2 z2 */
    E_(fq2_mul_xi)(&s, &t5);
    E_(fq2_add)(&z2, &s, &z2); E_(fq2_dbl)(&z2, &z2); E_(fq2_add)(&z2, &z2, &s);
    /* z3 = 3 t4 - 2 z3 */
    E_(fq2_sub)(&z3, &t4, &z3); E_(fq2_dbl)(&z3, &z3); E_(fq2_add)(&z3, &z3, &t4);
    /* z4 = 3 t2 - 2 z4 */
    E_(fq2_sub)(&z4, &t2, &z4); E_(fq2_dbl)(&z4, &z4); E_(fq2_add)(&z4, &z4, &t2);
    /* z5 = 3 t3 + 2 z5 */
    E_(fq2_add)(&z5, &t3, &z5); E_(fq2_dbl)(&z5, &z5); E_(fq2_add)(&z5, &z5, &t3);

    r->c0.c0 = z0; r->c0.c1 = z4; r->c0.c2 = z3;
    r->c1.c0 = z2; r->c1.c1 = z1; r->c1.c2 = z5;
}

/* Frobenius maps with the per-coefficient constants pre-multiplied. */
BNE_FN void E_(fq12_frob1)(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    struct bn_fq2 t;
    E_(fq2_conj)(&r->c0.c0, &a->c0.c0);
    E_(fq2_conj)(&t, &a->c0.c1); E_(fq2_mul)(&r->c0.c1, &t, &g_frob.w1_1);
    E_(fq2_conj)(&t, &a->c0.c2); E_(fq2_mul)(&r->c0.c2, &t, &g_frob.w1_2);
    E_(fq2_conj)(&t, &a->c1.c0); E_(fq2_mul)(&r->c1.c0, &t, &g_frob.w1_6);
    E_(fq2_conj)(&t, &a->c1.c1); E_(fq2_mul)(&r->c1.c1, &t, &g_frob.k1_1);
    E_(fq2_conj)(&t, &a->c1.c2); E_(fq2_mul)(&r->c1.c2, &t, &g_frob.k1_2);
}

BNE_FN void E_(fq12_frob2)(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    r->c0.c0 = a->c0.c0;
    E_(fq2_mul_fq)(&r->c0.c1, &a->c0.c1, &g_frob.w2_1);
    E_(fq2_mul_fq)(&r->c0.c2, &a->c0.c2, &g_frob.w2_2);
    E_(fq2_mul_fq)(&r->c1.c0, &a->c1.c0, &g_frob.w2_6);
    E_(fq2_mul_fq)(&r->c1.c1, &a->c1.c1, &g_frob.k2_1);
    E_(fq2_mul_fq)(&r->c1.c2, &a->c1.c2, &g_frob.k2_2);
}

BNE_FN void E_(fq12_frob3)(struct bn_fq12 *r, const struct bn_fq12 *a)
{
    struct bn_fq2 t;
    E_(fq2_conj)(&r->c0.c0, &a->c0.c0);
    E_(fq2_conj)(&t, &a->c0.c1); E_(fq2_mul)(&r->c0.c1, &t, &g_frob.w3_1);
    E_(fq2_conj)(&t, &a->c0.c2); E_(fq2_mul)(&r->c0.c2, &t, &g_frob.w3_2);
    E_(fq2_conj)(&t, &a->c1.c0); E_(fq2_mul)(&r->c1.c0, &t, &g_frob.w3_6);
    E_(fq2_conj)(&t, &a->c1.c1); E_(fq2_mul)(&r->c1.c1, &t, &g_frob.k3_1);
    E_(fq2_conj)(&t, &a->c1.c2); E_(fq2_mul)(&r->c1.c2, &t, &g_frob.k3_2);
}

/* ══════════════ G1 (Jacobian, a = 0) ══════════════ */

BNE_FN void E_(g1_dbl)(struct bn_g1 *r, const struct bn_g1 *a)
{
    if (E_(fq_is_zero)(&a->z)) { *r = *a; return; }
    struct bn_fq A, B, C, D, E, F, t, x3, y3, z3;
    E_(fq_sqr)(&A, &a->x);
    E_(fq_sqr)(&B, &a->y);
    E_(fq_sqr)(&C, &B);
    E_(fq_add)(&t, &a->x, &B);
    E_(fq_sqr)(&t, &t);
    E_(fq_sub)(&t, &t, &A);
    E_(fq_sub)(&t, &t, &C);
    E_(fq_dbl)(&D, &t);
    E_(fq_dbl)(&E, &A);
    E_(fq_add)(&E, &E, &A);
    E_(fq_sqr)(&F, &E);
    E_(fq_mul)(&z3, &a->y, &a->z);
    E_(fq_dbl)(&z3, &z3);
    E_(fq_dbl)(&t, &D);
    E_(fq_sub)(&x3, &F, &t);
    E_(fq_sub)(&t, &D, &x3);
    E_(fq_mul)(&t, &E, &t);
    E_(fq_dbl)(&C, &C);
    E_(fq_dbl)(&C, &C);
    E_(fq_dbl)(&C, &C);
    E_(fq_sub)(&y3, &t, &C);
    r->x = x3; r->y = y3; r->z = z3;
}

/* Complete Jacobian + affine addition. (bx, by) is a finite affine point. */
BNE_FN void E_(g1_add_mixed)(struct bn_g1 *r, const struct bn_g1 *a,
                             const struct bn_fq *bx, const struct bn_fq *by)
{
    if (E_(fq_is_zero)(&a->z)) {
        r->x = *bx; r->y = *by; r->z = g_eng.fq_one;
        return;
    }
    struct bn_fq z1z1, u2, s2, h, hh, i, j, rr, v, t, x3, y3, z3;
    E_(fq_sqr)(&z1z1, &a->z);
    E_(fq_mul)(&u2, bx, &z1z1);
    E_(fq_mul)(&s2, by, &a->z);
    E_(fq_mul)(&s2, &s2, &z1z1);
    E_(fq_sub)(&h, &u2, &a->x);
    E_(fq_sub)(&rr, &s2, &a->y);
    if (E_(fq_is_zero)(&h)) {
        if (E_(fq_is_zero)(&rr)) { E_(g1_dbl)(r, a); return; }
        r->x = g_eng.fq_zero; r->y = g_eng.fq_one; r->z = g_eng.fq_zero;
        return;
    }
    E_(fq_sqr)(&hh, &h);
    E_(fq_dbl)(&i, &hh);
    E_(fq_dbl)(&i, &i);
    E_(fq_mul)(&j, &h, &i);
    E_(fq_dbl)(&rr, &rr);
    E_(fq_mul)(&v, &a->x, &i);
    E_(fq_sqr)(&x3, &rr);
    E_(fq_sub)(&x3, &x3, &j);
    E_(fq_dbl)(&t, &v);
    E_(fq_sub)(&x3, &x3, &t);
    E_(fq_sub)(&t, &v, &x3);
    E_(fq_mul)(&y3, &rr, &t);
    E_(fq_mul)(&t, &a->y, &j);
    E_(fq_dbl)(&t, &t);
    E_(fq_sub)(&y3, &y3, &t);
    E_(fq_add)(&z3, &a->z, &h);
    E_(fq_sqr)(&z3, &z3);
    E_(fq_sub)(&z3, &z3, &z1z1);
    E_(fq_sub)(&z3, &z3, &hh);
    r->x = x3; r->y = y3; r->z = z3;
}

/* Complete Jacobian + Jacobian addition (the original bn_g1_add). */
BNE_FN void E_(g1_add)(struct bn_g1 *r, const struct bn_g1 *a, const struct bn_g1 *b)
{
    if (E_(fq_is_zero)(&a->z)) { *r = *b; return; }
    if (E_(fq_is_zero)(&b->z)) { *r = *a; return; }
    struct bn_fq z1sq, z2sq, u1, u2, s1, s2, h, i, j, rr, v, t, x3, y3, z3;
    E_(fq_sqr)(&z1sq, &a->z);
    E_(fq_sqr)(&z2sq, &b->z);
    E_(fq_mul)(&u1, &a->x, &z2sq);
    E_(fq_mul)(&u2, &b->x, &z1sq);
    E_(fq_mul)(&s1, &a->y, &z2sq);
    E_(fq_mul)(&s1, &s1, &b->z);
    E_(fq_mul)(&s2, &b->y, &z1sq);
    E_(fq_mul)(&s2, &s2, &a->z);
    if (E_(fq_eq)(&u1, &u2)) {
        if (E_(fq_eq)(&s1, &s2)) { E_(g1_dbl)(r, a); return; }
        r->x = g_eng.fq_zero; r->y = g_eng.fq_one; r->z = g_eng.fq_zero;
        return;
    }
    E_(fq_sub)(&h, &u2, &u1);
    E_(fq_dbl)(&i, &h);
    E_(fq_sqr)(&i, &i);
    E_(fq_mul)(&j, &h, &i);
    E_(fq_sub)(&rr, &s2, &s1);
    E_(fq_dbl)(&rr, &rr);
    E_(fq_mul)(&v, &u1, &i);
    E_(fq_sqr)(&x3, &rr);
    E_(fq_sub)(&x3, &x3, &j);
    E_(fq_dbl)(&t, &v);
    E_(fq_sub)(&x3, &x3, &t);
    E_(fq_sub)(&y3, &v, &x3);
    E_(fq_mul)(&y3, &rr, &y3);
    E_(fq_mul)(&t, &s1, &j);
    E_(fq_dbl)(&t, &t);
    E_(fq_sub)(&y3, &y3, &t);
    E_(fq_add)(&z3, &a->z, &b->z);
    E_(fq_sqr)(&z3, &z3);
    E_(fq_sub)(&z3, &z3, &z1sq);
    E_(fq_sub)(&z3, &z3, &z2sq);
    E_(fq_mul)(&z3, &z3, &h);
    r->x = x3; r->y = y3; r->z = z3;
}

/* Affine coordinates of a finite Jacobian point. z == 1 needs no inversion. */
BNE_FN void E_(g1_to_affine)(struct bn_fq *ax, struct bn_fq *ay, const struct bn_g1 *p)
{
    if (E_(fq_eq)(&p->z, &g_eng.fq_one)) { *ax = p->x; *ay = p->y; return; }
    struct bn_fq zi, zi2, zi3;
    E_(fq_inv)(&zi, &p->z);
    E_(fq_sqr)(&zi2, &zi);
    E_(fq_mul)(&zi3, &zi2, &zi);
    E_(fq_mul)(ax, &p->x, &zi2);
    E_(fq_mul)(ay, &p->y, &zi3);
}

/* Plain double-and-add (LSB first), used when no precomputed table applies. */
BNE_FN void E_(g1_scalar_mul)(struct bn_g1 *r, const struct bn_g1 *p, const uint64_t s[4])
{
    struct bn_g1 acc, base = *p;
    acc.x = g_eng.fq_zero; acc.y = g_eng.fq_one; acc.z = g_eng.fq_zero;
    for (int i = 0; i < 4; i++)
        for (int bit = 0; bit < 64; bit++) {
            if ((s[i] >> bit) & 1)
                E_(g1_add)(&acc, &acc, &base);
            E_(g1_dbl)(&base, &base);
        }
    *r = acc;
}

/* ══════════════ G2 (Jacobian on the twist) ══════════════ */

BNE_FN void E_(g2_dbl)(struct bn_g2 *r, const struct bn_g2 *a)
{
    if (E_(fq2_is_zero)(&a->z)) { *r = *a; return; }
    struct bn_fq2 A, B, C, D, E, F, t, x3, y3, z3;
    E_(fq2_sqr)(&A, &a->x);
    E_(fq2_sqr)(&B, &a->y);
    E_(fq2_sqr)(&C, &B);
    E_(fq2_add)(&t, &a->x, &B);
    E_(fq2_sqr)(&t, &t);
    E_(fq2_sub)(&t, &t, &A);
    E_(fq2_sub)(&t, &t, &C);
    E_(fq2_dbl)(&D, &t);
    E_(fq2_dbl)(&E, &A);
    E_(fq2_add)(&E, &E, &A);
    E_(fq2_sqr)(&F, &E);
    E_(fq2_mul)(&z3, &a->y, &a->z);
    E_(fq2_dbl)(&z3, &z3);
    E_(fq2_dbl)(&t, &D);
    E_(fq2_sub)(&x3, &F, &t);
    E_(fq2_sub)(&t, &D, &x3);
    E_(fq2_mul)(&t, &E, &t);
    E_(fq2_dbl)(&C, &C);
    E_(fq2_dbl)(&C, &C);
    E_(fq2_dbl)(&C, &C);
    E_(fq2_sub)(&y3, &t, &C);
    r->x = x3; r->y = y3; r->z = z3;
}

/* Complete Jacobian + Jacobian addition (the original bn_g2_add). */
BNE_FN void E_(g2_add)(struct bn_g2 *r, const struct bn_g2 *a, const struct bn_g2 *b)
{
    if (E_(fq2_is_zero)(&a->z)) { *r = *b; return; }
    if (E_(fq2_is_zero)(&b->z)) { *r = *a; return; }
    struct bn_fq2 z1sq, z2sq, u1, u2, s1, s2, h, i, j, rr, v, t, x3, y3, z3;
    E_(fq2_sqr)(&z1sq, &a->z);
    E_(fq2_sqr)(&z2sq, &b->z);
    E_(fq2_mul)(&u1, &a->x, &z2sq);
    E_(fq2_mul)(&u2, &b->x, &z1sq);
    E_(fq2_mul)(&s1, &a->y, &z2sq);
    E_(fq2_mul)(&s1, &s1, &b->z);
    E_(fq2_mul)(&s2, &b->y, &z1sq);
    E_(fq2_mul)(&s2, &s2, &a->z);
    if (E_(fq2_eq)(&u1, &u2)) {
        if (E_(fq2_eq)(&s1, &s2)) { E_(g2_dbl)(r, a); return; }
        r->x.c0 = g_eng.fq_zero; r->x.c1 = g_eng.fq_zero;
        r->y.c0 = g_eng.fq_one; r->y.c1 = g_eng.fq_zero;
        r->z.c0 = g_eng.fq_zero; r->z.c1 = g_eng.fq_zero;
        return;
    }
    E_(fq2_sub)(&h, &u2, &u1);
    E_(fq2_dbl)(&i, &h);
    E_(fq2_sqr)(&i, &i);
    E_(fq2_mul)(&j, &h, &i);
    E_(fq2_sub)(&rr, &s2, &s1);
    E_(fq2_dbl)(&rr, &rr);
    E_(fq2_mul)(&v, &u1, &i);
    E_(fq2_sqr)(&x3, &rr);
    E_(fq2_sub)(&x3, &x3, &j);
    E_(fq2_dbl)(&t, &v);
    E_(fq2_sub)(&x3, &x3, &t);
    E_(fq2_sub)(&y3, &v, &x3);
    E_(fq2_mul)(&y3, &rr, &y3);
    E_(fq2_mul)(&t, &s1, &j);
    E_(fq2_dbl)(&t, &t);
    E_(fq2_sub)(&y3, &y3, &t);
    E_(fq2_add)(&z3, &a->z, &b->z);
    E_(fq2_sqr)(&z3, &z3);
    E_(fq2_sub)(&z3, &z3, &z1sq);
    E_(fq2_sub)(&z3, &z3, &z2sq);
    E_(fq2_mul)(&z3, &z3, &h);
    r->x = x3; r->y = y3; r->z = z3;
}

BNE_FN void E_(g2_to_affine)(struct bn_fq2 *ax, struct bn_fq2 *ay, const struct bn_g2 *p)
{
    struct bn_fq2 zi, zi2, zi3;
    E_(fq2_inv)(&zi, &p->z);
    E_(fq2_sqr)(&zi2, &zi);
    E_(fq2_mul)(&zi3, &zi2, &zi);
    E_(fq2_mul)(ax, &p->x, &zi2);
    E_(fq2_mul)(ay, &p->y, &zi3);
}

/* psi, the untwist-Frobenius-twist endomorphism, on an affine point. */
BNE_INL void E_(g2_psi_affine)(struct bn_fq2 *rx, struct bn_fq2 *ry,
                               const struct bn_fq2 *qx, const struct bn_fq2 *qy)
{
    struct bn_fq2 cx, cy;
    E_(fq2_conj)(&cx, qx);
    E_(fq2_conj)(&cy, qy);
    E_(fq2_mul)(rx, &g_frob.twist_frob_x, &cx);
    E_(fq2_mul)(ry, &g_frob.twist_frob_y, &cy);
}

/* [u]P for the BN parameter u (63 bits), P a finite affine-or-Jacobian point:
 * MSB-first double-and-add with the complete addition. */
BNE_FN void E_(g2_mul_u)(struct bn_g2 *r, const struct bn_g2 *p)
{
    struct bn_g2 acc = *p;
    for (int i = 61; i >= 0; i--) {
        E_(g2_dbl)(&acc, &acc);
        if ((BNE_U >> i) & 1)
            E_(g2_add)(&acc, &acc, p);
    }
    *r = acc;
}

/* True iff the finite affine twist point P (on y^2 = x^3 + b') lies in the
 * order-r subgroup G2, i.e. iff r*P = O (zclassicd Proof.cpp:166).
 *
 * Test used here: psi(P) == [6u^2]P.
 *
 * Proof. Let E' be the twist over Fq2, t = 6u^2 + 1 the trace of Frobenius of
 * the BN254 base curve, p = q the field characteristic and r = 36u^4 + 36u^3 +
 * 18u^2 + 6u + 1, with p = 36u^4 + 36u^3 + 24u^2 + 6u + 1 (BN family), so that
 * p + 1 - t = r. psi = phi^-1 o pi o phi (phi the degree-6 twist isomorphism,
 * pi the q-power Frobenius of the base curve) is an endomorphism of E' of
 * degree p; pi satisfies pi^2 - t pi + p = 0, hence so does psi, so
 * deg(psi - [m]) = m^2 - t m + p for every integer m. With m = 6u^2:
 *   m^2 - t m + p = 36u^4 - (6u^2 + 1) 6u^2 + p = p - 6u^2
 *                 = 36u^4 + 36u^3 + 18u^2 + 6u + 1 = r.
 * An isogeny of degree r has a kernel of at most r points, so
 * K = { P in E'(Fq2-bar) : psi(P) = [6u^2]P } has |K| <= r. G2 = E'(Fq2)[r] is
 * cyclic of order r (r^2 does not divide #E'(Fq2) = r (2q - r)) and psi acts on
 * it as multiplication by q mod r = 6u^2 mod r, so G2 is contained in K, and
 * |G2| = r >= |K| forces K = G2. A finite point passes the test iff it is in G2.
 * The Frobenius-eigenvalue claim, the constants of psi and the identity above
 * are checked numerically by the unit test (psi(G2 generator) == [6u^2]G2
 * generator, random subgroup and non-subgroup points against the [r]P == O
 * test of the original implementation). */
BNE_FN bool E_(g2_in_subgroup)(const struct bn_g2 *p)
{
    struct bn_fq2 px, py, qx, qy;
    if (E_(fq2_is_zero)(&p->z)) return true; /* r*O == O */
    if (E_(fq2_eq)(&p->z, &g_eng.fq2_one)) { px = p->x; py = p->y; }
    else E_(g2_to_affine)(&px, &py, p);
    struct bn_g2 ap, t1, t2, d, e, s;
    ap.x = px; ap.y = py; ap.z = g_eng.fq2_one;
    E_(g2_mul_u)(&t1, &ap);          /* [u]P */
    E_(g2_mul_u)(&t2, &t1);          /* [u^2]P */
    E_(g2_dbl)(&d, &t2);             /* 2 u^2 P */
    E_(g2_dbl)(&e, &d);              /* 4 u^2 P */
    E_(g2_add)(&s, &d, &e);          /* 6 u^2 P */
    E_(g2_psi_affine)(&qx, &qy, &px, &py);
    if (E_(fq2_is_zero)(&s.z)) return false; /* psi(P) is finite */
    /* psi(P) == S  <=>  qx * Z^2 == X and qy * Z^3 == Y (S Jacobian) */
    struct bn_fq2 z2, z3, l;
    E_(fq2_sqr)(&z2, &s.z);
    E_(fq2_mul)(&z3, &z2, &s.z);
    E_(fq2_mul)(&l, &qx, &z2);
    if (!E_(fq2_eq)(&l, &s.x)) return false;
    E_(fq2_mul)(&l, &qy, &z3);
    return E_(fq2_eq)(&l, &s.y);
}

/* ══════════════ Miller loop with precomputed line functions ══════════════
 *
 * A G2 point Q yields BN_NLINES lines, in application order: for each of the 64
 * loop iterations a doubling line and, when the bit of 6u+2 is set, an addition
 * line; then the two Frobenius additions. The line values (e0, vw, vv) are the
 * ones the original doubling_step / mixed_addition_step produced, unscaled; the
 * scaling by the G1 point (vw * yP, vv * xP) is done when a line is used. */

BNE_FN void E_(dbl_step)(struct bn_g2 *cur, struct bn_line *ln)
{
    struct bn_fq2 X = cur->x, Y = cur->y, Z = cur->z;
    struct bn_fq2 XY, A, B, C, D, E, F, G, H, I, J, Esq, t, t2;
    E_(fq2_mul)(&XY, &X, &Y);
    E_(fq2_mul_fq)(&A, &XY, &g_eng.two_inv);
    E_(fq2_sqr)(&B, &Y);
    E_(fq2_sqr)(&C, &Z);
    E_(fq2_dbl)(&D, &C);
    E_(fq2_add)(&D, &D, &C);                 /* D = 3C */
    E_(fq2_mul)(&E, &g_eng.twist_b, &D);     /* E = b' D */
    E_(fq2_dbl)(&F, &E);
    E_(fq2_add)(&F, &F, &E);                 /* F = 3E */
    E_(fq2_add)(&t, &B, &F);
    E_(fq2_mul_fq)(&G, &t, &g_eng.two_inv);  /* G = (B+F)/2 */
    E_(fq2_add)(&t, &Y, &Z);
    E_(fq2_sqr)(&t, &t);
    E_(fq2_add)(&t2, &B, &C);
    E_(fq2_sub)(&H, &t, &t2);                /* H = (Y+Z)^2 - (B+C) */
    E_(fq2_sub)(&I, &E, &B);                 /* I = E - B */
    E_(fq2_sqr)(&J, &X);                     /* J = X^2 */
    E_(fq2_sqr)(&Esq, &E);
    E_(fq2_sub)(&t, &B, &F);
    E_(fq2_mul)(&cur->x, &A, &t);            /* X3 = A (B - F) */
    E_(fq2_sqr)(&t, &G);
    E_(fq2_dbl)(&t2, &Esq);
    E_(fq2_add)(&t2, &t2, &Esq);
    E_(fq2_sub)(&cur->y, &t, &t2);           /* Y3 = G^2 - 3 E^2 */
    E_(fq2_mul)(&cur->z, &B, &H);            /* Z3 = B H */
    E_(fq2_mul_xi)(&ln->e0, &I);
    E_(fq2_neg)(&ln->vw, &H);
    E_(fq2_dbl)(&ln->vv, &J);
    E_(fq2_add)(&ln->vv, &ln->vv, &J);       /* 3 J */
}

BNE_FN void E_(add_step)(struct bn_g2 *cur, const struct bn_fq2 *x2,
                         const struct bn_fq2 *y2, struct bn_line *ln)
{
    struct bn_fq2 X1 = cur->x, Y1 = cur->y, Z1 = cur->z;
    struct bn_fq2 D, E, F, G, H, I, J, x2Z1, y2Z1, Z1G, twoI, ImJ, HY1, Ex2, Dy2, t;
    E_(fq2_mul)(&x2Z1, x2, &Z1);
    E_(fq2_sub)(&D, &X1, &x2Z1);
    E_(fq2_mul)(&y2Z1, y2, &Z1);
    E_(fq2_sub)(&E, &Y1, &y2Z1);
    E_(fq2_sqr)(&F, &D);
    E_(fq2_sqr)(&G, &E);
    E_(fq2_mul)(&H, &D, &F);
    E_(fq2_mul)(&I, &X1, &F);
    E_(fq2_mul)(&Z1G, &Z1, &G);
    E_(fq2_dbl)(&twoI, &I);
    E_(fq2_add)(&J, &H, &Z1G);
    E_(fq2_sub)(&J, &J, &twoI);
    E_(fq2_mul)(&cur->x, &D, &J);
    E_(fq2_sub)(&ImJ, &I, &J);
    E_(fq2_mul)(&ImJ, &E, &ImJ);
    E_(fq2_mul)(&HY1, &H, &Y1);
    E_(fq2_sub)(&cur->y, &ImJ, &HY1);
    E_(fq2_mul)(&cur->z, &Z1, &H);
    E_(fq2_mul)(&Ex2, &E, x2);
    E_(fq2_mul)(&Dy2, &D, y2);
    E_(fq2_sub)(&t, &Ex2, &Dy2);
    E_(fq2_mul_xi)(&ln->e0, &t);
    E_(fq2_neg)(&ln->vv, &E);
    ln->vw = D;
}

/* Fill ln[BN_NLINES] for the affine point (qx, qy). */
BNE_FN void E_(g2_lines)(struct bn_line *ln, const struct bn_fq2 *qx, const struct bn_fq2 *qy)
{
    struct bn_g2 R;
    R.x = *qx; R.y = *qy; R.z = g_eng.fq2_one;
    int n = 0;
    for (int i = 63; i >= 0; i--) {
        E_(dbl_step)(&R, &ln[n++]);
        if ((ATE_LOOP[0] >> i) & 1)
            E_(add_step)(&R, qx, qy, &ln[n++]);
    }
    struct bn_fq2 q1x, q1y, q2x, q2y;
    E_(g2_psi_affine)(&q1x, &q1y, qx, qy);
    E_(g2_psi_affine)(&q2x, &q2y, &q1x, &q1y);
    E_(fq2_neg)(&q2y, &q2y);
    E_(add_step)(&R, &q1x, &q1y, &ln[n++]);
    E_(add_step)(&R, &q2x, &q2y, &ln[n++]);
}

/* f *= line scaled by the affine G1 point (xp, yp). */
BNE_INL void E_(apply_line)(struct bn_fq12 *f, const struct bn_line *ln,
                            const struct bn_fq *xp, const struct bn_fq *yp)
{
    struct bn_fq2 vw, vv;
    E_(fq2_mul_fq)(&vw, &ln->vw, yp);
    E_(fq2_mul_fq)(&vv, &ln->vv, xp);
    E_(fq12_mul_by_024)(f, &ln->e0, &vw, &vv);
}

/* Product of the Miller loops of n pairs, with the squarings shared. A pair is
 * (lines of Q, xP, yP); pairs whose P or Q is the identity must not be passed
 * (their Miller value is 1). */
BNE_FN void E_(miller_multi)(struct bn_fq12 *f, const struct bn_pair *pr, size_t n)
{
    size_t idx = 0;
    /* first iteration: f = 1, so f^2 = 1 and the first line is f itself */
    bool first = true;
    for (int i = 63; i >= 0; i--) {
        if (!first)
            E_(fq12_sqr)(f, f);
        for (size_t k = 0; k < n; k++) {
            if (first && k == 0) {
                struct bn_fq2 vw, vv;
                const struct bn_line *ln = &pr[0].lines[idx];
                E_(fq2_mul_fq)(&vw, &ln->vw, pr[0].yp);
                E_(fq2_mul_fq)(&vv, &ln->vv, pr[0].xp);
                memset(f, 0, sizeof(*f));
                f->c0.c0 = ln->e0;
                f->c0.c2 = vv;
                f->c1.c1 = vw;
            } else {
                E_(apply_line)(f, &pr[k].lines[idx], pr[k].xp, pr[k].yp);
            }
        }
        first = false;
        idx++;
        if ((ATE_LOOP[0] >> i) & 1) {
            for (size_t k = 0; k < n; k++)
                E_(apply_line)(f, &pr[k].lines[idx], pr[k].xp, pr[k].yp);
            idx++;
        }
    }
    for (int j = 0; j < 2; j++) {
        for (size_t k = 0; k < n; k++)
            E_(apply_line)(f, &pr[k].lines[idx], pr[k].xp, pr[k].yp);
        idx++;
    }
}

/* f^z, z = 4965661367192848881, for f in the cyclotomic subgroup; then the
 * conjugate, i.e. f^{-z}. MSB-first square-and-multiply. */
BNE_FN void E_(exp_by_neg_z)(struct bn_fq12 *r, const struct bn_fq12 *f)
{
    struct bn_fq12 acc = *f; /* bit 62 of z is its top set bit */
    for (int i = 61; i >= 0; i--) {
        E_(fq12_cyc_sqr)(&acc, &acc);
        if ((BNE_U >> i) & 1)
            E_(fq12_mul)(&acc, &acc, f);
    }
    E_(fq12_conj)(r, &acc);
}

/* f^{(p^12-1)/r * m}, the same exponent and chain as the original. */
BNE_FN void E_(final_exp)(struct bn_fq12 *f)
{
    struct bn_fq12 t0, t1;
    E_(fq12_conj)(&t0, f);
    E_(fq12_inv)(&t1, f);
    E_(fq12_mul)(f, &t0, &t1);
    E_(fq12_frob2)(&t0, f);
    E_(fq12_mul)(f, &t0, f);

    struct bn_fq12 A, B, C, D, E, F2, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U;
    E_(exp_by_neg_z)(&A, f);
    E_(fq12_cyc_sqr)(&B, &A);
    E_(fq12_cyc_sqr)(&C, &B);
    E_(fq12_mul)(&D, &C, &B);
    E_(exp_by_neg_z)(&E, &D);
    E_(fq12_cyc_sqr)(&F2, &E);
    E_(exp_by_neg_z)(&G, &F2);
    E_(fq12_conj)(&H, &D);
    E_(fq12_conj)(&I, &G);
    E_(fq12_mul)(&J, &I, &E);
    E_(fq12_mul)(&K, &J, &H);
    E_(fq12_mul)(&L, &K, &B);
    E_(fq12_mul)(&M, &K, &E);
    E_(fq12_mul)(&N, &M, f);
    E_(fq12_frob1)(&O, &L);
    E_(fq12_mul)(&P, &O, &N);
    E_(fq12_frob2)(&Q, &K);
    E_(fq12_mul)(&R, &Q, &P);
    E_(fq12_conj)(&S, f);
    E_(fq12_mul)(&T, &S, &L);
    E_(fq12_frob3)(&U, &T);
    E_(fq12_mul)(f, &U, &R);
}

/* ══════════════ decompression ══════════════ */

BNE_FN bool E_(g1_decompress)(struct bn_g1 *p, const uint8_t data[33])
{
    if ((data[0] & 0xFE) != 0x02)
        return false;
    bool y_lsb = (data[0] & 0x01) != 0;
    if (!bn_fq_from_bytes_be(&p->x, data + 1))
        return false;
    struct bn_fq x3;
    E_(fq_sqr)(&x3, &p->x);
    E_(fq_mul)(&x3, &x3, &p->x);
    E_(fq_add)(&x3, &x3, &g_eng.three);
    if (!E_(fq_sqrt)(&p->y, &x3))
        return false;
    /* canonical low bit of y: Montgomery -> integer is a multiply by 1 */
    uint64_t raw[4];
    static const uint64_t one[4] = {1, 0, 0, 0};
    BNE_MUL(raw, p->y.d, one);
    if (((raw[0] & 1) != 0) != y_lsb)
        E_(fq_neg)(&p->y, &p->y);
    p->z = g_eng.fq_one;
    return true;
}

/* sqrt of a0 (in Fq) inside Fq2: root a, or t*u with t^2 = -a0. */
BNE_FN bool E_(fq2_sqrt_of_fq)(struct bn_fq2 *r, const struct bn_fq *a0)
{
    struct bn_fq t, neg;
    if (E_(fq_sqrt)(&t, a0)) {
        r->c0 = t;
        r->c1 = g_eng.fq_zero;
        return true;
    }
    E_(fq_neg)(&neg, a0);
    if (!E_(fq_sqrt)(&t, &neg))
        return false;
    r->c0 = g_eng.fq_zero;
    r->c1 = t;
    return true;
}

BNE_FN bool E_(fq2_sqrt)(struct bn_fq2 *r, const struct bn_fq2 *a)
{
    const struct bn_fq2 in = *a;
    if (E_(fq_is_zero)(&in.c1))
        return E_(fq2_sqrt_of_fq)(r, &in.c0);
    struct bn_fq norm, d, s, y0, den, t1;
    E_(fq_sqr)(&norm, &in.c0);
    E_(fq_sqr)(&t1, &in.c1);
    E_(fq_add)(&norm, &norm, &t1);
    if (!E_(fq_sqrt)(&d, &norm))
        return false;
    E_(fq_add)(&s, &in.c0, &d);
    E_(fq_mul)(&s, &s, &g_eng.two_inv);
    if (!E_(fq_sqrt)(&y0, &s)) {
        E_(fq_sub)(&s, &in.c0, &d);
        E_(fq_mul)(&s, &s, &g_eng.two_inv);
        if (!E_(fq_sqrt)(&y0, &s))
            return false;
    }
    if (E_(fq_is_zero)(&y0))
        return false;
    E_(fq_add)(&den, &y0, &y0);
    E_(fq_inv)(&den, &den);
    r->c0 = y0;
    E_(fq_mul)(&r->c1, &in.c1, &den);
    struct bn_fq2 chk;
    E_(fq2_sqr)(&chk, r);
    return E_(fq2_eq)(&chk, &in);
}

BNE_FN bool E_(g2_decompress)(struct bn_g2 *p, const uint8_t data[65])
{
    if ((data[0] & 0xFE) != 0x0a)
        return false;
    bool y_gt = (data[0] & 0x01) != 0;
    if (!fq2_decode_fe2ip(&p->x.c0, &p->x.c1, data + 1))
        return false;
    struct bn_fq2 rhs, y, neg_y;
    E_(fq2_sqr)(&rhs, &p->x);
    E_(fq2_mul)(&rhs, &rhs, &p->x);
    E_(fq2_add)(&rhs, &rhs, &g_eng.twist_b);
    if (!E_(fq2_sqrt)(&y, &rhs))
        return false;
    E_(fq2_neg)(&neg_y, &y);
    if ((bn_fq2_fe2ip_cmp(&y, &neg_y) > 0) != y_gt)
        y = neg_y;
    p->y = y;
    p->z = g_eng.fq2_one;
    return E_(g2_in_subgroup)(p);
}

/* ══════════════ PPZKSNARK verification ══════════════ */

/* acc = ic[0] + sum in[i] * ic[i+1], Straus with 4-bit windows over the
 * prepared affine tables when present, else plain double-and-add. */
BNE_FN void E_(accumulate)(struct bn_g1 *acc, const struct bn_phgr_prep *pp,
                           const struct ppzksnark_vk *vk,
                           const uint64_t (*in)[4], size_t n)
{
    *acc = vk->ic[0];
    if (!pp->have_tables) {
        for (size_t i = 0; i < n; i++) {
            struct bn_g1 term;
            E_(g1_scalar_mul)(&term, &vk->ic[i + 1], in[i]);
            E_(g1_add)(acc, acc, &term);
        }
        return;
    }
    struct bn_g1 sum;
    sum.x = g_eng.fq_zero; sum.y = g_eng.fq_one; sum.z = g_eng.fq_zero;
    for (int w = 63; w >= 0; w--) {
        if (w != 63) {
            E_(g1_dbl)(&sum, &sum); E_(g1_dbl)(&sum, &sum);
            E_(g1_dbl)(&sum, &sum); E_(g1_dbl)(&sum, &sum);
        }
        for (size_t i = 0; i < n; i++) {
            unsigned d = (unsigned)((in[i][w / 16] >> (4 * (w % 16))) & 15);
            if (!d) continue;
            const struct bn_tab_pt *e = &pp->tab[i][d - 1];
            if (e->inf) continue;
            E_(g1_add_mixed)(&sum, &sum, &e->x, &e->y);
        }
    }
    E_(g1_add)(acc, acc, &sum);
}

BNE_FN void E_(build_tables)(struct bn_phgr_prep *pp, const struct ppzksnark_vk *vk)
{
    size_t n = vk->ic_len - 1;
    for (size_t i = 0; i < n; i++) {
        const struct bn_g1 *b = &vk->ic[i + 1];
        struct bn_fq bx, by;
        bool binf = E_(fq_is_zero)(&b->z);
        if (!binf) E_(g1_to_affine)(&bx, &by, b);
        struct bn_g1 cur = *b;
        for (int k = 0; k < 15; k++) {
            struct bn_tab_pt *e = &pp->tab[i][k];
            if (binf) { e->inf = true; e->x = g_eng.fq_zero; e->y = g_eng.fq_zero; continue; }
            if (k == 0) cur = *b;
            else E_(g1_add_mixed)(&cur, &cur, &bx, &by);
            if (E_(fq_is_zero)(&cur.z)) {
                e->inf = true; e->x = g_eng.fq_zero; e->y = g_eng.fq_zero;
            } else {
                e->inf = false;
                E_(g1_to_affine)(&e->x, &e->y, &cur);
            }
        }
    }
}

/* Lines of one fixed G2 point. Returns false when the point is the identity. */
BNE_FN bool E_(prep_g2)(struct bn_line *ln, const struct bn_g2 *q)
{
    if (E_(fq2_is_zero)(&q->z))
        return false;
    struct bn_fq2 qx, qy;
    if (E_(fq2_eq)(&q->z, &g_eng.fq2_one)) { qx = q->x; qy = q->y; }
    else E_(g2_to_affine)(&qx, &qy, q);
    E_(g2_lines)(ln, &qx, &qy);
    return true;
}

BNE_FN void E_(prep_build)(struct bn_phgr_prep *pp, const struct ppzksnark_vk *vk)
{
    pp->have_alpha_a = E_(prep_g2)(pp->l_alpha_a, &vk->alpha_a_g2);
    pp->have_alpha_c = E_(prep_g2)(pp->l_alpha_c, &vk->alpha_c_g2);
    pp->have_gamma = E_(prep_g2)(pp->l_gamma, &vk->gamma_g2);
    pp->have_gamma_beta = E_(prep_g2)(pp->l_gamma_beta, &vk->gamma_beta_g2);
    pp->have_rc_z = E_(prep_g2)(pp->l_rc_z, &vk->rc_z_g2);
    struct bn_g2 g2;
    bn254_g2_one(&g2);
    pp->g2_one_ok = bn_g2_is_on_curve(&g2);
    pp->have_g2_one = E_(prep_g2)(pp->l_g2_one, &g2);
    pp->have_tables = (vk->ic_len >= 1 && vk->ic_len - 1 <= BN_PREP_MAX_INPUTS);
    if (pp->have_tables)
        E_(build_tables)(pp, vk);
}

/* One pairing-product check: prod e(P_i, Q_i) == 1 after the final
 * exponentiation. A pair whose lines pointer is NULL (identity P or Q)
 * contributes 1, as the original Miller loop did. */
BNE_FN bool E_(check_pairs)(const struct bn_pair *in, size_t n)
{
    struct bn_pair live[3];
    size_t m = 0;
    for (size_t i = 0; i < n && m < 3; i++)
        if (in[i].lines != NULL)
            live[m++] = in[i];
    struct bn_fq12 f;
    if (m == 0)
        f = g_eng.fq12_one;
    else
        E_(miller_multi)(&f, live, m);
    E_(final_exp)(&f);
    return memcmp(&f, &g_eng.fq12_one, sizeof f) == 0;
}

/* A G1 operand in affine form; fin is false for the identity. */
struct E_(pt) { struct bn_fq x, y; bool fin; };

BNE_FN void E_(pt_load)(struct E_(pt) *o, const struct bn_g1 *p, bool neg)
{
    o->fin = !E_(fq_is_zero)(&p->z);
    if (!o->fin) return;
    E_(g1_to_affine)(&o->x, &o->y, p);
    if (neg) E_(fq_neg)(&o->y, &o->y);
}

BNE_INL struct bn_pair E_(mk_pair)(const struct bn_line *l, const struct E_(pt) *p)
{
    struct bn_pair r;
    r.lines = (p->fin) ? l : NULL;
    r.xp = &p->x;
    r.yp = &p->y;
    return r;
}

/* The five PHGR13 checks. `pp` is prepared for `vk`. Returns the verdict of the
 * original ppzksnark_verify after its argument checks. */
BNE_FN int E_(verify)(const struct ppzksnark_vk *vk, const struct bn_phgr_prep *pp,
                       const struct ppzksnark_proof *proof,
                       const uint64_t (*in)[4], size_t n)
{
    if (!pp->g2_one_ok)
        return 6;
    /* a NULL line table (identity vk element) makes its pair contribute 1 */
    const struct bn_line *l_aa = pp->have_alpha_a ? pp->l_alpha_a : NULL;
    const struct bn_line *l_ac = pp->have_alpha_c ? pp->l_alpha_c : NULL;
    const struct bn_line *l_g = pp->have_gamma ? pp->l_gamma : NULL;
    const struct bn_line *l_gb = pp->have_gamma_beta ? pp->l_gamma_beta : NULL;
    const struct bn_line *l_rc = pp->have_rc_z ? pp->l_rc_z : NULL;
    const struct bn_line *l_one = pp->have_g2_one ? pp->l_g2_one : NULL;

    struct bn_g1 acc, a_acc, a_acc_c;
    E_(accumulate)(&acc, pp, vk, in, n);
    E_(g1_add)(&a_acc, &proof->a, &acc);
    E_(g1_add)(&a_acc_c, &a_acc, &proof->c);

    struct bn_line lb[BN_NLINES];
    bool have_b = E_(prep_g2)(lb, &proof->b);
    const struct bn_line *l_b = have_b ? lb : NULL;

    struct E_(pt) pa, npap, abp, nbp, pc, npcp, nc, nh, pk, naacc, ngb, paac;
    struct bn_pair pr[3];

    /* 1: e(A, alphaA) e(-A', G2) == 1 */
    E_(pt_load)(&pa, &proof->a, false);
    E_(pt_load)(&npap, &proof->a_prime, true);
    pr[0] = E_(mk_pair)(l_aa, &pa);
    pr[1] = E_(mk_pair)(l_one, &npap);
    if (!E_(check_pairs)(pr, 2))
        return 1;
    /* 2: e(alphaB, B) e(-B', G2) == 1 */
    E_(pt_load)(&abp, &vk->alpha_b_g1, false);
    E_(pt_load)(&nbp, &proof->b_prime, true);
    pr[0] = E_(mk_pair)(l_b, &abp);
    pr[1] = E_(mk_pair)(l_one, &nbp);
    if (!E_(check_pairs)(pr, 2))
        return 2;
    /* 3: e(C, alphaC) e(-C', G2) == 1 */
    E_(pt_load)(&pc, &proof->c, false);
    E_(pt_load)(&npcp, &proof->c_prime, true);
    pr[0] = E_(mk_pair)(l_ac, &pc);
    pr[1] = E_(mk_pair)(l_one, &npcp);
    if (!E_(check_pairs)(pr, 2))
        return 3;
    /* 4: e(A+acc, B) e(-H, rC_Z) e(-C, G2) == 1 */
    E_(pt_load)(&paac, &a_acc, false);
    E_(pt_load)(&nh, &proof->h, true);
    E_(pt_load)(&nc, &proof->c, true);
    pr[0] = E_(mk_pair)(l_b, &paac);
    pr[1] = E_(mk_pair)(l_rc, &nh);
    pr[2] = E_(mk_pair)(l_one, &nc);
    if (!E_(check_pairs)(pr, 3))
        return 4;
    /* 5: e(K, gamma) e(-(A+acc+C), gammaBeta2) e(-gammaBeta1, B) == 1 */
    E_(pt_load)(&pk, &proof->k, false);
    E_(pt_load)(&naacc, &a_acc_c, true);
    E_(pt_load)(&ngb, &vk->gamma_beta_g1, true);
    pr[0] = E_(mk_pair)(l_g, &pk);
    pr[1] = E_(mk_pair)(l_gb, &naacc);
    pr[2] = E_(mk_pair)(l_b, &ngb);
    return E_(check_pairs)(pr, 3) ? 0 : 5;
}

/* Generic pairing product for the public API: a sequence of single-pair Miller
 * loops (lines on the stack), multiplied, then one final exponentiation. */
BNE_FN void E_(pairing_product)(struct bn_fq12 *acc, const struct bn_g1 *p,
                                const struct bn_g2 *q, size_t n)
{
    *acc = g_eng.fq12_one;
    for (size_t i = 0; i < n; i++) {
        if (E_(fq_is_zero)(&p[i].z) || E_(fq2_is_zero)(&q[i].z))
            continue;
        struct bn_line ln[BN_NLINES];
        struct E_(pt) pt;
        E_(pt_load)(&pt, &p[i], false);
        (void)E_(prep_g2)(ln, &q[i]);
        struct bn_pair pr = E_(mk_pair)(ln, &pt);
        struct bn_fq12 ml;
        E_(miller_multi)(&ml, &pr, 1);
        E_(fq12_mul)(acc, acc, &ml);
    }
}

BNE_FN void E_(pairing_full)(struct bn_fq12 *r, const struct bn_g1 *p, const struct bn_g2 *q)
{
    E_(pairing_product)(r, p, q, 1);
    E_(final_exp)(r);
}

BNE_FN bool E_(multi_pairing_check)(const struct bn_g1 *p, const struct bn_g2 *q, size_t n)
{
    struct bn_fq12 acc;
    E_(pairing_product)(&acc, p, q, n);
    E_(final_exp)(&acc);
    return memcmp(&acc, &g_eng.fq12_one, sizeof acc) == 0;
}

#undef BNE_CAT2
#undef BNE_CAT
#undef E_
#undef BNE_FN
#undef BNE_INL
