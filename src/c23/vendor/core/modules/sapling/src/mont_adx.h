/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Montgomery multiply with a REAL dual carry chain (MULX + ADCX + ADOX).
 *
 * WHY INLINE ASM AND NOT INTRINSICS
 * ---------------------------------
 * The entire value of ADX is that ADCX and ADOX write DIFFERENT flags — ADCX
 * reads/writes only CF, ADOX reads/writes only OF — so the two dependent
 * addition chains of a Montgomery multiply (the partial-product low words and
 * the partial-product high words) can be in flight simultaneously instead of
 * serializing on one flag register.
 *
 * C cannot express that. `_addcarry_u64` and `_addcarryx_u64` both return a
 * plain `unsigned char` carry and take one in; there is no way to tell the
 * compiler "this carry lives in OF and that one in CF, keep both alive across
 * the whole loop". GCC and Clang therefore materialize both intrinsics with
 * ordinary ADC and a scalar fold. That is precisely how the previous
 * implementation of this file's callers ended up disassembling to
 * mulx=64, adcx=0, adox=0 while its operator-visible string claimed
 * "BMI2+ADX (MULX+ADCX+ADOX)". Inline asm is the only way to pin the two
 * chains to the two flags, so inline asm is what this uses.
 *
 * ALGORITHM — CIOS (Coarsely Integrated Operand Scanning), n+1 limb
 * accumulator, register-rotated so no limb shuffle is needed between rounds.
 * Per round i:
 *   phase 1   t += a[] * b[i]        (CF chain: low words, OF chain: high words)
 *   phase 2   m = t[0] * INV; t += m * q   (makes t[0] == 0)
 *   shift     implicit — the next round's register window starts one limb up
 *
 * BOUND / PRECONDITION. Writing T_i for the accumulator at the start of round
 * i, T_0 = 0 and
 *     T_{i+1} <= (T_i + (q-1)(2^64-1) + (2^64-1) q) / 2^64 < T_i/2^64 + 2q,
 * so T_i < 2q holds for every i by induction, PROVIDED a < q. Every modulus
 * here is "sparse" (top bit of the top limb clear: BN254 Fq top limb
 * 0x30644e72…, BLS12-381 Fr 0x73eda753…, BLS12-381 Fp 0x1a0111ea…), hence
 * 2q < 2^(64n) and the (n+1)-th limb is 0 at every round boundary. The largest
 * intermediate is T_i + a*b[i] + m*q < q*(2^64+2) < 2^(64(n+1)), so the n+1
 * limb accumulator never overflows and both carry folds into the top limb are
 * safe. The final T_n < 2q, so ONE conditional subtraction yields the canonical
 * representative — the same single conditional subtraction the portable
 * reference performs, which is why the two are bit-identical.
 *
 * The precondition is a < q (b is unconstrained by the bound above). Every
 * field wrapper in this tree keeps its representatives canonical, and the
 * differential test drives the boundary cases explicitly. */

#ifndef ZCL_SAPLING_MONT_ADX_H
#define ZCL_SAPLING_MONT_ADX_H

#include <stdbool.h>
#include <stdint.h>

#if defined(__x86_64__) || defined(_M_X64)

/* d = s - q, returning the borrow out. Plain uint64_t arithmetic rather than
 * __int128 so the header stays clean under -Wpedantic (simd_bench builds with
 * -Werror -pedantic). */
#define MADX_SUB_N(N)                                                         \
    uint64_t d[N];                                                            \
    uint64_t borrow = 0;                                                      \
    for (int i = 0; i < (N); i++) {                                           \
        uint64_t si = s[i], qi = q[i];                                        \
        uint64_t p = si - qi;                                                 \
        uint64_t b1 = (uint64_t)(si < qi);                                    \
        d[i] = p - borrow;                                                    \
        borrow = b1 | (uint64_t)(p < borrow);                                 \
    }                                                                         \
    /* 0 when s < q (keep s), all-ones when s >= q (take s - q). */           \
    uint64_t mask = borrow - 1u;                                              \
    for (int i = 0; i < (N); i++)                                             \
        r[i] = (s[i] & ~mask) | (d[i] & mask);

/* One partial-product row: t[TLO] += lo(rdx*src) on the CF chain, and
 * t[THI] += hi(rdx*src) on the OF chain. The two adds are independent because
 * they touch different flags — that is the whole trick. */
#define MADX_ROW(SRC, OFF, TLO, THI)                                          \
    "mulxq " OFF "(" SRC "), %[lo], %[hi]\n\t"                                \
    "adcxq %[lo], %[" TLO "]\n\t"                                             \
    "adoxq %[hi], %[" THI "]\n\t"

/* Fold the two chains' final carries into the top limb. ADCX leaves OF alone
 * and ADOX leaves CF alone, so both are needed and the order is irrelevant. By
 * the bound above neither can carry out. Z names whatever operand holds a
 * literal 0 — a register for the 4-limb routines, a stack slot for the 6-limb
 * one, which is one register short of being able to spare a whole GPR. */
#define MADX_FOLD(Z, TTOP)                                                    \
    "adcxq %[" Z "], %[" TTOP "]\n\t"                                         \
    "adoxq %[" Z "], %[" TTOP "]\n\t"

/* `xorl` on a 32-bit register zeroes it and clears BOTH CF and OF, arming the
 * two chains for the next phase in a single uop. X names a register that is
 * dead at this point: [zero] when we keep a zero register, otherwise [lo],
 * which the next MULX is about to overwrite anyway.
 *
 * MUST be issued AFTER the reduction phase's `imulq`, never before: IMUL writes
 * CF and OF, so arming first and then computing m silently re-dirties both
 * chains. MULX is flag-free, which is why the `movq b[i]` / MULX sequence in
 * phase 1 may follow the arm safely. */
#define MADX_ARM(X) "xorl %k[" X "], %k[" X "]\n\t"

/* ── 4-limb round (BN254 Fq, BLS12-381 Fr) ───────────────────────────
 * T0..T4 name the rotating register window; BOFF is the byte offset of b[i]. */
#define MADX_ROUND4(BOFF, T0, T1, T2, T3, T4)                                 \
    MADX_ARM("zero")                                                          \
    "movq " BOFF "(%[bp]), %%rdx\n\t"                                         \
    MADX_ROW("%[ap]",  "0", T0, T1)                                           \
    MADX_ROW("%[ap]",  "8", T1, T2)                                           \
    MADX_ROW("%[ap]", "16", T2, T3)                                           \
    MADX_ROW("%[ap]", "24", T3, T4)                                           \
    MADX_FOLD("zero", T4)                                                     \
    "movq %[" T0 "], %%rdx\n\t"                                               \
    "imulq %[inv], %%rdx\n\t"                                                 \
    MADX_ARM("zero")                                                          \
    MADX_ROW("%[qp]",  "0", T0, T1)                                           \
    MADX_ROW("%[qp]",  "8", T1, T2)                                           \
    MADX_ROW("%[qp]", "16", T2, T3)                                           \
    MADX_ROW("%[qp]", "24", T3, T4)                                           \
    MADX_FOLD("zero", T4)

/* ── 6-limb round (BLS12-381 Fp) ─────────────────────────────────────── */
#define MADX_ROUND6(BOFF, T0, T1, T2, T3, T4, T5, T6)                         \
    MADX_ARM("lo")                                                            \
    "movq " BOFF "(%[bp]), %%rdx\n\t"                                         \
    MADX_ROW("%[ap]",  "0", T0, T1)                                           \
    MADX_ROW("%[ap]",  "8", T1, T2)                                           \
    MADX_ROW("%[ap]", "16", T2, T3)                                           \
    MADX_ROW("%[ap]", "24", T3, T4)                                           \
    MADX_ROW("%[ap]", "32", T4, T5)                                           \
    MADX_ROW("%[ap]", "40", T5, T6)                                           \
    MADX_FOLD("zmem", T6)                                                     \
    "movq %[" T0 "], %%rdx\n\t"                                               \
    "imulq %[inv], %%rdx\n\t"                                                 \
    MADX_ARM("lo")                                                            \
    MADX_ROW("%[qp]",  "0", T0, T1)                                           \
    MADX_ROW("%[qp]",  "8", T1, T2)                                           \
    MADX_ROW("%[qp]", "16", T2, T3)                                           \
    MADX_ROW("%[qp]", "24", T3, T4)                                           \
    MADX_ROW("%[qp]", "32", T4, T5)                                           \
    MADX_ROW("%[qp]", "40", T5, T6)                                           \
    MADX_FOLD("zmem", T6)

/* One round as a complete asm statement. All seven accumulator limbs are bound
 * every time; the round macro decides which of them plays which role. */
#define MADX_ROUND6_ASM(BOFF, T0, T1, T2, T3, T4, T5, T6)                     \
    __asm__(MADX_ROUND6(BOFF, T0, T1, T2, T3, T4, T5, T6)                     \
        : [t0] "+&r"(t0), [t1] "+&r"(t1), [t2] "+&r"(t2), [t3] "+&r"(t3),     \
          [t4] "+&r"(t4), [t5] "+&r"(t5), [t6] "+&r"(t6),                     \
          [lo] "=&r"(lo), [hi] "=&r"(hi)                                      \
        : [ap] "r"(a), [bp] "r"(b), [qp] "r"(q), [inv] "r"(inv),              \
          [zmem] "m"(zmem)                                                    \
        : "rdx", "cc", "memory")

/* r = a*b*R^{-1} mod q, canonical. 4 limbs. Caller must be target("bmi2,adx")
 * and must have confirmed CPUID support. Precondition: a < q. */
__attribute__((always_inline))
static inline void mont_mul_adx4(uint64_t r[4], const uint64_t a[4],
                                 const uint64_t b[4], const uint64_t q[4],
                                 uint64_t inv)
{
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
    uint64_t lo, hi, zero;

    __asm__(
        MADX_ROUND4( "0", "t0", "t1", "t2", "t3", "t4")
        MADX_ROUND4( "8", "t1", "t2", "t3", "t4", "t0")
        MADX_ROUND4("16", "t2", "t3", "t4", "t0", "t1")
        MADX_ROUND4("24", "t3", "t4", "t0", "t1", "t2")
        : [t0] "+&r"(t0), [t1] "+&r"(t1), [t2] "+&r"(t2), [t3] "+&r"(t3),
          [t4] "+&r"(t4), [lo] "=&r"(lo), [hi] "=&r"(hi), [zero] "=&r"(zero)
        : [ap] "r"(a), [bp] "r"(b), [qp] "r"(q), [inv] "r"(inv)
        : "rdx", "cc", "memory");

    /* After the last round the window is (t3,t4,t0,t1,t2) with t3 == 0, so the
     * product occupies t4,t0,t1,t2 low-to-high. */
    uint64_t s[4] = { t4, t0, t1, t2 };

    /* Single conditional subtraction: s < 2q, so s -= q iff s >= q. Done
     * branchlessly on the borrow so the timing does not depend on the value. */
    MADX_SUB_N(4)
}

/* Same, 6 limbs (BLS12-381 Fp). Precondition: a < q. */
__attribute__((always_inline))
static inline void mont_mul_adx6(uint64_t r[6], const uint64_t a[6],
                                 const uint64_t b[6], const uint64_t q[6],
                                 uint64_t inv)
{
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0;
    uint64_t lo, hi;
    /* Seven accumulator limbs + lo/hi + three pointers + RDX is already 13 of
     * the 15 usable GPRs, so unlike the 4-limb routines this one cannot afford
     * a dedicated zero register: the carry folds read a zero from the stack
     * instead, and the flags are armed by zeroing [lo], which is dead there. */
    const uint64_t zmem = 0;

    /* One asm statement PER ROUND rather than one for the whole multiply.
     * Six rounds concatenated make a single string literal of ~6.2 KB, and ISO
     * C only requires 4095 — clang rejects it under -pedantic (the
     * check-clang-portability gate catches this; GCC alone does not).
     *
     * Splitting is safe because a round carries no state across its boundary
     * except the accumulator limbs, which live in the "+&r" operands: each
     * phase re-arms CF and OF itself, so no flag value has to survive from one
     * statement to the next. The register rotation is expressed purely by which
     * operand name appears in which slot of the template. */
    MADX_ROUND6_ASM( "0", "t0", "t1", "t2", "t3", "t4", "t5", "t6");
    MADX_ROUND6_ASM( "8", "t1", "t2", "t3", "t4", "t5", "t6", "t0");
    MADX_ROUND6_ASM("16", "t2", "t3", "t4", "t5", "t6", "t0", "t1");
    MADX_ROUND6_ASM("24", "t3", "t4", "t5", "t6", "t0", "t1", "t2");
    MADX_ROUND6_ASM("32", "t4", "t5", "t6", "t0", "t1", "t2", "t3");
    MADX_ROUND6_ASM("40", "t5", "t6", "t0", "t1", "t2", "t3", "t4");

    /* Window after the last round is (t5,t6,t0,t1,t2,t3,t4) with t5 == 0. */
    uint64_t s[6] = { t6, t0, t1, t2, t3, t4 };

    MADX_SUB_N(6)
}

#endif /* __x86_64__ */

#endif /* ZCL_SAPLING_MONT_ADX_H */
