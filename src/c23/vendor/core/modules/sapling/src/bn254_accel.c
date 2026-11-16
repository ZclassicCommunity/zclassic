/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hardware-accelerated BN254 (alt-bn128) Fq Montgomery multiply.
 *
 * Fq is the 254-bit base field of BN254, the curve every Sprout Groth16
 * JoinSplit proof verifies over. In a from-genesis mint fold the early chain is
 * dense with Sprout proofs, and every tower/point op there bottoms out in this
 * one 4-limb Montgomery multiply (bn254.c bn_fq_mont_mul).
 *
 * SPEED path only: every implementation returns a BIT-IDENTICAL canonical
 * Montgomery product to the portable reference, so the accept/reject result of
 * any proof is unchanged. Proven by test_bn254_accel (differential oracle:
 * every path vs portable over a large random corpus + boundary vectors).
 *
 * Runtime CPUID with graceful degradation:
 *   Tier 1: BMI2+ADX — MULX with two REAL carry chains (ADCX on CF, ADOX on
 *           OF), in inline asm; see mont_adx.h.
 *   Tier 2: portable — __uint128 schoolbook (always available)
 * Detection runs once at first use; the binary runs on any x86-64 CPU.
 *
 * HISTORY — read before "simplifying" this back to intrinsics. Tier 1 used to
 * be written with _mulx_u64 + _addcarryx_u64 and was named
 * "BMI2+ADX (MULX+ADCX+ADOX)", but every _addcarryx_u64 took a literal 0
 * carry-in and folded the carry with a scalar add, so GCC emitted plain ADC:
 * the shipped object disassembled to mulx=64, adcx=0, adox=0. It was also
 * SLOWER than the portable C it displaced — 0.82x latency / 0.81x throughput
 * on Zen 4. The rewrite to real dual carry chains is 1.03x / 1.16x FASTER than
 * portable instead. Numbers and method: docs/CRYPTO_PERF.md. */

#include "sapling/bn254_accel.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include "mont_adx.h"
#endif

/* BN254 Fq modulus (little-endian limbs) and -q^{-1} mod 2^64. Must match the
 * FQ_Q / FQ_INV in bn254.c exactly — a mismatch is a reduction bug, caught by
 * the differential oracle on the first vector. */
static const uint64_t BN_Q[4] = {
    0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL,
    0xb85045b68181585dULL, 0x30644e72e131a029ULL
};
static const uint64_t BN_INV = 0x87d20782e4866389ULL;

/* ── CPUID detection ─────────────────────────────────────────────── */

#if defined(__x86_64__) || defined(_M_X64)
static bool g_cpu_bmi2 = false;
static bool g_cpu_adx = false;
#endif
static bool g_cpu_detected = false;

static void bn_detect_cpu(void)
{
    if (g_cpu_detected)
        return;
#if defined(__x86_64__) || defined(_M_X64)
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(7), "c"(0));
    g_cpu_bmi2 = (ebx >> 8) & 1;    /* EBX bit 8  */
    g_cpu_adx = (ebx >> 19) & 1;    /* EBX bit 19 */
#endif
    g_cpu_detected = true;
}

/* ── Tier 2: portable __uint128 schoolbook (canonical reference) ──── */

static void bn_fq_mont_mul_portable(uint64_t r[4], const uint64_t a[4],
                                    const uint64_t b[4])
{
    uint64_t t[8] = {0};

    for (int i = 0; i < 4; i++) {
        __uint128_t carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (__uint128_t)a[j] * b[i] + t[i + j];
            t[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        t[i + 4] = (uint64_t)carry;
    }

    for (int i = 0; i < 4; i++) {
        uint64_t m = t[i] * BN_INV;
        __uint128_t carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (__uint128_t)m * BN_Q[j] + t[i + j];
            t[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        for (int j = i + 4; j < 8; j++) {
            carry += t[j];
            t[j] = (uint64_t)carry;
            carry >>= 64;
        }
    }

    memcpy(r, t + 4, 32);
    /* Canonical final subtraction: r -= q once if r >= q. */
    bool ge = true;
    for (int i = 3; i >= 0; i--) {
        if (r[i] > BN_Q[i]) { ge = true; break; }
        if (r[i] < BN_Q[i]) { ge = false; break; }
    }
    if (ge) {
        __uint128_t borrow = 0;
        for (int i = 0; i < 4; i++) {
            __uint128_t v = (__uint128_t)r[i] - BN_Q[i] - borrow;
            r[i] = (uint64_t)v;
            borrow = (v >> 64) & 1;
        }
    }
}

/* ── Tier 1: BMI2+ADX — MULX with two real carry chains ─────────────
 * The CIOS core, the reason it is inline asm, and the accumulator bound that
 * makes one conditional subtraction sufficient all live in mont_adx.h. */

#if defined(__x86_64__) || defined(_M_X64)
__attribute__((target("bmi2,adx")))
static void bn_fq_mont_mul_adx(uint64_t r[4], const uint64_t a[4],
                               const uint64_t b[4])
{
    mont_mul_adx4(r, a, b, BN_Q, BN_INV);
}
#endif /* __x86_64__ */

/* ── Runtime dispatch ─────────────────────────────────────────────── */

typedef void (*bn_fq_mul_fn)(uint64_t r[4], const uint64_t a[4],
                             const uint64_t b[4]);

static bn_fq_mul_fn g_bn_fq_mont_mul = NULL;

static void bn_init_dispatch(void)
{
    bn_detect_cpu();
#if defined(__x86_64__) || defined(_M_X64)
    if (g_cpu_bmi2 && g_cpu_adx)
        g_bn_fq_mont_mul = bn_fq_mont_mul_adx;
    else
#endif
        g_bn_fq_mont_mul = bn_fq_mont_mul_portable;
}

void bn_fq_mont_mul_accel(uint64_t r[4], const uint64_t a[4],
                          const uint64_t b[4])
{
    if (__builtin_expect(!g_bn_fq_mont_mul, 0))
        bn_init_dispatch();
    g_bn_fq_mont_mul(r, a, b);
}

const char *bn254_accel_implementation(void)
{
    bn_detect_cpu();
#if defined(__x86_64__) || defined(_M_X64)
    if (g_cpu_bmi2 && g_cpu_adx)
        return "BMI2+ADX (MULX+ADCX+ADOX)";
#endif
    return "portable (__int128)";
}

void bn254_accel_mont_mul_portable(uint64_t r[4], const uint64_t a[4],
                                   const uint64_t b[4])
{
    bn_fq_mont_mul_portable(r, a, b);
}

const void *bn254_accel_adx_code(void)
{
    bn_detect_cpu();
#if defined(__x86_64__) || defined(_M_X64)
    if (g_cpu_bmi2 && g_cpu_adx) {
        /* ISO C has no function-pointer-to-object-pointer conversion (a direct
         * cast trips -Wpedantic), but the whole point here is to hand a test
         * the address of the emitted code. A union does the reinterpretation
         * without inventing a conversion the standard lacks. */
        union {
            void (*fn)(uint64_t *, const uint64_t *, const uint64_t *);
            const void *p;
        } u;
        u.fn = bn_fq_mont_mul_adx;
        return u.p;
    }
#endif
    return NULL;
}

bool bn254_accel_mont_mul_adx(uint64_t r[4], const uint64_t a[4],
                              const uint64_t b[4])
{
    bn_detect_cpu();
#if defined(__x86_64__) || defined(_M_X64)
    if (g_cpu_bmi2 && g_cpu_adx) {
        bn_fq_mont_mul_adx(r, a, b);
        return true;
    }
#endif
    (void)r; (void)a; (void)b;
    return false;
}
