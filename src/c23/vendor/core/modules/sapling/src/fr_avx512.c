/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hardware-accelerated field arithmetic for BLS12-381 Fr and Fp.
 *
 * Runtime CPUID detection with graceful degradation. Two tiers EXIST:
 *   Tier 1: BMI2+ADX — MULX with two REAL carry chains, ADCX on CF and ADOX on
 *           OF, in inline asm (target attribute, so it compiles into the
 *           x86-64-v3 baseline and is entered only after CPUID confirms
 *           support). The CIOS core is shared with BN254 Fq in mont_adx.h,
 *           which also explains why it must be asm and not intrinsics.
 *   Tier 2: Portable — __int128 fallback (always available)
 *
 * AVX-512 IFMA (VPMADD52) is DETECTED but not implemented — there is no
 * VPMADD52 code in this file. fr_accel_implementation() reports it as present-
 * and-unused rather than claiming a tier that has never executed.
 *
 * Detection runs once at first use. Binary works on any x86-64 CPU.
 *
 * HISTORY — read before "simplifying" this back to intrinsics. Tier 1 used to
 * be _mulx_u64 + _addcarryx_u64 with a literal 0 carry-in everywhere, so GCC
 * emitted plain ADC and the object disassembled to adcx=0, adox=0. It was
 * SLOWER than the portable C it displaced on Zen 4: Fr 0.85x latency / 0.73x
 * throughput, Fp 0.78x / 0.72x. Real dual carry chains are instead 1.09x /
 * 1.07x (Fr) and 1.26x / 1.38x (Fp) FASTER than portable. See
 * docs/CRYPTO_PERF.md for the method and the full table. */

#include "sapling/fr.h"
#include "sapling/fr_accel.h"
#include "crypto/simd_dispatch.h"
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if defined(__x86_64__) || defined(_M_X64)
#include "mont_adx.h"
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

/* ── CPUID detection ─────────────────────────────────────────────── */

static bool cpu_has_bmi2 = false;
static bool cpu_has_adx = false;
static bool cpu_has_avx512ifma = false;
static bool cpu_detected = false;

static void detect_cpu_features(void)
{
    if (cpu_detected) return;

    /* The probe honours the maximum-supported-leaf reported by CPUID leaf 0.
     * This used to be a raw `cpuid` with EAX=7, which on a CPU whose maximum
     * basic leaf is below 7 silently returns the HIGHEST leaf's registers
     * instead of failing — another leaf's bits read as feature bits. It also
     * executed XGETBV after checking only AVX512F, never OSXSAVE; XGETBV is
     * itself #UD when the OS has not enabled XSAVE. */
    struct simd_cpu_words w;
    simd_cpu_words_probe(&w);

    /* BMI2 (EBX bit 8) and ADX (EBX bit 19) are general-purpose-register
     * instructions with no XSAVE state component beyond what 64-bit mode always
     * enables, so the CPUID bit settles them on its own. */
    cpu_has_bmi2 = w.leaf7_valid && ((w.leaf7_ebx >> 8) & 1);
    cpu_has_adx  = w.leaf7_valid && ((w.leaf7_ebx >> 19) & 1);

    /* IFMA is a ZMM tier, so it needs the full OS-state check. */
    cpu_has_avx512ifma = simd_avx512_ifma_usable(&w);

    cpu_detected = true;
}

/* Reports the multiply that init_dispatch() ACTUALLY installs — never a tier
 * that merely exists in CPUID. There is no VPMADD52 implementation in this
 * file, so an IFMA-capable host still runs the BMI2 path; saying otherwise made
 * `zclassic23`'s boot banner claim a tier that has never executed. IFMA is
 * still reported, as an unused capability, so the headroom stays visible.
 * ADX is now claimed because the installed path genuinely builds two carry
 * chains — `test_mont_adx_honest_string` re-derives this from the running
 * binary's own disassembly rather than trusting this comment. */
const char *fr_accel_implementation(void)
{
    detect_cpu_features();
    if (cpu_has_bmi2 && cpu_has_adx)
        return cpu_has_avx512ifma
            ? "BMI2+ADX (MULX+ADCX+ADOX) (AVX-512 IFMA present, unimplemented)"
            : "BMI2+ADX (MULX+ADCX+ADOX)";
    return "portable (__int128)";
}

/* ================================================================
 * Tier 3: Portable Montgomery multiply (__int128)
 * Always compiled. Used as fallback on older CPUs.
 * ================================================================ */

static const uint64_t FR_P_PORT[4] = {
    0xffffffff00000001ULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL
};
static const uint64_t FR_INV_PORT = 0xfffffffeffffffffULL;

static bool port_gte4(const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true;
}

static void port_sub4(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 tmp = (unsigned __int128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)tmp;
        borrow = (tmp >> 127) & 1;
    }
}

static void fr_mont_mul_portable(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
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

        uint64_t m = t[0] * FR_INV_PORT;
        carry = 0;
        unsigned __int128 prod0 = (unsigned __int128)m * FR_P_PORT[0] + t[0];
        carry = prod0 >> 64;
        for (int j = 1; j < 4; j++) {
            unsigned __int128 prod = (unsigned __int128)m * FR_P_PORT[j] + t[j] + carry;
            t[j - 1] = (uint64_t)prod;
            carry = prod >> 64;
        }
        unsigned __int128 sum = (unsigned __int128)t[4] + carry;
        t[3] = (uint64_t)sum;
        t[4] = (uint64_t)(sum >> 64);
    }
    if (t[4] || port_gte4(t, FR_P_PORT))
        port_sub4(r, t, FR_P_PORT);
    else
        memcpy(r, t, 32);
}

static const uint64_t FP_Q_PORT[6] = {
    0xb9feffffffffaaabULL, 0x1eabfffeb153ffffULL,
    0x6730d2a0f6b0f624ULL, 0x64774b84f38512bfULL,
    0x4b1ba7b6434bacd7ULL, 0x1a0111ea397fe69aULL
};
static const uint64_t FP_INV_PORT = 0x89f3fffcfffcfffdULL;

static bool port_gte6(const uint64_t a[6], const uint64_t b[6])
{
    for (int i = 5; i >= 0; i--) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true;
}

static void port_sub6(uint64_t r[6], const uint64_t a[6], const uint64_t b[6])
{
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 6; i++) {
        unsigned __int128 tmp = (unsigned __int128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)tmp;
        borrow = (tmp >> 127) & 1;
    }
}

static void fp_mont_mul_portable(uint64_t r[6], const uint64_t a[6], const uint64_t b[6])
{
    uint64_t t[7] = {0};
    for (int i = 0; i < 6; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 6; j++) {
            unsigned __int128 prod = (unsigned __int128)a[j] * b[i] + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        t[6] = (uint64_t)carry;

        uint64_t m = t[0] * FP_INV_PORT;
        carry = 0;
        unsigned __int128 prod0 = (unsigned __int128)m * FP_Q_PORT[0] + t[0];
        carry = prod0 >> 64;
        for (int j = 1; j < 6; j++) {
            unsigned __int128 prod = (unsigned __int128)m * FP_Q_PORT[j] + t[j] + carry;
            t[j - 1] = (uint64_t)prod;
            carry = prod >> 64;
        }
        unsigned __int128 sum = (unsigned __int128)t[6] + carry;
        t[5] = (uint64_t)sum;
        t[6] = (uint64_t)(sum >> 64);
    }
    if (t[6] || port_gte6(t, FP_Q_PORT))
        port_sub6(r, t, FP_Q_PORT);
    else
        memcpy(r, t, 48);
}

/* ── TRUE dual carry chain (MULX + ADCX + ADOX) ────────────────────
 * Shares the CIOS core in mont_adx.h with BN254 Fq; see that file for why it
 * is inline asm and for the accumulator bound that makes one conditional
 * subtraction sufficient. */

#if defined(__x86_64__) || defined(_M_X64)
__attribute__((target("bmi2,adx")))
static void fr_mont_mul_adx(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    mont_mul_adx4(r, a, b, FR_P_PORT, FR_INV_PORT);
}

__attribute__((target("bmi2,adx")))
static void fp_mont_mul_adx(uint64_t r[6], const uint64_t a[6], const uint64_t b[6])
{
    mont_mul_adx6(r, a, b, FP_Q_PORT, FP_INV_PORT);
}
#endif

/* ================================================================
 * Runtime dispatch — function pointers, set once at first call
 * ================================================================ */

typedef void (*fr_mul_fn)(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
typedef void (*fp_mul_fn)(uint64_t r[6], const uint64_t a[6], const uint64_t b[6]);

static fr_mul_fn g_fr_mont_mul = NULL;
static fp_mul_fn g_fp_mont_mul = NULL;

static void init_dispatch(void)
{
    detect_cpu_features();
#if defined(__x86_64__) || defined(_M_X64)
    if (cpu_has_bmi2 && cpu_has_adx) {
        g_fr_mont_mul = fr_mont_mul_adx;
        g_fp_mont_mul = fp_mont_mul_adx;
    } else
#endif
    {
        g_fr_mont_mul = fr_mont_mul_portable;
        g_fp_mont_mul = fp_mont_mul_portable;
    }
}

/* Public dispatchers — called by fr_mul/fp_mul via extern */
void fr_mont_mul_accel(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    if (__builtin_expect(!g_fr_mont_mul, 0))
        init_dispatch();
    g_fr_mont_mul(r, a, b);
}

void fp_mont_mul_accel(uint64_t r[6], const uint64_t a[6], const uint64_t b[6])
{
    if (__builtin_expect(!g_fp_mont_mul, 0))
        init_dispatch();
    g_fp_mont_mul(r, a, b);
}

bool fr_accel_mont_mul_adx(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
#if defined(__x86_64__) || defined(_M_X64)
    detect_cpu_features();
    if (!cpu_has_bmi2 || !cpu_has_adx)
        return false;
    fr_mont_mul_adx(r, a, b);
    return true;
#else
    (void)r; (void)a; (void)b;
    return false;
#endif
}

bool fp_accel_mont_mul_adx(uint64_t r[6], const uint64_t a[6], const uint64_t b[6])
{
#if defined(__x86_64__) || defined(_M_X64)
    detect_cpu_features();
    if (!cpu_has_bmi2 || !cpu_has_adx)
        return false;
    fp_mont_mul_adx(r, a, b);
    return true;
#else
    (void)r; (void)a; (void)b;
    return false;
#endif
}

/* ── Per-tier hooks (differential oracle + benchmark) ─────────────
 *
 * Mirrors sapling/bn254_accel.h. These bypass the dispatcher entirely so a
 * caller can drive one input through BOTH tiers in a single process and assert
 * the products are byte-identical — the only way to prove the BMI2 path is a
 * pure speed change. The bmi2 entry points report false rather than executing
 * an unsupported instruction. */

void fr_accel_mont_mul_portable(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    fr_mont_mul_portable(r, a, b);
}

void fp_accel_mont_mul_portable(uint64_t r[6], const uint64_t a[6], const uint64_t b[6])
{
    fp_mont_mul_portable(r, a, b);
}


#pragma GCC diagnostic pop
