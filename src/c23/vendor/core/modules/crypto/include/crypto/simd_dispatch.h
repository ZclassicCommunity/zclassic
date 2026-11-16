/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The audited "may I run this SIMD tier?" predicate.
 *
 * CPUID tells you what the SILICON can decode. It does NOT tell you whether the
 * OS agreed to save the corresponding register state on a context switch. If it
 * did not, the first wide instruction raises #UD and the process dies — CPUID
 * says yes, the machine says SIGILL. That is a real configuration, not a
 * theoretical one: `noxsave`, `clearcpuid=avx512f`, a hypervisor that masks
 * XCR0, and several container/VM stacks all produce it.
 *
 * So a dispatch predicate needs THREE facts, and using fewer is the bug this
 * module exists to make unrepresentable:
 *   1. CPUID.1:ECX[27] OSXSAVE — the OS turned XSAVE on. Until this is set,
 *      XGETBV ITSELF is #UD, so it must be checked FIRST.
 *   2. The feature bit in CPUID.7.0:EBX (AVX2 bit 5, AVX512F bit 16,
 *      AVX512DQ bit 17, AVX512VL bit 31).
 *   3. XCR0, read with XGETBV(0): bit 1 SSE state, bit 2 AVX (YMM) state,
 *      bit 5 opmask, bit 6 ZMM_Hi256, bit 7 Hi16_ZMM.
 *
 * The policy is split from the probe on purpose. `simd_cpu_words_probe` touches
 * the hardware; the `simd_*_usable` functions are PURE functions of the three
 * words, so tests/harness/src/test_simd_os_support.c can hand them the exact
 * register contents of a machine we do not have — an AVX-512-capable CPU whose
 * OS disabled ZMM state — and pin that the answer is "no".
 *
 * Enforced by the lint gate `check-simd-os-support`: any file that compiles
 * target("avx…") code must reach one of these predicates, read XGETBV itself,
 * or delegate to a named predicate that does. */

#ifndef ZCL_CRYPTO_SIMD_DISPATCH_H
#define ZCL_CRYPTO_SIMD_DISPATCH_H

#include <stdbool.h>
#include <stdint.h>

/* Raw capability words, exactly as the hardware reports them. */
struct simd_cpu_words {
    uint32_t leaf1_ecx;  /* CPUID.(EAX=1):ECX       */
    uint32_t leaf7_ebx;  /* CPUID.(EAX=7,ECX=0):EBX */
    uint64_t xcr0;       /* XGETBV(0); 0 when unreadable */
    bool leaf1_valid;    /* CPUID leaf 1 was readable */
    bool leaf7_valid;    /* CPUID leaf 7 was readable */
    bool xcr0_valid;     /* OSXSAVE was set, so XGETBV was legal to execute */
};

/* XCR0 state-component bits. */
#define SIMD_XCR0_SSE       (1ull << 1)
#define SIMD_XCR0_YMM       (1ull << 2)
#define SIMD_XCR0_OPMASK    (1ull << 5)
#define SIMD_XCR0_ZMM_HI256 (1ull << 6)
#define SIMD_XCR0_HI16_ZMM  (1ull << 7)

/* Everything AVX/AVX2 needs the OS to have enabled. */
#define SIMD_XCR0_AVX_MASK    (SIMD_XCR0_SSE | SIMD_XCR0_YMM)
/* Everything AVX-512 needs on top of that. */
#define SIMD_XCR0_AVX512_MASK (SIMD_XCR0_AVX_MASK | SIMD_XCR0_OPMASK | \
                               SIMD_XCR0_ZMM_HI256 | SIMD_XCR0_HI16_ZMM)

/* Read CPUID + XCR0 from this CPU. On non-x86, or when a leaf is unavailable,
 * the corresponding *_valid flag is false and every predicate below returns
 * false. Never executes XGETBV without OSXSAVE. */
void simd_cpu_words_probe(struct simd_cpu_words *w);

/* PURE policy — no hardware access. Safe to call with synthetic words. */
bool simd_avx2_usable(const struct simd_cpu_words *w);
bool simd_avx512f_usable(const struct simd_cpu_words *w);
/* AVX512F + DQ + VL, the tier the keccak/sha3 lanes need. */
bool simd_avx512_dq_vl_usable(const struct simd_cpu_words *w);
/* AVX512F + IFMA, the tier the sapling field arithmetic asks about. */
bool simd_avx512_ifma_usable(const struct simd_cpu_words *w);

/* Cached live answers (probe once, then pure policy). Thread-safe. */
bool simd_host_has_avx2(void);
bool simd_host_has_avx512f(void);
bool simd_host_has_avx512_dq_vl(void);
bool simd_host_has_avx512_ifma(void);

#endif
