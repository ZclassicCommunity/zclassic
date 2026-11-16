/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See crypto/simd_dispatch.h for why CPUID alone is not enough. */

#include "crypto/simd_dispatch.h"

#include <stdatomic.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

/* CPUID.1:ECX bits. */
#define LEAF1_ECX_XSAVE   (1u << 26)
#define LEAF1_ECX_OSXSAVE (1u << 27)
#define LEAF1_ECX_AVX     (1u << 28)

/* CPUID.7.0:EBX bits. */
#define LEAF7_EBX_AVX2       (1u << 5)
#define LEAF7_EBX_AVX512F    (1u << 16)
#define LEAF7_EBX_AVX512DQ   (1u << 17)
#define LEAF7_EBX_AVX512IFMA (1u << 21)
#define LEAF7_EBX_AVX512VL   (1u << 31)

void simd_cpu_words_probe(struct simd_cpu_words *w)
{
    w->leaf1_ecx = 0;
    w->leaf7_ebx = 0;
    w->xcr0 = 0;
    w->leaf1_valid = false;
    w->leaf7_valid = false;
    w->xcr0_valid = false;

#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;

    /* __get_cpuid / __get_cpuid_count consult the maximum supported leaf first.
     * A raw `cpuid` with EAX=7 on a CPU whose maximum basic leaf is below 7
     * returns the HIGHEST leaf's registers instead of failing, which is how a
     * hand-rolled probe reads another leaf's bits as feature bits. */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        w->leaf1_ecx = ecx;
        w->leaf1_valid = true;
    }
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        w->leaf7_ebx = ebx;
        w->leaf7_valid = true;
    }

    /* XGETBV is #UD unless the OS set OSXSAVE. Check first, always. */
    if (w->leaf1_valid && (w->leaf1_ecx & LEAF1_ECX_OSXSAVE)) {
        uint32_t lo, hi;
        __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        w->xcr0 = ((uint64_t)hi << 32) | (uint64_t)lo;
        w->xcr0_valid = true;
    }
#endif
}

/* Common precondition for every XSAVE-backed vector tier. */
static bool os_state_readable(const struct simd_cpu_words *w)
{
    return w->leaf1_valid && w->leaf7_valid && w->xcr0_valid
        && (w->leaf1_ecx & LEAF1_ECX_XSAVE)
        && (w->leaf1_ecx & LEAF1_ECX_OSXSAVE);
}

bool simd_avx2_usable(const struct simd_cpu_words *w)
{
    if (!os_state_readable(w)) return false;
    if (!(w->leaf1_ecx & LEAF1_ECX_AVX)) return false;
    if (!(w->leaf7_ebx & LEAF7_EBX_AVX2)) return false;
    return (w->xcr0 & SIMD_XCR0_AVX_MASK) == SIMD_XCR0_AVX_MASK;
}

bool simd_avx512f_usable(const struct simd_cpu_words *w)
{
    if (!os_state_readable(w)) return false;
    if (!(w->leaf7_ebx & LEAF7_EBX_AVX512F)) return false;
    return (w->xcr0 & SIMD_XCR0_AVX512_MASK) == SIMD_XCR0_AVX512_MASK;
}

bool simd_avx512_dq_vl_usable(const struct simd_cpu_words *w)
{
    if (!simd_avx512f_usable(w)) return false;
    return (w->leaf7_ebx & LEAF7_EBX_AVX512DQ)
        && (w->leaf7_ebx & LEAF7_EBX_AVX512VL);
}

bool simd_avx512_ifma_usable(const struct simd_cpu_words *w)
{
    if (!simd_avx512f_usable(w)) return false;
    return (w->leaf7_ebx & LEAF7_EBX_AVX512IFMA) != 0;
}

/* ── Cached live answers ──────────────────────────────────────────────────
 *
 * One release store publishes all four answers, and every reader acquires on
 * the same flag. Two threads may both probe — CPUID and XGETBV are pure reads
 * of fixed hardware state, so both compute the same answer and the duplicate
 * work is a handful of cycles, once. What is NOT benign, and what the ordering
 * here rules out, is a reader seeing "probe done" while one of the four answers
 * is still its uninitialised default: that publishes a false negative for the
 * life of the process and silently parks the node on the scalar tier. */
static _Atomic bool g_probe_done = false;
static _Atomic bool g_avx2 = false;
static _Atomic bool g_avx512f = false;
static _Atomic bool g_avx512_dq_vl = false;
static _Atomic bool g_avx512_ifma = false;

static void host_probe_once(void)
{
    if (atomic_load_explicit(&g_probe_done, memory_order_acquire)) return;

    struct simd_cpu_words w;
    simd_cpu_words_probe(&w);

    atomic_store_explicit(&g_avx2, simd_avx2_usable(&w), memory_order_relaxed);
    atomic_store_explicit(&g_avx512f, simd_avx512f_usable(&w), memory_order_relaxed);
    atomic_store_explicit(&g_avx512_dq_vl, simd_avx512_dq_vl_usable(&w),
                          memory_order_relaxed);
    atomic_store_explicit(&g_avx512_ifma, simd_avx512_ifma_usable(&w),
                          memory_order_relaxed);

    atomic_store_explicit(&g_probe_done, true, memory_order_release);
}

bool simd_host_has_avx2(void)
{
    host_probe_once();
    return atomic_load_explicit(&g_avx2, memory_order_relaxed);
}

bool simd_host_has_avx512f(void)
{
    host_probe_once();
    return atomic_load_explicit(&g_avx512f, memory_order_relaxed);
}

bool simd_host_has_avx512_dq_vl(void)
{
    host_probe_once();
    return atomic_load_explicit(&g_avx512_dq_vl, memory_order_relaxed);
}

bool simd_host_has_avx512_ifma(void)
{
    host_probe_once();
    return atomic_load_explicit(&g_avx512_ifma, memory_order_relaxed);
}
