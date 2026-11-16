/* Copyright (c) 2016 Jack Grigg
 * Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Vectorized BLAKE2b compression for Equihash verification.
 *
 * x86-64 — 3-tier dispatch:
 *   Tier 2: AVX-512F — 8-way parallel BLAKE2b (8 blocks per call)
 *   Tier 1: AVX2     — 4-way parallel BLAKE2b (4 blocks per call)
 *   Tier 0: Scalar   — standard sequential BLAKE2b
 * arm64  — 2-tier dispatch (tier 2 has no NEON counterpart):
 *   Tier 1: NEON     — 4-way parallel BLAKE2b (4 blocks per call)
 *   Tier 0: Scalar   — the same sequential BLAKE2b
 *
 * Runtime gating. Equihash (200,9) needs 512 independent BLAKE2b hashes per
 * block — perfect for wide SIMD batching. On x86 the gate is the audited
 * CPUID/OSXSAVE/XCR0 predicate in crypto/simd_dispatch.h. On arm64 NEON is
 * part of the base ABI — there is no "does the OS save these registers?"
 * question and no CPUID to ask — so the gate there is a ONE-TIME KAT: the
 * 4-way NEON compress runs four fixed vectors and its states are compared
 * against the portable sequential implementation; a single divergent byte
 * downgrades the process to scalar for its whole life.
 */

#include "crypto/blake2b.h"
#include "crypto/simd_dispatch.h"
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64)
#include <immintrin.h>
#define ZCL_BLAKE2B_X86_SIMD 1
#define ZCL_BLAKE2B_ARM_NEON 0
#elif defined(__aarch64__)
#include <arm_neon.h>
#define ZCL_BLAKE2B_X86_SIMD 0
#define ZCL_BLAKE2B_ARM_NEON 1
#else
#define ZCL_BLAKE2B_X86_SIMD 0
#define ZCL_BLAKE2B_ARM_NEON 0
#endif

/* ── Runtime CPU feature detection ───────────────────────────── */

/* Two layers, deliberately separate:
 *   g_cap_*  — what CPUID says this host CAN do. Never overridden.
 *   g_use_*  — what finalize_states() actually dispatches on. Equal to the
 *              capability under AUTO; narrowed by
 *              equihash_blake2b_batch_select_impl() so a bench/oracle can time
 *              and compare a lower tier on a capable host.
 * A force can only ever turn a tier OFF, so it can never make the code execute
 * an instruction the CPU lacks.
 *
 * All five are _Atomic and g_detected is published LAST with release ordering,
 * matching sha256.c's `_Atomic int sha_ni_available`. The previous code set
 * g_detected before writing the feature flags, so a second thread could
 * observe "detection done" with both tiers still false and silently fall back
 * to scalar for the life of the process — on the Equihash PoW path, which runs
 * on both the reducer ingest thread and background validation. Correctness was
 * never at risk (scalar is the reference); the accelerator was. */
/* Declared on every arch so the arch-shared select/implementation functions
 * below stay one function each; only the arch that owns a tier ever stores to
 * or reads its capability flag, so the flags the running arch lacks compile as
 * deliberately unused rather than being #if'd away per arch. */
__attribute__((unused)) static _Atomic bool g_cap_avx2 = false;
__attribute__((unused)) static _Atomic bool g_cap_avx512f = false;
static _Atomic bool g_use_avx2 = false;
static _Atomic bool g_use_avx512f = false;
__attribute__((unused)) static _Atomic bool g_cap_neon = false;
static _Atomic bool g_use_neon = false;
static _Atomic bool g_detected = false;

#if ZCL_BLAKE2B_ARM_NEON
/* The one-time gate, defined next to the NEON compressor it guards. */
static bool blake2b_neon_kat(void);
#endif

static void detect_features(void)
{
    if (atomic_load_explicit(&g_detected, memory_order_acquire)) return;
#if defined(__x86_64__) || defined(_M_X64)
    /* Both tiers go through the audited predicate in crypto/simd_dispatch.h:
     * OSXSAVE first (XGETBV is itself #UD without it), then the CPUID feature
     * bit, then the XCR0 state components the tier needs. The AVX-512 arm here
     * used to check the three ZMM bits but not OSXSAVE, and the AVX2 arm
     * checked no OS state at all — a `noxsave` boot would have taken a SIGILL
     * on the first 4-way compress, on the Equihash PoW path. */
    struct simd_cpu_words w;
    simd_cpu_words_probe(&w);
    bool avx2 = simd_avx2_usable(&w);
    bool avx512f = simd_avx512f_usable(&w);

    atomic_store_explicit(&g_cap_avx2, avx2, memory_order_relaxed);
    atomic_store_explicit(&g_cap_avx512f, avx512f, memory_order_relaxed);
    atomic_store_explicit(&g_use_avx2, avx2, memory_order_relaxed);
    atomic_store_explicit(&g_use_avx512f, avx512f, memory_order_relaxed);
#elif ZCL_BLAKE2B_ARM_NEON
    /* Nothing to ask the hardware: NEON is in the arm64 base ABI, its register
     * state is saved on every context switch by definition, and there is no
     * CPUID/XCR0 to read (crypto/simd_dispatch.h is x86-only by construction).
     * What CAN still be wrong is the code — a wrong lane order, a bad rotate,
     * a mis-transposed message word — and a wrong vector digest on the Equihash
     * PoW path is a fork, not a crash. So the capability is proven, not
     * assumed: run the 4-way NEON compress on four fixed vectors and require
     * bit-identity with the portable sequential implementation. Anything else
     * leaves this process on scalar forever. */
    bool neon = blake2b_neon_kat();
    atomic_store_explicit(&g_cap_neon, neon, memory_order_relaxed);
    atomic_store_explicit(&g_use_neon, neon, memory_order_relaxed);
#endif
    atomic_store_explicit(&g_detected, true, memory_order_release);
}

/* ── Constants ───────────────────────────────────────────────── */

#if ZCL_BLAKE2B_X86_SIMD || ZCL_BLAKE2B_ARM_NEON
static const uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
};

#if ZCL_BLAKE2B_X86_SIMD
/* ══════════════════════════════════════════════════════════════
 *  AVX-512F: 8-way parallel BLAKE2b compression
 * ══════════════════════════════════════════════════════════════ */

#define ROTR64_512(x, n) _mm512_ror_epi64((x), (n))

#define G8(r, i, a, b, c, d, m) do { \
    a = _mm512_add_epi64(a, _mm512_add_epi64(b, m[SIGMA[r][2*(i)]])); \
    d = ROTR64_512(_mm512_xor_si512(d, a), 32); \
    c = _mm512_add_epi64(c, d); \
    b = ROTR64_512(_mm512_xor_si512(b, c), 24); \
    a = _mm512_add_epi64(a, _mm512_add_epi64(b, m[SIGMA[r][2*(i)+1]])); \
    d = ROTR64_512(_mm512_xor_si512(d, a), 16); \
    c = _mm512_add_epi64(c, d); \
    b = ROTR64_512(_mm512_xor_si512(b, c), 63); \
} while(0)

#define ROUND8(r, v, m) do { \
    G8(r, 0, v[0], v[4], v[ 8], v[12], m); \
    G8(r, 1, v[1], v[5], v[ 9], v[13], m); \
    G8(r, 2, v[2], v[6], v[10], v[14], m); \
    G8(r, 3, v[3], v[7], v[11], v[15], m); \
    G8(r, 4, v[0], v[5], v[10], v[15], m); \
    G8(r, 5, v[1], v[6], v[11], v[12], m); \
    G8(r, 6, v[2], v[7], v[ 8], v[13], m); \
    G8(r, 7, v[3], v[4], v[ 9], v[14], m); \
} while(0)

__attribute__((target("avx512f")))
static void blake2b_compress_8way(
    struct blake2b_ctx *c[8], const uint8_t *b[8])
{
    __m512i m[16], v[16];

    /* Load 16 message words, each from 8 blocks */
    for (int i = 0; i < 16; i++) {
        uint64_t w[8];
        for (int j = 0; j < 8; j++)
            memcpy(&w[j], b[j] + i * 8, 8);
        m[i] = _mm512_loadu_si512(w);
    }

    /* Load h[0..7] from 8 states */
    for (int i = 0; i < 8; i++) {
        uint64_t h[8];
        for (int j = 0; j < 8; j++) h[j] = c[j]->h[i];
        v[i] = _mm512_loadu_si512(h);
    }

    /* IV for v[8..11] — same across all states */
    for (int i = 0; i < 4; i++)
        v[8 + i] = _mm512_set1_epi64((long long)IV[i]);

    /* v[12..15] — XOR with per-state counter/flags */
    {
        uint64_t t0[8], t1[8], f0[8], f1[8];
        for (int j = 0; j < 8; j++) {
            t0[j] = IV[4] ^ c[j]->t[0];
            t1[j] = IV[5] ^ c[j]->t[1];
            f0[j] = IV[6] ^ c[j]->f[0];
            f1[j] = IV[7] ^ c[j]->f[1];
        }
        v[12] = _mm512_loadu_si512(t0);
        v[13] = _mm512_loadu_si512(t1);
        v[14] = _mm512_loadu_si512(f0);
        v[15] = _mm512_loadu_si512(f1);
    }

    ROUND8(0,v,m);  ROUND8(1,v,m);  ROUND8(2,v,m);  ROUND8(3,v,m);
    ROUND8(4,v,m);  ROUND8(5,v,m);  ROUND8(6,v,m);  ROUND8(7,v,m);
    ROUND8(8,v,m);  ROUND8(9,v,m);  ROUND8(10,v,m); ROUND8(11,v,m);

    /* Writeback: h[i] ^= v[i] ^ v[i+8] */
    for (int i = 0; i < 8; i++) {
        __m512i xr = _mm512_xor_si512(v[i], v[i + 8]);
        uint64_t out[8];
        _mm512_storeu_si512(out, xr);
        for (int j = 0; j < 8; j++)
            c[j]->h[i] ^= out[j];
    }
}

/* ══════════════════════════════════════════════════════════════
 *  AVX2: 4-way parallel BLAKE2b compression
 * ══════════════════════════════════════════════════════════════ */

#define ROTR64_256_GEN(x, n) \
    _mm256_or_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64-(n)))
/* BLAKE2b uses exactly four rotation amounts. Three of them are whole-byte
 * rotates that AVX2 does in ONE instruction; only 63 needs the shift pair. */
#define ROTR64_256_32(x) _mm256_shuffle_epi32((x), 0xB1)
#define ROTR64_256_24(x) _mm256_shuffle_epi8((x), ROT24_MASK)
#define ROTR64_256_16(x) _mm256_shuffle_epi8((x), ROT16_MASK)
#define ROTR64_256_63(x) ROTR64_256_GEN((x), 63)
#define ROTR64_256(x, n) ROTR64_256_##n(x)

#define G4(r, i, a, b, c, d, m) do { \
    a = _mm256_add_epi64(a, _mm256_add_epi64(b, m[SIGMA[r][2*(i)]])); \
    d = ROTR64_256(_mm256_xor_si256(d, a), 32); \
    c = _mm256_add_epi64(c, d); \
    b = ROTR64_256(_mm256_xor_si256(b, c), 24); \
    a = _mm256_add_epi64(a, _mm256_add_epi64(b, m[SIGMA[r][2*(i)+1]])); \
    d = ROTR64_256(_mm256_xor_si256(d, a), 16); \
    c = _mm256_add_epi64(c, d); \
    b = ROTR64_256(_mm256_xor_si256(b, c), 63); \
} while(0)

#define ROUND4(r, v, m) do { \
    G4(r, 0, v[0], v[4], v[ 8], v[12], m); \
    G4(r, 1, v[1], v[5], v[ 9], v[13], m); \
    G4(r, 2, v[2], v[6], v[10], v[14], m); \
    G4(r, 3, v[3], v[7], v[11], v[15], m); \
    G4(r, 4, v[0], v[5], v[10], v[15], m); \
    G4(r, 5, v[1], v[6], v[11], v[12], m); \
    G4(r, 6, v[2], v[7], v[ 8], v[13], m); \
    G4(r, 7, v[3], v[4], v[ 9], v[14], m); \
} while(0)

__attribute__((target("avx2")))
static void blake2b_compress_4way(
    struct blake2b_ctx *c[4], const uint8_t *b[4])
{
    /* Byte-rotate masks for ROTR64_256_24 / _16: within each 8-byte lane,
     * result byte i = source byte (i + k) mod 8, for k = 3 and k = 2. */
    const __m256i ROT24_MASK = _mm256_setr_epi8(
        3, 4, 5, 6, 7, 0, 1, 2,  11,12,13,14,15, 8, 9,10,
        3, 4, 5, 6, 7, 0, 1, 2,  11,12,13,14,15, 8, 9,10);
    const __m256i ROT16_MASK = _mm256_setr_epi8(
        2, 3, 4, 5, 6, 7, 0, 1,  10,11,12,13,14,15, 8, 9,
        2, 3, 4, 5, 6, 7, 0, 1,  10,11,12,13,14,15, 8, 9);
    __m256i m[16], v[16];

    for (int i = 0; i < 16; i++) {
        uint64_t w[4];
        for (int j = 0; j < 4; j++)
            memcpy(&w[j], b[j] + i * 8, 8);
        m[i] = _mm256_loadu_si256((const __m256i *)w);
    }

    for (int i = 0; i < 8; i++) {
        v[i] = _mm256_set_epi64x(
            (long long)c[3]->h[i], (long long)c[2]->h[i],
            (long long)c[1]->h[i], (long long)c[0]->h[i]);
    }
    for (int i = 0; i < 4; i++)
        v[8+i] = _mm256_set1_epi64x((long long)IV[i]);

    v[12] = _mm256_set_epi64x(
        (long long)(IV[4]^c[3]->t[0]), (long long)(IV[4]^c[2]->t[0]),
        (long long)(IV[4]^c[1]->t[0]), (long long)(IV[4]^c[0]->t[0]));
    v[13] = _mm256_set_epi64x(
        (long long)(IV[5]^c[3]->t[1]), (long long)(IV[5]^c[2]->t[1]),
        (long long)(IV[5]^c[1]->t[1]), (long long)(IV[5]^c[0]->t[1]));
    v[14] = _mm256_set_epi64x(
        (long long)(IV[6]^c[3]->f[0]), (long long)(IV[6]^c[2]->f[0]),
        (long long)(IV[6]^c[1]->f[0]), (long long)(IV[6]^c[0]->f[0]));
    v[15] = _mm256_set_epi64x(
        (long long)(IV[7]^c[3]->f[1]), (long long)(IV[7]^c[2]->f[1]),
        (long long)(IV[7]^c[1]->f[1]), (long long)(IV[7]^c[0]->f[1]));

    ROUND4(0,v,m);  ROUND4(1,v,m);  ROUND4(2,v,m);  ROUND4(3,v,m);
    ROUND4(4,v,m);  ROUND4(5,v,m);  ROUND4(6,v,m);  ROUND4(7,v,m);
    ROUND4(8,v,m);  ROUND4(9,v,m);  ROUND4(10,v,m); ROUND4(11,v,m);

    uint64_t out[4];
    for (int i = 0; i < 8; i++) {
        __m256i xr = _mm256_xor_si256(v[i], v[i + 8]);
        _mm256_storeu_si256((__m256i *)out, xr);
        for (int j = 0; j < 4; j++)
            c[j]->h[i] ^= out[j];
    }
}
#endif /* ZCL_BLAKE2B_X86_SIMD */

#if ZCL_BLAKE2B_ARM_NEON
/* ══════════════════════════════════════════════════════════════
 *  NEON: 4-way parallel BLAKE2b compression
 *
 *  NEON has no 256-bit vector: a 64-bit-lane value lives in a 128-bit
 *  uint64x2_t, so FOUR parallel states need a PAIR of registers per state
 *  word. The batch layout here is therefore
 *
 *      u64x4  v[i] = { v.lo = {state0.word[i], state1.word[i]},
 *                      v.hi = {state2.word[i], state3.word[i]} }
 *
 *  — state j of the batch is lane (j % 2) of the (j < 2 ? lo : hi) register,
 *  in order, with no permute anywhere in the round function. Bit-identity
 *  with the scalar reference is structural: every scalar operation maps to
 *  the same operation applied to .lo and .hi, and the two halves never talk
 *  to each other. The cost of the missing 256-bit width is exactly 2x the
 *  instruction count per 4-lane operation; what the pair layout buys over a
 *  2-way batch is not per-instruction throughput but a full 4-state round
 *  with one spill set, the shape the shared batch entry points hand us.
 *
 *  The four BLAKE2b rotations, per 128-bit half:
 *    32 — vrev64.32s: the two 32-bit halves of each 64-bit lane swap, which
 *         IS rotate-right-32. One instruction.
 *    24 — vqtbl1q_u8 with the same per-lane byte-forward mask the AVX2 code
 *         builds with pshufb: result byte i = source byte (i+3) mod 8.
 *    16 — vqtbl1q_u8, result byte i = source byte (i+2) mod 8.
 *    63 — VSRI #63 inserts x>>63 under the low bit of (x+x), which is
 *         rotate-left-1, which IS rotate-right-63. Two instructions.
 *  Every one of these is an ARMv8.0-A baseline instruction, so the tier needs
 *  no -march and no target attribute to compile. NEON register state is saved
 *  on every context switch by the base ABI, which is why this file needs no
 *  XSAVE-style OS-support probe for it (see check-simd-os-support, whose scan
 *  is x86 target("avx…") attributes for exactly that reason).
 * ══════════════════════════════════════════════════════════════ */

typedef struct { uint64x2_t lo, hi; } u64x4;   /* lo: states 0,1  hi: states 2,3 */

static inline u64x4 u64x4_add(u64x4 a, u64x4 b)
{
    u64x4 r;
    r.lo = vaddq_u64(a.lo, b.lo);
    r.hi = vaddq_u64(a.hi, b.hi);
    return r;
}

static inline u64x4 u64x4_xor(u64x4 a, u64x4 b)
{
    u64x4 r;
    r.lo = veorq_u64(a.lo, b.lo);
    r.hi = veorq_u64(a.hi, b.hi);
    return r;
}

static inline u64x4 u64x4_splat(uint64_t x)
{
    u64x4 r;
    r.lo = vdupq_n_u64(x);
    r.hi = vdupq_n_u64(x);
    return r;
}

/* Whole-byte rotates: vqtbl1q_u8 indexes a 16-byte table, and the byte index
 * for lane 1 is lane 0's plus 8 — the same two-lane shape pshufb wants. */
static inline uint64x2_t rot64_bytes(uint64x2_t x, const uint8_t idx[16])
{
    uint8x16_t tbl;
    memcpy(&tbl, idx, 16);
    return vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(x), tbl));
}

static inline uint64x2_t rot64_32(uint64x2_t x)
{
    return vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(x)));
}

static inline uint64x2_t rot64_24(uint64x2_t x)
{
    static const uint8_t idx[16] = {
        3, 4, 5, 6, 7, 0, 1, 2,  11, 12, 13, 14, 15, 8, 9, 10
    };
    return rot64_bytes(x, idx);
}

static inline uint64x2_t rot64_16(uint64x2_t x)
{
    static const uint8_t idx[16] = {
        2, 3, 4, 5, 6, 7, 0, 1,  10, 11, 12, 13, 14, 15, 8, 9
    };
    return rot64_bytes(x, idx);
}

static inline uint64x2_t rot64_63(uint64x2_t x)
{
    /* VSRI keeps the top 63 bits of (x+x) and inserts x>>63 into bit 0:
     * exactly rotr64(x, 63) — there is no ror-by-imm on 64-bit NEON lanes. */
    return vsriq_n_u64(vaddq_u64(x, x), x, 63);
}

static inline u64x4 u64x4_rot(u64x4 x, unsigned n)
{
    u64x4 r;
    switch (n) {
    case 32: r.lo = rot64_32(x.lo); r.hi = rot64_32(x.hi); break;
    case 24: r.lo = rot64_24(x.lo); r.hi = rot64_24(x.hi); break;
    case 16: r.lo = rot64_16(x.lo); r.hi = rot64_16(x.hi); break;
    default: r.lo = rot64_63(x.lo); r.hi = rot64_63(x.hi); break;
    }
    return r;
}

#define G4N(r, i, a, b, c, d, m) do { \
    a = u64x4_add(a, u64x4_add(b, m[SIGMA[r][2*(i)]])); \
    d = u64x4_rot(u64x4_xor(d, a), 32); \
    c = u64x4_add(c, d); \
    b = u64x4_rot(u64x4_xor(b, c), 24); \
    a = u64x4_add(a, u64x4_add(b, m[SIGMA[r][2*(i)+1]])); \
    d = u64x4_rot(u64x4_xor(d, a), 16); \
    c = u64x4_add(c, d); \
    b = u64x4_rot(u64x4_xor(b, c), 63); \
} while(0)

#define ROUND4N(r, v, m) do { \
    G4N(r, 0, v[0], v[4], v[ 8], v[12], m); \
    G4N(r, 1, v[1], v[5], v[ 9], v[13], m); \
    G4N(r, 2, v[2], v[6], v[10], v[14], m); \
    G4N(r, 3, v[3], v[7], v[11], v[15], m); \
    G4N(r, 4, v[0], v[5], v[10], v[15], m); \
    G4N(r, 5, v[1], v[6], v[11], v[12], m); \
    G4N(r, 6, v[2], v[7], v[ 8], v[13], m); \
    G4N(r, 7, v[3], v[4], v[ 9], v[14], m); \
} while(0)

static void blake2b_compress_4way_neon(
    struct blake2b_ctx *c[4], const uint8_t *b[4])
{
    u64x4 m[16], v[16];

    /* Lane j of u64x4 m[i] is word i of block j. The byte memcpy is what
     * makes this identical to the scalar load64: both take the little-endian
     * value the BLAKE2b block layout specifies. */
    for (int i = 0; i < 16; i++) {
        uint64_t w[4];
        for (int j = 0; j < 4; j++)
            memcpy(&w[j], b[j] + i * 8, 8);
        m[i].lo = vld1q_u64(w);
        m[i].hi = vld1q_u64(w + 2);
    }

    for (int i = 0; i < 8; i++) {
        uint64_t h[4];
        for (int j = 0; j < 4; j++) h[j] = c[j]->h[i];
        v[i].lo = vld1q_u64(h);
        v[i].hi = vld1q_u64(h + 2);
    }
    for (int i = 0; i < 4; i++)
        v[8 + i] = u64x4_splat(IV[i]);

    {
        uint64_t t0[4], t1[4], f0[4], f1[4];
        for (int j = 0; j < 4; j++) {
            t0[j] = IV[4] ^ c[j]->t[0];
            t1[j] = IV[5] ^ c[j]->t[1];
            f0[j] = IV[6] ^ c[j]->f[0];
            f1[j] = IV[7] ^ c[j]->f[1];
        }
        v[12].lo = vld1q_u64(t0); v[12].hi = vld1q_u64(t0 + 2);
        v[13].lo = vld1q_u64(t1); v[13].hi = vld1q_u64(t1 + 2);
        v[14].lo = vld1q_u64(f0); v[14].hi = vld1q_u64(f0 + 2);
        v[15].lo = vld1q_u64(f1); v[15].hi = vld1q_u64(f1 + 2);
    }

    ROUND4N(0,v,m);  ROUND4N(1,v,m);  ROUND4N(2,v,m);  ROUND4N(3,v,m);
    ROUND4N(4,v,m);  ROUND4N(5,v,m);  ROUND4N(6,v,m);  ROUND4N(7,v,m);
    ROUND4N(8,v,m);  ROUND4N(9,v,m);  ROUND4N(10,v,m); ROUND4N(11,v,m);

    uint64_t out[4];
    for (int i = 0; i < 8; i++) {
        u64x4 xr = u64x4_xor(v[i], v[i + 8]);
        vst1q_u64(out, xr.lo);
        vst1q_u64(out + 2, xr.hi);
        for (int j = 0; j < 4; j++)
            c[j]->h[i] ^= out[j];
    }
}

/* ── The one-time gate: NEON output == portable output ──────────
 *
 * Four fixed vectors, each a real Equihash-shaped state: personalized init
 * through the PORTABLE init, a header-shaped prefix absorbed through the
 * PORTABLE update, then the 4-byte index finalized both ways. The NEON leg is
 * driven exactly as finalize_states() drives it (same block buffer, same t/f
 * fields, same compress call) so the gate proves the thing that will actually
 * run, not a cousin of it. One divergent bit -> the process stays scalar. */
static bool blake2b_neon_kat(void)
{
    static const size_t OUTLEN = 50;   /* p->hash_output for Equihash (200,9) */
    static const uint8_t pers[BLAKE2B_PERSONALBYTES] = "zcl-neon-kat-v1";
    struct blake2b_ctx base[4];
    uint32_t idx[4];

    for (int j = 0; j < 4; j++) {
        uint8_t salt[BLAKE2B_SALTBYTES] = {0};
        salt[0] = (uint8_t)(0xA0 + j);
        if (blake2b_init_salt_personal(&base[j], OUTLEN, NULL, 0, salt, pers) < 0)
            return false;
        unsigned char pre[13];
        for (size_t i = 0; i < sizeof(pre); i++)
            pre[i] = (unsigned char)(i * 31 + (size_t)j);
        if (blake2b_update(&base[j], pre, sizeof(pre)) < 0)
            return false;
        idx[j] = 0x01020304u + 0x11111111u * (uint32_t)j;
    }

    struct blake2b_ctx ns[4];
    uint8_t blocks[4][BLAKE2B_BLOCKBYTES];
    for (int j = 0; j < 4; j++) {
        ns[j] = base[j];
        memset(blocks[j], 0, sizeof(blocks[j]));
        memcpy(blocks[j], base[j].buf, base[j].buflen);
        memcpy(blocks[j] + base[j].buflen, &idx[j], sizeof(idx[j]));
        ns[j].t[0] += base[j].buflen + sizeof(idx[j]);
        ns[j].t[1] = 0;
        ns[j].f[0] = (uint64_t)-1;
    }

    struct blake2b_ctx *cp[4] = {&ns[0], &ns[1], &ns[2], &ns[3]};
    const uint8_t *bp[4] = {blocks[0], blocks[1], blocks[2], blocks[3]};
    blake2b_compress_4way_neon(cp, bp);

    for (int j = 0; j < 4; j++) {
        struct blake2b_ctx s = base[j];
        unsigned char dig[BLAKE2B_OUTBYTES];
        if (blake2b_update(&s, &idx[j], sizeof(idx[j])) < 0)
            return false;
        if (blake2b_final(&s, dig, OUTLEN) < 0)
            return false;
        if (memcmp(ns[j].h, s.h, sizeof(s.h)) != 0)
            return false;
    }
    return true;
}
#endif /* ZCL_BLAKE2B_ARM_NEON */
#endif /* IV + SIGMA shared by the x86 and arm64 compressors */

/* ══════════════════════════════════════════════════════════════
 *  Equihash batch hash generation — tiered dispatch
 *  (x86-64: 8-way / 4-way / scalar; arm64: 4-way / scalar)
 * ══════════════════════════════════════════════════════════════ */

/* Scalar reference for indices[from .. n): one update + final per index. */
static inline void blake2b_finalize_scalar_range(const struct blake2b_ctx *base,
                                                 const uint32_t *indices,
                                                 int from, int n,
                                                 unsigned char **hashes,
                                                 size_t hash_len)
{
    for (int i = from; i < n; i++) {
        struct blake2b_ctx s = *base;
        blake2b_update(&s, &indices[i], sizeof(uint32_t));
        blake2b_final(&s, hashes[i], hash_len);
    }
}

#if ZCL_BLAKE2B_X86_SIMD || ZCL_BLAKE2B_ARM_NEON
/* Builds the n per-index states and their single padded final blocks. */
static inline void blake2b_prepare_batch_states(const struct blake2b_ctx *base,
                                                const uint32_t *indices, int n,
                                                struct blake2b_ctx states[8],
                                                uint8_t blocks[8][128])
{
    size_t bl = base->buflen;

    for (int i = 0; i < n; i++) {
        states[i] = *base;
        memset(blocks[i], 0, 128);
        memcpy(blocks[i], base->buf, bl);
        memcpy(blocks[i] + bl, &indices[i], 4);
        states[i].t[0] += bl + 4;
        states[i].t[1] = 0;
        states[i].f[0] = (uint64_t)-1;
    }
}
#endif

#if ZCL_BLAKE2B_X86_SIMD
#define BLAKE2B_COMPRESS_GROUP_OF_4 blake2b_compress_4way
#elif ZCL_BLAKE2B_ARM_NEON
#define BLAKE2B_COMPRESS_GROUP_OF_4 blake2b_compress_4way_neon
#endif

#if ZCL_BLAKE2B_X86_SIMD || ZCL_BLAKE2B_ARM_NEON
static inline void blake2b_finalize_groups_of_4(const struct blake2b_ctx *base,
                                                const uint32_t *indices, int n,
                                                struct blake2b_ctx states[8],
                                                uint8_t blocks[8][128],
                                                unsigned char **hashes,
                                                size_t hash_len)
{
    int done = 0;
    while (n - done >= 4) {
        struct blake2b_ctx *cp[4] = {&states[done],   &states[done+1],
                                     &states[done+2], &states[done+3]};
        const uint8_t *bp[4] = {blocks[done],   blocks[done+1],
                                blocks[done+2], blocks[done+3]};
        BLAKE2B_COMPRESS_GROUP_OF_4(cp, bp);
        for (int i = done; i < done + 4; i++)
            memcpy(hashes[i], states[i].h, hash_len);
        done += 4;
    }
    blake2b_finalize_scalar_range(base, indices, done, n, hashes, hash_len);
}
#endif

/* Internal: finalize N states that share the same base + 4-byte index */
static void finalize_states(const struct blake2b_ctx *base,
                            const uint32_t *indices, int n,
                            unsigned char **hashes, size_t hash_len)
{
#if ZCL_BLAKE2B_X86_SIMD
    struct blake2b_ctx states[8];
    uint8_t blocks[8][128];
    blake2b_prepare_batch_states(base, indices, n, states, blocks);

    if (n == 8 && atomic_load_explicit(&g_use_avx512f, memory_order_relaxed)) {
        struct blake2b_ctx *cp[8];
        const uint8_t *bp[8];
        for (int i = 0; i < 8; i++) { cp[i] = &states[i]; bp[i] = blocks[i]; }
        blake2b_compress_8way(cp, bp);
        for (int i = 0; i < 8; i++)
            memcpy(hashes[i], states[i].h, hash_len);
        return;
    }

    if (n >= 4 && atomic_load_explicit(&g_use_avx2, memory_order_relaxed)) {
        /* Whole groups of 4 go through the vector unit; any remainder (< 4)
         * goes through the scalar reference below.
         *
         * The remainder used to be padded up to 4 by repeating &states[4] in
         * the spare slots. That is not a harmless pad: blake2b_compress_4way
         * finishes with `c[j]->h[i] ^= out[j]` for j=0..3, so four aliases of
         * one context XOR four different lane results into the SAME state and
         * it comes out garbage. It was unreachable only because the two public
         * entry points pass exactly 4 and 8 -- a 5..7 caller would have
         * silently produced wrong Equihash hashes. Splitting on the group
         * boundary removes the aliasing rather than relying on nobody ever
         * passing the wrong n. */
        blake2b_finalize_groups_of_4(base, indices, n, states, blocks,
                                     hashes, hash_len);
        return;
    }
#elif ZCL_BLAKE2B_ARM_NEON
    struct blake2b_ctx states[8];
    uint8_t blocks[8][128];
    blake2b_prepare_batch_states(base, indices, n, states, blocks);

    if (n >= 4 && atomic_load_explicit(&g_use_neon, memory_order_relaxed)) {
        /* Same group-boundary split as the AVX2 arm above: whole groups of 4
         * go through the vector unit and the remainder goes through the scalar
         * reference. Repeating a context into a spare lane would XOR four lane
         * results into one state — the aliasing bug the AVX2 arm documents —
         * so the split, not the caller's discipline, is what prevents it. */
        blake2b_finalize_groups_of_4(base, indices, n, states, blocks,
                                     hashes, hash_len);
        return;
    }
#endif

    /* Scalar fallback */
    blake2b_finalize_scalar_range(base, indices, 0, n, hashes, hash_len);
}

/* Public API: generate 4 hashes (backward compatible) */
void equihash_generate_hash_batch4(
    const struct blake2b_ctx *base_state,
    const uint32_t indices[4],
    unsigned char *hash0, unsigned char *hash1,
    unsigned char *hash2, unsigned char *hash3,
    size_t hash_len)
{
    detect_features();
    unsigned char *h[4] = {hash0, hash1, hash2, hash3};

    if (base_state->buflen + 4 <= BLAKE2B_BLOCKBYTES) {
        finalize_states(base_state, indices, 4, h, hash_len);
    } else {
        /* Rare: buffer too full, use scalar */
        for (int i = 0; i < 4; i++) {
            struct blake2b_ctx s = *base_state;
            blake2b_update(&s, &indices[i], sizeof(uint32_t));
            blake2b_final(&s, h[i], hash_len);
        }
    }
}

/* New API: generate 8 hashes (AVX-512 optimized) */
void equihash_generate_hash_batch8(
    const struct blake2b_ctx *base_state,
    const uint32_t indices[8],
    unsigned char *hashes[8],
    size_t hash_len)
{
    detect_features();

    if (base_state->buflen + 4 <= BLAKE2B_BLOCKBYTES) {
        finalize_states(base_state, indices, 8, hashes, hash_len);
    } else {
        for (int i = 0; i < 8; i++) {
            struct blake2b_ctx s = *base_state;
            blake2b_update(&s, &indices[i], sizeof(uint32_t));
            blake2b_final(&s, hashes[i], hash_len);
        }
    }
}

/* ── Tier selection (differential oracle + benchmark) ─────────── */

int equihash_blake2b_batch_select_impl(enum blake2b_batch_impl which)
{
    detect_features();

#if ZCL_BLAKE2B_X86_SIMD
    const bool cap512 = atomic_load_explicit(&g_cap_avx512f, memory_order_relaxed);
    const bool cap256 = atomic_load_explicit(&g_cap_avx2, memory_order_relaxed);

    /* A request is narrowed to what the host can actually execute, never
     * widened. Returning the INSTALLED tier (not the requested one) is what
     * lets a caller skip rather than mis-report on a host that lacks it. */
    bool use512 = false, use256 = false;
    switch (which) {
    case BLAKE2B_BATCH_IMPL_SCALAR:
        break;
    case BLAKE2B_BATCH_IMPL_AVX2:
        use256 = cap256;
        break;
    case BLAKE2B_BATCH_IMPL_AVX512:
        use512 = cap512;
        use256 = cap256;   /* n<8 batches still take the widest legal path */
        break;
    case BLAKE2B_BATCH_IMPL_AUTO:
    default:
        use512 = cap512;
        use256 = cap256;
        break;
    }

    atomic_store_explicit(&g_use_avx512f, use512, memory_order_relaxed);
    atomic_store_explicit(&g_use_avx2, use256, memory_order_relaxed);

    if (use512) return BLAKE2B_BATCH_IMPL_AVX512;
    if (use256) return BLAKE2B_BATCH_IMPL_AVX2;
    return BLAKE2B_BATCH_IMPL_SCALAR;
#elif ZCL_BLAKE2B_ARM_NEON
    /* Value 1 of the enum names this host's 4-way SIMD tier, which on arm64 is
     * NEON. Value 2 (the 8-way tier) has no NEON counterpart, so a request for
     * it NARROWS to the widest tier that exists here — never widened, and
     * reported as the tier actually installed, exactly as on x86. */
    const bool cap_neon = atomic_load_explicit(&g_cap_neon, memory_order_relaxed);
    bool use_neon = false;
    switch (which) {
    case BLAKE2B_BATCH_IMPL_SCALAR:
        break;
    case BLAKE2B_BATCH_IMPL_AVX2:     /* the 4-way SIMD tier */
    case BLAKE2B_BATCH_IMPL_AVX512:   /* 8-way: narrowed to the 4-way here */
        use_neon = cap_neon;
        break;
    case BLAKE2B_BATCH_IMPL_AUTO:
    default:
        use_neon = cap_neon;
        break;
    }

    atomic_store_explicit(&g_use_neon, use_neon, memory_order_relaxed);
    return use_neon ? BLAKE2B_BATCH_IMPL_AVX2 : BLAKE2B_BATCH_IMPL_SCALAR;
#else
    (void)which;
    return BLAKE2B_BATCH_IMPL_SCALAR;
#endif
}

const char *equihash_blake2b_batch_implementation(void)
{
    detect_features();
    if (atomic_load_explicit(&g_use_avx512f, memory_order_relaxed))
        return "AVX-512 (8-way)";
    if (atomic_load_explicit(&g_use_avx2, memory_order_relaxed))
        return "AVX2 (4-way)";
    if (atomic_load_explicit(&g_use_neon, memory_order_relaxed))
        return "NEON (4-way)";
    return "scalar";
}
