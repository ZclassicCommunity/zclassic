/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "crypto/sha512.h"
#include "crypto/common.h"
#include <string.h>

#if defined(__aarch64__)
#include <arm_neon.h>
#include <stdatomic.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#endif

static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) { return z ^ (x & (y ^ z)); }
static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (z & (x | y)); }
static inline uint64_t Sigma0(uint64_t x) { return (x >> 28 | x << 36) ^ (x >> 34 | x << 30) ^ (x >> 39 | x << 25); }
static inline uint64_t Sigma1(uint64_t x) { return (x >> 14 | x << 50) ^ (x >> 18 | x << 46) ^ (x >> 41 | x << 23); }
static inline uint64_t sigma0_64(uint64_t x) { return (x >> 1 | x << 63) ^ (x >> 8 | x << 56) ^ (x >> 7); }
static inline uint64_t sigma1_64(uint64_t x) { return (x >> 19 | x << 45) ^ (x >> 61 | x << 3) ^ (x >> 6); }

static inline void Round(uint64_t a, uint64_t b, uint64_t c, uint64_t *d,
                          uint64_t e, uint64_t f, uint64_t g, uint64_t *h,
                          uint64_t k, uint64_t w)
{
    uint64_t t1 = *h + Sigma1(e) + Ch(e, f, g) + k + w;
    uint64_t t2 = Sigma0(a) + Maj(a, b, c);
    *d += t1;
    *h = t1 + t2;
}

static void sha512_transform_portable(uint64_t *s, const unsigned char *chunk)
{
    uint64_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    uint64_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, &d, e, f, g, &h, 0x428a2f98d728ae22ull, w0 = ReadBE64(chunk + 0));
    Round(h, a, b, &c, d, e, f, &g, 0x7137449123ef65cdull, w1 = ReadBE64(chunk + 8));
    Round(g, h, a, &b, c, d, e, &f, 0xb5c0fbcfec4d3b2full, w2 = ReadBE64(chunk + 16));
    Round(f, g, h, &a, b, c, d, &e, 0xe9b5dba58189dbbcull, w3 = ReadBE64(chunk + 24));
    Round(e, f, g, &h, a, b, c, &d, 0x3956c25bf348b538ull, w4 = ReadBE64(chunk + 32));
    Round(d, e, f, &g, h, a, b, &c, 0x59f111f1b605d019ull, w5 = ReadBE64(chunk + 40));
    Round(c, d, e, &f, g, h, a, &b, 0x923f82a4af194f9bull, w6 = ReadBE64(chunk + 48));
    Round(b, c, d, &e, f, g, h, &a, 0xab1c5ed5da6d8118ull, w7 = ReadBE64(chunk + 56));
    Round(a, b, c, &d, e, f, g, &h, 0xd807aa98a3030242ull, w8 = ReadBE64(chunk + 64));
    Round(h, a, b, &c, d, e, f, &g, 0x12835b0145706fbeull, w9 = ReadBE64(chunk + 72));
    Round(g, h, a, &b, c, d, e, &f, 0x243185be4ee4b28cull, w10 = ReadBE64(chunk + 80));
    Round(f, g, h, &a, b, c, d, &e, 0x550c7dc3d5ffb4e2ull, w11 = ReadBE64(chunk + 88));
    Round(e, f, g, &h, a, b, c, &d, 0x72be5d74f27b896full, w12 = ReadBE64(chunk + 96));
    Round(d, e, f, &g, h, a, b, &c, 0x80deb1fe3b1696b1ull, w13 = ReadBE64(chunk + 104));
    Round(c, d, e, &f, g, h, a, &b, 0x9bdc06a725c71235ull, w14 = ReadBE64(chunk + 112));
    Round(b, c, d, &e, f, g, h, &a, 0xc19bf174cf692694ull, w15 = ReadBE64(chunk + 120));

    Round(a, b, c, &d, e, f, g, &h, 0xe49b69c19ef14ad2ull, w0 += sigma1_64(w14) + w9 + sigma0_64(w1));
    Round(h, a, b, &c, d, e, f, &g, 0xefbe4786384f25e3ull, w1 += sigma1_64(w15) + w10 + sigma0_64(w2));
    Round(g, h, a, &b, c, d, e, &f, 0x0fc19dc68b8cd5b5ull, w2 += sigma1_64(w0) + w11 + sigma0_64(w3));
    Round(f, g, h, &a, b, c, d, &e, 0x240ca1cc77ac9c65ull, w3 += sigma1_64(w1) + w12 + sigma0_64(w4));
    Round(e, f, g, &h, a, b, c, &d, 0x2de92c6f592b0275ull, w4 += sigma1_64(w2) + w13 + sigma0_64(w5));
    Round(d, e, f, &g, h, a, b, &c, 0x4a7484aa6ea6e483ull, w5 += sigma1_64(w3) + w14 + sigma0_64(w6));
    Round(c, d, e, &f, g, h, a, &b, 0x5cb0a9dcbd41fbd4ull, w6 += sigma1_64(w4) + w15 + sigma0_64(w7));
    Round(b, c, d, &e, f, g, h, &a, 0x76f988da831153b5ull, w7 += sigma1_64(w5) + w0 + sigma0_64(w8));
    Round(a, b, c, &d, e, f, g, &h, 0x983e5152ee66dfabull, w8 += sigma1_64(w6) + w1 + sigma0_64(w9));
    Round(h, a, b, &c, d, e, f, &g, 0xa831c66d2db43210ull, w9 += sigma1_64(w7) + w2 + sigma0_64(w10));
    Round(g, h, a, &b, c, d, e, &f, 0xb00327c898fb213full, w10 += sigma1_64(w8) + w3 + sigma0_64(w11));
    Round(f, g, h, &a, b, c, d, &e, 0xbf597fc7beef0ee4ull, w11 += sigma1_64(w9) + w4 + sigma0_64(w12));
    Round(e, f, g, &h, a, b, c, &d, 0xc6e00bf33da88fc2ull, w12 += sigma1_64(w10) + w5 + sigma0_64(w13));
    Round(d, e, f, &g, h, a, b, &c, 0xd5a79147930aa725ull, w13 += sigma1_64(w11) + w6 + sigma0_64(w14));
    Round(c, d, e, &f, g, h, a, &b, 0x06ca6351e003826full, w14 += sigma1_64(w12) + w7 + sigma0_64(w15));
    Round(b, c, d, &e, f, g, h, &a, 0x142929670a0e6e70ull, w15 += sigma1_64(w13) + w8 + sigma0_64(w0));

    Round(a, b, c, &d, e, f, g, &h, 0x27b70a8546d22ffcull, w0 += sigma1_64(w14) + w9 + sigma0_64(w1));
    Round(h, a, b, &c, d, e, f, &g, 0x2e1b21385c26c926ull, w1 += sigma1_64(w15) + w10 + sigma0_64(w2));
    Round(g, h, a, &b, c, d, e, &f, 0x4d2c6dfc5ac42aedull, w2 += sigma1_64(w0) + w11 + sigma0_64(w3));
    Round(f, g, h, &a, b, c, d, &e, 0x53380d139d95b3dfull, w3 += sigma1_64(w1) + w12 + sigma0_64(w4));
    Round(e, f, g, &h, a, b, c, &d, 0x650a73548baf63deull, w4 += sigma1_64(w2) + w13 + sigma0_64(w5));
    Round(d, e, f, &g, h, a, b, &c, 0x766a0abb3c77b2a8ull, w5 += sigma1_64(w3) + w14 + sigma0_64(w6));
    Round(c, d, e, &f, g, h, a, &b, 0x81c2c92e47edaee6ull, w6 += sigma1_64(w4) + w15 + sigma0_64(w7));
    Round(b, c, d, &e, f, g, h, &a, 0x92722c851482353bull, w7 += sigma1_64(w5) + w0 + sigma0_64(w8));
    Round(a, b, c, &d, e, f, g, &h, 0xa2bfe8a14cf10364ull, w8 += sigma1_64(w6) + w1 + sigma0_64(w9));
    Round(h, a, b, &c, d, e, f, &g, 0xa81a664bbc423001ull, w9 += sigma1_64(w7) + w2 + sigma0_64(w10));
    Round(g, h, a, &b, c, d, e, &f, 0xc24b8b70d0f89791ull, w10 += sigma1_64(w8) + w3 + sigma0_64(w11));
    Round(f, g, h, &a, b, c, d, &e, 0xc76c51a30654be30ull, w11 += sigma1_64(w9) + w4 + sigma0_64(w12));
    Round(e, f, g, &h, a, b, c, &d, 0xd192e819d6ef5218ull, w12 += sigma1_64(w10) + w5 + sigma0_64(w13));
    Round(d, e, f, &g, h, a, b, &c, 0xd69906245565a910ull, w13 += sigma1_64(w11) + w6 + sigma0_64(w14));
    Round(c, d, e, &f, g, h, a, &b, 0xf40e35855771202aull, w14 += sigma1_64(w12) + w7 + sigma0_64(w15));
    Round(b, c, d, &e, f, g, h, &a, 0x106aa07032bbd1b8ull, w15 += sigma1_64(w13) + w8 + sigma0_64(w0));

    Round(a, b, c, &d, e, f, g, &h, 0x19a4c116b8d2d0c8ull, w0 += sigma1_64(w14) + w9 + sigma0_64(w1));
    Round(h, a, b, &c, d, e, f, &g, 0x1e376c085141ab53ull, w1 += sigma1_64(w15) + w10 + sigma0_64(w2));
    Round(g, h, a, &b, c, d, e, &f, 0x2748774cdf8eeb99ull, w2 += sigma1_64(w0) + w11 + sigma0_64(w3));
    Round(f, g, h, &a, b, c, d, &e, 0x34b0bcb5e19b48a8ull, w3 += sigma1_64(w1) + w12 + sigma0_64(w4));
    Round(e, f, g, &h, a, b, c, &d, 0x391c0cb3c5c95a63ull, w4 += sigma1_64(w2) + w13 + sigma0_64(w5));
    Round(d, e, f, &g, h, a, b, &c, 0x4ed8aa4ae3418acbull, w5 += sigma1_64(w3) + w14 + sigma0_64(w6));
    Round(c, d, e, &f, g, h, a, &b, 0x5b9cca4f7763e373ull, w6 += sigma1_64(w4) + w15 + sigma0_64(w7));
    Round(b, c, d, &e, f, g, h, &a, 0x682e6ff3d6b2b8a3ull, w7 += sigma1_64(w5) + w0 + sigma0_64(w8));
    Round(a, b, c, &d, e, f, g, &h, 0x748f82ee5defb2fcull, w8 += sigma1_64(w6) + w1 + sigma0_64(w9));
    Round(h, a, b, &c, d, e, f, &g, 0x78a5636f43172f60ull, w9 += sigma1_64(w7) + w2 + sigma0_64(w10));
    Round(g, h, a, &b, c, d, e, &f, 0x84c87814a1f0ab72ull, w10 += sigma1_64(w8) + w3 + sigma0_64(w11));
    Round(f, g, h, &a, b, c, d, &e, 0x8cc702081a6439ecull, w11 += sigma1_64(w9) + w4 + sigma0_64(w12));
    Round(e, f, g, &h, a, b, c, &d, 0x90befffa23631e28ull, w12 += sigma1_64(w10) + w5 + sigma0_64(w13));
    Round(d, e, f, &g, h, a, b, &c, 0xa4506cebde82bde9ull, w13 += sigma1_64(w11) + w6 + sigma0_64(w14));
    Round(c, d, e, &f, g, h, a, &b, 0xbef9a3f7b2c67915ull, w14 += sigma1_64(w12) + w7 + sigma0_64(w15));
    Round(b, c, d, &e, f, g, h, &a, 0xc67178f2e372532bull, w15 += sigma1_64(w13) + w8 + sigma0_64(w0));

    Round(a, b, c, &d, e, f, g, &h, 0xca273eceea26619cull, w0 += sigma1_64(w14) + w9 + sigma0_64(w1));
    Round(h, a, b, &c, d, e, f, &g, 0xd186b8c721c0c207ull, w1 += sigma1_64(w15) + w10 + sigma0_64(w2));
    Round(g, h, a, &b, c, d, e, &f, 0xeada7dd6cde0eb1eull, w2 += sigma1_64(w0) + w11 + sigma0_64(w3));
    Round(f, g, h, &a, b, c, d, &e, 0xf57d4f7fee6ed178ull, w3 += sigma1_64(w1) + w12 + sigma0_64(w4));
    Round(e, f, g, &h, a, b, c, &d, 0x06f067aa72176fbaull, w4 += sigma1_64(w2) + w13 + sigma0_64(w5));
    Round(d, e, f, &g, h, a, b, &c, 0x0a637dc5a2c898a6ull, w5 += sigma1_64(w3) + w14 + sigma0_64(w6));
    Round(c, d, e, &f, g, h, a, &b, 0x113f9804bef90daeull, w6 += sigma1_64(w4) + w15 + sigma0_64(w7));
    Round(b, c, d, &e, f, g, h, &a, 0x1b710b35131c471bull, w7 += sigma1_64(w5) + w0 + sigma0_64(w8));
    Round(a, b, c, &d, e, f, g, &h, 0x28db77f523047d84ull, w8 += sigma1_64(w6) + w1 + sigma0_64(w9));
    Round(h, a, b, &c, d, e, f, &g, 0x32caab7b40c72493ull, w9 += sigma1_64(w7) + w2 + sigma0_64(w10));
    Round(g, h, a, &b, c, d, e, &f, 0x3c9ebe0a15c9bebcull, w10 += sigma1_64(w8) + w3 + sigma0_64(w11));
    Round(f, g, h, &a, b, c, d, &e, 0x431d67c49c100d4cull, w11 += sigma1_64(w9) + w4 + sigma0_64(w12));
    Round(e, f, g, &h, a, b, c, &d, 0x4cc5d4becb3e42b6ull, w12 += sigma1_64(w10) + w5 + sigma0_64(w13));
    Round(d, e, f, &g, h, a, b, &c, 0x597f299cfc657e2aull, w13 += sigma1_64(w11) + w6 + sigma0_64(w14));
    Round(c, d, e, &f, g, h, a, &b, 0x5fcb6fab3ad6faecull, w14 + sigma1_64(w12) + w7 + sigma0_64(w15));
    Round(b, c, d, &e, f, g, h, &a, 0x6c44198c4a475817ull, w15 + sigma1_64(w13) + w8 + sigma0_64(w0));

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

#if defined(__aarch64__)
/* -1 = unprobed/AUTO, 0 = portable, 1 = verified FEAT_SHA512. Several hashing
 * threads may race the deterministic probe; relaxed atomics prevent a data
 * race without adding ordering that the immutable inputs do not need. */
static _Atomic int sha512_arm_available = -1;

static const uint64_t sha512_arm_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static inline uint64x2_t sha512_arm_load(const unsigned char *p)
{
    return vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p)));
}

__attribute__((target("+sha3")))
static inline uint64x2_t sha512_arm_schedule(uint64x2_t m8, uint64x2_t m7,
                                             uint64x2_t m4, uint64x2_t m3,
                                             uint64x2_t m1)
{
    uint64x2_t low_sigma = vsha512su0q_u64(m8, m7);
    return vsha512su1q_u64(low_sigma, m1, vextq_u64(m4, m3, 1));
}

/* Two rounds. State vectors are AB/CD/EF/GH; callers rotate their argument
 * positions every pair so no explicit state shuffle is needed between rounds. */
__attribute__((target("+sha3")))
static inline void sha512_arm_round2(unsigned round, uint64x2_t schedule,
                                     uint64x2_t *ab, uint64x2_t *cd,
                                     uint64x2_t *ef, uint64x2_t *gh)
{
    uint64x2_t kw = vaddq_u64(schedule, vld1q_u64(sha512_arm_k + round));
    uint64x2_t sum = vaddq_u64(*gh, vextq_u64(kw, kw, 1));
    uint64x2_t de = vextq_u64(*cd, *ef, 1);
    uint64x2_t fg = vextq_u64(*ef, *gh, 1);
    uint64x2_t t = vsha512hq_u64(sum, fg, de);
    *gh = vsha512h2q_u64(t, *cd, *ab);
    *cd = vaddq_u64(*cd, t);
}

__attribute__((target("+sha3")))
static void sha512_transform_arm(uint64_t *state, const unsigned char *data)
{
    uint64x2_t ab = vld1q_u64(state);
    uint64x2_t cd = vld1q_u64(state + 2);
    uint64x2_t ef = vld1q_u64(state + 4);
    uint64x2_t gh = vld1q_u64(state + 6);
    const uint64x2_t ab0 = ab, cd0 = cd, ef0 = ef, gh0 = gh;
    uint64x2_t w[8];

#define SHA512_ARM_PAIR(I, A, B, C, D) \
    sha512_arm_round2((I) * 2U, w[(I) & 7U], &(A), &(B), &(C), &(D))
#define SHA512_ARM_EXPAND(I) \
    w[(I) & 7U] = sha512_arm_schedule( \
        w[(I) & 7U], w[((I) + 1U) & 7U], w[((I) + 4U) & 7U], \
        w[((I) + 5U) & 7U], w[((I) + 7U) & 7U])

    for (unsigned i = 0; i < 8; ++i)
        w[i] = sha512_arm_load(data + 16U * i);

#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (unsigned i = 0; i < 40; ++i) {
        if (i >= 8)
            SHA512_ARM_EXPAND(i);
        switch (i & 3U) {
        case 0: SHA512_ARM_PAIR(i, ab, cd, ef, gh); break;
        case 1: SHA512_ARM_PAIR(i, gh, ab, cd, ef); break;
        case 2: SHA512_ARM_PAIR(i, ef, gh, ab, cd); break;
        default: SHA512_ARM_PAIR(i, cd, ef, gh, ab); break;
        }
    }

#undef SHA512_ARM_EXPAND
#undef SHA512_ARM_PAIR

    vst1q_u64(state, vaddq_u64(ab0, ab));
    vst1q_u64(state + 2, vaddq_u64(cd0, cd));
    vst1q_u64(state + 4, vaddq_u64(ef0, ef));
    vst1q_u64(state + 6, vaddq_u64(gh0, gh));
}

static bool sha512_arm_os_available(void)
{
#if defined(__APPLE__)
    static const char *const names[] = {
        "hw.optional.arm.FEAT_SHA512",
        "hw.optional.armv8_2_sha512",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        int present = 0;
        size_t len = sizeof(present);
        if (sysctlbyname(names[i], &present, &len, NULL, 0) == 0 &&
            len == sizeof(present) && present == 1)
            return true;
    }
#endif
    return false;
}

static void sha512_detect_arm(void)
{
    if (!sha512_arm_os_available()) {
        atomic_store_explicit(&sha512_arm_available, 0, memory_order_relaxed);
        return;
    }

    unsigned char block[SHA512_BLOCK_SIZE] = {0};
    block[0] = 'a'; block[1] = 'b'; block[2] = 'c'; block[3] = 0x80;
    block[127] = 24;
    uint64_t portable[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
    };
    uint64_t hardware[8];
    memcpy(hardware, portable, sizeof(hardware));
    sha512_transform_portable(portable, block);
    sha512_transform_arm(hardware, block);
    atomic_store_explicit(&sha512_arm_available,
                          memcmp(portable, hardware, sizeof(portable)) == 0,
                          memory_order_relaxed);
}

static int sha512_arm_state(void)
{
    int state = atomic_load_explicit(&sha512_arm_available,
                                     memory_order_relaxed);
    if (__builtin_expect(state < 0, 0)) {
        sha512_detect_arm();
        state = atomic_load_explicit(&sha512_arm_available,
                                     memory_order_relaxed);
    }
    return state;
}
#endif

static void sha512_transform(uint64_t *s, const unsigned char *chunk)
{
#if defined(__aarch64__)
    if (sha512_arm_state()) {
        sha512_transform_arm(s, chunk);
        return;
    }
#endif
    sha512_transform_portable(s, chunk);
}

bool sha512_selftest(void)
{
#if defined(__aarch64__)
    return sha512_arm_state() >= 0;
#else
    return true;
#endif
}

const char *sha512_implementation(void)
{
#if defined(__aarch64__)
    if (sha512_arm_state())
        return "ARMv8.2 SHA-512 (hardware)";
#endif
    return "portable C";
}

int sha512_select_impl(enum sha512_impl which)
{
#if defined(__aarch64__)
    if (which == SHA512_IMPL_PORTABLE) {
        atomic_store_explicit(&sha512_arm_available, 0, memory_order_relaxed);
        return SHA512_IMPL_PORTABLE;
    }
    atomic_store_explicit(&sha512_arm_available, -1, memory_order_relaxed);
    return sha512_arm_state() ? SHA512_IMPL_ARM : SHA512_IMPL_PORTABLE;
#else
    (void)which;
    return SHA512_IMPL_PORTABLE;
#endif
}

void sha512_init(struct sha512_ctx *ctx)
{
    ctx->s[0] = 0x6a09e667f3bcc908ull;
    ctx->s[1] = 0xbb67ae8584caa73bull;
    ctx->s[2] = 0x3c6ef372fe94f82bull;
    ctx->s[3] = 0xa54ff53a5f1d36f1ull;
    ctx->s[4] = 0x510e527fade682d1ull;
    ctx->s[5] = 0x9b05688c2b3e6c1full;
    ctx->s[6] = 0x1f83d9abfb41bd6bull;
    ctx->s[7] = 0x5be0cd19137e2179ull;
    ctx->bytes = 0;
}

void sha512_write(struct sha512_ctx *ctx, const unsigned char *data, size_t len)
{
    if (len == 0) return; /* no NULL + 0 pointer arithmetic; a zero-length write changes nothing */
    const unsigned char *end = data + len;
    size_t bufsize = ctx->bytes % 128;
    if (bufsize && bufsize + len >= 128) {
        memcpy(ctx->buf + bufsize, data, 128 - bufsize);
        ctx->bytes += 128 - bufsize;
        data += 128 - bufsize;
        sha512_transform(ctx->s, ctx->buf);
        bufsize = 0;
    }
    while (end >= data + 128) {
        sha512_transform(ctx->s, data);
        data += 128;
        ctx->bytes += 128;
    }
    if (end > data) {
        memcpy(ctx->buf + bufsize, data, end - data);
        ctx->bytes += end - data;
    }
}

void sha512_finalize(struct sha512_ctx *ctx, unsigned char hash[SHA512_OUTPUT_SIZE])
{
    static const unsigned char pad[128] = {0x80};
    unsigned char sizedesc[16] = {0x00};
    WriteBE64(sizedesc + 8, ctx->bytes << 3);
    sha512_write(ctx, pad, 1 + ((239 - (ctx->bytes % 128)) % 128));
    sha512_write(ctx, sizedesc, 16);
    WriteBE64(hash, ctx->s[0]);
    WriteBE64(hash + 8, ctx->s[1]);
    WriteBE64(hash + 16, ctx->s[2]);
    WriteBE64(hash + 24, ctx->s[3]);
    WriteBE64(hash + 32, ctx->s[4]);
    WriteBE64(hash + 40, ctx->s[5]);
    WriteBE64(hash + 48, ctx->s[6]);
    WriteBE64(hash + 56, ctx->s[7]);
}
