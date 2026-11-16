/* BLAKE2b implementation in pure C23.
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Based on RFC 7693 and the BLAKE2 reference implementation. */

#ifndef BITCOIN_CRYPTO_BLAKE2B_H
#define BITCOIN_CRYPTO_BLAKE2B_H

#include <stdint.h>
#include <stdlib.h>

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES   64
#define BLAKE2B_KEYBYTES   64
#define BLAKE2B_SALTBYTES  16
#define BLAKE2B_PERSONALBYTES 16

struct blake2b_param {
    uint8_t digest_length;
    uint8_t key_length;
    uint8_t fanout;
    uint8_t depth;
    uint32_t leaf_length;
    uint64_t node_offset;
    uint8_t node_depth;
    uint8_t inner_length;
    uint8_t reserved[14];
    uint8_t salt[BLAKE2B_SALTBYTES];
    uint8_t personal[BLAKE2B_PERSONALBYTES];
};

struct blake2b_ctx {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLAKE2B_BLOCKBYTES];
    size_t buflen;
    uint8_t outlen;
};

/* BLAKE2b (RFC 7693), streaming. init* selects the digest length and any
 * key/salt/personalization, then update and final produce the digest. All
 * variants return 0 on success and a negative value on failure, but NOT all
 * validate their parameters: blake2b_init and blake2b_init_key reject
 * outlen out of [1,64] (and init_key rejects keylen > 64); blake2b_init_param
 * and blake2b_init_salt_personal do NOT range-check — they trust the caller to
 * pass a valid outlen <= BLAKE2B_OUTBYTES (64) and keylen <= 64. */
int blake2b_init(struct blake2b_ctx *ctx, size_t outlen);
int blake2b_init_key(struct blake2b_ctx *ctx, size_t outlen,
                     const void *key, size_t keylen);
int blake2b_init_param(struct blake2b_ctx *ctx, const struct blake2b_param *p);
/* Keyed/salted/personalized init. The 16-byte `personal` (and `salt`) feed
 * into the BLAKE2b parameter block, giving domain separation — this is how
 * Equihash binds its (N,K) into the hash (see equihash_initialise_state).
 * `key`/`salt`/`personal` may be NULL to use the zero default for that slot. */
int blake2b_init_salt_personal(struct blake2b_ctx *ctx, size_t outlen,
                               const void *key, size_t keylen,
                               const uint8_t salt[BLAKE2B_SALTBYTES],
                               const uint8_t personal[BLAKE2B_PERSONALBYTES]);
int blake2b_update(struct blake2b_ctx *ctx, const void *in, size_t inlen);
int blake2b_final(struct blake2b_ctx *ctx, void *out, size_t outlen);

/* One-shot keyed/unkeyed BLAKE2b: digest `in[0..inlen)` to `out[0..outlen)`
 * (equivalent to init_key + update + final). Pass key=NULL,keylen=0 for the
 * unkeyed hash. Returns 0 on success, nonzero on invalid outlen/keylen. */
int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen);

/* Vectorized BLAKE2b for Equihash batch hashing.
 * x86-64: AVX-512 (8-way) -> AVX2 (4-way) -> scalar.
 * arm64:  NEON (4-way) -> scalar; the 8-way tier has no NEON counterpart. */
void equihash_generate_hash_batch4(
    const struct blake2b_ctx *base_state,
    const uint32_t indices[4],
    unsigned char *hash0, unsigned char *hash1,
    unsigned char *hash2, unsigned char *hash3,
    size_t hash_len);
void equihash_generate_hash_batch8(
    const struct blake2b_ctx *base_state,
    const uint32_t indices[8],
    unsigned char *hashes[8],
    size_t hash_len);

/* Force the batch compression tier. AVX2/AVX512 are REQUESTS: each falls back
 * to the next tier the host actually supports, so the returned value is the
 * tier actually installed — never a claim about a path that cannot run here.
 * SCALAR always succeeds. AUTO restores CPUID-driven selection.
 *
 * Every tier produces byte-identical digests by construction; this only ever
 * changes speed. It exists so a differential oracle can drive the SAME input
 * through all three tiers, and so `zclassic23-simd-bench` can time them
 * separately — without it there is no way to prove the 8-way AVX-512 Equihash
 * path is faster (or even correct) than the scalar one it replaces.
 * Not thread-safe against concurrent batch hashing. */
enum blake2b_batch_impl {
    BLAKE2B_BATCH_IMPL_AUTO   = -1,
    BLAKE2B_BATCH_IMPL_SCALAR = 0,
    /* Tier values 1 and 2 name THIS HOST's 4-way and 8-way SIMD tiers, not an
     * instruction set: 1 is AVX2 on x86-64 and NEON on arm64 (both 4-way), and
     * 2 exists only on x86-64 (AVX-512F, 8-way) — no 8-way NEON tier, so a
     * request for 2 on arm64 narrows to 1. The names are kept for the x86
     * callers that already ship against them; the string returned by
     * equihash_blake2b_batch_implementation() is always the honest one. */
    BLAKE2B_BATCH_IMPL_AVX2   = 1,
    BLAKE2B_BATCH_IMPL_AVX512 = 2
};
int equihash_blake2b_batch_select_impl(enum blake2b_batch_impl which);

/* Name of the tier currently installed ("AVX-512 (8-way)", "AVX2 (4-way)",
 * "NEON (4-way)", or "scalar"). */
const char *equihash_blake2b_batch_implementation(void);

#endif
