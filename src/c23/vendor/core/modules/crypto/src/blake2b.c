/* BLAKE2b implementation in pure C23.
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Based on RFC 7693 and the BLAKE2 reference implementation. */

#include "crypto/blake2b.h"
#include "util/log_macros.h"
#include <string.h>

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
    0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
    0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
};

static const uint8_t blake2b_sigma[12][16] = {
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

static inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static inline uint64_t load64(const void *src)
{
    uint64_t w;
    memcpy(&w, src, sizeof(w));
    return w;
}

static inline void store64(void *dst, uint64_t w)
{
    memcpy(dst, &w, sizeof(w));
}

#define G(r, i, a, b, c, d) do { \
    a = a + b + m[blake2b_sigma[r][2*i+0]]; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b + m[blake2b_sigma[r][2*i+1]]; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \
} while(0)

#define ROUND(r) do { \
    G(r, 0, v[0], v[4], v[ 8], v[12]); \
    G(r, 1, v[1], v[5], v[ 9], v[13]); \
    G(r, 2, v[2], v[6], v[10], v[14]); \
    G(r, 3, v[3], v[7], v[11], v[15]); \
    G(r, 4, v[0], v[5], v[10], v[15]); \
    G(r, 5, v[1], v[6], v[11], v[12]); \
    G(r, 6, v[2], v[7], v[ 8], v[13]); \
    G(r, 7, v[3], v[4], v[ 9], v[14]); \
} while(0)

static void blake2b_compress(struct blake2b_ctx *ctx, const uint8_t block[BLAKE2B_BLOCKBYTES])
{
    uint64_t m[16];
    uint64_t v[16];

    for (int i = 0; i < 16; i++)
        m[i] = load64(block + i * sizeof(uint64_t));

    for (int i = 0; i < 8; i++)
        v[i] = ctx->h[i];

    v[ 8] = blake2b_IV[0];
    v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ ctx->t[0];
    v[13] = blake2b_IV[5] ^ ctx->t[1];
    v[14] = blake2b_IV[6] ^ ctx->f[0];
    v[15] = blake2b_IV[7] ^ ctx->f[1];

    ROUND(0);  ROUND(1);  ROUND(2);  ROUND(3);
    ROUND(4);  ROUND(5);  ROUND(6);  ROUND(7);
    ROUND(8);  ROUND(9);  ROUND(10); ROUND(11);

    for (int i = 0; i < 8; i++)
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_increment_counter(struct blake2b_ctx *ctx, uint64_t inc)
{
    ctx->t[0] += inc;
    ctx->t[1] += (ctx->t[0] < inc) ? 1 : 0;
}

int blake2b_init_param(struct blake2b_ctx *ctx, const struct blake2b_param *p)
{
    memset(ctx, 0, sizeof(*ctx));
    const uint8_t *pb = (const uint8_t *)p;

    for (int i = 0; i < 8; i++)
        ctx->h[i] = blake2b_IV[i] ^ load64(pb + sizeof(uint64_t) * i);

    ctx->outlen = p->digest_length;
    return 0;
}

int blake2b_init(struct blake2b_ctx *ctx, size_t outlen)
{
    if (outlen == 0 || outlen > BLAKE2B_OUTBYTES)
        LOG_ERR("blake2b",
                "init: outlen=%zu out of range [1,%d]", outlen, BLAKE2B_OUTBYTES);

    struct blake2b_param p;
    memset(&p, 0, sizeof(p));
    p.digest_length = (uint8_t)outlen;
    p.fanout = 1;
    p.depth = 1;

    return blake2b_init_param(ctx, &p);
}

int blake2b_init_key(struct blake2b_ctx *ctx, size_t outlen,
                     const void *key, size_t keylen)
{
    if (outlen == 0 || outlen > BLAKE2B_OUTBYTES)
        LOG_ERR("blake2b",
                "init_key: outlen=%zu out of range [1,%d]", outlen, BLAKE2B_OUTBYTES);
    if (keylen == 0 || keylen > BLAKE2B_KEYBYTES)
        LOG_ERR("blake2b",
                "init_key: keylen=%zu out of range [1,%d]", keylen, BLAKE2B_KEYBYTES);

    struct blake2b_param p;
    memset(&p, 0, sizeof(p));
    p.digest_length = (uint8_t)outlen;
    p.key_length = (uint8_t)keylen;
    p.fanout = 1;
    p.depth = 1;

    if (blake2b_init_param(ctx, &p) < 0)
        LOG_ERR("blake2b", "init_key: blake2b_init_param failed");

    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset(block, 0, BLAKE2B_BLOCKBYTES);
    memcpy(block, key, keylen);
    blake2b_update(ctx, block, BLAKE2B_BLOCKBYTES);
    memset(block, 0, BLAKE2B_BLOCKBYTES);

    return 0;
}

int blake2b_init_salt_personal(struct blake2b_ctx *ctx, size_t outlen,
                               const void *key, size_t keylen,
                               const uint8_t salt[BLAKE2B_SALTBYTES],
                               const uint8_t personal[BLAKE2B_PERSONALBYTES])
{
    struct blake2b_param p;
    memset(&p, 0, sizeof(p));
    p.digest_length = (uint8_t)outlen;
    p.key_length = (uint8_t)keylen;
    p.fanout = 1;
    p.depth = 1;

    if (salt)
        memcpy(p.salt, salt, BLAKE2B_SALTBYTES);
    if (personal)
        memcpy(p.personal, personal, BLAKE2B_PERSONALBYTES);

    if (blake2b_init_param(ctx, &p) < 0)
        LOG_ERR("blake2b", "init_salt_personal: blake2b_init_param failed");

    if (key && keylen > 0) {
        uint8_t block[BLAKE2B_BLOCKBYTES];
        memset(block, 0, BLAKE2B_BLOCKBYTES);
        memcpy(block, key, keylen);
        blake2b_update(ctx, block, BLAKE2B_BLOCKBYTES);
        memset(block, 0, BLAKE2B_BLOCKBYTES);
    }

    return 0;
}

int blake2b_update(struct blake2b_ctx *ctx, const void *in, size_t inlen)
{
    const uint8_t *pin = (const uint8_t *)in;

    if (inlen == 0)
        return 0;

    size_t left = ctx->buflen;
    size_t fill = BLAKE2B_BLOCKBYTES - left;

    if (inlen > fill) {
        ctx->buflen = 0;
        memcpy(ctx->buf + left, pin, fill);
        blake2b_increment_counter(ctx, BLAKE2B_BLOCKBYTES);
        blake2b_compress(ctx, ctx->buf);
        pin += fill;
        inlen -= fill;

        while (inlen > BLAKE2B_BLOCKBYTES) {
            blake2b_increment_counter(ctx, BLAKE2B_BLOCKBYTES);
            blake2b_compress(ctx, pin);
            pin += BLAKE2B_BLOCKBYTES;
            inlen -= BLAKE2B_BLOCKBYTES;
        }
    }

    memcpy(ctx->buf + ctx->buflen, pin, inlen);
    ctx->buflen += inlen;
    return 0;
}

int blake2b_final(struct blake2b_ctx *ctx, void *out, size_t outlen)
{
    if (out == NULL || outlen < ctx->outlen)
        LOG_ERR("blake2b",
                "final: out=%p outlen=%zu ctx->outlen=%zu",
                out, outlen, (size_t)ctx->outlen);

    blake2b_increment_counter(ctx, ctx->buflen);
    ctx->f[0] = (uint64_t)-1;
    memset(ctx->buf + ctx->buflen, 0, BLAKE2B_BLOCKBYTES - ctx->buflen);
    blake2b_compress(ctx, ctx->buf);

    uint8_t buffer[BLAKE2B_OUTBYTES];
    for (int i = 0; i < 8; i++)
        store64(buffer + sizeof(uint64_t) * i, ctx->h[i]);

    memcpy(out, buffer, ctx->outlen);
    memset(buffer, 0, sizeof(buffer));
    return 0;
}

int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen)
{
    struct blake2b_ctx ctx;
    int ret;

    if (key && keylen > 0)
        ret = blake2b_init_key(&ctx, outlen, key, keylen);
    else
        ret = blake2b_init(&ctx, outlen);

    if (ret < 0) return ret;

    ret = blake2b_update(&ctx, in, inlen);
    if (ret < 0) return ret;

    return blake2b_final(&ctx, out, outlen);
}
