/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BLAKE2s hash — pure C23 implementation.
 * RFC 7693 compliant, 32-bit variant. */

#include "crypto/blake2s.h"
#include "util/log_macros.h"
#include "support/cleanse.h"
#include <string.h>

static const uint32_t blake2s_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

static uint32_t load32(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t rotr32(uint32_t w, unsigned c)
{
    return (w >> c) | (w << (32 - c));
}

#define G(r, i, a, b, c, d) do { \
    a += b + m[blake2s_sigma[r][2*i]]; \
    d = rotr32(d ^ a, 16); \
    c += d; \
    b = rotr32(b ^ c, 12); \
    a += b + m[blake2s_sigma[r][2*i+1]]; \
    d = rotr32(d ^ a, 8); \
    c += d; \
    b = rotr32(b ^ c, 7); \
} while(0)

static void blake2s_compress(struct blake2s_ctx *ctx, const uint8_t block[BLAKE2S_BLOCKBYTES])
{
    uint32_t m[16], v[16];

    for (int i = 0; i < 16; i++)
        m[i] = load32(block + i * 4);

    for (int i = 0; i < 8; i++) v[i] = ctx->h[i];
    v[8]  = blake2s_IV[0];
    v[9]  = blake2s_IV[1];
    v[10] = blake2s_IV[2];
    v[11] = blake2s_IV[3];
    v[12] = blake2s_IV[4] ^ ctx->t[0];
    v[13] = blake2s_IV[5] ^ ctx->t[1];
    v[14] = blake2s_IV[6] ^ ctx->f[0];
    v[15] = blake2s_IV[7] ^ ctx->f[1];

    for (int r = 0; r < 10; r++) {
        G(r, 0, v[0], v[4], v[8],  v[12]);
        G(r, 1, v[1], v[5], v[9],  v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[8],  v[13]);
        G(r, 7, v[3], v[4], v[9],  v[14]);
    }

    for (int i = 0; i < 8; i++)
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2s_increment_counter(struct blake2s_ctx *ctx, uint32_t inc)
{
    ctx->t[0] += inc;
    ctx->t[1] += (ctx->t[0] < inc) ? 1 : 0;
}

int blake2s_init(struct blake2s_ctx *ctx, size_t outlen)
{
    if (outlen == 0 || outlen > BLAKE2S_OUTBYTES)
        LOG_ERR("blake2s",
                "init: outlen=%zu out of range [1,%d]", outlen, BLAKE2S_OUTBYTES);

    memset(ctx, 0, sizeof(*ctx));
    for (int i = 0; i < 8; i++) ctx->h[i] = blake2s_IV[i];
    ctx->h[0] ^= 0x01010000 ^ (uint32_t)outlen;
    ctx->outlen = outlen;
    return 0;
}

int blake2s_init_personal(struct blake2s_ctx *ctx, size_t outlen,
                           const uint8_t personal[BLAKE2S_PERSONALBYTES])
{
    if (outlen == 0 || outlen > BLAKE2S_OUTBYTES)
        LOG_ERR("blake2s",
                "init_personal: outlen=%zu out of range [1,%d]",
                outlen, BLAKE2S_OUTBYTES);

    /* Build parameter block */
    uint8_t P[32];
    memset(P, 0, sizeof(P));
    P[0] = (uint8_t)outlen; /* digest length */
    P[2] = 1;               /* fanout */
    P[3] = 1;               /* depth */
    memcpy(P + 24, personal, BLAKE2S_PERSONALBYTES);

    memset(ctx, 0, sizeof(*ctx));
    for (int i = 0; i < 8; i++)
        ctx->h[i] = blake2s_IV[i] ^ load32(P + i * 4);
    ctx->outlen = outlen;
    return 0;
}

int blake2s_update(struct blake2s_ctx *ctx, const void *in, size_t inlen)
{
    const uint8_t *p = (const uint8_t *)in;

    while (inlen > 0) {
        size_t left = ctx->buflen;
        size_t fill = BLAKE2S_BLOCKBYTES - left;

        if (inlen > fill) {
            memcpy(ctx->buf + left, p, fill);
            blake2s_increment_counter(ctx, BLAKE2S_BLOCKBYTES);
            blake2s_compress(ctx, ctx->buf);
            ctx->buflen = 0;
            p += fill;
            inlen -= fill;
        } else {
            memcpy(ctx->buf + left, p, inlen);
            ctx->buflen += inlen;
            break;
        }
    }
    return 0;
}

int blake2s_final(struct blake2s_ctx *ctx, void *out, size_t outlen)
{
    if (outlen > ctx->outlen)
        LOG_ERR("blake2s",
                "final: requested outlen=%zu > ctx->outlen=%zu",
                outlen, (size_t)ctx->outlen);

    blake2s_increment_counter(ctx, (uint32_t)ctx->buflen);
    ctx->f[0] = 0xFFFFFFFF;

    memset(ctx->buf + ctx->buflen, 0, BLAKE2S_BLOCKBYTES - ctx->buflen);
    blake2s_compress(ctx, ctx->buf);

    uint8_t buffer[BLAKE2S_OUTBYTES];
    for (int i = 0; i < 8; i++) {
        buffer[i * 4 + 0] = (uint8_t)(ctx->h[i]);
        buffer[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 8);
        buffer[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 16);
        buffer[i * 4 + 3] = (uint8_t)(ctx->h[i] >> 24);
    }
    memcpy(out, buffer, outlen);
    /* blake2s output can be secret (e.g. Sapling crh_ivk → ivk); wipe the
     * local digest copy after it is delivered to the caller. */
    memory_cleanse(buffer, sizeof(buffer));
    return 0;
}

int blake2s(void *out, size_t outlen, const void *in, size_t inlen)
{
    struct blake2s_ctx ctx;
    if (blake2s_init(&ctx, outlen) != 0)
        LOG_ERR("blake2s", "one-shot: blake2s_init failed");
    blake2s_update(&ctx, in, inlen);
    return blake2s_final(&ctx, out, outlen);
}
