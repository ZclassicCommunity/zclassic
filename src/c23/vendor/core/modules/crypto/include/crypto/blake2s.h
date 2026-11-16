/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BLAKE2s hash — 32-bit optimized variant of BLAKE2.
 * Used for Zcash group_hash (Jubjub generator derivation). */

#ifndef ZCL_CRYPTO_BLAKE2S_H
#define ZCL_CRYPTO_BLAKE2S_H

#include <stdint.h>
#include <stddef.h>

#define BLAKE2S_BLOCKBYTES 64
#define BLAKE2S_OUTBYTES 32
#define BLAKE2S_PERSONALBYTES 8

struct blake2s_ctx {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[BLAKE2S_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
};

int blake2s_init(struct blake2s_ctx *ctx, size_t outlen);
int blake2s_init_personal(struct blake2s_ctx *ctx, size_t outlen,
                           const uint8_t personal[BLAKE2S_PERSONALBYTES]);
int blake2s_update(struct blake2s_ctx *ctx, const void *in, size_t inlen);
int blake2s_final(struct blake2s_ctx *ctx, void *out, size_t outlen);

int blake2s(void *out, size_t outlen, const void *in, size_t inlen);

#endif
