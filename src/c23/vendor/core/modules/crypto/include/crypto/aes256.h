/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * AES-256 block cipher — encrypt only (for FF1). */

#ifndef ZCL_CRYPTO_AES256_H
#define ZCL_CRYPTO_AES256_H

#include <stdint.h>

struct aes256_ctx {
    uint32_t rk[60]; /* round keys (14 rounds + 1) */
};

void aes256_init(struct aes256_ctx *ctx, const uint8_t key[32]);
void aes256_encrypt(const struct aes256_ctx *ctx,
                    const uint8_t in[16], uint8_t out[16]);

#endif
