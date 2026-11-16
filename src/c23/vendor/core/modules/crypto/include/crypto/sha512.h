/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CRYPTO_SHA512_H
#define BITCOIN_CRYPTO_SHA512_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define SHA512_OUTPUT_SIZE 64
#define SHA512_BLOCK_SIZE 128

struct sha512_ctx {
    uint64_t s[8];
    unsigned char buf[SHA512_BLOCK_SIZE];
    size_t bytes;
};

void sha512_init(struct sha512_ctx *ctx);
void sha512_write(struct sha512_ctx *ctx, const unsigned char *data, size_t len);
void sha512_finalize(struct sha512_ctx *ctx, unsigned char hash[SHA512_OUTPUT_SIZE]);

/* Runtime-selected SHA-512 compression. On arm64, AUTO uses FEAT_SHA512 only
 * after the OS advertises it and a compression KAT matches the portable C
 * reference. Other hosts retain portable C. The force hook exists for the
 * differential oracle and benchmark; production code should leave AUTO set.
 * A hardware request narrows to portable when unavailable or unverified. */
enum sha512_impl {
    SHA512_IMPL_AUTO = -1,
    SHA512_IMPL_PORTABLE = 0,
    SHA512_IMPL_ARM = 1
};
int sha512_select_impl(enum sha512_impl which);
const char *sha512_implementation(void);
bool sha512_selftest(void);

#endif
