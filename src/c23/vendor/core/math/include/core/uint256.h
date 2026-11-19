/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include <assert.h>
#include <stdint.h>
#include <string.h>

struct uint160 {
    alignas(4) uint8_t data[20];
};

struct uint256 {
    alignas(4) uint8_t data[32];
};

struct blob88 {
    alignas(4) uint8_t data[11];
};

static inline void uint160_set_null(struct uint160 *v) { memset(v->data, 0, 20); }
static inline void uint256_set_null(struct uint256 *v) { memset(v->data, 0, 32); }
static inline void blob88_set_null(struct blob88 *v) { memset(v->data, 0, 11); }

static inline int uint160_is_null(const struct uint160 *v)
{
    for (int i = 0; i < 20; i++)
        if (v->data[i] != 0) return 0;
    return 1;
}

static inline int uint256_is_null(const struct uint256 *v)
{
    for (int i = 0; i < 32; i++)
        if (v->data[i] != 0) return 0;
    return 1;
}

static inline int uint160_cmp(const struct uint160 *a, const struct uint160 *b)
{
    return memcmp(a->data, b->data, 20);
}

static inline int uint256_cmp(const struct uint256 *a, const struct uint256 *b)
{
    return memcmp(a->data, b->data, 32);
}

static inline int uint256_eq(const struct uint256 *a, const struct uint256 *b)
{
    return memcmp(a->data, b->data, 32) == 0;
}

static inline uint64_t uint256_get_cheap_hash(const struct uint256 *v)
{
    uint64_t result;
    memcpy(&result, v->data, 8);
    return result;
}

void uint256_get_hex(const struct uint256 *v, char out[65]);
void uint256_set_hex(struct uint256 *v, const char *psz);

#endif
