/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Ported verbatim from github.com/RhettCreighton/zclassic-c
 * (lib/core/include/core/uint256.h). The plain-C `struct uint256`
 * used by the ZSLP protocol library. Renamed include guard to
 * ZSLP_UINT256_C_H so it never collides with the daemon's C++
 * `class uint256` (src/uint256.h, guard BITCOIN_UINT256_H). */

#ifndef ZSLP_UINT256_C_H
#define ZSLP_UINT256_C_H

#include <assert.h>
#include <stdint.h>
#include <string.h>

/* The reference compiles as C23, where `alignas` is a keyword. In the
 * daemon's C build the C standard may be older (gnu11/gnu17), where
 * `alignas` is the macro from <stdalign.h>. C++ has `alignas` as a
 * keyword since C++11, so only the C path needs the header. */
#if !defined(__cplusplus) && (__STDC_VERSION__ < 202000L)
#include <stdalign.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif /* ZSLP_UINT256_C_H */
