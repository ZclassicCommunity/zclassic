/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#include <stdint.h>
#include <assert.h>
#include <string.h>

/* The Bitcoin Core spelling of the fixed-width byte-order codec, kept
 * because twelve files (two of them under the byte-sealed core/) call it
 * under these names. The implementation is NOT here: it is the one codec
 * in platform/modules/base/include/base/serialize_le.h, which every module may reach
 * because platform/modules/base is rank 1 in engine/composition/lib_module_order.def and core/modules/crypto
 * is rank 9. Same bytes, one definition. */
#include "base/serialize_le.h"

#if defined(NDEBUG)
# error "Zclassic cannot be compiled without assertions."
#endif

static inline uint16_t ReadLE16(const unsigned char *ptr)
{
    return zcl_read_u16_le((const uint8_t *)ptr);
}

static inline uint32_t ReadLE32(const unsigned char *ptr)
{
    return zcl_read_u32_le((const uint8_t *)ptr);
}

static inline uint64_t ReadLE64(const unsigned char *ptr)
{
    return zcl_read_u64_le((const uint8_t *)ptr);
}

static inline void WriteLE16(unsigned char *ptr, uint16_t x)
{
    zcl_write_u16_le((uint8_t *)ptr, x);
}

static inline void WriteLE32(unsigned char *ptr, uint32_t x)
{
    zcl_write_u32_le((uint8_t *)ptr, x);
}

static inline void WriteLE64(unsigned char *ptr, uint64_t x)
{
    zcl_write_u64_le((uint8_t *)ptr, x);
}

static inline uint32_t ReadBE32(const unsigned char *ptr)
{
    return zcl_read_u32_be((const uint8_t *)ptr);
}

static inline uint64_t ReadBE64(const unsigned char *ptr)
{
    return zcl_read_u64_be((const uint8_t *)ptr);
}

static inline void WriteBE32(unsigned char *ptr, uint32_t x)
{
    zcl_write_u32_be((uint8_t *)ptr, x);
}

static inline void WriteBE64(unsigned char *ptr, uint64_t x)
{
    zcl_write_u64_be((uint8_t *)ptr, x);
}

#endif
