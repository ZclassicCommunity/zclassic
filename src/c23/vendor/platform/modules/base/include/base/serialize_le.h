/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The one fixed-width byte-order codec. Load and store a 16/32/64-bit
 * integer at a byte address, little-endian (and the two big-endian widths
 * the tree actually uses).
 *
 * Why this file exists
 * --------------------
 * A canonical little-endian set already existed at
 * core/modules/crypto/include/crypto/common.h (ReadLE16/32/64, WriteLE16/32/64) and
 * only seven files used it. Everyone else wrote the shift ladder again as a
 * file-private `static` helper — the same eight lines under a different
 * name in each file. The two clearest symptoms:
 *
 *   - contexts/wallet/modules/zid defines the family THREE times inside ONE module, under
 *     three prefixes: put_le64/get_le64 (zid.c), zdesc_put_le64/
 *     zdesc_get_le64 (zdesc.c), and zendp_put_le{16,32,64}/
 *     zendp_get_le{16,32,64} (zendp.c);
 *   - engine/composition/src/consensus_state_snapshot_candidate.c writes a persisted
 *     8-byte field with `le64_encode`, and
 *     engine/composition/src/consensus_state_snapshot_candidate_validate.c reads that
 *     SAME field back with `le64_decode` — the encoder and the decoder for
 *     one wire field, split across two files under two names, with nothing
 *     tying them together but the reader's memory.
 *
 * Why platform/modules/base and not core/modules/crypto
 * -------------------------------
 * Rank, per config/lib_module_order.def. platform/modules/base is rank 1 — the sink
 * every other module is allowed to reach down into. core/modules/crypto is rank 9,
 * so the seven modules BELOW it (primitives, support, json, encoding,
 * overlay, platform, core) cannot include crypto/common.h without
 * inverting the link order. Byte-order conversion is the wrong thing to
 * gate on a module's rank: it is arithmetic, not cryptography.
 *
 * crypto/common.h also `#error`s out any translation unit compiled with
 * NDEBUG. That is a deliberate policy for consensus hashing; it has no
 * business riding along with a two-instruction load.
 *
 * crypto/common.h now forwards its ReadLE and WriteLE families here, so
 * there is one implementation and its twelve existing includers — two of
 * them under the byte-sealed core/ — keep their spelling and their bytes.
 *
 * Byte order is a wire and disk contract
 * --------------------------------------
 * Every caller of this header is serializing something that goes on the
 * P2P wire, into a file, or into a database column. These functions are
 * therefore defined by the BYTES, not by the arithmetic: `_le` writes
 * least-significant byte first at p[0], `_be` writes most-significant byte
 * first at p[0], on every host, forever. The signed forms reinterpret the
 * two's-complement bit pattern of the same width and add no encoding of
 * their own. Nothing here may be "optimized" into something that observes
 * host byte order.
 *
 * Unaligned addresses are fine: every access goes through memcpy, which
 * has no alignment requirement and which every supported compiler folds
 * into a single load or store (plus a bswap on a big-endian host).
 *
 * Header-only on purpose, same reason as base/hex.h: a dozen standalone
 * tools link their own explicit source lists, and `static inline` keeps
 * every one of them buildable without touching a link line.
 *
 * Enforced by lint gate `check-byte-order-codec-single` — a new private
 * fixed-width byte-order helper outside platform/modules/base fails `make lint`.
 */

#ifndef ZCL_BASE_SERIALIZE_LE_H
#define ZCL_BASE_SERIALIZE_LE_H

#include <stdint.h>
#include <string.h>

/* Compile-time host byte order. If the compiler tells us nothing, assume
 * little-endian (x86-64 and aarch64, the only targets this tree builds
 * for). Wrong here would be caught immediately: the byte-identity test
 * checks written bytes against hand-written arrays, not against a
 * round-trip. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ZCL_HOST_BIG_ENDIAN 1
#else
#define ZCL_HOST_BIG_ENDIAN 0
#endif

static inline uint16_t zcl_bswap16(uint16_t x)
{
    return (uint16_t)((uint16_t)(x >> 8) | (uint16_t)(x << 8));
}

static inline uint32_t zcl_bswap32(uint32_t x)
{
    return ((x >> 24) & 0x000000FFu) |
           ((x >>  8) & 0x0000FF00u) |
           ((x <<  8) & 0x00FF0000u) |
           ((x << 24) & 0xFF000000u);
}

static inline uint64_t zcl_bswap64(uint64_t x)
{
    return ((x >> 56) & 0x00000000000000FFull) |
           ((x >> 40) & 0x000000000000FF00ull) |
           ((x >> 24) & 0x0000000000FF0000ull) |
           ((x >>  8) & 0x00000000FF000000ull) |
           ((x <<  8) & 0x000000FF00000000ull) |
           ((x << 24) & 0x0000FF0000000000ull) |
           ((x << 40) & 0x00FF000000000000ull) |
           ((x << 56) & 0xFF00000000000000ull);
}

/* ── Little-endian, unsigned ──────────────────────────────────────────── */

/* Store `v` least-significant byte first at p[0..1]. */
static inline void zcl_write_u16_le(uint8_t *p, uint16_t v)
{
    uint16_t w = ZCL_HOST_BIG_ENDIAN ? zcl_bswap16(v) : v;
    memcpy(p, &w, 2);
}

/* Store `v` least-significant byte first at p[0..3]. */
static inline void zcl_write_u32_le(uint8_t *p, uint32_t v)
{
    uint32_t w = ZCL_HOST_BIG_ENDIAN ? zcl_bswap32(v) : v;
    memcpy(p, &w, 4);
}

/* Store `v` least-significant byte first at p[0..7]. */
static inline void zcl_write_u64_le(uint8_t *p, uint64_t v)
{
    uint64_t w = ZCL_HOST_BIG_ENDIAN ? zcl_bswap64(v) : v;
    memcpy(p, &w, 8);
}

/* Load p[0..1] as a little-endian unsigned 16-bit value. */
static inline uint16_t zcl_read_u16_le(const uint8_t *p)
{
    uint16_t w;
    memcpy(&w, p, 2);
    return ZCL_HOST_BIG_ENDIAN ? zcl_bswap16(w) : w;
}

/* Load p[0..3] as a little-endian unsigned 32-bit value. */
static inline uint32_t zcl_read_u32_le(const uint8_t *p)
{
    uint32_t w;
    memcpy(&w, p, 4);
    return ZCL_HOST_BIG_ENDIAN ? zcl_bswap32(w) : w;
}

/* Load p[0..7] as a little-endian unsigned 64-bit value. */
static inline uint64_t zcl_read_u64_le(const uint8_t *p)
{
    uint64_t w;
    memcpy(&w, p, 8);
    return ZCL_HOST_BIG_ENDIAN ? zcl_bswap64(w) : w;
}

/* ── Little-endian, signed ────────────────────────────────────────────── */
/* The two's-complement bit pattern of the same width, nothing more. A
 * negative value is stored as the unsigned value it converts to, which is
 * what every hand-rolled `(uint64_t)v` cast in the tree already did. */

static inline void zcl_write_i32_le(uint8_t *p, int32_t v)
{
    zcl_write_u32_le(p, (uint32_t)v);
}

static inline void zcl_write_i64_le(uint8_t *p, int64_t v)
{
    zcl_write_u64_le(p, (uint64_t)v);
}

static inline int32_t zcl_read_i32_le(const uint8_t *p)
{
    return (int32_t)zcl_read_u32_le(p);
}

static inline int64_t zcl_read_i64_le(const uint8_t *p)
{
    return (int64_t)zcl_read_u64_le(p);
}

/* ── Big-endian ───────────────────────────────────────────────────────── */
/* Network byte order. Used by the PNG chunk framing, the BIP32 keystore
 * and the AES/SHA cores — formats defined big-endian by someone else. */

/* Store `v` most-significant byte first at p[0..3]. */
static inline void zcl_write_u32_be(uint8_t *p, uint32_t v)
{
    uint32_t w = ZCL_HOST_BIG_ENDIAN ? v : zcl_bswap32(v);
    memcpy(p, &w, 4);
}

/* Store `v` most-significant byte first at p[0..7]. */
static inline void zcl_write_u64_be(uint8_t *p, uint64_t v)
{
    uint64_t w = ZCL_HOST_BIG_ENDIAN ? v : zcl_bswap64(v);
    memcpy(p, &w, 8);
}

/* Load p[0..3] as a big-endian unsigned 32-bit value. */
static inline uint32_t zcl_read_u32_be(const uint8_t *p)
{
    uint32_t w;
    memcpy(&w, p, 4);
    return ZCL_HOST_BIG_ENDIAN ? w : zcl_bswap32(w);
}

/* Load p[0..7] as a big-endian unsigned 64-bit value. */
static inline uint64_t zcl_read_u64_be(const uint8_t *p)
{
    uint64_t w;
    memcpy(&w, p, 8);
    return ZCL_HOST_BIG_ENDIAN ? w : zcl_bswap64(w);
}

#endif /* ZCL_BASE_SERIALIZE_LE_H */
