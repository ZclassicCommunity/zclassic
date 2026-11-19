/* zclassicd-owned. See zip32_codec.h. No allocation, no logging. */
#include "zip32_codec.h"

#include "witness_codec.h"

#include "sapling/fr.h"
#include "support/cleanse.h"

#include <string.h>

/* r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7,
 * little-endian bytes: the scalar `E::Fs::char()` of edwards.rs:320. */
static const uint8_t JUBJUB_R_LE[32] = {
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0,
    0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06,
    0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e,
};

bool zcl_c23_point_prime_order_canonical(const uint8_t in[32], uint8_t out[32])
{
    struct jub_point p, t;
    if (!jub_from_bytes(&p, in))
        return false;
    jub_scalar_mul(&t, &p, JUBJUB_R_LE);
    if (!jub_is_identity(&t))
        return false;
    jub_to_bytes(out, &p);
    return true;
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void wr32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Offsets of the 169-byte layout. */
enum {
    OFF_DEPTH = 0,
    OFF_TAG = 1,
    OFF_INDEX = 5,
    OFF_CHAIN = 9,
    OFF_KEY = 41, /* 96 bytes: ask|nsk|ovk or ak|nk|ovk */
    OFF_DK = 137,
};
_Static_assert(OFF_DK + 32 == ZCL_C23_ZIP32_KEY_LEN, "169-byte ZIP-32 layout");

bool zcl_c23_xsk_parse(const uint8_t in[ZCL_C23_ZIP32_KEY_LEN],
                       struct zip32_xsk *out)
{
    memset(out, 0, sizeof(*out));
    /* zip32 lib.rs ExpandedSpendingKey::read: Fs::from_repr(ask), then nsk;
     * either >= r is InvalidData. */
    if (!zcl_c23_lt_fs_modulus(in + OFF_KEY) ||
        !zcl_c23_lt_fs_modulus(in + OFF_KEY + 32))
        return false;
    out->depth = in[OFF_DEPTH];
    out->parent_fvk_tag = rd32le(in + OFF_TAG);
    out->child_index = rd32le(in + OFF_INDEX);
    memcpy(out->chain_code, in + OFF_CHAIN, 32);
    memcpy(out->expsk.ask, in + OFF_KEY, 32);
    memcpy(out->expsk.nsk, in + OFF_KEY + 32, 32);
    memcpy(out->expsk.ovk, in + OFF_KEY + 64, 32);
    memcpy(out->dk, in + OFF_DK, 32);
    return true;
}

void zcl_c23_xsk_write(const struct zip32_xsk *xsk,
                       uint8_t out[ZCL_C23_ZIP32_KEY_LEN])
{
    out[OFF_DEPTH] = xsk->depth;
    wr32le(out + OFF_TAG, xsk->parent_fvk_tag);
    wr32le(out + OFF_INDEX, xsk->child_index);
    memcpy(out + OFF_CHAIN, xsk->chain_code, 32);
    memcpy(out + OFF_KEY, xsk->expsk.ask, 32);
    memcpy(out + OFF_KEY + 32, xsk->expsk.nsk, 32);
    memcpy(out + OFF_KEY + 64, xsk->expsk.ovk, 32);
    memcpy(out + OFF_DK, xsk->dk, 32);
}

bool zcl_c23_xfvk_parse(const uint8_t in[ZCL_C23_ZIP32_KEY_LEN],
                        struct zip32_xfvk *out)
{
    memset(out, 0, sizeof(*out));
    /* zip32 lib.rs FullViewingKey::read: Point::read(ak) + as_prime_order,
     * then the same for nk. */
    if (!zcl_c23_point_prime_order_canonical(in + OFF_KEY, out->fvk.ak) ||
        !zcl_c23_point_prime_order_canonical(in + OFF_KEY + 32, out->fvk.nk)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    out->depth = in[OFF_DEPTH];
    out->parent_fvk_tag = rd32le(in + OFF_TAG);
    out->child_index = rd32le(in + OFF_INDEX);
    memcpy(out->chain_code, in + OFF_CHAIN, 32);
    memcpy(out->fvk.ovk, in + OFF_KEY + 64, 32);
    memcpy(out->dk, in + OFF_DK, 32);
    return true;
}

void zcl_c23_xfvk_write(const struct zip32_xfvk *xfvk,
                        uint8_t out[ZCL_C23_ZIP32_KEY_LEN])
{
    out[OFF_DEPTH] = xfvk->depth;
    wr32le(out + OFF_TAG, xfvk->parent_fvk_tag);
    wr32le(out + OFF_INDEX, xfvk->child_index);
    memcpy(out + OFF_CHAIN, xfvk->chain_code, 32);
    memcpy(out + OFF_KEY, xfvk->fvk.ak, 32);
    memcpy(out + OFF_KEY + 32, xfvk->fvk.nk, 32);
    memcpy(out + OFF_KEY + 64, xfvk->fvk.ovk, 32);
    memcpy(out + OFF_DK, xfvk->dk, 32);
}
