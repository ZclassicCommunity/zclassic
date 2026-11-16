/* zclassicd-owned. See witness_codec.h. No allocation, no logging. */
#include "witness_codec.h"

#include <string.h>

/* BLS12-381 scalar field modulus q (Jubjub base field), little-endian limbs:
 * 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 */
static const uint64_t FR_Q[4] = {
    UINT64_C(0xffffffff00000001), UINT64_C(0x53bda402fffe5bfe),
    UINT64_C(0x3339d80809a1d805), UINT64_C(0x73eda753299d7d48),
};

/* Jubjub prime subgroup order r (the scalar field Fs), little-endian limbs:
 * 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7 */
static const uint64_t FS_R[4] = {
    UINT64_C(0xd0970e5ed6f72cb7), UINT64_C(0xa6682093ccc81082),
    UINT64_C(0x06673b0101343b00), UINT64_C(0x0e7db4ea6533afa9),
};

static uint64_t load_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* Borrow out of (s - m) over four limbs, computed without branches:
 * 1 exactly when s < m. Each step uses 128-bit arithmetic so the borrow is
 * the top bit of the widened difference. */
static int lt_modulus(const uint8_t s[32], const uint64_t m[4])
{
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 d = (unsigned __int128)load_le64(s + 8 * i) -
                              (unsigned __int128)m[i] - borrow;
        borrow = (d >> 64) & 1u;
    }
    return (int)borrow;
}

int zcl_c23_lt_fr_modulus(const uint8_t s[32])
{
    return lt_modulus(s, FR_Q);
}

int zcl_c23_lt_fs_modulus(const uint8_t s[32])
{
    return lt_modulus(s, FS_R);
}

enum zcl_c23_witness_status zcl_c23_witness_to_compact(
    const uint8_t serialized[ZCL_C23_WITNESS_SERIALIZED_LEN],
    uint8_t compact[ZCL_C23_WITNESS_COMPACT_LEN],
    uint64_t *position_out, size_t *bad_level)
{
    enum zcl_c23_witness_status st = ZCL_C23_WITNESS_OK;
    const uint8_t *w = serialized;

    /* rustzcash.rs:1471 assert_eq!(witness[0], SAPLING_TREE_DEPTH as u8) */
    if (w[0] != ZCL_C23_SAPLING_DEPTH) {
        st = ZCL_C23_WITNESS_PANIC_DEPTH;
        goto fail;
    }
    w += 1;
    compact[0] = (uint8_t)ZCL_C23_SAPLING_DEPTH;

    /* rustzcash.rs:1478 `for i in (0..SAPLING_TREE_DEPTH).rev()`: serialized
     * entry k (k = 0 first) is auth_path[31 - k]. */
    for (size_t k = 0; k < ZCL_C23_SAPLING_DEPTH; k++) {
        const size_t level = ZCL_C23_SAPLING_DEPTH - 1u - k;
        /* rustzcash.rs:1480 assert_eq!(witness[0], 32) */
        if (w[0] != 32u) {
            if (bad_level)
                *bad_level = k;
            st = ZCL_C23_WITNESS_PANIC_INNER_LEN;
            goto fail;
        }
        const uint8_t *sibling = w + 1;
        /* rustzcash.rs:1489-1492 Fr::from_repr(read_le(&sibling)) -> false */
        if (!zcl_c23_lt_fr_modulus(sibling)) {
            if (bad_level)
                *bad_level = k;
            st = ZCL_C23_WITNESS_NONCANONICAL_SIBLING;
            goto fail;
        }
        memcpy(compact + 1 + level * 33u, sibling, 32);
        w += 33;
    }

    /* rustzcash.rs:1501-1503 read_u64::<LittleEndian>(); the argument is a
     * fixed [u8; 1065] so exactly 8 bytes remain and the read and the
     * assert_eq!(witness.len(), 0) at :1528 cannot fail. */
    uint64_t position = load_le64(w);
    /* rustzcash.rs:1519-1523 level-i bit = position & 1, then position >>= 1 */
    for (size_t i = 0; i < ZCL_C23_SAPLING_DEPTH; i++)
        compact[1 + i * 33u + 32u] = (uint8_t)((position >> i) & 1u);
    if (position_out)
        *position_out = position;
    return ZCL_C23_WITNESS_OK;

fail:
    memset(compact, 0, ZCL_C23_WITNESS_COMPACT_LEN);
    if (position_out)
        *position_out = 0;
    return st;
}

int zcl_c23_witness_from_compact(
    const uint8_t compact[ZCL_C23_WITNESS_COMPACT_LEN], uint64_t position,
    uint8_t serialized[ZCL_C23_WITNESS_SERIALIZED_LEN])
{
    if (compact[0] != ZCL_C23_SAPLING_DEPTH)
        goto fail;
    serialized[0] = (uint8_t)ZCL_C23_SAPLING_DEPTH;
    for (size_t k = 0; k < ZCL_C23_SAPLING_DEPTH; k++) {
        const size_t level = ZCL_C23_SAPLING_DEPTH - 1u - k;
        const uint8_t bit = compact[1 + level * 33u + 32u];
        if (bit > 1u || bit != (uint8_t)((position >> level) & 1u))
            goto fail;
        serialized[1 + k * 33u] = 32u;
        memcpy(serialized + 2 + k * 33u, compact + 1 + level * 33u, 32);
    }
    for (int i = 0; i < 8; i++)
        serialized[1 + 33u * ZCL_C23_SAPLING_DEPTH + (size_t)i] =
            (uint8_t)(position >> (8 * i));
    return 1;

fail:
    memset(serialized, 0, ZCL_C23_WITNESS_SERIALIZED_LEN);
    return 0;
}
