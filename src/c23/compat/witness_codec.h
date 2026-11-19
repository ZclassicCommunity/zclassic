/* zclassicd-owned. Conversion between zclassicd's serialized Sapling
 * MerklePath (the `witness` argument of librustzcash_sapling_spend_proof) and
 * the Z23 compact witness that sapling_spend_parse_witness() reads.
 *
 * zclassicd / librustzcash layout, 1065 bytes (IncrementalMerkleTree.hpp
 * MerklePath serialization; parsed by rustzcash.rs:1465-1528):
 *   0x20                                   CompactSize(32) of the path vector
 *   32 x { 0x20, sibling[32] }             CompactSize(32) + 32 bytes, ROOT
 *                                          LEVEL FIRST (Rust fills
 *                                          auth_path[i] for i in (0..32).rev())
 *   position                               u64 little-endian
 *
 * Z23 compact layout, 1057 bytes (sapling_prover_internal.h):
 *   32                                     depth
 *   32 x { sibling[32], bit }              LEAF LEVEL FIRST; bit = 1 when the
 *                                          running node is the right child
 *
 * So compact entry i = serialized sibling (31 - i), and its bit is
 * (position >> i) & 1 (rustzcash.rs:1519-1523; circuit_spend.c folds level d
 * with auth_path[d] and sets position bit d).
 *
 * Status codes keep Rust's distinction between a panic (assert_eq!, which
 * the caller must turn into abort()) and a plain `return false`. The checks
 * run in Rust's order and the FIRST failure is reported, so a non-canonical
 * sibling that precedes a bad length byte yields NONCANONICAL (Rust returns
 * false before it would reach the later assert). */
#ifndef ZCL_C23_WITNESS_CODEC_H
#define ZCL_C23_WITNESS_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_C23_SAPLING_DEPTH 32u
#define ZCL_C23_WITNESS_SERIALIZED_LEN (1u + 33u * ZCL_C23_SAPLING_DEPTH + 8u) /* 1065 */
#define ZCL_C23_WITNESS_COMPACT_LEN (1u + 33u * ZCL_C23_SAPLING_DEPTH)         /* 1057 */

enum zcl_c23_witness_status {
    ZCL_C23_WITNESS_OK = 0,
    /* witness[0] != 32: rustzcash.rs:1471 assert_eq! (panic -> abort) */
    ZCL_C23_WITNESS_PANIC_DEPTH = 1,
    /* an inner CompactSize != 32: rustzcash.rs:1480 assert_eq! (abort) */
    ZCL_C23_WITNESS_PANIC_INNER_LEN = 2,
    /* a sibling >= the BLS12-381 scalar modulus q: rustzcash.rs:1489-1492
     * Fr::from_repr -> return false */
    ZCL_C23_WITNESS_NONCANONICAL_SIBLING = 3,
};

/* Convert a 1065-byte serialized path to the 1057-byte compact form.
 * `position_out` receives the u64 position (all 64 bits; only the low 32
 * select tree directions). `bad_level` (may be NULL) receives the serialized
 * entry index 0..31 of the failing entry for the two per-entry errors.
 * On any status other than OK, `compact` is zeroed. */
enum zcl_c23_witness_status zcl_c23_witness_to_compact(
    const uint8_t serialized[ZCL_C23_WITNESS_SERIALIZED_LEN],
    uint8_t compact[ZCL_C23_WITNESS_COMPACT_LEN],
    uint64_t *position_out, size_t *bad_level);

/* Inverse, for tests and tooling: compact + position -> 1065-byte layout.
 * Returns false (output zeroed) if compact[0] != 32 or a direction byte is not
 * 0/1 or disagrees with the corresponding bit of `position`. */
int zcl_c23_witness_from_compact(
    const uint8_t compact[ZCL_C23_WITNESS_COMPACT_LEN], uint64_t position,
    uint8_t serialized[ZCL_C23_WITNESS_SERIALIZED_LEN]);

/* Constant-time "32-byte little-endian integer < modulus" helpers, shared by
 * the codecs and the ABI shim. Return 1 when canonical, 0 otherwise. The
 * running time does not depend on the value. */
int zcl_c23_lt_fr_modulus(const uint8_t s[32]); /* < q (BLS12-381 scalar) */
int zcl_c23_lt_fs_modulus(const uint8_t s[32]); /* < r (Jubjub subgroup order) */

#ifdef __cplusplus
}
#endif

#endif
