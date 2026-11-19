/* zclassicd-owned. The 169-byte ZIP-32 ExtendedSpendingKey /
 * ExtendedFullViewingKey encodings of librustzcash (zip32 crate lib.rs at the
 * librustzcash pin), mapped onto the Z23 structs of sapling/zip32.h.
 *
 * Layout (zip32 lib.rs ExtendedSpendingKey::write / ExtendedFullViewingKey::
 * write, lib.rs:443-452 and :537-546 at the pin):
 *   depth u8 | parent_fvk_tag [4] | child_index u32 LE | chain_code [32] |
 *   (ask [32] | nsk [32] | ovk [32])   or   (ak [32] | nk [32] | ovk [32]) |
 *   dk [32]
 * The tag is the first four bytes of the parent FVK fingerprint, written raw.
 * Z23 keeps it as a little-endian u32 of those bytes (zip32.c fvk_tag), so the
 * codec reads and writes it as u32 LE, which reproduces the raw bytes.
 *
 * Parsing applies exactly the checks of the Rust readers; the shim turns a
 * parse failure into abort(), because every Rust call site does
 * `::read(..).expect(..)` (rustzcash.rs:1650, :1666, :1688). */
#ifndef ZCL_C23_ZIP32_CODEC_H
#define ZCL_C23_ZIP32_CODEC_H

#include <stdbool.h>
#include <stdint.h>

#include "sapling/zip32.h"

#define ZCL_C23_ZIP32_KEY_LEN 169u

/* ExtendedSpendingKey::read: ask and nsk must be canonical Fs encodings
 * (ExpandedSpendingKey::read, Fs::from_repr). ovk, dk, chain code are raw. */
bool zcl_c23_xsk_parse(const uint8_t in[ZCL_C23_ZIP32_KEY_LEN],
                       struct zip32_xsk *out);
void zcl_c23_xsk_write(const struct zip32_xsk *xsk,
                       uint8_t out[ZCL_C23_ZIP32_KEY_LEN]);

/* ExtendedFullViewingKey::read: ak and nk must decode as Jubjub points
 * (edwards::Point::read) and be of prime order (as_prime_order, which accepts
 * the identity). They are stored RE-ENCODED canonically, because every later
 * Rust use (FullViewingKey::to_bytes for the fingerprint and the PRF input,
 * ViewingKey::ivk) writes the decoded point, never the input bytes. */
bool zcl_c23_xfvk_parse(const uint8_t in[ZCL_C23_ZIP32_KEY_LEN],
                        struct zip32_xfvk *out);
void zcl_c23_xfvk_write(const struct zip32_xfvk *xfvk,
                        uint8_t out[ZCL_C23_ZIP32_KEY_LEN]);

/* Decode a Jubjub point exactly as edwards::Point::read, require prime order
 * ([r]P == identity, edwards.rs as_prime_order) and write its canonical
 * encoding. False when either check fails. Shared with the ABI shim. */
bool zcl_c23_point_prime_order_canonical(const uint8_t in[32], uint8_t out[32]);

#endif
