/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). Small Jubjub / BLS12-381 helpers for the KAT suite,
 * built from the vendored Z23 primitives. They are used to CRAFT test inputs
 * (re-signed signatures with chosen nonces, non-canonical encodings) and to
 * check randomized outputs (RedJubjub signatures) against Rust's verification
 * equation. Expected verdicts for crafted inputs come from the real Rust
 * library (vectors/mutations.rust.out), never from these helpers. */
#ifndef ZCL_C23_KAT_JUB_H
#define ZCL_C23_KAT_JUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum kat_gen { KAT_GEN_SPEND_AUTH, KAT_GEN_VALUE_RAND };

/* Jubjub base field modulus q (= BLS12-381 Fr) and scalar order r, LE. */
extern const uint8_t KAT_Q_LE[32];
extern const uint8_t KAT_R_LE[32];
/* BLS12-381 base field modulus p, big-endian (48 bytes). */
extern const uint8_t KAT_P_BE[48];

void kat_jub_init(void);

/* [s] G for the generator, canonical encoding. s is a 256-bit LE integer. */
void kat_gen_mul(enum kat_gen g, const uint8_t s[32], uint8_t out[32]);
/* a + b for two encodings; false if either does not decode. */
bool kat_point_add(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);

/* Scalars mod r (inputs must be < r). */
void kat_fs_add(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);
void kat_fs_mul(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);
bool kat_fs_canonical(const uint8_t a[32]);
/* r - a (a < r, a != 0) */
void kat_fs_negate(const uint8_t a[32], uint8_t out[32]);

/* c = H*(rbar || msg) = to_uniform(BLAKE2b-512("Zcash_RedJubjubH", rbar || msg)). */
void kat_hstar(const uint8_t rbar[32], const uint8_t *msg, size_t msg_len, uint8_t c[32]);

/* Rust's redjubjub::PublicKey::verify: vk and R decode, S < r,
 * [8](c vk + R - S G) == 0. msg is the 64-byte (vk_or_rk || sighash) message. */
bool kat_rj_verify(const uint8_t vk[32], const uint8_t msg[64], const uint8_t sig[64], enum kat_gen g);

/* Sign with a caller-chosen R encoding and nonce scalar n: S = n + c sk, where
 * c = H*(rbar || msg). The caller makes rbar encode [n]G + (torsion). */
void kat_rj_sign_with(const uint8_t sk[32], const uint8_t msg[64], const uint8_t rbar[32], const uint8_t n[32],
                      uint8_t sig[64]);

/* If the encoding's y (low 255 bits) plus q is still < 2^255, write the
 * non-canonical y+q encoding (same sign bit) and return true. */
bool kat_enc_y_plus_q(const uint8_t enc[32], uint8_t out[32]);

/* BLS12-381 compressed coordinate x (48 bytes BE, top 3 bits flags): write
 * x + p with the same flags if it fits in 381 bits. */
bool kat_bls_x_plus_p(const uint8_t in[48], uint8_t out[48]);

#endif
