/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BLS12-381 scalar field (Fr) arithmetic for Jubjub curve operations.
 * Fr = GF(p) where p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
 * Uses Montgomery representation with R = 2^256. */

#ifndef ZCL_SAPLING_FR_H
#define ZCL_SAPLING_FR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct fr {
    uint64_t d[4]; /* little-endian limbs, Montgomery form */
};

void fr_zero(struct fr *r);
void fr_one(struct fr *r);
bool fr_is_zero(const struct fr *a);
bool fr_eq(const struct fr *a, const struct fr *b);

void fr_add(struct fr *r, const struct fr *a, const struct fr *b);
void fr_sub(struct fr *r, const struct fr *a, const struct fr *b);
void fr_neg(struct fr *r, const struct fr *a);
void fr_mul(struct fr *r, const struct fr *a, const struct fr *b);
void fr_sq(struct fr *r, const struct fr *a);
void fr_inv(struct fr *r, const struct fr *a);

/* Square root mod r (Tonelli-Shanks; r - 1 = 2^32 * odd, so the shortcut
 * exponentiations do not apply). Returns false when `a` is not a quadratic
 * residue, leaving `*r` untouched. WHICH of the two roots comes back is
 * deterministic but arbitrary — it falls out of the Tonelli-Shanks walk, not
 * out of any sign convention. A caller that needs a specific root must pin it
 * itself; see circuit_pedersen.c's montgomery_scale for why the in-circuit
 * Pedersen hash is such a caller. */
bool fr_sqrt(struct fr *r, const struct fr *a);

/* Convert 32 bytes (little-endian) to Montgomery form */
bool fr_from_bytes(struct fr *r, const uint8_t s[32]);

/* Convert from Montgomery form to 32 bytes (little-endian) */
void fr_to_bytes(uint8_t s[32], const struct fr *a);

/* Jubjub extended twisted Edwards point: -x^2 + y^2 = 1 + d*x^2*y^2
 * Extended coordinates: x = X/Z, y = Y/Z, T = X*Y/Z */
struct jub_point {
    struct fr x, y, z, t;
};

void jub_identity(struct jub_point *p);
bool jub_is_identity(const struct jub_point *p);
void jub_neg(struct jub_point *r, const struct jub_point *p);
void jub_add(struct jub_point *r, const struct jub_point *a, const struct jub_point *b);
void jub_double(struct jub_point *r, const struct jub_point *a);
void jub_scalar_mul(struct jub_point *r, const struct jub_point *p, const uint8_t scalar[32]);
void jub_mul_by_cofactor(struct jub_point *r, const struct jub_point *p);

/* A point in affine form prepared for mixed addition: (y+x, y-x, 2d*x*y).
 * Adding one to an extended point takes 7 multiplications instead of 10. */
struct jub_niels {
    struct fr y_plus_x, y_minus_x, t2d;
};

/* Largest batch jub_to_niels_batch converts (it shares one inversion). */
#define JUB_NIELS_BATCH_MAX 32

/* out[i] = in[i] in prepared affine form, for n <= JUB_NIELS_BATCH_MAX points
 * on the curve; a larger n (or 0) converts nothing. */
void jub_to_niels_batch(struct jub_niels *out, const struct jub_point *in,
                        size_t n);

/* r = a + b, or a - b when negate is set (selected without a branch).
 * r may alias a. */
void jub_add_niels(struct jub_point *r, const struct jub_point *a,
                   const struct jub_niels *b, bool negate);

/* Compress point to 32 bytes (y-coordinate + sign bit in top bit) */
void jub_to_bytes(uint8_t out[32], const struct jub_point *p);

/* Decompress 32 bytes to point (returns false if not on curve) */
bool jub_from_bytes(struct jub_point *p, const uint8_t in[32]);

/* Get the x-coordinate as Fr element (for PedersenHash output) */
void jub_get_x(struct fr *r, const struct jub_point *p);

/* Get the y-coordinate as Fr element */
void jub_get_y(struct fr *r, const struct jub_point *p);

/* Jubjub scalar field Fs (group order of Jubjub curve).
 * s = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
 * Used for Pedersen hash scalar accumulation. */
struct fs {
    uint64_t d[4]; /* little-endian limbs, NOT Montgomery form */
};

void fs_zero(struct fs *r);
void fs_one(struct fs *r);
void fs_add(struct fs *r, const struct fs *a, const struct fs *b);
void fs_neg(struct fs *r, const struct fs *a);
bool fs_is_zero(const struct fs *a);
void fs_to_bytes(uint8_t s[32], const struct fs *a);
bool fs_from_bytes(struct fs *r, const uint8_t s[32]);
void fs_mul(struct fs *r, const struct fs *a, const struct fs *b);

/* Reduce 64-byte LE to uniform Fs element (for ZIP 32 key derivation) */
void fs_to_uniform(struct fs *r, const uint8_t digest[64]);

#endif
