/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ported from librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Reimplemented in
 * C23; no reference code is linked into the production binary.
 *
 * R1CS circuit gadgets for Sapling spend and output circuits.
 * Boolean constraints, field arithmetic, Pedersen hash, Blake2s,
 * Jubjub curve operations, and Merkle tree authentication paths. */

#ifndef ZCL_SAPLING_CIRCUIT_GADGETS_H
#define ZCL_SAPLING_CIRCUIT_GADGETS_H

#include "sapling/groth16_prover.h"
#include <stdint.h>
#include <stdbool.h>

/* ── Boolean Gadgets ────────────────────────────────────────────── */

/* Constrain variable to be boolean: var * (1 - var) = 0 */
void gadget_boolean(struct constraint_system *cs, size_t var);

/* Allocate a boolean variable with value and constrain it */
size_t gadget_alloc_boolean(struct constraint_system *cs, bool value);

/* Allocate n boolean variables from a scalar (LSB first) */
void gadget_unpack_bits(struct constraint_system *cs,
                        size_t *bits_out, size_t n_bits,
                        const struct fr *value);

/* Pack boolean variables back into a field element: result = sum(bits[i] * 2^i) */
size_t gadget_pack_bits(struct constraint_system *cs,
                        const size_t *bits, size_t n_bits);

/* ── Strict bit decomposition / point representation ────────────── */

/* Number of bits a strict decomposition of a BLS12-381 Fr element emits:
 * one per bit position of (r - 1) at or below its most significant set bit. */
#define FR_STRICT_BITS 255

/* bellman AllocatedNum::into_bits_le_strict. Decomposes the value on wire
 * `var` into FR_STRICT_BITS boolean wires, LITTLE-endian (index 0 = LSB), and
 * constrains the decomposition to be the in-field representation — a
 * congruency >= r is rejected. 388 constraints / 387 aux per call; the count
 * is emergent from the bit pattern of r-1, not a tunable. */
void gadget_into_bits_le_strict(struct constraint_system *cs, size_t var,
                                size_t bits_out[FR_STRICT_BITS]);

/* bellman ecc::EdwardsPoint::repr. Unpacks x then y (order is load-bearing)
 * and writes 256 bits: y's 255 little-endian bits followed by x's sign bit
 * x[0]. 776 constraints. */
void gadget_point_repr(struct constraint_system *cs,
                       size_t x_var, size_t y_var, size_t bits_out[256]);

/* ── Field Arithmetic Gadgets ───────────────────────────────────── */

/* Constrain a * b = c (multiplication gate) */
void gadget_mul(struct constraint_system *cs, size_t a, size_t b, size_t c);

/* Allocate result = a * b and constrain */
size_t gadget_alloc_mul(struct constraint_system *cs, size_t a, size_t b);

/* Conditional select: result = condition ? a : b
 * Constraint: result = b + condition * (a - b) */
size_t gadget_select(struct constraint_system *cs,
                     size_t condition, size_t a, size_t b);

/* bellman's Möbius/subset-sum window interpolation: given constants[0..2^w-1],
 * produce assignment[0..2^w-1] with
 *   constants[index] == sum of assignment[j] over every j whose set bits are a
 *                       subset of index's.
 * Both window lookups in the circuit share this one body — the fixed-base mul's
 * 3-bit windows here, and the Pedersen hash's 2-bit windows in
 * circuit_pedersen.c. Both arrays must hold 2^window_size elements. */
void gadget_synth_coeffs(size_t window_size, const struct fr *constants,
                         struct fr *assignment);

/* ── Jubjub Montgomery-form constants ───────────────────────────── */

/* The two constants that turn a Jubjub twisted-Edwards point into the
 * Montgomery form the Pedersen hash gadget accumulates in:
 *   A     == 40962         == 2(a+d)/(a-d)
 *   scale == sqrt(-40964)  == sqrt(4/(a-d))
 * `scale` is DERIVED with fr_sqrt in circuit_pedersen.c, not read from a byte
 * blob — a blob that did not square to -40964 once shipped here undetected,
 * because only scale^2 reaches the Montgomery addition and a single-window hash
 * therefore still round-trips while every multi-window one is wrong.
 *
 * Exposed anyway, because deriving it is not sufficient. Both constants are
 * literal COEFFICIENTS inside the emitted constraints, and -scale is an equally
 * valid square root that computes the identical hash (the negation cancels
 * through the Montgomery addition and the conversion back to Edwards) over a
 * DIFFERENT coefficient matrix — same witness, same constraint count, different
 * QAP, so a proof would not verify against the Sapling trusted setup. Only a
 * test that pins the specific root against librustzcash's published value can
 * see that; tests/harness/src/groth16_merkle_path.c is that test. Either out-param
 * may be NULL. */
void gadget_jubjub_montgomery_params(struct fr *a_out, struct fr *scale_out);

/* ── Pedersen Hash Gadget (in-circuit) ──────────────────────────────
 * Implemented in circuit_pedersen.c together with the Montgomery-form
 * arithmetic it is the only consumer of. */

/* Width of the personalization prefix bellman prepends to every windowed
 * Pedersen hash input. bellman's `Personalization` is exactly a 6-bit
 * little-endian value: MerkleTree(depth) encodes the depth (0..62) and
 * NoteCommitment is the reserved all-ones value 63, which is why the MerkleTree
 * accessor below asserts depth < 63. */
#define PEDERSEN_PERSONALIZATION_BITS 6u

/* bellman `Personalization::get_bits` — the six CONSTANT bits that prefix every
 * Pedersen preimage. NoteCommitment is six 1 bits; MerkleTree(depth) is the six
 * little-endian bits of depth. They are the ONLY difference between the note
 * commitment hash and the 32 Merkle-level hashes, which is why the hash below
 * takes them as a parameter instead of existing twice.
 * The MerkleTree form returns false (logged) for depth >= 63. */
void gadget_pedersen_personalization_note_commitment(bool bits_out[6]);
bool gadget_pedersen_personalization_merkle_tree(size_t depth,
                                                 bool bits_out[6]);

/* sapling-crypto `circuit::pedersen_hash::pedersen_hash`. Hashes the 6
 * personalization bits followed by `n_bits` boolean-constrained input wires
 * (which the caller must already have constrained) and returns the resulting
 * Jubjub point as two wires.
 *
 * Constraint cost is a pure function of the bit count — 3-bit windows, 63
 * windows per segment generator, 2 constraints per window (1 when the window's
 * bits are all constant), 3 per within-segment Montgomery addition, 2 per
 * segment Edwards conversion and 6 per cross-segment Edwards addition. For the
 * Merkle path's 510-bit preimage that is exactly 867 constraints; for the
 * 576-bit note contents, 982.
 *
 * On a malformed request it logs and writes SIZE_MAX to both outputs rather
 * than a plausible-looking point — callers MUST check. */
void gadget_pedersen_hash_pers(struct constraint_system *cs,
                               const bool pers_bits[6],
                               const size_t *input_bits, size_t n_bits,
                               size_t *x_out, size_t *y_out);

/* Legacy entry point of the above, used by the non-parity circuits in
 * sapling_circuit.c. Recognizes only the string "Zcash_PH" and maps it to that
 * path's historical 6-bit prefix, which is NOT bellman's NoteCommitment
 * personalization. New code calls gadget_pedersen_hash_pers with an explicit
 * personalization from one of the two accessors above. */
void gadget_pedersen_hash(struct constraint_system *cs,
                          const size_t *input_bits, size_t n_bits,
                          const char *personalization,
                          size_t *x_out, size_t *y_out);

/* ── Jubjub Curve Gadgets ───────────────────────────────────────── */

/* Edwards curve point addition in-circuit.
 * Twisted Edwards: -x^2 + y^2 = 1 + d*x^2*y^2
 * Takes (x1,y1) and (x2,y2) variable indices, outputs (x3,y3). */
void gadget_edwards_add(struct constraint_system *cs,
                        size_t x1, size_t y1,
                        size_t x2, size_t y2,
                        size_t *x3, size_t *y3);

/* Fixed-base scalar multiplication with Jubjub generator.
 * scalar_bits: boolean variable indices for the scalar (LSB first).
 * base: the fixed base point (x, y) as constants.
 * Output: (x, y) coordinates of scalar * base. */
void gadget_fixed_base_mul(struct constraint_system *cs,
                           const size_t *scalar_bits, size_t n_bits,
                           const struct fr *base_x, const struct fr *base_y,
                           size_t *x_out, size_t *y_out);

/* ── Edwards Double ────────────────────────────────────────────── */
void gadget_edwards_double(struct constraint_system *cs,
                            size_t x1, size_t y1,
                            size_t *x3, size_t *y3);

/* ── Point On-Curve Check ──────────────────────────────────────── */
void gadget_point_interpret(struct constraint_system *cs, size_t x, size_t y);

/* ── Assert Not Small Order ────────────────────────────────────── */
void gadget_assert_not_small_order(struct constraint_system *cs,
                                     size_t x, size_t y);

/* ── Conditionally Select Point ────────────────────────────────── */

/* bellman ecc::EdwardsPoint::conditionally_select — result = cond ? p : O,
 * where O is the Edwards neutral element (0, 1). Two constraints:
 *       x * cond = x'          (cond=0 forces x' = 0)
 *   (y - 1) * cond = y' - 1    (cond=0 forces y' = 1)
 *
 * The condition enters only as a LINEAR COMBINATION, which is why this is the
 * form the whole gadget layer shares: a bare boolean wire, a bellman
 * `Boolean::Not` view and a folded constant all produce a different `cond_lc`
 * over the same two constraints. `cond_value` is the condition's logical value,
 * used to fill the witness. Callers should prefer one of the two wrappers
 * below or `gadget_conditionally_select_point_cbit` (circuit_bits.h). */
void gadget_conditionally_select_point_lc(struct constraint_system *cs,
                                          const struct linear_combination *cond_lc,
                                          bool cond_value,
                                          size_t px, size_t py,
                                          size_t *rx, size_t *ry);

/* The bare-wire condition. `cond` must already be boolean-constrained. */
void gadget_conditionally_select_point(struct constraint_system *cs,
                                         size_t cond, size_t px, size_t py,
                                         size_t *rx, size_t *ry);

/* ── Variable-Base Scalar Multiplication ───────────────────────── */

/* bellman ecc::EdwardsPoint::mul over `n_bits` bare boolean wires (LSB first).
 * Thin wrapper over gadget_variable_base_mul_cbits (circuit_bits.h) — there is
 * exactly ONE double-and-add body in the tree. 13*n_bits - 11 constraints. */
void gadget_variable_base_mul(struct constraint_system *cs,
                                size_t base_x, size_t base_y,
                                const size_t *scalar_bits, size_t n_bits,
                                size_t *out_x, size_t *out_y);

/* ── Point Inputize ────────────────────────────────────────────── */
void gadget_point_inputize(struct constraint_system *cs, size_t x, size_t y);

/* ── Scalar Inputize ───────────────────────────────────────────── */
void gadget_scalar_inputize(struct constraint_system *cs, size_t var);

#endif
