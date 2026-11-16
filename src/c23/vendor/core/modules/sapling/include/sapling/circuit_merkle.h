/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ported from librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Reimplemented in
 * C23; no reference code is linked into the production binary.
 *
 * Section 21 of bellman's Spend::synthesize: the 32-level Sapling Merkle
 * authentication path, in circuit. The C23 port of the `for (i, e) in
 * self.auth_path.into_iter().enumerate()` loop of sapling-crypto
 * `circuit::sapling::Spend::synthesize` (librustzcash
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5).
 *
 * WHAT THE SECTION IS
 * -------------------
 * The spend circuit proves the note it is spending is IN the commitment tree
 * without revealing which leaf. It starts from the note commitment's
 * x-coordinate and folds one level at a time: at each depth the prover
 * witnesses the sibling subtree hash and a bit saying whether the running value
 * sits on the right, the pair is conditionally swapped into (left, right)
 * order, both halves are decomposed into 255 bits and Pedersen-hashed under
 * `Personalization::MerkleTree(depth)`. The x-coordinate of the result is the
 * next level's running value (an injective encoding, so taking only x loses
 * nothing), and after 32 levels it is the anchor.
 *
 * WHY IT IS THE BIGGEST SECTION
 * -----------------------------
 * One level costs 1382 constraints and the tree is 32 deep, so section 21 is
 * 44224 constraints — 45% of the whole 98777-constraint spend circuit, and 65%
 * of everything that was unported when this landed. The per-level breakdown is
 * exact and is asserted, not assumed:
 *
 *      1   position bit          AllocatedBit::alloc  (booleanity)
 *      2   conditional swap      AllocatedNum::conditionally_reverse
 *    512   two decompositions    2 * (255 booleanity + 1 unpacking)
 *    867   Pedersen hash         516 preimage bits over 3 segments
 *   ----
 *   1382
 *
 * The position bits are RETURNED because section 24 needs them again: the
 * nullifier binds g^position, so the same 32 wires that steered the swap also
 * drive that fixed-base multiplication. Re-deriving them there would be a
 * second, unconstrained copy of the note's position. */

#ifndef ZCL_SAPLING_CIRCUIT_MERKLE_H
#define ZCL_SAPLING_CIRCUIT_MERKLE_H

#include "sapling/groth16_prover.h"
#include "sapling/sapling_circuit.h"    /* SAPLING_MERKLE_DEPTH */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bits a non-strict BLS12-381 Fr decomposition emits — `Fr::NUM_BITS`. */
#define MERKLE_FIELD_BITS 255

/* Exact per-level and whole-section constraint costs. Named here so the gate
 * asserts a documented number rather than whatever the code happens to emit. */
#define MERKLE_LEVEL_CONSTRAINTS   1382
#define MERKLE_PATH_CONSTRAINTS    (MERKLE_LEVEL_CONSTRAINTS * SAPLING_MERKLE_DEPTH)

/* bellman `AllocatedNum::into_bits_le` — 255 boolean aux wires (index 0 = LSB)
 * plus ONE unpacking constraint binding sum(2^i * bit_i) to `var`. 256
 * constraints.
 *
 * NOT the strict form (gadget_into_bits_le_strict, 388 constraints): a
 * congruency at or above r is accepted here, exactly as the reference does at
 * this call site. bellman's comment is the justification — the hash is
 * collision-resistant, so a prover who witnesses a congruency still cannot find
 * an authentication path. Using the strict form instead would be sound but
 * would put the section 132 constraints per level over the reference and the
 * circuit would no longer match the proving key. */
void gadget_into_bits_le(struct constraint_system *cs, size_t var,
                         size_t bits_out[MERKLE_FIELD_BITS]);

/* bellman `AllocatedNum::conditionally_reverse`. Writes the pair (a, b) in
 * their original order when `cond` is 0 and swapped when it is 1:
 *     lo = cond ? b : a        hi = cond ? a : b
 * as the two constraints (a - b) * cond = a - lo and (b - a) * cond = b - hi.
 * `cond` must already be boolean-constrained. 2 constraints. */
void gadget_conditionally_reverse(struct constraint_system *cs,
                                  size_t a, size_t b, size_t cond,
                                  size_t *lo, size_t *hi);

/* One Merkle level. `cur` is the running subtree value's wire, `sibling` the
 * 32-byte little-endian authentication-path element at this depth and
 * `cur_is_right` the position bit's value. Writes the next level's running wire
 * and the allocated position-bit wire.
 *
 * 1382 constraints. Returns false (logged) on a depth out of range or a
 * Pedersen hash that refused the request; on false the out-params are SIZE_MAX,
 * never a plausible-looking wire. */
bool gadget_merkle_level(struct constraint_system *cs, size_t depth,
                         size_t cur, const uint8_t sibling[32],
                         bool cur_is_right,
                         size_t *next_out, size_t *position_bit_out);

/* Section 21 whole: fold SAPLING_MERKLE_DEPTH levels from the note
 * commitment's x-coordinate up to the anchor. `root_out` receives the anchor's
 * wire (which sections 22/23 bind to public input 5) and
 * `position_bits_out` the 32 position-bit wires, least significant (deepest)
 * first — the order section 24 consumes them in.
 *
 * MERKLE_PATH_CONSTRAINTS constraints. Returns false (logged) if any level
 * fails; `root_out` is SIZE_MAX in that case. */
bool gadget_merkle_auth_path(struct constraint_system *cs, size_t leaf_x,
                             const uint8_t auth_path[SAPLING_MERKLE_DEPTH][32],
                             const bool path_bits[SAPLING_MERKLE_DEPTH],
                             size_t *root_out,
                             size_t position_bits_out[SAPLING_MERKLE_DEPTH]);

#endif
