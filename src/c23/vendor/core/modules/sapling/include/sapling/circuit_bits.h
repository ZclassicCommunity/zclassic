/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * In-circuit bit algebra for the Sapling circuits: a faithful C23 port of
 * bellman/sapling-crypto's `circuit::boolean::Boolean`,
 * `circuit::uint32::UInt32` and `circuit::multieq::MultiEq`
 * (librustzcash commit 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5).
 *
 * WHY THIS LAYER EXISTS
 * --------------------
 * `circuit_gadgets.h` represents every circuit wire as a bare `size_t`
 * variable index. That is enough for bit decompositions and curve arithmetic,
 * but it cannot express the two things bellman's blake2s depends on for its
 * constraint count:
 *
 *   1. a CONSTANT bit, which is not a variable at all, so folding it into an
 *      XOR or an addition costs ZERO constraints; and
 *   2. a NEGATED VIEW of an allocated bit, so `not` also costs zero.
 *
 * blake2s starts from an all-constant state vector and an all-constant IV, so
 * the first mixing round is largely constant-folded; getting the reference's
 * 21006 constraints for a 512-bit input is only possible with both. This is the
 * abstraction the spend-circuit port note calls the "architectural fork" — it
 * is a structure requirement, not an optimization.
 *
 * A `struct cbit` is bellman's `Boolean`: `Constant(bool) | Is(var) | Not(var)`.
 * A `struct cu32` is bellman's `UInt32`: 32 `cbit`s, LEAST significant first.
 * A `struct multieq` is bellman's `MultiEq`: it batches many small linear
 * equalities into one R1CS constraint by packing them at disjoint bit offsets
 * of the scalar field, flushing whenever the next equality would not fit.
 *
 * Every operation below documents its exact constraint cost, because the port's
 * acceptance bar is a constraint-for-constraint match against the reference
 * trace, not behavioural equivalence.
 */

#ifndef ZCL_SAPLING_CIRCUIT_BITS_H
#define ZCL_SAPLING_CIRCUIT_BITS_H

#include "sapling/groth16_prover.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ── Boolean (bellman circuit::boolean::Boolean) ─────────────────── */

enum cbit_kind {
    CBIT_CONSTANT = 0,  /* not a variable; folds for free */
    CBIT_IS       = 1,  /* the wire itself */
    CBIT_NOT      = 2,  /* the complement of the wire; free to take */
};

struct cbit {
    uint8_t kind;      /* enum cbit_kind */
    bool wire_value;   /* value ON the wire (CBIT_IS / CBIT_NOT only) */
    bool constant;     /* the bit's value (CBIT_CONSTANT only) */
    size_t var;        /* wire index (CBIT_IS / CBIT_NOT only) */
};

/* A known constant bit. 0 constraints, 0 variables. */
struct cbit cbit_constant(bool value);

/* Allocate a fresh boolean-constrained wire (bellman AllocatedBit::alloc:
 * `(1 - a) * a = 0`). 1 constraint, 1 aux variable. */
struct cbit cbit_alloc(struct constraint_system *cs, bool value);

/* Wrap a wire that some earlier gadget has ALREADY boolean-constrained (e.g.
 * the output of gadget_point_repr) as a `Boolean::Is`. 0 constraints — it adds
 * no booleanity constraint of its own, so the caller must have done so.
 * Reads the wire's assignment out of `cs->witness`; on an out-of-range index it
 * yields Constant(false), which is wrong-by-construction rather than a silent
 * out-of-bounds read, and the R1CS-satisfaction gate then fails loudly. */
struct cbit cbit_from_var(const struct constraint_system *cs, size_t var);

/* The negated view. 0 constraints (bellman Boolean::not). */
struct cbit cbit_not(struct cbit b);

/* The bit's logical value (applies the CBIT_NOT view). */
bool cbit_value(struct cbit b);

/* XOR (bellman Boolean::xor). Cost:
 *   either side constant           -> 0 constraints
 *   both allocated (any Is/Not mix) -> 1 constraint, 1 aux variable
 * The allocated case emits AllocatedBit::xor's `(a + a) * b = a + b - c` over
 * the two UNDERLYING wires, and returns `Not(c)` when exactly one input was a
 * negated view — that is how bellman keeps `Is ^ Not` free of an extra gate. */
struct cbit cbit_xor(struct constraint_system *cs, struct cbit a, struct cbit b);

/* Append `coeff * b` to `lc`, exactly as bellman's `Boolean::lc`:
 *   Constant(false) -> nothing        Constant(true) -> coeff * ONE
 *   Is(v)           -> coeff * v      Not(v)         -> coeff*ONE - coeff*v */
void cbit_lc_add(struct linear_combination *lc, struct cbit b,
                 const struct fr *coeff);

/* ── UInt32 (bellman circuit::uint32::UInt32) ────────────────────── */

/* bits[0] is the LEAST significant bit. */
struct cu32 {
    struct cbit bits[32];
};

/* All-constant word. 0 constraints. */
struct cu32 cu32_constant(uint32_t value);

/* Reinterpret 32 little-endian-ordered bits as a word (UInt32::from_bits).
 * 0 constraints — it is a view, not a gadget. */
struct cu32 cu32_from_bits_le(const struct cbit bits[32]);

/* Rotate right (UInt32::rotr). 0 constraints — pure re-indexing. */
struct cu32 cu32_rotr(const struct cu32 *a, unsigned by);

/* Bitwise XOR (UInt32::xor): 32 × cbit_xor, so 0..32 constraints depending on
 * how many bit positions have a constant on either side. */
struct cu32 cu32_xor(struct constraint_system *cs,
                     const struct cu32 *a, const struct cu32 *b);

/* ── MultiEq (bellman circuit::multieq::MultiEq) ─────────────────── */

/* Number of bits of a BLS12-381 Fr element that MultiEq is allowed to pack:
 * pairing's `Fr::CAPACITY` = NUM_BITS - 1 = 254. Load-bearing — the flush
 * schedule this number produces is what makes blake2s land on 21006 rather
 * than a nearby number. */
#define CBIT_FR_CAPACITY 254u

struct multieq {
    struct constraint_system *cs;
    size_t bits_used;
    size_t ops;                     /* number of constraints flushed so far */
    struct linear_combination lhs;
    struct linear_combination rhs;
};

void multieq_init(struct multieq *m, struct constraint_system *cs);

/* Defer `lhs == rhs` (an equality whose difference is known to fit in
 * `num_bits` bits) into the batch. Emits a constraint only when the batch is
 * full — i.e. when `CBIT_FR_CAPACITY <= bits_used + num_bits`. */
void multieq_enforce_equal(struct multieq *m, size_t num_bits,
                           const struct linear_combination *lhs,
                           const struct linear_combination *rhs);

/* bellman's `Drop for MultiEq`: flush any partial batch, then release. MUST be
 * called at the end of the scope the reference wraps in MultiEq, because the
 * flush point is a constraint-ORDER fact, not just a count. */
void multieq_finish(struct multieq *m);

/* Modular addition of 2..10 words (UInt32::addmany). Cost:
 *   all operand bits constant -> 0 constraints (returns a constant word)
 *   otherwise                 -> ceil(log2(n * 2^32)) alloc constraints
 *                                (33 for n=2, 34 for n=3) plus a deferred
 *                                MultiEq equality that costs a shared
 *                                fraction of one constraint.
 * The result is truncated to 32 bits; the carry bits stay allocated and stay
 * inside the equality, so they are constrained even though they are dropped. */
struct cu32 cu32_addmany(struct multieq *m, const struct cu32 *ops,
                         size_t n_ops);

/* ── blake2s (sapling-crypto circuit::blake2s::blake2s) ──────────── */

/* Personalized BLAKE2s-256 over `n_bits` input bits (must be a multiple of 8),
 * writing 256 little-endian output bits. For a 512-bit all-allocated input this
 * emits exactly 21006 constraints — the reference trace's cost for spend
 * section 10 ("computation of ivk") and section 27 ("nf computation").
 * Returns false (with a logged reason) on a malformed request. */
bool gadget_blake2s(struct constraint_system *cs,
                    const struct cbit *input, size_t n_bits,
                    const uint8_t personalization[8],
                    struct cbit out[256]);

/* ── Boolean-driven Jubjub scalar multiplication ─────────────────── */

/* bellman ecc::EdwardsPoint::conditionally_select with a `Boolean` condition.
 * The single reason this lives in the cbit layer rather than next to the other
 * curve gadgets: a `Boolean` may be a CONSTANT or a NEGATED view, so the
 * condition can only be handed to a constraint as a linear combination
 * (cbit_lc_add), never as a wire index. 2 constraints, the same two
 * gadget_conditionally_select_point emits for a bare wire. */
void gadget_conditionally_select_point_cbit(struct constraint_system *cs,
                                            struct cbit cond,
                                            size_t px, size_t py,
                                            size_t *rx, size_t *ry);

/* bellman ecc::EdwardsPoint::mul — double-and-add over `n_bits` Boolean bits,
 * LEAST significant first, against a base that is itself a pair of wires. This
 * is THE double-and-add body in the tree; gadget_variable_base_mul (bare wires)
 * is a wrapper over it.
 *
 * Cost: 13*n_bits - 11 constraints, and it does not depend on the bits' values
 * or kinds — bit 0 pays only a select (2), every later bit pays a double (5), a
 * select (2) and an add (6). Section 13 of the spend circuit multiplies g_d by
 * the 251 truncated ivk bits, which is exactly 3252 constraints.
 *
 * On a malformed request (n_bits == 0) it logs and writes SIZE_MAX to both
 * outputs rather than returning a plausible-looking point. */
void gadget_variable_base_mul_cbits(struct constraint_system *cs,
                                    size_t base_x, size_t base_y,
                                    const struct cbit *scalar_bits,
                                    size_t n_bits,
                                    size_t *out_x, size_t *out_y);

#endif
