/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ported from librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Reimplemented in
 * C23; no reference code is linked into the production binary.
 *
 * R1CS circuit gadgets matching Zcash bellman/sapling-crypto exactly.
 * Edwards add (6 constraints), double (5), windowed fixed-base mul,
 * strict bit decomposition. The Pedersen hash and the Jubjub Montgomery
 * arithmetic under it are the biggest single gadget in the circuit and live in
 * their own translation unit, circuit_pedersen.c. */

#include "sapling/circuit_gadgets.h"
#include "sapling/circuit_bits.h"
#include "sapling/pedersen_hash.h"
#include "sapling/sapling.h"
#include "crypto/blake2s.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "support/cleanse.h"

#define CS_ONE 0

/* Append every term of `src` onto `dst` — bellman's `|_| lc + &other` closure:
 * a condition that arrives as an LC gets spliced into A/B/C, not re-derived. */
static void lc_append(struct linear_combination *dst,
                      const struct linear_combination *src)
{
    for (size_t i = 0; i < src->num_terms; i++)
        lc_add_term(dst, src->terms[i].var, &src->terms[i].coeff);
}

/* ── Boolean Gadgets ────────────────────────────────────────────── */

void gadget_boolean(struct constraint_system *cs, size_t var)
{
    struct linear_combination a, b, c;
    struct fr one_val;
    fr_one(&one_val);
    struct fr neg_one;
    fr_neg(&neg_one, &one_val);

    lc_init(&a);
    lc_add_term(&a, CS_ONE, &one_val);
    lc_add_term(&a, var, &neg_one);

    lc_init(&b);
    lc_add_term(&b, var, &one_val);

    lc_init(&c);

    cs_enforce(cs, &a, &b, &c);
    lc_free(&a);
    lc_free(&b);
    lc_free(&c);
}

size_t gadget_alloc_boolean(struct constraint_system *cs, bool value)
{
    struct fr val;
    if (value) fr_one(&val); else fr_zero(&val);
    size_t var = cs_alloc_aux(cs, &val);
    gadget_boolean(cs, var);
    return var;
}

void gadget_unpack_bits(struct constraint_system *cs,
                        size_t *bits_out, size_t n_bits,
                        const struct fr *value)
{
    uint8_t bytes[32];
    fr_to_bytes(bytes, value);

    for (size_t i = 0; i < n_bits; i++) {
        size_t byte_idx = i / 8;
        size_t bit_idx = i % 8;
        bool bit = byte_idx < 32 && ((bytes[byte_idx] >> bit_idx) & 1);
        bits_out[i] = gadget_alloc_boolean(cs, bit);
    }

    size_t value_var = cs_alloc_aux(cs, value);
    struct linear_combination a, b, c;
    lc_init(&a);
    struct fr coeff;
    fr_one(&coeff);
    for (size_t i = 0; i < n_bits; i++) {
        lc_add_term(&a, bits_out[i], &coeff);
        fr_add(&coeff, &coeff, &coeff);
    }
    struct fr one_val;
    fr_one(&one_val);
    lc_init(&b);
    lc_add_term(&b, CS_ONE, &one_val);
    lc_init(&c);
    lc_add_term(&c, value_var, &one_val);
    cs_enforce(cs, &a, &b, &c);
    lc_free(&a);
    lc_free(&b);
    lc_free(&c);
}

size_t gadget_pack_bits(struct constraint_system *cs,
                        const size_t *bits, size_t n_bits)
{
    struct fr packed;
    fr_zero(&packed);
    struct fr coeff;
    fr_one(&coeff);
    for (size_t i = 0; i < n_bits; i++) {
        struct fr bit_val = cs->witness[bits[i]];
        struct fr term;
        fr_mul(&term, &bit_val, &coeff);
        fr_add(&packed, &packed, &term);
        fr_add(&coeff, &coeff, &coeff);
    }
    size_t result = cs_alloc_aux(cs, &packed);
    struct linear_combination a, b, c;
    lc_init(&a);
    fr_one(&coeff);
    for (size_t i = 0; i < n_bits; i++) {
        lc_add_term(&a, bits[i], &coeff);
        fr_add(&coeff, &coeff, &coeff);
    }
    struct fr one_val;
    fr_one(&one_val);
    lc_init(&b);
    lc_add_term(&b, CS_ONE, &one_val);
    lc_init(&c);
    lc_add_term(&c, result, &one_val);
    cs_enforce(cs, &a, &b, &c);
    lc_free(&a);
    lc_free(&b);
    lc_free(&c);
    return result;
}

/* ── Strict little-endian bit decomposition ─────────────────────────
 *
 * Port of bellman/sapling-crypto AllocatedNum::into_bits_le_strict
 * (sapling-crypto/src/circuit/num.rs at pinned commit 06da3b9a...), used by
 * EdwardsPoint::repr. "Strict" means the emitted bits are constrained to be a
 * representation that literally exists in the field — a congruency (a value
 * >= r that reduces to the same element) is rejected. Plain into_bits_le does
 * NOT do this and is a different, cheaper gadget; do not substitute it.
 *
 * The algorithm walks the bit pattern of (r - 1) from the most significant set
 * bit down, in BIG-endian order, and for each of the 255 positions:
 *   - r-1 has a 1 here  -> allocate an ordinary boolean bit (1 constraint).
 *   - r-1 has a 0 here  -> the value's bit may only be 1 if some earlier
 *                          higher-order run of ones was not fully matched. So
 *                          first collapse the just-ended run of ones (and the
 *                          previous run's flag) with a k-ary AND, then allocate
 *                          the bit CONDITIONALLY on that flag: if the flag is
 *                          set, the bit is forced to zero.
 * Finally one "unpacking" constraint binds the recomposed bits back to `var`.
 *
 * The constraint count is EMERGENT from the fixed bit pattern of r-1, not a
 * tunable: 133 plain bits + 122 conditional bits + 132 k-ary AND steps + 1
 * unpacking constraint = 388 constraints and 387 aux variables per field
 * element. That is why the section-boundary oracle (2032 -> 2808 -> 3584) is
 * the right acceptance test — the number cannot be reverse-engineered from a
 * target, it either falls out of a faithful port or it does not.
 *
 * Allocation ORDER is load-bearing for QAP alignment, so the k-ary AND
 * intermediates are allocated exactly where bellman allocates them: inside the
 * zero-bit branch, before that position's conditional bit.
 *
 * bits_out receives 255 variable indices in LITTLE-endian order (bit 0 = LSB),
 * which is the reverse of the order in which they are allocated. */

/* AllocatedBit::alloc_conditionally — allocate a boolean that is additionally
 * forced to zero when `must_be_false` is one.
 * Constraint: (1 - must_be_false - a) * a = 0.
 *   must_be_false = 1  ->  (-a) * a = 0  ->  a = 0
 *   must_be_false = 0  ->  (1 - a) * a = 0  ->  ordinary boolean constraint */
static size_t alloc_boolean_conditionally(struct constraint_system *cs,
                                          bool value, size_t must_be_false)
{
    struct fr val;
    if (value) fr_one(&val); else fr_zero(&val);
    size_t var = cs_alloc_aux(cs, &val);

    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);

    struct linear_combination la, lb, lc;
    lc_init(&la);
    lc_add_term(&la, CS_ONE, &one_val);
    lc_add_term(&la, must_be_false, &neg_one);
    lc_add_term(&la, var, &neg_one);
    lc_init(&lb);
    lc_add_term(&lb, var, &one_val);
    lc_init(&lc);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
    return var;
}

/* (r - 1) for the BLS12-381 scalar field, most-significant limb first.
 * r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 */
static const uint64_t FR_CHAR_MINUS_ONE_BE[4] = {
    UINT64_C(0x73eda753299d7d48), UINT64_C(0x3339d80809a1d805),
    UINT64_C(0x53bda402fffe5bfe), UINT64_C(0xffffffff00000000)
};

void gadget_into_bits_le_strict(struct constraint_system *cs, size_t var,
                                size_t bits_out[FR_STRICT_BITS])
{
    /* Canonical big-endian bit access to the wire's value. fr_to_bytes emits
     * the canonical (non-Montgomery) little-endian encoding. */
    uint8_t value_bytes[32];
    fr_to_bytes(value_bytes, &cs->witness[var]);

    size_t big_endian[FR_STRICT_BITS]; /* allocated order: MSB first */
    size_t n_be = 0;

    size_t current_run[FR_STRICT_BITS];
    size_t run_len = 0;
    size_t last_run = 0;
    bool have_last_run = false;
    bool found_one = false;

    for (size_t limb = 0; limb < 4; limb++) {
        for (int j = 63; j >= 0; j--) {
            size_t bit_pos = (3 - limb) * 64 + (size_t)j; /* 255..0 */
            bool char_bit = (FR_CHAR_MINUS_ONE_BE[limb] >> j) & 1;

            /* Skip leading zeros of r-1. Every field element is < r, so its
             * bits above the top set bit of r-1 are zero too — nothing to
             * allocate and nothing to constrain. */
            found_one |= char_bit;
            if (!found_one)
                continue;

            bool a_bit = (value_bytes[bit_pos / 8] >> (bit_pos % 8)) & 1;

            if (char_bit) {
                /* Inside a run of ones: an ordinary boolean bit. */
                size_t b = gadget_alloc_boolean(cs, a_bit);
                current_run[run_len++] = b;
                big_endian[n_be++] = b;
            } else {
                if (run_len > 0) {
                    /* A run of ones just ended. Fold it — together with the
                     * previous run's flag — into a single k-ary AND flag. */
                    if (have_last_run)
                        current_run[run_len++] = last_run;
                    size_t cur = current_run[0];
                    for (size_t k = 1; k < run_len; k++)
                        cur = gadget_alloc_mul(cs, cur, current_run[k]);
                    last_run = cur;
                    have_last_run = true;
                    run_len = 0;
                }
                /* r-1's top bit is one, so a flag always exists by here. */
                big_endian[n_be++] =
                    alloc_boolean_conditionally(cs, a_bit, last_run);
            }
        }
    }

    /* r is prime, so its low bit is one and r-1 always ends on a run of zeros:
     * every run of ones has been folded by now. */

    /* Unpacking constraint, exactly as bellman emits it:
     *   0 * 0 = (sum_i 2^i * bit_i) - var
     * A and B are EMPTY linear combinations (not 1*ONE) — that is the shape in
     * the reference and it is what the coefficient-level satisfaction check
     * evaluates, so it is written out literally. */
    struct linear_combination la, lb, lc;
    struct fr coeff, neg_one, one_val;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);
    fr_one(&coeff);
    lc_init(&la);
    lc_init(&lb);
    lc_init(&lc);
    for (size_t i = n_be; i-- > 0;) { /* LSB first: reverse of allocation */
        lc_add_term(&lc, big_endian[i], &coeff);
        fr_add(&coeff, &coeff, &coeff);
    }
    lc_add_term(&lc, var, &neg_one);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);

    /* Reverse to little-endian for the caller. */
    for (size_t i = 0; i < n_be; i++)
        bits_out[i] = big_endian[n_be - 1 - i];

    memory_cleanse(value_bytes, sizeof(value_bytes));
}

/* Port of ecc::EdwardsPoint::repr — the 256-bit representation of a Jubjub
 * point fed into the CRH^ivk / PRF^nf preimages. x is unpacked first (its
 * allocation order is load-bearing even though only x[0] survives), then y;
 * the result is y's 255 little-endian bits followed by the sign bit x[0].
 * 776 constraints (two strict decompositions). */
void gadget_point_repr(struct constraint_system *cs,
                       size_t x_var, size_t y_var, size_t bits_out[256])
{
    size_t x_bits[FR_STRICT_BITS];
    size_t y_bits[FR_STRICT_BITS];
    gadget_into_bits_le_strict(cs, x_var, x_bits);
    gadget_into_bits_le_strict(cs, y_var, y_bits);

    for (size_t i = 0; i < FR_STRICT_BITS; i++)
        bits_out[i] = y_bits[i];
    bits_out[FR_STRICT_BITS] = x_bits[0];
}

/* ── Field Arithmetic Gadgets ───────────────────────────────────── */

void gadget_mul(struct constraint_system *cs, size_t a, size_t b, size_t c)
{
    struct linear_combination la, lb, lc;
    struct fr one_val;
    fr_one(&one_val);
    lc_init(&la); lc_add_term(&la, a, &one_val);
    lc_init(&lb); lc_add_term(&lb, b, &one_val);
    lc_init(&lc); lc_add_term(&lc, c, &one_val);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

size_t gadget_alloc_mul(struct constraint_system *cs, size_t a, size_t b)
{
    struct fr product;
    fr_mul(&product, &cs->witness[a], &cs->witness[b]);
    size_t c = cs_alloc_aux(cs, &product);
    gadget_mul(cs, a, b, c);
    return c;
}

size_t gadget_select(struct constraint_system *cs,
                     size_t condition, size_t a, size_t b)
{
    struct fr cond_val = cs->witness[condition];
    struct fr a_val = cs->witness[a];
    struct fr b_val = cs->witness[b];
    struct fr diff;
    fr_sub(&diff, &a_val, &b_val);
    struct fr selected;
    fr_mul(&selected, &cond_val, &diff);
    fr_add(&selected, &selected, &b_val);
    size_t result = cs_alloc_aux(cs, &selected);

    struct linear_combination la, lb, lc;
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);
    lc_init(&la); lc_add_term(&la, condition, &one_val);
    lc_init(&lb); lc_add_term(&lb, a, &one_val); lc_add_term(&lb, b, &neg_one);
    lc_init(&lc); lc_add_term(&lc, result, &one_val); lc_add_term(&lc, b, &neg_one);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
    return result;
}

/* ── Jubjub d constant ─────────────────────────────────────────── */

static void jubjub_d(struct fr *d)
{
    static const uint8_t D_BYTES[32] = {
        0xb1,0x3e,0x34,0xd6,0xd6,0x5f,0x06,0x01,
        0x26,0x9d,0x57,0x37,0x6d,0x7f,0x2d,0x29,
        0xd4,0x7f,0xbd,0xe6,0x07,0x92,0xfd,0xf5,
        0x48,0x2b,0xfa,0x4b,0xe7,0x18,0x93,0x2a
    };
    fr_from_bytes(d, D_BYTES);
}

/* ── Edwards Addition (6 constraints) ──────────────────────────── */
/* Zcash bellman formula:
 * U = (x1+y1)*(x2+y2)  — 1 constraint
 * A = y2*x1             — 1 constraint
 * B = x2*y1             — 1 constraint
 * C = d*A*B             — 1 constraint: (d*A)*B = C
 * (1+C)*x3 = A+B        — 1 constraint
 * (1-C)*y3 = U-A-B      — 1 constraint
 * Total: 6 constraints */

void gadget_edwards_add(struct constraint_system *cs,
                        size_t x1, size_t y1,
                        size_t x2, size_t y2,
                        size_t *x3, size_t *y3)
{
    struct fr x1v = cs->witness[x1], y1v = cs->witness[y1];
    struct fr x2v = cs->witness[x2], y2v = cs->witness[y2];
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);
    struct fr d_val;
    jubjub_d(&d_val);

    /* U = (x1+y1)*(x2+y2) */
    struct fr u_val;
    {
        struct fr s1, s2;
        fr_add(&s1, &x1v, &y1v);
        fr_add(&s2, &x2v, &y2v);
        fr_mul(&u_val, &s1, &s2);
    }
    size_t u = cs_alloc_aux(cs, &u_val);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, x1, &one_val); lc_add_term(&la, y1, &one_val);
        lc_init(&lb); lc_add_term(&lb, x2, &one_val); lc_add_term(&lb, y2, &one_val);
        lc_init(&lc); lc_add_term(&lc, u, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* A = y2*x1 */
    struct fr a_val;
    fr_mul(&a_val, &y2v, &x1v);
    size_t a = cs_alloc_aux(cs, &a_val);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, y2, &one_val);
        lc_init(&lb); lc_add_term(&lb, x1, &one_val);
        lc_init(&lc); lc_add_term(&lc, a, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* B = x2*y1 */
    struct fr b_val;
    fr_mul(&b_val, &x2v, &y1v);
    size_t b = cs_alloc_aux(cs, &b_val);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, x2, &one_val);
        lc_init(&lb); lc_add_term(&lb, y1, &one_val);
        lc_init(&lc); lc_add_term(&lc, b, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* C = d*A*B: constrained as (d*A)*B = C */
    struct fr c_val;
    {
        struct fr da;
        fr_mul(&da, &d_val, &a_val);
        fr_mul(&c_val, &da, &b_val);
    }
    size_t c = cs_alloc_aux(cs, &c_val);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, a, &d_val);
        lc_init(&lb); lc_add_term(&lb, b, &one_val);
        lc_init(&lc); lc_add_term(&lc, c, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* x3 = (A+B) / (1+C) → (1+C)*x3 = A+B */
    struct fr x3v;
    {
        struct fr num, denom;
        fr_add(&num, &a_val, &b_val);
        fr_add(&denom, &one_val, &c_val);
        fr_inv(&x3v, &denom);
        fr_mul(&x3v, &x3v, &num);
    }
    *x3 = cs_alloc_aux(cs, &x3v);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, CS_ONE, &one_val); lc_add_term(&la, c, &one_val);
        lc_init(&lb); lc_add_term(&lb, *x3, &one_val);
        lc_init(&lc); lc_add_term(&lc, a, &one_val); lc_add_term(&lc, b, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* y3 = (U-A-B) / (1-C) → (1-C)*y3 = U-A-B */
    struct fr y3v;
    {
        struct fr num, denom;
        fr_sub(&num, &u_val, &a_val);
        fr_sub(&num, &num, &b_val);
        fr_sub(&denom, &one_val, &c_val);
        fr_inv(&y3v, &denom);
        fr_mul(&y3v, &y3v, &num);
    }
    *y3 = cs_alloc_aux(cs, &y3v);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, CS_ONE, &one_val); lc_add_term(&la, c, &neg_one);
        lc_init(&lb); lc_add_term(&lb, *y3, &one_val);
        lc_init(&lc); lc_add_term(&lc, u, &one_val); lc_add_term(&lc, a, &neg_one); lc_add_term(&lc, b, &neg_one);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }
}

/* ── Edwards Doubling (5 constraints) ──────────────────────────── */
/* Zcash bellman: T=(x+y)^2, A=x*y, C=d*A^2, (1+C)*x3=2A, (1-C)*y3=T-2A */

void gadget_edwards_double(struct constraint_system *cs,
                            size_t x1, size_t y1,
                            size_t *x3, size_t *y3)
{
    struct fr xv = cs->witness[x1], yv = cs->witness[y1];
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);
    struct fr d_val;
    jubjub_d(&d_val);
    struct fr two;
    fr_add(&two, &one_val, &one_val);

    /* T = (x+y)^2 */
    struct fr t_val;
    {
        struct fr s;
        fr_add(&s, &xv, &yv);
        fr_mul(&t_val, &s, &s);
    }
    size_t t = cs_alloc_aux(cs, &t_val);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, x1, &one_val); lc_add_term(&la, y1, &one_val);
        lc_init(&lb); lc_add_term(&lb, x1, &one_val); lc_add_term(&lb, y1, &one_val);
        lc_init(&lc); lc_add_term(&lc, t, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* A = x*y */
    struct fr a_val;
    fr_mul(&a_val, &xv, &yv);
    size_t a = cs_alloc_aux(cs, &a_val);
    gadget_mul(cs, x1, y1, a);

    /* C = d*A^2: (d*A)*A = C */
    struct fr c_val;
    {
        struct fr da;
        fr_mul(&da, &d_val, &a_val);
        fr_mul(&c_val, &da, &a_val);
    }
    size_t c = cs_alloc_aux(cs, &c_val);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, a, &d_val);
        lc_init(&lb); lc_add_term(&lb, a, &one_val);
        lc_init(&lc); lc_add_term(&lc, c, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* (1+C)*x3 = 2*A */
    struct fr x3v;
    {
        struct fr num, denom;
        fr_mul(&num, &two, &a_val);
        fr_add(&denom, &one_val, &c_val);
        fr_inv(&x3v, &denom);
        fr_mul(&x3v, &x3v, &num);
    }
    *x3 = cs_alloc_aux(cs, &x3v);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, CS_ONE, &one_val); lc_add_term(&la, c, &one_val);
        lc_init(&lb); lc_add_term(&lb, *x3, &one_val);
        lc_init(&lc); lc_add_term(&lc, a, &two);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* (1-C)*y3 = T-2A */
    struct fr y3v;
    {
        struct fr num, denom;
        fr_mul(&num, &two, &a_val);
        fr_sub(&num, &t_val, &num);
        fr_sub(&denom, &one_val, &c_val);
        fr_inv(&y3v, &denom);
        fr_mul(&y3v, &y3v, &num);
    }
    *y3 = cs_alloc_aux(cs, &y3v);
    {
        struct linear_combination la, lb, lc;
        struct fr neg_two;
        fr_neg(&neg_two, &two);
        lc_init(&la); lc_add_term(&la, CS_ONE, &one_val); lc_add_term(&la, c, &neg_one);
        lc_init(&lb); lc_add_term(&lb, *y3, &one_val);
        lc_init(&lc); lc_add_term(&lc, t, &one_val); lc_add_term(&lc, a, &neg_two);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }
}

/* ── 3-bit Lookup Table (synth interpolation) ──────────────────── */

/* Compute interpolation coefficients for 2^window_size values.
 * Given constants[0..2^w-1], computes assignment[0..2^w-1] such that:
 * constants[index] = sum over j (assignment[j] for j where j is subset of index bits)
 * This is the Möbius/subset-sum interpolation used by bellman.
 * Shared with the Pedersen hash's 2-bit windows in circuit_pedersen.c — there is
 * exactly one copy of this interpolation in the tree. */
void gadget_synth_coeffs(size_t window_size, const struct fr *constants,
                         struct fr *assignment)
{
    size_t n = (size_t)1 << window_size;
    for (size_t i = 0; i < n; i++)
        fr_zero(&assignment[i]);

    for (size_t i = 0; i < n; i++) {
        struct fr cur = assignment[i];
        fr_neg(&cur, &cur);
        fr_add(&cur, &cur, &constants[i]);
        assignment[i] = cur;
        for (size_t j = i + 1; j < n; j++) {
            if ((j & i) == i) {
                fr_add(&assignment[j], &assignment[j], &cur);
            }
        }
    }
}

/* Build the x or y lookup constraint, omitting each padded-bit term. */
static void lookup3_enforce_padded_coord(struct constraint_system *cs,
                                         size_t b0, size_t b1, size_t b2,
                                         bool b1_pad, bool b2_pad,
                                         bool have_precomp, size_t precomp,
                                         const struct fr *one_val,
                                         const struct fr c[8],
                                         size_t result)
{
    struct linear_combination la, lb, lc;
    lc_init(&la);
    lc_add_term(&la, CS_ONE, &c[0b001]);
    if (!b1_pad) lc_add_term(&la, b1, &c[0b011]);
    if (!b2_pad) lc_add_term(&la, b2, &c[0b101]);
    if (have_precomp) lc_add_term(&la, precomp, &c[0b111]);

    lc_init(&lb);
    lc_add_term(&lb, b0, one_val);

    lc_init(&lc);
    lc_add_term(&lc, result, one_val);
    struct fr neg_c0; fr_neg(&neg_c0, &c[0b000]);
    lc_add_term(&lc, CS_ONE, &neg_c0);
    if (!b1_pad) {
        struct fr neg_c2; fr_neg(&neg_c2, &c[0b010]);
        lc_add_term(&lc, b1, &neg_c2);
    }
    if (!b2_pad) {
        struct fr neg_c4; fr_neg(&neg_c4, &c[0b100]);
        lc_add_term(&lc, b2, &neg_c4);
    }
    if (have_precomp) {
        struct fr neg_c6; fr_neg(&neg_c6, &c[0b110]);
        lc_add_term(&lc, precomp, &neg_c6);
    }

    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

/* lookup3_xy with bellman's constant-false PADDING for the two high bits.
 *
 * `b1_pad` / `b2_pad` say that bit is `Boolean::constant(false)` rather than a
 * wire — which is what `fixed_base_multiplication` feeds the last window
 * whenever the scalar's bit count is not a multiple of 3. A constant-false
 * `Boolean` contributes NO TERM to any linear combination and makes
 * `Boolean::and` fold to another constant, so padding does not simplify the
 * gadget, it DELETES terms and (when b2 is padded) the precomp wire with its
 * constraint:
 *
 *   both padded (1 real bit) -> 2 constraints, 2 aux   (A = xc[001]*ONE)
 *   b2 padded  (2 real bits) -> 2 constraints, 2 aux   (b1 terms survive)
 *   none padded              -> 3 constraints, 3 aux
 *
 * The earlier code allocated dummy zero-valued wires for the padded bits
 * instead. That satisfies every A*B==C check on the honest witness and lands on
 * the same constraint count for the 2-real-bit case, but it inserts aux
 * variables the reference never allocates and puts a variable where the
 * reference has an empty linear combination — a different QAP, so it cannot
 * verify against the Sapling trusted setup. Only spend section 24 (g^position,
 * 32 bits -> 11 windows) reaches the 2-real-bit shape. */
static void lookup3_xy_padded(struct constraint_system *cs,
                              size_t b0, size_t b1, size_t b2,
                              bool b1_pad, bool b2_pad,
                              const struct fr coords_x[8],
                              const struct fr coords_y[8],
                              size_t *rx, size_t *ry)
{
    struct fr one_val;
    fr_one(&one_val);

    struct fr b1v, b2v;
    if (b1_pad) fr_zero(&b1v); else b1v = cs->witness[b1];
    if (b2_pad) fr_zero(&b2v); else b2v = cs->witness[b2];
    struct fr b0v = cs->witness[b0];

    /* ALLOCATION ORDER IS LOAD-BEARING. sapling-crypto's lookup3_xy allocates
     * res_x, then res_y, and only then the `precomp` wire that Boolean::and
     * introduces — so the window's three aux variables are (x, y, precomp), in
     * that order. Allocating precomp first is algebraically identical and
     * satisfies every A*B==C check, but it PERMUTES three aux indices per
     * window; the Groth16 proving key is indexed per variable, so the permuted
     * circuit is a different QAP and cannot verify against the Sapling trusted
     * setup. Only a matrix-level transcript diff sees this
     * (test_groth16_r1cs_oracle). The CONSTRAINT order is unchanged: the AND
     * comes first, then the x and y lookups. */
    int idx = 0;
    if (!fr_is_zero(&b0v)) idx |= 1;
    if (!fr_is_zero(&b1v)) idx |= 2;
    if (!fr_is_zero(&b2v)) idx |= 4;

    *rx = cs_alloc_aux(cs, &coords_x[idx]);
    *ry = cs_alloc_aux(cs, &coords_y[idx]);

    /* precomp = b1 AND b2. bellman's Boolean::and folds to Constant(false) as
     * soon as either side is constant-false, so a padded window has no precomp
     * wire and no AND constraint at all. */
    const bool have_precomp = !b1_pad && !b2_pad;
    size_t precomp = SIZE_MAX;
    if (have_precomp) {
        struct fr precomp_val;
        fr_mul(&precomp_val, &b1v, &b2v);
        precomp = cs_alloc_aux(cs, &precomp_val);
        gadget_mul(cs, b1, b2, precomp);
    }

    /* Compute synth coefficients */
    struct fr xc[8], yc[8];
    gadget_synth_coeffs(3, coords_x, xc);
    gadget_synth_coeffs(3, coords_y, yc);

    /* x-coordinate constraint (1 constraint):
     * (xc[001] + b1*xc[011] + b2*xc[101] + precomp*xc[111]) * b0
     *   = rx - xc[000] - b1*xc[010] - b2*xc[100] - precomp*xc[110] */
    lookup3_enforce_padded_coord(cs, b0, b1, b2, b1_pad, b2_pad,
                                 have_precomp, precomp, &one_val, xc, *rx);

    /* y-coordinate constraint (1 constraint): same structure */
    lookup3_enforce_padded_coord(cs, b0, b1, b2, b1_pad, b2_pad,
                                 have_precomp, precomp, &one_val, yc, *ry);
}

/* ── Fixed-Base Scalar Multiplication (windowed) ───────────────── */

void gadget_fixed_base_mul(struct constraint_system *cs,
                           const size_t *scalar_bits, size_t n_bits,
                           const struct fr *base_x, const struct fr *base_y,
                           size_t *x_out, size_t *y_out)
{
    /* Reconstruct the Jubjub base point from its (x, y) coordinates */
    struct jub_point gen;
    {
        struct fr gx, gy, gz, gt;
        gx = *base_x;
        gy = *base_y;
        fr_one(&gz);
        fr_mul(&gt, &gx, &gy);
        gen.x = gx; gen.y = gy; gen.z = gz; gen.t = gt;
    }

    size_t acc_x = SIZE_MAX, acc_y = SIZE_MAX;
    size_t n_windows = (n_bits + 2) / 3;

    struct jub_point cur_gen = gen;

    for (size_t w = 0; w < n_windows; w++) {
        /* The window's three bit wires. A short final chunk leaves the high
         * ones unset; lookup3_xy_padded is told so and never reads them. */
        const size_t b0 = scalar_bits[w * 3 + 0];
        const size_t b1 = (w * 3 + 1 < n_bits) ? scalar_bits[w * 3 + 1] : 0;
        const size_t b2 = (w * 3 + 2 < n_bits) ? scalar_bits[w * 3 + 2] : 0;

        /* Precompute 8 multiples: 0*G, 1*G, 2*G, ..., 7*G */
        struct fr coords_x[8], coords_y[8];
        /* 0*G = identity (0, 1) */
        fr_zero(&coords_x[0]);
        fr_one(&coords_y[0]);
        /* 1*G through 7*G */
        struct jub_point pt = cur_gen;
        for (int k = 1; k < 8; k++) {
            jub_get_x(&coords_x[k], &pt);
            jub_get_y(&coords_y[k], &pt);
            if (k < 7) {
                struct jub_point next;
                jub_add(&next, &pt, &cur_gen);
                pt = next;
            }
        }

        /* bellman chunks the bits by 3 and pads a short final chunk with
         * `Boolean::constant(false)`. b0 is never padded (window w exists only
         * because bit 3w does), so only the two high bits can be. */
        const bool b1_pad = (w * 3 + 1 >= n_bits);
        const bool b2_pad = (w * 3 + 2 >= n_bits);

        size_t wx, wy;
        lookup3_xy_padded(cs, b0, b1, b2, b1_pad, b2_pad,
                          coords_x, coords_y, &wx, &wy);

        if (acc_x == SIZE_MAX) {
            acc_x = wx;
            acc_y = wy;
        } else {
            size_t new_x, new_y;
            gadget_edwards_add(cs, acc_x, acc_y, wx, wy, &new_x, &new_y);
            acc_x = new_x;
            acc_y = new_y;
        }

        /* Advance generator: cur_gen *= 2^3 = 8 */
        if (w + 1 < n_windows) {
            struct jub_point tmp;
            jub_double(&tmp, &cur_gen);
            jub_double(&cur_gen, &tmp);
            jub_double(&tmp, &cur_gen);
            cur_gen = tmp;
        }
    }

    *x_out = acc_x;
    *y_out = acc_y;
}

/* ── Point On-Curve Check (4 constraints) ──────────────────────── */

void gadget_point_interpret(struct constraint_system *cs, size_t x, size_t y)
{
    size_t x2 = gadget_alloc_mul(cs, x, x);
    size_t y2 = gadget_alloc_mul(cs, y, y);
    size_t x2y2 = gadget_alloc_mul(cs, x2, y2);

    struct fr d_val;
    jubjub_d(&d_val);
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);

    struct linear_combination la, lb, lc;
    lc_init(&la);
    lc_add_term(&la, x2, &neg_one);
    lc_add_term(&la, y2, &one_val);
    lc_init(&lb);
    lc_add_term(&lb, CS_ONE, &one_val);
    lc_init(&lc);
    lc_add_term(&lc, CS_ONE, &one_val);
    lc_add_term(&lc, x2y2, &d_val);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

/* ── Assert Not Small Order (16 constraints) ──────────────────── */

void gadget_assert_not_small_order(struct constraint_system *cs,
                                     size_t x, size_t y)
{
    size_t cur_x = x, cur_y = y;
    for (int i = 0; i < 3; i++) {
        size_t dx, dy;
        gadget_edwards_double(cs, cur_x, cur_y, &dx, &dy);
        cur_x = dx;
        cur_y = dy;
    }

    struct fr x_val = cs->witness[cur_x];
    struct fr inv_val;
    fr_inv(&inv_val, &x_val);
    size_t inv_var = cs_alloc_aux(cs, &inv_val);

    struct linear_combination la, lb, lc;
    struct fr one_val;
    fr_one(&one_val);
    lc_init(&la); lc_add_term(&la, cur_x, &one_val);
    lc_init(&lb); lc_add_term(&lb, inv_var, &one_val);
    lc_init(&lc); lc_add_term(&lc, CS_ONE, &one_val);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

/* ── Conditionally Select Point (2 constraints) ──────────────── */

void gadget_conditionally_select_point_lc(struct constraint_system *cs,
                                          const struct linear_combination *cond_lc,
                                          bool cond_value,
                                          size_t px, size_t py,
                                          size_t *rx, size_t *ry)
{
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);
    struct linear_combination la, lb, lc;

    /* x' = cond ? x : 0, as `x * cond = x'`. */
    struct fr rx_val;
    if (cond_value) rx_val = cs->witness[px]; else fr_zero(&rx_val);
    *rx = cs_alloc_aux(cs, &rx_val);
    lc_init(&la); lc_add_term(&la, px, &one_val);
    lc_init(&lb); lc_append(&lb, cond_lc);
    lc_init(&lc); lc_add_term(&lc, *rx, &one_val);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);

    /* y' = cond ? y : 1. bellman writes this as
     *
     *     y * cond = y' - (1 - cond)
     *
     * so A = y, B = cond, C = y' - ONE + cond (because not(cond) is always the
     * linear combination ONE - cond, for every Boolean view). Still written
     * around the neutral element's y = 1 rather than around 0, so cond = 0
     * lands on the Edwards identity and not on the non-curve pair (0, 0).
     *
     * The tempting rearrangement `(y - 1) * cond = y' - 1` is the SAME identity
     * and is satisfied by the SAME witness, but it moves the constant term from
     * C into A. Groth16's proving key is per variable and per matrix, so that
     * form is a different QAP and will not verify against the Sapling trusted
     * setup. It was the native circuit's form until test_groth16_r1cs_oracle
     * diffed the matrices against the reference; A*B==C cannot see it, which is
     * exactly why that oracle exists. */
    struct fr ry_val;
    if (cond_value) ry_val = cs->witness[py]; else fr_one(&ry_val);
    *ry = cs_alloc_aux(cs, &ry_val);
    lc_init(&la);
    lc_add_term(&la, py, &one_val);
    lc_init(&lb); lc_append(&lb, cond_lc);
    lc_init(&lc);
    lc_add_term(&lc, *ry, &one_val);
    lc_add_term(&lc, CS_ONE, &neg_one);
    lc_append(&lc, cond_lc);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

void gadget_conditionally_select_point(struct constraint_system *cs,
                                         size_t cond, size_t px, size_t py,
                                         size_t *rx, size_t *ry)
{
    struct fr one_val;
    fr_one(&one_val);
    struct linear_combination cond_lc;
    lc_init(&cond_lc);
    lc_add_term(&cond_lc, cond, &one_val);
    gadget_conditionally_select_point_lc(
        cs, &cond_lc, !fr_is_zero(&cs->witness[cond]), px, py, rx, ry);
    lc_free(&cond_lc);
}

/* ── Variable-Base Scalar Multiplication ───────────────────────── */

void gadget_variable_base_mul(struct constraint_system *cs,
                                size_t base_x, size_t base_y,
                                const size_t *scalar_bits, size_t n_bits,
                                size_t *out_x, size_t *out_y)
{
    *out_x = SIZE_MAX;
    *out_y = SIZE_MAX;
    struct cbit *views = (n_bits > 0)
        ? zcl_malloc(n_bits * sizeof(*views), "vbm_bit_views") : NULL;
    if (!views) {
        LOG_ERROR("circuit_gadgets", "variable_base_mul: no bit views for "
                  "n_bits=%zu (empty scalar, or the allocation failed)", n_bits);
        return;
    }
    for (size_t i = 0; i < n_bits; i++)
        views[i] = cbit_from_var(cs, scalar_bits[i]);
    gadget_variable_base_mul_cbits(cs, base_x, base_y, views, n_bits,
                                   out_x, out_y);
    free(views);
}

/* ── Point Inputize (2 constraints) ────────────────────────────── */

void gadget_point_inputize(struct constraint_system *cs, size_t x, size_t y)
{
    struct fr x_val = cs->witness[x];
    struct fr y_val = cs->witness[y];
    size_t ix = cs_alloc_input(cs, &x_val);
    size_t iy = cs_alloc_input(cs, &y_val);
    struct fr one_val;
    fr_one(&one_val);

    /* bellman AllocatedNum::inputize emits A = the INPUT variable, B = ONE,
     * C = the COMPUTED wire:
     *
     *     cs.enforce(|lc| lc + input, |lc| lc + CS::one(), |lc| lc + self.variable)
     *
     * The mirror image satisfies the same A*B==C check but writes a coefficient
     * into the wrong QAP matrix, so it cannot verify against the trusted setup.
     * The spend circuit's equivalent (circuit_spend.c enforce_equal) is pinned
     * against the reference transcript by test_groth16_r1cs_oracle; this entry
     * point serves the OUTPUT circuit, which has no transcript oracle yet, so it
     * is corrected here by direct reading of the reference rather than proven. */
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, ix, &one_val);
        lc_init(&lb); lc_add_term(&lb, CS_ONE, &one_val);
        lc_init(&lc); lc_add_term(&lc, x, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, iy, &one_val);
        lc_init(&lb); lc_add_term(&lb, CS_ONE, &one_val);
        lc_init(&lc); lc_add_term(&lc, y, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }
}

/* ── Scalar Inputize (1 constraint) ────────────────────────────── */

void gadget_scalar_inputize(struct constraint_system *cs, size_t var)
{
    struct fr val = cs->witness[var];
    size_t ivar = cs_alloc_input(cs, &val);
    struct fr one_val;
    fr_one(&one_val);
    struct linear_combination la, lb, lc;
    lc_init(&la); lc_add_term(&la, var, &one_val);
    lc_init(&lb); lc_add_term(&lb, CS_ONE, &one_val);
    lc_init(&lc); lc_add_term(&lc, ivar, &one_val);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

/* ── Strict Bit Decomposition (into_bits_le_strict) ────────────── */

/* BLS12-381 Fr modulus - 1 as 256 raw bits (MSB first) */
/* ── field_into_boolean_vec_le (simple, no packing) ────────────── */

