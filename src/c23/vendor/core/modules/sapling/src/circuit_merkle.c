/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ported from librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Reimplemented in
 * C23; no reference code is linked into the production binary.
 *
 * Section 21 of the Sapling spend circuit: the 32-level Merkle authentication
 * path. Faithful C23 port of the auth-path loop in sapling-crypto
 * `circuit::sapling::Spend::synthesize` (librustzcash
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5). See sapling/circuit_merkle.h for
 * the section's shape and its exact 1382-per-level cost.
 *
 * ONE level gadget, called 32 times. The tree depth is a loop bound, not 32
 * copies of the same body: every level differs only in the Pedersen
 * personalization (`MerkleTree(depth)`) and in which sibling it consumes, and
 * the reference's own structure is a loop for the same reason.
 *
 * Everything the level needs already exists: the bit/boolean primitives and the
 * personalization-parameterized Pedersen hash live in circuit_gadgets.h, and
 * the running value is a bare wire, so nothing here re-implements curve or bit
 * arithmetic. The two gadgets this file does add are the two bellman primitives
 * that had no C23 port yet — the non-strict little-endian decomposition and the
 * conditional reversal. */

#include "sapling/circuit_merkle.h"
#include "sapling/circuit_gadgets.h"
#include "sapling/fr.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <string.h>

/* Index of the constant-ONE variable in every constraint system. */
#define CS_ONE 0

/* Preimage bits one level Pedersen-hashes: xl's 255 then xr's 255. */
#define MERKLE_PREIMAGE_BITS (2 * MERKLE_FIELD_BITS)

void gadget_into_bits_le(struct constraint_system *cs, size_t var,
                         size_t bits_out[MERKLE_FIELD_BITS])
{
    /* bellman `field_into_allocated_bits_le`: deconstruct the value and
     * allocate Fr::NUM_BITS boolean wires, least significant first. */
    uint8_t bytes[32];
    struct fr value;
    if (var < cs->num_vars)
        value = cs->witness[var];
    else
        fr_zero(&value);
    fr_to_bytes(bytes, &value);

    for (size_t i = 0; i < MERKLE_FIELD_BITS; i++) {
        const bool bit = ((bytes[i / 8] >> (i % 8)) & 1u) != 0u;
        bits_out[i] = gadget_alloc_boolean(cs, bit);
    }
    memory_cleanse(bytes, sizeof(bytes));

    /* The unpacking constraint. bellman writes it with EMPTY A and B and the
     * whole equality in C — `cs.enforce(|lc| lc, |lc| lc, |_| lc)` where lc is
     * sum(2^i * bit_i) - var. 0 * 0 = C forces C to zero, and keeping that
     * exact A/B/C split matters: an equivalent form with the sum in A and ONE
     * in B satisfies the same witness but yields a different QAP. */
    struct linear_combination la, lb, lc;
    struct fr coeff, neg_one, one_val;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);
    fr_one(&coeff);

    lc_init(&la);
    lc_init(&lb);
    lc_init(&lc);
    for (size_t i = 0; i < MERKLE_FIELD_BITS; i++) {
        lc_add_term(&lc, bits_out[i], &coeff);
        fr_add(&coeff, &coeff, &coeff);
    }
    lc_add_term(&lc, var, &neg_one);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

void gadget_conditionally_reverse(struct constraint_system *cs,
                                  size_t a, size_t b, size_t cond,
                                  size_t *lo, size_t *hi)
{
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);

    const bool swap = (cond < cs->num_vars) && !fr_is_zero(&cs->witness[cond]);
    struct fr a_val, b_val;
    if (a < cs->num_vars) a_val = cs->witness[a]; else fr_zero(&a_val);
    if (b < cs->num_vars) b_val = cs->witness[b]; else fr_zero(&b_val);

    /* lo = cond ? b : a, as (a - b) * cond = a - lo. */
    struct fr lo_val = swap ? b_val : a_val;
    *lo = cs_alloc_aux(cs, &lo_val);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la);
        lc_add_term(&la, a, &one_val);
        lc_add_term(&la, b, &neg_one);
        lc_init(&lb);
        lc_add_term(&lb, cond, &one_val);
        lc_init(&lc);
        lc_add_term(&lc, a, &one_val);
        lc_add_term(&lc, *lo, &neg_one);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* hi = cond ? a : b, as (b - a) * cond = b - hi. */
    struct fr hi_val = swap ? a_val : b_val;
    *hi = cs_alloc_aux(cs, &hi_val);
    {
        struct linear_combination la, lb, lc;
        lc_init(&la);
        lc_add_term(&la, b, &one_val);
        lc_add_term(&la, a, &neg_one);
        lc_init(&lb);
        lc_add_term(&lb, cond, &one_val);
        lc_init(&lc);
        lc_add_term(&lc, b, &one_val);
        lc_add_term(&lc, *hi, &neg_one);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }
}

bool gadget_merkle_level(struct constraint_system *cs, size_t depth,
                         size_t cur, const uint8_t sibling[32],
                         bool cur_is_right,
                         size_t *next_out, size_t *position_bit_out)
{
    if (!next_out || !position_bit_out)
        LOG_FAIL("circuit_merkle",
                 "merkle_level: NULL output pointer at depth %zu", depth);
    *next_out = SIZE_MAX;
    *position_bit_out = SIZE_MAX;
    if (!cs || !sibling)
        LOG_FAIL("circuit_merkle",
                 "merkle_level: missing input at depth %zu (cs=%p sibling=%p)",
                 depth, (const void *)cs, (const void *)sibling);
    if (cur >= cs->num_vars)
        LOG_FAIL("circuit_merkle",
                 "merkle_level: running wire %zu out of range at depth %zu "
                 "(num_vars=%zu)", cur, depth, cs->num_vars);

    bool pers_bits[6];
    if (!gadget_pedersen_personalization_merkle_tree(depth, pers_bits))
        LOG_FAIL("circuit_merkle",
                 "merkle_level: no MerkleTree personalization for depth %zu",
                 depth);

    /* "position bit" — AllocatedBit::alloc. 1 constraint. Allocated even though
     * its value is public to the prover: it steers the swap below AND feeds
     * section 24's g^position, so it has to be a constrained wire, not a
     * compile-time branch. */
    const size_t pos = gadget_alloc_boolean(cs, cur_is_right);

    /* "path element" — AllocatedNum::alloc. 0 constraints: the sibling is
     * witnessed, and what binds it is the anchor the fold ends on. */
    struct fr path_fr;
    if (!fr_from_bytes(&path_fr, sibling))
        LOG_FAIL("circuit_merkle",
                 "merkle_level: authentication-path element at depth %zu is not "
                 "a canonical Fr element", depth);
    const size_t path_var = cs_alloc_aux(cs, &path_fr);

    /* "conditional reversal of preimage" — 2 constraints. */
    size_t xl, xr;
    gadget_conditionally_reverse(cs, cur, path_var, pos, &xl, &xr);

    /* "xl into bits" / "xr into bits" — 256 constraints each. */
    size_t preimage[MERKLE_PREIMAGE_BITS];
    gadget_into_bits_le(cs, xl, &preimage[0]);
    gadget_into_bits_le(cs, xr, &preimage[MERKLE_FIELD_BITS]);

    /* "computation of pedersen hash" — 867 constraints. The new running value
     * is the result's x-coordinate only; bellman's comment calls that an
     * injective encoding, so nothing is lost by dropping y. */
    size_t hash_x = SIZE_MAX, hash_y = SIZE_MAX;
    gadget_pedersen_hash_pers(cs, pers_bits, preimage, MERKLE_PREIMAGE_BITS,
                              &hash_x, &hash_y);
    memory_cleanse(preimage, sizeof(preimage));
    if (hash_x == SIZE_MAX || hash_y == SIZE_MAX)
        LOG_FAIL("circuit_merkle",
                 "merkle_level: Pedersen hash refused the %d-bit preimage at "
                 "depth %zu", MERKLE_PREIMAGE_BITS, depth);

    *next_out = hash_x;
    *position_bit_out = pos;
    return true;
}

bool gadget_merkle_auth_path(struct constraint_system *cs, size_t leaf_x,
                             const uint8_t auth_path[SAPLING_MERKLE_DEPTH][32],
                             const bool path_bits[SAPLING_MERKLE_DEPTH],
                             size_t *root_out,
                             size_t position_bits_out[SAPLING_MERKLE_DEPTH])
{
    if (!root_out)
        LOG_FAIL("circuit_merkle", "merkle_auth_path: NULL root_out");
    *root_out = SIZE_MAX;
    if (!cs || !auth_path || !path_bits || !position_bits_out)
        LOG_FAIL("circuit_merkle",
                 "merkle_auth_path: missing input (cs=%p auth_path=%p "
                 "path_bits=%p position_bits_out=%p)",
                 (const void *)cs, (const void *)auth_path,
                 (const void *)path_bits, (const void *)position_bits_out);

    for (size_t i = 0; i < SAPLING_MERKLE_DEPTH; i++)
        position_bits_out[i] = SIZE_MAX;

    size_t cur = leaf_x;
    for (size_t depth = 0; depth < SAPLING_MERKLE_DEPTH; depth++) {
        size_t next = SIZE_MAX, pos = SIZE_MAX;
        if (!gadget_merkle_level(cs, depth, cur, auth_path[depth],
                                 path_bits[depth], &next, &pos))
            LOG_FAIL("circuit_merkle",
                     "merkle_auth_path: level %zu of %d failed — the anchor "
                     "cannot be derived, so the spend proof would be for a "
                     "note in no tree", depth, SAPLING_MERKLE_DEPTH);
        position_bits_out[depth] = pos;
        cur = next;
    }

    *root_out = cur;
    return true;
}
