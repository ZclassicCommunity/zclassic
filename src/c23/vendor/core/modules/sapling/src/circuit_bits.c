/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ported from librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Reimplemented in
 * C23; no reference code is linked into the production binary.
 *
 * Faithful C23 port of bellman/sapling-crypto's Boolean / UInt32 / MultiEq
 * bit algebra and the blake2s circuit built on top of it (librustzcash commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5). See circuit_bits.h for why this
 * layer is structurally required rather than a convenience.
 *
 * Every function's constraint cost is pinned by the reference; the
 * `groth16_selfverify` test group asserts the resulting cumulative counts
 * against the reference trace, so a "harmless" restructuring here that changes
 * a cost will turn that gate red. */

#include "sapling/circuit_bits.h"
#include "sapling/circuit_gadgets.h"
#include "base/serialize_le.h"
#include "util/log_macros.h"

#include <string.h>

/* Index of the constant-ONE variable in every constraint system. */
#define CS_ONE 0

/* ── Boolean ─────────────────────────────────────────────────────── */

struct cbit cbit_constant(bool value)
{
    struct cbit b;
    memset(&b, 0, sizeof b);
    b.kind = CBIT_CONSTANT;
    b.constant = value;
    b.var = 0;
    return b;
}

struct cbit cbit_alloc(struct constraint_system *cs, bool value)
{
    struct fr val;
    if (value)
        fr_one(&val);
    else
        fr_zero(&val);

    struct cbit b;
    memset(&b, 0, sizeof b);
    b.kind = CBIT_IS;
    b.wire_value = value;
    b.var = cs_alloc_aux(cs, &val);

    /* bellman AllocatedBit::alloc — `(1 - a) * a = 0`. */
    struct linear_combination a, bb, c;
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);

    lc_init(&a);
    lc_add_term(&a, CS_ONE, &one_val);
    lc_add_term(&a, b.var, &neg_one);
    lc_init(&bb);
    lc_add_term(&bb, b.var, &one_val);
    lc_init(&c);

    cs_enforce(cs, &a, &bb, &c);

    lc_free(&a);
    lc_free(&bb);
    lc_free(&c);
    return b;
}

struct cbit cbit_from_var(const struct constraint_system *cs, size_t var)
{
    if (!cs || !cs->witness || var >= cs->num_vars) {
        /* Wrong-by-construction rather than an out-of-bounds read: the
         * R1CS-satisfaction gate cannot miss the resulting divergence. */
        LOG_ERROR("circuit_bits",
                "cbit_from_var: wire %zu out of range (num_vars=%zu)",
                var, cs ? cs->num_vars : (size_t)0);
        return cbit_constant(false);
    }
    struct fr one_val;
    fr_one(&one_val);

    struct cbit b;
    memset(&b, 0, sizeof b);
    b.kind = CBIT_IS;
    b.var = var;
    b.wire_value = fr_eq(&cs->witness[var], &one_val);
    return b;
}

struct cbit cbit_not(struct cbit b)
{
    switch (b.kind) {
    case CBIT_CONSTANT: b.constant = !b.constant; break;
    case CBIT_IS:       b.kind = CBIT_NOT;        break;
    default:            b.kind = CBIT_IS;         break;
    }
    return b;
}

bool cbit_value(struct cbit b)
{
    if (b.kind == CBIT_CONSTANT)
        return b.constant;
    if (b.kind == CBIT_NOT)
        return !b.wire_value;
    return b.wire_value;
}

/* bellman AllocatedBit::xor — `(a + a) * b = a + b - c`, over the UNDERLYING
 * wires of both operands. 1 constraint, 1 aux variable. The `a` term is added
 * twice rather than once with coefficient 2, matching the reference's literal
 * `lc + a.variable + a.variable`; linear-combination terms are summed at
 * evaluation, so this is arithmetically identical and textually faithful. */
static struct cbit alloc_bit_xor(struct constraint_system *cs,
                                 struct cbit a, struct cbit b)
{
    const bool result_wire = a.wire_value ^ b.wire_value;

    struct fr val;
    if (result_wire)
        fr_one(&val);
    else
        fr_zero(&val);

    struct cbit r;
    memset(&r, 0, sizeof r);
    r.kind = CBIT_IS;
    r.wire_value = result_wire;
    r.var = cs_alloc_aux(cs, &val);

    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);

    struct linear_combination la, lb, lc;
    lc_init(&la);
    lc_add_term(&la, a.var, &one_val);
    lc_add_term(&la, a.var, &one_val);
    lc_init(&lb);
    lc_add_term(&lb, b.var, &one_val);
    lc_init(&lc);
    lc_add_term(&lc, a.var, &one_val);
    lc_add_term(&lc, b.var, &one_val);
    lc_add_term(&lc, r.var, &neg_one);

    cs_enforce(cs, &la, &lb, &lc);

    lc_free(&la);
    lc_free(&lb);
    lc_free(&lc);
    return r;
}

struct cbit cbit_xor(struct constraint_system *cs, struct cbit a, struct cbit b)
{
    /* (Constant(false), x) | (x, Constant(false)) -> x */
    if (a.kind == CBIT_CONSTANT && !a.constant)
        return b;
    if (b.kind == CBIT_CONSTANT && !b.constant)
        return a;
    /* (Constant(true), x) | (x, Constant(true)) -> x.not() */
    if (a.kind == CBIT_CONSTANT)
        return cbit_not(b);
    if (b.kind == CBIT_CONSTANT)
        return cbit_not(a);

    /* Both allocated. bellman normalizes `Is ^ Not` to `Is ^ Is` and then
     * negates the RESULT view, so exactly one allocated constraint is emitted
     * whatever the mix of views: (Is,Is) and (Not,Not) give Is(c),
     * (Is,Not) and (Not,Is) give Not(c).
     *
     * THE NORMALIZATION ALSO REORDERS THE OPERANDS, and that is not cosmetic.
     * bellman's mixed-view arm is
     *
     *     (is @ &Is(_), not @ &Not(_)) | (not @ &Not(_), is @ &Is(_))
     *         => Boolean::xor(cs, is, &not.not())?.not()
     *
     * so the `Is` operand always becomes the FIRST argument of the recursive
     * call. For an original `(Not, Is)` pair that swaps the two operands before
     * they reach AllocatedBit::xor — and AllocatedBit::xor is asymmetric in the
     * MATRICES it writes: it emits `(a + a) * b = a + b - c`, putting the
     * doubled term in A and the bare term in B. A*B is commutative, so swapping
     * the operands leaves every A*B==C check satisfied while writing a
     * different pair of QAP matrices, which cannot verify against the Sapling
     * trusted setup. Pinned by test_groth16_r1cs_oracle.
     *
     * (Is,Is) and (Not,Not) hit bellman's other arm, which preserves the order,
     * and (Is,Not) already binds is=a, so only (Not,Is) needs the swap. */
    const bool negate_result = (a.kind != b.kind);
    const bool swap_operands = (a.kind == CBIT_NOT && b.kind == CBIT_IS);
    struct cbit r = swap_operands ? alloc_bit_xor(cs, b, a)
                                  : alloc_bit_xor(cs, a, b);
    return negate_result ? cbit_not(r) : r;
}

void cbit_lc_add(struct linear_combination *lc, struct cbit b,
                 const struct fr *coeff)
{
    if (b.kind == CBIT_CONSTANT) {
        if (b.constant)
            lc_add_term(lc, CS_ONE, coeff);
        return;
    }
    if (b.kind == CBIT_IS) {
        lc_add_term(lc, b.var, coeff);
        return;
    }
    /* Not(v) == 1 - v */
    struct fr neg;
    fr_neg(&neg, coeff);
    lc_add_term(lc, CS_ONE, coeff);
    lc_add_term(lc, b.var, &neg);
}

/* ── UInt32 ──────────────────────────────────────────────────────── */

struct cu32 cu32_constant(uint32_t value)
{
    struct cu32 w;
    for (size_t i = 0; i < 32; i++)
        w.bits[i] = cbit_constant(((value >> i) & 1u) == 1u);
    return w;
}

struct cu32 cu32_from_bits_le(const struct cbit bits[32])
{
    struct cu32 w;
    for (size_t i = 0; i < 32; i++)
        w.bits[i] = bits[i];
    return w;
}

struct cu32 cu32_rotr(const struct cu32 *a, unsigned by)
{
    by %= 32u;
    struct cu32 w;
    for (size_t i = 0; i < 32; i++)
        w.bits[i] = a->bits[(i + by) % 32u];
    return w;
}

struct cu32 cu32_xor(struct constraint_system *cs,
                     const struct cu32 *a, const struct cu32 *b)
{
    struct cu32 w;
    for (size_t i = 0; i < 32; i++)
        w.bits[i] = cbit_xor(cs, a->bits[i], b->bits[i]);
    return w;
}

/* ── MultiEq ─────────────────────────────────────────────────────── */

void multieq_init(struct multieq *m, struct constraint_system *cs)
{
    m->cs = cs;
    m->bits_used = 0;
    m->ops = 0;
    lc_init(&m->lhs);
    lc_init(&m->rhs);
}

/* bellman MultiEq::accumulate — one constraint `lhs * 1 = rhs`. */
static void multieq_accumulate(struct multieq *m)
{
    struct fr one_val;
    fr_one(&one_val);

    struct linear_combination b;
    lc_init(&b);
    lc_add_term(&b, CS_ONE, &one_val);

    cs_enforce(m->cs, &m->lhs, &b, &m->rhs);

    lc_free(&b);
    lc_free(&m->lhs);
    lc_free(&m->rhs);
    lc_init(&m->lhs);
    lc_init(&m->rhs);
    m->bits_used = 0;
    m->ops++;
}

/* dst += coeff * src (bellman's `LinearCombination + (Fr, &LinearCombination)`,
 * which scales and APPENDS every term — duplicates are legal and summed). */
static void lc_add_scaled(struct linear_combination *dst,
                          const struct linear_combination *src,
                          const struct fr *coeff)
{
    for (size_t i = 0; i < src->num_terms; i++) {
        struct fr scaled;
        fr_mul(&scaled, coeff, &src->terms[i].coeff);
        lc_add_term(dst, src->terms[i].var, &scaled);
    }
}

void multieq_enforce_equal(struct multieq *m, size_t num_bits,
                           const struct linear_combination *lhs,
                           const struct linear_combination *rhs)
{
    if ((size_t)CBIT_FR_CAPACITY <= m->bits_used + num_bits)
        multieq_accumulate(m);

    /* coeff = 2^bits_used */
    struct fr coeff;
    fr_one(&coeff);
    for (size_t i = 0; i < m->bits_used; i++)
        fr_add(&coeff, &coeff, &coeff);

    lc_add_scaled(&m->lhs, lhs, &coeff);
    lc_add_scaled(&m->rhs, rhs, &coeff);
    m->bits_used += num_bits;
}

void multieq_finish(struct multieq *m)
{
    if (m->bits_used > 0)
        multieq_accumulate(m);
    lc_free(&m->lhs);
    lc_free(&m->rhs);
    m->bits_used = 0;
}

struct cu32 cu32_addmany(struct multieq *m, const struct cu32 *ops,
                         size_t n_ops)
{
    /* bellman's own bounds: fewer than 2 operands is a trivial case that never
     * happens, and more than 10 would overflow the packing budget. */
    if (n_ops < 2 || n_ops > 10) {
        LOG_ERROR("circuit_bits", "cu32_addmany: n_ops=%zu outside [2,10]", n_ops);
        return cu32_constant(0);
    }

    uint64_t max_value = (uint64_t)n_ops * (uint64_t)UINT32_MAX;
    uint64_t result_value = 0;
    bool all_constants = true;

    struct linear_combination lc;
    lc_init(&lc);

    for (size_t o = 0; o < n_ops; o++) {
        uint32_t opval = 0;
        struct fr coeff;
        fr_one(&coeff);
        for (size_t i = 0; i < 32; i++) {
            const struct cbit bit = ops[o].bits[i];
            if (cbit_value(bit))
                opval |= (uint32_t)1u << i;
            cbit_lc_add(&lc, bit, &coeff);
            if (bit.kind != CBIT_CONSTANT)
                all_constants = false;
            fr_add(&coeff, &coeff, &coeff);
        }
        result_value += (uint64_t)opval;
    }

    if (all_constants) {
        /* No allocated wires anywhere in the sum: fold to a constant word and
         * emit nothing at all. This branch is what makes blake2s's first
         * mixing round cheaper than the other nine. */
        lc_free(&lc);
        return cu32_constant((uint32_t)result_value);
    }

    /* Allocate one wire per bit of the maximum possible sum (33 wires for two
     * operands, 34 for three) — the carries above bit 31 are allocated and
     * constrained even though the word truncates them away. */
    struct cbit result_bits[40];
    struct linear_combination result_lc;
    lc_init(&result_lc);

    struct fr coeff;
    fr_one(&coeff);
    size_t nbits = 0;
    while (max_value != 0 && nbits < 40) {
        struct cbit b = cbit_alloc(m->cs,
                                   ((result_value >> nbits) & 1u) == 1u);
        lc_add_term(&result_lc, b.var, &coeff);
        result_bits[nbits] = b;
        max_value >>= 1;
        nbits++;
        fr_add(&coeff, &coeff, &coeff);
    }

    multieq_enforce_equal(m, nbits, &lc, &result_lc);

    lc_free(&lc);
    lc_free(&result_lc);

    struct cu32 out;
    for (size_t i = 0; i < 32; i++)
        out.bits[i] = result_bits[i];
    return out;
}

/* ── blake2s ─────────────────────────────────────────────────────── */

/* BLAKE2s rotation constants (RFC 7693 §2.1). */
#define BLAKE2S_R1 16u
#define BLAKE2S_R2 12u
#define BLAKE2S_R3  8u
#define BLAKE2S_R4  7u

static const uint8_t BLAKE2S_SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

static const uint32_t BLAKE2S_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

/* RFC 7693 §3.1 mixing function G, over the MultiEq-wrapped system so that all
 * four modular additions in one G share the equality batch. */
static void mixing_g(struct multieq *m, struct cu32 v[16],
                     size_t a, size_t b, size_t c, size_t d,
                     const struct cu32 *x, const struct cu32 *y)
{
    struct cu32 ops3[3], ops2[2], tmp;

    ops3[0] = v[a]; ops3[1] = v[b]; ops3[2] = *x;
    v[a] = cu32_addmany(m, ops3, 3);

    tmp = cu32_xor(m->cs, &v[d], &v[a]);
    v[d] = cu32_rotr(&tmp, BLAKE2S_R1);

    ops2[0] = v[c]; ops2[1] = v[d];
    v[c] = cu32_addmany(m, ops2, 2);

    tmp = cu32_xor(m->cs, &v[b], &v[c]);
    v[b] = cu32_rotr(&tmp, BLAKE2S_R2);

    ops3[0] = v[a]; ops3[1] = v[b]; ops3[2] = *y;
    v[a] = cu32_addmany(m, ops3, 3);

    tmp = cu32_xor(m->cs, &v[d], &v[a]);
    v[d] = cu32_rotr(&tmp, BLAKE2S_R3);

    ops2[0] = v[c]; ops2[1] = v[d];
    v[c] = cu32_addmany(m, ops2, 2);

    tmp = cu32_xor(m->cs, &v[b], &v[c]);
    v[b] = cu32_rotr(&tmp, BLAKE2S_R4);
}

/* RFC 7693 §3.2 compression function F. */
static void blake2s_compression(struct constraint_system *cs,
                                struct cu32 h[8], const struct cu32 m[16],
                                uint64_t t, bool f)
{
    struct cu32 v[16];
    for (size_t i = 0; i < 8; i++)
        v[i] = h[i];
    for (size_t i = 0; i < 8; i++)
        v[8 + i] = cu32_constant(BLAKE2S_IV[i]);

    struct cu32 tmp;

    tmp = cu32_constant((uint32_t)t);
    v[12] = cu32_xor(cs, &v[12], &tmp);
    tmp = cu32_constant((uint32_t)(t >> 32));
    v[13] = cu32_xor(cs, &v[13], &tmp);
    if (f) {
        tmp = cu32_constant(UINT32_MAX);
        v[14] = cu32_xor(cs, &v[14], &tmp);
    }

    {
        /* One MultiEq spans all ten rounds — its flush schedule (and therefore
         * the exact number of batching constraints) depends on that. */
        struct multieq meq;
        multieq_init(&meq, cs);

        for (size_t r = 0; r < 10; r++) {
            const uint8_t *s = BLAKE2S_SIGMA[r];
            mixing_g(&meq, v, 0, 4,  8, 12, &m[s[ 0]], &m[s[ 1]]);
            mixing_g(&meq, v, 1, 5,  9, 13, &m[s[ 2]], &m[s[ 3]]);
            mixing_g(&meq, v, 2, 6, 10, 14, &m[s[ 4]], &m[s[ 5]]);
            mixing_g(&meq, v, 3, 7, 11, 15, &m[s[ 6]], &m[s[ 7]]);
            mixing_g(&meq, v, 0, 5, 10, 15, &m[s[ 8]], &m[s[ 9]]);
            mixing_g(&meq, v, 1, 6, 11, 12, &m[s[10]], &m[s[11]]);
            mixing_g(&meq, v, 2, 7,  8, 13, &m[s[12]], &m[s[13]]);
            mixing_g(&meq, v, 3, 4,  9, 14, &m[s[14]], &m[s[15]]);
        }

        /* bellman drops the MultiEq HERE, before the halves are folded back
         * into h — the trailing flush therefore precedes those XORs. */
        multieq_finish(&meq);
    }

    for (size_t i = 0; i < 8; i++) {
        h[i] = cu32_xor(cs, &h[i], &v[i]);
        h[i] = cu32_xor(cs, &h[i], &v[i + 8]);
    }
}

/* Fill m[0..15] from input bits at block bi, using constant false past n_bits. */
static void blake2s_load_message_block(struct cu32 m[16],
                                       const struct cbit *input,
                                       size_t n_bits, size_t bi)
{
    for (size_t w = 0; w < 16; w++) {
        struct cbit word[32];
        for (size_t j = 0; j < 32; j++) {
            const size_t idx = bi * 512u + w * 32u + j;
            word[j] = (idx < n_bits) ? input[idx] : cbit_constant(false);
        }
        m[w] = cu32_from_bits_le(word);
    }
}

/* Copy h[0..7].bits into out[0..255] in that order. */
static void blake2s_write_digest_bits(struct cbit out[256],
                                      const struct cu32 h[8])
{
    for (size_t i = 0; i < 8; i++)
        for (size_t j = 0; j < 32; j++)
            out[i * 32u + j] = h[i].bits[j];
}

bool gadget_blake2s(struct constraint_system *cs,
                    const struct cbit *input, size_t n_bits,
                    const uint8_t personalization[8],
                    struct cbit out[256])
{
    if (!cs || !personalization || !out)
        LOG_FAIL("circuit_bits", "gadget_blake2s: NULL argument");
    if (n_bits % 8u != 0)
        LOG_FAIL("circuit_bits",
                 "gadget_blake2s: n_bits=%zu is not a whole number of bytes",
                 n_bits);
    if (n_bits > 0 && !input)
        LOG_FAIL("circuit_bits",
                 "gadget_blake2s: n_bits=%zu with NULL input", n_bits);

    /* Parameter block: digest length 32, no key, personalization in the last
     * two state words (RFC 7693 §2.8, as bellman applies it). */
    struct cu32 h[8];
    h[0] = cu32_constant(BLAKE2S_IV[0] ^ 0x01010000u ^ 32u);
    for (size_t i = 1; i < 6; i++)
        h[i] = cu32_constant(BLAKE2S_IV[i]);
    h[6] = cu32_constant(BLAKE2S_IV[6] ^ zcl_read_u32_le(&personalization[0]));
    h[7] = cu32_constant(BLAKE2S_IV[7] ^ zcl_read_u32_le(&personalization[4]));

    size_t n_blocks = (n_bits + 511u) / 512u;
    if (n_blocks == 0)
        n_blocks = 1;  /* the empty input still runs one all-zero final block */

    for (size_t bi = 0; bi < n_blocks; bi++) {
        struct cu32 m[16];
        blake2s_load_message_block(m, input, n_bits, bi);

        const bool last = (bi + 1u == n_blocks);
        /* Counter: full blocks so far for a non-final block, total input BYTES
         * for the final one. */
        const uint64_t t = last ? (uint64_t)(n_bits / 8u)
                                : ((uint64_t)bi + 1u) * 64u;
        blake2s_compression(cs, h, m, t, last);
    }

    blake2s_write_digest_bits(out, h);

    return true;
}

/* ── Boolean-driven Jubjub scalar multiplication ─────────────────── */

void gadget_conditionally_select_point_cbit(struct constraint_system *cs,
                                            struct cbit cond,
                                            size_t px, size_t py,
                                            size_t *rx, size_t *ry)
{
    struct fr one_val;
    fr_one(&one_val);
    struct linear_combination cond_lc;
    lc_init(&cond_lc);
    cbit_lc_add(&cond_lc, cond, &one_val);
    gadget_conditionally_select_point_lc(cs, &cond_lc, cbit_value(cond),
                                        px, py, rx, ry);
    lc_free(&cond_lc);
}

void gadget_variable_base_mul_cbits(struct constraint_system *cs,
                                    size_t base_x, size_t base_y,
                                    const struct cbit *scalar_bits,
                                    size_t n_bits,
                                    size_t *out_x, size_t *out_y)
{
    *out_x = SIZE_MAX;
    *out_y = SIZE_MAX;
    if (!scalar_bits || n_bits == 0) {
        LOG_ERROR("circuit_bits",
                  "variable_base_mul_cbits: empty scalar (bits=%p n_bits=%zu) "
                  "— refusing to return a point",
                  (const void *)scalar_bits, n_bits);
        return;
    }

    /* `cur` walks 1*P, 2*P, 4*P, ...; `acc` accumulates the selected multiples.
     * bellman skips the doubling on bit 0 and the addition on the first
     * selected point — that is where the -11 in 13n-11 comes from. */
    size_t cur_x = base_x, cur_y = base_y;
    size_t acc_x = SIZE_MAX, acc_y = SIZE_MAX;

    for (size_t i = 0; i < n_bits; i++) {
        if (i > 0) {
            size_t dbl_x, dbl_y;
            gadget_edwards_double(cs, cur_x, cur_y, &dbl_x, &dbl_y);
            cur_x = dbl_x;
            cur_y = dbl_y;
        }

        size_t sel_x, sel_y;
        gadget_conditionally_select_point_cbit(cs, scalar_bits[i],
                                              cur_x, cur_y, &sel_x, &sel_y);

        if (acc_x == SIZE_MAX) {
            acc_x = sel_x;
            acc_y = sel_y;
        } else {
            size_t new_x, new_y;
            gadget_edwards_add(cs, acc_x, acc_y, sel_x, sel_y,
                               &new_x, &new_y);
            acc_x = new_x;
            acc_y = new_y;
        }
    }

    *out_x = acc_x;
    *out_y = acc_y;
}
