/* Copyright 2026 The Zclassic developers - MIT License
 *
 * Sprout JoinSplit circuit (see sprout_circuit.h). Constraint-for-constraint
 * port of sapling-crypto circuit::{sprout, sha256, uint32, boolean} at
 * librustzcash 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5. Every function names
 * the Rust function it mirrors; allocation and constraint ORDER inside each is
 * load-bearing, because the Groth16 proving key is indexed by variable and by
 * constraint row. */

#include "sprout_circuit.h"

#include "sapling/circuit_bits.h"
#include "sapling/fr.h"
#include "sapling/bls12_381.h"

#include "support/cleanse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CS_ONE 0u

struct sp_ctx {
    struct constraint_system *cs;
    struct fr one;
    struct fr neg_one;
    size_t shrunk; /* rows below this index already compacted */
};

/* Release the slack in every row's term arrays (Z23's lc_add_term grows by
 * doubling from 8, so a 1-term LC holds 8 slots). Purely a memory change:
 * terms and their order are untouched. A failed shrinking realloc keeps the
 * original block, which is still valid. */
static void sp_shrink_lc(struct linear_combination *lc)
{
    if (lc->cap <= lc->num_terms)
        return;
    if (lc->num_terms == 0) {
        free(lc->terms);
        lc->terms = NULL;
        lc->cap = 0;
        return;
    }
    /* allocate-copy-free, not realloc: glibc shrinks in place and leaves a
     * hole the next 8-slot LC cannot use; a freed 8-slot block is reused by
     * the very next row instead. */
    struct lc_term *t = malloc(lc->num_terms * sizeof *t);
    if (t) {
        memcpy(t, lc->terms, lc->num_terms * sizeof *t);
        free(lc->terms);
        lc->terms = t;
        lc->cap = lc->num_terms;
    }
}

static void sp_shrink(struct sp_ctx *x)
{
    struct constraint_system *cs = x->cs;
    for (size_t i = x->shrunk; i < cs->num_constraints; i++) {
        sp_shrink_lc(&cs->constraints[i].a);
        sp_shrink_lc(&cs->constraints[i].b);
        sp_shrink_lc(&cs->constraints[i].c);
    }
    x->shrunk = cs->num_constraints;
}

/* ── small LC helpers ─────────────────────────────────────────────── */

static void sp_lc_bit(struct linear_combination *lc, struct cbit b,
                      const struct fr *coeff)
{
    cbit_lc_add(lc, b, coeff);
}

static void sp_enforce(struct sp_ctx *x, struct linear_combination *a,
                       struct linear_combination *b,
                       struct linear_combination *c)
{
    (void)cs_enforce(x->cs, a, b, c);
    lc_free(a);
    lc_free(b);
    lc_free(c);
}

/* Branch-free bit select: c ? a : b. */
static inline bool sp_sel(bool c, bool a, bool b)
{
    return (bool)((c & a) | (!c & b));
}

/* Branch-free 0/1 field element (witness values are secret). */
static void sp_fr_from_bit(const struct sp_ctx *x, bool value, struct fr *v)
{
    uint64_t mask = (uint64_t)0 - (uint64_t)value;
    for (size_t i = 0; i < 4; i++)
        v->d[i] = x->one.d[i] & mask;
}

/* bellman cs.alloc of a bit-valued wire with NO booleanity constraint (the
 * results of AllocatedBit::{xor, and, and_not, nor}, sha256_ch and maj). */
static struct cbit sp_alloc_plain(struct sp_ctx *x, bool value)
{
    struct fr v;
    sp_fr_from_bit(x, value, &v);
    struct cbit r;
    memset(&r, 0, sizeof r);
    r.kind = CBIT_IS;
    r.wire_value = value;
    r.var = cs_alloc_aux(x->cs, &v);
    return r;
}

/* AllocatedBit::alloc — the wire plus `(1 - a) * a = 0`. Same rows as the
 * vendored cbit_alloc, but its witness value is set without a branch. */
static struct cbit sp_alloc_bit(struct sp_ctx *x, bool value)
{
    struct cbit b = sp_alloc_plain(x, value);
    struct linear_combination la, lb, lc;
    lc_init(&la);
    lc_init(&lb);
    lc_init(&lc);
    lc_add_term(&la, CS_ONE, &x->one);
    lc_add_term(&la, b.var, &x->neg_one);
    lc_add_term(&lb, b.var, &x->one);
    sp_enforce(x, &la, &lb, &lc);
    return b;
}

/* ── AllocatedBit::{and, and_not, nor} ────────────────────────────── */

enum sp_andk { SP_AND, SP_AND_NOT, SP_NOR };

static struct cbit sp_allocated_and(struct sp_ctx *x, enum sp_andk k,
                                    struct cbit a, struct cbit b)
{
    /* a, b are allocated; their UNDERLYING wires are used. */
    bool av = a.wire_value, bv = b.wire_value;
    bool rv = (k == SP_AND) ? (av & bv)
            : (k == SP_AND_NOT) ? (av & !bv) : (!av & !bv);
    struct cbit r = sp_alloc_plain(x, rv);

    struct linear_combination la, lb, lc;
    lc_init(&la);
    lc_init(&lb);
    lc_init(&lc);
    if (k == SP_NOR) {
        lc_add_term(&la, CS_ONE, &x->one);
        lc_add_term(&la, a.var, &x->neg_one);
    } else {
        lc_add_term(&la, a.var, &x->one);
    }
    if (k == SP_AND) {
        lc_add_term(&lb, b.var, &x->one);
    } else {
        lc_add_term(&lb, CS_ONE, &x->one);
        lc_add_term(&lb, b.var, &x->neg_one);
    }
    lc_add_term(&lc, r.var, &x->one);
    sp_enforce(x, &la, &lb, &lc);
    return r;
}

/* Boolean::and */
static struct cbit sp_and(struct sp_ctx *x, struct cbit a, struct cbit b)
{
    if ((a.kind == CBIT_CONSTANT && !a.constant) ||
        (b.kind == CBIT_CONSTANT && !b.constant))
        return cbit_constant(false);
    if (a.kind == CBIT_CONSTANT)
        return b;
    if (b.kind == CBIT_CONSTANT)
        return a;
    if (a.kind == CBIT_IS && b.kind == CBIT_NOT)
        return sp_allocated_and(x, SP_AND_NOT, a, b);
    if (a.kind == CBIT_NOT && b.kind == CBIT_IS)
        return sp_allocated_and(x, SP_AND_NOT, b, a);
    if (a.kind == CBIT_NOT && b.kind == CBIT_NOT)
        return sp_allocated_and(x, SP_NOR, a, b);
    return sp_allocated_and(x, SP_AND, a, b);
}

static bool sp_is_const(struct cbit b, bool v)
{
    return b.kind == CBIT_CONSTANT && b.constant == v;
}

/* Boolean::sha256_ch — (a and b) xor ((not a) and c) */
static struct cbit sp_ch(struct sp_ctx *x, struct cbit a, struct cbit b,
                         struct cbit c)
{
    bool av = cbit_value(a), bv = cbit_value(b), cv = cbit_value(c);
    bool chv = (av & bv) ^ (!av & cv);

    if (a.kind == CBIT_CONSTANT && b.kind == CBIT_CONSTANT &&
        c.kind == CBIT_CONSTANT)
        return cbit_constant(chv);
    if (sp_is_const(a, false))
        return c;
    if (sp_is_const(b, false))
        return sp_and(x, cbit_not(a), c);
    if (sp_is_const(c, false))
        return sp_and(x, a, b);
    if (sp_is_const(c, true))
        return cbit_not(sp_and(x, a, cbit_not(b)));
    if (sp_is_const(b, true))
        return cbit_not(sp_and(x, cbit_not(a), cbit_not(c)));
    /* a constant true, or all allocated: the general gate. */

    struct cbit ch = sp_alloc_plain(x, chv);
    struct linear_combination la, lb, lc;
    lc_init(&la);
    lc_init(&lb);
    lc_init(&lc);
    /* a(b - c) = ch - c */
    sp_lc_bit(&la, b, &x->one);
    sp_lc_bit(&la, c, &x->neg_one);
    sp_lc_bit(&lb, a, &x->one);
    lc_add_term(&lc, ch.var, &x->one);
    sp_lc_bit(&lc, c, &x->neg_one);
    sp_enforce(x, &la, &lb, &lc);
    return ch;
}

/* Boolean::sha256_maj — (a and b) xor (a and c) xor (b and c) */
static struct cbit sp_maj(struct sp_ctx *x, struct cbit a, struct cbit b,
                          struct cbit c)
{
    bool av = cbit_value(a), bv = cbit_value(b), cv = cbit_value(c);
    bool majv = (av & bv) ^ (av & cv) ^ (bv & cv);

    if (a.kind == CBIT_CONSTANT && b.kind == CBIT_CONSTANT &&
        c.kind == CBIT_CONSTANT)
        return cbit_constant(majv);
    if (sp_is_const(a, false))
        return sp_and(x, b, c);
    if (sp_is_const(b, false))
        return sp_and(x, a, c);
    if (sp_is_const(c, false))
        return sp_and(x, a, b);
    if (sp_is_const(c, true))
        return cbit_not(sp_and(x, cbit_not(a), cbit_not(b)));
    if (sp_is_const(b, true))
        return cbit_not(sp_and(x, cbit_not(a), cbit_not(c)));
    if (sp_is_const(a, true))
        return cbit_not(sp_and(x, cbit_not(b), cbit_not(c)));

    /* maj is allocated BEFORE b-and-c (bellman order). */
    struct cbit maj = sp_alloc_plain(x, majv);
    struct cbit bc = sp_and(x, b, c);

    struct linear_combination la, lb, lc;
    lc_init(&la);
    lc_init(&lb);
    lc_init(&lc);
    /* (2bc - b - c) * a = bc - maj */
    sp_lc_bit(&la, bc, &x->one);
    sp_lc_bit(&la, bc, &x->one);
    sp_lc_bit(&la, b, &x->neg_one);
    sp_lc_bit(&la, c, &x->neg_one);
    sp_lc_bit(&lb, a, &x->one);
    sp_lc_bit(&lc, bc, &x->one);
    lc_add_term(&lc, maj.var, &x->neg_one);
    sp_enforce(x, &la, &lb, &lc);
    return maj;
}

/* ── UInt32 helpers missing from circuit_bits ────────────────────── */

static struct cu32 sp_from_bits_be(const struct cbit *bits)
{
    struct cu32 w;
    for (size_t i = 0; i < 32; i++)
        w.bits[i] = bits[31 - i];
    return w;
}

static void sp_into_bits_be(const struct cu32 *w, struct cbit *out)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = w->bits[31 - i];
}

static struct cu32 sp_shr(const struct cu32 *a, unsigned by)
{
    struct cu32 w;
    for (size_t i = 0; i < 32; i++)
        w.bits[i] = (i + by < 32) ? a->bits[i + by] : cbit_constant(false);
    return w;
}

static struct cu32 sp_xor3_rot(struct sp_ctx *x, const struct cu32 *v,
                               unsigned r1, unsigned r2, unsigned r3,
                               bool third_is_shift)
{
    struct cu32 t = cu32_rotr(v, r1);
    struct cu32 u = cu32_rotr(v, r2);
    t = cu32_xor(x->cs, &t, &u);
    u = third_is_shift ? sp_shr(v, r3) : cu32_rotr(v, r3);
    return cu32_xor(x->cs, &t, &u);
}

static struct cu32 sp_triop(struct sp_ctx *x, bool is_maj,
                            const struct cu32 *a, const struct cu32 *b,
                            const struct cu32 *c)
{
    struct cu32 w;
    for (size_t i = 0; i < 32; i++)
        w.bits[i] = is_maj ? sp_maj(x, a->bits[i], b->bits[i], c->bits[i])
                           : sp_ch(x, a->bits[i], b->bits[i], c->bits[i]);
    return w;
}

/* ── sha256 compression (sapling-crypto circuit::sha256) ─────────── */

static const uint32_t SP_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint32_t SP_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/* sha256's `Maybe`: either a concrete word or a deferred list of addends. */
struct sp_maybe {
    bool concrete;
    struct cu32 value;
    struct cu32 ops[8];
    size_t n_ops;
};

static struct cu32 sp_maybe_compute(struct multieq *m, const struct sp_maybe *v,
                                    const struct cu32 *other)
{
    if (v->concrete)
        return v->value; /* bellman ignores `others` for Concrete */
    struct cu32 ops[9];
    size_t n = v->n_ops;
    memcpy(ops, v->ops, n * sizeof ops[0]);
    if (other)
        ops[n++] = *other;
    return cu32_addmany(m, ops, n);
}

static void sp_sha256_compression(struct sp_ctx *x, const struct cbit *input,
                                  const struct cu32 cur[8], struct cu32 out[8])
{
    struct cu32 w[64];
    for (size_t i = 0; i < 16; i++)
        w[i] = sp_from_bits_be(input + 32 * i);

    struct multieq m;
    multieq_init(&m, x->cs);

    for (size_t i = 16; i < 64; i++) {
        struct cu32 s0 = sp_xor3_rot(x, &w[i - 15], 7, 18, 3, true);
        struct cu32 s1 = sp_xor3_rot(x, &w[i - 2], 17, 19, 10, true);
        struct cu32 ops[4] = { w[i - 16], s0, w[i - 7], s1 };
        w[i] = cu32_addmany(&m, ops, 4);
    }

    struct sp_maybe a = { .concrete = true, .value = cur[0] };
    struct cu32 b = cur[1], c = cur[2], d = cur[3];
    struct sp_maybe e = { .concrete = true, .value = cur[4] };
    struct cu32 f = cur[5], g = cur[6], h = cur[7];

    for (size_t i = 0; i < 64; i++) {
        struct cu32 new_e = sp_maybe_compute(&m, &e, NULL);
        struct cu32 s1 = sp_xor3_rot(x, &new_e, 6, 11, 25, false);
        struct cu32 ch = sp_triop(x, false, &new_e, &f, &g);
        struct cu32 temp1[5] = { h, s1, ch, cu32_constant(SP_K[i]), w[i] };

        struct cu32 new_a = sp_maybe_compute(&m, &a, NULL);
        struct cu32 s0 = sp_xor3_rot(x, &new_a, 2, 13, 22, false);
        struct cu32 maj = sp_triop(x, true, &new_a, &b, &c);

        h = g;
        g = f;
        f = new_e;
        e.concrete = false;
        memcpy(e.ops, temp1, sizeof temp1);
        e.ops[5] = d;
        e.n_ops = 6;
        d = c;
        c = b;
        b = new_a;
        a.concrete = false;
        memcpy(a.ops, temp1, sizeof temp1);
        a.ops[5] = s0;
        a.ops[6] = maj;
        a.n_ops = 7;
    }

    out[0] = sp_maybe_compute(&m, &a, &cur[0]);
    struct cu32 pair[2];
    pair[0] = cur[1]; pair[1] = b; out[1] = cu32_addmany(&m, pair, 2);
    pair[0] = cur[2]; pair[1] = c; out[2] = cu32_addmany(&m, pair, 2);
    pair[0] = cur[3]; pair[1] = d; out[3] = cu32_addmany(&m, pair, 2);
    out[4] = sp_maybe_compute(&m, &e, &cur[4]);
    pair[0] = cur[5]; pair[1] = f; out[5] = cu32_addmany(&m, pair, 2);
    pair[0] = cur[6]; pair[1] = g; out[6] = cu32_addmany(&m, pair, 2);
    pair[0] = cur[7]; pair[1] = h; out[7] = cu32_addmany(&m, pair, 2);

    /* bellman's Drop for MultiEq: flush at the end of the function. */
    multieq_finish(&m);
    sp_shrink(x);
}

static void sp_iv(struct cu32 iv[8])
{
    for (size_t i = 0; i < 8; i++)
        iv[i] = cu32_constant(SP_IV[i]);
}

/* sha256_block_no_padding */
static void sp_sha256_block(struct sp_ctx *x, const struct cbit in[512],
                            struct cbit out[256])
{
    struct cu32 iv[8], h[8];
    sp_iv(iv);
    sp_sha256_compression(x, in, iv, h);
    for (size_t i = 0; i < 8; i++)
        sp_into_bits_be(&h[i], out + 32 * i);
}

/* sha256 with standard padding; n_bits % 8 == 0 and n_bits <= 1024 - 65. */
static bool sp_sha256(struct sp_ctx *x, const struct cbit *in, size_t n_bits,
                      struct cbit out[256])
{
    struct cbit padded[1024];
    if (n_bits % 8 != 0 || n_bits + 65 > 1024)
        return false;
    size_t n = 0;
    for (; n < n_bits; n++)
        padded[n] = in[n];
    padded[n++] = cbit_constant(true);
    while ((n + 64) % 512 != 0)
        padded[n++] = cbit_constant(false);
    for (int i = 63; i >= 0; i--)
        padded[n++] = cbit_constant((((uint64_t)n_bits) >> i) & 1u);

    struct cu32 cur[8], next[8];
    sp_iv(cur);
    for (size_t blk = 0; blk < n / 512; blk++) {
        sp_sha256_compression(x, padded + 512 * blk, cur, next);
        memcpy(cur, next, sizeof cur);
    }
    for (size_t i = 0; i < 8; i++)
        sp_into_bits_be(&cur[i], out + 32 * i);
    return true;
}

/* ── sprout gadgets ───────────────────────────────────────────────── */

/* witness_bits: bytes MSB-first, skipping the first `skip` bits. */
static void sp_witness_bits(struct sp_ctx *x, const uint8_t *bytes,
                            size_t num_bits, size_t skip, struct cbit *out)
{
    for (size_t i = 0; i < num_bits; i++) {
        size_t bit = i + skip;
        bool v = ((bytes[bit / 8] >> (7 - bit % 8)) & 1u) != 0;
        out[i] = sp_alloc_bit(x, v);
    }
}

struct sp_note_value {
    uint64_t value;
    struct cbit bits[64]; /* least significant first */
};

static void sp_note_value(struct sp_ctx *x, uint64_t value,
                          struct sp_note_value *nv)
{
    nv->value = value;
    for (size_t i = 0; i < 64; i++)
        nv->bits[i] = sp_alloc_bit(x, ((value >> i) & 1u) != 0);
}

static void sp_note_value_bits_le(const struct sp_note_value *nv,
                                  struct cbit out[64])
{
    size_t k = 0;
    for (size_t chunk = 0; chunk < 8; chunk++)
        for (int j = 7; j >= 0; j--)
            out[k++] = nv->bits[chunk * 8 + (size_t)j];
}

static void sp_note_value_lc(const struct sp_note_value *nv,
                             struct linear_combination *lc)
{
    struct fr coeff;
    fr_one(&coeff);
    for (size_t i = 0; i < 64; i++) {
        lc_add_term(lc, nv->bits[i].var, &coeff);
        fr_add(&coeff, &coeff, &coeff);
    }
}

/* prf(a, b, c, d, x[252], y[256]) */
static void sp_prf(struct sp_ctx *x, bool a, bool b, bool c, bool d,
                   const struct cbit xs[252], const struct cbit *ys,
                   struct cbit out[256])
{
    struct cbit image[512];
    image[0] = cbit_constant(a);
    image[1] = cbit_constant(b);
    image[2] = cbit_constant(c);
    image[3] = cbit_constant(d);
    memcpy(image + 4, xs, 252 * sizeof image[0]);
    if (ys) {
        memcpy(image + 256, ys, 256 * sizeof image[0]);
    } else {
        for (size_t i = 0; i < 256; i++)
            image[256 + i] = cbit_constant(false);
    }
    sp_sha256_block(x, image, out);
}

/* commitment::note_comm */
static bool sp_note_comm(struct sp_ctx *x, const struct cbit a_pk[256],
                         const struct cbit value[64], const struct cbit rho[256],
                         const struct cbit r[256], struct cbit out[256])
{
    static const bool prefix[8] = { 1, 0, 1, 1, 0, 0, 0, 0 };
    struct cbit image[840];
    for (size_t i = 0; i < 8; i++)
        image[i] = cbit_constant(prefix[i]);
    memcpy(image + 8, a_pk, 256 * sizeof image[0]);
    memcpy(image + 264, value, 64 * sizeof image[0]);
    memcpy(image + 328, rho, 256 * sizeof image[0]);
    memcpy(image + 584, r, 256 * sizeof image[0]);
    return sp_sha256(x, image, 840, out);
}

/* input::conditionally_swap_u256 */
static void sp_cond_swap(struct sp_ctx *x, const struct cbit lhs[256],
                         const struct cbit rhs[256], struct cbit cond,
                         struct cbit out[512])
{
    bool cv = cond.wire_value;
    for (size_t i = 0; i < 256; i++) {
        struct linear_combination la, lb, lc;

        struct cbit xb = sp_alloc_bit(x, sp_sel(cv, cbit_value(rhs[i]),
                                               cbit_value(lhs[i])));
        lc_init(&la);
        lc_init(&lb);
        lc_init(&lc);
        sp_lc_bit(&la, rhs[i], &x->one);
        sp_lc_bit(&la, lhs[i], &x->neg_one);
        lc_add_term(&lb, cond.var, &x->one);
        sp_lc_bit(&lc, xb, &x->one);
        sp_lc_bit(&lc, lhs[i], &x->neg_one);
        sp_enforce(x, &la, &lb, &lc);

        struct cbit yb = sp_alloc_bit(x, sp_sel(cv, cbit_value(lhs[i]),
                                               cbit_value(rhs[i])));
        lc_init(&la);
        lc_init(&lb);
        lc_init(&lc);
        sp_lc_bit(&la, lhs[i], &x->one);
        sp_lc_bit(&la, rhs[i], &x->neg_one);
        lc_add_term(&lb, cond.var, &x->one);
        sp_lc_bit(&lc, yb, &x->one);
        sp_lc_bit(&lc, rhs[i], &x->neg_one);
        sp_enforce(x, &la, &lb, &lc);

        out[i] = xb;
        out[256 + i] = yb;
    }
}

/* input::InputNote::compute */
static bool sp_input_note(struct sp_ctx *x, const struct sprout_js_input *in,
                          const struct sp_note_value *value,
                          const struct cbit h_sig[256], bool nonce,
                          const struct cbit rt[256], struct cbit nf[256],
                          struct cbit mac[256])
{
    struct cbit a_sk[252], rho[256], r[256], a_pk[256], cm[256];
    struct cbit cur[256], sibling[256], preimage[512], vbits[64];

    sp_witness_bits(x, in->a_sk, 252, 4, a_sk);
    sp_witness_bits(x, in->rho, 256, 0, rho);
    sp_witness_bits(x, in->r, 256, 0, r);

    sp_prf(x, true, true, false, false, a_sk, NULL, a_pk);  /* PRF_addr */
    sp_prf(x, true, true, true, false, a_sk, rho, nf);      /* PRF_nf */
    sp_prf(x, false, nonce, false, false, a_sk, h_sig, mac); /* PRF_pk */

    sp_note_value_bits_le(value, vbits);
    if (!sp_note_comm(x, a_pk, vbits, rho, r, cm))
        return false;

    memcpy(cur, cm, sizeof cur);
    for (size_t layer = 0; layer < SPROUT_TREE_DEPTH; layer++) {
        struct cbit is_right = sp_alloc_bit(x, in->cur_is_right[layer]);
        sp_witness_bits(x, in->sibling[layer], 256, 0, sibling);
        sp_cond_swap(x, cur, sibling, is_right, preimage);
        sp_sha256_block(x, preimage, cur);
    }

    struct cbit enforce = sp_alloc_bit(x, value->value != 0);

    struct linear_combination la, lb, lc;
    /* value * (1 - enforce) = 0 */
    lc_init(&la);
    lc_init(&lb);
    lc_init(&lc);
    sp_note_value_lc(value, &la);
    lc_add_term(&lb, CS_ONE, &x->one);
    lc_add_term(&lb, enforce.var, &x->neg_one);
    sp_enforce(x, &la, &lb, &lc);

    /* (cur - rt) * enforce = 0, per bit */
    for (size_t i = 0; i < 256; i++) {
        lc_init(&la);
        lc_init(&lb);
        lc_init(&lc);
        sp_lc_bit(&la, cur[i], &x->one);
        sp_lc_bit(&la, rt[i], &x->neg_one);
        lc_add_term(&lb, enforce.var, &x->one);
        sp_enforce(x, &la, &lb, &lc);
    }
    return true;
}

/* output::OutputNote::compute */
static bool sp_output_note(struct sp_ctx *x, const struct sprout_js_output *o,
                           const struct sp_note_value *value,
                           const struct cbit phi[252],
                           const struct cbit h_sig[256], bool nonce,
                           struct cbit cm[256])
{
    struct cbit rho[256], a_pk[256], r[256], vbits[64];
    sp_prf(x, false, nonce, true, false, phi, h_sig, rho); /* PRF_rho */
    sp_witness_bits(x, o->a_pk, 256, 0, a_pk);
    sp_witness_bits(x, o->r, 256, 0, r);
    sp_note_value_bits_le(value, vbits);
    return sp_note_comm(x, a_pk, vbits, rho, r, cm);
}

/* ── native mirror ────────────────────────────────────────────────── */

static uint32_t sp_rotr32(uint32_t v, unsigned r)
{
    return (v >> r) | (v << (32u - r));
}

void sprout_sha256_compress(const uint8_t block[64], uint8_t out[32])
{
    uint32_t w[64];
    for (size_t i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[4 * i] << 24) |
               ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | block[4 * i + 3];
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = sp_rotr32(w[i - 15], 7) ^ sp_rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = sp_rotr32(w[i - 2], 17) ^ sp_rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = SP_IV[0], b = SP_IV[1], c = SP_IV[2], d = SP_IV[3];
    uint32_t e = SP_IV[4], f = SP_IV[5], g = SP_IV[6], h = SP_IV[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t S1 = sp_rotr32(e, 6) ^ sp_rotr32(e, 11) ^ sp_rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SP_K[i] + w[i];
        uint32_t S0 = sp_rotr32(a, 2) ^ sp_rotr32(a, 13) ^ sp_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    uint32_t hs[8] = { SP_IV[0] + a, SP_IV[1] + b, SP_IV[2] + c, SP_IV[3] + d,
                       SP_IV[4] + e, SP_IV[5] + f, SP_IV[6] + g, SP_IV[7] + h };
    for (size_t i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(hs[i] >> 24);
        out[4 * i + 1] = (uint8_t)(hs[i] >> 16);
        out[4 * i + 2] = (uint8_t)(hs[i] >> 8);
        out[4 * i + 3] = (uint8_t)hs[i];
    }
}

/* Generic multi-block compression chain (only used for the 105-byte note
 * commitment, which pads to two blocks). */
static void sp_sha256_full(const uint8_t *msg, size_t len, uint8_t out[32])
{
    /* Re-implement the chaining with explicit state because
     * sprout_sha256_compress always starts from the IV. */
    uint8_t buf[128];
    memset(buf, 0, sizeof buf);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8u;
    for (size_t i = 0; i < 8; i++)
        buf[127 - i] = (uint8_t)(bits >> (8 * i));

    uint32_t st[8];
    memcpy(st, SP_IV, sizeof st);
    for (size_t blk = 0; blk < 2; blk++) {
        const uint8_t *p = buf + 64 * blk;
        uint32_t w[64];
        for (size_t i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
                   ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
        for (size_t i = 16; i < 64; i++) {
            uint32_t s0 = sp_rotr32(w[i - 15], 7) ^ sp_rotr32(w[i - 15], 18) ^
                          (w[i - 15] >> 3);
            uint32_t s1 = sp_rotr32(w[i - 2], 17) ^ sp_rotr32(w[i - 2], 19) ^
                          (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
        uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
        for (size_t i = 0; i < 64; i++) {
            uint32_t S1 = sp_rotr32(e, 6) ^ sp_rotr32(e, 11) ^ sp_rotr32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + SP_K[i] + w[i];
            uint32_t S0 = sp_rotr32(a, 2) ^ sp_rotr32(a, 13) ^ sp_rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        st[0] += a; st[1] += b; st[2] += c; st[3] += d;
        st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    }
    for (size_t i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(st[i] >> 24);
        out[4 * i + 1] = (uint8_t)(st[i] >> 16);
        out[4 * i + 2] = (uint8_t)(st[i] >> 8);
        out[4 * i + 3] = (uint8_t)st[i];
    }
}

static void sp_native_prf(uint8_t nibble, const uint8_t x252[32],
                          const uint8_t *y, uint8_t out[32])
{
    uint8_t blk[64];
    memcpy(blk, x252, 32);
    blk[0] = (uint8_t)((nibble << 4) | (blk[0] & 0x0f));
    if (y)
        memcpy(blk + 32, y, 32);
    else
        memset(blk + 32, 0, 32);
    sprout_sha256_compress(blk, out);
}

static void sp_native_note_comm(const uint8_t a_pk[32], uint64_t value,
                                const uint8_t rho[32], const uint8_t r[32],
                                uint8_t out[32])
{
    uint8_t msg[105];
    msg[0] = 0xb0;
    memcpy(msg + 1, a_pk, 32);
    for (size_t i = 0; i < 8; i++)
        msg[33 + i] = (uint8_t)(value >> (8 * i));
    memcpy(msg + 41, rho, 32);
    memcpy(msg + 73, r, 32);
    sp_sha256_full(msg, sizeof msg, out);
}

void sprout_input_note_commitment(const uint8_t a_sk[32], uint64_t value,
                                  const uint8_t rho[32], const uint8_t r[32],
                                  uint8_t cm[32])
{
    uint8_t a_pk[32];
    sp_native_prf(0xc, a_sk, NULL, a_pk);
    sp_native_note_comm(a_pk, value, rho, r, cm);
}

void sprout_compute_public(const struct sprout_js_witness *w,
                           struct sprout_js_public *pub)
{
    for (size_t i = 0; i < 2; i++) {
        const struct sprout_js_input *in = &w->in[i];
        uint8_t a_pk[32], cur[32], blk[64];
        sp_native_prf(0xc, in->a_sk, NULL, a_pk);                 /* 1100 */
        sp_native_prf(0xe, in->a_sk, in->rho, pub->nf[i]);        /* 1110 */
        sp_native_prf(i ? 0x4 : 0x0, in->a_sk, w->h_sig, pub->mac[i]); /* 0n00 */
        sp_native_note_comm(a_pk, in->value, in->rho, in->r, cur);
        for (size_t layer = 0; layer < SPROUT_TREE_DEPTH; layer++) {
            /* Branch-free swap: the position is private. */
            uint8_t m = (uint8_t)(0u - (unsigned)in->cur_is_right[layer]);
            for (size_t j = 0; j < 32; j++) {
                uint8_t c = cur[j], s = in->sibling[layer][j];
                blk[j] = (uint8_t)((s & m) | (c & (uint8_t)~m));
                blk[32 + j] = (uint8_t)((c & m) | (s & (uint8_t)~m));
            }
            sprout_sha256_compress(blk, cur);
        }
        memcpy(pub->root[i], cur, 32);
    }
    for (size_t i = 0; i < 2; i++) {
        uint8_t rho[32];
        sp_native_prf(i ? 0x6 : 0x2, w->phi, w->h_sig, rho);     /* 0n10 */
        sp_native_note_comm(w->out[i].a_pk, w->out[i].value, rho, w->out[i].r,
                            pub->cm[i]);
    }
}

void sprout_pack_inputs(const uint8_t rt[32], const uint8_t h_sig[32],
                        const uint8_t nf[2][32], const uint8_t mac[2][32],
                        const uint8_t cm[2][32], uint64_t vpub_old,
                        uint64_t vpub_new, struct fr out[SPROUT_NUM_INPUTS])
{
    uint8_t input[272];
    memcpy(input, rt, 32);
    memcpy(input + 32, h_sig, 32);
    memcpy(input + 64, nf[0], 32);
    memcpy(input + 96, mac[0], 32);
    memcpy(input + 128, nf[1], 32);
    memcpy(input + 160, mac[1], 32);
    memcpy(input + 192, cm[0], 32);
    memcpy(input + 224, cm[1], 32);
    for (size_t i = 0; i < 8; i++) {
        input[256 + i] = (uint8_t)(vpub_old >> (8 * i));
        input[264 + i] = (uint8_t)(vpub_new >> (8 * i));
    }
    /* Fr::CAPACITY = 254 bits per element, bit j of a chunk weighs 2^j, bits
     * taken MSB-first from each byte (multipack::bytes_to_bits). */
    struct fr two, coeff;
    fr_one(&two);
    fr_add(&two, &two, &two);
    for (size_t k = 0; k < SPROUT_NUM_INPUTS; k++) {
        fr_zero(&out[k]);
        fr_one(&coeff);
        for (size_t j = 0; j < 254; j++) {
            size_t bit = k * 254 + j;
            if (bit >= 272 * 8)
                break;
            if ((input[bit / 8] >> (7 - bit % 8)) & 1u)
                fr_add(&out[k], &out[k], &coeff);
            fr_mul(&coeff, &coeff, &two);
        }
    }
}

bool sprout_parse_auth(const uint8_t auth[SPROUT_AUTH_LEN],
                       struct sprout_js_input *in)
{
    if (auth[0] != SPROUT_TREE_DEPTH)
        return false;
    const uint8_t *p = auth + 1;
    for (size_t k = 0; k < SPROUT_TREE_DEPTH; k++) {
        size_t i = SPROUT_TREE_DEPTH - 1 - k; /* root-first on the wire */
        if (p[0] != 32)
            return false;
        memcpy(in->sibling[i], p + 1, 32);
        p += 33;
    }
    uint64_t position = 0;
    for (size_t i = 0; i < 8; i++)
        position |= (uint64_t)p[i] << (8 * i);
    for (size_t i = 0; i < SPROUT_TREE_DEPTH; i++) {
        in->cur_is_right[i] = (position & 1u) == 1u;
        position >>= 1;
    }
    return true;
}

/* ── JoinSplit::synthesize ────────────────────────────────────────── */

bool sprout_synthesize(struct constraint_system *cs,
                       const struct sprout_js_witness *w)
{
    struct sp_ctx x;
    x.cs = cs;
    x.shrunk = 0;
    fr_one(&x.one);
    fr_neg(&x.neg_one, &x.one);

    if (cs->num_vars != 1 || cs->num_constraints != 0) {
        fprintf(stderr, "sprout_synthesize: constraint system not fresh\n");
        return false;
    }

    /* Public inputs first (see header). */
    struct sprout_js_public pub;
    sprout_compute_public(w, &pub);
    struct fr packed[SPROUT_NUM_INPUTS];
    sprout_pack_inputs(w->rt, w->h_sig, pub.nf, pub.mac, pub.cm, w->vpub_old,
                       w->vpub_new, packed);
    size_t input_var[SPROUT_NUM_INPUTS];
    for (size_t i = 0; i < SPROUT_NUM_INPUTS; i++)
        input_var[i] = cs_alloc_input(cs, &packed[i]);

    /* The big bit vectors live on the heap: the frame would otherwise be
     * ~100 KB, too much for a wallet thread's stack. */
    struct sp_bits {
        struct sp_note_value vpub_old, vpub_new, in_value[2], lhs_total,
            out_value[2];
        struct cbit rt[256], h_sig[256], phi[252];
        struct cbit nf[2][256], mac[2][256], cm[2][256];
        struct cbit pub_bits[2176];
    } *s = calloc(1, sizeof *s);
    if (!s) {
        fprintf(stderr, "sprout_synthesize: out of memory\n");
        return false;
    }
    bool ok = true;

    sp_note_value(&x, w->vpub_old, &s->vpub_old);
    sp_note_value(&x, w->vpub_new, &s->vpub_new);

    struct linear_combination lhs, rhs;
    lc_init(&lhs);
    lc_init(&rhs);
    sp_note_value_lc(&s->vpub_old, &lhs);
    sp_note_value_lc(&s->vpub_new, &rhs);

    sp_witness_bits(&x, w->rt, 256, 0, s->rt);
    sp_witness_bits(&x, w->h_sig, 256, 0, s->h_sig);
    sp_witness_bits(&x, w->phi, 252, 4, s->phi);

    uint64_t lhs_total = w->vpub_old;
    for (size_t i = 0; i < 2 && ok; i++) {
        lhs_total += w->in[i].value; /* wrapping, as in Rust */
        sp_note_value(&x, w->in[i].value, &s->in_value[i]);
        ok = sp_input_note(&x, &w->in[i], &s->in_value[i], s->h_sig, i == 1,
                           s->rt, s->nf[i], s->mac[i]);
        sp_note_value_lc(&s->in_value[i], &lhs);
    }

    if (ok) {
        sp_note_value(&x, lhs_total, &s->lhs_total);
        struct linear_combination la, lb, lc;
        lc_init(&la);
        lc_init(&lb);
        lc_init(&lc);
        for (size_t t = 0; t < lhs.num_terms; t++)
            lc_add_term(&la, lhs.terms[t].var, &lhs.terms[t].coeff);
        lc_add_term(&lb, CS_ONE, &x.one);
        sp_note_value_lc(&s->lhs_total, &lc);
        sp_enforce(&x, &la, &lb, &lc);
    }

    for (size_t i = 0; i < 2 && ok; i++) {
        sp_note_value(&x, w->out[i].value, &s->out_value[i]);
        ok = sp_output_note(&x, &w->out[i], &s->out_value[i], s->phi,
                            s->h_sig, i == 1, s->cm[i]);
        sp_note_value_lc(&s->out_value[i], &rhs);
    }

    if (ok) {
        /* balance: lhs * 1 = rhs */
        struct linear_combination lb;
        lc_init(&lb);
        lc_add_term(&lb, CS_ONE, &x.one);
        (void)cs_enforce(cs, &lhs, &lb, &rhs);
        lc_free(&lb);

        size_t n = 0;
        memcpy(s->pub_bits + n, s->rt, 256 * sizeof(struct cbit)); n += 256;
        memcpy(s->pub_bits + n, s->h_sig, 256 * sizeof(struct cbit)); n += 256;
        for (size_t i = 0; i < 2; i++) {
            memcpy(s->pub_bits + n, s->nf[i], 256 * sizeof(struct cbit)); n += 256;
            memcpy(s->pub_bits + n, s->mac[i], 256 * sizeof(struct cbit)); n += 256;
        }
        for (size_t i = 0; i < 2; i++) {
            memcpy(s->pub_bits + n, s->cm[i], 256 * sizeof(struct cbit)); n += 256;
        }
        sp_note_value_bits_le(&s->vpub_old, s->pub_bits + n); n += 64;
        sp_note_value_bits_le(&s->vpub_new, s->pub_bits + n); n += 64;

        /* multipack::pack_into_inputs */
        struct fr two;
        fr_one(&two);
        fr_add(&two, &two, &two);
        for (size_t k = 0; k * 254 < n; k++) {
            struct linear_combination la, lb2, lc;
            lc_init(&la);
            lc_init(&lb2);
            lc_init(&lc);
            struct fr coeff;
            fr_one(&coeff);
            for (size_t j = k * 254; j < n && j < (k + 1) * 254; j++) {
                sp_lc_bit(&la, s->pub_bits[j], &coeff);
                fr_mul(&coeff, &coeff, &two);
            }
            lc_add_term(&lb2, CS_ONE, &x.one);
            if (k < SPROUT_NUM_INPUTS)
                lc_add_term(&lc, input_var[k], &x.one);
            else
                ok = false;
            sp_enforce(&x, &la, &lb2, &lc);
        }
    }

    sp_shrink(&x);
    lc_free(&lhs);
    lc_free(&rhs);
    memory_cleanse(s, sizeof *s);
    free(s);

    if (!ok || cs->oom_error) {
        fprintf(stderr, "sprout_synthesize: internal failure (ok=%d oom=%d)\n",
                (int)ok, (int)cs->oom_error);
        return false;
    }
    return true;
}
