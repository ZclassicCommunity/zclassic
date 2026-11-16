/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ported from librustzcash / bellman / sapling-crypto (The Zcash developers /
 * Electric Coin Company), pinned 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5,
 * MIT / Apache-2.0. Reimplemented in C23; no reference code is linked in.
 *
 * The in-circuit Pedersen hash and the Jubjub Montgomery-form arithmetic it is
 * built on, split out of circuit_gadgets.c: this is the single hash body behind
 * BOTH the note commitment (section 17) and all 32 Merkle-level hashes
 * (section 21), which together are more than two thirds of the spend circuit's
 * constraints. It is the only consumer of the Montgomery add and
 * Montgomery-to-Edwards gadgets, so those live here too rather than in the
 * general gadget grab-bag.
 *
 * Matches sapling-crypto circuit::pedersen_hash::pedersen_hash constraint for
 * constraint, including the A/B/C split of each one — an algebraically
 * equivalent split is a DIFFERENT QAP and will not verify against the trusted
 * setup's proving key. */

#include "sapling/circuit_gadgets.h"
#include "sapling/pedersen_hash.h"
#include "sapling/sapling.h"
#include <pthread.h>
#include <string.h>
#include "util/log_macros.h"

#define CS_ONE 0

/* ── Montgomery Point Addition (3 constraints) ─────────────────── */

/* Jubjub Montgomery form: B*y^2 = x^3 + A*x^2 + x, where for the twisted
 * Edwards parameters a = -1 and d = -10240/10241:
 *   A = 2(a+d)/(a-d) = 40962
 *   B = 4/(a-d)      = -40964   (NOT -40960 — an earlier comment here said
 *                                -40960, and the scale constant below was
 *                                wrong to match it)
 * Montgomery A as Fr constant */
static void montgomery_a(struct fr *a_out)
{
    uint8_t bytes[32] = {0};
    /* 40962 = 0xA002 */
    bytes[0] = 0x02;
    bytes[1] = 0xA0;
    fr_from_bytes(a_out, bytes);
}

/* Montgomery addition:
 * lambda = (y2-y1)/(x2-x1)
 * x3 = lambda^2 - A - x1 - x2
 * y3 = lambda*(x1-x3) - y1
 * 3 constraints: lambda eval, x3 eval, y3 eval */
static void gadget_montgomery_add(struct constraint_system *cs,
                                   /* self (x1,y1) as LC term arrays */
                                   size_t self_x_nterms,
                                   const size_t *self_x_vars,
                                   const struct fr *self_x_coeffs,
                                   size_t self_y_nterms,
                                   const size_t *self_y_vars,
                                   const struct fr *self_y_coeffs,
                                   /* other (x2,y2) as LC term arrays */
                                   size_t other_x_nterms,
                                   const size_t *other_x_vars,
                                   const struct fr *other_x_coeffs,
                                   size_t other_y_nterms,
                                   const size_t *other_y_vars,
                                   const struct fr *other_y_coeffs,
                                   /* output */
                                   size_t *out_x, size_t *out_y)
{
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);
    struct fr mont_a;
    montgomery_a(&mont_a);

    /* Evaluate self and other LCs */
    struct fr x1v, y1v, x2v, y2v;
    fr_zero(&x1v);
    for (size_t i = 0; i < self_x_nterms; i++) {
        struct fr t;
        fr_mul(&t, &cs->witness[self_x_vars[i]], &self_x_coeffs[i]);
        fr_add(&x1v, &x1v, &t);
    }
    fr_zero(&y1v);
    for (size_t i = 0; i < self_y_nterms; i++) {
        struct fr t;
        fr_mul(&t, &cs->witness[self_y_vars[i]], &self_y_coeffs[i]);
        fr_add(&y1v, &y1v, &t);
    }
    fr_zero(&x2v);
    for (size_t i = 0; i < other_x_nterms; i++) {
        struct fr t;
        fr_mul(&t, &cs->witness[other_x_vars[i]], &other_x_coeffs[i]);
        fr_add(&x2v, &x2v, &t);
    }
    fr_zero(&y2v);
    for (size_t i = 0; i < other_y_nterms; i++) {
        struct fr t;
        fr_mul(&t, &cs->witness[other_y_vars[i]], &other_y_coeffs[i]);
        fr_add(&y2v, &y2v, &t);
    }

    /* lambda = (y2-y1)/(x2-x1) */
    struct fr lambda_val;
    {
        struct fr num, den;
        fr_sub(&num, &y2v, &y1v);
        fr_sub(&den, &x2v, &x1v);
        fr_inv(&lambda_val, &den);
        fr_mul(&lambda_val, &lambda_val, &num);
    }
    size_t lambda = cs_alloc_aux(cs, &lambda_val);

    /* Constraint 1: (x2-x1)*lambda = y2-y1 */
    {
        struct linear_combination la, lb, lc;
        lc_init(&la);
        for (size_t i = 0; i < other_x_nterms; i++)
            lc_add_term(&la, other_x_vars[i], &other_x_coeffs[i]);
        for (size_t i = 0; i < self_x_nterms; i++) {
            struct fr neg_c;
            fr_neg(&neg_c, &self_x_coeffs[i]);
            lc_add_term(&la, self_x_vars[i], &neg_c);
        }
        lc_init(&lb);
        lc_add_term(&lb, lambda, &one_val);
        lc_init(&lc);
        for (size_t i = 0; i < other_y_nterms; i++)
            lc_add_term(&lc, other_y_vars[i], &other_y_coeffs[i]);
        for (size_t i = 0; i < self_y_nterms; i++) {
            struct fr neg_c;
            fr_neg(&neg_c, &self_y_coeffs[i]);
            lc_add_term(&lc, self_y_vars[i], &neg_c);
        }
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* x3 = lambda^2 - A - x1 - x2 */
    struct fr x3v;
    {
        fr_mul(&x3v, &lambda_val, &lambda_val);
        fr_sub(&x3v, &x3v, &mont_a);
        fr_sub(&x3v, &x3v, &x1v);
        fr_sub(&x3v, &x3v, &x2v);
    }
    *out_x = cs_alloc_aux(cs, &x3v);

    /* Constraint 2: lambda*lambda = A + x1 + x2 + x3 */
    {
        struct linear_combination la, lb, lc;
        lc_init(&la); lc_add_term(&la, lambda, &one_val);
        lc_init(&lb); lc_add_term(&lb, lambda, &one_val);
        lc_init(&lc);
        lc_add_term(&lc, CS_ONE, &mont_a);
        for (size_t i = 0; i < self_x_nterms; i++)
            lc_add_term(&lc, self_x_vars[i], &self_x_coeffs[i]);
        for (size_t i = 0; i < other_x_nterms; i++)
            lc_add_term(&lc, other_x_vars[i], &other_x_coeffs[i]);
        lc_add_term(&lc, *out_x, &one_val);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* y3 = -(y1 + lambda*(x3-x1)) = lambda*(x1-x3) - y1 */
    struct fr y3v;
    {
        struct fr diff;
        fr_sub(&diff, &x3v, &x1v);
        fr_mul(&y3v, &lambda_val, &diff);
        fr_add(&y3v, &y3v, &y1v);
        fr_neg(&y3v, &y3v);
    }
    *out_y = cs_alloc_aux(cs, &y3v);

    /* Constraint 3: (x1-x3)*lambda = y3+y1 */
    {
        struct linear_combination la, lb, lc;
        lc_init(&la);
        for (size_t i = 0; i < self_x_nterms; i++)
            lc_add_term(&la, self_x_vars[i], &self_x_coeffs[i]);
        lc_add_term(&la, *out_x, &neg_one);

        lc_init(&lb);
        lc_add_term(&lb, lambda, &one_val);

        lc_init(&lc);
        lc_add_term(&lc, *out_y, &one_val);
        for (size_t i = 0; i < self_y_nterms; i++)
            lc_add_term(&lc, self_y_vars[i], &self_y_coeffs[i]);

        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }
}

/* sapling-crypto `JubjubBls12::scale` — the factor that normalizes the
 * Montgomery curve's B coefficient to 1:
 *
 *   Jubjub twisted Edwards:  a*x^2 + y^2 = 1 + d*x^2*y^2, a = -1,
 *                            d = -10240/10241
 *   Montgomery:              B*v^2 = u^3 + A*u^2 + u
 *                            A = 2(a+d)/(a-d) = 40962
 *                            B = 4/(a-d)      = -40964
 *
 * so scale = sqrt(4/(a-d)) = sqrt(-40964) mod r, and the reference's value is
 * the decimal
 *   17814886934372412843466061268024708274627479829237077604635722030778476050649
 *
 * DERIVED, not a literal. A hardcoded blob used to supply this, and that blob
 * did not square to -40964 — nothing structural could see the error, because
 * only scale^2 enters the Montgomery ADDITION (through lambda^2). A
 * wrong-magnitude scale therefore leaves a SINGLE-window hash round-tripping
 * while corrupting every multi-window one: identical constraint count, and the
 * honest witness still satisfies every emitted constraint because the witness
 * was computed by the same wrong formula the constraints encode. It only
 * surfaced when a per-wire differential against the out-of-circuit Pedersen hash
 * finally ran. Computing the factor from its defining equation removes the class
 * of failure rather than pinning one instance of it.
 *
 * WHICH ROOT is still load-bearing, and NOT for the reason a first reading
 * suggests. Negating scale negates every Montgomery y (the window tables, every
 * lambda, every y3) and gadget_montgomery_to_edwards divides scale*x by y, so
 * the negation cancels and the Edwards OUTPUT of both roots is identical — the
 * hash computes the same function either way. But `scale` also appears as a
 * literal COEFFICIENT, in this file's window-table constants and in the
 * conversion's `y*u = scale*x` constraint, so the two roots are two different
 * R1CS instances: same witness values, same count, different A/B/C matrices,
 * hence a different QAP and a proof that does not verify against the Sapling
 * trusted setup's proving key. So the root is pinned by the gate in
 * tests/harness/src/groth16_merkle_path.c against librustzcash's published decimal,
 * not merely against its own square. fr_sqrt happens to return exactly that
 * root today (measured, not assumed); the pin is what keeps it that way if
 * Tonelli-Shanks internals ever shift.
 *
 * On a derivation failure the factor stays ZERO, so the conversion divides by
 * zero and synthesis fails loudly rather than hashing to a wrong point. */
static struct fr s_mont_scale;
static pthread_once_t s_mont_scale_once = PTHREAD_ONCE_INIT;

static void load_montgomery_scale(void)
{
    uint8_t bytes[32] = {0};
    bytes[0] = 0x04;                        /* 40964 = 0xA004, little-endian */
    bytes[1] = 0xA0;
    struct fr neg_b, root, check;
    fr_zero(&s_mont_scale);
    if (!fr_from_bytes(&neg_b, bytes)) {
        LOG_ERROR("circuit_gadgets",
                  "montgomery_scale: 40964 is not a valid Fr encoding");
        return;
    }
    fr_neg(&neg_b, &neg_b);                 /* -40964 == B == 4/(a-d) */
    if (!fr_sqrt(&root, &neg_b)) {
        LOG_ERROR("circuit_gadgets",
                  "montgomery_scale: -40964 is not a quadratic residue in Fr "
                  "— Jubjub would have no Montgomery form");
        return;
    }
    fr_sq(&check, &root);
    if (!fr_eq(&check, &neg_b)) {
        LOG_ERROR("circuit_gadgets",
                  "montgomery_scale: sqrt(-40964) failed its own square check");
        return;
    }
    s_mont_scale = root;
}

static void montgomery_scale(struct fr *s)
{
    pthread_once(&s_mont_scale_once, load_montgomery_scale);
    *s = s_mont_scale;
}

void gadget_jubjub_montgomery_params(struct fr *a_out, struct fr *scale_out)
{
    if (a_out)
        montgomery_a(a_out);
    if (scale_out)
        montgomery_scale(scale_out);
}

/* Montgomery to Edwards conversion (2 constraints). Edwards (u, v) from
 * Montgomery (x, y):
 *   u = scale * x / y
 *   v = (x - 1) / (x + 1)
 * `scale` is the derived sqrt(-40964) above; it enters the first constraint as a
 * literal coefficient, which is why its exact root and not just its square is
 * pinned by a test. */
static void gadget_montgomery_to_edwards(struct constraint_system *cs,
                                           /* Montgomery point as LC terms */
                                           size_t mx_nterms,
                                           const size_t *mx_vars,
                                           const struct fr *mx_coeffs,
                                           size_t my_nterms,
                                           const size_t *my_vars,
                                           const struct fr *my_coeffs,
                                           /* output Edwards point */
                                           size_t *ex, size_t *ey)
{
    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);
    struct fr scale;
    montgomery_scale(&scale);

    /* Evaluate Montgomery LCs */
    struct fr mx_val, my_val;
    fr_zero(&mx_val);
    for (size_t i = 0; i < mx_nterms; i++) {
        struct fr t;
        fr_mul(&t, &cs->witness[mx_vars[i]], &mx_coeffs[i]);
        fr_add(&mx_val, &mx_val, &t);
    }
    fr_zero(&my_val);
    for (size_t i = 0; i < my_nterms; i++) {
        struct fr t;
        fr_mul(&t, &cs->witness[my_vars[i]], &my_coeffs[i]);
        fr_add(&my_val, &my_val, &t);
    }

    /* u = scale * x / y */
    struct fr u_val;
    {
        struct fr sx;
        fr_mul(&sx, &scale, &mx_val);
        fr_inv(&u_val, &my_val);
        fr_mul(&u_val, &u_val, &sx);
    }
    *ex = cs_alloc_aux(cs, &u_val);

    /* Constraint: y * u = scale * x */
    {
        struct linear_combination la, lb, lc;
        lc_init(&la);
        for (size_t i = 0; i < my_nterms; i++)
            lc_add_term(&la, my_vars[i], &my_coeffs[i]);
        lc_init(&lb);
        lc_add_term(&lb, *ex, &one_val);
        lc_init(&lc);
        for (size_t i = 0; i < mx_nterms; i++) {
            struct fr sc;
            fr_mul(&sc, &scale, &mx_coeffs[i]);
            lc_add_term(&lc, mx_vars[i], &sc);
        }
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }

    /* v = (x - 1) / (x + 1) */
    struct fr v_val;
    {
        struct fr num, den;
        fr_sub(&num, &mx_val, &one_val);
        fr_add(&den, &mx_val, &one_val);
        fr_inv(&v_val, &den);
        fr_mul(&v_val, &v_val, &num);
    }
    *ey = cs_alloc_aux(cs, &v_val);

    /* Constraint: (x + 1) * v = (x - 1) */
    {
        struct linear_combination la, lb, lc;
        lc_init(&la);
        for (size_t i = 0; i < mx_nterms; i++)
            lc_add_term(&la, mx_vars[i], &mx_coeffs[i]);
        lc_add_term(&la, CS_ONE, &one_val);
        lc_init(&lb);
        lc_add_term(&lb, *ey, &one_val);
        lc_init(&lc);
        for (size_t i = 0; i < mx_nterms; i++)
            lc_add_term(&lc, mx_vars[i], &mx_coeffs[i]);
        lc_add_term(&lc, CS_ONE, &neg_one);
        cs_enforce(cs, &la, &lb, &lc);
        lc_free(&la); lc_free(&lb); lc_free(&lc);
    }
}

/* ── Pedersen Hash (Montgomery-based) ──────────────────────────── */

/* Faithful port of sapling-crypto `circuit::pedersen_hash::pedersen_hash`
 * (librustzcash 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5).
 *
 * Shape, per reference: the preimage is 6 CONSTANT personalization bits
 * followed by the caller's bits, chopped into 3-bit windows. Each window is a
 * `lookup3_xy_with_conditional_negation` against that window's four Montgomery
 * multiples of the segment generator; windows inside a segment accumulate with
 * Montgomery addition (3 constraints each), every segment total converts to
 * twisted Edwards (2) and the segment totals accumulate with Edwards addition
 * (6). A segment carries 63 windows = 189 bits.
 *
 * Cost is therefore a pure function of the bit count, which is what makes the
 * spend circuit's section boundaries checkable: 516 bits (6 + 2*255, the Merkle
 * path's preimage) is 172 windows over 3 segments and lands on exactly 867
 * constraints — 342 window + 507 Montgomery-add + 6 into-Edwards + 12
 * Edwards-add. The 342 is not 2*172: the two all-constant personalization
 * windows fold their `Boolean::and` away for free.
 *
 * ONE body serves every Pedersen hash in the Sapling circuits. Only the six
 * leading bits differ between the note commitment and the 32 Merkle levels
 * (bellman `Personalization::get_bits`), so personalization is a parameter, not
 * a second copy of this function. */

#define PEDERSEN_CHUNKS_PER_GEN 63
#define PEDERSEN_NUM_GEN PEDERSEN_SEGMENT_GENERATORS
#define PEDERSEN_WINDOW_SLOTS 4

/* Per-window Montgomery coordinates of {1,2,3,4} * (16^window) * G_segment —
 * bellman `generate_pedersen_circuit_generators`, precomputed once because each
 * entry costs two field inversions and the Merkle path asks for 172 windows per
 * level, 32 levels deep. */
static struct fr ph_win_x[PEDERSEN_NUM_GEN][PEDERSEN_CHUNKS_PER_GEN]
                         [PEDERSEN_WINDOW_SLOTS];
static struct fr ph_win_y[PEDERSEN_NUM_GEN][PEDERSEN_CHUNKS_PER_GEN]
                         [PEDERSEN_WINDOW_SLOTS];
static pthread_once_t ph_windows_once = PTHREAD_ONCE_INIT;

/* Convert Edwards point to Montgomery coordinates — bellman
 * `montgomery::Point::from_edwards`:
 *   u = (1 + y) / (1 - y)        v = scale * u / x                          */
static void edwards_to_montgomery(struct fr *mx, struct fr *my,
                                    const struct jub_point *p)
{
    struct fr ex, ey;
    jub_get_x(&ex, p);
    jub_get_y(&ey, p);
    struct fr one_val;
    fr_one(&one_val);

    /* mx = (1+y)/(1-y) */
    struct fr num, den;
    fr_add(&num, &one_val, &ey);
    fr_sub(&den, &one_val, &ey);
    fr_inv(mx, &den);
    fr_mul(mx, mx, &num);

    /* my = scale * mx / ex */
    struct fr scale;
    montgomery_scale(&scale);
    struct fr inv_ex;
    fr_inv(&inv_ex, &ex);
    fr_mul(my, &scale, mx);
    fr_mul(my, my, &inv_ex);
}

static void ph_load_windows(void)
{
    for (size_t i = 0; i < PEDERSEN_NUM_GEN; i++) {
        /* The segment generators come from pedersen_hash.c, the out-of-circuit
         * hash's own cache. This file used to re-run find_group_hash into a
         * second cache of the same six points, and two caches of one set of
         * points are two things that can drift apart — with the in-circuit and
         * out-of-circuit hashes then committing to different notes while every
         * constraint count stayed right. One derivation, one cache. */
        struct jub_point gen;
        if (!pedersen_segment_generator(i, &gen)) {
            LOG_ERROR("circuit_gadgets",
                      "pedersen windows: segment generator %zu unavailable", i);
            return;
        }
        struct jub_point base = gen;
        for (size_t w = 0; w < PEDERSEN_CHUNKS_PER_GEN; w++) {
            struct jub_point pts[PEDERSEN_WINDOW_SLOTS];
            pts[0] = base;                       /* 1 * base */
            jub_double(&pts[1], &base);          /* 2 * base */
            jub_add(&pts[2], &pts[1], &base);    /* 3 * base */
            jub_double(&pts[3], &pts[1]);        /* 4 * base */
            for (size_t k = 0; k < PEDERSEN_WINDOW_SLOTS; k++)
                edwards_to_montgomery(&ph_win_x[i][w][k], &ph_win_y[i][w][k],
                                      &pts[k]);
            /* Windows are separated by 2 bits so their ranges cannot overlap,
             * so the base advances by 16 — four doublings. */
            struct jub_point t;
            jub_double(&t, &base);
            jub_double(&base, &t);
            jub_double(&t, &base);
            jub_double(&base, &t);
        }
    }
}

static void ensure_ph_windows(void)
{
    pthread_once(&ph_windows_once, ph_load_windows);
}

void gadget_pedersen_personalization_note_commitment(bool bits_out[6])
{
    for (size_t i = 0; i < 6; i++)
        bits_out[i] = true;
}

bool gadget_pedersen_personalization_merkle_tree(size_t depth, bool bits_out[6])
{
    if (depth >= 63)
        LOG_FAIL("circuit_gadgets",
                 "pedersen personalization: MerkleTree depth %zu exceeds the "
                 "6-bit encoding (bellman asserts depth < 63)", depth);
    for (size_t i = 0; i < 6; i++)
        bits_out[i] = ((depth >> i) & 1u) != 0u;
    return true;
}

/* One bit entering a Pedersen window: a known CONSTANT (folds into the ONE
 * column for free) or a boolean-constrained wire. This is the
 * Constant/Is subset of bellman's `Boolean`; a `Not` view never reaches here
 * because every Pedersen preimage in the Sapling circuits is a bare allocated
 * bit or a personalization constant. */
struct ph_bit {
    bool is_const;
    bool value;    /* the bit's logical value, either way */
    size_t var;    /* valid only when !is_const */
};

/* A linear combination over {ONE, b0, b1, precomp}, held as the parallel arrays
 * gadget_montgomery_add consumes. Index 0 is always the ONE (constant) column,
 * so constant-folding a bit is an addition into coeffs[0] and costs nothing. */
struct ph_lc {
    size_t nterms;
    size_t vars[4];
    struct fr coeffs[4];
};

/* bellman Boolean::and. A Constant(false) side short-circuits to a constant; a
 * Constant(true) side returns the OTHER bit UNCHANGED — which is why this
 * cannot collapse to "both constant, or allocate". Folding an allocated bit
 * into a constant here would drop it out of the linear combination while still
 * producing the right value for the honest witness: a silent soundness hole
 * that no constraint count and no value check can see. Costs 1 constraint only
 * when both sides are allocated. */
static struct ph_bit ph_and(struct constraint_system *cs,
                            struct ph_bit a, struct ph_bit b)
{
    struct ph_bit k = { .is_const = true, .value = false, .var = 0 };
    if ((a.is_const && !a.value) || (b.is_const && !b.value))
        return k;
    if (a.is_const)                 /* a is constant TRUE -> the AND is b */
        return b;
    if (b.is_const)                 /* b is constant TRUE -> the AND is a */
        return a;

    struct fr v;
    if (a.value && b.value) fr_one(&v); else fr_zero(&v);
    struct ph_bit out = { .is_const = false,
                          .value = a.value && b.value,
                          .var = cs_alloc_aux(cs, &v) };
    gadget_mul(cs, a.var, b.var, out.var);
    return out;
}

/* out = c[0]*ONE + c[1]*b0 + c[2]*b1 + c[3]*precomp — bellman's chain of
 * `Num::add_bool_with_coeff`. Zero constraints; it is a linear combination. */
static void ph_synth_lc(struct ph_lc *out, const struct fr c[4],
                        struct ph_bit b0, struct ph_bit b1,
                        struct ph_bit precomp)
{
    out->nterms = 1;
    out->vars[0] = CS_ONE;
    out->coeffs[0] = c[0];

    const struct ph_bit bits[3] = { b0, b1, precomp };
    for (size_t k = 0; k < 3; k++) {
        if (bits[k].is_const) {
            if (bits[k].value)
                fr_add(&out->coeffs[0], &out->coeffs[0], &c[k + 1]);
        } else {
            out->vars[out->nterms] = bits[k].var;
            out->coeffs[out->nterms] = c[k + 1];
            out->nterms++;
        }
    }
}

/* A one-term LC holding a single wire with coefficient 1. */
static struct ph_lc ph_lc_wire(size_t var)
{
    struct ph_lc out = {0};
    out.nterms = 1;
    out.vars[0] = var;
    fr_one(&out.coeffs[0]);
    return out;
}

/* bellman `lookup3_xy_with_conditional_negation`: a 2-bit table lookup on
 * (b0, b1) with b2 selecting the point's negation. The x coordinate comes back
 * as a free linear combination and the y coordinate as one allocated wire.
 * 2 constraints when all three bits are allocated (the b0&b1 AND, then the y
 * computation); 1 when the AND folds away. bellman's exact A*B=C split is kept:
 * `2*y_lc * b2 = y_lc - y`, NOT the equivalent `y_lc * (1 - 2*b2) = y` — same
 * witness, different QAP, so the latter cannot verify against the trusted setup.
 * (This comment asserted the opposite and the code matched the comment rather
 * than the reference; test_groth16_r1cs_oracle settled it.) */
static void ph_lookup3_cond_neg(struct constraint_system *cs,
                                struct ph_bit b0, struct ph_bit b1,
                                struct ph_bit b2,
                                const struct fr coords_x[4],
                                const struct fr coords_y[4],
                                struct ph_lc *x_out, size_t *y_out)
{
    struct fr xc[4], yc[4];
    gadget_synth_coeffs(2, coords_x, xc);
    gadget_synth_coeffs(2, coords_y, yc);

    /* ALLOCATION ORDER IS LOAD-BEARING: the reference allocates y BEFORE
     * Boolean::and's `precomp`. Swapping them permutes two aux indices in every
     * window with an allocated AND — same A*B==C, different QAP. Constraint
     * order is unaffected. Pinned by test_groth16_r1cs_oracle. */
    const size_t idx = (b0.value ? 1u : 0u) | (b1.value ? 2u : 0u);
    struct fr y_val = coords_y[idx];
    if (b2.value)
        fr_neg(&y_val, &y_val);
    *y_out = cs_alloc_aux(cs, &y_val);

    struct ph_bit precomp = ph_and(cs, b0, b1);   /* 0 or 1 constraint */
    ph_synth_lc(x_out, xc, b0, b1, precomp);
    struct ph_lc y_lc;
    ph_synth_lc(&y_lc, yc, b0, b1, precomp);

    struct fr one_val, neg_one;
    fr_one(&one_val);
    fr_neg(&neg_one, &one_val);

    /* A = y_lc added to ITSELF (every coefficient doubles), B = the selector bit
     * alone, C = y_lc - y. See the note above this function. */
    struct linear_combination la, lb, lc;
    lc_init(&la);
    for (size_t i = 0; i < y_lc.nterms; i++) {
        lc_add_term(&la, y_lc.vars[i], &y_lc.coeffs[i]);
        lc_add_term(&la, y_lc.vars[i], &y_lc.coeffs[i]);
    }

    lc_init(&lb);
    if (b2.is_const) {
        if (b2.value)
            lc_add_term(&lb, CS_ONE, &one_val);
        /* Constant(false) contributes no term at all, exactly as
         * Boolean::Constant(false).lc() returns the zero combination. */
    } else {
        lc_add_term(&lb, b2.var, &one_val);
    }

    lc_init(&lc);
    for (size_t i = 0; i < y_lc.nterms; i++)
        lc_add_term(&lc, y_lc.vars[i], &y_lc.coeffs[i]);
    lc_add_term(&lc, *y_out, &neg_one);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

/* Pull the next preimage bit. The first 6 are the constant personalization
 * bits; past the end of the input bellman pads with `Boolean::constant(false)`,
 * which is why a short final window costs less than a full one. */
static struct ph_bit ph_next_bit(const struct constraint_system *cs,
                                 const bool pers_bits[6],
                                 const size_t *input_bits, size_t total_bits,
                                 size_t *bit_pos)
{
    struct ph_bit out = { .is_const = true, .value = false, .var = 0 };
    if (*bit_pos >= total_bits)
        return out;                     /* pad — costs nothing */
    if (*bit_pos < 6) {
        out.value = pers_bits[*bit_pos];
        (*bit_pos)++;
        return out;
    }
    const size_t v = input_bits[*bit_pos - 6];
    (*bit_pos)++;
    out.is_const = false;
    out.var = v;
    out.value = (v < cs->num_vars) && !fr_is_zero(&cs->witness[v]);
    return out;
}

/* Fold occupied 3-bit windows into segments, convert each segment to
 * Edwards, and add the segments. *x_acc and *y_acc are SIZE_MAX when no
 * segment is synthesized. */
static void ph_accumulate_segments(struct constraint_system *cs,
                                   const bool pers_bits[6],
                                   const size_t *input_bits,
                                   size_t total_bits,
                                   size_t *x_acc, size_t *y_acc)
{
    *x_acc = SIZE_MAX;
    *y_acc = SIZE_MAX;

    size_t bit_pos = 0;
    size_t acc_x = SIZE_MAX, acc_y = SIZE_MAX;

    for (size_t seg = 0;
         seg < PEDERSEN_NUM_GEN && bit_pos < total_bits; seg++) {
        struct ph_lc seg_x, seg_y;
        bool have_seg = false;

        for (size_t w = 0;
             w < PEDERSEN_CHUNKS_PER_GEN && bit_pos < total_bits; w++) {
            struct ph_bit b[3];
            for (size_t k = 0; k < 3; k++)
                b[k] = ph_next_bit(cs, pers_bits, input_bits, total_bits,
                                   &bit_pos);

            struct ph_lc win_x;
            size_t win_y_var;
            ph_lookup3_cond_neg(cs, b[0], b[1], b[2],
                                ph_win_x[seg][w], ph_win_y[seg][w],
                                &win_x, &win_y_var);
            struct ph_lc win_y = ph_lc_wire(win_y_var);

            if (!have_seg) {
                seg_x = win_x;
                seg_y = win_y;
                have_seg = true;
                continue;
            }
            /* bellman: `tmp.add(cs, segment_result)` — the freshly looked-up
             * window point is SELF and the accumulator is OTHER. Montgomery
             * addition is commutative in value but not in its A/B/C split, so
             * the argument order is load-bearing for QAP alignment. */
            size_t rx, ry;
            gadget_montgomery_add(cs,
                                  win_x.nterms, win_x.vars, win_x.coeffs,
                                  win_y.nterms, win_y.vars, win_y.coeffs,
                                  seg_x.nterms, seg_x.vars, seg_x.coeffs,
                                  seg_y.nterms, seg_y.vars, seg_y.coeffs,
                                  &rx, &ry);
            seg_x = ph_lc_wire(rx);
            seg_y = ph_lc_wire(ry);
        }

        if (!have_seg)
            break;                      /* bits ended on a segment boundary */

        size_t ex, ey;
        gadget_montgomery_to_edwards(cs,
                                     seg_x.nterms, seg_x.vars, seg_x.coeffs,
                                     seg_y.nterms, seg_y.vars, seg_y.coeffs,
                                     &ex, &ey);
        if (acc_x == SIZE_MAX) {
            acc_x = ex;
            acc_y = ey;
        } else {
            /* bellman: `segment_result.add(cs, edwards_result)` — again the new
             * segment is SELF. */
            size_t nx, ny;
            gadget_edwards_add(cs, ex, ey, acc_x, acc_y, &nx, &ny);
            acc_x = nx;
            acc_y = ny;
        }
    }

    *x_acc = acc_x;
    *y_acc = acc_y;
}

void gadget_pedersen_hash_pers(struct constraint_system *cs,
                               const bool pers_bits[6],
                               const size_t *input_bits, size_t n_bits,
                               size_t *x_out, size_t *y_out)
{
    if (!x_out || !y_out) {
        LOG_ERROR("circuit_gadgets",
                  "pedersen_hash: NULL output pointer (x_out=%p y_out=%p)",
                  (const void *)x_out, (const void *)y_out);
        return;
    }
    *x_out = SIZE_MAX;
    *y_out = SIZE_MAX;
    if (!cs || !pers_bits || (n_bits > 0 && !input_bits)) {
        LOG_ERROR("circuit_gadgets",
                  "pedersen_hash: missing input (cs=%p pers=%p bits=%p "
                  "n_bits=%zu)", (const void *)cs, (const void *)pers_bits,
                  (const void *)input_bits, n_bits);
        return;
    }

    const size_t total_bits = 6 + n_bits;
    const size_t capacity =
        (size_t)PEDERSEN_NUM_GEN * PEDERSEN_CHUNKS_PER_GEN * 3;
    if (total_bits > capacity) {
        LOG_ERROR("circuit_gadgets",
                  "pedersen_hash: %zu preimage bits exceed the %zu-bit "
                  "capacity of %d generators", total_bits, capacity,
                  PEDERSEN_NUM_GEN);
        return;
    }
    ensure_ph_windows();

    size_t acc_x = SIZE_MAX, acc_y = SIZE_MAX;
    ph_accumulate_segments(cs, pers_bits, input_bits, total_bits,
                           &acc_x, &acc_y);

    if (acc_x == SIZE_MAX || acc_y == SIZE_MAX) {
        LOG_ERROR("circuit_gadgets",
                  "pedersen_hash: no segment was synthesized for %zu preimage "
                  "bits", total_bits);
        return;
    }
    *x_out = acc_x;
    *y_out = acc_y;
}

void gadget_pedersen_hash(struct constraint_system *cs,
                          const size_t *input_bits, size_t n_bits,
                          const char *personalization,
                          size_t *x_out, size_t *y_out)
{
    /* Legacy entry point, kept bit-for-bit compatible with the pre-existing
     * caller in sapling_circuit.c (the non-parity output/spend circuits). Its
     * personalization is NOT bellman's `Personalization::NoteCommitment`, which
     * is six 1 bits — use gadget_pedersen_personalization_note_commitment()
     * for the parity-faithful spend/output port. */
    bool pers_bits[6] = { false, false, false, false, false, false };
    if (personalization && strcmp(personalization, "Zcash_PH") == 0) {
        pers_bits[1] = true;
        pers_bits[2] = true;
        pers_bits[4] = true;
        pers_bits[5] = true;
    }
    gadget_pedersen_hash_pers(cs, pers_bits, input_bits, n_bits, x_out, y_out);
}
