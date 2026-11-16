/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Jubjub scalar field arithmetic for Sapling.
 * Implements 512-bit reduction modulo the Jubjub scalar field order.
 *
 * (constant-time): `jubjub_to_scalar` is on the Sapling
 * nullifier-derivation path (via `prf_nsk`) where `nsk` is a
 * long-lived secret reused across all spends from the same key.
 * Any per-bit timing or cache leak here correlates across many
 * spends, so the reduction loop and its helpers must be
 * branchless. See tests/harness/src/test_sapling_crypto.c for the
 * diff and Hamming-weight timing regressions.
 *
 * Branch-free is necessary but NOT sufficient: on arm64 (Apple
 * Silicon, Apple Clang 17) the previous 9x32-bit mask-selected
 * implementation ran ~25% faster on a near-zero input than on a
 * full-weight one (2x2000-iteration paired median: lo=~22.3ms,
 * hi=~27.9ms, ratio 1.24-1.26 across runs and checkouts, against a
 * 0.85..1.15 gate).  The disassembly has no data-dependent branch -
 * the divergence is microarchitectural: when the accumulator is
 * zero, the value-carrying chains through the load/store loop are
 * recognised as producing zero and their dependencies are
 * eliminated at rename, so 512 iterations of "stay zero" run
 * materially faster than 512 iterations of "carry a value".
 * Forcing the accumulator nonzero (timing probe) collapses the gap
 * to ~1.00, which confirms the mechanism.
 *
 * The fix used here keeps every intermediate nonzero for EVERY
 * input, so there is no zero-mode to fall into: the accumulator is
 * carried in the redundant shifted representation A = value + r
 * (invariant r <= A < 2r), and each MSB-down step is fused as
 *
 *      A' = 2A|b            (>= 2r, never zero)
 *      D  = A' - 3r         (single fused subtract, borrow = [A' < 3r])
 *      A  = D + r + borrow*r
 *
 * which is algebraically the old `acc = 2acc|b; if (acc >= r) acc -= r`
 * plus the constant r.  D hits zero only on a ~2^-256 limb alignment,
 * never persistently for any input class.  Measured on the same host:
 * ratio 0.94-1.03 across runs, and the real-world (nonzero-input) path
 * got faster than the old code (about 5.4us vs 7.0us per call in the
 * same session; 4.6us on a quieter one) because the 4x64-bit carry
 * chains replace 9x32-bit ones, matching the limb style already used
 * in core/modules/sapling/src/fr.c. */

#include "sapling/jubjub.h"
#include <string.h>

/* Jubjub scalar field order r (little-endian bytes):
 * r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7 */
static const unsigned char JUBJUB_R[32] = {
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0,
    0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06,
    0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e
};

/* 256-bit integer (4 x 64-bit limbs, little-endian).  r < 2^252, so the
 * shifted accumulator A < 2r < 2^253 and its doubled form 2A|b < 2^254
 * always fit without a limb carry-out; a subtracting step may wrap and
 * is corrected in the same iteration. Carry chains use the standard C23
 * 128-bit integer type rather than a compiler extension. */
#define NL 4

/* The standard C23 spelling is `unsigned _BitInt(128)`, and it is what every
 * compiler that implements _BitInt at that width gets. GCC 13 — still the
 * mingw-w64 cross compiler shipped for Windows — does not implement _BitInt
 * at all, so it falls back to the `unsigned __int128` extension it does have.
 * Both are unsigned 128-bit two's-complement integers with wrapping
 * arithmetic and identical value ranges, so every carry, borrow and shift
 * below computes the same value either way. Selection is by feature macro
 * only: no arithmetic, constant, limb count or reduction step is conditional.
 * A compiler that offers neither is refused rather than silently reduced to
 * 64-bit intermediates. */
#if defined(__BITINT_MAXWIDTH__) && __BITINT_MAXWIDTH__ >= 128
typedef unsigned _BitInt(128) jubjub_uint128;
#elif defined(__SIZEOF_INT128__)
/* Same suppression, and for the same reason, as core/modules/sapling/src/fr.c: the
 * extension is not ISO C, and this tree builds -pedantic -Werror. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef unsigned __int128 jubjub_uint128;
#pragma GCC diagnostic pop
#else
#error "jubjub requires a 128-bit unsigned integer type (C23 _BitInt(128) or __int128)"
#endif

struct bigint {
    uint64_t d[NL];
};

static void bi_from_bytes(struct bigint *a, const unsigned char *b, size_t n)
{
    memset(a->d, 0, sizeof(a->d));
    for (size_t i = 0; i < n && i < NL * 8; i++)
        a->d[i / 8] |= (uint64_t)b[i] << (8 * (i % 8));
}

static void bi_to_bytes(const struct bigint *a, unsigned char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        b[i] = (unsigned char)(a->d[i / 8] >> (8 * (i % 8)));
}

/* a <<= 1.  Branchless.  Callers keep A < 2r < 2^253, so the discarded
 * carry is always 0. */
static void bi_shl1(struct bigint *a)
{
    uint64_t carry = 0;
    for (int i = 0; i < NL; i++) {
        uint64_t new_carry = a->d[i] >> 63;
        a->d[i] = (a->d[i] << 1) | carry;
        carry = new_carry;
    }
    (void)carry;
}

/* a -= c (mod 2^256).  Returns the borrow (0 or 1); the caller folds it
 * back in within the same iteration, so no information escapes. */
static uint64_t bi_sub(struct bigint *a, const struct bigint *c)
{
    uint64_t borrow = 0;
    for (int i = 0; i < NL; i++) {
        jubjub_uint128 diff =
            (jubjub_uint128)a->d[i] - c->d[i] - borrow;
        a->d[i] = (uint64_t)diff;
        borrow = (uint64_t)(diff >> 64) & 1u;
    }
    return borrow;
}

/* a += r + w*r, with w in {0,1}.  The mask selects the public constant
 * without a wide multiplication; the carry chain is unconditional. */
static void bi_add_r_weighted(struct bigint *a, const struct bigint *r,
                              uint64_t w)
{
    jubjub_uint128 carry = 0;
    uint64_t mask = (uint64_t)0 - w;
    for (int i = 0; i < NL; i++) {
        jubjub_uint128 sum = (jubjub_uint128)a->d[i] +
                             (jubjub_uint128)r->d[i] +
                             (jubjub_uint128)(r->d[i] & mask) + carry;
        a->d[i] = (uint64_t)sum;
        carry = sum >> 64;
    }
}

/* result = a mod r, where a is 512-bit LE and r is 256-bit.
 *
 * Schoolbook shift-and-subtract, one bit per iteration from MSB down,
 * carried in the shifted representation A = value + r (see the file
 * comment for why the offset is load-bearing for timing).  All 512
 * iterations always execute; every operation inside an iteration runs
 * unconditionally; there are no data-dependent branches and no
 * data-dependent memory accesses.  Total work AND the value-pattern of
 * the intermediates are independent of the secret input.
 *
 * Threat: callers include `prf_nsk` (Sapling nullifier key) where the
 * input is derived from a long-lived spending secret; any timing leak
 * here correlates across every spend.  See AGENT-3.md ("prf.c
 * nullifier-path constant-time audit"). */
void jubjub_to_scalar(const unsigned char *input, unsigned char *result)
{
    struct bigint r, r3, acc;

    bi_from_bytes(&r, JUBJUB_R, 32);

    /* r3 = 3r, the fused per-step subtract constant. */
    bi_from_bytes(&r3, JUBJUB_R, 32);
    {
        uint64_t carry = 0;
        for (int i = 0; i < NL; i++) {
            uint64_t limb = r3.d[i];
            uint64_t twice = limb + limb;
            uint64_t thrice = twice + limb;
            uint64_t result = thrice + carry;
            carry = (twice < limb) + (thrice < twice) + (result < thrice);
            r3.d[i] = result;
        }
    }

    /* Shifted representation: A = value + r.  value starts at 0, so
     * A starts at r. */
    bi_from_bytes(&acc, JUBJUB_R, 32);

    /* Process 512 bits from MSB (bit 511) to LSB (bit 0). */
    for (int bit = 511; bit >= 0; bit--) {
        /* acc = 2A | b.  A >= r, so 2A|b >= 2r: never zero, and the
         * next subtract's borrow is exactly the old
         * "value >= r after shift" test. */
        bi_shl1(&acc);

        /* OR in the next input bit - branchless.  byte_idx / bit_idx
         * are derived from the public loop counter only, not from the
         * secret. */
        int byte_idx = bit >> 3;
        int bit_idx = bit & 7;
        acc.d[0] |= (uint64_t)((input[byte_idx] >> bit_idx) & 1u);

        /* Reduce: D = 2A|b - 3r, borrow = [2A|b < 3r] = [value' < r],
         * then A = D + r + borrow*r restores A = value + r.  Always
         * executes; the borrow only ever scales a public constant. */
        uint64_t need_add = bi_sub(&acc, &r3);
        bi_add_r_weighted(&acc, &r, need_add);
    }

    /* Back to canonical form: result = A - r (in [0, r)). */
    (void)bi_sub(&acc, &r);
    bi_to_bytes(&acc, result, 32);
    /* acc contains the reduced secret scalar after the output copy. */
    volatile unsigned char *secret = (volatile unsigned char *)&acc;
    for (size_t i = 0; i < sizeof acc; ++i) secret[i] = 0;
}
