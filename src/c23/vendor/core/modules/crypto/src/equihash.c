/* Copyright (c) 2016 Jack Grigg
 * Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Equihash proof-of-work verification — pure C23 implementation.
 *
 * AUTHORITY: this file is the verification PRIMITIVE
 * (equihash_is_valid_solution) plus a reference solver. The consensus
 * PREDICATE that block validation actually runs is
 * domain_consensus_verify_equihash_solution()
 * (core/consensus/src/equihash.c, byte-sealed via core/MANIFEST.sha3),
 * which wraps this primitive. Never call this primitive from validation
 * code directly — route through the sealed predicate (or the
 * crypto_registry "equihash-200-9" scheme, which itself delegates).
 * See the AUTHORITY NOTE in
 * core/modules/crypto_registry/src/scheme_equihash_200_9.c. */

#include "crypto/equihash.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

void equihash_params_init(struct equihash_params *p,
                          unsigned int N, unsigned int K)
{
    p->N = N;
    p->K = K;
    p->indices_per_hash_output = 512 / N;
    p->hash_output = p->indices_per_hash_output * N / 8;
    p->collision_bit_length = N / (K + 1);
    p->collision_byte_length = (p->collision_bit_length + 7) / 8;
    p->hash_length = (K + 1) * p->collision_byte_length;
    p->final_full_width = 2 * p->collision_byte_length +
                          sizeof(eh_index) * ((size_t)1 << K);
    p->solution_width = ((size_t)1 << K) * (p->collision_bit_length + 1) / 8;
}

bool equihash_params_supported(unsigned int N, unsigned int K)
{
    if (N == 0 || K == 0)
        return false;
    /* final_full_width / solution_width both compute (size_t)1 << K. */
    if (K >= 32)
        return false;
    /* indices_per_hash_output = 512 / N must be at least one, and
     * hash_output = indices_per_hash_output * N / 8 must be exact. */
    if (N > 512)
        return false;
    size_t ipho = 512u / N;
    if (ipho == 0 || (ipho * N) % 8 != 0)
        return false;

    size_t cbl = (size_t)N / ((size_t)K + 1);
    /* The bit-packers (eh_expand_array / eh_compress_array) require
     * bit_len >= 8 and 8 * sizeof(uint32_t) >= 7 + bit_len. The widest
     * bit_len they are ever handed is collision_bit_length + 1 (the minimal
     * solution packing in eh_get_indices_from_minimal), so the usable window
     * is 8 <= collision_bit_length <= 24. All four consensus parameter sets
     * land inside it: (48,5)=8, (96,5)=16, (200,9)=20, (192,7)=24. */
    if (cbl < 8)
        return false;
    if (8 * sizeof(uint32_t) < 7 + (cbl + 1))
        return false;
    /* eh_get_indices_from_minimal packs each index into sizeof(eh_index). */
    if (((cbl + 1) + 7) / 8 > sizeof(eh_index))
        return false;
    return true;
}

bool equihash_solution_params(size_t solution_len,
                              unsigned int *n, unsigned int *k)
{
    if (!n || !k)
        return false;

    switch (solution_len) {
    case 1344: *n = 200; *k = 9; return true;
    case 400:  *n = 192; *k = 7; return true;
    case 68:   *n =  96; *k = 5; return true;
    case 36:   *n =  48; *k = 5; return true;
    default:   return false;
    }
}

int equihash_initialise_state(const struct equihash_params *p,
                              struct blake2b_ctx *state)
{
    uint32_t le_N = p->N;
    uint32_t le_K = p->K;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    le_N = __builtin_bswap32(le_N);
    le_K = __builtin_bswap32(le_K);
#endif

    uint8_t personalization[BLAKE2B_PERSONALBYTES] = {0};
    memcpy(personalization, "ZcashPoW", 8);
    memcpy(personalization + 8, &le_N, 4);
    memcpy(personalization + 12, &le_K, 4);

    return blake2b_init_salt_personal(state,
                                      p->hash_output,
                                      NULL, 0,
                                      NULL,
                                      personalization);
}

static void generate_hash(const struct blake2b_ctx *base_state,
                           eh_index g,
                           unsigned char *hash, size_t hash_len)
{
    struct blake2b_ctx state = *base_state;
    eh_index lei = g;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    lei = __builtin_bswap32(lei);
#endif
    blake2b_update(&state, (const unsigned char *)&lei, sizeof(eh_index));
    blake2b_final(&state, hash, hash_len);
}

/* The asserts in the two bit-packers below and in eh_get_*_from_* are
 * DELIBERATELY left as asserts, unlike the hostile-input decoders elsewhere
 * in the tree. They are not reachable with attacker-chosen widths:
 *
 *   - Both inbound (block-verification) paths resolve (N,K) from the
 *     serialized solution LENGTH before anything else runs —
 *     core/consensus/src/equihash.c:54 and
 *     core/modules/crypto_registry/src/scheme_equihash_200_9.c:27 both call
 *     equihash_solution_params() first, and that admits exactly four sizes:
 *       1344 -> (200,9)  collision_bit_length 20
 *        400 -> (192,7)  collision_bit_length 24
 *         68 -> ( 96,5)  collision_bit_length 16
 *         36 -> ( 48,5)  collision_bit_length  8
 *     Every assert below holds for all four, so no peer-supplied block can
 *     trip one.
 *   - eh_compress_array is encode/mining side only (eh_get_minimal_from_
 *     indices); it never sees network input.
 *
 * Converting them would mean void -> bool on two exported symbols plus new
 * branches inside the PoW verifier — a consensus-divergence risk against
 * zclassicd for no live risk reduction. The gap that IS real is a FUTURE
 * chain-params (N,K) entry reaching the packer unchecked; that is closed by
 * equihash_params_supported() below, called at the mining config seams. */
void eh_expand_array(const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t out_len,
                     size_t bit_len, size_t byte_pad)
{
    assert(bit_len >= 8);
    assert(8 * sizeof(uint32_t) >= 7 + bit_len);

    size_t out_width = (bit_len + 7) / 8 + byte_pad;
    assert(out_len == 8 * out_width * in_len / bit_len);

    uint32_t bit_len_mask = ((uint32_t)1 << bit_len) - 1;

    size_t acc_bits = 0;
    uint32_t acc_value = 0;

    size_t j = 0;
    for (size_t i = 0; i < in_len; i++) {
        acc_value = (acc_value << 8) | in[i];
        acc_bits += 8;

        if (acc_bits >= bit_len) {
            acc_bits -= bit_len;
            for (size_t x = 0; x < byte_pad; x++)
                out[j + x] = 0;
            for (size_t x = byte_pad; x < out_width; x++) {
                out[j + x] = (unsigned char)(
                    (acc_value >> (acc_bits + (8 * (out_width - x - 1)))) &
                    ((bit_len_mask >> (8 * (out_width - x - 1))) & 0xFF));
            }
            j += out_width;
        }
    }
}

void eh_compress_array(const unsigned char *in, size_t in_len,
                       unsigned char *out, size_t out_len,
                       size_t bit_len, size_t byte_pad)
{
    assert(bit_len >= 8);
    assert(8 * sizeof(uint32_t) >= 7 + bit_len);

    size_t in_width = (bit_len + 7) / 8 + byte_pad;
    assert(out_len == bit_len * in_len / (8 * in_width));

    uint32_t bit_len_mask = ((uint32_t)1 << bit_len) - 1;

    size_t acc_bits = 0;
    uint32_t acc_value = 0;

    size_t j = 0;
    for (size_t i = 0; i < out_len; i++) {
        if (acc_bits < 8) {
            acc_value = acc_value << bit_len;
            for (size_t x = byte_pad; x < in_width; x++) {
                acc_value = acc_value |
                    ((in[j + x] &
                      ((bit_len_mask >> (8 * (in_width - x - 1))) & 0xFF))
                     << (8 * (in_width - x - 1)));
            }
            j += in_width;
            acc_bits += bit_len;
        }
        acc_bits -= 8;
        out[i] = (unsigned char)((acc_value >> acc_bits) & 0xFF);
    }
}

void eh_index_to_array(eh_index i, unsigned char *array)
{
    eh_index bei;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    bei = __builtin_bswap32(i);
#else
    bei = i;
#endif
    memcpy(array, &bei, sizeof(eh_index));
}

eh_index eh_array_to_index(const unsigned char *array)
{
    eh_index bei;
    memcpy(&bei, array, sizeof(eh_index));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(bei);
#else
    return bei;
#endif
}

size_t eh_get_indices_from_minimal(const unsigned char *minimal,
                                   size_t minimal_len,
                                   size_t collision_bit_len,
                                   eh_index *indices_out,
                                   size_t max_indices)
{
    assert(((collision_bit_len + 1) + 7) / 8 <= sizeof(eh_index));
    size_t len_indices = 8 * sizeof(eh_index) * minimal_len /
                         (collision_bit_len + 1);
    size_t byte_pad = sizeof(eh_index) - ((collision_bit_len + 1) + 7) / 8;

    unsigned char *array = zcl_malloc(len_indices, "eh_expand_indices");
    if (!array) return 0;
    eh_expand_array(minimal, minimal_len,
                    array, len_indices,
                    collision_bit_len + 1, byte_pad);

    size_t count = 0;
    for (size_t i = 0; i < len_indices && count < max_indices;
         i += sizeof(eh_index)) {
        indices_out[count++] = eh_array_to_index(array + i);
    }
    free(array);
    return count;
}

size_t eh_get_minimal_from_indices(const eh_index *indices,
                                   size_t num_indices,
                                   size_t collision_bit_len,
                                   unsigned char *minimal_out,
                                   size_t max_len)
{
    assert(((collision_bit_len + 1) + 7) / 8 <= sizeof(eh_index));
    size_t len_indices = num_indices * sizeof(eh_index);
    size_t min_len = (collision_bit_len + 1) * len_indices /
                     (8 * sizeof(eh_index));
    size_t byte_pad = sizeof(eh_index) - ((collision_bit_len + 1) + 7) / 8;

    if (min_len > max_len) return 0;

    unsigned char *array = zcl_malloc(len_indices, "eh_compress_indices");
    if (!array) return 0;
    for (size_t i = 0; i < num_indices; i++)
        eh_index_to_array(indices[i], array + i * sizeof(eh_index));

    eh_compress_array(array, len_indices,
                      minimal_out, min_len,
                      collision_bit_len + 1, byte_pad);
    free(array);
    return min_len;
}

/* A row in the verification: hash data + appended indices.
 * We dynamically allocate since final_full_width varies by parameters. */
struct eh_row {
    unsigned char *data;
};

static void eh_row_from_hash(struct eh_row *row,
                              const unsigned char *hash_in,
                              size_t h_in_len,
                              size_t h_len,
                              size_t collision_bit_len,
                              eh_index idx,
                              size_t width)
{
    row->data = zcl_calloc(1, width, "eh_row_data");
    if (!row->data) return;
    eh_expand_array(hash_in, h_in_len, row->data, h_len,
                    collision_bit_len, 0);
    eh_index_to_array(idx, row->data + h_len);
}

static bool eh_row_has_collision(const struct eh_row *a,
                                  const struct eh_row *b,
                                  size_t collision_byte_len)
{
    return memcmp(a->data, b->data, collision_byte_len) == 0;
}

static bool eh_row_indices_before(const struct eh_row *a,
                                   const struct eh_row *b,
                                   size_t hash_len,
                                   size_t len_indices)
{
    return memcmp(a->data + hash_len, b->data + hash_len, len_indices) < 0;
}

static bool eh_row_distinct_indices(const struct eh_row *a,
                                     const struct eh_row *b,
                                     size_t hash_len,
                                     size_t len_indices)
{
    for (size_t i = 0; i < len_indices; i += sizeof(eh_index)) {
        for (size_t j = 0; j < len_indices; j += sizeof(eh_index)) {
            if (memcmp(a->data + hash_len + i,
                       b->data + hash_len + j,
                       sizeof(eh_index)) == 0)
                return false;
        }
    }
    return true;
}

static bool eh_row_is_zero(const struct eh_row *row, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (row->data[i] != 0)
            return false;
    }
    return true;
}

static void eh_row_xor_merge(struct eh_row *out,
                               const struct eh_row *a,
                               const struct eh_row *b,
                               size_t hash_len,
                               size_t len_indices,
                               size_t collision_byte_len,
                               size_t width)
{
    out->data = zcl_calloc(1, width, "eh_row_xor");
    if (!out->data) return;

    size_t trim = collision_byte_len;
    for (size_t i = trim; i < hash_len; i++)
        out->data[i - trim] = a->data[i] ^ b->data[i];

    if (eh_row_indices_before(a, b, hash_len, len_indices)) {
        memcpy(out->data + hash_len - trim,
               a->data + hash_len, len_indices);
        memcpy(out->data + hash_len - trim + len_indices,
               b->data + hash_len, len_indices);
    } else {
        memcpy(out->data + hash_len - trim,
               b->data + hash_len, len_indices);
        memcpy(out->data + hash_len - trim + len_indices,
               a->data + hash_len, len_indices);
    }
}

/* Frees one collision round on a reject: every input row, the input array,
 * the `merged` output rows already built this round, and the output array.
 * A reject at pair i has built Xc[0 .. i/2-1]; freeing only X leaked them on
 * every invalid solution. */
static void eh_round_free(struct eh_row *X, size_t count,
                          struct eh_row *Xc, size_t merged)
{
    for (size_t j = 0; j < count; j++) free(X[j].data);
    for (size_t j = 0; j < merged; j++) free(Xc[j].data);
    free(X);
    free(Xc);
}

/* Frees the partially-built leaf rows [0, built), the row array, the index
 * array and the hash scratch on a leaf-row allocation failure. */
static inline void eh_verify_leaf_abort(struct eh_row *X, size_t built,
                                        eh_index *indices,
                                        unsigned char *tmp_hash)
{
    for (size_t j = 0; j < built; j++) free(X[j].data);
    free(X); free(indices); free(tmp_hash);
}

static inline bool eh_verify_leaf_rows_batch8(const struct equihash_params *p,
                                              const struct blake2b_ctx *base_state,
                                              eh_index *indices,
                                              size_t num_indices,
                                              struct eh_row *X,
                                              unsigned char *tmp_hash,
                                              size_t width, size_t *i_io,
                                              size_t *fail_at)
{
    unsigned char *th0 = tmp_hash;
    unsigned char *th1 = tmp_hash + p->hash_output;
    unsigned char *th2 = tmp_hash + p->hash_output * 2;
    unsigned char *th3 = tmp_hash + p->hash_output * 3;

    /* 8-way batch hash generation (AVX-512 -> AVX2 -> scalar) */
    size_t i = *i_io;
    unsigned int iph = (unsigned int)p->indices_per_hash_output;
    unsigned char *th_arr[8] = {th0, th1, th2, th3,
                                tmp_hash + p->hash_output * 4,
                                tmp_hash + p->hash_output * 5,
                                tmp_hash + p->hash_output * 6,
                                tmp_hash + p->hash_output * 7};
    for (; i + 8 <= num_indices; i += 8) {
        uint32_t gi[8];
        for (int k = 0; k < 8; k++)
            gi[k] = indices[i+k] / iph;
        equihash_generate_hash_batch8(base_state, gi, th_arr,
                                       p->hash_output);
        for (int k = 0; k < 8; k++) {
            size_t offset = (indices[i+k] % iph) * p->N / 8;
            eh_row_from_hash(&X[i+k], th_arr[k] + offset,
                             p->N / 8, p->hash_length,
                             p->collision_bit_length, indices[i+k], width);
            if (!X[i+k].data) {
                eh_verify_leaf_abort(X, i + (size_t)k, indices, tmp_hash);
                *fail_at = i + (size_t)k;
                return false;
            }
        }
    }
    *i_io = i;
    return true;
}

static inline bool eh_verify_leaf_rows_batch4(const struct equihash_params *p,
                                              const struct blake2b_ctx *base_state,
                                              eh_index *indices,
                                              size_t num_indices,
                                              struct eh_row *X,
                                              unsigned char *tmp_hash,
                                              size_t width, size_t *i_io,
                                              size_t *fail_at)
{
    unsigned char *th0 = tmp_hash;
    unsigned char *th1 = tmp_hash + p->hash_output;
    unsigned char *th2 = tmp_hash + p->hash_output * 2;
    unsigned char *th3 = tmp_hash + p->hash_output * 3;

    size_t i = *i_io;
    unsigned int iph = (unsigned int)p->indices_per_hash_output;
    /* Handle remaining indices with 4-way or scalar */
    for (; i + 4 <= num_indices; i += 4) {
        uint32_t gi[4] = {
            indices[i]/iph, indices[i+1]/iph,
            indices[i+2]/iph, indices[i+3]/iph
        };
        equihash_generate_hash_batch4(base_state, gi,
                                       th0, th1, th2, th3,
                                       p->hash_output);
        for (int k = 0; k < 4; k++) {
            unsigned char *th = tmp_hash + (size_t)k * p->hash_output;
            size_t offset = (indices[i+k] % iph) * p->N / 8;
            eh_row_from_hash(&X[i+k], th + offset,
                             p->N / 8, p->hash_length,
                             p->collision_bit_length, indices[i+k], width);
            if (!X[i+k].data) {
                eh_verify_leaf_abort(X, i + (size_t)k, indices, tmp_hash);
                *fail_at = i + (size_t)k;
                return false;
            }
        }
    }
    *i_io = i;
    return true;
}

static inline bool eh_verify_leaf_rows_scalar(const struct equihash_params *p,
                                              const struct blake2b_ctx *base_state,
                                              eh_index *indices,
                                              size_t num_indices,
                                              struct eh_row *X,
                                              unsigned char *tmp_hash,
                                              size_t width, size_t *i_io,
                                              size_t *fail_at)
{
    unsigned char *th0 = tmp_hash;
    size_t i = *i_io;
    unsigned int iph = (unsigned int)p->indices_per_hash_output;
    for (; i < num_indices; i++) {
        generate_hash(base_state, indices[i] / iph, th0, p->hash_output);
        size_t offset = (indices[i] % iph) * p->N / 8;
        eh_row_from_hash(&X[i], th0 + offset,
                         p->N / 8, p->hash_length,
                         p->collision_bit_length, indices[i], width);
        if (!X[i].data) {
            eh_verify_leaf_abort(X, i, indices, tmp_hash);
            *fail_at = i;
            return false;
        }
    }
    *i_io = i;
    return true;
}

enum eh_verify_status {
    EH_VERIFY_OK = 0,
    EH_VERIFY_ROUND_ALLOC,
    EH_VERIFY_NO_COLLISION,
    EH_VERIFY_OUT_OF_ORDER,
    EH_VERIFY_NON_DISTINCT,
    EH_VERIFY_MERGE_ALLOC
};

/* Runs every collision round of the verifier over X (count rows). On
 * EH_VERIFY_OK, *X_io / *count_io / *hash_len_io hold the final layer and
 * the caller owns it. On any other status everything is already freed and
 * *fail_at is the row position (or the row count for ROUND_ALLOC). */
static inline enum eh_verify_status eh_verify_collision_rounds(
        const struct equihash_params *p, struct eh_row **X_io,
        size_t *count_io, size_t *hash_len_io, size_t width,
        size_t *fail_at)
{
    struct eh_row *X = *X_io;
    size_t count = *count_io;
    size_t hash_len = *hash_len_io;
    size_t len_indices = sizeof(eh_index);

    while (count > 1) {
        struct eh_row *Xc = zcl_malloc((count / 2) * sizeof(struct eh_row), "equihash_collision_rows");
        if (!Xc) {
            for (size_t i = 0; i < count; i++) free(X[i].data);
            free(X);
            *fail_at = count;
            return EH_VERIFY_ROUND_ALLOC;
        }

        for (size_t i = 0; i < count; i += 2) {
            if (!eh_row_has_collision(&X[i], &X[i + 1],
                                      p->collision_byte_length)) {
                eh_round_free(X, count, Xc, i / 2);
                *fail_at = i;
                return EH_VERIFY_NO_COLLISION;
            }
            if (eh_row_indices_before(&X[i + 1], &X[i],
                                       hash_len, len_indices)) {
                eh_round_free(X, count, Xc, i / 2);
                *fail_at = i;
                return EH_VERIFY_OUT_OF_ORDER;
            }
            if (!eh_row_distinct_indices(&X[i], &X[i + 1],
                                          hash_len, len_indices)) {
                eh_round_free(X, count, Xc, i / 2);
                *fail_at = i;
                return EH_VERIFY_NON_DISTINCT;
            }
            eh_row_xor_merge(&Xc[i / 2], &X[i], &X[i + 1],
                              hash_len, len_indices,
                              p->collision_byte_length, width);
            if (!Xc[i / 2].data) {
                eh_round_free(X, count, Xc, i / 2);
                *fail_at = i;
                return EH_VERIFY_MERGE_ALLOC;
            }
        }

        for (size_t i = 0; i < count; i++) free(X[i].data);
        free(X);
        X = Xc;
        hash_len -= p->collision_byte_length;
        len_indices *= 2;
        count /= 2;
    }

    *X_io = X;
    *count_io = count;
    *hash_len_io = hash_len;
    return EH_VERIFY_OK;
}

/* Final check: a single surviving row whose remaining hash is all zero.
 * Frees the row and the row array. */
static inline bool eh_verify_final_row(struct eh_row *X, size_t count,
                                       size_t hash_len)
{
    bool valid = (count == 1) && eh_row_is_zero(&X[0], hash_len);
    free(X[0].data);
    free(X);
    return valid;
}

bool equihash_is_valid_solution(const struct equihash_params *p,
                                const struct blake2b_ctx *base_state,
                                const unsigned char *soln, size_t soln_len)
{
    if (soln_len != p->solution_width)
        LOG_FAIL("equihash",
                 "is_valid_solution: soln_len=%zu != expected %zu (N=%u K=%u)",
                 soln_len, p->solution_width, p->N, p->K);

    size_t num_indices = (size_t)1 << p->K;
    eh_index *indices = zcl_malloc(num_indices * sizeof(eh_index), "equihash_indices");
    if (!indices)
        LOG_FAIL("equihash",
                 "is_valid_solution: zcl_malloc for %zu indices failed", num_indices);

    size_t got = eh_get_indices_from_minimal(soln, soln_len,
                                             p->collision_bit_length,
                                             indices, num_indices);
    if (got != num_indices) {
        free(indices);
        LOG_FAIL("equihash",
                 "is_valid_solution: unpacked %zu indices, expected %zu",
                 got, num_indices);
    }

    size_t width = p->final_full_width;
    struct eh_row *X = zcl_malloc(num_indices * sizeof(struct eh_row), "equihash_rows");
    if (!X) {
        free(indices);
        LOG_FAIL("equihash", "is_valid_solution: zcl_malloc for rows failed");
    }

    unsigned char *tmp_hash = zcl_malloc(p->hash_output * 8, "equihash_tmp_hash");
    if (!tmp_hash) {
        free(indices); free(X);
        LOG_FAIL("equihash", "is_valid_solution: zcl_malloc for tmp_hash failed");
    }

    size_t i = 0;
    size_t fail_at = 0;
    if (!eh_verify_leaf_rows_batch8(p, base_state, indices, num_indices, X,
                                    tmp_hash, width, &i, &fail_at)) {
        LOG_FAIL("equihash",
                 "is_valid_solution: eh_row_from_hash alloc failed (batch8 i=%zu)",
                 fail_at);
    }
    if (!eh_verify_leaf_rows_batch4(p, base_state, indices, num_indices, X,
                                    tmp_hash, width, &i, &fail_at)) {
        LOG_FAIL("equihash",
                 "is_valid_solution: eh_row_from_hash alloc failed (batch4 i=%zu)",
                 fail_at);
    }
    if (!eh_verify_leaf_rows_scalar(p, base_state, indices, num_indices, X,
                                    tmp_hash, width, &i, &fail_at)) {
        LOG_FAIL("equihash",
                 "is_valid_solution: eh_row_from_hash alloc failed (scalar i=%zu)",
                 fail_at);
    }
    free(tmp_hash);
    free(indices);

    size_t hash_len = p->hash_length;
    size_t count = num_indices;

    enum eh_verify_status st =
        eh_verify_collision_rounds(p, &X, &count, &hash_len, width, &fail_at);
    if (st == EH_VERIFY_ROUND_ALLOC)
        LOG_FAIL("equihash",
                 "is_valid_solution: zcl_malloc for collision rows failed (count=%zu)",
                 fail_at);
    if (st == EH_VERIFY_NO_COLLISION)
        LOG_FAIL("equihash",
                 "is_valid_solution: expected collision at i=%zu (PoW reject)", fail_at);
    if (st == EH_VERIFY_OUT_OF_ORDER)
        LOG_FAIL("equihash",
                 "is_valid_solution: indices out of order at i=%zu (PoW reject)", fail_at);
    if (st == EH_VERIFY_NON_DISTINCT)
        LOG_FAIL("equihash",
                 "is_valid_solution: non-distinct indices at i=%zu (PoW reject)", fail_at);
    if (st == EH_VERIFY_MERGE_ALLOC)
        LOG_FAIL("equihash",
                 "is_valid_solution: eh_row_xor_merge alloc failed at i=%zu",
                 fail_at);

    return eh_verify_final_row(X, count, hash_len);
}

/* ── Generic Wagner-algorithm solver (BasicSolve) ──────────────────
 *
 * Reference port of zcashd src/crypto/equihash.cpp::Equihash<N,K>::BasicSolve.
 * Correctness-first, not the optimised mainnet path — intended for the
 * small regtest/testnet parameter sets where it runs in well under a
 * millisecond. It reuses the same row primitives the verifier above is
 * built from (eh_row_from_hash / eh_row_xor_merge / eh_row_has_collision
 * / eh_row_distinct_indices), so a solution it emits is, by construction,
 * an input equihash_is_valid_solution() accepts for the same base_state. */

/* Sort context for the per-round leading-bytes sort. The solver runs
 * single-threaded for the duration of one solve (callers hold their own
 * serialization), so a file-static comparison length is safe and keeps
 * the row comparator a plain qsort callback. */
static size_t g_eh_sort_hash_len;

static int eh_row_sort_cmp(const void *a, const void *b)
{
    const struct eh_row *ra = a;
    const struct eh_row *rb = b;
    return memcmp(ra->data, rb->data, g_eh_sort_hash_len);
}

static void eh_rows_free(struct eh_row *rows, size_t count)
{
    if (!rows)
        return;
    for (size_t i = 0; i < count; i++)
        free(rows[i].data);
    free(rows);
}

/* Per-round state shared by the BasicSolve pair helpers. */
struct eh_solve_ctx {
    const struct equihash_params *p;
    unsigned int round;
    size_t hash_len;
    size_t len_indices;
    size_t collision_byte_len;
    size_t width;
    unsigned char *soln_out;
    size_t soln_out_len;
    struct eh_row *Xc;
    size_t cap;
    size_t out_count;
};

enum eh_solve_step {
    EH_SOLVE_MORE = 0,
    EH_SOLVE_OOM,
    EH_SOLVE_FOUND
};

/* Builds the init_size leaf rows into X (and frees the hash scratch). On
 * failure X and every row built so far are freed too. */
static inline bool eh_solve_build_leaves(const struct equihash_params *p,
                                         const struct blake2b_ctx *base_state,
                                         struct eh_row *X, size_t init_size,
                                         size_t width, size_t *count_out)
{
    const size_t iph = p->indices_per_hash_output;

    unsigned char *tmp = zcl_malloc(p->hash_output, "eh_solve_tmp_hash");
    if (!tmp) {
        free(X);
        return false;
    }

    size_t count = 0;
    for (size_t g = 0; g < init_size; g++) {
        if (g % iph == 0)
            generate_hash(base_state, (eh_index)(g / iph), tmp, p->hash_output);
        size_t offset = (g % iph) * p->N / 8;
        eh_row_from_hash(&X[count], tmp + offset, p->N / 8, p->hash_length,
                         p->collision_bit_length, (eh_index)g, width);
        if (!X[count].data) {
            free(tmp);
            eh_rows_free(X, count);
            return false;
        }
        count++;
    }
    free(tmp);
    *count_out = count;
    return true;
}

/* Final-round pair: accept only a complete solution. */
static inline enum eh_solve_step eh_solve_pair_final(struct eh_solve_ctx *c,
                                                     struct eh_row *X,
                                                     size_t l, size_t m)
{
    const struct equihash_params *p = c->p;
    size_t hash_len = c->hash_len;
    size_t len_indices = c->len_indices;

    /* Final round: accept only a FULL collision over
     * the whole remaining hash with all-distinct
     * indices — that is a complete solution. */
    if (memcmp(X[l].data, X[m].data, hash_len) != 0)
        return EH_SOLVE_MORE;
    if (!eh_row_distinct_indices(&X[l], &X[m],
                                 hash_len, len_indices))
        return EH_SOLVE_MORE;

    size_t num_idx = (size_t)1 << p->K;
    eh_index *indices = zcl_malloc(
            num_idx * sizeof(eh_index), "eh_solve_indices");
    if (!indices) return EH_SOLVE_OOM;
    /* Canonical ordering: the lexicographically-smaller
     * index block comes first (matches xor_merge). */
    const struct eh_row *a = &X[l], *b = &X[m];
    if (eh_row_indices_before(b, a, hash_len, len_indices)) {
        const struct eh_row *t = a; a = b; b = t;
    }
    /* The row stores each index as a big-endian byte
     * array (eh_index_to_array). eh_get_minimal_from_indices
     * expects a NATIVE eh_index array (it re-encodes), so
     * decode here with eh_array_to_index. */
    for (size_t t = 0; t < num_idx / 2; t++) {
        indices[t] = eh_array_to_index(
                a->data + hash_len + t * sizeof(eh_index));
        indices[num_idx / 2 + t] = eh_array_to_index(
                b->data + hash_len + t * sizeof(eh_index));
    }

    size_t got = eh_get_minimal_from_indices(
            indices, num_idx, p->collision_bit_length,
            c->soln_out, c->soln_out_len);
    free(indices);
    if (got == p->solution_width)
        return EH_SOLVE_FOUND;
    /* Encoding mismatch (should not happen) — keep
     * searching other pairs. */
    return EH_SOLVE_MORE;
}

/* Non-final pair: merge into the next layer, growing it as needed. */
static inline enum eh_solve_step eh_solve_pair_merge(struct eh_solve_ctx *c,
                                                     struct eh_row *X,
                                                     size_t l, size_t m)
{
    if (!eh_row_distinct_indices(&X[l], &X[m],
                                 c->hash_len, c->len_indices))
        return EH_SOLVE_MORE;
    if (c->out_count >= c->cap) {
        size_t ncap = c->cap * 2;
        struct eh_row *grown = zcl_realloc(
                c->Xc, ncap * sizeof(struct eh_row),
                "eh_solve_round_grow");
        if (!grown) return EH_SOLVE_OOM;
        c->Xc = grown;
        c->cap = ncap;
    }
    eh_row_xor_merge(&c->Xc[c->out_count], &X[l], &X[m],
                     c->hash_len, c->len_indices,
                     c->collision_byte_len, c->width);
    if (!c->Xc[c->out_count].data) return EH_SOLVE_OOM;
    c->out_count++;
    return EH_SOLVE_MORE;
}

/* Walks every colliding run of the sorted layer X and feeds each pair to
 * the final or merge helper. Stops at the first OOM or FOUND. */
static inline enum eh_solve_step eh_solve_collide_round(struct eh_solve_ctx *c,
                                                        struct eh_row *X,
                                                        size_t count)
{
    enum eh_solve_step st = EH_SOLVE_MORE;
    for (size_t i = 0; i + 1 < count && st == EH_SOLVE_MORE; ) {
        /* Find the run [i, j) colliding on the leading collision bytes. */
        size_t j = i + 1;
        while (j < count &&
               eh_row_has_collision(&X[i], &X[j], c->collision_byte_len))
            j++;

        for (size_t l = i; l + 1 < j && st == EH_SOLVE_MORE; l++) {
            for (size_t m = l + 1; m < j && st == EH_SOLVE_MORE; m++) {
                st = (c->round == c->p->K)
                         ? eh_solve_pair_final(c, X, l, m)
                         : eh_solve_pair_merge(c, X, l, m);
            }
        }
        i = j;
    }
    return st;
}

bool equihash_basic_solve(const struct equihash_params *p,
                          const struct blake2b_ctx *base_state,
                          unsigned char *soln_out, size_t soln_out_len)
{
    if (!p || !base_state || !soln_out)
        return false;
    if (soln_out_len < p->solution_width)
        return false;

    const size_t width = p->final_full_width;
    const size_t collision_byte_len = p->collision_byte_length;

    /* init_size = number of leaf rows = 2^(collision_bit_length+1). Each
     * BLAKE2b call yields `iph` sub-hashes, so we make init_size/iph calls. */
    const size_t init_size = (size_t)1 << (p->collision_bit_length + 1);

    struct eh_row *X = zcl_malloc(init_size * sizeof(struct eh_row),
                                  "eh_solve_rows");
    if (!X)
        return false;

    size_t count = 0;
    if (!eh_solve_build_leaves(p, base_state, X, init_size, width, &count))
        return false;

    size_t hash_len = p->hash_length;
    size_t len_indices = sizeof(eh_index);

    /* K collision rounds. Rounds 1..K-1 trim+merge; round K finds the
     * final zero-XOR pairs over the last collision_byte_len hash bytes. */
    for (unsigned int round = 1; round <= p->K; round++) {
        g_eh_sort_hash_len = hash_len;
        qsort(X, count, sizeof(struct eh_row), eh_row_sort_cmp);

        /* Worst-case the next layer cannot exceed `count` rows for our
         * use (each colliding run contributes a bounded number of pairs);
         * grow geometrically to stay safe against dense regtest hashes. */
        size_t cap = count > 0 ? count : 1;
        struct eh_solve_ctx ctx = {
            .p = p, .round = round, .hash_len = hash_len,
            .len_indices = len_indices,
            .collision_byte_len = collision_byte_len, .width = width,
            .soln_out = soln_out, .soln_out_len = soln_out_len,
            .Xc = zcl_malloc(cap * sizeof(struct eh_row),
                             "eh_solve_round_rows"),
            .cap = cap, .out_count = 0
        };
        if (!ctx.Xc) {
            eh_rows_free(X, count);
            return false;
        }

        enum eh_solve_step st = eh_solve_collide_round(&ctx, X, count);
        if (st == EH_SOLVE_FOUND) {
            eh_rows_free(ctx.Xc, ctx.out_count);
            eh_rows_free(X, count);
            return true;
        }

        eh_rows_free(X, count);
        if (st == EH_SOLVE_OOM) {
            eh_rows_free(ctx.Xc, ctx.out_count);
            return false;
        }

        if (round == p->K) {
            /* No full-collision solution found this challenge. */
            eh_rows_free(ctx.Xc, ctx.out_count);
            return false;
        }

        X = ctx.Xc;
        count = ctx.out_count;
        hash_len -= collision_byte_len;
        len_indices *= 2;

        if (count == 0)
            break;
    }

    eh_rows_free(X, count);
    return false;
}
