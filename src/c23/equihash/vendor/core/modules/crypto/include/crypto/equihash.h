/* Copyright (c) 2016 Jack Grigg
 * Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Equihash proof-of-work — pure C23 implementation.
 * Based on: Biryukov & Khovratovich, "Equihash: Asymmetric Proof-of-Work
 * Based on the Generalized Birthday Problem", NDSS 2016.
 *
 * AUTHORITY: this is the verification PRIMITIVE's interface. The consensus
 * PREDICATE block validation runs is domain_consensus_verify_equihash_
 * solution() (core/consensus/src/equihash.c, byte-sealed), which wraps the
 * primitive implemented in core/modules/crypto/src/equihash.c — see the AUTHORITY
 * note there and in core/modules/crypto_registry/src/scheme_equihash_200_9.c. */

#ifndef ZCL_CRYPTO_EQUIHASH_H
#define ZCL_CRYPTO_EQUIHASH_H

#include "crypto/blake2b.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t eh_index;
typedef uint8_t eh_trunc;

struct equihash_params {
    unsigned int N;
    unsigned int K;
    size_t indices_per_hash_output;  /* 512/N */
    size_t hash_output;              /* IndicesPerHashOutput * N/8 */
    size_t collision_bit_length;     /* N/(K+1) */
    size_t collision_byte_length;    /* (CollisionBitLength+7)/8 */
    size_t hash_length;              /* (K+1)*CollisionByteLength */
    size_t final_full_width;         /* 2*CollisionByteLength + sizeof(eh_index)*(1<<K) */
    size_t solution_width;           /* (1<<K)*(CollisionBitLength+1)/8 */
};

/* Fill `p` with every derived dimension for the (N,K) Equihash instance
 * (sub-hash counts, collision bit/byte lengths, row widths, and the on-wire
 * solution_width). Pure arithmetic on N,K — does not touch crypto. Must be
 * called before equihash_initialise_state / equihash_is_valid_solution. */
void equihash_params_init(struct equihash_params *p,
                          unsigned int N, unsigned int K);

/* True iff this build's Equihash machinery can actually run (N,K): the
 * derived collision_bit_length must land in the window the bit-packers
 * (eh_expand_array / eh_compress_array) assert on — 8..24 — and the index
 * packing must fit sizeof(eh_index). All four consensus parameter sets pass:
 * (48,5), (96,5), (200,9), (192,7).
 *
 * Block VERIFICATION does not need this: equihash_solution_params() already
 * admits only those four. It exists for the configuration seams that read
 * (N,K) from chain params — today the miner — so that a future parameter set
 * is refused with a message instead of reaching the bit-packers unchecked. */
bool equihash_params_supported(unsigned int N, unsigned int K);

/* Map a serialized Equihash solution length to its (N, K) parameter set.
 * Recognised sizes: 1344 -> (200,9), 400 -> (192,7), 68 -> (96,5),
 * 36 -> (48,5). Returns true on a recognised size (and writes *n and *k);
 * false otherwise, including when n or k is NULL. */
bool equihash_solution_params(size_t solution_len,
                              unsigned int *n, unsigned int *k);

/* Initialise the BLAKE2b base state that personalizes every per-index hash
 * for this (N,K): keyless BLAKE2b with digest length p->hash_output and the
 * 16-byte personalization "ZcashPoW" || LE32(N) || LE32(K). The caller then
 * feeds the header pre-solution bytes + nonce via blake2b_update before
 * passing this state to equihash_is_valid_solution. Returns blake2b_init's
 * status (0 on success). This personalization is consensus-fixed; changing
 * it changes which solutions verify. */
int equihash_initialise_state(const struct equihash_params *p,
                              struct blake2b_ctx *state);

/* The Equihash PoW verifier. Returns true IFF `soln` is a valid Equihash
 * answer for `base_state` (the personalized BLAKE2b state already fed the
 * header+nonce) under the (N,K) in `p`. A true return certifies ALL of:
 *   - soln_len == p->solution_width and it unpacks to exactly 2^K indices;
 *   - at every Wagner round the paired rows collide on the expected leading
 *     bytes, their index blocks are in canonical (ascending) order, and all
 *     2^K indices are pairwise distinct;
 *   - the final merged row XORs to all-zero over the remaining hash bytes.
 * Any failure of any check returns false (it logs the specific reason and
 * returns; it does NOT abort the process). `base_state` is read-only — the
 * function copies it per index, so the same state verifies many solutions.
 * This is the function the consensus block check dispatches to via the
 * crypto registry (CRYPTO_PROOF_EQUIHASH_200_9). */
bool equihash_is_valid_solution(const struct equihash_params *p,
                                const struct blake2b_ctx *base_state,
                                const unsigned char *soln, size_t soln_len);

/* Generic Wagner-algorithm Equihash solver (BasicSolve).
 *
 * Given the personalised BLAKE2b base_state (already initialised via
 * equihash_initialise_state() and fed the header pre-solution bytes +
 * nonce — exactly the input equihash_is_valid_solution() verifies
 * against), search for ONE valid Equihash answer for the (N,K) in `p`.
 *
 * On success writes the minimal on-wire solution (p->solution_width
 * bytes) to soln_out and returns true. soln_out must have room for at
 * least p->solution_width bytes. Returns false when this challenge has
 * no solution reachable by the basic algorithm (the caller advances the
 * nonce and retries) or on allocation failure.
 *
 * The produced bytes are the same encoding equihash_is_valid_solution()
 * consumes; a true return guarantees that verifier accepts soln_out for
 * the same base_state. This is intended for the small regtest/testnet
 * parameter sets (e.g. (48,5)); it is a correctness-first reference
 * solver, not the optimised mainnet miner in core/modules/crypto/equihash_solver.c. */
bool equihash_basic_solve(const struct equihash_params *p,
                          const struct blake2b_ctx *base_state,
                          unsigned char *soln_out, size_t soln_out_len);

void eh_expand_array(const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t out_len,
                     size_t bit_len, size_t byte_pad);

void eh_compress_array(const unsigned char *in, size_t in_len,
                       unsigned char *out, size_t out_len,
                       size_t bit_len, size_t byte_pad);

void eh_index_to_array(eh_index i, unsigned char *array);
eh_index eh_array_to_index(const unsigned char *array);

size_t eh_get_indices_from_minimal(const unsigned char *minimal,
                                   size_t minimal_len,
                                   size_t collision_bit_len,
                                   eh_index *indices_out,
                                   size_t max_indices);

size_t eh_get_minimal_from_indices(const eh_index *indices,
                                   size_t num_indices,
                                   size_t collision_bit_len,
                                   unsigned char *minimal_out,
                                   size_t max_len);

#endif
