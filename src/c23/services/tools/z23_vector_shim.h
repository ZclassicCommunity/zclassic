/* Shim for tools/z23-vector-check.sh: the few things Z23's own SLP tests use
 * that are not in the vendored closure. zclassicd-owned test support; it is
 * compiled only by that script, never into a zclassic binary.
 *
 * The test bodies themselves are extracted VERBATIM from the pinned Z23
 * commit at run time. Nothing in this file decides a test outcome. */
#ifndef ZCL_SERVICES_Z23_VECTOR_SHIM_H
#define ZCL_SERVICES_Z23_VECTOR_SHIM_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zslp/slp.h"
#include "script/op_return_push.h"
#include "core/uint256.h"
#include "primitives/transaction.h"

/* From Z23 tests/harness/src/test_overlay_parse_parity.c (file-scope items the
 * extracted functions refer to). */
#define CORPUS_MAX 512

struct script_case {
    uint8_t bytes[CORPUS_MAX];
    size_t len;
};

static uint64_t prng_state = 0x9E3779B97F4A7C15ULL;

/* Z23's transaction helpers, over the glue's thin struct transaction. The
 * classifier test only needs: writable vout[i].script_pub_key buffers and a
 * stable tx.hash. Any fixed hash will do; the test compares a token id with
 * the hash it was derived from. */
#define SHIM_SCRIPT_CAP 512

static inline void transaction_init(struct transaction *tx)
{
    memset(tx, 0, sizeof(*tx));
}

static inline bool transaction_alloc(struct transaction *tx, size_t num_vin,
                                     size_t num_vout)
{
    (void)num_vin;
    tx->vout = calloc(num_vout ? num_vout : 1, sizeof(*tx->vout));
    if (!tx->vout)
        return false;
    tx->num_vout = num_vout;
    for (size_t i = 0; i < num_vout; i++) {
        tx->vout[i].script_pub_key.data = calloc(1, SHIM_SCRIPT_CAP);
        if (!tx->vout[i].script_pub_key.data)
            return false;
    }
    return true;
}

static inline void transaction_compute_hash(struct transaction *tx)
{
    uint64_t h = 0xcbf29ce484222325ULL; /* FNV-1a over every script byte */
    for (size_t i = 0; i < tx->num_vout; i++)
        for (size_t j = 0; j < tx->vout[i].script_pub_key.size; j++)
            h = (h ^ tx->vout[i].script_pub_key.data[j]) * 0x100000001b3ULL;
    for (int i = 0; i < 32; i++) {
        h = (h ^ (uint64_t)i) * 0x100000001b3ULL;
        tx->hash.data[i] = (uint8_t)(h >> 32);
    }
}

static inline void transaction_free(struct transaction *tx)
{
    if (tx->vout) {
        for (size_t i = 0; i < tx->num_vout; i++)
            free(tx->vout[i].script_pub_key.data);
        free(tx->vout);
    }
    memset(tx, 0, sizeof(*tx));
}

#endif
