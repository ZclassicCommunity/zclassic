/* zclassicd glue for the vendored Z23 service parsers (src/c23/services).
 *
 * Stands in for Z23's primitives/transaction.h. The one vendored function that
 * takes a struct transaction, slp_classify_tx_output (slp.c), reads exactly:
 *     tx->num_vout, tx->vout[0].script_pub_key.{data,size}, tx->hash.data
 * so this is the thinnest view that satisfies it, with the same member names
 * and the same (non-const) pointer types Z23 uses. Borrowed pointers, nothing
 * owned, nothing serialized. zcl_token_guard.c fills one in per call.
 *
 * This header is found through -iquote, which is searched before -I. That is
 * what keeps the vendored `#include "primitives/transaction.h"` from resolving
 * to zclassicd's own C++ src/primitives/transaction.h. C only: this directory
 * must never be on a C++ include path. */
#ifndef ZCL_SERVICES_GLUE_PRIMITIVES_TRANSACTION_H
#define ZCL_SERVICES_GLUE_PRIMITIVES_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>
#include "core/uint256.h"

struct script {
    uint8_t *data;
    size_t size;
};

struct tx_out {
    struct script script_pub_key;
};

struct transaction {
    struct tx_out *vout;  /* only vout[0] is ever read */
    size_t num_vout;      /* the REAL output count of the transaction */
    struct uint256 hash;  /* txid, internal byte order */
};

#endif
