/* ZSLP index seam: C interface between zclassicd's C++ token index
 * (src/zslp) and the vendored Z23 SLP Token Type 1 wire parser
 * (src/c23/services/vendor), plus the pure validity rules.
 *
 * Plain pointers and integers only, like zcl_token_guard.h: none of the vendor
 * or glue include directories may reach a C++ target.
 *
 * Provenance. zcl_slp_parse_message forwards to the vendored slp_parse,
 * unmodified. zcl_slp_evaluate is GLUE, not vendored: it carries the rule set
 * of Z23's contexts/market/models/src/zslp_validity.c (validity_inputs_total,
 * validity_validate_genesis / _mint / _send, validate_message) with the SQLite
 * reads and ledger writes removed. Z23 keeps its parent facts in node.db
 * tables; here the caller supplies them in struct zcl_slp_input. The reason
 * strings are Z23's own, so the two implementations can be compared line by
 * line. The caller applies blocks in order, so every parent is settled before
 * its child and Z23's bounded ancestry walk is not needed.
 *
 * Nothing here is consensus, mempool policy or relay. */
#ifndef ZCL_SLP_INDEX_H
#define ZCL_SLP_INDEX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_SLP_TX_GENESIS 1
#define ZCL_SLP_TX_MINT    2
#define ZCL_SLP_TX_SEND    3

#define ZCL_SLP_MAX_OUTPUTS 19 /* a SEND names vout 1..19 */

/* A parsed SLP Token Type 1 message. Strings are NUL terminated, already
 * clipped by the vendored parser (ticker 63, name 127, url 255 bytes). */
struct zcl_slp_parsed {
    int type;                          /* ZCL_SLP_TX_* */
    char ticker[64];
    char name[128];
    char document_url[256];
    uint8_t document_hash[32];
    int has_document_hash;
    uint8_t decimals;
    uint8_t mint_baton_vout;           /* 0 = none, else >= 2 */
    uint64_t quantity;                 /* GENESIS initial, MINT additional */
    uint8_t token_id_wire[32];         /* MINT/SEND: wire (display) order */
    int num_outputs;                   /* SEND: 1..19 */
    uint64_t output_quantities[ZCL_SLP_MAX_OUTPUTS + 1];
};

/* Returns 1 and fills *out when `script` is a valid SLP Token Type 1 message
 * (the script must start with OP_RETURN), else 0. */
int zcl_slp_parse_message(const uint8_t *script, size_t len,
                          struct zcl_slp_parsed *out);

#define ZCL_SLP_STATUS_UNKNOWN 0
#define ZCL_SLP_STATUS_VALID   1
#define ZCL_SLP_STATUS_INVALID 2

#define ZCL_SLP_ROLE_TOKEN      1
#define ZCL_SLP_ROLE_MINT_BATON 2

/* What the caller knows about one input of the transaction under evaluation. */
struct zcl_slp_input {
    int has_ledger;            /* the spent outpoint is a recorded token or baton output */
    int role;                  /* ZCL_SLP_ROLE_*, when has_ledger */
    uint8_t token_id[32];      /* internal order, when has_ledger */
    uint64_t amount;           /* base units, when has_ledger */
    int parent_same_token;     /* the spent outpoint's tx is an SLP tx of the target token */
    int parent_status;         /* ZCL_SLP_STATUS_*, when parent_same_token */
};

struct zcl_slp_eval {
    int status;                /* ZCL_SLP_STATUS_* */
    const char *reason;        /* static string, Z23's reason code */
    uint64_t input_units;
    uint64_t output_units;     /* units the transaction creates or forwards */
    uint64_t minted_units;     /* GENESIS / MINT only */
    uint64_t burned_units;     /* SEND: input minus output */
};

/* Decide the validity of one SLP transaction. token_id is the target token in
 * internal byte order (the GENESIS txid for a GENESIS). num_vout is the real
 * output count. On a VALID result the outputs named by the message carry the
 * tokens: GENESIS/MINT vout 1 (when quantity > 0) and mint_baton_vout, SEND
 * vout i+1 for each nonzero quantity i. Otherwise the transaction creates no
 * token output. */
void zcl_slp_evaluate(const struct zcl_slp_parsed *msg,
                      const uint8_t token_id[32], size_t num_vout,
                      const struct zcl_slp_input *inputs, size_t num_inputs,
                      struct zcl_slp_eval *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SLP_INDEX_H */
