/* Wallet token guard glue: see zcl_token_guard.h.
 *
 * zclassicd-owned. Calls the vendored Z23 parser; never edits it. */

#include "zcl_token_guard.h"

#include <string.h>

#include "zslp/slp.h"
#include "primitives/transaction.h"

size_t zcl_token_guard_roles(const uint8_t *msg_script, size_t msg_len,
                             const uint8_t txid[32], size_t num_vout,
                             uint8_t *roles, size_t roles_len)
{
    if (!msg_script || msg_len == 0 || !roles || roles_len == 0 || num_vout < 2)
        return 0;

    /* The vendored classifier reads the message from tx->vout[0]. The caller
     * decides which output's script is the candidate message, so present that
     * script as vout[0] of a borrowed view carrying the real output count.
     * The cast drops const only to fit Z23's struct layout: the classifier
     * takes a const struct transaction * and never writes through it. */
    struct tx_out message;
    message.script_pub_key.data = (uint8_t *)msg_script;
    message.script_pub_key.size = msg_len;

    struct transaction view;
    memset(&view, 0, sizeof(view));
    view.vout = &message;
    view.num_vout = num_vout;
    if (txid)
        memcpy(view.hash.data, txid, sizeof(view.hash.data));

    size_t last = num_vout - 1;
    if (last > ZCL_TOKEN_GUARD_MAX_VOUT)
        last = ZCL_TOKEN_GUARD_MAX_VOUT;
    if (last > roles_len - 1)
        last = roles_len - 1;

    size_t raised = 0;
    for (size_t i = 1; i <= last; i++) {
        struct slp_output_metadata meta;
        if (!slp_classify_tx_output(&view, (uint32_t)i, &meta))
            continue;
        uint8_t role = ZCL_TOKEN_ROLE_NONE;
        if (meta.role == SLP_OUTPUT_MINT_BATON)
            role = ZCL_TOKEN_ROLE_MINT_BATON;
        else if (meta.role == SLP_OUTPUT_TOKEN)
            role = ZCL_TOKEN_ROLE_TOKEN;
        if (role != ZCL_TOKEN_ROLE_NONE && roles[i] == ZCL_TOKEN_ROLE_NONE) {
            roles[i] = role;
            raised++;
        }
    }
    return raised;
}

size_t zcl_token_guard_build_genesis(uint8_t *out, size_t out_len,
                                     const char *ticker, const char *name,
                                     const char *document_url,
                                     const uint8_t *document_hash,
                                     uint8_t decimals, uint8_t mint_baton_vout,
                                     uint64_t initial_quantity)
{
    return slp_build_genesis(out, out_len, ticker, name, document_url,
                             document_hash, decimals, mint_baton_vout,
                             initial_quantity);
}

size_t zcl_token_guard_build_mint(uint8_t *out, size_t out_len,
                                  const uint8_t token_id[32],
                                  uint8_t mint_baton_vout,
                                  uint64_t additional_quantity)
{
    struct uint256 id;
    if (!token_id)
        return 0;
    memcpy(id.data, token_id, sizeof(id.data));
    return slp_build_mint(out, out_len, &id, mint_baton_vout,
                          additional_quantity);
}

size_t zcl_token_guard_build_send(uint8_t *out, size_t out_len,
                                  const uint8_t token_id[32],
                                  const uint64_t *quantities, int num_outputs)
{
    struct uint256 id;
    if (!token_id || !quantities)
        return 0;
    memcpy(id.data, token_id, sizeof(id.data));
    return slp_build_send(out, out_len, &id, quantities, num_outputs);
}
