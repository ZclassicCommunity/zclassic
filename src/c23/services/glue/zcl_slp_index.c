/* ZSLP index seam: see zcl_slp_index.h.
 *
 * zclassicd-owned glue. zcl_slp_parse_message calls the vendored Z23 parser
 * unmodified. zcl_slp_evaluate ports the decision rules of Z23's
 * contexts/market/models/src/zslp_validity.c (Apache-2.0); see the header for
 * exactly what that means. */

#include "zcl_slp_index.h"

#include <stdbool.h>
#include <string.h>

#include "zslp/slp.h"

int zcl_slp_parse_message(const uint8_t *script, size_t len,
                          struct zcl_slp_parsed *out)
{
    struct slp_message msg;
    if (!script || len == 0 || !out)
        return 0;
    memset(&msg, 0, sizeof(msg));
    if (!slp_parse(script, len, &msg))
        return 0;
    memset(out, 0, sizeof(*out));
    switch (msg.type) {
    case SLP_TX_GENESIS: out->type = ZCL_SLP_TX_GENESIS; break;
    case SLP_TX_MINT:    out->type = ZCL_SLP_TX_MINT; break;
    case SLP_TX_SEND:    out->type = ZCL_SLP_TX_SEND; break;
    default: return 0;
    }
    memcpy(out->ticker, msg.ticker, sizeof(out->ticker));
    memcpy(out->name, msg.name, sizeof(out->name));
    memcpy(out->document_url, msg.document_url, sizeof(out->document_url));
    out->ticker[sizeof(out->ticker) - 1] = '\0';
    out->name[sizeof(out->name) - 1] = '\0';
    out->document_url[sizeof(out->document_url) - 1] = '\0';
    memcpy(out->document_hash, msg.document_hash, 32);
    out->has_document_hash = msg.has_document_hash ? 1 : 0;
    out->decimals = msg.decimals;
    out->mint_baton_vout = msg.mint_baton_vout;
    out->quantity = out->type == ZCL_SLP_TX_GENESIS ? msg.initial_quantity
                                                    : msg.additional_quantity;
    memcpy(out->token_id_wire, msg.token_id.data, 32);
    out->num_outputs = msg.num_outputs;
    if (out->type == ZCL_SLP_TX_SEND) {
        if (msg.num_outputs < 1 || msg.num_outputs > ZCL_SLP_MAX_OUTPUTS)
            return 0;
        for (int i = 0; i < msg.num_outputs; i++)
            out->output_quantities[i] = msg.output_quantities[i];
    }
    return 1;
}

/* ---- rules: ports of zslp_validity.c, SQL removed ---------------------- */

struct input_totals {
    uint64_t token_inputs;
    size_t batons;
    bool mixed_token;
    bool unknown_parent;
    bool invalid_parent;
};

static void set_result(struct zcl_slp_eval *e, int status, const char *reason)
{
    e->status = status;
    e->reason = reason;
}

/* validity_note_input_baton */
static void note_input_baton(struct input_totals *t,
                             const struct zcl_slp_input *in,
                             const uint8_t token_id[32])
{
    if (in->has_ledger && in->role == ZCL_SLP_ROLE_MINT_BATON &&
        memcmp(in->token_id, token_id, 32) == 0)
        t->batons++;
    if (in->parent_same_token && in->parent_status == ZCL_SLP_STATUS_UNKNOWN)
        t->unknown_parent = true;
    if (in->parent_same_token && in->parent_status == ZCL_SLP_STATUS_INVALID)
        t->invalid_parent = true;
}

/* validity_inputs_total: false only when the token input sum overflows. */
static bool inputs_total(const struct zcl_slp_input *inputs, size_t count,
                         const uint8_t token_id[32], struct input_totals *t)
{
    memset(t, 0, sizeof(*t));
    for (size_t i = 0; i < count; i++) {
        if (inputs[i].has_ledger && inputs[i].role == ZCL_SLP_ROLE_TOKEN) {
            if (memcmp(inputs[i].token_id, token_id, 32) != 0) {
                t->mixed_token = true;
                continue;
            }
            if (inputs[i].amount > UINT64_MAX - t->token_inputs)
                return false;
            t->token_inputs += inputs[i].amount;
        }
        note_input_baton(t, &inputs[i], token_id);
    }
    return true;
}

static bool vout_exists(size_t num_vout, uint64_t vout)
{
    return vout < num_vout;
}

static void eval_genesis(const struct zcl_slp_parsed *msg, size_t num_vout,
                         struct zcl_slp_eval *e)
{
    if (msg->quantity > (uint64_t)INT64_MAX) {
        set_result(e, ZCL_SLP_STATUS_UNKNOWN, "quantity_unrepresentable");
    } else if (msg->quantity > 0 && !vout_exists(num_vout, 1)) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "genesis_token_vout_missing");
    } else if (msg->mint_baton_vout &&
               !vout_exists(num_vout, msg->mint_baton_vout)) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "genesis_baton_vout_missing");
    } else {
        set_result(e, ZCL_SLP_STATUS_VALID, "valid_genesis");
        e->output_units = msg->quantity;
        e->minted_units = msg->quantity;
    }
}

static void eval_mint(const struct zcl_slp_parsed *msg, size_t num_vout,
                      const struct input_totals *t, struct zcl_slp_eval *e)
{
    if (t->unknown_parent) {
        set_result(e, ZCL_SLP_STATUS_UNKNOWN, "mint_parent_unknown");
    } else if (t->invalid_parent || t->batons != 1) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "mint_baton_lineage_invalid");
    } else if (msg->quantity > (uint64_t)INT64_MAX) {
        set_result(e, ZCL_SLP_STATUS_UNKNOWN, "quantity_unrepresentable");
    } else if (msg->quantity > 0 && !vout_exists(num_vout, 1)) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "mint_token_vout_missing");
    } else if (msg->mint_baton_vout &&
               !vout_exists(num_vout, msg->mint_baton_vout)) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "mint_baton_vout_missing");
    } else {
        set_result(e, ZCL_SLP_STATUS_VALID, "valid_mint");
        e->output_units = msg->quantity;
        e->minted_units = msg->quantity;
    }
}

static void eval_send(const struct zcl_slp_parsed *msg, size_t num_vout,
                      const struct input_totals *t, struct zcl_slp_eval *e)
{
    uint64_t output_sum = 0;
    bool missing_output = false, output_overflow = false;
    for (int i = 0; i < msg->num_outputs; i++) {
        uint64_t q = msg->output_quantities[i];
        if (q > UINT64_MAX - output_sum)
            output_overflow = true;
        else
            output_sum += q;
        if (q > 0 && !vout_exists(num_vout, (uint64_t)i + 1))
            missing_output = true;
    }
    if (output_overflow) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "output_quantity_overflow");
    } else if (output_sum > (uint64_t)INT64_MAX) {
        set_result(e, ZCL_SLP_STATUS_UNKNOWN, "quantity_unrepresentable");
    } else if (t->unknown_parent) {
        set_result(e, ZCL_SLP_STATUS_UNKNOWN, "send_parent_unknown");
    } else if (t->invalid_parent || t->token_inputs == 0) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "send_ancestry_invalid");
    } else if (t->mixed_token) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "mixed_token_inputs");
    } else if (missing_output) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "send_output_missing");
    } else if (output_sum > t->token_inputs) {
        set_result(e, ZCL_SLP_STATUS_INVALID, "send_output_exceeds_input");
    } else {
        set_result(e, ZCL_SLP_STATUS_VALID, "valid_send");
        e->output_units = output_sum;
        e->burned_units = t->token_inputs - output_sum;
    }
}

/* validate_message */
void zcl_slp_evaluate(const struct zcl_slp_parsed *msg,
                      const uint8_t token_id[32], size_t num_vout,
                      const struct zcl_slp_input *inputs, size_t num_inputs,
                      struct zcl_slp_eval *out)
{
    struct input_totals totals;
    memset(out, 0, sizeof(*out));
    if (!msg || !token_id || (num_inputs && !inputs)) {
        set_result(out, ZCL_SLP_STATUS_UNKNOWN, "bad_arguments");
        return;
    }
    if (!inputs_total(inputs, num_inputs, token_id, &totals)) {
        set_result(out, ZCL_SLP_STATUS_INVALID, "input_quantity_overflow");
        return;
    }
    if (totals.token_inputs > (uint64_t)INT64_MAX) {
        set_result(out, ZCL_SLP_STATUS_UNKNOWN, "input_quantity_unrepresentable");
        return;
    }
    out->input_units = totals.token_inputs;
    if (msg->type == ZCL_SLP_TX_GENESIS)
        eval_genesis(msg, num_vout, out);
    else if (msg->type == ZCL_SLP_TX_MINT)
        eval_mint(msg, num_vout, &totals, out);
    else if (msg->type == ZCL_SLP_TX_SEND)
        eval_send(msg, num_vout, &totals, out);
    else
        set_result(out, ZCL_SLP_STATUS_INVALID, "unsupported_transaction_type");
}
