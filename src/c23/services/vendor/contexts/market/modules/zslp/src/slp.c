/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Simple Ledger Protocol (SLP) — Token Type 1 parser and builder.
 * Based on the SLP specification from Bitcoin Cash, adapted for ZClassic.
 *
 * OP_RETURN format:
 *   OP_RETURN <lokad_id:4> <token_type:1-2> <tx_type:4-7>
 *             [<field>...] — fields depend on tx_type
 *
 * All integer fields are big-endian. */

#include "zslp/slp.h"
#include "overlay/overlay_codec.h"
#include "primitives/transaction.h"
#include "util/log_macros.h"
#include <string.h>

/* Parsing and building run on the shared overlay cursors
 * (overlay/overlay_codec.h). Two live-on-mainnet constraints shape how:
 *
 *  - No overlay_reader_finish. SLP shipped without a trailing-byte check, and
 *    blog_build_node_announce deliberately appends a hostname after a complete
 *    SEND; those transactions parse today and must keep parsing.
 *  - Empty fields are written with overlay_put_empty_pushdata1 (0x4c 0x00),
 *    which is what this builder has always emitted. The one-byte OP_0 that
 *    overlay_put_field(len=0) produces would change the script bytes, and with
 *    them the txid of every genesis/mint that omits an optional field. */

/* Read a big-endian uint64 from data of given length (1-8 bytes). */
static uint64_t be_to_u64(const uint8_t *data, size_t len)
{
    uint64_t val = 0;
    for (size_t i = 0; i < len && i < 8; i++)
        val = (val << 8) | data[i];
    return val;
}

/* Write a big-endian uint64 (8 bytes). */
static void u64_to_be(uint8_t *out, uint64_t val)
{
    for (int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(val & 0xff);
        val >>= 8;
    }
}

static void slp_token_id_to_internal(const uint8_t wire[32], uint8_t out[32])
{
    for (int i = 0; i < 32; i++)
        out[i] = wire[31 - i];
}

/* True when the classify request is usable: a transaction, a metadata
 * buffer, and a vout index that exists on that transaction. */
static bool slp_classify_args_valid(const struct transaction *tx,
                                    uint32_t vout,
                                    const struct slp_output_metadata *out)
{
    if (!tx || !out || tx->num_vout == 0 || vout == 0 ||
        vout >= tx->num_vout)
        return false;
    return true;
}

/* Classify vout 1 or the mint-baton vout of a GENESIS or MINT
 * transaction: vout 1 carries the minted amount, and a nonzero
 * mint_baton_vout names the baton output. Any other vout is not an SLP
 * output. */
static bool slp_classify_genesis_mint_output(uint32_t vout,
                                             uint8_t mint_baton_vout,
                                             uint64_t amount,
                                             struct slp_output_metadata *out)
{
    if (vout == 1) {
        out->role = SLP_OUTPUT_TOKEN;
        out->amount = amount;
        return true;
    }
    if (mint_baton_vout != 0 && vout == mint_baton_vout) {
        out->role = SLP_OUTPUT_MINT_BATON;
        return true;
    }
    return false;
}

/* Classify an output of a SEND transaction: outputs 1..num_outputs each
 * carry their listed quantity; any other vout is not an SLP output. */
static bool slp_classify_send_output(uint32_t vout,
                                     const struct slp_message *msg,
                                     struct slp_output_metadata *out)
{
    if (vout > (uint32_t)msg->num_outputs)
        return false;
    slp_token_id_to_internal(msg->token_id.data, out->token_id);
    out->role = SLP_OUTPUT_TOKEN;
    out->amount = msg->output_quantities[vout - 1];
    return true;
}

bool slp_classify_tx_output(const struct transaction *tx, uint32_t vout,
                            struct slp_output_metadata *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!slp_classify_args_valid(tx, vout, out))
        return false;

    struct slp_message msg;
    const struct script *opret = &tx->vout[0].script_pub_key;
    if (!slp_parse(opret->data, opret->size, &msg))
        return false;

    switch (msg.type) {
    case SLP_TX_GENESIS:
        memcpy(out->token_id, tx->hash.data, 32);
        return slp_classify_genesis_mint_output(vout, msg.mint_baton_vout,
                                                msg.initial_quantity, out);
    case SLP_TX_MINT:
        slp_token_id_to_internal(msg.token_id.data, out->token_id);
        return slp_classify_genesis_mint_output(vout, msg.mint_baton_vout,
                                                msg.additional_quantity, out);
    case SLP_TX_SEND:
        return slp_classify_send_output(vout, &msg, out);
    default:
        return false;
    }
}

/* Copy a length-prefixed SLP string field into a fixed buffer.
 * The caller has zeroed *out (slp_parse memsets the whole message), so an
 * empty (len==0) or over-long (len >= out_len) field leaves *out as the
 * empty string — preserving the SLP overlay's existing accept-but-drop
 * behavior. An over-long field logs context (Law 2: every dropped field logs
 * context). */
static void slp_copy_str_field(const uint8_t *data, size_t len,
                               char *out, size_t out_len, const char *field_name)
{
    if (len == 0)
        return; /* empty field: keep the zeroed default */
    if (len >= out_len) {
        LOG_WARN("slp", "%s field discarded: len=%zu exceeds cap=%zu",
                 field_name, len, out_len);
        return; /* preserve current behavior: drop, leave empty */
    }
    memcpy(out, data, len);
    out[len] = '\0';
}

/* Read the token_type field and require it to be SLP_TOKEN_TYPE_1.
 * Returns 0 on success, -1 on a malformed field. */
static int slp_read_token_type(struct overlay_reader *r,
                               struct slp_message *msg)
{
    const uint8_t *data = NULL;
    size_t len = 0;
    if (!overlay_read_field(r, &data, &len)) return -1;
    if (len < 1 || len > 2) return -1;
    msg->token_type = (uint8_t)be_to_u64(data, len);
    if (msg->token_type != SLP_TOKEN_TYPE_1) return -1;
    return 0;
}

/* Read the optional mint_baton_vout field: an empty field keeps the
 * zeroed default, a 1-byte field must name a vout >= 2. Returns 0 on
 * success, -1 on a malformed field. */
static int slp_read_mint_baton_vout(struct overlay_reader *r,
                                    struct slp_message *msg)
{
    const uint8_t *data = NULL;
    size_t len = 0;
    if (!overlay_read_field(r, &data, &len)) return -1;
    if (len == 1) {
        if (data[0] < 2) return -1; /* vout must be >= 2 */
        msg->mint_baton_vout = data[0];
    }
    return 0;
}

/* Parse the GENESIS body fields (3-9) that follow the transaction_type.
 * Returns 0 on success, -1 on a malformed field. */
static int slp_parse_genesis_fields(struct overlay_reader *r,
                                    struct slp_message *msg)
{
    const uint8_t *data = NULL;
    size_t len = 0;

    /* Field 3: ticker */
    if (!overlay_read_field(r, &data, &len)) return -1;
    slp_copy_str_field(data, len, msg->ticker, sizeof(msg->ticker), "ticker");

    /* Field 4: name */
    if (!overlay_read_field(r, &data, &len)) return -1;
    slp_copy_str_field(data, len, msg->name, sizeof(msg->name), "name");

    /* Field 5: document_url */
    if (!overlay_read_field(r, &data, &len)) return -1;
    slp_copy_str_field(data, len, msg->document_url, sizeof(msg->document_url),
                       "document_url");

    /* Field 6: document_hash (0 or 32 bytes) */
    if (!overlay_read_field(r, &data, &len)) return -1;
    if (len == 32) {
        memcpy(msg->document_hash, data, 32);
        msg->has_document_hash = true;
    }

    /* Field 7: decimals (1 byte, 0-9) */
    uint8_t decimals = 0;
    if (!overlay_read_u8(r, &decimals)) return -1;
    if (decimals > 9) return -1;
    msg->decimals = decimals;

    /* Field 8: mint_baton_vout (0 or 1 byte) */
    if (slp_read_mint_baton_vout(r, msg) != 0) return -1;

    /* Field 9: initial_token_mint_quantity (8 bytes) */
    uint8_t qty[8];
    if (!overlay_read_fixed(r, qty, sizeof(qty))) return -1;
    msg->initial_quantity = be_to_u64(qty, sizeof(qty));

    return 0;
}

/* Parse the MINT body fields (3-5) that follow the transaction_type.
 * Returns 0 on success, -1 on a malformed field. */
static int slp_parse_mint_fields(struct overlay_reader *r,
                                 struct slp_message *msg)
{
    /* Field 3: token_id (32 bytes) */
    if (!overlay_read_fixed(r, msg->token_id.data, 32)) return -1;

    /* Field 4: mint_baton_vout */
    if (slp_read_mint_baton_vout(r, msg) != 0) return -1;

    /* Field 5: additional_token_quantity (8 bytes) */
    uint8_t qty[8];
    if (!overlay_read_fixed(r, qty, sizeof(qty))) return -1;
    msg->additional_quantity = be_to_u64(qty, sizeof(qty));

    return 0;
}

/* Parse the SEND body fields (3+) that follow the transaction_type.
 * Returns 0 on success, -1 on a malformed field. */
static int slp_parse_send_fields(struct overlay_reader *r,
                                 struct slp_message *msg)
{
    /* Field 3: token_id (32 bytes) */
    if (!overlay_read_fixed(r, msg->token_id.data, 32)) return -1;

    /* Fields 4+: output quantities (8 bytes each, 1-19 outputs). The list
     * ends at the first field that is not an 8-byte push — which is a
     * terminator, not a parse error, so it reads through
     * overlay_try_read_fixed and leaves the cursor on that field. */
    uint8_t qty[8];
    msg->num_outputs = 0;
    while (msg->num_outputs < 19 &&
           overlay_try_read_fixed(r, qty, sizeof(qty)))
        msg->output_quantities[msg->num_outputs++] =
            be_to_u64(qty, sizeof(qty));
    if (msg->num_outputs < 1) return -1;

    return 0;
}

bool slp_parse(const uint8_t *script, size_t script_len,
               struct slp_message *msg)
{
    if (!msg) return false;
    memset(msg, 0, sizeof(*msg));
    msg->type = SLP_TX_INVALID;

    /* Field 0: lokad_id — must be "SLP\0" (4 bytes), after OP_RETURN. */
    struct overlay_reader r;
    if (!overlay_reader_begin(&r, script, script_len, SLP_LOKAD_BYTES))
        return false;

    const uint8_t *data = NULL;
    size_t len = 0;

    /* Field 1: token_type — must be 1 (1-2 bytes) */
    if (slp_read_token_type(&r, msg) != 0) return false;

    /* Field 2: transaction_type */
    if (!overlay_read_field(&r, &data, &len)) return false;

    if (len == 7 && memcmp(data, "GENESIS", 7) == 0) {
        msg->type = SLP_TX_GENESIS;
        return slp_parse_genesis_fields(&r, msg) == 0;
    } else if (len == 4 && memcmp(data, "MINT", 4) == 0) {
        msg->type = SLP_TX_MINT;
        return slp_parse_mint_fields(&r, msg) == 0;
    } else if (len == 4 && memcmp(data, "SEND", 4) == 0) {
        msg->type = SLP_TX_SEND;
        return slp_parse_send_fields(&r, msg) == 0;
    }

    return false;
}

/* ── Builders ────────────────────────────────────────────────── */

size_t slp_build_genesis(uint8_t *out, size_t out_len,
                          const char *ticker, const char *name,
                          const char *document_url,
                          const uint8_t *document_hash,
                          uint8_t decimals, uint8_t mint_baton_vout,
                          uint64_t initial_quantity)
{
    struct overlay_writer w;
    overlay_writer_begin(&w, out, out_len, SLP_LOKAD_BYTES);

    overlay_put_u8(&w, SLP_TOKEN_TYPE_1);
    overlay_put_field(&w, (const uint8_t *)"GENESIS", 7);

    /* ticker */
    if (ticker && ticker[0])
        overlay_put_field(&w, (const uint8_t *)ticker, strlen(ticker));
    else
        overlay_put_empty_pushdata1(&w);

    /* name */
    if (name && name[0])
        overlay_put_field(&w, (const uint8_t *)name, strlen(name));
    else
        overlay_put_empty_pushdata1(&w);

    /* document_url */
    if (document_url && document_url[0])
        overlay_put_field(&w, (const uint8_t *)document_url,
                          strlen(document_url));
    else
        overlay_put_empty_pushdata1(&w);

    /* document_hash */
    if (document_hash)
        overlay_put_field(&w, document_hash, 32);
    else
        overlay_put_empty_pushdata1(&w);

    /* decimals */
    overlay_put_u8(&w, decimals);

    /* mint_baton_vout */
    if (mint_baton_vout >= 2)
        overlay_put_u8(&w, mint_baton_vout);
    else
        overlay_put_empty_pushdata1(&w);

    /* initial_quantity */
    uint8_t qty[8];
    u64_to_be(qty, initial_quantity);
    overlay_put_field(&w, qty, sizeof(qty));

    return overlay_writer_finish(&w);
}

size_t slp_build_mint(uint8_t *out, size_t out_len,
                       const struct uint256 *token_id,
                       uint8_t mint_baton_vout,
                       uint64_t additional_quantity)
{
    struct overlay_writer w;
    overlay_writer_begin(&w, out, out_len, SLP_LOKAD_BYTES);

    overlay_put_u8(&w, SLP_TOKEN_TYPE_1);
    overlay_put_field(&w, (const uint8_t *)"MINT", 4);
    overlay_put_field(&w, token_id->data, 32);

    if (mint_baton_vout >= 2)
        overlay_put_u8(&w, mint_baton_vout);
    else
        overlay_put_empty_pushdata1(&w);

    uint8_t qty[8];
    u64_to_be(qty, additional_quantity);
    overlay_put_field(&w, qty, sizeof(qty));

    return overlay_writer_finish(&w);
}

size_t slp_build_send(uint8_t *out, size_t out_len,
                       const struct uint256 *token_id,
                       const uint64_t *quantities, int num_outputs)
{
    if (num_outputs < 1 || num_outputs > 19) return 0;

    struct overlay_writer w;
    overlay_writer_begin(&w, out, out_len, SLP_LOKAD_BYTES);

    overlay_put_u8(&w, SLP_TOKEN_TYPE_1);
    overlay_put_field(&w, (const uint8_t *)"SEND", 4);
    overlay_put_field(&w, token_id->data, 32);

    for (int i = 0; i < num_outputs; i++) {
        uint8_t qty[8];
        u64_to_be(qty, quantities[i]);
        overlay_put_field(&w, qty, sizeof(qty));
    }

    return overlay_writer_finish(&w);
}
