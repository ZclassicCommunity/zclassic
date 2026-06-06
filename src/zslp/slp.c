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

#include "slp.h"
#include "op_return_push.h"
#include <string.h>

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

bool slp_parse(const uint8_t *script, size_t script_len,
               struct slp_message *msg)
{
    memset(msg, 0, sizeof(*msg));
    msg->type = SLP_TX_INVALID;

    const uint8_t *p = script;
    const uint8_t *end = script + script_len;

    /* Must start with OP_RETURN (0x6a) */
    if (p >= end || *p != 0x6a) return false;
    p++;

    /* Field 0: lokad_id — must be "SLP\0" (4 bytes) */
    const uint8_t *data; size_t len;
    p = read_push(p, end, &data, &len);
    if (!p || len != 4 || memcmp(data, SLP_LOKAD_BYTES, 4) != 0)
        return false;

    /* Field 1: token_type — must be 1 (1-2 bytes) */
    p = read_push(p, end, &data, &len);
    if (!p || len < 1 || len > 2) return false;
    msg->token_type = (uint8_t)be_to_u64(data, len);
    if (msg->token_type != SLP_TOKEN_TYPE_1) return false;

    /* Field 2: transaction_type */
    p = read_push(p, end, &data, &len);
    if (!p) return false;

    if (len == 7 && memcmp(data, "GENESIS", 7) == 0) {
        msg->type = SLP_TX_GENESIS;

        /* Field 3: ticker */
        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len > 0 && len < sizeof(msg->ticker)) {
            memcpy(msg->ticker, data, len);
            msg->ticker[len] = 0;
        }

        /* Field 4: name */
        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len > 0 && len < sizeof(msg->name)) {
            memcpy(msg->name, data, len);
            msg->name[len] = 0;
        }

        /* Field 5: document_url */
        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len > 0 && len < sizeof(msg->document_url)) {
            memcpy(msg->document_url, data, len);
            msg->document_url[len] = 0;
        }

        /* Field 6: document_hash (0 or 32 bytes) */
        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len == 32) {
            memcpy(msg->document_hash, data, 32);
            msg->has_document_hash = true;
        }

        /* Field 7: decimals (1 byte, 0-9) */
        p = read_push(p, end, &data, &len);
        if (!p || len != 1 || data[0] > 9) return false;
        msg->decimals = data[0];

        /* Field 8: mint_baton_vout (0 or 1 byte) */
        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len == 1) {
            if (data[0] < 2) return false; /* vout must be >= 2 */
            msg->mint_baton_vout = data[0];
        }

        /* Field 9: initial_token_mint_quantity (8 bytes) */
        p = read_push(p, end, &data, &len);
        if (!p || len != 8) return false;
        msg->initial_quantity = be_to_u64(data, 8);

        return true;

    } else if (len == 4 && memcmp(data, "MINT", 4) == 0) {
        msg->type = SLP_TX_MINT;

        /* Field 3: token_id (32 bytes) */
        p = read_push(p, end, &data, &len);
        if (!p || len != 32) return false;
        memcpy(msg->token_id.data, data, 32);

        /* Field 4: mint_baton_vout */
        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len == 1) {
            if (data[0] < 2) return false;
            msg->mint_baton_vout = data[0];
        }

        /* Field 5: additional_token_quantity (8 bytes) */
        p = read_push(p, end, &data, &len);
        if (!p || len != 8) return false;
        msg->additional_quantity = be_to_u64(data, 8);

        return true;

    } else if (len == 4 && memcmp(data, "SEND", 4) == 0) {
        msg->type = SLP_TX_SEND;

        /* Field 3: token_id (32 bytes) */
        p = read_push(p, end, &data, &len);
        if (!p || len != 32) return false;
        memcpy(msg->token_id.data, data, 32);

        /* Fields 4+: output quantities (8 bytes each, 1-19 outputs) */
        msg->num_outputs = 0;
        while (msg->num_outputs < 19) {
            const uint8_t *saved = p;
            p = read_push(p, end, &data, &len);
            if (!p || len != 8) {
                p = saved; /* restore for check below */
                break;
            }
            msg->output_quantities[msg->num_outputs++] = be_to_u64(data, 8);
        }
        if (msg->num_outputs < 1) return false;

        return true;
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
    if (out_len < 1) return 0;
    size_t off = 0;
    out[off++] = 0x6a; /* OP_RETURN */

    bool ok = true;
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)SLP_LOKAD_BYTES, 4);

    uint8_t tt = 1;
    ok = ok && push_data_checked(out, &off, out_len, &tt, 1);

    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)"GENESIS", 7);

    /* ticker */
    if (ticker && ticker[0])
        ok = ok && push_data_checked(out, &off, out_len,
                                     (const uint8_t *)ticker, strlen(ticker));
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    /* name */
    if (name && name[0])
        ok = ok && push_data_checked(out, &off, out_len,
                                     (const uint8_t *)name, strlen(name));
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    /* document_url */
    if (document_url && document_url[0])
        ok = ok && push_data_checked(out, &off, out_len,
                                     (const uint8_t *)document_url,
                                     strlen(document_url));
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    /* document_hash */
    if (document_hash)
        ok = ok && push_data_checked(out, &off, out_len, document_hash, 32);
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    /* decimals */
    ok = ok && push_data_checked(out, &off, out_len, &decimals, 1);

    /* mint_baton_vout */
    if (mint_baton_vout >= 2)
        ok = ok && push_data_checked(out, &off, out_len, &mint_baton_vout, 1);
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    /* initial_quantity */
    uint8_t qty[8];
    u64_to_be(qty, initial_quantity);
    ok = ok && push_data_checked(out, &off, out_len, qty, 8);

    return ok ? off : 0;
}

size_t slp_build_mint(uint8_t *out, size_t out_len,
                       const struct uint256 *token_id,
                       uint8_t mint_baton_vout,
                       uint64_t additional_quantity)
{
    if (out_len < 1) return 0;
    size_t off = 0;
    out[off++] = 0x6a;

    bool ok = true;
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)SLP_LOKAD_BYTES, 4);
    uint8_t tt = 1;
    ok = ok && push_data_checked(out, &off, out_len, &tt, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)"MINT", 4);
    ok = ok && push_data_checked(out, &off, out_len, token_id->data, 32);

    if (mint_baton_vout >= 2)
        ok = ok && push_data_checked(out, &off, out_len, &mint_baton_vout, 1);
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    uint8_t qty[8];
    u64_to_be(qty, additional_quantity);
    ok = ok && push_data_checked(out, &off, out_len, qty, 8);

    return ok ? off : 0;
}

size_t slp_build_send(uint8_t *out, size_t out_len,
                       const struct uint256 *token_id,
                       const uint64_t *quantities, int num_outputs)
{
    if (num_outputs < 1 || num_outputs > 19) return 0;
    if (out_len < 1) return 0;

    size_t off = 0;
    out[off++] = 0x6a;

    bool ok = true;
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)SLP_LOKAD_BYTES, 4);
    uint8_t tt = 1;
    ok = ok && push_data_checked(out, &off, out_len, &tt, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)"SEND", 4);
    ok = ok && push_data_checked(out, &off, out_len, token_id->data, 32);

    for (int i = 0; i < num_outputs; i++) {
        uint8_t qty[8];
        u64_to_be(qty, quantities[i]);
        ok = ok && push_data_checked(out, &off, out_len, qty, 8);
    }

    return ok ? off : 0;
}
