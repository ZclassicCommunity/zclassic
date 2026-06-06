/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Simple Ledger Protocol (SLP) — Token support for ZClassic.
 * Based on SLP Token Type 1 specification from Bitcoin Cash.
 * Tokens are encoded in OP_RETURN outputs (vout[0]).
 *
 * Operations: GENESIS (create), MINT (issue more), SEND (transfer), BURN.
 * Lokad ID: "SLP\x00" (0x534c5000) */

#ifndef ZCL_ZSLP_SLP_H
#define ZCL_ZSLP_SLP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "uint256_c.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SLP Lokad ID */
#define SLP_LOKAD_ID     0x00504c53  /* "SLP\0" little-endian */
#define SLP_LOKAD_BYTES  "\x53\x4c\x50\x00"  /* "SLP\0" */

/* Token type */
#define SLP_TOKEN_TYPE_1  1

/* Canonical SEND output-quantity cap (R-SEND-1 / R-12). A SEND MUST carry
 * 1..ZSLP_SEND_MAX_OUTPUTS quantity pushes; a list of more than this (e.g. a
 * 20th 8-byte push) makes the WHOLE message INVALID — NOT "first N win". This
 * single constant is shared by the parser, the C++ message bridge, the store,
 * and every array bound so all layers agree on the cap (a divergence here
 * forks the ledger). */
#define ZSLP_SEND_MAX_OUTPUTS  19

/* Transaction types */
enum slp_tx_type {
    SLP_TX_GENESIS = 1,
    SLP_TX_MINT    = 2,
    SLP_TX_SEND    = 3,
    SLP_TX_BURN    = 4,  /* implicit — send less than input */
    SLP_TX_INVALID = 0,
};

/* Parsed SLP message from OP_RETURN */
struct slp_message {
    enum slp_tx_type type;
    uint8_t token_type;  /* always 1 for now */

    /* GENESIS fields */
    char ticker[64];
    char name[128];
    char document_url[256];
    uint8_t document_hash[32];
    bool has_document_hash;
    uint8_t decimals;
    uint8_t mint_baton_vout;  /* 0 = no baton */
    uint64_t initial_quantity;

    /* MINT fields */
    struct uint256 token_id;
    uint64_t additional_quantity;
    /* mint_baton_vout reused */

    /* SEND fields */
    /* token_id reused */
    uint64_t output_quantities[ZSLP_SEND_MAX_OUTPUTS]; /* vout[1]..vout[19] */
    int num_outputs;
};

/* Parse an OP_RETURN script into an SLP message.
 * Returns true if the script is a valid SLP message. */
bool slp_parse(const uint8_t *script, size_t script_len,
               struct slp_message *msg);

/* Build OP_RETURN scripts for each transaction type.
 * Caller provides the output buffer; all builders return the number of
 * bytes written, or 0 if the buffer is too small (or, where noted, on
 * invalid input). Token type is always 1. */

/* GENESIS: create a token. ticker/name/document_url may be NULL/empty
 * (encoded as empty pushes); document_hash, if non-NULL, is 32 bytes.
 * mint_baton_vout is emitted only when >= 2 (0/1 mean no baton). */
size_t slp_build_genesis(uint8_t *out, size_t out_len,
                          const char *ticker, const char *name,
                          const char *document_url,
                          const uint8_t *document_hash,
                          uint8_t decimals, uint8_t mint_baton_vout,
                          uint64_t initial_quantity);

/* MINT: issue more of an existing token. token_id is required (32 bytes).
 * mint_baton_vout is emitted only when >= 2 (0/1 mean no baton). */
size_t slp_build_mint(uint8_t *out, size_t out_len,
                       const struct uint256 *token_id,
                       uint8_t mint_baton_vout,
                       uint64_t additional_quantity);

/* SEND: transfer token amounts. token_id and the quantities array are
 * required; num_outputs must be in 1..ZSLP_SEND_MAX_OUTPUTS (returns 0
 * otherwise). */
size_t slp_build_send(uint8_t *out, size_t out_len,
                       const struct uint256 *token_id,
                       const uint64_t *quantities, int num_outputs);

#ifdef __cplusplus
}
#endif

#endif
