/* Wallet token guard: C seam between zclassicd's C++ wallet and the vendored
 * Z23 SLP Token Type 1 wire parser (src/c23/services/vendor).
 *
 * This is the only header of src/c23/services a C++ file may include. It uses
 * plain pointers and integers on purpose: the vendored headers reuse names
 * that zclassicd already has (primitives/transaction.h, uint256), so none of
 * the vendor or glue include directories may reach a C++ target.
 *
 * Wallet-only. Nothing here is consensus, mempool policy or relay. */
#ifndef ZCL_TOKEN_GUARD_H
#define ZCL_TOKEN_GUARD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Roles written by zcl_token_guard_roles. */
#define ZCL_TOKEN_ROLE_NONE       0
#define ZCL_TOKEN_ROLE_TOKEN      1 /* is assigned a token quantity by the message (zero included) */
#define ZCL_TOKEN_ROLE_MINT_BATON 2 /* carries the mint baton */

/* An SLP message can name at most vout 255 (the baton index is one byte; a
 * SEND names vout 1..19), so roles past this index are always NONE. */
#define ZCL_TOKEN_GUARD_MAX_VOUT 255

/* Classify the outputs of one transaction against one candidate SLP message.
 *
 *   msg_script/msg_len  scriptPubKey of the output that would carry the SLP
 *                       message (it must start with OP_RETURN to parse).
 *   txid                32 bytes, internal byte order. Only copied into the
 *                       classifier's token-id result; it never changes a role.
 *   num_vout            the transaction's real output count.
 *   roles/roles_len     roles[i] is only ever RAISED from NONE: an entry that
 *                       is already nonzero is kept. That lets the caller take
 *                       the union of several candidate messages by calling
 *                       this more than once on the same array.
 *
 * Each vout is classified by the vendored slp_classify_tx_output, unmodified.
 * A token output with quantity zero IS protected, as in Z23: the message still
 * assigns the output to the token, and a zero-quantity SEND slot is part of the
 * token transfer that a later spend of the output would take apart.
 *
 * Returns the number of entries that this call raised from NONE (0 when the
 * script is not a parseable SLP message). */
size_t zcl_token_guard_roles(const uint8_t *msg_script, size_t msg_len,
                             const uint8_t txid[32], size_t num_vout,
                             uint8_t *roles, size_t roles_len);

/* Thin forwards to the vendored builders, so tests and tools build real
 * messages with the same code Z23 uses. token_id is 32 bytes in SLP WIRE order
 * (the genesis txid as displayed, i.e. the byte-reverse of the internal txid).
 * Each returns the script length, or 0 if it does not fit / input is invalid. */
size_t zcl_token_guard_build_genesis(uint8_t *out, size_t out_len,
                                     const char *ticker, const char *name,
                                     const char *document_url,
                                     const uint8_t *document_hash,
                                     uint8_t decimals, uint8_t mint_baton_vout,
                                     uint64_t initial_quantity);
size_t zcl_token_guard_build_mint(uint8_t *out, size_t out_len,
                                  const uint8_t token_id[32],
                                  uint8_t mint_baton_vout,
                                  uint64_t additional_quantity);
size_t zcl_token_guard_build_send(uint8_t *out, size_t out_len,
                                  const uint8_t token_id[32],
                                  const uint64_t *quantities, int num_outputs);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TOKEN_GUARD_H */
