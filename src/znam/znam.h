/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names (ZNAM) — On-chain name registry protocol.
 *
 * Design inspired by Ethereum Name Service (ENS):
 *   https://github.com/ensdomains/ens-contracts
 *   Copyright (c) ENS contributors — MIT License
 *
 * Key concepts from ENS adapted to OP_RETURN on ZClassic:
 *   - Separate registry (ownership) from records (resolution)
 *   - Multiple record types per name (addr, text, content)
 *   - Multi-coin address resolution (ZCL, BTC, LTC, DOGE)
 *   - Arbitrary key-value text records (email, url, avatar)
 *
 * Encoded in OP_RETURN outputs (vout[0]), same pattern as ZSLP.
 * Lokad ID: "ZNAM" (0x5a4e414d)
 *
 * Commands: REGISTER, UPDATE, TRANSFER, RENEW, SET_RECORD, SET_TEXT
 * Ownership determined by first input's address (P2PKH signer).
 * First-come-first-served registration, like ENS FIFSRegistrar.
 *
 * PORTED from lib/znam (github.com/RhettCreighton/zclassic-c, Apache-2.0,
 * Rhett Creighton) into the C++ daemon. The wire bytes are PERMANENT: this
 * file is the authoritative encoder/decoder; see
 * doc/platform/ZNAM_DETERMINISM_SPEC.md. The only daemon-port edits are the
 * two include paths below (the protocol bytes are unchanged). */

#ifndef ZCL_ZNAM_H
#define ZCL_ZNAM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ZNAM Lokad ID */
#define ZNAM_LOKAD_BYTES  "ZNAM"

/* Target types (ENS-style multi-coin, plus .onion) */
#define ZNAM_TYPE_ONION   0x01   /* .onion hidden service address */
#define ZNAM_TYPE_ZADDR   0x02   /* ZCL shielded z-address */
#define ZNAM_TYPE_TADDR   0x03   /* ZCL transparent t-address */
#define ZNAM_TYPE_BTC     0x04   /* Bitcoin address */
#define ZNAM_TYPE_LTC     0x05   /* Litecoin address */
#define ZNAM_TYPE_DOGE    0x06   /* Dogecoin address */
#define ZNAM_TYPE_CONTENT 0x07   /* Content hash (file market root_hash) */

/* Commands */
enum znam_command {
    ZNAM_CMD_INVALID    = 0,
    ZNAM_CMD_REGISTER   = 1,   /* Register name + primary target */
    ZNAM_CMD_UPDATE     = 2,   /* Update primary target */
    ZNAM_CMD_TRANSFER   = 3,   /* Transfer ownership */
    ZNAM_CMD_RENEW      = 4,   /* Renew registration */
    ZNAM_CMD_SET_RECORD = 5,   /* Set additional address record (multi-coin) */
    ZNAM_CMD_SET_TEXT   = 6,   /* Set text record (key-value, ENS TextResolver) */
};

/* Max name length */
#define ZNAM_NAME_MAX 63

/* Max target value length */
#define ZNAM_VALUE_MAX 128

/* Max text key/value lengths */
#define ZNAM_TEXT_KEY_MAX 32
#define ZNAM_TEXT_VAL_MAX 128

/* Parsed ZNAM message from OP_RETURN */
struct znam_message {
    enum znam_command command;
    char name[ZNAM_NAME_MAX + 1];
    uint8_t target_type;                    /* ZNAM_TYPE_* */
    char target_value[ZNAM_VALUE_MAX + 1];
    char new_owner[64];                     /* TRANSFER only */
    char text_key[ZNAM_TEXT_KEY_MAX + 1];   /* SET_TEXT only */
    char text_value[ZNAM_TEXT_VAL_MAX + 1]; /* SET_TEXT only */
};

/* Parse an OP_RETURN script into a ZNAM message.
 * Returns true if the script is a valid ZNAM message. */
bool znam_parse(const uint8_t *script, size_t script_len,
                struct znam_message *msg);

/* Validate a ZNAM name: lowercase alphanumeric + hyphens,
 * no leading/trailing hyphen, 1-63 chars. */
bool znam_validate_name(const char *name);

/* Build OP_RETURN scripts for each command.
 * Caller provides the output buffer; all builders return the number of
 * bytes written, or 0 on invalid input or if the buffer is too small. */

/* REGISTER: name + primary target. Requires znam_validate_name(name),
 * non-NULL target_value, and target_type in 1..ZNAM_TYPE_CONTENT (the
 * full multi-coin/onion/content range the parser round-trips). */
size_t znam_build_register(uint8_t *out, size_t out_len,
                           const char *name, uint8_t target_type,
                           const char *target_value);

/* UPDATE: replace the primary target. Same constraints as REGISTER. */
size_t znam_build_update(uint8_t *out, size_t out_len,
                         const char *name, uint8_t target_type,
                         const char *target_value);

/* TRANSFER: hand ownership to new_owner. Requires a valid name and a
 * non-NULL new_owner string. */
size_t znam_build_transfer(uint8_t *out, size_t out_len,
                           const char *name, const char *new_owner);

/* RENEW: extend the registration. Requires only a valid name. */
size_t znam_build_renew(uint8_t *out, size_t out_len,
                        const char *name);

/* SET_RECORD (ENS-inspired): set an additional address for a coin type.
 * Same constraints as REGISTER (valid name, non-NULL target_value,
 * target_type in 1..ZNAM_TYPE_CONTENT). */
size_t znam_build_set_record(uint8_t *out, size_t out_len,
                             const char *name, uint8_t target_type,
                             const char *target_value);

/* SET_TEXT (ENS-inspired): set an arbitrary key-value text record.
 * Requires a valid name and a non-empty key of at most ZNAM_TEXT_KEY_MAX
 * bytes; value may be NULL/empty (record deletion) but if present must be
 * at most ZNAM_TEXT_VAL_MAX bytes. */
size_t znam_build_set_text(uint8_t *out, size_t out_len,
                           const char *name, const char *key,
                           const char *value);

#endif
