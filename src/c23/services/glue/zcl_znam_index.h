/* ZNAM index seam: C interface between zclassicd's C++ name index
 * (src/znam) and the vendored Z23 ZNAM wire parser/builder
 * (src/c23/services/vendor/contexts/naming), plus the pure rule set.
 *
 * Plain pointers and integers only, like zcl_slp_index.h: none of the vendor
 * or glue include directories may reach a C++ target.
 *
 * Provenance.
 *   zcl_znam_parse_message, zcl_znam_build, zcl_znam_validate_name forward to
 *     the vendored znam_parse / znam_build_* / znam_validate_name, unmodified.
 *   zcl_znam_owner_hash and zcl_znam_evaluate are GLUE, not vendored. They
 *     carry the rule set of Z23's contexts/explorer/models/src/explorer_index_overlays.c
 *     (apply_znam, apply_znam_register ... apply_znam_renew) and of
 *     core/modules/script/src/standard.c:utxo_classify_script, with the SQLite
 *     reads and writes removed. Z23 keeps the current name state in node.db
 *     tables; here the caller supplies the current entry. The rejection
 *     reasons are this port's own words: Z23 logs nothing for them. doc/znam.md
 *     cites the Z23 line of every rule.
 *
 * Nothing here is consensus, mempool policy or relay. */
#ifndef ZCL_ZNAM_INDEX_H
#define ZCL_ZNAM_INDEX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Z23 znam.h: ZNAM_CMD_* */
#define ZCL_ZNAM_CMD_REGISTER   1
#define ZCL_ZNAM_CMD_UPDATE     2
#define ZCL_ZNAM_CMD_TRANSFER   3
#define ZCL_ZNAM_CMD_RENEW      4
#define ZCL_ZNAM_CMD_SET_RECORD 5
#define ZCL_ZNAM_CMD_SET_TEXT   6

/* Z23 znam.h: ZNAM_TYPE_* */
#define ZCL_ZNAM_TYPE_ONION   1
#define ZCL_ZNAM_TYPE_ZADDR   2
#define ZCL_ZNAM_TYPE_TADDR   3
#define ZCL_ZNAM_TYPE_BTC     4
#define ZCL_ZNAM_TYPE_LTC     5
#define ZCL_ZNAM_TYPE_DOGE    6
#define ZCL_ZNAM_TYPE_CONTENT 7

#define ZCL_ZNAM_NAME_MAX 63
#define ZCL_ZNAM_VALUE_MAX 128
#define ZCL_ZNAM_TEXT_KEY_MAX 32
#define ZCL_ZNAM_TEXT_VAL_MAX 128
#define ZCL_ZNAM_OWNER_MAX 63
/* Z23 ZNAM_REGISTRATION_TERM_BLOCKS: bookkeeping only, nothing reaps a name. */
#define ZCL_ZNAM_REGISTRATION_TERM_BLOCKS 210240

/* A parsed ZNAM message. Strings are NUL terminated. Like Z23's own struct
 * znam_message they are C strings: a pushed field with an embedded NUL byte is
 * read as the text before the NUL (see doc/znam.md, ambiguity A9). */
struct zcl_znam_parsed {
    int command;                              /* ZCL_ZNAM_CMD_* */
    char name[ZCL_ZNAM_NAME_MAX + 1];
    uint8_t target_type;                      /* REGISTER/UPDATE/SET_RECORD */
    char target_value[ZCL_ZNAM_VALUE_MAX + 1];
    char new_owner[ZCL_ZNAM_OWNER_MAX + 1];   /* TRANSFER */
    char text_key[ZCL_ZNAM_TEXT_KEY_MAX + 1]; /* SET_TEXT */
    char text_value[ZCL_ZNAM_TEXT_VAL_MAX + 1];
};

/* Returns 1 and fills *out when `script` (starting with OP_RETURN) is a valid
 * ZNAM message, else 0. */
int zcl_znam_parse_message(const uint8_t *script, size_t len,
                           struct zcl_znam_parsed *out);

/* Z23 znam_validate_name: 1-63 chars of a-z 0-9 and '-', no leading or
 * trailing '-'. No case folding, no Unicode. Returns 1 when valid. */
int zcl_znam_validate_name(const char *name);

/* Builds the OP_RETURN script of one command with the vendored builders.
 * Fields a command does not use are ignored (NULL allowed). Returns the byte
 * count, or 0 on invalid input, a small buffer, or a script over 223 bytes. */
size_t zcl_znam_build(int command, const char *name, uint8_t target_type,
                      const char *target_value, const char *new_owner,
                      const char *text_key, const char *text_value,
                      uint8_t *out, size_t cap);

/* Owner of a name-changing transaction: Z23 looks at the output its FIRST
 * input spends. Only an exact P2PKH (25 byte) or P2SH (23 byte) script has an
 * address hash; anything else (bare P2PK, multisig, non-standard) has none and
 * the message is ignored. Fills hash20 and returns 1 for P2PKH, 2 for P2SH,
 * 0 for the rest. Rule ZNAM-OWNER-2 (shared with Z23, token-name-rules vectors):
 * the owner text is the P2PKH address for 1 and the P2SH address for 2, so a
 * script hash and a key hash with the same 20 bytes are two different owners.
 * (Before the rule Z23 rendered BOTH as a P2PKH address.) */
int zcl_znam_owner_hash(const uint8_t *script, size_t len, uint8_t hash20[20]);

/* The state the rules read and write for one name. */
struct zcl_znam_entry {
    char owner[ZCL_ZNAM_OWNER_MAX + 1];
    uint8_t target_type;
    char target_value[ZCL_ZNAM_VALUE_MAX + 1];
    int32_t reg_height;
    int32_t expiry_height;
};

#define ZCL_ZNAM_EFFECT_NONE       0 /* ignored: see reason */
#define ZCL_ZNAM_EFFECT_REGISTER   1 /* entry is the new registration */
#define ZCL_ZNAM_EFFECT_SET_TARGET 2 /* entry has the new primary target */
#define ZCL_ZNAM_EFFECT_SET_OWNER  3 /* entry has the new owner */
#define ZCL_ZNAM_EFFECT_EXTEND     4 /* entry has the new expiry */
#define ZCL_ZNAM_EFFECT_SET_RECORD 5 /* record_type / record_value */
#define ZCL_ZNAM_EFFECT_SET_TEXT   6 /* text_key / text_value (empty value kept as a row, as Z23) */

struct zcl_znam_result {
    int effect;                           /* ZCL_ZNAM_EFFECT_* */
    const char *reason;                   /* static string, set when effect is NONE */
    struct zcl_znam_entry entry;          /* REGISTER, SET_TARGET, SET_OWNER, EXTEND */
    uint8_t record_type;                  /* SET_RECORD */
    char record_value[ZCL_ZNAM_VALUE_MAX + 1];
    char text_key[ZCL_ZNAM_TEXT_KEY_MAX + 1];   /* SET_TEXT */
    char text_value[ZCL_ZNAM_TEXT_VAL_MAX + 1];
};

/* Decide what one parsed message does to the name it names.
 *   has_entry / current: the name's present state (NULL when absent).
 *   have_owner / owner:  the P2PKH-form address text of the first input's
 *                        spent output; have_owner is 0 when there is none.
 *   height:              the confirming block's height.
 * Messages are evaluated in block order, transaction order within a block,
 * so "first come, first served" is the caller's ordering, not this function's. */
void zcl_znam_evaluate(const struct zcl_znam_parsed *msg, int has_entry,
                       const struct zcl_znam_entry *current, int have_owner,
                       const char *owner, int32_t height,
                       struct zcl_znam_result *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_ZNAM_INDEX_H */
