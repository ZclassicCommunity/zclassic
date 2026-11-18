/* ZNAM index seam: see zcl_znam_index.h.
 *
 * zclassicd-owned glue. The parse, build and name-syntax functions call the
 * vendored Z23 code unmodified. zcl_znam_owner_hash and zcl_znam_evaluate port
 * the decision rules of Z23's contexts/explorer/models/src/explorer_index_overlays.c
 * and core/modules/script/src/standard.c (Apache-2.0); see the header. */

#include "zcl_znam_index.h"

#include <stdbool.h>
#include <string.h>

#include "znam/znam.h"

int zcl_znam_parse_message(const uint8_t *script, size_t len,
                           struct zcl_znam_parsed *out)
{
    struct znam_message msg;
    if (!script || len == 0 || !out)
        return 0;
    if (!znam_parse(script, len, &msg))
        return 0;
    memset(out, 0, sizeof(*out));
    out->command = (int)msg.command;
    memcpy(out->name, msg.name, sizeof(out->name));
    out->target_type = msg.target_type;
    memcpy(out->target_value, msg.target_value, sizeof(out->target_value));
    memcpy(out->new_owner, msg.new_owner, sizeof(out->new_owner));
    memcpy(out->text_key, msg.text_key, sizeof(out->text_key));
    memcpy(out->text_value, msg.text_value, sizeof(out->text_value));
    out->name[sizeof(out->name) - 1] = '\0';
    out->target_value[sizeof(out->target_value) - 1] = '\0';
    out->new_owner[sizeof(out->new_owner) - 1] = '\0';
    out->text_key[sizeof(out->text_key) - 1] = '\0';
    out->text_value[sizeof(out->text_value) - 1] = '\0';
    return 1;
}

int zcl_znam_validate_name(const char *name)
{
    return znam_validate_name(name) ? 1 : 0;
}

size_t zcl_znam_build(int command, const char *name, uint8_t target_type,
                      const char *target_value, const char *new_owner,
                      const char *text_key, const char *text_value,
                      uint8_t *out, size_t cap)
{
    if (!out || cap == 0 || !name)
        return 0;
    switch (command) {
    case ZCL_ZNAM_CMD_REGISTER:
        return znam_build_register(out, cap, name, target_type, target_value);
    case ZCL_ZNAM_CMD_UPDATE:
        return znam_build_update(out, cap, name, target_type, target_value);
    case ZCL_ZNAM_CMD_TRANSFER:
        return znam_build_transfer(out, cap, name, new_owner);
    case ZCL_ZNAM_CMD_RENEW:
        return znam_build_renew(out, cap, name);
    case ZCL_ZNAM_CMD_SET_RECORD:
        return znam_build_set_record(out, cap, name, target_type, target_value);
    case ZCL_ZNAM_CMD_SET_TEXT:
        return znam_build_set_text(out, cap, name, text_key, text_value);
    default:
        return 0;
    }
}

/* Z23 standard.c:97-113 (utxo_classify_script), the two forms with an address
 * hash. OP_DUP=0x76 OP_HASH160=0xa9 OP_EQUALVERIFY=0x88 OP_CHECKSIG=0xac
 * OP_EQUAL=0x87. */
int zcl_znam_owner_hash(const uint8_t *script, size_t len, uint8_t hash20[20])
{
    if (!script || !hash20)
        return 0;
    if (len == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
        script[2] == 20 && script[23] == 0x88 && script[24] == 0xac) {
        memcpy(hash20, script + 3, 20);
        return 1;
    }
    if (len == 23 && script[0] == 0xa9 && script[1] == 20 && script[22] == 0x87) {
        memcpy(hash20, script + 2, 20);
        return 1;
    }
    return 0;
}

static void ignore(struct zcl_znam_result *out, const char *reason)
{
    out->effect = ZCL_ZNAM_EFFECT_NONE;
    out->reason = reason;
}

/* explorer_index_overlays.c:118 and the like: only the current owner, as the
 * first input's address, may change a name. */
static bool is_owner(const struct zcl_znam_entry *e, int have_owner,
                     const char *owner)
{
    return have_owner && owner && strcmp(e->owner, owner) == 0;
}

void zcl_znam_evaluate(const struct zcl_znam_parsed *msg, int has_entry,
                       const struct zcl_znam_entry *current, int have_owner,
                       const char *owner, int32_t height,
                       struct zcl_znam_result *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->effect = ZCL_ZNAM_EFFECT_NONE;
    out->reason = "invalid input";
    if (!msg)
        return;
    /* apply_znam, line 220 */
    if (!zcl_znam_validate_name(msg->name)) {
        ignore(out, "invalid name");
        return;
    }
    if (has_entry && current)
        out->entry = *current;

    switch (msg->command) {
    case ZCL_ZNAM_CMD_REGISTER:
        /* apply_znam_register, lines 92-108 */
        if (!have_owner) {
            ignore(out, "the first input is not a P2PKH or P2SH output");
            return;
        }
        if (has_entry) {
            ignore(out, "name already registered (first come, first served)");
            return;
        }
        /* db_znam_entry_validate: a target that is empty as a C string is refused */
        if (!msg->target_value[0] || !owner || !owner[0]) {
            ignore(out, "the model refused the entry (empty target)");
            return;
        }
        memset(&out->entry, 0, sizeof(out->entry));
        strncpy(out->entry.owner, owner, ZCL_ZNAM_OWNER_MAX);
        out->entry.target_type = msg->target_type;
        strncpy(out->entry.target_value, msg->target_value, ZCL_ZNAM_VALUE_MAX);
        out->entry.reg_height = height;
        out->entry.expiry_height = height + ZCL_ZNAM_REGISTRATION_TERM_BLOCKS;
        out->effect = ZCL_ZNAM_EFFECT_REGISTER;
        return;
    case ZCL_ZNAM_CMD_UPDATE:
        /* apply_znam_update, lines 111-125 */
        if (!has_entry) {
            ignore(out, "name is not registered");
            return;
        }
        if (!is_owner(current, have_owner, owner)) {
            ignore(out, "the first input is not the name's owner");
            return;
        }
        if (!msg->target_value[0]) {
            ignore(out, "the model refused the entry (empty target)");
            return;
        }
        out->entry.target_type = msg->target_type;
        memset(out->entry.target_value, 0, sizeof(out->entry.target_value));
        strncpy(out->entry.target_value, msg->target_value, ZCL_ZNAM_VALUE_MAX);
        out->effect = ZCL_ZNAM_EFFECT_SET_TARGET;
        return;
    case ZCL_ZNAM_CMD_TRANSFER:
        /* apply_znam_transfer, lines 127-140: new_owner is stored as given,
         * it is never checked to be an address */
        if (!has_entry) {
            ignore(out, "name is not registered");
            return;
        }
        if (!is_owner(current, have_owner, owner)) {
            ignore(out, "the first input is not the name's owner");
            return;
        }
        if (!msg->new_owner[0]) {
            ignore(out, "the model refused the entry (empty owner)");
            return;
        }
        memset(out->entry.owner, 0, sizeof(out->entry.owner));
        strncpy(out->entry.owner, msg->new_owner, ZCL_ZNAM_OWNER_MAX);
        out->effect = ZCL_ZNAM_EFFECT_SET_OWNER;
        return;
    case ZCL_ZNAM_CMD_SET_RECORD:
        /* apply_znam_set_record, lines 142-156 */
        if (!has_entry) {
            ignore(out, "name is not registered");
            return;
        }
        if (!is_owner(current, have_owner, owner)) {
            ignore(out, "the first input is not the name's owner");
            return;
        }
        if (!msg->target_value[0]) {
            ignore(out, "the model refused the record (empty address)");
            return;
        }
        out->record_type = msg->target_type;
        strncpy(out->record_value, msg->target_value, ZCL_ZNAM_VALUE_MAX);
        out->effect = ZCL_ZNAM_EFFECT_SET_RECORD;
        return;
    case ZCL_ZNAM_CMD_SET_TEXT:
        /* apply_znam_set_text, lines 158-170: an empty value is stored, not a deletion */
        if (!has_entry) {
            ignore(out, "name is not registered");
            return;
        }
        if (!is_owner(current, have_owner, owner)) {
            ignore(out, "the first input is not the name's owner");
            return;
        }
        if (!msg->text_key[0]) {
            ignore(out, "the model refused the record (empty key)");
            return;
        }
        strncpy(out->text_key, msg->text_key, ZCL_ZNAM_TEXT_KEY_MAX);
        strncpy(out->text_value, msg->text_value, ZCL_ZNAM_TEXT_VAL_MAX);
        out->effect = ZCL_ZNAM_EFFECT_SET_TEXT;
        return;
    case ZCL_ZNAM_CMD_RENEW: {
        /* apply_znam_renew, lines 172-186: anyone may renew */
        if (!has_entry) {
            ignore(out, "name is not registered");
            return;
        }
        int32_t base = current->expiry_height > height ? current->expiry_height : height;
        out->entry.expiry_height = base + ZCL_ZNAM_REGISTRATION_TERM_BLOCKS;
        out->effect = ZCL_ZNAM_EFFECT_EXTEND;
        return;
    }
    default:
        ignore(out, "unknown command");
        return;
    }
}
