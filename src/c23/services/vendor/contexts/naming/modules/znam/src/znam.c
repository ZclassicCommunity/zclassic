/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names (ZNAM) — parser and OP_RETURN builder.
 * Follows the same OP_RETURN encoding pattern as ZSLP. */

#include "znam/znam.h"
#include "overlay/overlay_codec.h"
#include "script/standard.h"
#include <string.h>

/* Parsing and building both run on the shared overlay cursors
 * (overlay/overlay_codec.h), which wrap the same PUSH encoding ZSLP uses.
 *
 * One deliberate omission: this parser does NOT call overlay_reader_finish.
 * ZNAM shipped without a trailing-byte check and its registrations are live on
 * mainnet, so a script carrying bytes after the last field parses today.
 * Rejecting those would change which on-chain records the node honours. */

/* ZNAM version byte — field 1 of every record. */
#define ZNAM_VERSION 1

/* ── Name validation ────────────────────────────────────────────── */

bool znam_validate_name(const char *name)
{
    if (!name) return false;
    size_t len = strlen(name);
    if (len == 0 || len > ZNAM_NAME_MAX) return false;
    if (name[0] == '-' || name[len - 1] == '-') return false;

    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

/* ── Parser ─────────────────────────────────────────────────────── */

static bool znam_parse_target(struct overlay_reader *r, struct znam_message *msg)
{
    uint8_t target_type = 0;
    if (!overlay_read_u8(r, &target_type)) return false;
    if (target_type < 1 || target_type > ZNAM_TYPE_CONTENT) return false;
    msg->target_type = target_type;
    size_t len = 0;
    if (!overlay_read_bounded(r, (uint8_t *)msg->target_value, ZNAM_VALUE_MAX, &len))
        return false;
    if (len == 0) return false;
    msg->target_value[len] = '\0';
    return true;
}

static bool znam_parse_owner(struct overlay_reader *r, struct znam_message *msg)
{
    size_t len = 0;
    if (!overlay_read_bounded(r, (uint8_t *)msg->new_owner, sizeof(msg->new_owner) - 1, &len))
        return false;
    if (len == 0) return false;
    msg->new_owner[len] = '\0';
    return true;
}

static bool znam_parse_text(struct overlay_reader *r, struct znam_message *msg)
{
    size_t len = 0;
    if (!overlay_read_bounded(r, (uint8_t *)msg->text_key, ZNAM_TEXT_KEY_MAX, &len))
        return false;
    if (len == 0) return false;
    msg->text_key[len] = '\0';
    if (!overlay_read_bounded(r, (uint8_t *)msg->text_value, ZNAM_TEXT_VAL_MAX, &len))
        return false;
    msg->text_value[len] = '\0';
    return true;
}

static bool znam_parse_name(struct overlay_reader *r, struct znam_message *msg)
{
    size_t len = 0;
    if (!overlay_read_bounded(r, (uint8_t *)msg->name, ZNAM_NAME_MAX, &len))
        return false;
    if (len == 0) return false;
    msg->name[len] = '\0';
    if (!znam_validate_name(msg->name)) {
        msg->command = ZNAM_CMD_INVALID;
        return false;
    }
    return true;
}

bool znam_parse(const uint8_t *script, size_t script_len,
                struct znam_message *msg)
{
    if (!msg) return false;
    memset(msg, 0, sizeof(*msg));
    msg->command = ZNAM_CMD_INVALID;

    /* Field 0: lokad_id — must be "ZNAM" (4 bytes), after OP_RETURN. */
    struct overlay_reader r;
    if (!overlay_reader_begin(&r, script, script_len, ZNAM_LOKAD_BYTES))
        return false;

    /* Field 1: version — must be 1 */
    if (!overlay_expect_u8(&r, ZNAM_VERSION)) return false;

    /* Field 2: command */
    uint8_t cmd = 0;
    if (!overlay_read_u8(&r, &cmd)) return false;
    if (cmd < 1 || cmd > 6) return false;
    msg->command = (enum znam_command)cmd;

    /* Field 3: name (always present) */
    if (!znam_parse_name(&r, msg)) return false;

    switch (msg->command) {
    case ZNAM_CMD_REGISTER:
    case ZNAM_CMD_UPDATE:
    case ZNAM_CMD_SET_RECORD:
        return znam_parse_target(&r, msg);
    case ZNAM_CMD_TRANSFER:
        return znam_parse_owner(&r, msg);
    case ZNAM_CMD_RENEW:
        return true;
    case ZNAM_CMD_SET_TEXT:
        return znam_parse_text(&r, msg);
    default:
        return false;
    }
}

/* ── Builders ───────────────────────────────────────────────────── */

/* Emit the shared ZNAM OP_RETURN framing (OP_RETURN + lokad + version +
 * command + name) and arm the writer. */
static void znam_build_header(struct overlay_writer *w, uint8_t *out,
                              size_t cap, uint8_t command, const char *name)
{
    overlay_writer_begin(w, out, cap, ZNAM_LOKAD_BYTES);
    overlay_put_u8(w, ZNAM_VERSION);
    overlay_put_u8(w, command);
    overlay_put_field(w, (const uint8_t *)name, strlen(name));
}

/* Every builder ends here. Standard relay policy caps an OP_RETURN script at
 * MAX_OP_RETURN_RELAY (223) bytes; a longer script is NON-STANDARD and will
 * not relay, so a builder that hands one back has produced a transaction that
 * can never confirm. That was reachable: a maximal SET_TEXT — 63-char name +
 * 32-char key + 128-char value — encodes to 237 bytes. Refuse instead of
 * emitting it. Same shape as blog_anchor_script_build
 * (engine/services/src/blog_publication.c). */
static size_t znam_build_finish(struct overlay_writer *w)
{
    size_t off = overlay_writer_finish(w);
    if (off > MAX_OP_RETURN_RELAY) return 0;
    return off;
}

/* Shared body for the REGISTER / UPDATE / SET_RECORD builders: they differ
 * only in the ZNAM_CMD_* code passed to znam_build_header. The literal-3
 * cap is lifted to ZNAM_TYPE_CONTENT so callers accept the multi-coin types
 * (BTC/LTC/DOGE) and the CONTENT hash that the parser already round-trips. */
static size_t znam_build_targeted(uint8_t *out, size_t out_len,
                                  uint8_t command, const char *name,
                                  uint8_t target_type,
                                  const char *target_value)
{
    if (!znam_validate_name(name) || !target_value || !target_value[0]) return 0;
    if (target_type < 1 || target_type > ZNAM_TYPE_CONTENT) return 0;

    struct overlay_writer w;
    znam_build_header(&w, out, out_len, command, name);
    overlay_put_u8(&w, target_type);
    overlay_put_field(&w, (const uint8_t *)target_value, strlen(target_value));
    return znam_build_finish(&w);
}

size_t znam_build_register(uint8_t *out, size_t out_len,
                           const char *name, uint8_t target_type,
                           const char *target_value)
{
    return znam_build_targeted(out, out_len, ZNAM_CMD_REGISTER, name,
                               target_type, target_value);
}

size_t znam_build_update(uint8_t *out, size_t out_len,
                         const char *name, uint8_t target_type,
                         const char *target_value)
{
    return znam_build_targeted(out, out_len, ZNAM_CMD_UPDATE, name,
                               target_type, target_value);
}

size_t znam_build_transfer(uint8_t *out, size_t out_len,
                           const char *name, const char *new_owner)
{
    if (!znam_validate_name(name) || !new_owner || !new_owner[0]) return 0;

    struct overlay_writer w;
    znam_build_header(&w, out, out_len, ZNAM_CMD_TRANSFER, name);
    overlay_put_field(&w, (const uint8_t *)new_owner, strlen(new_owner));
    return znam_build_finish(&w);
}

size_t znam_build_renew(uint8_t *out, size_t out_len,
                        const char *name)
{
    if (!znam_validate_name(name)) return 0;

    struct overlay_writer w;
    znam_build_header(&w, out, out_len, ZNAM_CMD_RENEW, name);
    return znam_build_finish(&w);
}

/* ENS-inspired: set additional address record for a coin type */
size_t znam_build_set_record(uint8_t *out, size_t out_len,
                             const char *name, uint8_t target_type,
                             const char *target_value)
{
    return znam_build_targeted(out, out_len, ZNAM_CMD_SET_RECORD, name,
                               target_type, target_value);
}

/* ENS-inspired: set arbitrary text record (key-value) */
size_t znam_build_set_text(uint8_t *out, size_t out_len,
                           const char *name, const char *key,
                           const char *value)
{
    if (!znam_validate_name(name) || !key || !key[0]) return 0;
    if (strlen(key) > ZNAM_TEXT_KEY_MAX) return 0;
    if (value && strlen(value) > ZNAM_TEXT_VAL_MAX) return 0;

    struct overlay_writer w;
    znam_build_header(&w, out, out_len, ZNAM_CMD_SET_TEXT, name);
    overlay_put_field(&w, (const uint8_t *)key, strlen(key));
    /* An absent value is the one-byte OP_0 empty push, matching what
     * push_data(len=0) has always emitted here. ZSLP's 0x4c 0x00 spelling is
     * NOT used by ZNAM. */
    overlay_put_field(&w, (const uint8_t *)(value ? value : ""),
                      value ? strlen(value) : 0);
    return znam_build_finish(&w);
}
