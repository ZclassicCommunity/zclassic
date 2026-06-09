/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names (ZNAM) — parser and OP_RETURN builder.
 * Follows the same OP_RETURN encoding pattern as ZSLP.
 *
 * PORTED from lib/znam (github.com/RhettCreighton/zclassic-c, Apache-2.0).
 * The only daemon-port change from the reference is the two #include paths
 * (the reference used "znam/znam.h" and "script/op_return_push.h"); the
 * protocol bytes are byte-for-byte identical. */

#include "znam.h"
#include "../zslp/op_return_push.h"
#include <string.h>

/* Script push helpers (read_push/push_data) live in
 * zslp/op_return_push.h — same encoding as ZSLP. */

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

bool znam_parse(const uint8_t *script, size_t script_len,
                struct znam_message *msg)
{
    memset(msg, 0, sizeof(*msg));
    msg->command = ZNAM_CMD_INVALID;

    const uint8_t *p = script;
    const uint8_t *end = script + script_len;

    /* Must start with OP_RETURN (0x6a) */
    if (p >= end || *p != 0x6a) return false;
    p++;

    /* Field 0: lokad_id — must be "ZNAM" (4 bytes) */
    const uint8_t *data;
    size_t len;
    p = read_push(p, end, &data, &len);
    if (!p || len != 4 || memcmp(data, ZNAM_LOKAD_BYTES, 4) != 0)
        return false;

    /* Field 1: version — must be 1 */
    p = read_push(p, end, &data, &len);
    if (!p || len != 1 || data[0] != 1) return false;

    /* Field 2: command */
    p = read_push(p, end, &data, &len);
    if (!p || len != 1) return false;

    uint8_t cmd = data[0];
    if (cmd < 1 || cmd > 6) return false;
    msg->command = (enum znam_command)cmd;

    /* Field 3: name (always present) */
    p = read_push(p, end, &data, &len);
    if (!p || len == 0 || len > ZNAM_NAME_MAX) return false;
    memcpy(msg->name, data, len);
    msg->name[len] = '\0';

    if (!znam_validate_name(msg->name)) {
        msg->command = ZNAM_CMD_INVALID;
        return false;
    }

    switch (msg->command) {
    case ZNAM_CMD_REGISTER:
    case ZNAM_CMD_UPDATE:
    case ZNAM_CMD_SET_RECORD:
        /* Field 4: target_type */
        p = read_push(p, end, &data, &len);
        if (!p || len != 1) return false;
        if (data[0] < 1 || data[0] > ZNAM_TYPE_CONTENT) return false;
        msg->target_type = data[0];

        /* Field 5: target_value */
        p = read_push(p, end, &data, &len);
        if (!p || len == 0 || len > ZNAM_VALUE_MAX) return false;
        memcpy(msg->target_value, data, len);
        msg->target_value[len] = '\0';
        return true;

    case ZNAM_CMD_TRANSFER:
        /* Field 4: new_owner address */
        p = read_push(p, end, &data, &len);
        if (!p || len == 0 || len > 63) return false;
        memcpy(msg->new_owner, data, len);
        msg->new_owner[len] = '\0';
        return true;

    case ZNAM_CMD_RENEW:
        /* No additional fields */
        return true;

    case ZNAM_CMD_SET_TEXT:
        /* Field 4: text key */
        p = read_push(p, end, &data, &len);
        if (!p || len == 0 || len > ZNAM_TEXT_KEY_MAX) return false;
        memcpy(msg->text_key, data, len);
        msg->text_key[len] = '\0';

        /* Field 5: text value */
        p = read_push(p, end, &data, &len);
        if (!p || len > ZNAM_TEXT_VAL_MAX) return false;
        memcpy(msg->text_value, data, len);
        msg->text_value[len] = '\0';
        return true;

    default:
        return false;
    }
}

/* ── Builders ───────────────────────────────────────────────────── */

/* Emit the shared ZNAM OP_RETURN framing (lokad + version + command + name)
 * into out within the cap. Advances *off and returns true on success;
 * returns false (offset untouched at the failing push) on buffer overflow. */
static bool znam_build_header(uint8_t *out, size_t *off, size_t cap,
                              uint8_t command, const char *name)
{
    if (cap < 1) return false;
    out[(*off)++] = 0x6a; /* OP_RETURN */

    if (!push_data_checked(out, off, cap,
                           (const uint8_t *)ZNAM_LOKAD_BYTES, 4))
        return false;

    uint8_t version = 1;
    if (!push_data_checked(out, off, cap, &version, 1)) return false;

    if (!push_data_checked(out, off, cap, &command, 1)) return false;

    return push_data_checked(out, off, cap,
                             (const uint8_t *)name, strlen(name));
}

size_t znam_build_register(uint8_t *out, size_t out_len,
                           const char *name, uint8_t target_type,
                           const char *target_value)
{
    if (!znam_validate_name(name) || !target_value) return 0;
    /* lift the literal-3 cap to ZNAM_TYPE_CONTENT so REGISTER
     * accepts the multi-coin types (BTC/LTC/DOGE) and CONTENT hash
     * that the parser and znam_build_set_record already round-trip. */
    if (target_type < 1 || target_type > ZNAM_TYPE_CONTENT) return 0;

    size_t off = 0;
    bool ok = znam_build_header(out, &off, out_len, ZNAM_CMD_REGISTER, name);
    ok = ok && push_data_checked(out, &off, out_len, &target_type, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)target_value,
                                 strlen(target_value));
    return ok ? off : 0;
}

size_t znam_build_update(uint8_t *out, size_t out_len,
                         const char *name, uint8_t target_type,
                         const char *target_value)
{
    if (!znam_validate_name(name) || !target_value) return 0;
    /* lift the literal-3 cap to ZNAM_TYPE_CONTENT (parser parity). */
    if (target_type < 1 || target_type > ZNAM_TYPE_CONTENT) return 0;

    size_t off = 0;
    bool ok = znam_build_header(out, &off, out_len, ZNAM_CMD_UPDATE, name);
    ok = ok && push_data_checked(out, &off, out_len, &target_type, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)target_value,
                                 strlen(target_value));
    return ok ? off : 0;
}

size_t znam_build_transfer(uint8_t *out, size_t out_len,
                           const char *name, const char *new_owner)
{
    if (!znam_validate_name(name) || !new_owner) return 0;

    size_t off = 0;
    bool ok = znam_build_header(out, &off, out_len, ZNAM_CMD_TRANSFER, name);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)new_owner,
                                 strlen(new_owner));
    return ok ? off : 0;
}

size_t znam_build_renew(uint8_t *out, size_t out_len,
                        const char *name)
{
    if (!znam_validate_name(name)) return 0;

    size_t off = 0;
    if (!znam_build_header(out, &off, out_len, ZNAM_CMD_RENEW, name))
        return 0;
    return off;
}

/* ENS-inspired: set additional address record for a coin type */
size_t znam_build_set_record(uint8_t *out, size_t out_len,
                             const char *name, uint8_t target_type,
                             const char *target_value)
{
    if (!znam_validate_name(name) || !target_value) return 0;
    if (target_type < 1 || target_type > ZNAM_TYPE_CONTENT) return 0;

    size_t off = 0;
    bool ok = znam_build_header(out, &off, out_len, ZNAM_CMD_SET_RECORD, name);
    ok = ok && push_data_checked(out, &off, out_len, &target_type, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)target_value,
                                 strlen(target_value));
    return ok ? off : 0;
}

/* ENS-inspired: set arbitrary text record (key-value) */
size_t znam_build_set_text(uint8_t *out, size_t out_len,
                           const char *name, const char *key,
                           const char *value)
{
    if (!znam_validate_name(name) || !key || !key[0]) return 0;
    if (strlen(key) > ZNAM_TEXT_KEY_MAX) return 0;
    if (value && strlen(value) > ZNAM_TEXT_VAL_MAX) return 0;

    size_t off = 0;
    bool ok = znam_build_header(out, &off, out_len, ZNAM_CMD_SET_TEXT, name);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)key, strlen(key));
    /* An empty value (record deletion) MUST use the canonical empty push
     * (OP_PUSHDATA1 0x00) so read_push can decode it on the way back: a bare
     * push_data of length 0 emits 0x00 (OP_0), which this codebase's read_push
     * does NOT accept (it handles 0x01..0x4b / 0x4c / 0x4d only) — a daemon-port
     * fix over the reference, caught by the SET_TEXT round-trip gtest. */
    {
        size_t vlen = value ? strlen(value) : 0;
        if (vlen == 0)
            ok = ok && push_empty_checked(out, &off, out_len);
        else
            ok = ok && push_data_checked(out, &off, out_len,
                                         (const uint8_t *)value, vlen);
    }
    return ok ? off : 0;
}
