/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared OP_RETURN push helpers — raw-buffer Bitcoin script PUSH
 * encode/decode used by the on-chain data protocols (ZSLP, ZNAM).
 *
 * Shared by lib/zslp/src/slp.c and lib/znam/src/znam.c so both encode/decode
 * OP_RETURN pushes through one definition. */

#ifndef SCRIPT_OP_RETURN_PUSH_H
#define SCRIPT_OP_RETURN_PUSH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Read a Bitcoin script PUSH data field.
 * Returns pointer past the field, or NULL on error.
 * Sets *data and *len to the pushed bytes. */
static inline const uint8_t *read_push(const uint8_t *p, const uint8_t *end,
                                       const uint8_t **data, size_t *len)
{
    if (p >= end) return NULL;
    uint8_t opcode = *p++;

    if (opcode >= 0x01 && opcode <= 0x4b) {
        *len = opcode;
    } else if (opcode == 0x4c) { /* OP_PUSHDATA1 */
        if (p >= end) return NULL;
        *len = *p++;
    } else if (opcode == 0x4d) { /* OP_PUSHDATA2 */
        if (p + 2 > end) return NULL;
        *len = (size_t)p[0] | ((size_t)p[1] << 8);
        p += 2;
    } else {
        return NULL; /* invalid push opcode */
    }

    if (p + *len > end) return NULL;
    *data = p;
    return p + *len;
}

/* Encoded byte count of a PUSH field (prefix + payload), without writing. */
static inline size_t push_data_size(size_t len)
{
    size_t prefix = (len <= 0x4b) ? 1 : (len <= 0xff) ? 2 : 3;
    return prefix + len;
}

/* Encode a PUSH data field into out, returning the bytes written. */
static inline size_t push_data(uint8_t *out, const uint8_t *data, size_t len)
{
    size_t off = 0;
    if (len <= 0x4b) {
        out[off++] = (uint8_t)len;
    } else if (len <= 0xff) {
        out[off++] = 0x4c;
        out[off++] = (uint8_t)len;
    } else {
        out[off++] = 0x4d;
        out[off++] = (uint8_t)(len & 0xff);
        out[off++] = (uint8_t)((len >> 8) & 0xff);
    }
    memcpy(out + off, data, len);
    return off + len;
}

/* Emit an empty push (OP_PUSHDATA1 with length 0x00). */
static inline size_t push_empty(uint8_t *out)
{
    out[0] = 0x4c;
    out[1] = 0x00;
    return 2;
}

/* Bounded PUSH encode. Writes at *off only if the field fits within cap;
 * advances *off and returns true on success, returns false (leaving *off
 * untouched) when the field would overflow the caller's buffer. Produces
 * the same bytes as push_data for every in-bounds field. */
static inline bool push_data_checked(uint8_t *out, size_t *off, size_t cap,
                                     const uint8_t *data, size_t len)
{
    size_t need = push_data_size(len);
    if (need > cap - *off) return false;
    *off += push_data(out + *off, data, len);
    return true;
}

/* Bounded empty-PUSH encode. Same contract as push_data_checked. */
static inline bool push_empty_checked(uint8_t *out, size_t *off, size_t cap)
{
    if (2 > cap - *off) return false;
    *off += push_empty(out + *off);
    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* SCRIPT_OP_RETURN_PUSH_H */
