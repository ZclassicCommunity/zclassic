/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Overlay SDK codec — the shared, pedantic OP_RETURN PUSH reader/writer behind
 * every on-chain overlay (ZNAM/ZSLP/ZMSG/ZANC). See overlay/overlay_codec.h.
 * Wraps the raw PUSH encode/decode in script/op_return_push.h so every overlay
 * shares one wire encoding. Fail-anything: every malformed/truncated/oversize
 * field latches the cursor's sticky error and is refused. No logging — these
 * are hot-path predicate helpers over adversarial chain bytes; a rejected
 * overlay is a normal negative result, not an error to record. */

#include "overlay/overlay_codec.h"
#include "script/op_return_push.h"

#include <string.h>

/* ── Reader ─────────────────────────────────────────────────────────── */

bool overlay_reader_open(struct overlay_reader *r,
                         const uint8_t *script, size_t script_len)
{
    if (!r) return false;
    r->p = NULL;
    r->end = NULL;
    r->ok = false;

    if (!script || script_len == 0) return false;
    if (script[0] != 0x6a) return false;          /* OP_RETURN */

    r->p = script + 1;
    r->end = script + script_len;
    r->ok = true;
    return true;
}

bool overlay_reader_begin(struct overlay_reader *r,
                          const uint8_t *script, size_t script_len,
                          const char lokad[OVERLAY_LOKAD_LEN])
{
    if (!overlay_reader_open(r, script, script_len)) return false;
    if (!lokad) { r->ok = false; return false; }

    const uint8_t *data = NULL;
    size_t len = 0;
    if (!overlay_read_field(r, &data, &len)) return false;
    if (len != OVERLAY_LOKAD_LEN ||
        memcmp(data, lokad, OVERLAY_LOKAD_LEN) != 0) {
        r->ok = false;
        return false;
    }
    return true;
}

bool overlay_read_field(struct overlay_reader *r,
                        const uint8_t **data, size_t *len)
{
    if (!r || !r->ok || !data || !len) {
        if (r) r->ok = false;
        return false;
    }
    const uint8_t *next = read_push(r->p, r->end, data, len);
    if (!next) {
        r->ok = false;
        return false;
    }
    r->p = next;
    return true;
}

bool overlay_read_fixed(struct overlay_reader *r, uint8_t *dst, size_t n)
{
    const uint8_t *data = NULL;
    size_t len = 0;
    if (!overlay_read_field(r, &data, &len)) return false;
    if (len != n) {
        r->ok = false;
        return false;
    }
    if (n) {
        if (!dst) {
            r->ok = false;
            return false;
        }
        memcpy(dst, data, n);
    }
    return true;
}

bool overlay_read_u8(struct overlay_reader *r, uint8_t *out)
{
    const uint8_t *data = NULL;
    size_t len = 0;
    if (!overlay_read_field(r, &data, &len)) return false;
    if (len != 1) {
        r->ok = false;
        return false;
    }
    if (out) *out = data[0];
    return true;
}

bool overlay_expect_u8(struct overlay_reader *r, uint8_t expect)
{
    uint8_t got = 0;
    if (!overlay_read_u8(r, &got)) return false;
    if (got != expect) {
        r->ok = false;
        return false;
    }
    return true;
}

bool overlay_read_bounded(struct overlay_reader *r, uint8_t *dst,
                          size_t max_len, size_t *out_len)
{
    const uint8_t *data = NULL;
    size_t len = 0;
    if (!overlay_read_field(r, &data, &len)) return false;
    if (len > max_len) {
        r->ok = false;
        return false;
    }
    if (len) {
        if (!dst) {
            r->ok = false;
            return false;
        }
        memcpy(dst, data, len);
    }
    if (out_len) *out_len = len;
    return true;
}

bool overlay_try_read_fixed(struct overlay_reader *r, uint8_t *dst, size_t n)
{
    if (!r || !r->ok) {
        if (r) r->ok = false;
        return false;
    }

    /* Rewind point: a non-matching field is the END OF THE LIST, so the cursor
     * must be left exactly where the caller can read whatever follows. */
    const uint8_t *save = r->p;
    const uint8_t *data = NULL;
    size_t len = 0;
    if (!overlay_read_field(r, &data, &len) || len != n) {
        r->p = save;
        r->ok = true;               /* not a parse error — see the header */
        return false;
    }
    if (n) {
        if (!dst) {
            r->ok = false;
            return false;
        }
        memcpy(dst, data, n);
    }
    return true;
}

bool overlay_reader_finish(struct overlay_reader *r)
{
    if (!r || !r->ok) {
        if (r) r->ok = false;
        return false;
    }
    if (r->p != r->end) {                          /* trailing bytes */
        r->ok = false;
        return false;
    }
    return true;
}

/* ── Writer ─────────────────────────────────────────────────────────── */

void overlay_writer_begin(struct overlay_writer *w, uint8_t *out, size_t cap,
                          const char lokad[OVERLAY_LOKAD_LEN])
{
    if (!w) return;
    w->out = out;
    w->off = 0;
    w->cap = cap;
    w->ok = false;

    if (!out || cap < 1 || !lokad) return;
    out[0] = 0x6a;                                 /* OP_RETURN */
    w->off = 1;
    w->ok = true;
    overlay_put_field(w, (const uint8_t *)lokad, OVERLAY_LOKAD_LEN);
}

bool overlay_put_field(struct overlay_writer *w,
                       const uint8_t *data, size_t len)
{
    if (!w || !w->ok) {
        if (w) w->ok = false;
        return false;
    }
    if (len && !data) {
        w->ok = false;
        return false;
    }
    static const uint8_t empty = 0;
    if (!push_data_checked(w->out, &w->off, w->cap,
                           len ? data : &empty, len)) {
        w->ok = false;
        return false;
    }
    return true;
}

bool overlay_put_u8(struct overlay_writer *w, uint8_t v)
{
    return overlay_put_field(w, &v, 1);
}

bool overlay_put_empty_pushdata1(struct overlay_writer *w)
{
    if (!w || !w->ok) {
        if (w) w->ok = false;
        return false;
    }
    if (!push_empty_checked(w->out, &w->off, w->cap)) {
        w->ok = false;
        return false;
    }
    return true;
}

size_t overlay_writer_finish(struct overlay_writer *w)
{
    if (!w || !w->ok) return 0;
    return w->off;
}
