/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Overlay SDK — the shared codec skeleton behind every on-chain "application"
 * overlay (ZNAM names, ZSLP tokens, ZMSG messages, ZANC anchors). All of these
 * are parity-safe OP_RETURN / Sapling-memo overlays: a lokad-tagged, versioned
 * PUSH sequence encoded into a standard OP_RETURN output — NEVER a new opcode
 * and NEVER a consensus-rule change.
 *
 * Historically each overlay hand-rolled the same triple: (a) a lokad-tagged
 * pedantic OP_RETURN parser, (b) an event-log-fed rebuildable projection, and
 * (c) a command/RPC surface. This module extracts (a) — the parser/builder —
 * as two sticky-error cursors:
 *
 *   struct overlay_reader — bounds-checked, fail-anything PUSH field readers.
 *     Every field length, every truncation, every overflow is refused; once a
 *     read fails the cursor latches !ok and all further reads no-op. A parse is
 *     a straight-line sequence of read_* calls ending in overlay_reader_finish,
 *     which additionally rejects any trailing bytes.
 *
 *   struct overlay_writer — bounded PUSH builder with the same sticky-error
 *     model. A build is a straight-line sequence of put_* calls ending in
 *     overlay_writer_finish, which returns the encoded length or 0 if any step
 *     would have overflowed the caller's buffer.
 *
 * Both wrap the raw PUSH encode/decode in script/op_return_push.h so every
 * overlay speaks one wire encoding. Pure: no clock, no RNG, no I/O, no alloc.
 *
 * The rebuildable-projection scaffold + the shared lokad registry / explorer-
 * ingestion seam live in overlay/overlay_projection.h.
 *
 * ADOPTION: all five on-chain overlays now parse and build through these
 * cursors — ZANC (contexts/commons/modules/zanc/src/zanc.c), ZDIR (contexts/naming/modules/zdir/src/zdir.c),
 * ZID (contexts/wallet/modules/zid/src/zid_anchor.c), ZNAM (contexts/naming/modules/znam/src/znam.c) and
 * ZSLP (contexts/market/modules/zslp/src/slp.c). No hand-rolled OP_RETURN PUSH walk is left.
 * ZMSG is deliberately absent: it is a Sapling-memo codec (core/modules/net/src/zmsg.c),
 * not a lokad-tagged OP_RETURN payload, so it has no PUSH sequence to share.
 *
 * ZNAM and ZSLP are already live on mainnet, which constrains this API in two
 * ways a greenfield overlay would not — see overlay_try_read_fixed (an optional
 * repeated field is not a parse error) and overlay_put_empty_pushdata1 (ZSLP
 * encodes an empty field as OP_PUSHDATA1/0, not as OP_0). Neither may be
 * "cleaned up": both describe bytes that already exist in blocks. New overlays
 * should use overlay_put_field(w, NULL-or-data, 0) for an empty field. */

#ifndef ZCL_OVERLAY_CODEC_H
#define ZCL_OVERLAY_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Every overlay lokad tag is exactly four ASCII bytes (e.g. "ZANC"). */
#define OVERLAY_LOKAD_LEN 4

/* ── Pedantic parser cursor ────────────────────────────────────────────
 *
 * Zero-initialize is NOT enough — call overlay_reader_open/begin, which set
 * `ok`. A cursor with ok==false rejects every subsequent read. */
struct overlay_reader {
    const uint8_t *p;     /* next unread byte */
    const uint8_t *end;   /* one past the last script byte */
    bool ok;              /* sticky: false latches all reads to failure */
};

/* Open a reader over an OP_RETURN script: requires a non-empty script whose
 * first byte is 0x6a (OP_RETURN), positioning the cursor just after it. On any
 * failure the reader latches !ok. Returns r->ok. */
bool overlay_reader_open(struct overlay_reader *r,
                         const uint8_t *script, size_t script_len);

/* Open + consume the mandatory 4-byte lokad push, requiring it to equal
 * `lokad`. This is the standard start of every overlay parse. Returns r->ok. */
bool overlay_reader_begin(struct overlay_reader *r,
                          const uint8_t *script, size_t script_len,
                          const char lokad[OVERLAY_LOKAD_LEN]);

/* Read the next PUSH field. On success sets *data (into the script buffer) and
 * *len and returns true; on a malformed/truncated push, or an already-failed
 * cursor, latches !ok and returns false. */
bool overlay_read_field(struct overlay_reader *r,
                        const uint8_t **data, size_t *len);

/* Read a PUSH that must be EXACTLY `n` bytes and copy it into dst (dst must
 * have room for n bytes; may be NULL iff n==0). A shorter or longer push is
 * refused. Returns r->ok. */
bool overlay_read_fixed(struct overlay_reader *r, uint8_t *dst, size_t n);

/* Read a 1-byte PUSH, returning its value in *out. Returns r->ok. */
bool overlay_read_u8(struct overlay_reader *r, uint8_t *out);

/* Read a 1-byte PUSH whose value must equal `expect` (e.g. a version byte).
 * Returns r->ok. */
bool overlay_expect_u8(struct overlay_reader *r, uint8_t expect);

/* Read a variable PUSH of length 0..max_len into dst (dst must have room for
 * max_len bytes), setting *out_len to the number of bytes copied. A push
 * longer than max_len is refused. Does NOT NUL-terminate — callers that want a
 * C string terminate at *out_len themselves. out_len may be NULL if unwanted.
 * Returns r->ok. */
bool overlay_read_bounded(struct overlay_reader *r, uint8_t *dst,
                          size_t max_len, size_t *out_len);

/* Try to read a PUSH of EXACTLY `n` bytes into dst. On a match the cursor
 * advances and this returns true. On a malformed push, or a push of a
 * different length, the cursor is REWOUND to where that field started, `ok` is
 * left true, and this returns false.
 *
 * This is the one shape the straight-line sticky-error model cannot express: an
 * OPTIONAL REPEATED field, where "the next field does not match" means the list
 * ended here, not that the parse failed. ZSLP SEND carries 1..19 eight-byte
 * output quantities terminated exactly that way, and those transactions are
 * already in blocks — the terminator is wire format, not sloppiness. A cursor
 * that had already failed stays failed and returns false. */
bool overlay_try_read_fixed(struct overlay_reader *r, uint8_t *dst, size_t n);

/* Finish a parse: succeeds only if the cursor never failed AND is positioned
 * exactly at end (no trailing bytes after the last field). Returns the final
 * verdict; call once at the end of every parse.
 *
 * NOT every overlay may call this. ZNAM and ZSLP shipped without a trailing-
 * byte check and are live on mainnet, so scripts with bytes after the last
 * field parse as valid today — blog_build_node_announce (engine/controllers/src/
 * blog_controller.c) even appends a hostname after a complete ZSLP SEND on
 * purpose. Adding the check there would reject records the chain already
 * contains, which is a chain-interpretation change. New overlays call it. */
bool overlay_reader_finish(struct overlay_reader *r);

/* ── Bounded builder cursor ─────────────────────────────────────────────
 *
 * overlay_writer_begin writes the OP_RETURN + lokad framing and arms the
 * cursor; each put_* appends a PUSH; overlay_writer_finish returns the length
 * or 0 if any step overflowed. */
struct overlay_writer {
    uint8_t *out;   /* caller buffer */
    size_t off;     /* bytes written so far */
    size_t cap;     /* capacity of out */
    bool ok;        /* sticky: false latches all puts to failure */
};

/* Begin building: write 0x6a (OP_RETURN) then the 4-byte lokad push into out.
 * A NULL/zero buffer or an immediate overflow latches !ok. */
void overlay_writer_begin(struct overlay_writer *w, uint8_t *out, size_t cap,
                          const char lokad[OVERLAY_LOKAD_LEN]);

/* Append a PUSH of `data[0..len)`. len==0 emits the canonical empty push.
 * Latches !ok on overflow. Returns w->ok. */
bool overlay_put_field(struct overlay_writer *w,
                       const uint8_t *data, size_t len);

/* Append a 1-byte PUSH. Returns w->ok. */
bool overlay_put_u8(struct overlay_writer *w, uint8_t v);

/* Append an empty field encoded as OP_PUSHDATA1 with length 0 (0x4c 0x00) —
 * two bytes, NOT the one-byte OP_0 that overlay_put_field(w, x, 0) emits.
 *
 * For ZSLP only. Its builders have always encoded an absent ticker / name /
 * document_url / document_hash / mint baton this way, so those exact bytes are
 * in mainnet transactions and their txids depend on them. Both encodings parse
 * back to a zero-length field, so this is an encoder-side compatibility
 * requirement, not a parser split. Do not use it in a new overlay. */
bool overlay_put_empty_pushdata1(struct overlay_writer *w);

/* Finish building: returns the total encoded length, or 0 if the cursor ever
 * overflowed. */
size_t overlay_writer_finish(struct overlay_writer *w);

#endif /* ZCL_OVERLAY_CODEC_H */
