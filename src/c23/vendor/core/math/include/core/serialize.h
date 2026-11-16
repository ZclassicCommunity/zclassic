/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SERIALIZE_H
#define ZCL_SERIALIZE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

enum ser_type {
    SER_NETWORK = (1 << 0),
    SER_DISK    = (1 << 1),
    SER_GETHASH = (1 << 2)
};

struct byte_stream {
    unsigned char *data;
    size_t size;
    size_t capacity;
    size_t read_pos;
    bool error;
    bool owns_data;
};

/* Initialize an owning, growable write/read buffer with the given starting
 * capacity (0 = allocate lazily on first write). On allocation failure the
 * stream is marked error and subsequent writes fail. */
void stream_init(struct byte_stream *s, size_t initial_capacity);
/* Initialize a read-only view over caller-owned data (no copy, no ownership).
 * Writes against this stream fail; stream_free will not release data. */
void stream_init_from_data(struct byte_stream *s, const unsigned char *data,
                           size_t len);
/* Release the backing buffer if the stream owns it, then zero its fields. */
void stream_free(struct byte_stream *s);

/* Append len bytes, growing the buffer as needed. Returns false (and sets the
 * sticky error flag) on overflow, allocation failure, or a non-owning stream. */
bool stream_write(struct byte_stream *s, const void *buf, size_t len);
/* Consume len bytes from the current read position into buf. Returns false
 * and sets the sticky error flag if fewer than len bytes remain. */
bool stream_read(struct byte_stream *s, void *buf, size_t len);
/* Number of unread bytes between the read position and the end of data. */
size_t stream_remaining(const struct byte_stream *s);

/* Append a fixed-width integer in little-endian wire order. Signed variants
 * reinterpret the two's-complement bits of the unsigned width. Each returns
 * false on a failed underlying stream_write. */
bool stream_write_u8(struct byte_stream *s, uint8_t v);
bool stream_write_u16_le(struct byte_stream *s, uint16_t v);
bool stream_write_u32_le(struct byte_stream *s, uint32_t v);
bool stream_write_u64_le(struct byte_stream *s, uint64_t v);
bool stream_write_i32_le(struct byte_stream *s, int32_t v);
bool stream_write_i64_le(struct byte_stream *s, int64_t v);

/* Read a fixed-width little-endian integer into *v. Returns false (leaving *v
 * unmodified) when fewer than the needed bytes remain. */
bool stream_read_u8(struct byte_stream *s, uint8_t *v);
bool stream_read_u16_le(struct byte_stream *s, uint16_t *v);
bool stream_read_u32_le(struct byte_stream *s, uint32_t *v);
bool stream_read_u64_le(struct byte_stream *s, uint64_t *v);
bool stream_read_i32_le(struct byte_stream *s, int32_t *v);
bool stream_read_i64_le(struct byte_stream *s, int64_t *v);

/* Bitcoin CompactSize length prefix (1/3/5/9 bytes). The reader accepts
 * non-canonical encodings for wire compatibility with the reference node. */
bool stream_write_compact_size(struct byte_stream *s, uint64_t size);
bool stream_read_compact_size(struct byte_stream *s, uint64_t *size);

/* Number of bytes stream_write_compact_size will emit for n. */
static inline size_t compact_size_sizeof(uint64_t n)
{
    if (n < 253)         return 1;
    else if (n <= 0xffff) return 3;
    else if (n <= 0xffffffffULL) return 5;
    else                  return 9;
}

/* Bitcoin Core VarInt (the base-128 variant used for undo/coin records, not
 * CompactSize). Each returns false on a failed underlying byte read/write. */
bool stream_write_varint(struct byte_stream *s, uint64_t n);
bool stream_read_varint(struct byte_stream *s, uint64_t *n);

/* Append / consume a raw byte run with no length prefix. Thin aliases over
 * stream_write / stream_read. */
bool stream_write_bytes(struct byte_stream *s, const unsigned char *data, size_t len);
bool stream_read_bytes(struct byte_stream *s, unsigned char *data, size_t len);

#endif
