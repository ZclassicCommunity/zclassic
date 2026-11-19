/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: UTF-8 validation, decoding, and encoding for C23.
 *          Allocation-free, bounded, and total: every byte sequence is
 *          either a valid encoding of a Unicode scalar value (RFC 3629
 *          table 3-7 well-formedness) or a clean failure. No undefined
 *          behaviour on any input; validation runs in one pass.
 *
 * Rules enforced (Unicode standard, "well-formed UTF-8 byte sequences"):
 *  - 1-byte: 0x00..0x7F
 *  - 2-byte: 0xC2..0xDF + continuation (0xC0/0xC1 are overlong)
 *  - 3-byte: 0xE0 + 0xA0..0xBF (else overlong), 0xED + 0x80..0x9F
 *    (else UTF-16 surrogate), other 0xE1..0xEC/0xEE..0xEF + two
 *    continuations
 *  - 4-byte: 0xF0 + 0x90..0xBF (else overlong), 0xF4 + 0x80..0x8F
 *    (else above U+10FFFF), 0xF1..0xF3 + three continuations
 *  - 0xF5..0xFF, lone continuations, and truncated sequences are
 *    invalid.
 *
 * Decode returns a Unicode scalar value; encode rejects surrogates and
 * values above U+10FFFF. Neither allocates.
 */
#ifndef ZUTF8_H
#define ZUTF8_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Result of decoding one code point. */
typedef enum {
  ZUTF8_OK = 0,       /* a full, well-formed sequence was decoded */
  ZUTF8_TRUNCATED,    /* input ended mid-sequence */
  ZUTF8_INVALID       /* malformed byte (overlong, surrogate, stray,
                         out-of-range lead, or bad continuation) */
} zutf8_status;

/* True when str[0..len) is entirely well-formed UTF-8. */
bool zutf8_validate_n(const char *str, size_t len);

/* NUL-terminated convenience wrapper. */
bool zutf8_validate(const char *str);

/* Decode one code point at str[0..len). On ZUTF8_OK, *cp_out receives
 * the scalar value and the return value is the sequence length (1..4).
 * On ZUTF8_TRUNCATED / ZUTF8_INVALID the return value is 0. NULL
 * str with nonzero len, or NULL cp_out, returns ZUTF8_INVALID. */
zutf8_status zutf8_decode_n(const char *str, size_t len, uint32_t *cp_out,
                            size_t *consumed_out);

/* Encode cp as UTF-8 into out[0..4); returns the byte count, or 0 when
 * cp is a surrogate (0xD800..0xDFFF) or above U+10FFFF. out may be
 * NULL to only measure. */
size_t zutf8_encode(uint32_t cp, char out[4]);

/* Number of code points in str[0..len) when valid; SIZE_MAX when the
 * input is not well-formed UTF-8. */
size_t zutf8_count_n(const char *str, size_t len);

#endif /* ZUTF8_H */
