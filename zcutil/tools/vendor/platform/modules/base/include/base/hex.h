/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The one hex codec. Base-16 encode/decode of a byte buffer.
 *
 * Why this file exists
 * --------------------
 * Twelve private copies of this ~10-line codec had accumulated across
 * controllers, services, contexts/commons/modules/vcs and tools/, because the only thing
 * encoding/utilstrencodings.h ever exported was the raw `p_util_hexdigit`
 * lookup table — there was no `bytes_to_hex`/`hex_to_bytes` to call. The
 * copies did NOT agree with each other:
 *
 *   - some rejected an odd-length input, some never looked at the length;
 *   - some accepted `A-F`, some silently rejected it;
 *   - one validated nothing at all and used sscanf("%2x"), which skips
 *     leading whitespace and accepts a sign, so " 1" and "+1" decoded;
 *   - several left the caller's output buffer half-written on failure, and
 *     at least one call site ignored the return value and read it anyway.
 *
 * Reconciled semantics, strictest-sane of the twelve
 * --------------------------------------------------
 * ENCODE is unanimous across all twelve and is preserved byte for byte:
 * LOWERCASE, exactly `2 * len` characters, always NUL-terminated. Nothing
 * that goes on the wire, into a filename, or into a database changes.
 *
 * DECODE is exact-length by default (`strlen(hex) == 2 * want`), rejects
 * every character outside its accepted alphabet, rejects NULL, and — unlike
 * every copy it replaces — ZEROES the caller's buffer on failure so an
 * ignored return value cannot expose half-decoded or uninitialised bytes.
 *
 * Case policy is a named choice rather than an accident, because the two
 * uses genuinely differ:
 *
 *   zcl_hex_decode()        accepts [0-9a-fA-F]. Use for operator- and
 *                           peer-supplied hex (CLI arguments, request
 *                           parameters, file contents from elsewhere).
 *   zcl_hex_decode_lower()  accepts [0-9a-f] only. Use where the string
 *                           must round-trip byte-identically through
 *                           zcl_hex_encode() — on-disk directory and file
 *                           names, self-written records — so that one value
 *                           cannot have two spellings.
 *
 * zcl_hex_decode_n() is the variable-length form: 1..cap bytes, still even
 * and still fully validated, reporting how many bytes it wrote.
 *
 * Header-only on purpose: a dozen standalone tools link their own explicit
 * source lists (see BUILD_NODE_TOOL and the `-Iplatform/modules/base/include` rules in
 * the Makefile), and `static inline` keeps every one of them buildable
 * without touching a link line.
 *
 * Enforced by lint gate `check-hex-codec-single` — a new private hex
 * encoder or decoder outside platform/modules/base fails `make lint`.
 */

#ifndef ZCL_BASE_HEX_H
#define ZCL_BASE_HEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Encode `len` bytes as `2 * len` lowercase hex characters plus a NUL.
 *
 * `out` must have room for `2 * len + 1` bytes; there is no way for the
 * callee to check that, so it is the caller's contract (the codec test
 * covers the exactly-one-byte-short case for decode, which CAN be checked).
 * `len == 0` writes just the NUL. A NULL `out` is a no-op; a NULL `in` with
 * a non-zero `len` writes the empty string rather than reading it. */
static inline void zcl_hex_encode(const uint8_t *in, size_t len, char *out)
{
    /* The single lowercase hex-digit table in the tree. */
    static const char digits[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    if (!out)
        return;
    if (!in) {
        out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = digits[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = digits[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

/* One hex character -> 0..15, or -1. `allow_upper` false rejects A-F. */
static inline int zcl_hex_nibble(char c, bool allow_upper)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (allow_upper && c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Shared body for the two exact-length decoders. */
static inline bool zcl_hex_decode_exact(const char *hex, uint8_t *out,
                                        size_t want, bool allow_upper)
{
    if (out)
        memset(out, 0, want);
    if (!hex || (want > 0 && !out))
        return false;
    if (strlen(hex) != 2 * want)
        return false;
    for (size_t i = 0; i < want; i++) {
        int hi = zcl_hex_nibble(hex[2 * i], allow_upper);
        int lo = zcl_hex_nibble(hex[2 * i + 1], allow_upper);
        if (hi < 0 || lo < 0) {
            memset(out, 0, want);
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* Exact-length decode, accepting [0-9a-fA-F].
 *
 * True only when `hex` is exactly `2 * want` hex characters. `want == 0`
 * accepts (only) the empty string. On any failure `out` is zeroed. */
static inline bool zcl_hex_decode(const char *hex, uint8_t *out, size_t want)
{
    return zcl_hex_decode_exact(hex, out, want, true);
}

/* Exact-length decode in canonical (lowercase) form only.
 *
 * Same as zcl_hex_decode() except that A-F is rejected, so the accepted
 * input is exactly the output of zcl_hex_encode(). Use for on-disk names
 * and other strings that must have one spelling per value. */
static inline bool zcl_hex_decode_lower(const char *hex, uint8_t *out,
                                        size_t want)
{
    return zcl_hex_decode_exact(hex, out, want, false);
}

/* Variable-length decode: 1..`cap` bytes, accepting [0-9a-fA-F].
 *
 * Rejects the empty string and any odd length. Writes the decoded byte
 * count through `out_len` when it is non-NULL (set to 0 on failure). On any
 * failure `out` is zeroed over the full `cap`. */
static inline bool zcl_hex_decode_n(const char *hex, uint8_t *out, size_t cap,
                                    size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (out)
        memset(out, 0, cap);
    if (!hex || !out)
        return false;
    size_t n = strlen(hex);
    if (n == 0 || (n & 1u) != 0 || n / 2 > cap)
        return false;
    size_t want = n / 2;
    for (size_t i = 0; i < want; i++) {
        int hi = zcl_hex_nibble(hex[2 * i], true);
        int lo = zcl_hex_nibble(hex[2 * i + 1], true);
        if (hi < 0 || lo < 0) {
            memset(out, 0, cap);
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (out_len)
        *out_len = want;
    return true;
}

#endif /* ZCL_BASE_HEX_H */
