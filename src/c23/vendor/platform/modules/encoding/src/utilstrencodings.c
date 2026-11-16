/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "encoding/utilstrencodings.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char SAFE_DEFAULT[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;_/:?@()";
static const char SAFE_UA[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;_?@";

void SanitizeString(const char *str, int rule, char *out, size_t out_size)
{
    if (out_size == 0)
        return;
    const char *safe = (rule == SAFE_CHARS_UA_COMMENT) ? SAFE_UA : SAFE_DEFAULT;
    size_t j = 0;
    for (size_t i = 0; str[i] && j + 1 < out_size; i++) {
        if (strchr(safe, str[i]))
            out[j++] = str[i];
    }
    out[j] = '\0';
}

const signed char p_util_hexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

signed char HexDigit(char c)
{
    return p_util_hexdigit[(unsigned char)c];
}

bool IsHex(const char *str)
{
    size_t len = strlen(str);
    if (len == 0 || len % 2 != 0)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (HexDigit(str[i]) < 0)
            return false;
    }
    return true;
}

size_t ParseHex(const char *psz, unsigned char *out, size_t out_size)
{
    size_t count = 0;
    while (count < out_size) {
        while (isspace((unsigned char)*psz))
            psz++;
        signed char c = HexDigit(*psz++);
        if (c == (signed char)-1)
            break;
        unsigned char n = (unsigned char)(c << 4);
        c = HexDigit(*psz++);
        if (c == (signed char)-1)
            break;
        n |= (unsigned char)c;
        out[count++] = n;
    }
    return count;
}

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t EncodeBase64(const unsigned char *data, size_t len, char *out, size_t out_size)
{
    if (out_size == 0)
        return 0;
    size_t j = 0;
    size_t acc = 0, bits = 0;
    for (size_t i = 0; i < len; i++) {
        acc = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            if (j + 1 < out_size)
                out[j++] = base64_chars[(acc >> bits) & 0x3F];
        }
    }
    if (bits > 0 && j + 1 < out_size)
        out[j++] = base64_chars[(acc << (6 - bits)) & 0x3F];
    while (j % 4 != 0 && j + 1 < out_size)
        out[j++] = '=';
    out[j] = '\0';
    return j;
}

static const int decode64_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,
    -1,-1,-1,-1,-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,
    29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
    49,50,51,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

size_t DecodeBase64(const char *p, unsigned char *out, size_t out_size, bool *invalid)
{
    const char *start = p;
    size_t acc = 0, bits = 0, j = 0;

    while (*p) {
        int x = decode64_table[(unsigned char)*p];
        if (x == -1) break;
        acc = (acc << 6) | (unsigned)x;
        bits += 6;
        while (bits >= 8) {
            bits -= 8;
            if (j < out_size)
                out[j++] = (unsigned char)((acc >> bits) & 0xFF);
        }
        p++;
    }

    const char *q = p;
    bool valid = true;
    while (*p) {
        if (*p != '=') { valid = false; break; }
        p++;
    }
    valid = valid && (p - start) % 4 == 0 && p - q < 4;
    if (invalid) *invalid = !valid;
    return j;
}

static const char base32_chars[] = "abcdefghijklmnopqrstuvwxyz234567";

size_t EncodeBase32(const unsigned char *data, size_t len, char *out, size_t out_size)
{
    if (out_size == 0) return 0;
    size_t j = 0, acc = 0, bits = 0;
    for (size_t i = 0; i < len; i++) {
        acc = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (j + 1 < out_size)
                out[j++] = base32_chars[(acc >> bits) & 0x1F];
        }
    }
    if (bits > 0 && j + 1 < out_size)
        out[j++] = base32_chars[(acc << (5 - bits)) & 0x1F];
    while (j % 8 != 0 && j + 1 < out_size)
        out[j++] = '=';
    out[j] = '\0';
    return j;
}

/* --- Hex encode -----------------------------------------------------------
 *
 * Two implementations of the same non-spaces encoder: the original scalar
 * loop, kept verbatim as the frozen reference, and an AArch64 NEON version.
 *
 * HexStr output feeds consensus-visible surfaces (core/math/src/core_io.c
 * renders scripts and transaction input scripts through it), so the NEON copy
 * follows the same contract as core/modules/crypto/src/sha256.c: it is compiled into
 * every AArch64 build rather than hidden behind a compile-time feature guard,
 * selected at RUNTIME, and only enabled after it reproduces the portable
 * reference byte for byte on known-answer vectors. A mismatch keeps callers on
 * the scalar path instead of letting a wrong encoding reach a hash-bearing
 * string. On ARMv8 NEON is architectural baseline, so unlike the x86 tiers
 * there is no capability CPUID bit to read and no target() attribute to spell:
 * the gate verifies correctness, which is the part consensus cares about.
 */

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#include <stdatomic.h>

static void hexstr_portable(const unsigned char *data, size_t len, bool spaces,
                            char *out, size_t out_size);

/* -1 = not probed, 0 = portable, 1 = NEON. Relaxed atomic because independent
 * callers may race to probe; every racer derives the same answer from the same
 * constants, so ordering is irrelevant and only the absence of a data race
 * matters. */
static _Atomic int hex_neon_available = -1;

/* NEON non-spaces encoder. Writes exactly `npairs` nibble pairs taken from
 * `data[0..npairs)` followed by one NUL, using 32 bytes of output per
 * 16 input bytes. Never reads past data[npairs] and never writes past
 * out[2*npairs]. */
__attribute__((noinline))
static void hexstr_neon(const unsigned char *data, size_t npairs, char *out)
{
    /* Lowercase digit table, same order as hexmap. */
    static const uint8_t hex_lut[16] = { '0','1','2','3','4','5','6','7',
                                         '8','9','a','b','c','d','e','f' };
    const uint8x16_t tbl     = vld1q_u8(hex_lut);
    const uint8x16_t nibmask = vdupq_n_u8(0x0F);

    size_t i = 0;
    while (i + 16 <= npairs) {
        uint8x16_t v = vld1q_u8(data + i);
        uint8x16_t hch = vqtbl1q_u8(tbl, vandq_u8(vshrq_n_u8(v, 4), nibmask));
        uint8x16_t lch = vqtbl1q_u8(tbl, vandq_u8(v, nibmask));
        vst1q_u8((unsigned char *)(void *)out,        vzip1q_u8(hch, lch));
        vst1q_u8((unsigned char *)(void *)(out + 16), vzip2q_u8(hch, lch));
        out += 32;
        i += 16;
    }
    static const char hexmap[] = "0123456789abcdef";
    for (; i < npairs; i++) {
        *out++ = hexmap[data[i] >> 4];
        *out++ = hexmap[data[i] & 0xF];
    }
    *out = '\0';
}

/* Known-answer gate: the NEON kernel must reproduce the portable encoder
 * bit-for-bit across lengths spanning both vector lanes and the scalar tail,
 * including truncating buffer sizes, before it is allowed to serve callers. */
static bool hex_neon_selftest(void)
{
    unsigned char buf[100];
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (unsigned char)(i * 37u + 11u);

    char ref[256], got[256];
    for (size_t n = 0; n <= sizeof(buf); n++) {
        /* Full fit: 2*n characters plus terminator must all be written. */
        if (2u * n + 1u > sizeof(ref))
            continue;
        memset(ref, 0xA5, sizeof(ref));
        hexstr_portable(buf, n, false, ref, sizeof(ref));

        memset(got, 0xA5, sizeof(got));
        hexstr_neon(buf, n, got);           /* full-fit precondition holds */
        if (memcmp(ref, got, sizeof(ref)) != 0)
            return false;

        /* Truncated fit: padded to the exact bound so no stale byte can hide a
         * difference, and compared over the caller-visible region only. */
        for (size_t os = 3; os <= 2u * n + 1u; os++) {
            memset(ref, 0x5C, os);
            hexstr_portable(buf, n, false, ref, os);
            memcpy(got, ref, os);
            size_t npairs = (os - 1) / 2;
            if (npairs >= 16) {             /* mirrors the dispatch threshold */
                hexstr_neon(buf, npairs, got);
                got[npairs * 2] = '\0';
            }
            if (memcmp(ref, got, os) != 0)
                return false;
        }
    }
    return true;
}

static void detect_hex_neon(void)
{
    atomic_store_explicit(&hex_neon_available, hex_neon_selftest() ? 1 : 0,
                          memory_order_relaxed);
    if (atomic_load_explicit(&hex_neon_available, memory_order_relaxed) == 0)
        fprintf(stderr,  // obs-ok:encoding-hex-neon-selfcheck
                "[HexStr] NEON encode self-check failed against the portable "
                "reference; using scalar hex encoding\n");
}

/* Probe-on-first-use accessor. 0 = portable, nonzero = NEON. */
static inline int hex_neon_state(void)
{
    int v = atomic_load_explicit(&hex_neon_available, memory_order_relaxed);
    if (__builtin_expect(v < 0, 0)) {
        detect_hex_neon();
        v = atomic_load_explicit(&hex_neon_available, memory_order_relaxed);
    }
    return v;
}
#endif /* __aarch64__ && __ARM_NEON */

/* Frozen portable reference. Body unchanged from before the NEON tier existed;
 * used directly as the fallback and as the oracle for the self-test above. */
static void hexstr_portable(const unsigned char *data, size_t len, bool spaces,
                            char *out, size_t out_size)
{
    static const char hexmap[] = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        size_t need = 2 + ((spaces && i > 0) ? 1 : 0);
        if (j + need >= out_size)
            break;
        if (spaces && i > 0)
            out[j++] = ' ';
        out[j++] = hexmap[data[i] >> 4];
        out[j++] = hexmap[data[i] & 0xF];
    }
    out[j] = '\0';
}

void HexStr(const unsigned char *data, size_t len, bool spaces, char *out, size_t out_size)
{
#if defined(__aarch64__) && defined(__ARM_NEON)
    if (!spaces && out_size >= 3 && len >= 16) {
        /* Whole bytes whose two characters provably fit alongside a NUL. This
         * reproduces the reference's break condition exactly: it encodes
         * min(len, (out_size - 1) / 2) bytes and then stops. */
        size_t npairs = (out_size - 1) / 2;
        if (npairs > len)
            npairs = len;

        /* Overlapping arguments: the scalar loop happens to read a nibble
         * before writing past it, so those calls have a definite answer today.
         * The vector kernel writes 32 bytes at a time and would corrupt source
         * it has not consumed yet, so such calls stay on the reference path.
         * Done in uintptr_t because both operands need not belong to one
         * object, which makes direct relational comparison unspecified. */
        bool overlapped =
            (uintptr_t)data < (uintptr_t)(void *)(out + 2 * npairs) &&
            (uintptr_t)(void *)out < (uintptr_t)(data + npairs);

        if (npairs >= 16 && !overlapped && hex_neon_state()) {
            hexstr_neon(data, npairs, out);
            return;
        }
    }
#endif
    hexstr_portable(data, len, spaces, out, out_size);
}

const char *HexStr_impl_name(void)
{
#if defined(__aarch64__) && defined(__ARM_NEON)
    return hex_neon_state() ? "neon" : "scalar";
#else
    return "scalar";
#endif
}

static bool parse_prechecks(const char *str)
{
    size_t len = strlen(str);
    if (len == 0) return false;
    if (isspace((unsigned char)str[0]) || isspace((unsigned char)str[len - 1]))
        return false;
    if (len != strlen(str)) return false;
    return true;
}

bool ParseInt32(const char *str, int32_t *out)
{
    if (!parse_prechecks(str))
        return false;
    char *endp = NULL;
    errno = 0;
    long n = strtol(str, &endp, 10);
    if (out) *out = (int32_t)n;
    return endp && *endp == 0 && !errno &&
        n >= INT32_MIN && n <= INT32_MAX;
}

static const int64_t UPPER_BOUND = 1000000000000000000LL - 1LL;

static bool process_mantissa_digit(char ch, int64_t *mantissa, int *mantissa_tzeros)
{
    if (ch == '0') {
        ++(*mantissa_tzeros);
    } else {
        for (int i = 0; i <= *mantissa_tzeros; ++i) {
            if (*mantissa > (UPPER_BOUND / 10LL))
                return false;
            *mantissa *= 10;
        }
        *mantissa += ch - '0';
        *mantissa_tzeros = 0;
    }
    return true;
}

/* Consumes a run of decimal digits into the mantissa; false on overflow. */
static bool consume_mantissa_digits(const char *val, int *ptr, int end,
                                    int64_t *mantissa, int *mantissa_tzeros)
{
    while (*ptr < end && val[*ptr] >= '0' && val[*ptr] <= '9') {
        bool digit_ok = process_mantissa_digit(val[*ptr], mantissa, mantissa_tzeros);
        if (!digit_ok)
            return digit_ok;
        ++(*ptr);
    }
    return true;
}

/* Parses the optional sign and the integer digits; false on syntax error or
 * mantissa overflow. */
static bool parse_fixed_point_int_part(const char *val, int *ptr, int end,
                                       int64_t *mantissa, int *mantissa_tzeros,
                                       bool *mantissa_sign)
{
    if (*ptr < end && val[*ptr] == '-') {
        *mantissa_sign = true;
        ++(*ptr);
    }
    if (*ptr < end) {
        if (val[*ptr] == '0') {
            ++(*ptr);
        } else if (val[*ptr] >= '1' && val[*ptr] <= '9') {
            return consume_mantissa_digits(val, ptr, end, mantissa, mantissa_tzeros);
        } else return false;
    } else return false;
    return true;
}

/* Parses the fraction after a '.', counting its digits in *point_ofs; true
 * when no '.' is present. */
static bool parse_fixed_point_fraction(const char *val, int *ptr, int end,
                                       int64_t *mantissa, int *mantissa_tzeros,
                                       int *point_ofs)
{
    if (*ptr < end && val[*ptr] == '.') {
        ++(*ptr);
        if (*ptr < end && val[*ptr] >= '0' && val[*ptr] <= '9') {
            int start = *ptr;
            bool digits_ok = consume_mantissa_digits(val, ptr, end, mantissa, mantissa_tzeros);
            if (digits_ok)
                *point_ofs += *ptr - start;
            return digits_ok;
        } else return false;
    }
    return true;
}

/* Consumes an optional '+' or '-' exponent sign, flagging '-'. */
static void consume_exponent_sign(const char *val, int *ptr, int end,
                                  bool *exponent_sign)
{
    if (*ptr < end && val[*ptr] == '+')
        ++(*ptr);
    else if (*ptr < end && val[*ptr] == '-') {
        *exponent_sign = true;
        ++(*ptr);
    }
}

/* Reads exponent digits, rejecting values too large to scale. */
static bool consume_exponent_digits(const char *val, int *ptr, int end,
                                    int64_t *exponent)
{
    while (*ptr < end && val[*ptr] >= '0' && val[*ptr] <= '9') {
        if (*exponent > (UPPER_BOUND / 10LL))
            return false;
        *exponent = *exponent * 10 + val[*ptr] - '0';
        ++(*ptr);
    }
    return true;
}

/* Parses the optional 'e'/'E' exponent and its sign; false on syntax error
 * or exponent overflow. */
static bool parse_fixed_point_exponent(const char *val, int *ptr, int end,
                                       int64_t *exponent, bool *exponent_sign)
{
    if (*ptr < end && (val[*ptr] == 'e' || val[*ptr] == 'E')) {
        ++(*ptr);
        consume_exponent_sign(val, ptr, end, exponent_sign);
        if (*ptr < end && val[*ptr] >= '0' && val[*ptr] <= '9')
            return consume_exponent_digits(val, ptr, end, exponent);
        else return false;
    }
    return true;
}

/* Multiplies the mantissa by 10^exponent and enforces the final range. */
static bool scale_mantissa_to_range(int64_t *mantissa, int64_t exponent)
{
    for (int i = 0; i < exponent; ++i) {
        if (*mantissa > (UPPER_BOUND / 10LL) || *mantissa < -(UPPER_BOUND / 10LL))
            return false;
        *mantissa *= 10;
    }
    if (*mantissa > UPPER_BOUND || *mantissa < -UPPER_BOUND)
        return false;
    return true;
}

bool ParseFixedPoint(const char *val, int decimals, int64_t *amount_out)
{
    int64_t mantissa = 0;
    int64_t exponent = 0;
    int mantissa_tzeros = 0;
    bool mantissa_sign = false;
    bool exponent_sign = false;
    int ptr = 0;
    int end = (int)strlen(val);
    int point_ofs = 0;

    if (!parse_fixed_point_int_part(val, &ptr, end, &mantissa, &mantissa_tzeros, &mantissa_sign))
        return false;

    if (!parse_fixed_point_fraction(val, &ptr, end, &mantissa, &mantissa_tzeros, &point_ofs))
        return false;

    if (!parse_fixed_point_exponent(val, &ptr, end, &exponent, &exponent_sign))
        return false;

    if (ptr != end)
        return false;

    if (exponent_sign)
        exponent = -exponent;
    exponent = exponent - point_ofs + mantissa_tzeros;

    if (mantissa_sign)
        mantissa = -mantissa;

    exponent += decimals;
    if (exponent < 0)
        return false;
    if (exponent >= 18)
        return false;

    if (!scale_mantissa_to_range(&mantissa, exponent))
        return false;

    if (amount_out)
        *amount_out = mantissa;

    return true;
}

bool ConvertBits(int frombits, int tobits, bool pad,
                 const unsigned char *in, size_t in_len,
                 unsigned char *out, size_t out_size, size_t *out_len)
{
    /* Both alphabets must fit in the byte-sized input and output elements. */
    if (frombits < 1 || frombits > 8 || tobits < 1 || tobits > 8)
        return false;
    size_t acc = 0, bits = 0, j = 0;
    size_t maxv = ((size_t)1 << tobits) - 1;
    size_t max_acc = ((size_t)1 << (frombits + tobits - 1)) - 1;

    for (size_t i = 0; i < in_len; i++) {
        acc = ((acc << frombits) | in[i]) & max_acc;
        bits += (size_t)frombits;
        while (bits >= (size_t)tobits) {
            bits -= (size_t)tobits;
            if (j < out_size)
                out[j++] = (unsigned char)((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits && j < out_size)
            out[j++] = (unsigned char)((acc << (tobits - bits)) & maxv);
    } else if (bits >= (size_t)frombits || ((acc << (tobits - bits)) & maxv)) {
        if (out_len) *out_len = j;
        return false;
    }
    if (out_len) *out_len = j;
    return true;
}
