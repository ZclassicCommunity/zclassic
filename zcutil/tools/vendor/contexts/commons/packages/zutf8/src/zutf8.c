/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: UTF-8 validate/decode/encode (see the header for the rules). */
#include "zutf8/zutf8.h"

static bool is_cont(unsigned char b) { return (b & 0xC0u) == 0x80u; }

/* Sequence length and the legal range for the second byte, which is
 * where the overlong / surrogate / >U+10FFFF exclusions live. */
static const struct {
  unsigned char first, last;
  size_t n;
  unsigned char lo, hi;
} lead_rules[] = {
    {0xC2u, 0xDFu, 2, 0x80u, 0xBFu},
    {0xE0u, 0xE0u, 3, 0xA0u, 0xBFu}, /* exclude overlong */
    {0xEDu, 0xEDu, 3, 0x80u, 0x9Fu}, /* exclude UTF-16 surrogates */
    {0xE1u, 0xEFu, 3, 0x80u, 0xBFu},
    {0xF0u, 0xF0u, 4, 0x90u, 0xBFu}, /* exclude overlong */
    {0xF4u, 0xF4u, 4, 0x80u, 0x8Fu}, /* exclude above U+10FFFF */
    {0xF1u, 0xF3u, 4, 0x80u, 0xBFu},
};

/* Look up a multi-byte lead byte's sequence length and second-byte range;
 * returns false for bytes that cannot start a sequence. */
static bool classify_lead_byte(unsigned char b0, size_t *n, unsigned char *lo,
                               unsigned char *hi) {
  for (size_t i = 0; i < sizeof(lead_rules) / sizeof(lead_rules[0]); i++) {
    if (b0 >= lead_rules[i].first && b0 <= lead_rules[i].last) {
      *n = lead_rules[i].n;
      *lo = lead_rules[i].lo;
      *hi = lead_rules[i].hi;
      return true;
    }
  }
  return false;
}

/* Check the second byte's legal range and the remaining continuation
 * bytes of a multi-byte sequence. */
static zutf8_status check_tail_bytes(const char *str, size_t n,
                                     unsigned char b1, unsigned char lo,
                                     unsigned char hi) {
  if (b1 < lo || b1 > hi)
    return ZUTF8_INVALID;
  for (size_t i = 2; i < n; i++) {
    if (!is_cont((unsigned char)str[i]))
      return ZUTF8_INVALID;
  }
  return ZUTF8_OK;
}

/* Assemble the code point from a validated sequence's payload bytes. */
static uint32_t decode_code_point(unsigned char b0, unsigned char b1,
                                  const char *str, size_t n) {
  switch (n) {
  case 2:
    return ((uint32_t)(b0 & 0x1Fu) << 6) | (uint32_t)(b1 & 0x3Fu);
  case 3:
    return ((uint32_t)(b0 & 0x0Fu) << 12) | ((uint32_t)(b1 & 0x3Fu) << 6) |
           (uint32_t)(str[2] & 0x3Fu);
  default:
    return ((uint32_t)(b0 & 0x07u) << 18) | ((uint32_t)(b1 & 0x3Fu) << 12) |
           ((uint32_t)(str[2] & 0x3Fu) << 6) | (uint32_t)(str[3] & 0x3Fu);
  }
}

zutf8_status zutf8_decode_n(const char *str, size_t len, uint32_t *cp_out,
                            size_t *consumed_out) {
  if (consumed_out)
    *consumed_out = 0;
  if (!str || !cp_out)
    return ZUTF8_INVALID;
  if (!len)
    return ZUTF8_TRUNCATED;

  const unsigned char b0 = (unsigned char)str[0];
  if (b0 <= 0x7Fu) {
    *cp_out = b0;
    if (consumed_out)
      *consumed_out = 1;
    return ZUTF8_OK;
  }

  size_t n;
  unsigned char lo, hi;
  if (!classify_lead_byte(b0, &n, &lo, &hi))
    return ZUTF8_INVALID; /* 0x80..0xC1, 0xF5..0xFF */

  if (len < n)
    return ZUTF8_TRUNCATED;
  const unsigned char b1 = (unsigned char)str[1];
  if (check_tail_bytes(str, n, b1, lo, hi) != ZUTF8_OK)
    return ZUTF8_INVALID;

  *cp_out = decode_code_point(b0, b1, str, n);
  if (consumed_out)
    *consumed_out = n;
  return ZUTF8_OK;
}

bool zutf8_validate_n(const char *str, size_t len) {
  if (!str)
    return !len;
  size_t pos = 0;
  while (pos < len) {
    uint32_t cp;
    size_t used;
    if (zutf8_decode_n(str + pos, len - pos, &cp, &used) != ZUTF8_OK)
      return false;
    pos += used;
  }
  return true;
}

bool zutf8_validate(const char *str) {
  if (!str)
    return false;
  size_t len = 0;
  while (str[len])
    len++;
  return zutf8_validate_n(str, len);
}

size_t zutf8_encode(uint32_t cp, char out[4]) {
  if (cp >= 0xD800u && cp <= 0xDFFFu)
    return 0; /* UTF-16 surrogates have no UTF-8 encoding */
  if (cp > 0x10FFFFu)
    return 0;
  if (cp <= 0x7Fu) {
    if (out)
      out[0] = (char)cp;
    return 1;
  }
  if (cp <= 0x7FFu) {
    if (out) {
      out[0] = (char)(0xC0u | (cp >> 6));
      out[1] = (char)(0x80u | (cp & 0x3Fu));
    }
    return 2;
  }
  if (cp <= 0xFFFFu) {
    if (out) {
      out[0] = (char)(0xE0u | (cp >> 12));
      out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
      out[2] = (char)(0x80u | (cp & 0x3Fu));
    }
    return 3;
  }
  if (out) {
    out[0] = (char)(0xF0u | (cp >> 18));
    out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
    out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[3] = (char)(0x80u | (cp & 0x3Fu));
  }
  return 4;
}

size_t zutf8_count_n(const char *str, size_t len) {
  if (!str)
    return len ? SIZE_MAX : 0;
  size_t pos = 0, count = 0;
  while (pos < len) {
    uint32_t cp;
    size_t used;
    if (zutf8_decode_n(str + pos, len - pos, &cp, &used) != ZUTF8_OK)
      return SIZE_MAX;
    pos += used;
    count++;
  }
  return count;
}
