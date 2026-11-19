/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded RFC 8259 pull parser (see the header). */
#include "zjsonp/zjsonp.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zutf8/zutf8.h"

void zjsonp_init(zjsonp *p, const char *text, size_t len) {
  if (!p)
    return;
  memset(p, 0, sizeof(*p));
  p->text = text;
  p->len = text ? len : 0;
}

size_t zjsonp_pos(const zjsonp *p) { return p ? p->pos : 0; }

const char *zjsonp_status_name(zjsonp_status st) {
  switch (st) {
  case ZJRP_OK: return "ok";
  case ZJRP_DONE: return "done";
  case ZJRP_SYNTAX: return "syntax";
  case ZJRP_DEPTH: return "depth";
  }
  return "unknown";
}

static bool is_ws(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void skip_ws(zjsonp *p) {
  while (p->pos < p->len && is_ws(p->text[p->pos]))
    p->pos++;
}

static bool string_error(zjsonp *p, size_t pos) {
  p->pos = pos;
  return false;
}

static bool string_payload_valid(zjsonp *p, size_t start, size_t end) {
  size_t at = start;
  while (at < end) {
    uint32_t cp;
    size_t consumed;
    if (zutf8_decode_n(p->text + at, end - at, &cp, &consumed) != ZUTF8_OK)
      return string_error(p, at);
    at += consumed;
  }
  return true;
}

static bool scan_unicode_escape(zjsonp *p, size_t *pos) {
  size_t i = *pos;
  if (i + 5 >= p->len)
    return string_error(p, p->len);
  for (int k = 2; k <= 5; k++) {
    char h = p->text[i + k];
    bool hex = (h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
               (h >= 'A' && h <= 'F');
    if (!hex)
      return string_error(p, i + (size_t)k);
  }
  *pos += 6;
  return true;
}

static bool scan_escape(zjsonp *p, size_t *pos) {
  size_t i = *pos;
  if (i + 1 >= p->len)
    return string_error(p, p->len);
  char e = p->text[i + 1];
  if (e == 'u')
    return scan_unicode_escape(p, pos);
  if (e != '"' && e != '\\' && e != '/' && e != 'b' && e != 'f' &&
      e != 'n' && e != 'r' && e != 't')
    return string_error(p, i + 1);
  *pos += 2;
  return true;
}

/* Scan a string whose opening quote is at pos. On success returns
 * true, sets off/len to the raw payload between the quotes, and
 * leaves pos past the closing quote. Raw payload bytes must be
 * well-formed UTF-8 with no raw control bytes; escapes must be
 * well-formed (\uXXXX needs four hex digits; the escaped set is
 * exactly "\"\\/bfnrtu"). */
static bool scan_string(zjsonp *p, size_t *off, size_t *len) {
  size_t i = p->pos + 1;
  size_t start = i;
  while (i < p->len) {
    unsigned char c = (unsigned char)p->text[i];
    if (c == '"') {
      *off = start;
      *len = i - start;
      p->pos = i + 1;
      return string_payload_valid(p, start, i);
    }
    if (c == '\\') {
      if (!scan_escape(p, &i))
        return false;
      continue;
    }
    if (c < 0x20)
      return string_error(p, i); /* raw control byte */
    i++;
  }
  return string_error(p, p->len); /* unterminated */
}

static size_t number_error(zjsonp *p, size_t pos) {
  p->pos = pos;
  return 0;
}

static bool literal_error(zjsonp *p, const char *lit, size_t n) {
  size_t i = 0;
  while (i < n && i < p->len - p->pos && p->text[p->pos + i] == lit[i])
    i++;
  p->pos += i;
  return false;
}

/* Scan a number per the strict grammar starting at pos. On success
 * advances pos past the number and returns its length, else 0 and
 * pos identifies the offending byte (len at end of input). */
static bool number_digit(char c) { return c >= '0' && c <= '9'; }

static bool number_integer(zjsonp *p, size_t *at) {
  size_t i = *at;
  if (i < p->len && p->text[i] == '-') i++;
  if (i >= p->len) { number_error(p, i); return false; }
  if (p->text[i] == '0') i++;
  else if (p->text[i] >= '1' && p->text[i] <= '9') {
    while (i < p->len && number_digit(p->text[i])) i++;
  } else { number_error(p, i); return false; }
  *at = i;
  return true;
}

static bool number_fraction(zjsonp *p, size_t *at) {
  size_t i = *at;
  if (i < p->len && p->text[i] == '.') {
    i++;
    if (i >= p->len || !number_digit(p->text[i])) {
      number_error(p, i); return false;
    }
    while (i < p->len && number_digit(p->text[i])) i++;
  }
  *at = i;
  return true;
}

static bool number_exponent(zjsonp *p, size_t *at) {
  size_t i = *at;
  if (i < p->len && (p->text[i] == 'e' || p->text[i] == 'E')) {
    i++;
    if (i < p->len && (p->text[i] == '+' || p->text[i] == '-'))
      i++;
    if (i >= p->len || !number_digit(p->text[i])) {
      number_error(p, i); return false;
    }
    while (i < p->len && number_digit(p->text[i])) i++;
  }
  *at = i;
  return true;
}

static size_t scan_number(zjsonp *p) {
  size_t i = p->pos;
  if (!number_integer(p, &i) || !number_fraction(p, &i) ||
      !number_exponent(p, &i)) return 0;
  size_t n = i - p->pos;
  p->pos = i;
  return n;
}

static bool match_literal(zjsonp *p, const char *lit, size_t n) {
  if (p->len - p->pos < n || memcmp(p->text + p->pos, lit, n) != 0)
    return literal_error(p, lit, n);
  p->pos += n;
  return true;
}

/* Separator handling before a value: at the top level a single value
 * is allowed; in an array a ',' separates elements; in an object the
 * value follows its key's ':'. */
static bool value_preamble(zjsonp *p) {
  if (p->depth == 0)
    return !p->top_done;
  uint32_t lvl = p->depth - 1;
  if ((p->is_array >> lvl) & 1u) {
    if (!((p->first >> lvl) & 1u)) {
      if (p->pos >= p->len || p->text[p->pos] != ',')
        return false;
      p->pos++;
      p->after_comma |= 1u << lvl;
      skip_ws(p);
    }
    return true;
  }
  if ((p->expect_key >> lvl) & 1u)
    return false; /* object key expected, not a value */
  if (p->pos >= p->len || p->text[p->pos] != ':')
    return false;
  p->pos++;
  skip_ws(p);
  return true;
}

static void value_done(zjsonp *p) {
  if (p->depth == 0) {
    p->top_done = true;
    return;
  }
  uint32_t lvl = p->depth - 1;
  p->first &= ~(1u << lvl);
  p->after_comma &= ~(1u << lvl);
  p->expect_key |= 1u << lvl; /* object: back to expecting a key */
}

/* Keep new state checks outside the existing over-cap parser body. */
static bool parser_ready(const zjsonp *p, const zjsonp_event *ev) {
  return ev && !p->failed;
}

static zjsonp_status syntax_failure(zjsonp *p) {
  p->failed = true;
  return ZJRP_SYNTAX;
}

static zjsonp_status close_container(zjsonp *p, zjsonp_event *ev) {
  uint32_t lvl = p->depth - 1;
  bool is_arr = (p->is_array >> lvl) & 1u;
  char c = p->text[p->pos];
  if (is_arr != (c == ']')) return syntax_failure(p);
  if ((p->after_comma >> lvl) & 1u) return syntax_failure(p);
  if (!is_arr && !((p->expect_key >> lvl) & 1u)) return syntax_failure(p);
  p->pos++;
  p->depth--;
  ev->kind = is_arr ? ZJRP_ARR_CLOSE : ZJRP_OBJ_CLOSE;
  ev->off = p->pos - 1;
  ev->len = 0;
  value_done(p);
  return ZJRP_OK;
}

static zjsonp_status read_key(zjsonp *p, zjsonp_event *ev, uint32_t lvl) {
  if (!((p->first >> lvl) & 1u)) {
    if (p->pos >= p->len || p->text[p->pos] != ',') return syntax_failure(p);
    p->pos++;
    p->after_comma |= 1u << lvl;
    skip_ws(p);
  }
  if (p->pos >= p->len || p->text[p->pos] != '"') return syntax_failure(p);
  size_t off = 0, len = 0;
  if (!scan_string(p, &off, &len)) return syntax_failure(p);
  p->expect_key &= ~(1u << lvl);
  ev->kind = ZJRP_KEY;
  ev->off = off;
  ev->len = len;
  return ZJRP_OK;
}

static zjsonp_status open_container(zjsonp *p, zjsonp_event *ev, char c) {
  if (p->depth == ZJRP_MAX_DEPTH) return ZJRP_DEPTH;
  uint32_t lvl = p->depth;
  p->depth++;
  if (c == '[') {
    p->is_array |= 1u << lvl;
    p->expect_key &= ~(1u << lvl);
  } else {
    p->is_array &= ~(1u << lvl);
    p->expect_key |= 1u << lvl;
  }
  p->first |= 1u << lvl;
  p->after_comma &= ~(1u << lvl);
  p->pos++;
  ev->kind = c == '[' ? ZJRP_ARR_OPEN : ZJRP_OBJ_OPEN;
  ev->len = 0;
  return ZJRP_OK;
}

static zjsonp_status read_value(zjsonp *p, zjsonp_event *ev) {
  char c = p->text[p->pos];
  ev->off = p->pos;
  switch (c) {
  case '{': case '[': return open_container(p, ev, c);
  case '"': {
    size_t off = 0, len = 0;
    if (!scan_string(p, &off, &len)) return syntax_failure(p);
    ev->kind = ZJRP_STR;
    ev->off = off;
    ev->len = len;
    value_done(p);
    return ZJRP_OK;
  }
  case 't':
    if (!match_literal(p, "true", 4)) return syntax_failure(p);
    ev->kind = ZJRP_BOOL; ev->len = 4; value_done(p); return ZJRP_OK;
  case 'f':
    if (!match_literal(p, "false", 5)) return syntax_failure(p);
    ev->kind = ZJRP_BOOL; ev->len = 5; value_done(p); return ZJRP_OK;
  case 'n':
    if (!match_literal(p, "null", 4)) return syntax_failure(p);
    ev->kind = ZJRP_NULL; ev->len = 4; value_done(p); return ZJRP_OK;
  default: {
    size_t n = scan_number(p);
    if (n == 0) return syntax_failure(p);
    ev->kind = ZJRP_NUM; ev->len = n; value_done(p); return ZJRP_OK;
  }
  }
}

zjsonp_status zjsonp_next(zjsonp *p, zjsonp_event *ev) {
  if (!p || !parser_ready(p, ev)) return ZJRP_SYNTAX;
  skip_ws(p);
  if (p->top_done && p->depth == 0)
    return p->pos == p->len ? ZJRP_DONE : syntax_failure(p);
  if (p->depth > 0 && p->pos < p->len &&
      (p->text[p->pos] == '}' || p->text[p->pos] == ']'))
    return close_container(p, ev);
  if (p->depth > 0) {
    uint32_t lvl = p->depth - 1;
    if (!((p->is_array >> lvl) & 1u) && ((p->expect_key >> lvl) & 1u))
      return read_key(p, ev, lvl);
  }
  if (!value_preamble(p)) return syntax_failure(p);
  if (p->pos >= p->len) return syntax_failure(p);
  return read_value(p, ev);
}

/* Raw UTF-8 is one scalar, not one scalar per byte. Escapes enter with
 * their resolved scalar and an ASCII backslash at text[0]. */
static size_t encode_string_scalar(const char *text, size_t remaining,
                                   uint32_t cp, size_t *advance, char enc[4]) {
  if ((unsigned char)text[0] >= 0x80 &&
      zutf8_decode_n(text, remaining, &cp, advance) != ZUTF8_OK)
    return 0;
  return zutf8_encode(cp, enc);
}

static bool decode_hex4(const char *text, uint32_t *out) {
  uint32_t v = 0;
  for (int k = 0; k < 4; k++) {
    char h = text[k];
    v <<= 4;
    if (h >= '0' && h <= '9') v |= (uint32_t)(h - '0');
    else if (h >= 'a' && h <= 'f') v |= (uint32_t)(h - 'a' + 10);
    else if (h >= 'A' && h <= 'F') v |= (uint32_t)(h - 'A' + 10);
    else return false;
  }
  *out = v;
  return true;
}

static bool decode_unicode_escape(const char *text, size_t remaining,
                                  uint32_t *cp, size_t *adv) {
  uint32_t v;
  if (remaining < 6 || !decode_hex4(text + 2, &v)) return false;
  *adv = 6;
  if (v >= 0xd800 && v <= 0xdbff) {
    uint32_t lo;
    if (remaining < 12 || text[6] != '\\' || text[7] != 'u' ||
        !decode_hex4(text + 8, &lo) || lo < 0xdc00 || lo > 0xdfff)
      return false;
    *cp = 0x10000 + ((v - 0xd800) << 10) + (lo - 0xdc00);
    *adv = 12;
  } else if (v >= 0xdc00 && v <= 0xdfff) {
    return false;
  } else {
    *cp = v;
  }
  return true;
}

static bool decode_escape(const char *text, size_t remaining,
                          uint32_t *cp, size_t *adv) {
  if (remaining < 2) return false;
  *adv = 2;
  switch (text[1]) {
  case '"': *cp = '"'; return true;
  case '\\': *cp = '\\'; return true;
  case '/': *cp = '/'; return true;
  case 'b': *cp = 0x08; return true;
  case 'f': *cp = 0x0c; return true;
  case 'n': *cp = 0x0a; return true;
  case 'r': *cp = 0x0d; return true;
  case 't': *cp = 0x09; return true;
  case 'u': return decode_unicode_escape(text, remaining, cp, adv);
  default: return false;
  }
}

size_t zjsonp_str_decode(const char *text, const zjsonp_event *ev,
                         char *out, size_t cap) {
  if (!text || !ev || (ev->kind != ZJRP_KEY && ev->kind != ZJRP_STR))
    return SIZE_MAX;
  size_t n = 0;
  size_t i = ev->off, end = ev->off + ev->len;
  while (i < end) {
    unsigned char c = (unsigned char)text[i];
    uint32_t cp = c;
    size_t adv = 1;
    if (c == '\\' && !decode_escape(text + i, end - i, &cp, &adv))
      return SIZE_MAX;
    char enc[4];
    size_t en = encode_string_scalar(text + i, end - i, cp, &adv, enc);
    if (en == 0) return SIZE_MAX;
    for (size_t k = 0; k < en; k++) {
      if (n < cap && out) out[n] = enc[k];
      n++;
    }
    i += adv;
  }
  return n;
}

/* JSON permits negative zero; strtoll formats it back as positive zero. */
static bool integer_spelling_matches(const char *input, const char *back) {
  return strcmp(input, back) == 0 || strcmp(input, "-0") == 0;
}

bool zjsonp_num_i64(const char *text, const zjsonp_event *ev,
                    int64_t *out) {
  if (!text || !ev || ev->kind != ZJRP_NUM || !out)
    return false;
  if (ev->len == 0 || ev->len >= 24)
    return false;
  char tmp[24];
  memcpy(tmp, text + ev->off, ev->len);
  tmp[ev->len] = '\0';
  if (strchr(tmp, '.') || strchr(tmp, 'e') || strchr(tmp, 'E'))
    return false; /* integer form only */
  char *end = NULL;
  long long v = strtoll(tmp, &end, 10);
  if (!end || *end != '\0')
    return false;
  if ((long long)(int64_t)v != v)
    return false;
  /* range check: strtoll clamps on overflow; reformat to detect it */
  char back[24];
  snprintf(back, sizeof back, "%lld", v);
  if (!integer_spelling_matches(tmp, back))
    return false;
  *out = (int64_t)v;
  return true;
}

bool zjsonp_num_f64(const char *text, const zjsonp_event *ev,
                    double *out) {
  if (!text || !ev || ev->kind != ZJRP_NUM || !out)
    return false;
  if (ev->len == 0 || ev->len >= 64)
    return false;
  char tmp[64];
  memcpy(tmp, text + ev->off, ev->len);
  tmp[ev->len] = '\0';
  char *end = NULL;
  double v = strtod(tmp, &end);
  if (!end || *end != '\0')
    return false;
  *out = v;
  return true;
}
