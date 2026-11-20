/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * zcl-agent-guard: decoding of one printf or echo -e escape. This is the "simple encodings" step:
 * a command spelled \x72\x6d (or in octal) and piped to a shell is scanned as the command it is. */

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>

#include "rules_int.h"

static int hex_val(int c)
{
    if (isdigit((unsigned char)c)) return c - '0';
    return tolower((unsigned char)c) - 'a' + 10;
}

/* \xHH: one or two hex digits; p points at the x. */
static const char *esc_hex(const char *p, char *out, size_t *n)
{
    unsigned v = 0;
    int digits = 0;
    for (p++; digits < 2 && isxdigit((unsigned char)*p); p++, digits++)
        v = v * 16 + (unsigned)hex_val(*p);
    if (digits == 0) {
        out[0] = 'x';
        *n = 1;
        return p;
    }
    out[0] = (char)v;
    *n = v ? 1 : 0; /* a NUL byte is dropped: the text is a C string */
    return p;
}

/* \NNN octal (echo -e: \0NNN); p points at the first digit. */
static const char *esc_oct(const char *p, bool echo, char *out, size_t *n)
{
    unsigned v = 0;
    int digits = 0;
    if (*p == '0' && echo) p++;
    for (; digits < 3 && *p >= '0' && *p <= '7'; p++, digits++) v = v * 8 + (unsigned)(*p - '0');
    v &= 0xff;
    out[0] = (char)v;
    *n = v ? 1 : 0;
    return p;
}

/* The single-letter escapes; 0 when ch is not one. */
static char esc_letter(char ch, bool echo)
{
    switch (ch) {
    case 'n': return '\n';
    case 't': return '\t';
    case 'r': return '\r';
    case 'a': return '\a';
    case 'b': return '\b';
    case 'f': return '\f';
    case 'v': return '\v';
    case 'e':
    case 'E': return echo ? '\033' : 0;
    default: return 0;
    }
}

const char *ag_esc_one(const char *p, bool echo, char *out, size_t *n)
{
    char c = esc_letter(*p, echo);
    if (c) {
        out[0] = c;
        *n = 1;
        return p + 1;
    }
    if (*p == 'x') return esc_hex(p, out, n);
    if (*p >= '0' && *p <= '7') return esc_oct(p, echo, out, n);
    out[0] = *p; /* a backslash and any other character: the character itself */
    *n = 1;
    return p + 1;
}
