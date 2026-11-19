/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard_rules.c@9a191ef7b, Apache-2.0, changed (zclassicd's rules; see
 * zcutil/tools/NOTICE). zcl-agent-guard: shell glob matching of a component pattern (split out of
 * rules.c). */

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include "rules_int.h"

static int lc(int ch)
{
    return tolower((unsigned char)ch);
}

static bool glob_match_r(const char *p, const char *s);

/* The bracket expression at p ("[a-c]", "[!x]") against the character *s; q ends past the ']' and
 * the verdict is in *ok. Returns false for an unclosed bracket (then '[' is a literal). */
static bool bracket(const char *p, const char *s, const char **end, bool *ok)
{
    const char *q = p + 1;
    bool neg = false, hit = false, first = true;
    if (*q == '!' || *q == '^') {
        neg = true;
        q++;
    }
    while (*q && (*q != ']' || first)) {
        first = false;
        if (q[1] == '-' && q[2] && q[2] != ']') {
            if (lc(*s) >= lc(q[0]) && lc(*s) <= lc(q[2])) hit = true;
            q += 3;
        } else {
            if (lc(*s) == lc(*q)) hit = true;
            q++;
        }
    }
    *end = q;
    *ok = hit != neg;
    return *q != '\0';
}

/* Shell glob match of pattern p against s, case-insensitive. '*' also matches a leading dot
 * (dotglob and zsh both exist), so the match errs toward refusing. A very long pattern matches. */
static bool glob_match_r(const char *p, const char *s)
{
    const char *q;
    bool ok;
    if (!*p) return !*s;
    if (*p == '*') {
        while (*p == '*') p++;
        if (!*p) return true;
        for (;; s++) {
            if (glob_match_r(p, s)) return true;
            if (!*s) return false;
        }
    }
    if (!*s) return false;
    if (*p == '?') return glob_match_r(p + 1, s + 1);
    if (*p == '[') {
        if (!bracket(p, s, &q, &ok)) return lc(*s) == '[' && glob_match_r(p + 1, s + 1);
        return ok && glob_match_r(q + 1, s + 1);
    }
    return lc(*p) == lc(*s) && glob_match_r(p + 1, s + 1);
}

bool ag_glob_match(const char *p, const char *s)
{
    return strlen(p) > 64 || glob_match_r(p, s);
}
