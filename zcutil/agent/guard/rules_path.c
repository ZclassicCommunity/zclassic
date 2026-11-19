/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard_rules.c@9a191ef7b, Apache-2.0, changed (zclassicd's rules; see
 * zcutil/tools/NOTICE). zcl-agent-guard: does a path word contain a given directory or file name,
 * whatever its spelling (split out of rules.c). */

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "rules_int.h"

/* The characters that separate path words in a command word (see PATH_SEPS in rules.c). */
static bool is_psep(char ch)
{
    return ch != '\0' && strchr("/\\=:, \t\n\"'()`;|&<>", ch) != NULL;
}

/* End of the component of w that starts at i (the next / or backslash, or n). */
static size_t comp_end(const char *w, size_t i, size_t n)
{
    while (i < n && w[i] != '/' && w[i] != '\\') i++;
    return i;
}

/* A '..' component against the output so far: 'x/..' vanishes unless x is '..' or the root.
 * True when the '..' is absorbed and nothing is copied. */
static bool fold_dotdot(char *out, size_t *o)
{
    size_t e = *o, k;
    if (e == 0) return false;
    if (out[e - 1] == '/') e--;
    k = e;
    while (k > 0 && out[k - 1] != '/') k--;
    if (e == k) return true; /* '/..' is '/' */
    if (e - k == 2 && out[k] == '.' && out[k + 1] == '.') return false;
    *o = k;
    return true;
}

/* Copy w with backslashes as '/', '//' collapsed, '.' components dropped, 'x/..' folded and
 * letters lower-cased: NTFS and default APFS are case-insensitive, and the shell resolves the
 * rest, so every spelling must reach the same compare. NULL when out of memory. */
static char *norm_path(const char *w)
{
    size_t n = strlen(w), o = 0;
    char *out = malloc(n + 1); // raw-alloc-ok:build-tool
    if (!out) {
        ag_mark_complex();
        return NULL;
    }
    for (size_t i = 0; i < n;) {
        size_t cs = i, ce = comp_end(w, i, n);
        i = ce < n ? ce + 1 : n;
        if (ce == cs) { /* empty component: '//' or a leading separator */
            if (cs == 0) out[o++] = '/';
            continue;
        }
        if (ce - cs == 1 && w[cs] == '.') continue;
        if (ce - cs == 2 && w[cs] == '.' && w[cs + 1] == '.' && fold_dotdot(out, &o)) continue;
        for (size_t k = cs; k < ce; k++) out[o++] = (char)tolower((unsigned char)w[k]);
        if (ce < n) out[o++] = '/';
    }
    out[o] = '\0';
    return out;
}

static bool path_has_norm(const char *w, const char *pat, bool dir_mode)
{
    size_t m = strlen(pat);
    for (size_t i = 0; w[i]; i++) {
        size_t k = 0;
        if (i > 0 && !is_psep(w[i - 1])) continue;
        while (k < m && w[i + k] && w[i + k] == pat[k]) k++;
        if (k != m) continue;
        if (w[i + k] == '\0') return true;
        if (dir_mode && w[i + k] == '/') return true;
    }
    return false;
}

/* True when pat (written lower-case with '/') occurs in w at a component boundary, after
 * normalisation. dir_mode: the match may be followed by a path separator or the end (a
 * directory); otherwise it must end the word. */
bool ag_path_has(const char *w, const char *pat, bool dir_mode)
{
    char *nw = norm_path(w), *np = norm_path(pat);
    bool r = nw && np && path_has_norm(nw, np, dir_mode);
    free(nw);
    free(np);
    return r;
}
