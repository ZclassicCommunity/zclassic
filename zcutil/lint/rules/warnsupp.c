/* zcl-lint warnsupp: compiler warning suppressions may not grow.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from the Z23 make target check-no-warning-suppression@9a191ef7b1184e14d9116362dff7def64cd300e3; modified.
 *
 * Counts per file: #pragma GCC|clang diagnostic ignored, #pragma warning(disable, and -Wno- in configure.ac,
 * Makefile.am and *.include build fragments. Baseline zcutil/lint/warnsupp.txt, shrink-only.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

/* Word at p (after whitespace), compared case-sensitively; advances p past it. */
static bool take_word(const char **pp, const char *w)
{
    const char *p = skip_ws(*pp);
    size_t n = strlen(w);
    if (strncmp(p, w, n) != 0 || lint_idc((unsigned char)p[n])) return false;
    *pp = p + n;
    return true;
}

static bool is_suppression_pragma(const char *l)
{
    l = skip_ws(l);
    if (*l != '#') return false;
    l++;
    if (!take_word(&l, "pragma")) return false;
    const char *q = l;
    if (take_word(&q, "GCC") || (q = l, take_word(&q, "clang"))) {
        if (!take_word(&q, "diagnostic")) return false;
        return take_word(&q, "ignored");
    }
    q = l;
    if (take_word(&q, "warning")) {
        q = skip_ws(q);
        if (*q != '(') return false;
        q++;
        return take_word(&q, "disable");
    }
    return false;
}

static bool is_build_fragment(const char *p)
{
    const char *base = strrchr(p, '/');
    base = base ? base + 1 : p;
    return !strcmp(base, "configure.ac") || !strcmp(base, "Makefile.am") || lint_has_suffix(base, ".include");
}

static long count_wno(const char *line)
{
    const char *s = skip_ws(line);
    if (*s == '#' || lint_has_prefix(s, "dnl")) return 0;
    long n = 0;
    for (const char *p = strstr(line, "-Wno-"); p; p = strstr(p + 5, "-Wno-")) n++;
    return n;
}

static bool in_scope_source(const char *path)
{
    if (!lint_is_c_source(path)) return false;
    return lint_has_prefix(path, "src/") || lint_has_prefix(path, "wallet/") || lint_has_prefix(path, "qa/") || lint_has_prefix(path, "zcutil/");
}

/* Suppressions in one file's text (modified in place). */
static long count_text(char *txt, bool frag)
{
    long n = 0;
    bool blk = false;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        if (frag) { n += count_wno(line); continue; }
        bool pragma = !blk && *skip_ws(line) == '#' && is_suppression_pragma(line);   /* a directive, so not inside a block comment */
        lint_scrub_c_line(line, &blk);
        if (pragma) n++;
    }
    return n;
}

int lint_rule_warnsupp(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        const char *path = lint_files[i];
        bool frag = is_build_fragment(path);
        if (lint_is_vendored(path) || !(frag || in_scope_source(path))) continue;
        char *txt = lint_slurp(path, NULL);
        if (!txt) continue;
        scanned++;
        long n = count_text(txt, frag);
        if (n) lint_rows_add(&cur, path, n);
        free(txt);
    }
    return lint_ratchet("warnsupp", "warning suppressions (pragmas and -Wno- flags)", &cur, scanned, update);
}
