/* zcl-lint victory: no uncited victory claims in the live-state page. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_no_uncited_victory.c@9a191ef7b1184e14d9116362dff7def64cd300e3,
 * modified (zclassicd citation forms), not verbatim; see zcutil/tools/NOTICE.
 *
 * Only doc/agent/HANDOFF.md is read. A paragraph (blank-line separated, outside code fences) that says
 * fixed / cured / fully synced / at tip / green must carry a citation token:
 *   - a commit id of 7 to 40 hex digits that names a commit in this repository (git cat-file),
 *   - a receipt path (a word with a '/' containing "receipt"), or
 *   - a local-ci results path (a word with a '/' containing "local-ci"),
 * or the exemption <!-- victory-ok: reason --> with a non-empty reason. A missing HANDOFF.md is a hollow scan.
 */
#define _POSIX_C_SOURCE 200809L
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HANDOFF "doc/agent/HANDOFF.md"

static const char *const phrases[] = { "fixed", "cured", "fully synced", "at tip", "green" };

static bool word_at(const char *p, const char *start, size_t n)
{
    return (p == start || !isalnum((unsigned char)p[-1])) && !isalnum((unsigned char)p[n]);
}

/* Lower-case copy of a paragraph so phrases match in any case. */
static char *lower(const char *s)
{
    char *d = lint_xstrdup(s);
    for (char *p = d; *p; p++) *p = (char)tolower((unsigned char)*p);
    return d;
}

static bool has_victory(const char *low)
{
    for (size_t i = 0; i < sizeof phrases / sizeof phrases[0]; i++) {
        size_t n = strlen(phrases[i]);
        for (const char *p = strstr(low, phrases[i]); p; p = strstr(p + 1, phrases[i]))
            if (word_at(p, low, n)) return true;
    }
    return false;
}

static bool commit_exists(const char *hex)
{
    char spec[200];
    if (strlen(hex) > 100) return false;
    snprintf(spec, sizeof spec, "%s^{commit}", hex);
    char *argv[] = { "git", "-C", (char *)lint_root, "cat-file", "-e", spec, NULL };
    return lint_run_argv(argv, true) == 0;
}

static bool has_ok(const char *para)
{
    const char *p = strstr(para, "<!-- victory-ok:");
    if (!p) return false;
    p += 16;
    const char *e = strstr(p, "-->");
    if (!e) return false;
    for (; p < e; p++)
        if (!isspace((unsigned char)*p)) return true;
    return false;
}

static bool has_citation(const char *para)
{
    char *copy = lint_xstrdup(para);
    bool ok = false;
    for (char *w = strtok(copy, " \t\r\n`()[],;<>\"'"); w && !ok; w = strtok(NULL, " \t\r\n`()[],;<>\"'")) {
        size_t n = strlen(w);
        while (n && strchr(".:", w[n - 1])) w[--n] = '\0';
        if (strchr(w, '/') && (strstr(w, "receipt") || strstr(w, "local-ci"))) { ok = true; break; }
        if (n >= 7 && n <= 40 && strspn(w, "0123456789abcdef") == n && strpbrk(w, "0123456789") && commit_exists(w)) ok = true;
    }
    free(copy);
    return ok;
}

/* Judge one paragraph; line is its first line. Returns 1 on a finding. */
static int judge(char *para, long line)
{
    if (!*para) return 0;
    char *low = lower(para);
    int bad = 0;
    if (has_victory(low) && !has_ok(para) && !has_citation(para)) {
        printf("FAIL victory: %s:%ld: victory wording (fixed/cured/fully synced/at tip/green) without a commit id, receipt path, "
               "local-ci results path or <!-- victory-ok: reason -->\n", HANDOFF, line);
        bad = 1;
    }
    free(low);
    return bad;
}

int lint_rule_victory(bool update)
{
    (void)update; /* no baseline; the driver refuses --update-baseline for this rule */
    char *txt = lint_slurp(HANDOFF, NULL);
    if (!txt || !lint_is_tracked(HANDOFF)) {
        free(txt);
        printf("FAIL victory: hollow scan (%s is not a tracked readable file)\n", HANDOFF);
        return 2;
    }
    size_t cap = strlen(txt) + 1;
    char *para = lint_xrealloc(NULL, cap);
    size_t used = 0;
    long ln = 0, start = 1;
    int bad = 0;
    bool fence = false;
    for (char *l = txt; l && *l;) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        ln++;
        const char *t = l;
        while (*t == ' ') t++;
        bool blank = !*t;
        if (lint_has_prefix(t, "```") || lint_has_prefix(t, "~~~")) { fence = !fence; blank = true; }
        if (fence && !blank) blank = true;                        /* fenced text is an example, not a statement */
        if (blank) {
            para[used] = '\0';
            bad += judge(para, start);
            used = 0;
            start = ln + 1;
        } else {
            size_t n = strlen(l);
            memcpy(para + used, l, n);
            used += n;
            para[used++] = '\n';
        }
        l = nl ? nl + 1 : NULL;
    }
    para[used] = '\0';
    bad += judge(para, start);
    free(para);
    free(txt);
    if (bad) return 1;
    printf("victory: ok (%s)\n", HANDOFF);
    return 0;
}
