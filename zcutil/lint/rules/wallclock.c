/* zcl-lint wallclock: a test must not pass or fail on how long the machine took.
 *
 * Copyright 2026 Rhett Creighton - MIT (zclassicd).
 * Derived from Z23 tools/lint/lintc/gate_no_wallclock_assertion*
 * @9a191ef7b1184e14d9116362dff7def64cd300e3 (rule shape); modified, not verbatim. See zcutil/lint/NOTICE.
 *
 * Scope: shell scripts under qa/ and any test directory, and C/C++ under qa/, src/test/ and src/gtest/.
 *   shell  a line that compares a time quantity (elapsed, duration, took, runtime, SECONDS, `date +%s`) with
 *          -lt -le -gt -ge or an arithmetic < > (a timeout loop that only waits is fine: it must not assert)
 *   C/C++  an EXPECT_*, ASSERT_*, BOOST_CHECK*, BOOST_REQUIRE* or assert statement that compares (_LT _LE _GT _GE or < >)
 *          a real clock reading (duration, elapsed, GetTime, GetTimeMillis, GetTimeMicros, chrono, steady_clock, system_clock, clock)
 * Override with `real-clock: reason` in a comment on any line of the statement. Baseline row: "<path>	<count>".
 */
#define _POSIX_C_SOURCE 200809L
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool in_scope_sh(const char *p)
{
    if (lint_is_vendored(p) || !lint_is_shell_file(p)) return false;
    return lint_has_prefix(p, "qa/") || strstr(p, "/test/") || strstr(p, "/tests/") || lint_has_prefix(p, "test/");
}

static bool in_scope_c(const char *p)
{
    if (lint_is_vendored(p) || !lint_is_c_source(p)) return false;
    return lint_has_prefix(p, "qa/") || lint_has_prefix(p, "src/test/") || lint_has_prefix(p, "src/gtest/");
}

static const char *find_ci(const char *h, const char *n)
{
    size_t k = strlen(n);
    for (; *h; h++) {
        size_t i;
        for (i = 0; i < k && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)n[i]); i++) {}
        if (i == k) return h;
    }
    return NULL;
}

static bool sh_time_word(const char *l)
{
    static const char *const w[] = { "elapsed", "duration", "took", "runtime", "date +%s", "$seconds", "${seconds}", "_secs", "wall_time" };
    for (size_t i = 0; i < sizeof w / sizeof w[0]; i++) if (find_ci(l, w[i])) return true;
    return false;
}

static bool sh_compare(const char *l)
{
    static const char *const op[] = { " -lt ", " -le ", " -gt ", " -ge " };
    for (size_t i = 0; i < sizeof op / sizeof op[0]; i++) if (strstr(l, op[i])) return true;
    const char *a = strstr(l, "((");
    return a && (strchr(a, '<') || strchr(a, '>')) && !strstr(a, "<<") && !strstr(a, ">>") ? true : false;
}

static bool sh_test_line(const char *l)
{
    while (*l == ' ' || *l == '\t') l++;
    if (*l == '#') return false;
    if ((!strncmp(l, "echo", 4) && (l[4] == ' ' || l[4] == '\t' || !l[4])) || !strncmp(l, "printf ", 7)) return false;   /* a report, not an assertion */
    if (!strstr(l, "[") && !strstr(l, "test ") && !strstr(l, "((")) return false;   /* needs a test command */
    return sh_time_word(l) && sh_compare(l);
}

static bool c_assert_head(const char *s, size_t n)
{
    static const char *const h[] = { "EXPECT_", "ASSERT_", "BOOST_CHECK", "BOOST_REQUIRE", "assert(", "assert (" };
    for (size_t i = 0; i < n; i++) {
        if (i && lint_idc((unsigned char)s[i - 1])) continue;
        for (size_t k = 0; k < sizeof h / sizeof h[0]; k++)
            if (!strncmp(s + i, h[k], strlen(h[k]))) return true;
    }
    return false;
}

/* Identifier tokens that read a real clock: exact names, or a token containing duration or elapsed. */
static bool c_clock(const char *s)
{
    static const char *const exact[] = { "GetTime", "GetTimeMillis", "GetTimeMicros", "chrono", "steady_clock", "system_clock", "clock" };
    for (size_t i = 0; s[i];) {
        if (!lint_idc((unsigned char)s[i]) || isdigit((unsigned char)s[i])) { i++; continue; }
        size_t j = i;
        while (lint_idc((unsigned char)s[j])) j++;
        char tok[128];
        size_t k = j - i < sizeof tok - 1 ? j - i : sizeof tok - 1;
        memcpy(tok, s + i, k);
        tok[k] = '\0';
        if (find_ci(tok, "duration") || find_ci(tok, "elapsed")) return true;
        for (size_t e = 0; e < sizeof exact / sizeof exact[0]; e++) if (!strcmp(tok, exact[e])) return true;
        i = j;
    }
    return false;
}

/* A comparison decides the test: an _LT/_LE/_GT/_GE/_NEAR macro, or a spaced < > <= >= operator. */
static bool c_compare(const char *s)
{
    static const char *const m[] = { "_LT(", "_LE(", "_GT(", "_GE(", "_NEAR(", " < ", " > ", " <= ", " >= ", "_LT (", "_GT (" };
    for (size_t i = 0; i < sizeof m / sizeof m[0]; i++) if (strstr(s, m[i])) return true;
    return false;
}

static long scan_c(const char *raw, const char *scrub)
{
    long hits = 0;
    size_t len = strlen(scrub), st = 0;
    int depth = 0;
    for (size_t i = 0; i <= len; i++) {
        char c = i < len ? scrub[i] : ';';
        if (c == '(') depth++;
        else if (c == ')' && depth > 0) depth--;
        if (i == len || (depth == 0 && (c == ';' || c == '{' || c == '}'))) {
            size_t n = i - st;
            /* The override window starts at the statement's first code character (comments are blanked in scrub),
             * so the previous statement's trailing comment cannot excuse this one; it runs to the end of the
             * last line so a trailing override comment counts. */
            size_t ws = st;
            while (ws < i && isspace((unsigned char)scrub[ws])) ws++;
            size_t rn = i - ws;
            while (raw[ws + rn] && raw[ws + rn] != '\n') rn++;
            char *chunk = malloc(n + 1), *rc = malloc(rn + 1);
            if (!chunk || !rc) { fprintf(stderr, "zcl-lint: wallclock: out of memory\n"); exit(2); }
            memcpy(chunk, scrub + st, n); chunk[n] = '\0';
            memcpy(rc, raw + ws, rn); rc[rn] = '\0';
            /* A *_MESSAGE macro's message argument is not the condition: only the first argument is judged. */
            char *mm = strstr(chunk, "_MESSAGE");
            if (mm) {
                char *p = strchr(mm, '(');
                int d = 0;
                for (; p && *p; p++) {
                    if (*p == '(') d++;
                    else if (*p == ')') d--;
                    else if (*p == ',' && d == 1) { *p = '\0'; break; }
                }
            }
            if (c_assert_head(chunk, n) && c_clock(chunk) && c_compare(chunk) && !strstr(rc, "real-clock:")) hits++;
            free(chunk); free(rc);
            st = i + 1;
        }
    }
    return hits;
}

int lint_rule_wallclock(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t f = 0; f < lint_nfiles; f++) {
        const char *path = lint_files[f];
        bool sh = in_scope_sh(path), c = in_scope_c(path);
        if (!sh && !c) continue;
        char *raw = lint_slurp(path, NULL);
        if (!raw) continue;
        scanned++;
        long n = 0;
        if (sh) {
            for (char *s = raw;;) {
                char *e = strchr(s, '\n');
                if (e) *e = '\0';
                if (sh_test_line(s) && !strstr(s, "real-clock:")) n++;
                if (!e) break;
                s = e + 1;
            }
        } else {
            char *scrub = lint_xstrdup(raw);
            bool blk = false;
            for (char *ln = scrub; *ln;) {
                char *nlp = strchr(ln, '\n');
                if (nlp) *nlp = '\0';
                lint_scrub_c_line(ln, &blk);
                if (!nlp) break;
                *nlp = '\n';
                ln = nlp + 1;
            }
            n = scan_c(raw, scrub);
            free(scrub);
        }
        if (n) lint_rows_add(&cur, path, n);
        free(raw);
    }
    return lint_ratchet("wallclock", "assertions decided by elapsed real time", &cur, scanned, update);
}
