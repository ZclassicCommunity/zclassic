/* zcl-lint shellport: shell scripts must not lean on GNU-only or Linux-only tools that break on macOS.
 *
 * Copyright 2026 Rhett Creighton - MIT (zclassicd).
 * Derived from Z23 tools/lint/lintc/gate_shell_host_assumptions.c and gate_pipefail_status_pipe*
 * @9a191ef7b1184e14d9116362dff7def64cd300e3 (rule shape); modified, not verbatim. See zcutil/lint/NOTICE.
 *
 * Scope: every tracked shell file outside vendored trees. Comments and quoted text are blanked first, then each
 * simple command is checked at command position. Kinds, each its own baseline row "<path>:<kind>":
 *   sed-i  stat-c  nproc  ss  readlink-f  date-d  grep-P  timeout   a GNU/Linux-only command or option
 *   pipefail-grep-q   `... | grep -q` in a script that sets pipefail (grep -q closes the pipe early: SIGPIPE
 *                     then fails the pipeline although the match was found)
 * Override a line with `port-ok: reason` in a comment (for example a command guarded by `command -v`).
 */
#define _POSIX_C_SOURCE 200809L
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum kind { K_SED_I, K_STAT_C, K_NPROC, K_SS, K_READLINK_F, K_DATE_D, K_GREP_P, K_TIMEOUT, K_PIPEFAIL, K_COUNT };
static const char *const kind_name[K_COUNT] = {
    "sed-i", "stat-c", "nproc", "ss", "readlink-f", "date-d", "grep-P", "timeout", "pipefail-grep-q" };

static bool is_sep(const char *s, size_t i)
{
    char c = s[i];
    if (c == ';' || c == '|' || c == '(' || c == ')' || c == '`' || c == '{' || c == '}') return true;
    if (c == '&') return !(i > 0 && (s[i - 1] == '>' || s[i - 1] == '<')) && s[i + 1] != '>';
    return false;
}

static bool skip_word(const char *w)
{
    static const char *const kw[] = { "then", "do", "else", "elif", "if", "while", "until", "!", "time", "sudo", "env", "exec", "command", "builtin" };
    for (size_t i = 0; i < sizeof kw / sizeof kw[0]; i++)
        if (!strcmp(w, kw[i])) return true;
    return strchr(w, '=') && w[0] != '=' && (isalpha((unsigned char)w[0]) || w[0] == '_') && !strchr(w, '/') ? true : false;
}

/* Words of one simple command, split on blanks. Returns count; w[] point into seg (modified). */
static size_t words(char *seg, char **w, size_t max)
{
    size_t n = 0;
    for (char *p = strtok(seg, " \t\r"); p && n < max; p = strtok(NULL, " \t\r")) w[n++] = p;
    return n;
}

static bool flag_has(const char *w, char c)
{
    return w[0] == '-' && w[1] != '-' && w[1] && strchr(w + 1, c);
}

static void classify(char *seg, char prev_sep, bool pipefail, long *cnt)
{
    char *w[64];
    size_t n = words(seg, w, 64), i = 0;
    while (i < n && skip_word(w[i])) i++;
    if (i >= n) return;
    const char *cmd = w[i];
    const char *base = strrchr(cmd, '/') ? strrchr(cmd, '/') + 1 : cmd;
    bool any = false;
    if (!strcmp(base, "nproc")) cnt[K_NPROC]++;
    else if (!strcmp(base, "ss")) cnt[K_SS]++;
    else if (!strcmp(base, "timeout")) cnt[K_TIMEOUT]++;
    else if (!strcmp(base, "sed")) {
        for (size_t j = i + 1; j < n && !any; j++)
            if (!strncmp(w[j], "-i", 2) || !strcmp(w[j], "--in-place")) any = true;
        if (any) cnt[K_SED_I]++;
    } else if (!strcmp(base, "stat")) {
        for (size_t j = i + 1; j < n && !any; j++) if (flag_has(w[j], 'c')) any = true;
        if (any) cnt[K_STAT_C]++;
    } else if (!strcmp(base, "readlink")) {
        for (size_t j = i + 1; j < n && !any; j++) if (flag_has(w[j], 'f')) any = true;
        if (any) cnt[K_READLINK_F]++;
    } else if (!strcmp(base, "date")) {
        for (size_t j = i + 1; j < n && !any; j++) if (flag_has(w[j], 'd') || !strncmp(w[j], "--date", 6)) any = true;
        if (any) cnt[K_DATE_D]++;
    } else if (!strcmp(base, "grep") || !strcmp(base, "egrep") || !strcmp(base, "fgrep")) {
        bool q = false, p = false;
        for (size_t j = i + 1; j < n; j++) {
            if (flag_has(w[j], 'P') || !strcmp(w[j], "--perl-regexp")) p = true;
            if (flag_has(w[j], 'q') || !strcmp(w[j], "--quiet")) q = true;
        }
        if (p) cnt[K_GREP_P]++;
        if (q && pipefail && prev_sep == '|') cnt[K_PIPEFAIL]++;
    }
}

/* Does the (scrubbed) line set pipefail? */
static bool sets_pipefail(const char *s)
{
    const char *p = strstr(s, "pipefail");
    if (!p) return false;
    const char *set = strstr(s, "set");
    return set && set < p;
}

static void scan_line(char *scrub, bool pipefail, long *cnt)
{
    char *seg = scrub;
    char prev = 0;
    size_t len = strlen(scrub);
    for (size_t i = 0; i <= len; i++) {
        if (i < len && !is_sep(scrub, i)) continue;
        char sep = i < len ? scrub[i] : 0;
        bool dbl = sep == '|' && i + 1 < len && scrub[i + 1] == '|';
        scrub[i] = '\0';
        classify(seg, prev, pipefail, cnt);
        if (i == len) break;
        if (dbl) { i++; prev = 'o'; } else prev = sep;
        seg = scrub + i + 1;
    }
}

int lint_rule_shellport(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t f = 0; f < lint_nfiles; f++) {
        const char *path = lint_files[f];
        if (lint_is_vendored(path) || !lint_is_shell_file(path)) continue;
        char *txt = lint_slurp(path, NULL);
        if (!txt) continue;
        scanned++;
        long cnt[K_COUNT] = { 0 };
        bool pipefail = false;
        char quote = 0;
        for (char *s = txt; *s;) {
            char *e = strchr(s, '\n');
            if (e) *e = '\0';
            char *raw = lint_xstrdup(s);
            lint_scrub_sh_line(s, &quote);
            if (!strstr(raw, "port-ok:")) {
                if (sets_pipefail(s)) pipefail = true;
                scan_line(s, pipefail, cnt);
            }
            free(raw);
            if (!e) break;
            s = e + 1;
        }
        for (int k = 0; k < K_COUNT; k++) {
            if (!cnt[k]) continue;
            char key[1024];
            snprintf(key, sizeof key, "%s:%s", path, kind_name[k]);
            lint_rows_add(&cur, key, cnt[k]);
        }
        free(txt);
    }
    return lint_ratchet("shellport", "host-specific commands in shell scripts per path and kind", &cur, scanned, update);
}
