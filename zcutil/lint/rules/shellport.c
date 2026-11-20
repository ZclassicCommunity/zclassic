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
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
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

/* Shell scrubber that keeps command substitutions: literal text of quotes and comments is blanked, but the code
 * inside $(...) and backticks within double quotes survives (blanking it hid `make -j"$(nproc)"`). A `$(` or
 * backtick inside double quotes becomes ';' so its first word sits at command position. The mode stack carries
 * across lines like the quote state of lint_scrub_sh_line. */
#define SCRUB_DEPTH 16
struct scrub { char mode[SCRUB_DEPTH]; int paren[SCRUB_DEPTH]; int top; };   /* mode: c code, s ', d ", b backtick */

static void scrub_push(struct scrub *st, char m)
{
    if (st->top + 1 < SCRUB_DEPTH) { st->top++; st->mode[st->top] = m; st->paren[st->top] = 0; }
}

static void sh_scrub(char *s, struct scrub *st)
{
    for (size_t i = 0; s[i]; i++) {
        char m = st->mode[st->top];
        if (m == 's') {
            if (s[i] == '\'') st->top--;
            s[i] = ' ';
        } else if (m == 'd') {
            if (s[i] == '\\' && s[i + 1]) { s[i] = ' '; i++; s[i] = ' '; continue; }
            if (s[i] == '"') { st->top--; s[i] = ' '; }
            else if (s[i] == '$' && s[i + 1] == '(' && s[i + 2] != '(') { s[i] = ' '; i++; s[i] = ';'; scrub_push(st, 'c'); }
            else if (s[i] == '`') { s[i] = ';'; scrub_push(st, 'b'); }
            else s[i] = ' ';
        } else {
            if (s[i] == '\\' && s[i + 1]) { i++; continue; }
            if (s[i] == '\'') { s[i] = ' '; scrub_push(st, 's'); }
            else if (s[i] == '"') { s[i] = ' '; scrub_push(st, 'd'); }
            else if (m == 'b' && s[i] == '`') { s[i] = ';'; st->top--; }
            else if (st->top > 0 && m == 'c' && s[i] == '(') st->paren[st->top]++;
            else if (st->top > 0 && m == 'c' && s[i] == ')') {
                if (st->paren[st->top] > 0) st->paren[st->top]--; else { s[i] = ';'; st->top--; }
            } else if (s[i] == '#' && (i == 0 || isspace((unsigned char)s[i - 1]) || strchr(";&|(", s[i - 1]))) {
                memset(s + i, ' ', strlen(s + i));
                return;
            }
        }
    }
}

/* Heredoc delimiters opened on this raw line; scrubbed line s marks which '<' are real code. */
#define MAX_HD 4
static int heredocs(const char *raw, const char *s, char dl[MAX_HD][128], bool strip[MAX_HD])
{
    int n = 0;
    if (strstr(s, "((")) return 0;   /* arithmetic shift, not a heredoc */
    for (size_t i = 0; raw[i] && raw[i + 1] && n < MAX_HD; i++) {
        if (raw[i] != '<' || raw[i + 1] != '<' || s[i] != '<') continue;
        size_t j = i + 2;
        if (raw[j] == '<') { i = j; continue; }   /* here-string */
        bool st = raw[j] == '-';
        if (st) j++;
        while (raw[j] == ' ' || raw[j] == '\t') j++;
        char q = 0;
        if (raw[j] == '\'' || raw[j] == '"') q = raw[j++]; else if (raw[j] == '\\') j++;
        size_t k = 0;
        while (raw[j] && k < 127 && (q ? raw[j] != q : (isalnum((unsigned char)raw[j]) || raw[j] == '_'))) dl[n][k++] = raw[j++];
        dl[n][k] = '\0';
        i = j;
        if (!k || (!q && !isalpha((unsigned char)dl[n][0]) && dl[n][0] != '_')) continue;
        strip[n++] = st;
    }
    return n;
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
        struct scrub st;
        memset(&st, 0, sizeof st);
        st.mode[0] = 'c';
        char hd[MAX_HD][128];
        bool hd_strip[MAX_HD];
        int nhd = 0, hd_at = 0;   /* pending heredoc bodies: skip lines (data, not commands) up to each delimiter */
        for (char *s = txt; *s;) {
            char *e = strchr(s, '\n');
            if (e) *e = '\0';
            if (nhd > 0) {
                const char *l = s;
                if (hd_strip[hd_at]) while (*l == '\t') l++;
                size_t len = strlen(l);
                if (len && l[len - 1] == '\r') len--;
                if (strlen(hd[hd_at]) == len && !strncmp(l, hd[hd_at], len) && ++hd_at == nhd) nhd = hd_at = 0;
                if (!e) break;
                s = e + 1;
                continue;
            }
            char *raw = lint_xstrdup(s);
            sh_scrub(s, &st);
            int found = st.top == 0 ? heredocs(raw, s, hd, hd_strip) : 0;
            if (!strstr(raw, "port-ok:")) {
                if (sets_pipefail(s)) pipefail = true;
                scan_line(s, pipefail, cnt);
            }
            nhd = found; hd_at = 0;
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
