/* zcl-lint testiso: tests must run isolated from the machine they run on.
 *
 * Copyright 2026 Rhett Creighton - MIT (zclassicd).
 * Derived from Z23 tools/lint/lintc/gate_no_bare_tmp_fixture.c and gate_live_datadir_isolation*
 * @9a191ef7b1184e14d9116362dff7def64cd300e3 (rule shape); modified, not verbatim. See zcutil/lint/NOTICE.
 *
 * Scope: shell and C/C++ files under qa/, src/test/ and src/gtest/. Three kinds, each its own baseline row
 * "<path>:<kind>":
 *   tmp      a literal /tmp/ path (use mktemp -d, or ${TMPDIR:-/tmp}; lines naming mktemp are fine)
 *   datadir  a default datadir (~/.zclassic, $HOME/.zclassic, %APPDATA%\Zclassic) with no -datadir= on the same command
 *   port     a fixed -port=N or -rpcport=N literal in the shell tests under qa/rpc-tests (ports are leased by qa/lib, not hard-coded)
 * Override a line with `iso-ok: reason` in a comment. Comment-only lines are ignored.
 * The rule only reads qa/; it never edits it.
 */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under a POSIX-only mask */
#endif
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool in_scope(const char *p)
{
    if (lint_is_vendored(p)) return false;
    if (!(lint_has_prefix(p, "qa/") || lint_has_prefix(p, "src/test/") || lint_has_prefix(p, "src/gtest/"))) return false;
    return lint_is_shell_file(p) || lint_is_c_source(p);
}

static bool comment_line(const char *l, bool c_src)
{
    while (*l == ' ' || *l == '\t') l++;
    /* a leading star is a block-comment line only in C sources; in shell it is a case arm */
    return *l == '#' || (l[0] == '/' && (l[1] == '/' || l[1] == '*')) ||
           (c_src && l[0] == '*' && (l[1] == ' ' || l[1] == '/' || l[1] == '\0'));
}

/* ci: case-insensitive */
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

static bool has_default_datadir(const char *l)
{
    return strstr(l, "~/.zclassic") || strstr(l, "$HOME/.zclassic") || strstr(l, "${HOME}/.zclassic") ||
           find_ci(l, "%APPDATA%\\Zclassic") || find_ci(l, "%APPDATA%/Zclassic");
}

/* A fixed -port=N / -rpcport=N: the option directly followed by a digit. */
static bool has_fixed_port(const char *l)
{
    for (const char *p = strstr(l, "port="); p; p = strstr(p + 1, "port=")) {
        bool dash = p > l && p[-1] == '-';
        bool rpcd = p - l >= 4 && !strncmp(p - 4, "-rpc", 4);
        if ((dash || rpcd) && isdigit((unsigned char)p[5])) return true;
    }
    return false;
}

static bool is_rpc_test_sh(const char *p)
{
    return lint_has_prefix(p, "qa/rpc-tests/") && lint_has_suffix(p, ".sh") && !strchr(p + 13, '/');
}

int lint_rule_testiso(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t f = 0; f < lint_nfiles; f++) {
        const char *path = lint_files[f];
        if (!in_scope(path)) continue;
        char *txt = lint_slurp(path, NULL);
        if (!txt) continue;
        scanned++;
        size_t nl = 1;
        for (char *c = txt; *c; c++) if (*c == '\n') nl++;
        char **ln = calloc(nl, sizeof *ln);
        if (!ln) { fprintf(stderr, "zcl-lint: testiso: out of memory\n"); exit(2); }
        size_t n = 0;
        for (char *s = txt;; ) {
            ln[n++] = s;
            char *e = strchr(s, '\n');
            if (!e) break;
            *e = '\0';
            s = e + 1;
        }
        long tmp = 0, dd = 0, port = 0;
        bool rpc = is_rpc_test_sh(path), csrc = lint_is_c_source(path);
        for (size_t i = 0; i < n; i++) {
            const char *l = ln[i];
            if (comment_line(l, csrc) || strstr(l, "iso-ok:")) continue;
            if (strstr(l, "/tmp/") && !strstr(l, "mktemp")) tmp++;
            if (has_default_datadir(l)) {
                size_t a = i, b = i;
                while (a > 0 && ln[a - 1][0] && ln[a - 1][strlen(ln[a - 1]) - 1] == '\\') a--;
                while (b + 1 < n && ln[b][0] && ln[b][strlen(ln[b]) - 1] == '\\') b++;
                bool set = false;
                for (size_t k = a; k <= b; k++) if (strstr(ln[k], "-datadir=")) set = true;
                if (!set) dd++;
            }
            if (rpc && has_fixed_port(l)) port++;
        }
        char key[1024];
        if (tmp) { snprintf(key, sizeof key, "%s:tmp", path); lint_rows_add(&cur, key, tmp); }
        if (dd) { snprintf(key, sizeof key, "%s:datadir", path); lint_rows_add(&cur, key, dd); }
        if (port) { snprintf(key, sizeof key, "%s:port", path); lint_rows_add(&cur, key, port); }
        free(ln);
        free(txt);
    }
    return lint_ratchet("testiso", "test isolation breaks (tmp, datadir, port) per path and kind", &cur, scanned, update);
}
