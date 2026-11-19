/* gitfiles: see gitfiles.h. MIT, like the rest of zclassicd. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L /* popen under a strict -std=c2x */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under a POSIX-only mask */
#endif
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include "gitfiles.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#define chdir _chdir
#else
#include <unistd.h>
#endif

void zd_die(const char *fmt, ...)
{
    va_list ap;
    fputs("zcl-dev code: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

void *zd_xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) zd_die("out of memory");
    return q;
}

char *zd_xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(zd_xrealloc(NULL, n), s, n);
}

void zlist_push(ZList *l, const char *s)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->v = zd_xrealloc(l->v, l->cap * sizeof *l->v);
    }
    l->v[l->n++] = zd_xstrdup(s);
}

int zlist_has(const ZList *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp(l->v[i], s)) return 1;
    return 0;
}

void zlist_free(ZList *l)
{
    for (size_t i = 0; i < l->n; i++) free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

int zd_cmd_exit;

int zd_cmd_lines(const char *cmd, ZList *out)
{
    zd_cmd_exit = 0;
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char *line = NULL;
    size_t cap = 0, len = 0;
    int ch;
    for (;;) {
        ch = fgetc(p);
        if (ch == EOF || ch == '\n') {
            if (ch == EOF && len == 0) break;
            if (len && line[len - 1] == '\r') len--;
            if (len + 1 >= cap) line = zd_xrealloc(line, cap = cap ? cap * 2 : 256);
            line[len] = 0;
            zlist_push(out, line);
            len = 0;
            if (ch == EOF) break;
            continue;
        }
        if (len + 2 >= cap) line = zd_xrealloc(line, cap = cap ? cap * 2 : 256);
        line[len++] = (char)ch;
    }
    free(line);
    int st = pclose(p);
#ifdef WIFEXITED
    zd_cmd_exit = st == -1 ? -1 : WIFEXITED(st) ? WEXITSTATUS(st) : -1;
#else
    zd_cmd_exit = st;
#endif
    return st == 0 ? 0 : -1;
}

static int str_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

int zd_git_ls(ZList *out)
{
    if (zd_cmd_lines("git -c core.quotepath=off ls-files", out)) return -1;
    qsort(out->v, out->n, sizeof *out->v, str_cmp);
    return 0;
}

long zd_find(const ZList *l, const char *s)
{
    size_t lo = 0, hi = l->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = strcmp(l->v[mid], s);
        if (!c) return (long)mid;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return -1;
}

char *zd_read_file(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 8192, len = 0;
    char *buf = zd_xrealloc(NULL, cap);
    for (;;) {
        size_t r = fread(buf + len, 1, cap - len - 1, f);
        len += r;
        if (len + 1 < cap) break;
        buf = zd_xrealloc(buf, cap *= 2);
    }
    fclose(f);
    buf[len] = 0;
    if (n) *n = len;
    return buf;
}

void zd_enter_repo(void)
{
    ZList l = {0};
    if (!getenv("ZCL_DEV_PREFIX")) { /* run directly from a subdirectory: remember where we were */
        ZList pf = {0};
        if (!zd_cmd_lines("git rev-parse --show-prefix", &pf) && pf.n && pf.v[0][0]) {
#ifdef _WIN32
            _putenv_s("ZCL_DEV_PREFIX", pf.v[0]);
#else
            setenv("ZCL_DEV_PREFIX", pf.v[0], 1);
#endif
        }
        zlist_free(&pf);
    }
    if (zd_cmd_lines("git rev-parse --show-toplevel", &l) || !l.n) zd_die("not inside a git repository");
    if (chdir(l.v[0])) zd_die("cannot chdir to %s", l.v[0]);
    zlist_free(&l);
}

int zd_has_prefix(const char *s, const char *p) { return !strncmp(s, p, strlen(p)); }

int zd_has_suffix(const char *s, const char *x)
{
    size_t a = strlen(s), b = strlen(x);
    return a >= b && !strcmp(s + a - b, x);
}

void zd_norm_path(const char *in, char *out, size_t cap)
{
    char tmp[1024];
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < sizeof tmp; p++) tmp[o++] = *p == '\\' ?'/' : *p;
    tmp[o] = 0;
    /* split on '/', drop "" and ".", fold ".." */
    char *seg[128];
    size_t ns = 0;
    int lead = tmp[0] == '/';
    for (char *s = strtok(tmp, "/"); s && ns < 128; s = strtok(NULL, "/")) {
        if (!strcmp(s, ".")) continue;
        if (!strcmp(s, "..") && ns && strcmp(seg[ns - 1], "..")) {
            ns--;
            continue;
        }
        seg[ns++] = s;
    }
    o = 0;
    if (lead && o + 1 < cap) out[o++] = '/';
    for (size_t i = 0; i < ns; i++) {
        size_t l = strlen(seg[i]);
        if (o + l + 2 >= cap) break;
        if (i) out[o++] = '/';
        memcpy(out + o, seg[i], l);
        o += l;
    }
    out[o] = 0;
}
