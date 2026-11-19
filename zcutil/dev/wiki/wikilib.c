/* Shared helpers of zcl-dev-wiki, -read, -lessons and -know. MIT, like the rest of zclassicd. */
#include "wikilib.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

int g_json;
const char *g_argv0 = "";

void die(const char *fmt, ...)
{
    va_list ap;
    fputs("zcl-dev: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) die("out of memory");
    return q;
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(xrealloc(NULL, n), s, n);
}

void list_push(List *l, const char *s)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 16;
        l->v = xrealloc(l->v, l->cap * sizeof *l->v);
    }
    l->v[l->n++] = xstrdup(s);
}

int list_has(const List *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp(l->v[i], s)) return 1;
    return 0;
}

void list_free(List *l)
{
    for (size_t i = 0; i < l->n; i++) free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

void buf_addn(Buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->p = xrealloc(b->p, b->cap);
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}

void buf_add(Buf *b, const char *s) { buf_addn(b, s, strlen(s)); }

void buf_printf(Buf *b, const char *fmt, ...)
{
    char tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) die("format error");
    if ((size_t)n >= sizeof tmp) n = (int)sizeof tmp - 1; /* callers keep fields short */
    buf_addn(b, tmp, (size_t)n);
}

void buf_free(Buf *b)
{
    free(b->p);
    b->p = NULL;
    b->n = b->cap = 0;
}

/* Length of the valid UTF-8 sequence at s (1 to 4), or 0 when it is malformed. */
static size_t utf8_len(const unsigned char *s)
{
    if (s[0] < 0x80) return 1;
    if (s[0] >= 0xc2 && s[0] <= 0xdf) return (s[1] & 0xc0) == 0x80 ? 2 : 0;
    if (s[0] >= 0xe0 && s[0] <= 0xef) {
        if ((s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80) return 0;
        if (s[0] == 0xe0 && s[1] < 0xa0) return 0;
        if (s[0] == 0xed && s[1] >= 0xa0) return 0;
        return 3;
    }
    if (s[0] >= 0xf0 && s[0] <= 0xf4) {
        if ((s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80 || (s[3] & 0xc0) != 0x80) return 0;
        if (s[0] == 0xf0 && s[1] < 0x90) return 0;
        if (s[0] == 0xf4 && s[1] >= 0x90) return 0;
        return 4;
    }
    return 0;
}

void buf_json(Buf *b, const char *s)
{
    buf_add(b, "\"");
    for (const unsigned char *p = (const unsigned char *)s; *p;) {
        if (*p == '"' || *p == '\\') { char e[2] = {'\\', (char)*p}; buf_addn(b, e, 2); p++; }
        else if (*p == '\n') { buf_add(b, "\\n"); p++; }
        else if (*p == '\r') { buf_add(b, "\\r"); p++; }
        else if (*p == '\t') { buf_add(b, "\\t"); p++; }
        else if (*p < 0x20 || *p == 0x7f) { buf_printf(b, "\\u%04x", *p); p++; }
        else if (*p < 0x80) { buf_addn(b, (const char *)p, 1); p++; }
        else {
            size_t n = utf8_len(p);
            if (n) { buf_addn(b, (const char *)p, n); p += n; }
            else { buf_add(b, "?"); p++; }
        }
    }
    buf_add(b, "\"");
}

int has_prefix(const char *s, const char *p) { return !strncmp(s, p, strlen(p)); }

int has_suffix(const char *s, const char *x)
{
    size_t a = strlen(s), b = strlen(x);
    return a >= b && !strcmp(s + a - b, x);
}

int contains_ci(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    if (!n) return 1;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] && tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == n) return 1;
    }
    return 0;
}

char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = 0;
    return s;
}

void clip_text(char *s, size_t max)
{
    size_t n = strlen(s);
    if (n <= max || max < 4) return;
    size_t k = max - 3;
    while (k && ((unsigned char)s[k] & 0xc0) == 0x80) k--; /* do not split a sequence */
    memcpy(s + k, "...", 4);
}

int fail_reply(const char *code, const char *message, const char *evidence)
{
    if (g_json) {
        Buf b = {0};
        buf_add(&b, "{\"ok\":false,\"code\":");
        buf_json(&b, code);
        buf_add(&b, ",\"message\":");
        buf_json(&b, message);
        buf_add(&b, ",\"evidence\":");
        buf_json(&b, evidence ? evidence : "");
        buf_add(&b, "}\n");
        fwrite(b.p, 1, b.n, stdout);
        buf_free(&b);
    }
    if (evidence && *evidence) fprintf(stderr, "%s: %s (%s)\n", code, message, evidence);
    else fprintf(stderr, "%s: %s\n", code, message);
    return 2;
}

static void read_lines(FILE *f, List *out)
{
    char line[8192];
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        list_push(out, line);
    }
}

void git_files(List *out)
{
    FILE *p = popen("git -c core.quotepath=off ls-files", "r");
    if (!p) die("cannot run git ls-files");
    read_lines(p, out);
    if (pclose(p) != 0 || !out->n) die("git ls-files found no tracked files (run inside a git checkout)");
}

char *read_file(const char *path, size_t max, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = xrealloc(NULL, max + 1);
    size_t n = fread(buf, 1, max, f);
    fclose(f);
    buf[n] = 0;
    if (len) *len = n;
    return buf;
}

int file_lines(const char *path, List *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    read_lines(f, out);
    fclose(f);
    return 0;
}

int real_path(const char *p, char *out, size_t cap)
{
    char tmp[PATH_CAP];
#ifdef _WIN32
    if (!_fullpath(tmp, p, sizeof tmp) || strlen(tmp) >= cap) return 1;
    for (char *r = tmp; *r; r++) if (*r == '\\') *r = '/';
#else
    if (!realpath(p, tmp) || strlen(tmp) >= cap) return 1;
#endif
    snprintf(out, cap, "%s", tmp);
    return 0;
}

void link_render(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < cap;) {
        int image = (*p == '!' && p[1] == '[');
        if (*p == '[' || image) {
            const char *t = p + (image ? 2 : 1);
            const char *e = strchr(t, ']');
            if (e && (e[1] == '(' || e[1] == '[')) {
                char close = e[1] == '(' ? ')' : ']';
                const char *u = e + 2;
                int depth = 1;
                while (*u && depth) {
                    if (*u == '(' && close == ')') depth++;
                    else if (*u == close) depth--;
                    if (depth) u++;
                }
                if (*u == close) {
                    for (const char *q = t; q < e && o + 1 < cap; q++) out[o++] = *q;
                    p = u + 1;
                    continue;
                }
            }
        }
        if (*p == '<' && (has_prefix(p + 1, "http://") || has_prefix(p + 1, "https://"))) {
            const char *e = strchr(p, '>');
            if (e) {
                for (const char *q = p + 1; q < e && o + 1 < cap; q++) out[o++] = *q;
                p = e + 1;
                continue;
            }
        }
        out[o++] = *p++;
    }
    out[o] = 0;
}

/* Copy the line at p into line (truncated to cap) and return the start of the next line. */
static const char *next_line(const char *p, char *line, size_t cap)
{
    size_t n = strcspn(p, "\n");
    size_t k = n < cap - 1 ? n : cap - 1;
    memcpy(line, p, k);
    line[k] = 0;
    while (k && line[k - 1] == '\r') line[--k] = 0;
    return p[n] ? p + n + 1 : p + n;
}

/* Is the line after p a setext underline (only '=' or only '-')? */
static int setext_follows(const char *p)
{
    char nx[256];
    next_line(p, nx, sizeof nx);
    char *t = trim(nx);
    size_t n = strlen(t);
    return n >= 3 && (strspn(t, "=") == n || strspn(t, "-") == n);
}

void md_summary(const char *text, char *out, size_t cap)
{
    char line[1024], para[2048];
    int fence = 0, comment = 0;
    size_t pn = 0;
    para[0] = 0;
    for (const char *p = text; *p;) {
        p = next_line(p, line, sizeof line);
        char *t = trim(line);
        if (!fence && *t && setext_follows(p)) { /* a setext heading: skip it and its underline */
            if (pn) break;
            char skip[256];
            p = next_line(p, skip, sizeof skip);
            continue;
        }
        if (has_prefix(t, "```") || has_prefix(t, "~~~")) { fence = !fence; if (pn) break; continue; }
        if (fence) continue;
        if (comment) { if (strstr(t, "-->")) comment = 0; continue; }
        if (has_prefix(t, "<!--")) { if (!strstr(t, "-->")) comment = 1; continue; }
        if (!*t) { if (pn) break; continue; }
        if (*t == '#') { if (pn) break; continue; }
        if (!pn && (*t == '|' || has_prefix(t, "---") || has_prefix(t, "===") || has_prefix(t, "![") ||
                    has_prefix(t, "[!["))) continue;
        if (pn && pn + 2 < sizeof para) para[pn++] = ' ';
        for (const char *q = t; *q && pn + 1 < sizeof para; q++) para[pn++] = *q;
        para[pn] = 0;
    }
    link_render(para, out, cap);
    clip_text(out, TEXT_MAX);
}

void md_title(const char *text, char *out, size_t cap)
{
    char line[1024];
    int fence = 0;
    out[0] = 0;
    for (const char *p = text; *p;) {
        p = next_line(p, line, sizeof line);
        char *t = trim(line);
        if (has_prefix(t, "```") || has_prefix(t, "~~~")) { fence = !fence; continue; }
        if (!fence && has_prefix(t, "# ")) {
            link_render(trim(t + 2), out, cap);
            clip_text(out, TEXT_MAX);
            return;
        }
        if (!fence && *t && setext_follows(p)) { /* "Title" over "=====" */
            char nx[256];
            next_line(p, nx, sizeof nx);
            if (*trim(nx) == '=') {
                link_render(t, out, cap);
                clip_text(out, TEXT_MAX);
                return;
            }
        }
    }
}

/* Built-in subcommands of zcl-dev itself (zcutil/dev/zcl-dev.c); keep in step with its table. */
static const char *const builtin_subs[] = {"guide", "select", "check-rules", "check-docs", "receipt", "help", NULL};

static int exe_dir_of(char *out, size_t cap)
{
    char buf[1024];
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, buf, sizeof buf);
    if (n == 0 || n >= sizeof buf) return 0;
#else
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) { /* no /proc (macOS): zcl-dev runs us by an absolute path */
        if (!strchr(g_argv0, '/') || strlen(g_argv0) >= sizeof buf) return 0;
        snprintf(buf, sizeof buf, "%s", g_argv0);
        n = (ssize_t)strlen(buf);
    }
#endif
    buf[n] = 0;
    for (char *r = buf; *r; r++) if (*r == '\\') *r = '/';
    char *slash = strrchr(buf, '/');
    if (!slash || (size_t)(slash - buf) >= cap) return 0;
    *slash = 0;
    snprintf(out, cap, "%s", buf);
    return 1;
}

int sub_resolves(const char *cmd)
{
    char path[PATH_CAP], dir[1024];
    for (int i = 0; builtin_subs[i]; i++)
        if (!strcmp(builtin_subs[i], cmd)) return 1;
    if (!*cmd) return 0;
    for (const char *c = cmd; *c; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-')) return 0;
    const char *sfx[2] = {"", ".exe"};
    for (int s = 0; s < 2; s++) {
        snprintf(path, sizeof path, "zcutil/bin/zcl-dev-%s%s", cmd, sfx[s]);
        FILE *f = fopen(path, "rb");
        if (f) { fclose(f); return 1; }
        if (exe_dir_of(dir, sizeof dir)) {
            snprintf(path, sizeof path, "%s/zcl-dev-%s%s", dir, cmd, sfx[s]);
            f = fopen(path, "rb");
            if (f) { fclose(f); return 1; }
        }
    }
    return 0;
}
