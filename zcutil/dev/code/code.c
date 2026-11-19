/* zcl-dev-code: cheap, bounded, deterministic code navigation for the zclassicd tree.
 * MIT, like the rest of zclassicd. Plain C, libc only; gnu17 and C23 clean; gcc, clang, mingw-w64.
 * The behaviour follows Z23's `code map|owner|impact|file|sym|refs|cost|recent`
 * (Z23 engine/composition/commands/code.def, derived, not copied).
 *
 *   zcl-dev code map
 *   zcl-dev code owner <path>
 *   zcl-dev code impact <path> [--tests] [--depth=N]
 *   zcl-dev code cost <path>
 *   zcl-dev code file <path>
 *   zcl-dev code sym <name>
 *   zcl-dev code refs <name>
 *   zcl-dev code body <path> <func>
 *   zcl-dev code recent [--since=7d]
 * Every command takes --json and --after=N (paging); output stays under 16 KiB per page.
 * Exit codes: 0 ok, 1 nothing found, 2 broken usage or a hollow scan.
 * No index: everything is computed from `git ls-files` on the fly (well under a second).
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif
#include <stdint.h>

#include "../lib/automake.h"
#include "../lib/cxxscan.h"
#include "../lib/gitfiles.h"
#include "../lib/incgraph.h"
#include "platform/modules/platform/include/platform/glob_match.h"

#define ROOTS_FILE "zcutil/dev/code/source_roots.def"
#define RULES_FILE "zcutil/dev/impact.rules"
#define PAGE_BYTES 15000
#define ROW_MAX 2000 /* a row is cut here; JSON escaping at most sextuples it */

/* ---- output with paging ------------------------------------------------------------------- */

typedef struct { char *k, *v; int isint; } Kv;

typedef struct {
    const char *cmd;
    Kv *kv;
    size_t nkv, capkv;
    char **rows; /* fields joined by '\t' */
    size_t nrows, caprows;
    const char *cols; /* "kind,name,n:i" */
    int raw;          /* text mode prints field 0 of each row as is */
} Out;

static struct { int json; size_t after; } opt;
static int keep_tabs; /* body rows keep source tabs */

static char *dupclean(const char *s)
{
    char *d = zd_xstrdup(s);
    for (char *p = d; *p; p++)
        if (*p == '\t' || *p == '\n' || *p == '\r') *p = ' ';
    return d;
}

static void out_kv(Out *o, const char *k, const char *v, int isint)
{
    if (o->nkv == o->capkv) {
        o->capkv = o->capkv ? o->capkv * 2 : 8;
        o->kv = zd_xrealloc(o->kv, o->capkv * sizeof *o->kv);
    }
    o->kv[o->nkv].k = zd_xstrdup(k);
    o->kv[o->nkv].v = dupclean(v);
    o->kv[o->nkv].isint = isint;
    o->nkv++;
}

static void out_kvn(Out *o, const char *k, long v)
{
    char b[32];
    snprintf(b, sizeof b, "%ld", v);
    out_kv(o, k, b, 1);
}

/* Drops an incomplete UTF-8 sequence at the end of s (a cut must not leave invalid JSON). */
static void utf8_trim(char *s)
{
    size_t n = strlen(s), i = n;
    while (i > 0 && ((unsigned char)s[i - 1] & 0xC0) == 0x80) i--; /* continuation bytes */
    if (i == 0) return;
    unsigned char lead = (unsigned char)s[i - 1];
    size_t need = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
    if (lead >= 0x80 && n - (i - 1) < need) s[i - 1] = 0;
}

/* One row; the fields are NULL terminated const char * (tabs and newlines become spaces). */
static void out_row(Out *o, ...)
{
    va_list ap;
    size_t len = 0, cap = 128, nf = 0;
    char *row = zd_xrealloc(NULL, cap);
    va_start(ap, o);
    for (const char *f; (f = va_arg(ap, const char *));) {
        size_t fl = strlen(f);
        if (len + fl + 2 >= cap) row = zd_xrealloc(row, cap = (len + fl) * 2 + 2);
        if (nf++) row[len++] = '\t';
        for (size_t i = 0; i < fl; i++) {
            char ch = f[i];
            if ((ch == '\t' && !keep_tabs) || ch == '\n' || ch == '\r') ch = ' ';
            row[len++] = ch;
        }
    }
    va_end(ap);
    row[len] = 0;
    if (len > ROW_MAX) { /* bound every row so a page stays under PAGE_BYTES */
        row[ROW_MAX - 3] = 0;
        utf8_trim(row);
        memcpy(row + strlen(row), "...", 4);
    }
    if (o->nrows == o->caprows) {
        o->caprows = o->caprows ? o->caprows * 2 : 64;
        o->rows = zd_xrealloc(o->rows, o->caprows * sizeof *o->rows);
    }
    o->rows[o->nrows++] = row;
}

static void jstr(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c == '\n') fputs("\\n", f);
        else if (c == '\t') fputs("\\t", f);
        else if (c == '\r') fputs("\\r", f);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

/* Column names and types of o->cols. */
static size_t cols_parse(const char *cols, char names[8][32], int isint[8])
{
    size_t n = 0;
    const char *p = cols;
    while (p && *p && n < 8) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        isint[n] = 0;
        if (l > 2 && p[l - 2] == ':' && p[l - 1] == 'i') {
            isint[n] = 1;
            l -= 2;
        }
        if (l >= 32) l = 31;
        memcpy(names[n], p, l);
        names[n][l] = 0;
        n++;
        p = e ? e + 1 : NULL;
    }
    return n;
}

/* Renders one row as a string of the active format (text: fields joined by two spaces). */
static char *row_render(const Out *o, const char *row)
{
    char names[8][32];
    int isint[8];
    size_t nc = cols_parse(o->cols, names, isint);
    size_t cap = strlen(row) * 6 + 64 + nc * 40;
    char *b = zd_xrealloc(NULL, cap);
    size_t len = 0;
    if (!opt.json) {
        if (o->raw) { /* one field, tabs kept */
            memcpy(b, row, strlen(row) + 1);
            return b;
        }
        for (const char *p = row; *p; p++) {
            if (*p == '\t') {
                b[len++] = ' ';
                b[len++] = ' ';
            } else {
                b[len++] = *p;
            }
        }
        while (len && b[len - 1] == ' ') len--; /* an empty last column */
        b[len] = 0;
        return b;
    }
    b[len++] = '{';
    const char *p = row;
    for (size_t c = 0; c < nc; c++) {
        const char *e = c + 1 < nc ? strchr(p, '\t') : NULL; /* the last column takes the rest */
        size_t l = e ? (size_t)(e - p) : strlen(p);
        len += (size_t)snprintf(b + len, cap - len, "%s\"%s\":", c ? "," : "", names[c]);
        if (isint[c] && l == 0) {
            len += (size_t)snprintf(b + len, cap - len, "null");
        } else if (isint[c]) {
            len += (size_t)snprintf(b + len, cap - len, "%ld", strtol(p, NULL, 10));
        } else {
            b[len++] = '"';
            for (size_t q = 0; q < l; q++) {
                unsigned char ch = (unsigned char)p[q];
                if (ch == '"' || ch == '\\') {
                    b[len++] = '\\';
                    b[len++] = (char)ch;
                } else if (ch < 0x20) {
                    len += (size_t)snprintf(b + len, cap - len, "\\u%04x", ch);
                } else {
                    b[len++] = (char)ch;
                }
            }
            b[len++] = '"';
        }
        p = e ? e + 1 : p + l;
    }
    b[len++] = '}';
    b[len] = 0;
    return b;
}

static int out_emit(Out *o)
{
    size_t total = o->nrows;
    size_t first = opt.after < total ? opt.after : total;
    size_t used = 0, next = first;
    for (size_t i = 0; i < o->nkv; i++) used += strlen(o->kv[i].k) + 6 * strlen(o->kv[i].v) + 8;
    char **lines = zd_xrealloc(NULL, (total + 1) * sizeof *lines);
    size_t nl = 0;
    while (next < total) {
        char *r = row_render(o, o->rows[next]);
        size_t rl = strlen(r) + 2;
        if (used + rl > PAGE_BYTES && nl > 0) {
            free(r);
            break;
        }
        used += rl;
        lines[nl++] = r;
        next++;
    }
    int more = next < total;
    if (opt.json) {
        printf("{\"cmd\":");
        jstr(stdout, o->cmd);
        for (size_t i = 0; i < o->nkv; i++) {
            putchar(',');
            jstr(stdout, o->kv[i].k);
            putchar(':');
            if (o->kv[i].isint) fputs(o->kv[i].v, stdout);
            else jstr(stdout, o->kv[i].v);
        }
        printf(",\"total\":%zu,\"after\":%zu,\"next\":", total, first);
        if (more) printf("%zu", next);
        else fputs("null", stdout);
        fputs(",\"rows\":[", stdout);
        for (size_t i = 0; i < nl; i++) printf("%s%s", i ? "," : "", lines[i]);
        fputs("]}\n", stdout);
    } else {
        for (size_t i = 0; i < o->nkv; i++) printf("%s: %s\n", o->kv[i].k, o->kv[i].v);
        for (size_t i = 0; i < nl; i++) printf("%s\n", lines[i]);
        if (more) printf("-- %zu of %zu rows shown; next page: --after=%zu\n", next - first, total, next);
    }
    for (size_t i = 0; i < nl; i++) free(lines[i]);
    free(lines);
    return 0;
}

static void out_free(Out *o)
{
    for (size_t i = 0; i < o->nkv; i++) {
        free(o->kv[i].k);
        free(o->kv[i].v);
    }
    free(o->kv);
    for (size_t i = 0; i < o->nrows; i++) free(o->rows[i]);
    free(o->rows);
}

/* ---- the source universe ------------------------------------------------------------------ */

typedef struct { char *name, *prefix; } Group;

typedef struct {
    Group *g;
    size_t ng;
    ZList vendored, incdirs, automakes;
} Roots;

static Roots roots;
static ZList files; /* every tracked file, sorted */

static void roots_load(void)
{
    ZList lines = {0};
    size_t n = 0;
    char *src = zd_read_file(ROOTS_FILE, &n);
    if (!src) zd_die("cannot read %s (run from the zclassicd tree)", ROOTS_FILE);
    char *save = src;
    for (char *l = strtok(save, "\n"); l; l = strtok(NULL, "\n")) zlist_push(&lines, l);
    free(src);
    for (size_t i = 0; i < lines.n; i++) {
        char *l = lines.v[i];
        size_t ll = strlen(l);
        while (ll && (l[ll - 1] == '\r' || l[ll - 1] == ' ')) l[--ll] = 0;
        if (!*l || *l == '#') continue;
        char *f[3] = {0};
        int nf = 0;
        for (char *p = l; nf < 3;) {
            f[nf++] = p;
            char *t = strchr(p, '\t');
            if (!t) break;
            *t = 0;
            p = t + 1;
        }
        if (!strcmp(f[0], "group") && nf == 3) {
            roots.g = zd_xrealloc(roots.g, (roots.ng + 1) * sizeof *roots.g);
            roots.g[roots.ng].name = zd_xstrdup(f[1]);
            roots.g[roots.ng++].prefix = zd_xstrdup(f[2]);
        } else if (!strcmp(f[0], "vendored") && nf == 2) {
            zlist_push(&roots.vendored, f[1]);
        } else if (!strcmp(f[0], "include") && nf == 2) {
            zlist_push(&roots.incdirs, f[1]);
        } else if (!strcmp(f[0], "automake") && nf == 2) {
            zlist_push(&roots.automakes, f[1]);
        } else {
            zd_die("%s: bad row: %s", ROOTS_FILE, l);
        }
    }
    zlist_free(&lines);
}

static int is_vendored(const char *path)
{
    for (size_t i = 0; i < roots.vendored.n; i++)
        if (zd_has_prefix(path, roots.vendored.v[i])) return 1;
    return 0;
}

static int skip_cb(const char *path, void *ctx)
{
    (void)ctx;
    return is_vendored(path);
}

static const char *lang_of(const char *p)
{
    if (zd_has_suffix(p, ".c")) return "c";
    if (zd_has_suffix(p, ".cc") || zd_has_suffix(p, ".cpp") || zd_has_suffix(p, ".cxx")) return "cpp";
    if (zd_has_suffix(p, ".h") || zd_has_suffix(p, ".hpp") || zd_has_suffix(p, ".hh")) return "h";
    if (zd_has_suffix(p, ".sh")) return "sh";
    return NULL;
}

static const char *group_of(const char *p)
{
    for (size_t i = 0; i < roots.ng; i++)
        if (zd_has_prefix(p, roots.g[i].prefix)) return roots.g[i].name;
    return "other";
}

static void universe_load(void)
{
    roots_load();
    if (zd_git_ls(&files) || files.n == 0) zd_die("git ls-files found nothing: hollow scan");
}

static char *norm_arg(const char *arg)
{
    char buf[1100];
    const char *pre = getenv("ZCL_DEV_PREFIX");
    zd_norm_path(arg, buf, sizeof buf);
    if (pre && *pre && zd_find(&files, buf) < 0) {
        char both[1200];
        char full[1100];
        snprintf(both, sizeof both, "%s%s", pre, arg);
        zd_norm_path(both, full, sizeof full);
        if (zd_find(&files, full) >= 0) return zd_xstrdup(full);
    }
    return zd_xstrdup(buf);
}

static long tracked_index(const char *path)
{
    long i = zd_find(&files, path);
    if (i < 0) fprintf(stderr, "zcl-dev code: %s is not a tracked file\n", path);
    return i;
}

static long count_lines(const char *s, size_t n)
{
    long l = 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] == '\n') l++;
    if (n && s[n - 1] != '\n') l++;
    return l;
}

/* ---- map ---------------------------------------------------------------------------------- */

static int cmd_map(Out *o)
{
    typedef struct { char name[64]; long files, loc, c, cpp, h, sh; } G;
    size_t cap = roots.ng + 2, ng = 0;
    G *gs = zd_xrealloc(NULL, cap * sizeof *gs);
    memset(gs, 0, cap * sizeof *gs);
    long nv = (long)roots.vendored.n;
    long *vf = zd_xrealloc(NULL, (size_t)(nv + 1) * sizeof *vf);
    for (long i = 0; i < nv; i++) vf[i] = 0;
    long total_files = 0, total_loc = 0;
    for (size_t i = 0; i < files.n; i++) {
        const char *p = files.v[i];
        int vend = -1;
        for (long k = 0; k < nv; k++)
            if (zd_has_prefix(p, roots.vendored.v[k])) {
                vend = (int)k;
                break;
            }
        if (vend >= 0) {
            vf[vend]++;
            continue;
        }
        const char *lang = lang_of(p);
        if (!lang) continue;
        const char *gn = group_of(p);
        G *g = NULL;
        for (size_t k = 0; k < ng; k++)
            if (!strcmp(gs[k].name, gn)) g = &gs[k];
        if (!g) {
            if (ng == cap) gs = zd_xrealloc(gs, (cap *= 2) * sizeof *gs);
            g = &gs[ng++];
            memset(g, 0, sizeof *g);
            snprintf(g->name, sizeof g->name, "%s", gn);
        }
        size_t n = 0;
        char *src = zd_read_file(p, &n);
        long loc = src ? count_lines(src, n) : 0;
        free(src);
        g->files++;
        g->loc += loc;
        if (!strcmp(lang, "c")) g->c++;
        else if (!strcmp(lang, "cpp")) g->cpp++;
        else if (!strcmp(lang, "h")) g->h++;
        else g->sh++;
        total_files++;
        total_loc += loc;
    }
    if (total_files == 0) {
        fputs("zcl-dev code: map found no source files: hollow scan\n", stderr);
        return 2;
    }
    out_kvn(o, "files", total_files);
    out_kvn(o, "loc", total_loc);
    o->cols = "kind,name,files:i,loc:i,c:i,cpp:i,h:i,sh:i";
    for (size_t k = 0; k < ng; k++) {
        char a[24], b[24], c[24], d[24], e[24], f[24];
        snprintf(a, sizeof a, "%ld", gs[k].files);
        snprintf(b, sizeof b, "%ld", gs[k].loc);
        snprintf(c, sizeof c, "%ld", gs[k].c);
        snprintf(d, sizeof d, "%ld", gs[k].cpp);
        snprintf(e, sizeof e, "%ld", gs[k].h);
        snprintf(f, sizeof f, "%ld", gs[k].sh);
        out_row(o, "group", gs[k].name, a, b, c, d, e, f, NULL);
    }
    for (long k = 0; k < nv; k++) {
        char a[24];
        snprintf(a, sizeof a, "%ld", vf[k]);
        out_row(o, "vendored", roots.vendored.v[k], a, "0", "0", "0", "0", "0", NULL);
    }
    free(gs);
    free(vf);
    return 0;
}

/* ---- owner -------------------------------------------------------------------------------- */

static void load_automake(Automake *am)
{
    if (am_load(am, &roots.automakes)) zd_die("no autotools makefile readable (%s ...)", roots.automakes.n ? roots.automakes.v[0] : "none");
}

static int has_tu_target(const Automake *am, const char *path, ZList *targets)
{
    if (!ig_is_tu(path)) return 0;
    am_targets_for(am, path, targets);
    return (int)targets->n;
}

static char *nearest_agents(const char *path)
{
    char dir[1100];
    snprintf(dir, sizeof dir, "%s", path);
    for (;;) {
        char *s = strrchr(dir, '/');
        char cand[1200];
        if (s) {
            *s = 0;
            snprintf(cand, sizeof cand, "%s/AGENTS.md", dir);
        } else {
            snprintf(cand, sizeof cand, "AGENTS.md");
        }
        if (zd_find(&files, cand) >= 0) return zd_xstrdup(cand);
        if (!s) return NULL;
    }
}

static char *tests_line(const char *agents)
{
    size_t n = 0;
    char *src = agents ? zd_read_file(agents, &n) : NULL;
    if (!src) return NULL;
    char *res = NULL;
    for (char *l = strtok(src, "\n"); l && !res; l = strtok(NULL, "\n")) {
        const char *p = l;
        while (*p && !isalpha((unsigned char)*p)) p++;
        if (!strncasecmp(p, "tests:", 6) || !strncasecmp(p, "test:", 5)) {
            const char *t = l;
            while (*t == 0x2d || *t == 0x2a || *t == 0x20) t++;
            res = zd_xstrdup(t);
            size_t rl = strlen(res);
            while (rl && (res[rl - 1] == 0x0d || res[rl - 1] == 0x20)) res[--rl] = 0;
        }
    }
    free(src);
    return res;
}

#ifdef _WIN32
#define EXE_SUFFIX ".exe"
#else
#define EXE_SUFFIX ""
#endif

/* Appends arg to cmd as one shell word. POSIX: single quotes, with ' written as '\''. Windows
 * (cmd.exe): double quotes; the characters cmd still interprets inside them are refused.
 * Returns 0, or -1 when arg is unusable or cmd is full. */
static int cmd_append_arg(char *cmd, size_t cap, const char *arg)
{
#ifdef _WIN32
    const char q = '"';
#else
    const char q = '\'';
#endif
    size_t len = strlen(cmd);
    if (len + 3 >= cap) return -1;
    cmd[len++] = ' ';
    cmd[len++] = q;
    for (const char *p = arg; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) return -1;
#ifdef _WIN32
        if (strchr("\"%^&|<>!", c)) return -1;
        if (len + 3 >= cap) return -1;
        cmd[len++] = (char)c;
#else
        if (c == '\'') {
            if (len + 6 >= cap) return -1;
            memcpy(cmd + len, "'\''", 4);
            len += 4;
        } else {
            if (len + 3 >= cap) return -1;
            cmd[len++] = (char)c;
        }
#endif
    }
    cmd[len++] = q;
    cmd[len] = 0;
    return 0;
}

/* The directory of the running executable, or "" when it cannot be found. */
static void exe_dir(char *out, size_t cap, const char *argv0)
{
    char buf[1024];
    out[0] = 0;
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, buf, sizeof buf);
    if (n == 0 || n >= sizeof buf) return;
    (void)argv0;
#else
    ssize_t n = -1;
#ifdef __APPLE__
    uint32_t sz = sizeof buf;
    if (_NSGetExecutablePath(buf, &sz) == 0) n = (ssize_t)strlen(buf);
#else
    n = readlink("/proc/self/exe", buf, sizeof buf - 1);
#endif
    if (n <= 0 && argv0 && argv0[0] && strlen(argv0) < sizeof buf) {
        if (strchr(argv0, '/')) {
            snprintf(buf, sizeof buf, "%s", argv0);
            n = (ssize_t)strlen(buf);
        } else {
            const char *pe = getenv("PATH");
            while (pe && *pe && n <= 0) { /* bare name: look it up on PATH */
                const char *colon = strchr(pe, ':');
                size_t dl = colon ? (size_t)(colon - pe) : strlen(pe);
                if (dl && dl + strlen(argv0) + 2 < sizeof buf) {
                    snprintf(buf, sizeof buf, "%.*s/%s", (int)dl, pe, argv0);
                    if (access(buf, X_OK) == 0) n = (ssize_t)strlen(buf);
                }
                pe = colon ? colon + 1 : NULL;
            }
        }
    }
    if (n <= 0) return;
#endif
    buf[n] = 0;
    for (char *r = buf; *r; r++)
        if (*r == '\\') *r = '/';
    char *slash = strrchr(buf, '/');
    if (!slash) return;
    *slash = 0;
    snprintf(out, cap, "%s", buf);
}

static const char *self_argv0;

static int cmd_owner(Out *o, const char *arg)
{
    char *path = norm_arg(arg);
    if (tracked_index(path) < 0) return 1;
    char *agents = nearest_agents(path);
    char *tl = tests_line(agents);
    out_kv(o, "path", path, 0);
    out_kv(o, "agents", agents ? agents : "none", 0);
    out_kv(o, "tests", tl ? tl : "none", 0);
    o->cols = "kind,value";
    /* impact.rules rows that match */
    {
        size_t n = 0;
        char *src = zd_read_file(RULES_FILE, &n);
        int rules = 0;
        if (src) {
            for (char *l = strtok(src, "\n"); l; l = strtok(NULL, "\n")) {
                if (*l == '#' || !*l) continue;
                char *tab = strchr(l, '\t');
                if (!tab) continue;
                *tab = 0;
                char *toks = tab + 1;
                while (*toks == '\t' || *toks == ' ') toks++;
                size_t tl2 = strlen(toks);
                while (tl2 && (toks[tl2 - 1] == '\r' || toks[tl2 - 1] == ' ')) toks[--tl2] = 0;
                char *pats = zd_xstrdup(l);
                char *hit = NULL;
                for (char *pt = pats; pt && !hit;) { /* no strtok: the outer loop owns it */
                    char *bar = strchr(pt, '|');
                    if (bar) *bar = 0;
                    if (platform_glob_match(pt, path, false)) hit = pt;
                    pt = bar ? bar + 1 : NULL;
                }
                if (hit) {
                    char row[1500];
                    snprintf(row, sizeof row, "%s -> %s", hit, toks);
                    out_row(o, "rule", row, NULL);
                    rules++;
                }
                free(pats);
            }
            free(src);
        }
        if (!rules) out_row(o, "rule", "none (an unmapped path selects every CI step)", NULL);
    }
    /* autotools targets */
    Automake am;
    load_automake(&am);
    ZList t = {0}, listed = {0}, rel = {0};
    if (ig_is_tu(path)) {
        am_targets_for(&am, path, &t);
        for (size_t i = 0; i < t.n; i++) am_relinks(&am, t.v[i], &rel);
        for (size_t i = 0; i < t.n; i++) out_row(o, "compiled-by", t.v[i], NULL);
        for (size_t i = 0; i < rel.n; i++) out_row(o, "relinks", rel.v[i], NULL);
        if (!t.n) out_row(o, "compiled-by", "none (not listed in any *_SOURCES)", NULL);
    } else {
        am_targets_for(&am, path, &listed);
        for (size_t i = 0; i < listed.n; i++) out_row(o, "listed-in", listed.v[i], NULL);
        if (ig_is_source(path)) {
            IncGraph g;
            ZList inc = roots.incdirs;
            ig_build(&g, &files, &inc, skip_cb, NULL);
            int *ord, *dist;
            long idx = zd_find(&files, path);
            size_t n = ig_reverse_closure(&g, (int)idx, 0, &ord, &dist);
            for (size_t k = 0; k < n; k++) {
                const char *p = files.v[ord[k]];
                if (ig_is_tu(p)) am_targets_for(&am, p, &t);
            }
            for (size_t i = 0; i < t.n; i++) out_row(o, "compiled-via-includes-by", t.v[i], NULL);
            for (size_t i = 0; i < t.n; i++) am_relinks(&am, t.v[i], &rel);
            for (size_t i = 0; i < rel.n; i++) out_row(o, "relinks-via-includes-by", rel.v[i], NULL);
            free(ord);
            free(dist);
            ig_free(&g);
        }
    }
    /* the rest of `zcl-dev guide`: lessons and traps for this path */
    {
        char dir[1024], cmd[4400];
        exe_dir(dir, sizeof dir, self_argv0);
        char ex[1100];
        snprintf(ex, sizeof ex, "%s/zcl-dev%s", dir[0] ? dir : "zcutil/bin", EXE_SUFFIX);
        FILE *ef = fopen(ex, "rb");
        if (ef) fclose(ef);
        /* cmd.exe drops the outer quotes of a line that starts with one, so wrap the whole line */
#ifdef _WIN32
        snprintf(cmd, sizeof cmd, "\"");
#else
        cmd[0] = 0;
#endif
        int built = !cmd_append_arg(cmd, sizeof cmd, ex) && !cmd_append_arg(cmd, sizeof cmd, "guide") &&
                    !cmd_append_arg(cmd, sizeof cmd, path);
#ifdef _WIN32
        if (built && strlen(cmd) + 2 < sizeof cmd) memcpy(cmd + strlen(cmd), "\"", 2);
        else built = 0;
#endif
        ZList g = {0};
        int got = 0;
        int inrules = 0;
        if (ef && built && !zd_cmd_lines(cmd, &g)) {
            for (size_t i = 0; i < g.n; i++) {
                if (!strncmp(g.v[i], "== ", 3)) continue;
                if (!strncmp(g.v[i], "rules (", 7)) { /* the AGENTS.md bullets: owner names the file already */
                    inrules = 1;
                    continue;
                }
                if (inrules) {
                    if (g.v[i][0] == 0x20) continue;
                    inrules = 0;
                }
                if (!g.v[i][0]) continue;
                if (!strncmp(g.v[i], "first commands", 14)) break;
                out_row(o, "guide", g.v[i], NULL);
                got++;
            }
        }
        if (!got) out_row(o, "guide", "unavailable (zcl-dev guide did not run)", NULL);
        zlist_free(&g);
    }
    zlist_free(&t);
    zlist_free(&listed);
    zlist_free(&rel);
    am_free(&am);
    free(agents);
    free(tl);
    free(path);
    return 0;
}

/* ---- impact and cost ---------------------------------------------------------------------- */

typedef struct { int idx; int fanin; } Rank;

/* "target <name> <n>": n is how many TUs of the closure (plus the path itself) the target compiles. */
static void target_row(Out *o, const Automake *am, const char *name, const char *path, const int *ord, size_t n,
                       const ZList *files)
{
    long c = 0;
    char nb[24];
    const AmTarget *t = am_find(am, name);
    for (size_t k = 0; t && k < n; k++)
        if (ig_is_tu(files->v[ord[k]]) && zlist_has(&t->sources, files->v[ord[k]])) c++;
    if (t && ig_is_tu(path) && zlist_has(&t->sources, path)) c++;
    snprintf(nb, sizeof nb, "%ld", c);
    out_row(o, "target", name, nb, NULL);
}

static int rank_cmp(const void *a, const void *b)
{
    const Rank *x = a, *y = b;
    if (x->fanin != y->fanin) return y->fanin - x->fanin;
    return strcmp(files.v[x->idx], files.v[y->idx]);
}

static int idx_cmp(const void *a, const void *b) { return strcmp(files.v[*(const int *)a], files.v[*(const int *)b]); }

static int cmd_impact(Out *o, const char *arg, int with_tests, int depth, int cost_only)
{
    char *path = norm_arg(arg);
    long start = tracked_index(path);
    if (start < 0) return 1;
    IncGraph g;
    ig_build(&g, &files, &roots.incdirs, skip_cb, NULL);
    size_t scanned = 0;
    for (size_t i = 0; i < files.n; i++)
        if (ig_is_source(files.v[i]) && !is_vendored(files.v[i])) scanned++;
    if (scanned == 0) {
        fputs("zcl-dev code: no C/C++ files scanned: hollow scan\n", stderr);
        return 2;
    }
    int *ord, *dist;
    size_t n = ig_reverse_closure(&g, (int)start, depth, &ord, &dist);
    Automake am;
    load_automake(&am);
    /* sort the closure by path for stable output */
    qsort(ord, n, sizeof *ord, idx_cmp);
    ZList targets = {0}, relinks = {0}, tests = {0};
    long tus = 0, headers = 0, direct = 0, built = 0;
    if (ig_is_tu(path)) {
        tus++;
        ZList own = {0};
        if (has_tu_target(&am, path, &own)) {
            built++;
            for (size_t i = 0; i < own.n; i++)
                if (!zlist_has(&targets, own.v[i])) zlist_push(&targets, own.v[i]);
        }
        zlist_free(&own);
    }
    for (size_t k = 0; k < n; k++) {
        const char *p = files.v[ord[k]];
        if (ig_is_tu(p)) {
            tus++;
            ZList own = {0};
            if (has_tu_target(&am, p, &own)) {
                built++;
                for (size_t i = 0; i < own.n; i++) {
                    if (!zlist_has(&targets, own.v[i])) zlist_push(&targets, own.v[i]);
                    const AmTarget *t = am_find(&am, own.v[i]);
                    if (t && t->is_test && !zlist_has(&tests, p)) zlist_push(&tests, p);
                }
            }
            zlist_free(&own);
        } else {
            headers++;
        }
    }
    for (int k = 0; k < g.nrev[start]; k++) direct++;
    for (size_t i = 0; i < targets.n; i++) am_relinks(&am, targets.v[i], &relinks);
    out_kv(o, "path", path, 0);
    if (!cost_only) {
        out_kvn(o, "direct", direct);
        out_kvn(o, "transitive", (long)n);
        out_kvn(o, "tus-in-closure", tus);
        out_kvn(o, "headers", headers);
    } else {
        out_kvn(o, "built-tus", built); /* the closure's TUs that some *_SOURCES lists */
        out_kvn(o, "headers-in-closure", headers);
        out_kvn(o, "relink-targets", (long)relinks.n);
    }
    if (g.unresolved) out_kvn(o, "unresolved-quoted-includes", (long)g.unresolved);
    o->cols = "kind,path,n:i";
    char nb[24];
    if (cost_only) {
        for (size_t i = 0; i < targets.n; i++) target_row(o, &am, targets.v[i], path, ord, n, &files);
        for (size_t i = 0; i < relinks.n; i++) out_row(o, "relink", relinks.v[i], "", NULL);
    } else {
        /* the top 20 by direct fan-in among the includers */
        Rank *rk = zd_xrealloc(NULL, (n + 1) * sizeof *rk);
        for (size_t k = 0; k < n; k++) {
            rk[k].idx = ord[k];
            rk[k].fanin = g.nrev[ord[k]];
        }
        qsort(rk, n, sizeof *rk, rank_cmp);
        for (size_t k = 0; k < n && k < 20 && rk[k].fanin > 0; k++) {
            snprintf(nb, sizeof nb, "%d", rk[k].fanin);
            out_row(o, "top-fan-in", files.v[rk[k].idx], nb, NULL);
        }
        free(rk);
        for (size_t i = 0; i < targets.n; i++) target_row(o, &am, targets.v[i], path, ord, n, &files);
        for (size_t i = 0; i < relinks.n; i++) out_row(o, "relink", relinks.v[i], "", NULL);
        if (with_tests)
            for (size_t i = 0; i < tests.n; i++) out_row(o, "test-tu", tests.v[i], "", NULL);
        /* direct includers, then the rest are not listed row by row: the count is in the header */
        for (int k = 0; k < g.nrev[start]; k++) out_row(o, "direct", files.v[g.rev[start][k]], "", NULL);
    }
    free(ord);
    free(dist);
    zlist_free(&targets);
    zlist_free(&relinks);
    zlist_free(&tests);
    am_free(&am);
    ig_free(&g);
    free(path);
    return 0;
}

/* ---- file, body, sym ---------------------------------------------------------------------- */

static int read_source(const char *path, char **src, size_t *n)
{
    *src = zd_read_file(path, n);
    if (!*src) {
        fprintf(stderr, "zcl-dev code: cannot read %s\n", path);
        return -1;
    }
    return 0;
}

static int cmd_file(Out *o, const char *arg)
{
    char *path = norm_arg(arg);
    if (tracked_index(path) < 0) return 1;
    char *src;
    size_t n;
    if (read_source(path, &src, &n)) return 2;
    CxxIncs incs = {0};
    CxxDefs defs = {0};
    cxx_includes(src, n, &incs);
    cxx_defs(src, n, &defs);
    out_kv(o, "path", path, 0);
    out_kvn(o, "lines", count_lines(src, n));
    out_kvn(o, "includes", (long)incs.n);
    out_kvn(o, "definitions", (long)defs.n);
    o->cols = "kind,name,range";
    char r[64];
    for (size_t i = 0; i < incs.n; i++) {
        snprintf(r, sizeof r, "%d", incs.v[i].line);
        char nm[300];
        snprintf(nm, sizeof nm, incs.v[i].angle ? "<%s>" : "\"%s\"", incs.v[i].name);
        out_row(o, "include", nm, r, NULL);
    }
    for (size_t i = 0; i < defs.n; i++) {
        snprintf(r, sizeof r, "%d-%d", defs.v[i].start_line, defs.v[i].end_line);
        out_row(o, defs.v[i].kind == CXX_CLASS ? "class" : "func", defs.v[i].name, r, NULL);
    }
    cxx_free_incs(&incs);
    cxx_free_defs(&defs);
    free(src);
    free(path);
    return 0;
}

static int cmd_body(Out *o, const char *arg, const char *func)
{
    char *path = norm_arg(arg);
    if (tracked_index(path) < 0) return 1;
    char *src;
    size_t n;
    if (read_source(path, &src, &n)) return 2;
    CxxDefs defs = {0};
    cxx_defs(src, n, &defs);
    size_t *hit = zd_xrealloc(NULL, (defs.n + 1) * sizeof *hit);
    size_t nh = 0;
    for (size_t i = 0; i < defs.n; i++)
        if (defs.v[i].kind == CXX_FUNC && cxx_def_matches(&defs.v[i], func)) hit[nh++] = i;
    if (nh == 0) {
        fprintf(stderr, "zcl-dev code: no function named %s in %s (see: zcl-dev code file %s)\n", func, path, path);
        free(hit);
        cxx_free_defs(&defs);
        free(src);
        free(path);
        return 1;
    }
    /* line table */
    size_t nl = 0, *ls = zd_xrealloc(NULL, ((size_t)count_lines(src, n) + 2) * sizeof *ls);
    ls[nl++] = 0;
    for (size_t i = 0; i < n; i++)
        if (src[i] == '\n' && i + 1 < n) ls[nl++] = i + 1;
    ls[nl] = n;
    o->raw = 1;
    keep_tabs = 1;
    o->cols = "text";
    out_kv(o, "path", path, 0);
    out_kv(o, "function", func, 0);
    out_kvn(o, "matches", (long)nh);
    for (size_t h = 0; h < nh; h++) {
        const CxxDef *d = &defs.v[hit[h]];
        char range[96];
        snprintf(range, sizeof range, "%d-%d", d->start_line, d->end_line);
        if (nh > 1) {
            char sep[512];
            snprintf(sep, sizeof sep, "// ---- %s %s:%s", d->name, path, range);
            out_row(o, sep, NULL);
        } else {
            out_kv(o, "lines", range, 0);
        }
        for (int ln = d->start_line; ln <= d->end_line && (size_t)ln <= nl; ln++) {
            size_t b = ls[ln - 1], e = ls[ln];
            if (e > b && src[e - 1] == '\n') e--;
            if (e > b && src[e - 1] == '\r') e--;
            char *line = zd_xrealloc(NULL, e - b + 1);
            memcpy(line, src + b, e - b);
            line[e - b] = 0;
            out_row(o, line, NULL);
            free(line);
        }
    }
    free(ls);
    free(hit);
    cxx_free_defs(&defs);
    free(src);
    free(path);
    return 0;
}

static int valid_name(const char *s)
{
    if (!*s || strlen(s) > 120) return 0;
    for (; *s; s++)
        if (!(isalnum((unsigned char)*s) || *s == '_' || *s == ':' || *s == '~')) return 0;
    return 1;
}

static int cmd_sym(Out *o, const char *name)
{
    if (!valid_name(name)) {
        fputs("zcl-dev code: sym takes an identifier such as ConnectBlock or CWallet::SetBestChain\n", stderr);
        return 2;
    }
    const char *last = strrchr(name, ':');
    last = last ? last + 1 : name;
    long scanned = 0, found = 0;
    o->cols = "kind,name,path,range";
    for (size_t i = 0; i < files.n; i++) {
        const char *p = files.v[i];
        if (!ig_is_source(p) || is_vendored(p)) continue;
        size_t n = 0;
        char *src = zd_read_file(p, &n);
        if (!src) continue;
        scanned++;
        if (strstr(src, last)) {
            CxxDefs defs = {0};
            cxx_defs(src, n, &defs);
            for (size_t k = 0; k < defs.n; k++)
                if (cxx_def_matches(&defs.v[k], name)) {
                    char r[64];
                    snprintf(r, sizeof r, "%d-%d", defs.v[k].start_line, defs.v[k].end_line);
                    out_row(o, defs.v[k].kind == CXX_CLASS ? "class" : "func", defs.v[k].name, p, r, NULL);
                    found++;
                }
            cxx_free_defs(&defs);
        }
        free(src);
    }
    if (scanned == 0) {
        fputs("zcl-dev code: no C/C++ files scanned: hollow scan\n", stderr);
        return 2;
    }
    out_kv(o, "symbol", name, 0);
    out_kvn(o, "scanned-files", scanned);
    out_kvn(o, "definitions", found);
    return found ? 0 : 1;
}

/* ---- refs --------------------------------------------------------------------------------- */

static int cmd_refs(Out *o, const char *name)
{
    if (!valid_name(name)) {
        fputs("zcl-dev code: refs takes an identifier\n", stderr);
        return 2;
    }
    char cmd[400] = "git grep -nwF -e";
    if (cmd_append_arg(cmd, sizeof cmd, name)) {
        fputs("zcl-dev code: refs: name cannot be passed to git\n", stderr);
        return 2;
    }
    ZList lines = {0};
    if (zd_cmd_lines(cmd, &lines) && zd_cmd_exit != 1) { /* exit 1 means no match */
        fputs("zcl-dev code: refs: git grep failed\n", stderr);
        return 2;
    }
    long total = 0, shown = 0;
    o->cols = "location,text";
    for (size_t i = 0; i < lines.n; i++) {
        char *l = lines.v[i];
        char *c1 = strchr(l, ':');
        if (!c1) continue;
        char *c2 = strchr(c1 + 1, ':');
        if (!c2) continue;
        *c1 = 0;
        if (is_vendored(l)) continue;
        total++;
        if (shown >= 50) continue;
        *c2 = 0;
        char loc[1200];
        snprintf(loc, sizeof loc, "%s:%s", l, c1 + 1);
        char text[200];
        const char *t = c2 + 1;
        while (*t == ' ' || *t == '\t') t++;
        snprintf(text, sizeof text, "%s", t);
        utf8_trim(text);
        out_row(o, loc, text, NULL);
        shown++;
    }
    out_kv(o, "symbol", name, 0);
    out_kvn(o, "matches", total);
    out_kvn(o, "shown", shown);
    zlist_free(&lines);
    return total ? 0 : 1;
}

/* ---- recent ------------------------------------------------------------------------------- */

static int cmd_recent(Out *o, const char *since)
{
    char spec[64];
    size_t l = strlen(since);
    if (l < 2 || l > 6) goto bad;
    for (size_t i = 0; i + 1 < l; i++)
        if (!isdigit((unsigned char)since[i])) goto bad;
    {
        const char *unit = since[l - 1] == 'd' ? "days" : since[l - 1] == 'w' ? "weeks" : since[l - 1] == 'h' ? "hours" : NULL;
        if (!unit) goto bad;
        snprintf(spec, sizeof spec, "%.*s.%s", (int)(l - 1), since, unit);
    }
    char cmd[300];
    snprintf(cmd, sizeof cmd, "git log --since=%.*s.%s.ago --name-only --pretty=format:", (int)(l - 1), since,
             since[l - 1] == 'd' ? "days" : since[l - 1] == 'w' ? "weeks" : "hours");
    ZList lines = {0}, uniq = {0};
    if (zd_cmd_lines(cmd, &lines)) {
        fputs("zcl-dev code: git log failed\n", stderr);
        return 2;
    }
    typedef struct { char *path; int n; } E;
    E *es = NULL;
    size_t ne = 0;
    for (size_t i = 0; i < lines.n; i++) {
        if (!lines.v[i][0] || zd_find(&files, lines.v[i]) < 0) continue;
        size_t k;
        for (k = 0; k < ne; k++)
            if (!strcmp(es[k].path, lines.v[i])) break;
        if (k == ne) {
            es = zd_xrealloc(es, (ne + 1) * sizeof *es);
            es[ne].path = lines.v[i];
            es[ne++].n = 0;
        }
        es[k].n++;
    }
    for (size_t a = 1; a < ne; a++) { /* insertion sort by group then path */
        E t = es[a];
        size_t b = a;
        while (b > 0) {
            int c = strcmp(group_of(es[b - 1].path), group_of(t.path));
            if (c < 0 || (c == 0 && strcmp(es[b - 1].path, t.path) <= 0)) break;
            es[b] = es[b - 1];
            b--;
        }
        es[b] = t;
    }
    out_kv(o, "since", since, 0);
    out_kvn(o, "files", (long)ne);
    o->cols = "area,path,commits:i";
    for (size_t k = 0; k < ne; k++) {
        char nb[24];
        snprintf(nb, sizeof nb, "%d", es[k].n);
        out_row(o, group_of(es[k].path), es[k].path, nb, NULL);
    }
    free(es);
    zlist_free(&lines);
    zlist_free(&uniq);
    (void)spec;
    return ne ? 0 : 1;
bad:
    fputs("zcl-dev code: --since takes N followed by h, d or w (for example 7d)\n", stderr);
    return 2;
}

/* ---- driver ------------------------------------------------------------------------------- */

static void usage(void)
{
    fputs("usage: zcl-dev code <command> [--json] [--after=N]\n"
          "  map                          groups with file, LOC and language counts\n"
          "  owner <path>                 AGENTS.md, rules, autotools targets, traps and lessons\n"
          "  impact <path> [--tests] [--depth=N]   reverse #include closure\n"
          "  cost <path>                  TUs that recompile and targets that relink\n"
          "  file <path>                  includes and definitions with line ranges\n"
          "  sym <name>                   definition sites\n"
          "  refs <name>                  git grep -w, at most 50 hits\n"
          "  body <path> <func>           print one function\n"
          "  recent [--since=7d]          files changed recently, by area\n",
          stderr);
}

int main(int argc, char **argv)
{
    self_argv0 = argv[0];
    if (argc >= 2 && !strcmp(argv[1], "--purpose")) {
        puts("code intelligence: map, owner, impact, cost, file, sym, refs, body, recent");
        return 0;
    }
    const char *pos[4];
    int npos = 0, tests = 0, depth = 0;
    const char *since = "7d";
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--json")) opt.json = 1;
        else if (!strcmp(a, "--tests")) tests = 1;
        else if (!strncmp(a, "--after=", 8) || !strncmp(a, "--depth=", 8)) {
            const char *v = a + 8;
            char *end = NULL;
            errno = 0;
            unsigned long n = strtoul(v, &end, 10);
            if (!isdigit((unsigned char)*v) || *end || errno || n > 1000000000UL) {
                fprintf(stderr, "zcl-dev code: %.7s takes a non-negative integer, got '%s'\n", a, v);
                return 2;
            }
            if (a[2] == 'a') opt.after = (size_t)n;
            else depth = (int)n;
        }
        else if (!strncmp(a, "--since=", 8)) since = a + 8;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage();
            return 2;
        } else if (!strncmp(a, "--", 2)) {
            fprintf(stderr, "zcl-dev code: unknown option %s\n", a);
            return 2;
        } else if (npos < 4) pos[npos++] = a;
    }
    if (npos == 0) {
        usage();
        return 2;
    }
    const char *cmd = pos[0];
    Out o;
    memset(&o, 0, sizeof o);
    o.cmd = cmd;
    zd_enter_repo();
    universe_load();
    int rc;
    if (!strcmp(cmd, "map") && npos == 1) rc = cmd_map(&o);
    else if (!strcmp(cmd, "owner") && npos == 2) rc = cmd_owner(&o, pos[1]);
    else if (!strcmp(cmd, "impact") && npos == 2) rc = cmd_impact(&o, pos[1], tests, depth, 0);
    else if (!strcmp(cmd, "cost") && npos == 2) rc = cmd_impact(&o, pos[1], 0, 0, 1);
    else if (!strcmp(cmd, "file") && npos == 2) rc = cmd_file(&o, pos[1]);
    else if (!strcmp(cmd, "body") && npos == 3) rc = cmd_body(&o, pos[1], pos[2]);
    else if (!strcmp(cmd, "sym") && npos == 2) rc = cmd_sym(&o, pos[1]);
    else if (!strcmp(cmd, "refs") && npos == 2) rc = cmd_refs(&o, pos[1]);
    else if (!strcmp(cmd, "recent") && npos == 1) rc = cmd_recent(&o, since);
    else {
        usage();
        return 2;
    }
    if (rc == 0 || (rc == 1 && o.nkv)) out_emit(&o);
    out_free(&o);
    return rc;
}
