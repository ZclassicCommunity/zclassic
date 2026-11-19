/* zcl-dev-gen: generated references and parity gates for the zclassicd tree. MIT.
 * Plain C, libc only, compiles as gnu17 and as C23. The idea (a generated API
 * reference, a capability inventory, parity gates) comes from Z23's
 * tools/gen_api_reference.c, tools/gen_capability_inventory.c and the
 * route/command parity lint gates; the implementation is new and targets the
 * C++ sources of zclassicd.
 *
 *   zcl-dev gen rpc-reference   [--out=F]   zcutil/gen/RPC_REFERENCE.md
 *   zcl-dev gen args-reference  [--out=F]   zcutil/gen/ARGS_REFERENCE.md
 *   zcl-dev gen inventory       [--out=F] [--no-tools]   zcutil/gen/CAPABILITY_INVENTORY.jsonl
 *   zcl-dev gen --check rpc-parity | flags [--baseline=F] [--update-baseline] [--json] [--after=N]
 *   zcl-dev gen --selftest
 * Exit: 0 ok, 1 finding, 2 broken or hollow scan (nothing to scan is a failure).
 * Run from the repository root (zcl-dev dispatch does that) or pass --root=DIR.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#define popen _popen
#define pclose _pclose
#define chdir _chdir
#define mkdir_one(p) _mkdir(p)
#else
#include <unistd.h>
#define mkdir_one(p) mkdir((p), 0777)
#endif

#define OUT_LIMIT 16384
#define RPC_REF_DEFAULT "zcutil/gen/RPC_REFERENCE.md"
#define ARGS_REF_DEFAULT "zcutil/gen/ARGS_REFERENCE.md"
#define INV_DEFAULT "zcutil/gen/CAPABILITY_INVENTORY.jsonl"
#define BASELINE_DEFAULT "zcutil/dev/gen/flags-undocumented.txt"
#define RPC_BASELINE_DEFAULT "zcutil/dev/gen/rpc-parity-baseline.txt"

/* ---- small utilities ---------------------------------------------------- */
typedef struct { char *p; size_t n, cap; } Buf;

static void die(const char *fmt, ...)
{
    va_list ap;
    fputs("zcl-dev-gen: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}
static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) die("out of memory");
    return q;
}
static char *xstrndup(const char *s, size_t n)
{
    char *d = (char *)xrealloc(NULL, n + 1);
    memcpy(d, s, n);
    d[n] = 0;
    return d;
}
static char *xstrdup(const char *s) { return xstrndup(s, strlen(s)); }

static void buf_addn(Buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->p = (char *)xrealloc(b->p, b->cap);
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}
static void buf_adds(Buf *b, const char *s) { buf_addn(b, s, strlen(s)); }
static void buf_addc(Buf *b, char c) { buf_addn(b, &c, 1); }
static void buf_addf(Buf *b, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    int k;
    va_start(ap, fmt);
    k = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (k < 0) return;
    if ((size_t)k < sizeof tmp) { buf_addn(b, tmp, (size_t)k); return; }
    {
        char *big = (char *)xrealloc(NULL, (size_t)k + 1);
        va_start(ap, fmt);
        vsnprintf(big, (size_t)k + 1, fmt, ap);
        va_end(ap);
        buf_addn(b, big, (size_t)k);
        free(big);
    }
}
static const char *buf_str(const Buf *b) { return b->p ? b->p : ""; }

/* JSON string with escapes. */
static void json_str(Buf *b, const char *s)
{
    buf_addc(b, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { buf_addc(b, '\\'); buf_addc(b, (char)c); }
        else if (c == '\n') buf_adds(b, "\\n");
        else if (c == '\t') buf_adds(b, "\\t");
        else if (c == '\r') buf_adds(b, "\\r");
        else if (c < 0x20) buf_addf(b, "\\u%04x", c);
        else buf_addc(b, (char)c);
    }
    buf_addc(b, '"');
}

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *p;
    long sz;
    size_t got;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    p = (char *)xrealloc(NULL, (size_t)sz + 1);
    got = fread(p, 1, (size_t)sz, f);
    fclose(f);
    p[got] = 0;
    if (len) *len = got;
    return p;
}

static void make_parent_dirs(const char *path)
{
    char *d = xstrdup(path);
    char *s;
    for (s = d + 1; *s; s++) {
        if (*s == '/') {
            *s = 0;
            mkdir_one(d);
            *s = '/';
        }
    }
    free(d);
}

/* Write a generated file; "-" means stdout. */
static void write_out(const char *path, const char *data, size_t n)
{
    FILE *f;
    if (!strcmp(path, "-")) { fwrite(data, 1, n, stdout); return; }
    make_parent_dirs(path);
    f = fopen(path, "wb");
    if (!f) die("cannot write %s: %s", path, strerror(errno));
    if (fwrite(data, 1, n, f) != n || fclose(f) != 0) die("write failed for %s", path);
}

typedef struct { char **v; size_t n, cap; } List;
static void list_add(List *l, char *s)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->v = (char **)xrealloc(l->v, l->cap * sizeof *l->v);
    }
    l->v[l->n++] = s;
}
static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static int ends_with(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && !strcmp(s + a - b, suf);
}
static int starts_with(const char *s, const char *pre) { return !strncmp(s, pre, strlen(pre)); }

/* ---- source files ------------------------------------------------------- */
typedef struct { char *path; char *text; size_t len; } Src;
typedef struct { Src *v; size_t n, cap; } SrcSet;

static int is_dir(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Directories under src/ that are tests or third-party code: not the node's own surface. */
static int skip_src_dir(const char *rel)
{
    static const char *const skip[] = {
        "src/test", "src/gtest", "src/leveldb", "src/secp256k1", "src/univalue", "src/snark",
        "src/zcash/gtest", "src/bench", "src/obj", "src/c23/vendor", "src/c23/services/vendor", "src/c23/test", NULL };
    int i;
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    if (!strcmp(base, "test") || !strcmp(base, "gtest") || !strcmp(base, "tests")) return 1; /* tests read flags to exercise them */
    for (i = 0; skip[i]; i++) if (!strcmp(rel, skip[i])) return 1;
    return 0;
}

/* Sorted recursive walk; accept() picks files, prune (when set) drops directories. */
static void walk(const char *rel, List *out, int (*accept)(const char *), int (*prune)(const char *))
{
    DIR *d = opendir(rel);
    struct dirent *e;
    List names = {0, 0, 0};
    size_t i;
    if (!d) return;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        list_add(&names, xstrdup(e->d_name));
    }
    closedir(d);
    if (names.n) qsort(names.v, names.n, sizeof *names.v, cmp_str);
    for (i = 0; i < names.n; i++) {
        size_t k = strlen(rel) + strlen(names.v[i]) + 2;
        char *full = (char *)xrealloc(NULL, k);
        snprintf(full, k, "%s/%s", rel, names.v[i]);
        if (is_dir(full)) {
            if (!prune || !prune(full)) walk(full, out, accept, prune);
            free(full);
        } else if (accept(full)) {
            list_add(out, full);
        } else {
            free(full);
        }
    }
    for (i = 0; i < names.n; i++) free(names.v[i]);
    free(names.v);
}

static int accept_cpp_h(const char *p) { return ends_with(p, ".cpp") || ends_with(p, ".h"); }

static void srcset_load(SrcSet *s, const List *paths)
{
    size_t i;
    for (i = 0; i < paths->n; i++) {
        size_t len = 0;
        char *t = read_file(paths->v[i], &len);
        if (!t) continue;
        if (s->n == s->cap) {
            s->cap = s->cap ? s->cap * 2 : 128;
            s->v = (Src *)xrealloc(s->v, s->cap * sizeof *s->v);
        }
        s->v[s->n].path = paths->v[i];
        s->v[s->n].text = t;
        s->v[s->n].len = len;
        s->n++;
    }
}

static SrcSet g_src;   /* node sources: .cpp and .h under src, minus tests and third-party code */

static void load_node_sources(void)
{
    List paths = {0, 0, 0};
    if (g_src.n) return;
    walk("src", &paths, accept_cpp_h, skip_src_dir);
    srcset_load(&g_src, &paths);
    if (!g_src.n) die("hollow scan: no .cpp or .h files under src/ (run from the repository root or pass --root=DIR)");
}

static int line_of(const char *text, size_t off)
{
    int line = 1;
    size_t i;
    for (i = 0; i < off; i++) if (text[i] == '\n') line++;
    return line;
}

/* ---- tiny C++ lexer helpers -------------------------------------------- */
static size_t skip_ws(const char *s, size_t n, size_t i)
{
    for (;;) {
        while (i < n && isspace((unsigned char)s[i])) i++;
        if (i + 1 < n && s[i] == '/' && s[i + 1] == '/') {
            while (i < n && s[i] != '\n') i++;
        } else if (i + 1 < n && s[i] == '/' && s[i + 1] == '*') {
            i += 2;
            while (i + 1 < n && !(s[i] == '*' && s[i + 1] == '/')) i++;
            i = i + 2 < n ? i + 2 : n;
        } else {
            return i;
        }
    }
}

/* skip_ws plus preprocessor lines (rows inside #if blocks all count). */
static size_t skip_ws_pp(const char *s, size_t n, size_t i)
{
    for (;;) {
        size_t j = skip_ws(s, n, i);
        if (j < n && s[j] == '#') {
            while (j < n && s[j] != '\n') { if (s[j] == '\\' && j + 1 < n) j++; j++; }
            i = j;
        } else {
            return j;
        }
    }
}

/* s[i] is a quote: index after the closing quote. */
static size_t skip_quoted(const char *s, size_t n, size_t i)
{
    char q = s[i++];
    while (i < n && s[i] != q) { if (s[i] == '\\') i++; i++; }
    return i < n ? i + 1 : n;
}

/* s[i] opens ( [ {: index of the matching close, or n when unbalanced. */
static size_t match_close(const char *s, size_t n, size_t i)
{
    int depth = 0;
    while (i < n) {
        char c = s[i];
        if (c == '"' || c == '\'') { i = skip_quoted(s, n, i); continue; }
        if (c == '/' && i + 1 < n && (s[i + 1] == '/' || s[i + 1] == '*')) { i = skip_ws(s, n, i); continue; }
        if (c == '(' || c == '[' || c == '{') depth++;
        else if (c == ')' || c == ']' || c == '}') { if (--depth == 0) return i; }
        i++;
    }
    return n;
}

static int is_idch(int c) { return isalnum(c) || c == '_'; }

/* Decode one C string literal at s[i]=='"'; appends to out, returns index after it. */
static size_t read_one_literal(const char *s, size_t n, size_t i, Buf *out)
{
    i++;
    while (i < n && s[i] != '"') {
        if (s[i] == '\\' && i + 1 < n) {
            i++;
            switch (s[i]) {
            case 'n': buf_addc(out, '\n'); break;
            case 't': buf_addc(out, '\t'); break;
            case 'r': buf_addc(out, '\r'); break;
            case '0': break;
            case 'x': {
                int v = 0, k = 0;
                while (k < 2 && i + 1 < n && isxdigit((unsigned char)s[i + 1])) {
                    char h = s[++i];
                    v = v * 16 + (isdigit((unsigned char)h) ? h - '0' : (tolower(h) - 'a' + 10));
                    k++;
                }
                if (v) buf_addc(out, (char)v);
                break;
            }
            default: buf_addc(out, s[i]); break;
            }
            i++;
        } else {
            buf_addc(out, s[i++]);
        }
    }
    return i < n ? i + 1 : n;
}

/* Adjacent literals "a" "b" concatenate; returns index after the last one. */
static size_t read_literals(const char *s, size_t n, size_t i, Buf *out)
{
    for (;;) {
        size_t j;
        i = read_one_literal(s, n, i, out);
        j = skip_ws(s, n, i);
        if (j < n && s[j] == '"') i = j; else return i;
    }
}

/* Split the top-level comma list inside (s[open], s[close]); fills start/end offsets. */
static int top_split(const char *s, size_t open, size_t close, size_t *st, size_t *en, int max)
{
    int cnt = 0, depth = 0;
    size_t i = open + 1, from = i;
    for (; i < close; i++) {
        char c = s[i];
        if (c == '"' || c == '\'') { i = skip_quoted(s, close, i) - 1; continue; }
        if (c == '(' || c == '[' || c == '{') depth++;
        else if (c == ')' || c == ']' || c == '}') depth--;
        else if (c == ',' && depth == 0) {
            if (cnt < max) { st[cnt] = from; en[cnt] = i; }
            cnt++;
            from = i + 1;
        }
    }
    if (cnt < max) { st[cnt] = from; en[cnt] = close; }
    return cnt + 1;
}

static void render_expr(const char *s, size_t i, size_t end, Buf *out);

static void render_example(const char *s, size_t open, size_t close, int rpc, Buf *out)
{
    size_t st[2] = {0, 0}, en[2] = {0, 0};
    Buf name = {0, 0, 0}, args = {0, 0, 0};
    int k = top_split(s, open, close, st, en, 2);
    if (k >= 1) render_expr(s, st[0], en[0], &name);
    if (k >= 2) render_expr(s, st[1], en[1], &args);
    if (rpc)
        buf_addf(out, "> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"%s\", "
                 "\"params\": [%s] }' -H 'content-type: text/plain;' http://127.0.0.1:8232/\n", buf_str(&name), buf_str(&args));
    else
        buf_addf(out, "> zclassic-cli %s %s\n", buf_str(&name), buf_str(&args));
    free(name.p);
    free(args.p);
}

/* Render a help-text expression: literals verbatim, HelpExample* calls expanded,
 * anything else as {expr} so a reader sees where the text is computed. */
static void render_expr(const char *s, size_t i, size_t end, Buf *out)
{
    while (i < end) {
        i = skip_ws(s, end, i);
        if (i >= end) break;
        if (s[i] == '"') { i = read_literals(s, end, i, out); continue; }
        if (is_idch((unsigned char)s[i]) || s[i] == ':') {
            size_t a = i, j;
            char *id;
            while (i < end && (is_idch((unsigned char)s[i]) || s[i] == ':')) i++;
            id = xstrndup(s + a, i - a);
            j = skip_ws(s, end, i);
            if (j < end && s[j] == '(') {
                size_t c = match_close(s, end, j);
                if (!strcmp(id, "HelpExampleCli") || !strcmp(id, "HelpExampleRpc"))
                    render_example(s, j, c, !strcmp(id, "HelpExampleRpc"), out);
                else
                    buf_addf(out, "{%s(...)}", id);
                i = c < end ? c + 1 : end;
            } else {
                buf_addf(out, "{%s}", id);
            }
            free(id);
            continue;
        }
        if (s[i] == '(') {
            size_t c = match_close(s, end, i);
            render_expr(s, i + 1, c < end ? c : end, out);
            i = c < end ? c + 1 : end;
            continue;
        }
        i++; /* + , ; and other separators */
    }
}

/* ---- findings and paged output ------------------------------------------ */
typedef struct { char *file; int line; char *msg; } Finding;
typedef struct { Finding *v; size_t n, cap; } Findings;

static void find_add(Findings *f, const char *file, int line, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    if (f->n == f->cap) {
        f->cap = f->cap ? f->cap * 2 : 32;
        f->v = (Finding *)xrealloc(f->v, f->cap * sizeof *f->v);
    }
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    f->v[f->n].file = xstrdup(file);
    f->v[f->n].line = line;
    f->v[f->n].msg = xstrdup(tmp);
    f->n++;
}

static int g_json, g_after;

/* Print findings (paged under 16 KiB); returns the exit status 0 or 1. */
static int report(const char *check, const Findings *f, const char *ok_note)
{
    Buf b = {0, 0, 0};
    size_t i;
    int shown = 0;
    int truncated = 0;
    size_t start = g_after < 0 ? 0 : (size_t)g_after;
    if (g_json) buf_addf(&b, "{\"check\":\"%s\",\"count\":%zu,\"findings\":[", check, f->n);
    for (i = start; i < f->n; i++) {
        Buf one = {0, 0, 0};
        if (g_json) {
            buf_addf(&one, "%s{\"file\":", shown ? "," : "");
            json_str(&one, f->v[i].file);
            buf_addf(&one, ",\"line\":%d,\"message\":", f->v[i].line);
            json_str(&one, f->v[i].msg);
            buf_addc(&one, '}');
        } else {
            buf_addf(&one, "%s:%d: %s\n", f->v[i].file, f->v[i].line, f->v[i].msg);
        }
        if (b.n + one.n > OUT_LIMIT - 256) { truncated = 1; free(one.p); break; }
        buf_adds(&b, buf_str(&one));
        free(one.p);
        shown++;
    }
    if (g_json) {
        buf_addf(&b, "],\"next\":%d}\n", truncated ? (int)(start + (size_t)shown) : -1);
    } else if (truncated) {
        buf_addf(&b, "... %zu more findings: rerun with --after=%zu\n", f->n - start - (size_t)shown, start + (size_t)shown);
    } else if (!f->n) {
        buf_addf(&b, "%s: ok%s%s\n", check, ok_note && *ok_note ? " " : "", ok_note ? ok_note : "");
    } else {
        buf_addf(&b, "%s: %zu finding(s)\n", check, f->n);
    }
    fwrite(b.p, 1, b.n, stdout);
    free(b.p);
    return f->n ? 1 : 0;
}

/* ---- RPC command tables ------------------------------------------------- */
typedef struct {
    char *cat, *name, *actor;
    int safe;                 /* 1 true, 0 false, -1 not a literal */
    int src, line;            /* g_src index of the table, line of the row */
    char *help;               /* decoded help text, NULL when none found */
    int def_src, def_line, help_line;
} Cmd;

typedef struct { char *name; int src; size_t brace; int line; } Def;

static Cmd *g_cmds;
static size_t g_ncmds, g_ncmds_cap;
static size_t g_ntables;
static Def *g_defs;
static size_t g_ndefs, g_ndefs_cap;

typedef struct { char *name; int idx; int src, line; } Conv;
static Conv *g_conv;
static size_t g_nconv, g_nconv_cap;

static char *trim_dup(const char *s, size_t a, size_t b)
{
    while (a < b && isspace((unsigned char)s[a])) a++;
    while (b > a && isspace((unsigned char)s[b - 1])) b--;
    return xstrndup(s + a, b - a);
}

static int word_at(const char *s, size_t n, size_t i, const char *w)
{
    size_t k = strlen(w);
    if (i + k > n || strncmp(s + i, w, k)) return 0;
    if (i > 0 && is_idch((unsigned char)s[i - 1])) return 0;
    if (i + k < n && is_idch((unsigned char)s[i + k])) return 0;
    return 1;
}

static void cmd_add(const Cmd *c)
{
    if (g_ncmds == g_ncmds_cap) {
        g_ncmds_cap = g_ncmds_cap ? g_ncmds_cap * 2 : 128;
        g_cmds = (Cmd *)xrealloc(g_cmds, g_ncmds_cap * sizeof *g_cmds);
    }
    g_cmds[g_ncmds++] = *c;
}

static void parse_tables(int si)
{
    const Src *f = &g_src.v[si];
    const char *s = f->text;
    size_t n = f->len, i = 0;
    while (i < n) {
        const char *hit = strstr(s + i, "CRPCCommand");
        size_t p, open, close, q;
        if (!hit) break;
        p = (size_t)(hit - s);
        i = p + 11;
        if (p > 0 && is_idch((unsigned char)s[p - 1])) continue;
        q = skip_ws(s, n, p + 11);
        if (q >= n || !(isalpha((unsigned char)s[q]) || s[q] == '_')) continue;
        while (q < n && is_idch((unsigned char)s[q])) q++;
        q = skip_ws(s, n, q);
        if (q >= n || s[q] != '[') continue;
        q = skip_ws(s, n, q + 1);
        if (q >= n || s[q] != ']') continue;
        q = skip_ws(s, n, q + 1);
        if (q >= n || s[q] != '=') continue;
        q = skip_ws(s, n, q + 1);
        if (q >= n || s[q] != '{') continue;
        open = q;
        close = match_close(s, n, open);
        if (close >= n) continue;
        g_ntables++;
        q = open + 1;
        for (;;) {
            size_t rc, st[4] = {0}, en[4] = {0};
            Cmd c;
            Buf a = {0, 0, 0}, b = {0, 0, 0};
            int k;
            q = skip_ws_pp(s, close, q);
            if (q >= close) break;
            if (s[q] == ',') { q++; continue; }
            if (s[q] != '{') { q++; continue; }
            rc = match_close(s, close, q);
            if (rc >= close) break;
            k = top_split(s, q, rc, st, en, 4);
            memset(&c, 0, sizeof c);
            c.src = si;
            c.line = line_of(s, q);
            c.safe = -1;
            c.def_src = -1;
            if (k >= 4) {
                size_t x = skip_ws(s, en[0], st[0]), y = skip_ws(s, en[1], st[1]);
                if (x < en[0] && s[x] == '"' && y < en[1] && s[y] == '"') {
                    char *act, *sf;
                    read_literals(s, en[0], x, &a);
                    read_literals(s, en[1], y, &b);
                    act = trim_dup(s, st[2], en[2]);
                    sf = trim_dup(s, st[3], en[3]);
                    c.cat = xstrdup(buf_str(&a));
                    c.name = xstrdup(buf_str(&b));
                    c.actor = xstrdup(act[0] == '&' ? act + 1 : act);
                    c.safe = !strcmp(sf, "true") ? 1 : !strcmp(sf, "false") ? 0 : -1;
                    free(act);
                    free(sf);
                    cmd_add(&c);
                }
            }
            free(a.p);
            free(b.p);
            q = rc + 1;
        }
        i = close + 1;
    }
}

static void def_add(const char *name, int si, size_t brace)
{
    if (g_ndefs == g_ndefs_cap) {
        g_ndefs_cap = g_ndefs_cap ? g_ndefs_cap * 2 : 512;
        g_defs = (Def *)xrealloc(g_defs, g_ndefs_cap * sizeof *g_defs);
    }
    g_defs[g_ndefs].name = xstrdup(name);
    g_defs[g_ndefs].src = si;
    g_defs[g_ndefs].brace = brace;
    g_defs[g_ndefs].line = line_of(g_src.v[si].text, brace);
    g_ndefs++;
}

/* Index every definition `UniValue name(...) {` in one file. */
static void index_defs(int si)
{
    const char *s = g_src.v[si].text;
    size_t n = g_src.v[si].len, i = 0;
    while (i < n) {
        const char *hit = strstr(s + i, "UniValue");
        size_t p, q, a, close;
        char *id;
        if (!hit) break;
        p = (size_t)(hit - s);
        i = p + 8;
        if (!word_at(s, n, p, "UniValue")) continue;
        q = skip_ws(s, n, p + 8);
        a = q;
        while (q < n && (is_idch((unsigned char)s[q]) || s[q] == ':')) q++;
        if (q == a) continue;
        id = xstrndup(s + a, q - a);
        q = skip_ws(s, n, q);
        if (q < n && s[q] == '(') {
            close = match_close(s, n, q);
            if (close < n) {
                size_t b = skip_ws(s, n, close + 1);
                if (b < n && s[b] == '{') {
                    const char *last = strrchr(id, ':');
                    def_add(last ? last + 1 : id, si, b);
                }
            }
        }
        free(id);
    }
}

/* First code occurrence of word w in [from, to), skipping strings and comments; n if none. */
static size_t find_word_code(const char *s, size_t from, size_t to, const char *w)
{
    size_t i = from;
    while (i < to) {
        char c = s[i];
        if (c == '"' || c == '\'') { i = skip_quoted(s, to, i); continue; }
        if (c == '/' && i + 1 < to && (s[i + 1] == '/' || s[i + 1] == '*')) { i = skip_ws(s, to, i); continue; }
        if (is_idch((unsigned char)c) && (i == 0 || !is_idch((unsigned char)s[i - 1]))) {
            if (word_at(s, to, i, w)) return i;
            while (i < to && is_idch((unsigned char)s[i])) i++;
            continue;
        }
        i++;
    }
    return to;
}

/* Find the actor's definition, preferring the table's own file; extract its help literal. */
static void resolve_help(Cmd *c)
{
    size_t d, best = (size_t)-1;
    const char *s;
    size_t n, end, hp, th, open, close;
    const char *last = strrchr(c->actor, ':');
    const char *aname = last ? last + 1 : c->actor;
    Buf h = {0, 0, 0};
    for (d = 0; d < g_ndefs; d++) {
        if (strcmp(g_defs[d].name, aname)) continue;
        if (g_defs[d].src == c->src) { best = d; break; }
        if (best == (size_t)-1) best = d;
    }
    if (best == (size_t)-1) return;
    c->def_src = g_defs[best].src;
    c->def_line = g_defs[best].line;
    s = g_src.v[c->def_src].text;
    n = g_src.v[c->def_src].len;
    end = match_close(s, n, g_defs[best].brace);
    hp = find_word_code(s, g_defs[best].brace, end, "fHelp");
    if (hp >= end) return;
    th = find_word_code(s, hp, end, "runtime_error");
    if (th >= end) return;
    open = skip_ws(s, end, th + 13);
    if (open >= end || s[open] != '(') return;
    close = match_close(s, end, open);
    if (close >= end) return;
    render_expr(s, open + 1, close, &h);
    if (!h.n) { free(h.p); return; }
    c->help = h.p;
    c->help_line = line_of(s, th);
}

static void load_rpc(void)
{
    size_t i;
    load_node_sources();
    if (g_ncmds) return;
    for (i = 0; i < g_src.n; i++) {
        index_defs((int)i);
        parse_tables((int)i);
        if (strstr(g_src.v[i].text, "vRPCConvertParams")) {
            const char *s = g_src.v[i].text;
            size_t n = g_src.v[i].len;
            const char *hit = strstr(s, "CRPCConvertParam vRPCConvertParams");
            size_t q, close;
            if (!hit) continue;
            q = (size_t)(hit - s);
            while (q < n && s[q] != '=') q++;
            q = skip_ws(s, n, q + 1);
            if (q >= n || s[q] != '{') continue;
            close = match_close(s, n, q);
            q++;
            for (;;) {
                size_t rc, st[2] = {0}, en[2] = {0};
                q = skip_ws_pp(s, close, q);
                if (q >= close) break;
                if (s[q] != '{') { q++; continue; }
                rc = match_close(s, close, q);
                if (rc >= close) break;
                if (top_split(s, q, rc, st, en, 2) >= 2) {
                    size_t x = skip_ws(s, en[0], st[0]);
                    if (x < en[0] && s[x] == '"') {
                        Buf nm = {0, 0, 0};
                        char *idx;
                        read_literals(s, en[0], x, &nm);
                        idx = trim_dup(s, st[1], en[1]);
                        if (g_nconv == g_nconv_cap) {
                            g_nconv_cap = g_nconv_cap ? g_nconv_cap * 2 : 128;
                            g_conv = (Conv *)xrealloc(g_conv, g_nconv_cap * sizeof *g_conv);
                        }
                        g_conv[g_nconv].name = xstrdup(buf_str(&nm));
                        g_conv[g_nconv].idx = atoi(idx);
                        g_conv[g_nconv].src = (int)i;
                        g_conv[g_nconv].line = line_of(s, q);
                        g_nconv++;
                        free(idx);
                        free(nm.p);
                    }
                }
                q = rc + 1;
            }
        }
    }
    if (!g_ncmds) die("hollow scan: no CRPCCommand tables found under src/");
    for (i = 0; i < g_ncmds; i++) resolve_help(&g_cmds[i]);
}

static int cmp_cmd(const void *a, const void *b)
{
    const Cmd *x = *(const Cmd *const *)a, *y = *(const Cmd *const *)b;
    int r = strcmp(x->cat, y->cat);
    if (r) return r;
    r = strcmp(x->name, y->name);
    if (r) return r;
    r = x->src - y->src;
    return r ? r : x->line - y->line;
}

static Cmd **sorted_cmds(void)
{
    Cmd **v = (Cmd **)xrealloc(NULL, g_ncmds * sizeof *v);
    size_t i;
    for (i = 0; i < g_ncmds; i++) v[i] = &g_cmds[i];
    qsort(v, g_ncmds, sizeof *v, cmp_cmd);
    return v;
}

/* Documented argument count from the usage line; -1 when not parseable or variadic. */
static int usage_argc(const char *name, const char *help)
{
    const char *e = strchr(help, '\n');
    size_t len = e ? (size_t)(e - help) : strlen(help), nl = strlen(name), i;
    int count = 0;
    if (len < nl || strncmp(help, name, nl) || (len > nl && help[nl] != ' ')) return -1;
    i = nl;
    while (i < len) {
        int depth = 0, inq = 0, real = 0;
        size_t a;
        char tok[256];
        size_t tk = 0;
        while (i < len && help[i] == ' ') i++;
        a = i;
        for (; i < len; i++) {
            char c = help[i];
            if (c == '"') inq = !inq;
            else if (!inq && (c == '{' || c == '[')) depth++;
            else if (!inq && (c == '}' || c == ']')) depth--;
            else if (!inq && depth <= 0 && c == ' ') break;
            if (c != '(' && c != ')' && tk + 1 < sizeof tok) { tok[tk++] = c; real = 1; }
        }
        (void)a;
        tok[tk] = 0;
        if (!real) continue;
        if (!strcmp(tok, "...")) return -1;
        if (!strcmp(tok, "|") || !strcmp(tok, "or")) continue;
        count++;
    }
    return count;
}

static char *cmd_where(const Cmd *c)
{
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s:%d", g_src.v[c->src].path, c->line);
    return xstrdup(tmp);
}

/* ---- gen rpc-reference --------------------------------------------------- */
static int cmd_rpc_reference(const char *out_path)
{
    Cmd **v;
    Buf b = {0, 0, 0};
    size_t i, ncat = 0;
    load_rpc();
    v = sorted_cmds();
    for (i = 0; i < g_ncmds; i++) if (!i || strcmp(v[i]->cat, v[i - 1]->cat)) ncat++;
    buf_adds(&b, "# zclassicd RPC reference\n\n"
                 "Generated by `zcl-dev gen rpc-reference` from the `CRPCCommand` tables and the help literals in `src/`.\n"
                 "Do not edit and do not track: `zcutil/gen/` is git-ignored.\n\n");
    buf_addf(&b, "%zu commands in %zu categories, from %zu tables.\n\n", g_ncmds, ncat, g_ntables);
    buf_adds(&b, "| Command | Category | Safe mode | Actor | Registered at |\n|---|---|---|---|---|\n");
    for (i = 0; i < g_ncmds; i++) {
        char *w = cmd_where(v[i]);
        buf_addf(&b, "| `%s` | %s | %s | `%s` | %s |\n", v[i]->name, v[i]->cat,
                 v[i]->safe == 1 ? "yes" : v[i]->safe == 0 ? "no" : "?", v[i]->actor, w);
        free(w);
    }
    for (i = 0; i < g_ncmds; i++) {
        const Cmd *c = v[i];
        char *w = cmd_where(c);
        if (!i || strcmp(c->cat, v[i - 1]->cat)) buf_addf(&b, "\n## %s\n", c->cat);
        buf_addf(&b, "\n### `%s`\n\nRegistered at `%s`, actor `%s`", c->name, w, c->actor);
        if (c->def_src >= 0) buf_addf(&b, " (defined at `%s:%d`)", g_src.v[c->def_src].path, c->def_line);
        buf_addf(&b, ", okSafeMode: %s.\n\n", c->safe == 1 ? "true" : c->safe == 0 ? "false" : "unknown");
        if (c->help) {
            buf_adds(&b, "```text\n");
            buf_adds(&b, c->help);
            if (b.n && b.p[b.n - 1] != '\n') buf_addc(&b, '\n');
            buf_adds(&b, "```\n");
        } else {
            buf_adds(&b, "No help text found in the actor.\n");
        }
        free(w);
    }
    free(v);
    write_out(out_path, b.p, b.n);
    if (g_json) printf("{\"generated\":\"rpc-reference\",\"commands\":%zu,\"categories\":%zu,\"out\":\"%s\"}\n", g_ncmds, ncat, out_path);
    else printf("rpc-reference: %zu commands, %zu categories -> %s\n", g_ncmds, ncat, out_path);
    free(b.p);
    return 0;
}

/* ---- command-line options ------------------------------------------------- */
typedef struct { char *name; char *reason; } BaseRow;
typedef struct { char *form, *group, *desc; int src, line; } DocOpt;  /* one HelpMessageOpt("-x...") */
typedef struct { char *flag; int src, line; } ReadHit;               /* one GetArg("-x") style read */

static DocOpt *g_docs;
static size_t g_ndocs, g_ndocs_cap;
static ReadHit *g_reads;
static size_t g_nreads, g_nreads_cap;

/* Flag text starting at s[i] == '-': [A-Za-z0-9_.?-]+ ; returns a new string. */
static char *flag_at(const char *s, size_t n, size_t i, size_t *end)
{
    size_t a = i;
    while (i < n && (isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '.' || s[i] == '-' || s[i] == '?')) i++;
    if (end) *end = i;
    return xstrndup(s + a, i - a);
}

/* Decoded text of the string literals in [from,to) that read as prose: at top level every one,
 * inside a call (strprintf(_("..."), x)) only those before its first comma. */
static void lits_in_range(const char *s, size_t from, size_t to, Buf *out)
{
    size_t i = from;
    int depth = 0;
    unsigned char comma[32] = {0};
    while (i < to) {
        if (s[i] == '"') {
            if (depth > 0 && depth < 32 && comma[depth]) i = skip_quoted(s, to, i);
            else i = read_one_literal(s, to, i, out);
            continue;
        }
        if (s[i] == '\'') { i = skip_quoted(s, to, i); continue; }
        if (s[i] == '/' && i + 1 < to && (s[i + 1] == '/' || s[i + 1] == '*')) { i = skip_ws(s, to, i); continue; }
        if (s[i] == '(') { if (depth + 1 < 32) comma[depth + 1] = 0; depth++; }
        else if (s[i] == ')') { if (depth > 0) depth--; }
        else if (s[i] == ',' && depth > 0 && depth < 32) comma[depth] = 1;
        i++;
    }
}

static void scan_flags(void)
{
    static const char *const readers[] = {
        "GetArg(\"", "GetBoolArg(\"", "GetArgs(\"", "IsArgSet(\"", "mapArgs.count(\"", "mapArgs[\"", "mapMultiArgs[\"",
        "mapMultiArgs.count(\"", NULL };
    size_t fi;
    load_node_sources();
    if (g_ndocs || g_nreads) return;
    for (fi = 0; fi < g_src.n; fi++) {
        const char *s = g_src.v[fi].text;
        size_t n = g_src.v[fi].len, i = 0;
        char *group = NULL;
        int k;
        for (k = 0; readers[k]; k++) {
            const char *p = s;
            size_t rl = strlen(readers[k]);
            while ((p = strstr(p, readers[k]))) {
                size_t off = (size_t)(p - s), e;
                p += rl;
                if (off > 0 && is_idch((unsigned char)s[off - 1])) continue; /* a longer identifier */
                if (s[off + rl] != '-') continue;
                {
                    char *fl = flag_at(s, n, off + rl, &e);
                    if (strlen(fl) < 2) { free(fl); continue; } /* "-" + a computed name */
                    if (g_nreads == g_nreads_cap) {
                        g_nreads_cap = g_nreads_cap ? g_nreads_cap * 2 : 256;
                        g_reads = (ReadHit *)xrealloc(g_reads, g_nreads_cap * sizeof *g_reads);
                    }
                    g_reads[g_nreads].flag = fl;
                    g_reads[g_nreads].src = (int)fi;
                    g_reads[g_nreads].line = line_of(s, off);
                    g_nreads++;
                }
            }
        }
        if (!strstr(s, "HelpMessage")) continue;
        while (i < n) {
            const char *hit = strstr(s + i, "HelpMessage");
            size_t p, open, close, st[8] = {0}, en[8] = {0};
            int isopt;
            if (!hit) break;
            p = (size_t)(hit - s);
            i = p + 11;
            if (p > 0 && is_idch((unsigned char)s[p - 1])) continue;
            isopt = !strncmp(s + p, "HelpMessageOpt", 14);
            if (!isopt && strncmp(s + p, "HelpMessageGroup", 16)) continue;
            open = skip_ws(s, n, p + (isopt ? 14 : 16));
            if (open >= n || s[open] != '(') continue;
            close = match_close(s, n, open);
            if (close >= n) continue;
            i = close + 1;
            if (!isopt) {
                Buf g = {0, 0, 0};
                lits_in_range(s, open + 1, close, &g);
                free(group);
                group = g.p ? g.p : xstrdup("");
                continue;
            }
            {
                size_t x;
                int cnt = top_split(s, open, close, st, en, 8);
                x = skip_ws(s, en[0], st[0]);
                if (cnt < 2 || x >= en[0] || s[x] != '"' || s[x + 1] != '-') continue;
                {
                    Buf form = {0, 0, 0}, desc = {0, 0, 0};
                    read_literals(s, en[0], x, &form);
                    lits_in_range(s, st[1], close, &desc);
                    if (g_ndocs == g_ndocs_cap) {
                        g_ndocs_cap = g_ndocs_cap ? g_ndocs_cap * 2 : 256;
                        g_docs = (DocOpt *)xrealloc(g_docs, g_ndocs_cap * sizeof *g_docs);
                    }
                    g_docs[g_ndocs].form = form.p;
                    g_docs[g_ndocs].desc = desc.p ? desc.p : xstrdup("");
                    g_docs[g_ndocs].group = xstrdup(group ? group : "");
                    g_docs[g_ndocs].src = (int)fi;
                    g_docs[g_ndocs].line = line_of(s, p);
                    g_ndocs++;
                }
            }
        }
        free(group);
    }
    if (!g_ndocs) die("hollow scan: no HelpMessageOpt(\"-x\") found under src/");
    if (!g_nreads) die("hollow scan: no GetArg/GetBoolArg/mapArgs reads found under src/");
}

/* Option name inside a documented form: "-x=<n>" -> "-x". */
static char *doc_flag(const DocOpt *d)
{
    size_t k = 1;
    while (d->form[k] && (isalnum((unsigned char)d->form[k]) || strchr("_.-?", d->form[k]))) k++;
    return xstrndup(d->form, k);
}

static int is_documented(const char *flag)
{
    size_t i;
    char pos[256] = "";
    int found = 0;
    /* -h and -help are documented by -? ; -nofoo is the negation of -foo */
    if (!strcmp(flag, "-h") || !strcmp(flag, "-help")) flag = "-?";
    if (starts_with(flag, "-no") && flag[3]) snprintf(pos, sizeof pos, "-%s", flag + 3);
    for (i = 0; i < g_ndocs && !found; i++) {
        char *d = doc_flag(&g_docs[i]);
        if (!strcmp(d, flag) || (pos[0] && !strcmp(d, pos))) found = 1;
        free(d);
    }
    return found;
}

static int cmp_read(const void *a, const void *b)
{
    const ReadHit *x = (const ReadHit *)a, *y = (const ReadHit *)b;
    int r = strcmp(x->flag, y->flag);
    if (r) return r;
    r = strcmp(g_src.v[x->src].path, g_src.v[y->src].path);
    return r ? r : x->line - y->line;
}

static BaseRow *g_base;
static size_t g_nbase;

static int load_baseline(const char *path, int must_exist)
{
    size_t len = 0, i = 0;
    char *t = read_file(path, &len);
    if (!t) {
        if (must_exist) die("cannot read baseline %s", path);
        return 0;
    }
    while (i < len) {
        size_t e = i;
        char *line, *tab;
        while (e < len && t[e] != '\n') e++;
        line = xstrndup(t + i, e - i);
        i = e + 1;
        if (!line[0] || line[0] == '#') { free(line); continue; }
        tab = strchr(line, '\t');
        g_base = (BaseRow *)xrealloc(g_base, (g_nbase + 1) * sizeof *g_base);
        if (tab) { *tab = 0; g_base[g_nbase].reason = xstrdup(tab + 1); }
        else g_base[g_nbase].reason = xstrdup("");
        g_base[g_nbase].name = xstrdup(line);
        g_nbase++;
        free(line);
    }
    free(t);
    return 1;
}

static const BaseRow *base_find(const char *flag)
{
    size_t i;
    for (i = 0; i < g_nbase; i++) if (!strcmp(g_base[i].name, flag)) return &g_base[i];
    return NULL;
}

/* Distinct flags that are read; fills `names` (sorted, unique) from the sorted g_reads. */
static void sort_reads(void) { qsort(g_reads, g_nreads, sizeof *g_reads, cmp_read); }

static void reads_text(Buf *b, const char *flag, int max)
{
    size_t i;
    int shown = 0, total = 0;
    for (i = 0; i < g_nreads; i++) if (!strcmp(g_reads[i].flag, flag)) total++;
    for (i = 0; i < g_nreads && shown < max; i++) {
        if (strcmp(g_reads[i].flag, flag)) continue;
        buf_addf(b, "%s%s:%d", shown ? ", " : "", g_src.v[g_reads[i].src].path, g_reads[i].line);
        shown++;
    }
    if (total > shown) buf_addf(b, " (+%d more)", total - shown);
    if (!total) buf_adds(b, "not read");
}

/* ---- gen args-reference ---------------------------------------------------- */
static int cmd_args_reference(const char *out_path, const char *baseline)
{
    Buf b = {0, 0, 0};
    size_t i, undoc = 0, distinct = 0;
    int last_src = -1;
    char *last_group = NULL;
    scan_flags();
    sort_reads();
    load_baseline(baseline, 0);
    for (i = 0; i < g_nreads; i++) if (!i || strcmp(g_reads[i].flag, g_reads[i - 1].flag)) {
        distinct++;
        if (!is_documented(g_reads[i].flag)) undoc++;
    }
    buf_adds(&b, "# zclassicd command-line argument reference\n\n"
                 "Generated by `zcl-dev gen args-reference` from `HelpMessageOpt` / `HelpMessageGroup` and from every\n"
                 "`GetArg`, `GetBoolArg`, `mapArgs` and `mapMultiArgs` read under `src/`. Do not edit and do not track.\n\n");
    buf_addf(&b, "%zu documented options, %zu distinct flags read, %zu read but not documented.\n", g_ndocs, distinct, undoc);
    for (i = 0; i < g_ndocs; i++) {
        const DocOpt *d = &g_docs[i];
        char *fl = doc_flag(d);
        if (d->src != last_src || !last_group || strcmp(last_group, d->group)) {
            buf_addf(&b, "\n## %s%s%s\n\n", g_src.v[d->src].path, d->group[0] ? ": " : "", d->group);
            last_src = d->src;
            free(last_group);
            last_group = xstrdup(d->group);
        }
        buf_addf(&b, "- `%s` %s%s\n  - documented at `%s:%d`; read at: ", d->form, d->desc[0] ? "- " : "", d->desc, g_src.v[d->src].path, d->line);
        reads_text(&b, fl, 3);
        buf_addc(&b, '\n');
        free(fl);
    }
    buf_adds(&b, "\n## Read but not documented\n\n");
    if (!undoc) buf_adds(&b, "None.\n");
    for (i = 0; i < g_nreads; i++) {
        const BaseRow *r;
        if (i && !strcmp(g_reads[i].flag, g_reads[i - 1].flag)) continue;
        if (is_documented(g_reads[i].flag)) continue;
        r = base_find(g_reads[i].flag);
        buf_addf(&b, "- `%s` - read at: ", g_reads[i].flag);
        reads_text(&b, g_reads[i].flag, 3);
        buf_addf(&b, "; baseline: %s\n", r ? (r->reason[0] ? r->reason : "listed") : "not listed");
    }
    free(last_group);
    write_out(out_path, b.p, b.n);
    if (g_json) printf("{\"generated\":\"args-reference\",\"documented\":%zu,\"read\":%zu,\"undocumented\":%zu,\"out\":\"%s\"}\n", g_ndocs, distinct, undoc, out_path);
    else printf("args-reference: %zu documented, %zu read, %zu undocumented -> %s\n", g_ndocs, distinct, undoc, out_path);
    free(b.p);
    return 0;
}

/* ---- gate flags -------------------------------------------------------------- */
/* ---- gate rpc-parity ------------------------------------------------------ */
static int baseline_update(const char *check, const char *baseline, size_t nnew, const Findings *f, int (*live)(const char *));
static List g_live_keys;   /* "name:idx" of the convert-param mismatches seen on this run */

static int key_live(const char *key)
{
    size_t i;
    for (i = 0; i < g_live_keys.n; i++) if (!strcmp(g_live_keys.v[i], key)) return 1;
    return 0;
}

/* Gate: no duplicate names, every actor has help, convert-params rows name real commands and
 * stay inside the documented argument count. Index mismatches may be baselined (name:idx). */
static int check_rpc_parity(const char *baseline, int update)
{
    Findings f = {0, 0, 0};
    Cmd **v;
    size_t i, j, nnew = 0;
    char note[160];
    load_rpc();
    if (!g_nconv) die("hollow scan: no vRPCConvertParams rows found under src/");
    load_baseline(baseline, 0);
    v = sorted_cmds();
    {
        Cmd **byname = (Cmd **)xrealloc(NULL, g_ncmds * sizeof *byname);
        for (i = 0; i < g_ncmds; i++) byname[i] = &g_cmds[i];
        for (i = 0; i < g_ncmds; i++)
            for (j = i + 1; j < g_ncmds; j++)
                if (!strcmp(byname[i]->name, byname[j]->name)) {
                    find_add(&f, g_src.v[byname[j]->src].path, byname[j]->line, "duplicate RPC name `%s` (first registered at %s:%d)",
                             byname[j]->name, g_src.v[byname[i]->src].path, byname[i]->line);
                    nnew++;
                }
        free(byname);
    }
    for (i = 0; i < g_ncmds; i++) {
        const Cmd *c = v[i];
        if (!c->help) {
            find_add(&f, g_src.v[c->src].path, c->line, "`%s`: actor `%s` has no help text (%s)", c->name, c->actor,
                     c->def_src < 0 ? "definition not found" : "no `if (fHelp ...) throw runtime_error(` literal");
            nnew++;
        }
    }
    for (i = 0; i < g_nconv; i++) {
        const Conv *k = &g_conv[i];
        const Cmd *hit = NULL;
        for (j = 0; j < g_ncmds; j++) if (!strcmp(g_cmds[j].name, k->name)) { hit = &g_cmds[j]; break; }
        if (!hit) {
            find_add(&f, g_src.v[k->src].path, k->line, "vRPCConvertParams names `%s`, which is not a registered command", k->name);
            nnew++;
        } else if (hit->help) {
            int argc = usage_argc(hit->name, hit->help);
            if (argc >= 0 && k->idx >= argc) {
                char key[300];
                snprintf(key, sizeof key, "%s:%d", k->name, k->idx);
                list_add(&g_live_keys, xstrdup(key));
                if (!base_find(key)) {
                    find_add(&f, g_src.v[k->src].path, k->line, "vRPCConvertParams `%s` index %d, but the usage line documents %d argument(s)",
                             k->name, k->idx, argc);
                    nnew++;
                }
            }
        }
    }
    for (i = 0; i < g_nbase; i++)
        if (!key_live(g_base[i].name))
            find_add(&f, baseline, (int)i + 1, "stale baseline row `%s`: the mismatch is gone; remove the row (the baseline only shrinks)", g_base[i].name);
    free(v);
    if (update) return baseline_update("rpc-parity", baseline, nnew, &f, key_live);
    snprintf(note, sizeof note, "(%zu commands, %zu convert-param rows, %zu baseline rows)", g_ncmds, g_nconv, g_nbase);
    return report("rpc-parity", &f, note);
}

static int flag_live(const char *name)
{
    size_t j;
    for (j = 0; j < g_nreads; j++) if (!strcmp(g_reads[j].flag, name)) return !is_documented(name);
    return 0;
}

/* Rewrite a baseline without its stale rows. Never adds a row: the baseline only shrinks. */
static int baseline_update(const char *check, const char *baseline, size_t nnew, const Findings *f, int (*live)(const char *))
{
    Buf out = {0, 0, 0};
    size_t p = 0, len = 0, dropped = 0;
    char *t;
    if (nnew) {
        fprintf(stderr, "zcl-dev-gen: refusing --update-baseline: %zu finding(s) are not in the baseline; fix them, never add rows here\n", nnew);
        return report(check, f, "");
    }
    t = read_file(baseline, &len);
    while (t && p < len) {
        size_t e = p;
        char *line, *name;
        int keep = 1;
        while (e < len && t[e] != '\n') e++;
        line = xstrndup(t + p, e - p);
        p = e + 1;
        name = xstrndup(line, strcspn(line, "\t"));
        if (name[0] && name[0] != '#') {
            keep = live(name);
            if (!keep) dropped++;
        }
        if (keep) { buf_adds(&out, line); buf_addc(&out, '\n'); }
        free(name);
        free(line);
    }
    free(t);
    write_out(baseline, out.p ? out.p : "", out.n);
    free(out.p);
    printf("%s: baseline %s rewritten, %zu stale row(s) removed\n", check, baseline, dropped);
    return 0;
}

static int check_flags(const char *baseline, int update)
{
    Findings f = {0, 0, 0};
    size_t i, nnew = 0, distinct = 0;
    char note[160];
    scan_flags();
    sort_reads();
    load_baseline(baseline, 1);
    for (i = 0; i < g_nreads; i++) {
        if (i && !strcmp(g_reads[i].flag, g_reads[i - 1].flag)) continue;
        distinct++;
        if (is_documented(g_reads[i].flag) || base_find(g_reads[i].flag)) continue;
        find_add(&f, g_src.v[g_reads[i].src].path, g_reads[i].line,
                 "flag `%s` is read but not documented in HelpMessage and not in %s", g_reads[i].flag, baseline);
        nnew++;
    }
    for (i = 0; i < g_nbase; i++) {
        size_t j;
        int read = 0;
        for (j = 0; j < g_nreads && !read; j++) read = !strcmp(g_reads[j].flag, g_base[i].name);
        if (!read)
            find_add(&f, baseline, (int)i + 1, "stale baseline row `%s`: the flag is no longer read; remove the row (the baseline only shrinks)", g_base[i].name);
        else if (is_documented(g_base[i].name))
            find_add(&f, baseline, (int)i + 1, "stale baseline row `%s`: the flag is now documented; remove the row (the baseline only shrinks)", g_base[i].name);
    }
    if (update) return baseline_update("flags", baseline, nnew, &f, flag_live);
    snprintf(note, sizeof note, "(%zu flags read, %zu baseline rows)", distinct, g_nbase);
    return report("flags", &f, note);
}

/* ---- gen inventory ------------------------------------------------------------ */
static int skip_third_party(const char *rel)
{
    static const char *const skip[] = {
        "src/leveldb", "src/secp256k1", "src/univalue", "src/snark", "src/c23/vendor", "src/c23/services/vendor", "src/obj", NULL };
    int i;
    for (i = 0; skip[i]; i++) if (!strcmp(rel, skip[i])) return 1;
    return 0;
}
static int accept_cpp(const char *p) { return ends_with(p, ".cpp"); }
static int accept_sh(const char *p) { return ends_with(p, ".sh"); }
static int accept_makefile(const char *p)
{
    const char *b = strrchr(p, '/');
    b = b ? b + 1 : p;
    return !strcmp(b, "Makefile.am") || (starts_with(b, "Makefile.") && ends_with(b, ".include"));
}

typedef struct { Buf b; size_t counts[10]; } Inv;
static const char *const g_inv_kinds[10] = { "rpc", "arg", "boost_suite", "gtest_suite", "qa_script", "ci_step",
                                             "autotools_target", "area", "tool", "lesson" };

static void inv_begin(Inv *v, int kind) { buf_addf(&v->b, "{\"record\":\"%s\"", g_inv_kinds[kind]); v->counts[kind]++; }
static void inv_s(Inv *v, const char *k, const char *val) { buf_addf(&v->b, ",\"%s\":", k); json_str(&v->b, val); }
static void inv_i(Inv *v, const char *k, long val) { buf_addf(&v->b, ",\"%s\":%ld", k, val); }
static void inv_bool(Inv *v, const char *k, int val) { buf_addf(&v->b, ",\"%s\":%s", k, val ? "true" : "false"); }
static void inv_end(Inv *v) { buf_adds(&v->b, "}\n"); }

static void inv_rpc(Inv *v)
{
    Cmd **c = sorted_cmds();
    size_t i;
    for (i = 0; i < g_ncmds; i++) {
        Buf usage = {0, 0, 0};
        if (c[i]->help) {
            const char *e = strchr(c[i]->help, '\n');
            buf_addn(&usage, c[i]->help, e ? (size_t)(e - c[i]->help) : strlen(c[i]->help));
        }
        inv_begin(v, 0);
        inv_s(v, "name", c[i]->name);
        inv_s(v, "category", c[i]->cat);
        inv_s(v, "actor", c[i]->actor);
        inv_bool(v, "safe_mode", c[i]->safe == 1);
        inv_s(v, "file", g_src.v[c[i]->src].path);
        inv_i(v, "line", c[i]->line);
        inv_bool(v, "has_help", c[i]->help != NULL);
        inv_s(v, "usage", buf_str(&usage));
        inv_end(v);
        free(usage.p);
    }
    free(c);
}

static void inv_args(Inv *v)
{
    size_t i;
    for (i = 0; i < g_ndocs; i++) {
        char *fl = doc_flag(&g_docs[i]);
        size_t r, reads = 0;
        for (r = 0; r < g_nreads; r++) if (!strcmp(g_reads[r].flag, fl)) reads++;
        inv_begin(v, 1);
        inv_s(v, "name", fl);
        inv_s(v, "form", g_docs[i].form);
        inv_bool(v, "documented", 1);
        inv_s(v, "group", g_docs[i].group);
        inv_s(v, "file", g_src.v[g_docs[i].src].path);
        inv_i(v, "line", g_docs[i].line);
        inv_i(v, "reads", (long)reads);
        inv_end(v);
        free(fl);
    }
    for (i = 0; i < g_nreads; i++) {
        size_t r, reads = 0;
        if (i && !strcmp(g_reads[i].flag, g_reads[i - 1].flag)) continue;
        if (is_documented(g_reads[i].flag)) continue;
        for (r = 0; r < g_nreads; r++) if (!strcmp(g_reads[r].flag, g_reads[i].flag)) reads++;
        inv_begin(v, 1);
        inv_s(v, "name", g_reads[i].flag);
        inv_bool(v, "documented", 0);
        inv_s(v, "file", g_src.v[g_reads[i].src].path);
        inv_i(v, "line", g_reads[i].line);
        inv_i(v, "reads", (long)reads);
        inv_end(v);
    }
}

static void inv_tests(Inv *v)
{
    List paths = {0, 0, 0};
    size_t fi;
    walk("src", &paths, accept_cpp, skip_third_party);
    for (fi = 0; fi < paths.n; fi++) {
        size_t len = 0;
        char *s = read_file(paths.v[fi], &len);
        const char *p;
        List seen = {0, 0, 0};
        if (!s) continue;
        /* Boost: a suite runs from its macro to the next SUITE_END */
        for (p = s; (p = strstr(p, "_TEST_SUITE(")); ) {
            size_t off = (size_t)(p - s), open = off + 11, close;
            const char *b = p;
            while (b > s && (is_idch((unsigned char)b[-1]))) b--;
            p += 12;
            if (strncmp(b, "BOOST_AUTO_TEST_SUITE", 21) && strncmp(b, "BOOST_FIXTURE_TEST_SUITE", 24)) continue;
            close = match_close(s, len, open);
            if (close >= len) continue;
            {
                size_t st[1] = {0}, en[1] = {0};
                const char *endp = strstr(s + close, "BOOST_AUTO_TEST_SUITE_END");
                size_t stop = endp ? (size_t)(endp - s) : len, cases = 0;
                const char *q = s + close;
                char *nm;
                top_split(s, open, close, st, en, 1);
                nm = trim_dup(s, st[0], en[0]);
                while ((q = strstr(q, "_TEST_CASE")) && (size_t)(q - s) < stop) { cases++; q += 10; }
                inv_begin(v, 2);
                inv_s(v, "name", nm);
                inv_s(v, "file", paths.v[fi]);
                inv_i(v, "line", line_of(s, off));
                inv_i(v, "cases", (long)cases);
                inv_end(v);
                free(nm);
            }
        }
        /* gtest: TEST(Suite, Name) at the start of a line, one record per suite and file */
        {
            char **suite = NULL;
            size_t *first = NULL, *count = NULL, ns = 0, k;
            for (p = s; *p; ) {
                const char *nl;
                if (!strncmp(p, "TEST(", 5) || !strncmp(p, "TEST_F(", 7) || !strncmp(p, "TEST_P(", 7)) {
                    const char *o = strchr(p, '('), *c = strchr(o, ',');
                    const char *eol = strchr(p, '\n');
                    if (c && (!eol || c < eol)) {
                        char *nm = trim_dup(o + 1, 0, (size_t)(c - o - 1));
                        for (k = 0; k < ns; k++) if (!strcmp(suite[k], nm)) break;
                        if (k == ns) {
                            suite = (char **)xrealloc(suite, (ns + 1) * sizeof *suite);
                            first = (size_t *)xrealloc(first, (ns + 1) * sizeof *first);
                            count = (size_t *)xrealloc(count, (ns + 1) * sizeof *count);
                            suite[ns] = nm;
                            first[ns] = (size_t)(p - s);
                            count[ns] = 0;
                            ns++;
                        } else {
                            free(nm);
                        }
                        count[k]++;
                    }
                }
                nl = strchr(p, '\n');
                if (!nl) break;
                p = nl + 1;
            }
            for (k = 0; k < ns; k++) {
                inv_begin(v, 3);
                inv_s(v, "name", suite[k]);
                inv_s(v, "file", paths.v[fi]);
                inv_i(v, "line", line_of(s, first[k]));
                inv_i(v, "tests", (long)count[k]);
                inv_end(v);
                free(suite[k]);
            }
            free(suite);
            free(first);
            free(count);
        }
        (void)seen;
        free(s);
    }
}

static void inv_qa(Inv *v)
{
    List paths = {0, 0, 0};
    size_t i;
    walk("qa", &paths, accept_sh, NULL);
    for (i = 0; i < paths.n; i++) {
        size_t len = 0, p = 0;
        char *s = read_file(paths.v[i], &len);
        char purpose[300] = "";
        int lines = 0;
        while (s && p < len && lines < 12 && !purpose[0]) {
            size_t e = p;
            while (e < len && s[e] != '\n') e++;
            if (s[p] == '#' && !(p + 1 < len && s[p + 1] == '!')) {
                size_t a = p + 1;
                while (a < e && (s[a] == ' ' || s[a] == '#')) a++;
                if (a < e) snprintf(purpose, sizeof purpose, "%.*s", (int)(e - a), s + a);
            }
            p = e + 1;
            lines++;
        }
        inv_begin(v, 4);
        inv_s(v, "path", paths.v[i]);
        inv_s(v, "purpose", purpose);
        inv_end(v);
        free(s);
    }
}

static void inv_ci(Inv *v)
{
    size_t len = 0, p = 0;
    char *s = read_file("zcutil/local-ci.sh", &len);
    List seen = {0, 0, 0};
    int line = 0;
    while (s && p < len) {
        size_t e = p, a;
        char name[128], fn[128];
        int to;
        while (e < len && s[e] != '\n') e++;
        line++;
        a = p;
        while (a < e && (s[a] == ' ' || s[a] == '\t')) a++;
        if (e - a > 5 && !strncmp(s + a, "step ", 5)) {
            char tmp[400];
            snprintf(tmp, sizeof tmp, "%.*s", (int)(e - a), s + a);
            if (sscanf(tmp, "step %127s %d %127s", name, &to, fn) == 3 && name[0] != '$' && name[0] != '"' && fn[0] != '$') {
                size_t k;
                int dup = 0;
                for (k = 0; k < seen.n; k++) if (!strcmp(seen.v[k], name)) dup = 1;
                if (!dup) {
                    list_add(&seen, xstrdup(name));
                    inv_begin(v, 5);
                    inv_s(v, "name", name);
                    inv_i(v, "timeout_s", to);
                    inv_s(v, "function", fn);
                    inv_s(v, "file", "zcutil/local-ci.sh");
                    inv_i(v, "line", line);
                    inv_end(v);
                }
            }
        }
        p = e + 1;
    }
    free(s);
}

static const char *make_kind(const char *var)
{
    if (ends_with(var, "_LTLIBRARIES") || ends_with(var, "_LIBRARIES")) return "library";
    if (ends_with(var, "_PROGRAMS")) return "program";
    if (ends_with(var, "_SCRIPTS")) return "script";
    if (!strcmp(var, "TESTS")) return "test";
    return NULL;
}

/* Logical Makefile lines (backslash continuations joined) with their first line number. */
typedef struct { char **text; int *line; size_t n; } MkLines;

static void mk_split(const char *s, size_t len, MkLines *out)
{
    size_t p = 0;
    int line = 0;
    while (p < len) {
        size_t e = p;
        char *ln;
        int start;
        line++;
        start = line;
        while (e < len && s[e] != '\n') e++;
        ln = xstrndup(s + p, e - p);
        while (ln[0] && ln[strlen(ln) - 1] == '\\' && e < len) {
            size_t e2 = e + 1;
            char *more, *joined;
            while (e2 < len && s[e2] != '\n') e2++;
            more = xstrndup(s + e + 1, e2 - e - 1);
            ln[strlen(ln) - 1] = ' ';
            joined = (char *)xrealloc(NULL, strlen(ln) + strlen(more) + 2);
            sprintf(joined, "%s%s", ln, more);
            free(ln);
            free(more);
            ln = joined;
            e = e2;
            line++;
        }
        p = e + 1;
        out->text = (char **)xrealloc(out->text, (out->n + 1) * sizeof *out->text);
        out->line = (int *)xrealloc(out->line, (out->n + 1) * sizeof *out->line);
        out->text[out->n] = ln;
        out->line[out->n] = start;
        out->n++;
    }
}

/* `NAME = value` -> NAME (new string), *op set to the offset after `=` or `+=`; NULL when not an assignment. */
static char *mk_assign(const char *ln, size_t *after, int *plus)
{
    size_t k = 0, m;
    while (ln[k] == ' ' || ln[k] == '\t') k++;
    m = k;
    while (is_idch((unsigned char)ln[m])) m++;
    if (m == k) return NULL;
    {
        size_t n = m;
        while (ln[n] == ' ' || ln[n] == '\t') n++;
        *plus = 0;
        if (ln[n] == '+') { *plus = 1; n++; }
        if (ln[n] != '=') return NULL;
        *after = n + 1;
    }
    return xstrndup(ln + k, m - k);
}

static void inv_autotools(Inv *v)
{
    List paths = {0, 0, 0};
    size_t i;
    walk(".", &paths, accept_makefile, NULL);
    for (i = 0; i < paths.n; i++) {
        const char *rel = paths.v[i] + 2;   /* walk(".") yields ./path */
        size_t len = 0, k;
        char *s;
        MkLines ml = {0, 0, 0};
        char *vname[256], *vval[256];
        size_t nv = 0;
        if (starts_with(rel, "src/leveldb") || starts_with(rel, "src/secp256k1") || starts_with(rel, "src/univalue") ||
            starts_with(rel, "depends/") || starts_with(rel, "src/snark") || starts_with(rel, "build/")) continue;
        s = read_file(paths.v[i], &len);
        if (!s) continue;
        mk_split(s, len, &ml);
        free(s);
        /* pass 1: simple one-token variables, so $(LIBFOO) can be resolved */
        for (k = 0; k < ml.n && nv < 256; k++) {
            size_t after;
            int plus;
            char *nm = mk_assign(ml.text[k], &after, &plus);
            if (nm && !plus) {
                char *val = trim_dup(ml.text[k], after, strlen(ml.text[k]));
                if (val[0] && !strpbrk(val, " \t$")) { vname[nv] = nm; vval[nv] = val; nv++; continue; }
                free(val);
            }
            free(nm);
        }
        /* pass 2: targets and the *_PROGRAMS family */
        for (k = 0; k < ml.n; k++) {
            const char *ln = ml.text[k];
            size_t after;
            int plus;
            char *var;
            if (ln[0] && !isspace((unsigned char)ln[0]) && ln[0] != '#' && ln[0] != '.') {
                size_t q = 0;
                while (is_idch((unsigned char)ln[q])) q++;
                if (q && ln[q] == ':' && ln[q + 1] != '=' && !strchr(ln, '$') && !strchr(ln, '%')) {
                    char *nm = xstrndup(ln, q);
                    inv_begin(v, 6);
                    inv_s(v, "kind", "make-target");
                    inv_s(v, "name", nm);
                    inv_s(v, "file", rel);
                    inv_i(v, "line", ml.line[k]);
                    inv_end(v);
                    free(nm);
                    continue;
                }
            }
            var = mk_assign(ln, &after, &plus);
            if (var && make_kind(var)) {
                char *copy = xstrdup(ln + after), *tok;
                for (tok = strtok(copy, " \t"); tok; tok = strtok(NULL, " \t")) {
                    char name[256];
                    size_t r;
                    if (tok[0] == '#') break;
                    snprintf(name, sizeof name, "%s", tok);
                    if (starts_with(tok, "$(") && ends_with(tok, ")")) {
                        for (r = 0; r < nv; r++)
                            if (strlen(vname[r]) == strlen(tok) - 3 && !strncmp(vname[r], tok + 2, strlen(vname[r])))
                                snprintf(name, sizeof name, "%s", vval[r]);
                    }
                    inv_begin(v, 6);
                    inv_s(v, "kind", make_kind(var));
                    inv_s(v, "name", name);
                    inv_s(v, "file", rel);
                    inv_i(v, "line", ml.line[k]);
                    inv_end(v);
                }
                free(copy);
            }
            free(var);
        }
        for (k = 0; k < ml.n; k++) free(ml.text[k]);
        for (k = 0; k < nv; k++) { free(vname[k]); free(vval[k]); }
        free(ml.text);
        free(ml.line);
    }
}

static void inv_area(Inv *v)
{
    size_t len = 0, p = 0;
    char *s = read_file("AGENTS.md", &len);
    int in_layout = 0;
    while (s && p < len) {
        size_t e = p;
        while (e < len && s[e] != '\n') e++;
        if (!strncmp(s + p, "## ", 3)) in_layout = !strncmp(s + p, "## Layout", 9);
        else if (in_layout && !strncmp(s + p, "- `", 3)) {
            size_t a = p + 3, b = a;
            while (b < e && s[b] != '`') b++;
            if (b < e) {
                char *path = xstrndup(s + a, b - a), *desc;
                size_t d = b + 1;
                while (d < e && s[d] == ' ') d++;
                desc = xstrndup(s + d, e - d);
                inv_begin(v, 7);
                inv_s(v, "path", path);
                inv_s(v, "description", desc);
                inv_end(v);
                free(path);
                free(desc);
            }
        }
        p = e + 1;
    }
    free(s);
}

static void inv_tools(Inv *v, const char *self)
{
    char cmd[1024], dir[900], line[1024];
    FILE *fp;
    const char *slash = strrchr(self, '/');
    if (slash && slash - self < (long)sizeof dir) { snprintf(dir, sizeof dir, "%.*s", (int)(slash - self), self); }
    else snprintf(dir, sizeof dir, "zcutil/bin");
    snprintf(cmd, sizeof cmd, "\"%s/zcl-dev\" help", dir);
    fp = popen(cmd, "r");
    if (!fp) { fprintf(stderr, "zcl-dev-gen: warning: cannot run zcl-dev help, no tool records\n"); return; }
    while (fgets(line, sizeof line, fp)) {
        char *q = line, *name, *desc;
        size_t nl = strlen(line);
        while (nl && (line[nl - 1] == '\n' || line[nl - 1] == '\r')) line[--nl] = 0;
        if (strncmp(q, "  ", 2) || q[2] == ' ' || !q[2]) continue;
        name = q + 2;
        desc = name;
        while (*desc && *desc != ' ') desc++;
        if (*desc) { *desc++ = 0; while (*desc == ' ') desc++; }
        inv_begin(v, 8);
        inv_s(v, "name", name);
        inv_s(v, "purpose", desc);
        inv_end(v);
    }
    pclose(fp);
}

static void inv_lessons(Inv *v)
{
    size_t len = 0, p = 0;
    char *s = read_file("doc/agent/LESSONS.md", &len);
    int line = 0;
    while (s && p < len) {
        size_t e = p;
        int open = !strncmp(s + p, "OPEN ", 5), done = !strncmp(s + p, "DONE ", 5);
        line++;
        while (e < len && s[e] != '\n') e++;
        if (open || done) {
            size_t a = p + 5, b = a;
            while (b < e && s[b] != ' ') b++;
            {
                char *path = xstrndup(s + a, b - a), *text;
                const char *dash = strstr(s + b, "\xe2\x80\x94");
                size_t t = (dash && (size_t)(dash - s) < e) ? (size_t)(dash - s) + 3 : b;
                while (t < e && s[t] == ' ') t++;
                text = xstrndup(s + t, e - t);
                inv_begin(v, 9);
                inv_s(v, "status", open ? "OPEN" : "DONE");
                inv_s(v, "path", path);
                inv_s(v, "text", text);
                inv_i(v, "line", line);
                inv_end(v);
                free(path);
                free(text);
            }
        }
        p = e + 1;
    }
    free(s);
}

static int cmd_inventory(const char *out_path, int with_tools, const char *self)
{
    Inv v;
    size_t i, total = 0;
    memset(&v, 0, sizeof v);
    load_rpc();
    scan_flags();
    sort_reads();
    inv_rpc(&v);
    inv_args(&v);
    inv_tests(&v);
    inv_qa(&v);
    inv_ci(&v);
    inv_autotools(&v);
    inv_area(&v);
    if (with_tools) inv_tools(&v, self);
    inv_lessons(&v);
    for (i = 0; i < 10; i++) total += v.counts[i];
    if (!v.counts[0] || !v.counts[1]) die("hollow inventory: no rpc or arg records");
    write_out(out_path, v.b.p, v.b.n);
    if (g_json) {
        printf("{\"generated\":\"inventory\",\"records\":%zu,\"out\":\"%s\",\"kinds\":{", total, out_path);
        for (i = 0; i < 10; i++) printf("%s\"%s\":%zu", i ? "," : "", g_inv_kinds[i], v.counts[i]);
        printf("}}\n");
    } else {
        printf("inventory: %zu records -> %s\n", total, out_path);
        for (i = 0; i < 10; i++) printf("  %-17s %zu\n", g_inv_kinds[i], v.counts[i]);
    }
    free(v.b.p);
    return 0;
}

/* ---- self-test and main ------------------------------------------------------------ */
static int g_fail;
#define EXPECT(cond) do { if (!(cond)) { fprintf(stderr, "selftest FAIL line %d: %s\n", __LINE__, #cond); g_fail++; } } while (0)

static int selftest(void)
{
    const char *src = "\"a\\n\" \"b\\\"c\" + HelpExampleCli(\"x\", \"1 2\") + foo(3)";
    Buf b = {0, 0, 0};
    render_expr(src, 0, strlen(src), &b);
    EXPECT(!strcmp(buf_str(&b), "a\nb\"c> zclassic-cli x 1 2\n{foo(...)}"));
    free(b.p);
    EXPECT(usage_argc("f", "f") == 0);
    EXPECT(usage_argc("f", "f \"a\" ( b c )\nrest") == 3);
    EXPECT(usage_argc("f", "f \"a\" {\"k\":1,\"j\": 2} [x, y] ( z )") == 4);
    EXPECT(usage_argc("f", "f a ...") == -1);
    EXPECT(usage_argc("f", "g a") == -1);
    EXPECT(usage_argc("f", "f a|b") == 1);
    {
        const char *t = "x  /* c */ // d\n y";
        EXPECT(skip_ws(t, strlen(t), 1) == strlen(t) - 1);
        EXPECT(match_close("(a(\")\")b)c", 10, 0) == 8);
    }
    {
        char *fl = flag_at("-rpcport=8", 10, 0, NULL);
        EXPECT(!strcmp(fl, "-rpcport"));
        free(fl);
    }
    if (g_fail) return 1;
    puts("zcl-dev-gen selftest ok");
    return 0;
}

static void usage(void)
{
    fputs("usage: zcl-dev gen rpc-reference|args-reference|inventory [--out=FILE] [--json] [--no-tools]\n"
          "       zcl-dev gen --check rpc-parity|flags [--baseline=FILE] [--update-baseline] [--json] [--after=N]\n"
          "       zcl-dev gen --selftest\n"
          "run from the repository root, or pass --root=DIR. exit: 0 ok, 1 finding, 2 broken or hollow scan\n", stderr);
}

int main(int argc, char **argv)
{
    const char *mode = NULL, *check = NULL, *out = NULL, *baseline = NULL, *root = NULL, *rpc_base;
    int update = 0, with_tools = 1, a;
    g_after = -1;
    for (a = 1; a < argc; a++) {
        const char *s = argv[a];
        if (!strcmp(s, "--purpose")) { puts("generated RPC/argument references, capability inventory, parity gates"); return 0; }
        if (!strcmp(s, "--selftest")) return selftest();
        if (!strcmp(s, "-C") && a + 1 < argc) root = argv[++a];
        else if (starts_with(s, "--root=")) root = s + 7;
        else if (!strcmp(s, "--check") && a + 1 < argc) check = argv[++a];
        else if (starts_with(s, "--check=")) check = s + 8;
        else if (starts_with(s, "--out=")) out = s + 6;
        else if (starts_with(s, "--baseline=")) baseline = s + 11;
        else if (!strcmp(s, "--update-baseline")) update = 1;
        else if (!strcmp(s, "--json")) g_json = 1;
        else if (!strcmp(s, "--no-tools")) with_tools = 0;
        else if (starts_with(s, "--after=")) g_after = atoi(s + 8);
        else if (!strcmp(s, "--from-node")) die("--from-node is not implemented in this build");
        else if (s[0] == '-') { usage(); return 2; }
        else if (!mode) mode = s;
        else { usage(); return 2; }
    }
    if (root && chdir(root) != 0) die("cannot enter %s", root);
    rpc_base = baseline ? baseline : RPC_BASELINE_DEFAULT;
    if (!baseline) baseline = BASELINE_DEFAULT;
    if (check) {
        if (!strcmp(check, "rpc-parity")) return check_rpc_parity(rpc_base, update);
        if (!strcmp(check, "flags")) return check_flags(baseline, update);
        usage();
        return 2;
    }
    if (!mode) { usage(); return 2; }
    if (!strcmp(mode, "rpc-reference")) return cmd_rpc_reference(out ? out : RPC_REF_DEFAULT);
    if (!strcmp(mode, "args-reference")) return cmd_args_reference(out ? out : ARGS_REF_DEFAULT, baseline);
    if (!strcmp(mode, "inventory")) return cmd_inventory(out ? out : INV_DEFAULT, with_tools, argv[0]);
    usage();
    return 2;
}
