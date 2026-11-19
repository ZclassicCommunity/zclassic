/*
 * zcl-dev-compdb: compile_commands.json for clangd from a configured (in-tree or out-of-tree) build.
 *
 * It runs `make -n -B -w -C <build-dir>/<subdir>` (argv, no shell, LC_ALL=C), follows make's
 * Entering/Leaving directory lines and turns every compile recipe into one database entry.
 * Libc only; builds with the host cc, clang and x86_64-w64-mingw32-gcc (-D__USE_MINGW_ANSI_STDIO=1).
 * It also builds alone: cc -std=gnu17 -o zcl-dev-compdb zcl-dev-compdb.c
 * Behaviour modelled on Z23 tools/dev/generate-compdb.sh (dry-run recipes become the database);
 * written anew in C, no Z23 text copied.
 *
 * usage: zcl-dev compdb [--build-dir DIR] [--out PATH] [--subdir src] [--check] [--selftest] [--purpose]
 * Exit: 0 written (or --check: fresh), 1 --check found the file stale or missing, 2 broken
 * invocation, no usable make (UNAVAILABLE) or zero entries (hollow).
 * Environment: ZCL_COMPDB_MAKE names the make program (default "make").
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#else
#include <sys/wait.h>
#endif

/* ---------- memory helpers: every allocation is checked ---------- */

typedef struct {
    char *s;
    size_t n, cap;
} Buf;

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fprintf(stderr, "zcl-dev-compdb: out of memory allocating %lu bytes\n", (unsigned long)n);
        exit(2);
    }
    return q;
}

static char *xstrndup(const char *s, size_t n)
{
    char *r = xrealloc(NULL, n + 1);
    memcpy(r, s, n);
    r[n] = 0;
    return r;
}

static void buf_put(Buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->s = xrealloc(b->s, b->cap);
    }
    if (n) memcpy(b->s + b->n, s, n);
    b->n += n;
    b->s[b->n] = 0;
}

static void buf_putc(Buf *b, char c) { buf_put(b, &c, 1); }
static void buf_puts(Buf *b, const char *s) { buf_put(b, s, strlen(s)); }

/* The text as a fresh C string; the buffer is empty afterwards. */
static char *buf_take(Buf *b)
{
    char *r = b->s ? b->s : xstrndup("", 0);
    b->s = NULL;
    b->n = b->cap = 0;
    return r;
}

/* ---------- shell words ---------- */

typedef struct {
    char *s;
    int subst; /* a `$(` or a backtick survived in this word */
} Word;

typedef struct {
    Word *v;
    size_t n, cap;
} Words;

static void words_add(Words *w, char *s, int subst)
{
    if (w->n == w->cap) {
        w->cap = w->cap ? w->cap * 2 : 16;
        w->v = xrealloc(w->v, w->cap * sizeof *w->v);
    }
    w->v[w->n].s = s;
    w->v[w->n].subst = subst;
    w->n++;
}

static void words_free(Words *w)
{
    for (size_t i = 0; i < w->n; i++) free(w->v[i].s);
    free(w->v);
    w->v = NULL;
    w->n = w->cap = 0;
}

typedef struct {
    const char *p;
    Buf cur;
    int subst;
} Lex;

/* After the opener: copy raw up to the matching close (parens nest, a backslash escapes). */
static void lex_group(Lex *x, char open, char close)
{
    int depth = 1;
    x->subst = 1;
    while (*x->p && depth > 0) {
        char c = *x->p++;
        if (c == '\\' && *x->p) {
            buf_putc(&x->cur, c);
            c = *x->p++;
        } else if (c == close) {
            depth--;
        } else if (c == open && open != close) {
            depth++;
        }
        buf_putc(&x->cur, c);
    }
}

/* c was just consumed; returns 1 when it started a backtick or `$(` group (copied raw). */
static int lex_subst(Lex *x, char c)
{
    if (c == '`') {
        buf_putc(&x->cur, c);
        lex_group(x, '`', '`');
        return 1;
    }
    if (c == '$' && *x->p == '(') {
        buf_puts(&x->cur, "$(");
        x->p++;
        lex_group(x, '(', ')');
        return 1;
    }
    return 0;
}

static void lex_squote(Lex *x)
{
    while (*x->p && *x->p != '\'') buf_putc(&x->cur, *x->p++);
    if (*x->p) x->p++;
}

static void lex_dquote(Lex *x)
{
    while (*x->p && *x->p != '"') {
        char c = *x->p++;
        if (c == '\\' && *x->p && strchr("\"\\$`", *x->p)) {
            buf_putc(&x->cur, *x->p++);
        } else if (!lex_subst(x, c)) {
            buf_putc(&x->cur, c);
        }
    }
    if (*x->p) x->p++;
}

static void lex_plain(Lex *x, char c)
{
    if (c == '\'') {
        lex_squote(x);
    } else if (c == '"') {
        lex_dquote(x);
    } else if (c == '\\') {
        if (*x->p) buf_putc(&x->cur, *x->p++);
    } else if (!lex_subst(x, c)) {
        buf_putc(&x->cur, c);
    }
}

static void lex_flush(Lex *x, Words *out)
{
    words_add(out, buf_take(&x->cur), x->subst);
    x->subst = 0;
}

/* Split one command into words: '...', "..." and backslash escapes; nothing else is expanded. */
static void tokenize(const char *s, Words *out)
{
    Lex x = {s, {NULL, 0, 0}, 0};
    int in_word = 0;
    while (*x.p) {
        char c = *x.p++;
        if (isspace((unsigned char)c)) {
            if (in_word) lex_flush(&x, out);
            in_word = 0;
        } else {
            in_word = 1;
            lex_plain(&x, c);
        }
    }
    if (in_word) lex_flush(&x, out);
}

/* ---------- splitting a recipe line on && || ; outside quotes ---------- */

static int is_opener(const char *p)
{
    return (*p && strchr("\\'\"`", *p)) || (p[0] == '$' && p[1] == '(');
}

static const char *skip_quoted(const char *p, char q)
{
    p++;
    while (*p && *p != q) p += (*p == '\\' && p[1] && q != '\'') ? 2 : 1;
    return *p ? p + 1 : p;
}

/* p is at a quote, backslash, backtick or `$(`; returns the position after that item. */
static const char *skip_item(const char *p)
{
    int depth = 1;
    if (*p == '\\') return p[1] ? p + 2 : p + 1;
    if (*p == '\'' || *p == '"' || *p == '`') return skip_quoted(p, *p);
    p += 2;
    while (*p && depth > 0) {
        if (*p == '(') depth++;
        else if (*p == ')') depth--;
        p++;
    }
    return p;
}

/* Length of the command at p; *sep is the length of the separator that ends it (0 at the end). */
static size_t seg_len(const char *p, size_t *sep)
{
    const char *q = p;
    *sep = 0;
    while (*q) {
        if (is_opener(q)) {
            q = skip_item(q);
        } else if (*q == ';') {
            *sep = 1;
            break;
        } else if ((q[0] == '&' && q[1] == '&') || (q[0] == '|' && q[1] == '|')) {
            *sep = 2;
            break;
        } else {
            q++;
        }
    }
    return (size_t)(q - p);
}

/* ---------- recognising a compile ---------- */

static const char *base_name(const char *w)
{
    const char *a = strrchr(w, '/');
    const char *b = strrchr(w, '\\');
    if (b && (!a || b > a)) a = b;
    return a ? a + 1 : w;
}

static int ends_with(const char *s, const char *suf)
{
    size_t n = strlen(s), m = strlen(suf);
    return n >= m && !strcmp(s + n - m, suf);
}

static int is_compiler(const char *word)
{
    static const char *const names[] = {"g++", "gcc", "c++", "cc", "clang", "clang++", NULL};
    static const char *const tails[] = {"-g++", "-gcc", "-clang", "-clang++", NULL};
    char b[128];
    snprintf(b, sizeof b, "%s", base_name(word));
    if (ends_with(b, ".exe")) b[strlen(b) - 4] = 0;
    for (int i = 0; names[i]; i++)
        if (!strcmp(b, names[i])) return 1;
    for (int i = 0; tails[i]; i++)
        if (ends_with(b, tails[i])) return 1;
    return 0;
}

static int is_ccache(const char *w)
{
    const char *b = base_name(w);
    return !strcmp(b, "ccache") || !strcmp(b, "ccache.exe");
}

static int is_assign(const char *s)
{
    if (!isalpha((unsigned char)*s) && *s != '_') return 0;
    while (isalnum((unsigned char)*s) || *s == '_') s++;
    return *s == '=';
}

/* Index where the compile command starts: after --mode=compile or `libtool: compile:`. */
static size_t cmd_start(const Words *w)
{
    for (size_t i = 0; i < w->n; i++) {
        if (!strcmp(w->v[i].s, "--mode=compile")) return i + 1;
        if (i + 1 < w->n && !strcmp(w->v[i].s, "libtool:") && !strcmp(w->v[i + 1].s, "compile:")) return i + 2;
    }
    return 0;
}

/* Leading VAR=value words and a leading ccache are not part of the compile. */
static size_t skip_prefix(const Words *w, size_t i)
{
    while (i < w->n && (is_assign(w->v[i].s) || is_ccache(w->v[i].s))) i++;
    return i;
}

static int is_dep_arg_flag(const char *w) { return !strcmp(w, "-MT") || !strcmp(w, "-MF") || !strcmp(w, "-MQ"); }

static int is_dep_flag(const char *w)
{
    return !strcmp(w, "-MD") || !strcmp(w, "-MMD") || !strcmp(w, "-MP") || !strcmp(w, "-MG");
}

/* Copy the words from `first` on into `out`, minus the dependency-file flags. */
static void filter_args(const Words *w, size_t first, Words *out)
{
    for (size_t i = first; i < w->n; i++) {
        if (is_dep_arg_flag(w->v[i].s)) {
            i++;
        } else if (!is_dep_flag(w->v[i].s)) {
            words_add(out, xstrndup(w->v[i].s, strlen(w->v[i].s)), w->v[i].subst);
        }
    }
}

static int takes_arg(const char *w)
{
    static const char *const flags[] = {"-o", "-x", "-include", "-imacros", "-I", "-isystem", "-iquote",
                                        "-idirafter", "-D", "-U", "-isysroot", "-Xclang", NULL};
    for (int i = 0; flags[i]; i++)
        if (!strcmp(w, flags[i])) return 1;
    return 0;
}

static int is_source(const char *s)
{
    return ends_with(s, ".c") || ends_with(s, ".cc") || ends_with(s, ".cpp") || ends_with(s, ".cxx");
}

/* Number of source words after the compiler word; *src is the index of the last one. */
static int count_sources(const Words *a, size_t *src)
{
    int n = 0;
    for (size_t i = 1; i < a->n; i++) {
        const char *s = a->v[i].s;
        if (s[0] == '-' || takes_arg(a->v[i - 1].s)) continue;
        if (is_source(s)) {
            n++;
            *src = i;
        }
    }
    return n;
}

static int has_dash_c(const Words *a)
{
    for (size_t i = 1; i < a->n; i++)
        if (!strcmp(a->v[i].s, "-c")) return 1;
    return 0;
}

static int any_subst(const Words *a)
{
    for (size_t i = 0; i < a->n; i++)
        if (a->v[i].subst) return 1;
    return 0;
}

/* ---------- paths ---------- */

static size_t abs_prefix(const char *s)
{
    if (s[0] == '/') return 1;
    if (isalpha((unsigned char)s[0]) && s[1] == ':' && s[2] == '/') return 3;
    return 0;
}

static int is_abs_path(const char *s) { return abs_prefix(s) > 0; }

static void norm_component(Buf *out, size_t pre, const char *c, size_t n)
{
    if (n == 0 || (n == 1 && c[0] == '.')) return;
    if (n == 2 && c[0] == '.' && c[1] == '.') {
        size_t i = out->n;
        while (i > pre && out->s[i - 1] != '/') i--;
        out->n = i > pre ? i - 1 : pre;
        out->s[out->n] = 0;
        return;
    }
    if (out->n > pre) buf_putc(out, '/');
    buf_put(out, c, n);
}

/* dir/file made absolute with `.` and `..` collapsed lexically. */
static char *join_norm(const char *dir, const char *file)
{
    Buf f = {NULL, 0, 0}, out = {NULL, 0, 0};
    if (!is_abs_path(file)) {
        buf_puts(&f, dir);
        buf_putc(&f, '/');
    }
    buf_puts(&f, file);
#ifdef _WIN32
    for (size_t i = 0; i < f.n; i++)
        if (f.s[i] == '\\') f.s[i] = '/';
#endif
    size_t pre = abs_prefix(f.s);
    buf_put(&out, f.s, pre);
    for (const char *p = f.s + pre; *p;) {
        size_t n = strcspn(p, "/");
        norm_component(&out, pre, p, n);
        p += n;
        if (*p == '/') p++;
    }
    free(f.s);
    return buf_take(&out);
}

/* ---------- the database ---------- */

typedef struct {
    char *dir, *file;
    Words args;
    size_t seq;
} Entry;

typedef struct {
    Entry *v;
    size_t n, cap, skipped, duplicates;
} Db;

static void db_push(Db *db, const char *dir, const char *src, Words *args)
{
    if (db->n == db->cap) {
        db->cap = db->cap ? db->cap * 2 : 256;
        db->v = xrealloc(db->v, db->cap * sizeof *db->v);
    }
    Entry *e = &db->v[db->n];
    e->dir = xstrndup(dir, strlen(dir));
    e->file = join_norm(dir, src);
    e->args = *args;
    e->seq = db->n++;
}

/* args is consumed: moved into the database or freed. */
static void consider(Db *db, Words *a, const char *dir)
{
    size_t src = 0;
    int candidate = a->n > 1 && (is_compiler(a->v[0].s) || a->v[0].subst);
    if (!candidate || !has_dash_c(a) || count_sources(a, &src) != 1) {
        words_free(a);
        return;
    }
    if (any_subst(a)) {
        db->skipped++;
        words_free(a);
        return;
    }
    db_push(db, dir, a->v[src].s, a);
}

static void add_segment(Db *db, const char *seg, size_t len, const char *dir)
{
    char *copy = xstrndup(seg, len);
    Words w = {NULL, 0, 0}, a = {NULL, 0, 0};
    tokenize(copy, &w);
    free(copy);
    filter_args(&w, skip_prefix(&w, cmd_start(&w)), &a);
    words_free(&w);
    consider(db, &a, dir);
}

static int entry_cmp(const void *x, const void *y)
{
    const Entry *a = x, *b = y;
    int c = strcmp(a->file, b->file);
    if (c) return c;
    return a->seq < b->seq ? -1 : a->seq > b->seq;
}

static void entry_free(Entry *e)
{
    free(e->dir);
    free(e->file);
    words_free(&e->args);
}

/* Sort by file, keep the first of each file and count the rest as duplicates. */
static void db_finish(Db *db)
{
    size_t keep = 0;
    qsort(db->v, db->n, sizeof *db->v, entry_cmp);
    for (size_t i = 0; i < db->n; i++) {
        if (keep && !strcmp(db->v[keep - 1].file, db->v[i].file)) {
            db->duplicates++;
            entry_free(&db->v[i]);
        } else {
            db->v[keep++] = db->v[i];
        }
    }
    db->n = keep;
}

static void db_free(Db *db)
{
    for (size_t i = 0; i < db->n; i++) entry_free(&db->v[i]);
    free(db->v);
    memset(db, 0, sizeof *db);
}

/* ---------- make output ---------- */

typedef struct {
    char **v;
    size_t n, cap;
} Dirs;

static void dirs_push(Dirs *d, const char *s, size_t len)
{
    if (d->n == d->cap) {
        d->cap = d->cap ? d->cap * 2 : 16;
        d->v = xrealloc(d->v, d->cap * sizeof *d->v);
    }
    d->v[d->n++] = xstrndup(s, len);
}

static void dirs_pop(Dirs *d)
{
    if (d->n > 1) free(d->v[--d->n]);
}

/* The next logical line: backslash-continued physical lines are joined with a space. */
static char *next_line(const char **pp)
{
    Buf b = {NULL, 0, 0};
    const char *p = *pp;
    for (;;) {
        size_t n = strcspn(p, "\n"), m = n;
        if (m && p[m - 1] == '\r') m--;
        int cont = m && p[m - 1] == '\\';
        buf_put(&b, p, cont ? m - 1 : m);
        p += n;
        if (*p == '\n') p++;
        if (!cont) break;
        buf_putc(&b, ' ');
        if (!*p) break;
    }
    *pp = p;
    return buf_take(&b);
}

/* "make[1]: Entering directory '/x'" style message; returns the quoted text or NULL. */
static const char *make_msg(const char *line, const char *what, size_t *len)
{
    if (strncmp(line, "make", 4) && strncmp(line, "gmake", 5)) return NULL;
    const char *m = strstr(line, what);
    if (!m) return NULL;
    const char *a = strchr(m, '\'');
    const char *z = strrchr(m, '\'');
    if (!a || z <= a) return NULL;
    *len = (size_t)(z - a - 1);
    return a + 1;
}

static void handle_line(const char *line, Db *db, Dirs *d)
{
    size_t len = 0, sep = 0;
    const char *dir = make_msg(line, ": Entering directory", &len);
    if (dir) {
        dirs_push(d, dir, len);
        return;
    }
    if (make_msg(line, ": Leaving directory", &len)) {
        dirs_pop(d);
        return;
    }
    for (const char *p = line; *p;) {
        size_t n = seg_len(p, &sep);
        add_segment(db, p, n, d->v[d->n - 1]);
        p += n + sep;
    }
}

static void parse_make(const char *text, const char *initial_dir, Db *db)
{
    Dirs d = {NULL, 0, 0};
    dirs_push(&d, initial_dir, strlen(initial_dir));
    for (const char *p = text; *p;) {
        char *line = next_line(&p);
        handle_line(line, db, &d);
        free(line);
    }
    while (d.n) free(d.v[--d.n]);
    free(d.v);
}

/* ---------- JSON ---------- */

static void json_str(Buf *b, const char *s)
{
    buf_putc(b, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        char tmp[8];
        if (c == '"' || c == '\\') {
            buf_putc(b, '\\');
            buf_putc(b, (char)c);
        } else if (c == '\n' || c == '\t' || c == '\r') {
            buf_puts(b, c == '\n' ? "\\n" : c == '\t' ? "\\t" : "\\r");
        } else if (c < 0x20) {
            snprintf(tmp, sizeof tmp, "\\u%04x", c);
            buf_puts(b, tmp);
        } else {
            buf_putc(b, (char)c);
        }
    }
    buf_putc(b, '"');
}

static void json_db(Buf *b, const Db *db)
{
    buf_puts(b, "[\n");
    for (size_t i = 0; i < db->n; i++) {
        const Entry *e = &db->v[i];
        buf_puts(b, "{\"directory\": ");
        json_str(b, e->dir);
        buf_puts(b, ", \"file\": ");
        json_str(b, e->file);
        buf_puts(b, ", \"arguments\": [");
        for (size_t k = 0; k < e->args.n; k++) {
            if (k) buf_puts(b, ", ");
            json_str(b, e->args.v[k].s);
        }
        buf_puts(b, i + 1 < db->n ? "]},\n" : "]}\n");
    }
    buf_puts(b, "]\n");
}

/* ---------- running make ---------- */

/* Run argv with stdout sent to fd. Returns the exit status, or -1 when it cannot start. */
static int run_to_fd(char *const *argv, int fd)
{
#ifdef _WIN32
    _putenv("LC_ALL=C");
    _putenv("MAKEFLAGS=");
    _putenv("MFLAGS=");
    _putenv("MAKELEVEL=");
    fflush(NULL);
    int save = _dup(1);
    if (save < 0 || _dup2(fd, 1) < 0) return -1;
    intptr_t r = _spawnvp(_P_WAIT, argv[0], (const char *const *)argv);
    _dup2(save, 1);
    _close(save);
    return r == -1 ? -1 : (int)r;
#else
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setenv("LC_ALL", "C", 1);
        unsetenv("MAKEFLAGS");
        unsetenv("MFLAGS");
        unsetenv("MAKELEVEL");
        if (dup2(fd, 1) >= 0) execvp(argv[0], argv);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    if (WIFEXITED(st)) return WEXITSTATUS(st) == 127 ? -1 : WEXITSTATUS(st);
    return 128;
#endif
}

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    Buf b = {NULL, 0, 0};
    char chunk[8192];
    size_t n;
    if (!f) return NULL;
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) buf_put(&b, chunk, n);
    fclose(f);
    *len = b.n;
    return buf_take(&b);
}

/* make -n -B -w -C dir: its stdout, or NULL on failure (*rc = -1 when make cannot run). */
static char *make_dry_run(const char *dir, const char *scratch, int *rc)
{
    const char *make = getenv("ZCL_COMPDB_MAKE");
    char *argv[8];
    size_t len = 0;
    FILE *f = fopen(scratch, "wb+");
    char *text;
    if (!f) {
        fprintf(stderr, "zcl-dev-compdb: cannot create %s: %s\n", scratch, strerror(errno));
        *rc = 2;
        return NULL;
    }
    argv[0] = (char *)(make && *make ? make : "make");
    argv[1] = "-n";
    argv[2] = "-B";
    argv[3] = "-w";
    argv[4] = "-C";
    argv[5] = (char *)dir;
    argv[6] = NULL;
    *rc = run_to_fd(argv, fileno(f));
    fclose(f);
    text = read_file(scratch, &len);
    remove(scratch);
    return text;
}

/* ---------- command line ---------- */

typedef struct {
    const char *build_dir, *out, *subdir;
    int check, selftest;
} Opts;

static int opt_value(int argc, char **argv, int *i, const char *name, const char **out)
{
    size_t n = strlen(name);
    const char *a = argv[*i];
    if (strncmp(a, name, n)) return 0;
    if (a[n] == '=') {
        *out = a + n + 1;
        return 1;
    }
    if (a[n]) return 0;
    if (*i + 1 >= argc) {
        fprintf(stderr, "zcl-dev-compdb: %s needs a value\n", name);
        return -1;
    }
    *out = argv[++*i];
    return 1;
}

static int parse_value_opt(int argc, char **argv, int *i, Opts *o)
{
    static const char *const names[] = {"--build-dir", "--out", "--subdir"};
    const char **fields[3];
    fields[0] = &o->build_dir;
    fields[1] = &o->out;
    fields[2] = &o->subdir;
    for (int k = 0; k < 3; k++) {
        int r = opt_value(argc, argv, i, names[k], fields[k]);
        if (r) return r;
    }
    return 0;
}

/* Returns 0 to continue, or 1000 + exit status when the process should stop. */
static int parse_args(int argc, char **argv, Opts *o)
{
    for (int i = 1; i < argc; i++) {
        int r;
        if (!strcmp(argv[i], "--check")) {
            o->check = 1;
        } else if (!strcmp(argv[i], "--selftest")) {
            o->selftest = 1;
        } else if (!strcmp(argv[i], "--purpose")) {
            puts("compile_commands.json for clangd from a configured out-of-tree build");
            return 1000;
        } else if ((r = parse_value_opt(argc, argv, &i, o)) < 0) {
            return 1002;
        } else if (r == 0) {
            fprintf(stderr, "zcl-dev-compdb: unknown argument '%s'\n", argv[i]);
            fputs("usage: zcl-dev compdb [--build-dir DIR] [--out PATH] [--subdir src] [--check]\n", stderr);
            return 1002;
        }
    }
    return 0;
}

/* The repo root: the nearest directory at or above cwd holding configure.ac, else cwd. */
static char *find_root(void)
{
    char cwd[4096], probe[4200];
    struct stat st;
    if (!getcwd(cwd, sizeof cwd)) return NULL;
    char *work = join_norm(cwd, ".");
    size_t pre = abs_prefix(work);
    for (;;) {
        snprintf(probe, sizeof probe, "%s/configure.ac", work);
        if (stat(probe, &st) == 0) return work;
        size_t n = strlen(work);
        while (n > pre && work[n - 1] != '/') n--;
        if (n <= pre) break;
        work[n - 1] = 0;
    }
    free(work);
    return join_norm(cwd, ".");
}

/* ---------- generate / check / write ---------- */

typedef struct {
    char *root, *dir, *out;
} Paths;

static int resolve_paths(const Opts *o, Paths *p)
{
    char cwd[4096];
    p->root = find_root();
    if (!p->root || !getcwd(cwd, sizeof cwd)) {
        fprintf(stderr, "zcl-dev-compdb: cannot determine the current directory\n");
        return 2;
    }
    char *bd = join_norm(o->build_dir ? cwd : p->root, o->build_dir ? o->build_dir : ".");
    p->dir = o->subdir && *o->subdir ? join_norm(bd, o->subdir) : bd;
    if (p->dir != bd) free(bd);
    p->out = join_norm(o->out ? cwd : p->root, o->out ? o->out : "compile_commands.json");
    return 0;
}

static int write_atomic(const char *path, const Buf *b)
{
    char tmp[4200];
    snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid());
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        fprintf(stderr, "zcl-dev-compdb: cannot write %s: %s\n", tmp, strerror(errno));
        return 2;
    }
    int bad = fwrite(b->s, 1, b->n, f) != b->n;
    bad |= fclose(f) != 0;
#ifdef _WIN32
    if (!bad) remove(path);
#endif
    if (!bad && rename(tmp, path) != 0) bad = 1;
    if (bad) {
        fprintf(stderr, "zcl-dev-compdb: cannot replace %s: %s\n", path, strerror(errno));
        remove(tmp);
        return 2;
    }
    return 0;
}

/* Append one printf-formatted message line to the log (printed to stderr by main). */
static void log_line(Buf *log, const char *fmt, ...)
{
    char line[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    buf_puts(log, line);
    buf_putc(log, '\n');
}

/* Build the database JSON into json; returns 0, or an exit status for a failure. */
static int generate(const Paths *p, Buf *json, Buf *log)
{
    int rc = 0;
    char scratch[4200];
    Db db = {NULL, 0, 0, 0, 0};
    snprintf(scratch, sizeof scratch, "%s.make.%ld", p->out, (long)getpid());
    char *text = make_dry_run(p->dir, scratch, &rc);
    if (!text || rc < 0) {
        free(text);
        if (rc < 0) log_line(log, "zcl-dev-compdb: UNAVAILABLE: cannot run make (set ZCL_COMPDB_MAKE)");
        return 2;
    }
    if (rc != 0) log_line(log, "zcl-dev-compdb: warning: make exited %d in %s", rc, p->dir);
    parse_make(text, p->dir, &db);
    free(text);
    db_finish(&db);
    log_line(log, "entries %lu, skipped %lu, duplicates %lu", (unsigned long)db.n, (unsigned long)db.skipped,
             (unsigned long)db.duplicates);
    rc = db.n ? 0 : 2;
    if (rc) log_line(log, "zcl-dev-compdb: no compile commands under %s (not configured? hollow)", p->dir);
    json_db(json, &db);
    db_free(&db);
    return rc;
}

/* Generate, then write the file or (--check) compare with it. Messages go to log. */
static int run_compdb(const Opts *o, Buf *log)
{
    Paths p = {NULL, NULL, NULL};
    Buf json = {NULL, 0, 0};
    int rc = resolve_paths(o, &p);
    if (!rc) rc = generate(&p, &json, log);
    if (!rc && o->check) {
        size_t len = 0;
        char *old = read_file(p.out, &len);
        rc = old && len == json.n && !memcmp(old, json.s, len) ? 0 : 1;
        log_line(log, "%s: %s", p.out, rc ? "stale" : "fresh");
        free(old);
    } else if (!rc) {
        rc = write_atomic(p.out, &json);
    }
    free(json.s);
    free(p.root);
    free(p.dir);
    free(p.out);
    return rc;
}

/* ---------- selftest ---------- */

#define CHECK(c)                                                          \
    do {                                                                  \
        if (!(c)) {                                                       \
            fprintf(stderr, "selftest FAIL line %d: %s\n", __LINE__, #c); \
            return 1;                                                     \
        }                                                                 \
    } while (0)

static int st_tokens(void)
{
    Words w = {NULL, 0, 0};
    tokenize("g++ -DA=\"\\\"x y\\\"\" -DQ='a b' c\\ d '' -DV=$(echo 1)", &w);
    CHECK(w.n == 6);
    CHECK(!strcmp(w.v[1].s, "-DA=\"x y\""));
    CHECK(!strcmp(w.v[2].s, "-DQ=a b"));
    CHECK(!strcmp(w.v[3].s, "c d") && !w.v[3].subst);
    CHECK(w.v[4].s[0] == 0);
    CHECK(w.v[5].subst);
    words_free(&w);
    return 0;
}

static int st_split(void)
{
    size_t sep = 0;
    const char *s = "a 'x;y' \"&&\" `p;q` $(r;s) && b ; c";
    size_t n = seg_len(s, &sep);
    CHECK(sep == 2 && n == strlen("a 'x;y' \"&&\" `p;q` $(r;s) "));
    s += n + sep;
    n = seg_len(s, &sep);
    CHECK(sep == 1 && n == 3);
    n = seg_len(s + n + sep, &sep);
    CHECK(sep == 0 && n == 2);
    return 0;
}

static int st_paths(void)
{
    char *p = join_norm("/a/b/c", "../../x/./y.cc");
    CHECK(!strcmp(p, "/a/x/y.cc"));
    free(p);
    p = join_norm("/a", "/abs//f.c");
    CHECK(!strcmp(p, "/abs/f.c"));
    free(p);
    p = join_norm("/a", "../../..");
    CHECK(!strcmp(p, "/"));
    free(p);
    CHECK(is_compiler("/usr/bin/x86_64-w64-mingw32-g++.exe") && is_compiler("ccache") == 0);
    CHECK(is_compiler("clang++") && !is_compiler("mv"));
    return 0;
}

static int st_parse(void)
{
    Db db = {NULL, 0, 0, 0, 0};
    const char *text =
        "make: Entering directory '/r/src'\n"
        "ccache g++ -DX -MT a.o -MD -MP -MF .deps/a.Tpo -c -o a.o ../src/a.cc \\\n  -O2\n"
        "make[1]: Entering directory '/r/src/sub'\n"
        "depbase=`echo b.lo | sed 's|;||'`;\\\n/bin/sh ./libtool --tag=CXX --mode=compile gcc -c b.c && mv x y\n"
        "make[1]: Leaving directory '/r/src/sub'\n"
        "g++ -DV=$(echo 1) -c -o s.o s.cc\n"
        "g++ -c -o a2.o a.cc\n"
        "make: Leaving directory '/r/src'\n";
    parse_make(text, "/r/src", &db);
    db_finish(&db);
    CHECK(db.n == 2 && db.skipped == 1 && db.duplicates == 1);
    CHECK(!strcmp(db.v[0].file, "/r/src/a.cc") && !strcmp(db.v[0].dir, "/r/src"));
    CHECK(db.v[0].args.n == 7 && !strcmp(db.v[0].args.v[0].s, "g++"));
    CHECK(!strcmp(db.v[1].file, "/r/src/sub/b.c") && !strcmp(db.v[1].dir, "/r/src/sub"));
    db_free(&db);
    return 0;
}

static int selftest(void)
{
    if (st_tokens() || st_split() || st_paths() || st_parse()) return 1;
    puts("zcl-dev-compdb selftest ok");
    return 0;
}

int main(int argc, char **argv)
{
    Opts o = {NULL, NULL, "src", 0, 0};
    int r = parse_args(argc, argv, &o);
    if (r) return r - 1000;
    if (o.selftest) return selftest();
    Buf log = {NULL, 0, 0};
    r = run_compdb(&o, &log);
    if (log.s) fputs(log.s, stderr);
    free(log.s);
    return r;
}
