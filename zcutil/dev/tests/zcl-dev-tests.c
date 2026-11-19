/* zcl-dev-tests: focused C++ test selection for the zclassicd tree. MIT, like the rest of zclassicd.
 * Plain C, libc only, compiles as gnu17 and (with a C23 compiler) as C23. Builds with the host cc,
 * x86_64-w64-mingw32-gcc and macOS clang. The glob matcher is Z23's platform/glob_match.h, vendored
 * verbatim under zcutil/tools/vendor. The behaviour follows Z23's `t-fast`, `code tests` and the
 * test registration gate (gate_test_registration.c); the code is new.
 *
 * One binary serves four commands, chosen by its own file name (zcl-dev dispatches to
 * zcl-dev-<cmd>, and the Makefile installs one copy per name):
 *
 *   zcl-dev tests [--json] <path>...                       the focused test set
 *   zcl-dev t-fast [--changed[=base]] [--dry-run] [--narrow] [--no-qa] [--json]
 *                  [--bin=src] [<path>...]                 run it
 *   zcl-dev t-list [--json] [--after=N] [boost|gtest|qa|ci] every registered test and CI step
 *   zcl-dev check-tests [--json] [--after=N]               the registration gate
 *
 * A direct run takes `-C dir` first and `--as=<cmd>` for the command (the self-test uses neither).
 * Exit codes: 0 ok, 1 finding or failed test, 2 broken input or empty scan, 3 binary missing/stale.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#define chdir _chdir
#define dup _dup
#define dup2 _dup2
#define close _close
#define EXE_SUFFIX ".exe"
#else
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>
#define EXE_SUFFIX ""
#endif

#include "platform/modules/platform/include/platform/glob_match.h"

#define IMPACT_FILE "zcutil/dev/impact.rules"
#define RULES_FILE "zcutil/dev/tests.rules"
#define CI_FILE "zcutil/local-ci.sh"
#define BOOST_INC "src/Makefile.test.include"
#define GTEST_INC "src/Makefile.gtest.include"
#define PAGE_BYTES 15000 /* output stays under 16 KiB per page */
#define WORK_DIR "zcutil/gen/t-fast-work"

typedef struct { char **v; size_t n, cap; } List;

static void die(const char *fmt, ...)
{
    va_list ap;
    fputs("zcl-dev-tests: ", stderr);
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

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(xrealloc(NULL, n), s, n);
}

static char *xvfmt(const char *fmt, va_list ap)
{
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    if (n < 0) die("format error");
    char *s = xrealloc(NULL, (size_t)n + 1);
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

static char *xfmt(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *s = xvfmt(fmt, ap);
    va_end(ap);
    return s;
}

static void list_push(List *l, const char *s)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 16;
        l->v = xrealloc(l->v, l->cap * sizeof *l->v);
    }
    l->v[l->n++] = xstrdup(s);
}

/* list_push of a malloc()ed string that is then freed. */
static void list_push_free(List *l, char *s)
{
    list_push(l, s);
    free(s);
}

static int list_has(const List *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp(l->v[i], s)) return 1;
    return 0;
}

static void list_add(List *l, const char *s)
{
    if (!list_has(l, s)) list_push(l, s);
}

static int str_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
static void list_sort(List *l) { if (l->n > 1) qsort(l->v, l->n, sizeof *l->v, str_cmp); }

static char *join(const List *l, const char *sep)
{
    size_t len = 1, sl = strlen(sep);
    for (size_t i = 0; i < l->n; i++) len += strlen(l->v[i]) + sl;
    char *r = xrealloc(NULL, len), *p = r;
    *p = 0;
    for (size_t i = 0; i < l->n; i++) {
        if (i) { memcpy(p, sep, sl); p += sl; }
        size_t n = strlen(l->v[i]);
        memcpy(p, l->v[i], n);
        p += n;
    }
    *p = 0;
    return r;
}

static void read_lines(FILE *f, List *out)
{
    size_t cap = 256, n = 0;
    char *buf = xrealloc(NULL, cap);
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (c == '\n') {
            while (n && buf[n - 1] == '\r') n--;
            buf[n] = 0;
            list_push(out, buf);
            n = 0;
            continue;
        }
        if (n + 2 > cap) buf = xrealloc(buf, cap *= 2);
        buf[n++] = (char)c;
    }
    if (n) { buf[n] = 0; list_push(out, buf); }
    free(buf);
}

static int file_lines(const char *path, List *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    read_lines(f, out);
    fclose(f);
    return 0;
}

static int cmd_lines(const char *cmd, List *out)
{
    FILE *p = popen(cmd, "r");
    if (!p) die("cannot run: %s", cmd);
    read_lines(p, out);
    return pclose(p);
}

static int has_prefix(const char *s, const char *p) { return !strncmp(s, p, strlen(p)); }

static int has_suffix(const char *s, const char *x)
{
    size_t a = strlen(s), b = strlen(x);
    return a >= b && !strcmp(s + a - b, x);
}

static int ci_eq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    return !*a && !*b;
}

static int safe_ref(const char *s)
{
    if (!*s || *s == '-') return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && !strchr("._/~^@-", *s)) return 0;
    return 1;
}

static void split_words(const char *s, const char *seps, List *out)
{
    char *c = xstrdup(s), *p = c;
    while (*p) {
        size_t n = strcspn(p, seps);
        if (n) { char save = p[n]; p[n] = 0; list_push(out, p); p[n] = save; }
        p += n + (p[n] ? 1 : 0);
    }
    free(c);
}

/* ---- JSON and paging ----------------------------------------------------- */

static void jstr(const char *s)
{
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') printf("\\%c", c);
        else if (c < 0x20) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

static void jlist(const char *key, const List *l, int comma)
{
    jstr(key);
    fputs(":[", stdout);
    for (size_t i = 0; i < l->n; i++) {
        if (i) putchar(',');
        jstr(l->v[i]);
    }
    putchar(']');
    if (comma) putchar(',');
}

/* Print items[after..] while the page stays under PAGE_BYTES; say how to continue. */
static void emit_page(const List *items, int json, size_t after)
{
    size_t total = items->n, i, used = 0, page = PAGE_BYTES;
    const char *env = getenv("ZCL_DEV_PAGE_BYTES"); /* test hook: a small page */
    if (env && strtoul(env, NULL, 10)) page = (size_t)strtoul(env, NULL, 10);
    if (after > total) after = total;
    i = after;
    if (json) printf("{\"total\":%zu,\"after\":%zu,\"items\":[", total, after);
    for (; i < total; i++) {
        size_t len = strlen(items->v[i]) * (json ? 2 : 1) + 4;
        if (i > after && used + len > page) break;
        if (json) { if (i > after) putchar(','); jstr(items->v[i]); }
        else puts(items->v[i]);
        used += len;
    }
    if (json) {
        if (i < total) printf("],\"next\":%zu}\n", i);
        else puts("],\"next\":null}");
    } else if (i < total) {
        printf("-- more: rerun with --after=%zu (%zu of %zu shown)\n", i, i - after, total);
    }
}

static void parse_after(const char *a, size_t *after)
{
    char *end;
    unsigned long v = strtoul(a, &end, 10);
    if (!*a || *end) die("bad --after value '%s'", a);
    *after = (size_t)v;
}

/* ---- repository ---------------------------------------------------------- */

static char prefix[1024]; /* cwd relative to the repo root, with trailing '/' or "" */

static void enter_repo(const char *dir)
{
    List l = {0};
    const char *env = getenv("ZCL_DEV_PREFIX");
    if (dir && chdir(dir)) die("cannot chdir to %s", dir);
    if (cmd_lines("git rev-parse --show-prefix", &l) || l.n > 1) die("not inside a git work tree");
    snprintf(prefix, sizeof prefix, "%s", env ? env : (l.n ? l.v[0] : ""));
    l.n = 0;
    if (cmd_lines("git rev-parse --show-toplevel", &l) || !l.n) die("cannot find the repository root");
    if (chdir(l.v[0])) die("cannot chdir to %s", l.v[0]);
}

static char *norm_path(const char *arg)
{
    char *p = xstrdup(arg), *r;
    for (r = p; *r; r++) if (*r == '\\') *r = '/';
    r = p;
    while (r[0] == '.' && r[1] == '/') r += 2;
    char *out = xfmt("%s%s", r[0] == '/' ? "" : prefix, r);
    free(p);
    return out;
}

static int exists(const char *path)
{
    struct stat st;
    return !stat(path, &st);
}

/* Tracked plus untracked-not-ignored files that exist: an unregistered new test file counts. */
static List files;
static void load_files(void)
{
    List raw = {0};
    if (cmd_lines("git ls-files --cached --others --exclude-standard", &raw)) die("git ls-files failed");
    for (size_t i = 0; i < raw.n; i++)
        if (exists(raw.v[i])) list_add(&files, raw.v[i]);
    if (!files.n) die("git ls-files returned no files: empty scan");
}

/* ---- the test index ------------------------------------------------------ */

typedef struct { char *file; int gtest; List suites; } TFile;
static TFile *tfiles;
static size_t ntfiles;
static const char *const boost_dirs[] = {"src/test/", "src/wallet/test/", NULL};
static const char *const gtest_dirs[] = {"src/gtest/", "src/wallet/gtest/", NULL};

static int in_dir(const char *path, const char *const *dirs)
{
    for (; *dirs; dirs++)
        if (has_prefix(path, *dirs) && !strchr(path + strlen(*dirs), '/') && has_suffix(path, ".cpp")) return 1;
    return 0;
}

static size_t ident_end(const char *s)
{
    size_t n = 0;
    while (isalnum((unsigned char)s[n]) || s[n] == '_') n++;
    return n;
}

/* Suite name declared on this line, or NULL. Boost: the SUITE macros; gtest: TEST, TEST_F, TEST_P. */
static char *suite_of(const char *line, int gtest)
{
    static const char *const bm[] = {"BOOST_FIXTURE_TEST_SUITE(", "BOOST_AUTO_TEST_SUITE(", NULL};
    static const char *const gm[] = {"TEST(", "TEST_F(", "TEST_P(", NULL};
    const char *const *m = gtest ? gm : bm;
    for (; *m; m++) {
        if (!has_prefix(line, *m)) continue;
        const char *a = line + strlen(*m);
        while (*a == ' ' || *a == '\t') a++;
        size_t n = ident_end(a);
        if (!n) return NULL;
        char *r = xrealloc(NULL, n + 1);
        memcpy(r, a, n);
        r[n] = 0;
        return r;
    }
    return NULL;
}

static void scan_file(const char *path, int gtest, TFile *t)
{
    List lines = {0};
    int in_block = 0;
    t->file = xstrdup(path);
    t->gtest = gtest;
    if (file_lines(path, &lines)) die("cannot read %s", path);
    for (size_t i = 0; i < lines.n; i++) {
        char *s = lines.v[i];
        if (in_block) {
            char *e = strstr(s, "*/");
            if (!e) continue;
            s = e + 2;
            in_block = 0;
        }
        while (*s == ' ' || *s == '\t') s++;
        if (s[0] == '/' && s[1] == '/') continue;
        if (s[0] == '/' && s[1] == '*') {
            if (!strstr(s + 2, "*/")) in_block = 1;
            continue;
        }
        char *name = suite_of(s, gtest);
        if (name) { list_add(&t->suites, name); free(name); }
    }
}

static void build_index(void)
{
    ntfiles = 0;
    tfiles = xrealloc(NULL, (files.n + 1) * sizeof *tfiles);
    for (size_t i = 0; i < files.n; i++) {
        int b = in_dir(files.v[i], boost_dirs), g = in_dir(files.v[i], gtest_dirs);
        if (!b && !g) continue;
        memset(&tfiles[ntfiles], 0, sizeof tfiles[0]);
        scan_file(files.v[i], g, &tfiles[ntfiles]);
        ntfiles++;
    }
}

static TFile *tfile_find(const char *path, int ci)
{
    for (size_t i = 0; i < ntfiles; i++)
        if (ci ? ci_eq(tfiles[i].file, path) : !strcmp(tfiles[i].file, path)) return &tfiles[i];
    return NULL;
}

static int suite_known(const char *name, int gtest)
{
    for (size_t i = 0; i < ntfiles; i++)
        if (tfiles[i].gtest == gtest && list_has(&tfiles[i].suites, name)) return 1;
    return 0;
}

/* ---- rule files ---------------------------------------------------------- */

typedef struct { List globs, tokens; size_t line; } Rule;
typedef struct { Rule *v; size_t n; } Rules;

static Rules load_rules(const char *file)
{
    List lines = {0};
    Rules r = {0};
    if (file_lines(file, &lines)) die("cannot read %s", file);
    r.v = xrealloc(NULL, (lines.n + 1) * sizeof *r.v);
    for (size_t i = 0; i < lines.n; i++) {
        char *s = lines.v[i], *tab;
        while (*s == ' ') s++;
        if (!*s || *s == '#') continue;
        tab = strchr(s, '\t');
        if (!tab) die("%s:%zu: missing TAB between globs and tokens", file, i + 1);
        Rule *x = &r.v[r.n++];
        memset(x, 0, sizeof *x);
        x->line = i + 1;
        *tab = 0;
        split_words(s, "|", &x->globs);
        split_words(tab + 1, " \t", &x->tokens);
        if (!x->globs.n || !x->tokens.n) die("%s:%zu: empty globs or tokens", file, i + 1);
    }
    return r;
}

static int rule_match(const Rule *r, const char *path)
{
    for (size_t g = 0; g < r->globs.n; g++)
        if (platform_glob_match(r->globs.v[g], path, false)) return 1;
    return 0;
}

/* ---- selection ----------------------------------------------------------- */

typedef struct {
    List boost, gtest, qa, notes, nofocus, wallet_qt;
    int broad, narrowed;
    char *why;
} Sel;

static int is_doc_path(const char *p) { return has_prefix(p, "doc/") || has_suffix(p, ".md"); }

static int is_cxx_path(const char *p)
{
    static const char *const ext[] = {".cpp", ".cc", ".c", ".h", ".hpp", NULL};
    for (const char *const *e = ext; *e; e++) if (has_suffix(p, *e)) return 1;
    return 0;
}

static int is_qa_script(const char *p)
{
    return has_prefix(p, "qa/rpc-tests/") && has_suffix(p, ".sh") && !strchr(p + 13, '/') && !has_suffix(p, "_lib.sh");
}

static void add_tfile(Sel *s, const TFile *t)
{
    for (size_t i = 0; i < t->suites.n; i++) list_add(t->gtest ? &s->gtest : &s->boost, t->suites.v[i]);
}

/* Heuristic (b): src/foo.cpp or src/x/foo.h maps to src/test/foo_tests.cpp, src/gtest/test_foo.cpp
 * and the same names beside the source (src/wallet/test, src/wallet/gtest). Case-insensitive. */
static void heuristic(Sel *s, const char *p)
{
    if (!has_prefix(p, "src/") || !is_cxx_path(p)) return;
    const char *slash = strrchr(p, '/'), *dot = strrchr(p, '.');
    if (dot < slash) return;
    char *dir = xrealloc(NULL, (size_t)(slash - p) + 1), *base = xrealloc(NULL, (size_t)(dot - slash));
    memcpy(dir, p, (size_t)(slash - p));
    dir[slash - p] = 0;
    memcpy(base, slash + 1, (size_t)(dot - slash - 1));
    base[dot - slash - 1] = 0;
    char *cand[4] = {xfmt("%s/test/%s_tests.cpp", dir, base), xfmt("src/test/%s_tests.cpp", base),
                     xfmt("%s/gtest/test_%s.cpp", dir, base), xfmt("src/gtest/test_%s.cpp", base)};
    for (int i = 0; i < 4; i++) {
        TFile *t = tfile_find(cand[i], 1);
        if (t) add_tfile(s, t);
        free(cand[i]);
    }
    free(dir);
    free(base);
}

static void add_token(Sel *s, const char *tk, int *narrow)
{
    if (has_prefix(tk, "boost:")) list_add(&s->boost, tk + 6);
    else if (has_prefix(tk, "gtest:")) list_add(&s->gtest, tk + 6);
    else if (has_prefix(tk, "qa:")) list_add(&s->qa, tk + 3);
    else if (!strcmp(tk, "narrow")) *narrow = 1;
}

/* Broad when impact.rules marks the path ALL, or matches no rule (an unmapped source is never narrowed). */
static int impact_broad(const Rules *impact, const char *path, char **why)
{
    int hit = 0;
    for (size_t i = 0; i < impact->n; i++) {
        if (!rule_match(&impact->v[i], path)) continue;
        hit = 1;
        if (list_has(&impact->v[i].tokens, "ALL")) { *why = xfmt("broad rule: %s", path); return 1; }
    }
    if (!hit) { *why = xfmt("unmapped source path: %s", path); return 1; }
    return 0;
}

static void select_path(Sel *s, const char *p, const Rules *rules, const Rules *impact)
{
    size_t before = s->boost.n + s->gtest.n + s->qa.n;
    int narrow = 0;
    if (is_doc_path(p)) { list_add(&s->nofocus, p); return; }
    TFile *self = tfile_find(p, 0);
    if (self) add_tfile(s, self);
    if (is_qa_script(p)) list_add(&s->qa, p);
    for (size_t i = 0; i < rules->n; i++) {
        if (!rule_match(&rules->v[i], p)) continue;
        for (size_t t = 0; t < rules->v[i].tokens.n; t++) add_token(s, rules->v[i].tokens.v[t], &narrow);
    }
    heuristic(s, p);
    char *why = NULL;
    if (impact_broad(impact, p, &why)) {
        if (narrow) {
            s->narrowed = 1;
            list_add(&s->notes, why);
            free(why);
        } else if (!s->broad) {
            s->broad = 1;
            s->why = why;
        } else free(why);
    }
    if (has_prefix(p, "wallet/src/")) {
        for (size_t i = 0; i < files.n; i++)
            if (has_prefix(files.v[i], "wallet/tests/") && has_suffix(files.v[i], ".pro")) list_add(&s->wallet_qt, files.v[i]);
    }
    if (s->boost.n + s->gtest.n + s->qa.n == before && !has_prefix(p, "wallet/src/")) list_add(&s->nofocus, p);
}

static void sel_finish(Sel *s)
{
    list_sort(&s->boost);
    list_sort(&s->gtest);
    list_sort(&s->qa);
    list_sort(&s->wallet_qt);
    if (s->narrowed) {
        char *w = join(&s->notes, "; ");
        s->notes.n = 0;
        list_push_free(&s->notes, xfmt("impact.rules marks ALL (%s) but tests.rules narrows it to the focused set; run zcutil/local-ci.sh test-changed before landing", w));
        free(w);
    }
    if (s->nofocus.n) {
        size_t show = s->nofocus.n < 4 ? s->nofocus.n : 4;
        List first = {0};
        for (size_t i = 0; i < show; i++) list_push(&first, s->nofocus.v[i]);
        char *j = join(&first, ", ");
        if (s->nofocus.n > show) list_push_free(&s->notes, xfmt("no focused tests for %zu path(s): %s, ... (+%zu more)", s->nofocus.n, j, s->nofocus.n - show));
        else list_push_free(&s->notes, xfmt("no focused tests for %zu path(s): %s", s->nofocus.n, j));
        free(j);
    }
    if (s->wallet_qt.n) {
        char *j = join(&s->wallet_qt, " ");
        list_push_free(&s->notes, xfmt("info: Qt wallet tests, qmake builds are out of scope here: %s", j));
        free(j);
    }
}

static Sel select_all(const List *paths)
{
    Sel s;
    memset(&s, 0, sizeof s);
    Rules rules = load_rules(RULES_FILE), impact = load_rules(IMPACT_FILE);
    for (size_t i = 0; i < paths->n; i++) select_path(&s, paths->v[i], &rules, &impact);
    sel_finish(&s);
    return s;
}

/* ---- tests --------------------------------------------------------------- */

static void print_sel(const Sel *s, const List *paths, int json)
{
    if (json) {
        printf("{");
        jlist("paths", paths, 1);
        printf("\"broad\":%s,\"why\":", s->broad ? "true" : "false");
        jstr(s->why ? s->why : "");
        printf(",\"narrowed\":%s,", s->narrowed ? "true" : "false");
        jlist("boost", &s->boost, 1);
        jlist("gtest", &s->gtest, 1);
        jlist("qa", &s->qa, 1);
        jlist("notes", &s->notes, 0);
        puts("}");
        return;
    }
    if (s->broad) printf("broad: run zcutil/local-ci.sh test-changed (%s)\n", s->why);
    for (size_t i = 0; i < s->boost.n; i++) printf("boost:%s\n", s->boost.v[i]);
    for (size_t i = 0; i < s->gtest.n; i++) printf("gtest:%s\n", s->gtest.v[i]);
    for (size_t i = 0; i < s->qa.n; i++) printf("qa:%s\n", s->qa.v[i]);
    for (size_t i = 0; i < s->notes.n; i++) printf("note: %s\n", s->notes.v[i]);
}

static int cmd_tests(int argc, char **argv)
{
    int json = 0;
    List paths = {0};
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (argv[i][0] == '-') die("tests: unknown option %s", argv[i]);
        else list_add(&paths, (argv[i] = norm_path(argv[i])));
    }
    if (!paths.n) die("usage: zcl-dev tests [--json] <path>...");
    load_files();
    build_index();
    Sel s = select_all(&paths);
    print_sel(&s, &paths, json);
    return 0;
}

/* ---- t-list -------------------------------------------------------------- */

static void ci_steps(List *out)
{
    List lines = {0};
    if (file_lines(CI_FILE, &lines)) return;
    for (size_t i = 0; i < lines.n; i++) {
        if (!has_prefix(lines.v[i], "    step ")) continue;
        List w = {0};
        split_words(lines.v[i], " \t", &w);
        if (w.n >= 3 && !has_prefix(w.v[1], "dry-") && strspn(w.v[2], "0123456789") == strlen(w.v[2])) list_add(out, w.v[1]);
    }
}

static void qa_scripts(List *out)
{
    for (size_t i = 0; i < files.n; i++)
        if (is_qa_script(files.v[i])) list_add(out, files.v[i]);
    list_sort(out);
}

static int cmd_t_list(int argc, char **argv)
{
    int json = 0;
    size_t after = 0;
    const char *kind = NULL;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (has_prefix(argv[i], "--after=")) parse_after(argv[i] + 8, &after);
        else if (!strcmp(argv[i], "boost") || !strcmp(argv[i], "gtest") || !strcmp(argv[i], "qa") || !strcmp(argv[i], "ci")) kind = argv[i];
        else die("usage: zcl-dev t-list [--json] [--after=N] [boost|gtest|qa|ci]");
    }
    load_files();
    build_index();
    List items = {0}, tmp = {0};
    for (int pass = 0; pass < 2; pass++) { /* Boost then gtest, each sorted by suite */
        const char *k = pass ? "gtest" : "boost";
        if (kind && strcmp(kind, k)) continue;
        tmp.n = 0;
        for (size_t i = 0; i < ntfiles; i++) {
            if (tfiles[i].gtest != pass) continue;
            for (size_t j = 0; j < tfiles[i].suites.n; j++) list_push_free(&tmp, xfmt("%s %s %s", k, tfiles[i].suites.v[j], tfiles[i].file));
        }
        list_sort(&tmp);
        for (size_t i = 0; i < tmp.n; i++) list_push(&items, tmp.v[i]);
    }
    if (!kind || !strcmp(kind, "qa")) {
        tmp.n = 0;
        qa_scripts(&tmp);
        for (size_t i = 0; i < tmp.n; i++) list_push_free(&items, xfmt("qa %s", tmp.v[i]));
    }
    if (!kind || !strcmp(kind, "ci")) {
        tmp.n = 0;
        ci_steps(&tmp);
        for (size_t i = 0; i < tmp.n; i++) list_push_free(&items, xfmt("ci %s", tmp.v[i]));
    }
    if (!items.n) { fputs("zcl-dev-tests: t-list found nothing: empty scan\n", stderr); return 2; }
    emit_page(&items, json, after);
    return 0;
}

/* ---- check-tests --------------------------------------------------------- */

/* Tokens of `var = ... \` / `var += ...` assignments in a Makefile include. */
static int makefile_var(const char *path, const char *var, List *out)
{
    List lines = {0};
    size_t vl = strlen(var);
    int cont = 0, seen = 0;
    if (file_lines(path, &lines)) return -1;
    for (size_t i = 0; i < lines.n; i++) {
        char *s = lines.v[i];
        if (!cont) {
            if (strncmp(s, var, vl)) continue;
            char *a = s + vl;
            while (*a == ' ' || *a == '\t') a++;
            if (*a == '+') a++;
            if (*a != '=') continue;
            s = a + 1;
            seen = 1;
        }
        char *hash = strchr(s, '#');
        if (hash) *hash = 0;
        size_t n = strlen(s);
        while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
        cont = n && s[n - 1] == '\\';
        if (cont) s[n - 1] = 0;
        split_words(s, " \t", out);
    }
    return seen ? 0 : -1;
}

static void finding(List *f, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    list_push_free(f, xvfmt(fmt, ap));
    va_end(ap);
}

static void check_registration(List *f, const char *inc, const char *var, const char *const *dirs, int only_tests_files)
{
    List listed = {0};
    if (makefile_var(inc, var, &listed)) { finding(f, "FAIL registry: %s has no %s assignment", inc, var); return; }
    if (!listed.n) { finding(f, "FAIL registry: %s lists nothing in %s", inc, var); return; }
    for (size_t i = 0; i < files.n; i++) {
        const char *p = files.v[i];
        if (!in_dir(p, dirs)) continue;
        if (only_tests_files && !has_suffix(p, "_tests.cpp")) continue;
        if (!list_has(&listed, p + 4)) finding(f, "FAIL unregistered: %s is not listed in %s of %s", p, var, inc);
    }
    for (size_t i = 0; i < listed.n; i++) {
        char *p = xfmt("src/%s", listed.v[i]);
        if (!list_has(&files, p)) finding(f, "FAIL dangling: %s lists %s, which does not exist", inc, p);
        free(p);
    }
}

static void check_unique(List *f)
{
    for (size_t i = 0; i < ntfiles; i++) {
        if (tfiles[i].gtest) continue;
        for (size_t j = 0; j < tfiles[i].suites.n; j++)
            for (size_t k = i + 1; k < ntfiles; k++)
                if (!tfiles[k].gtest && list_has(&tfiles[k].suites, tfiles[i].suites.v[j]))
                    finding(f, "FAIL duplicate-suite: Boost suite %s is declared in %s and %s", tfiles[i].suites.v[j], tfiles[i].file, tfiles[k].file);
    }
}

static void check_rules_tokens(List *f, const Rules *rules)
{
    for (size_t i = 0; i < rules->n; i++) {
        const Rule *r = &rules->v[i];
        int hit = 0;
        for (size_t j = 0; j < files.n && !hit; j++) hit = rule_match(r, files.v[j]);
        if (!hit) finding(f, "FAIL dead-rule: %s:%zu matches no file", RULES_FILE, r->line);
        for (size_t t = 0; t < r->tokens.n; t++) {
            const char *tk = r->tokens.v[t];
            if (has_prefix(tk, "boost:")) { if (!suite_known(tk + 6, 0)) finding(f, "FAIL token: %s:%zu names unknown Boost suite %s", RULES_FILE, r->line, tk + 6); }
            else if (has_prefix(tk, "gtest:")) { if (!suite_known(tk + 6, 1)) finding(f, "FAIL token: %s:%zu names unknown gtest suite %s", RULES_FILE, r->line, tk + 6); }
            else if (has_prefix(tk, "qa:")) { if (!list_has(&files, tk + 3)) finding(f, "FAIL token: %s:%zu names missing qa script %s", RULES_FILE, r->line, tk + 3); }
            else if (strcmp(tk, "narrow")) finding(f, "FAIL token: %s:%zu has unknown token %s", RULES_FILE, r->line, tk);
        }
    }
}

#define BASELINE_FILE "zcutil/dev/tests.baseline"

/* Does the text of `script` run `target`: its basename, or a glob such as wallet_matrix_scn?.sh. */
static int script_calls(const char *script, const char *target)
{
    List lines = {0};
    const char *base = strrchr(target, '/') + 1;
    if (file_lines(script, &lines)) return 0;
    for (size_t i = 0; i < lines.n; i++) {
        List w = {0};
        split_words(lines.v[i], "\t \"'$(){}<>;|&=:,`", &w);
        for (size_t k = 0; k < w.n; k++) {
            const char *tok = strrchr(w.v[k], '/') ? strrchr(w.v[k], '/') + 1 : w.v[k];
            if (!has_suffix(tok, ".sh")) continue;
            if (!strcmp(tok, base) || (strpbrk(tok, "?*") && platform_glob_match(tok, base, false))) return 1;
        }
    }
    return 0;
}

/* qa scripts that nothing runs: not named by impact.rules, tests.rules or local-ci.sh, and not called
 * by a script that is. Sorted. */
static void qa_unreachable(const Rules *rules, List *out)
{
    Rules impact = load_rules(IMPACT_FILE);
    List ci = {0}, qa = {0}, reach = {0};
    char *citext = file_lines(CI_FILE, &ci) ? NULL : join(&ci, "\n");
    qa_scripts(&qa);
    for (size_t q = 0; q < qa.n; q++) {
        const char *p = qa.v[q], *base = strrchr(p, '/') + 1;
        char *tk = xfmt("qa:%s", p);
        int ok = citext && (strstr(citext, p) || strstr(citext, base));
        for (size_t i = 0; i < impact.n && !ok; i++) ok = list_has(&impact.v[i].tokens, p);
        for (size_t i = 0; i < rules->n && !ok; i++) ok = list_has(&rules->v[i].tokens, tk);
        if (ok) list_push(&reach, p);
        free(tk);
    }
    for (int grew = 1; grew;) { /* transitive closure over script-to-script calls */
        grew = 0;
        for (size_t q = 0; q < qa.n; q++) {
            if (list_has(&reach, qa.v[q])) continue;
            for (size_t r = 0; r < reach.n; r++)
                if (script_calls(reach.v[r], qa.v[q])) { list_push(&reach, qa.v[q]); grew = 1; break; }
        }
    }
    for (size_t q = 0; q < qa.n; q++) if (!list_has(&reach, qa.v[q])) list_push(out, qa.v[q]);
}

/* The ratchet: BASELINE_FILE lists qa scripts allowed to be unreachable today. It may only shrink:
 * a new unreachable script fails, and so does a baseline entry that is reachable or gone. */
static void check_qa_reachable(List *f, const Rules *rules, List *stale_out)
{
    List un = {0}, base = {0}, lines = {0};
    qa_unreachable(rules, &un);
    if (!file_lines(BASELINE_FILE, &lines))
        for (size_t i = 0; i < lines.n; i++)
            if (lines.v[i][0] && lines.v[i][0] != '#') list_add(&base, lines.v[i]);
    for (size_t i = 0; i < un.n; i++)
        if (!list_has(&base, un.v[i])) finding(f, "FAIL unreachable-qa: %s is not named by impact.rules, tests.rules or local-ci.sh (run it from a local-ci step or a tests.rules qa: token; %s may only shrink)", un.v[i], BASELINE_FILE);
    for (size_t i = 0; i < base.n; i++)
        if (!list_has(&un, base.v[i])) {
            list_add(stale_out, base.v[i]);
            finding(f, "FAIL stale-baseline: %s is reachable or gone; remove it from %s (check-tests --update-baseline)", base.v[i], BASELINE_FILE);
        }
}

/* --update-baseline: refuse while anything rose; otherwise drop the stale entries. */
static int update_baseline(const List *stale, size_t rose)
{
    List lines = {0};
    if (rose) { fprintf(stderr, "zcl-dev-tests: %s may only shrink: %zu new unreachable qa script(s); fix them first\n", BASELINE_FILE, rose); return 1; }
    if (file_lines(BASELINE_FILE, &lines)) die("cannot read %s", BASELINE_FILE);
    FILE *o = fopen(BASELINE_FILE, "wb");
    if (!o) die("cannot write %s", BASELINE_FILE);
    for (size_t i = 0; i < lines.n; i++) if (!list_has(stale, lines.v[i])) fprintf(o, "%s\n", lines.v[i]);
    fclose(o);
    printf("check-tests: removed %zu stale baseline row(s)\n", stale->n);
    return 0;
}

static int cmd_check_tests(int argc, char **argv)
{
    int json = 0, upd = 0;
    size_t after = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (has_prefix(argv[i], "--after=")) parse_after(argv[i] + 8, &after);
        else if (!strcmp(argv[i], "--update-baseline")) upd = 1;
        else die("usage: zcl-dev check-tests [--json] [--after=N] [--update-baseline]");
    }
    load_files();
    build_index();
    size_t nb = 0, ng = 0, nsuite = 0;
    for (size_t i = 0; i < ntfiles; i++) { if (tfiles[i].gtest) ng++; else nb++; nsuite += tfiles[i].suites.n; }
    if (!nb || !ng || !nsuite) {
        fprintf(stderr, "zcl-dev-tests: check-tests scanned %zu Boost files, %zu gtest files, %zu suites: hollow scan\n", nb, ng, nsuite);
        return 2;
    }
    List f = {0};
    check_registration(&f, BOOST_INC, "BITCOIN_TESTS", boost_dirs, 1);
    check_registration(&f, GTEST_INC, "zcash_gtest_SOURCES", gtest_dirs, 0);
    check_unique(&f);
    Rules rules = load_rules(RULES_FILE);
    check_rules_tokens(&f, &rules);
    List stale = {0};
    check_qa_reachable(&f, &rules, &stale);
    if (upd) return update_baseline(&stale, f.n - stale.n);
    if (!f.n) {
        if (json) printf("{\"total\":0,\"after\":0,\"items\":[],\"next\":null,\"boost_files\":%zu,\"gtest_files\":%zu,\"suites\":%zu}\n", nb, ng, nsuite);
        else printf("check-tests: ok (%zu Boost files, %zu gtest files, %zu suites)\n", nb, ng, nsuite);
        return 0;
    }
    emit_page(&f, json, after);
    return 1;
}

/* ---- t-fast -------------------------------------------------------------- */

#ifdef _WIN32
/* Quote one argument by the CommandLineToArgvW rules (MSVCRT re-parses the joined command line). */
static char *quote_arg(const char *a)
{
    size_t n = strlen(a), cap = 2 * n + 3, o = 0;
    char *q = xrealloc(NULL, cap);
    if (*a && !strpbrk(a, " \t\n\v\"")) { memcpy(q, a, n + 1); return q; }
    q[o++] = '"';
    for (size_t i = 0;; i++) {
        size_t bs = 0;
        while (a[i] == '\\') { bs++; i++; }
        if (!a[i]) { for (size_t k = 0; k < 2 * bs; k++) q[o++] = '\\'; break; }
        if (a[i] == '"') { for (size_t k = 0; k < 2 * bs + 1; k++) q[o++] = '\\'; }
        else for (size_t k = 0; k < bs; k++) q[o++] = '\\';
        q[o++] = a[i];
    }
    q[o++] = '"';
    q[o] = 0;
    return q;
}

#endif

/* One word for a POSIX shell: single quotes unless it is plain. */
static char *shq(const char *a)
{
    if (*a && strspn(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/:=,*-+%@") == strlen(a)) return xstrdup(a);
    size_t o = 0;
    char *q = xrealloc(NULL, 4 * strlen(a) + 3);
    q[o++] = '\'';
    for (; *a; a++) {
        if (*a == '\'') { memcpy(q + o, "'\\''", 4); o += 4; }
        else q[o++] = *a;
    }
    q[o++] = '\'';
    q[o] = 0;
    return q;
}

static char *argv_line(const List *a)
{
    List w = {0};
    for (size_t i = 0; i < a->n; i++) list_push_free(&w, shq(a->v[i]));
    return join(&w, " ");
}

/* Run argv without a shell and wait. With `to_stderr` the child's stdout goes to stderr (--json). */
static int run_argv(const List *a, int to_stderr)
{
    int saved = -1, rc;
    char **av = xrealloc(NULL, (a->n + 1) * sizeof *av);
    for (size_t i = 0; i < a->n; i++) av[i] = a->v[i];
    av[a->n] = NULL;
    fflush(stdout);
    fflush(stderr);
    if (to_stderr) { saved = dup(1); dup2(2, 1); }
#ifdef _WIN32
    char **qv = xrealloc(NULL, (a->n + 1) * sizeof *qv);
    for (size_t i = 0; i < a->n; i++) qv[i] = quote_arg(a->v[i]);
    qv[a->n] = NULL;
    intptr_t r = _spawnvp(_P_WAIT, av[0], (const char *const *)qv);
    rc = r == -1 ? 127 : (int)r;
#else
    pid_t pid = fork();
    if (pid < 0) die("fork failed");
    if (!pid) { execvp(av[0], av); _exit(127); }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) die("waitpid failed");
    rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
#endif
    if (to_stderr) { dup2(saved, 1); close(saved); }
    free(av);
    return rc;
}

/* One command line for popen(): quoted for cmd.exe on Windows, for sh elsewhere, stderr merged. */
static char *popen_line(const List *a)
{
#ifdef _WIN32
    List w = {0};
    for (size_t i = 0; i < a->n; i++) list_push_free(&w, quote_arg(a->v[i]));
    char *j = join(&w, " "), *r = xfmt("\"%s 2>&1\"", j);
    free(j);
    return r;
#else
    char *j = argv_line(a), *r = xfmt("%s 2>&1", j);
    free(j);
    return r;
#endif
}

/* Run argv, copy its output through, and note which `expect` suites printed their
 * `Entering test suite "<name>"` line. Boost 1.85 accepts --run_test=a:b, but --list_content does
 * not apply the filter, so the only reliable check that a multi-suite filter ran every suite is the
 * suite log itself; the caller reruns the missing ones one by one. */
static int run_tee(const List *a, int to_stderr, const List *expect, List *missing)
{
    char *cmd = popen_line(a), buf[8192];
    FILE *out = to_stderr ? stderr : stdout;
    List seen = {0};
    fflush(stdout);
    fflush(stderr);
    FILE *p = popen(cmd, "r");
    if (!p) die("cannot run: %s", cmd);
    while (fgets(buf, sizeof buf, p)) {
        fputs(buf, out);
        if (!strstr(buf, "Entering test suite \"")) continue;
        for (size_t i = 0; i < expect->n; i++) {
            char *needle = xfmt("Entering test suite \"%s\"", expect->v[i]);
            if (strstr(buf, needle)) list_add(&seen, expect->v[i]);
            free(needle);
        }
    }
    int st = pclose(p), rc;
#ifdef _WIN32
    rc = st;
#else
    rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
#endif
    for (size_t i = 0; i < expect->n; i++) if (!list_has(&seen, expect->v[i])) list_push(missing, expect->v[i]);
    free(cmd);
    return rc;
}

static void mkdir_p(const char *path)
{
    char *p = xstrdup(path);
    for (char *s = p + 1;; s++) {
        char c = *s;
        if (c != '/' && c) continue;
        *s = 0;
#ifdef _WIN32
        _mkdir(p);
#else
        mkdir(p, 0777);
#endif
        *s = c;
        if (!c) break;
    }
    free(p);
}

static int file_mentions(const char *path, const char *needle)
{
    List l = {0};
    if (file_lines(path, &l)) return 0;
    for (size_t i = 0; i < l.n; i++) if (strstr(l.v[i], needle)) return 1;
    return 0;
}

static int newer_than(const char *src, const char *bin)
{
    struct stat a, b;
    if (stat(src, &a) || stat(bin, &b)) return 0;
    return a.st_mtime > b.st_mtime;
}

typedef struct { List *v; List *expect; size_t n; } Plan; /* v[i] is one argv; expect[i] lists suites to confirm ran */

static List *plan_new(Plan *pl)
{
    pl->v = xrealloc(pl->v, (pl->n + 1) * sizeof *pl->v);
    pl->expect = xrealloc(pl->expect, (pl->n + 1) * sizeof *pl->expect);
    memset(&pl->v[pl->n], 0, sizeof pl->v[0]);
    memset(&pl->expect[pl->n], 0, sizeof pl->expect[0]);
    return &pl->v[pl->n++];
}

static void boost_cmd(Plan *pl, const char *tb, const char *filter)
{
    List *c = plan_new(pl);
    list_push(c, tb);
    if (filter) list_push_free(c, xfmt("--run_test=%s", filter));
    list_push(c, "--log_level=test_suite");
}

/* A full run takes no filter. Otherwise one invocation with the suites joined by ':' (Boost 1.85);
 * the run confirms every suite entered and reruns the missing ones singly. */
static void plan_boost(Plan *pl, const char *tb, const List *suites, int full)
{
    if (full) { boost_cmd(pl, tb, NULL); return; }
    char *f = join(suites, ":");
    boost_cmd(pl, tb, f);
    free(f);
    if (suites->n > 1)
        for (size_t i = 0; i < suites->n; i++) list_push(&pl->expect[pl->n - 1], suites->v[i]);
}

static void plan_gtest(Plan *pl, const char *tg, const List *suites, int full)
{
    List *c = plan_new(pl);
    list_push(c, tg);
    if (full) return;
    List f = {0};
    for (size_t i = 0; i < suites->n; i++) list_push_free(&f, xfmt("%s.*", suites->v[i]));
    char *j = join(&f, ":");
    list_push_free(c, xfmt("--gtest_filter=%s", j));
    free(j);
}

static void plan_qa(Plan *pl, const char *script, const char *bindir)
{
    List *c = plan_new(pl);
    list_push(c, "sh");
    list_push(c, script);
    if (!file_mentions(script, "--bin")) return;
    const char *b = strrchr(script, '/') + 1;
    size_t n = strlen(b) - (has_suffix(b, ".sh") ? 3 : 0);
    list_push(c, "--bin");
    list_push(c, bindir);
    list_push(c, "--work");
    list_push_free(c, xfmt("%s/%.*s", WORK_DIR, (int)n, b));
}

static int cmd_t_fast(int argc, char **argv)
{
    int json = 0, dry = 0, narrow = 0, noqa = 0, changed = 0;
    const char *base = "origin/master", *bindir = "src";
    List paths = {0};
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--json")) json = 1;
        else if (!strcmp(a, "--dry-run")) dry = 1;
        else if (!strcmp(a, "--narrow")) narrow = 1;
        else if (!strcmp(a, "--no-qa")) noqa = 1;
        else if (!strcmp(a, "--changed")) changed = 1;
        else if (has_prefix(a, "--changed=")) { changed = 1; base = a + 10; }
        else if (has_prefix(a, "--bin=")) bindir = a + 6;
        else if (a[0] == '-') die("t-fast: unknown option %s", a);
        else list_add(&paths, (argv[i] = norm_path(a)));
    }
    if (changed) {
        char cmd[512];
        List diff = {0};
        if (!safe_ref(base)) die("t-fast: unsafe base ref '%s'", base);
        snprintf(cmd, sizeof cmd, "git diff --name-only %s...HEAD", base);
        if (cmd_lines(cmd, &diff)) die("t-fast: %s failed (is %s a known ref?)", cmd, base);
        if (!diff.n && !paths.n) die("t-fast: no changed files against %s: empty scan, nothing to run", base);
        for (size_t i = 0; i < diff.n; i++) if (diff.v[i][0]) list_add(&paths, diff.v[i]);
    }
    if (!paths.n) die("usage: zcl-dev t-fast [--changed[=base]] [--dry-run] [--narrow] [--no-qa] [--json] [--bin=src] <path>...");
    load_files();
    build_index();
    Sel s = select_all(&paths);
    int full = s.broad && !narrow;
    char *tb = xfmt("%s/test/test_bitcoin%s", bindir, EXE_SUFFIX), *tg = xfmt("%s/zcash-gtest%s", bindir, EXE_SUFFIX),
         *zd = xfmt("%s/zclassicd%s", bindir, EXE_SUFFIX);
    int run_boost = full || s.boost.n, run_gtest = full || s.gtest.n, run_qa = !noqa && s.qa.n;
    List notes = {0}, need = {0}, srcs = {0};
    for (size_t i = 0; i < s.notes.n; i++) list_push(&notes, s.notes.v[i]);
    if (s.broad) list_push_free(&notes, xfmt("broad: run zcutil/local-ci.sh test-changed (%s); %s", s.why,
                                             full ? "running the full test_bitcoin and zcash-gtest" : "--narrow given, running the focused set only"));

    /* Build check: a missing or stale binary is reported with the exact make line, never built here. */
    for (size_t i = 0; i < paths.n; i++)
        if (has_prefix(paths.v[i], "src/") && is_cxx_path(paths.v[i]) && exists(paths.v[i])) list_push(&srcs, paths.v[i]);
    const struct { int want; const char *bin, *target; } bins[3] = {{run_boost, tb, "test/test_bitcoin"}, {run_gtest, tg, "zcash-gtest"}, {run_qa != 0, zd, "zclassicd"}};
    for (int b = 0; b < 3; b++) {
        if (!bins[b].want) continue;
        int bad = !exists(bins[b].bin);
        for (size_t i = 0; i < srcs.n && !bad; i++) bad = newer_than(srcs.v[i], bins[b].bin);
        if (bad) list_push_free(&need, xfmt("make -C %s -j$(nproc) %s", bindir, bins[b].target));
    }
    if (need.n && !dry) {
        fprintf(stderr, "t-fast: a test binary is missing or older than a changed source; build it first (never built implicitly):\n");
        for (size_t i = 0; i < need.n; i++) fprintf(stderr, "  %s\n", need.v[i]);
        return 3;
    }
    for (size_t i = 0; i < need.n; i++) list_push_free(&notes, xfmt("build needed before running: %s", need.v[i]));

    Plan plan = {0};
    if (run_boost) plan_boost(&plan, tb, &s.boost, full);
    if (run_gtest) plan_gtest(&plan, tg, &s.gtest, full);
    if (run_qa) for (size_t i = 0; i < s.qa.n; i++) plan_qa(&plan, s.qa.v[i], bindir);
    if (!plan.n) {
        if (json) { printf("{\"dry_run\":%s,\"commands\":[],", dry ? "true" : "false"); jlist("notes", &notes, 0); puts("}"); }
        else { for (size_t i = 0; i < notes.n; i++) printf("note: %s\n", notes.v[i]); puts("t-fast: nothing to run (no focused tests for these paths)"); }
        return 0;
    }
    if (dry) {
        if (json) {
            printf("{\"dry_run\":true,\"broad\":%s,\"commands\":[", s.broad ? "true" : "false");
            for (size_t i = 0; i < plan.n; i++) { if (i) putchar(','); fputs("[", stdout); for (size_t k = 0; k < plan.v[i].n; k++) { if (k) putchar(','); jstr(plan.v[i].v[k]); } putchar(']'); }
            printf("],");
            jlist("notes", &notes, 0);
            puts("}");
        } else {
            for (size_t i = 0; i < notes.n; i++) printf("note: %s\n", notes.v[i]);
            for (size_t i = 0; i < plan.n; i++) { char *l = argv_line(&plan.v[i]); printf("exec: %s\n", l); free(l); }
        }
        return 0;
    }
    int failed = 0;
    List results = {0};
    for (size_t i = 0; i < notes.n; i++) fprintf(json ? stderr : stdout, "note: %s\n", notes.v[i]);
    for (size_t i = 0; i < plan.n; i++) {
        char *l = argv_line(&plan.v[i]);
        if (!strcmp(plan.v[i].v[0], "sh") && plan.v[i].n > 5) mkdir_p(plan.v[i].v[5]);
        fprintf(json ? stderr : stdout, "== %s\n", l);
        int rc;
        if (plan.expect[i].n) {
            List missing = {0};
            rc = run_tee(&plan.v[i], json, &plan.expect[i], &missing);
            for (size_t m = 0; m < missing.n; m++) {
                fprintf(json ? stderr : stdout, "note: suite %s did not run under the a:b filter; running it alone\n", missing.v[m]);
                List one = {0};
                list_push(&one, tb);
                list_push_free(&one, xfmt("--run_test=%s", missing.v[m]));
                list_push(&one, "--log_level=test_suite");
                if (run_argv(&one, json)) rc = rc ? rc : 1;
            }
        } else rc = run_argv(&plan.v[i], json);
        if (rc) failed++;
        list_push_free(&results, xfmt("%d", rc));
        fprintf(json ? stderr : stdout, "== exit %d\n", rc);
        free(l);
    }
    if (json) {
        printf("{\"dry_run\":false,\"failed\":%d,\"results\":[", failed);
        for (size_t i = 0; i < plan.n; i++) {
            char *l = argv_line(&plan.v[i]);
            if (i) putchar(',');
            printf("{\"command\":");
            jstr(l);
            printf(",\"rc\":%s}", results.v[i]);
            free(l);
        }
        puts("]}");
    } else printf("t-fast: %zu command(s), %d failed\n", plan.n, failed);
    return failed ? 1 : 0;
}

/* ---- entry --------------------------------------------------------------- */

static const struct { const char *name, *purpose; } cmds[] = {
    {"tests", "focused Boost, gtest and qa set for paths (broad when consensus or wallet)"},
    {"t-fast", "run the focused test set (--dry-run prints argv, --changed uses the diff)"},
    {"t-list", "list every Boost suite, gtest suite, qa script and local-ci step"},
    {"check-tests", "gate: every test file registered, suite names unique, rules resolve"},
};

static const char *self_name(const char *argv0)
{
    const char *b = argv0, *s;
    for (s = argv0; *s; s++) if (*s == '/' || *s == '\\') b = s + 1;
    return b;
}

int main(int argc, char **argv)
{
    const char *dir = NULL, *as = NULL, *self = self_name(argv[0]);
    int a = 1;
    if (has_prefix(self, "zcl-dev-")) {
        self += 8;
        size_t n = strlen(self);
        if (n > 4 && !strcmp(self + n - 4, ".exe")) as = xfmt("%.*s", (int)(n - 4), self);
        else as = self;
    }
    while (a < argc && (!strcmp(argv[a], "-C") || has_prefix(argv[a], "--as="))) {
        if (!strcmp(argv[a], "-C")) {
            if (a + 1 >= argc) die("-C needs a directory");
            dir = argv[a + 1];
            a += 2;
        } else as = argv[a++] + 5;
    }
    if (a < argc && !strcmp(argv[a], "--purpose")) {
        for (size_t i = 0; i < sizeof cmds / sizeof *cmds; i++)
            if (as && !strcmp(as, cmds[i].name)) { puts(cmds[i].purpose); return 0; }
        puts("focused C++ test selection (tests, t-fast, t-list, check-tests)");
        return 0;
    }
    int known = 0;
    for (size_t i = 0; i < sizeof cmds / sizeof *cmds; i++) known |= as && !strcmp(as, cmds[i].name);
    if (!known) {
        fputs("usage: zcl-dev tests|t-fast|t-list|check-tests ...   (zcl-dev-tests --as=<cmd> when run directly)\n", stderr);
        return 2;
    }
    enter_repo(dir);
    if (!strcmp(as, "tests")) return cmd_tests(argc - a, argv + a);
    if (!strcmp(as, "t-fast")) return cmd_t_fast(argc - a, argv + a);
    if (!strcmp(as, "t-list")) return cmd_t_list(argc - a, argv + a);
    return cmd_check_tests(argc - a, argv + a);
}
