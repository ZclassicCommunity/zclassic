/* zcl-dev: developer tool for the zclassicd tree. MIT, like the rest of zclassicd.
 * Plain C, libc only, compiles as gnu17 and (with a C23 compiler) as C23.
 * Builds with the host cc, x86_64-w64-mingw32-gcc and macOS clang.
 *
 *   zcl-dev [-C dir] guide [--json] <path>...
 *   zcl-dev [-C dir] select [--json|--steps] [--stdin] [base-ref]
 *   zcl-dev [-C dir] check-rules
 *   zcl-dev [-C dir] check-docs
 *   zcl-dev receipt <step> [dir]
 *
 * The glob matcher is Z23's platform/glob_match.h, vendored verbatim under
 * zcutil/tools/vendor (see zcutil/tools/Z23_SOURCE.tsv).
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L /* popen, strnlen under a strict -std=c2x */
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1 /* %zu works only with the C99 printf */
#endif
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#include <dirent.h>
#include <process.h>
#include <windows.h>
#define chdir _chdir
#else
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#endif

#include "platform/modules/platform/include/platform/glob_match.h"

#define RULES_FILE "zcutil/dev/impact.rules"
#define LESSONS_FILE "doc/agent/LESSONS.md"
#define TRAPS_FILE "doc/agent/TRAPS.md"
#define CI_FILE "zcutil/local-ci.sh"
#define DOCS_STEP "check-dev-tools"

typedef struct { char **v; size_t n, cap; } List;

static void die(const char *fmt, ...)
{
    va_list ap;
    fputs("zcl-dev: ", stderr);
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

static void list_push(List *l, const char *s)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 16;
        l->v = xrealloc(l->v, l->cap * sizeof *l->v);
    }
    l->v[l->n++] = xstrdup(s);
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

/* Run a shell command and collect its output lines; returns its exit status. */
static int cmd_lines(const char *cmd, List *out)
{
    FILE *p = popen(cmd, "r");
    if (!p) die("cannot run: %s", cmd);
    read_lines(p, out);
    return pclose(p);
}

static int safe_ref(const char *s)
{
    if (!*s || *s == '-') return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && !strchr("._/~^@-", *s)) return 0;
    return 1;
}

static int has_prefix(const char *s, const char *p) { return !strncmp(s, p, strlen(p)); }

static int has_suffix(const char *s, const char *x)
{
    size_t a = strlen(s), b = strlen(x);
    return a >= b && !strcmp(s + a - b, x);
}

static int contains_ci(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    if (!n) return 0;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] && tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == n) return 1;
    }
    return 0;
}

static char *dir_of(const char *path)
{
    char *d = xstrdup(path), *s = strrchr(d, '/');
    if (s) *s = 0; else *d = 0;
    return d;
}

/* ---- JSON output --------------------------------------------------------- */

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

/* ---- repository ---------------------------------------------------------- */

static char prefix[1024]; /* cwd relative to the repo root, with trailing '/' or "" */

static void enter_repo(const char *dir)
{
    List l = {0};
    if (dir && chdir(dir)) die("cannot chdir to %s", dir);
    if (cmd_lines("git rev-parse --show-prefix", &l) || l.n > 1) die("not inside a git work tree");
    snprintf(prefix, sizeof prefix, "%s", l.n ? l.v[0] : "");
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
    size_t n = strlen(prefix) + strlen(r) + 1;
    char *out = xrealloc(NULL, n);
    snprintf(out, n, "%s%s", r[0] == '/' ? "" : prefix, r);
    free(p);
    return out;
}

static void ls_files(List *out)
{
    if (cmd_lines("git ls-files", out)) die("git ls-files failed");
}

/* ---- impact rules -------------------------------------------------------- */

typedef struct { List globs, tokens; size_t line; } Rule;
typedef struct { Rule *v; size_t n; } Rules;

static int is_stage(const char *s)
{
    return !strcmp(s, "daemon-linux") || !strcmp(s, "daemon-win64") || !strcmp(s, "wallet-linux");
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

static Rules load_rules(void)
{
    List lines = {0};
    Rules r = {0};
    if (file_lines(RULES_FILE, &lines)) die("cannot read %s", RULES_FILE);
    r.v = xrealloc(NULL, (lines.n + 1) * sizeof *r.v);
    for (size_t i = 0; i < lines.n; i++) {
        char *s = lines.v[i], *tab;
        while (*s == ' ') s++;
        if (!*s || *s == '#') continue;
        tab = strchr(s, '\t');
        if (!tab) die("%s:%zu: missing TAB between globs and steps", RULES_FILE, i + 1);
        Rule *x = &r.v[r.n++];
        memset(x, 0, sizeof *x);
        x->line = i + 1;
        *tab = 0;
        split_words(s, "|", &x->globs);
        split_words(tab + 1, " \t", &x->tokens);
        if (!x->globs.n || !x->tokens.n) die("%s:%zu: empty globs or steps", RULES_FILE, i + 1);
    }
    return r;
}

static int glob_hit(const char *pat, const char *path) { return platform_glob_match(pat, path, false); }

static int rule_match(const Rule *r, const char *path)
{
    for (size_t g = 0; g < r->globs.n; g++)
        if (glob_hit(r->globs.v[g], path)) return 1;
    return 0;
}

/* why: the reason the scope is ALL ("unmapped source path: ..." or "broad rule: ..."). */
typedef struct { List steps, stages, scripts; int all; char *why; } Impact;

/* A rule token that selects every step (consensus, chain state, wallet, build system). */
#define ALL_TOKEN "ALL"

static int is_doc_path(const char *p)
{
    return has_prefix(p, "doc/") || has_suffix(p, ".md");
}

static void set_all(Impact *im, const char *kind, const char *path)
{
    if (!im->all) {
        size_t n = strlen(kind) + strlen(path) + 1;
        im->why = xrealloc(NULL, n);
        snprintf(im->why, n, "%s%s", kind, path);
    }
    im->all = 1;
}

static void add_token(Impact *im, const char *t, const char *path)
{
    if (!strcmp(t, "-")) return;
    if (!strcmp(t, ALL_TOKEN)) set_all(im, "broad rule: ", path);
    else if (strchr(t, '/')) list_add(&im->scripts, t);
    else if (is_stage(t)) list_add(&im->stages, t);
    else list_add(&im->steps, t);
}

static void impact_path(Impact *im, const Rules *rs, const char *path)
{
    int hit = 0;
    /* Documentation selects the docs check only, wherever it lives. */
    if (is_doc_path(path)) { list_add(&im->steps, DOCS_STEP); return; }
    for (size_t i = 0; i < rs->n; i++) {
        if (!rule_match(&rs->v[i], path)) continue;
        hit = 1;
        for (size_t t = 0; t < rs->v[i].tokens.n; t++) add_token(im, rs->v[i].tokens.v[t], path);
    }
    if (!hit) set_all(im, "unmapped source path: ", path);
}

static void impact_expand_all(Impact *im, const Rules *rs)
{
    if (!im->all) return;
    for (size_t i = 0; i < rs->n; i++)
        for (size_t t = 0; t < rs->v[i].tokens.n; t++) {
            const char *tk = rs->v[i].tokens.v[t];
            if (strcmp(tk, "-") && strcmp(tk, ALL_TOKEN) && !strchr(tk, '/') && !is_stage(tk))
                list_add(&im->steps, tk);
        }
}

/* ---- select -------------------------------------------------------------- */

static int cmd_select(int argc, char **argv)
{
    int json = 0, only_steps = 0, use_stdin = 0;
    const char *base = "origin/master";
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--steps")) only_steps = 1;
        else if (!strcmp(argv[i], "--stdin")) use_stdin = 1;
        else if (argv[i][0] == '-') die("select: unknown option %s", argv[i]);
        else base = argv[i];
    }
    List files = {0};
    if (use_stdin) {
        List raw = {0};
        read_lines(stdin, &raw);
        for (size_t i = 0; i < raw.n; i++) if (raw.v[i][0]) list_push(&files, raw.v[i]);
    } else {
        char cmd[512];
        if (!safe_ref(base)) die("select: unsafe base ref '%s'", base);
        snprintf(cmd, sizeof cmd, "git diff --name-only %s...HEAD", base);
        if (cmd_lines(cmd, &files)) die("select: %s failed (is %s a known ref?)", cmd, base);
    }
    Rules rs = load_rules();
    Impact im = {{0}, {0}, {0}, 0, NULL};
    for (size_t i = 0; i < files.n; i++) impact_path(&im, &rs, files.v[i]);
    impact_expand_all(&im, &rs);
    if (only_steps) {
        if (im.all) puts("ALL");
        else if (im.steps.n) { char *j = join(&im.steps, ","); puts(j); free(j); }
        else puts("NONE");
        return 0;
    }
    if (json) {
        printf("{\"base\":"); jstr(use_stdin ? "(stdin)" : base);
        printf(",\"files\":%zu,\"all\":%s,", files.n, im.all ? "true" : "false");
        jlist("steps", &im.steps, 1);
        jlist("stages", &im.stages, 1);
        jlist("scripts", &im.scripts, 0);
        puts("}");
        return 0;
    }
    printf("base: %s  files: %zu\n", use_stdin ? "(stdin)" : base, files.n);
    if (im.all) printf("scope: ALL (%s)\n", im.why);
    else printf("scope: selective\n");
    char *s = join(&im.steps, " "), *g = join(&im.stages, " "), *c = join(&im.scripts, " ");
    printf("steps: %s\nstages: %s\nscripts: %s\n", s, g, c);
    free(s); free(g); free(c);
    return 0;
}

/* ---- check-rules --------------------------------------------------------- */

static int under_scope(const char *p)
{
    return has_prefix(p, "src/") || has_prefix(p, "wallet/src/") || has_prefix(p, "qa/") ||
           has_prefix(p, "zcutil/");
}

static int cmd_check_rules(void)
{
    List files = {0}, ci = {0};
    int bad = 0;
    ls_files(&files);
    Rules rs = load_rules();
    size_t scoped = 0;
    for (size_t i = 0; i < files.n; i++) {
        if (!under_scope(files.v[i]) || is_doc_path(files.v[i])) continue;
        scoped++;
        int hit = 0;
        for (size_t r = 0; r < rs.n && !hit; r++) hit = rule_match(&rs.v[r], files.v[i]);
        if (!hit) { fprintf(stderr, "FAIL: no rule matches %s\n", files.v[i]); bad++; }
    }
    for (size_t r = 0; r < rs.n; r++) {
        int hit = 0;
        for (size_t i = 0; i < files.n && !hit; i++) hit = rule_match(&rs.v[r], files.v[i]);
        if (!hit) {
            fprintf(stderr, "FAIL: %s:%zu: rule matches no tracked file\n", RULES_FILE, rs.v[r].line);
            bad++;
        }
    }
    int have_ci = file_lines(CI_FILE, &ci) == 0;
    char *cis = have_ci ? join(&ci, "\n") : NULL;
    for (size_t r = 0; r < rs.n; r++)
        for (size_t t = 0; t < rs.v[r].tokens.n; t++) {
            const char *tk = rs.v[r].tokens.v[t];
            if (!strcmp(tk, "-") || !strcmp(tk, ALL_TOKEN)) continue;
            if (strchr(tk, '/')) {
                if (!list_has(&files, tk)) {
                    fprintf(stderr, "FAIL: %s:%zu: script %s is not tracked\n", RULES_FILE, rs.v[r].line, tk);
                    bad++;
                }
            } else if (cis && !is_stage(tk)) {
                char pat[256];
                snprintf(pat, sizeof pat, "step %s ", tk);
                if (!strstr(cis, pat) && strcmp(tk, DOCS_STEP)) {
                    fprintf(stderr, "FAIL: %s:%zu: step %s is not a step of %s\n", RULES_FILE, rs.v[r].line, tk,
                            CI_FILE);
                    bad++;
                }
            }
        }
    if (bad) { fprintf(stderr, "check-rules: FAILED (%d problems)\n", bad); return 1; }
    printf("check-rules: OK (%zu files in scope, %zu rules)\n", scoped, rs.n);
    return 0;
}

/* ---- lessons and traps --------------------------------------------------- */

static const char *const stop[] = {"src", "test", "tests", "wallet", "util", "main", "include", "data", "index", NULL};

static void keywords(const List *paths, List *kw)
{
    for (size_t i = 0; i < paths->n; i++) {
        List w = {0};
        char *c = xstrdup(paths->v[i]);
        for (char *p = c; *p; p++) *p = isalnum((unsigned char)*p) ? (char)tolower((unsigned char)*p) : ' ';
        split_words(c, " ", &w);
        for (size_t k = 0; k < w.n; k++) {
            int skip = strlen(w.v[k]) < 4;
            for (int s = 0; stop[s]; s++) if (!strcmp(stop[s], w.v[k])) skip = 1;
            if (!skip) list_add(kw, w.v[k]);
        }
        free(c);
    }
}

typedef struct { int score; size_t idx; } Hit;

static int hit_cmp(const void *a, const void *b)
{
    const Hit *x = a, *y = b;
    if (x->score != y->score) return y->score - x->score;
    return (x->idx > y->idx) - (x->idx < y->idx);
}

static int lesson_path(const char *line, char *out, size_t cap)
{
    if (!has_prefix(line, "OPEN ") && !has_prefix(line, "DONE ")) return 0;
    const char *p = line + 5;
    size_t n = strcspn(p, " ");
    if (!n || n >= cap) return 0;
    memcpy(out, p, n);
    out[n] = 0;
    return 1;
}

static void find_lessons(const List *paths, const List *kw, List *out)
{
    List lines = {0};
    if (file_lines(LESSONS_FILE, &lines)) return;
    Hit *hits = xrealloc(NULL, (lines.n + 1) * sizeof *hits);
    size_t nh = 0;
    for (size_t i = 0; i < lines.n; i++) {
        char lp[512];
        if (!lesson_path(lines.v[i], lp, sizeof lp)) continue;
        char *ld = dir_of(lp);
        int score = 0;
        for (size_t k = 0; k < paths->n; k++) {
            char *pd = dir_of(paths->v[k]);
            int s = 0;
            if (!strcmp(lp, paths->v[k])) s = 100;
            else if (strchr(ld, '/') && !strcmp(ld, pd)) s = 50;
            else if (strchr(ld, '/') && strchr(pd, '/') && (has_prefix(pd, ld) || has_prefix(ld, pd))) s = 20;
            if (s > score) score = s;
            free(pd);
        }
        for (size_t k = 0; k < kw->n; k++) if (contains_ci(lines.v[i], kw->v[k])) score += 3;
        free(ld);
        if (score >= 3) { hits[nh].score = score; hits[nh++].idx = i; }
    }
    qsort(hits, nh, sizeof *hits, hit_cmp);
    for (size_t i = 0; i < nh && i < 8; i++) list_push(out, lines.v[hits[i].idx]);
    free(hits);
}

static void find_traps(const List *paths, const List *kw, List *out)
{
    List lines = {0};
    if (file_lines(TRAPS_FILE, &lines)) return;
    for (size_t i = 0; i < lines.n; i++) {
        if (!has_prefix(lines.v[i], "## (")) continue;
        const char *title = lines.v[i] + 3;
        int score = 0;
        for (size_t j = i + 1; j < lines.n && j < i + 4; j++) {
            if (!has_prefix(lines.v[j], "Paths:")) continue;
            List pre = {0};
            split_words(lines.v[j] + 6, " \t", &pre);
            for (size_t a = 0; a < paths->n; a++)
                for (size_t b = 0; b < pre.n; b++)
                    if (has_prefix(paths->v[a], pre.v[b])) score += 50;
        }
        for (size_t k = 0; k < kw->n; k++) if (contains_ci(title, kw->v[k])) score += 3;
        if (score) list_push(out, title);
    }
}

/* ---- guide --------------------------------------------------------------- */

static void agents_for(const char *path, List *files)
{
    char *d = dir_of(path);
    for (;;) {
        char f[1100];
        snprintf(f, sizeof f, "%s%sAGENTS.md", d, *d ? "/" : "");
        FILE *fp = fopen(f, "rb");
        if (fp) { fclose(fp); list_add(files, f); break; }
        if (!*d) break;
        char *s = strrchr(d, '/');
        if (s) *s = 0; else *d = 0;
    }
    free(d);
}

static char *clip(const char *s, size_t max)
{
    size_t n = strlen(s);
    char *r = xrealloc(NULL, max + 4);
    if (n <= max) { memcpy(r, s, n + 1); return r; }
    n = max;
    while (n && ((unsigned char)s[n] & 0xC0) == 0x80) n--;
    memcpy(r, s, n);
    memcpy(r + n, "...", 4);
    return r;
}

static void bullets(const char *file, List *out)
{
    List l = {0};
    if (file_lines(file, &l)) return;
    for (size_t i = 0; i < l.n && out->n < 14; i++)
        if (has_prefix(l.v[i], "- ") || has_prefix(l.v[i], "* ")) {
            char *c = clip(l.v[i], 150);
            list_push(out, c);
            free(c);
        }
}

static int cmd_guide(int argc, char **argv)
{
    int json = 0;
    List paths = {0}, agents = {0}, kw = {0}, lessons = {0}, traps = {0}, cmds = {0};
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (argv[i][0] == '-') die("guide: unknown option %s", argv[i]);
        else { char *p = norm_path(argv[i]); list_add(&paths, p); free(p); }
    }
    if (!paths.n) die("usage: zcl-dev guide [--json] <path>...");
    Rules rs = load_rules();
    Impact im = {{0}, {0}, {0}, 0, NULL};
    for (size_t i = 0; i < paths.n; i++) {
        agents_for(paths.v[i], &agents);
        impact_path(&im, &rs, paths.v[i]);
    }
    impact_expand_all(&im, &rs);
    keywords(&paths, &kw);
    find_lessons(&paths, &kw, &lessons);
    find_traps(&paths, &kw, &traps);

    char *steps = join(&im.steps, ",");
    if (im.all) list_push(&cmds, "zcutil/local-ci.sh --commit HEAD test <outdir>");
    else if (im.steps.n) {
        char c[2048];
        snprintf(c, sizeof c, "zcutil/local-ci.sh --commit HEAD --only %s test <outdir>", steps);
        list_push(&cmds, c);
    }
    for (size_t i = 0; i < im.stages.n; i++) {
        char c[256];
        snprintf(c, sizeof c, "zcutil/local-ci.sh --commit HEAD %s <outdir>", im.stages.v[i]);
        list_push(&cmds, c);
    }
    for (size_t i = 0; i < im.scripts.n && i < 5; i++) {
        char c[600];
        snprintf(c, sizeof c, "sh %s <dir-with-zclassicd>", im.scripts.v[i]);
        list_push(&cmds, c);
    }
    list_push(&cmds, "zcutil/bin/zcl-dev select");

    if (json) {
        printf("{");
        jlist("paths", &paths, 1);
        printf("\"agents\":[");
        for (size_t i = 0; i < agents.n; i++) {
            List b = {0};
            bullets(agents.v[i], &b);
            printf("%s{\"file\":", i ? "," : "");
            jstr(agents.v[i]);
            putchar(',');
            jlist("bullets", &b, 0);
            putchar('}');
        }
        printf("],\"all\":%s,", im.all ? "true" : "false");
        jlist("steps", &im.steps, 1);
        jlist("stages", &im.stages, 1);
        jlist("scripts", &im.scripts, 1);
        jlist("lessons", &lessons, 1);
        jlist("traps", &traps, 1);
        jlist("commands", &cmds, 0);
        puts("}");
        return 0;
    }
    printf("== %s\n", (paths.n == 1) ? paths.v[0] : "paths");
    if (paths.n > 1) for (size_t i = 0; i < paths.n; i++) printf("   %s\n", paths.v[i]);
    for (size_t i = 0; i < agents.n; i++) {
        List b = {0};
        bullets(agents.v[i], &b);
        printf("\nrules (%s):\n", agents.v[i]);
        for (size_t k = 0; k < b.n; k++) printf("  %s\n", b.v[k]);
    }
    if (im.all) printf("\nci steps (ALL, %s): ", im.why);
    else printf("\nci steps: ");
    if (im.steps.n) { char *j = join(&im.steps, " "); puts(j); free(j); } else puts("(none)");
    if (im.stages.n) { char *j = join(&im.stages, " "); printf("ci stages: %s\n", j); free(j); }
    if (im.scripts.n) { char *j = join(&im.scripts, " "); printf("qa scripts: %s\n", j); free(j); }
    printf("\nlessons (%s):\n", LESSONS_FILE);
    if (!lessons.n) puts("  (none)");
    for (size_t i = 0; i < lessons.n; i++) { char *c = clip(lessons.v[i], 200); printf("  %s\n", c); free(c); }
    printf("\ntraps (%s):\n", TRAPS_FILE);
    if (!traps.n) puts("  (none)");
    for (size_t i = 0; i < traps.n; i++) printf("  %s\n", traps.v[i]);
    puts("\nfirst commands:");
    for (size_t i = 0; i < cmds.n; i++) printf("  $ %s\n", cmds.v[i]);
    return 0;
}

/* ---- check-docs ---------------------------------------------------------- */

static int cmd_check_docs(void)
{
    List files = {0}, lines = {0};
    int bad = 0, n = 0, traps = 0;
    ls_files(&files);
    if (file_lines(LESSONS_FILE, &lines)) die("cannot read %s", LESSONS_FILE);
    for (size_t i = 0; i < lines.n; i++) {
        char lp[512];
        if (!has_prefix(lines.v[i], "OPEN ") && !has_prefix(lines.v[i], "DONE ")) continue;
        n++;
        if (!lesson_path(lines.v[i], lp, sizeof lp) || !strstr(lines.v[i], " \xe2\x80\x94 ")) {
            fprintf(stderr, "FAIL: %s:%zu: not 'OPEN|DONE <path> — <text>'\n", LESSONS_FILE, i + 1);
            bad++;
        } else if (!list_has(&files, lp)) {
            fprintf(stderr, "FAIL: %s:%zu: %s is not a tracked path\n", LESSONS_FILE, i + 1, lp);
            bad++;
        }
    }
    lines.n = 0;
    if (file_lines(TRAPS_FILE, &lines)) die("cannot read %s", TRAPS_FILE);
    for (size_t i = 0; i < lines.n; i++) {
        if (!has_prefix(lines.v[i], "## (")) continue;
        traps++;
        int ok = 0;
        for (size_t j = i + 1; j < lines.n && j < i + 4; j++) ok |= has_prefix(lines.v[j], "Paths:");
        if (!ok) { fprintf(stderr, "FAIL: %s:%zu: section without a Paths: line\n", TRAPS_FILE, i + 1); bad++; }
    }
    if (bad) { fprintf(stderr, "check-docs: FAILED (%d problems)\n", bad); return 1; }
    printf("check-docs: OK (%d lessons, %d trap sections)\n", n, traps);
    return 0;
}

/* ---- receipt ------------------------------------------------------------- */

static int cmd_receipt(int argc, char **argv)
{
    if (argc < 1 || argc > 2) die("usage: zcl-dev receipt <step> [dir]");
    char path[1200], pat[600];
    snprintf(path, sizeof path, "%s/receipts.jsonl", argc > 1 ? argv[1] : ".");
    snprintf(pat, sizeof pat, "\"step\":\"%s\"", argv[0]);
    List l = {0};
    if (file_lines(path, &l)) die("cannot read %s", path);
    for (size_t i = l.n; i-- > 0;)
        if (strstr(l.v[i], pat)) { puts(l.v[i]); return 0; }
    fprintf(stderr, "zcl-dev: no receipt for step %s in %s\n", argv[0], path);
    return 1;
}

/* ---- git-style dispatch ---------------------------------------------------
 * An unknown `zcl-dev <cmd> args...` runs `zcl-dev-<cmd>[.exe] args...`, found
 * beside this executable or in <repo>/zcutil/bin. The child starts in the repo
 * root (after -C) with ZCL_DEV_PREFIX set to the original cwd relative to the
 * root, and its exit status is ours. Each unit ships its own binary, so units
 * never share a source file. `zcl-dev-<cmd> --purpose` prints one line for help.
 */
#ifdef _WIN32
#define EXE_SUFFIX ".exe"
#else
#define EXE_SUFFIX ""
#endif

typedef struct { const char *name, *purpose; } Builtin;
static const Builtin builtins[] = {
    {"guide", "brief for the files you will touch: rules, CI steps, lessons, traps"},
    {"select", "which local-ci steps a diff needs"},
    {"check-rules", "every source file has an impact rule, every rule matches a file"},
    {"check-docs", "agent documents point at tracked paths and known steps"},
    {"receipt", "print the latest local-ci receipt of one step"},
    {"help", "this table: built-in and discovered subcommands"},
    {NULL, NULL}};

static char exe_dir[1024];

/* Directory of the running executable, or "" when it cannot be found. */
static void find_exe_dir(const char *argv0)
{
    char buf[1024];
    exe_dir[0] = 0;
    (void)argv0; /* unused on Windows */
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, buf, sizeof buf);
    if (n == 0 || n >= sizeof buf) return;
#else
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) {
        if (!argv0 || !strchr(argv0, '/') || strlen(argv0) >= sizeof buf) return;
        snprintf(buf, sizeof buf, "%s", argv0);
        n = (ssize_t)strlen(buf);
    }
#endif
    buf[n] = 0;
    for (char *r = buf; *r; r++) if (*r == '\\') *r = '/';
    char *slash = strrchr(buf, '/');
    if (!slash) return;
    *slash = 0;
    snprintf(exe_dir, sizeof exe_dir, "%s", buf);
}

static int valid_cmd_name(const char *s)
{
    if (!*s || strlen(s) > 64) return 0;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '-')) return 0;
    return 1;
}

static int is_builtin(const char *cmd)
{
    for (const Builtin *b = builtins; b->name; b++) if (!strcmp(b->name, cmd)) return 1;
    return 0;
}

/* Path of zcl-dev-<cmd> in exe_dir or ./zcutil/bin (cwd is the repo root), or 0. */
static int find_sub(const char *cmd, char *out, size_t cap)
{
    const char *dirs[2] = {exe_dir[0] ? exe_dir : NULL, "zcutil/bin"};
    for (int i = 0; i < 2; i++) {
        if (!dirs[i]) continue;
        snprintf(out, cap, "%s/zcl-dev-%s%s", dirs[i], cmd, EXE_SUFFIX);
        FILE *f = fopen(out, "rb");
        if (f) { fclose(f); return 1; }
    }
    return 0;
}

/* Quote one argument by the CommandLineToArgvW rules (MSVCRT re-parses the joined command line).
 * Returns a malloc()ed string. Compiled everywhere so `zcl-dev __quote` can test it off Windows. */
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

#ifndef _WIN32
/* Run `path --purpose` without a shell, with a 5 s alarm; returns a stream of its stdout. */
static pid_t purpose_pid;
static FILE *purpose_pipe(const char *path)
{
    int fd[2];
    if (pipe(fd)) return NULL;
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return NULL; }
    if (!pid) {
        alarm(5);
        dup2(fd[1], 1);
        close(fd[0]); close(fd[1]);
        execl(path, path, "--purpose", (char *)NULL);
        _exit(127);
    }
    close(fd[1]);
    purpose_pid = pid;
    return fdopen(fd[0], "r");
}
#endif

static int run_sub(const char *path, char **args)
{
#ifdef _WIN32
    size_t na = 0;
    while (args[na]) na++;
    char **qa = xrealloc(NULL, (na + 1) * sizeof *qa);
    for (size_t i = 0; i < na; i++) qa[i] = quote_arg(args[i]);
    qa[na] = NULL;
    intptr_t rc = _spawnv(_P_WAIT, path, (const char *const *)qa);
    if (rc == -1) die("cannot run %s", path);
    return (int)rc;
#else
    execv(path, args);
    die("cannot run %s", path);
    return 2;
#endif
}

static int dispatch(const char *cmd, int argc, char **argv, const char *dir)
{
    char path[1400];
    if (!valid_cmd_name(cmd)) { fprintf(stderr, "zcl-dev: unknown command; see zcl-dev help\n"); return 2; }
    enter_repo(dir);
    if (!find_sub(cmd, path, sizeof path)) {
        fprintf(stderr, "zcl-dev: unknown command; see zcl-dev help\n");
        return 2;
    }
#ifdef _WIN32
    _putenv_s("ZCL_DEV_PREFIX", prefix);
#else
    setenv("ZCL_DEV_PREFIX", prefix, 1);
#endif
    char **args = xrealloc(NULL, ((size_t)argc + 2) * sizeof *args);
    args[0] = path;
    for (int i = 0; i < argc; i++) args[i + 1] = argv[i];
    args[argc + 1] = NULL;
    return run_sub(path, args);
}

static int name_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static int cmd_help(void)
{
    puts("usage: zcl-dev [-C dir] <command> [args]\n\nbuilt in:");
    for (const Builtin *b = builtins; b->name; b++) printf("  %-14s %s\n", b->name, b->purpose);
    List names = {0};
    const char *dirs[2] = {exe_dir[0] ? exe_dir : NULL, "zcutil/bin"};
    for (int i = 0; i < 2; i++) {
        if (!dirs[i]) continue;
        DIR *d = opendir(dirs[i]);
        if (!d) continue;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (strncmp(e->d_name, "zcl-dev-", 8)) continue;
            char name[80];
            snprintf(name, sizeof name, "%s", e->d_name + 8);
            size_t n = strlen(name);
            if (n > 4 && !strcmp(name + n - 4, ".exe")) name[n - 4] = 0;
            if (!valid_cmd_name(name) || is_builtin(name) || list_has(&names, name)) continue;
            list_push(&names, name);
        }
        closedir(d);
    }
    qsort(names.v, names.n, sizeof *names.v, name_cmp);
    if (names.n) puts("\ndiscovered (zcl-dev-<cmd> --purpose):");
    for (size_t i = 0; i < names.n; i++) {
        char path[1400], line[256] = "";
        if (find_sub(names.v[i], path, sizeof path)) {
#ifdef _WIN32
            char cmd[1500];
            snprintf(cmd, sizeof cmd, "\"%s\" --purpose", path);
            FILE *p = popen(cmd, "r");
#else
            FILE *p = purpose_pipe(path);
#endif
            if (p) {
                if (!fgets(line, sizeof line, p)) line[0] = 0;
#ifdef _WIN32
                pclose(p);
#else
                fclose(p);
                kill(purpose_pid, SIGKILL);
                waitpid(purpose_pid, NULL, 0);
#endif
                line[strcspn(line, "\r\n")] = 0;
            }
        }
        printf("  %-14s %s\n", names.v[i], line[0] ? line : "(no --purpose output)");
    }
    return 0;
}

int main(int argc, char **argv)
{
    int a = 1;
    const char *dir = NULL;
    find_exe_dir(argv[0]);
    if (a + 1 < argc && !strcmp(argv[a], "-C")) { dir = argv[a + 1]; a += 2; }
    if (a >= argc || !strcmp(argv[a], "-h") || !strcmp(argv[a], "--help")) {
        fputs("usage: zcl-dev [-C dir] guide [--json] <path>...\n"
              "       zcl-dev [-C dir] select [--json|--steps] [--stdin] [base-ref]\n"
              "       zcl-dev [-C dir] check-rules | check-docs\n"
              "       zcl-dev receipt <step> [dir]\n"
              "       zcl-dev help                 built-in and discovered subcommands\n"
              "       zcl-dev [-C dir] <cmd> ...   runs zcl-dev-<cmd> (see help)\n", stderr);
        return 2;
    }
    const char *cmd = argv[a++];
    if (!strcmp(cmd, "__quote")) { /* test hook: one quoted argument per line */
        for (; a < argc; a++) { char *q = quote_arg(argv[a]); puts(q); free(q); }
        return 0;
    }
    if (!strcmp(cmd, "help")) {
        if (dir && chdir(dir)) die("cannot chdir to %s", dir);
        { /* find the repo root when there is one, so zcutil/bin is listed from a subdirectory */
            List l = {0};
            if (!cmd_lines("git rev-parse --show-toplevel", &l) && l.n && chdir(l.v[0]))
                die("cannot chdir to %s", l.v[0]);
        }
        return cmd_help();
    }
    if (!strcmp(cmd, "receipt")) {
        if (dir && chdir(dir)) die("cannot chdir to %s", dir);
        return cmd_receipt(argc - a, argv + a);
    }
    if (!is_builtin(cmd)) return dispatch(cmd, argc - a, argv + a, dir);
    enter_repo(dir);
    if (!strcmp(cmd, "guide")) return cmd_guide(argc - a, argv + a);
    if (!strcmp(cmd, "select")) return cmd_select(argc - a, argv + a);
    if (!strcmp(cmd, "check-rules")) return cmd_check_rules();
    if (!strcmp(cmd, "check-docs")) return cmd_check_docs();
    die("unknown command; see zcl-dev help");
    return 2;
}
