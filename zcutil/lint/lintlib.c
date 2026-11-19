/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_hardening_ratchet.c, gate_no_new_bash.c and gate_markdown_links.c
 * @1f5d0f69448c4811884b2c918ae0723ab24830da, and (helper semantics) Z23 tools/lint/lintc/lib.c and
 * tools/lint/strip_c_comments.awk@9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim. See NOTICE.
 */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under a POSIX-only mask */
#endif
#include "lintlib.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

const char *lint_root = ".";

/* ---- small helpers --------------------------------------------------------------------- */

void *lint_xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "zcl-lint: out of memory\n"); exit(2); }
    return q;
}

char *lint_xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(lint_xrealloc(NULL, n), s, n);
}

char *lint_rootpath(const char *rel)
{
    size_t n = strlen(lint_root) + strlen(rel) + 2;
    char *p = lint_xrealloc(NULL, n);
    snprintf(p, n, "%s/%s", lint_root, rel);
    return p;
}

/* Whole file into a NUL-terminated buffer; NULL when unreadable. */
char *lint_slurp(const char *rel, size_t *len)
{
    char *p = lint_rootpath(rel);
    FILE *f = fopen(p, "rb");
    free(p);
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    char *buf = lint_xrealloc(NULL, cap);
    size_t r;
    while ((r = fread(buf + n, 1, cap - n - 1, f)) > 0) {
        n += r;
        if (n + 1 >= cap) { cap *= 2; buf = lint_xrealloc(buf, cap); }
    }
    fclose(f);
    buf[n] = '\0';
    if (len) *len = n;
    return buf;
}

bool lint_has_prefix(const char *s, const char *p) { return strncmp(s, p, strlen(p)) == 0; }

bool lint_has_suffix(const char *s, const char *x)
{
    size_t n = strlen(s), k = strlen(x);
    return n >= k && strcmp(s + n - k, x) == 0;
}

int lint_cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
/* ---- tracked files (git ls-files -z) --------------------------------------------------- */

char **lint_files;
size_t lint_nfiles;

void lint_load_tracked(void)
{
    char *args[] = { "ls-files", "-z", NULL };
    size_t n = 0;
    char *buf = lint_git_out(args, &n);
    if (!buf || n == 0) { fprintf(stderr, "zcl-lint: git ls-files failed in %s\n", lint_root); exit(2); }
    size_t i = 0, fc = 0;
    while (i < n) {
        if (lint_nfiles == fc) { fc = fc ? fc * 2 : 1024; lint_files = lint_xrealloc(lint_files, fc * sizeof *lint_files); }
        lint_files[lint_nfiles++] = lint_xstrdup(buf + i);
        i += strlen(buf + i) + 1;
    }
    free(buf);
    qsort(lint_files, lint_nfiles, sizeof *lint_files, lint_cmp_str);
}

bool lint_is_tracked(const char *path)
{
    return bsearch(&path, lint_files, lint_nfiles, sizeof *lint_files, lint_cmp_str) != NULL;
}

/* A directory is "tracked" when some tracked path lies below it. */
bool lint_dir_tracked(const char *dir)
{
    size_t n = strlen(dir);
    for (size_t i = 0; i < lint_nfiles; i++)
        if (strncmp(lint_files[i], dir, n) == 0 && lint_files[i][n] == '/') return true;
    return false;
}

/* Vendored or third-party trees: edits there are the vendor rule's business, not a style gate's. */
bool lint_is_vendored(const char *p)
{
    static const char *const roots[] = {
        "src/c23/vendor/", "src/c23/services/vendor/", "zcutil/tools/vendor/", "src/secp256k1/", "src/leveldb/",
        "src/univalue/", "depends/", "wallet/src/3rdparty/", "src/pow/tromp/" };
    for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++)
        if (lint_has_prefix(p, roots[i])) return true;
    return false;
}

/* ---- findings and baselines ------------------------------------------------------------ */


void lint_rows_add(struct lint_rows *r, const char *path, long count)
{
    if (r->n == r->cap) { r->cap = r->cap ? r->cap * 2 : 64; r->v = lint_xrealloc(r->v, r->cap * sizeof *r->v); }
    r->v[r->n].path = lint_xstrdup(path);
    r->v[r->n].count = count;
    r->n++;
}

int lint_cmp_row(const void *a, const void *b) { return strcmp(((const struct lint_row *)a)->path, ((const struct lint_row *)b)->path); }

long lint_rows_find(const struct lint_rows *r, const char *path)
{
    if (!r->n) return -1;
    struct lint_row key = { (char *)path, 0 };
    const struct lint_row *hit = bsearch(&key, r->v, r->n, sizeof *r->v, lint_cmp_row);
    return hit ? hit->count : -1;
}

static char *baseline_rel(const char *rule)
{
    size_t n = strlen(rule) + 32;
    char *p = lint_xrealloc(NULL, n);
    snprintf(p, n, "zcutil/lint/%s.txt", rule);
    return p;
}

/* Load a baseline; *exists says whether the file was there. Rows are re-sorted so a hand edit is forgiven. */
static struct lint_rows load_baseline(const char *rule, bool *exists)
{
    struct lint_rows r = { NULL, 0, 0 };
    char *rel = baseline_rel(rule), *txt = lint_slurp(rel, NULL);
    free(rel);
    *exists = txt != NULL;
    if (!txt) return r;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        if (line[0] == '#' || line[0] == '\0') continue;
        char *tab = strrchr(line, '\t');
        if (!tab) { fprintf(stderr, "zcl-lint: %s baseline: bad row '%s'\n", rule, line); exit(2); }
        *tab = '\0';
        lint_rows_add(&r, line, atol(tab + 1));
    }
    free(txt);
    if (r.n) qsort(r.v, r.n, sizeof *r.v, lint_cmp_row);
    return r;
}

static int write_baseline(const char *rule, const char *what, const struct lint_rows *cur)
{
    char *rel = baseline_rel(rule), *p = lint_rootpath(rel);
    FILE *f = fopen(p, "wb");
    free(rel);
    free(p);
    if (!f) { fprintf(stderr, "zcl-lint: cannot write baseline for %s: %s\n", rule, strerror(errno)); return 2; }
    fprintf(f, "# zcl-lint %s baseline: %s per path.\n", rule, what);
    fprintf(f, "# Shrink-only: lower a count or delete a row when it falls; never raise one or add a path.\n");
    fprintf(f, "# Regenerate with: zcl-lint %s --update-baseline (refused while anything rose).\n", rule);
    for (size_t i = 0; i < cur->n; i++) fprintf(f, "%s\t%ld\n", cur->v[i].path, cur->v[i].count);
    fclose(f);
    return 0;
}

/* The lint_ratchet: compare findings with the baseline. Returns 0 clean, 1 findings, 2 error. */
int lint_ratchet(const char *rule, const char *what, struct lint_rows *cur, size_t scanned, bool update)
{
    if (!scanned) return lint_hollow(rule, scanned);
    bool exists;
    struct lint_rows base = load_baseline(rule, &exists);
    if (cur->n) qsort(cur->v, cur->n, sizeof *cur->v, lint_cmp_row);
    int bad = 0, shrunk = 0;
    long total = 0;
    for (size_t i = 0; i < cur->n; i++) {
        long b = lint_rows_find(&base, cur->v[i].path), c = cur->v[i].count;
        total += c;
        if (!exists) continue;
        if (b < 0) { printf("FAIL %s: %s: %ld new (not in the baseline)\n", rule, cur->v[i].path, c); bad++; }
        else if (c > b) { printf("FAIL %s: %s: %ld, baseline %ld (rose)\n", rule, cur->v[i].path, c, b); bad++; }
        else if (c < b) shrunk++;
    }
    for (size_t i = 0; exists && i < base.n; i++)
        if (lint_rows_find(cur, base.v[i].path) < 0) shrunk++;
    if (update) {
        if (bad) { printf("%s: baseline NOT updated: counts rose or paths are new (fix them, the baseline only shrinks)\n", rule); return 1; }
        if (exists && !shrunk) { printf("%s: baseline already tight (%zu paths, %ld)\n", rule, cur->n, total); return 0; }
        int rc = write_baseline(rule, what, cur);
        if (!rc) printf("%s: baseline %s (%zu paths, %ld)\n", rule, exists ? "lowered" : "created", cur->n, total);
        return rc;
    }
    if (!exists) { printf("FAIL %s: no baseline zcutil/lint/%s.txt (create it with: zcl-lint %s --update-baseline)\n", rule, rule, rule); return 1; }
    if (bad) return 1;
    if (shrunk) printf("%s: ok, but the baseline can be lowered (%d path(s) fell): run zcl-lint %s --update-baseline\n", rule, shrunk, rule);
    else printf("%s: ok (%zu paths, %ld)\n", rule, cur->n, total);
    return 0;
}

/* ---- shell detection ------------------------------------------------------------------- */

/* First line of a tracked file names sh, bash, dash or ksh (directly or through env). */
bool lint_shebang_is_shell(const char *txt)
{
    if (txt[0] != '#' || txt[1] != '!') return false;
    char line[256];
    size_t n = strcspn(txt, "\r\n");
    if (n >= sizeof line) n = sizeof line - 1;
    memcpy(line, txt, n);
    line[n] = '\0';
    static const char *const shells[] = { "sh", "bash", "dash", "ksh" };
    for (char *w = strtok(line + 2, " \t"); w; w = strtok(NULL, " \t")) {
        if (w[0] == '-' || strchr(w, '=')) continue;
        char *base = strrchr(w, '/');
        base = base ? base + 1 : w;
        if (strcmp(base, "env") == 0) continue;
        for (size_t i = 0; i < sizeof shells / sizeof shells[0]; i++)
            if (strcmp(base, shells[i]) == 0) return true;
        return false;
    }
    return false;
}

bool lint_shebang_is_bash(const char *txt)
{
    if (!lint_shebang_is_shell(txt)) return false;
    size_t n = strcspn(txt, "\r\n");
    for (size_t i = 0; i + 4 <= n; i++)
        if (memcmp(txt + i, "bash", 4) == 0) return true;
    return false;
}

/* Shell file by suffix, else by the first line (only 128 bytes are read). */
bool lint_is_shell_file(const char *path)
{
    if (lint_has_suffix(path, ".sh") || lint_has_suffix(path, ".bash")) return true;
    char *p = lint_rootpath(path), head[128];
    FILE *f = fopen(p, "rb");
    free(p);
    if (!f) return false;
    size_t n = fread(head, 1, sizeof head - 1, f);
    fclose(f);
    head[n] = '\0';
    return lint_shebang_is_shell(head);
}

bool lint_is_c_source(const char *p)
{
    static const char *const ext[] = { ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc" };
    for (size_t i = 0; i < sizeof ext / sizeof ext[0]; i++)
        if (lint_has_suffix(p, ext[i])) return true;
    return false;
}
bool lint_idc(int c) { return c == '_' || isalnum(c); }

/* Blank out comments, string and char literals of one line; *blk carries an open block comment across lines. */
void lint_scrub_c_line(char *s, bool *blk)
{
    for (size_t i = 0; s[i]; i++) {
        if (*blk) {
            if (s[i] == '*' && s[i + 1] == '/') { s[i] = s[i + 1] = ' '; i++; *blk = false; }
            else s[i] = ' ';
        } else if (s[i] == '/' && s[i + 1] == '*') { s[i] = s[i + 1] = ' '; i++; *blk = true; }
        else if (s[i] == '/' && s[i + 1] == '/') { memset(s + i, ' ', strlen(s + i)); return; }
        else if (s[i] == '"' || s[i] == '\'') {
            char q = s[i];
            for (i++; s[i] && s[i] != q; i++) {
                if (s[i] == '\\' && s[i + 1]) s[i++] = ' ';
                s[i] = ' ';
            }
            if (!s[i]) return;
        }
    }
}


/* ---- child processes without a shell ------------------------------------------------------ */
/* Arguments reach a program as an argv array on POSIX, so no root, tracked file name or document token can
 * break out of quoting. The Windows build has only a command string, so it refuses every argument that cmd.exe
 * or the CRT could read as syntax instead of quoting it. */

#ifdef _WIN32
static bool win_arg_ok(const char *a)
{
    return a[0] != '\0' && strlen(a) < 1000 && !strpbrk(a, "\"'%&|<>^!`$;()\r\n\t");
}
/* "a" "b" ... (+ redirection); NULL when an argument is unsafe or the line would be truncated. */
static char *win_line(const char *cwd, char *const argv[], int flags)
{
    size_t cap = 64;
    for (size_t i = 0; argv[i]; i++) { if (!win_arg_ok(argv[i])) return NULL; cap += strlen(argv[i]) + 3; }
    if (cwd) { if (!win_arg_ok(cwd)) return NULL; cap += strlen(cwd) + 12; }
    char *s = lint_xrealloc(NULL, cap), *w = s;
    if (cwd) w += snprintf(w, cap, "cd /d \"%s\" && ", cwd);
    for (size_t i = 0; argv[i]; i++) w += snprintf(w, cap - (size_t)(w - s), "%s\"%s\"", i ? " " : "", argv[i]);
    if (flags & LINT_PROC_QUIET) snprintf(w, cap - (size_t)(w - s), " >NUL 2>&1");
    else if (flags & LINT_PROC_MERGE) snprintf(w, cap - (size_t)(w - s), " 2>&1");
    return s;
}
#endif

#ifndef _WIN32
/* In the forked child: wire stdout (and stderr) to the pipe or the null device, enter cwd, exec. Never returns. */
static void child_exec(const char *cwd, char *const argv[], int flags, const int fd[2])
{
    if (flags & LINT_PROC_QUIET) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul < 0 || dup2(nul, 1) < 0 || dup2(nul, 2) < 0) _exit(127);
    } else if (!(flags & LINT_PROC_INHERIT)) {
        if (dup2(fd[1], 1) < 0) _exit(127);
        if ((flags & LINT_PROC_MERGE) && dup2(fd[1], 2) < 0) _exit(127);
        close(fd[0]);
        close(fd[1]);
    }
    if (cwd && chdir(cwd) != 0) _exit(127);
    execvp(argv[0], argv);
    _exit(127);
}
#endif

int lint_proc_open(struct lint_proc *p, const char *cwd, char *const argv[], int flags)
{
    p->fp = NULL;
    p->pid = -1;
    fflush(stdout);
    fflush(stderr);
#ifndef _WIN32
    int fd[2] = { -1, -1 };
    bool piped = !(flags & (LINT_PROC_QUIET | LINT_PROC_INHERIT));
    if (piped && pipe(fd) != 0) return -1;
    pid_t pid = fork();
    if (pid == 0) child_exec(cwd, argv, flags, fd);
    if (piped) close(fd[1]);
    if (pid < 0) { if (piped) close(fd[0]); return -1; }
    p->pid = (long)pid;
    if (piped && !(p->fp = fdopen(fd[0], "r"))) { close(fd[0]); lint_proc_close(p); return -1; }
    return 0;
#else
    char *line = win_line(cwd, argv, flags);
    if (!line) { fprintf(stderr, "zcl-lint: refusing an argument that cmd.exe could read as syntax\n"); return -1; }
    if (!(flags & LINT_PROC_MERGE) && (flags & (LINT_PROC_QUIET | LINT_PROC_INHERIT))) { p->pid = system(line); free(line); return p->pid == -1 ? -1 : 0; }
    p->fp = popen(line, "r");
    free(line);
    return p->fp ? 0 : -1;
#endif
}

int lint_proc_close(struct lint_proc *p)
{
#ifndef _WIN32
    if (p->fp) { fclose(p->fp); p->fp = NULL; }
    int st = 0;
    pid_t r;
    do r = waitpid((pid_t)p->pid, &st, 0); while (r < 0 && errno == EINTR);
    p->pid = -1;
    if (r < 0 || !WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
#else
    if (p->fp) { int st = pclose(p->fp); p->fp = NULL; return st; }
    return (int)p->pid;
#endif
}

int lint_status_argv(const char *cwd, char *const argv[], bool quiet)
{
    struct lint_proc p;
    if (lint_proc_open(&p, cwd, argv, quiet ? LINT_PROC_QUIET : LINT_PROC_INHERIT) != 0) return -1;
    return lint_proc_close(&p);
}

int lint_run_argv(char *const argv[], bool quiet)
{
    int st = lint_status_argv(NULL, argv, quiet);
    if (st == 0) return 0;
    return st == 2 ? 2 : 1; /* 2: the script reported a hollow scan */
}

/* Whole stdout of `git -C <lint_root> <args...>` (NUL-terminated, length in *len); NULL when git cannot run or
 * exits nonzero. */
char *lint_git_out(char *const args[], size_t *len)
{
    char *argv[16] = { "git", "-C", (char *)lint_root };
    size_t k = 3;
    for (size_t i = 0; args[i] && k < 15; i++) argv[k++] = args[i];
    argv[k] = NULL;
    struct lint_proc p;
    if (lint_proc_open(&p, NULL, argv, 0) != 0) return NULL;
    size_t cap = 4096, n = 0, r;
    char *buf = lint_xrealloc(NULL, cap);
    while ((r = fread(buf + n, 1, cap - n, p.fp)) > 0) {
        n += r;
        if (n == cap) { cap *= 2; buf = lint_xrealloc(buf, cap); }
    }
    if (lint_proc_close(&p) != 0) { free(buf); return NULL; }
    buf = lint_xrealloc(buf, n + 1);
    buf[n] = '\0';
    *len = n;
    return buf;
}

/* Blank sh comments (a # at the start of a word) and quoted text. Heredoc bodies are not recognised. */
void lint_scrub_sh_line(char *s, char *quote)
{
    for (size_t i = 0; s[i]; i++) {
        if (*quote) {
            if (*quote == '"' && s[i] == '\\' && s[i + 1]) { s[i] = ' '; i++; s[i] = ' '; continue; }
            if (s[i] == *quote) *quote = 0;
            s[i] = ' ';
        } else if (s[i] == '\\' && s[i + 1]) {
            i++;
        } else if (s[i] == '\'' || s[i] == '"') {
            *quote = s[i];
            s[i] = ' ';
        } else if (s[i] == '#' && (i == 0 || isspace((unsigned char)s[i - 1]) || strchr(";&|(", s[i - 1]))) {
            memset(s + i, ' ', strlen(s + i));
            return;
        }
    }
}

int lint_hollow(const char *rule, size_t scanned)
{
    if (scanned) return 0;
    printf("FAIL %s: hollow scan (no file was scanned; an empty scan set is a failure, not a pass)\n", rule);
    return 2;
}
