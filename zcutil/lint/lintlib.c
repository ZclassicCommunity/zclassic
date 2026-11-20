/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_hardening_ratchet.c, gate_no_new_bash.c and gate_markdown_links.c
 * @1f5d0f69448c4811884b2c918ae0723ab24830da, and (helper semantics) Z23 tools/lint/lintc/lib.c and
 * tools/lint/strip_c_comments.awk@9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim. See NOTICE.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include "lintlib.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#else
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

#ifdef _WIN32
/* A core.autocrlf=true checkout: drop each CR that comes before an LF, so verdicts match the LF tree. */
static size_t fold_crlf(char *buf, size_t n)
{
    size_t w = 0;
    for (size_t r = 0; r < n; r++)
        if (!(buf[r] == '\r' && r + 1 < n && buf[r + 1] == '\n')) buf[w++] = buf[r];
    buf[w] = '\0';
    return w;
}
#endif

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
#ifdef _WIN32
    n = fold_crlf(buf, n);
#endif
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
 * break out of quoting. Windows has one command line per process: CreateProcess receives it quoted by the
 * MSVCRT rules below. No cmd.exe is involved, so % & | < > ^ ! are plain characters there. */

static bool quote_put(char *out, size_t *o, size_t cap, char c, size_t times)
{
    if (*o + times >= cap) return false;
    memset(out + *o, c, times);
    *o += times;
    return true;
}

/* MSVCRT splits on space and tab and unquotes "; an MSYS child (sh.exe) also unquotes ' and globs * ? [ { ~. */
static bool quote_needed(const char *a) { return a[0] == '\0' || strpbrk(a, " \t\"'*?[{~") != NULL; }

static bool quote_one(const char *a, char *out, size_t *o, size_t cap)
{
    if (!quote_needed(a)) {
        size_t n = strlen(a);
        if (*o + n >= cap) return false;
        memcpy(out + *o, a, n);
        *o += n;
        return true;
    }
    if (!quote_put(out, o, cap, '"', 1)) return false;
    size_t bs = 0;
    for (; *a; a++) {
        if (*a == '\\') { bs++; continue; }
        size_t k = *a == '"' ? 2 * bs + 1 : bs;   /* backslashes before a quote are doubled, plus one for it */
        if (!quote_put(out, o, cap, '\\', k) || !quote_put(out, o, cap, *a, 1)) return false;
        bs = 0;
    }
    return quote_put(out, o, cap, '\\', 2 * bs) && quote_put(out, o, cap, '"', 1);
}

int lint_win_quote_argv(char *const argv[], char *out, size_t cap)
{
    size_t o = 0;
    if (!cap) return -1;
    for (size_t i = 0; argv[i]; i++)
        if ((i && !quote_put(out, &o, cap, ' ', 1)) || !quote_one(argv[i], out, &o, cap)) return -1;
    out[o] = '\0';
    return o > (size_t)INT_MAX ? -1 : (int)o;
}

char *lint_tool_path(const char *rel)
{
    static const char *const ext[] = { LINT_EXE, "" };
    for (size_t i = 0; i < sizeof ext / sizeof ext[0]; i++) {
        size_t n = strlen(rel) + strlen(ext[i]) + 1;
        char *r = lint_xrealloc(NULL, n);
        snprintf(r, n, "%s%s", rel, ext[i]);
        char *p = lint_rootpath(r);
        free(r);
        FILE *f = fopen(p, "rb");
        if (f) { fclose(f); return p; }
        free(p);
    }
    return NULL;
}

#ifndef _WIN32
/* In the forked child: point stdout and stderr where flags say. Exits 127 when a descriptor cannot be set. */
static void child_redirect(int flags, const int fd[2])
{
    int nul = -1;
    if ((flags & (LINT_PROC_QUIET | LINT_PROC_NOERR)) && (nul = open("/dev/null", O_WRONLY)) < 0) _exit(127);
    if ((flags & LINT_PROC_QUIET) && dup2(nul, 1) < 0) _exit(127);
    if ((flags & LINT_PROC_TO_STDERR) && dup2(2, 1) < 0) _exit(127);
    if (fd[1] >= 0) {
        if (dup2(fd[1], 1) < 0) _exit(127);
        if ((flags & LINT_PROC_MERGE) && dup2(fd[1], 2) < 0) _exit(127);
        close(fd[0]);
        close(fd[1]);
    }
    if (nul >= 0 && dup2(nul, 2) < 0) _exit(127);
}

/* In the forked child: wire stdout and stderr, enter cwd, exec. Never returns. */
static void child_exec(const char *cwd, char *const argv[], int flags, const int fd[2])
{
    child_redirect(flags, fd);
    if (cwd && chdir(cwd) != 0) _exit(127);
    execvp(argv[0], argv);
    _exit(127);
}

static int posix_open(struct lint_proc *p, const char *cwd, char *const argv[], int flags)
{
    int fd[2] = { -1, -1 };
    bool piped = !(flags & (LINT_PROC_QUIET | LINT_PROC_INHERIT | LINT_PROC_TO_STDERR));
    if (piped && pipe(fd) != 0) return -1;
    pid_t pid = fork();
    if (pid == 0) child_exec(cwd, argv, flags, fd);
    if (piped) close(fd[1]);
    if (pid < 0) { if (piped) close(fd[0]); return -1; }
    p->pid = (long)pid;
    if (piped && !(p->fp = fdopen(fd[0], "r"))) { close(fd[0]); lint_proc_close(p); return -1; }
    return 0;
}

static int posix_close(struct lint_proc *p)
{
    if (p->fp) { fclose(p->fp); p->fp = NULL; }
    int st = 0;
    pid_t r;
    do r = waitpid((pid_t)p->pid, &st, 0); while (r < 0 && errno == EINTR);
    p->pid = -1;
    if (r < 0 || !WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}
#else
/* Windows: CreateProcessA on a quoted command line, stdout through CreatePipe, the null device through
 * CreateFile("NUL"), the working directory through lpCurrentDirectory. */
static HANDLE win_std(DWORD which)   /* an inheritable copy of one of our standard handles, or NULL */
{
    HANDLE h = GetStdHandle(which), d = NULL;
    if (h == NULL || h == INVALID_HANDLE_VALUE) return NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, TRUE, DUPLICATE_SAME_ACCESS)) return NULL;
    return d;
}

static HANDLE win_null(void)
{
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE h = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    return h == INVALID_HANDLE_VALUE ? NULL : h;
}

struct win_io { HANDLE in, out, err, rd; }; /* the child's three handles; rd is our end of the stdout pipe */

static bool win_io_open(struct win_io *io, int flags)
{
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    memset(io, 0, sizeof *io);
    io->in = win_std(STD_INPUT_HANDLE);
    if (flags & LINT_PROC_QUIET) { io->out = io->err = win_null(); return io->out != NULL; }
    io->err = (flags & LINT_PROC_NOERR) ? win_null() : win_std(STD_ERROR_HANDLE);
    if (flags & (LINT_PROC_INHERIT | LINT_PROC_TO_STDERR)) {
        io->out = win_std((flags & LINT_PROC_INHERIT) ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
        return true;
    }
    if (!CreatePipe(&io->rd, &io->out, &sa, 0)) { io->rd = io->out = NULL; return false; }
    SetHandleInformation(io->rd, HANDLE_FLAG_INHERIT, 0);
    if (flags & LINT_PROC_MERGE) {
        if (io->err) CloseHandle(io->err);
        io->err = io->out;
    }
    return true;
}

static void win_io_close(struct win_io *io) /* the child's ends, once it has them (or failed to start) */
{
    if (io->in) CloseHandle(io->in);
    if (io->out) CloseHandle(io->out);
    if (io->err && io->err != io->out) CloseHandle(io->err);
}

static bool win_file(const char *p)
{
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool win_shebang(const char *p)
{
    char h[2] = { 0, 0 };
    FILE *f = fopen(p, "rb");
    if (!f) return false;
    size_t n = fread(h, 1, sizeof h, f);
    fclose(f);
    return n == 2 && h[0] == '#' && h[1] == '!';
}

/* name (".exe" added when it has no extension) in the directories of PATH only, never the current directory. */
static bool win_search(const char *name, char *out, size_t cap)
{
    const char *path = getenv("PATH");
    if (!path || !*path) return false;
    DWORD n = SearchPathA(path, name, ".exe", (DWORD)cap, out, NULL);
    return n > 0 && n < cap;
}

/* A program named by a path: relative to cwd (CreateProcess resolves it against ours), with ".exe" when that exists. */
static void win_path(const char *cwd, const char *a0, char *out, size_t cap)
{
    bool abs = a0[0] == '/' || a0[0] == '\\' || (a0[0] && a0[1] == ':');
    snprintf(out, cap, "%s%s%s", cwd && !abs ? cwd : "", cwd && !abs ? "/" : "", a0);
    size_t n = strlen(out);
    if (lint_has_suffix(out, ".exe") || n + 5 > cap) return;
    memcpy(out + n, ".exe", 5);
    if (!win_file(out)) out[n] = '\0';
}

static int win_unavailable(const char *name)
{
    printf("UNAVAILABLE: %s not found on PATH\n", name);
    fflush(stdout);
    return LINT_PROC_UNAVAILABLE;
}

/* prog: the executable to start. A script (*.sh, or a path whose file starts with #!) runs as sh.exe, and
 * *script is set; argv[0] then stays the script's name relative to the child's working directory. */
static int win_resolve(const char *cwd, const char *a0, char *prog, size_t cap, bool *script)
{
    bool has_dir = strpbrk(a0, "/\\") != NULL;
    *script = lint_has_suffix(a0, ".sh");
    if (has_dir) win_path(cwd, a0, prog, cap);
    else if (!*script && !win_search(a0, prog, cap)) return win_unavailable(a0);
    if (has_dir && !*script) *script = win_shebang(prog);
    if (*script && !win_search("sh", prog, cap)) return win_unavailable("sh");
    return 0;
}

static char *win_cmdline(bool script, char *const argv[])
{
    size_t n = 0, k = 0;
    while (argv[n]) n++;
    char **v = lint_xrealloc(NULL, (n + 2) * sizeof *v);
    if (script) v[k++] = "sh";
    for (size_t i = 0; i <= n; i++) v[k++] = argv[i];
    enum { CMDLINE_MAX = 32767 };
    char *line = lint_xrealloc(NULL, CMDLINE_MAX);
    int len = lint_win_quote_argv(v, line, CMDLINE_MAX);
    free(v);
    if (len < 0) { free(line); return NULL; }
    return line;
}

static bool win_create(struct lint_proc *p, const char *prog, char *line, const char *cwd, const struct win_io *io)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = io->in;
    si.hStdOutput = io->out;
    si.hStdError = io->err;
    if (!CreateProcessA(prog, line, NULL, NULL, TRUE, 0, NULL, cwd, &si, &pi)) {
        fprintf(stderr, "zcl-lint: cannot run %s (Windows error %lu)\n", prog, (unsigned long)GetLastError());
        return false;
    }
    CloseHandle(pi.hThread);
    p->handle = pi.hProcess;
    p->pid = (long)pi.dwProcessId;
    return true;
}

static bool win_args_ok(const char *cwd, char *const argv[])
{
    for (size_t i = 0; argv[i]; i++)
        if (strpbrk(argv[i], "\r\n")) return false;
    return !cwd || !strpbrk(cwd, "\r\n");
}

static bool win_wrap(struct lint_proc *p, HANDLE rd)
{
    int fd = _open_osfhandle((intptr_t)rd, _O_RDONLY | _O_BINARY);
    if (fd < 0) { CloseHandle(rd); return false; }
    if (!(p->fp = _fdopen(fd, "rb"))) { _close(fd); return false; }
    return true;
}

static int win_open(struct lint_proc *p, const char *cwd, char *const argv[], int flags)
{
    char prog[2048];
    bool script;
    if (!win_args_ok(cwd, argv)) { fprintf(stderr, "zcl-lint: refusing an argument with an embedded CR or LF\n"); return -1; }
    int rc = win_resolve(cwd, argv[0], prog, sizeof prog, &script);
    if (rc) return rc;
    char *line = win_cmdline(script, argv);
    if (!line) { fprintf(stderr, "zcl-lint: command line too long for %s\n", argv[0]); return -1; }
    struct win_io io;
    bool ok = win_io_open(&io, flags) && win_create(p, prog, line, cwd, &io);
    win_io_close(&io);
    free(line);
    if (!ok) { if (io.rd) CloseHandle(io.rd); return -1; }
    if (io.rd && !win_wrap(p, io.rd)) { lint_proc_close(p); return -1; }
    return 0;
}

static int win_close(struct lint_proc *p)
{
    if (p->fp) { fclose(p->fp); p->fp = NULL; }
    if (!p->handle) return -1;
    DWORD code = 0;
    bool ok = WaitForSingleObject(p->handle, INFINITE) == WAIT_OBJECT_0 && GetExitCodeProcess(p->handle, &code);
    CloseHandle(p->handle);
    p->handle = NULL;
    p->pid = -1;
    return ok && code <= 255 ? (int)code : -1;
}
#endif

int lint_proc_open(struct lint_proc *p, const char *cwd, char *const argv[], int flags)
{
    p->fp = NULL;
    p->pid = -1;
    p->handle = NULL;
    fflush(stdout);
    fflush(stderr);
#ifdef _WIN32
    return win_open(p, cwd, argv, flags);
#else
    return posix_open(p, cwd, argv, flags);
#endif
}

int lint_proc_close(struct lint_proc *p)
{
#ifdef _WIN32
    return win_close(p);
#else
    return posix_close(p);
#endif
}

int lint_status_argv(const char *cwd, char *const argv[], bool quiet)
{
    struct lint_proc p;
    int rc = lint_proc_open(&p, cwd, argv, quiet ? LINT_PROC_QUIET : LINT_PROC_INHERIT);
    if (rc != 0) return rc;
    return lint_proc_close(&p);
}

int lint_run_argv(char *const argv[], bool quiet)
{
    int st = lint_status_argv(NULL, argv, quiet);
    if (st == 0) return 0;
    return st == 2 || st == LINT_PROC_UNAVAILABLE ? 2 : 1; /* 2: the script reported a hollow scan, or cannot run */
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
