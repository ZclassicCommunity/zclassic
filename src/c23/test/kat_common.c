/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). See kat_common.h. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "kat_common.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <process.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

const char KAT_SPEND_HASH[] =
    "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
const char KAT_OUTPUT_HASH[] =
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
const char KAT_SPROUT_HASH[] =
    "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";

const char *kat_cur_file = "";

void *kat_xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "out of memory (%zu bytes)\n", n);
        exit(2);
    }
    return p;
}

bool kat_read_line(FILE *f, char **buf, size_t *cap)
{
    size_t len = 0;
    if (!*buf) {
        *cap = 4096;
        *buf = kat_xmalloc(*cap);
    }
    for (;;) {
        if (!fgets(*buf + len, (int)(*cap - len), f))
            return len > 0;
        len += strlen(*buf + len);
        if (len && (*buf)[len - 1] == '\n')
            return true;
        if (len + 1 < *cap)
            continue; /* short read without newline: EOF next */
        size_t ncap = *cap * 2;
        char *nb = realloc(*buf, ncap);
        if (!nb) {
            fprintf(stderr, "out of memory reading line\n");
            exit(2);
        }
        *buf = nb;
        *cap = ncap;
    }
}

void kat_tokenize(const char *line, unsigned long lineno, KatToks *k)
{
    size_t len = strlen(line);
    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        len--;
    char *copy = kat_xmalloc(len + 1);
    memcpy(copy, line, len);
    copy[len] = 0;
    k->n = 0;
    k->base = copy;
    k->lineno = lineno;
    char *p = copy;
    while (*p) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        if (k->n == KAT_MAXTOK) {
            fprintf(stderr, "%s:%lu: too many fields\n", kat_cur_file, lineno);
            exit(2);
        }
        k->t[k->n++] = p;
        while (*p && *p != ' ')
            p++;
        if (*p)
            *p++ = 0;
    }
}

void kat_toks_free(KatToks *k)
{
    free(k->base);
    k->base = NULL;
    k->n = 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

bool kat_parse_hex(const char *s, unsigned char *out, size_t n)
{
    if (strlen(s) != 2 * n)
        return false;
    for (size_t j = 0; j < n; j++) {
        int h = hexval(s[2 * j]), l = hexval(s[2 * j + 1]);
        if (h < 0 || l < 0)
            return false;
        out[j] = (unsigned char)(h * 16 + l);
    }
    return true;
}

void kat_hexn(const KatToks *k, int i, unsigned char *out, size_t n)
{
    if (i >= k->n) {
        fprintf(stderr, "%s:%lu: missing field %d\n", kat_cur_file, k->lineno, i);
        exit(2);
    }
    if (!kat_parse_hex(k->t[i], out, n)) {
        fprintf(stderr, "%s:%lu: field %d is not %zu hex bytes\n", kat_cur_file, k->lineno, i, n);
        exit(2);
    }
}

uint64_t kat_u64(const KatToks *k, int i)
{
    if (i >= k->n) {
        fprintf(stderr, "%s:%lu: missing field %d\n", kat_cur_file, k->lineno, i);
        exit(2);
    }
    errno = 0;
    char *e = NULL;
    unsigned long long v = strtoull(k->t[i], &e, 10);
    if (errno || !e || *e || k->t[i][0] == '-') {
        fprintf(stderr, "%s:%lu: bad unsigned field %d\n", kat_cur_file, k->lineno, i);
        exit(2);
    }
    return (uint64_t)v;
}

int64_t kat_i64(const KatToks *k, int i)
{
    if (i >= k->n) {
        fprintf(stderr, "%s:%lu: missing field %d\n", kat_cur_file, k->lineno, i);
        exit(2);
    }
    errno = 0;
    char *e = NULL;
    long long v = strtoll(k->t[i], &e, 10);
    if (errno || !e || *e) {
        fprintf(stderr, "%s:%lu: bad signed field %d\n", kat_cur_file, k->lineno, i);
        exit(2);
    }
    return (int64_t)v;
}

void kat_tohex(char *out, const unsigned char *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t j = 0; j < n; j++) {
        out[2 * j] = d[b[j] >> 4];
        out[2 * j + 1] = d[b[j] & 15];
    }
    out[2 * n] = 0;
}

bool kat_eqhex(const KatToks *k, int i, const unsigned char *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    if (i >= k->n)
        return false;
    const char *s = k->t[i];
    if (strlen(s) != 2 * n)
        return false;
    for (size_t j = 0; j < n; j++)
        if (s[2 * j] != d[b[j] >> 4] || s[2 * j + 1] != d[b[j] & 15])
            return false;
    return true;
}

bool kat_is(const KatToks *k, int i, const char *s) { return i < k->n && strcmp(k->t[i], s) == 0; }
const char *kat_tf(bool b) { return b ? "T" : "F"; }

/* ---------------------------------------------------------------- params */

#if defined(_WIN32)
static codeunit *to_codeunits(const char *utf8, size_t *len)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
    if (n <= 0) {
        fprintf(stderr, "path is not UTF-8: %s\n", utf8);
        exit(2);
    }
    wchar_t *w = kat_xmalloc((size_t)n * sizeof(wchar_t));
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, w, n) != n) {
        fprintf(stderr, "UTF-16 conversion failed\n");
        exit(2);
    }
    *len = (size_t)n - 1;
    return (codeunit *)w;
}
#else
static codeunit *to_codeunits(const char *utf8, size_t *len)
{
    size_t n = strlen(utf8);
    codeunit *c = kat_xmalloc(n + 1);
    memcpy(c, utf8, n + 1);
    *len = n;
    return c;
}
#endif

static codeunit *join_path(const char *dir, const char *name, size_t *len)
{
    if (name[0] == 0) { /* an empty path (length 0), not the directory */
        *len = 0;
        return kat_xmalloc(sizeof(codeunit));
    }
    size_t need = strlen(dir) + 1 + strlen(name) + 1;
    char *s = kat_xmalloc(need);
    snprintf(s, need, "%s/%s", dir, name);
    codeunit *c = to_codeunits(s, len);
    free(s);
    return c;
}

void kat_init_params(const char *dir, const char *spend_name, const char *spend_hash, const char *output_name,
                     const char *output_hash, const char *sprout_name, const char *sprout_hash)
{
    size_t sl, ol, gl;
    codeunit *s = join_path(dir, spend_name, &sl);
    codeunit *o = join_path(dir, output_name, &ol);
    codeunit *g = join_path(dir, sprout_name, &gl);
    librustzcash_init_zksnark_params(s, sl, spend_hash, o, ol, output_hash, g, gl, sprout_hash);
    free(s);
    free(o);
    free(g);
}

void kat_init_canonical(const char *dir)
{
    kat_init_params(dir, "sapling-spend.params", KAT_SPEND_HASH, "sapling-output.params", KAT_OUTPUT_HASH,
                    "sprout-groth16.params", KAT_SPROUT_HASH);
}

/* ------------------------------------------------------------- isolation */

static int g_argc;
static char **g_argv;
static bool g_child;
static const char *g_child_file;
static unsigned long g_child_line;

#if defined(_WIN32)
static void child_sigabrt(int sig)
{
    (void)sig;
    fflush(stdout);
    _exit(134);
}
#endif

void kat_isolation_setup(int argc, char **argv)
{
    g_argc = argc;
    g_argv = argv;
#if defined(_WIN32)
    const char *f = getenv("KAT_CHILD_FILE");
    const char *l = getenv("KAT_CHILD_LINE");
    if (f && *f && l && *l) {
        g_child = true;
        g_child_file = f;
        g_child_line = strtoul(l, NULL, 10);
        /* abort() must neither pop a dialog nor go through WER; the SIGABRT
         * handler records "abort() was called" as exit status 134. */
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
        signal(SIGABRT, child_sigabrt);
        if (!getenv("KAT_VERBOSE"))
            (void)freopen("NUL", "w", stderr);
    }
#endif
}

bool kat_in_child(void) { return g_child; }
const char *kat_child_file(void) { return g_child_file; }
unsigned long kat_child_line(void) { return g_child_line; }

const char *kat_child_str(enum kat_child c)
{
    switch (c) {
    case KAT_CHILD_RETURNED:
        return "returned";
    case KAT_CHILD_ABORTED:
        return "aborted";
    case KAT_CHILD_CRASHED:
        return "crashed";
    default:
        return "child-error";
    }
}

#if defined(_WIN32)
static char *quote_arg(const char *a)
{
    if (!strpbrk(a, " \t\"")) {
        size_t n = strlen(a) + 1;
        char *c = kat_xmalloc(n);
        memcpy(c, a, n);
        return c;
    }
    if (strchr(a, '"')) {
        fprintf(stderr, "argument with a double quote cannot be passed to a child: %s\n", a);
        exit(2);
    }
    size_t n = strlen(a) + 3;
    char *c = kat_xmalloc(n);
    snprintf(c, n, "\"%s\"", a);
    return c;
}

enum kat_child kat_isolate(const char *file, unsigned long lineno, void (*fn)(void *), void *arg, long *detail)
{
    if (g_child) {
        fn(arg);
        fflush(stdout);
        fflush(stderr);
        exit(0);
    }
    char exe[MAX_PATH * 4];
    DWORD n = GetModuleFileNameA(NULL, exe, (DWORD)sizeof exe);
    if (n == 0 || n >= sizeof exe) {
        fprintf(stderr, "GetModuleFileNameA failed\n");
        exit(2);
    }
    char line[32];
    snprintf(line, sizeof line, "%lu", lineno);
    if (_putenv_s("KAT_CHILD_FILE", file) != 0 || _putenv_s("KAT_CHILD_LINE", line) != 0) {
        fprintf(stderr, "_putenv_s failed\n");
        exit(2);
    }
    char **av = kat_xmalloc(((size_t)g_argc + 1) * sizeof(char *));
    for (int i = 0; i < g_argc; i++)
        av[i] = quote_arg(g_argv[i]);
    av[g_argc] = NULL;
    fflush(NULL);
    intptr_t rc = _spawnv(_P_WAIT, exe, (const char *const *)av);
    for (int i = 0; i < g_argc; i++)
        free(av[i]);
    free(av);
    (void)_putenv_s("KAT_CHILD_FILE", "");
    (void)_putenv_s("KAT_CHILD_LINE", "");
    if (rc == -1) {
        fprintf(stderr, "_spawnv failed: %s\n", strerror(errno));
        exit(2);
    }
    unsigned long code = (unsigned long)(uint32_t)rc;
    if (detail)
        *detail = (long)code;
    if (code == 0)
        return KAT_CHILD_RETURNED;
    if (code == 134)
        return KAT_CHILD_ABORTED;
    if (code >= 0xC0000000ul)
        return KAT_CHILD_CRASHED;
    return KAT_CHILD_ERROR;
}
#else
enum kat_child kat_isolate(const char *file, unsigned long lineno, void (*fn)(void *), void *arg, long *detail)
{
    (void)file;
    (void)lineno;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) {
        if (!getenv("KAT_VERBOSE")) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0)
                dup2(devnull, 2);
        }
        /* No core files from the expected aborts. */
        signal(SIGABRT, SIG_DFL);
        fn(arg);
        fflush(stdout);
        _exit(0);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) {
            perror("waitpid");
            exit(2);
        }
    }
    if (WIFSIGNALED(st)) {
        if (detail)
            *detail = WTERMSIG(st);
        return WTERMSIG(st) == SIGABRT ? KAT_CHILD_ABORTED : KAT_CHILD_CRASHED;
    }
    if (detail)
        *detail = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? KAT_CHILD_RETURNED : KAT_CHILD_ERROR;
}
#endif

double kat_now(void)
{
#if defined(_WIN32)
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
#endif
}
