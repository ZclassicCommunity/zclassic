/*
 * Fixture tests for zcl-dev-compdb: each case under <fixtures>/<case>/src is a tiny Makefile whose
 * compiler is a fake `g++` that `make -n` never runs. The tool runs in-process; its database, log and
 * exit status (the fixtures path masked as @W@) must equal <fixtures>/../golden/<case>.txt.
 *
 * usage: zcl-compdb-test <fixtures dir> [--update]     (--update rewrites the goldens)
 * Builds alone: cc -std=gnu17 -o zcl-compdb-test test/compdb_test.c   (it includes the tool source)
 */
#define main compdb_main
#include "../zcl-dev-compdb.c"
#undef main
#include <fcntl.h>

#ifdef _WIN32
#define MKDIR(p) _mkdir(p)
#define NULL_DEV "NUL"
#define SETENV_MAKE(v) _putenv("ZCL_COMPDB_MAKE=" v)
#else
#define MKDIR(p) mkdir((p), 0777)
#define NULL_DEV "/dev/null"
#define SETENV_MAKE(v) setenv("ZCL_COMPDB_MAKE", (v), 1)
#endif

#define FX_CHECK(c)                                                          \
    do {                                                                     \
        if (!(c)) {                                                          \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c);             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static const char *const cases[] = {"indir",     "recursive", "lt-compile", "ccache", "quoted",
                                    "continued", "duplicate", "subst", "subst-src", "empty",  "vpath", NULL};

typedef struct {
    char *root, *golden, *tmp;
    int update;
} Fx;

static char *abs_real(const char *p)
{
    char cwd[4096];
#ifndef _WIN32
    char *r = realpath(p, NULL);
    if (r) {
        char *c = xstrndup(r, strlen(r));
        free(r);
        return c;
    }
#endif
    if (!getcwd(cwd, sizeof cwd)) return NULL;
    return join_norm(cwd, p);
}

/* s with every occurrence of root replaced by @W@. */
static char *mask_text(const char *s, const char *root)
{
    Buf o = {NULL, 0, 0};
    size_t n = strlen(root);
    while (*s) {
        if (!strncmp(s, root, n)) {
            buf_puts(&o, "@W@");
            s += n;
        } else {
            buf_putc(&o, *s++);
        }
    }
    return buf_take(&o);
}

static int golden_check(const Fx *fx, const char *name, const char *report)
{
    char path[4200];
    size_t len = 0;
    snprintf(path, sizeof path, "%s/%s.txt", fx->golden, name);
    if (fx->update) {
        FILE *f = fopen(path, "wb");
        if (!f) return 1;
        fputs(report, f);
        return fclose(f) != 0;
    }
    char *want = read_file(path, &len);
    int bad = !want || strcmp(want, report) != 0;
    if (bad) fprintf(stderr, "FAIL %s: differs from %s\n--- got\n%s", name, path, report);
    free(want);
    return bad;
}

static int run_case(const Fx *fx, const char *name)
{
    char dir[4200], out[4200], tail[32];
    Opts o = {dir, out, "src", 0, 0};
    Buf log = {NULL, 0, 0}, rep = {NULL, 0, 0};
    size_t len = 0;
    snprintf(dir, sizeof dir, "%s/%s", fx->root, name);
    snprintf(out, sizeof out, "%s/%s.json", fx->tmp, name);
    int rc = run_compdb(&o, &log);
    char *json = read_file(out, &len);
    remove(out);
    if (json) buf_puts(&rep, json);
    free(json);
    buf_puts(&rep, "--- log\n");
    if (log.s) buf_puts(&rep, log.s);
    snprintf(tail, sizeof tail, "exit=%d\n", rc);
    buf_puts(&rep, tail);
    char *masked = mask_text(rep.s, fx->root);
    int bad = golden_check(fx, name, masked);
    free(masked);
    free(rep.s);
    free(log.s);
    return bad;
}

static int run_with(const Fx *fx, const char *name, const char *out_name, int check, Buf *log)
{
    char dir[4200], out[4200];
    Opts o = {dir, out, "src", check, 0};
    snprintf(dir, sizeof dir, "%s/%s", fx->root, name);
    snprintf(out, sizeof out, "%s/%s", fx->tmp, out_name);
    return run_compdb(&o, log);
}

static int file_exists(const Fx *fx, const char *name)
{
    char path[4200];
    struct stat st;
    snprintf(path, sizeof path, "%s/%s", fx->tmp, name);
    return stat(path, &st) == 0;
}

/* --check: fresh after a write, stale once edited, stale when missing, and it never writes. */
static int check_flow(const Fx *fx)
{
    char path[4200];
    Buf log = {NULL, 0, 0};
    snprintf(path, sizeof path, "%s/chk.json", fx->tmp);
    FX_CHECK(run_with(fx, "indir", "chk.json", 0, &log) == 0);
    FX_CHECK(run_with(fx, "indir", "chk.json", 1, &log) == 0);
    FILE *f = fopen(path, "ab");
    FX_CHECK(f && fputs(" ", f) >= 0 && fclose(f) == 0);
    FX_CHECK(run_with(fx, "indir", "chk.json", 1, &log) == 1);
    FX_CHECK(remove(path) == 0);
    FX_CHECK(run_with(fx, "indir", "chk.json", 1, &log) == 1);
    FX_CHECK(!file_exists(fx, "chk.json"));
    free(log.s);
    return 0;
}

/* A missing build directory is hollow; a missing make is UNAVAILABLE; neither writes a file. */
static int failure_flow(const Fx *fx)
{
    Buf log = {NULL, 0, 0};
    /* make complains about the missing directory on stderr; keep that out of the test log */
    fflush(NULL);
    int save = dup(2), nul = open(NULL_DEV, O_WRONLY);
    FX_CHECK(save >= 0 && nul >= 0 && dup2(nul, 2) >= 0);
    int nrc = run_with(fx, "nowhere", "nowhere.json", 0, &log);
    fflush(NULL);
    dup2(save, 2);
    close(save);
    close(nul);
    FX_CHECK(nrc == 2);
    FX_CHECK(!file_exists(fx, "nowhere.json"));
    free(log.s);
    log.s = NULL;
    log.n = log.cap = 0;
    SETENV_MAKE("zcl-compdb-no-such-make");
    int rc = run_with(fx, "indir", "nomake.json", 0, &log);
    SETENV_MAKE("");
    FX_CHECK(rc == 2 && log.s && strstr(log.s, "UNAVAILABLE"));
    FX_CHECK(!file_exists(fx, "nomake.json"));
    free(log.s);
    return 0;
}

static void cleanup_tmp(const Fx *fx)
{
    static const char *const extra[] = {"chk.json", "nowhere.json", "nomake.json"};
    char path[4200];
    for (int i = 0; cases[i]; i++) {
        snprintf(path, sizeof path, "%s/%s.json", fx->tmp, cases[i]);
        remove(path);
    }
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof path, "%s/%s", fx->tmp, extra[i]);
        remove(path);
    }
    rmdir(fx->tmp);
}

static int run_all(Fx *fx)
{
    char tmp[4200];
    int bad = 0;
    const char *base = getenv("TMPDIR");
    if (!base || !*base) base = getenv("TEMP");
    if (!base || !*base) base = "/tmp";
    snprintf(tmp, sizeof tmp, "%s/zcl-compdb-test-%ld", base, (long)getpid());
    fx->tmp = tmp;
    if (MKDIR(tmp) != 0) {
        fprintf(stderr, "compdb-test: cannot create %s: %s\n", tmp, strerror(errno));
        return 2;
    }
    for (int i = 0; cases[i]; i++) bad |= run_case(fx, cases[i]);
    bad |= check_flow(fx);
    bad |= failure_flow(fx);
    cleanup_tmp(fx);
    return bad;
}

int main(int argc, char **argv)
{
    Fx fx = {NULL, NULL, NULL, 0};
    if (argc < 2 || argc > 3 || (argc == 3 && strcmp(argv[2], "--update"))) {
        fputs("usage: zcl-compdb-test <fixtures dir> [--update]\n", stderr);
        return 2;
    }
    fx.update = argc == 3;
    fx.root = abs_real(argv[1]);
    if (!fx.root) return 2;
    fx.golden = join_norm(fx.root, "../golden");
    int rc = run_all(&fx);
    free(fx.root);
    free(fx.golden);
    if (!rc) puts("compdb fixture tests ok");
    return rc;
}
