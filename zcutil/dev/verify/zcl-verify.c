/* zcl-dev verify: the one-trip check of committed changes, the analogue of Z23's
 * 'make agent-verify ONLY=@changed'. Libc only; builds with the host cc, clang and the mingw cross
 * compiler.
 *
 *   zcl-dev verify [--base REF] [--json] [--selftest] [--purpose]
 *
 * It runs from the repository root (git rev-parse --show-toplevel) and, in order, stops at the first
 * failing step:
 *   1. zcl-dev select REF            which CI steps and qa scripts the committed diff needs (REF defaults to
 *                                    ZCL_CI_BASE, then origin/master)
 *   2. zcl-dev-t-fast --changed=REF  focused unit tests; SKIPPED with a visible line when that tool is not
 *                                    built (U2 must install the zcl-dev-t-fast alias for this gate to run)
 *   3. zcl-lint all                  every lint rule and ratchet (there is no cheaper subset); zcl-lint is
 *                                    not cross-built, so on Windows this step is UNAVAILABLE: run verify on
 *                                    a POSIX host
 *   4. a hint: the zcutil/local-ci.sh test-changed command that runs the selected CI steps
 * Tools are spawned with an argv array, never through a shell. With --json stdout holds exactly one JSON
 * line; the child tools' output and the progress lines go to stderr.
 * Exit: 0 every step that ran passed, 1 a step found a problem, 2 broken (a required tool is missing,
 * unavailable, or select failed). A skipped optional step never hides behind a pass: the summary names it.
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#define EXE ".exe"
#define popen _popen
#define pclose _pclose
#define GITNULL "NUL"
#else
#include <sys/wait.h>
#include <unistd.h>
#define EXE ""
#define GITNULL "/dev/null"
#endif

static char bindir[1024] = "zcutil/bin";
static FILE *say;   /* progress and summary lines */
static FILE *jout;  /* the single --json line */
static int child_to_stderr;

static void find_bindir(const char *argv0)
{
    const char *p = getenv("ZCL_DEV_BINDIR");
    if (p && *p) { snprintf(bindir, sizeof bindir, "%s", p); return; }
    const char *s = strrchr(argv0, '/');
#ifdef _WIN32
    const char *b = strrchr(argv0, '\\');
    if (b && (!s || b > s)) s = b;
#endif
    if (s && s > argv0) snprintf(bindir, sizeof bindir, "%.*s", (int)(s - argv0), argv0);
}

static int is_absolute(const char *p)
{
    if (*p == '/') return 1;
#ifdef _WIN32
    if (*p == '\\' || (isalpha((unsigned char)p[0]) && p[1] == ':')) return 1;
#endif
    return 0;
}

static int safe_ref(const char *s)
{
    if (!*s || *s == '-') return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && !strchr("._/~^@-", *s)) return 0;
    return 1;
}

static int tool_exists(const char *tool)
{
    char p[1100];
    snprintf(p, sizeof p, "%s/%s%s", bindir, tool, EXE);
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

/* Run "<bindir>/<tool>" with the arguments in argv (NULL terminated, argv[0] is the tool name), without a
 * shell; returns the exit status, 128+signal, or -1. */
#ifdef _WIN32
static int spawn_wait(const char *path, char *const argv[])
{
    int saved = -1;
    if (child_to_stderr) {
        saved = _dup(1);
        if (saved < 0 || _dup2(2, 1) < 0) { fprintf(stderr, "zcl-dev verify: cannot redirect child output\n"); return -1; }
    }
    intptr_t rc = _spawnv(_P_WAIT, path, (const char *const *)argv);
    if (saved >= 0) { _dup2(saved, 1); _close(saved); }
    return rc == -1 ? -1 : (int)rc;
}
#else
static int spawn_wait(const char *path, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) { perror("zcl-dev verify: fork"); return -1; }
    if (pid == 0) {
        if (child_to_stderr && dup2(2, 1) < 0) _exit(127);
        execv(path, argv);
        perror(path);
        _exit(127);
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) { perror("zcl-dev verify: waitpid"); return -1; }
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return WEXITSTATUS(st);
}
#endif

static int run(const char *tool, char *const argv[])
{
    char path[1100];
    int n = snprintf(path, sizeof path, "%s/%s%s", bindir, tool, EXE);
    if (n < 0 || (size_t)n >= sizeof path) { fprintf(stderr, "zcl-dev verify: tool path too long\n"); return -1; }
    fflush(stdout);
    fflush(stderr);
    if (say && say != stdout && say != stderr) fflush(say);
    return spawn_wait(path, argv);
}

struct result { const char *name; const char *verdict; int rc; };

static const char *verdict_of(int rc)
{
    if (rc == 0) return "PASS";
    return rc == 1 ? "FAIL" : "BROKEN";
}

static void print_json(const struct result *r, size_t n, int code, const char *base)
{
    fprintf(jout, "{\"base\":\"%s\",\"exit\":%d,\"steps\":[", base, code);
    for (size_t i = 0; i < n; i++)
        fprintf(jout, "%s{\"step\":\"%s\",\"verdict\":\"%s\",\"rc\":%d}", i ? "," : "", r[i].name, r[i].verdict, r[i].rc);
    fputs("]}\n", jout);
}

/* One step each; they return the exit code contribution (0 pass or skipped, 1 finding, 2 broken). */
static int step_select(const char *base, struct result *r)
{
    fprintf(say, "== verify: select (base %s)\n", base);
    int rc = run("zcl-dev", (char *[]){"zcl-dev", "select", (char *)base, NULL});
    *r = (struct result){"select", rc == 0 ? "PASS" : "BROKEN", rc};
    return rc == 0 ? 0 : 2;
}

static int step_tfast(const char *base, struct result *r)
{
    char changed[700];
    if (!tool_exists("zcl-dev-t-fast") && tool_exists("zcl-dev-tests")) {
        fprintf(stderr, "zcl-dev verify: zcl-dev-tests is built but the zcl-dev-t-fast alias is missing; install it beside zcl-dev-tests\n");
        *r = (struct result){"t-fast", "BROKEN", 2};
        return 2;
    }
    if (!tool_exists("zcl-dev-t-fast")) {
        fprintf(say, "== verify: t-fast SKIPPED (%s/zcl-dev-t-fast is not built in this tree)\n", bindir);
        *r = (struct result){"t-fast", "SKIPPED", 0};
        return 0;
    }
    fprintf(say, "== verify: t-fast --changed=%s\n", base);
    snprintf(changed, sizeof changed, "--changed=%s", base);
    int rc = run("zcl-dev-t-fast", (char *[]){"zcl-dev-t-fast", changed, NULL});
    *r = (struct result){"t-fast", verdict_of(rc), rc};
    return rc == 0 ? 0 : rc == 1 ? 1 : 2;
}

static int step_lint(struct result *r)
{
    if (!tool_exists("zcl-lint")) {
#ifdef _WIN32
        fprintf(stderr, "zcl-dev verify: zcl-lint is not built for Windows; run zcl-dev verify on a POSIX host\n");
        *r = (struct result){"zcl-lint", "UNAVAILABLE", 2};
#else
        fprintf(stderr, "zcl-dev verify: %s/zcl-lint is missing; run make -C zcutil\n", bindir);
        *r = (struct result){"zcl-lint", "BROKEN", 2};
#endif
        return 2;
    }
    fprintf(say, "== verify: zcl-lint all\n");
    int rc = run("zcl-lint", (char *[]){"zcl-lint", "all", NULL});
    *r = (struct result){"zcl-lint", verdict_of(rc), rc};
    return rc == 0 ? 0 : rc == 1 ? 1 : 2;
}

static int verify(const char *base, int json)
{
    struct result res[3];
    size_t n = 0;
    int code;
    child_to_stderr = json;
    if (!tool_exists("zcl-dev")) {
        fprintf(stderr, "zcl-dev verify: %s/zcl-dev is missing; run make -C zcutil\n", bindir);
        return 2;
    }
    code = step_select(base, &res[n++]);
    if (!code) code = step_tfast(base, &res[n++]);
    if (!code) {
        code = step_lint(&res[n++]);
    }
    fprintf(say, "== verify summary\n");
    for (size_t i = 0; i < n; i++) fprintf(say, "  %-10s %s\n", res[i].name, res[i].verdict);
    if (code == 0)
        fprintf(say, "next: ZCL_CI_BASE=%s zcutil/local-ci.sh --commit HEAD test-changed <outdir>   (runs the CI steps select listed)\n", base);
    if (json) print_json(res, n, code, base);
    return code;
}

#ifndef _WIN32
/* Fixture: stub tools in a temp bindir (its name holds a quote on purpose), checking call order, the base
 * argument, the skip of a missing t-fast, the stop on failure and the exit codes. */
static char calls_path[1000];
static char tmp_root[900];
static char fix_bin[1000];

static int stub(const char *name, int code)
{
    char p[1300];
    snprintf(p, sizeof p, "%s/%s", fix_bin, name);
    FILE *f = fopen(p, "w");
    if (!f) return -1;
    fprintf(f, "#!/bin/sh\necho \"%s $*\" >>\"%s\"\nexit %d\n", name, calls_path, code);
    fclose(f);
    return chmod(p, 0755);
}

static int calls_equal(const char *want)
{
    char buf[1024] = "";
    FILE *f = fopen(calls_path, "r");
    if (f) { size_t k = fread(buf, 1, sizeof buf - 1, f); buf[k] = 0; fclose(f); }
    return !strcmp(buf, want);
}

static int fixture_run(const char *base, int json, int want, const char *calls, const char *what)
{
    FILE *c = fopen(calls_path, "w");
    if (c) fclose(c);
    int rc = verify(base, json);
    if (rc != want || (calls && !calls_equal(calls))) {
        fprintf(stderr, "selftest: %s: exit %d (want %d) or call order differs\n", what, rc, want);
        return 1;
    }
    return 0;
}

static int fixture(void)
{
    int bad = 0;
    char outp[1000], old_bin[1024];
    const char *t = getenv("TMPDIR");
    snprintf(tmp_root, sizeof tmp_root, "%s/zcl-verify-st.XXXXXX", t && *t ? t : "/tmp");
    if (!mkdtemp(tmp_root)) { perror("selftest: mkdtemp"); return 1; }
    snprintf(fix_bin, sizeof fix_bin, "%s/b'in", tmp_root);
    snprintf(calls_path, sizeof calls_path, "%s/calls", tmp_root);
    snprintf(outp, sizeof outp, "%s/out", tmp_root);
    if (mkdir(fix_bin, 0755) != 0) { perror("selftest: mkdir"); return 1; }
    snprintf(old_bin, sizeof old_bin, "%s", bindir);
    snprintf(bindir, sizeof bindir, "%s", fix_bin);
    say = fopen(outp, "w");
    jout = say;
    if (!say) { perror("selftest: fopen"); return 1; }

    bad |= fixture_run("main", 0, 2, NULL, "no zcl-dev");
    bad |= stub("zcl-dev", 0) | stub("zcl-lint", 0);
    bad |= fixture_run("main", 0, 0, "zcl-dev select main\nzcl-lint all\n", "no t-fast");
    bad |= stub("zcl-dev-t-fast", 0);
    bad |= fixture_run("origin/master", 1, 0,
                       "zcl-dev select origin/master\nzcl-dev-t-fast --changed=origin/master\nzcl-lint all\n", "with t-fast");
    bad |= stub("zcl-dev-t-fast", 1);
    bad |= fixture_run("main", 0, 1, "zcl-dev select main\nzcl-dev-t-fast --changed=main\n", "t-fast failure stops before lint");
    bad |= stub("zcl-dev-t-fast", 0) | stub("zcl-lint", 1);
    bad |= fixture_run("main", 0, 1, NULL, "lint finding");
    bad |= stub("zcl-lint", 2);
    bad |= fixture_run("main", 0, 2, NULL, "lint broken");
    bad |= stub("zcl-dev", 1) | stub("zcl-lint", 0);
    bad |= fixture_run("main", 0, 2, "zcl-dev select main\n", "select failure stops everything");
    bad |= stub("zcl-dev", 0);
    {
        char p[1300];
        snprintf(p, sizeof p, "%s/zcl-lint", fix_bin);
        remove(p);
    }
    bad |= fixture_run("main", 0, 2, NULL, "missing lint is broken");

    const char *inbin[] = {"zcl-dev", "zcl-dev-t-fast", "zcl-lint"};
    for (size_t i = 0; i < sizeof inbin / sizeof *inbin; i++) {
        char p[1300];
        snprintf(p, sizeof p, "%s/%s", fix_bin, inbin[i]);
        remove(p);
    }
    fclose(say);
    say = stdout;
    jout = stdout;
    remove(calls_path);
    remove(outp);
    rmdir(fix_bin);
    rmdir(tmp_root);
    snprintf(bindir, sizeof bindir, "%s", old_bin);
    return bad;
}
#endif

static int selftest(void)
{
    if (!safe_ref("origin/master") || !safe_ref("HEAD~3") || safe_ref("") || safe_ref("-x") || safe_ref("a b") || safe_ref("a;b")) {
        fputs("selftest: safe_ref failed\n", stderr);
        return 1;
    }
#ifndef _WIN32
    if (fixture()) return 1;
#endif
    puts("zcl-dev verify selftest: ok");
    return 0;
}

/* Run from the repository root, as zcl-dev dispatch does; make a relative bindir absolute first. */
static void enter_toplevel(void)
{
    char cwd[512], top[512], full[1600];
    FILE *p = popen("git rev-parse --show-toplevel 2>" GITNULL, "r");
    if (!p) return;
    if (!fgets(top, sizeof top, p)) { pclose(p); return; }
    pclose(p);
    top[strcspn(top, "\r\n")] = 0;
    if (!*top) return;
    if (!is_absolute(bindir) && getcwd(cwd, sizeof cwd)) {
        snprintf(full, sizeof full, "%s/%s", cwd, bindir);
        if (strlen(full) < sizeof bindir) memcpy(bindir, full, strlen(full) + 1);
    }
    if (chdir(top) != 0) fprintf(stderr, "zcl-dev verify: cannot enter %s\n", top);
}

int main(int argc, char **argv)
{
    const char *base = getenv("ZCL_CI_BASE");
    int json = 0;
    say = stdout;
    jout = stdout;
    if (!base || !*base) base = "origin/master";
    find_bindir(argv[0]);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--purpose")) { puts("select, focused tests and lint for the committed changes in one trip"); return 0; }
        if (!strcmp(argv[i], "--selftest")) return selftest();
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--base") && i + 1 < argc) base = argv[++i];
        else { fputs("usage: zcl-dev verify [--base REF] [--json] [--selftest]\n", stderr); return 2; }
    }
    if (!safe_ref(base)) { fprintf(stderr, "zcl-dev verify: unsafe base ref\n"); return 2; }
    if (json) say = stderr;
    enter_toplevel();
    return verify(base, json);
}
