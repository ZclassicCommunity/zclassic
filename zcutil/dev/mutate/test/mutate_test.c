/* Fixture tests for zcl-dev mutate (C, so the shell_lines KPI floor does not rise). POSIX only.
 *
 *   mutate_test <zcl-dev-mutate> <testdir>    every test below; UPDATE=1 rewrites test/golden/
 *   mutate_test --role check|slow|hang|build  the test and build commands the runs use (cwd = fixture repo)
 *
 * Golden `list` output for a C and a C++ fixture (no site on a NOSITE line or on std::vector<int>),
 * the --class/--lines filter and --json, then `run` in a throwaway git repository: exactly the two
 * known survivors of calc.c, a build failure counted UNCOMPILABLE and not scored, a timeout that
 * kills the sleeping test's whole process group, SIGTERM mid-run (file byte-identical, no .orig,
 * exit 130), `restore`, and the refusals: stale .orig, unstaged, staged, untracked, vendored.
 */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static char tool[PATH_MAX], self[PATH_MAX], tdir[PATH_MAX], work[PATH_MAX], repo[PATH_MAX + 8];

#define FAIL(...) do { printf("FAIL mutate: "); printf(__VA_ARGS__); putchar('\n'); fails++; } while (0)

/* ---- small helpers ------------------------------------------------------------------------- */
static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    char *b = malloc(cap + 1);
    while (b) {
        n += fread(b + n, 1, cap - n, f);
        if (n < cap) break;
        char *nb = realloc(b, cap * 2 + 1);
        if (!nb) free(b);
        b = nb;
        cap *= 2;
    }
    fclose(f);
    if (b) b[n] = 0;
    return b;
}

static bool spit(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool same_file(const char *a, const char *b)
{
    char *x = slurp(a), *y = slurp(b);
    bool same = x && y && strcmp(x, y) == 0;
    free(x);
    free(y);
    return same;
}

static bool exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

static void nap_ms(long ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Starts argv in dir with stdout and stderr to files (NULL: /dev/null). */
static pid_t start(const char *dir, char *const argv[], const char *out, const char *err)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid != 0) return pid;
    int o = open(out ? out : "/dev/null", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int e = open(err ? err : "/dev/null", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (o < 0 || e < 0 || (dir && chdir(dir) != 0)) _exit(126);
    dup2(o, 1);
    dup2(e, 2);
    execvp(argv[0], argv);
    _exit(127);
}

static int finish(pid_t pid)
{
    int st = 0;
    if (pid < 0) return -1;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static int run(const char *dir, char *const argv[], const char *out, const char *err)
{
    return finish(start(dir, argv, out, err));
}

static void path_in(char *dst, size_t cap, const char *dir, const char *name)
{
    if (snprintf(dst, cap, "%s/%s", dir, name) >= (int)cap) dst[0] = 0;
}

static int git(char *a, char *b, char *c, char *d)
{
    char *argv[] = {"git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", a, b, c, d, NULL};
    return run(repo, argv, NULL, NULL);
}

/* ---- roles: the test and build commands of the fixture runs -------------------------------- */
static bool calc_says(const char *arg, const char *want)
{
    char *argv[] = {"./calc", (char *)arg, NULL};
    if (run(NULL, argv, "calc.out", NULL) != 0) return false;
    char *got = slurp("calc.out");
    bool ok = got && strcmp(got, want) == 0;
    free(got);
    return ok;
}

static int role_check(void)
{
    char *noarg[] = {"./calc", NULL};
    bool ok = calc_says("-5", "0 0\n") && calc_says("3", "3 0\n") && calc_says("4", "4 1\n") && calc_says("15", "10 0\n");
    return ok && run(NULL, noarg, NULL, NULL) == 2 ? 0 : 1;
}

static int role_slow(void)
{
    if (same_file("calc.c", "pristine.c")) return 0;
    pid_t child = fork();
    if (child == 0) { sleep(30); _exit(0); }
    char pid[32];
    snprintf(pid, sizeof pid, "%ld\n", (long)child);
    spit("sleep.pid", pid);
    return finish(child);
}

static int role(const char *name)
{
    if (!strcmp(name, "check")) return role_check();
    if (!strcmp(name, "slow")) return role_slow();
    if (!strcmp(name, "hang")) {
        if (same_file("calc.c", "pristine.c")) return 0;
        spit("started", "started\n");
        sleep(30);
        return 0;
    }
    if (!strcmp(name, "build")) {
        char *text = slurp("calc.c"), *cc[] = {"cc", "-o", "calc", "calc.c", NULL};
        bool poisoned = !text || strstr(text, "if (v >= hi)");
        free(text);
        return poisoned ? 1 : run(NULL, cc, NULL, NULL);
    }
    return 2;
}

/* ---- list ---------------------------------------------------------------------------------- */
static void golden(const char *name, const char *fixture)
{
    char fx[PATH_MAX + 64], out[PATH_MAX + 64], want[PATH_MAX + 64];
    path_in(fx, sizeof fx, tdir, fixture);
    snprintf(out, sizeof out, "%s/%s.out", work, name);
    snprintf(want, sizeof want, "%s/golden/%s.out", tdir, name);
    char *argv[] = {tool, "list", fx, NULL};
    int rc = run(NULL, argv, out, NULL);
    if (rc != 0) FAIL("list %s exited %d", fixture, rc);
    char *got = slurp(out);
    if (getenv("UPDATE") && got) spit(want, got);
    char *exp = slurp(want);
    if (!got || !exp || strcmp(got, exp) != 0) FAIL("list %s differs from golden/%s.out", fixture, name);
    free(got);
    free(exp);
}

/* Does a line of the `list` output start with "<line>:"? */
static bool listed(const char *list, long line)
{
    char head[40];
    snprintf(head, sizeof head, "\n%ld:", line);
    return strncmp(list, head + 1, strlen(head + 1)) == 0 || strstr(list, head) != NULL;
}

/* No listed site on a line of `fixture` that contains `marker`. */
static void no_site_on(const char *name, const char *fixture, const char *marker)
{
    char fx[PATH_MAX + 64], out[PATH_MAX + 64];
    path_in(fx, sizeof fx, tdir, fixture);
    snprintf(out, sizeof out, "%s/%s.out", work, name);
    char *src = slurp(fx), *list = slurp(out);
    if (!src || !list) FAIL("cannot read %s or its list output", fixture);
    long line = 1;
    for (char *p = list ? src : NULL; p && *p; line++) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        if (strstr(p, marker) && listed(list, line)) FAIL("%s: a site on line %ld (%s)", fixture, line, marker);
        p = nl ? nl + 1 : NULL;
    }
    free(src);
    free(list);
}

static void test_list(void)
{
    golden("list-c", "list_fixture.c");
    golden("list-cpp", "list_fixture.cpp");
    no_site_on("list-c", "list_fixture.c", "NOSITE");
    no_site_on("list-cpp", "list_fixture.cpp", "NOSITE");
    no_site_on("list-cpp", "list_fixture.cpp", "std::vector<int>");
    char fx[PATH_MAX + 64], out[PATH_MAX + 64];
    path_in(fx, sizeof fx, tdir, "list_fixture.c");
    path_in(out, sizeof out, work, "f.out");
    char *filt[] = {tool, "list", fx, "--class", "return", "--lines", "24-28", NULL};
    run(NULL, filt, out, NULL);
    char *got = slurp(out);
    if (!got || strcmp(got, "25:9 return 'return true;' -> 'return false;'\n26:5 return 'return false;' -> 'return true;'\nsites 2\n"))
        FAIL("--class/--lines filter: %s", got ? got : "(none)");
    free(got);
    path_in(fx, sizeof fx, tdir, "list_fixture.cpp");
    char *js[] = {tool, "list", fx, "--json", NULL};
    run(NULL, js, out, NULL);
    got = slurp(out);
    if (!got || strncmp(got, "{\"file\":", 8) || !strstr(got, "\"count\":18,\"sites\":[{\"line\":7,")) FAIL("list --json: %s", got ? got : "");
    free(got);
    char *bad[] = {tool, "list", fx, "--class", "arith", NULL}, *norun[] = {tool, "run", fx, NULL};
    if (run(NULL, bad, NULL, NULL) != 2) FAIL("an unknown class does not exit 2");
    if (run(NULL, norun, NULL, NULL) != 2) FAIL("run without a test command does not exit 2");
}

/* ---- run ----------------------------------------------------------------------------------- */
static bool make_repo(void)
{
    char src[PATH_MAX + 64], dst[PATH_MAX + 64];
    char *rm[] = {"rm", "-rf", repo, NULL}, *mk[] = {"mkdir", "-p", repo, NULL};
    run(NULL, rm, NULL, NULL);
    run(NULL, mk, NULL, NULL);
    path_in(src, sizeof src, tdir, "calc.c");
    char *text = slurp(src);
    path_in(dst, sizeof dst, repo, "calc.c");
    bool ok = text && spit(dst, text);
    path_in(dst, sizeof dst, repo, "pristine.c");
    ok = ok && spit(dst, text);
    free(text);
    path_in(dst, sizeof dst, repo, ".gitignore");
    ok = ok && spit(dst, "calc\ncalc.out\npristine.c\nsleep.pid\nstarted\nzcutil/gen/\n");
    return ok && git("init", "-q", NULL, NULL) == 0 && git("add", ".", NULL, NULL) == 0 &&
           git("commit", "-qm", "fixture", NULL) == 0;
}

/* The file is byte-identical to the original, no .orig is left, and git sees nothing. */
static void clean_after(const char *what)
{
    char a[PATH_MAX + 64], b[PATH_MAX + 64], st[PATH_MAX + 64];
    path_in(a, sizeof a, repo, "calc.c");
    path_in(b, sizeof b, repo, "pristine.c");
    if (!same_file(a, b)) FAIL("%s: calc.c was not restored", what);
    path_in(a, sizeof a, repo, "calc.c.zcl-mutate.orig");
    if (exists(a)) FAIL("%s: .orig left behind", what);
    path_in(st, sizeof st, work, "status.out");
    char *argv[] = {"git", "status", "--short", NULL};
    run(repo, argv, st, NULL);
    char *s = slurp(st);
    if (!s || s[0]) FAIL("%s: git status is not clean: %s", what, s ? s : "?");
    free(s);
}

/* Runs the tool in the fixture repo; its stdout lands in work/<name>.out and is returned. */
static char *mutate(const char *name, char *const args[], int want_rc)
{
    char out[PATH_MAX + 64], err[PATH_MAX + 64];
    snprintf(out, sizeof out, "%s/%s.out", work, name);
    snprintf(err, sizeof err, "%s/%s.err", work, name);
    char *argv[24] = {tool};
    for (int i = 0; i < 22 && args[i]; i++) argv[i + 1] = args[i];
    int rc = run(repo, argv, out, err);
    if (rc != want_rc) {
        char *e = slurp(err);
        FAIL("%s: exit %d, want %d: %s", name, rc, want_rc, e ? e : "");
        free(e);
    }
    return slurp(out);
}

static int count_lines_starting_digit(const char *s)
{
    int n = 0;
    const char *p = s;
    while (p && *p) {
        if (*p >= '0' && *p <= '9') n++;
        p = strchr(p, '\n');
        if (p) p++;
    }
    return n;
}

static void test_survivors(void)
{
    char *args[] = {"run", "calc.c", "--build", "cc -o calc calc.c", "--", self, "--role", "check", NULL};
    char *out = mutate("run", args, 1);
    if (!out || !strstr(out, " survived 2 uncompilable 0 timeouts 0 score=")) FAIL("run summary: %s", out ? out : "");
    if (count_lines_starting_digit(out) != 2) FAIL("want exactly 2 survivor lines: %s", out ? out : "");
    if (!out || !strstr(out, "7:11 relational '<' -> '<='\n")) FAIL("the survivor on line 7 is missing");
    if (!out || !strstr(out, "8:11 relational '>' -> '>='\n")) FAIL("the survivor on line 8 is missing");
    if (!out || !strstr(out, "receipt zcutil/gen/mutate/calc.c-")) FAIL("no receipt line");
    free(out);
    clean_after("run");
}

static void test_uncompilable(void)
{
    char *args[] = {"run", "calc.c", "--json", "--build", (char *)self, "--", self, "--role", "check", NULL};
    char build[PATH_MAX + 16];
    snprintf(build, sizeof build, "%s --role build", self);
    args[4] = build;
    char *out = mutate("uncompilable", args, 1);
    if (!out || !strstr(out, "\"uncompilable\":1,")) FAIL("the build failure is not UNCOMPILABLE: %s", out ? out : "");
    if (!out || !strstr(out, "\"survived\":1,") || !strstr(out, "\"survivors\":[{\"line\":7,"))
        FAIL("an uncompilable mutant was scored: %s", out ? out : "");
    free(out);
    clean_after("uncompilable");
}

static void test_timeout(void)
{
    char *args[] = {"run", "calc.c", "--max", "1", "--timeout", "1", "--", self, "--role", "slow", NULL};
    char *out = mutate("timeout", args, 0);
    if (!out || !strstr(out, " killed 1 survived 0 uncompilable 0 timeouts 1 score=1/1\n")) FAIL("timeout summary: %s", out ? out : "");
    free(out);
    char pidfile[PATH_MAX + 64];
    path_in(pidfile, sizeof pidfile, repo, "sleep.pid");
    char *p = slurp(pidfile);
    long pid = p ? strtol(p, NULL, 10) : 0;
    free(p);
    if (pid <= 0) FAIL("the slow test never ran on a mutant");
    bool alive = pid > 0;
    for (int i = 0; i < 100 && alive; i++, nap_ms(20)) alive = kill((pid_t)pid, 0) == 0;
    if (alive) FAIL("the sleeping test survived its timeout");
    clean_after("timeout");
}

static void test_sigterm(void)
{
    char out[PATH_MAX + 64], started[PATH_MAX + 64];
    snprintf(out, sizeof out, "%s/sigterm.out", work);
    path_in(started, sizeof started, repo, "started");
    char *argv[] = {tool, "run", "calc.c", "--max", "3", "--", self, "--role", "hang", NULL};
    pid_t pid = start(repo, argv, out, NULL);
    for (int i = 0; i < 300 && !exists(started); i++) nap_ms(100);
    if (!exists(started)) FAIL("the hanging test never started");
    kill(pid, SIGTERM);
    int rc = finish(pid);
    if (rc != 130) FAIL("SIGTERM mid-run: exit %d, want 130", rc);
    unlink(started);
    clean_after("sigterm");
}

/* ---- restore and refusals ------------------------------------------------------------------ */
static void refused(const char *what, const char *file, const char *pattern)
{
    char err[PATH_MAX + 64];
    char *args[] = {"run", (char *)file, "--", self, "--role", "check", NULL};
    free(mutate(what, args, 2));
    snprintf(err, sizeof err, "%s/%s.err", work, what);
    char *e = slurp(err);
    if (!e || !strstr(e, pattern)) FAIL("%s: no '%s' in: %s", what, pattern, e ? e : "");
    free(e);
}

static void append(const char *name, const char *text)
{
    char p[PATH_MAX + 64];
    path_in(p, sizeof p, repo, name);
    char *old = slurp(p);
    size_t n = old ? strlen(old) + strlen(text) + 1 : 0;
    char *both = n ? malloc(n) : NULL;
    if (both) snprintf(both, n, "%s%s", old, text);
    if (!both || !spit(p, both)) FAIL("cannot append to %s", name);
    free(old);
    free(both);
}

static void test_refusals(void)
{
    char a[PATH_MAX + 64], b[PATH_MAX + 64];
    path_in(a, sizeof a, repo, "pristine.c");
    path_in(b, sizeof b, repo, "calc.c.zcl-mutate.orig");
    char *text = slurp(a);
    spit(b, text ? text : "");
    refused("stale-orig", "calc.c", "run `zcl-dev mutate restore calc.c`");
    append("calc.c", "/* edit */\n");
    char *rs[] = {"restore", "calc.c", NULL};
    free(mutate("restore", rs, 0));
    clean_after("restore");
    append("calc.c", "/* edit */\n");
    refused("unstaged", "calc.c", "unstaged changes");
    git("add", "calc.c", NULL, NULL);
    refused("staged", "calc.c", "staged changes");
    git("reset", "-q", NULL, NULL);
    git("checkout", "-q", "calc.c", NULL);
    path_in(b, sizeof b, repo, "untracked.c");
    spit(b, text ? text : "");
    refused("untracked", "untracked.c", "not tracked");
    unlink(b);
    path_in(b, sizeof b, repo, "src/leveldb");
    char *mk[] = {"mkdir", "-p", b, NULL};
    run(NULL, mk, NULL, NULL);
    path_in(b, sizeof b, repo, "src/leveldb/calc.c");
    spit(b, text ? text : "");
    git("add", "src", NULL, NULL);
    git("commit", "-qm", "vendored", NULL);
    refused("vendored", "src/leveldb/calc.c", "vendored");
    free(text);
    clean_after("refusals");
}

static bool setup(const char *tool_arg, const char *dir_arg, const char *argv0)
{
    char tmpl[PATH_MAX];
    const char *tmp = getenv("TMPDIR");
    snprintf(tmpl, sizeof tmpl, "%s/zcl-mutate-test.XXXXXX", tmp && tmp[0] ? tmp : "/tmp");
    if (!realpath(tool_arg, tool) || !realpath(dir_arg, tdir) || !realpath(argv0, self) || !mkdtemp(tmpl)) return false;
    snprintf(work, sizeof work, "%s", tmpl);
    snprintf(repo, sizeof repo, "%s/r", work);
    unsetenv("ZCL_DEV_PREFIX");
    return true;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--role")) return role(argv[2]);
    if (argc != 3) { fputs("usage: mutate_test <zcl-dev-mutate> <testdir> | --role <name>\n", stderr); return 2; }
    if (!setup(argv[1], argv[2], argv[0])) { perror("mutate_test: setup"); return 2; }
    test_list();
    if (!make_repo()) FAIL("cannot create the fixture repository");
    else {
        test_survivors();
        test_uncompilable();
        test_timeout();
        test_sigterm();
        test_refusals();
    }
    char *rm[] = {"rm", "-rf", work, NULL};
    run(NULL, rm, NULL, NULL);
    if (fails) { printf("zcl-dev mutate tests: %d failure(s)\n", fails); return 1; }
    puts("zcl-dev mutate tests: ok");
    return 0;
}
