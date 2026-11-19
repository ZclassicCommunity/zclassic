/* zcl-dev verify: the one-trip check of committed changes, the analogue of Z23's
 * 'make agent-verify ONLY=@changed'. Libc only; builds with the host cc, clang and the mingw cross
 * compiler.
 *
 *   zcl-dev verify [--base REF] [--json] [--selftest] [--purpose]
 *   zcl-dev verify --gates [--json]   the check-dev-tools gate sequence (CI and local CI run this after
 *                                     'make -C zcutil check'): zcl-lint all, zcl-dev check-tests, know --check,
 *                                     gen --check rpc-parity, gen --check flags; stops at the first failure.
 *                                     check-tests is skipped by name only when zcl-dev-tests is not built; when
 *                                     it is built but the zcl-dev-check-tests alias is missing the gate is BROKEN.
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
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
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
    if (rc == 3) {   /* U2: test binary missing or stale; t-fast printed the make command */
        fprintf(stderr, "zcl-dev verify: t-fast needs a build; run the make command it printed, then verify again\n");
        *r = (struct result){"t-fast", "NEEDS-BUILD", 3};
        return 2;
    }
    *r = (struct result){"t-fast", verdict_of(rc), rc};
    return rc == 0 ? 0 : rc == 1 ? 1 : 2;
}

/* One gate: "zcl-dev <args>" or another tool, named for the summary. */
static int step_gate(const char *name, const char *tool, char *const argv[], struct result *r)
{
    fprintf(say, "== verify: %s\n", name);
    int rc = run(tool, argv);
    *r = (struct result){name, verdict_of(rc), rc};
    return rc == 0 ? 0 : rc == 1 ? 1 : 2;
}

static int step_checktests(const char *base, struct result *r)
{
    if (!tool_exists("zcl-dev-tests") && !tool_exists("zcl-dev-check-tests")) {
        fprintf(say, "== verify: check-tests SKIPPED (%s/zcl-dev-tests is not built in this tree)\n", bindir);
        *r = (struct result){"check-tests", "SKIPPED", 0};
        return 0;
    }
    if (!tool_exists("zcl-dev-check-tests")) {
        fprintf(stderr, "zcl-dev verify: zcl-dev-tests is built but the zcl-dev-check-tests alias is missing; install it beside zcl-dev-tests\n");
        *r = (struct result){"check-tests", "BROKEN", 2};
        return 2;
    }
    char arg[600];
    snprintf(arg, sizeof arg, "--base=%s", base);
    return step_gate("check-tests", "zcl-dev", (char *[]){"zcl-dev", "check-tests", arg, NULL}, r);
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

static void summary(const struct result *res, size_t n)
{
    fprintf(say, "== verify summary\n");
    for (size_t i = 0; i < n; i++) fprintf(say, "  %-11s %s\n", res[i].name, res[i].verdict);
}

/* The base check-tests compares the baseline with, named explicitly so it never depends on origin/master:
 * the caller or ZCL_CI_BASE, else the merge-base of HEAD with origin/master when that resolves, else the
 * parent of HEAD (a CI clone or bundle checkout has the commit history but no origin/master), else HEAD. */
static int git_line(const char *cmd, char *out, size_t n)
{
    FILE *p = popen(cmd, "r");
    if (!p) return 0;
    int ok = fgets(out, (int)n, p) != NULL;
    pclose(p);
    out[ok ? strcspn(out, "\r\n") : 0] = 0;
    return ok && *out && safe_ref(out);
}

static void gate_base(char *out, size_t n, const char *explicit_base)
{
    char buf[512];
    if (explicit_base && *explicit_base) snprintf(out, n, "%s", explicit_base);
    else if (git_line("git merge-base HEAD origin/master 2>" GITNULL, buf, sizeof buf)) snprintf(out, n, "%s", buf);
    else if (git_line("git rev-parse --verify --quiet HEAD^ 2>" GITNULL, buf, sizeof buf)) snprintf(out, n, "%s", buf);
    else snprintf(out, n, "HEAD");
}

/* The check-dev-tools gates, in order, stopping at the first one that does not pass. */
static int verify_gates(int json, const char *explicit_base)
{
    struct result res[5];
    char base[512];
    size_t n = 0;
    int code;
    child_to_stderr = json;
    if (!tool_exists("zcl-dev")) {
        fprintf(stderr, "zcl-dev verify: %s/zcl-dev is missing; run make -C zcutil\n", bindir);
        return 2;
    }
    code = step_lint(&res[n++]);
    gate_base(base, sizeof base, explicit_base);
    if (!code) code = step_checktests(base, &res[n++]);
    if (!code) code = step_gate("know", "zcl-dev", (char *[]){"zcl-dev", "know", "--check", NULL}, &res[n++]);
    if (!code) code = step_gate("rpc-parity", "zcl-dev", (char *[]){"zcl-dev", "gen", "--check", "rpc-parity", NULL}, &res[n++]);
    if (!code) code = step_gate("flags", "zcl-dev", (char *[]){"zcl-dev", "gen", "--check", "flags", NULL}, &res[n++]);
    summary(res, n);
    if (json) print_json(res, n, code, base);
    return code;
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
    if (!code) code = step_lint(&res[n++]);
    summary(res, n);
    if (code == 0)
        fprintf(say, "next: ZCL_CI_BASE=%s zcutil/local-ci.sh --commit HEAD test-changed <outdir>   (runs the CI steps select listed)\n", base);
    if (json) print_json(res, n, code, base);
    return code;
}

#ifndef _WIN32
/* Fixture: stub tools in a temp bindir (its name holds a quote on purpose), checking call order, the base
 * argument, the skip of missing optional tools, the BROKEN verdicts of missing aliases, the stop on failure,
 * the exit codes and the one-line --json output. Stubs read the calls file name from the environment, so no
 * character of TMPDIR can reach a shell string. */
static char calls_path[1000];
static char tmp_root[900];
static char fix_bin[1000];
static char out_path[1000];
static char json_path[1000];
static const char *const stub_names[] = {"zcl-dev", "zcl-dev-t-fast", "zcl-dev-tests", "zcl-dev-check-tests", "zcl-lint"};

static int stub(const char *name, int code)
{
    char p[1300];
    snprintf(p, sizeof p, "%s/%s", fix_bin, name);
    FILE *f = fopen(p, "w");
    if (!f) return -1;
    fprintf(f, "#!/bin/sh\necho \"%s $*\" >>\"$ZCL_VERIFY_CALLS\"\nexit %d\n", name, code);
    fclose(f);
    return chmod(p, 0755);
}

static void unstub(const char *name)
{
    char p[1300];
    snprintf(p, sizeof p, "%s/%s", fix_bin, name);
    remove(p);
}

static int slurp_equal(const char *path, const char *want)
{
    char buf[1024] = "";
    FILE *f = fopen(path, "r");
    if (f) { size_t k = fread(buf, 1, sizeof buf - 1, f); buf[k] = 0; fclose(f); }
    return !strcmp(buf, want);
}

/* The --json file must hold exactly one line that starts with jhead and names every verdict in jhas. */
static int json_ok(const char *jhead, const char *jhas)
{
    char buf[2048] = "";
    FILE *f = fopen(json_path, "r");
    if (f) { size_t k = fread(buf, 1, sizeof buf - 1, f); buf[k] = 0; fclose(f); }
    char *nl = strchr(buf, '\n');
    if (!nl || nl[1] || strncmp(buf, jhead, strlen(jhead))) return 0;
    return strstr(buf, jhas) != NULL;
}

struct fcase { const char *base; int json, gates, want; const char *calls, *jhead, *jhas, *what; };

static int fixture_run(const struct fcase *c)
{
    FILE *f = fopen(calls_path, "w");
    if (f) fclose(f);
    fflush(jout);
    if (ftruncate(fileno(jout), 0) != 0) { perror("selftest: ftruncate"); return 1; }
    rewind(jout);
    int rc = c->gates ? verify_gates(c->json, strcmp(c->base, "-") ? c->base : NULL) : verify(c->base, c->json);
    fflush(jout);
    if (rc != c->want || (c->calls && !slurp_equal(calls_path, c->calls))) {
        fprintf(stderr, "selftest: %s: exit %d (want %d) or call order differs\n", c->what, rc, c->want);
        return 1;
    }
    if (c->json && !json_ok(c->jhead, c->jhas)) {
        fprintf(stderr, "selftest: %s: --json is not one line with the expected verdicts\n", c->what);
        return 1;
    }
    return 0;
}

#define FX(...) (bad |= fixture_run(&(struct fcase){__VA_ARGS__}))

static int fixture_cases(void)
{
    int bad = 0;
    FX("main", 0, 0, 2, NULL, NULL, NULL, "no zcl-dev");
    bad |= stub("zcl-dev", 0) | stub("zcl-lint", 0);
    FX("main", 0, 0, 0, "zcl-dev select main\nzcl-lint all\n", NULL, NULL, "no t-fast");
    bad |= stub("zcl-dev-tests", 0);
    FX("main", 0, 0, 2, "zcl-dev select main\n", NULL, NULL, "zcl-dev-tests without the t-fast alias is broken");
    FX("main", 1, 0, 2, "zcl-dev select main\n", "{\"base\":\"main\",\"exit\":2,", "{\"step\":\"t-fast\",\"verdict\":\"BROKEN\",\"rc\":2}",
       "zcl-dev-tests without the t-fast alias, json");
    unstub("zcl-dev-tests");
    bad |= stub("zcl-dev-t-fast", 0);
    FX("origin/master", 1, 0, 0, "zcl-dev select origin/master\nzcl-dev-t-fast --changed=origin/master\nzcl-lint all\n",
       "{\"base\":\"origin/master\",\"exit\":0,\"steps\":[{\"step\":\"select\",\"verdict\":\"PASS\",\"rc\":0},",
       "{\"step\":\"t-fast\",\"verdict\":\"PASS\",\"rc\":0},{\"step\":\"zcl-lint\",\"verdict\":\"PASS\",\"rc\":0}]}", "with t-fast, json");
    bad |= stub("zcl-dev-t-fast", 1);
    FX("main", 0, 0, 1, "zcl-dev select main\nzcl-dev-t-fast --changed=main\n", NULL, NULL, "t-fast failure stops before lint");
    bad |= stub("zcl-dev-t-fast", 3);
    FX("main", 1, 0, 2, "zcl-dev select main\nzcl-dev-t-fast --changed=main\n", "{\"base\":\"main\",\"exit\":2,",
       "{\"step\":\"t-fast\",\"verdict\":\"NEEDS-BUILD\",\"rc\":3}", "t-fast needing a build");
    bad |= stub("zcl-dev-t-fast", 0) | stub("zcl-lint", 1);
    FX("main", 0, 0, 1, NULL, NULL, NULL, "lint finding");
    bad |= stub("zcl-lint", 2);
    FX("main", 0, 0, 2, NULL, NULL, NULL, "lint broken");
    bad |= stub("zcl-dev", 1) | stub("zcl-lint", 0);
    FX("main", 0, 0, 2, "zcl-dev select main\n", NULL, NULL, "select failure stops everything");
    bad |= stub("zcl-dev", 0);
    unstub("zcl-lint");
    FX("main", 0, 0, 2, NULL, NULL, NULL, "missing lint is broken");

    /* --gates */
    bad |= stub("zcl-lint", 0);
    unstub("zcl-dev-t-fast");
    FX("refx", 0, 1, 0, "zcl-lint all\nzcl-dev know --check\nzcl-dev gen --check rpc-parity\nzcl-dev gen --check flags\n", NULL, NULL,
       "gates, check-tests skipped by name");
    bad |= stub("zcl-dev-tests", 0);
    FX("refx", 0, 1, 2, "zcl-lint all\n", NULL, NULL, "gates: zcl-dev-tests without the check-tests alias is broken");
    bad |= stub("zcl-dev-check-tests", 0);
    FX("refx", 1, 1, 0, "zcl-lint all\nzcl-dev check-tests --base=refx\nzcl-dev know --check\nzcl-dev gen --check rpc-parity\nzcl-dev gen --check flags\n",
       "{\"base\":\"refx\",\"exit\":0,\"steps\":[{\"step\":\"zcl-lint\",\"verdict\":\"PASS\",\"rc\":0},{\"step\":\"check-tests\",\"verdict\":\"PASS\",\"rc\":0},",
       "{\"step\":\"flags\",\"verdict\":\"PASS\",\"rc\":0}]}", "gates with check-tests, json");
    bad |= stub("zcl-lint", 1);
    FX("refx", 0, 1, 1, "zcl-lint all\n", NULL, NULL, "gates stop at the lint finding");
    bad |= stub("zcl-lint", 0) | stub("zcl-dev", 1);
    FX("refx", 0, 1, 1, "zcl-lint all\nzcl-dev check-tests --base=refx\n", NULL, NULL, "gates stop at the check-tests finding");
    unstub("zcl-dev-tests");
    unstub("zcl-dev-check-tests");
    FX("refx", 0, 1, 1, "zcl-lint all\nzcl-dev know --check\n", NULL, NULL, "gates stop at the know finding");
    return bad;
}

static int fixture(void)
{
    int bad;
    char old_bin[1024];
    const char *t = getenv("TMPDIR");
    snprintf(tmp_root, sizeof tmp_root, "%s/zcl-verify-st.XXXXXX", t && *t ? t : "/tmp");
    if (!mkdtemp(tmp_root)) { perror("selftest: mkdtemp"); return 1; }
    snprintf(fix_bin, sizeof fix_bin, "%s/b'in", tmp_root);
    snprintf(calls_path, sizeof calls_path, "%s/calls", tmp_root);
    snprintf(out_path, sizeof out_path, "%s/out", tmp_root);
    snprintf(json_path, sizeof json_path, "%s/json", tmp_root);
    snprintf(old_bin, sizeof old_bin, "%s", bindir);
    setenv("ZCL_VERIFY_CALLS", calls_path, 1);
    say = fopen(out_path, "w");
    jout = fopen(json_path, "w");
    if (mkdir(fix_bin, 0755) != 0 || !say || !jout) {
        perror("selftest: fixture setup");
        bad = 1;
    } else {
        snprintf(bindir, sizeof bindir, "%s", fix_bin);
        bad = fixture_cases();
    }
    /* cleanup on every path */
    if (say) fclose(say);
    if (jout) fclose(jout);
    say = stdout;
    jout = stdout;
    for (size_t i = 0; i < sizeof stub_names / sizeof *stub_names; i++) unstub(stub_names[i]);
    remove(calls_path);
    remove(out_path);
    remove(json_path);
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
    int json = 0, gates = 0, explicit = 0;
    say = stdout;
    jout = stdout;
    explicit = base && *base;
    if (!base || !*base) base = "origin/master";
    find_bindir(argv[0]);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--purpose")) { puts("select, focused tests and lint for the committed changes in one trip"); return 0; }
        if (!strcmp(argv[i], "--selftest")) return selftest();
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--gates")) gates = 1;
        else if (!strcmp(argv[i], "--base") && i + 1 < argc) { base = argv[++i]; explicit = 1; }
        else { fputs("usage: zcl-dev verify [--base REF] [--json] [--selftest]\n", stderr); return 2; }
    }
    if (!safe_ref(base)) { fprintf(stderr, "zcl-dev verify: unsafe base ref\n"); return 2; }
    if (json) say = stderr;
    enter_toplevel();
    return gates ? verify_gates(json, explicit ? base : NULL) : verify(base, json);
}
