/*
 * Fixture-command tests for zcl-dev-flaky: sh one-liners stand in for qa scripts. The driver is C because
 * the shell-lines ratchet (zcl-lint kpi) leaves no room for another test script.
 * usage: flaky_test <path to zcl-dev-flaky>      (POSIX only)
 */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *tool;
static int failures;

#define CHECK(name, cond)                                                   \
    do {                                                                    \
        if (cond) printf("ok   %s\n", name);                                \
        else { printf("FAIL %s\n", name); failures++; }                     \
    } while (0)

struct res {
    int code;
    char out[16384];
};

/* Run the tool with args (NULL terminated), capturing stdout and stderr. */
static void run_tool(struct res *r, const char *const *args)
{
    int fd[2];
    const char *argv[64] = {tool};
    size_t n = 0, got = 0;
    for (size_t i = 0; args[i] && i < 60; i++) argv[1 + i] = args[i];
    r->out[0] = 0;
    r->code = -1;
    if (pipe(fd) != 0) return;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fd[1], 1);
        dup2(fd[1], 2);
        close(fd[0]);
        close(fd[1]);
        execv(tool, (char *const *)argv);
        _exit(127);
    }
    close(fd[1]);
    while ((n = (size_t)read(fd[0], r->out + got, sizeof r->out - 1 - got)) > 0 && got < sizeof r->out - 1) got += n;
    r->out[got] = 0;
    close(fd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    r->code = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

/* Text of the line starting with prefix, copied to dst (empty when absent). */
static void line_after(const struct res *r, const char *prefix, char *dst, size_t cap)
{
    const char *p = strstr(r->out, prefix);
    size_t n = 0;
    dst[0] = 0;
    if (!p) return;
    for (p += strlen(prefix); *p && *p != '\n' && n + 1 < cap; p++) dst[n++] = *p;
    dst[n] = 0;
}

static int has(const struct res *r, const char *s) { return strstr(r->out, s) != NULL; }

static int file_has(const char *path, const char *s)
{
    char buf[4096] = {0};
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, s) != NULL;
}

static int exists(const char *dir, const char *name)
{
    char p[4200];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    return access(p, F_OK) == 0;
}

static int rm_cb(const char *p, const struct stat *sb, int type, struct FTW *ftw)
{
    (void)sb; (void)type; (void)ftw;
    return remove(p);
}

static void test_verdicts(void)
{
    struct res r;
    char log[4200], dir[4200];
    run_tool(&r, (const char *[]){"-n", "3", "--", "sh", "-c", "exit 0", NULL});
    CHECK("always-pass is PASS, exit 0", r.code == 0 && has(&r, "PASS: 3 runs, 3 passed, 0 failed"));
    run_tool(&r, (const char *[]){"-n", "3", "--", "sh", "-c", "exit 3", NULL});
    CHECK("always-fail is FAILING, exit 1", r.code == 1 && has(&r, "FAILING: 3 runs, 0 passed, 3 failed"));
    CHECK("failing exit code listed", has(&r, "exit codes seen: 3\n"));
    run_tool(&r, (const char *[]){"-n", "5", "--", "sh", "-c",
             "if [ \"$ZCL_FLAKY_RUN\" = 2 ] || [ \"$ZCL_FLAKY_RUN\" = 5 ]; then echo boom-$ZCL_FLAKY_RUN; exit 1; fi", NULL});
    CHECK("fails on runs 2 and 5 is FLAKY, exit 1", r.code == 1 && has(&r, "FLAKY: 5 runs, 3 passed, 2 failed"));
    line_after(&r, "first failing log: ", log, sizeof log);
    CHECK("first failing log is run-2", strstr(log, "/run-2/log") != NULL);
    CHECK("failing log holds its output", file_has(log, "boom-2"));
    line_after(&r, "run directory: ", dir, sizeof dir);
    CHECK("failing run 5 kept", exists(dir, "run-5/log"));
    CHECK("passing run 1 removed", !exists(dir, "run-1"));
    run_tool(&r, (const char *[]){"-n", "2", "--keep", "--", "sh", "-c", "exit 0", NULL});
    line_after(&r, "run directory: ", dir, sizeof dir);
    CHECK("--keep keeps passing runs", r.code == 0 && exists(dir, "run-1/log") && exists(dir, "run-2/log"));
}

static void test_errors(void)
{
    struct res r;
    run_tool(&r, (const char *[]){"-n", "2", "--", "/nonexistent/zcl-flaky-no-such-binary", NULL});
    CHECK("missing binary is BROKEN, exit 2", r.code == 2 && has(&r, "BROKEN: cannot start"));
    run_tool(&r, (const char *[]){"-n", "0", "--", "true", NULL});
    CHECK("-n 0 is a usage error", r.code == 2 && has(&r, "usage"));
    run_tool(&r, (const char *[]){"-n", "2", NULL});
    CHECK("no command is a usage error", r.code == 2 && has(&r, "usage"));
    run_tool(&r, (const char *[]){"-n", "2", "--jobs", "5", "--", "true", NULL});
    CHECK("--jobs above 4 is a usage error", r.code == 2 && has(&r, "usage"));
    run_tool(&r, (const char *[]){"-n", "1", "--timeout", "1", "--", "sh", "-c", "sleep 30", NULL});
    CHECK("sleep beyond --timeout is killed and fails", r.code == 1 && has(&r, "FAILING: 1 runs") && has(&r, "(killed on timeout)"));
    CHECK("timeout listed among exit codes", has(&r, "exit codes seen: timeout"));
}

static void test_work_and_jobs(const char *tmp)
{
    struct res r;
    char dir[4200], p[4300], share[4300], script[1024];
    run_tool(&r, (const char *[]){"-n", "2", "--keep", "--", "sh", "-c",
             "echo \"$1\" >\"$1/marker\"; echo \"$2\" >\"$1/num\"; echo \"$TMPDIR\" >\"$1/tmpdir\"", "sh", "@WORK@", "@RUN@", NULL});
    line_after(&r, "run directory: ", dir, sizeof dir);
    snprintf(p, sizeof p, "%s/run-2/num", dir);
    CHECK("@RUN@ substituted", r.code == 0 && file_has(p, "2\n"));
    snprintf(p, sizeof p, "%s/run-2/marker", dir);
    CHECK("@WORK@ substituted", strstr(dir, "run-2") == NULL && file_has(p, dir) && file_has(p, "/run-2\n"));
    snprintf(p, sizeof p, "%s/run-2/tmpdir", dir);
    CHECK("TMPDIR is the run directory", file_has(p, "/run-2\n"));

    /* the same fixture under --jobs 3 gives the same verdict */
    const char *flaky = "if [ \"$ZCL_FLAKY_RUN\" = 2 ] || [ \"$ZCL_FLAKY_RUN\" = 5 ]; then exit 1; fi; sleep 0.2";
    run_tool(&r, (const char *[]){"-n", "6", "--jobs", "3", "--", "sh", "-c", flaky, NULL});
    CHECK("--jobs 3 gives FLAKY 4/2 like sequential", r.code == 1 && has(&r, "FLAKY: 6 runs, 4 passed, 2 failed"));
    run_tool(&r, (const char *[]){"-n", "6", "--jobs", "1", "--", "sh", "-c", flaky, NULL});
    CHECK("--jobs 1 gives FLAKY 4/2", r.code == 1 && has(&r, "FLAKY: 6 runs, 4 passed, 2 failed"));
    run_tool(&r, (const char *[]){"-n", "3", "--json", "--", "sh", "-c", "test \"$ZCL_FLAKY_RUN\" != 3", NULL});
    CHECK("--json report", r.code == 1 && has(&r, "\"verdict\":\"FLAKY\"") && has(&r, "\"failures\":1"));

    /* runs overlap under --jobs 3: each waits (bounded) until all three have started */
    snprintf(share, sizeof share, "%s/overlap", tmp);
    mkdir(share, 0755);
    snprintf(script, sizeof script,
             "touch \"$1/m$2\"; i=0; while [ \"$(ls \"$1\" | grep -c '^m')\" -lt 3 ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; [ $i -lt 100 ]");
    run_tool(&r, (const char *[]){"-n", "3", "--jobs", "3", "--", "sh", "-c", script, "sh", share, "@RUN@", NULL});
    CHECK("--jobs 3 runs three at once", r.code == 0 && has(&r, "PASS: 3 runs"));
}

int main(int argc, char **argv)
{
    char tmp[4200];
    const char *base = getenv("TMPDIR");
    if (argc != 2) { fputs("usage: flaky_test <zcl-dev-flaky>\n", stderr); return 2; }
    tool = argv[1];
    snprintf(tmp, sizeof tmp, "%s/zcl-flaky-test.XXXXXX", base && *base ? base : "/tmp");
    if (!mkdtemp(tmp)) { perror("mkdtemp"); return 2; }
    char out[4300];
    snprintf(out, sizeof out, "%s/out", tmp);
    setenv("ZCL_FLAKY_OUT", out, 1);
    test_verdicts();
    test_errors();
    test_work_and_jobs(tmp);
    nftw(tmp, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
    if (failures) { printf("zcl-dev-flaky tests: %d failure(s)\n", failures); return 1; }
    puts("zcl-dev-flaky tests: ok");
    return 0;
}
