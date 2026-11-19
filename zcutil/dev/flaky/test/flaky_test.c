/*
 * Fixture-command tests for zcl-dev-flaky: sh one-liners stand in for qa scripts. The driver is C because
 * the shell-lines ratchet (zcl-lint kpi) leaves no room for another test script.
 * usage: flaky_test <path to zcl-dev-flaky>      (POSIX only)
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#define _XOPEN_SOURCE 700
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
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
    snprintf(p, sizeof p, "%s/run-2/work/num", dir);
    CHECK("@RUN@ substituted", r.code == 0 && file_has(p, "2\n"));
    snprintf(p, sizeof p, "%s/run-2/work/marker", dir);
    CHECK("@WORK@ substituted", strstr(dir, "run-2") == NULL && file_has(p, dir) && file_has(p, "/run-2/work\n"));
    snprintf(p, sizeof p, "%s/run-2/work/tmpdir", dir);
    CHECK("TMPDIR is run-<k>/tmp", file_has(p, "/run-2/tmp\n"));
    /* the command sees an empty work directory (qa scripts refuse a non-empty --work) */
    run_tool(&r, (const char *[]){"-n", "2", "--", "sh", "-c", "[ -z \"$(ls -A \"$1\")\" ]", "sh", "@WORK@", NULL});
    CHECK("@WORK@ is empty when the command starts", r.code == 0 && has(&r, "PASS: 2 runs"));

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

/* pid written by a fixture run into path, 0 until it is there */
static long read_pid(const char *path)
{
    char buf[64] = {0};
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    return n && buf[n - 1] == '\n' ? atol(buf) : 0;
}

static void nap(int ms)
{
    struct timespec ts = {0, (long)ms * 1000000L};
    nanosleep(&ts, NULL);
}

/* Both fixture runs have written their pid; 0 when they did not within 10 s. */
static int wait_pids(const char *share, long *pid)
{
    char p[4400];
    for (int tries = 0; tries < 200; tries++) {
        int have = 0;
        for (int k = 0; k < 2; k++) {
            snprintf(p, sizeof p, "%s/pid.%d", share, k + 1);
            if ((pid[k] = read_pid(p)) > 0) have++;
        }
        if (have == 2) return 1;
        nap(50);
    }
    return 0;
}

static int all_dead(const long *pid)
{
    for (int tries = 0; tries < 100; tries++) {
        if (kill((pid_t)pid[0], 0) != 0 && kill((pid_t)pid[1], 0) != 0) return 1;
        nap(50);
    }
    return 0;
}

/* Signal the runner while two long sleeps run: it must exit 2, say INTERRUPTED and leave no child alive. */
static void test_signal(const char *tmp, int sig, const char *name)
{
    char share[4300], outp[4400], title[128], script[] = "echo $$ >\"$1/pid.$2\"; exec sleep 300";
    char *const args[] = {(char *)tool, "-n", "2", "--jobs", "2", "--", "sh", "-c", script, "sh", share, "@RUN@", NULL};
    long pid[2] = {0, 0};
    snprintf(share, sizeof share, "%s/sig%d", tmp, sig);
    snprintf(outp, sizeof outp, "%s/sig%d.out", tmp, sig);
    mkdir(share, 0755);
    pid_t runner = fork();
    if (runner == 0) {
        if (!freopen(outp, "w", stdout)) _exit(127);
        dup2(1, 2);
        execv(tool, args);
        _exit(127);
    }
    int started = wait_pids(share, pid), st = 0;
    if (started) kill(runner, sig);
    else kill(runner, SIGKILL);
    waitpid(runner, &st, 0);
    snprintf(title, sizeof title, "%s: runner exits 2 and says INTERRUPTED", name);
    CHECK(title, started && WIFEXITED(st) && WEXITSTATUS(st) == 2 && file_has(outp, "INTERRUPTED: signal"));
    snprintf(title, sizeof title, "%s: no child survives the runner", name);
    CHECK(title, started && all_dead(pid));
    for (int k = 0; k < 2; k++) if (pid[k] > 0) kill((pid_t)pid[k], SIGKILL);
}

static void test_limits(void)
{
    struct res r;
    char dir[4200];
    run_tool(&r, (const char *[]){"-n", "1", "--", "sh", "-c", "exit 0", NULL});
    CHECK("passing report says the directory was removed", r.code == 0 && has(&r, "run directory: removed")
          && !has(&r, "run directory: /"));
    run_tool(&r, (const char *[]){"-n", "1", "--json", "--", "sh", "-c", "exit 0", NULL});
    CHECK("passing --json has dir null", r.code == 0 && has(&r, "\"dir\":null"));
    run_tool(&r, (const char *[]){"-n", "2", "--keep", "--", "sh", "-c", "exit 0", NULL});
    line_after(&r, "run directory: ", dir, sizeof dir);
    CHECK("--keep report names an existing directory", exists(dir, "run-1/log"));
    setenv("ZCL_FLAKY_LOG_CAP", "100000", 1);
    run_tool(&r, (const char *[]){"-n", "1", "--timeout", "60", "--", "sh", "-c", "head -c 3000000 /dev/zero; sleep 30", NULL});
    unsetenv("ZCL_FLAKY_LOG_CAP");
    CHECK("a runaway log is killed and fails", r.code == 1 && has(&r, "FAILING: 1 runs") && has(&r, "(killed: log passed"));
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
    test_limits();
    test_signal(tmp, SIGINT, "SIGINT");
    test_signal(tmp, SIGTERM, "SIGTERM");
    test_signal(tmp, SIGHUP, "SIGHUP");
    nftw(tmp, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
    if (failures) { printf("zcl-dev-flaky tests: %d failure(s)\n", failures); return 1; }
    puts("zcl-dev-flaky tests: ok");
    return 0;
}
