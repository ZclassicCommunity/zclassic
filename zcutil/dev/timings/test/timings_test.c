/*
 * Golden-output tests for zcl-dev-timings over the fixture outdirs in test/fixture. The driver is C because
 * the shell-lines ratchet (zcl-lint kpi) leaves no room for another test script.
 * usage: timings_test <path to zcl-dev-timings> <test dir>        (UPDATE=1 rewrites test/golden; POSIX only)
 * Each case runs the tool inside the test directory, appends "exit N" to its output and compares the result
 * with golden/<name>.txt.
 */
#define _XOPEN_SOURCE 700 /* POSIX.1-2008 with XSI: realpath */
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *tool;
static int failures, update;

static int run_case(const char *const *args, char *out, size_t cap)
{
    int fd[2];
    const char *argv[32] = {tool};
    size_t got = 0, n;
    for (size_t i = 0; args[i] && i < 30; i++) argv[1 + i] = args[i];
    if (pipe(fd) != 0) return -1;
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
    while (got < cap - 32 && (n = (size_t)read(fd[0], out + got, cap - 32 - got)) > 0) got += n;
    close(fd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
    snprintf(out + got, 32, "exit %d\n", code);
    return code;
}

static size_t read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    if (f) fclose(f);
    buf[n] = 0;
    return f ? n : (size_t)-1;
}

static void write_file(const char *path, const char *s)
{
    FILE *f = fopen(path, "wb");
    if (!f || fputs(s, f) == EOF) { perror(path); failures++; }
    if (f) fclose(f);
}

static void check_case(const char *name, int want, const char *const *args)
{
    static char out[65536], gold[65536];
    char path[256];
    int code = run_case(args, out, sizeof out);
    snprintf(path, sizeof path, "golden/%s.txt", name);
    if (code != want) { printf("FAIL %s (exit %d, wanted %d)\n%s", name, code, want, out); failures++; return; }
    if (update) { write_file(path, out); return; }
    if (read_file(path, gold, sizeof gold) == (size_t)-1 || strcmp(gold, out)) {
        printf("FAIL %s (differs from %s)\n--- got\n%s--- want\n%s", name, path, out, gold);
        failures++;
        return;
    }
    printf("ok   %s\n", name);
}

int main(int argc, char **argv)
{
    if (argc != 3) { fputs("usage: timings_test <zcl-dev-timings> <test dir>\n", stderr); return 2; }
    char real[4096];
    tool = realpath(argv[1], real) ? strdup(real) : argv[1];
    update = getenv("UPDATE") && !strcmp(getenv("UPDATE"), "1");
    if (chdir(argv[2]) != 0) { perror(argv[2]); return 2; }
    mkdir("golden", 0755);
    check_case("three-good", 0, (const char *[]){"fixture/good1", "fixture/good2", "fixture/good3", NULL});
    check_case("missing-receipts", 0, (const char *[]){"fixture/good1", "fixture/norcpt", NULL});
    check_case("corrupt-line", 0, (const char *[]){"fixture/good1", "fixture/corrupt", NULL});
    check_case("mismatch", 1, (const char *[]){"fixture/good1", "fixture/mismatch", NULL});
    check_case("all-unreadable", 2, (const char *[]){"fixture/empty", "fixture/does-not-exist", NULL});
    check_case("json", 0, (const char *[]){"--json", "fixture/good1", "fixture/good2", "fixture/good3", NULL});
    check_case("step-filter", 0, (const char *[]){"--step", "regtest-smoke", "fixture/good1", "fixture/good2", "fixture/good3", NULL});
    check_case("empty-results-falls-back", 0, (const char *[]){"fixture/emptytsv", NULL});
    check_case("empty-results-only", 2, (const char *[]){"fixture/emptyonly", NULL});
    check_case("flavors-not-mismatch", 0, (const char *[]){"fixture/flavors", NULL});
    check_case("build-tests-flavors", 0, (const char *[]){"fixture/buildflavors", NULL});
    check_case("nested-receipts-corrupt", 0, (const char *[]){"fixture/nested", NULL});
    check_case("no-args", 2, (const char *[]){NULL});
    if (failures) { printf("zcl-dev-timings tests: %d failure(s)\n", failures); return 1; }
    puts("zcl-dev-timings tests: ok");
    return 0;
}
