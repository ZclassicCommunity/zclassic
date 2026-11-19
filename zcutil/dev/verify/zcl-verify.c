/* zcl-dev verify: the one-trip check of committed changes, the analogue of Z23's
 * 'make agent-verify ONLY=@changed'. Libc only; builds with the host cc, clang and the mingw cross
 * compiler.
 *
 *   zcl-dev verify [--base REF] [--json] [--selftest] [--purpose]
 *
 * It runs, in order, and stops at the first failing step:
 *   1. zcl-dev select REF         which CI steps and qa scripts the committed diff needs (REF defaults to
 *                                 ZCL_CI_BASE, then origin/master)
 *   2. zcl-dev-t-fast --changed   focused unit tests; SKIPPED with a visible line when that tool is not built
 *   3. zcl-lint all               every lint rule and ratchet (there is no cheaper subset)
 *   4. a hint: the zcutil/local-ci.sh test-changed command that runs the selected CI steps
 * Exit: 0 every step that ran passed, 1 a step found a problem, 2 broken (a required tool is missing or
 * select failed). A skipped optional step never hides behind a pass: the summary names it.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define QUOTE '"'
#define EXE ".exe"
#else
#define QUOTE '\''
#define EXE ""
#endif

static char bindir[1024] = "zcutil/bin";

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

/* Run "<bindir>/<tool>" args through the shell; returns the exit status or -1. */
static int run(const char *tool, const char *args)
{
    char cmd[2400];
    int n = snprintf(cmd, sizeof cmd, "%c%s/%s%s%c %s", QUOTE, bindir, tool, EXE, QUOTE, args);
    if (n < 0 || (size_t)n >= sizeof cmd) { fprintf(stderr, "zcl-dev verify: command too long\n"); return -1; }
    fflush(stdout);
    int rc = system(cmd);
    if (rc == -1) return -1;
#ifdef _WIN32
    return rc;
#else
    if (rc & 0x7f) return 128 + (rc & 0x7f);
    return (rc >> 8) & 0xff;
#endif
}

struct result { const char *name; const char *verdict; int rc; };

static void print_json(const struct result *r, size_t n, int code, const char *base)
{
    printf("{\"base\":\"%s\",\"exit\":%d,\"steps\":[", base, code);
    for (size_t i = 0; i < n; i++)
        printf("%s{\"step\":\"%s\",\"verdict\":\"%s\",\"rc\":%d}", i ? "," : "", r[i].name, r[i].verdict, r[i].rc);
    puts("]}");
}

static int verify(const char *base, int json)
{
    struct result res[3];
    size_t n = 0;
    int code = 0, rc;
    char args[600];
    if (!tool_exists("zcl-dev")) {
        fprintf(stderr, "zcl-dev verify: %s/zcl-dev is missing; run make -C zcutil\n", bindir);
        return 2;
    }
    snprintf(args, sizeof args, "select %c%s%c", QUOTE, base, QUOTE);
    printf("== verify: select (base %s)\n", base);
    rc = run("zcl-dev", args);
    res[n++] = (struct result){"select", rc == 0 ? "PASS" : "BROKEN", rc};
    if (rc != 0) { code = 2; goto done; }

    if (tool_exists("zcl-dev-t-fast")) {
        printf("== verify: t-fast --changed\n");
        rc = run("zcl-dev-t-fast", "--changed");
        res[n++] = (struct result){"t-fast", rc == 0 ? "PASS" : "FAIL", rc};
        if (rc != 0) { code = 1; goto done; }
    } else {
        printf("== verify: t-fast SKIPPED (%s/zcl-dev-t-fast is not built in this tree)\n", bindir);
        res[n++] = (struct result){"t-fast", "SKIPPED", 0};
    }

    if (!tool_exists("zcl-lint")) {
        fprintf(stderr, "zcl-dev verify: %s/zcl-lint is missing (it builds on POSIX hosts only); run make -C zcutil\n", bindir);
        res[n++] = (struct result){"zcl-lint", "BROKEN", 2};
        code = 2;
        goto done;
    }
    printf("== verify: zcl-lint all\n");
    rc = run("zcl-lint", "all");
    res[n++] = (struct result){"zcl-lint", rc == 0 ? "PASS" : "FAIL", rc};
    if (rc != 0) code = rc == 1 ? 1 : 2;

done:
    printf("== verify summary\n");
    for (size_t i = 0; i < n; i++) printf("  %-10s %s\n", res[i].name, res[i].verdict);
    if (code == 0)
        printf("next: ZCL_CI_BASE=%s zcutil/local-ci.sh --commit HEAD test-changed <outdir>   (runs the CI steps select listed)\n", base);
    if (json) print_json(res, n, code, base);
    return code;
}

static int selftest(void)
{
    if (!safe_ref("origin/master") || !safe_ref("HEAD~3") || safe_ref("") || safe_ref("-x") || safe_ref("a b") || safe_ref("a;b")) {
        fputs("selftest: safe_ref failed\n", stderr);
        return 1;
    }
    puts("zcl-dev verify selftest: ok");
    return 0;
}

int main(int argc, char **argv)
{
    const char *base = getenv("ZCL_CI_BASE");
    int json = 0;
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
    return verify(base, json);
}
