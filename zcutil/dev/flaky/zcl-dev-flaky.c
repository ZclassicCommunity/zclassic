/*
 * zcl-dev flaky: run one command N times in isolated directories and say whether it is stable.
 *
 * usage: zcl-dev flaky -n N [--jobs J] [--timeout SECS] [--keep] [--json] -- <argv...>
 *        zcl-dev-flaky --selftest | --purpose
 * Run k gets <out>/<UTC stamp>-<pid>/run-<k>/ (TMPDIR and @WORK@ point at it, ZCL_FLAKY_RUN=k, @RUN@ is k).
 * Verdict: PASS, FLAKY (some failed), FAILING (all failed), BROKEN (could not start).
 * Exit: 0 PASS, 1 FLAKY or FAILING, 2 BROKEN, bad arguments or Windows (UNAVAILABLE).
 * Libc and POSIX only; Windows prints UNAVAILABLE. Written for zclassicd (idea from Z23 tools/process_group_exec.c).
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#define PURPOSE "repeat a test N times in isolated workdirs; PASS, FLAKY or FAILING with logs"
#define NMAX 1000
#define JOBS_MAX 4
#define TIMEOUT_DEFAULT 900
#define PATH_BUF 4096
#define LOG_CAP (256LL * 1024 * 1024) /* a run whose log passes this is killed and fails (local-ci caps step logs the same) */

struct cfg {
    int n, jobs, timeout, keep, json;
    char **argv; /* command, NULL terminated, still holding @WORK@ and @RUN@ */
    int argc;
};

struct run {
    int code;      /* exit status; 128+signal when killed by a signal */
    int timed_out; /* killed by our deadline */
    int oversize;  /* killed because its log passed LOG_CAP */
    int ran;       /* finished */
    double secs;
    char dir[PATH_BUF];
    char log[PATH_BUF];
    char work[PATH_BUF]; /* run-<k>/work: empty when the command starts */
    char tmp[PATH_BUF];  /* run-<k>/tmp: TMPDIR */
#ifndef _WIN32
    pid_t pid;
    double t0;
#endif
};

/* ---------------------------------------------------------------- pure helpers */

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Sort v[0..n) in place and return its median. */
static double median_of(double *v, int n)
{
    if (n <= 0) return 0;
    qsort(v, (size_t)n, sizeof *v, cmp_double);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

/* Replace every @WORK@ and @RUN@ in s; the result is malloc'd (NULL when out of memory). */
static char *subst(const char *s, const char *work, int k)
{
    char num[16];
    snprintf(num, sizeof num, "%d", k);
    size_t cap = strlen(s) + 1, wl = strlen(work), nl = strlen(num);
    for (const char *p = s; *p; p++) cap += wl + nl;
    char *out = malloc(cap), *o = out;
    if (!out) return NULL;
    while (*s) {
        if (!strncmp(s, "@WORK@", 6)) { memcpy(o, work, wl); o += wl; s += 6; }
        else if (!strncmp(s, "@RUN@", 5)) { memcpy(o, num, nl); o += nl; s += 5; }
        else *o++ = *s++;
    }
    *o = 0;
    return out;
}

static const char *verdict_of(int n, int failures)
{
    if (failures == 0) return "PASS";
    return failures == n ? "FAILING" : "FLAKY";
}

/* Parse a decimal int in [lo, hi]; -1 on anything else. */
static int parse_int(const char *s, int lo, int hi)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < lo || v > hi) return -1;
    return (int)v;
}

static void usage(FILE *f)
{
    fputs("usage: zcl-dev flaky -n N [--jobs J<=4] [--timeout SECS] [--keep] [--json] -- <argv...>\n"
          "  runs argv N times (1..1000); @WORK@ in argv is the run directory, @RUN@ the run number;\n"
          "  verdict PASS | FLAKY | FAILING | BROKEN; exit 0 PASS, 1 FLAKY or FAILING, 2 BROKEN or usage\n",
          f);
}

/* ---------------------------------------------------------------- arguments */

/* One option at argv[*i]; returns 0 ok, -1 bad. */
static int parse_opt(int argc, char **argv, int *i, struct cfg *c)
{
    const char *a = argv[*i];
    int *slot = NULL, lo = 1, hi = 0;
    if (!strcmp(a, "--keep")) { c->keep = 1; return 0; }
    if (!strcmp(a, "--json")) { c->json = 1; return 0; }
    if (!strcmp(a, "-n")) { slot = &c->n; hi = NMAX; }
    else if (!strcmp(a, "--jobs")) { slot = &c->jobs; hi = JOBS_MAX; }
    else if (!strcmp(a, "--timeout")) { slot = &c->timeout; hi = 86400 * 7; }
    if (!slot || *i + 1 >= argc) return -1;
    *slot = parse_int(argv[++*i], lo, hi);
    return *slot < 0 ? -1 : 0;
}

static int parse_args(int argc, char **argv, struct cfg *c)
{
    int i;
    memset(c, 0, sizeof *c);
    c->jobs = 1;
    c->timeout = TIMEOUT_DEFAULT;
    for (i = 1; i < argc && strcmp(argv[i], "--"); i++)
        if (parse_opt(argc, argv, &i, c)) return -1;
    if (i >= argc - 1 || c->n < 1) return -1;
    c->argv = argv + i + 1;
    c->argc = argc - i - 1;
    return 0;
}

#ifdef _WIN32

static int run_main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    puts("UNAVAILABLE: zcl-dev flaky needs POSIX process groups; run it on Linux or macOS");
    return 2;
}

#else

static int is_failure(const struct run *r) { return r->timed_out || r->oversize || r->code != 0; }

/* ---------------------------------------------------------------- signals */

/* Each run is its own process group, so a terminal Ctrl-C never reaches it: the runner catches the
 * signal itself, kills every group and reports INTERRUPTED. No SA_RESTART, so sleeps return at once. */
static volatile sig_atomic_t g_sig;

static void on_signal(int sig) { g_sig = sig; }

static void install_signals(void)
{
    static const int sigs[] = {SIGINT, SIGTERM, SIGHUP};
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) sigaction(sigs[i], &sa, NULL);
}

/* ---------------------------------------------------------------- filesystem */

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void rmtree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (!S_ISDIR(st.st_mode)) { unlink(path); return; }
    chmod(path, 0700);
    DIR *d = opendir(path);
    struct dirent *e;
    while (d && (e = readdir(d))) {
        char sub[PATH_BUF];
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (snprintf(sub, sizeof sub, "%s/%s", path, e->d_name) >= (int)sizeof sub) continue;
        rmtree(sub);
    }
    if (d) closedir(d);
    rmdir(path);
}

static int mkdir_p(const char *path)
{
    char buf[PATH_BUF];
    size_t n = strlen(path);
    if (n >= sizeof buf) return -1;
    memcpy(buf, path, n + 1);
    for (size_t i = 1; i < n; i++) {
        if (buf[i] != '/') continue;
        buf[i] = 0;
        if (mkdir(buf, 0777) != 0 && errno != EEXIST) return -1;
        buf[i] = '/';
    }
    return mkdir(buf, 0777) != 0 && errno != EEXIST ? -1 : 0;
}

/* Output root: ZCL_FLAKY_OUT, else <dir of this binary>/../gen/flaky, else zcutil/gen/flaky. */
static void out_root(const char *argv0, char *dst, size_t cap)
{
    const char *env = getenv("ZCL_FLAKY_OUT");
    const char *slash = strrchr(argv0, '/');
    if (env && *env) snprintf(dst, cap, "%s", env);
    else if (slash) snprintf(dst, cap, "%.*s/../gen/flaky", (int)(slash - argv0), argv0);
    else snprintf(dst, cap, "zcutil/gen/flaky");
}

static int make_stamp_dir(const char *root, char *dst, size_t cap)
{
    char stamp[32];
    time_t t = time(NULL);
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(stamp, sizeof stamp, "%Y%m%dT%H%M%SZ", &tmv);
    if (snprintf(dst, cap, "%s/%s-%ld", root, stamp, (long)getpid()) >= (int)cap) return -1;
    return mkdir_p(dst);
}

/* ---------------------------------------------------------------- spawning */

static void free_argv(char **v)
{
    for (int i = 0; v && v[i]; i++) free(v[i]);
    free(v);
}

static char **build_argv(const struct cfg *c, const char *work, int k)
{
    char **v = calloc((size_t)c->argc + 1, sizeof *v);
    if (!v) return NULL;
    for (int i = 0; i < c->argc; i++)
        if (!(v[i] = subst(c->argv[i], work, k))) { free_argv(v); return NULL; }
    return v;
}

static void child_exec(char **av, const char *dir, int k, int logfd, int errfd)
{
    char num[16];
    int nul = open("/dev/null", O_RDONLY);
    setpgid(0, 0);
    if (nul >= 0) dup2(nul, 0);
    dup2(logfd, 1);
    dup2(logfd, 2);
    snprintf(num, sizeof num, "%d", k);
    setenv("TMPDIR", dir, 1);
    setenv("ZCL_FLAKY_RUN", num, 1);
    execvp(av[0], av);
    int e = errno;
    if (write(errfd, &e, sizeof e) < 0) _exit(127);
    _exit(127);
}

/* Start run k; 0 on success, else -1 with errno from the failed exec or fork. */
static int launch(const struct cfg *c, struct run *r, int k)
{
    int ep[2], err = 0;
    char **av = build_argv(c, r->work, k);
    int logfd = open(r->log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!av || logfd < 0 || pipe(ep) != 0) {
        free_argv(av);
        if (logfd >= 0) close(logfd);
        return -1;
    }
    fcntl(ep[0], F_SETFD, FD_CLOEXEC);
    fcntl(ep[1], F_SETFD, FD_CLOEXEC);
    r->t0 = now_s();
    r->pid = fork();
    if (r->pid == 0) child_exec(av, r->tmp, k, logfd, ep[1]);
    close(ep[1]);
    close(logfd);
    free_argv(av);
    if (r->pid < 0) { close(ep[0]); return -1; }
    setpgid(r->pid, r->pid);
    if (read(ep[0], &err, sizeof err) == (ssize_t)sizeof err) {
        waitpid(r->pid, NULL, 0);
        close(ep[0]);
        r->pid = 0;
        errno = err;
        return -1;
    }
    close(ep[0]);
    return 0;
}

enum { WHY_EXIT, WHY_TIMEOUT, WHY_OVERSIZE };

static void finish(struct run *r, int status, int why)
{
    r->secs = now_s() - r->t0;
    r->ran = 1;
    r->timed_out = why == WHY_TIMEOUT;
    r->oversize = why == WHY_OVERSIZE;
    if (WIFEXITED(status)) r->code = WEXITSTATUS(status);
    else r->code = 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

/* Kill the whole group, then reap its leader. The kill comes first: until the leader is reaped its pid cannot
 * be reused, so the signal cannot reach an unrelated group. Processes that stay in the group die; one that calls setsid or setpgid escapes. */
static void kill_and_reap(struct run *r, int why)
{
    int st = 0;
    kill(-r->pid, SIGKILL);
    waitpid(r->pid, &st, 0);
    finish(r, st, why);
}

static long long g_log_cap = LOG_CAP; /* ZCL_FLAKY_LOG_CAP overrides it (bytes; the tests use it) */

static int log_oversize(const struct run *r)
{
    struct stat sb;
    return stat(r->log, &sb) == 0 && (long long)sb.st_size > g_log_cap;
}

/* Poll one running run: 1 when it finished this call. */
static int poll_one(struct run *r, int timeout)
{
    siginfo_t si;
    memset(&si, 0, sizeof si);
    /* WNOWAIT leaves the leader a zombie, so the group kill below still names our own group */
    if (waitid(P_PID, (id_t)r->pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == r->pid) {
        kill_and_reap(r, WHY_EXIT);
        return 1;
    }
    if (log_oversize(r)) { kill_and_reap(r, WHY_OVERSIZE); return 1; }
    if (now_s() - r->t0 <= timeout) return 0;
    kill_and_reap(r, WHY_TIMEOUT);
    return 1;
}

/* Kill and reap every run that is still going among runs[0..upto); returns how many. */
static int abort_all(struct run *runs, int upto)
{
    int st, killed = 0;
    for (int i = 0; i < upto; i++) {
        if (runs[i].ran || runs[i].pid <= 0) continue;
        kill(-runs[i].pid, SIGKILL);
        waitpid(runs[i].pid, &st, 0);
        runs[i].pid = 0;
        killed++;
    }
    return killed;
}

enum { DRIVE_OK = 0, DRIVE_BROKEN = -1, DRIVE_INTERRUPTED = -2 };

/* Drive all runs; returns DRIVE_OK, or DRIVE_BROKEN after printing BROKEN, or DRIVE_INTERRUPTED after a
 * signal (every running group already killed and reaped, *killed says how many). */
static int drive(const struct cfg *c, struct run *runs, int *killed)
{
    int next = 0, running = 0, done = 0;
    struct timespec nap = {0, 20 * 1000 * 1000};
    while (done < c->n) {
        if (g_sig) { *killed = abort_all(runs, next); return DRIVE_INTERRUPTED; }
        while (running < c->jobs && next < c->n && !g_sig) {
            if (launch(c, &runs[next], next + 1) != 0) {
                printf("BROKEN: cannot start `%s`: %s\n", c->argv[0], strerror(errno));
                abort_all(runs, next);
                return DRIVE_BROKEN;
            }
            next++;
            running++;
        }
        int before = done;
        for (int i = 0; i < next; i++)
            if (!runs[i].ran && poll_one(&runs[i], c->timeout)) { done++; running--; }
        if (done == before) nanosleep(&nap, NULL);
    }
    return DRIVE_OK;
}

/* ---------------------------------------------------------------- report */

struct summary {
    int failures, first_fail;
    double min, med, max;
    int codes[257]; /* 0..255 seen; 256 timeout */
};

static void summarize(const struct cfg *c, const struct run *runs, struct summary *s)
{
    double *v = malloc((size_t)c->n * sizeof *v);
    memset(s, 0, sizeof *s);
    s->first_fail = -1;
    for (int i = 0; i < c->n; i++) {
        if (is_failure(&runs[i])) {
            s->failures++;
            if (s->first_fail < 0) s->first_fail = i;
        }
        s->codes[runs[i].timed_out ? 256 : runs[i].code & 255] = 1;
        if (v) v[i] = runs[i].secs;
    }
    if (v) {
        s->med = median_of(v, c->n);
        s->min = v[0];
        s->max = v[c->n - 1];
    }
    free(v);
}

static void code_list(const struct summary *s, char *dst, size_t cap)
{
    size_t n = 0;
    dst[0] = 0;
    for (int i = 0; i < 257 && n + 12 < cap; i++) {
        if (!s->codes[i]) continue;
        if (i == 256) n += (size_t)snprintf(dst + n, cap - n, "%stimeout", n ? " " : "");
        else n += (size_t)snprintf(dst + n, cap - n, "%s%d", n ? " " : "", i);
    }
}

static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') fprintf(f, "\\%c", *s);
        else if ((unsigned char)*s < 0x20) fprintf(f, "\\u%04x", (unsigned char)*s);
        else fputc(*s, f);
    }
    fputc('"', f);
}

/* The run directory survives a report when --keep is given or some run failed. */
static int dir_kept(const struct cfg *c, const struct summary *s) { return c->keep || s->failures > 0; }

static void report_json(const struct cfg *c, const struct run *runs, const struct summary *s,
                        const char *verdict, const char *dir)
{
    char codes[256];
    code_list(s, codes, sizeof codes);
    printf("{\"verdict\":\"%s\",\"runs\":%d,\"failures\":%d,\"jobs\":%d,\"timeout\":%d,"
           "\"min_s\":%.3f,\"median_s\":%.3f,\"max_s\":%.3f,\"exit_codes\":\"%s\",\"dir\":",
           verdict, c->n, s->failures, c->jobs, c->timeout, s->min, s->med, s->max, codes);
    if (dir_kept(c, s)) json_str(stdout, dir);
    else fputs("null", stdout);
    fputs(",\"first_failing_log\":", stdout);
    if (s->first_fail >= 0) json_str(stdout, runs[s->first_fail].log);
    else fputs("null", stdout);
    puts("}");
}

static void report_text(const struct cfg *c, const struct run *runs, const struct summary *s,
                        const char *verdict, const char *dir)
{
    char codes[256];
    code_list(s, codes, sizeof codes);
    printf("%s: %d runs, %d passed, %d failed (jobs %d, timeout %ds)\n", verdict, c->n,
           c->n - s->failures, s->failures, c->jobs, c->timeout);
    printf("seconds: min %.2f median %.2f max %.2f\n", s->min, s->med, s->max);
    printf("exit codes seen: %s\n", codes);
    if (s->first_fail >= 0)
        printf("first failing log: %s%s\n", runs[s->first_fail].log,
               runs[s->first_fail].timed_out ? " (killed on timeout)"
               : runs[s->first_fail].oversize ? " (killed: log passed 256 MiB)" : "");
    if (dir_kept(c, s)) printf("run directory: %s\n", dir);
    else puts("run directory: removed (every run passed; --keep keeps it)");
}

/* Remove what a passing run left (its whole directory) unless --keep; tidy an empty stamp directory. */
static void cleanup(const struct cfg *c, const struct run *runs, const char *dir)
{
    if (c->keep) return;
    for (int i = 0; i < c->n; i++)
        if (!is_failure(&runs[i])) rmtree(runs[i].dir);
    rmdir(dir);
}

static int setup_runs(const struct cfg *c, struct run *runs, const char *dir)
{
    for (int i = 0; i < c->n; i++) {
        if (snprintf(runs[i].dir, sizeof runs[i].dir, "%s/run-%d", dir, i + 1) >= (int)sizeof runs[i].dir) return -1;
        if (snprintf(runs[i].log, sizeof runs[i].log, "%s/log", runs[i].dir) >= (int)sizeof runs[i].log) return -1;
        if (snprintf(runs[i].work, sizeof runs[i].work, "%s/work", runs[i].dir) >= (int)sizeof runs[i].work) return -1;
        if (snprintf(runs[i].tmp, sizeof runs[i].tmp, "%s/tmp", runs[i].dir) >= (int)sizeof runs[i].tmp) return -1;
        if (mkdir(runs[i].dir, 0777) != 0 || mkdir(runs[i].work, 0777) != 0 || mkdir(runs[i].tmp, 0777) != 0) return -1;
    }
    return 0;
}

static int run_main(int argc, char **argv)
{
    struct cfg c;
    struct summary s;
    char root[PATH_BUF], dir[PATH_BUF];
    if (parse_args(argc, argv, &c)) { usage(stderr); return 2; }
    struct run *runs = calloc((size_t)c.n, sizeof *runs);
    out_root(argv[0], root, sizeof root);
    if (!runs || make_stamp_dir(root, dir, sizeof dir) || setup_runs(&c, runs, dir)) {
        fprintf(stderr, "zcl-dev flaky: cannot create run directories under %s: %s\n", root, strerror(errno));
        free(runs);
        return 2;
    }
    const char *cap_env = getenv("ZCL_FLAKY_LOG_CAP");
    if (cap_env && atoll(cap_env) > 0) g_log_cap = atoll(cap_env);
    install_signals();
    int killed = 0, rc = drive(&c, runs, &killed);
    if (rc == DRIVE_INTERRUPTED) {
        printf("INTERRUPTED: signal %d; killed %d running group(s); partial logs kept under %s\n", (int)g_sig, killed, dir);
        free(runs);
        return 2;
    }
    if (rc != DRIVE_OK) { rmtree(dir); free(runs); return 2; }
    summarize(&c, runs, &s);
    const char *verdict = verdict_of(c.n, s.failures);
    if (c.json) report_json(&c, runs, &s, verdict, dir);
    else report_text(&c, runs, &s, verdict, dir);
    cleanup(&c, runs, dir);
    free(runs);
    return s.failures ? 1 : 0;
}

#endif /* _WIN32 */

/* ---------------------------------------------------------------- selftest */

static int st_fail;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "selftest FAIL line %d: %s\n", __LINE__, #x); st_fail++; } } while (0)

static void selftest_args(void)
{
    struct cfg c;
    char *ok[] = {"flaky", "-n", "5", "--jobs", "3", "--timeout", "7", "--keep", "--", "sh", "-c", "x", NULL};
    char *bad_n[] = {"flaky", "-n", "0", "--", "sh", NULL};
    char *big_j[] = {"flaky", "-n", "2", "--jobs", "5", "--", "sh", NULL};
    char *no_cmd[] = {"flaky", "-n", "2", "--", NULL};
    char *no_n[] = {"flaky", "--", "sh", NULL};
    CHECK(parse_args(12, ok, &c) == 0 && c.n == 5 && c.jobs == 3 && c.timeout == 7 && c.keep && c.argc == 3);
    CHECK(parse_args(5, bad_n, &c) != 0);
    CHECK(parse_args(7, big_j, &c) != 0);
    CHECK(parse_args(4, no_cmd, &c) != 0);
    CHECK(parse_args(3, no_n, &c) != 0);
    CHECK(parse_int("1000", 1, NMAX) == 1000 && parse_int("1001", 1, NMAX) < 0 && parse_int("2x", 1, 9) < 0);
}

static void selftest_pure(void)
{
    double a[] = {3, 1, 2}, b[] = {4, 1, 2, 3};
    char *s = subst("--work=@WORK@/x run @RUN@ @RUN@", "/w/run-3", 3);
    CHECK(s && !strcmp(s, "--work=/w/run-3/x run 3 3"));
    free(s);
    CHECK(median_of(a, 3) == 2.0 && median_of(b, 4) == 2.5);
    CHECK(!strcmp(verdict_of(3, 0), "PASS") && !strcmp(verdict_of(3, 2), "FLAKY") && !strcmp(verdict_of(3, 3), "FAILING"));
    CHECK(!strcmp(verdict_of(1, 1), "FAILING"));
}

static int selftest(void)
{
    selftest_args();
    selftest_pure();
    if (st_fail) {
        fprintf(stderr, "zcl-dev-flaky selftest: %d failure(s)\n", st_fail);
        return 1;
    }
    puts("zcl-dev-flaky selftest: ok");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "--purpose")) { puts(PURPOSE); return 0; }
    if (argc >= 2 && !strcmp(argv[1], "--selftest")) return selftest();
    if (argc >= 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) { usage(stdout); return 0; }
    return run_main(argc, argv);
}
