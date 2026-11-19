/* zcl-dev mutate run and restore: apply one mutant at a time to a tracked file, build, test, restore.
 *
 * Derived from Z23 tools/dev/mutation_run.c@9a191ef7b, Apache-2.0; changed. See zcutil/tools/NOTICE
 *
 * Changed from Z23: Z23 compiles each mutant from a scratch copy and never writes the checkout. Here the
 * build is whatever command the caller names, so the mutant is written to the file itself, and safety
 * comes from the guards instead: the file must be tracked and clean, its original bytes are kept in
 * memory and in <file>.zcl-mutate.orig (O_EXCL), every restore is verified by memcmp of the re-read
 * file, SIGINT/SIGTERM/SIGHUP only set a flag that the loop honours (restore, exit 130), an atexit
 * handler restores, and a normal finish asserts `git diff --quiet -- <file>`. Children run in their
 * own process group (the pattern of zcutil/tools/vendor/tools/process_group_exec.c) and the group is
 * killed on timeout, on interrupt and after every run. POSIX only; on Windows run and restore exit 2.
 */
#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#endif
#include "mutate_ops.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)

int mut_run(const struct mut_opts *o)
{
    (void)o;
    fputs("UNAVAILABLE on Windows: run on a POSIX host\n", stderr);
    return 2;
}

int mut_restore(const char *file)
{
    (void)file;
    fputs("UNAVAILABLE on Windows: run on a POSIX host\n", stderr);
    return 2;
}

#else

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ORIG_SUFFIX ".zcl-mutate.orig"
#define ST_TIMEOUT (-2)
#define ST_STOPPED (-3)

static const char *const vendored[] = {
    "src/c23/vendor/", "src/c23/services/vendor/", "zcutil/tools/vendor/", "src/leveldb/",
    "src/secp256k1/", "src/univalue/", "depends/", "wallet/src/3rdparty/", "src/pow/tromp/", NULL,
};

/* What the atexit handler needs to put the file back. */
static struct {
    char path[PATH_MAX];
    char orig_path[PATH_MAX + sizeof ORIG_SUFFIX];
    const char *bytes;
    size_t len;
    bool dirty; /* the file may not hold the original bytes */
} g;
static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
}

/* ---- files --------------------------------------------------------------------------------- */
static bool write_all(int fd, const char *b, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, b, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        b += w;
        n -= (size_t)w;
    }
    return true;
}

/* Rewrites an existing file in place (its mode and inode stay). */
static bool overwrite(const char *path, const char *b, size_t n)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return false;
    bool ok = write_all(fd, b, n);
    return close(fd) == 0 && ok;
}

static bool holds(const char *path, const char *b, size_t n)
{
    size_t len = 0;
    char *now = mut_read_file(path, &len);
    bool same = now && len == n && memcmp(now, b, n) == 0;
    free(now);
    return same;
}

/* Puts the original bytes back and proves it by re-reading. */
static bool restore_verified(void)
{
    for (int attempt = 0; attempt < 3; attempt++)
        if (overwrite(g.path, g.bytes, g.len) && holds(g.path, g.bytes, g.len)) {
            g.dirty = false;
            return true;
        }
    fprintf(stderr, "zcl-dev mutate: RESTORE FAILED for %s: the original bytes are in %s; run `zcl-dev mutate restore %s`\n",
            g.path, g.orig_path, g.path);
    return false;
}

static void at_exit_restore(void)
{
    if (g.dirty && restore_verified()) (void)unlink(g.orig_path);
}

static bool write_orig(void)
{
    int fd = open(g.orig_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return false;
    bool ok = write_all(fd, g.bytes, g.len) && fsync(fd) == 0;
    if (close(fd) != 0 || !ok) {
        (void)unlink(g.orig_path);
        return false;
    }
    return true;
}

/* ---- processes ----------------------------------------------------------------------------- */
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void nap_ms(long ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static int decode(int st)
{
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return WIFSIGNALED(st) ? 128 + WTERMSIG(st) : 125;
}

/* The child: leader of its own process group, stdin from /dev/null, output to out_fd. */
static void child_exec(char *const argv[], int out_fd, int err_fd)
{
    (void)setpgid(0, 0);
    int nul = open("/dev/null", O_RDONLY);
    if (nul >= 0) (void)dup2(nul, 0);
    (void)dup2(out_fd, 1);
    (void)dup2(err_fd, 2);
    execvp(argv[0], argv);
    dprintf(2, "zcl-dev mutate: cannot run %s: %s\n", argv[0], strerror(errno));
    _exit(127);
}

static bool leader_exited(pid_t pid)
{
    siginfo_t si;
    memset(&si, 0, sizeof si);
    return waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == pid;
}

/* While the exited leader is still unreaped its pid names the group, so killing the group cannot hit
 * anyone else; SIGTERM first when asked, then SIGKILL for every straggler, then reap. */
static int end_group(pid_t pid, bool term_first)
{
    if (term_first) {
        (void)kill(-pid, SIGTERM);
        for (int i = 0; i < 100 && !leader_exited(pid); i++) nap_ms(20);
    }
    (void)kill(-pid, SIGKILL);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return decode(st);
}

/* Runs argv with a timeout; returns its exit status, 128+signal, ST_TIMEOUT, ST_STOPPED or -1. */
static int run_supervised(char *const argv[], long timeout_s, int log_fd)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) child_exec(argv, log_fd, log_fd);
    (void)setpgid(pid, pid);
    long long deadline = now_ms() + timeout_s * 1000LL;
    for (;;) {
        if (leader_exited(pid)) return end_group(pid, false);
        if (g_stop) { end_group(pid, true); return ST_STOPPED; }
        if (now_ms() >= deadline) { end_group(pid, true); return ST_TIMEOUT; }
        nap_ms(20);
    }
}

/* Reads fd to end of file into a fresh NUL-terminated buffer, or NULL. */
static char *read_all(int fd, size_t *len)
{
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap + 1);
    while (buf) {
        ssize_t r = read(fd, buf + n, cap - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
        if (n < cap) continue;
        char *nb = realloc(buf, cap * 2 + 1);
        if (!nb) free(buf);
        buf = nb;
        cap *= 2;
    }
    if (buf) buf[n] = 0;
    *len = n;
    return buf;
}

/* Runs argv to completion, capturing stdout (stderr is dropped); returns the exit status or -1. */
static int run_capture(char *const argv[], char **out, size_t *out_len)
{
    int p[2];
    if (pipe(p) != 0) return -1;
    int nul = open("/dev/null", O_WRONLY);
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        child_exec(argv, p[1], nul >= 0 ? nul : 2);
    }
    close(p[1]);
    if (nul >= 0) close(nul);
    size_t n = 0;
    char *buf = pid > 0 ? read_all(p[0], &n) : NULL;
    close(p[0]);
    int st = 0;
    while (pid > 0 && waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    int rc = pid > 0 && buf ? decode(st) : -1;
    if (out) {
        *out = buf;
        *out_len = n;
    } else {
        free(buf);
    }
    return rc;
}

/* `git <a> <b> <c> -- <path>` with output dropped; returns its exit status. */
static int git(const char *a, const char *b, const char *c, const char *path)
{
    char *argv[] = {"git", (char *)a, (char *)b, (char *)c, "--", (char *)path, NULL};
    if (!c) {
        argv[3] = "--";
        argv[4] = (char *)path;
        argv[5] = NULL;
    }
    return run_capture(argv, NULL, NULL);
}

/* First line of a git command's stdout, or false. */
static bool git_line(char *dst, size_t cap, const char *a, const char *b, const char *c)
{
    char *argv[] = {"git", (char *)a, (char *)b, (char *)c, NULL};
    char *out = NULL;
    size_t n = 0;
    bool ok = run_capture(argv, &out, &n) == 0 && out && n > 0 && n < cap;
    if (ok) {
        out[strcspn(out, "\r\n")] = 0;
        memcpy(dst, out, strlen(out) + 1);
    }
    free(out);
    return ok && dst[0];
}

/* ---- path and preconditions ---------------------------------------------------------------- */
static int refuse(const char *rel, const char *why)
{
    fprintf(stderr, "zcl-dev mutate: refused: %s: %s\n", rel, why);
    return 2;
}

/* Resolves `file` (relative to ZCL_DEV_PREFIX when zcl-dev dispatched us) to a path relative to the
 * repository root, and moves into the root. */
static bool join_prefix(const char *file, char *joined, size_t cap)
{
    const char *prefix = getenv("ZCL_DEV_PREFIX");
    bool pre = prefix && prefix[0] && strcmp(prefix, ".") != 0 && file[0] != '/';
    int n = snprintf(joined, cap, "%s%s%s", pre ? prefix : "", pre ? "/" : "", file);
    return n > 0 && (size_t)n < cap;
}

static int resolve(const char *file, char *rel, size_t cap)
{
    char joined[PATH_MAX], full[PATH_MAX], top[PATH_MAX], realtop[PATH_MAX];
    struct stat st;
    if (!join_prefix(file, joined, sizeof joined)) return refuse(file, "path too long");
    if (lstat(joined, &st) != 0 || !S_ISREG(st.st_mode)) return refuse(file, "not a regular file");
    if (!realpath(joined, full)) return refuse(file, strerror(errno));
    if (!git_line(top, sizeof top, "rev-parse", "--show-toplevel", NULL) || !realpath(top, realtop))
        return refuse(file, "not inside a git repository");
    size_t tl = strlen(realtop);
    if (strncmp(full, realtop, tl) != 0 || full[tl] != '/' || strlen(full + tl + 1) >= cap)
        return refuse(file, "outside the repository");
    memcpy(rel, full + tl + 1, strlen(full + tl + 1) + 1);
    if (chdir(realtop) != 0) return refuse(file, "cannot enter the repository root");
    return 0;
}

static int preconditions(const char *rel)
{
    struct stat st;
    for (const char *const *v = vendored; *v; v++)
        if (strncmp(rel, *v, strlen(*v)) == 0) return refuse(rel, "vendored or third-party tree; mutate the code we own");
    if (git("ls-files", "--error-unmatch", NULL, rel) != 0) return refuse(rel, "not tracked by git");
    if (git("diff", "--quiet", NULL, rel) != 0) return refuse(rel, "has unstaged changes; commit or stash them first");
    if (git("diff", "--cached", "--quiet", rel) != 0) return refuse(rel, "has staged changes; commit them first");
    if (lstat(g.orig_path, &st) == 0) {
        fprintf(stderr, "zcl-dev mutate: refused: %s exists from an interrupted run; run `zcl-dev mutate restore %s`\n",
                g.orig_path, rel);
        return 2;
    }
    return 0;
}

/* The consensus-seal lint fails while a sealed file holds a mutant; say so, then go on. */
static void warn_if_sealed(const char *rel)
{
    size_t len = 0;
    char *seal = mut_read_file("zcutil/consensus.seal", &len);
    size_t n = strlen(rel);
    for (char *line = seal; line && *line;) {
        if (strncmp(line, rel, n) == 0 && line[n] == '\t') {
            fprintf(stderr, "zcl-dev mutate: warning: %s is in zcutil/consensus.seal; the consensus-seal lint fails while a mutant is applied\n", rel);
            break;
        }
        char *nl = strchr(line, '\n');
        line = nl ? nl + 1 : NULL;
    }
    free(seal);
}

/* ---- the campaign -------------------------------------------------------------------------- */
enum outcome { O_KILLED, O_TIMEOUT, O_SURVIVED, O_UNCOMPILABLE, O_STOPPED, O_BROKEN };
static const char *const outcome_names[] = {"KILLED", "KILLED(timeout)", "SURVIVED", "UNCOMPILABLE", "STOPPED", "BROKEN"};

struct campaign {
    const struct mut_opts *o;
    const char *rel;
    char head[64];
    char *build_argv[64];
    char *build_buf;
    int log_fd;
    struct mut_sites sites;
    size_t tried;
    enum outcome *res;
    size_t count[O_BROKEN + 1];
};

/* --build is split on single spaces: no quoting, no shell. */
static bool split_build(struct campaign *c)
{
    if (!c->o->build) return true;
    c->build_buf = strdup(c->o->build);
    if (!c->build_buf) return false;
    size_t n = 0;
    for (char *tok = strtok(c->build_buf, " "); tok; tok = strtok(NULL, " ")) {
        if (n + 1 >= sizeof c->build_argv / sizeof c->build_argv[0]) return false;
        c->build_argv[n++] = tok;
    }
    c->build_argv[n] = NULL;
    return n > 0;
}

static void log_header(const struct campaign *c, const char *what)
{
    dprintf(c->log_fd, "\n==== zcl-dev mutate: %s\n", what);
}

static enum outcome test_once(struct campaign *c)
{
    if (c->build_argv[0]) {
        int b = run_supervised(c->build_argv, c->o->timeout, c->log_fd);
        if (b == ST_STOPPED) return O_STOPPED;
        if (b == -1) return O_BROKEN;
        if (b != 0) return O_UNCOMPILABLE;
    }
    int t = run_supervised(c->o->test, c->o->timeout, c->log_fd);
    if (t == ST_STOPPED) return O_STOPPED;
    if (t == ST_TIMEOUT) return O_TIMEOUT;
    if (t == -1) return O_BROKEN;
    return t == 0 ? O_SURVIVED : O_KILLED;
}

static enum outcome try_site(struct campaign *c, const struct mut_site *s)
{
    size_t n = 0;
    char *img = mut_apply(g.bytes, g.len, s, &n);
    if (!img) return O_BROKEN;
    g.dirty = true;
    bool wrote = overwrite(g.path, img, n);
    free(img);
    char what[200];
    snprintf(what, sizeof what, "mutant %zu:%zu %s '%s' -> '%s'", s->line, s->column, mut_class_name(s->cls), s->orig, s->repl);
    log_header(c, what);
    enum outcome r = wrote ? test_once(c) : O_BROKEN;
    if (!restore_verified()) return O_BROKEN;
    return r;
}

/* The unmutated file must build and pass, or no mutant result means anything. */
static int baseline(struct campaign *c)
{
    log_header(c, "baseline (unmutated)");
    enum outcome r = test_once(c);
    if (r == O_SURVIVED) return 0;
    if (r == O_STOPPED) return 130;
    fprintf(stderr, "zcl-dev mutate: the unmutated file does not %s (%s); see the log in zcutil/gen/mutate/\n",
            r == O_UNCOMPILABLE ? "build" : "pass its test", outcome_names[r]);
    return 2;
}

static int loop(struct campaign *c)
{
    for (size_t k = 0; k < c->tried; k++) {
        if (g_stop) return 130;
        enum outcome r = try_site(c, &c->sites.v[k]);
        if (r == O_BROKEN) return 2;
        if (r == O_STOPPED) return 130;
        c->res[k] = r;
        c->count[r]++;
        if (!c->o->json) fprintf(stderr, "  [%zu/%zu] %s\n", k + 1, c->tried, outcome_names[r]);
    }
    return g_stop ? 130 : 0;
}

/* zcutil/gen/mutate/<path with '/' as '_'>-<HEAD7>.<ext>; false when it does not fit. */
static bool receipt_path(const struct campaign *c, char *dst, size_t cap, const char *ext)
{
    int n = snprintf(dst, cap, "zcutil/gen/mutate/%s-%s.%s", c->rel, c->head, ext);
    if (n < 0 || (size_t)n >= cap) return false;
    for (char *p = dst + strlen("zcutil/gen/mutate/"); *p; p++)
        if (*p == '/') *p = '_';
    return true;
}

static void score_text(const struct campaign *c, char *dst, size_t cap)
{
    size_t k = c->count[O_KILLED] + c->count[O_TIMEOUT], v = c->count[O_SURVIVED];
    if (k + v == 0) snprintf(dst, cap, "n/a");
    else snprintf(dst, cap, "%zu/%zu", k, k + v);
}

static void summary(const struct campaign *c, FILE *f)
{
    char score[64];
    score_text(c, score, sizeof score);
    fprintf(f, "sites %zu tried %zu killed %zu survived %zu uncompilable %zu timeouts %zu score=%s\n", c->sites.n,
            c->tried, c->count[O_KILLED] + c->count[O_TIMEOUT], c->count[O_SURVIVED], c->count[O_UNCOMPILABLE],
            c->count[O_TIMEOUT], score);
}

static bool write_receipt(const struct campaign *c, char *path, size_t cap)
{
    if (!receipt_path(c, path, cap, "tsv")) return false;
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fprintf(f, "# zcl-dev mutate %s at %s\nline\tcol\tclass\torig\trepl\toutcome\n", c->rel, c->head);
    for (size_t k = 0; k < c->tried; k++) {
        const struct mut_site *s = &c->sites.v[k];
        fprintf(f, "%zu\t%zu\t%s\t%s\t%s\t%s\n", s->line, s->column, mut_class_name(s->cls), s->orig, s->repl,
                outcome_names[c->res[k]]);
    }
    fputs("# ", f);
    summary(c, f);
    return fclose(f) == 0;
}

static void report_json(const struct campaign *c, const char *receipt)
{
    char score[64];
    score_text(c, score, sizeof score);
    fputs("{\"file\":", stdout);
    mut_json_str(stdout, c->rel);
    printf(",\"head\":\"%s\",\"sites\":%zu,\"tried\":%zu,\"killed\":%zu,\"survived\":%zu,\"uncompilable\":%zu,"
           "\"timeouts\":%zu,\"score\":\"%s\",\"receipt\":", c->head, c->sites.n, c->tried,
           c->count[O_KILLED] + c->count[O_TIMEOUT], c->count[O_SURVIVED], c->count[O_UNCOMPILABLE],
           c->count[O_TIMEOUT], score);
    mut_json_str(stdout, receipt);
    fputs(",\"survivors\":[", stdout);
    bool first = true;
    for (size_t k = 0; k < c->tried; k++) {
        if (c->res[k] != O_SURVIVED) continue;
        if (!first) fputc(',', stdout);
        mut_json_site(stdout, &c->sites.v[k]);
        first = false;
    }
    puts("]}");
}

static void report(const struct campaign *c, const char *receipt)
{
    if (c->o->json) { report_json(c, receipt); return; }
    for (size_t k = 0; k < c->tried; k++)
        if (c->res[k] == O_SURVIVED) mut_print_site(stdout, &c->sites.v[k]);
    summary(c, stdout);
    printf("receipt %s\n", receipt);
}

/* Normal end: delete the .orig and prove git sees the file unchanged. */
static int finish(struct campaign *c)
{
    if (c->build_argv[0]) {
        log_header(c, "rebuild of the restored original");
        if (run_supervised(c->build_argv, c->o->timeout, c->log_fd) != 0)
            fprintf(stderr, "zcl-dev mutate: warning: rebuilding the restored original failed; rebuild by hand\n");
    }
    if (unlink(g.orig_path) != 0) { fprintf(stderr, "zcl-dev mutate: cannot delete %s\n", g.orig_path); return 2; }
    if (git("diff", "--quiet", NULL, c->rel) != 0) {
        fprintf(stderr, "zcl-dev mutate: BROKEN: git diff reports %s changed after the run; inspect it now\n", c->rel);
        return 2;
    }
    char receipt[PATH_MAX + 64];
    if (!write_receipt(c, receipt, sizeof receipt)) fprintf(stderr, "zcl-dev mutate: warning: cannot write %s\n", receipt);
    report(c, receipt);
    return c->count[O_SURVIVED] ? 1 : 0;
}

static int open_log(struct campaign *c)
{
    char path[PATH_MAX + 64];
    (void)mkdir("zcutil", 0755);
    (void)mkdir("zcutil/gen", 0755);
    (void)mkdir("zcutil/gen/mutate", 0755);
    if (!receipt_path(c, path, sizeof path, "log")) return refuse(c->rel, "path too long for a receipt name");
    c->log_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (c->log_fd < 0) { fprintf(stderr, "zcl-dev mutate: cannot write %s\n", path); return 2; }
    if (!c->o->json) fprintf(stderr, "zcl-dev mutate: build and test output goes to %s\n", path);
    return 0;
}

static int prepare(struct campaign *c)
{
    if (!git_line(c->head, sizeof c->head, "rev-parse", "--short=7", "HEAD")) return refuse(c->rel, "no HEAD commit");
    if (!split_build(c)) return refuse(c->rel, "--build is empty or has more than 63 words");
    size_t len = 0;
    char *bytes = mut_read_file(c->rel, &len);
    if (!bytes) return refuse(c->rel, "cannot read");
    g.bytes = bytes;
    g.len = len;
    if (!mut_enumerate(bytes, len, &c->sites)) return refuse(c->rel, "out of memory");
    mut_filter(&c->sites, c->o);
    c->tried = c->sites.n < c->o->max ? c->sites.n : c->o->max;
    c->res = calloc(c->tried + 1, sizeof *c->res);
    if (!c->res) return refuse(c->rel, "out of memory");
    warn_if_sealed(c->rel);
    return open_log(c);
}

int mut_run(const struct mut_opts *o)
{
    static struct campaign c;
    char rel[PATH_MAX];
    install_signals();
    int rc = resolve(o->file, rel, sizeof rel);
    if (rc) return rc;
    snprintf(g.path, sizeof g.path, "%s", rel);
    snprintf(g.orig_path, sizeof g.orig_path, "%s%s", rel, ORIG_SUFFIX);
    c.o = o;
    c.rel = g.path;
    if ((rc = preconditions(rel)) || (rc = prepare(&c)) || (rc = baseline(&c))) return rc;
    if (!write_orig()) return refuse(rel, "cannot create the .orig backup (O_EXCL)");
    atexit(at_exit_restore);
    rc = loop(&c);
    if (rc == 0) return finish(&c);
    if (g.dirty && !restore_verified()) return 2;
    if (rc == 130) {
        (void)unlink(g.orig_path);
        fprintf(stderr, "zcl-dev mutate: interrupted; %s restored\n", rel);
    }
    return rc;
}

int mut_restore(const char *file)
{
    char rel[PATH_MAX], orig_path[PATH_MAX + sizeof ORIG_SUFFIX];
    int rc = resolve(file, rel, sizeof rel);
    if (rc) return rc;
    snprintf(orig_path, sizeof orig_path, "%s%s", rel, ORIG_SUFFIX);
    size_t olen = 0, hlen = 0;
    char *orig = mut_read_file(orig_path, &olen);
    if (!orig) return refuse(rel, "no .zcl-mutate.orig to restore from");
    char spec[PATH_MAX + 8];
    snprintf(spec, sizeof spec, "HEAD:%s", rel);
    char *argv[] = {"git", "show", spec, NULL}, *head = NULL;
    bool same = run_capture(argv, &head, &hlen) == 0 && head && hlen == olen && memcmp(head, orig, olen) == 0;
    free(head);
    if (!same) { free(orig); return refuse(rel, "the .orig does not match HEAD; compare it by hand"); }
    bool ok = overwrite(rel, orig, olen) && holds(rel, orig, olen);
    free(orig);
    if (!ok) return refuse(rel, "cannot write the original bytes back");
    if (unlink(orig_path) != 0) return refuse(rel, "restored, but cannot delete the .orig");
    printf("restored %s from %s and verified it against HEAD\n", rel, orig_path);
    return 0;
}

#endif
