/* zcl-dev-hook and zcl-dev-hooks: git hooks for the zclassicd tree. MIT, like the rest of zclassicd.
 * Plain C, libc only; compiles as gnu17 and C2x, with the host cc, mingw-w64 and macOS clang.
 * Behaviour ported from Z23 (primary-checkout guard in tools/githooks/pre-commit, pre-push main
 * guard in tools/dev/z23_git_hook.c, hooks_status.c, tools/scripts/install_git_hooks.sh);
 * the code is new.
 *
 *   zcl-dev-hook pre-commit                  run by zcutil/githooks/pre-commit
 *   zcl-dev-hook pre-push <remote> <url>     run by zcutil/githooks/pre-push (ref lines on stdin)
 *   zcl-dev hooks install [--force] [--json] core.hooksPath = zcutil/githooks
 *   zcl-dev hooks status [--json]            read-only report; exit 1 unless fully installed
 *
 * One binary, installed under two names: zcl-dev-hooks (zcl-dev hooks ...) and zcl-dev-hook (the shims).
 *
 * pre-commit refuses (1) a commit in the primary checkout (git dir == common dir) on a named
 * non-master branch while other worktrees exist (override ZCL_LANE_COMMIT_OK=1), (2) any staged
 * *.py, (3) a staged file under zcutil/tools/vendor/ whose row in zcutil/tools/Z23_SOURCE.tsv
 * does not change in the same commit. A detached HEAD is not a named branch and is allowed.
 *
 * pre-push refuses a push to refs/heads/master or refs/heads/release/<name> (and its deletion) unless
 * the update is a fast-forward and a local-ci receipt for the exact pushed commit shows every
 * required step passed. Required steps are `zcl-dev select --steps` over the pushed diff; ALL
 * means every `step` of zcutil/local-ci.sh at that commit except tor-* (opt-in); in that
 * expansion a step whose only receipts are SKIP also counts (it declined itself, rc 77).
 * Receipts are $ZCL_CI_OUT/receipts.jsonl, else $HOME/work/zc23-localci-out/<9-char sha>/.
 * Override ZCL_PUSH_OK=<reason>: printed and appended to <common git dir>/zcl-push-overrides.log.
 * Exit codes: 0 allowed, 1 refused, 2 broken (cannot run git, bad arguments).
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L /* popen, readlink under a strict -std=c2x */
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <process.h>
#include <windows.h>
#define popen _popen
#define pclose _pclose
#define getpid _getpid
#define EXE_SUFFIX ".exe"
#else
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define EXE_SUFFIX ""
#endif

#define HOOKS_PATH "zcutil/githooks"
#define TSV_PATH "zcutil/tools/Z23_SOURCE.tsv"
#define VENDOR_PREFIX "zcutil/tools/vendor/"
#define EMPTY_TREE "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

typedef struct { char *p; size_t n; } Buf;

static void die(const char *fmt, ...)
{
    va_list ap;
    fputs("zcl-dev-hook: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

static void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n);
    if (!p) die("out of memory");
    return p;
}

static char *xstrdup(const char *s) { return strcpy(xrealloc(NULL, strlen(s) + 1), s); }

static int exit_code(int status)
{
#ifdef _WIN32
    return status;
#else
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
#endif
}

/* Run a shell command, collect stdout (NUL-terminated) in *out, return its exit code or -1. */
static int run(const char *cmd, Buf *out)
{
    Buf b = {xrealloc(NULL, 1), 0};
    b.p[0] = 0;
#ifdef _WIN32
    size_t cl = strlen(cmd) + 3;
    char *wrapped = xrealloc(NULL, cl); /* cmd.exe strips one pair of outer quotes */
    snprintf(wrapped, cl, "\"%s\"", cmd);
    FILE *f = popen(wrapped, "r");
    free(wrapped);
#else
    FILE *f = popen(cmd, "r");
#endif
    if (!f) {
        if (out) *out = b; else free(b.p);
        return -1;
    }
    char tmp[4096];
    size_t got;
    while ((got = fread(tmp, 1, sizeof tmp, f)) > 0) {
        b.p = xrealloc(b.p, b.n + got + 1);
        memcpy(b.p + b.n, tmp, got);
        b.n += got;
        b.p[b.n] = 0;
    }
    int rc = exit_code(pclose(f));
    if (out) *out = b; else free(b.p);
    return rc;
}

static void trim_eol(Buf *b)
{
    while (b->n && (b->p[b->n - 1] == '\n' || b->p[b->n - 1] == '\r')) b->p[--b->n] = 0;
}

/* Output of a git command without the final newline; NULL when it exits non-zero. Caller frees. */
static char *git_line(const char *cmd, int *rc)
{
    Buf b;
    int r = run(cmd, &b);
    if (rc) *rc = r;
    trim_eol(&b);
    if (r != 0) { free(b.p); return NULL; }
    return b.p;
}

static int has_prefix(const char *s, const char *p) { return !strncmp(s, p, strlen(p)); }
static int has_suffix_ci(const char *s, const char *x)
{
    size_t a = strlen(s), b = strlen(x);
    if (a < b) return 0;
    for (size_t i = 0; i < b; i++)
        if (tolower((unsigned char)s[a - b + i]) != tolower((unsigned char)x[i])) return 0;
    return 1;
}

/* Safe to put inside double quotes in a shell command. */
static int quotable(const char *s) { return !strpbrk(s, "\"\r\n$`%!"); }

static int is_hex(const char *s, size_t len)
{
    if (strlen(s) != len) return 0;
    for (; *s; s++) if (!isxdigit((unsigned char)*s)) return 0;
    return 1;
}
static int is_sha(const char *s) { return is_hex(s, 40) || is_hex(s, 64); }
static int is_zero(const char *s)
{
    for (; *s; s++) if (*s != '0') return 0;
    return 1;
}

static char *norm_path(char *s)
{
    size_t n = strlen(s);
    for (char *r = s; *r; r++) if (*r == '\\') *r = '/';
    while (n > 1 && s[n - 1] == '/') s[--n] = 0;
    return s;
}

/* ---- repository facts ------------------------------------------------------ */

typedef struct { char *gitdir, *common, *top; } Repo;

static Repo repo_open(void)
{
    Repo r = {0};
    Buf b;
    if (run("git rev-parse --path-format=absolute --absolute-git-dir --git-common-dir", &b) != 0)
        die("git rev-parse failed (git older than 2.31, or not inside a repository)");
    trim_eol(&b);
    char *nl = strchr(b.p, '\n');
    if (!nl) die("unexpected git rev-parse output");
    *nl = 0;
    r.gitdir = norm_path(b.p);
    r.common = norm_path(nl + 1);
    r.top = git_line("git rev-parse --show-toplevel", NULL);
    if (!r.top) die("not inside a work tree");
    norm_path(r.top);
    return r;
}

static int is_primary(const Repo *r) { return !strcmp(r->gitdir, r->common); }

/* ---- pre-commit ------------------------------------------------------------ */

static int worktree_count(void)
{
    Buf b;
    if (run("git worktree list --porcelain", &b) != 0) die("git worktree list failed");
    int n = 0;
    for (char *l = b.p; l && *l;) {
        if (has_prefix(l, "worktree ")) n++;
        l = strchr(l, '\n');
        if (l) l++;
    }
    free(b.p);
    return n;
}

/* Names from a `git diff -z --name-only` run, pointing into b. */
static size_t split_nul(const Buf *b, char ***names)
{
    size_t n = 0, cap = 16;
    *names = xrealloc(NULL, cap * sizeof **names);
    for (size_t i = 0; i < b->n;) {
        if (n == cap) *names = xrealloc(*names, (cap *= 2) * sizeof **names);
        (*names)[n++] = b->p + i;
        i += strlen(b->p + i) + 1;
    }
    return n;
}

/* True when the staged diff of Z23_SOURCE.tsv adds or removes a row for `path`. */
static int row_changed(const char *tsv_diff, const char *path)
{
    size_t pl = strlen(path);
    for (const char *l = tsv_diff; l && *l;) {
        if ((*l == '+' || *l == '-') && !strncmp(l + 1, path, pl) && l[1 + pl] == '\t') return 1;
        l = strchr(l, '\n');
        if (l) l++;
    }
    return 0;
}

static int pre_commit(void)
{
    Repo r = repo_open();
    int bad = 0;
    if (is_primary(&r)) {
        char *br = git_line("git symbolic-ref --short -q HEAD", NULL); /* fails when detached */
        const char *ok = getenv("ZCL_LANE_COMMIT_OK");
        if (br && strcmp(br, "master") && !(ok && !strcmp(ok, "1")) && worktree_count() > 1) {
            fprintf(stderr,
                    "zcl-dev-hook: refusing to commit on branch '%s' in the primary checkout.\n"
                    "  The primary checkout stays on master while other worktrees exist; work on a\n"
                    "  branch belongs in its own worktree: git worktree add ../<name> -b %s\n"
                    "  Intentional (a lane or merge fix): ZCL_LANE_COMMIT_OK=1 git commit ...\n",
                    br, br);
            bad++;
        }
        free(br);
    }
    Buf all, add;
    if (run("git diff --cached --no-renames --name-only -z", &all) != 0) die("git diff --cached failed");
    if (run("git diff --cached --no-renames --diff-filter=ACMT --name-only -z", &add) != 0) die("git diff --cached failed");
    char **names;
    size_t n = split_nul(&add, &names);
    for (size_t i = 0; i < n; i++)
        if (has_suffix_ci(names[i], ".py")) {
            fprintf(stderr, "zcl-dev-hook: refusing to stage %s: Python is not allowed in this tree.\n"
                            "  Write the tool in C or POSIX sh (zcutil/check-no-python.sh).\n", names[i]);
            bad++;
        }
    free(names);
    char **vn;
    size_t vc = split_nul(&all, &vn);
    Buf tsv = {NULL, 0};
    for (size_t i = 0; i < vc; i++) {
        if (!has_prefix(vn[i], VENDOR_PREFIX)) continue;
        if (!tsv.p && run("git diff --cached --no-renames -U0 -- " TSV_PATH, &tsv) != 0) die("git diff of " TSV_PATH " failed");
        if (!row_changed(tsv.p, vn[i])) {
            fprintf(stderr, "zcl-dev-hook: refusing to stage %s: it is vendored Z23 source and its row in\n"
                            "  " TSV_PATH " does not change in this commit. Re-vendor with\n"
                            "  zcutil/tools/revendor.sh (which updates the row), or stage the row with the file.\n", vn[i]);
            bad++;
        }
    }
    free(vn);
    free(tsv.p);
    free(all.p);
    free(add.p);
    free(r.gitdir);
    free(r.top);
    return bad ? 1 : 0;
}

/* ---- pre-push -------------------------------------------------------------- */

typedef struct { char *step, *stage, *verdict; } Rcpt;

/* Value of "key":"..." in a one-line JSON object (receipt fields never contain quotes). */
static char *jfield(const char *line, const char *key)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(line, pat);
    if (!p) return NULL;
    p += strlen(pat);
    const char *e = strchr(p, '"');
    if (!e) return NULL;
    char *v = xrealloc(NULL, (size_t)(e - p) + 1);
    memcpy(v, p, (size_t)(e - p));
    v[e - p] = 0;
    return v;
}

static char *receipts_path(const char *sha)
{
    const char *out = getenv("ZCL_CI_OUT");
    char path[2048];
    if (out && *out) snprintf(path, sizeof path, "%s/receipts.jsonl", out);
    else {
        const char *home = getenv("HOME");
        if (!home || !*home) home = getenv("USERPROFILE");
        snprintf(path, sizeof path, "%s/work/zc23-localci-out/%.9s/receipts.jsonl", home ? home : ".", sha);
    }
    return xstrdup(path);
}

static void add_receipt(Rcpt **v, size_t *n, size_t *cap, const char *line)
{
    char *st = jfield(line, "step"), *sg = jfield(line, "stage"), *vd = jfield(line, "verdict");
    if (!st || !vd) { free(st); free(sg); free(vd); return; }
    if (*n == *cap) *v = xrealloc(*v, (*cap *= 2) * sizeof **v);
    (*v)[(*n)++] = (Rcpt){st, sg ? sg : xstrdup(""), vd};
}

/* Receipts of exactly `sha`, in file order. */
static size_t load_receipts(const char *path, const char *sha, Rcpt **out)
{
    FILE *f = fopen(path, "rb");
    size_t n = 0, cap = 32;
    *out = xrealloc(NULL, cap * sizeof **out);
    if (!f) return 0;
    size_t lc = 4096, ln = 0;
    char *line = xrealloc(NULL, lc);
    int c;
    do {
        c = fgetc(f);
        if (c == '\n' || c == EOF) {
            line[ln] = 0;
            char *cm = jfield(line, "commit");
            if (cm && !strcmp(cm, sha)) add_receipt(out, &n, &cap, line);
            free(cm);
            ln = 0;
        } else {
            if (ln + 2 > lc) line = xrealloc(line, lc *= 2);
            line[ln++] = (char)c;
        }
    } while (c != EOF);
    free(line);
    fclose(f);
    return n;
}

/* "" when step `s` is satisfied, else a reason. */
static const char *step_state(const Rcpt *rc, size_t n, const char *s, int skip_ok)
{
    int pass = 0, skip = 0, any = 0, failed = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(rc[i].step, s)) continue;
        any = 1;
        if (!strcmp(rc[i].verdict, "PASS")) pass = 1;
        if (!strcmp(rc[i].verdict, "SKIP")) skip = 1;
        /* the latest receipt of each (stage, step) decides a failure */
        int later = 0;
        for (size_t j = i + 1; j < n; j++) if (!strcmp(rc[j].step, s) && !strcmp(rc[j].stage, rc[i].stage)) later = 1;
        if (!later && !strcmp(rc[i].verdict, "FAIL")) failed = 1;
    }
    if (failed) return "failed";
    if (pass) return "";
    if (skip && skip_ok) return "";
    return any ? "not passed" : "no receipt";
}

/* Step names declared in zcutil/local-ci.sh at `sha`, minus dry-* and tor-*. */
static size_t declared_steps(const char *sha, char ***out)
{
    char cmd[256];
    snprintf(cmd, sizeof cmd, "git show %s:zcutil/local-ci.sh", sha);
    Buf b;
    if (run(cmd, &b) != 0) die("cannot read zcutil/local-ci.sh at %s", sha);
    size_t n = 0, cap = 32;
    *out = xrealloc(NULL, cap * sizeof **out);
    for (char *l = b.p; l && *l;) {
        char *e = strchr(l, '\n');
        char name[128];
        int secs;
        while (*l == ' ' || *l == '\t') l++;
        if (!strncmp(l, "step ", 5) && sscanf(l + 5, "%127s %d", name, &secs) == 2 && strncmp(name, "dry-", 4) &&
            strncmp(name, "tor-", 4) && name[0] != '$') {
            if (n == cap) *out = xrealloc(*out, (cap *= 2) * sizeof **out);
            (*out)[n++] = xstrdup(name);
        }
        l = e ? e + 1 : NULL;
    }
    free(b.p);
    return n;
}

static void self_dir(char *out, size_t cap)
{
    out[0] = 0;
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    if (n == 0 || n >= cap) { out[0] = 0; return; }
#else
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0) { out[0] = 0; return; }
    out[n] = 0;
#endif
    for (char *r = out; *r; r++) if (*r == '\\') *r = '/';
    char *s = strrchr(out, '/');
    if (s) *s = 0; else out[0] = 0;
}

/* Required steps for base..sha through `zcl-dev select`: returns count, *all set for ALL. */
static int required_steps(const Repo *r, const char *base, const char *sha, char ***steps, size_t *ns, int *all, char *msg, size_t cap)
{
    char cmd[4096], dir[1024], list[1200];
    snprintf(list, sizeof list, "%s/zcl-hook-files.%ld", r->common, (long)getpid());
    snprintf(cmd, sizeof cmd, "git -c core.quotepath=off diff --no-renames --name-only %s %s > \"%s\"", base, sha, list);
    if (!quotable(list) || run(cmd, NULL) != 0) { snprintf(msg, cap, "cannot list the files changed by the push"); return 1; }
    self_dir(dir, sizeof dir);
    if (!dir[0] || !quotable(dir) || !quotable(r->top)) { snprintf(msg, cap, "cannot locate zcl-dev"); remove(list); return 1; }
    snprintf(cmd, sizeof cmd, "\"%s/zcl-dev%s\" -C \"%s\" select --steps --stdin < \"%s\"", dir, EXE_SUFFIX, r->top, list);
    Buf sel;
    int rc = run(cmd, &sel);
    remove(list);
    trim_eol(&sel);
    if (rc != 0 || !sel.p[0]) {
        snprintf(msg, cap, "zcl-dev select failed (build zcutil/bin/zcl-dev: make -C zcutil)");
        free(sel.p);
        return 1;
    }
    *ns = 0;
    *steps = NULL;
    *all = !strcmp(sel.p, "ALL");
    if (*all) {
        *ns = declared_steps(sha, steps);
        if (*ns == 0) snprintf(msg, cap, "zcutil/local-ci.sh declares no steps; cannot compute the required set");
    } else if (strcmp(sel.p, "NONE")) {
        *steps = xrealloc(NULL, 64 * sizeof **steps);
        for (char *t = strtok(sel.p, ","); t && *ns < 64; t = strtok(NULL, ",")) (*steps)[(*ns)++] = xstrdup(t);
    }
    free(sel.p);
    return *all && *ns == 0;
}

/* Fills msg with why the receipts do not cover base..sha; returns 0 when they do. */
static int check_receipts(const Repo *r, const char *base, const char *sha, char *msg, size_t cap)
{
    char **steps;
    size_t ns;
    int all;
    msg[0] = 0;
    if (required_steps(r, base, sha, &steps, &ns, &all, msg, cap)) return 1;
    char *path = receipts_path(sha);
    Rcpt *rcs;
    size_t nr = load_receipts(path, sha, &rcs);
    size_t used = 0;
    int bad = 0;
    if (nr == 0 && ns > 0) {
        snprintf(msg, cap, "no local-ci receipt for %s in %s", sha, path);
        bad = 1;
    } else {
        for (size_t i = 0; i < ns; i++) {
            const char *st = step_state(rcs, nr, steps[i], all);
            if (!*st || used + 128 >= cap) continue;
            used += (size_t)snprintf(msg + used, cap - used, "%s%s: %s", used ? "; " : "required steps not passing: ", steps[i], st);
            bad = 1;
        }
    }
    for (size_t i = 0; i < nr; i++) { free(rcs[i].step); free(rcs[i].stage); free(rcs[i].verdict); }
    free(rcs);
    free(path);
    for (size_t i = 0; i < ns; i++) free(steps[i]);
    free(steps);
    return bad;
}

static void record_override(const Repo *r, const char *ref, const char *old, const char *new_, const char *reason)
{
    char clean[256], path[1200], ts[32];
    size_t k = 0;
    for (const char *p = reason; *p && k + 1 < sizeof clean; p++) clean[k++] = ((unsigned char)*p < 0x20) ? ' ' : *p;
    clean[k] = 0;
    time_t t = time(NULL);
    struct tm *g = gmtime(&t);
    if (!g || !strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", g)) snprintf(ts, sizeof ts, "unknown");
    snprintf(path, sizeof path, "%s/zcl-push-overrides.log", r->common);
    FILE *f = fopen(path, "ab");
    if (!f || fprintf(f, "%s ref=%s old=%s new=%s reason=%s\n", ts, ref, old, new_, clean) < 0 || fclose(f) != 0)
        die("cannot record the override in %s; push refused", path);
    fprintf(stderr, "zcl-dev-hook: ZCL_PUSH_OK override for %s (%s); recorded in %s\n", ref, clean, path);
}

static int protected_ref(const char *ref)
{
    return !strcmp(ref, "refs/heads/master") || has_prefix(ref, "refs/heads/release/");
}

/* Why one update of a protected ref is not allowed; "" when it is. */
static void judge(const Repo *r, const char *rref, const char *lsha, const char *rsha, char *why, size_t cap)
{
    why[0] = 0;
    if (is_zero(lsha)) { snprintf(why, cap, "deleting %s is not allowed", rref); return; }
    int zero_remote = is_zero(rsha), verifiable = 1;
    size_t w = 0;
    if (!zero_remote) {
        char cmd[512];
        snprintf(cmd, sizeof cmd, "git merge-base --is-ancestor %s %s", rsha, lsha);
        int rc = run(cmd, NULL);
        if (rc == 1)
            w = (size_t)snprintf(why, cap, "not a fast-forward of the remote %s (%.12s is not an ancestor of %.12s)", rref, rsha, lsha);
        else if (rc != 0) {
            w = (size_t)snprintf(why, cap, "cannot verify fast-forward: remote commit %.12s is unknown locally (fetch first)", rsha);
            verifiable = 0;
        }
    }
    if (!verifiable) return;
    char msg[2048];
    if (check_receipts(r, zero_remote ? EMPTY_TREE : rsha, lsha, msg, sizeof msg))
        snprintf(why + w, cap - w, "%s%s", w ? "; " : "", msg);
}

static int pre_push(void)
{
    Repo r = repo_open();
    char lref[512], lsha[80], rref[512], rsha[80], line[2048];
    int refused = 0;
    while (fgets(line, sizeof line, stdin)) {
        if (sscanf(line, "%511s %79s %511s %79s", lref, lsha, rref, rsha) != 4) continue;
        if (!protected_ref(rref)) continue;
        if (!is_sha(lsha) || !is_sha(rsha)) die("malformed ref update line from git");
        char why[4096];
        judge(&r, rref, lsha, rsha, why, sizeof why);
        if (!why[0]) continue;
        const char *ov = getenv("ZCL_PUSH_OK");
        if (ov && *ov) { record_override(&r, rref, rsha, lsha, ov); continue; }
        fprintf(stderr, "zcl-dev-hook: refusing to push %.12s to %s: %s.\n"
                        "  Land through a local-ci run on the exact commit (zcutil/local-ci.sh test-changed),\n"
                        "  then push. Deliberate exception: ZCL_PUSH_OK=<reason> git push ... (logged).\n",
                lsha, rref, why);
        refused = 1;
    }
    free(r.gitdir);
    free(r.top);
    return refused;
}


static int file_state(const Repo *r, const char *name)
{
    char p[1400];
    snprintf(p, sizeof p, "%s/" HOOKS_PATH "/%s", r->top, name);
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    fclose(f);
#ifndef _WIN32
    struct stat st;
    if (stat(p, &st) != 0 || !(st.st_mode & S_IXUSR)) return 1; /* present, not executable */
#endif
    return 2;
}

static const char *const state_name[] = {"missing", "not executable", "ok"};

static int binary_present(const Repo *r)
{
    char p[1400];
    snprintf(p, sizeof p, "%s/zcutil/bin/zcl-dev-hook" EXE_SUFFIX, r->top);
    FILE *f = fopen(p, "rb");
    if (f) fclose(f);
    return f != NULL;
}

static char *hooks_path(const Repo *r)
{
    char cmd[1400];
    if (!quotable(r->top)) die("unsupported characters in the work tree path");
    snprintf(cmd, sizeof cmd, "git -C \"%s\" config --get core.hooksPath", r->top);
    return git_line(cmd, NULL); /* exit 1 when unset */
}

static int cmd_status(int json)
{
    Repo r = repo_open();
    char *hp = hooks_path(&r);
    int installed = hp && !strcmp(hp, HOOKS_PATH);
    int pc = file_state(&r, "pre-commit"), pp = file_state(&r, "pre-push"), bin = binary_present(&r);
    int ok = installed && pc == 2 && pp == 2 && bin;
    if (json) {
        printf("{\"installed\":%s,\"hooks_path\":\"%s\",\"pre_commit\":\"%s\",\"pre_push\":\"%s\",\"binary\":%s,\"primary\":%s,\"ok\":%s}\n",
               installed ? "true" : "false", installed ? HOOKS_PATH : "", state_name[pc], state_name[pp], bin ? "true" : "false",
               is_primary(&r) ? "true" : "false", ok ? "true" : "false");
    } else {
        printf("hooks: %s\ncore.hooksPath: %s\npre-commit: %s\npre-push: %s\nzcl-dev-hook: %s\ncheckout: %s\n", ok ? "installed" : "NOT ready",
               hp ? hp : "(unset)", state_name[pc], state_name[pp], bin ? "built" : "not built (make -C zcutil)",
               is_primary(&r) ? "primary" : "linked worktree");
        if (!installed) puts("fix: zcl-dev hooks install");
    }
    free(hp);
    free(r.gitdir);
    free(r.top);
    return ok ? 0 : 1;
}

static int cmd_install(int force, int json)
{
    Repo r = repo_open();
    if (file_state(&r, "pre-commit") == 0 || file_state(&r, "pre-push") == 0) {
        fputs("zcl-dev hooks: " HOOKS_PATH "/pre-commit or pre-push is missing in this checkout\n", stderr);
        return 1;
    }
    char *hp = hooks_path(&r);
    if (hp && strcmp(hp, HOOKS_PATH) && !force) {
        fprintf(stderr, "zcl-dev hooks: core.hooksPath is already '%s'; rerun with --force to replace it\n", hp);
        free(hp);
        return 1;
    }
    free(hp);
    char cmd[1400];
    snprintf(cmd, sizeof cmd, "git -C \"%s\" config core.hooksPath " HOOKS_PATH, r.top);
    if (run(cmd, NULL) != 0) die("git config core.hooksPath failed");
    if (json) puts("{\"installed\":true,\"hooks_path\":\"" HOOKS_PATH "\"}");
    else puts("core.hooksPath = " HOOKS_PATH);
    if (!binary_present(&r)) fputs("note: zcutil/bin/zcl-dev-hook is not built here; run make -C zcutil\n", stderr);
    free(r.gitdir);
    free(r.top);
    return 0;
}

int main(int argc, char **argv)
{
    const char *cmd = argc >= 2 ? argv[1] : "";
    if (!strcmp(cmd, "--purpose")) { puts("install and inspect the git hooks (install | status)"); return 0; }
    if (!strcmp(cmd, "pre-commit")) return pre_commit();
    if (!strcmp(cmd, "pre-push")) return pre_push();
    int json = 0, force = 0;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--force")) force = 1;
        else die("hooks: unknown option %s", argv[i]);
    }
    if (!strcmp(cmd, "status")) return cmd_status(json);
    if (!strcmp(cmd, "install")) return cmd_install(force, json);
    fputs("usage: zcl-dev hooks install [--force] [--json] | status [--json]\n"
          "       zcl-dev-hook pre-commit | pre-push <remote> <url>   (run by zcutil/githooks)\n", stderr);
    return 2;
}
