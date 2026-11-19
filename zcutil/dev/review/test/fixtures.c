/* fixtures.c: fixture-repo tests for zcl-dev-review, driven by test/run.sh. MIT, like the rest of zclassicd.
 * Throwaway repositories under mkdtemp(), commits with Co-Authored-By trailers, golden outputs in test/golden/
 * with commit ids replaced by labels (@c1, @r1, ...) and dates by <date>. POSIX only (fork/exec, no shell);
 * it is a test driver and is never part of the shipped tools. It is C, not shell, because the zcl-lint kpi
 * floor for shell_lines is exactly met and may only fall.
 *
 *   zcl-review-fixtures <zcl-dev-review> <golden-dir>      UPDATE=1 rewrites the golden files.
 *   zcl-review-fixtures --hook <bindir> <githooks-dir>     real git pushes through zcl-dev-hook (review gate)
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define OPUS "Claude Opus 5.5 <noreply@anthropic.com>"
#define SONNET "Claude Sonnet 5.5 <noreply@anthropic.com>"
#define ROWS "doc/agent/REVIEWS.tsv"

typedef struct { char name[24], sha[65]; } Label;

static char work[512], repo[600], tool[600], golden_dir[600];
static Label labels[64];
static int nlabels, fails, counter;

static void die(const char *m)
{
    fprintf(stderr, "fixtures: %s\n", m);
    exit(2);
}

/* Run argv in cwd with stdout and stderr merged into *out; returns the exit code. */
static int run_in(const char *cwd, char *const argv[], char **out)
{
    int fd[2];
    if (pipe(fd) != 0) die("pipe");
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        close(fd[0]);
        dup2(fd[1], 1);
        dup2(fd[1], 2);
        if (cwd && chdir(cwd) != 0) _exit(126);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fd[1]);
    size_t n = 0, cap = 4096;
    char *b = malloc(cap);
    ssize_t got;
    while (b && (got = read(fd[0], b + n, cap - n - 1)) > 0) {
        n += (size_t)got;
        if (n + 1 >= cap) b = realloc(b, cap *= 2);
    }
    if (!b) die("out of memory");
    close(fd[0]);
    b[n] = 0;
    int st = 0;
    waitpid(pid, &st, 0);
    if (out) *out = b; else free(b);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

/* git -C repo <args...> (NULL-terminated); dies on failure. Returns the output. */
static char *git(const char *first, ...)
{
    char *av[40] = {"git", "-C", repo, (char *)first};
    int n = 4;
    va_list ap;
    va_start(ap, first);
    for (const char *a; (a = va_arg(ap, const char *)) && n < 39;) av[n++] = (char *)a;
    va_end(ap);
    av[n] = NULL;
    char *out;
    if (run_in(NULL, av, &out) != 0) {
        fprintf(stderr, "fixtures: git %s failed: %s\n", first, out);
        exit(2);
    }
    out[strcspn(out, "\n")] = 0;
    return out;
}

static const char *L(const char *name)
{
    for (int i = 0; i < nlabels; i++) if (!strcmp(labels[i].name, name)) return labels[i].sha;
    die("unknown label");
    return NULL;
}

static void lab(const char *name, const char *rev)
{
    char *sha = git("rev-parse", rev, NULL);
    snprintf(labels[nlabels].name, sizeof labels[nlabels].name, "%s", name);
    snprintf(labels[nlabels].sha, sizeof labels[nlabels].sha, "%s", sha);
    nlabels++;
    free(sha);
}

static void write_file(const char *rel, const char *text, const char *mode)
{
    char path[700];
    snprintf(path, sizeof path, "%s/%s", repo, rel);
    FILE *f = fopen(path, mode);
    if (!f || fputs(text, f) < 0 || fclose(f) != 0) die("cannot write a fixture file");
}

static void mk(const char *subject, const char *trailer)
{
    char name[32], trail[200];
    snprintf(name, sizeof name, "f%d", ++counter);
    write_file(name, "x\n", "w");
    free(git("add", name, NULL));
    if (trailer) {
        snprintf(trail, sizeof trail, "Co-Authored-By: %s", trailer);
        free(git("commit", "-q", "-m", subject, "-m", trail, NULL));
    } else {
        free(git("commit", "-q", "-m", subject, NULL));
    }
}

static void commit_rows(void) { free(git("commit", "-q", "-m", "review: record", "--", ROWS, NULL)); }

static void rows_row(const char *range, const char *tree, const char *authors, const char *reviewer, const char *verdict)
{
    char row[400];
    snprintf(row, sizeof row, "%s\t%s\t%s\t%s\t%s\t2026-01-01T00:00:00Z\thand written\n", range, tree, authors, reviewer, verdict);
    write_file(ROWS, row, "a");
    commit_rows();
}

static void branch(const char *name, const char *at) { free(git("checkout", "-q", "-b", name, at, NULL)); }

/* ---- normalization --------------------------------------------------------------------- */

static int date_at(const char *p)
{
    static const char shape[] = "dddd-dd-ddTdd:dd:ddZ";
    for (size_t i = 0; shape[i]; i++)
        if (shape[i] == 'd' ? !isdigit((unsigned char)p[i]) : p[i] != shape[i]) return 0;
    return 1;
}

static const char *label_for(const char *hex, size_t len)
{
    for (int i = 0; i < nlabels; i++)
        if (!strncmp(labels[i].sha, hex, len) && (len == strlen(labels[i].sha) || len == 7)) return labels[i].name;
    return NULL;
}

static size_t hex_run(const char *p)
{
    size_t len = 0;
    while (isxdigit((unsigned char)p[len]) && !isupper((unsigned char)p[len])) len++;
    return len;
}

/* What replaces the hex run of `len` digits at p; NULL keeps it. */
static const char *hex_replacement(const char *in, const char *p, size_t len, char *buf, size_t cap)
{
    const char *name = (len == 40 || len == 7) ? label_for(p, len) : NULL;
    if (name) {
        snprintf(buf, cap, "@%s", name);
        return buf;
    }
    if (len == 40) return "<id>";
    int line_start = len == 7 && p >= in + 2 && p[-1] == ' ' && p[-2] == ' ' && (p == in + 2 || p[-3] == '\n');
    return line_start ? "<sha7>" : NULL;
}

/* Replace labelled ids by @name, other 40-hex ids by <id>, unlabelled 7-hex ids opening a listed line by <sha7>,
 * dates by <date>. */
static char *normalize(const char *in)
{
    size_t n = 0;
    char *out = malloc(strlen(in) * 4 + 64), buf[40];
    if (!out) die("out of memory");
    for (const char *p = in; *p;) {
        const char *rep = NULL;
        size_t take = hex_run(p);
        if (date_at(p)) {
            rep = "<date>";
            take = 20;
        } else if (take) {
            rep = hex_replacement(in, p, take, buf, sizeof buf);
        } else {
            take = 1;
        }
        size_t put = rep ? strlen(rep) : take;
        memcpy(out + n, rep ? rep : p, put);
        n += put;
        p += take;
    }
    out[n] = 0;
    return out;
}

/* ---- comparing with the golden file --------------------------------------------------------- */

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t n = 0, cap = 4096;
    char *b = malloc(cap);
    size_t got;
    while ((got = fread(b + n, 1, cap - n - 1, f)) > 0) {
        n += got;
        if (n + 1 >= cap) b = realloc(b, cap *= 2);
    }
    fclose(f);
    b[n] = 0;
    return b;
}

static void compare(const char *name, const char *got)
{
    char path[800];
    snprintf(path, sizeof path, "%s/%s.out", golden_dir, name);
    if (getenv("UPDATE")) {
        FILE *f = fopen(path, "wb");
        if (!f || fputs(got, f) < 0 || fclose(f) != 0) die("cannot write a golden file");
        return;
    }
    char *want = slurp(path);
    if (want && !strcmp(want, got)) {
        printf("ok   %s\n", name);
    } else {
        printf("FAIL %s\n--- golden\n%s\n--- got\n%s\n", name, want ? want : "(missing)", got);
        fails++;
    }
    free(want);
}

static void golden(const char *name, int want, char *const argv[])
{
    char *out;
    int rc = run_in(repo, argv, &out);
    if (rc != want) {
        printf("FAIL %s (exit %d, wanted %d)\n%s\n", name, rc, want, out);
        fails++;
        free(out);
        return;
    }
    size_t flen = strlen(out) + 32;
    char *full = malloc(flen);
    snprintf(full, flen, "%sexit=%d\n", out, rc);
    char *norm = normalize(full);
    compare(name, norm);
    free(out);
    free(full);
    free(norm);
}

#define GOLDEN(name, want, ...) golden(name, want, (char *const[]){tool, __VA_ARGS__, NULL})

static char *range(const char *a, const char *b)
{
    static char r[4][200];
    static int k;
    k = (k + 1) % 4;
    snprintf(r[k], sizeof r[k], "%s..%s", L(a), L(b));
    return r[k];
}

/* The shape of one page of output: line count, size bound, first and last lines cut short. */
static void page(const char *name, char *const argv[])
{
    char *out;
    int rc = run_in(repo, argv, &out), lines = 0;
    for (char *p = out; *p; p++) lines += *p == '\n';
    char *shape = malloc(1000), *s = shape;
    int big = strlen(out) >= 16384;
    s += snprintf(s, 200, "exit=%d\nlines=%d\n%s\n", rc, lines, big ? "OVER 16 KiB" : "under 16 KiB");
    char *l[400];
    int n = 0;
    for (char *p = strtok(out, "\n"); p && n < 400; p = strtok(NULL, "\n")) l[n++] = p;
    for (int i = 0; i < n; i++)
        if (i < 2 || i >= n - 3) s += snprintf(s, 100, "%.60s\n", l[i]);
    char *norm = normalize(shape);
    compare(name, norm);
    free(out);
    free(shape);
    free(norm);
}

/* ---- scenarios --------------------------------------------------------------------------------- */

static void history(void)
{
    write_file(ROWS, "# test header\n", "w");
    free(git("add", "-A", NULL));
    free(git("commit", "-q", "-m", "base", NULL));
    lab("base", "HEAD");
    mk("feat: one", OPUS);
    lab("c1", "HEAD");
    mk("fix: two", SONNET);
    lab("c2", "HEAD");
    lab("tree2", "HEAD^{tree}");
}

static void record_and_cover(void)
{
    GOLDEN("usage", 2, "check");
    GOLDEN("uncovered", 1, "check", range("base", "c2"));
    GOLDEN("empty-range-check", 0, "check", range("base", "base"));
    GOLDEN("empty-range-record", 1, "record", "--reviewer", "x", "--verdict", "ACCEPT", range("base", "base"));
    GOLDEN("bad-verdict", 1, "record", "--reviewer", "x", "--verdict", "MAYBE", range("base", "c2"));
    GOLDEN("author-same-name", 1, "record", "--reviewer", "Claude Opus 5.5", "--verdict", "ACCEPT", range("base", "c2"));
    GOLDEN("author-normalized", 1, "record", "--reviewer", "claude-opus-5-5", "--verdict", "ACCEPT", range("base", "c2"));
    GOLDEN("bad-range-record", 2, "record", "--reviewer", "x", "--verdict", "ACCEPT", (char *)L("base"));
    GOLDEN("record-accept", 0, "record", "--reviewer", "Gpt Reviewer", "--verdict", "ACCEPT-WITH-FIXES", "--evidence", "log /tmp/review-1.log",
           range("base", "c2"));
    GOLDEN("worktree-not-read", 1, "check", range("base", "c2"));
    commit_rows();
    lab("r1", "HEAD");
    GOLDEN("covered", 0, "check", range("base", "r1"));
    GOLDEN("rows-from", 0, "check", "--rows-from", (char *)L("r1"), range("base", "c2"));
    GOLDEN("rows-from-tip", 1, "check", range("base", "c2"));
    GOLDEN("json-covered", 0, "check", "--json", range("base", "r1"));
    GOLDEN("json-uncovered", 1, "check", "--json", range("base", "c2"));
    GOLDEN("not-ancestor", 2, "check", range("c2", "c1"));
    GOLDEN("bad-revision", 2, "check", "nosuchrev..nosuchrev2");
    GOLDEN("no-rows-file", 2, "check", "--rows-from", "nosuchrev", range("base", "c2"));
}

static void stale_cases(void)
{
    branch("author-row", L("c2"));
    rows_row(range("base", "c2"), L("tree2"), "claude sonnet 5.5", "claude-sonnet-5-5", "ACCEPT");
    lab("tip_author", "HEAD");
    GOLDEN("author-row", 1, "check", range("base", "tip_author"));
    branch("bad-tree", L("c2"));
    rows_row(range("base", "c2"), "0000000000000000000000000000000000000000", "x", "someone else", "ACCEPT");
    lab("tip_tree", "HEAD");
    GOLDEN("stale-tree", 1, "check", range("base", "tip_tree"));
    /* commit --amend after the review: the new tip is not covered, the unchanged first commit still is */
    branch("amend", L("c2"));
    write_file("fa", "amended\n", "w");
    free(git("add", "fa", NULL));
    free(git("commit", "-q", "--amend", "-m", "fix: two", "-m", "Co-Authored-By: " SONNET, NULL));
    lab("c2a", "HEAD");
    free(git("cherry-pick", L("r1"), NULL));
    lab("r1a", "HEAD");
    GOLDEN("stale-amend", 1, "check", range("base", "r1a"));
}

static void reject_and_human(void)
{
    branch("reject", L("r1"));
    GOLDEN("reject-record", 0, "record", "--reviewer", "Strict Rev", "--verdict", "REJECT", "--evidence", "needs work", range("base", "r1"));
    commit_rows();
    lab("r2", "HEAD");
    GOLDEN("reject-override", 1, "check", range("base", "r2"));
    GOLDEN("reject-reaccept", 0, "record", "--reviewer", "Third Rev", "--verdict", "ACCEPT", range("base", "r2"));
    commit_rows();
    lab("r3", "HEAD");
    GOLDEN("reject-then-accept", 0, "check", range("base", "r3"));
    /* a commit without trailers is human work: record refuses its author as reviewer */
    branch("human", L("c2"));
    mk("chore: human edit", NULL);
    lab("c3", "HEAD");
    GOLDEN("human-uncovered", 1, "check", range("c2", "c3"));
    GOLDEN("human-author", 1, "record", "--reviewer", "pat-human", "--verdict", "ACCEPT", range("c2", "c3"));
    GOLDEN("human-record", 0, "record", "--json", "--reviewer", "Other Person", "--verdict", "ACCEPT", range("c2", "c3"));
    commit_rows();
    lab("r4", "HEAD");
    GOLDEN("human-covered", 0, "check", range("c2", "r4"));
}

static void malformed_rows(void)
{
    char row[400];
    branch("malformed", L("c2"));
    write_file(ROWS, "not a row\n", "a");
    commit_rows();
    lab("mal1", "HEAD");
    GOLDEN("malformed-fields", 2, "check", range("base", "mal1"));
    free(git("reset", "-q", "--hard", L("c2"), NULL));
    snprintf(row, sizeof row, "%s..%s\t%s\ta\tb\tMAYBE\t2026-01-01T00:00:00Z\t\n", L("base"), L("c2"), L("tree2"));
    write_file(ROWS, row, "a");
    commit_rows();
    lab("mal2", "HEAD");
    GOLDEN("malformed-verdict", 2, "check", range("base", "mal2"));
}

static void paging(void)
{
    char sub[400], big[320], *out, spec[200];
    branch("many", L("c2"));
    memset(big, 'x', 300);
    big[300] = 0;
    for (int i = 1; i <= 80; i++) {
        snprintf(sub, sizeof sub, "change %d %s", i, big);
        free(git("commit", "-q", "--allow-empty", "-m", sub, NULL));
    }
    lab("many_tip", "HEAD");
    snprintf(spec, sizeof spec, "%s", range("c2", "many_tip"));
    page("paging-first", (char *const[]){tool, "check", spec, NULL});
    run_in(repo, (char *const[]){tool, "check", spec, NULL}, &out);
    char *more = strstr(out, "rerun with --after=");
    char after[40] = "--after=0";
    if (more) snprintf(after, sizeof after, "--after=%ld", strtol(more + 19, NULL, 10));
    free(out);
    page("paging-second", (char *const[]){tool, "check", after, spec, NULL});
    page("paging-past-end", (char *const[]){tool, "check", "--after=1000", spec, NULL});
    page("paging-json", (char *const[]){tool, "check", "--json", spec, NULL});
}

/* A commit by a named human author, without a Co-Authored-By trailer. */
static void mk_by(const char *subject, const char *author)
{
    char name[32];
    snprintf(name, sizeof name, "f%d", ++counter);
    write_file(name, "x\n", "w");
    free(git("add", name, NULL));
    free(git("commit", "-q", "--author", author, "-m", subject, NULL));
}

/* A commit after a reviewed range is unreviewed ("no row"), not stale; records that cannot be written or
 * could not be told apart from an author are refused; a range of many authors makes a long row that parses. */
static void later_and_wide(void)
{
    char author[80], subject[40];
    branch("later", L("r1"));
    mk("feat: after the review", OPUS);
    lab("later_tip", "HEAD");
    GOLDEN("new-commit-no-row", 1, "check", range("base", "later_tip"));
    GOLDEN("reviewer-no-alnum", 1, "record", "--reviewer", "---", "--verdict", "ACCEPT", range("base", "c2"));
    branch("tabbed", L("base"));
    mk("feat: tabbed author", "Tab\tName <t@example.org>");
    lab("tabbed_tip", "HEAD");
    GOLDEN("author-control-char", 1, "record", "--reviewer", "Fine Rev", "--verdict", "ACCEPT", range("base", "tabbed_tip"));
    branch("wide", L("base"));
    for (int i = 1; i <= 45; i++) {
        snprintf(author, sizeof author, "Backport Contributor %02d <c%02d@example.org>", i, i);
        snprintf(subject, sizeof subject, "backport %d", i);
        mk_by(subject, author);
    }
    lab("wide_tip", "HEAD");
    GOLDEN("wide-record", 0, "record", "--reviewer", "Wide Rev", "--verdict", "ACCEPT", range("base", "wide_tip"));
    commit_rows();
    lab("wide_rows", "HEAD");
    GOLDEN("wide-check", 0, "check", range("base", "wide_rows"));
}

/* ---- the pre-push review gate (zcl-dev-hook with real git pushes) -------------------------------- */

static char rc_dir[700], remote[700];

static void expect(const char *name, int refuse, const char *pat, char *const argv[])
{
    char *out;
    int rc = run_in(repo, argv, &out);
    int ok = (refuse ? rc != 0 : rc == 0) && (!pat || strstr(out, pat));
    if (ok) printf("ok   %s\n", name);
    else printf("FAIL %s (exit %d, wanted %s, pattern '%s')\n%s\n", name, rc, refuse ? "refusal" : "admission", pat ? pat : "", out);
    fails += !ok;
    free(out);
}

static void push(const char *name, int refuse, const char *pat, const char *refspec)
{
    expect(name, refuse, pat, (char *const[]){"git", "push", "-q", "origin", (char *)refspec, NULL});
}

static void push_ok(const char *name, int refuse, const char *pat, const char *refspec)
{
    setenv("ZCL_PUSH_OK", "fixture", 1);
    push(name, refuse, pat, refspec);
    unsetenv("ZCL_PUSH_OK");
}

/* receipts of the steps a push of `sha` needs here: unit-a, unit-b and the docs step doc/agent selects */
static void receipts(const char *sha)
{
    static const char *const steps[] = {"unit-a", "unit-b", "check-dev-tools"};
    char path[800], line[300];
    snprintf(path, sizeof path, "%s/receipts.jsonl", rc_dir);
    for (int i = 0; i < 3; i++) {
        snprintf(line, sizeof line, "{\"commit\":\"%s\",\"tree\":\"t\",\"stage\":\"test-run/release\",\"step\":\"%s\",\"verdict\":\"PASS\",\"seconds\":1}\n", sha, steps[i]);
        FILE *f = fopen(path, "a");
        if (!f || fputs(line, f) < 0 || fclose(f) != 0) die("cannot write a receipt");
    }
}

static void edit_commit(const char *subject)
{
    write_file("src/a.c", subject, "a");
    free(git("add", "src/a.c", NULL));
    free(git("commit", "-q", "--no-verify", "-m", subject, NULL));
}

static void mkdir_p(const char *sub)
{
    char p[900];
    snprintf(p, sizeof p, "%s/%s", repo, sub);
    run_in(NULL, (char *const[]){"mkdir", "-p", p, NULL}, NULL);
}

static void hook_fixture(const char *bindir, const char *githooks)
{
    char p[900], bin[900];
    mkdir_p("zcutil/bin");
    mkdir_p("zcutil/dev");
    mkdir_p("src");
    snprintf(bin, sizeof bin, "%s/zcutil/bin", repo);
    snprintf(p, sizeof p, "%s/zcutil/githooks", repo);
    run_in(NULL, (char *const[]){"cp", "-R", (char *)githooks, p, NULL}, NULL);
    for (int i = 0; i < 3; i++) {
        static const char *const names[] = {"zcl-dev", "zcl-dev-hook", "zcl-dev-hooks"};
        snprintf(p, sizeof p, "%s/%s", bindir, names[i]);
        run_in(NULL, (char *const[]){"cp", p, bin, NULL}, NULL);
    }
    write_file(".gitignore", "zcutil/bin/\n", "w");
    write_file("zcutil/dev/impact.rules", "src/*|zcutil/*|.gitignore|doc/*\tunit-a unit-b\n", "w");
    write_file("zcutil/local-ci.sh", "step() { :; }\n    step unit-a 10 t_a\n    step unit-b 10 t_b\n", "w");
    write_file("src/a.c", "a\n", "w");
    free(git("add", "-A", NULL));
    free(git("commit", "-q", "--no-verify", "-m", "init", NULL));
    snprintf(remote, sizeof remote, "%s/remote.git", work);
    run_in(NULL, (char *const[]){"git", "init", "-q", "--bare", remote, NULL}, NULL);
    free(git("remote", "add", "origin", remote, NULL));
    free(git("push", "-q", "--no-verify", "origin", "master", NULL));
    free(git("config", "core.hooksPath", "zcutil/githooks", NULL));
    snprintf(rc_dir, sizeof rc_dir, "%s/rc", work);
    run_in(NULL, (char *const[]){"mkdir", "-p", rc_dir, NULL}, NULL);
    setenv("ZCL_CI_OUT", rc_dir, 1);
    unsetenv("ZCL_PUSH_OK");
}

static void commit_record(const char *subject, const char *from, const char *to)
{
    char *rec[] = {tool, "record", "--reviewer", "Rev One", "--verdict", "ACCEPT", range(from, to), NULL};
    if (run_in(repo, rec, NULL) != 0) die("record failed");
    free(git("commit", "-q", "--no-verify", "-m", subject, "--", ROWS, NULL));
}

static void hook_cases(void)
{
    lab("init", "HEAD");
    write_file(ROWS, "# review record\n", "w");
    free(git("add", ROWS, NULL));
    free(git("commit", "-q", "--no-verify", "-m", "review: add the record", NULL));
    lab("r0", "HEAD");
    receipts(L("r0"));
    push("a commit that only adds the record needs no review row", 0, NULL, "master");
    edit_commit("feat: reviewed code\n");
    lab("rv1", "HEAD");
    receipts(L("rv1"));
    push("master push with receipts and no review row is refused", 1, "no accepted review", "master");
    push_ok("ZCL_PUSH_OK=1 does not waive review", 1, "ZCL_PUSH_OK does not waive review", "master");
    edit_commit("feat: no receipt, no row\n");
    push_ok("an override of the receipts still leaves review in force", 1, "no accepted review", "master");
    free(git("reset", "-q", "--hard", L("rv1"), NULL));
    commit_record("review: record", "r0", "rv1");
    lab("rv1r", "HEAD");
    receipts(L("rv1r"));
    push("master push with a review row is admitted", 0, NULL, "master");
    edit_commit("feat: second slice\n");
    lab("rv3", "HEAD");
    receipts(L("rv3"));
    push("an earlier row does not cover a later commit", 1, "feat: second slice (no row)", "master");
    commit_record("review: record second", "rv1r", "rv3");
    push_ok("ZCL_PUSH_OK=1 with a row and no receipts is admitted through the override", 0, NULL, "master");
    edit_commit("feat: unreviewed release\n");
    lab("rv4", "HEAD");
    receipts(L("rv4"));
    push("a new release/* ref is held to review from the remote master", 1, "no accepted review", "master:refs/heads/release/9");
    push("deleting a protected ref keeps its own refusal", 1, "deleting refs/heads/master", ":master");
    expect("git push --no-verify is the explicit bypass", 0, NULL,
           (char *const[]){"git", "push", "-q", "--no-verify", "origin", "master:refs/heads/release/9", NULL});
}

static void env_setup(void)
{
    const char *tmp = getenv("TMPDIR");
    char home[700];
    snprintf(work, sizeof work, "%s/zcl-review-test.XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(work)) die("mkdtemp");
    snprintf(repo, sizeof repo, "%s/repo", work);
    snprintf(home, sizeof home, "%s/home", work);
    setenv("HOME", home, 1);
    setenv("GIT_CONFIG_NOSYSTEM", "1", 1);
    setenv("GIT_CONFIG_GLOBAL", "/dev/null", 1);
    unsetenv("GIT_DIR");
    unsetenv("GIT_WORK_TREE");
    unsetenv("GIT_INDEX_FILE");
    if (run_in(NULL, (char *const[]){"git", "init", "-q", "-b", "master", repo, NULL}, NULL) != 0) die("git init");
    free(git("config", "user.name", "Pat Human", NULL));
    free(git("config", "user.email", "pat@example.invalid", NULL));
    mkdir_p("doc/agent");
}

static int finish(void)
{
    run_in("/", (char *const[]){"rm", "-rf", work, NULL}, NULL);
    if (!fails) {
        puts("review: all tests passed");
        return 0;
    }
    fprintf(stderr, "review: %d FAILED\n", fails);
    return 1;
}

static void set_tool(const char *path)
{
    char *tp = realpath(path, NULL);
    if (!tp) die("zcl-dev-review not found");
    snprintf(tool, sizeof tool, "%s", tp);
    free(tp);
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--hook")) {
        char *bd = realpath(argv[2], NULL), *gh = realpath(argv[3], NULL), t[900];
        if (!bd || !gh) die("bin or githooks directory not found");
        snprintf(t, sizeof t, "%s/zcl-dev-review", bd);
        set_tool(t);
        env_setup();
        hook_fixture(bd, gh);
        hook_cases();
        return finish();
    }
    if (argc != 3) die("usage: zcl-review-fixtures <zcl-dev-review> <golden-dir> | --hook <bindir> <githooks-dir>");
    char *gp = realpath(argv[2], NULL);
    if (!gp) die("golden directory not found");
    snprintf(golden_dir, sizeof golden_dir, "%s", gp);
    set_tool(argv[1]);
    env_setup();
    history();
    record_and_cover();
    stale_cases();
    reject_and_human();
    malformed_rows();
    paging();
    later_and_wide();
    return finish();
}
