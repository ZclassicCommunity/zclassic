/* zcl-dev-review: the review record. MIT, like the rest of zclassicd.
 * Plain C, libc only; compiles as gnu17 and C2x, with the host cc, mingw-w64 and macOS clang.
 * The idea (a verdict kept next to the commits it covers, bound to a tip tree, written by a reviewer
 * who is not an author) follows Z23's z23-review agent and its pre-commit/land gates; the code is new.
 *
 *   zcl-dev review record --reviewer R --verdict V [--evidence E] [--json] <base>..<tip>
 *   zcl-dev review check [--json] [--rows-from <commit>] [--after=N] <base>..<tip>
 *   zcl-dev review --selftest | --purpose
 *
 * record appends one row to the working-tree doc/agent/REVIEWS.tsv (temp file, fsync, rename) and prints
 * the commit command; it never commits. check reads the rows from the tip commit (or --rows-from), never
 * from the working tree. Exit codes: 0 ok, 1 refused or uncovered commits, 2 broken.
 * The check logic is review-core.c, which the pre-push hook links too.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L /* fsync, getpid under a strict -std=c2x */
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include "review-core.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <io.h>
#include <process.h>
#define fsync _commit
#define fileno _fileno
#define getpid _getpid
#else
#include <unistd.h>
#endif

#define PAGE_BYTES 15000 /* output stays under 16 KiB per page */
#define RECORD_USAGE "usage: zcl-dev review record --reviewer R --verdict ACCEPT|ACCEPT-WITH-FIXES|REJECT [--evidence E] [--json] <base>..<tip>"
#define CHECK_USAGE "usage: zcl-dev review check [--json] [--rows-from <commit>] [--after=N] <base>..<tip>"

static int fail_msg(int rc, const char *fmt, ...)
{
    va_list ap;
    fputs("zcl-dev review: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return rc;
}

static void jstr(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c == '\t') fputs("\\t", f);
        else if (c == '\n') fputs("\\n", f);
        else if (c == '\r') fputs("\\r", f);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

/* ---- check ----------------------------------------------------------------------------- */

typedef struct { int json; size_t after; const char *rows_from; const char *range; } CheckArgs;

static size_t item_size(const RvMiss *m, int json)
{
    char line[700];
    rv_miss_line(m, line, sizeof line);
    return json ? strlen(m->subject) * 2 + 120 : strlen(line) + 4; /* a subject has no control characters */
}

static size_t page_end(const RvResult *res, size_t after, int json)
{
    size_t i = after, used = 0;
    for (; i < res->n; i++) {
        size_t len = item_size(&res->v[i], json);
        if (i > after && used + len > PAGE_BYTES) break;
        used += len;
    }
    return i;
}

static void print_items(const RvResult *res, size_t after, size_t end, int json)
{
    for (size_t i = after; i < end; i++) {
        if (json) {
            printf("%s{\"sha\":\"%s\",\"subject\":", i > after ? "," : "", res->v[i].sha);
            jstr(stdout, res->v[i].subject);
            printf(",\"reason\":\"%s\"}", res->v[i].reason);
        } else {
            char line[700];
            rv_miss_line(&res->v[i], line, sizeof line);
            printf("  %s\n", line);
        }
    }
}

static void report_check(const RvResult *res, const CheckArgs *a)
{
    size_t after = a->after > res->n ? res->n : a->after, end = page_end(res, after, a->json);
    int more = end < res->n;
    if (a->json) {
        printf("{\"ok\":%s,\"commits\":%zu,\"exempt\":%zu,\"uncovered\":%zu,\"after\":%zu,\"items\":[", res->n ? "false" : "true",
               res->commits, res->exempt, res->n, after);
        print_items(res, after, end, 1);
        if (more) printf("],\"next\":%zu}\n", end);
        else printf("],\"next\":null}\n");
        return;
    }
    if (!res->n) {
        printf("review: %zu commits covered in %.7s..%.7s (%zu exempt: only " RV_ROWS_PATH ")\n", res->commits, res->base, res->tip, res->exempt);
        return;
    }
    printf("review: %zu of %zu commits in %.7s..%.7s have no accepted review:\n", res->n, res->commits, res->base, res->tip);
    print_items(res, after, end, 0);
    if (more) printf("-- more: rerun with --after=%zu (%zu of %zu shown)\n", end, end - after, res->n);
    printf("record: zcl-dev review record --reviewer <name> --verdict ACCEPT %.7s..%.7s\n", res->base, res->tip);
}

static int parse_after(const char *s, size_t *out)
{
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (!*s || *end || !isdigit((unsigned char)*s)) return -1;
    *out = (size_t)v;
    return 0;
}

static int parse_check_args(int argc, char **argv, CheckArgs *a)
{
    memset(a, 0, sizeof *a);
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) a->json = 1;
        else if (!strcmp(argv[i], "--rows-from") && i + 1 < argc) a->rows_from = argv[++i];
        else if (!strncmp(argv[i], "--after=", 8)) {
            if (parse_after(argv[i] + 8, &a->after) != 0) return fail_msg(2, "bad --after value '%s'", argv[i] + 8);
        } else if (argv[i][0] == '-' || a->range) return fail_msg(2, "%s", CHECK_USAGE);
        else a->range = argv[i];
    }
    return a->range ? 0 : fail_msg(2, "%s", CHECK_USAGE);
}

static int cmd_check(int argc, char **argv)
{
    CheckArgs a;
    char base[200], tip[200], err[RV_MSG];
    if (parse_check_args(argc, argv, &a) != 0) return 2;
    if (rv_range_parse(a.range, base, tip, sizeof base) != 0) return fail_msg(2, "bad range '%s' (want <base>..<tip>)", a.range);
    RvResult res;
    err[0] = 0;
    int rc = rv_check_range(base, tip, a.rows_from, &res, err, sizeof err);
    if (rc == 2) {
        rv_result_free(&res);
        return fail_msg(2, "%s", err);
    }
    report_check(&res, &a);
    rv_result_free(&res);
    return rc;
}

/* ---- record ---------------------------------------------------------------------------- */

typedef struct { const char *reviewer, *verdict, *evidence, *range; int json; } RecordArgs;

static int parse_record_args(int argc, char **argv, RecordArgs *a)
{
    memset(a, 0, sizeof *a);
    a->evidence = "";
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) a->json = 1;
        else if (!strcmp(argv[i], "--reviewer") && i + 1 < argc) a->reviewer = argv[++i];
        else if (!strcmp(argv[i], "--verdict") && i + 1 < argc) a->verdict = argv[++i];
        else if (!strcmp(argv[i], "--evidence") && i + 1 < argc) a->evidence = argv[++i];
        else if ((argv[i][0] == '-' && argv[i][1]) || a->range) return fail_msg(2, "%s", RECORD_USAGE);
        else a->range = argv[i];
    }
    if (!a->reviewer || !a->verdict || !a->range) return fail_msg(2, "%s", RECORD_USAGE);
    return 0;
}

static int printable_field(const char *s, size_t max)
{
    if (strlen(s) > max) return 0;
    for (; *s; s++) if ((unsigned char)*s < 0x20 || *s == 0x7f) return 0;
    return 1;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* Sorted, comma-joined, de-duplicated authors of every commit of the range. */
static char *join_authors(const RvRange *rg)
{
    RvList all = {NULL, 0, 0};
    size_t total = 1;
    for (size_t i = 0; i < rg->n; i++) total += rg->v[i].authors.n;
    all.v = malloc(total * sizeof *all.v);
    if (!all.v) return NULL;
    for (size_t i = 0; i < rg->n; i++)
        for (size_t k = 0; k < rg->v[i].authors.n; k++) all.v[all.n++] = rg->v[i].authors.v[k];
    qsort(all.v, all.n, sizeof *all.v, cmp_str);
    size_t len = 1;
    for (size_t i = 0; i < all.n; i++) len += strlen(all.v[i]) + 1;
    char *out = malloc(len);
    size_t o = 0;
    for (size_t i = 0; out && i < all.n; i++) {
        if (i && !strcmp(all.v[i], all.v[i - 1])) continue;
        size_t l = strlen(all.v[i]);
        if (o) out[o++] = ',';
        memcpy(out + o, all.v[i], l);
        o += l;
    }
    if (out) out[o] = 0;
    free(all.v);
    return out;
}

/* The reviewer may not be any author of the range; names compare lowercased, alphanumerics only. */
static const char *author_clash(const RvRange *rg, const char *reviewer)
{
    char rn[300], an[300];
    rv_norm(reviewer, rn, sizeof rn);
    for (size_t i = 0; i < rg->n; i++)
        for (size_t k = 0; k < rg->v[i].authors.n; k++) {
            const char *a = rg->v[i].authors.v[k];
            rv_norm(!strncmp(a, "human:", 6) ? a + 6 : a, an, sizeof an);
            if (!strcmp(an, rn)) return a;
        }
    return NULL;
}

static int tree_of(const char *tip, char *out, size_t cap)
{
    char spec[200];
    snprintf(spec, sizeof spec, "%s^{tree}", tip);
    const char *av[] = {"git", "rev-parse", "--verify", "-q", spec, NULL};
    RvBuf b;
    int rc = rv_git(av, &b);
    while (b.n && (b.p[b.n - 1] == '\n' || b.p[b.n - 1] == '\r')) b.p[--b.n] = 0;
    if (rc == 0 && b.n && b.n < cap) snprintf(out, cap, "%s", b.p);
    int ok = rc == 0 && b.n && b.n < cap;
    rv_buf_free(&b);
    return ok ? 0 : -1;
}

static int rows_file_path(char *out, size_t cap)
{
    const char *av[] = {"git", "rev-parse", "--show-toplevel", NULL};
    RvBuf b;
    int rc = rv_git(av, &b);
    while (b.n && (b.p[b.n - 1] == '\n' || b.p[b.n - 1] == '\r')) b.p[--b.n] = 0;
    int ok = rc == 0 && b.n && snprintf(out, cap, "%s/" RV_ROWS_PATH, b.p) < (int)cap;
    rv_buf_free(&b);
    return ok ? 0 : -1;
}

static char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, n = 0, got;
    char *p = malloc(cap);
    while (p && (got = fread(p + n, 1, cap - n - 1, f)) > 0) {
        n += got;
        if (n + 1 >= cap) {
            char *q = realloc(p, cap *= 2);
            if (!q) { free(p); p = NULL; }
            else p = q;
        }
    }
    fclose(f);
    if (p) { p[n] = 0; *len = n; }
    return p;
}

/* Temp file in the same directory, fsync, rename: a reader sees the old file or the new one. */
static int append_row(const char *path, const char *row)
{
    size_t len = 0;
    char *old = slurp(path, &len), tmp[1200];
    if (!old) return fail_msg(2, "cannot read %s (run inside a checkout that has " RV_ROWS_PATH ")", path);
    snprintf(tmp, sizeof tmp, "%s.tmp%d", path, (int)getpid());
    FILE *f = fopen(tmp, "wb");
    int ok = f != NULL;
    if (ok) ok = fwrite(old, 1, len, f) == len;
    if (ok && len && old[len - 1] != '\n') ok = fputc('\n', f) != EOF;
    if (ok) ok = fputs(row, f) >= 0 && fputc('\n', f) != EOF;
    if (ok) ok = fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (f && fclose(f) != 0) ok = 0;
    free(old);
    if (ok) {
#ifdef _WIN32
        remove(path); /* rename does not replace on Windows: not atomic there */
#endif
        ok = rename(tmp, path) == 0;
    }
    if (!ok) {
        remove(tmp);
        return fail_msg(2, "cannot write %s", path);
    }
    return 0;
}

static void utc_now(char *out, size_t cap)
{
    time_t t = time(NULL);
    struct tm *g = gmtime(&t);
    if (!g || !strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", g)) snprintf(out, cap, "1970-01-01T00:00:00Z");
}

static int record_refusal(const RecordArgs *a, const RvRange *rg)
{
    if (!rv_verdict_ok(a->verdict)) return fail_msg(1, "verdict '%s' is not ACCEPT, ACCEPT-WITH-FIXES or REJECT", a->verdict);
    if (!a->reviewer[0] || !printable_field(a->reviewer, 100)) return fail_msg(1, "reviewer must be 1-100 printable characters without tab or newline");
    char rn[300];
    rv_norm(a->reviewer, rn, sizeof rn);
    if (!rn[0]) return fail_msg(1, "reviewer '%s' has no letters or digits, so it cannot be told apart from an author", a->reviewer);
    if (!printable_field(a->evidence, 200)) return fail_msg(1, "evidence must be at most 200 printable characters without tab or newline");
    if (!rg->n) return fail_msg(1, "the range %.7s..%.7s has no commits to review", rg->base, rg->tip);
    const char *clash = author_clash(rg, a->reviewer);
    if (clash) return fail_msg(1, "reviewer '%s' is an author of the range (%s); a reviewer must not have written the commits", a->reviewer, clash);
    return 0;
}

static char *lowered(const char *s)
{
    char *d = malloc(strlen(s) + 1);
    if (!d) return NULL;
    size_t i = 0;
    for (; s[i]; i++) d[i] = (char)tolower((unsigned char)s[i]);
    d[i] = 0;
    return d;
}

/* The row in a buffer sized for it: a range of many authors makes a long row, and a truncated row would be malformed. */
static char *format_row(const RecordArgs *a, const RvRange *rg, const char *tree, const char *authors, const char *rev, const char *date)
{
    const char *fmt = "%s..%s\t%s\t%s\t%s\t%s\t%s\t%s";
    int n = snprintf(NULL, 0, fmt, rg->base, rg->tip, tree, authors, rev, a->verdict, date, a->evidence);
    char *row = n < 0 ? NULL : malloc((size_t)n + 1);
    if (row) snprintf(row, (size_t)n + 1, fmt, rg->base, rg->tip, tree, authors, rev, a->verdict, date, a->evidence);
    return row;
}

static int write_row(const RecordArgs *a, const RvRange *rg, const char *tree)
{
    char path[1100], date[32], *row = NULL;
    char *authors = join_authors(rg), *rev = lowered(a->reviewer);
    int rc = 2;
    if (!authors || !rev) {
        fail_msg(2, "out of memory");
    } else if (!printable_field(authors, (size_t)-1)) {
        rc = fail_msg(1, "an author name of the range contains a control character; it cannot be written to " RV_ROWS_PATH);
    } else if (rows_file_path(path, sizeof path) != 0) {
        fail_msg(2, "not inside a work tree");
    } else {
        utc_now(date, sizeof date);
        row = format_row(a, rg, tree, authors, rev, date);
        rc = row ? append_row(path, row) : fail_msg(2, "out of memory");
        if (row && rc == 0) {
            if (a->json) {
                fputs("{\"ok\":true,\"row\":", stdout);
                jstr(stdout, row);
                printf(",\"commit\":\"git commit -m \\\"review: record %.7s..%.7s\\\" -- " RV_ROWS_PATH "\"}\n", rg->base, rg->tip);
            } else {
                printf("%s\ngit commit -m \"review: record %.7s..%.7s\" -- " RV_ROWS_PATH "\n", row, rg->base, rg->tip);
            }
        }
    }
    free(row);
    free(authors);
    free(rev);
    return rc;
}

static int cmd_record(int argc, char **argv)
{
    RecordArgs a;
    char base[200], tip[200], err[RV_MSG], tree[80];
    if (parse_record_args(argc, argv, &a) != 0) return 2;
    if (rv_range_parse(a.range, base, tip, sizeof base) != 0) return fail_msg(2, "bad range '%s' (want <base>..<tip>)", a.range);
    RvRange rg;
    err[0] = 0;
    if (rv_load_range(base, tip, &rg, err, sizeof err) != 0) return fail_msg(1, "%s", err);
    int rc = record_refusal(&a, &rg);
    if (rc == 0 && tree_of(rg.tip, tree, sizeof tree) != 0) rc = fail_msg(2, "cannot read the tree of %s", rg.tip);
    if (rc == 0) rc = write_row(&a, &rg, tree);
    rv_range_free(&rg);
    return rc;
}

/* ---- selftest -------------------------------------------------------------------------- */

static int expect(int cond, const char *what)
{
    if (!cond) fprintf(stderr, "selftest FAIL: %s\n", what);
    return cond ? 0 : 1;
}

static int selftest_rows(void)
{
    int bad = 0;
    char err[200], good[400], b1[100], t1[100];
    RvRow row;
    snprintf(good, sizeof good, "%.40s..%.40s\t%.40s\tclaude opus 5.5\tfoo\tACCEPT\t2026-11-19T10:00:00Z\tnote",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
             "cccccccccccccccccccccccccccccccccccccccccccccccc");
    bad += expect(rv_parse_row(good, 5, &row, err, sizeof err) == 0 && !strcmp(row.verdict, "ACCEPT") && row.tip[0] == 'b', "good row parses");
    snprintf(good, sizeof good, "x..y\tz\ta\tb\tACCEPT\td\te");
    bad += expect(rv_parse_row(good, 7, &row, err, sizeof err) != 0 && strstr(err, "line 7"), "bad range names the line");
    snprintf(good, sizeof good, "a\tb");
    bad += expect(rv_parse_row(good, 3, &row, err, sizeof err) != 0 && strstr(err, "7 tab"), "short row refused");
    bad += expect(rv_range_parse("abc..def", b1, t1, sizeof b1) == 0 && !strcmp(b1, "abc") && !strcmp(t1, "def"), "range splits");
    bad += expect(rv_range_parse("abc...def", b1, t1, sizeof b1) != 0 && rv_range_parse("abc", b1, t1, sizeof b1) != 0, "bad ranges refused");
    return bad;
}

static int selftest(void)
{
    int bad = selftest_rows();
    char a[64], b[64];
    rv_norm("Claude Opus 5.5", a, sizeof a);
    rv_norm("claude-opus-5-5", b, sizeof b);
    bad += expect(!strcmp(a, b) && !strcmp(a, "claudeopus55"), "normalize equates Claude Opus 5.5 and claude-opus-5-5");
    rv_norm("human:Ann Lee", a, sizeof a);
    bad += expect(!strcmp(a, "humanannlee"), "normalize drops punctuation");
    bad += expect(rv_verdict_ok("ACCEPT") && rv_verdict_ok("ACCEPT-WITH-FIXES") && rv_verdict_ok("REJECT") && !rv_verdict_ok("accept"), "verdict tokens");
    bad += expect(printable_field("ok", 5) && !printable_field("a\tb", 5) && !printable_field("toolong", 3), "field printability");
    size_t after = 0;
    bad += expect(parse_after("12", &after) == 0 && after == 12 && parse_after("x", &after) != 0 && parse_after("", &after) != 0, "after parses");
    if (bad) return 1;
    puts("zcl-dev-review: selftest ok");
    return 0;
}

int main(int argc, char **argv)
{
    const char *cmd = argc >= 2 ? argv[1] : "";
    if (!strcmp(cmd, "--purpose")) {
        puts("record and check non-author review verdicts bound to a commit range and its tip tree");
        return 0;
    }
    if (!strcmp(cmd, "--selftest")) return selftest();
    if (!strcmp(cmd, "record")) return cmd_record(argc - 2, argv + 2);
    if (!strcmp(cmd, "check")) return cmd_check(argc - 2, argv + 2);
    fputs(RECORD_USAGE "\n" CHECK_USAGE "\n", stderr);
    return 2;
}
