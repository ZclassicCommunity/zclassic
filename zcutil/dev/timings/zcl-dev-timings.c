/*
 * zcl-dev timings: where does local CI spend its time, and what got slower?
 *
 * usage: zcl-dev timings [--json] [--step NAME] <outdir>...
 *        zcl-dev-timings --selftest | --purpose
 * Reads, per local-ci output directory (doc/local-ci.md):
 *   results.tsv    <step> TAB <PASS|FAIL|SKIP> TAB <seconds>, at <outdir>/results.tsv, <outdir>/test/results.tsv
 *                  (debug flavor) and <outdir>/test-release/results.tsv (release flavor), as local-ci.sh writes them;
 *   receipts.jsonl one flat JSON object per line with "step", "verdict" and "seconds" (strict flat-field scan).
 * A missing or corrupt file is printed as `unavailable: <path>: <reason>` and never counted as zero: a file with
 * one bad line is dropped whole. Statistics come from results.tsv, or from receipts.jsonl when results.tsv is
 * unusable. SKIP rows carry no timing. Directories are taken in argument order as oldest to newest.
 * Exit: 0 data read, 1 a MISMATCH between results.tsv and receipts.jsonl, 2 nothing readable or bad arguments.
 * Libc only. Written for zclassicd; the idea (report existing artifacts, state coverage limits) is Z23's tools/dev/timings.c.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PURPOSE "step durations over local-ci results: slowest steps, pass rates, slower-than-before, with coverage limits"
#define FILE_MAX (16L * 1024 * 1024)
#define NAME_MAX_LEN 64
#define LINE_MAX_LEN 4096
#define SLOWER_RATIO 1.5
#define SLOWER_MIN_SECS 5.0

enum { V_PASS, V_FAIL, V_SKIP };
static const char *const vname[] = {"PASS", "FAIL", "SKIP"};

struct rec {
    char name[NAME_MAX_LEN];
    int verdict;
    double secs;
};

struct recs {
    struct rec *v;
    size_t n, cap;
};

struct sample {
    double secs;
    int od;
};

struct step {
    char name[NAME_MAX_LEN];
    int pass, fail, skip;
    struct sample *s;
    size_t n, cap;
};

struct lines {
    char **v;
    size_t n, cap;
};

struct ctx {
    int total, read;
    struct lines unavailable, mismatch;
    struct step *steps;
    size_t nsteps, capsteps;
};

/* ---------------------------------------------------------------- small utilities */

static void *grow(void *p, size_t *cap, size_t need, size_t elt)
{
    if (need <= *cap) return p;
    size_t nc = *cap ? *cap * 2 : 16;
    void *q = realloc(p, nc * elt);
    if (!q) { fprintf(stderr, "zcl-dev timings: out of memory\n"); exit(2); }
    *cap = nc;
    return q;
}

static void lines_add(struct lines *l, const char *fmt, const char *a, const char *b, const char *c)
{
    char buf[LINE_MAX_LEN];
    l->v = grow(l->v, &l->cap, l->n + 1, sizeof *l->v);
    snprintf(buf, sizeof buf, fmt, a, b, c);
    l->v[l->n] = strdup(buf);
    if (!l->v[l->n]) { fprintf(stderr, "zcl-dev timings: out of memory\n"); exit(2); }
    l->n++;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Sort v[0..n) in place and return its median (0 for none). */
static double median_of(double *v, size_t n)
{
    if (!n) return 0;
    qsort(v, n, sizeof *v, cmp_double);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

/* ---------------------------------------------------------------- line parsing */

static int verdict_code(const char *s)
{
    for (int i = 0; i < 3; i++)
        if (!strcmp(s, vname[i])) return i;
    return -1;
}

/* digits with an optional fraction, nothing else */
static int parse_secs(const char *s, double *out)
{
    size_t d = strspn(s, "0123456789");
    if (!d) return -1;
    if (s[d] == '.') {
        size_t f = strspn(s + d + 1, "0123456789");
        if (!f) return -1;
        d += 1 + f;
    }
    if (s[d] || d > 15) return -1;
    *out = strtod(s, NULL);
    return 0;
}

static int fill_rec(struct rec *r, const char *name, const char *verdict, const char *secs)
{
    size_t n = strlen(name);
    if (!n || n >= sizeof r->name) return -1;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)name[i] < 0x20 || name[i] == 0x7f) return -1;
    if ((r->verdict = verdict_code(verdict)) < 0) return -1;
    if (parse_secs(secs, &r->secs)) return -1;
    memcpy(r->name, name, n + 1);
    return 0;
}

/* line is modified in place; <step> TAB <verdict> TAB <seconds> */
static int parse_tsv_line(char *line, struct rec *r)
{
    char *t1 = strchr(line, '\t'), *t2 = t1 ? strchr(t1 + 1, '\t') : NULL;
    if (!t2 || strchr(t2 + 1, '\t')) return -1;
    *t1 = 0;
    *t2 = 0;
    return fill_rec(r, line, t1 + 1, t2 + 1);
}

/* value start after `"key":` when the key is a top-level field of a flat object, else NULL */
static const char *find_key(const char *line, const char *key)
{
    char pat[40];
    const char *p = line;
    snprintf(pat, sizeof pat, "\"%s\":", key);
    while ((p = strstr(p, pat))) {
        if (p == line + 1 || p[-1] == ',') return p + strlen(pat);
        p++;
    }
    return NULL;
}

static int get_str(const char *line, const char *key, char *dst, size_t cap)
{
    const char *p = find_key(line, key);
    size_t n = 0;
    if (!p || *p != '"') return -1;
    for (p++; *p && *p != '"'; p++, n++)
        if (*p == '\\' || (unsigned char)*p < 0x20 || n + 1 >= cap) return -1;
    if (*p != '"') return -1;
    memcpy(dst, p - n, n);
    dst[n] = 0;
    return 0;
}

static int get_num(const char *line, const char *key, char *dst, size_t cap)
{
    const char *p = find_key(line, key);
    size_t n = p ? strspn(p, "0123456789.") : 0;
    if (!n || n >= cap) return -1;
    memcpy(dst, p, n);
    dst[n] = 0;
    return 0;
}

/* one receipts.jsonl line; modified in place only by trimming a trailing CR */
static int parse_receipt_line(char *line, struct rec *r)
{
    char verdict[16], secs[32], name[NAME_MAX_LEN];
    size_t n = strlen(line);
    if (n && line[n - 1] == '\r') line[--n] = 0;
    if (n < 2 || line[0] != '{' || line[n - 1] != '}') return -1;
    if (get_str(line, "step", name, sizeof name) || get_str(line, "verdict", verdict, sizeof verdict)) return -1;
    if (get_num(line, "seconds", secs, sizeof secs)) return -1;
    return fill_rec(r, name, verdict, secs);
}

/* ---------------------------------------------------------------- file loading */

enum { LOAD_OK = 0, LOAD_MISSING = 1, LOAD_BAD = 2 };

/* The whole file in a NUL-terminated buffer; on failure reason names why. */
static int slurp(const char *path, char **out, char *reason, size_t rcap)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(reason, rcap, "%s", errno == ENOENT ? "not found" : strerror(errno));
        return errno == ENOENT ? LOAD_MISSING : LOAD_BAD;
    }
    char *buf = malloc((size_t)FILE_MAX + 1);
    size_t n = buf ? fread(buf, 1, (size_t)FILE_MAX + 1, f) : 0;
    int bad = ferror(f) || n > (size_t)FILE_MAX || !buf;
    fclose(f);
    if (bad) { snprintf(reason, rcap, "unreadable or larger than 16 MiB"); free(buf); return LOAD_BAD; }
    buf[n] = 0;
    if (strlen(buf) != n) { snprintf(reason, rcap, "contains a NUL byte"); free(buf); return LOAD_BAD; }
    *out = buf;
    return LOAD_OK;
}

typedef int (*line_parser)(char *, struct rec *);

/* Parse every line of text into out; all or nothing. reason says which line failed. */
static int parse_lines(char *text, line_parser parse, struct recs *out, char *reason, size_t rcap)
{
    size_t base = out->n;
    int lineno = 0;
    char *p = text;
    while (*p) {
        char *nl = strchr(p, '\n');
        char copy[LINE_MAX_LEN];
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        lineno++;
        out->v = grow(out->v, &out->cap, out->n + 1, sizeof *out->v);
        if (len >= sizeof copy) len = sizeof copy - 1;
        memcpy(copy, p, len);
        copy[len] = 0;
        if (parse(copy, &out->v[out->n])) {
            snprintf(reason, rcap, "corrupt line %d", lineno);
            out->n = base;
            return LOAD_BAD;
        }
        out->n++;
        p = nl ? nl + 1 : p + len;
    }
    return LOAD_OK;
}

static int load_file(const char *path, line_parser parse, struct recs *out, char *reason, size_t rcap)
{
    char *text = NULL;
    int rc = slurp(path, &text, reason, rcap);
    if (rc != LOAD_OK) return rc;
    rc = parse_lines(text, parse, out, reason, rcap);
    free(text);
    return rc;
}

/* ---------------------------------------------------------------- per-outdir work */

static const char *const tsv_names[] = {"results.tsv", "test/results.tsv", "test-release/results.tsv"};

/* results.tsv of every flavor present; 1 when usable (all present ones parsed, at least one present) */
static int load_results(struct ctx *c, const char *dir, struct recs *out)
{
    int found = 0, bad = 0;
    for (size_t i = 0; i < 3; i++) {
        char path[LINE_MAX_LEN], reason[128];
        snprintf(path, sizeof path, "%s/%s", dir, tsv_names[i]);
        int rc = load_file(path, parse_tsv_line, out, reason, sizeof reason);
        if (rc == LOAD_MISSING) continue;
        found++;
        if (rc == LOAD_BAD) { bad++; lines_add(&c->unavailable, "unavailable: %s: %s%s", path, reason, ""); }
    }
    if (!found) {
        char path[LINE_MAX_LEN];
        snprintf(path, sizeof path, "%s/results.tsv", dir);
        lines_add(&c->unavailable, "unavailable: %s: not found%s%s", path, " (also tried test/ and test-release/)", "");
    }
    if (bad) out->n = 0;
    return found && !bad;
}

static int load_receipts(struct ctx *c, const char *dir, struct recs *out)
{
    char path[LINE_MAX_LEN], reason[128];
    snprintf(path, sizeof path, "%s/receipts.jsonl", dir);
    int rc = load_file(path, parse_receipt_line, out, reason, sizeof reason);
    if (rc != LOAD_OK) lines_add(&c->unavailable, "unavailable: %s: %s%s", path, reason, "");
    return rc == LOAD_OK;
}

static const struct rec *last_of(const struct recs *r, const char *name)
{
    for (size_t i = r->n; i-- > 0;)
        if (!strcmp(r->v[i].name, name)) return &r->v[i];
    return NULL;
}

/* A step both sources know, with different last verdicts, is a MISMATCH. Returns the count. */
static int compare_sources(struct ctx *c, const char *dir, const struct recs *tsv, const struct recs *rc)
{
    int mism = 0;
    for (size_t i = 0; i < tsv->n; i++) {
        const struct rec *a = last_of(tsv, tsv->v[i].name), *b = last_of(rc, tsv->v[i].name);
        if (a != &tsv->v[i] || !b || a->verdict == b->verdict) continue;
        char msg[LINE_MAX_LEN];
        snprintf(msg, sizeof msg, "MISMATCH %s: step %s results.tsv=%s receipts.jsonl=%s", dir, a->name,
                 vname[a->verdict], vname[b->verdict]);
        lines_add(&c->mismatch, "%s%s%s", msg, "", "");
        mism++;
    }
    return mism;
}

static struct step *step_for(struct ctx *c, const char *name)
{
    for (size_t i = 0; i < c->nsteps; i++)
        if (!strcmp(c->steps[i].name, name)) return &c->steps[i];
    c->steps = grow(c->steps, &c->capsteps, c->nsteps + 1, sizeof *c->steps);
    struct step *s = &c->steps[c->nsteps++];
    memset(s, 0, sizeof *s);
    memcpy(s->name, name, strlen(name) + 1);
    return s;
}

static void add_recs(struct ctx *c, const struct recs *r, int od)
{
    for (size_t i = 0; i < r->n; i++) {
        struct step *s = step_for(c, r->v[i].name);
        if (r->v[i].verdict == V_SKIP) { s->skip++; continue; }
        if (r->v[i].verdict == V_PASS) s->pass++;
        else s->fail++;
        s->s = grow(s->s, &s->cap, s->n + 1, sizeof *s->s);
        s->s[s->n].secs = r->v[i].secs;
        s->s[s->n++].od = od;
    }
}

static void process_outdir(struct ctx *c, const char *dir, int od)
{
    struct recs tsv = {0}, rc = {0};
    int tsv_ok = load_results(c, dir, &tsv), rc_ok = load_receipts(c, dir, &rc);
    if (tsv_ok && rc_ok) compare_sources(c, dir, &tsv, &rc);
    if (tsv_ok || rc_ok) { add_recs(c, tsv_ok ? &tsv : &rc, od); c->read++; }
    free(tsv.v);
    free(rc.v);
}

/* ---------------------------------------------------------------- statistics and output */

struct stat_row {
    const struct step *st;
    double min, med, max, last, prior;
    int has_trend;
};

static void fill_row(const struct step *st, struct stat_row *r)
{
    double *v = malloc((st->n ? st->n : 1) * sizeof *v), *pv = malloc((st->n ? st->n : 1) * sizeof *pv);
    int newest = -1;
    size_t np = 0;
    memset(r, 0, sizeof *r);
    r->st = st;
    if (!v || !pv) { free(v); free(pv); return; }
    for (size_t i = 0; i < st->n; i++) {
        v[i] = st->s[i].secs;
        if (st->s[i].od > newest) newest = st->s[i].od;
    }
    for (size_t i = 0; i < st->n; i++) {
        if (st->s[i].od == newest) r->last = st->s[i].secs;
        else pv[np++] = st->s[i].secs;
    }
    r->has_trend = np > 0 && st->n > np;
    r->prior = median_of(pv, np);
    r->med = median_of(v, st->n);
    r->min = st->n ? v[0] : 0;
    r->max = st->n ? v[st->n - 1] : 0;
    free(v);
    free(pv);
}

static int is_slower(const struct stat_row *r)
{
    return r->has_trend && r->last >= r->prior * SLOWER_RATIO && r->last - r->prior >= SLOWER_MIN_SECS;
}

static int cmp_row(const void *a, const void *b)
{
    const struct stat_row *x = a, *y = b;
    if (x->med != y->med) return x->med < y->med ? 1 : -1;
    return strcmp(x->st->name, y->st->name);
}

static struct stat_row *build_rows(const struct ctx *c, const char *only, size_t *nrows)
{
    struct stat_row *rows = calloc(c->nsteps ? c->nsteps : 1, sizeof *rows);
    size_t n = 0;
    for (size_t i = 0; rows && i < c->nsteps; i++) {
        if (only && strcmp(only, c->steps[i].name)) continue;
        fill_row(&c->steps[i], &rows[n++]);
    }
    if (rows) qsort(rows, n, sizeof *rows, cmp_row);
    *nrows = rows ? n : 0;
    return rows;
}

static void print_lines(const struct lines *l)
{
    for (size_t i = 0; i < l->n; i++) puts(l->v[i]);
}

static void print_row(const struct stat_row *r)
{
    int timed = r->st->pass + r->st->fail;
    char rate[16], mn[16] = "-", md[16] = "-", mx[16] = "-", trend[96] = "";
    if (timed) {
        snprintf(rate, sizeof rate, "%d%%", 100 * r->st->pass / timed);
        snprintf(mn, sizeof mn, "%.1f", r->min);
        snprintf(md, sizeof md, "%.1f", r->med);
        snprintf(mx, sizeof mx, "%.1f", r->max);
    } else snprintf(rate, sizeof rate, "n/a");
    if (r->has_trend)
        snprintf(trend, sizeof trend, "  last %.1fs vs prior median %.1fs%s", r->last, r->prior, is_slower(r) ? " SLOWER" : "");
    printf("%-34s %5d %6s %5d %9s %9s %9s%s\n", r->st->name, timed, rate, r->st->skip, mn, md, mx, trend);
}

static void print_text(const struct ctx *c, const struct stat_row *rows, size_t n, const char *only)
{
    printf("timings: read %d of %d outdirs\n", c->read, c->total);
    print_lines(&c->unavailable);
    print_lines(&c->mismatch);
    if (!c->read) { puts("no readable results.tsv or receipts.jsonl: nothing to report"); return; }
    printf("%-34s %5s %6s %5s %9s %9s %9s\n", "STEP", "RUNS", "PASS%", "SKIP", "MIN(s)", "MEDIAN(s)", "MAX(s)");
    for (size_t i = 0; i < n; i++) print_row(&rows[i]);
    if (!n && only) printf("step %s: no runs in the readable outdirs\n", only);
    puts("limits: wall-clock seconds under whatever load the host had; PASS and FAIL runs both count, SKIP has no time;\n"
         "  outdirs listed as unavailable are absent from every figure, not zero; outdirs are read oldest first.");
}

static void json_str(const char *s)
{
    putchar('"');
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') printf("\\%c", *s);
        else if ((unsigned char)*s < 0x20) printf("\\u%04x", (unsigned char)*s);
        else putchar(*s);
    }
    putchar('"');
}

static void json_lines(const char *key, const struct lines *l)
{
    printf(",\"%s\":[", key);
    for (size_t i = 0; i < l->n; i++) {
        if (i) putchar(',');
        json_str(l->v[i]);
    }
    putchar(']');
}

static void print_json(const struct ctx *c, const struct stat_row *rows, size_t n)
{
    printf("{\"outdirs_total\":%d,\"outdirs_read\":%d", c->total, c->read);
    json_lines("unavailable", &c->unavailable);
    json_lines("mismatch", &c->mismatch);
    printf(",\"steps\":[");
    for (size_t i = 0; i < n; i++) {
        const struct step *s = rows[i].st;
        printf("%s{\"step\":", i ? "," : "");
        json_str(s->name);
        printf(",\"runs\":%d,\"pass\":%d,\"fail\":%d,\"skip\":%d,\"min_s\":%.3f,\"median_s\":%.3f,\"max_s\":%.3f,\"slower\":%s}",
               s->pass + s->fail, s->pass, s->fail, s->skip, rows[i].min, rows[i].med, rows[i].max,
               is_slower(&rows[i]) ? "true" : "false");
    }
    puts("]}");
}

static void usage(FILE *f)
{
    fputs("usage: zcl-dev timings [--json] [--step NAME] <outdir>...\n"
          "  reads <outdir>/results.tsv (or test/, test-release/) and <outdir>/receipts.jsonl;\n"
          "  exit 0 data read, 1 MISMATCH between the two files, 2 nothing readable or bad arguments\n",
          f);
}

static int run_main(int argc, char **argv)
{
    struct ctx c = {0};
    const char *only = NULL;
    int json = 0, first = 1;
    for (; first < argc && argv[first][0] == '-' && argv[first][1]; first++) {
        if (!strcmp(argv[first], "--json")) json = 1;
        else if (!strcmp(argv[first], "--step") && first + 1 < argc) only = argv[++first];
        else { usage(stderr); return 2; }
    }
    if (first >= argc) { usage(stderr); return 2; }
    c.total = argc - first;
    for (int i = first; i < argc; i++) process_outdir(&c, argv[i], i - first);
    size_t n = 0;
    struct stat_row *rows = build_rows(&c, only, &n);
    if (json) print_json(&c, rows, n);
    else print_text(&c, rows, n, only);
    free(rows);
    return !c.read ? 2 : c.mismatch.n ? 1 : 0;
}

/* ---------------------------------------------------------------- selftest */

static int st_fail;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "selftest FAIL line %d: %s\n", __LINE__, #x); st_fail++; } } while (0)

static void selftest_tsv(void)
{
    struct rec r;
    char good[] = "unit-a\tPASS\t12", frac[] = "unit-b\tFAIL\t3.5", skip[] = "unit-c\tSKIP\t0";
    char two[] = "unit-a\tPASS", four[] = "a\tPASS\t1\tx", badv[] = "a\tpass\t1", bads[] = "a\tPASS\t-1", empty[] = "";
    char nodot[] = "a\tPASS\t1.", noname[] = "\tPASS\t1";
    CHECK(parse_tsv_line(good, &r) == 0 && r.verdict == V_PASS && r.secs == 12 && !strcmp(r.name, "unit-a"));
    CHECK(parse_tsv_line(frac, &r) == 0 && r.verdict == V_FAIL && r.secs == 3.5);
    CHECK(parse_tsv_line(skip, &r) == 0 && r.verdict == V_SKIP);
    CHECK(parse_tsv_line(two, &r) != 0 && parse_tsv_line(four, &r) != 0 && parse_tsv_line(badv, &r) != 0);
    CHECK(parse_tsv_line(bads, &r) != 0 && parse_tsv_line(empty, &r) != 0 && parse_tsv_line(nodot, &r) != 0);
    CHECK(parse_tsv_line(noname, &r) != 0);
}

static void selftest_receipt(void)
{
    struct rec r;
    char good[] = "{\"commit\":\"abc\",\"stage\":\"test-run/debug\",\"step\":\"unit-a\",\"verdict\":\"FAIL\",\"seconds\":41,"
                  "\"gcc\":\"a \\\"step\\\":\\\"x\\\" b\",\"env_names\":[\"CC\"]}";
    char nostep[] = "{\"verdict\":\"PASS\",\"seconds\":1}";
    char trunc[] = "{\"step\":\"a\",\"verdict\":\"PASS\",\"seconds\":1";
    char badsec[] = "{\"step\":\"a\",\"verdict\":\"PASS\",\"seconds\":\"1\"}";
    char junk[] = "not json";
    CHECK(parse_receipt_line(good, &r) == 0 && r.verdict == V_FAIL && r.secs == 41 && !strcmp(r.name, "unit-a"));
    CHECK(parse_receipt_line(nostep, &r) != 0 && parse_receipt_line(trunc, &r) != 0);
    CHECK(parse_receipt_line(badsec, &r) != 0 && parse_receipt_line(junk, &r) != 0);
}

static void selftest_stats(void)
{
    double a[] = {5, 1, 3}, b[] = {4, 1, 2, 3};
    struct step s = {{0}, 0, 0, 0, NULL, 0, 0};
    struct sample smp[] = {{10, 0}, {12, 1}, {30, 2}};
    struct stat_row row;
    CHECK(median_of(a, 3) == 3 && median_of(b, 4) == 2.5 && median_of(a, 0) == 0);
    s.s = smp;
    s.n = 3;
    fill_row(&s, &row);
    CHECK(row.med == 12 && row.min == 10 && row.max == 30 && row.last == 30 && row.prior == 11 && is_slower(&row));
    smp[2].secs = 13;
    fill_row(&s, &row);
    CHECK(!is_slower(&row));
}

static int selftest(void)
{
    selftest_tsv();
    selftest_receipt();
    selftest_stats();
    if (st_fail) {
        fprintf(stderr, "zcl-dev-timings selftest: %d failure(s)\n", st_fail);
        return 1;
    }
    puts("zcl-dev-timings selftest: ok");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "--purpose")) { puts(PURPOSE); return 0; }
    if (argc >= 2 && !strcmp(argv[1], "--selftest")) return selftest();
    if (argc >= 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) { usage(stdout); return 0; }
    return run_main(argc, argv);
}
