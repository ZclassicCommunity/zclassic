/* review-core.c: see review-core.h. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L /* fork, pipe, waitpid under a strict -std=c2x */
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include "review-core.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fputs("review: out of memory\n", stderr);
        exit(2);
    }
    return q;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(xrealloc(NULL, n), s, n);
}

static char *xstrndup(const char *s, size_t n)
{
    char *d = xrealloc(NULL, n + 1);
    memcpy(d, s, n);
    d[n] = 0;
    return d;
}

static void msg_set(char *err, size_t cap, const char *fmt, const char *a, const char *b)
{
    if (err && cap) snprintf(err, cap, fmt, a ? a : "", b ? b : "");
}

static void buf_add(RvBuf *b, const char *s, size_t n)
{
    b->p = xrealloc(b->p, b->n + n + 1);
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}

void rv_buf_free(RvBuf *b)
{
    free(b->p);
    b->p = NULL;
    b->n = 0;
}

static void list_push(RvList *l, const char *s)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 4;
        l->v = xrealloc(l->v, l->cap * sizeof *l->v);
    }
    l->v[l->n++] = xstrdup(s);
}

/* ---- spawning git without a shell ------------------------------------------- */

#ifdef _WIN32
/* One argument by the CommandLineToArgvW rules. */
static void quote_into(RvBuf *cmd, const char *a)
{
    if (*a && !strpbrk(a, " \t\n\v\"")) {
        buf_add(cmd, a, strlen(a));
        return;
    }
    buf_add(cmd, "\"", 1);
    for (size_t i = 0;; i++) {
        size_t bs = 0;
        while (a[i] == '\\') { bs++; i++; }
        for (size_t k = 0; k < (a[i] ? bs : 2 * bs); k++) buf_add(cmd, "\\", 1);
        if (!a[i]) break;
        if (a[i] == '"') for (size_t k = 0; k <= bs; k++) buf_add(cmd, "\\", 1);
        buf_add(cmd, &a[i], 1);
    }
    buf_add(cmd, "\"", 1);
}

int rv_git(const char *const *argv, RvBuf *out)
{
    RvBuf cmd = {NULL, 0}, b = {NULL, 0};
    SECURITY_ATTRIBUTES sa;
    HANDLE rd = NULL, wr = NULL;
    memset(&sa, 0, sizeof sa);
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    buf_add(&b, "", 0);
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        if (out) *out = b; else rv_buf_free(&b);
        return -1;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    for (size_t i = 0; argv[i]; i++) {
        if (i) buf_add(&cmd, " ", 1);
        quote_into(&cmd, argv[i]);
    }
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = wr;
    si.hStdError = nul;
    BOOL ok = CreateProcessA(NULL, cmd.p, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(wr);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    rv_buf_free(&cmd);
    int rc = -1;
    if (ok) {
        char tmp[4096];
        DWORD got, code = 1;
        while (ReadFile(rd, tmp, sizeof tmp, &got, NULL) && got > 0) buf_add(&b, tmp, got);
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        rc = (int)code;
    }
    CloseHandle(rd);
    if (out) *out = b; else rv_buf_free(&b);
    return rc;
}
#else
static void child_exec(const char *const *argv, int wfd)
{
    int nul = open("/dev/null", O_RDWR);
    if (nul >= 0) {
        dup2(nul, 0);
        dup2(nul, 2);
    }
    dup2(wfd, 1);
    execvp("git", (char *const *)argv);
    _exit(127);
}

int rv_git(const char *const *argv, RvBuf *out)
{
    RvBuf b = {NULL, 0};
    int fd[2];
    buf_add(&b, "", 0);
    if (pipe(fd) != 0) {
        if (out) *out = b; else rv_buf_free(&b);
        return -1;
    }
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        if (out) *out = b; else rv_buf_free(&b);
        return -1;
    }
    if (pid == 0) {
        close(fd[0]);
        child_exec(argv, fd[1]);
    }
    close(fd[1]);
    char tmp[4096];
    ssize_t got;
    while ((got = read(fd[0], tmp, sizeof tmp)) > 0) buf_add(&b, tmp, (size_t)got);
    close(fd[0]);
    int st = 0, rc = -1;
    if (waitpid(pid, &st, 0) == pid) rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
    if (out) *out = b; else rv_buf_free(&b);
    return rc;
}
#endif

static void trim_eol(RvBuf *b)
{
    while (b->n && (b->p[b->n - 1] == '\n' || b->p[b->n - 1] == '\r')) b->p[--b->n] = 0;
}

/* ---- small parsers ----------------------------------------------------------- */

static int is_hex(const char *s, size_t len)
{
    if (strlen(s) != len) return 0;
    for (; *s; s++) if (!isxdigit((unsigned char)*s)) return 0;
    return 1;
}

static int is_sha(const char *s) { return is_hex(s, 40) || is_hex(s, 64); }

void rv_norm(const char *s, char *out, size_t cap)
{
    size_t o = 0;
    for (; *s && o + 1 < cap; s++)
        if (isalnum((unsigned char)*s)) out[o++] = (char)tolower((unsigned char)*s);
    out[o] = 0;
}

int rv_range_parse(const char *s, char *base, char *tip, size_t cap)
{
    const char *dd = strstr(s, "..");
    if (!dd || dd == s || !dd[2] || dd[2] == '.' || strstr(dd + 2, "..")) return -1;
    size_t bl = (size_t)(dd - s), tl = strlen(dd + 2);
    if (bl >= cap || tl >= cap) return -1;
    memcpy(base, s, bl);
    base[bl] = 0;
    memcpy(tip, dd + 2, tl + 1);
    return 0;
}

int rv_verdict_ok(const char *v)
{
    return !strcmp(v, "ACCEPT") || !strcmp(v, "ACCEPT-WITH-FIXES") || !strcmp(v, "REJECT");
}

static int safe_rev(const char *rev)
{
    return rev[0] && rev[0] != '-' && strlen(rev) < 256 && !strpbrk(rev, " \t\r\n");
}

int rv_resolve(const char *rev, char out[65])
{
    char spec[300];
    if (!safe_rev(rev)) return -1;
    snprintf(spec, sizeof spec, "%s^{commit}", rev);
    const char *av[] = {"git", "rev-parse", "--verify", "-q", spec, NULL};
    RvBuf b;
    int rc = rv_git(av, &b);
    trim_eol(&b);
    int ok = rc == 0 && is_sha(b.p);
    if (ok) snprintf(out, 65, "%s", b.p);
    rv_buf_free(&b);
    return ok ? 0 : -1;
}

/* ---- commits of a range -------------------------------------------------------- */

static void author_from_trailer(RvList *a, const char *line, size_t len)
{
    char *t = xstrndup(line, len), *lt = strchr(t, '<');
    if (lt) *lt = 0;
    size_t n = strlen(t), s = 0;
    while (s < n && isspace((unsigned char)t[s])) s++;
    while (n > s && isspace((unsigned char)t[n - 1])) n--;
    t[n] = 0;
    for (char *p = t + s; *p; p++) *p = *p == ',' ? ' ' : (char)tolower((unsigned char)*p);
    if (n > s) list_push(a, t + s);
    free(t);
}

static void trailer_authors(RvList *a, const char *trailers)
{
    for (const char *l = trailers; *l;) {
        const char *e = strchr(l, '\n');
        size_t len = e ? (size_t)(e - l) : strlen(l);
        author_from_trailer(a, l, len);
        l += len + (e ? 1 : 0);
    }
}

static void paths_only_rows(RvCommit *c, const char *paths)
{
    size_t n = 0, other = 0;
    for (const char *l = paths; *l;) {
        const char *e = strchr(l, '\n');
        size_t len = e ? (size_t)(e - l) : strlen(l);
        if (len) {
            n++;
            if (len != strlen(RV_ROWS_PATH) || strncmp(l, RV_ROWS_PATH, len)) other++;
        }
        l += len + (e ? 1 : 0);
    }
    c->only_rows = n > 0 && !other;
}

static void commit_add(RvRange *rg, char *rec)
{
    char *f[4];
    char *p = rec;
    for (int i = 0; i < 4; i++) {
        f[i] = p;
        p = strchr(p, '\x1f');
        if (!p) return;
        *p++ = 0;
    }
    if (rg->n == rg->cap) {
        rg->cap = rg->cap ? rg->cap * 2 : 16;
        rg->v = xrealloc(rg->v, rg->cap * sizeof *rg->v);
    }
    RvCommit *c = &rg->v[rg->n++];
    memset(c, 0, sizeof *c);
    c->sha = xstrdup(f[0]);
    c->subject = xstrdup(f[2]);
    for (char *s = c->subject; *s; s++) if ((unsigned char)*s < 0x20) *s = ' ';
    trailer_authors(&c->authors, f[3]);
    if (!c->authors.n) {
        char who[300];
        snprintf(who, sizeof who, "human:%s", f[1]);
        for (char *s = who; *s; s++) *s = *s == ',' ? ' ' : (char)tolower((unsigned char)*s);
        list_push(&c->authors, who);
    }
    paths_only_rows(c, p);
}

static void parse_log(char *text, RvRange *rg)
{
    for (char *r = strchr(text, '\x1e'); r;) {
        char *next = strchr(r + 1, '\x1e');
        if (next) *next = 0;
        commit_add(rg, r + 1);
        r = next;
    }
}

static const RvRange *cmp_ctx;
static int cmp_idx(const void *a, const void *b)
{
    return strcmp(cmp_ctx->v[*(const size_t *)a].sha, cmp_ctx->v[*(const size_t *)b].sha);
}

static void build_order(RvRange *rg)
{
    rg->order = xrealloc(NULL, (rg->n + 1) * sizeof *rg->order);
    for (size_t i = 0; i < rg->n; i++) rg->order[i] = i;
    cmp_ctx = rg;
    if (rg->n > 1) qsort(rg->order, rg->n, sizeof *rg->order, cmp_idx);
}

static long range_find(const RvRange *rg, const char *sha)
{
    size_t lo = 0, hi = rg->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = strcmp(rg->v[rg->order[mid]].sha, sha);
        if (!c) return (long)rg->order[mid];
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return -1;
}

int rv_load_range(const char *base, const char *tip, RvRange *rg, char *err, size_t cap)
{
    memset(rg, 0, sizeof *rg);
    if (rv_resolve(base, rg->base) != 0) { msg_set(err, cap, "bad range: %s is not a commit", base, NULL); return 2; }
    if (rv_resolve(tip, rg->tip) != 0) { msg_set(err, cap, "bad range: %s is not a commit", tip, NULL); return 2; }
    const char *anc[] = {"git", "merge-base", "--is-ancestor", rg->base, rg->tip, NULL};
    int rc = rv_git(anc, NULL);
    if (rc == 1) { msg_set(err, cap, "bad range: %s is not an ancestor of %s", base, tip); return 2; }
    if (rc != 0) { msg_set(err, cap, "cannot run git merge-base for %s..%s", base, tip); return 2; }
    char spec[140];
    snprintf(spec, sizeof spec, "%s..%s", rg->base, rg->tip);
    const char *log[] = {"git", "-c", "core.quotepath=off", "log", "--no-merges", "--reverse", "--no-renames", "--name-only",
                         "--format=%x1e%H%x1f%an%x1f%s%x1f%(trailers:key=Co-Authored-By,valueonly,unfold)%x1f", spec, NULL};
    RvBuf b;
    if (rv_git(log, &b) != 0) { rv_buf_free(&b); msg_set(err, cap, "git log failed for %s", spec, NULL); return 2; }
    parse_log(b.p, rg);
    rv_buf_free(&b);
    build_order(rg);
    return 0;
}

void rv_range_free(RvRange *rg)
{
    for (size_t i = 0; i < rg->n; i++) {
        free(rg->v[i].sha);
        free(rg->v[i].subject);
        for (size_t k = 0; k < rg->v[i].authors.n; k++) free(rg->v[i].authors.v[k]);
        free(rg->v[i].authors.v);
    }
    free(rg->v);
    free(rg->order);
    memset(rg, 0, sizeof *rg);
}

/* ---- rows -------------------------------------------------------------------------- */

static int date_ok(const char *d)
{
    static const char shape[] = "dddd-dd-ddTdd:dd:ddZ";
    if (strlen(d) != strlen(shape)) return 0;
    for (size_t i = 0; shape[i]; i++)
        if (shape[i] == 'd' ? !isdigit((unsigned char)d[i]) : d[i] != shape[i]) return 0;
    return 1;
}

static int range_field_ok(const char *r)
{
    char a[80], b[80];
    return rv_range_parse(r, a, b, sizeof a) == 0 && is_sha(a) && is_sha(b) && strlen(a) == strlen(b);
}

static int row_fields_ok(const RvRow *r, char *err, size_t cap)
{
    const char *bad = NULL;
    if (!range_field_ok(r->base)) bad = "range is not <base>..<tip> of full commit ids";
    else if (!is_sha(r->tree)) bad = "tip_tree is not a full object id";
    else if (!r->reviewer[0]) bad = "reviewer is empty";
    else if (!rv_verdict_ok(r->verdict)) bad = "verdict is not ACCEPT, ACCEPT-WITH-FIXES or REJECT";
    else if (!date_ok(r->date)) bad = "date is not YYYY-MM-DDTHH:MM:SSZ";
    else if (strlen(r->evidence) > 200) bad = "evidence is longer than 200 characters";
    if (bad) snprintf(err, cap, "%s line %d: %s", RV_ROWS_PATH, r->line, bad);
    return bad == NULL;
}

static int split_tabs(char *line, char **f, int n)
{
    char *p = line;
    for (int i = 0; i < n; i++) {
        f[i] = p;
        if (i == n - 1) break;
        p = strchr(p, '\t');
        if (!p) return -1;
        *p++ = 0;
    }
    return strchr(f[n - 1], '\t') ? -1 : 0;
}

int rv_parse_row(char *line, int lineno, RvRow *row, char *err, size_t cap)
{
    char *f[7];
    if (split_tabs(line, f, 7) != 0) {
        snprintf(err, cap, "%s line %d: expected 7 tab-separated fields", RV_ROWS_PATH, lineno);
        return -1;
    }
    row->base = f[0]; /* the range field; split at the dots below */
    row->tree = f[1];
    row->reviewer = f[3];
    row->verdict = f[4];
    row->date = f[5];
    row->evidence = f[6];
    row->tip = NULL;
    row->line = lineno;
    if (!row_fields_ok(row, err, cap)) return -1;
    char *dd = strstr(row->base, "..");
    *dd = 0;
    row->tip = dd + 2;
    return 0;
}

int rv_load_rows(const char *from, RvRows *rows, char *err, size_t cap)
{
    memset(rows, 0, sizeof *rows);
    char spec[300];
    if (!safe_rev(from)) { msg_set(err, cap, "bad revision %s", from, NULL); return 2; }
    snprintf(spec, sizeof spec, "%s:%s", from, RV_ROWS_PATH);
    const char *av[] = {"git", "show", spec, NULL};
    RvBuf b;
    if (rv_git(av, &b) != 0) { rv_buf_free(&b); msg_set(err, cap, "cannot read " RV_ROWS_PATH " at %s", from, NULL); return 2; }
    rows->text = b.p;
    size_t cap_rows = 0;
    int lineno = 0;
    for (char *l = rows->text; l && *l;) {
        char *e = strchr(l, '\n');
        if (e) *e = 0;
        lineno++;
        size_t len = strlen(l);
        if (len && l[len - 1] == '\r') l[--len] = 0;
        if (len && l[0] != '#') {
            if (rows->n == cap_rows) {
                cap_rows = cap_rows ? cap_rows * 2 : 16;
                rows->v = xrealloc(rows->v, cap_rows * sizeof *rows->v);
            }
            if (rv_parse_row(l, lineno, &rows->v[rows->n], err, cap) != 0) {
                rv_rows_free(rows);
                return 2;
            }
            rows->n++;
        }
        l = e ? e + 1 : NULL;
    }
    return 0;
}

void rv_rows_free(RvRows *rows)
{
    free(rows->text);
    free(rows->v);
    memset(rows, 0, sizeof *rows);
}

int rv_rows_exist(const char *rev)
{
    char spec[300];
    if (!safe_rev(rev)) return 0;
    snprintf(spec, sizeof spec, "%s:%s", rev, RV_ROWS_PATH);
    const char *av[] = {"git", "cat-file", "-e", spec, NULL};
    return rv_git(av, NULL) == 0;
}

/* ---- the check ------------------------------------------------------------------------ */

enum { ROW_UNUSABLE, ROW_STALE, ROW_LIVE };

typedef struct { int state, rewritten; unsigned char *hit; } RowSet;

static int row_state(const RvRow *row)
{
    char tipc[65], spec[300];
    if (rv_resolve(row->tip, tipc) != 0) return ROW_UNUSABLE;
    snprintf(spec, sizeof spec, "%s^{tree}", tipc);
    const char *av[] = {"git", "rev-parse", "--verify", "-q", spec, NULL};
    RvBuf b;
    int rc = rv_git(av, &b);
    trim_eol(&b);
    int same = rc == 0 && !strcmp(b.p, row->tree);
    rv_buf_free(&b);
    return same ? ROW_LIVE : ROW_STALE;
}

/* Mark the range commits that descend from the row's base and are ancestors-or-equal of its tip. */
static void row_hits(const RvRange *rg, const RvRow *row, RowSet *rs)
{
    char spec[200];
    snprintf(spec, sizeof spec, "%s..%s", row->base, row->tip);
    const char *av[] = {"git", "rev-list", "--ancestry-path", spec, NULL};
    RvBuf b;
    if (rv_git(av, &b) != 0) {
        rv_buf_free(&b);
        rs->state = ROW_UNUSABLE;
        return;
    }
    for (char *l = b.p; *l;) {
        char *e = strchr(l, '\n');
        if (e) *e = 0;
        long i = range_find(rg, l);
        if (i >= 0) rs->hit[i] = 1;
        l = e ? e + 1 : l + strlen(l);
    }
    rv_buf_free(&b);
}

static int is_own_author(const RvCommit *c, const char *reviewer)
{
    char rn[300], an[300];
    rv_norm(reviewer, rn, sizeof rn);
    for (size_t i = 0; i < c->authors.n; i++) {
        const char *a = c->authors.v[i];
        if (!strncmp(a, "human:", 6)) a += 6;
        rv_norm(a, an, sizeof an);
        if (!strcmp(an, rn)) return 1;
    }
    return 0;
}

typedef struct { int covered, rejected, stale, author; } Verdict;

static void apply_row(Verdict *v, const RvCommit *c, const RvRow *row, int state)
{
    if (!strcmp(row->verdict, "REJECT")) {
        v->rejected = 1;
        v->covered = 0;
    } else if (state == ROW_STALE) {
        v->stale = 1;
    } else if (is_own_author(c, row->reviewer)) {
        v->author = 1;
    } else {
        v->covered = 1;
        v->rejected = 0;
    }
}

/* A row whose base precedes the commit, and whose tip is no longer in the history being checked, is stale for
 * that commit: it was written for history that has since been rewritten. A row for an older, intact range that
 * simply does not reach the commit is not stale; the commit has no row. */
static int base_precedes(const RvRow *row, const char *sha)
{
    const char *av[] = {"git", "merge-base", "--is-ancestor", row->base, sha, NULL};
    return rv_git(av, NULL) == 0;
}

static const char *reason_of(const Verdict *v)
{
    if (v->covered) return NULL;
    if (v->rejected) return "rejected";
    if (v->author) return "reviewer is author";
    if (v->stale) return "stale row";
    return "no row";
}

static const char *judge_commit(const RvRange *rg, size_t ci, const RvRows *rows, const RowSet *sets)
{
    Verdict v = {0, 0, 0, 0};
    for (size_t r = 0; r < rows->n; r++)
        if (sets[r].state != ROW_UNUSABLE && sets[r].hit[ci]) apply_row(&v, &rg->v[ci], &rows->v[r], sets[r].state);
    const char *why = reason_of(&v);
    if (why && !strcmp(why, "no row"))
        for (size_t r = 0; r < rows->n; r++)
            if (sets[r].rewritten && strcmp(rows->v[r].verdict, "REJECT") && base_precedes(&rows->v[r], rg->v[ci].sha)) return "stale row";
    return why;
}

static void miss_add(RvResult *res, const RvCommit *c, const char *why)
{
    if (res->n == res->cap) {
        res->cap = res->cap ? res->cap * 2 : 16;
        res->v = xrealloc(res->v, res->cap * sizeof *res->v);
    }
    res->v[res->n++] = (RvMiss){xstrdup(c->sha), xstrdup(c->subject), why};
}

/* The row tip is the checked tip or one of its ancestors. */
static int tip_in_history(const RvRow *row, const char *checked_tip)
{
    const char *av[] = {"git", "merge-base", "--is-ancestor", row->tip, checked_tip, NULL};
    return rv_git(av, NULL) == 0;
}

static void check_commits(const RvRange *rg, const RvRows *rows, RvResult *res)
{
    RowSet *sets = xrealloc(NULL, (rows->n + 1) * sizeof *sets);
    for (size_t r = 0; r < rows->n; r++) {
        sets[r].hit = xrealloc(NULL, rg->n + 1);
        memset(sets[r].hit, 0, rg->n + 1);
        sets[r].state = row_state(&rows->v[r]);
        sets[r].rewritten = sets[r].state != ROW_LIVE || !tip_in_history(&rows->v[r], rg->tip);
        if (sets[r].state != ROW_UNUSABLE) row_hits(rg, &rows->v[r], &sets[r]);
    }
    for (size_t i = 0; i < rg->n; i++) {
        if (rg->v[i].only_rows) {
            res->exempt++;
            continue;
        }
        res->commits++;
        const char *why = judge_commit(rg, i, rows, sets);
        if (why) miss_add(res, &rg->v[i], why);
    }
    for (size_t r = 0; r < rows->n; r++) free(sets[r].hit);
    free(sets);
}

int rv_check_range(const char *base, const char *tip, const char *rows_from, RvResult *res, char *err, size_t cap)
{
    RvRange rg;
    RvRows rows;
    memset(res, 0, sizeof *res);
    int rc = rv_load_range(base, tip, &rg, err, cap);
    if (rc) return rc;
    snprintf(res->base, sizeof res->base, "%s", rg.base);
    snprintf(res->tip, sizeof res->tip, "%s", rg.tip);
    rc = rv_load_rows(rows_from ? rows_from : tip, &rows, err, cap);
    if (rc == 0) {
        check_commits(&rg, &rows, res);
        rv_rows_free(&rows);
        rc = res->n ? 1 : 0;
    }
    rv_range_free(&rg);
    return rc;
}

void rv_result_free(RvResult *res)
{
    for (size_t i = 0; i < res->n; i++) {
        free(res->v[i].sha);
        free(res->v[i].subject);
    }
    free(res->v);
    memset(res, 0, sizeof *res);
}

void rv_miss_line(const RvMiss *m, char *out, size_t cap)
{
    snprintf(out, cap, "%.7s %s (%s)", m->sha, m->subject, m->reason);
}

/* ---- the pre-push gate ------------------------------------------------------------------- */

static void gate_message(const RvResult *res, char *msg, size_t cap)
{
    size_t w = (size_t)snprintf(msg, cap, "%zu of %zu commits in %.7s..%.7s have no accepted review in " RV_ROWS_PATH ":",
                                res->n, res->commits, res->base, res->tip);
    for (size_t i = 0; i < res->n && i < 20 && w < cap; i++) {
        char line[600];
        rv_miss_line(&res->v[i], line, sizeof line);
        w += (size_t)snprintf(msg + w, cap - w, "\n    %s", line);
    }
    if (res->n > 20 && w < cap) w += (size_t)snprintf(msg + w, cap - w, "\n    ... and %zu more", res->n - 20);
    if (w < cap)
        snprintf(msg + w, cap - w,
                 "\n  A reviewer who is not an author records a verdict, then the record is committed:\n"
                 "    zcl-dev review record --reviewer <name> --verdict ACCEPT %.7s..%.7s\n"
                 "    git commit -m \"review: record %.7s..%.7s\" -- " RV_ROWS_PATH "\n"
                 "  ZCL_PUSH_OK does not waive review; only `git push --no-verify` does, as the operator's explicit choice",
                 res->base, res->tip, res->base, res->tip);
}

int rv_gate(const char *base, const char *tip, char *msg, size_t cap)
{
    msg[0] = 0;
    if (!rv_rows_exist(base) && !rv_rows_exist(tip)) return 0; /* review is not in force on this line of history */
    RvResult res;
    char err[RV_MSG];
    err[0] = 0;
    int rc = rv_check_range(base, tip, NULL, &res, err, sizeof err);
    if (rc == 1) gate_message(&res, msg, cap);
    else if (rc == 2) snprintf(msg, cap, "review check is broken: %s", err);
    rv_result_free(&res);
    return rc;
}
