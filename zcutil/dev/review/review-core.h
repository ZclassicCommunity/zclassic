/* review-core: the review record (doc/agent/REVIEWS.tsv) and its check, shared by zcl-dev-review
 * and the pre-push hook (zcl-dev-hooks.c compiles review-core.c in). MIT, like the rest of zclassicd.
 * Plain C, libc only; gnu17 and C2x, host cc, mingw-w64 and macOS clang. git is spawned with an
 * argument vector, never through a shell. */
#ifndef ZCL_REVIEW_CORE_H
#define ZCL_REVIEW_CORE_H
#include <stddef.h>

#define RV_ROWS_PATH "doc/agent/REVIEWS.tsv"
#define RV_MSG 4096

typedef struct { char *p; size_t n; } RvBuf;
typedef struct { char **v; size_t n, cap; } RvList;

typedef struct {
    char *sha, *subject;
    RvList authors; /* lowercased trailer names, or one "human:<git author>" */
    int only_rows;  /* its only changed path is RV_ROWS_PATH */
} RvCommit;

typedef struct {
    RvCommit *v;
    size_t n, cap;
    size_t *order; /* indexes sorted by sha, for lookups */
    char base[65], tip[65];
} RvRange;

typedef struct { char *base, *tip, *tree, *reviewer, *verdict, *date, *evidence; int line; } RvRow;
typedef struct { char *text; RvRow *v; size_t n; } RvRows;

typedef struct { char *sha, *subject; const char *reason; } RvMiss;
typedef struct { RvMiss *v; size_t n, cap, commits, exempt; char base[65], tip[65]; } RvResult;

void rv_buf_free(RvBuf *b);
/* Run git with argv (argv[0] = "git", NULL-terminated), stdout captured NUL-terminated, stderr dropped.
 * Returns the exit code, or -1 when it cannot run. */
int rv_git(const char *const *argv, RvBuf *out);
/* Lowercase and keep only [a-z0-9]; the reviewer-is-author comparison. */
void rv_norm(const char *s, char *out, size_t cap);
/* Split "<base>..<tip>" (two dots only); returns 0 and fills the buffers. */
int rv_range_parse(const char *s, char *base, char *tip, size_t cap);
/* Resolve a revision to its full commit id; 0 on success. A name starting with '-' is refused. */
int rv_resolve(const char *rev, char out[65]);
/* Commits of base..tip (non-merge, oldest first). 0 ok; 2 broken (message in err). */
int rv_load_range(const char *base, const char *tip, RvRange *rg, char *err, size_t cap);
void rv_range_free(RvRange *rg);
/* Rows of RV_ROWS_PATH at `from` (a commit). 0 ok; 2 unreadable or malformed (names the line). */
int rv_load_rows(const char *from, RvRows *rows, char *err, size_t cap);
void rv_rows_free(RvRows *rows);
/* Parse one data line in place (tab separated); 0 ok else a message in err. */
int rv_parse_row(char *line, int lineno, RvRow *row, char *err, size_t cap);
int rv_rows_exist(const char *rev);
int rv_verdict_ok(const char *v);
/* Check base..tip against the rows of `rows_from` (NULL = tip). 0 covered; 1 uncovered; 2 broken. */
int rv_check_range(const char *base, const char *tip, const char *rows_from, RvResult *res, char *err, size_t cap);
void rv_result_free(RvResult *res);
/* One line for a miss: "<sha7> <subject> (<reason>)". */
void rv_miss_line(const RvMiss *m, char *out, size_t cap);
/* The pre-push gate. 0 admitted (or review not in force: neither base nor tip carries the record);
 * 1 refused, 2 broken; msg explains. */
int rv_gate(const char *base, const char *tip, char *msg, size_t cap);

#endif
