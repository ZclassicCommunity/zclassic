/* gitfiles: tracked-file enumeration, file reading and small list helpers for zcl-dev code.
 * MIT, like the rest of zclassicd. Libc only; builds with gcc, clang and mingw-w64. */
#ifndef ZCUTIL_GITFILES_H
#define ZCUTIL_GITFILES_H
#include <stddef.h>

typedef struct { char **v; size_t n, cap; } ZList;

void zd_die(const char *fmt, ...); /* "zcl-dev code: ..." on stderr, exit 2 */
void *zd_xrealloc(void *p, size_t n);
char *zd_xstrdup(const char *s);
void zlist_push(ZList *l, const char *s);
int zlist_has(const ZList *l, const char *s);
void zlist_free(ZList *l);
/* Runs a shell command and collects its stdout lines. Returns 0 when the command ran and
 * exited 0, -1 otherwise. Callers pass only arguments made of [A-Za-z0-9_./:=,-]. */
int zd_cmd_lines(const char *cmd, ZList *out);
/* git ls-files, sorted bytewise. Returns 0 on success. */
int zd_git_ls(ZList *out);
/* Index of s in a sorted list, or -1. */
long zd_find(const ZList *sorted, const char *s);
/* Whole file, NUL terminated; *n receives the length. NULL when unreadable. */
char *zd_read_file(const char *path, size_t *n);
/* chdir to the repository root (the one containing the current directory). */
void zd_enter_repo(void);
/* Normalises a user path: backslashes to slashes, leading "./" removed, "a/../b" collapsed.
 * Writes into out. */
void zd_norm_path(const char *in, char *out, size_t cap);
int zd_has_prefix(const char *s, const char *p);
int zd_has_suffix(const char *s, const char *x);

#endif
