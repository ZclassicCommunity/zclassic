/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_hardening_ratchet.c, gate_no_new_bash.c and gate_markdown_links.c
 * @1f5d0f69448c4811884b2c918ae0723ab24830da, and (helper semantics) Z23 tools/lint/lintc/lib.c and
 * tools/lint/strip_c_comments.awk@9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim. See NOTICE.
 */
#ifndef ZCL_LINTLIB_H
#define ZCL_LINTLIB_H
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Shared by the driver (zcl-lint.c) and every rule (rules/<rule>.c). A rule is one file under rules/ plus one
 * row in rules.def; it needs nothing but this header. */

extern const char *lint_root;  /* --root DIR, default "." */
/* consensus-seal ritual flags, set by the driver from --reseal and --reason (defined in zcl-lint.c). */
extern bool lint_reseal;
extern const char *lint_reason;

/* Checked allocation helpers: abort with exit 2 on out of memory. */
void *lint_xrealloc(void *p, size_t n);
char *lint_xstrdup(const char *s);
char *lint_rootpath(const char *rel);              /* malloc'd "<root>/<rel>" */
char *lint_slurp(const char *rel, size_t *len);    /* whole tracked file, NUL-terminated; NULL if unreadable */
bool lint_has_prefix(const char *s, const char *p);
bool lint_has_suffix(const char *s, const char *x);
int lint_cmp_str(const void *a, const void *b);
/* Child processes run from an argv array, never through a shell: no --root, tracked file name or document token
 * can break out of quoting. Windows refuses arguments cmd.exe could read as syntax. */
#define LINT_PROC_QUIET 1   /* stdout and stderr to the null device, no pipe */
#define LINT_PROC_MERGE 2   /* stderr joins the stdout pipe */
#define LINT_PROC_INHERIT 4 /* no pipe: the child shares our stdout and stderr */
struct lint_proc { FILE *fp; long pid; };
int lint_proc_open(struct lint_proc *p, const char *cwd, char *const argv[], int flags); /* 0, or -1 */
int lint_proc_close(struct lint_proc *p);          /* exit status 0..255, -1 when it could not run or was killed */
int lint_status_argv(const char *cwd, char *const argv[], bool quiet);  /* exit status or -1 */
int lint_run_argv(char *const argv[], bool quiet); /* 0 on success, 2 when it exited 2 (hollow scan), else 1 */
char *lint_git_out(char *const args[], size_t *len); /* stdout of git -C <root> <args>; NULL on failure */

/* Git tracked-file iteration (git ls-files -z), sorted bytewise. Loaded once by lint_load_tracked(). */
extern char **lint_files;
extern size_t lint_nfiles;
void lint_load_tracked(void);                      /* exits 2 when git fails or tracks nothing */
bool lint_is_tracked(const char *path);
bool lint_dir_tracked(const char *dir);
/* The one vendored/third-party exclusion list: edits there belong to the vendor rule, not a style gate. */
bool lint_is_vendored(const char *path);

/* File kinds. */
bool lint_is_shell_file(const char *path);         /* .sh/.bash or a sh/bash/dash/ksh shebang */
bool lint_shebang_is_shell(const char *txt);
bool lint_shebang_is_bash(const char *txt);
bool lint_is_c_source(const char *path);           /* .c .cc .cpp .cxx .h .hh .hpp .inc */
bool lint_idc(int c);                              /* identifier character */

/* Comment and string stripping, in place, one line at a time; blanked bytes become spaces so columns hold. */
void lint_scrub_c_line(char *s, bool *in_block);   /* C and C++: comments, string and char literals */
void lint_scrub_sh_line(char *s, char *quote);     /* sh: # comments, quoted text; *quote carries \' or " across lines */

/* Baselines: rows "<path><TAB><count>" in zcutil/lint/<rule>.txt, shrink-only. */
struct lint_row { char *path; long count; };
struct lint_rows { struct lint_row *v; size_t n, cap; };
void lint_rows_add(struct lint_rows *r, const char *path, long count);
int lint_cmp_row(const void *a, const void *b);
long lint_rows_find(const struct lint_rows *r, const char *path);
/* Compare findings with the baseline. Returns 0 clean, 1 findings, 2 broken or hollow: scanned == 0 is a
 * failure, never a pass. */
int lint_ratchet(const char *rule, const char *what, struct lint_rows *cur, size_t scanned, bool update);
/* For rules without a baseline: 0 when scanned > 0, else prints FAIL and returns 2. */
int lint_hollow(const char *rule, size_t scanned);

#endif
