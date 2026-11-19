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
 * can break out of quoting. On Windows the argv is quoted into one CreateProcess command line by the MSVCRT rules
 * (lint_win_quote_argv); a script (*.sh, or a file that starts with #!) runs as `sh.exe <script> args...` with
 * sh.exe found on PATH, and a missing program prints "UNAVAILABLE: <name> not found on PATH". */
#define LINT_PROC_QUIET 1     /* stdout and stderr to the null device, no pipe */
#define LINT_PROC_MERGE 2     /* stderr joins the stdout pipe */
#define LINT_PROC_INHERIT 4   /* no pipe: the child shares our stdout and stderr */
#define LINT_PROC_TO_STDERR 8 /* no pipe: the child's stdout is our stderr */
#define LINT_PROC_NOERR 16    /* the child's stderr goes to the null device */
#define LINT_PROC_UNAVAILABLE (-2) /* lint_proc_open: the program (or sh for a script) is not on PATH */
#ifdef _WIN32
#define LINT_EXE ".exe"
#else
#define LINT_EXE ""
#endif
struct lint_proc { FILE *fp; long pid; void *handle; };
int lint_proc_open(struct lint_proc *p, const char *cwd, char *const argv[], int flags); /* 0, -1 or UNAVAILABLE */
int lint_proc_close(struct lint_proc *p);          /* exit status 0..255, -1 when it could not run or was killed */
int lint_status_argv(const char *cwd, char *const argv[], bool quiet);  /* exit status, -1 or UNAVAILABLE */
int lint_run_argv(char *const argv[], bool quiet); /* 0 on success, 2 when it exited 2 (hollow scan) or is unavailable, else 1 */
char *lint_git_out(char *const args[], size_t *len); /* stdout of git -C <root> <args>; NULL on failure */
/* MSVCRT command line of argv: an argument that is empty or holds space, tab, a quote, or a character an MSYS
 * child would glob or unquote (' * ? [ { ~) is wrapped in double quotes; backslashes before a quote or the closing
 * quote are doubled and " becomes \". Returns the length written to out, or -1 when it does not fit in cap.
 * Platform-neutral so it is unit-tested everywhere. */
int lint_win_quote_argv(char *const argv[], char *out, size_t cap);
/* malloc'd "<root>/<rel>.exe" (Windows) or "<root>/<rel>" when that file exists, else NULL. */
char *lint_tool_path(const char *rel);

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
