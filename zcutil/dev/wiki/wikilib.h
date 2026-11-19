/* Shared helpers of zcl-dev-wiki, -read, -lessons and -know. MIT, like the rest of zclassicd.
 * Plain C, libc only, gnu17 and c2x clean; builds with the host cc, mingw and macOS clang.
 * The tools are designed after Z23's wiki, read, lessons and know commands
 * (tools/command/native_wiki_*.c, engine/composition/fleet_facts.def); no Z23 code is copied. */
#ifndef ZCL_WIKILIB_H
#define ZCL_WIKILIB_H

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700 /* popen, realpath, lstat, strcasecmp under a strict -std=c2x */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under a POSIX-only mask */
#endif
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1 /* %zu works only with the C99 printf */
#endif
#include <stddef.h>
#include <stdio.h>

#define REPLY_MAX 16384 /* every reply stays under 16 KiB */
#define TEXT_MAX 240    /* one summary or title, in bytes */
#define PATH_CAP 4096

typedef struct { char **v; size_t n, cap; } List;
typedef struct { char *p; size_t n, cap; } Buf;

extern int g_json; /* --json given */
extern const char *g_argv0; /* argv[0], for the executable directory where /proc is absent */

void die(const char *fmt, ...);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
void list_push(List *l, const char *s);
int list_has(const List *l, const char *s);
void list_free(List *l);

void buf_add(Buf *b, const char *s);
void buf_addn(Buf *b, const char *s, size_t n);
void buf_printf(Buf *b, const char *fmt, ...);
void buf_json(Buf *b, const char *s); /* a quoted JSON string; invalid UTF-8 bytes become '?' */
void buf_free(Buf *b);

int has_prefix(const char *s, const char *p);
int has_suffix(const char *s, const char *x);
int contains_ci(const char *hay, const char *needle);
char *trim(char *s);                     /* in place; returns s advanced past leading blanks */
void clip_text(char *s, size_t max);     /* cut at a UTF-8 boundary, with "..." appended */

/* Print a failure reply (plain on stderr, JSON on stdout) and return 2. */
int fail_reply(const char *code, const char *message, const char *evidence);
/* The tracked files of the repository in the current directory; dies when there are none. */
void git_files(List *out);
/* Whole file, malloc()ed and NUL-terminated; NULL when unreadable. At most max bytes. */
char *read_file(const char *path, size_t max, size_t *len);
/* Lines of a file (CR stripped); returns 0 when readable. */
int file_lines(const char *path, List *out);
/* Absolute path with symlinks resolved; 0 on success. */
int real_path(const char *p, char *out, size_t cap);
/* Links rendered as plain text: [t](u) and ![t](u) become t, <u> becomes u. */
void link_render(const char *in, char *out, size_t cap);
/* First paragraph of Markdown text, links rendered, clipped to TEXT_MAX. */
void md_summary(const char *text, char *out, size_t cap);
/* First "# " heading of Markdown text, links rendered; "" when none. */
void md_title(const char *text, char *out, size_t cap);
/* A zcl-dev subcommand name resolves (built in, or a zcl-dev-<cmd> binary exists). */
int sub_resolves(const char *cmd);

int cmd_wiki(int argc, char **argv);
int cmd_read(int argc, char **argv);
int cmd_lessons(int argc, char **argv);
int cmd_know(int argc, char **argv);

#endif
