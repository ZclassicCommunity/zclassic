/* cxxscan: a small C/C++ lexer for developer tools. MIT, like the rest of zclassicd.
 * Plain C, libc only, gnu17 and C23 clean; builds with gcc, clang and mingw-w64.
 *
 * It masks comments, string and character literals (including raw strings) and preprocessor
 * directives, tracks braces, and lists the top-level definitions of a translation unit:
 * functions (free, member, constructors, operators, test macros such as BOOST_AUTO_TEST_CASE)
 * and classes/structs. namespace bodies, extern "C" bodies and class bodies are transparent
 * scopes; function bodies, enums and initialisers are skipped by brace matching. U3 owns this
 * lexer; the complexity counter of U7 links it.
 */
#ifndef ZCUTIL_CXXSCAN_H
#define ZCUTIL_CXXSCAN_H
#include <stddef.h>

enum { CXX_FUNC = 0, CXX_CLASS = 1 };

typedef struct {
    char name[192];  /* Class::Method as written, class scopes prefixed; macro(arg) for test macros */
    char alias[96];  /* the first macro argument of BOOST_AUTO_TEST_CASE(arg), else empty */
    int kind;        /* CXX_FUNC or CXX_CLASS */
    int start_line;  /* first line of the header, 1-based */
    int end_line;    /* line of the closing brace */
    size_t start_off, open_off, end_off; /* byte offsets: header start, {, } */
} CxxDef;

typedef struct { CxxDef *v; size_t n, cap; } CxxDefs;

typedef struct {
    char name[256];
    int angle; /* 1 for <...>, 0 for "..." */
    int line;
} CxxInc;

typedef struct { CxxInc *v; size_t n, cap; } CxxIncs;

/* Returns a malloc()ed copy of src (n bytes, NUL terminated) in which comments and the contents
 * of string and character literals are blanked to spaces (newlines kept). Quote characters stay. */
char *cxx_mask(const char *src, size_t n);
/* Blanks every preprocessor directive line (with continuations) of a masked buffer in place. */
void cxx_blank_directives(char *masked, size_t n);
/* Collects the #include directives of src. */
void cxx_includes(const char *src, size_t n, CxxIncs *out);
/* Collects the top-level definitions of src, in source order. */
void cxx_defs(const char *src, size_t n, CxxDefs *out);
/* 1-based line of a byte offset. */
int cxx_line_of(const char *src, size_t off);
/* Does a definition answer to query? Exact name, last "::" component, or macro argument. */
int cxx_def_matches(const CxxDef *d, const char *query);
void cxx_free_defs(CxxDefs *d);
void cxx_free_incs(CxxIncs *d);

#endif
