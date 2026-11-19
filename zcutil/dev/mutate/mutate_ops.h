/* zcl-dev mutate: mutation operators. Pure text in, sites out; no I/O.
 *
 * Derived from Z23 tools/dev/mutation_harness.h@9a191ef7b, Apache-2.0; changed. See zcutil/tools/NOTICE
 *
 * A site is one realistic defect at one byte offset: replace `span` bytes at `offset` with `repl`.
 * Sites are only found in code the compiler reads: comments, string and character literals, C++ raw
 * strings and every preprocessor directive except #define are masked out. The classes:
 *   relational  ` < ` <-> ` <= `, ` > ` <-> ` >= `, ` == ` <-> ` != ` (whitespace on both sides only,
 *               so template brackets, `<<` and `>>` are never touched)
 *   logical     ` && ` <-> ` || `
 *   boundary    a decimal integer literal n -> n+1 and n-1 (n-1 only when n > 0); never a part of an
 *               identifier, a float, a hex or octal literal, or the n of `[n]`
 *   return      `return true;` <-> `return false;`
 *   statement   a one-line call statement ending in `);` -> `(void)0;`
 * C, libc only; gnu17 that also compiles as c2x.
 */
#ifndef ZCL_MUTATE_OPS_H
#define ZCL_MUTATE_OPS_H

#include <stdbool.h>
#include <stddef.h>

enum mut_class {
    MUT_RELATIONAL = 0,
    MUT_LOGICAL,
    MUT_BOUNDARY,
    MUT_RETURN,
    MUT_STATEMENT,
    MUT_CLASS_COUNT
};

#define MUT_TEXT_MAX 64

struct mut_site {
    size_t offset;              /* byte offset of the replaced text */
    size_t span;                /* bytes replaced */
    size_t line;                /* 1-based */
    size_t column;              /* 1-based byte column of offset */
    enum mut_class cls;
    char orig[MUT_TEXT_MAX];    /* replaced text, elided with "..." when longer */
    char repl[MUT_TEXT_MAX];    /* the exact replacement */
};

struct mut_sites {
    struct mut_site *v;
    size_t n, cap;
};

const char *mut_class_name(enum mut_class c);
/* Parses a comma list of class names into a bit set (bit i = class i). False on an unknown name. */
bool mut_class_parse(const char *list, unsigned *bits);

/* The code mask: one byte per input byte, 1 where the compiler reads code. */
void mut_code_mask(const char *text, size_t len, unsigned char *mask);

/* Appends every site of `text` to `out` in offset order. False only when memory runs out. */
bool mut_enumerate(const char *text, size_t len, struct mut_sites *out);
void mut_sites_free(struct mut_sites *s);

/* The mutated image for one site: a fresh NUL-terminated buffer the caller frees, or NULL. */
char *mut_apply(const char *text, size_t len, const struct mut_site *s, size_t *out_len);

/* ---- the driver (zcl-dev-mutate.c and mutate_run.c; these do I/O) ---------------------------- */
#include <stdio.h>

struct mut_opts {
    const char *file;
    size_t lo, hi;      /* --lines A-B; 0 and SIZE_MAX when absent */
    unsigned classes;   /* --class bit set; every class when absent */
    bool json;
    size_t max;         /* --max; SIZE_MAX when absent */
    long timeout;       /* --timeout seconds, for the build and for the test */
    const char *build;  /* --build words, split on single spaces */
    char **test;        /* the test argv after --, NULL-terminated */
};

char *mut_read_file(const char *path, size_t *len);
/* Keeps only the sites inside --lines and --class. */
void mut_filter(struct mut_sites *s, const struct mut_opts *o);
void mut_print_site(FILE *f, const struct mut_site *s);
void mut_json_site(FILE *f, const struct mut_site *s);
void mut_json_str(FILE *f, const char *s);

int mut_run(const struct mut_opts *o);  /* exit 0 no survivors, 1 survivors, 2 broken */
int mut_restore(const char *file);      /* exit 0 restored, 2 refused or broken */

#endif
