/* automake: reads the _SOURCES, _LDADD and _PROGRAMS/_LIBRARIES variables of the autotools
 * Makefile.am family so tools can answer "which targets compile this file". MIT, like the rest
 * of zclassicd. Libc only. Conditionals are ignored (every branch counts, an else-branch
 * assignment adds to the variable); $(VAR) and ${VAR} expand recursively. */
#ifndef ZCUTIL_AUTOMAKE_H
#define ZCUTIL_AUTOMAKE_H
#include "gitfiles.h"

typedef struct {
    char *name;      /* display name: libbitcoin_server.a, zclassicd, test/test_bitcoin */
    ZList sources;   /* repo-relative paths of the files listed in *_SOURCES */
    ZList ldadd;     /* expanded *_LDADD / *_LIBADD tokens */
    int is_program;
    int is_test;     /* name contains "test" */
} AmTarget;

typedef struct { AmTarget *t; size_t n, cap; } Automake;

/* Loads each makefile in order, as one namespace (Makefile.am includes the .include files).
 * Sources are made repo-relative with the directory of the first makefile. Returns 0 if at
 * least one file was read. */
int am_load(Automake *am, const ZList *makefiles);
/* Targets whose *_SOURCES list path (repo-relative). */
void am_targets_for(const Automake *am, const char *path, ZList *out);
/* Programs that must relink when target name changes: the program itself, or every program
 * whose LDADD names the library. */
void am_relinks(const Automake *am, const char *name, ZList *out);
const AmTarget *am_find(const Automake *am, const char *name);
void am_free(Automake *am);

#endif
