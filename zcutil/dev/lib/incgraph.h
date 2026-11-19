/* incgraph: the #include graph of the tracked C/C++ files. MIT, like the rest of zclassicd.
 * An edge A -> B means A has #include of B, resolved to a tracked file: the including file's
 * directory first (quoted includes only), then each include directory in order. */
#ifndef ZCUTIL_INCGRAPH_H
#define ZCUTIL_INCGRAPH_H
#include "gitfiles.h"

typedef struct {
    const ZList *files;  /* all tracked files, sorted; node i is files->v[i] */
    int **fwd;           /* includes of node i */
    int *nfwd;
    int **rev;           /* includers of node i */
    int *nrev;
    size_t unresolved;   /* quoted includes that matched no tracked file */
} IncGraph;

/* skip(path, ctx) != 0 leaves a file out of the scan (vendored trees): it stays a valid target. */
void ig_build(IncGraph *g, const ZList *files, const ZList *incdirs, int (*skip)(const char *, void *), void *ctx);
/* True for a path the graph scans (C/C++ source or header extension). */
int ig_is_source(const char *path);
int ig_is_tu(const char *path); /* .c .cc .cpp .cxx */
/* Reverse closure of start: nodes that include it directly or transitively, nearest first,
 * start excluded. dist[k] is the include distance of order[k]. maxdepth 0 means unlimited. */
size_t ig_reverse_closure(const IncGraph *g, int start, int maxdepth, int **order, int **dist);
void ig_free(IncGraph *g);

#endif
