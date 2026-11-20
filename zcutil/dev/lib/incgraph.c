/* incgraph: see incgraph.h. MIT, like the rest of zclassicd. */
#include "incgraph.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cxxscan.h"

int ig_is_tu(const char *p)
{
    return zd_has_suffix(p, ".c") || zd_has_suffix(p, ".cc") || zd_has_suffix(p, ".cpp") || zd_has_suffix(p, ".cxx");
}

int ig_is_source(const char *p)
{
    return ig_is_tu(p) || zd_has_suffix(p, ".h") || zd_has_suffix(p, ".hpp") || zd_has_suffix(p, ".hh") ||
           zd_has_suffix(p, ".hxx") || zd_has_suffix(p, ".inc");
}

static char *dir_of(const char *p, char *buf, size_t cap)
{
    const char *s = strrchr(p, '/');
    size_t n = s ? (size_t)(s - p) : 0;
    if (n >= cap) n = cap - 1;
    memcpy(buf, p, n);
    buf[n] = 0;
    return buf;
}

static long try_resolve(const ZList *files, const char *dir, const char *name)
{
    char cand[1100], norm[1100];
    if (dir[0]) snprintf(cand, sizeof cand, "%s/%s", dir, name);
    else snprintf(cand, sizeof cand, "%s", name);
    zd_norm_path(cand, norm, sizeof norm);
    return zd_find(files, norm);
}

void ig_build(IncGraph *g, const ZList *files, const ZList *incdirs, int (*skip)(const char *, void *), void *ctx)
{
    size_t n = files->n;
    memset(g, 0, sizeof *g);
    g->files = files;
    g->fwd = zd_xrealloc(NULL, n * sizeof *g->fwd);
    g->nfwd = zd_xrealloc(NULL, n * sizeof *g->nfwd);
    g->rev = zd_xrealloc(NULL, n * sizeof *g->rev);
    g->nrev = zd_xrealloc(NULL, n * sizeof *g->nrev);
    int *revcap = zd_xrealloc(NULL, n * sizeof *revcap);
    for (size_t i = 0; i < n; i++) {
        g->fwd[i] = NULL;
        g->nfwd[i] = 0;
        g->rev[i] = NULL;
        g->nrev[i] = 0;
        revcap[i] = 0;
    }
    for (size_t i = 0; i < n; i++) {
        const char *p = files->v[i];
        if (!ig_is_source(p) || (skip && skip(p, ctx))) continue;
        size_t len = 0;
        char *src = zd_read_file(p, &len);
        if (!src) continue;
        CxxIncs incs = {0};
        cxx_includes(src, len, &incs);
        free(src);
        char dir[1024];
        dir_of(p, dir, sizeof dir);
        int *seen = NULL, nseen = 0;
        for (size_t k = 0; k < incs.n; k++) {
            const CxxInc *e = &incs.v[k];
            long t = -1;
            if (!e->angle) t = try_resolve(files, dir, e->name);
            for (size_t d = 0; t < 0 && d < incdirs->n; d++) t = try_resolve(files, incdirs->v[d], e->name);
            if (t < 0) {
                if (!e->angle) g->unresolved++;
                continue;
            }
            if (t == (long)i) continue;
            int dup = 0;
            for (int s = 0; s < nseen; s++)
                if (seen[s] == t) dup = 1;
            if (dup) continue;
            seen = zd_xrealloc(seen, (size_t)(nseen + 1) * sizeof *seen);
            seen[nseen++] = (int)t;
        }
        cxx_free_incs(&incs);
        g->fwd[i] = seen;
        g->nfwd[i] = nseen;
        for (int s = 0; s < nseen; s++) {
            int t = seen[s];
            if (g->nrev[t] == revcap[t]) {
                revcap[t] = revcap[t] ? revcap[t] * 2 : 4;
                g->rev[t] = zd_xrealloc(g->rev[t], (size_t)revcap[t] * sizeof(int));
            }
            g->rev[t][g->nrev[t]++] = (int)i;
        }
    }
    free(revcap);
}

size_t ig_reverse_closure(const IncGraph *g, int start, int maxdepth, int **order, int **dist)
{
    size_t n = g->files->n, head = 0, tail = 0;
    int *q = zd_xrealloc(NULL, n * sizeof *q);
    int *d = zd_xrealloc(NULL, n * sizeof *d);
    char *seen = zd_xrealloc(NULL, n);
    memset(seen, 0, n);
    seen[start] = 1;
    q[tail] = start;
    d[tail++] = 0;
    while (head < tail) {
        int u = q[head], du = d[head++];
        if (maxdepth && du >= maxdepth) continue;
        for (int k = 0; k < g->nrev[u]; k++) {
            int v = g->rev[u][k];
            if (seen[v]) continue;
            seen[v] = 1;
            q[tail] = v;
            d[tail++] = du + 1;
        }
    }
    free(seen);
    /* drop start (index 0) */
    for (size_t i = 1; i < tail; i++) {
        q[i - 1] = q[i];
        d[i - 1] = d[i];
    }
    *order = q;
    *dist = d;
    return tail - 1;
}

void ig_free(IncGraph *g)
{
    for (size_t i = 0; i < g->files->n; i++) {
        free(g->fwd[i]);
        free(g->rev[i]);
    }
    free(g->fwd);
    free(g->nfwd);
    free(g->rev);
    free(g->nrev);
    memset(g, 0, sizeof *g);
}
