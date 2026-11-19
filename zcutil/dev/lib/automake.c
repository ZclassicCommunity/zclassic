/* automake: see automake.h. MIT, like the rest of zclassicd. */
#include "automake.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *name, *value; } Var;
typedef struct { Var *v; size_t n, cap; } Vars;

static Var *var_find(Vars *vs, const char *name)
{
    for (size_t i = 0; i < vs->n; i++)
        if (!strcmp(vs->v[i].name, name)) return &vs->v[i];
    return NULL;
}

static void var_set(Vars *vs, const char *name, const char *value, int append)
{
    Var *v = var_find(vs, name);
    if (!v) {
        if (vs->n == vs->cap) {
            vs->cap = vs->cap ? vs->cap * 2 : 128;
            vs->v = zd_xrealloc(vs->v, vs->cap * sizeof *vs->v);
        }
        v = &vs->v[vs->n++];
        v->name = zd_xstrdup(name);
        v->value = zd_xstrdup("");
    }
    if (append) {
        size_t a = strlen(v->value), b = strlen(value);
        v->value = zd_xrealloc(v->value, a + b + 2);
        v->value[a] = ' ';
        memcpy(v->value + a + 1, value, b + 1);
    } else {
        free(v->value);
        v->value = zd_xstrdup(value);
    }
}

/* Appends the expansion of s to *out (a malloc()ed string). */
static void expand(Vars *vs, const char *s, char **out, size_t *len, size_t *cap, int depth)
{
    for (size_t i = 0; s[i];) {
        if (s[i] == '$' && (s[i + 1] == '(' || s[i + 1] == '{')) {
            char close = s[i + 1] == '(' ? ')' : '}';
            const char *e = strchr(s + i + 2, close);
            if (e) {
                char name[128];
                size_t nl = (size_t)(e - (s + i + 2));
                if (nl < sizeof name) {
                    memcpy(name, s + i + 2, nl);
                    name[nl] = 0;
                    i = (size_t)(e - s) + 1;
                    if (!strcmp(name, "srcdir") || !strcmp(name, "top_srcdir")) {
                        if (s[i] == '/') i++;
                        continue;
                    }
                    Var *v = var_find(vs, name);
                    if (v && depth < 12) expand(vs, v->value, out, len, cap, depth + 1);
                    if (*len + 2 >= *cap) *out = zd_xrealloc(*out, *cap = *cap ? *cap * 2 : 256);
                    (*out)[(*len)++] = ' '; /* a variable never glues to its neighbours */
                    continue;
                }
            }
        }
        if (*len + 2 >= *cap) *out = zd_xrealloc(*out, *cap = *cap ? *cap * 2 : 256);
        (*out)[(*len)++] = s[i++];
    }
    if (*out) (*out)[*len] = 0;
}

static void tokens(const char *s, ZList *out)
{
    size_t i = 0;
    while (s[i]) {
        while (s[i] && isspace((unsigned char)s[i])) i++;
        size_t b = i;
        while (s[i] && !isspace((unsigned char)s[i])) i++;
        if (i > b) {
            char *t = zd_xrealloc(NULL, i - b + 1);
            memcpy(t, s + b, i - b);
            t[i - b] = 0;
            if (t[0] != '$' && t[0] != '-' && t[0] != '@') zlist_push(out, t);
            free(t);
        }
    }
}

static void expand_tokens(Vars *vs, const char *name, ZList *out)
{
    Var *v = var_find(vs, name);
    if (!v) return;
    char *buf = NULL;
    size_t len = 0, cap = 0;
    expand(vs, v->value, &buf, &len, &cap, 0);
    if (buf) tokens(buf, out);
    free(buf);
}

static void canon(const char *in, char *out, size_t cap)
{
    size_t i = 0;
    for (; in[i] && i + 1 < cap; i++) out[i] = isalnum((unsigned char)in[i]) ? in[i] : '_';
    out[i] = 0;
}

static AmTarget *target_for(Automake *am, const char *name)
{
    for (size_t i = 0; i < am->n; i++)
        if (!strcmp(am->t[i].name, name)) return &am->t[i];
    if (am->n == am->cap) {
        am->cap = am->cap ? am->cap * 2 : 32;
        am->t = zd_xrealloc(am->t, am->cap * sizeof *am->t);
    }
    AmTarget *t = &am->t[am->n++];
    memset(t, 0, sizeof *t);
    t->name = zd_xstrdup(name);
    return t;
}

/* Reads one makefile into vs; first-seen variable names are appended to order. */
static int read_makefile(Vars *vs, const char *path, ZList *order)
{
    size_t n = 0;
    char *src = zd_read_file(path, &n);
    if (!src) return -1;
    char *line = NULL;
    size_t lcap = 0;
    int ifstack[32] = {0}, depth = 0;
    size_t i = 0;
    while (i < n) {
        size_t ll = 0;
        int recipe = src[i] == '\t';
        for (;;) { /* join backslash continuations */
            size_t j = i;
            while (j < n && src[j] != '\n') j++;
            size_t e = j;
            if (e > i && src[e - 1] == '\r') e--;
            int cont = e > i && src[e - 1] == '\\';
            if (cont) e--;
            if (ll + (e - i) + 3 >= lcap) line = zd_xrealloc(line, lcap = (ll + (e - i)) * 2 + 64);
            memcpy(line + ll, src + i, e - i);
            ll += e - i;
            line[ll++] = ' ';
            i = j < n ? j + 1 : n;
            if (!cont || i >= n) break;
        }
        line[ll] = 0;
        if (recipe) continue;
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        size_t pl = strlen(p);
        while (pl && isspace((unsigned char)p[pl - 1])) p[--pl] = 0;
        if (!*p) continue;
        if (!strncmp(p, "if", 2) && (isspace((unsigned char)p[2]) || !strncmp(p, "ifdef", 5) || !strncmp(p, "ifndef", 6) ||
                                      !strncmp(p, "ifeq", 4) || !strncmp(p, "ifneq", 5))) {
            if (depth < 31) ifstack[++depth] = 0;
            continue;
        }
        if (!strcmp(p, "else") || !strncmp(p, "else ", 5)) {
            if (depth) ifstack[depth] = 1;
            continue;
        }
        if (!strcmp(p, "endif")) {
            if (depth) depth--;
            continue;
        }
        int in_else = 0;
        for (int d = 1; d <= depth; d++)
            if (ifstack[d]) in_else = 1;
        size_t k = 0; /* assignment: NAME [+:?]= value */
        while (p[k] && (isalnum((unsigned char)p[k]) || p[k] == '_' || p[k] == '.' || p[k] == '@')) k++;
        if (k == 0 || k >= 160) continue;
        char name[160];
        memcpy(name, p, k);
        name[k] = 0;
        size_t q = k;
        while (p[q] == ' ' || p[q] == '\t') q++;
        int append = 0;
        if (p[q] == '+' && p[q + 1] == '=') {
            append = 1;
            q += 2;
        } else if ((p[q] == ':' || p[q] == '?') && p[q + 1] == '=') {
            q += 2;
        } else if (p[q] == '=') {
            q++;
        } else {
            continue;
        }
        if (in_else) append = 1;
        while (p[q] == ' ' || p[q] == '\t') q++;
        if (!var_find(vs, name)) zlist_push(order, name);
        var_set(vs, name, p + q, append);
    }
    free(line);
    free(src);
    return 0;
}

int am_load(Automake *am, const ZList *makefiles)
{
    memset(am, 0, sizeof *am);
    Vars vs = {0};
    ZList order = {0};
    int any = 0;
    for (size_t f = 0; f < makefiles->n; f++)
        if (!read_makefile(&vs, makefiles->v[f], &order)) any = 1;
    char prefix[512] = "";
    if (makefiles->n) {
        const char *s = strrchr(makefiles->v[0], '/');
        if (s) {
            size_t l = (size_t)(s - makefiles->v[0]) + 1;
            if (l < sizeof prefix) {
                memcpy(prefix, makefiles->v[0], l);
                prefix[l] = 0;
            }
        }
    }
    /* display names come from the PROGRAMS / LIBRARIES lists */
    ZList disp = {0}, progs = {0};
    for (size_t i = 0; i < order.n; i++) {
        const char *nm = order.v[i];
        int isprog = zd_has_suffix(nm, "_PROGRAMS");
        if (isprog || zd_has_suffix(nm, "_LIBRARIES") || zd_has_suffix(nm, "_LTLIBRARIES")) {
            ZList t = {0};
            expand_tokens(&vs, nm, &t);
            for (size_t k = 0; k < t.n; k++) {
                if (!zlist_has(&disp, t.v[k])) zlist_push(&disp, t.v[k]);
                if (isprog && !zlist_has(&progs, t.v[k])) zlist_push(&progs, t.v[k]);
            }
            zlist_free(&t);
        }
    }
    for (size_t i = 0; i < order.n; i++) {
        const char *nm = order.v[i];
        int src = zd_has_suffix(nm, "_SOURCES");
        int ld = zd_has_suffix(nm, "_LDADD") || zd_has_suffix(nm, "_LIBADD");
        if (!src && !ld) continue;
        char base[160];
        snprintf(base, sizeof base, "%s", nm);
        base[strlen(base) - (src ? 8 : (zd_has_suffix(nm, "_LDADD") ? 6 : 7))] = 0;
        const char *b = base;
        if (!strncmp(b, "nodist_", 7)) b += 7;
        if (!strncmp(b, "dist_", 5)) b += 5;
        char dn[160];
        const char *shown = b;
        for (size_t k = 0; k < disp.n; k++) {
            canon(disp.v[k], dn, sizeof dn);
            if (!strcmp(dn, b)) {
                shown = disp.v[k];
                break;
            }
        }
        AmTarget *t = target_for(am, shown);
        t->is_program = zlist_has(&progs, shown);
        t->is_test = strstr(shown, "test") != NULL;
        ZList toks = {0};
        expand_tokens(&vs, nm, &toks);
        for (size_t k = 0; k < toks.n; k++) {
            if (src) {
                char full[1100];
                snprintf(full, sizeof full, "%s%s", prefix, toks.v[k]);
                if (!zlist_has(&t->sources, full)) zlist_push(&t->sources, full);
            } else {
                zlist_push(&t->ldadd, toks.v[k]);
            }
        }
        zlist_free(&toks);
    }
    for (size_t i = 0; i < vs.n; i++) {
        free(vs.v[i].name);
        free(vs.v[i].value);
    }
    free(vs.v);
    zlist_free(&order);
    zlist_free(&disp);
    zlist_free(&progs);
    return any ? 0 : -1;
}

const AmTarget *am_find(const Automake *am, const char *name)
{
    for (size_t i = 0; i < am->n; i++)
        if (!strcmp(am->t[i].name, name)) return &am->t[i];
    return NULL;
}

void am_targets_for(const Automake *am, const char *path, ZList *out)
{
    for (size_t i = 0; i < am->n; i++)
        if (zlist_has(&am->t[i].sources, path) && !zlist_has(out, am->t[i].name)) zlist_push(out, am->t[i].name);
}

void am_relinks(const Automake *am, const char *name, ZList *out)
{
    const AmTarget *self = am_find(am, name);
    if (self && self->is_program) {
        if (!zlist_has(out, name)) zlist_push(out, name);
        return;
    }
    for (size_t i = 0; i < am->n; i++)
        if (am->t[i].is_program && zlist_has(&am->t[i].ldadd, name) && !zlist_has(out, am->t[i].name))
            zlist_push(out, am->t[i].name);
}

void am_free(Automake *am)
{
    for (size_t i = 0; i < am->n; i++) {
        free(am->t[i].name);
        zlist_free(&am->t[i].sources);
        zlist_free(&am->t[i].ldadd);
    }
    free(am->t);
    memset(am, 0, sizeof *am);
}
