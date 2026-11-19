/* zcl-lint wiring: the rule table, its documentation and what `zcl-lint all` runs must be one list. C, libc only.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_lint_gate_wiring.c@9a191ef7b1184e14d9116362dff7def64cd300e3;
 * modified, not verbatim. See zcutil/tools/NOTICE.
 *
 * Three lists must agree: the rule names in zcutil/lint/rules.def (read as text from the tree), the names this
 * binary was compiled with (what `zcl-lint all` runs; a difference means a stale binary), and the documented
 * list in doc/local-ci.md between <!-- LINT-RULES-BEGIN --> and <!-- LINT-RULES-END -->, one `name` in
 * backticks per line. A rule missing from the document, a documented name that is not a rule, a duplicate, or a
 * missing or empty block fails (exit 1); an unreadable rules.def or document is exit 2.
 */
#define _POSIX_C_SOURCE 200809L
#include "../lintlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIRING_DOC "doc/local-ci.md"
#define WIRING_DEF "zcutil/lint/rules.def"
#define BLOCK_BEGIN "<!-- LINT-RULES-BEGIN -->"
#define BLOCK_END "<!-- LINT-RULES-END -->"

#define LINT_RULE(name, fn, baseline) name,
static const char *const compiled[] = {
#include "../rules.def"
};
#undef LINT_RULE
#define NCOMPILED (sizeof compiled / sizeof compiled[0])

struct names { char **v; size_t n, cap; };

static void names_add(struct names *s, const char *name, size_t len)
{
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 32;
        s->v = lint_xrealloc(s->v, s->cap * sizeof *s->v);
    }
    char *c = lint_xrealloc(NULL, len + 1);
    memcpy(c, name, len);
    c[len] = '\0';
    s->v[s->n++] = c;
}

static bool names_has(const struct names *s, const char *name)
{
    for (size_t i = 0; i < s->n; i++)
        if (!strcmp(s->v[i], name)) return true;
    return false;
}

static void names_free(struct names *s)
{
    for (size_t i = 0; i < s->n; i++) free(s->v[i]);
    free(s->v);
}

/* Names in rules.def: the quoted first argument of each LINT_RULE( row that is not a comment. */
static bool read_def(struct names *out)
{
    char *txt = lint_slurp(WIRING_DEF, NULL);
    if (!txt) return false;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        if (!lint_has_prefix(line, "LINT_RULE(\"")) continue;
        const char *s = line + strlen("LINT_RULE(\"");
        const char *e = strchr(s, '"');
        if (e) names_add(out, s, (size_t)(e - s));
    }
    free(txt);
    return true;
}

/* Documented names: the first `backticked` word of each line of the block. *state: 0 before, 1 inside, 2 closed. */
static int read_doc(struct names *out, bool *readable)
{
    char *txt = lint_slurp(WIRING_DOC, NULL);
    *readable = txt != NULL;
    if (!txt) return 0;
    int state = 0;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        if (strstr(line, BLOCK_BEGIN)) { state = 1; continue; }
        if (strstr(line, BLOCK_END)) { if (state == 1) state = 2; continue; }
        if (state != 1) continue;
        const char *a = strchr(line, '`');
        const char *b = a ? strchr(a + 1, '`') : NULL;
        if (a && b && b > a + 1) names_add(out, a + 1, (size_t)(b - a - 1));
    }
    free(txt);
    return state;
}

static int dups(const struct names *s, const char *what)
{
    int bad = 0;
    for (size_t i = 0; i < s->n; i++)
        for (size_t j = 0; j < i; j++)
            if (!strcmp(s->v[i], s->v[j])) { printf("FAIL wiring: '%s' appears twice in %s\n", s->v[i], what); bad++; break; }
    return bad;
}

/* Rule table against the documented list and the compiled table. Returns the number of problems. */
static int compare_lists(const struct names *def, const struct names *doc, int state)
{
    int bad = 0;
    if (state != 2) {
        printf("FAIL wiring: %s has no closed %s ... %s block\n", WIRING_DOC, BLOCK_BEGIN, BLOCK_END);
        bad++;
    } else if (doc->n == 0) {
        printf("FAIL wiring: the documented rule list in %s is empty\n", WIRING_DOC);
        bad++;
    }
    bad += dups(def, WIRING_DEF) + dups(doc, WIRING_DOC);
    for (size_t i = 0; i < doc->n; i++)
        if (!names_has(def, doc->v[i])) {
            printf("FAIL wiring: %s documents '%s', which is not a rule in %s\n", WIRING_DOC, doc->v[i], WIRING_DEF);
            bad++;
        }
    for (size_t i = 0; state == 2 && i < def->n; i++)
        if (!names_has(doc, def->v[i])) {
            printf("FAIL wiring: rule '%s' is in %s but not in the documented list in %s\n", def->v[i], WIRING_DEF, WIRING_DOC);
            bad++;
        }
    return bad;
}

static bool compiled_has(const char *name)
{
    for (size_t j = 0; j < NCOMPILED; j++)
        if (!strcmp(compiled[j], name)) return true;
    return false;
}

/* What `zcl-lint all` runs (this binary's table) against rules.def: a difference is a stale build. */
static int compare_compiled(const struct names *def)
{
    int bad = 0;
    for (size_t i = 0; i < def->n; i++)
        if (!compiled_has(def->v[i])) {
            printf("FAIL wiring: rule '%s' is in %s but this zcl-lint binary does not run it (stale build)\n", def->v[i], WIRING_DEF);
            bad++;
        }
    for (size_t j = 0; j < NCOMPILED; j++)
        if (!names_has(def, compiled[j])) {
            printf("FAIL wiring: this zcl-lint binary runs '%s', which is not in %s (stale build)\n", compiled[j], WIRING_DEF);
            bad++;
        }
    return bad;
}

int lint_rule_wiring(bool update)
{
    (void)update;
    struct names def = { NULL, 0, 0 }, doc = { NULL, 0, 0 };
    bool doc_ok;
    if (!read_def(&def) || def.n == 0) {
        fprintf(stderr, "zcl-lint wiring: cannot read any rule from %s\n", WIRING_DEF);
        names_free(&def);
        return 2;
    }
    int state = read_doc(&doc, &doc_ok);
    if (!doc_ok) {
        fprintf(stderr, "zcl-lint wiring: cannot read %s\n", WIRING_DOC);
        names_free(&def);
        return 2;
    }
    int bad = compare_lists(&def, &doc, state) + compare_compiled(&def);
    size_t n = def.n;
    names_free(&def);
    names_free(&doc);
    if (bad) return 1;
    printf("wiring: ok (%zu rules in the table, the document and `zcl-lint all`)\n", n);
    return 0;
}
