/* zcl-lint doc-paths: backticked repository paths in Markdown must exist. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_doc_inline_paths.c@9a191ef7b1184e14d9116362dff7def64cd300e3,
 * modified (one resolution rule, no suffix index), not verbatim; see zcutil/tools/NOTICE.
 *
 * A `code span` on one line of a tracked *.md file (outside code fences) is a path claim when it holds no
 * spaces, contains a '/', and either ends in a known source or document extension (prong 1) or starts with the
 * name of a tracked top-level directory (prong 2). It must resolve, from the repository root or from the
 * document's own directory, to a tracked file or directory. A trailing :LINE, #anchor or punctuation is ignored;
 * globs and placeholders (* ? < > { } $) and the build outputs zcutil/bin and zcutil/gen are skipped.
 * `<!-- doc-path-ok -->` anywhere on a line exempts that line. Shrink-only baseline zcutil/lint/doc-paths.txt,
 * a count per document.
 */
#define _POSIX_C_SOURCE 200809L
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const exts[] = {
    "c", "h", "cc", "cpp", "hpp", "inc", "def", "sh", "md", "txt", "tsv", "json", "jsonl", "am", "ac", "mk", "in",
    "yml", "yaml", "toml", "pro", "qrc", "ui", "cfg", "conf", "plist", "rules", "patch", "html", "js", "css",
};

struct finding { char *doc; long line; char *tok; };
struct findings { struct finding *v; size_t n, cap; };

static bool path_char(unsigned char c)
{
    return isalnum(c) || strchr("_./+@-%,=~", c) != NULL;
}

static bool known_ext(const char *p)
{
    const char *dot = strrchr(p, '.'), *sl = strrchr(p, '/');
    if (!dot || (sl && dot < sl) || !dot[1]) return false;
    for (size_t i = 0; i < sizeof exts / sizeof exts[0]; i++)
        if (!strcmp(dot + 1, exts[i])) return true;
    return false;
}

/* True when the first component of p names a directory that holds tracked files. */
static bool top_dir(const char *p)
{
    char d[300];
    size_t n = strcspn(p, "/");
    if (!p[n] || n >= sizeof d) return false;
    snprintf(d, sizeof d, "%.*s", (int)n, p);
    return lint_dir_tracked(d);
}

/* Collapse ./ and ../ segments of dir/target. NULL when it escapes the repository. */
static char *join_norm(const char *dir, const char *target, char *out, size_t cap)
{
    char tmp[1700];
    snprintf(tmp, sizeof tmp, "%s%s%s", dir, *dir ? "/" : "", target);
    size_t o = 0;
    out[0] = '\0';
    for (char *seg = strtok(tmp, "/"); seg; seg = strtok(NULL, "/")) {
        if (!strcmp(seg, ".") || !*seg) continue;
        if (!strcmp(seg, "..")) {
            if (!o) return NULL;
            while (o && out[o - 1] != '/') o--;
            if (o) o--;
            out[o] = '\0';
            continue;
        }
        if (o + strlen(seg) + 2 >= cap) return NULL;
        o += (size_t)snprintf(out + o, cap - o, "%s%s", o ? "/" : "", seg);
    }
    return out;
}

/* A tracked path (or directory) ending in /tok: documents under src/ name files from src/ or src/c23 downwards. */
static bool suffix_match(const char *tok)
{
    char t[1100], mid[1104];
    snprintf(t, sizeof t, "%s", tok);
    size_t n = strlen(t);
    while (n > 1 && t[n - 1] == '/') t[--n] = 0;
    snprintf(mid, sizeof mid, "/%s/", t);
    for (size_t i = 0; i < lint_nfiles; i++) {
        const char *f = lint_files[i];
        size_t fl = strlen(f);
        if (fl > n && f[fl - n - 1] == '/' && !strcmp(f + fl - n, t)) return true;
        if (strstr(f, mid)) return true;
    }
    return false;
}

/* Build outputs named in documents are git-ignored paths. */
static bool ignored(const char *tok)
{
    char *argv[] = { "git", "-C", (char *)lint_root, "check-ignore", "-q", "--no-index", "--", (char *)tok, NULL };
    return lint_run_argv(argv, true) == 0;
}

static bool resolves(const char *docdir, const char *p)
{
    char n[1100];
    if (join_norm("", p, n, sizeof n) && *n && (lint_is_tracked(n) || lint_dir_tracked(n))) return true;
    if (*docdir && join_norm(docdir, p, n, sizeof n) && *n && (lint_is_tracked(n) || lint_dir_tracked(n))) return true;
    return suffix_match(p) || ignored(p);
}

/* Does the code span look like a path claim? On yes, tok receives the cleaned path. */
static bool claim_token(const char *span, char *tok, size_t cap)
{
    snprintf(tok, cap, "%s", span);
    char *h = strchr(tok, '#');
    if (h) *h = '\0';
    size_t n = strlen(tok);
    while (n && strchr(".,;:)", tok[n - 1])) tok[--n] = '\0';
    char *c = strrchr(tok, ':');                                             /* path:LINE or path:LINE-LINE */
    if (c && c[1] && strspn(c + 1, "0123456789-") == strlen(c + 1)) *c = '\0';
    if (!tok[0] || !strchr(tok, '/') || strstr(tok, "://") || strstr(tok, "//") || strstr(tok, "...")) return false;
    for (const char *s = tok; *s; s++)
        if (!path_char((unsigned char)*s)) return false;
    if (tok[0] == '/' || tok[0] == '-' || tok[0] == '~' || tok[0] == '%') return false;
    if (lint_has_prefix(tok, "zcutil/bin/") || lint_has_prefix(tok, "zcutil/gen/") || !strcmp(tok, "zcutil/bin") ||
        !strcmp(tok, "zcutil/gen"))
        return false;
    return known_ext(tok) || top_dir(tok);
}

static void add_finding(struct findings *f, const char *doc, long line, const char *tok)
{
    if (f->n == f->cap) { f->cap = f->cap ? f->cap * 2 : 32; f->v = lint_xrealloc(f->v, f->cap * sizeof *f->v); }
    f->v[f->n++] = (struct finding){ lint_xstrdup(doc), line, lint_xstrdup(tok) };
}

static long scan_doc(const char *md, char *txt, struct findings *f)
{
    char docdir[600];
    snprintf(docdir, sizeof docdir, "%s", md);
    char *sl = strrchr(docdir, '/');
    if (sl) *sl = '\0'; else docdir[0] = '\0';
    bool fence = false;
    long ln = 0, bad = 0;
    for (char *l = txt; l && *l;) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        ln++;
        char *t = l;
        while (*t == ' ') t++;
        if (lint_has_prefix(t, "```") || lint_has_prefix(t, "~~~")) fence = !fence;
        else if (!fence && strchr(l, '`') && !strstr(l, "<!-- doc-path-ok -->") && !strstr(l, "<!--doc-path-ok-->")) {
            for (size_t i = 0; l[i];) {
                if (l[i] != '`') { i++; continue; }
                size_t run = 0;
                while (l[i + run] == '`') run++;
                size_t k = i + run;
                bool closed = false;
                size_t end = 0;
                while (l[k]) {
                    size_t r = 0;
                    while (l[k + r] == '`') r++;
                    if (r == run) { closed = true; end = k; k += r; break; }
                    k += r ? r : 1;
                }
                if (!closed) { i += run; continue; }
                char span[700], tok[700];
                size_t len = end - (i + run);
                if (len < sizeof span) {
                    snprintf(span, sizeof span, "%.*s", (int)len, l + i + run);
                    if (claim_token(span, tok, sizeof tok) && !resolves(docdir, tok)) { bad++; add_finding(f, md, ln, tok); }
                }
                i = k;
            }
        }
        l = nl ? nl + 1 : NULL;
    }
    return bad;
}

int lint_rule_doc_paths(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    struct findings f = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!lint_has_suffix(lint_files[i], ".md") || lint_is_vendored(lint_files[i])) continue;
        char *txt = lint_slurp(lint_files[i], NULL);
        if (!txt) continue;
        scanned++;
        long bad = scan_doc(lint_files[i], txt, &f);
        if (bad) lint_rows_add(&cur, lint_files[i], bad);
        free(txt);
    }
    int rc = lint_ratchet("doc-paths", "backticked repository paths that do not resolve to a tracked file", &cur, scanned, update);
    if (rc == 1 && !update)                                                    /* name every unresolved path with file:line */
        for (size_t i = 0; i < f.n; i++)
            printf("FAIL doc-paths: %s:%ld: `%s` does not resolve to a tracked file (fix it, or add <!-- doc-path-ok -->)\n",
                   f.v[i].doc, f.v[i].line, f.v[i].tok);
    return rc;
}
