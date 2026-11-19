/* zcl-lint doc-claims: machine-checked statements in Markdown. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_doc_claims{,_eval,_scan}.c@9a191ef7b1184e14d9116362dff7def64cd300e3,
 * modified (zclassicd predicates), not verbatim; see zcutil/tools/NOTICE.
 *
 * A claim is an HTML comment on one line of a tracked *.md file:
 *     <!-- claim: PREDICATE args # note -->
 * Predicates: file-present <path>, file-absent <path>, symbol-present <sym> <pathspec>,
 * symbol-absent <sym> <pathspec> (git grep -lwF), rule-passes <zcl-lint rule>, step-exists <local-ci step>.
 * A malformed or false claim fails with file:line. Claims inside code fences or `code spans` are examples
 * and are ignored. Fewer than 3 documents scanned is a hollow scan (exit 2).
 */
#define _POSIX_C_SOURCE 200809L
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MIN_DOCS = 3, MAX_ARGS = 4 };

/* Blank `code spans` in place (a run of backticks up to the next run of the same length). */
static void blank_code(char *l)
{
    for (size_t i = 0; l[i];) {
        if (l[i] != '`') { i++; continue; }
        size_t run = 0;
        while (l[i + run] == '`') run++;
        size_t k = i + run;
        bool closed = false;
        while (l[k]) {
            size_t r = 0;
            while (l[k + r] == '`') r++;
            if (r == run) { closed = true; k += r; break; }
            k += r ? r : 1;
        }
        if (!closed) { i += run; continue; }
        memset(l + i, ' ', k - i);
        i = k;
    }
}

static bool safe_word(const char *s, const char *extra)
{
    if (!*s) return false;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && !strchr(extra, *s)) return false;
    return true;
}

static bool safe_path(const char *s)
{
    return safe_word(s, "_./-+@") && s[0] != '/' && s[0] != '-' && !strstr(s, "..");
}

static bool safe_pathspec(const char *s)
{
    return safe_word(s, "_./-+@*:!") && s[0] != '/' && s[0] != '-' && !strstr(s, "..");
}

static bool step_exists(const char *name)
{
    char *txt = lint_slurp("zcutil/local-ci.sh", NULL);
    if (!txt) return false;
    bool found = false;
    for (char *l = strtok(txt, "\n"); l && !found; l = strtok(NULL, "\n")) {
        while (*l == ' ' || *l == '\t') l++;
        if (strncmp(l, "step ", 5)) continue;
        l += 5;
        size_t n = strlen(name);
        found = !strncmp(l, name, n) && (l[n] == ' ' || l[n] == '\0');
    }
    free(txt);
    return found;
}

/* Evaluate one tokenised claim. Returns NULL when it holds, else a static reason. *malformed is set when the
 * claim itself is unusable (unknown predicate, wrong arguments), as opposed to false. */
static const char *eval_claim(char **a, int n, bool *malformed)
{
    static char reason[160];
    *malformed = true;
    if (!n) return "empty claim";
    const char *p = a[0];
    bool file = !strcmp(p, "file-present") || !strcmp(p, "file-absent");
    bool sym = !strcmp(p, "symbol-present") || !strcmp(p, "symbol-absent");
    bool want = !strcmp(p, "file-present") || !strcmp(p, "symbol-present");
    if (file) {
        if (n != 2 || !safe_path(a[1])) return "needs exactly one repository-relative path";
        *malformed = false;
        bool there = lint_is_tracked(a[1]) || lint_dir_tracked(a[1]);
        if (there == want) return NULL;
        return want ? "path is not tracked" : "path is tracked";
    }
    if (sym) {
        if (n != 3 || !safe_word(a[1], "_.:-") || a[1][0] == '-' || !safe_pathspec(a[2])) return "needs a symbol and one pathspec";
        char *gargv[] = { "git", "-C", (char *)lint_root, "grep", "-qwF", "-e", a[1], "--", a[2], NULL };
        int rc = lint_status_argv(NULL, gargv, true);
        *malformed = false;
        if (rc != 0 && rc != 1) return "git grep failed";
        if ((rc == 0) == want) return NULL;
        return want ? "symbol not found" : "symbol found";
    }
    if (!strcmp(p, "rule-passes")) {
        if (n != 2 || !safe_word(a[1], "-")) return "needs one zcl-lint rule name";
        if (!strcmp(a[1], "doc-claims") || !strcmp(a[1], "all")) return "a claim cannot ask for itself or for all rules";
        *malformed = false;
        char *bin = lint_tool_path("zcutil/bin/zcl-lint");
        if (!bin) return "zcutil/bin/zcl-lint is not built";
        char *rargv[] = { bin, "--root", (char *)lint_root, a[1], NULL };
        int st = lint_status_argv(NULL, rargv, true);
        free(bin);
        if (st == 0) return NULL;
        snprintf(reason, sizeof reason, "rule %s does not pass", a[1]);
        return reason;
    }
    if (!strcmp(p, "step-exists")) {
        if (n != 2 || !safe_word(a[1], "_.-")) return "needs one local-ci step name";
        *malformed = false;
        return step_exists(a[1]) ? NULL : "no such step in zcutil/local-ci.sh";
    }
    return "unknown predicate";
}

static void scan_doc(const char *md, char *txt, long *claims, long *failed)
{
    bool fence = false;
    long ln = 0;
    for (char *l = txt; l && *l;) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        ln++;
        char *t = l;
        while (*t == ' ') t++;
        if (lint_has_prefix(t, "```") || lint_has_prefix(t, "~~~")) fence = !fence;
        else if (!fence && strstr(l, "<!--")) {
            blank_code(l);
            for (char *c = strstr(l, "<!--"); c; c = strstr(c + 4, "<!--")) {
                char *b = c + 4;
                while (*b == ' ' || *b == '\t') b++;
                if (strncmp(b, "claim", 5) || isalnum((unsigned char)b[5]) || b[5] == '_') continue;
                (*claims)++;
                char *end = strstr(b, "-->");
                if (b[5] != ':' || !end) {
                    printf("FAIL doc-claims: %s:%ld: malformed claim (want <!-- claim: PREDICATE args # note --> on one line)\n", md, ln);
                    (*failed)++;
                    continue;
                }
                char body[1024];
                size_t len = (size_t)(end - (b + 6));
                snprintf(body, sizeof body, "%.*s", (int)(len < sizeof body ? len : sizeof body - 1), b + 6);
                char *note = strstr(body, " #");
                if (note) *note = '\0';
                char *a[MAX_ARGS + 1];
                int n = 0;
                for (char *w = strtok(body, " \t"); w; w = strtok(NULL, " \t")) {
                    if (n == MAX_ARGS) { n++; break; }
                    a[n++] = w;
                }
                bool malformed = true;
                const char *why = n > MAX_ARGS ? "too many arguments" : eval_claim(a, n, &malformed);
                if (!why) continue;
                printf("FAIL doc-claims: %s:%ld: %s claim: %s%s%s\n", md, ln, malformed ? "malformed" : "false", why,
                       n && !malformed ? " - " : "", n && !malformed ? a[0] : "");
                (*failed)++;
            }
        }
        l = nl ? nl + 1 : NULL;
    }
}

int lint_rule_doc_claims(bool update)
{
    (void)update; /* no baseline; the driver refuses --update-baseline for this rule */
    size_t docs = 0;
    long claims = 0, failed = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!lint_has_suffix(lint_files[i], ".md") || lint_is_vendored(lint_files[i])) continue;
        char *txt = lint_slurp(lint_files[i], NULL);
        if (!txt) continue;
        docs++;
        scan_doc(lint_files[i], txt, &claims, &failed);
        free(txt);
    }
    if (docs < MIN_DOCS) {
        printf("FAIL doc-claims: hollow scan (%zu tracked documents, need at least %d)\n", docs, MIN_DOCS);
        return 2;
    }
    if (failed) return 1;
    printf("doc-claims: ok (%ld claims in %zu documents)\n", claims, docs);
    return 0;
}
