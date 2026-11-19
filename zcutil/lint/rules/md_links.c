/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_hardening_ratchet.c, gate_no_new_bash.c and gate_markdown_links.c
 * @1f5d0f69448c4811884b2c918ae0723ab24830da, and (helper semantics) Z23 tools/lint/lintc/lib.c and
 * tools/lint/strip_c_comments.awk@9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim. See NOTICE.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Code point of the UTF-8 sequence at s (length in *len); invalid bytes decode as themselves. */
static unsigned long utf8_cp(const unsigned char *s, size_t *len)
{
    size_t n = s[0] >= 0xF0 ? 4 : s[0] >= 0xE0 ? 3 : s[0] >= 0xC0 ? 2 : 1;
    unsigned long cp = n == 1 ? s[0] : (unsigned long)(s[0] & (0xFFu >> (n + 1)));
    for (size_t i = 1; i < n; i++) {
        if ((s[i] & 0xC0) != 0x80) { *len = i; return s[0]; }
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    *len = n;
    return cp;
}

/* GitHub heading slug: lowercase, keep alnum _ - and non-symbol UTF-8, spaces become '-'.
 * Punctuation and symbol blocks (U+00A0-00BF, U+2000-2BFF, U+3000-303F, emoji) are dropped. */
static void slugify(const char *h, char *out, size_t cap)
{
    size_t o = 0, k;
    for (; *h && o + 1 < cap; h += k) {
        unsigned char c = (unsigned char)*h;
        k = 1;
        if (c == ' ') out[o++] = '-';
        else if (isalnum(c)) out[o++] = (char)tolower(c);
        else if (c == '_' || c == '-') out[o++] = (char)c;
        else if (c >= 0x80) {
            unsigned long cp = utf8_cp((const unsigned char *)h, &k);
            bool sym = (cp >= 0xA0 && cp <= 0xBF) || (cp >= 0x2000 && cp <= 0x2BFF) || (cp >= 0x3000 && cp <= 0x303F) ||
                       cp == 0xFE0F || cp >= 0x1F000;
            if (!sym && o + k < cap) { memcpy(out + o, h, k); o += k; }
        }
    }
    out[o] = 0;
}

/* Remove `code` spans in place (a run of backticks up to the next run of the same length). */
static void strip_code(char *l)
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
        memmove(l + i, l + k, strlen(l + k) + 1);
    }
}

static const char *normalize(const char *dir, const char *target, char *out, size_t cap)
{
    char tmp[1700];
    if (target[0] == '/') snprintf(tmp, sizeof tmp, "%s", target + 1);              /* site-absolute: from the repository root */
    else snprintf(tmp, sizeof tmp, "%s/%s", dir, target);
    size_t o = 0;
    out[0] = '\0';
    for (char *seg = strtok(tmp, "/"); seg; seg = strtok(NULL, "/")) {
        if (!strcmp(seg, ".") || !*seg) continue;
        if (!strcmp(seg, "..")) {
            if (!o) return NULL;                                  /* escapes the repository */
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

struct anchors { char **v; size_t n, cap; };

static void anchor_add(struct anchors *a, const char *s)
{
    if (a->n == a->cap) { a->cap = a->cap ? a->cap * 2 : 32; a->v = lint_xrealloc(a->v, a->cap * sizeof *a->v); }
    a->v[a->n++] = lint_xstrdup(s);
}

static bool anchor_has(const struct anchors *a, const char *s)
{
    for (size_t i = 0; i < a->n; i++)
        if (!strcmp(a->v[i], s)) return true;
    return false;
}

/* Heading anchors (with -1, -2 suffixes for repeats) and explicit <a name/id> anchors, outside code fences. */
static void collect_anchors(const char *txt, struct anchors *a)
{
    char *copy = lint_xstrdup(txt);
    bool fence = false;
    for (char *l = strtok(copy, "\n"); l; l = strtok(NULL, "\n")) {
        const char *t = l;
        while (*t == ' ') t++;
        if (lint_has_prefix(t, "```") || lint_has_prefix(t, "~~~")) { fence = !fence; continue; }
        if (fence) continue;
        for (const char *p = strstr(l, "<a "); p; p = strstr(p + 1, "<a ")) {
            const char *n = strstr(p, "name=\""), *d = strstr(p, "id=\"");
            const char *q = n ? n + 6 : d ? d + 4 : NULL;
            if (q) { char id[200]; size_t k = strcspn(q, "\""); snprintf(id, sizeof id, "%.*s", (int)(k < 199 ? k : 199), q); anchor_add(a, id); }
        }
        size_t hashes = strspn(l, "#");
        if (!hashes || hashes > 6 || l[hashes] != ' ') continue;
        char text[512], slug[512], uniq[560];
        snprintf(text, sizeof text, "%s", l + hashes + 1);
        for (char *e = text + strlen(text); e > text && (e[-1] == ' ' || e[-1] == '#'); ) *--e = '\0';
        char plain[512];
        size_t o = 0;
        for (const char *p = text; *p && o + 1 < sizeof plain; p++) {
            if (*p == ']' && p[1] == '(') { while (*p && *p != ')') p++; if (!*p) break; continue; }
            if (*p != '[' && *p != '*' && *p != '`') plain[o++] = *p;
        }
        plain[o] = '\0';
        slugify(plain, slug, sizeof slug);
        snprintf(uniq, sizeof uniq, "%s", slug);
        for (int k = 1; anchor_has(a, uniq); k++) snprintf(uniq, sizeof uniq, "%s-%d", slug, k);
        anchor_add(a, uniq);
    }
    free(copy);
}

static void unescape_pct(char *s)
{
    char *w = s;
    for (; *s; s++) {
        if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
            char h[3] = { s[1], s[2], 0 };
            *w++ = (char)strtol(h, NULL, 16);
            s += 2;
        } else *w++ = *s;
    }
    *w = '\0';
}

/* 1 when the target is broken. `line` is only used for the report. */
static int check_target(const char *md, const char *dir, const struct anchors *anc, char *target, long line)
{
    if (!*target || strstr(target, "{{") || target[0] == '$') return 0;
    size_t sc = strspn(target, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-");
    if (target[sc] == ':' || lint_has_prefix(target, "//")) return 0;                       /* external URL or mail */
    char *frag = strchr(target, '#');
    char anchor[300] = "";
    if (frag) { snprintf(anchor, sizeof anchor, "%s", frag + 1); *frag = '\0'; }
    char *q = strchr(target, '?');
    if (q) *q = '\0';
    unescape_pct(target);
    unescape_pct(anchor);
    if (!*target) {                                                                    /* same-file anchor */
        if (!*anchor || !strcmp(anchor, "top") || anchor_has(anc, anchor)) return 0;
        printf("FAIL md-links: %s:%ld: no heading for anchor #%s\n", md, line, anchor);
        return 1;
    }
    char path[1100];
    if (!normalize(dir, target, path, sizeof path)) { printf("FAIL md-links: %s:%ld: %s leaves the repository\n", md, line, target); return 1; }
    if (!*path || lint_is_tracked(path) || lint_dir_tracked(path)) return 0;
    printf("FAIL md-links: %s:%ld: %s does not resolve to a tracked file\n", md, line, target);
    return 1;
}

static void md_scan(const char *md, char *txt, long *broken)
{
    struct anchors anc = { NULL, 0, 0 };
    collect_anchors(txt, &anc);
    char dir[600];
    snprintf(dir, sizeof dir, "%s", md);
    char *sl = strrchr(dir, '/');
    if (sl) *sl = '\0'; else dir[0] = '\0';
    bool fence = false;
    long ln = 0;
    for (char *l = txt; l && *l;) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        ln++;
        char *t = l;
        while (*t == ' ') t++;
        if (lint_has_prefix(t, "```") || lint_has_prefix(t, "~~~")) fence = !fence;
        else if (!fence && strlen(l) < 4000) {
            char buf[4096];
            snprintf(buf, sizeof buf, "%s", l);
            strip_code(buf);
            for (char *p = strstr(buf, "]("); p; p = strstr(p + 1, "](")) {
                char *s = p + 2, *e;
                char tgt[1100];
                if (*s == '<') { s++; e = strchr(s, '>'); }
                else {
                    int depth = 0;
                    for (e = s; *e && !(depth == 0 && (*e == ')' || *e == ' ')); e++) depth += *e == '(' ? 1 : *e == ')' ? -1 : 0;
                    if (!*e) e = NULL;
                }
                if (!e || (size_t)(e - s) >= sizeof tgt) continue;
                snprintf(tgt, sizeof tgt, "%.*s", (int)(e - s), s);
                *broken += check_target(md, dir, &anc, tgt, ln);
            }
            if (*t == '[') {                                                        /* [label]: target */
                char *c = strstr(t, "]:");
                if (c && c[2] == ' ') {
                    char *s = c + 3;
                    while (*s == ' ') s++;
                    char tgt[1100];
                    snprintf(tgt, sizeof tgt, "%.*s", (int)strcspn(s, " \t"), s);
                    if (tgt[0] == '<') memmove(tgt, tgt + 1, strlen(tgt)), tgt[strcspn(tgt, ">")] = '\0';
                    *broken += check_target(md, dir, &anc, tgt, ln);
                }
            }
        }
        l = nl ? nl + 1 : NULL;
    }
    for (size_t i = 0; i < anc.n; i++) free(anc.v[i]);
    free(anc.v);
}

/* md-links is a lint_ratchet too: the per-path count is the number of broken links. */
int lint_rule_md_links(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!lint_has_suffix(lint_files[i], ".md") || lint_is_vendored(lint_files[i])) continue;
        char *txt = lint_slurp(lint_files[i], NULL);
        if (!txt) continue;
        scanned++;
        long broken = 0;
        md_scan(lint_files[i], txt, &broken);
        if (broken) lint_rows_add(&cur, lint_files[i], broken);
        free(txt);
    }
    return lint_ratchet("md-links", "broken relative links or same-file anchors", &cur, scanned, update);
}
