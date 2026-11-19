/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Rule logic derived from Z23 tools/lint/lintc/gate_hardening_ratchet.c@1f5d0f69448c4811884b2c918ae0723ab24830da, changed:
 *   banned string functions, shrink-only per-path baselines, comment/string scrubbing.
 * Rule logic derived from Z23 tools/lint/lintc/gate_no_new_bash.c@1f5d0f69448c4811884b2c918ae0723ab24830da, changed:
 *   shell file detection by suffix or shebang; here a ratchet on bash shebangs and bashisms.
 * Rule logic derived from Z23 tools/lint/lintc/gate_markdown_links.c@1f5d0f69448c4811884b2c918ae0723ab24830da, changed:
 *   fenced/inline code skipped, relative targets must resolve to tracked files; plus same-file anchors.
 * Z23 is Apache-2.0 (Copyright 2026 Rhett Creighton); this file is a modified derivative, not a verbatim copy.
 *
 * usage: zcl-lint [--root DIR] <rule>|all [--update-baseline]
 *   rules: no-new-jq no-new-bash banned-str md-links vendor
 * Baselines: <root>/zcutil/lint/<rule>.txt, rows "<path><TAB><count>", sorted by path (bytewise).
 * A ratchet rule fails when a path's count rises or a path appears that is not in the baseline;
 * a count that falls passes and tells you to lower the baseline (--update-baseline, shrink-only:
 * it refuses to write while anything rose, and only creates a missing baseline from scratch).
 * Exit: 0 clean, 1 findings, 2 usage or internal error.
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char *g_root = ".";

/* ---- small helpers --------------------------------------------------------------------- */

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "zcl-lint: out of memory\n"); exit(2); }
    return q;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(xrealloc(NULL, n), s, n);
}

static char *rootpath(const char *rel)
{
    size_t n = strlen(g_root) + strlen(rel) + 2;
    char *p = xrealloc(NULL, n);
    snprintf(p, n, "%s/%s", g_root, rel);
    return p;
}

/* Whole file into a NUL-terminated buffer; NULL when unreadable. */
static char *slurp(const char *rel, size_t *len)
{
    char *p = rootpath(rel);
    FILE *f = fopen(p, "rb");
    free(p);
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    char *buf = xrealloc(NULL, cap);
    size_t r;
    while ((r = fread(buf + n, 1, cap - n - 1, f)) > 0) {
        n += r;
        if (n + 1 >= cap) { cap *= 2; buf = xrealloc(buf, cap); }
    }
    fclose(f);
    buf[n] = '\0';
    if (len) *len = n;
    return buf;
}

static bool has_prefix(const char *s, const char *p) { return strncmp(s, p, strlen(p)) == 0; }

static bool has_suffix(const char *s, const char *x)
{
    size_t n = strlen(s), k = strlen(x);
    return n >= k && strcmp(s + n - k, x) == 0;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* ---- tracked files (git ls-files -z) --------------------------------------------------- */

static char **g_files;
static size_t g_nfiles;

static void load_tracked(void)
{
    char cmd[1200];
    snprintf(cmd, sizeof cmd, "git -C '%s' ls-files -z", g_root);
    FILE *p = popen(cmd, "r");
    if (!p) { fprintf(stderr, "zcl-lint: cannot run git\n"); exit(2); }
    size_t cap = 4096, n = 0, r;
    char *buf = xrealloc(NULL, cap);
    while ((r = fread(buf + n, 1, cap - n, p)) > 0) {
        n += r;
        if (n == cap) { cap *= 2; buf = xrealloc(buf, cap); }
    }
    if (pclose(p) != 0 || n == 0) { fprintf(stderr, "zcl-lint: git ls-files failed in %s\n", g_root); exit(2); }
    size_t i = 0, fc = 0;
    while (i < n) {
        if (g_nfiles == fc) { fc = fc ? fc * 2 : 1024; g_files = xrealloc(g_files, fc * sizeof *g_files); }
        g_files[g_nfiles++] = xstrdup(buf + i);
        i += strlen(buf + i) + 1;
    }
    free(buf);
    qsort(g_files, g_nfiles, sizeof *g_files, cmp_str);
}

static bool is_tracked(const char *path)
{
    return bsearch(&path, g_files, g_nfiles, sizeof *g_files, cmp_str) != NULL;
}

/* A directory is "tracked" when some tracked path lies below it. */
static bool dir_tracked(const char *dir)
{
    size_t n = strlen(dir);
    for (size_t i = 0; i < g_nfiles; i++)
        if (strncmp(g_files[i], dir, n) == 0 && g_files[i][n] == '/') return true;
    return false;
}

/* Vendored or third-party trees: edits there are the vendor rule's business, not a style gate's. */
static bool is_vendored(const char *p)
{
    static const char *const roots[] = {
        "src/c23/vendor/", "src/c23/services/vendor/", "zcutil/tools/vendor/", "src/secp256k1/", "src/leveldb/",
        "src/univalue/", "depends/", "wallet/src/3rdparty/", "src/pow/tromp/" };
    for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++)
        if (has_prefix(p, roots[i])) return true;
    return false;
}

/* ---- findings and baselines ------------------------------------------------------------ */

struct row { char *path; long count; };
struct rows { struct row *v; size_t n, cap; };

static void rows_add(struct rows *r, const char *path, long count)
{
    if (r->n == r->cap) { r->cap = r->cap ? r->cap * 2 : 64; r->v = xrealloc(r->v, r->cap * sizeof *r->v); }
    r->v[r->n].path = xstrdup(path);
    r->v[r->n].count = count;
    r->n++;
}

static int cmp_row(const void *a, const void *b) { return strcmp(((const struct row *)a)->path, ((const struct row *)b)->path); }

static long rows_find(const struct rows *r, const char *path)
{
    if (!r->n) return -1;
    struct row key = { (char *)path, 0 };
    const struct row *hit = bsearch(&key, r->v, r->n, sizeof *r->v, cmp_row);
    return hit ? hit->count : -1;
}

static char *baseline_rel(const char *rule)
{
    size_t n = strlen(rule) + 32;
    char *p = xrealloc(NULL, n);
    snprintf(p, n, "zcutil/lint/%s.txt", rule);
    return p;
}

/* Load a baseline; *exists says whether the file was there. Rows are re-sorted so a hand edit is forgiven. */
static struct rows load_baseline(const char *rule, bool *exists)
{
    struct rows r = { NULL, 0, 0 };
    char *rel = baseline_rel(rule), *txt = slurp(rel, NULL);
    free(rel);
    *exists = txt != NULL;
    if (!txt) return r;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        if (line[0] == '#' || line[0] == '\0') continue;
        char *tab = strrchr(line, '\t');
        if (!tab) { fprintf(stderr, "zcl-lint: %s baseline: bad row '%s'\n", rule, line); exit(2); }
        *tab = '\0';
        rows_add(&r, line, atol(tab + 1));
    }
    free(txt);
    if (r.n) qsort(r.v, r.n, sizeof *r.v, cmp_row);
    return r;
}

static int write_baseline(const char *rule, const char *what, const struct rows *cur)
{
    char *rel = baseline_rel(rule), *p = rootpath(rel);
    FILE *f = fopen(p, "wb");
    free(rel);
    free(p);
    if (!f) { fprintf(stderr, "zcl-lint: cannot write baseline for %s: %s\n", rule, strerror(errno)); return 2; }
    fprintf(f, "# zcl-lint %s baseline: %s per path.\n", rule, what);
    fprintf(f, "# Shrink-only: lower a count or delete a row when it falls; never raise one or add a path.\n");
    fprintf(f, "# Regenerate with: zcl-lint %s --update-baseline (refused while anything rose).\n", rule);
    for (size_t i = 0; i < cur->n; i++) fprintf(f, "%s\t%ld\n", cur->v[i].path, cur->v[i].count);
    fclose(f);
    return 0;
}

/* The ratchet: compare findings with the baseline. Returns 0 clean, 1 findings, 2 error. */
static int ratchet(const char *rule, const char *what, struct rows *cur, bool update)
{
    bool exists;
    struct rows base = load_baseline(rule, &exists);
    if (cur->n) qsort(cur->v, cur->n, sizeof *cur->v, cmp_row);
    int bad = 0, shrunk = 0;
    long total = 0;
    for (size_t i = 0; i < cur->n; i++) {
        long b = rows_find(&base, cur->v[i].path), c = cur->v[i].count;
        total += c;
        if (!exists) continue;
        if (b < 0) { printf("FAIL %s: %s: %ld new (not in the baseline)\n", rule, cur->v[i].path, c); bad++; }
        else if (c > b) { printf("FAIL %s: %s: %ld, baseline %ld (rose)\n", rule, cur->v[i].path, c, b); bad++; }
        else if (c < b) shrunk++;
    }
    for (size_t i = 0; exists && i < base.n; i++)
        if (rows_find(cur, base.v[i].path) < 0) shrunk++;
    if (update) {
        if (bad) { printf("%s: baseline NOT updated: counts rose or paths are new (fix them, the baseline only shrinks)\n", rule); return 1; }
        if (exists && !shrunk) { printf("%s: baseline already tight (%zu paths, %ld)\n", rule, cur->n, total); return 0; }
        int rc = write_baseline(rule, what, cur);
        if (!rc) printf("%s: baseline %s (%zu paths, %ld)\n", rule, exists ? "lowered" : "created", cur->n, total);
        return rc;
    }
    if (!exists) { printf("FAIL %s: no baseline zcutil/lint/%s.txt (create it with: zcl-lint %s --update-baseline)\n", rule, rule, rule); return 1; }
    if (bad) return 1;
    if (shrunk) printf("%s: ok, but the baseline can be lowered (%d path(s) fell): run zcl-lint %s --update-baseline\n", rule, shrunk, rule);
    else printf("%s: ok (%zu paths, %ld)\n", rule, cur->n, total);
    return 0;
}

/* ---- shell detection ------------------------------------------------------------------- */

/* First line of a tracked file names sh, bash, dash or ksh (directly or through env). */
static bool shebang_is_shell(const char *txt)
{
    if (txt[0] != '#' || txt[1] != '!') return false;
    char line[256];
    size_t n = strcspn(txt, "\r\n");
    if (n >= sizeof line) n = sizeof line - 1;
    memcpy(line, txt, n);
    line[n] = '\0';
    static const char *const shells[] = { "sh", "bash", "dash", "ksh" };
    for (char *w = strtok(line + 2, " \t"); w; w = strtok(NULL, " \t")) {
        if (w[0] == '-' || strchr(w, '=')) continue;
        char *base = strrchr(w, '/');
        base = base ? base + 1 : w;
        if (strcmp(base, "env") == 0) continue;
        for (size_t i = 0; i < sizeof shells / sizeof shells[0]; i++)
            if (strcmp(base, shells[i]) == 0) return true;
        return false;
    }
    return false;
}

static bool shebang_is_bash(const char *txt)
{
    if (!shebang_is_shell(txt)) return false;
    size_t n = strcspn(txt, "\r\n");
    for (size_t i = 0; i + 4 <= n; i++)
        if (memcmp(txt + i, "bash", 4) == 0) return true;
    return false;
}

/* Shell file by suffix, else by the first line (only 128 bytes are read). */
static bool is_shell_file(const char *path)
{
    if (has_suffix(path, ".sh") || has_suffix(path, ".bash")) return true;
    char *p = rootpath(path), head[128];
    FILE *f = fopen(p, "rb");
    free(p);
    if (!f) return false;
    size_t n = fread(head, 1, sizeof head - 1, f);
    fclose(f);
    head[n] = '\0';
    return shebang_is_shell(head);
}

/* ---- rule no-new-jq -------------------------------------------------------------------- */

static bool word_at(const char *s, const char *w)
{
    size_t k = strlen(w);
    if (strncmp(s, w, k) != 0) return false;
    return !(isalnum((unsigned char)s[k]) || s[k] == '_');
}

static long count_word_lines(char *txt, const char *w)
{
    long hits = 0;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        for (char *p = strstr(line, w); p; p = strstr(p + 1, w)) {
            bool left = p == line || !(isalnum((unsigned char)p[-1]) || p[-1] == '_' || p[-1] == '-');
            if (left && word_at(p, w)) { hits++; break; }
        }
    }
    return hits;
}

static int rule_jq(bool update)
{
    struct rows cur = { NULL, 0, 0 };
    for (size_t i = 0; i < g_nfiles; i++) {
        if (is_vendored(g_files[i]) || has_prefix(g_files[i], "zcutil/lint/") || !is_shell_file(g_files[i])) continue;
        char *txt = slurp(g_files[i], NULL);
        if (!txt) continue;
        long n = count_word_lines(txt, "jq");
        if (n) rows_add(&cur, g_files[i], n);
        free(txt);
    }
    return ratchet("no-new-jq", "lines mentioning jq in shell scripts", &cur, update);
}

/* ---- rule no-new-bash ------------------------------------------------------------------ */

/* Constructs that dash and busybox ash reject or treat differently. One hit per line at most. */
static bool line_has_bashism(const char *l)
{
    while (*l == ' ' || *l == '\t') l++;
    if (*l == '#' || *l == '\0') return false;
    static const char *const marks[] = { "[[ ", " ]]", "<(", ">(", "${!", "&>", "|&", "BASH_", "$RANDOM", "$BASHPID",
                                         "mapfile ", "readarray ", "shopt ", "declare -", "typeset -", "echo -e ", "read -a ",
                                         "read -p ", "[ -v " };
    for (size_t i = 0; i < sizeof marks / sizeof marks[0]; i++)
        if (strstr(l, marks[i])) return true;
    for (const char *p = strstr(l, "${"); p; p = strstr(p + 1, "${")) {          /* ${v//x/y}  ${v^^}  ${v,,}  ${v:1:2} */
        const char *q = p + 2;
        while (isalnum((unsigned char)*q) || *q == '_') q++;
        if (*q == '/' || *q == '^' || *q == ',') return true;
        if (*q == ':' && !strchr("-=+?", q[1]) && q[1]) return true;
    }
    if (has_prefix(l, "source ") || has_prefix(l, "function ") || has_prefix(l, "((")) return true;
    for (const char *p = strstr(l, "=("); p; p = strstr(p + 1, "=("))               /* name=(a b)  array literal */
        if (p > l && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) return true;
    return false;
}

static int rule_bash(bool update)
{
    struct rows cur = { NULL, 0, 0 };
    for (size_t i = 0; i < g_nfiles; i++) {
        if (is_vendored(g_files[i]) || has_prefix(g_files[i], "zcutil/lint/") || !is_shell_file(g_files[i])) continue;
        char *txt = slurp(g_files[i], NULL);
        if (!txt) continue;
        long n = shebang_is_bash(txt) ? 1 : 0;
        for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n"))
            if (line_has_bashism(line)) n++;
        if (n) rows_add(&cur, g_files[i], n);
        free(txt);
    }
    return ratchet("no-new-bash", "bash shebang and bashism lines in shell scripts", &cur, update);
}

/* ---- rule banned-str ------------------------------------------------------------------- */

static bool c_source(const char *p)
{
    static const char *const ext[] = { ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc" };
    for (size_t i = 0; i < sizeof ext / sizeof ext[0]; i++)
        if (has_suffix(p, ext[i])) return true;
    return false;
}

static bool idc(int c) { return c == '_' || isalnum(c); }

/* Blank out comments, string and char literals of one line; *blk carries an open block comment across lines. */
static void scrub_line(char *s, bool *blk)
{
    for (size_t i = 0; s[i]; i++) {
        if (*blk) {
            if (s[i] == '*' && s[i + 1] == '/') { s[i] = s[i + 1] = ' '; i++; *blk = false; }
            else s[i] = ' ';
        } else if (s[i] == '/' && s[i + 1] == '*') { s[i] = s[i + 1] = ' '; i++; *blk = true; }
        else if (s[i] == '/' && s[i + 1] == '/') { memset(s + i, ' ', strlen(s + i)); return; }
        else if (s[i] == '"' || s[i] == '\'') {
            char q = s[i];
            for (i++; s[i] && s[i] != q; i++) {
                if (s[i] == '\\' && s[i + 1]) s[i++] = ' ';
                s[i] = ' ';
            }
            if (!s[i]) return;
        }
    }
}

static long count_banned(char *s)
{
    static const char *const ban[] = { "strcpy", "strcat", "sprintf", "vsprintf", "gets" };
    long hits = 0;
    for (size_t i = 0; s[i];) {
        if (!idc((unsigned char)s[i])) { i++; continue; }
        size_t b = i;
        while (idc((unsigned char)s[i])) i++;
        size_t j = i;
        while (s[j] == ' ' || s[j] == '\t') j++;
        bool member = (b >= 1 && s[b - 1] == '.') || (b >= 2 && s[b - 2] == '-' && s[b - 1] == '>');
        if (s[j] != '(' || member) continue;
        for (size_t k = 0; k < sizeof ban / sizeof ban[0]; k++)
            if (strlen(ban[k]) == i - b && memcmp(ban[k], s + b, i - b) == 0) hits++;
    }
    return hits;
}

static int rule_banned(bool update)
{
    struct rows cur = { NULL, 0, 0 };
    for (size_t i = 0; i < g_nfiles; i++) {
        if (!c_source(g_files[i]) || is_vendored(g_files[i])) continue;
        char *txt = slurp(g_files[i], NULL);
        if (!txt) continue;
        long n = 0;
        bool blk = false;
        for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
            bool okline = strstr(line, "lint-ok:") != NULL;
            scrub_line(line, &blk);
            if (!okline) n += count_banned(line);
        }
        if (n) rows_add(&cur, g_files[i], n);
        free(txt);
    }
    return ratchet("banned-str", "calls to strcpy, strcat, sprintf, vsprintf, gets", &cur, update);
}

/* ---- rule md-links --------------------------------------------------------------------- */
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
    if (a->n == a->cap) { a->cap = a->cap ? a->cap * 2 : 32; a->v = xrealloc(a->v, a->cap * sizeof *a->v); }
    a->v[a->n++] = xstrdup(s);
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
    char *copy = xstrdup(txt);
    bool fence = false;
    for (char *l = strtok(copy, "\n"); l; l = strtok(NULL, "\n")) {
        const char *t = l;
        while (*t == ' ') t++;
        if (has_prefix(t, "```") || has_prefix(t, "~~~")) { fence = !fence; continue; }
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
    if (target[sc] == ':' || has_prefix(target, "//")) return 0;                       /* external URL or mail */
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
    if (!*path || is_tracked(path) || dir_tracked(path)) return 0;
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
        if (has_prefix(t, "```") || has_prefix(t, "~~~")) fence = !fence;
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

/* md-links is a ratchet too: the per-path count is the number of broken links. */
static int rule_md(bool update)
{
    struct rows cur = { NULL, 0, 0 };
    for (size_t i = 0; i < g_nfiles; i++) {
        if (!has_suffix(g_files[i], ".md") || is_vendored(g_files[i])) continue;
        char *txt = slurp(g_files[i], NULL);
        if (!txt) continue;
        long broken = 0;
        md_scan(g_files[i], txt, &broken);
        if (broken) rows_add(&cur, g_files[i], broken);
        free(txt);
    }
    return ratchet("md-links", "broken relative links or same-file anchors", &cur, update);
}

/* ---- rule vendor: every manifest must match its vendored tree (delegates to check-vendor) -- */

static int run(const char *cmd)
{
    fflush(stdout);
    int rc = system(cmd);
    return rc == 0 ? 0 : 1;
}

static int rule_vendor(void)
{
    int bad = 0, n = 0;
    for (size_t i = 0; i < g_nfiles; i++) {
        if (!has_suffix(g_files[i], "Z23_SOURCE.tsv")) continue;
        char dir[600], cmd[2400];
        snprintf(dir, sizeof dir, "%s", g_files[i]);
        *strrchr(dir, '/') = '\0';
        char own[700];
        snprintf(own, sizeof own, "%s/tools/check-vendor.sh", dir);        /* a root with its own checker */
        if (is_tracked(own)) snprintf(cmd, sizeof cmd, "sh '%s/%s' '%s/%s'", g_root, own, g_root, dir);
        else snprintf(cmd, sizeof cmd, "sh '%s/src/c23/tools/check-vendor.sh' '%s/%s'", g_root, g_root, g_files[i]);
        n++;
        if (run(cmd)) { printf("FAIL vendor: %s does not match its vendored tree\n", g_files[i]); bad++; }
    }
    if (!n) { printf("FAIL vendor: no Z23_SOURCE.tsv manifest is tracked\n"); return 1; }
    if (!bad) printf("vendor: ok (%d manifests)\n", n);
    return bad ? 1 : 0;
}

/* The no-python gate lives on another branch (zcutil/check-no-python.sh). When it is present `all` runs it. */
static int rule_python_hook(void)
{
    char *p = rootpath("zcutil/check-no-python.sh");
    struct stat st;
    bool have = stat(p, &st) == 0;
    free(p);
    if (!have) { printf("no-python: skipped (zcutil/check-no-python.sh not present)\n"); return 0; }
    char cmd[1200];
    snprintf(cmd, sizeof cmd, "sh '%s/zcutil/check-no-python.sh'", g_root);
    return run(cmd);
}

/* ---- main ------------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *rule = NULL;
    bool update = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--root") && i + 1 < argc) g_root = argv[++i];
        else if (!strcmp(argv[i], "--update-baseline")) update = true;
        else if (!rule && argv[i][0] != '-') rule = argv[i];
        else { rule = NULL; break; }
    }
    if (!rule) {
        fprintf(stderr, "usage: zcl-lint [--root DIR] no-new-jq|no-new-bash|banned-str|md-links|vendor|all [--update-baseline]\n");
        return 2;
    }
    bool all = !strcmp(rule, "all");
    if (all && update) { fprintf(stderr, "zcl-lint: --update-baseline needs one rule, not all\n"); return 2; }
    load_tracked();
    int rc = 0, ran = 0;
    if (all || !strcmp(rule, "no-new-jq")) { rc |= rule_jq(update); ran++; }
    if (all || !strcmp(rule, "no-new-bash")) { rc |= rule_bash(update); ran++; }
    if (all || !strcmp(rule, "banned-str")) { rc |= rule_banned(update); ran++; }
    if (all || !strcmp(rule, "md-links")) { rc |= rule_md(update); ran++; }
    if (all || !strcmp(rule, "vendor")) { if (update) { fprintf(stderr, "zcl-lint: vendor has no baseline\n"); return 2; } rc |= rule_vendor(); ran++; }
    if (all) rc |= rule_python_hook();
    if (!ran) { fprintf(stderr, "zcl-lint: unknown rule '%s'\n", rule); return 2; }
    return rc ? 1 : 0;
}
