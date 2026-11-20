/* zcl-lint complexity and long-functions: per-function shape of maintained C and C++.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_function_complexity.c and gate_long_functions.c
 * @9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim (C++ aware scanner, own baseline keys).
 *
 * complexity:     M = 1 + if, for, while, case, catch, and, or, &&, ||, ?   cap 15
 * long-functions: lines from the function name to its closing brace          cap 500
 * Baselines (shrink-only): zcutil/lint/complexity.txt and zcutil/lint/long-functions.txt, rows
 * "<path><TAB><Qualified::name(arity)><TAB><value>", only for functions over the cap, so a function's identity does
 * not move when lines shift. Overloads of equal arity get "#2", "#3" in file order; test-framework macros
 * (BOOST_AUTO_TEST_CASE(name), TEST(a, b)) are keyed by their arguments.
 * Scope: src/ (not vendored trees), wallet/src/, qa/ and zcutil/ (not vendor/).
 *
 * The scanner is deliberately small and local (a shared cxxscan may replace it): comments, strings, char literals,
 * raw strings and preprocessor lines are blanked; a "{" at namespace, class or file level opens a function when its
 * header holds a parameter list, a container (namespace, extern, class, struct, union, enum) is walked into, and
 * anything else (initialiser braces, lambdas at file scope) is skipped. Lambdas inside a function belong to it.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMPLEXITY_CAP 15L
#define LONG_FUNCTION_CAP 500L
#define NAMES_MAX 64

static bool in_shape_scope(const char *p)
{
    if (!lint_is_c_source(p) || lint_is_vendored(p)) return false;
    return lint_has_prefix(p, "src/") || lint_has_prefix(p, "wallet/src/") || lint_has_prefix(p, "qa/") || lint_has_prefix(p, "zcutil/");
}

/* ---- scrubbing: blank comments, literals and preprocessor lines, keep every newline ------------------------ */

static void blank(char *s, size_t a, size_t b)
{
    for (size_t i = a; i < b; i++)
        if (s[i] != '\n') s[i] = ' ';
}

static bool is_digit_separator(const char *s, size_t i)
{
    if (i == 0 || !isxdigit((unsigned char)s[i - 1]) || !isxdigit((unsigned char)s[i + 1])) return false;
    size_t b = i;
    while (b > 0 && lint_idc((unsigned char)s[b - 1])) b--;
    return isdigit((unsigned char)s[b]) != 0;
}

static bool line_continues(const char *s, size_t n, size_t j)
{
    if (s[j] != '\\' || j + 1 >= n) return false;
    return s[j + 1] == '\n' || (s[j + 1] == '\r' && j + 2 < n && s[j + 2] == '\n');
}

static size_t block_end(const char *s, size_t n, size_t from)      /* from: just after the opening slash-star */
{
    for (size_t j = from; j + 1 < n; j++)
        if (s[j] == '*' && s[j + 1] == '/') return j + 2;
    return n;
}

static size_t directive_end(const char *s, size_t n, size_t i)
{
    size_t j = i;
    for (; j < n && s[j] != '\n'; j++) {
        if (line_continues(s, n, j)) j++;
        else if (s[j] == '/' && s[j + 1] == '*') j = block_end(s, n, j + 2) - 1;   /* a comment inside the directive may span lines */
    }
    return j;
}

static size_t line_comment_end(const char *s, size_t n, size_t i)
{
    size_t j = i;
    while (j < n && s[j] != '\n') {
        if (line_continues(s, n, j)) j++;
        j++;
    }
    return j;
}

static bool is_raw_start(const char *s, size_t i)                    /* s[i] is the quote of R"delim( ... )delim" */
{
    if (s[i] != '"' || i == 0 || s[i - 1] != 'R') return false;
    return i == 1 || !lint_idc((unsigned char)s[i - 2]) || strchr("Lu8U", s[i - 2]) != NULL;
}

static size_t raw_string_end(const char *s, size_t n, size_t i)
{
    size_t d = i + 1, e = d;
    while (e < n && s[e] != '(' && e - d < 16) e++;
    size_t dl = e - d;
    for (size_t j = e + 1; j < n; j++)
        if (s[j] == ')' && j + 1 + dl < n && memcmp(s + j + 1, s + d, dl) == 0 && s[j + 1 + dl] == '"') return j + dl + 2;
    return n;
}

static size_t quoted_end(const char *s, size_t n, size_t i, char q)
{
    size_t j = i + 1;
    while (j < n && s[j] != q && s[j] != '\n') {
        if (s[j] == '\\' && j + 1 < n) j++;
        j++;
    }
    return (j < n && s[j] == q) ? j + 1 : j;
}

/* Blank the comment, literal or directive that starts at s[i]; returns the index after it (i + 1 when none). */
static size_t scrub_token(char *s, size_t n, size_t i, bool bol)
{
    char c = s[i];
    size_t j;
    if (bol && c == '#') j = directive_end(s, n, i);
    else if (c == '/' && s[i + 1] == '/') j = line_comment_end(s, n, i);
    else if (c == '/' && s[i + 1] == '*') j = block_end(s, n, i + 2);
    else if (is_raw_start(s, i)) { j = raw_string_end(s, n, i); blank(s, i - 1, j); return j; }
    else if (c == '"' || (c == '\'' && !is_digit_separator(s, i))) j = quoted_end(s, n, i, c);
    else return i + 1;
    blank(s, i, j);
    return j;
}

static void scrub_file(char *s, size_t n)
{
    bool bol = true;
    for (size_t i = 0; i < n;) {
        char c = s[i];
        if (c == '\n') { bol = true; i++; }
        else if (c == ' ' || c == '\t' || c == '\r') i++;
        else { i = scrub_token(s, n, i, bol); bol = false; }
    }
}

/* ---- scanning ------------------------------------------------------------------------------------------- */

struct fn { char *key; long cx, lines; };
struct fns { struct fn *v; size_t n, cap; };

struct scan {
    const char *s;
    size_t n;
    size_t *lstart;   /* offsets of line starts */
    size_t nl;
    struct fns *out;
    char *names[NAMES_MAX];
    size_t depth;
};

static long line_of(const struct scan *sc, size_t off)
{
    size_t lo = 0, hi = sc->nl;
    while (hi - lo > 1) {
        size_t mid = (lo + hi) / 2;
        if (sc->lstart[mid] <= off) lo = mid; else hi = mid;
    }
    return (long)lo + 1;
}

static size_t match_brace(const char *s, size_t n, size_t open)
{
    long d = 0;
    for (size_t i = open; i < n; i++) {
        if (s[i] == '{') d++;
        else if (s[i] == '}' && --d == 0) return i;
    }
    return n ? n - 1 : 0;
}

static bool word_at(const char *s, size_t n, size_t i, const char *w)
{
    size_t l = strlen(w);
    if (i + l > n || memcmp(s + i, w, l) != 0) return false;
    if (i > 0 && lint_idc((unsigned char)s[i - 1])) return false;
    return !(i + l < n && lint_idc((unsigned char)s[i + l]));
}

static bool decision_word(const char *s, size_t i, size_t e)
{
    static const char *const words[] = { "if", "for", "while", "case", "catch", "and", "or", "BOOST_FOREACH", "BOOST_REVERSE_FOREACH" };
    for (size_t k = 0; k < sizeof words / sizeof words[0]; k++)
        if (strlen(words[k]) == e - i && memcmp(words[k], s + i, e - i) == 0) return true;
    return false;
}

/* "T&& x" and "auto&& x" are rvalue references, not a decision: glued to the type, followed by a space. */
static bool is_rvalue_ref(const char *s, size_t a, size_t b, size_t i)
{
    if (i <= a || isspace((unsigned char)s[i - 1]) || s[i - 1] == ')' || i + 2 >= b || s[i + 2] != ' ') return false;
    return lint_idc((unsigned char)s[i - 1]) || s[i - 1] == '>';
}

/* Decision points at s[*i] (0 or 1); advances *i past the token. */
static long decision_at(const char *s, size_t a, size_t b, size_t *i)
{
    size_t k = *i;
    unsigned char c = (unsigned char)s[k];
    *i = k + 1;
    if (lint_idc(c)) {
        size_t e = k;
        while (e < b && lint_idc((unsigned char)s[e])) e++;
        *i = e;
        return !isdigit(c) && decision_word(s, k, e);
    }
    if (c == '&' && s[k + 1] == '&') { *i = k + 2; return !is_rvalue_ref(s, a, b, k); }
    if (c == '|' && s[k + 1] == '|') { *i = k + 2; return 1; }
    return c == '?';
}

static long complexity_of(const char *s, size_t a, size_t b)
{
    long m = 1;
    for (size_t i = a; i < b;) m += decision_at(s, a, b, &i);
    return m;
}

static const char *const not_function[] = { "alignas", "__attribute__", "__declspec", "decltype", "noexcept", "throw", "sizeof", "typeof",
                                            "if", "while", "for", "switch", "return", "requires", "static_assert", "defined" };

static bool is_keyword_fn(const char *s, size_t a, size_t b)
{
    for (size_t k = 0; k < sizeof not_function / sizeof not_function[0]; k++)
        if (strlen(not_function[k]) == b - a && memcmp(not_function[k], s + a, b - a) == 0) return true;
    return false;
}

static size_t match_paren(const char *s, size_t n, size_t open)
{
    long d = 0;
    for (size_t i = open; i < n; i++) {
        if (s[i] == '(') d++;
        else if (s[i] == ')' && --d == 0) return i;
    }
    return n;
}

static bool all_caps_macro(const char *s, size_t a, size_t b)
{
    if (b - a < 4) return false;
    for (size_t i = a; i < b; i++)
        if (!(isupper((unsigned char)s[i]) || isdigit((unsigned char)s[i]) || s[i] == '_')) return false;
    return true;
}

struct cand { size_t po, ns, ne; };

/* Step back over a balanced "<...>" ending just before k; returns the index of its "<" (or k when there is none). */
static size_t skip_angle_back(const char *s, size_t a, size_t k)
{
    if (k <= a || s[k - 1] != '>') return k;
    long d = 0;
    while (k > a) {
        k--;
        if (s[k] == '>') d++;
        else if (s[k] == '<' && --d == 0) break;
    }
    return k;
}

static size_t ident_start_back(const char *s, size_t a, size_t k)
{
    while (k > a && lint_idc((unsigned char)s[k - 1])) k--;
    return k;
}

/* Qualified name start for the identifier beginning at st in a header beginning at a: Foo<T>::Bar::name and ~Name. */
static size_t qualified_start(const char *s, size_t a, size_t st)
{
    if (st > a && s[st - 1] == '~') st--;
    while (st >= a + 2 && s[st - 1] == ':' && s[st - 2] == ':') {
        size_t k = st - 2;
        while (k > a && isspace((unsigned char)s[k - 1])) k--;
        k = skip_angle_back(s, a, k);
        size_t ks = ident_start_back(s, a, k);
        if (ks == k) break;
        st = (ks > a && s[ks - 1] == '~') ? ks - 1 : ks;
    }
    return st;
}

/* "operator==(", "operator()(", "operator bool(" at s[i]: fills *c (parameter list "(" and name span). */
static bool operator_candidate(const char *s, size_t a, size_t b, size_t i, struct cand *c)
{
    size_t q = i + 8;
    while (q < b && isspace((unsigned char)s[q])) q++;
    if (q < b && s[q] == '(') {
        size_t r = q + 1;
        while (r < b && isspace((unsigned char)s[r])) r++;
        if (r < b && s[r] == ')') q = r + 1;
    }
    while (q < b && s[q] != '(') q++;
    if (q >= b) return false;
    c->po = q;
    c->ne = q;
    c->ns = qualified_start(s, a, i);
    return true;
}

/* The identifier before the "(" at s[i] as a candidate; false for a lambda, cast, decltype(...) and friends. */
static bool paren_candidate(const char *s, size_t a, size_t i, struct cand *c)
{
    size_t e = i;
    while (e > a && isspace((unsigned char)s[e - 1])) e--;
    size_t st = ident_start_back(s, a, e);
    if (st == e || is_keyword_fn(s, st, e) || isdigit((unsigned char)s[st])) return false;
    c->po = i;
    c->ne = e;
    c->ns = qualified_start(s, a, st);
    return true;
}

/* Locate the parameter list of a function header [a, b): its "(" (*po), the first character of the name (*ns) and the
 * end of the name (*ne). Of several candidates the last non-macro one wins (so "DEFINE_X(a) int f(int)" and trailing
 * "EXCLUSIVE_LOCKS_REQUIRED(cs)" annotations do not mislead), else the last macro (test-case macros). False when the
 * header holds no function-like parameter list. */
static bool find_params(const char *s, size_t a, size_t b, size_t *po, size_t *ns, size_t *ne)
{
    struct cand best = { 0, 0, 0 }, macro = { 0, 0, 0 }, c = { 0, 0, 0 };
    bool have = false, have_macro = false;
    for (size_t i = a; i < b; i++) {
        bool is_op = word_at(s, b, i, "operator");
        if (!is_op && s[i] != '(') continue;
        size_t open = i;
        bool found;
        if (is_op) {
            found = operator_candidate(s, a, b, i, &c);
            if (!found) break;
            open = c.po;
        } else {
            found = paren_candidate(s, a, i, &c);
        }
        i = match_paren(s, b, open);
        if (!found) continue;
        if (!is_op && all_caps_macro(s, c.ns, c.ne)) { macro = c; have_macro = true; }
        else { best = c; have = true; }
    }
    if (!have && !have_macro) return false;
    struct cand r = have ? best : macro;
    *po = r.po;
    *ns = r.ns;
    *ne = r.ne;
    return true;
}

static void squash(char *dst, size_t cap, const char *s, size_t a, size_t b)
{
    size_t o = 0;
    for (size_t i = a; i < b && o + 1 < cap; i++)
        if (!isspace((unsigned char)s[i])) dst[o++] = s[i];
    dst[o] = '\0';
}

static int nest_delta(char c)
{
    if (c == '(' || c == '<' || c == '[' || c == '{') return 1;
    if (c == ')' || c == '>' || c == ']' || c == '}') return -1;
    return 0;
}

static int arity_of(const char *s, size_t a, size_t b)    /* parameters between the parentheses (a, b exclusive) */
{
    int args = 0;
    long d = 0;
    bool any = false;
    for (size_t i = a; i < b; i++) {
        char c = s[i];
        if (isspace((unsigned char)c)) continue;
        any = true;
        if (c == ',' && d == 0) args++;
        d += nest_delta(c);
        if (d < 0) d = 0;
    }
    if (!any) return 0;
    char buf[8];
    squash(buf, sizeof buf, s, a, b < a + 7 ? b : a + 7);
    return strcmp(buf, "void") == 0 ? 0 : args + 1;
}

static void fns_add(struct fns *f, char *key, long cx, long lines)
{
    if (f->n == f->cap) { f->cap = f->cap ? f->cap * 2 : 32; f->v = lint_xrealloc(f->v, f->cap * sizeof *f->v); }
    f->v[f->n].key = key;
    f->v[f->n].cx = cx;
    f->v[f->n].lines = lines;
    f->n++;
}

static bool key_taken(const struct fns *f, const char *key)
{
    for (size_t i = 0; i < f->n; i++)
        if (strcmp(f->v[i].key, key) == 0) return true;
    return false;
}

static void record(struct scan *sc, size_t hs, size_t open, size_t po, size_t ns, size_t ne)
{
    (void)hs;
    const char *s = sc->s;
    size_t close = match_brace(s, sc->n, open), pc = match_paren(s, open, po);
    char nm[256], qual[400] = "", args[200];
    squash(nm, sizeof nm, s, ns, ne);
    for (size_t i = 0; i < sc->depth && i < NAMES_MAX; i++) {
        if (!sc->names[i]) continue;
        if (strlen(qual) + strlen(sc->names[i]) + 3 < sizeof qual) { memcpy(qual + strlen(qual), sc->names[i], strlen(sc->names[i]) + 1); memcpy(qual + strlen(qual), "::", 3); }
    }
    char key[1000];
    size_t pe = pc < open ? pc : open;
    if (all_caps_macro(s, ns, ne)) {
        squash(args, sizeof args, s, po + 1, pe);
        snprintf(key, sizeof key, "%s%s(%s)", qual, nm, args);
    } else {
        snprintf(key, sizeof key, "%s%s(%d)", qual, nm, arity_of(s, po + 1, pe));
    }
    char uniq[1024];
    snprintf(uniq, sizeof uniq, "%s", key);
    for (int k = 2; key_taken(sc->out, uniq); k++) snprintf(uniq, sizeof uniq, "%s#%d", key, k);
    long start = line_of(sc, ns), end = line_of(sc, close);
    fns_add(sc->out, lint_xstrdup(uniq), complexity_of(s, open + 1, close), end - start + 1);
}

static size_t skip_ws_back(const char *s, size_t a, size_t i)    /* index of the last non-space char before i, or a-1 style: returns i when none */
{
    while (i > a && isspace((unsigned char)s[i - 1])) i--;
    return i;
}

/* Skip a "template <...>" prefix: index just past its closing ">", or a when there is none. */
static size_t skip_template(const char *s, size_t a, size_t b)
{
    size_t i = a;
    while (i < b && isspace((unsigned char)s[i])) i++;
    if (!word_at(s, b, i, "template")) return a;
    i += 8;
    while (i < b && isspace((unsigned char)s[i])) i++;
    if (i >= b || s[i] != '<') return a;
    long d = 0;
    for (; i < b; i++) {
        if (s[i] == '<') d++;
        else if (s[i] == '>' && --d == 0) return i + 1;
    }
    return a;
}

static bool header_has_call_or_init(const char *s, size_t a, size_t b)   /* a function, or a variable with an initialiser */
{
    for (size_t i = a; i < b; i++)
        if (s[i] == '(' || s[i] == '=') return true;
    return false;
}

/* The container keyword that starts at s[i], or -1; the name after it goes to name (empty for extern, unnamed, enum). */
static int keyword_at(const char *s, size_t b, size_t i)
{
    static const char *const kw[] = { "namespace", "extern", "class", "struct", "union", "enum" };
    for (size_t k = 0; k < sizeof kw / sizeof kw[0]; k++)
        if (word_at(s, b, i, kw[k])) return (int)k;
    return -1;
}

static void container_name(const char *s, size_t b, size_t e, char *name, size_t cap)
{
    while (e < b && isspace((unsigned char)s[e])) e++;
    size_t ne = e;
    while (ne < b && (lint_idc((unsigned char)s[ne]) || s[ne] == ':')) ne++;   /* namespace a::b */
    if (ne > e) squash(name, cap, s, e, ne);
    if (!strcmp(name, "final") || !strcmp(name, "alignas")) name[0] = '\0';
}

static bool header_is_container(const char *s, size_t a, size_t b, char *name, size_t cap)
{
    static const size_t kwlen[] = { 9, 6, 5, 6, 5, 4 };
    name[0] = '\0';
    a = skip_template(s, a, b);
    if (header_has_call_or_init(s, a, b)) return false;
    for (size_t i = a; i < b; i++) {
        int k = lint_idc((unsigned char)s[i]) ? keyword_at(s, b, i) : -1;
        if (k < 0) continue;
        if (k != 5) container_name(s, b, i + kwlen[k], name, cap);           /* 5 is enum: never named */
        return true;
    }
    return false;
}

static void names_pop(struct scan *sc)
{
    if (!sc->depth) return;
    sc->depth--;
    if (sc->depth < NAMES_MAX) { free(sc->names[sc->depth]); sc->names[sc->depth] = NULL; }
}

static void names_push(struct scan *sc, const char *name)
{
    if (sc->depth < NAMES_MAX) sc->names[sc->depth] = name[0] ? lint_xstrdup(name) : NULL;
    sc->depth++;
}

/* Header state of the statement being read at namespace, class or file level. */
struct hdr { size_t hs, popen_i, initpos; long pd; bool initlist, seen_close; };

static void hdr_reset(struct hdr *h, size_t hs)
{
    h->hs = hs;
    h->initlist = h->seen_close = false;
}

/* "SUITE(x)  CASE(y) {": an all-caps macro call followed by an upper-case token is a statement of its own. */
static void on_paren_close(const struct scan *sc, struct hdr *h, size_t i)
{
    const char *s = sc->s;
    if (h->pd > 0) h->pd--;
    if (h->pd) return;
    h->seen_close = true;
    size_t e = h->popen_i;
    while (e > h->hs && isspace((unsigned char)s[e - 1])) e--;
    size_t st = ident_start_back(s, h->hs, e), nx = i + 1;
    while (nx < sc->n && isspace((unsigned char)s[nx])) nx++;
    if (st < e && all_caps_macro(s, st, e) && nx < sc->n && isupper((unsigned char)s[nx]) && !h->initlist) hdr_reset(h, i + 1);
}

static bool is_access_label(const char *s, size_t a, size_t i)
{
    static const char *const w[] = { "public", "private", "protected", "slots", "signals" };
    while (a < i && isspace((unsigned char)s[a])) a++;
    for (size_t k = 0; k < sizeof w / sizeof w[0]; k++)
        if (word_at(s, i, a, w[k])) return true;
    return false;
}

static void on_colon(const char *s, struct hdr *h, size_t i)
{
    if (is_access_label(s, h->hs, i)) hdr_reset(h, i + 1);
    else if (h->seen_close && !h->initlist) { h->initlist = true; h->initpos = i; }
}

/* A "{" at statement level: walk into a container, record a function, or skip an initialiser. Returns the new i. */
static size_t on_open_brace(struct scan *sc, struct hdr *h, size_t i)
{
    const char *s = sc->s;
    size_t n = sc->n;
    if (h->pd > 0) return match_brace(s, n, i);                                    /* argument braces, lambda arguments */
    size_t p = skip_ws_back(s, h->hs, i), prev = p ? (unsigned char)s[p - 1] : 0;
    if (h->initlist && (lint_idc(prev) || prev == '>')) return match_brace(s, n, i);   /* member{init} */
    char name[128];
    if (header_is_container(s, h->hs, i, name, sizeof name)) {
        names_push(sc, name);
        hdr_reset(h, i + 1);
        return i;
    }
    size_t po, ns, ne;
    if (!find_params(s, h->hs, h->initlist ? h->initpos : i, &po, &ns, &ne)) return match_brace(s, n, i);   /* file-scope lambda body */
    record(sc, h->hs, i, po, ns, ne);
    size_t close = match_brace(s, n, i);
    hdr_reset(h, close + 1);
    h->pd = 0;
    return close;
}

static bool is_scope_colon(const char *s, size_t n, size_t i)
{
    return !(i + 1 < n && s[i + 1] == ':') && !(i > 0 && s[i - 1] == ':');
}

static void scan_text(struct scan *sc)
{
    const char *s = sc->s;
    struct hdr h = { 0, 0, 0, 0, false, false };
    for (size_t i = 0; i < sc->n; i++) {
        char c = s[i];
        if (c == '(') { if (h.pd++ == 0) h.popen_i = i; }
        else if (c == ')') on_paren_close(sc, &h, i);
        else if (c == ';') { hdr_reset(&h, i + 1); h.pd = 0; }
        else if (c == ':' && h.pd == 0 && is_scope_colon(s, sc->n, i)) on_colon(s, &h, i);
        else if (c == '}') { names_pop(sc); hdr_reset(&h, i + 1); h.pd = 0; }
        else if (c == '{') i = on_open_brace(sc, &h, i);
    }
}

/* Scan one scrubbed file. Returns the functions found. Container names are copied, freed by the caller of scan_file. */
static struct fns scan_file(char *txt, size_t len)
{
    struct fns out = { NULL, 0, 0 };
    scrub_file(txt, len);
    struct scan sc = { txt, len, NULL, 0, &out, { NULL }, 0 };
    size_t cap = 1;
    for (size_t i = 0; i < len; i++)
        if (txt[i] == '\n') cap++;
    sc.lstart = lint_xrealloc(NULL, cap * sizeof *sc.lstart);
    sc.lstart[sc.nl++] = 0;
    for (size_t i = 0; i < len; i++)
        if (txt[i] == '\n') sc.lstart[sc.nl++] = i + 1;
    scan_text(&sc);
    for (size_t i = 0; i < NAMES_MAX; i++) free(sc.names[i]);
    free(sc.lstart);
    return out;
}

/* ---- the two rules --------------------------------------------------------------------------------------- */

static int run_rule(const char *rule, const char *what, long cap, bool lines, bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!in_shape_scope(lint_files[i])) continue;
        size_t len = 0;
        char *txt = lint_slurp(lint_files[i], &len);
        if (!txt) continue;
        scanned++;
        struct fns f = scan_file(txt, len);
        for (size_t k = 0; k < f.n; k++) {
            long v = lines ? f.v[k].lines : f.v[k].cx;
            if (v > cap) {
                size_t m = strlen(lint_files[i]) + strlen(f.v[k].key) + 2;
                char *row = lint_xrealloc(NULL, m);
                snprintf(row, m, "%s\t%s", lint_files[i], f.v[k].key);
                lint_rows_add(&cur, row, v);
                free(row);
            }
            free(f.v[k].key);
        }
        free(f.v);
        free(txt);
    }
    return lint_ratchet(rule, what, &cur, scanned, update);
}

int lint_rule_complexity(bool update)
{
    return run_rule("complexity", "cyclomatic complexity above 15 per function", COMPLEXITY_CAP, false, update);
}

int lint_rule_long_functions(bool update)
{
    return run_rule("long-functions", "line count above 500 per function", LONG_FUNCTION_CAP, true, update);
}
