/* zcl-dev mutate: the mutation operators. Pure text in, sites out: nothing here opens a file.
 *
 * Derived from Z23 tools/dev/mutation_ops.c@9a191ef7b, Apache-2.0; changed. See zcutil/tools/NOTICE
 *
 * Changed from Z23: C++ raw strings and digit separators are masked; relational and logical flips
 * fire only on operators with whitespace on both sides (no template brackets, never `<<` or `>>`);
 * return flips only `return true;` and `return false;`; the `[n]` of an array declarator is not a
 * boundary site; statement deletion takes only a one-line call statement; no unary-not or
 * true/false operators.
 */
#include "mutate_ops.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const class_names[MUT_CLASS_COUNT] = {
    "relational", "logical", "boundary", "return", "statement",
};

const char *mut_class_name(enum mut_class c)
{
    return (unsigned)c < MUT_CLASS_COUNT ? class_names[c] : "unknown";
}

static int class_by_name(const char *s, size_t n)
{
    for (int c = 0; c < MUT_CLASS_COUNT; c++)
        if (strlen(class_names[c]) == n && memcmp(class_names[c], s, n) == 0) return c;
    return -1;
}

bool mut_class_parse(const char *list, unsigned *bits)
{
    *bits = 0;
    const char *p = list;
    while (*p) {
        size_t n = strcspn(p, ",");
        int c = class_by_name(p, n);
        if (c < 0) return false;
        *bits |= 1u << c;
        p += n;
        if (*p == ',') p++;
    }
    return *bits != 0;
}

/* ---- the code mask ---------------------------------------------------------------------------
 * #define stays code (its bound is the highest-signal boundary mutant); every other directive,
 * comments and literals are masked. */
static bool idc(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static bool blank(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

enum mstate { M_CODE, M_LINE, M_BLOCK, M_STR, M_CHR, M_DIR };

struct mask {
    const char *t;
    size_t len;
    unsigned char *m;
    enum mstate st, resume;
    bool bol; /* only blanks so far on this line */
};

static bool next_is(const struct mask *k, size_t i, char c)
{
    return i + 1 < k->len && k->t[i + 1] == c;
}

static size_t skip_blanks(const char *t, size_t len, size_t i)
{
    while (i < len && (t[i] == ' ' || t[i] == '\t')) i++;
    return i;
}

static bool is_define(const char *t, size_t len, size_t hash)
{
    size_t i = skip_blanks(t, len, hash + 1);
    return i + 6 <= len && memcmp(t + i, "define", 6) == 0 && (i + 6 == len || !idc(t[i + 6]));
}

/* The identifier that ends right before i (a literal prefix such as u8, L or R). */
static size_t ident_back(const char *t, size_t i)
{
    size_t k = i;
    while (k > 0 && idc(t[k - 1])) k--;
    return k;
}

static bool is_prefix(const char *t, size_t a, size_t b, const char *const *set)
{
    for (; *set; set++)
        if (strlen(*set) == b - a && memcmp(t + a, *set, b - a) == 0) return true;
    return false;
}

static const char *const char_prefixes[] = {"", "L", "u", "U", "u8", NULL};
static const char *const raw_prefixes[] = {"R", "LR", "uR", "UR", "u8R", NULL};

/* Index of the closing quote of a raw string whose opening quote is at q, or SIZE_MAX. */
static size_t raw_end(const char *t, size_t len, size_t q)
{
    size_t d = q + 1, n = 0;
    while (d + n < len && n <= 16 && t[d + n] != '(') {
        char c = t[d + n];
        if (c == ')' || c == '\\' || c == ' ' || c == '"' || c == '\n') return SIZE_MAX;
        n++;
    }
    if (d + n >= len || n > 16) return SIZE_MAX;
    for (size_t j = d + n + 1; j + n + 1 < len; j++)
        if (t[j] == ')' && memcmp(t + j + 1, t + d, n) == 0 && t[j + 1 + n] == '"') return j + 1 + n;
    return SIZE_MAX;
}

/* A '"' in code: a raw string is skipped whole, any other string starts the string state. */
static size_t mask_quote(struct mask *k, size_t i)
{
    size_t a = ident_back(k->t, i);
    k->bol = false;
    if (a < i && is_prefix(k->t, a, i, raw_prefixes)) {
        size_t e = raw_end(k->t, k->len, i);
        if (e != SIZE_MAX) {
            for (size_t j = a; j < i; j++) k->m[j] = 0;
            return e;
        }
    }
    k->st = M_STR;
    return i;
}

/* A '\'' in code: a character literal unless an identifier or number glued to it makes it a C++
 * digit separator (1'000), which stays code. */
static size_t mask_apostrophe(struct mask *k, size_t i)
{
    size_t a = ident_back(k->t, i);
    k->bol = false;
    if (a == i || is_prefix(k->t, a, i, char_prefixes)) {
        k->st = M_CHR;
        return i;
    }
    k->m[i] = 1;
    return i;
}

static size_t mask_hash(struct mask *k, size_t i)
{
    if (!is_define(k->t, k->len, i)) {
        k->st = M_DIR;
        return i;
    }
    k->bol = false;
    return skip_blanks(k->t, k->len, i + 1) + 5; /* last byte of "define" */
}

static size_t mask_code(struct mask *k, size_t i)
{
    char c = k->t[i];
    if (k->bol && c == '#') return mask_hash(k, i);
    if (c == '/' && next_is(k, i, '/')) {
        k->st = M_LINE;
    } else if (c == '/' && next_is(k, i, '*')) {
        k->resume = M_CODE;
        k->st = M_BLOCK;
        return i + 1;
    } else if (c == '"') {
        return mask_quote(k, i);
    } else if (c == '\'') {
        return mask_apostrophe(k, i);
    } else if (c == '\n') {
        k->bol = true;
    } else {
        if (!blank(c)) k->bol = false;
        k->m[i] = 1;
    }
    return i;
}

static bool line_ends(const struct mask *k, size_t i)
{
    return k->t[i] == '\n' && (i == 0 || k->t[i - 1] != '\\');
}

static size_t mask_other(struct mask *k, size_t i)
{
    char c = k->t[i];
    switch (k->st) {
    case M_LINE:
        if (line_ends(k, i)) { k->st = M_CODE; k->bol = true; }
        return i;
    case M_BLOCK:
        if (c == '*' && next_is(k, i, '/')) { k->st = k->resume; return i + 1; }
        return i;
    case M_STR:
    case M_CHR:
        if (c == '\\') return i + 1;
        if (c == (k->st == M_STR ? '"' : '\'')) k->st = M_CODE;
        return i;
    default: /* M_DIR */
        if (c == '/' && next_is(k, i, '*')) { k->resume = M_DIR; k->st = M_BLOCK; return i + 1; }
        if (line_ends(k, i)) { k->st = M_CODE; k->bol = true; }
        return i;
    }
}

void mut_code_mask(const char *text, size_t len, unsigned char *mask)
{
    struct mask k = {text, len, mask, M_CODE, M_CODE, true};
    memset(mask, 0, len);
    for (size_t i = 0; i < len; i++)
        i = k.st == M_CODE ? mask_code(&k, i) : mask_other(&k, i);
}

/* ---- site emission ------------------------------------------------------------------------- */
struct scan {
    const char *t;
    size_t len;
    const unsigned char *m;
    struct mut_sites *out;
    size_t line, line_start;
    bool oom;
};

static void copy_text(char *dst, const char *src, size_t n)
{
    if (n < MUT_TEXT_MAX) {
        memcpy(dst, src, n);
        dst[n] = 0;
        return;
    }
    memcpy(dst, src, MUT_TEXT_MAX - 4);
    memcpy(dst + MUT_TEXT_MAX - 4, "...", 4);
}

static void emit(struct scan *s, size_t off, size_t span, enum mut_class c, const char *repl)
{
    struct mut_sites *o = s->out;
    if (o->n == o->cap) {
        size_t cap = o->cap ? o->cap * 2 : 64;
        struct mut_site *v = realloc(o->v, cap * sizeof *v);
        if (!v) { s->oom = true; return; }
        o->v = v;
        o->cap = cap;
    }
    struct mut_site *x = &o->v[o->n++];
    memset(x, 0, sizeof *x);
    x->offset = off;
    x->span = span;
    x->line = s->line;
    x->column = off - s->line_start + 1;
    x->cls = c;
    copy_text(x->orig, s->t + off, span);
    (void)snprintf(x->repl, sizeof x->repl, "%s", repl);
}

/* ---- relational and logical: an operator token with whitespace on both sides -------------- */
struct flip { const char *from, *to; enum mut_class c; };
static const struct flip flips[] = {
    {"<=", "<", MUT_RELATIONAL}, {">=", ">", MUT_RELATIONAL}, {"==", "!=", MUT_RELATIONAL},
    {"!=", "==", MUT_RELATIONAL}, {"&&", "||", MUT_LOGICAL}, {"||", "&&", MUT_LOGICAL},
    {"<", "<=", MUT_RELATIONAL}, {">", ">=", MUT_RELATIONAL},
};

static bool ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* `> >` closing two templates and `operator <` are not comparisons. */
static bool comparison_context(const struct scan *s, size_t i)
{
    size_t j = i;
    while (j > 0 && ws(s->t[j - 1])) j--;
    if (j == 0 || s->t[j - 1] == '<' || s->t[j - 1] == '>') return false;
    size_t a = ident_back(s->t, j);
    return !(j - a == 8 && memcmp(s->t + a, "operator", 8) == 0);
}

static bool scan_flip(struct scan *s, size_t i)
{
    if (i == 0 || !ws(s->t[i - 1])) return false;
    for (size_t f = 0; f < sizeof flips / sizeof flips[0]; f++) {
        size_t n = strlen(flips[f].from);
        if (i + n >= s->len || memcmp(s->t + i, flips[f].from, n) != 0) continue;
        if (!ws(s->t[i + n]) || !comparison_context(s, i)) return false;
        emit(s, i, n, flips[f].c, flips[f].to);
        return true;
    }
    return false;
}

/* ---- boundary: a plain decimal integer literal --------------------------------------------- */
static size_t prev_code_char(const char *t, size_t i)
{
    while (i > 0 && ws(t[i - 1])) i--;
    return i > 0 ? (size_t)(unsigned char)t[i - 1] : 0;
}

static bool literal_end_ok(const char *t, size_t len, size_t j)
{
    if (j < len && strchr(".xXbBeE'", t[j]) != NULL) return false;
    while (j < len && strchr("uUlL", t[j]) != NULL) j++;
    return !(j < len && (idc(t[j]) || t[j] == '.' || t[j] == '\''));
}

static bool in_declarator(const char *t, size_t len, size_t i, size_t j)
{
    if (prev_code_char(t, i) != '[') return false;
    while (j < len && strchr("uUlL", t[j]) != NULL) j++;
    while (j < len && ws(t[j])) j++;
    return j < len && t[j] == ']';
}

/* Digits of a decimal literal at i, or 0. Hex, binary, octal and float literals are rejected. */
static size_t decimal_at(const char *t, size_t len, size_t i)
{
    if (t[i] < '0' || t[i] > '9') return 0;
    if (i > 0 && (idc(t[i - 1]) || t[i - 1] == '.' || t[i - 1] == '\'')) return 0;
    size_t n = 0;
    while (i + n < len && t[i + n] >= '0' && t[i + n] <= '9') n++;
    if (n > 18 || (n > 1 && t[i] == '0')) return 0;
    if (!literal_end_ok(t, len, i + n) || in_declarator(t, len, i, i + n)) return SIZE_MAX;
    return n;
}

static size_t scan_integer(struct scan *s, size_t i)
{
    size_t n = decimal_at(s->t, s->len, i);
    if (n == 0 || n == SIZE_MAX) return n == SIZE_MAX ? 1 : 0;
    char buf[24], repl[24];
    memcpy(buf, s->t + i, n);
    buf[n] = 0;
    unsigned long long v = strtoull(buf, NULL, 10);
    (void)snprintf(repl, sizeof repl, "%llu", v + 1);
    emit(s, i, n, MUT_BOUNDARY, repl);
    if (v > 0) {
        (void)snprintf(repl, sizeof repl, "%llu", v - 1);
        emit(s, i, n, MUT_BOUNDARY, repl);
    }
    return n;
}

/* ---- return true; <-> return false; -------------------------------------------------------- */
static bool word_at(const char *t, size_t len, size_t i, const char *w)
{
    size_t n = strlen(w);
    if (i > 0 && idc(t[i - 1])) return false;
    return i + n <= len && memcmp(t + i, w, n) == 0 && (i + n == len || !idc(t[i + n]));
}

static bool scan_return(struct scan *s, size_t i)
{
    if (!word_at(s->t, s->len, i, "return")) return false;
    size_t j = skip_blanks(s->t, s->len, i + 6);
    bool is_true = word_at(s->t, s->len, j, "true");
    if (!is_true && !word_at(s->t, s->len, j, "false")) return false;
    j = skip_blanks(s->t, s->len, j + (is_true ? 4 : 5));
    if (j >= s->len || s->t[j] != ';' || j == i + 6) return false;
    emit(s, i, j - i + 1, MUT_RETURN, is_true ? "return false;" : "return true;");
    return true;
}

/* ---- statement: a one-line call statement ending in `);` ----------------------------------- */
static const char *const keywords[] = {
    "if", "for", "while", "switch", "return", "do", "else", "case", "default", "goto", "break",
    "continue", "typedef", "sizeof", "throw", "delete", "new", "using", "namespace", "template",
    "static_assert", "typename", "class", "struct", "enum", "union", "public", "private",
    "protected", "friend", "operator", "co_return", "co_await", "co_yield", NULL,
};

static bool starts_with_keyword(const char *t, size_t len, size_t i)
{
    for (const char *const *k = keywords; *k; k++)
        if (word_at(t, len, i, *k)) return true;
    return false;
}

struct stmt {
    int depth;
    bool call;   /* a '(' was seen */
    size_t last; /* last non-blank code byte */
};

/* Brackets and braces: 1 continue, 0 reject, -1 not one of them. */
static int stmt_bracket(struct stmt *st, char c)
{
    if (c == '(' || c == '[') {
        st->call |= c == '(';
        st->depth++;
        return 1;
    }
    if (c == ')' || c == ']') return --st->depth < 0 ? 0 : 1;
    return c == '{' || c == '}' ? 0 : -1;
}

/* Punctuation outside any bracket: 0 reject, 2 the terminating ';', 1 continue. */
static int stmt_top(const char *t, size_t j)
{
    char c = t[j];
    if (c == '=' || c == ',' || c == '?') return 0;
    if (c == ':' && t[j + 1] != ':' && t[j - 1] != ':') return 0; /* a label or a case */
    return c == ';' ? 2 : 1;
}

/* One code byte of a candidate statement: 1 continue, 0 reject, 2 the terminating ';'. */
static int stmt_byte(struct stmt *st, const char *t, size_t j)
{
    char c = t[j];
    int r = stmt_bracket(st, c);
    if (r < 0 && st->depth == 0) r = stmt_top(t, j);
    if (r < 0) r = 1;
    if (r == 1 && !st->call && blank(c) && idc(t[j + 1])) return 0; /* a type and a name: a declaration */
    if (r == 1 && !blank(c)) st->last = j;
    return r;
}

/* After the ';' only blanks and comments may follow on the line. */
static bool rest_of_line_empty(const struct scan *s, size_t j)
{
    for (; j < s->len && s->t[j] != '\n'; j++)
        if (s->m[j] && !blank(s->t[j])) return false;
    return true;
}

static size_t statement_end(const struct scan *s, size_t i)
{
    struct stmt st = {0, false, i};
    for (size_t j = i; j + 1 < s->len && s->t[j] != '\n'; j++) {
        if (!s->m[j]) continue;
        int r = stmt_byte(&st, s->t, j);
        if (r == 0) return SIZE_MAX;
        if (r == 2) {
            bool ok = st.call && s->t[st.last] == ')' && rest_of_line_empty(s, j + 1);
            return ok ? j : SIZE_MAX;
        }
    }
    return SIZE_MAX;
}

static void scan_statement(struct scan *s, size_t i)
{
    const char *t = s->t;
    bool scope = t[i] == ':' && i + 1 < s->len && t[i + 1] == ':';
    if (!scope && (!idc(t[i]) || (t[i] >= '0' && t[i] <= '9'))) return;
    if (t[skip_blanks(t, s->len, s->line_start)] == '#') return; /* a #define body */
    if (starts_with_keyword(t, s->len, i)) return;
    size_t end = statement_end(s, i);
    if (end != SIZE_MAX) emit(s, i, end - i + 1, MUT_STATEMENT, "(void)0;");
}

/* ---- the scan ------------------------------------------------------------------------------ */
/* Skips the rest of an identifier so digits inside it are never a literal. */
static size_t skip_ident(const struct scan *s, size_t i)
{
    while (i + 1 < s->len && idc(s->t[i + 1]) && s->m[i + 1]) i++;
    return i;
}

/* Emits the sites starting at code byte i; returns the last byte consumed. */
static size_t scan_byte(struct scan *s, size_t i, bool first)
{
    if (first) scan_statement(s, i);
    if (scan_flip(s, i)) return i;
    (void)scan_return(s, i);
    size_t n = scan_integer(s, i);
    if (n > 0) return i + n - 1;
    return idc(s->t[i]) ? skip_ident(s, i) : i;
}

bool mut_enumerate(const char *text, size_t len, struct mut_sites *out)
{
    if (len == 0) return true;
    unsigned char *mask = malloc(len);
    if (!mask) return false;
    mut_code_mask(text, len, mask);
    struct scan s = {text, len, mask, out, 1, 0, false};
    bool first = true;
    for (size_t i = 0; i < len && !s.oom; i++) {
        if (text[i] == '\n') {
            s.line++;
            s.line_start = i + 1;
            first = true;
            continue;
        }
        if (!mask[i] || blank(text[i])) continue;
        i = scan_byte(&s, i, first);
        first = false;
    }
    free(mask);
    return !s.oom;
}

void mut_sites_free(struct mut_sites *s)
{
    free(s->v);
    s->v = NULL;
    s->n = s->cap = 0;
}

char *mut_apply(const char *text, size_t len, const struct mut_site *s, size_t *out_len)
{
    if (s->offset > len || s->span > len - s->offset) return NULL;
    size_t rl = strlen(s->repl), total = len - s->span + rl;
    char *buf = malloc(total + 1);
    if (!buf) return NULL;
    memcpy(buf, text, s->offset);
    memcpy(buf + s->offset, s->repl, rl);
    memcpy(buf + s->offset + rl, text + s->offset + s->span, len - s->offset - s->span);
    buf[total] = 0;
    *out_len = total;
    return buf;
}
