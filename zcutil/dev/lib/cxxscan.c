/* cxxscan: C/C++ lexer for developer tools. MIT, like the rest of zclassicd. See cxxscan.h. */
#include "cxxscan.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *xalloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fputs("cxxscan: out of memory\n", stderr);
        exit(2);
    }
    return q;
}

static int is_id(int c) { return isalnum((unsigned char)c) || c == '_'; }

/* ---- masking ---------------------------------------------------------------------------- */

char *cxx_mask(const char *src, size_t n)
{
    char *m = xalloc(NULL, n + 1);
    memcpy(m, src, n);
    m[n] = 0;
    size_t i = 0;
    while (i < n) {
        char c = m[i];
        if (c == '/' && i + 1 < n && m[i + 1] == '/') {
            while (i < n && m[i] != '\n') {
                m[i++] = ' ';
            }
        } else if (c == '/' && i + 1 < n && m[i + 1] == '*') {
            m[i++] = ' ';
            m[i++] = ' ';
            while (i < n && !(m[i] == '*' && i + 1 < n && m[i + 1] == '/')) {
                if (m[i] != '\n') m[i] = ' ';
                i++;
            }
            if (i < n) {
                m[i++] = ' ';
                if (i < n) m[i++] = ' ';
            }
        } else if (c == '"') {
            int raw = i > 0 && m[i - 1] == 'R' && (i < 2 || !is_id(m[i - 2]) || m[i - 2] == '8' || m[i - 2] == 'u' ||
                                                  m[i - 2] == 'U' || m[i - 2] == 'L');
            if (raw) {
                char delim[20];
                size_t d = 0, j = i + 1;
                while (j < n && m[j] != '(' && d < 16 && m[j] != '"' && m[j] != '\n') delim[d++] = m[j++];
                if (j < n && m[j] == '(') {
                    delim[d] = 0;
                    j++;
                    /* find )delim" */
                    size_t k = j;
                    int found = 0;
                    while (k < n) {
                        if (m[k] == ')' && !strncmp(m + k + 1, delim, d) && k + 1 + d < n && m[k + 1 + d] == '"') {
                            found = 1;
                            break;
                        }
                        k++;
                    }
                    size_t end = found ? k + 1 + d : n; /* index of closing quote, or n */
                    for (size_t x = i + 1; x < end; x++)
                        if (m[x] != '\n') m[x] = ' ';
                    i = found ? end + 1 : n;
                    continue;
                }
            }
            i++;
            while (i < n && m[i] != '"' && m[i] != '\n') {
                if (m[i] == '\\' && i + 1 < n && m[i + 1] != '\n') {
                    m[i++] = ' ';
                    m[i++] = ' ';
                } else {
                    m[i++] = ' ';
                }
            }
            if (i < n && m[i] == '"') i++;
        } else if (c == '\'') {
            /* digit separator (1'000) or a prefix like u8'x'; otherwise a character literal */
            if (i > 0 && is_id(m[i - 1]) && m[i - 1] != 'L' && m[i - 1] != 'u' && m[i - 1] != 'U' && m[i - 1] != '8') {
                i++;
                continue;
            }
            i++;
            size_t guard = 0;
            while (i < n && m[i] != '\'' && m[i] != '\n' && guard++ < 16) {
                if (m[i] == '\\' && i + 1 < n && m[i + 1] != '\n') {
                    m[i++] = ' ';
                    m[i++] = ' ';
                } else {
                    m[i++] = ' ';
                }
            }
            if (i < n && m[i] == '\'') i++;
        } else {
            i++;
        }
    }
    return m;
}

void cxx_blank_directives(char *m, size_t n)
{
    size_t i = 0;
    while (i < n) {
        size_t ls = i;
        while (i < n && (m[i] == ' ' || m[i] == '\t')) i++;
        if (i < n && m[i] == '#') {
            for (;;) {
                size_t j = i;
                while (j < n && m[j] != '\n') j++;
                int cont = 0;
                size_t k = j;
                while (k > ls && (m[k - 1] == ' ' || m[k - 1] == '\t' || m[k - 1] == '\r')) k--;
                if (k > ls && m[k - 1] == '\\') cont = 1;
                for (size_t x = ls; x < j; x++) m[x] = ' ';
                i = j;
                if (cont && i < n) {
                    i++;
                    ls = i;
                    continue;
                }
                break;
            }
        } else {
            while (i < n && m[i] != '\n') i++;
        }
        if (i < n) i++;
    }
}

int cxx_line_of(const char *src, size_t off)
{
    int line = 1;
    for (size_t i = 0; i < off && src[i]; i++)
        if (src[i] == '\n') line++;
    return line;
}

/* ---- includes --------------------------------------------------------------------------- */

void cxx_includes(const char *src, size_t n, CxxIncs *out)
{
    char *m = cxx_mask(src, n);
    size_t i = 0;
    int line = 1;
    while (i < n) {
        size_t ls = i;
        while (i < n && (m[i] == ' ' || m[i] == '\t')) i++;
        if (i < n && m[i] == '#') {
            size_t j = i + 1;
            while (j < n && (m[j] == ' ' || m[j] == '\t')) j++;
            if (n - j > 7 && !strncmp(m + j, "include", 7) && !is_id(m[j + 7])) {
                j += 7;
                while (j < n && (m[j] == ' ' || m[j] == '\t')) j++;
                char open = j < n ? m[j] : 0;
                if (open == '"' || open == '<') {
                    char close = open == '"' ? '"' : '>';
                    size_t k = j + 1;
                    while (k < n && m[k] != close && m[k] != '\n') k++;
                    if (k < n && m[k] == close && k - j - 1 < sizeof out->v[0].name) {
                        if (out->n == out->cap) {
                            out->cap = out->cap ? out->cap * 2 : 16;
                            out->v = xalloc(out->v, out->cap * sizeof *out->v);
                        }
                        CxxInc *e = &out->v[out->n++];
                        memcpy(e->name, src + j + 1, k - j - 1);
                        e->name[k - j - 1] = 0;
                        e->angle = open == '<';
                        e->line = line;
                    }
                }
            }
        }
        (void)ls;
        while (i < n && m[i] != '\n') i++;
        if (i < n) {
            i++;
            line++;
        }
    }
    free(m);
}

/* ---- definitions ------------------------------------------------------------------------ */

typedef struct {
    int kind;       /* 0 namespace / extern "C", 1 class */
    char name[96];
    size_t def;     /* index into defs for a class */
} Scope;

static const char *const QUAL_WORDS[] = {"const", "volatile", "noexcept", "override", "final", "throw", "mutable", "try", NULL};

static int word_is(const char *p, size_t len, const char *w)
{
    return strlen(w) == len && !strncmp(p, w, len);
}

static int is_qual(const char *p, size_t len)
{
    for (int i = 0; QUAL_WORDS[i]; i++)
        if (word_is(p, len, QUAL_WORDS[i])) return 1;
    return 0;
}

static int allcaps(const char *p, size_t len)
{
    int up = 0;
    for (size_t i = 0; i < len; i++) {
        if (islower((unsigned char)p[i])) return 0;
        if (isupper((unsigned char)p[i])) up++;
    }
    return up >= 2;
}

/* h[0..len) is the header. Skips a balanced (...) group starting at h[i]=='('; returns index after. */
static size_t skip_parens(const char *h, size_t len, size_t i)
{
    int d = 0;
    for (; i < len; i++) {
        if (h[i] == '(') d++;
        else if (h[i] == ')' && --d == 0) return i + 1;
    }
    return len;
}

/* After a closing paren, is the rest of the header only qualifiers, annotations, a trailing
 * return type or a constructor initialiser list? */
static int rest_ok(const char *h, size_t len, size_t i)
{
    for (;;) {
        while (i < len && isspace((unsigned char)h[i])) i++;
        if (i >= len) return 1;
        if (h[i] == '&') {
            i++;
            continue;
        }
        if (h[i] == ':' && (i + 1 >= len || h[i + 1] != ':')) return 1; /* init list */
        if (h[i] == '-' && i + 1 < len && h[i + 1] == '>') return 1;     /* trailing return */
        if (h[i] == '[' && i + 1 < len && h[i + 1] == '[') { /* [[attr]] */
            while (i < len && !(h[i] == ']' && i + 1 < len && h[i + 1] == ']')) i++;
            i += 2;
            continue;
        }
        if (!is_id(h[i])) return 0;
        size_t s = i;
        while (i < len && is_id(h[i])) i++;
        size_t wl = i - s;
        int macro = allcaps(h + s, wl) || (wl > 2 && h[s] == '_' && h[s + 1] == '_');
        if (!is_qual(h + s, wl) && !macro) return 0;
        size_t k = i;
        while (k < len && isspace((unsigned char)h[k])) k++;
        if (k < len && h[k] == '(') i = skip_parens(h, len, k);
    }
}

/* Drops a leading template<...> header; returns the new start. */
static size_t strip_template(const char *h, size_t len, size_t i)
{
    for (;;) {
        while (i < len && isspace((unsigned char)h[i])) i++;
        if (len - i > 8 && !strncmp(h + i, "template", 8) && !is_id(h[i + 8])) {
            size_t j = i + 8;
            while (j < len && isspace((unsigned char)h[j])) j++;
            if (j < len && h[j] == '<') {
                int d = 0;
                for (; j < len; j++) {
                    if (h[j] == '<') d++;
                    else if (h[j] == '>' && --d == 0) {
                        j++;
                        break;
                    }
                }
                i = j;
                continue;
            }
        }
        return i;
    }
}

static void copy_clean(char *dst, size_t cap, const char *s, size_t len)
{
    size_t o = 0;
    int sp = 0;
    for (size_t i = 0; i < len && o + 2 < cap; i++) {
        if (isspace((unsigned char)s[i])) {
            sp = 1;
            continue;
        }
        if (sp && o && is_id(dst[o - 1]) && is_id(s[i])) dst[o++] = ' ';
        sp = 0;
        dst[o++] = s[i];
    }
    dst[o] = 0;
}

static void push_def(CxxDefs *d, const CxxDef *e)
{
    if (d->n == d->cap) {
        d->cap = d->cap ? d->cap * 2 : 32;
        d->v = xalloc(d->v, d->cap * sizeof *d->v);
    }
    d->v[d->n++] = *e;
}

static size_t match_brace(const char *m, size_t n, size_t open)
{
    int d = 0;
    for (size_t i = open; i < n; i++) {
        if (m[i] == '{') d++;
        else if (m[i] == '}' && --d == 0) return i;
    }
    return n;
}

/* Name of the function whose parameter list opens at h[open]. Returns length, 0 if none. */
static size_t func_name(const char *h, size_t open, size_t *name_start)
{
    size_t e = open;
    while (e > 0 && isspace((unsigned char)h[e - 1])) e--;
    size_t s = e;
    while (s > 0 && (is_id(h[s - 1]) || h[s - 1] == ':' || h[s - 1] == '~')) s--;
    /* operator overloads: operator==, operator(), operator new */
    {
        size_t from = e > 40 ? e - 40 : 0;
        size_t found = (size_t)-1;
        for (size_t i = from; i + 8 <= e; i++)
            if (!strncmp(h + i, "operator", 8) && (i == 0 || !is_id(h[i - 1])) && (i + 8 >= e || !is_id(h[i + 8]) || 1))
                found = i;
        if (found != (size_t)-1 && (s == e || found + 8 >= s)) {
            size_t b = found;
            while (b > 0 && (is_id(h[b - 1]) || h[b - 1] == ':')) b--;
            *name_start = b;
            return e - b;
        }
    }
    *name_start = s;
    return e - s;
}

static int first_word(const char *h, size_t len, size_t i, char *out, size_t cap, size_t *end)
{
    while (i < len && isspace((unsigned char)h[i])) i++;
    size_t s = i;
    while (i < len && is_id(h[i])) i++;
    size_t w = i - s;
    if (w == 0 || w >= cap) {
        out[0] = 0;
        *end = i;
        return 0;
    }
    memcpy(out, h + s, w);
    out[w] = 0;
    *end = i;
    return 1;
}

static const char *const NOT_FUNC[] = {"if", "for", "while", "switch", "catch", "return", "sizeof", "else", "do", "using", "decltype", NULL};

void cxx_defs(const char *src, size_t n, CxxDefs *out)
{
    char *m = cxx_mask(src, n);
    cxx_blank_directives(m, n);
    Scope *stack = NULL;
    size_t sp = 0, scap = 0;
    size_t hs = (size_t)-1;
    int pd = 0;
    size_t i = 0;
    while (i < n) {
        char c = m[i];
        if (isspace((unsigned char)c)) {
            i++;
            continue;
        }
        if (hs == (size_t)-1) hs = i;
        if (c == '(') {
            pd++;
            i++;
        } else if (c == ')') {
            if (pd > 0) pd--;
            i++;
        } else if (c == ';') {
            if (pd == 0) hs = (size_t)-1;
            i++;
        } else if (c == ':' && pd == 0 && (i + 1 >= n || m[i + 1] != ':') && (i == 0 || m[i - 1] != ':')) {
            char t[32];
            copy_clean(t, sizeof t, m + hs, i - hs);
            if (!strcmp(t, "public") || !strcmp(t, "private") || !strcmp(t, "protected")) hs = (size_t)-1;
            i++;
        } else if (c == '}') {
            if (sp) {
                sp--;
                if (stack[sp].kind == 1) {
                    CxxDef *d = &out->v[stack[sp].def];
                    d->end_off = i;
                }
            }
            hs = (size_t)-1;
            pd = 0;
            i++;
        } else if (c == '{') {
            if (pd > 0) { /* braced init or lambda inside an argument list */
                i = match_brace(m, n, i) + 1;
                continue;
            }
            const char *h = m + hs;
            size_t len = i - hs;
            size_t b = strip_template(h, len, 0);
            char w[48];
            size_t we = 0;
            /* skip specifiers to find the keyword */
            size_t kp = b;
            int guard = 0;
            while (guard++ < 6 && first_word(h, len, kp, w, sizeof w, &we) &&
                   (!strcmp(w, "static") || !strcmp(w, "inline") || !strcmp(w, "constexpr") || !strcmp(w, "const") ||
                    !strcmp(w, "extern") || !strcmp(w, "typedef") || !strcmp(w, "friend"))) {
                if (!strcmp(w, "extern")) {
                    size_t q = we;
                    while (q < len && isspace((unsigned char)h[q])) q++;
                    if (q < len && h[q] == '"') {
                        w[0] = 'E'; /* extern "C" */
                        w[1] = 0;
                        break;
                    }
                }
                kp = we;
            }
            int has_paren = memchr(h + b, '(', len - b) != NULL;
            int has_eq = 0;
            size_t eqend = b;
            while (eqend < len && h[eqend] != '(') eqend++;
            for (size_t q = b; q + 8 <= eqend; q++) /* operator== and friends are not initialisers */
                if (!strncmp(h + q, "operator", 8)) {
                    eqend = q;
                    break;
                }
            for (size_t q = b; q < eqend; q++)
                if (h[q] == '=') has_eq = 1;
            int handled = 0;
            if ((!strcmp(w, "namespace") || (!strcmp(w, "E") && !has_paren)) && !has_eq) {
                if (sp == scap) {
                    scap = scap ? scap * 2 : 8;
                    stack = xalloc(stack, scap * sizeof *stack);
                }
                stack[sp].kind = 0;
                stack[sp].name[0] = 0;
                stack[sp].def = 0;
                sp++;
                hs = (size_t)-1;
                i++;
                continue;
            }
            if ((!strcmp(w, "class") || !strcmp(w, "struct") || !strcmp(w, "union")) && !has_paren && !has_eq) {
                char nm[96] = "";
                size_t q = we;
                while (q < len && isspace((unsigned char)h[q])) q++;
                if (q + 1 < len && h[q] == '[' && h[q + 1] == '[') { /* [[attr]] */
                    while (q < len && !(h[q] == ']' && q + 1 < len && h[q + 1] == ']')) q++;
                    q += 2;
                    while (q < len && isspace((unsigned char)h[q])) q++;
                }
                size_t ns = q;
                while (q < len && (is_id(h[q]) || h[q] == ':')) q++;
                copy_clean(nm, sizeof nm, h + ns, q - ns);
                if (nm[0]) {
                    CxxDef d;
                    memset(&d, 0, sizeof d);
                    d.kind = CXX_CLASS;
                    snprintf(d.name, sizeof d.name, "%s", nm);
                    d.start_off = hs;
                    d.open_off = i;
                    d.end_off = i;
                    d.start_line = cxx_line_of(src, hs);
                    push_def(out, &d);
                    if (sp == scap) {
                        scap = scap ? scap * 2 : 8;
                        stack = xalloc(stack, scap * sizeof *stack);
                    }
                    stack[sp].kind = 1;
                    snprintf(stack[sp].name, sizeof stack[sp].name, "%s", nm);
                    stack[sp].def = out->n - 1;
                    sp++;
                    hs = (size_t)-1;
                    i++;
                    continue;
                }
                handled = 1; /* anonymous: opaque */
            }
            if (!handled && (strcmp(w, "enum") || has_paren) && !has_eq) {
                /* function: find the first top-level ')' followed by only qualifiers */
                int d = 0;
                size_t open = 0, nfound = 0;
                size_t cand_open[16], cand_close[16];
                for (size_t q = b; q < len && nfound < 16; q++) {
                    if (h[q] == '(') {
                        if (d++ == 0) open = q;
                    } else if (h[q] == ')' && d > 0 && --d == 0) {
                        if (rest_ok(h, len, q + 1)) {
                            cand_open[nfound] = open;
                            cand_close[nfound] = q;
                            nfound++;
                        }
                    }
                }
                size_t pick = (size_t)-1;
                for (size_t k = 0; k < nfound; k++) {
                    size_t ns, nl = func_name(h, cand_open[k], &ns);
                    if (nl == 0) continue;
                    if (allcaps(h + ns, nl) && ns == b && k + 1 < nfound) continue; /* macro prefix */
                    pick = k;
                    break;
                }
                if (pick != (size_t)-1) {
                    size_t ns, nl = func_name(h, cand_open[pick], &ns);
                    /* control statements and lambdas are not definitions */
                    size_t lastc = nl;
                    while (lastc > 0 && h[ns + lastc - 1] != ':') lastc--;
                    int bad = 0;
                    for (int k = 0; NOT_FUNC[k]; k++)
                        if (word_is(h + ns + lastc, nl - lastc, NOT_FUNC[k])) bad = 1;
                    for (size_t q = b; q < ns; q++) {
                        if (h[q] == '[' && q + 1 < len && h[q + 1] == '[') { /* [[attribute]] is fine */
                            while (q + 1 < len && !(h[q] == ']' && h[q + 1] == ']')) q++;
                            continue;
                        }
                        if (h[q] == '=' || h[q] == '[') bad = 1;
                    }
                    if (!bad) { /* a '{' inside a constructor initialiser list is a braced init */
                        int initlist = 0;
                        for (size_t q = cand_close[pick] + 1; q < len; q++) {
                            if (h[q] == '-' && q + 1 < len && h[q + 1] == '>') break;
                            if (h[q] == ':' && (q + 1 >= len || h[q + 1] != ':') && (q == 0 || h[q - 1] != ':')) {
                                initlist = 1;
                                break;
                            }
                            if (h[q] == ':') q++;
                        }
                        size_t pe = len;
                        while (pe > 0 && isspace((unsigned char)h[pe - 1])) pe--;
                        if (initlist && pe > 0 && h[pe - 1] != ')' && h[pe - 1] != '}') bad = 1;
                    }
                    if (!bad) {
                        CxxDef df;
                        memset(&df, 0, sizeof df);
                        df.kind = CXX_FUNC;
                        char nm[192];
                        copy_clean(nm, sizeof nm, h + ns, nl);
                        char pre[192] = "";
                        if (!strchr(nm, ':') || 1) {
                            for (size_t k = 0; k < sp; k++)
                                if (stack[k].kind == 1 && strlen(pre) + strlen(stack[k].name) + 3 < sizeof pre) {
                                    strcat(pre, stack[k].name);
                                    strcat(pre, "::");
                                }
                        }
                        if (allcaps(nm, strlen(nm))) { /* BOOST_AUTO_TEST_CASE(arg) */
                            size_t a = cand_open[pick] + 1, e = cand_close[pick];
                            size_t ae = a;
                            while (ae < e && h[ae] != ',' && h[ae] != ')') ae++;
                            copy_clean(df.alias, sizeof df.alias, h + a, ae - a);
                            snprintf(df.name, sizeof df.name, "%s(%s)", nm, df.alias);
                        } else {
                            snprintf(df.name, sizeof df.name, "%s%s", pre, nm);
                        }
                        df.start_off = hs;
                        if (pick > 0) { /* a macro prefix such as BOOST_AUTO_TEST_SUITE(x) is not part of this definition */
                            size_t s = cand_close[pick - 1] + 1;
                            while (s < len && isspace((unsigned char)h[s])) s++;
                            df.start_off = hs + s;
                        }
                        df.open_off = i;
                        df.end_off = match_brace(m, n, i);
                        if (df.end_off >= n) df.end_off = n - 1;
                        df.start_line = cxx_line_of(src, df.start_off);
                        df.end_line = cxx_line_of(src, df.end_off);
                        push_def(out, &df);
                        i = df.end_off + 1;
                        hs = (size_t)-1;
                        pd = 0;
                        continue;
                    }
                }
            }
            /* opaque brace: enum, initialiser, lambda at namespace scope. The header goes on. */
            i = match_brace(m, n, i) + 1;
        } else {
            i++;
        }
    }
    for (size_t k = 0; k < out->n; k++) {
        CxxDef *d = &out->v[k];
        if (d->kind == CXX_CLASS) {
            if (d->end_off < d->open_off) d->end_off = d->open_off;
            d->end_line = cxx_line_of(src, d->end_off);
        }
    }
    free(stack);
    free(m);
}

int cxx_def_matches(const CxxDef *d, const char *q)
{
    if (!strcmp(d->name, q)) return 1;
    if (d->alias[0] && !strcmp(d->alias, q)) return 1;
    const char *last = strrchr(d->name, ':');
    if (last && !strcmp(last + 1, q)) return 1;
    size_t ql = strlen(q), nl = strlen(d->name);
    if (nl > ql + 2 && !strcmp(d->name + nl - ql, q) && d->name[nl - ql - 1] == ':') return 1;
    return 0;
}

void cxx_free_defs(CxxDefs *d)
{
    free(d->v);
    d->v = NULL;
    d->n = d->cap = 0;
}

void cxx_free_incs(CxxIncs *d)
{
    free(d->v);
    d->v = NULL;
    d->n = d->cap = 0;
}
