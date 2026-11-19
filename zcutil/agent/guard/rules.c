/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard_rules.c@9a191ef7b, Apache-2.0, changed: the rule set is
 * zclassicd's (datadir, reindex, spend or key export, python, git identity, git push, hosted
 * CI, vendored code, consensus seal), paths are Windows-aware, and the Z23-only rules (host
 * config, reindex flag file, devbuild help) are gone. See zcutil/tools/NOTICE.
 *
 * zcl-agent-guard rule engine: scans a Bash command or a file path and names the never-do rule
 * it breaks. The hook, replay and CLI live in zcl-agent-guard.c.
 *
 * Precision matters as much as coverage, because a false refusal stalls the worker and a guard
 * that blocks everyday commands gets switched off.
 *
 * Shell scanning: the command is split into segments at ; && || | & and newlines (also $( ) ( )
 * and backticks outside quotes). Quoted text is data, except the argument of ssh, eval and
 * sh/bash/dash/zsh -c, the contents of $( ) and backticks inside double quotes, and a heredoc
 * body that feeds a shell or ssh, which are scanned again as commands.
 *
 * Writes: only the written operand counts (cp/rsync/scp/install/ln: the destination; sed -i: the
 * files, not the script; dd: of=; sqlq/sqlite3: only with a SQL write verb; curl/wget: the
 * output file). A cd into a datadir is tracked along the command chain. Spend and key-export
 * names count only in the method position (first word after the RPC client, or a JSON-RPC
 * "method" value in a request body).
 *
 * Known limits (not closed, one per line):
 *   alias g=git; g push                  aliases and shell functions are not expanded
 *   D=~/.zclassic; rm $D/x               variable values are not tracked
 *   -datadir=$D                          a variable datadir is assumed to be a test directory
 *   $C sendmany (C=zclassic-cli ...)     a variable client counts as regtest when -regtest appears
 *                                        anywhere in the command
 *   xargs / find -exec git push          only xargs as a wrapper; find -exec only for writers
 *   sh script.sh / bash x.sh             the script file's content is not read
 *   rsync --remove-source-files <dd> x   a datadir source deleted by rsync is a read
 *   tar czf <dd>/x.tgz ...               tar create into a datadir is not checked (extract is)
 *   curl -d @file with a spend method    request bodies in files are not read
 *   sqlq db < file.sql                   SQL read from a file is not checked for write verbs
 *   python via a symlink or a renamed    only the command word and .py names are recognised
 *     binary
 *   git commit --reset-author            not a refused identity form
 *   zclassicd -regtest (no -datadir)     allowed: the node's own regtest default is not parsed
 *   git push remote <branch-alias>       only the literal name master is recognised
 *   backslash paths inside Bash          Git Bash consumes the backslash before the guard sees it */

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#include "rules.h"

#define MAX_NEST 4
#define MAX_WORDS 4096
#define MAX_SEGS 1024
#define MAX_REDIR 512
#define MAX_SUBS 64
#define MAX_HD 4

struct gseg {
    int w0, nw;
    size_t hd_off, hd_len;
    bool hd_has;
};

struct gctx {
    const char *src;
    char *arena;
    size_t apos;
    char *words[MAX_WORDS];
    int nwords;
    char *redir[MAX_REDIR];
    int redir_seg[MAX_REDIR];
    int nredir;
    struct gseg segs[MAX_SEGS];
    int nsegs;
    struct {
        size_t off, len;
    } subs[MAX_SUBS]; /* $( ) and backtick bodies inside double quotes */
    int nsubs;
};

enum { P_NONE, P_OUT, P_IN, P_HEREDOC };

struct tok {
    struct gctx *c;
    const char *s;
    size_t len, i, wstart;
    bool in_word, digits;
    int pend, cw0, cr0, nhd;
    struct {
        int seg;
        char delim[64];
    } hd[MAX_HD];
};

static const char *eval_buf(const char *s, size_t len, int depth);

/* ---- quote-aware skipping inside $( ) and heredocs ---------------- */

static size_t skip_dq(const char *s, size_t len, size_t i, int lvl);

/* Parse a heredoc delimiter word at s[i..]; returns the index past it. */
static size_t parse_delim(const char *s, size_t len, size_t i, char *out,
                          size_t cap)
{
    size_t n = 0;
    while (i < len && (s[i] == ' ' || s[i] == '\t')) i++;
    while (i < len && !strchr(" \t\n;|&()<>", s[i])) {
        if (s[i] != '\'' && s[i] != '"' && s[i] != '\\' && n + 1 < cap)
            out[n++] = s[i];
        i++;
    }
    out[n] = '\0';
    return i;
}

/* Read a heredoc body starting at the line beginning at p. Returns the
 * index after the delimiter line; the body is [*off, *off + *blen). */
static size_t read_heredoc_body(const char *s, size_t len, size_t p,
                                const char *delim, size_t *off, size_t *blen)
{
    size_t dl = strlen(delim);
    *off = p;
    while (p < len) {
        size_t eol = p;
        while (eol < len && s[eol] != '\n') eol++;
        size_t b = p;
        while (b < eol && s[b] == '\t') b++;
        if (eol - b == dl && memcmp(s + b, delim, dl) == 0) {
            *blen = p - *off;
            return eol < len ? eol + 1 : len;
        }
        p = eol < len ? eol + 1 : len;
    }
    *blen = len - *off;
    return len;
}

/* Skip a heredoc nested inside a $( ) region; i is just past "<<". */
static size_t skip_heredoc(const char *s, size_t len, size_t i)
{
    char delim[64];
    size_t off, blen;
    if (i < len && s[i] == '-') i++;
    i = parse_delim(s, len, i, delim, sizeof delim);
    if (delim[0] == '\0') return i;
    while (i < len && s[i] != '\n') i++;
    if (i >= len) return len;
    return read_heredoc_body(s, len, i + 1, delim, &off, &blen);
}

/* i is just past "$("; returns the index after the matching ")". */
static size_t skip_paren(const char *s, size_t len, size_t i, int lvl)
{
    int depth = 1;
    if (lvl > 12) return len;
    while (i < len) {
        char ch = s[i];
        if (ch == '\\') {
            i += 2;
        } else if (ch == '\'') {
            i++;
            while (i < len && s[i] != '\'') i++;
            i++;
        } else if (ch == '"') {
            i = skip_dq(s, len, i + 1, lvl + 1);
        } else if (ch == '<' && i + 2 < len && s[i + 1] == '<' && s[i + 2] != '<') {
            i = skip_heredoc(s, len, i + 2);
        } else {
            if (ch == '(') depth++;
            if (ch == ')' && --depth == 0) return i + 1;
            i++;
        }
    }
    return len;
}

/* i is just past an opening double quote; returns the index past the close. */
static size_t skip_dq(const char *s, size_t len, size_t i, int lvl)
{
    while (i < len) {
        if (s[i] == '\\') {
            i += 2;
        } else if (s[i] == '"') {
            return i + 1;
        } else if (s[i] == '$' && i + 1 < len && s[i + 1] == '(') {
            i = skip_paren(s, len, i + 2, lvl + 1);
        } else {
            i++;
        }
    }
    return len;
}

/* ---- tokenizer ---------------------------------------------------- */

static void tk_push(struct tok *t, char ch)
{
    if (!t->in_word) {
        t->in_word = true;
        t->digits = true;
        t->wstart = t->c->apos;
    }
    if (!isdigit((unsigned char)ch)) t->digits = false;
    t->c->arena[t->c->apos++] = ch;
}

static void tk_mark_quoted(struct tok *t)
{
    if (!t->in_word) {
        t->in_word = true;
        t->wstart = t->c->apos;
    }
    t->digits = false;
}

static void tk_route_word(struct tok *t, char *wd)
{
    struct gctx *c = t->c;
    if (t->pend == P_NONE && c->nwords < MAX_WORDS) {
        c->words[c->nwords++] = wd;
    } else if (t->pend == P_OUT && c->nredir < MAX_REDIR) {
        c->redir_seg[c->nredir] = c->nsegs;
        c->redir[c->nredir++] = wd;
    } else if (t->pend == P_HEREDOC && t->nhd < MAX_HD) {
        t->hd[t->nhd].seg = c->nsegs;
        snprintf(t->hd[t->nhd].delim, sizeof t->hd[t->nhd].delim, "%s", wd);
        t->nhd++;
    }
    t->pend = P_NONE;
}

static void tk_end_word(struct tok *t)
{
    if (!t->in_word) return;
    t->c->arena[t->c->apos++] = '\0';
    t->in_word = false;
    tk_route_word(t, t->c->arena + t->wstart);
}

static void tk_end_seg(struct tok *t)
{
    struct gctx *c = t->c;
    tk_end_word(t);
    t->pend = P_NONE;
    if ((c->nwords > t->cw0 || c->nredir > t->cr0) && c->nsegs < MAX_SEGS) {
        struct gseg *g = &c->segs[c->nsegs++];
        memset(g, 0, sizeof *g);
        g->w0 = t->cw0;
        g->nw = c->nwords - t->cw0;
    }
    t->cw0 = c->nwords;
    t->cr0 = c->nredir;
}

static void tk_newline(struct tok *t)
{
    struct gctx *c = t->c;
    size_t p = t->i + 1;
    tk_end_seg(t);
    for (int k = 0; k < t->nhd; k++) {
        size_t off, blen;
        p = read_heredoc_body(t->s, t->len, p, t->hd[k].delim, &off, &blen);
        int sg = t->hd[k].seg;
        if (sg < c->nsegs && !c->segs[sg].hd_has) {
            c->segs[sg].hd_off = off;
            c->segs[sg].hd_len = blen;
            c->segs[sg].hd_has = true;
        }
    }
    t->nhd = 0;
    t->i = p > t->len ? t->len : p;
}

static void tk_squote(struct tok *t)
{
    size_t i = t->i + 1;
    tk_mark_quoted(t);
    while (i < t->len && t->s[i] != '\'') tk_push(t, t->s[i++]);
    t->i = i < t->len ? i + 1 : t->len;
}

/* Backslash escape inside double quotes; true when consumed. */
static bool tk_dq_escape(struct tok *t, size_t *ip)
{
    size_t i = *ip;
    char n;
    if (t->s[i] != '\\' || i + 1 >= t->len) return false;
    n = t->s[i + 1];
    if (n == '\n') {
        *ip = i + 2;
    } else if (strchr("\"\\$`", n)) {
        tk_push(t, n);
        *ip = i + 2;
    } else {
        tk_push(t, '\\');
        *ip = i + 1;
    }
    return true;
}

static void tk_add_sub(struct tok *t, size_t off, size_t end)
{
    struct gctx *c = t->c;
    if (c->nsubs >= MAX_SUBS || end <= off) return;
    c->subs[c->nsubs].off = off;
    c->subs[c->nsubs].len = end - off;
    c->nsubs++;
}

/* Code substitution inside double quotes: copy it into the word as data and
 * record its body so eval_buf scans it as a command. True when consumed. */
static bool tk_dq_subst(struct tok *t, size_t *ip)
{
    size_t i = *ip, j;
    if (t->s[i] == '$' && i + 1 < t->len && t->s[i + 1] == '(') {
        j = skip_paren(t->s, t->len, i + 2, 0);
        tk_add_sub(t, i + 2, (j > i + 2 && t->s[j - 1] == ')') ? j - 1 : j);
    } else if (t->s[i] == '`') {
        j = i + 1;
        while (j < t->len && t->s[j] != '`') j += t->s[j] == '\\' ? 2u : 1u;
        if (j > t->len) j = t->len;
        tk_add_sub(t, i + 1, j);
        if (j < t->len) j++;
    } else {
        return false;
    }
    while (i < j) tk_push(t, t->s[i++]);
    *ip = j;
    return true;
}

static void tk_dquote(struct tok *t)
{
    size_t i = t->i + 1;
    tk_mark_quoted(t);
    while (i < t->len && t->s[i] != '"') {
        if (tk_dq_escape(t, &i) || tk_dq_subst(t, &i)) continue;
        tk_push(t, t->s[i++]);
    }
    t->i = i < t->len ? i + 1 : t->len;
}

static bool tk_step_quote(struct tok *t)
{
    char ch = t->s[t->i];
    if (ch == '\'') {
        tk_squote(t);
    } else if (ch == '"') {
        tk_dquote(t);
    } else if (ch == '\\') {
        if (t->i + 1 >= t->len) {
            t->i++;
        } else if (t->s[t->i + 1] == '\n') {
            t->i += 2;
        } else {
            tk_mark_quoted(t);
            tk_push(t, t->s[t->i + 1]);
            t->i += 2;
        }
    } else {
        return false;
    }
    return true;
}

static bool tk_step_ws(struct tok *t)
{
    char ch = t->s[t->i];
    if (ch == ' ' || ch == '\t' || ch == '\r') {
        tk_end_word(t);
        t->i++;
        return true;
    }
    if (ch == '#' && !t->in_word) {
        while (t->i < t->len && t->s[t->i] != '\n') t->i++;
        return true;
    }
    return false;
}

static void tk_op_begin(struct tok *t)
{
    if (t->in_word && t->digits) {
        t->c->apos = t->wstart;
        t->in_word = false;
    } else {
        tk_end_word(t);
    }
}

/* Index past the operator tail after a redirect character. */
static size_t tk_redir_tail(const char *s, size_t len, size_t j, char ch,
                            bool amp_out, int *kind)
{
    char c0 = j < len ? s[j] : '\0';
    if (ch == '>') {
        if (c0 == '>' || c0 == '|') j++;
        else if (c0 == '&' && !amp_out) j++;
    } else if (c0 == '<') {
        j++;
        if (j < len && s[j] == '<') {
            j++;
            *kind = P_IN;
        } else {
            if (j < len && s[j] == '-') j++;
            *kind = P_HEREDOC;
        }
    } else if (c0 == '&') {
        j++;
    }
    return j;
}

static bool tk_step_redir(struct tok *t)
{
    char ch = t->s[t->i];
    char nx = t->i + 1 < t->len ? t->s[t->i + 1] : '\0';
    bool amp_out = ch == '&' && nx == '>';
    int kind;
    size_t j;
    if (ch != '>' && ch != '<' && !amp_out) return false;
    if (nx == '(' && !amp_out) {
        tk_end_seg(t);
        t->i += 2;
        return true;
    }
    tk_op_begin(t);
    kind = ch == '<' ? P_IN : P_OUT;
    j = tk_redir_tail(t->s, t->len, t->i + (amp_out ? 2u : 1u), ch, amp_out, &kind);
    t->pend = kind;
    t->i = j;
    return true;
}

static bool tk_step_sep(struct tok *t)
{
    char ch = t->s[t->i];
    char nx = t->i + 1 < t->len ? t->s[t->i + 1] : '\0';
    switch (ch) {
    case '\n':
        tk_newline(t);
        return true;
    case ';': case '(': case ')': case '`':
        tk_end_seg(t);
        t->i++;
        return true;
    case '|': case '&':
        tk_end_seg(t);
        t->i += (nx == ch || (ch == '|' && nx == '&')) ? 2u : 1u;
        return true;
    case '$':
        if (nx != '(') return false;
        tk_end_seg(t);
        t->i += 2;
        return true;
    default:
        return false;
    }
}

static void tokenize(struct gctx *c, const char *s, size_t len)
{
    struct tok t;
    memset(&t, 0, sizeof t);
    t.c = c;
    t.s = s;
    t.len = len;
    while (t.i < len) {
        if (tk_step_ws(&t) || tk_step_quote(&t) || tk_step_redir(&t) ||
            tk_step_sep(&t))
            continue;
        tk_push(&t, s[t.i++]);
    }
    tk_end_seg(&t);
}

/* ---- word classification ----------------------------------------- */

static const char *base_name(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static bool is_assign(const char *w)
{
    if (!isalpha((unsigned char)*w) && *w != '_') return false;
    w++;
    while (isalnum((unsigned char)*w) || *w == '_') w++;
    return *w == '=';
}

static bool is_identity_env(const char *w)
{
    static const char *const names[] = {
        "GIT_AUTHOR_NAME=", "GIT_AUTHOR_EMAIL=", "GIT_COMMITTER_NAME=",
        "GIT_COMMITTER_EMAIL="};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (strncmp(w, names[i], strlen(names[i])) == 0) return true;
    return false;
}

static bool in_list(const char *w, const char *const *list, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(w, list[i]) == 0) return true;
    return false;
}
#define IN_LIST(w, arr) in_list((w), (arr), sizeof(arr) / sizeof((arr)[0]))

static bool is_keyword(const char *w)
{
    static const char *const kw[] = {"if", "then", "else", "elif", "while",
                                     "until", "do", "{", "!"};
    return IN_LIST(w, kw);
}

/* True when w is a short option group of letters containing flag ch. */
static bool short_group_has(const char *w, char ch)
{
    if (w[0] != '-' || w[1] == '-' || w[1] == '\0') return false;
    for (const char *p = w + 1; *p; p++)
        if (!isalpha((unsigned char)*p)) return false;
    return strchr(w + 1, ch) != NULL;
}

static bool opt_takes_arg(const char *argopts, const char *opt)
{
    char key[40];
    int n = snprintf(key, sizeof key, " %s ", opt);
    return n > 0 && (size_t)n < sizeof key && strstr(argopts, key) != NULL;
}

/* ---- command word discovery -------------------------------------- */

#define WF_TIMEOUT 1
#define WF_QUERY 4

struct wrapper {
    const char *name;
    const char *argopts;
    int flags;
};

static const struct wrapper wrappers[] = {
    {"sudo", " -u -g -C -h -p -r -t -U -D -R -T ", 0},
    {"env", " -u -C -S -P ", 0},
    {"nice", " -n ", 0},
    {"ionice", " -c -n -p -P -u ", 0},
    {"nohup", " ", 0},
    {"exec", " -a ", 0},
    {"command", " ", WF_QUERY},
    {"time", " -f -o ", 0},
    {"timeout", " -k -s ", WF_TIMEOUT},
    {"devbuild", " --project ", 0},
    {"xargs", " -a -d -E -e -I -L -l -n -P -s ", 0},
};

struct pinfo {
    bool id_assign;
};

/* Words consumed by a wrapper at w[i]; 0 when not a wrapper; -1 when the
 * segment only queries a command (command -v). */
static const struct wrapper *wrapper_lookup(const char *name)
{
    for (size_t k = 0; k < sizeof wrappers / sizeof wrappers[0]; k++)
        if (strcmp(name, wrappers[k].name) == 0) return &wrappers[k];
    return NULL;
}

static bool opt_is(const char *w, const char *a, const char *b)
{
    return strcmp(w, a) == 0 || strcmp(w, b) == 0;
}

static int wrapper_skip(char **w, int n, int i)
{
    const struct wrapper *wr = wrapper_lookup(base_name(w[i]));
    int j = i + 1;
    if (!wr) return 0;
    while (j < n && w[j][0] == '-' && w[j][1]) {
        if (strcmp(w[j], "--") == 0) {
            j++;
            break;
        }
        if ((wr->flags & WF_QUERY) && opt_is(w[j], "-v", "-V")) return -1;
        j += opt_takes_arg(wr->argopts, w[j]) && j + 1 < n ? 2 : 1;
    }
    if ((wr->flags & WF_TIMEOUT) && j < n) j++;
    return j - i;
}

static int find_cmd(char **w, int n, struct pinfo *pi)
{
    int i = 0;
    while (i < n) {
        int sk;
        if (is_assign(w[i])) {
            if (is_identity_env(w[i])) pi->id_assign = true;
            i++;
        } else if (is_keyword(w[i])) {
            i++;
        } else if ((sk = wrapper_skip(w, n, i)) == 0) {
            return i;
        } else if (sk < 0) {
            return -1;
        } else {
            i += sk;
        }
    }
    return -1;
}

/* ---- path predicates --------------------------------------------- */

#define PATH_SEPS "/\\=:, \t\n\"'"

static bool is_psep(char ch)
{
    return ch != '\0' && strchr(PATH_SEPS, ch) != NULL;
}

/* Advance *pp to the next path component; false at the end of w. */
static bool next_comp(const char **pp, size_t *n)
{
    const char *p = *pp;
    while (*p && is_psep(*p)) p++;
    if (!*p) {
        *pp = p;
        return false;
    }
    *n = 0;
    while (p[*n] && !is_psep(p[*n])) (*n)++;
    *pp = p;
    return true;
}

/* Case-insensitive: component c of length n starts with the lower-case prefix pre. */
static bool comp_starts_ci(const char *c, size_t n, const char *pre)
{
    size_t m = strlen(pre);
    return n >= m && strncasecmp(c, pre, m) == 0;
}

static bool comp_is_ci(const char *c, size_t n, const char *name)
{
    return strlen(name) == n && strncasecmp(c, name, n) == 0;
}

static bool comp_is_appdata(const char *c, size_t n)
{
    static const char *const names[] = {"appdata", "%appdata%", "$appdata", "${appdata}"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (comp_is_ci(c, n, names[i])) return true;
    return false;
}

/* ~/.zclassic*, ~/.zcash-params, and %APPDATA%/Zclassic or %APPDATA%/ZcashParams. */
static bool mentions_datadir(const char *w)
{
    const char *p = w;
    size_t n = 0;
    bool appdata = false;
    while (next_comp(&p, &n)) {
        if (comp_starts_ci(p, n, ".zclassic") || comp_starts_ci(p, n, ".zcash-params"))
            return true;
        if (appdata && (comp_is_ci(p, n, "zclassic") || comp_is_ci(p, n, "zcashparams")))
            return true;
        if (comp_is_appdata(p, n)) appdata = true;
        p += n;
    }
    return false;
}

static bool slash_eq(char a, char b)
{
    return a == b || ((a == '/' || a == '\\') && (b == '/' || b == '\\'));
}

/* True when pat (written with '/') occurs in w at a component boundary. dir_mode: the match may
 * be followed by a path separator or the end (a directory); otherwise it must end the word. */
static bool path_has(const char *w, const char *pat, bool dir_mode)
{
    size_t m = strlen(pat);
    for (size_t i = 0; w[i]; i++) {
        size_t k = 0;
        if (i > 0 && !is_psep(w[i - 1])) continue;
        while (k < m && w[i + k] && slash_eq(w[i + k], pat[k])) k++;
        if (k != m) continue;
        if (w[i + k] == '\0') return true;
        if (dir_mode && (w[i + k] == '/' || w[i + k] == '\\')) return true;
    }
    return false;
}

static bool is_vendor_path(const char *w)
{
    return path_has(w, "zcutil/tools/vendor", true) || path_has(w, "src/c23/vendor", true) ||
           path_has(w, "src/c23/services/vendor", true);
}

static bool is_workflow_path(const char *w)
{
    return path_has(w, ".github/workflows", true);
}

/* The sealed consensus set (zcutil/consensus.seal): edits warn, they do not refuse. */
static bool is_sealed_path(const char *w)
{
    static const char *const dirs[] = {"src/consensus", "src/primitives", "src/pow"};
    static const char *const files[] = {
        "src/pow.cpp", "src/pow.h", "src/script/interpreter.cpp", "src/script/interpreter.h",
        "src/script/script.cpp", "src/script/script.h", "src/chainparams.cpp",
        "src/zcash/JoinSplit.cpp", "src/zcash/JoinSplit.h", "src/zcash/Note.cpp",
        "src/zcash/Note.h", "src/zcash/NoteEncryption.cpp", "src/zcash/NoteEncryption.h",
        "src/zcash/Proof.cpp", "src/zcash/Proof.h", "src/zcash/Address.cpp",
        "src/zcash/Address.h", "src/zcash/IncrementalMerkleTree.cpp",
        "src/zcash/IncrementalMerkleTree.h"};
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        if (path_has(w, dirs[i], true))
            return strcmp(dirs[i], "src/pow") != 0 || !path_has(w, "src/pow/tromp", true);
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++)
        if (path_has(w, files[i], false)) return true;
    return false;
}

/* A -datadir value that is a throwaway test directory: under a temp location, a test*, tmp*
 * or mktemp name, or a shell expansion (its value is not tracked). Never a node datadir. */
static bool is_test_dir(const char *v)
{
    const char *p = v;
    size_t n = 0;
    if (mentions_datadir(v)) return false;
    if (!v[0]) return true; /* -datadir=$(mktemp -d): the tokenizer split the substitution off */
    if (v[0] == '$' || v[0] == '`') return true;
    while (next_comp(&p, &n)) {
        if (comp_starts_ci(p, n, "tmp") || comp_starts_ci(p, n, "temp") ||
            (comp_starts_ci(p, n, "test") && !comp_starts_ci(p, n, "testnet")) ||
            comp_is_ci(p, n, "shm") || comp_is_ci(p, n, "folders"))
            return true;
        p += n;
    }
    return false;
}

static const char *path_rule(const char *w)
{
    if (mentions_datadir(w)) return R_DATADIR;
    if (is_workflow_path(w)) return R_CI;
    if (is_vendor_path(w)) return R_VENDOR;
    return NULL;
}

/* ---- per-segment rules ------------------------------------------- */

struct cmdv {
    const struct gctx *c;
    const struct gseg *sg;
    const char *cmd;
    char **a;
    int na;
    char **w;
    int nw;
    int depth;
    bool in_dd; /* an earlier cd in this chain entered a datadir */
};

static bool is_python_cmd(const char *cmd)
{
    const char *rest = NULL;
    if (strcmp(cmd, "pipx") == 0) return true;
    if (strncmp(cmd, "python", 6) == 0) rest = cmd + 6;
    else if (strncmp(cmd, "pip", 3) == 0) rest = cmd + 3;
    if (!rest) return false;
    return strspn(rest, "0123456789.") == strlen(rest);
}

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n > m && strcmp(s + n - m, suffix) == 0;
}

/* python, pipx, pip, uv run/pip/tool, and an executed *.py file. */
static const char *check_python(const struct cmdv *v)
{
    if (is_python_cmd(v->cmd) || ends_with(v->cmd, ".py")) return R_PYTHON;
    if (strcmp(v->cmd, "uvx") == 0) return R_PYTHON;
    if (strcmp(v->cmd, "uv") == 0 && v->na > 0 &&
        (strcmp(v->a[0], "run") == 0 || strcmp(v->a[0], "pip") == 0 ||
         strcmp(v->a[0], "tool") == 0))
        return R_PYTHON;
    return NULL;
}

static bool is_identity_key(const char *k)
{
    char lower[24];
    size_t n = strcspn(k, "=");
    if (n == 0 || n >= sizeof lower) return false;
    for (size_t i = 0; i < n; i++) lower[i] = (char)tolower((unsigned char)k[i]);
    lower[n] = '\0';
    return strcmp(lower, "user.name") == 0 || strcmp(lower, "user.email") == 0 ||
           strncmp(lower, "author.", 7) == 0 || strncmp(lower, "committer.", 10) == 0;
}

/* Collect the positional words of a git config call. Returns false for a
 * read-only form (--get*, --list); *unset reports an unset-style option. */
static bool config_positionals(char **a, int na, const char **pos, int *np,
                               bool *unset)
{
    static const char *const unsets[] = {"--unset", "--unset-all", "--replace-all"};
    static const char *const skips[] = {"--file", "-f", "--blob", "--type", "-t", "--default"};
    for (int i = 0; i < na; i++) {
        if (a[i][0] != '-') {
            if (*np < 3) pos[(*np)++] = a[i];
        } else if (strncmp(a[i], "--get", 5) == 0 || opt_is(a[i], "--list", "-l")) {
            return false;
        } else if (IN_LIST(a[i], unsets)) {
            *unset = true;
        } else if (IN_LIST(a[i], skips)) {
            i++;
        }
    }
    return true;
}

static bool config_sets_identity(char **a, int na)
{
    const char *pos[3];
    int np = 0, k = 0;
    bool unset = false;
    if (!config_positionals(a, na, pos, &np, &unset)) return false;
    if (np > 0 && strcmp(pos[0], "get") == 0) return false;
    if (np > 0 && (strcmp(pos[0], "set") == 0 || strcmp(pos[0], "unset") == 0)) {
        unset = unset || strcmp(pos[0], "unset") == 0;
        k = 1;
    }
    if (np <= k || !is_identity_key(pos[k])) return false;
    return unset || np > k + 1;
}

/* Index of the git subcommand after global options; -1 on a refusal-worthy
 * -c identity override (caller checks *bad). */
static int git_subcommand(char **a, int na, bool *bad)
{
    int i = 0;
    while (i < na && a[i][0] == '-') {
        if (strncmp(a[i], "-c", 2) == 0 && a[i][2] != '\0') {
            if (is_identity_key(a[i] + 2)) *bad = true;
            i++;
        } else if (strcmp(a[i], "-c") == 0 && i + 1 < na) {
            if (is_identity_key(a[i + 1])) *bad = true;
            i += 2;
        } else if (strcmp(a[i], "-C") == 0 || strcmp(a[i], "--git-dir") == 0 ||
                   strcmp(a[i], "--work-tree") == 0 || strcmp(a[i], "--namespace") == 0) {
            i += 2;
        } else {
            i++;
        }
    }
    return i < na ? i : -1;
}

/* Refspec predicates. A "+" prefix forces; the destination master, src:master or
 * refs/heads/master updates master. */
static bool refspec_forces(const char *r)
{
    return r[0] == '+';
}

static bool refspec_names_master(const char *r)
{
    const char *dst = strchr(r, ':');
    dst = dst ? dst + 1 : r;
    if (dst[0] == '+') dst++;
    if (strncmp(dst, "refs/heads/", 11) == 0) dst += 11;
    return strcmp(dst, "master") == 0;
}

static bool push_opt_takes_arg(const char *a)
{
    static const char *const opts[] = {"--repo", "-o", "--push-option", "--receive-pack",
                                       "--exec", "--signed"};
    return IN_LIST(a, opts);
}

/* git push: refuse a force, a push to master, --all/--mirror, and an unnamed target (a bare push
 * or HEAD), because that may be master. --dry-run and --help only look. */
static const char *push_rule(char **a, int na)
{
    bool force = false, master = false, tags = false;
    int pos = 0;
    for (int i = 0; i < na; i++) {
        if (a[i][0] == '-' && a[i][1]) {
            if (opt_is(a[i], "--help", "-h") || opt_is(a[i], "--dry-run", "-n")) return NULL;
            if (strncmp(a[i], "--force", 7) == 0 || short_group_has(a[i], 'f')) force = true;
            else if (strcmp(a[i], "--all") == 0 || strcmp(a[i], "--mirror") == 0) master = true;
            else if (strcmp(a[i], "--tags") == 0) tags = true;
            else if (push_opt_takes_arg(a[i]) && i + 1 < na) i++;
            continue;
        }
        if (++pos < 2) continue;
        if (refspec_forces(a[i])) force = true;
        if (refspec_names_master(a[i]) || strcmp(a[i], "HEAD") == 0) master = true;
    }
    if (force || master) return R_PUSH;
    return pos < 2 && !tags ? R_PUSH : NULL;
}

static const char *check_git(const struct cmdv *v)
{
    bool bad = false;
    int si;
    const char *sub;
    if (strcmp(v->cmd, "git") != 0) return NULL;
    si = git_subcommand(v->a, v->na, &bad);
    if (bad) return R_IDENT;
    if (si < 0) return NULL;
    sub = v->a[si];
    if (strcmp(sub, "push") == 0) return push_rule(v->a + si + 1, v->na - si - 1);
    if (strcmp(sub, "config") == 0)
        return config_sets_identity(v->a + si + 1, v->na - si - 1) ? R_IDENT : NULL;
    if (strcmp(sub, "commit") == 0)
        for (int i = si + 1; i < v->na; i++)
            if (strcmp(v->a[i], "--author") == 0 || strncmp(v->a[i], "--author=", 9) == 0)
                return R_IDENT;
    return NULL;
}

static const char *check_export(const struct cmdv *v)
{
    static const char *const decl[] = {"export", "declare", "typeset", "readonly"};
    if (!IN_LIST(v->cmd, decl)) return NULL;
    for (int i = 0; i < v->na; i++)
        if (is_identity_env(v->a[i])) return R_IDENT;
    return NULL;
}

static bool is_word_char(char ch)
{
    return isalnum((unsigned char)ch) || ch == '_';
}

static bool is_method(const char *s, size_t n)
{
    static const char *const methods[] = {
        "sendtoaddress", "sendfrom", "sendmany", "z_sendmany", "z_shieldcoinbase",
        "z_mergetoaddress", "sendrawtransaction", "dumpprivkey", "dumpwallet",
        "z_exportkey", "z_exportwallet", "z_exportviewingkey", "backupwallet",
        "walletpassphrase", "walletpassphrasechange", "encryptwallet"};
    for (size_t k = 0; k < sizeof methods / sizeof methods[0]; k++)
        if (strlen(methods[k]) == n && memcmp(s, methods[k], n) == 0) return true;
    return false;
}

/* A JSON-RPC body: a "method" key whose value is a refused method. */
static bool body_has_method(const char *s, size_t len)
{
    static const char *const skip = "\"'\\ \t\n";
    for (size_t i = 1; i + 6 <= len; i++) {
        size_t j = i + 6, k;
        if (memcmp(s + i, "method", 6) != 0 || !strchr("\"'\\", s[i - 1])) continue;
        while (j < len && strchr(skip, s[j])) j++;
        if (j >= len || s[j] != ':') continue;
        j++;
        while (j < len && strchr(skip, s[j])) j++;
        for (k = j; k < len && is_word_char(s[k]); k++) {}
        if (is_method(s + j, k - j)) return true;
    }
    return false;
}

/* The whole payload is a bare method name (curl -d z_sendmany). */
static bool bare_method(const char *s)
{
    size_t n = strlen(s);
    while (n && strchr("\"' \t\n", *s)) {
        s++;
        n--;
    }
    while (n && strchr("\"' \t\n", s[n - 1])) n--;
    return n && is_method(s, n);
}

static bool payload_has_method(const char *s)
{
    return body_has_method(s, strlen(s)) || bare_method(s);
}

/* The request body argument of a curl/wget flag at a[i]: the next word, the
 * text after '=', or the text glued to -d; NULL when a[i] carries no body. */
static const char *body_arg(char **a, int na, int i)
{
    static const char *const flags[] = {"-d", "--data", "--data-raw", "--data-binary",
                                        "--data-ascii", "--json", "--post-data",
                                        "--body-data"};
    const char *eq;
    if (IN_LIST(a[i], flags)) return i + 1 < na ? a[i + 1] : NULL;
    if (strncmp(a[i], "--", 2) == 0) {
        eq = strchr(a[i], '=');
        if (!eq || (size_t)(eq - a[i]) > 16) return NULL;
        return strncmp(a[i], "--data", 6) == 0 || strncmp(a[i], "--post-data", 11) == 0 ||
                       strncmp(a[i], "--json", 6) == 0 || strncmp(a[i], "--body-data", 11) == 0
                   ? eq + 1
                   : NULL;
    }
    return strncmp(a[i], "-d", 2) == 0 && a[i][2] ? a[i] + 2 : NULL;
}

static const char *check_http(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++) {
        const char *b = body_arg(v->a, v->na, i);
        if (b && payload_has_method(b)) return R_SPEND;
    }
    if (v->sg->hd_has && body_has_method(v->c->src + v->sg->hd_off, v->sg->hd_len))
        return R_SPEND;
    return NULL;
}

static int first_word(char **a, int na, int from)
{
    while (from < na && a[from][0] == '-') from++;
    return from < na ? from : -1;
}

/* Index of the RPC method word of an invocation, or -1 when v is no client. */
static int method_index(const struct cmdv *v)
{
    static const char *const clients[] = {"zclassic-cli", "zcash-cli"};
    if (v->cmd[0] == '$' || IN_LIST(v->cmd, clients)) return first_word(v->a, v->na, 0);
    return -1;
}

static bool is_regtest(const struct cmdv *v);

/* The whole command line mentions -regtest: a client held in a variable (C="zclassic-cli
 * -regtest ..."; $C z_sendmany) is then a regtest client. Set by ag_eval_bash. */
static bool g_regtest_hint;

/* guard.spend_or_key_export: a spend or key-export method outside -regtest. */
static const char *check_rpc(const struct cmdv *v)
{
    int i;
    if (strcmp(v->cmd, "curl") == 0 || strcmp(v->cmd, "wget") == 0) return check_http(v);
    i = method_index(v);
    if (i < 0 || !is_method(v->a[i], strlen(v->a[i]))) return NULL;
    if (v->cmd[0] == '$' && g_regtest_hint) return NULL;
    return is_regtest(v) ? NULL : R_SPEND;
}

static bool has_flag(const struct cmdv *v, const char *flag, bool value_ok)
{
    size_t n = strlen(flag);
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (strcmp(a, flag) == 0) return true;
        if (a[0] == '-' && a[1] == '-' && strcmp(a + 1, flag) == 0) return true;
        if (value_ok && strncmp(a, flag, n) == 0 && a[n] == '=')
            return strcmp(a + n + 1, "0") != 0 && strcmp(a + n + 1, "false") != 0;
    }
    return false;
}

static bool is_regtest(const struct cmdv *v)
{
    return has_flag(v, "-regtest", true);
}

/* The value of -datadir (=VALUE, or the next word), or NULL when absent. */
static const char *datadir_value(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (strncmp(a, "--", 2) == 0) a++;
        if (strncmp(a, "-datadir=", 9) == 0) return a + 9;
        if (strcmp(a, "-datadir") == 0 && i + 1 < v->na) return v->a[i + 1];
    }
    return NULL;
}

/* A flag that only prints help or the version: the node never touches a datadir. */
static bool info_only(const struct cmdv *v)
{
    static const char *const flags[] = {"-help", "--help", "-h", "-?", "-version", "--version",
                                        "-help-debug"};
    for (int i = 0; i < v->na; i++)
        if (IN_LIST(v->a[i], flags)) return true;
    return false;
}

static bool is_reindex_arg(const char *a)
{
    static const char *const flags[] = {"-reindex", "-reindex-chainstate", "-rescan",
                                        "reindex", "reindex-chainstate", "rescan"};
    const char *eq = strchr(a, '=');
    char name[32];
    size_t n = eq ? (size_t)(eq - a) : strlen(a);
    if (n == 0 || n >= sizeof name) return false;
    memcpy(name, a, n);
    name[n] = '\0';
    if (name[0] == '-' && name[1] == '-') memmove(name, name + 1, n);
    if (!IN_LIST(name, flags)) return false;
    return !eq || (strcmp(eq + 1, "0") != 0 && strcmp(eq + 1, "false") != 0);
}

/* zclassicd/zcashd, and the test programs that open node state. */
static const char *const node_progs[] = {"zclassicd", "zcashd", "test_bitcoin", "zcash-gtest",
                                         "zclassic-qt", "zcl-qt-wallet"};

/* guard.reindex: -reindex, -reindex-chainstate or -rescan outside regtest or a test datadir. */
static const char *check_reindex_args(const struct cmdv *v)
{
    const char *dd;
    if (!IN_LIST(v->cmd, node_progs) || is_regtest(v)) return NULL;
    dd = datadir_value(v);
    if (dd && is_test_dir(dd)) return NULL;
    for (int i = 0; i < v->na; i++)
        if (is_reindex_arg(v->a[i])) return R_REINDEX;
    return NULL;
}

/* guard.datadir for programs: an explicit -datadir must be a test temp directory, and a daemon
 * with neither -datadir nor -regtest would open the default node datadir. */
static const char *check_daemon_datadir(const struct cmdv *v)
{
    static const char *const daemons[] = {"zclassicd", "zcashd"};
    const char *dd;
    if (!IN_LIST(v->cmd, node_progs)) return NULL;
    dd = datadir_value(v);
    if (dd) return is_test_dir(dd) ? NULL : R_DATADIR;
    if (IN_LIST(v->cmd, daemons) && !is_regtest(v) && !info_only(v)) return R_DATADIR;
    return NULL;
}

static bool ends_ci(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcasecmp(s + n - m, suffix) == 0;
}

/* guard.hosted_ci: gh workflow run, gh run rerun, and API workflow dispatches. */
static const char *check_gh(const struct cmdv *v)
{
    const char *pos[2] = {"", ""};
    int np = 0;
    if (strcmp(v->cmd, "gh") != 0) return NULL;
    for (int i = 0; i < v->na; i++) {
        if (strstr(v->a[i], "/dispatches")) return R_CI;
        if (v->a[i][0] != '-' && np < 2) pos[np++] = v->a[i];
    }
    if (strcmp(pos[0], "workflow") == 0 && (strcmp(pos[1], "run") == 0 || strcmp(pos[1], "enable") == 0))
        return R_CI;
    return strcmp(pos[0], "run") == 0 && strcmp(pos[1], "rerun") == 0 ? R_CI : NULL;
}

/* ---- writers: only the written operand counts --------------------- */

enum wkind { W_NONE, W_ALL, W_DEST, W_SED, W_SQL, W_TAR, W_FIND, W_DL };

static bool is_all_writer(const char *cmd)
{
    static const char *const names[] = {
        "rm", "rmdir", "mv", "truncate", "dd", "shred", "chmod", "chown", "touch",
        "tee", "vi", "vim", "nano", "emacs", "ed", "sudoedit"};
    return IN_LIST(cmd, names);
}

static bool sed_inplace(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++)
        if (strncmp(v->a[i], "--in-place", 10) == 0 || short_group_has(v->a[i], 'i'))
            return true;
    return false;
}

static bool find_writes(const struct cmdv *v)
{
    static const char *const execs[] = {"-exec", "-execdir", "-ok", "-okdir"};
    for (int i = 0; i < v->na; i++) {
        if (strcmp(v->a[i], "-delete") == 0) return true;
        if (IN_LIST(v->a[i], execs) && i + 1 < v->na && is_all_writer(base_name(v->a[i + 1])))
            return true;
    }
    return false;
}

static bool tar_extracts(const struct cmdv *v)
{
    bool extract = false;
    for (int i = 0; i < v->na; i++) {
        if (strcmp(v->a[i], "--to-stdout") == 0 || short_group_has(v->a[i], 'O')) return false;
        if (strcmp(v->a[i], "--extract") == 0 || strcmp(v->a[i], "--get") == 0 ||
            short_group_has(v->a[i], 'x'))
            extract = true;
    }
    if (v->na > 0 && v->a[0][0] != '-' && strchr(v->a[0], 'x') &&
        strspn(v->a[0], "abcdefghijklmnopqrstuvwxyz") == strlen(v->a[0]))
        extract = true;
    return extract;
}

static enum wkind writer_kind(const struct cmdv *v)
{
    static const char *const dest[] = {"cp", "ln", "install", "rsync", "scp"};
    static const char *const sql[] = {"sqlq", "sqlite3"};
    static const char *const dl[] = {"curl", "wget"};
    if (is_all_writer(v->cmd)) return W_ALL;
    if (IN_LIST(v->cmd, dest)) return W_DEST;
    if (IN_LIST(v->cmd, sql)) return W_SQL;
    if (IN_LIST(v->cmd, dl)) return W_DL;
    if (strcmp(v->cmd, "sed") == 0 && sed_inplace(v)) return W_SED;
    if (strcmp(v->cmd, "find") == 0 && find_writes(v)) return W_FIND;
    if (strcmp(v->cmd, "tar") == 0 && tar_extracts(v)) return W_TAR;
    return W_NONE;
}

/* A relative operand: after cd into a datadir it names a file inside it. */
static bool relative_word(const char *t)
{
    return t[0] && !strchr("-/~$", t[0]) && strspn(t, "0123456789") != strlen(t);
}

static const char *target_rule(const struct cmdv *v, const char *t)
{
    const char *r = path_rule(t);
    if (r) return r;
    return v->in_dd && relative_word(t) ? R_DATADIR : NULL;
}

static const char *wr_all(const struct cmdv *v)
{
    bool dd = strcmp(v->cmd, "dd") == 0;
    for (int i = 0; i < v->na; i++) {
        const char *r;
        if (dd && strncmp(v->a[i], "of=", 3) != 0) continue; /* dd: only of= is written */
        r = target_rule(v, v->a[i]);
        if (r) return r;
    }
    return NULL;
}

/* cp, ln, install, rsync, scp: the destination (-t DIR, else the last operand). */
static const char *wr_dest(const struct cmdv *v)
{
    bool tdir = strcmp(v->cmd, "rsync") != 0 && strcmp(v->cmd, "scp") != 0;
    const char *dest = NULL;
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (tdir && i + 1 < v->na && (short_group_has(a, 't') || strcmp(a, "--target-directory") == 0))
            return target_rule(v, v->a[i + 1]);
        if (tdir && strncmp(a, "--target-directory=", 19) == 0) return target_rule(v, a + 19);
        if (a[0] != '-') dest = a;
    }
    if (dest && ends_ci(dest, ".py")) return R_PYTHON;
    return dest ? target_rule(v, dest) : NULL;
}

/* 0 operand, 1 plain option, 2 script option taking the next word, 3 script
 * option with the script attached. */
static int sed_opt(const char *a)
{
    if (a[0] != '-' || !a[1]) return 0;
    if (strcmp(a, "--expression") == 0 || strcmp(a, "--file") == 0) return 2;
    if (strncmp(a, "--expression=", 13) == 0 || strncmp(a, "--file=", 7) == 0) return 3;
    if (short_group_has(a, 'e') || short_group_has(a, 'f')) return 2;
    return 1;
}

/* sed -i: only the FILE operands; the script (first operand, or the -e/-f
 * argument) is data. */
static const char *wr_sed(const struct cmdv *v)
{
    bool script = false;
    for (int i = 0; i < v->na; i++) {
        int o = sed_opt(v->a[i]);
        const char *r;
        if (o) {
            script = script || o > 1;
            i += o == 2 ? 1 : 0;
        } else if (!script) {
            script = true;
        } else if ((r = target_rule(v, v->a[i])) != NULL) {
            return r;
        }
    }
    return NULL;
}

static bool sql_has_write(const char *s, size_t len)
{
    static const char *const verbs[] = {"insert", "update", "delete", "drop", "alter",
                                        "create", "replace", "vacuum", "attach", "pragma"};
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && is_word_char(s[j])) j++;
        if (j == i) {
            i++;
            continue;
        }
        for (size_t k = 0; k < sizeof verbs / sizeof verbs[0]; k++) {
            if (strlen(verbs[k]) != j - i || strncasecmp(s + i, verbs[k], j - i) != 0) continue;
            if (k < 9 || memchr(s + j, '=', len - j)) return true;
        }
        i = j;
    }
    return false;
}

/* sqlq / sqlite3: a write only with a SQL write verb AND a datadir operand. */
static const char *wr_sql(const struct cmdv *v)
{
    bool wr = false;
    const char *r = NULL;
    for (int i = 0; i < v->na; i++) {
        const char *p = path_rule(v->a[i]);
        if (p) r = r ? r : p;
        else wr = wr || sql_has_write(v->a[i], strlen(v->a[i]));
    }
    if (v->sg->hd_has && sql_has_write(v->c->src + v->sg->hd_off, v->sg->hd_len)) wr = true;
    return wr ? r : NULL;
}

/* curl / wget: the output file or directory. */
static const char *wr_dl(const struct cmdv *v)
{
    static const char *const longs[] = {"--output", "--output-dir", "--output-document",
                                        "--output-file", "--directory-prefix"};
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i], *r = NULL;
        const char *eq = strncmp(a, "--", 2) == 0 ? strchr(a, '=') : NULL;
        if (eq && (strncmp(a, "--output", 8) == 0 || strncmp(a, "--directory-prefix", 18) == 0))
            r = path_rule(eq + 1);
        else if (i + 1 < v->na && (IN_LIST(a, longs) || short_group_has(a, 'o') ||
                                   short_group_has(a, 'O') || short_group_has(a, 'P')))
            r = path_rule(v->a[i + 1]);
        if (r) return r;
    }
    return NULL;
}

static const char *check_writer_paths(const struct cmdv *v)
{
    switch (writer_kind(v)) {
    case W_NONE: return NULL;
    case W_DEST: return wr_dest(v);
    case W_SED: return wr_sed(v);
    case W_SQL: return wr_sql(v);
    case W_DL: return wr_dl(v);
    default: return wr_all(v);
    }
}

static const char *eval_here(const struct cmdv *v)
{
    if (!v->sg->hd_has) return NULL;
    return eval_buf(v->c->src + v->sg->hd_off, v->sg->hd_len, v->depth + 1);
}

static bool is_shell_name(const char *cmd)
{
    static const char *const shells[] = {"sh", "bash", "dash", "zsh"};
    return IN_LIST(cmd, shells);
}

/* sh/bash: scan the -c string. *script is set when stdin is the script
 * (no -c), so a heredoc body is scanned as commands. */
static const char *nested_shell(const struct cmdv *v, bool *script)
{
    *script = true;
    for (int i = 0; i < v->na && v->a[i][0] == '-'; i++) {
        if (short_group_has(v->a[i], 'c') && i + 1 < v->na) {
            *script = false;
            return eval_buf(v->a[i + 1], strlen(v->a[i + 1]), v->depth + 1);
        }
        if (strcmp(v->a[i], "-o") == 0 || strcmp(v->a[i], "+o") == 0) i++;
    }
    return NULL;
}

/* Scan words a[i..] joined by spaces as one command line (ssh, eval). */
static const char *eval_joined(const struct cmdv *v, int i)
{
    size_t total = 1, used = 0;
    char *buf;
    const char *r;
    for (int k = i; k < v->na; k++) total += strlen(v->a[k]) + 1;
    buf = malloc(total); // raw-alloc-ok:build-tool
    if (!buf) return NULL;
    for (int k = i; k < v->na; k++) {
        size_t n = strlen(v->a[k]);
        if (k > i) buf[used++] = ' ';
        memcpy(buf + used, v->a[k], n);
        used += n;
    }
    buf[used] = '\0';
    r = eval_buf(buf, used, v->depth + 1);
    free(buf);
    return r;
}

/* ssh: scan the remote command string. stdin is a script only when there is
 * no remote command (login shell) or the remote command is a shell. */
static const char *nested_ssh(const struct cmdv *v, bool *script)
{
    static const char *const ssh_opts =
        " -B -b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w ";
    int i = 0;
    while (i < v->na && v->a[i][0] == '-')
        i += opt_takes_arg(ssh_opts, v->a[i]) ? 2 : 1;
    i++;
    *script = i >= v->na;
    if (i >= v->na) return NULL;
    *script = is_shell_name(base_name(v->a[i]));
    return eval_joined(v, i);
}

static const char *check_nested(const struct cmdv *v)
{
    bool script = false;
    const char *r = NULL;
    if (is_shell_name(v->cmd)) r = nested_shell(v, &script);
    else if (strcmp(v->cmd, "ssh") == 0) r = nested_ssh(v, &script);
    else if (strcmp(v->cmd, "eval") == 0) return eval_joined(v, 0);
    else return NULL;
    return r ? r : (script ? eval_here(v) : NULL);
}

typedef const char *(*check_fn)(const struct cmdv *);

static const check_fn checks[] = {
    check_python,       check_git,          check_export,  check_rpc, check_gh,
    check_reindex_args, check_daemon_datadir, check_writer_paths, check_nested,
};

/* Track a cd into a datadir along the command chain. */
static void track_cd(const struct cmdv *v, bool *in_dd)
{
    int i;
    if (strcmp(v->cmd, "popd") == 0) *in_dd = false;
    if (strcmp(v->cmd, "cd") != 0 && strcmp(v->cmd, "pushd") != 0) return;
    i = first_word(v->a, v->na, 0);
    *in_dd = i >= 0 && mentions_datadir(v->a[i]);
}

/* Windows spells programs python.exe, git.exe, zclassic-cli.exe: drop the suffix in place. */
static void strip_exe(char *word)
{
    size_t n = strlen(word);
    if (n > 4 && strcasecmp(word + n - 4, ".exe") == 0) word[n - 4] = '\0';
}

static const char *seg_check(const struct gctx *c, int si, int depth, bool *in_dd)
{
    const struct gseg *sg = &c->segs[si];
    char **w = (char **)c->words + sg->w0;
    struct pinfo pi = {false};
    int ci = find_cmd(w, sg->nw, &pi);
    struct cmdv v;
    if (pi.id_assign) return R_IDENT;
    if (ci < 0) return NULL;
    strip_exe(w[ci]);
    v = (struct cmdv){c, sg, base_name(w[ci]), w + ci + 1, sg->nw - ci - 1, w, sg->nw, depth,
                      *in_dd};
    track_cd(&v, in_dd);
    for (size_t k = 0; k < sizeof checks / sizeof checks[0]; k++) {
        const char *r = checks[k](&v);
        if (r) return r;
    }
    return NULL;
}

/* Redirect targets of segment si; after a cd into a datadir a relative
 * target is a datadir file. */
static const char *redir_check(const struct gctx *c, int si, bool in_dd)
{
    for (int i = 0; i < c->nredir; i++) {
        const char *r;
        if (c->redir_seg[i] != si) continue;
        r = path_rule(c->redir[i]);
        if (r) return r;
        if (ends_ci(c->redir[i], ".py")) return R_PYTHON;
        if (in_dd && relative_word(c->redir[i])) return R_DATADIR;
    }
    return NULL;
}

static const char *eval_buf(const char *s, size_t len, int depth)
{
    struct gctx *c;
    const char *r = NULL;
    bool in_dd = false;
    if (depth > MAX_NEST) return NULL;
    c = calloc(1, sizeof *c); // raw-alloc-ok:build-tool
    if (!c) return NULL;
    c->arena = malloc(len * 2 + 16); // raw-alloc-ok:build-tool
    if (!c->arena) {
        free(c);
        return NULL;
    }
    c->src = s;
    tokenize(c, s, len);
    for (int i = 0; !r && i < c->nsegs; i++) {
        r = redir_check(c, i, in_dd);
        if (!r) r = seg_check(c, i, depth, &in_dd);
    }
    for (int i = 0; !r && i < c->nsubs; i++)
        r = eval_buf(s + c->subs[i].off, c->subs[i].len, depth + 1);
    free(c->arena);
    free(c);
    return r;
}

const char *ag_eval_bash(const char *cmd)
{
    g_regtest_hint = strstr(cmd, "-regtest") != NULL;
    return eval_buf(cmd, strlen(cmd), 0);
}

const char *ag_eval_path(const char *tool, const char *path, const char *content)
{
    const char *r;
    if (!path) return NULL;
    r = path_rule(path);
    if (r) return r;
    if (ends_ci(path, ".py")) return R_PYTHON;
    if (content && strcmp(tool, "Write") == 0 && strncmp(content, "#!", 2) == 0) {
        size_t eol = strcspn(content, "\n");
        for (size_t i = 0; i + 6 <= eol; i++)
            if (memcmp(content + i, "python", 6) == 0) return R_PYTHON;
    }
    return is_sealed_path(path) ? R_SEAL : NULL;
}

bool ag_rule_is_warning(const char *rule)
{
    return rule && strcmp(rule, R_SEAL) == 0;
}

/* The rule text, quoted or condensed from AGENTS.md. */
const char *ag_rule_text(const char *rule)
{
    static const struct {
        const char *rule, *why;
    } table[] = {
        {R_DATADIR, "Custody: never touch a real datadir, wallet file or profile; tests use "
                    "isolated datadirs (AGENTS.md Hard rules). Production: do not edit a "
                    "production service or its datadir without being asked"},
        {R_REINDEX, "Production: do not restart or reindex a node you were not asked to; "
                    "-reindex, -reindex-chainstate and -rescan are for -regtest or a test "
                    "datadir only (AGENTS.md Hard rules)"},
        {R_SPEND, "Custody: never spend funds or export keys; spend and key-export RPCs run "
                  "only against -regtest (AGENTS.md Hard rules)"},
        {R_PYTHON, "No Python, no Rust, no GitHub CI: new tooling is C23 or small POSIX sh "
                   "(AGENTS.md Hard rules)"},
        {R_IDENT, "Commits are authored by the repository owner: never set, unset or override "
                  "the git author (AGENTS.md Hard rules, Review)"},
        {R_PUSH, "Never rewrite shared history, and name the branch you push: no force push, "
                 "no push to master, no bare push (AGENTS.md Hard rules)"},
        {R_CI, "No GitHub CI: never add, edit or dispatch GitHub Actions; CI runs on our own "
               "machines with zcutil/local-ci.sh (AGENTS.md Hard rules)"},
        {R_VENDOR, "Vendored code is verbatim: change it only through the matching "
                   "revendor.sh, never by hand (AGENTS.md Hard rules)"},
        {R_SEAL, "This file is in the sealed consensus set. Consensus does not change; a "
                 "reviewed unseal is the only way (doc/agent/UNSEAL.md)"},
    };
    for (size_t i = 0; rule && i < sizeof table / sizeof table[0]; i++)
        if (strcmp(table[i].rule, rule) == 0) return table[i].why;
    return "refused";
}
