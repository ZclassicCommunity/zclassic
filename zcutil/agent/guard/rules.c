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
 * Shell scanning: the command is split into segments at ; && || | & and newlines (also ( ) outside
 * quotes). Quoted text is data, except the argument of ssh, eval and sh/bash/dash/zsh -c, the
 * contents of $( ) and backticks (quoted or not), and a heredoc body that feeds a shell or ssh,
 * which are scanned again as commands. A $( ) or backtick stays in its word too, so an operand
 * that substitutes a datadir is a datadir operand.
 *
 * Writes: only the written operand counts (cp/rsync/scp/install/ln: the destination; sed -i: the
 * files, not the script; dd: of=; sqlq/sqlite3: only with a SQL write verb; curl/wget: the
 * output file). A deleter, a mover (its sources), a recursive chmod/chown and find with -delete or
 * -exec <deleter> also refuse an ancestor of a datadir (/, ~, $HOME, /home, /home/<u>, %APPDATA%,
 * C:\Users\<u> ...) and a glob or brace that could reach one. A cd is tracked as a path prefix
 * along the command chain, and a NAME=value assignment earlier in the command is expanded when
 * the name is used. A datadir piped into xargs <writer> (or a PowerShell deleter with no path of
 * its own) is a datadir write, and so is one fed by a producer that lists or searches a datadir
 * place: find, ls or Get-ChildItem of a datadir, an ancestor or a glob that could reach one (the
 * find -delete checks), or a name pattern such as wallet.dat or Zcl* under a non-test root;
 * `while read f; do rm "$f"` loops count the same way. A literal echo, printf, here-string or
 * heredoc piped into sh, bash, dash or zsh is scanned as commands; any other producer feeding a
 * shell's stdin is guard.too_complex. Spend and key-export names count only in the method position
 * (first word after the RPC client, or a JSON-RPC "method" value in a request body).
 *
 * Options of zclassicd and zclassic-cli are read the way ParseParameters reads them: up to the
 * first word that is not an option, the last value wins, -noX is X=0 (see parse_opts).
 *
 * Known limits (not closed, one per line):
 *   alias g=git; g push                  aliases and shell functions are not expanded
 *   rm -r "$(echo ~)"                    a substitution that computes an ancestor is not run
 *   NAME=$(...) other than mktemp        the substitution's value is not known; -datadir=$NAME with
 *                                        -reindex refuses, with -regtest it is allowed
 *   xargs / find -exec git push          only xargs as a wrapper; find -exec only for writers
 *   sh script.sh / bash x.sh             the script file's content is not read
 *   rsync --remove-source-files <dd> x   a datadir source deleted by rsync is a read
 *   rsync --delete src/ <ancestor>/      the destination of an rsync is not an ancestor check
 *   tar czf <dd>/x.tgz ...               tar create into a datadir is not checked (extract is)
 *   curl -d @file with a spend method    request bodies in files are not read
 *   sqlq db < file.sql                   SQL read from a file is not checked for write verbs
 *   python via a symlink or a renamed    only the command word and .py/.pyw/.pyi names are
 *     binary                             recognised
 *   git commit --reset-author            not a refused identity form
 *   zclassicd -regtest (no -datadir)     allowed: the node's own regtest default is not parsed
 *   git push remote <branch-alias>       only the literal name master (or a wildcard) is recognised
 *   backslash paths inside Bash          Git Bash consumes the backslash before the guard sees it
 *   PowerShell `$d += x`, splatting,     not tracked; a path built from a command's output
 *     functions, aliases                 ((Get-Item x).FullName) is only caught by the statement
 *                                        rule (APPDATA/HOME and a Zclassic name in one statement)
 *   sed -i / patch / git apply on a      Bash and PowerShell writes to sealed consensus files give no
 *     sealed consensus file              guard.consensus_seal warning (only Edit, Write, MultiEdit)
 *   iwr -InFile body.json                a request body read from a file is not read
 *   xargs with a method on a pipe        `printf getinfo | xargs zclassic-cli getblockcount` is
 *                                        allowed: a visible method is the method
 *   tar --remove-files -C <ancestor> .   the archived operands count, an ancestor given by -C does not
 *   Windows 8.3 names                    ZCLASS~N and ZCASHP~N under AppData are matched; other
 *                                        short forms of a profile path are not
 *   eval "$(printf ...)", bash -c        computed command text is not run (also PowerShell code built
 *     "$(... | base64 -d)"              at run time from a non-literal, other than iex and Create)
 *   perl/node/ruby -e code               only a datadir name next to a deleting or writing call
 *                                        is seen; names computed in the code (...+'/.zclassic') and
 *                                        `perl -e 'exec "python3"'` are not
 *   set -- ~/.zclassic; rm -rf "$1"      positional parameters are not tracked (read -r D <<< x is)
 *   ln -s a b; rm -rf b/                 `ln -s <datadir or ancestor>` is refused, a link to
 *                                        another place that is itself a link to one is not followed
 *   curl -d @- from a computed producer  an `@-` body is read only when echo, printf or a heredoc
 *   nc host 8232 < req                   feeds it; nc/ncat/socat/telnet to 8232 or 8233 are refused
 *                                        (-z probes pass), other ways to open a socket are not
 *   zclassic-cli -regtest -conf=/tmp/x   a test -conf can set rpcport and mainnet credentials; the
 *                                        -regtest exemption does not read the file
 *   gh api (other endpoints)             only a write to heads/master is refused; merging a pull
 *                                        request or creating a ref through another endpoint is not
 *   find x | xargs rm, ls | xargs rm     a producer is judged by its own paths and name patterns
 *                                        (a pattern opening with * is too generic); a Where-Object
 *                                        filter or a producer written as a script is not read
 *   | sh, | bash, <<< (stdin script)     the text of echo, printf, cat <<EOF and a here-string is
 *                                        scanned; any other producer (curl, base64 -d, cat file)
 *                                        is too complex; `sh < file` reads the file unseen */

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
#define MAX_WORDS 8192
#define MAX_SEGS 2048
#define MAX_REDIR 512
#define MAX_SUBS 128
#define MAX_HD 4

/* Set when any cap or depth limit drops input: the verdict is then guard.too_complex, never
 * allow (a guard that skips the tail of a long command fails open). */
static bool g_complex;

/* Name of the variable of a `for VAR in <datadir>` loop seen earlier in the command, else "". */
static char g_loopvar[48];

/* `NAME=value` assignments seen earlier in the same command (Bash tool calls share no shell
 * state, so a variable can only come from the command itself). Values are stored expanded. */
#define MAX_VARS 64
#define VAR_VAL 512
static struct {
    char name[40];
    char val[VAR_VAL];
} g_vars[MAX_VARS];
static int g_nvars;

#define MAX_HS 8
#define CWD_CAP 512

struct gseg {
    int w0, nw;
    size_t hd_off, hd_len;
    bool hd_has;
    bool pipe_in; /* this segment reads the pipe of the one before it */
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
    char *hstr[MAX_HS]; /* here-string words (<<< word) */
    int hstr_seg[MAX_HS];
    int nhs;
    struct gseg segs[MAX_SEGS];
    int nsegs;
    struct {
        size_t off, len;
    } subs[MAX_SUBS]; /* $( ) and backtick bodies inside double quotes */
    int nsubs;
};

enum { P_NONE, P_OUT, P_IN, P_HEREDOC, P_HSTR };

struct tok {
    struct gctx *c;
    const char *s;
    size_t len, i, wstart;
    bool in_word, digits, pipe_pending;
    int pend, cw0, cr0, ch0, nhd;
    struct {
        int seg;
        char delim[64];
    } hd[MAX_HD];
};

static const char *eval_buf(const char *s, size_t len, int depth);
static const char *ps_eval(const char *s, size_t len, int depth);
static bool ci_has(const char *s, const char *needle);

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
    if (lvl > 12) {
        g_complex = true;
        return len;
    }
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
    if (t->pend == P_NONE) {
        if (c->nwords < MAX_WORDS) c->words[c->nwords++] = wd;
        else g_complex = true;
    } else if (t->pend == P_OUT) {
        if (c->nredir < MAX_REDIR) {
            c->redir_seg[c->nredir] = c->nsegs;
            c->redir[c->nredir++] = wd;
        } else {
            g_complex = true;
        }
    } else if (t->pend == P_HSTR) {
        if (c->nhs < MAX_HS) {
            c->hstr_seg[c->nhs] = c->nsegs;
            c->hstr[c->nhs++] = wd;
        } else {
            g_complex = true;
        }
    } else if (t->pend == P_HEREDOC) {
        if (t->nhd < MAX_HD) {
            t->hd[t->nhd].seg = c->nsegs;
            snprintf(t->hd[t->nhd].delim, sizeof t->hd[t->nhd].delim, "%s", wd);
            t->nhd++;
        } else {
            g_complex = true;
        }
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
    if ((c->nwords > t->cw0 || c->nredir > t->cr0 || c->nhs > t->ch0) && c->nsegs >= MAX_SEGS) {
        g_complex = true;
    } else if (c->nwords > t->cw0 || c->nredir > t->cr0 || c->nhs > t->ch0) {
        struct gseg *g = &c->segs[c->nsegs++];
        memset(g, 0, sizeof *g);
        g->w0 = t->cw0;
        g->nw = c->nwords - t->cw0;
        g->pipe_in = t->pipe_pending;
        t->pipe_pending = false;
    }
    t->ch0 = c->nhs;
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
    if (end <= off) return;
    if (c->nsubs >= MAX_SUBS) {
        g_complex = true;
        return;
    }
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
            *kind = P_HSTR;
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

/* An unquoted $( ) or backtick substitution: its text stays in the word (so a datadir it names
 * is seen by the operand checks) and its body is scanned as a command line. */
static bool tk_step_subst(struct tok *t)
{
    size_t i = t->i;
    if (!tk_dq_subst(t, &i)) return false;
    t->i = i;
    return true;
}

static bool tk_step_sep(struct tok *t)
{
    char ch = t->s[t->i];
    char nx = t->i + 1 < t->len ? t->s[t->i + 1] : '\0';
    if ((ch == '`' || (ch == '$' && nx == '(')) && tk_step_subst(t)) return true;
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
        t->pipe_pending = ch == '|' && nx != '|';
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

static bool is_identity_key(const char *k);

/* True when s (any case) contains an identity config key: user.name, user.email, author.*,
 * committer.* (GIT_CONFIG_PARAMETERS carries "'user.name=x'" style text). */
static bool mentions_identity_key(const char *s)
{
    static const char *const keys[] = {"user.name", "user.email", "author.", "committer."};
    for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++) {
        size_t m = strlen(keys[k]);
        for (size_t i = 0; s[i]; i++)
            if (strncasecmp(s + i, keys[k], m) == 0) return true;
    }
    return false;
}

static bool is_identity_env(const char *w)
{
    static const char *const names[] = {
        "GIT_AUTHOR_NAME=", "GIT_AUTHOR_EMAIL=", "GIT_COMMITTER_NAME=",
        "GIT_COMMITTER_EMAIL=", "EMAIL="};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (strncmp(w, names[i], strlen(names[i])) == 0) return true;
    if (strncmp(w, "GIT_CONFIG_PARAMETERS=", 22) == 0) return mentions_identity_key(w + 22);
    if (strncmp(w, "GIT_CONFIG_KEY_", 15) == 0) {
        const char *p = w + 15;
        while (isdigit((unsigned char)*p)) p++;
        return *p == '=' && p > w + 15 && is_identity_key(p + 1);
    }
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
    {"doas", " -u -C ", 0},
    {"busybox", " ", 0},
    {"stdbuf", " -i -o -e ", 0},
    {"setsid", " ", 0},
    {"watch", " -n -d ", 0},
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

#define PATH_SEPS "/\\=:, \t\n\"'()`;|&<>"

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
    static const char *const names[] = {"appdata", "%appdata%", "$appdata", "${appdata}",
        "appdata}"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (comp_is_ci(c, n, names[i])) return true;
    return false;
}

/* ~/.zclassic*, ~/.zcash-params, %APPDATA%/Zclassic or %APPDATA%/ZcashParams, and on macOS
 * ~/Library/Application Support/Zclassic or .../ZcashParams (the path words split at the space,
 * so the two-word name is three components). */
static bool mentions_datadir(const char *w)
{
    const char *p = w;
    size_t n = 0;
    bool appdata = false;
    int mac = 0; /* 1 after Library, 2 after Application, then Support sets appdata */
    while (next_comp(&p, &n)) {
        if (comp_starts_ci(p, n, ".zclassic") || comp_starts_ci(p, n, ".zcash-params"))
            return true;
        if (appdata && (comp_is_ci(p, n, "zclassic") || comp_is_ci(p, n, "zcashparams")))
            return true;
        /* the Windows 8.3 short names of the two folders: ZCLASS~1, ZCASHP~1 */
        if (appdata && n == 8 && (comp_starts_ci(p, n, "zclass~") || comp_starts_ci(p, n, "zcashp~")) &&
            isdigit((unsigned char)p[7]))
            return true;
        if (comp_is_appdata(p, n)) appdata = true;
        if (mac == 2 && comp_is_ci(p, n, "support")) appdata = true;
        mac = comp_is_ci(p, n, "library") ? 1 : (mac == 1 && comp_is_ci(p, n, "application")) ? 2 : 0;
        p += n;
    }
    return false;
}

/* Copy w with backslashes as '/', '//' collapsed, '.' components dropped, 'x/..' folded and
 * letters lower-cased: NTFS and default APFS are case-insensitive, and the shell resolves the
 * rest, so every spelling must reach the same compare. NULL when out of memory. */
static char *norm_path(const char *w)
{
    size_t n = strlen(w), o = 0;
    char *out = malloc(n + 1); // raw-alloc-ok:build-tool
    if (!out) {
        g_complex = true;
        return NULL;
    }
    for (size_t i = 0; i < n;) {
        size_t j = i, cs, ce;
        while (j < n && w[j] != '/' && w[j] != '\\') j++;
        cs = i;
        ce = j;
        i = j < n ? j + 1 : n;
        if (ce == cs) { /* empty component: '//' or a leading separator */
            if (cs == 0) out[o++] = '/';
            continue;
        }
        if (ce - cs == 1 && w[cs] == '.') continue;
        if (ce - cs == 2 && w[cs] == '.' && w[cs + 1] == '.' && o > 0) {
            size_t e = o, k; /* fold 'x/..' unless x is '..' or the root */
            if (out[e - 1] == '/') e--;
            k = e;
            while (k > 0 && out[k - 1] != '/') k--;
            if (e == k) continue; /* '/..' is '/' */
            if (!(e - k == 2 && out[k] == '.' && out[k + 1] == '.')) {
                o = k;
                continue;
            }
        }
        for (size_t k = cs; k < ce; k++) out[o++] = (char)tolower((unsigned char)w[k]);
        if (j < n) out[o++] = '/';
    }
    out[o] = '\0';
    return out;
}

static bool path_has_norm(const char *w, const char *pat, bool dir_mode)
{
    size_t m = strlen(pat);
    for (size_t i = 0; w[i]; i++) {
        size_t k = 0;
        if (i > 0 && !is_psep(w[i - 1])) continue;
        while (k < m && w[i + k] && w[i + k] == pat[k]) k++;
        if (k != m) continue;
        if (w[i + k] == '\0') return true;
        if (dir_mode && w[i + k] == '/') return true;
    }
    return false;
}

/* True when pat (written lower-case with '/') occurs in w at a component boundary, after
 * normalisation. dir_mode: the match may be followed by a path separator or the end (a
 * directory); otherwise it must end the word. */
static bool path_has(const char *w, const char *pat, bool dir_mode)
{
    char *nw = norm_path(w), *np = norm_path(pat);
    bool r = nw && np && path_has_norm(nw, np, dir_mode);
    free(nw);
    free(np);
    return r;
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

/* ---- py names, guard files, globs, braces, folded paths ------------------ */

static bool ends_ci(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcasecmp(s + n - m, suffix) == 0;
}

/* A Python source name: .py, .pyw (windowed scripts) or .pyi (stubs). */
static bool is_py_name(const char *w)
{
    return ends_ci(w, ".py") || ends_ci(w, ".pyw") || ends_ci(w, ".pyi");
}

/* The guard's own files: the hook settings, the hook entry and binaries, and its sources. A
 * change there can switch the guard off without a notice, so it asks first. */
static bool is_guard_path(const char *w)
{
    static const char *const files[] = {
        ".claude/settings.json", ".claude/settings.local.json", "zcutil/bin/zcl-agent-guard",
        "zcutil/bin/zcl-agent-guard.exe", "zcutil/bin/zcl-agent-guard-selftest",
        "zcutil/bin/zcl-agent-guard-selftest.exe"};
    if (path_has(w, "zcutil/agent/guard", true)) return true;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++)
        if (path_has(w, files[i], false)) return true;
    return false;
}

static bool has_glob(const char *s)
{
    return strpbrk(s, "*?[") != NULL;
}

static int lc(int ch)
{
    return tolower((unsigned char)ch);
}

/* Shell glob match of pattern p against s, case-insensitive. '*' also matches a leading dot
 * (dotglob and zsh both exist), so the match errs toward refusing. A very long pattern matches. */
static bool glob_match_r(const char *p, const char *s)
{
    if (!*p) return !*s;
    if (*p == '*') {
        while (*p == '*') p++;
        if (!*p) return true;
        for (;; s++) {
            if (glob_match_r(p, s)) return true;
            if (!*s) return false;
        }
    }
    if (!*s) return false;
    if (*p == '?') return glob_match_r(p + 1, s + 1);
    if (*p == '[') {
        const char *q = p + 1;
        bool neg = false, ok = false, first = true;
        if (*q == '!' || *q == '^') {
            neg = true;
            q++;
        }
        while (*q && (*q != ']' || first)) {
            first = false;
            if (q[1] == '-' && q[2] && q[2] != ']') {
                if (lc(*s) >= lc(q[0]) && lc(*s) <= lc(q[2])) ok = true;
                q += 3;
            } else {
                if (lc(*s) == lc(*q)) ok = true;
                q++;
            }
        }
        if (!*q) return lc(*s) == '[' && glob_match_r(p + 1, s + 1); /* unclosed: literal */
        return ok != neg && glob_match_r(q + 1, s + 1);
    }
    return lc(*p) == lc(*s) && glob_match_r(p + 1, s + 1);
}

static bool glob_match(const char *p, const char *s)
{
    return strlen(p) > 64 || glob_match_r(p, s);
}

#define MAX_ALTS 64

struct alts {
    char *v[MAX_ALTS];
    int n;
};

static void alts_free(struct alts *a)
{
    for (int i = 0; i < a->n; i++) free(a->v[i]);
    a->n = 0;
}

static void alts_add(struct alts *a, const char *s)
{
    char *d;
    if (a->n >= MAX_ALTS) {
        g_complex = true;
        return;
    }
    d = strdup(s); // raw-alloc-ok:build-tool
    if (!d) {
        g_complex = true;
        return;
    }
    a->v[a->n++] = d;
}

/* Brace expansion of w into out: a {a,b} list gives each alternative, a {1..3} sequence becomes
 * a '*'. A ${...} is not a brace expansion. At most MAX_ALTS results, beyond that too complex. */
static void brace_one(const char *w, const char *open, const char *close, struct alts *out,
                      int depth);

static void brace_expand(const char *w, struct alts *out, int depth)
{
    const char *open = NULL, *close = NULL;
    int d = 0;
    for (const char *p = w; *p; p++)
        if (*p == '{' && (p == w || p[-1] != '$')) {
            open = p;
            break;
        }
    if (open && depth < 6) {
        for (const char *p = open; *p; p++) {
            if (*p == '{') d++;
            else if (*p == '}' && --d == 0) {
                close = p;
                break;
            }
        }
    }
    if (open && close) brace_one(w, open, close, out, depth);
    else alts_add(out, w);
}

static void brace_one(const char *w, const char *open, const char *close, struct alts *out,
                      int depth)
{
    const char *seg = open + 1, *p;
    bool listed = false;
    int nest = 0;
    size_t pre = (size_t)(open - w), post = strlen(close + 1);
    for (p = seg; p < close; p++) {
        if (*p == '{') nest++;
        else if (*p == '}') nest--;
        else if (*p == ',' && nest == 0) listed = true;
    }
    nest = 0;
    for (p = seg;; p++) {
        if (p == close || (*p == ',' && nest == 0 && listed)) {
            size_t mid = listed ? (size_t)(p - seg) : 1;
            char *t = malloc(pre + mid + post + 1); // raw-alloc-ok:build-tool
            if (!t) {
                g_complex = true;
                return;
            }
            memcpy(t, w, pre);
            if (listed) memcpy(t + pre, seg, mid);
            else t[pre] = '*';
            memcpy(t + pre + mid, close + 1, post + 1);
            brace_expand(t, out, depth + 1);
            free(t);
            if (p == close) return;
            seg = p + 1;
        } else if (*p == '{') {
            nest++;
        } else if (*p == '}') {
            nest--;
        }
    }
}

/* A path folded to components: backslashes as '/', lower case, '.' dropped, '..' applied. The
 * root is '/', a drive (dropped), or '~' for the home directory in any spelling ($HOME,
 * %USERPROFILE%, $env:USERPROFILE, ~user); the APPDATA forms fold to ~/appdata/roaming. '@up'
 * is the unknown directory above a home. */
#define MAX_COMPS 48

struct fpath {
    char *buf;
    const char *c[MAX_COMPS];
    int n;
    bool rooted;
};

static bool tok_in(const char *c, const char *const *list, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(c, list[i]) == 0) return true;
    return false;
}
#define TOK_IN(c, arr) tok_in((c), (arr), sizeof(arr) / sizeof((arr)[0]))

static bool fp_push(struct fpath *f, const char *c)
{
    if (f->n >= MAX_COMPS) {
        g_complex = true;
        return false;
    }
    f->c[f->n++] = c;
    return true;
}

static void fp_pop(struct fpath *f)
{
    if (f->n > 0 && strcmp(f->c[f->n - 1], "..") != 0) {
        if (f->n == 1 && strcmp(f->c[0], "~") == 0) f->c[0] = "@up";
        else f->n--;
    } else if (!f->rooted) {
        fp_push(f, "..");
    }
}

static bool fp_first(struct fpath *f, const char *c0)
{
    static const char *const homes[] = {"$home", "${home}", "$userprofile", "${userprofile}",
        "%userprofile%", "$env:userprofile", "${env:userprofile}", "$env:home", "${env:home}",
        "$homepath", "%homepath%"};
    static const char *const apps[] = {"$appdata", "${appdata}", "%appdata%", "$env:appdata",
        "${env:appdata}"};
    static const char *const locals[] = {"$localappdata", "${localappdata}", "%localappdata%",
        "$env:localappdata", "${env:localappdata}"};
    char norm[48];
    const char *c = c0;
    if (c0[0] == '$' && c0[1] == '{') { /* ${HOME:?}, ${HOME:-x}, ${HOME%/}: the variable itself */
        size_t k = 2, o = 2;
        norm[0] = '$';
        norm[1] = '{';
        while (c0[k] && o + 2 < sizeof norm && !strchr("-+=?#%/}", c0[k]) &&
               !(c0[k] == ':' && c0[k + 1] && strchr("-+=?", c0[k + 1])))
            norm[o++] = c0[k++];
        norm[o++] = '}';
        norm[o] = '\0';
        c = norm;
    }
    if (c0[0] == '~' || TOK_IN(c, homes)) {
        f->rooted = true;
        return fp_push(f, "~");
    }
    if (TOK_IN(c, apps) || TOK_IN(c, locals)) {
        f->rooted = true;
        return fp_push(f, "~") && fp_push(f, "appdata") &&
               fp_push(f, TOK_IN(c, apps) ? "roaming" : "local");
    }
    if (isalpha((unsigned char)c0[0]) && c0[1] == ':' && !c0[2]) { /* a drive */
        f->rooted = true;
        return true;
    }
    return fp_push(f, c0);
}

static void fp_shift(struct fpath *f, int k)
{
    memmove(f->c, f->c + k, (size_t)(f->n - k) * sizeof f->c[0]);
    f->n -= k;
}

static bool fold_path(const char *w, struct fpath *f)
{
    size_t n = strlen(w);
    char *p;
    bool first = true;
    memset(f, 0, sizeof *f);
    f->buf = malloc(n + 1); // raw-alloc-ok:build-tool
    if (!f->buf) {
        g_complex = true;
        return false;
    }
    for (size_t i = 0; i <= n; i++) f->buf[i] = w[i] == '\\' ? '/' : (char)lc(w[i]);
    p = f->buf;
    f->rooted = *p == '/';
    while (*p) {
        char *e;
        while (*p == '/') p++;
        if (!*p) break;
        e = p;
        while (*e && *e != '/') e++;
        if (*e) *e++ = '\0';
        if (strcmp(p, ".") == 0) {
            /* dropped */
        } else if (strcmp(p, "..") == 0) {
            fp_pop(f);
        } else if (first) {
            if (!fp_first(f, p)) return false;
        } else if (!fp_push(f, p)) {
            return false;
        }
        first = false;
        p = e;
    }
    /* WSL /mnt/c/Users/x and Git Bash /c/Users/x name the same place as C:/Users/x. */
    if (f->rooted && f->n >= 2 && strcmp(f->c[0], "mnt") == 0 && strlen(f->c[1]) == 1)
        fp_shift(f, 2);
    else if (f->rooted && f->n >= 2 && strlen(f->c[0]) == 1 && strcmp(f->c[1], "users") == 0)
        fp_shift(f, 1);
    return true;
}

static void fold_free(struct fpath *f)
{
    free(f->buf);
    f->buf = NULL;
}

/* Render a folded path back to text (for the tracked working directory); false when too long. */
static bool fold_render(const struct fpath *f, char *out, size_t cap)
{
    size_t o = 0;
    if (f->rooted && !(f->n > 0 && strcmp(f->c[0], "~") == 0)) out[o++] = '/';
    for (int i = 0; i < f->n; i++) {
        size_t m = strlen(f->c[i]);
        if (o + m + 2 > cap) {
            g_complex = true;
            out[0] = '\0';
            return false;
        }
        if (i > 0) out[o++] = '/';
        memcpy(out + o, f->c[i], m);
        o += m;
    }
    if (o == 0) out[o++] = f->rooted ? '/' : '.';
    out[o] = '\0';
    return true;
}

/* The node-datadir places, as component templates: <root> + <tail>. A root is ~, /home/<user>,
 * /Users/<user> or /root; "@u" is any one component. A path whose components match a prefix of
 * one of these is an ancestor of a datadir (or a glob that could name one), and a path that
 * matches the whole template and goes on is inside it. */
static const char *const dd_roots[4][3] = {
    {"~"}, {"home", "@u"}, {"users", "@u"}, {"root"}};
static const char *const dd_tails[6][3] = {
    {".zclassic"}, {".zcash-params"}, {"appdata", "roaming", "zclassic"},
    {"appdata", "roaming", "zcashparams"}, {"library", "application support", "zclassic"},
    {"library", "application support", "zcashparams"}};

static int arr_len(const char *const *a)
{
    int n = 0;
    while (n < 3 && a[n]) n++;
    return n;
}

static bool pm_comp(const char *pc, const char *tc, int pos)
{
    if (strcmp(tc, "@u") == 0) return true;
    if (strcmp(pc, "@up") == 0)
        return pos == 0 && (strcmp(tc, "home") == 0 || strcmp(tc, "users") == 0 ||
                            strcmp(tc, "root") == 0);
    return has_glob(pc) ? glob_match(pc, tc) : strcmp(pc, tc) == 0;
}

/* anc: also count a path that stops short of a datadir (an ancestor, or a glob that could
 * match the way to one). Otherwise only a path at or inside a datadir place counts. */
static bool path_hits(const struct fpath *f, bool anc)
{
    if (!f->rooted) return false;
    for (int r = 0; r < 4; r++)
        for (int t = 0; t < 6; t++) {
            int rl = arr_len(dd_roots[r]), tl = arr_len(dd_tails[t]), total = rl + tl, m;
            bool ok = true;
            if (f->n < total && !anc) continue;
            m = f->n < total ? f->n : total;
            for (int i = 0; ok && i < m; i++)
                ok = pm_comp(f->c[i], i < rl ? dd_roots[r][i] : dd_tails[t][i - rl], i);
            if (ok) return true;
        }
    return false;
}

/* A value that still starts with a variable or substitution: its value is not known. */
static bool is_unresolved(const char *v)
{
    return v[0] == '$' || v[0] == '`';
}

/* $TMPDIR, ${TMP}, $TEMP...: the variable names a temp location. */
static bool starts_tmpvar(const char *v)
{
    static const char *const vars[] = {"TMPDIR", "TMP", "TEMP", "TEMPDIR", "RUNNER_TEMP"};
    const char *p = v + 1;
    if (v[0] != '$') return false;
    if (*p == '{') p++;
    for (size_t i = 0; i < sizeof vars / sizeof vars[0]; i++) {
        size_t n = strlen(vars[i]);
        if (strncasecmp(p, vars[i], n) == 0 && !isalnum((unsigned char)p[n]) && p[n] != '_')
            return true;
    }
    return false;
}

/* A -datadir value that is a throwaway test directory: under a temp location, a test*, tmp*
 * or mktemp name. An unresolved variable is not one (it may hold a node datadir), and neither
 * is an empty value. Never a node datadir. */
static bool is_test_dir(const char *v)
{
    const char *p = v;
    size_t n = 0;
    if (mentions_datadir(v) || !v[0]) return false;
    if (starts_tmpvar(v) || strncmp(v, "$(mktemp", 8) == 0 || strncmp(v, "`mktemp", 7) == 0)
        return true;
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
    if (is_guard_path(w)) return R_SELF;
    return NULL;
}

/* ---- per-segment rules ------------------------------------------- */

/* State carried along a ; && || | chain: where a cd put us ("" unknown), whether an earlier
 * segment of the pipeline being read names a datadir or lists/searches a place that holds one
 * (pipe_hit), the text the previous segment prints when it is a literal echo, printf or cat of a
 * heredoc (prod_lit/prod), and a `while read` loop fed by such a pipeline (loop_fed). */
#define MAX_READ_VARS 4
struct chain {
    char cwd[CWD_CAP];
    bool pipe_dd;
    bool pipe_hit;
    bool prod_lit;
    char *prod;
    bool loop_fed;
    char read_vars[MAX_READ_VARS][40];
    int nread;
};

struct cmdv {
    const struct gctx *c;
    const struct gseg *sg;
    const char *cmd;
    char **a;
    int na;
    char **w;
    int nw;
    int depth;
    bool in_dd;      /* the tracked working directory is inside a datadir */
    const char *cwd; /* the tracked working directory, "" when unknown */
    const struct chain *ch; /* the chain being read; NULL for PowerShell */
};

static bool is_python_cmd(const char *cmd)
{
    const char *rest = NULL;
    if (strcmp(cmd, "pipx") == 0 || strcmp(cmd, "py") == 0 || strcmp(cmd, "pyw") == 0)
        return true; /* py: the Windows launcher */
    if (strncmp(cmd, "python", 6) == 0) rest = cmd + 6;
    else if (strncmp(cmd, "pip", 3) == 0) rest = cmd + 3;
    if (!rest) return false;
    if (strcmp(rest, "w") == 0) return true; /* pythonw */
    return strspn(rest, "0123456789.") == strlen(rest);
}

/* python, pipx, pip, uv run/pip/tool, and an executed *.py file. */
static const char *check_python(const struct cmdv *v)
{
    if (is_python_cmd(v->cmd) || is_py_name(v->cmd)) return R_PYTHON;
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

/* git config that writes a key with a side effect on identity or pushes: remote.<n>.push and
 * remote.<n>.mirror set the refspec a bare push uses, and an alias whose text sets an identity
 * key runs it later. Returns the rule id or NULL. */
static const char *config_sets_hazard(char **a, int na)
{
    const char *pos[3];
    int np = 0, k = 0;
    bool unset = false;
    char key[64];
    size_t n;
    if (!config_positionals(a, na, pos, &np, &unset) || np == 0) return NULL;
    if (strcmp(pos[0], "set") == 0) k = 1;
    if (np <= k + 1) return NULL; /* no value: a read or an unset */
    n = strlen(pos[k]);
    if (n >= sizeof key) return NULL;
    for (size_t i = 0; i <= n; i++) key[i] = (char)tolower((unsigned char)pos[k][i]);
    if (strncmp(key, "remote.", 7) == 0 && (ends_ci(key, ".push") || ends_ci(key, ".mirror")))
        return R_PUSH;
    if (strncmp(key, "alias.", 6) == 0 && mentions_identity_key(pos[k + 1])) return R_IDENT;
    return NULL;
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
    return strcmp(dst, "master") == 0 || has_glob(dst); /* a wildcard refspec may name master */
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
            if (strncmp(a[i], "--force", 7) == 0 || short_group_has(a[i], 'f') ||
                strcmp(a[i], "--delete") == 0 || short_group_has(a[i], 'd'))
                force = true; /* a force, or a branch delete */
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

static const char *target_rule(const struct cmdv *v, const char *t);

/* git clean, rm, mv, restore, checkout, reset delete or rewrite working-tree files: a datadir
 * operand or a `git -C <datadir>` working directory is a datadir write. */
static const char *git_worktree_writer(const struct cmdv *v, int si)
{
    static const char *const subs[] = {"clean", "rm", "mv", "restore", "checkout", "reset"};
    if (!IN_LIST(v->a[si], subs)) return NULL;
    for (int i = 0; i + 1 < si; i++)
        if (strcmp(v->a[i], "-C") == 0 && mentions_datadir(v->a[i + 1])) return R_DATADIR;
    for (int i = si + 1; i < v->na; i++) {
        const char *r;
        if (v->a[i][0] != '-' && (r = target_rule(v, v->a[i])) != NULL) return r;
    }
    return NULL;
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
    if (strcmp(sub, "push") == 0 || strcmp(sub, "send-pack") == 0)
        return push_rule(v->a + si + 1, v->na - si - 1);
    if (strcmp(sub, "config") == 0) {
        if (config_sets_identity(v->a + si + 1, v->na - si - 1)) return R_IDENT;
        return config_sets_hazard(v->a + si + 1, v->na - si - 1);
    }
    if (strcmp(sub, "commit") == 0)
        for (int i = si + 1; i < v->na; i++)
            if (strcmp(v->a[i], "--author") == 0 || strncmp(v->a[i], "--author=", 9) == 0)
                return R_IDENT;
    return git_worktree_writer(v, si);
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
        if (b && strcmp(b, "@-") == 0 && v->ch && v->sg->pipe_in && v->ch->prod_lit &&
            v->ch->prod && payload_has_method(v->ch->prod))
            return R_SPEND; /* echo '{"method":...}' | curl -d @- */
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
static int method_index(const struct cmdv *v, bool lax)
{
    static const char *const clients[] = {"zclassic-cli", "zcash-cli"};
    int i;
    if (v->cmd[0] != '$' && !IN_LIST(v->cmd, clients)) return -1;
    i = first_word(v->a, v->na, 0);
    /* On Windows a '/x' word is an option too, so the method is the first word past those. */
    while (lax && i >= 0 && v->a[i][0] == '/') i = first_word(v->a, v->na, i + 1);
    return i;
}
/* ---- option parsing the way zclassicd does it ---------------------------------------------
 * ParseParameters (src/util.cpp) reads argv left to right, stops at the first word that does not
 * start with '-', turns --x into -x, splits at '=', lets the last occurrence of an option win,
 * and reads -noX as -X=0 when -X is not set. On Windows it also lower-cases the name and takes
 * '/x' as '-x'. A word after the first non-dash word is not an option (for zclassic-cli it is an
 * RPC parameter, for the node it is ignored). The guard parses both ways ("lax" is the Windows
 * way) and a check that exempts a call needs both to agree. */

#define MAX_POPTS 128

struct popt {
    char name[40];
    const char *val;
    bool eq; /* written -name=value (an empty value is still a value); false: bare -name */
};

struct popts {
    struct popt o[MAX_POPTS];
    int n;
};

static void parse_opts(const struct cmdv *v, bool lax, struct popts *p)
{
    p->n = 0;
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i], *eq;
        struct popt *o;
        size_t len, k = 0;
        char first = a[0];
        if (lax && first == '/') first = '-';
        if (first != '-') break;
        if (p->n >= MAX_POPTS) {
            g_complex = true;
            return;
        }
        eq = strchr(a, '=');
        len = eq ? (size_t)(eq - a) : strlen(a);
        o = &p->o[p->n++];
        o->name[k++] = '-';
        for (size_t j = 1; j < len && k + 1 < sizeof o->name; j++)
            o->name[k++] = lax ? (char)lc(a[j]) : a[j];
        o->name[k] = '\0';
        if (o->name[1] == '-' && o->name[2]) memmove(o->name + 1, o->name + 2, k - 1);
        o->val = eq ? eq + 1 : "";
        o->eq = eq != NULL;
    }
}

static bool interpret_bool(const char *s)
{
    return !s[0] || atoi(s) != 0; /* InterpretBool: empty is true, else atoi(value) != 0 */
}

/* GetBoolArg(name, def) over the parsed options; name is "-regtest" style. */
static bool popts_bool(const struct popts *p, const char *name, bool def)
{
    const struct popt *last = NULL, *lastno = NULL;
    char no[44];
    snprintf(no, sizeof no, "-no%s", name + 1);
    for (int i = 0; i < p->n; i++) {
        if (strcmp(p->o[i].name, name) == 0) last = &p->o[i];
        if (strcmp(p->o[i].name, no) == 0) lastno = &p->o[i];
    }
    if (last) return interpret_bool(last->val);
    if (lastno) return !interpret_bool(lastno->val);
    return def;
}


/* -regtest is in effect under both parses. */
static bool is_regtest(const struct cmdv *v)
{
    struct popts strict, lax;
    parse_opts(v, false, &strict);
    parse_opts(v, true, &lax);
    return popts_bool(&strict, "-regtest", false) && popts_bool(&lax, "-regtest", false);
}

enum { DD_NONE, DD_TEST, DD_UNRESOLVED, DD_REAL };

/* What -datadir (or -conf, the name given) points at, over every occurrence in both parses: the
 * worst one wins. A bare -datadir (zclassicd has no space form) and an empty value are not a
 * test directory; a value still holding a variable is unresolved. */
static int opt_dir_state(const struct cmdv *v, const char *name)
{
    int st = DD_NONE;
    for (int pass = 0; pass < 2; pass++) {
        struct popts p;
        parse_opts(v, pass == 1, &p);
        for (int i = 0; i < p.n; i++) {
            int s;
            if (strcmp(p.o[i].name, name) != 0) continue;
            if (p.o[i].eq && is_test_dir(p.o[i].val)) s = DD_TEST;
            else if (p.o[i].eq && is_unresolved(p.o[i].val) && !mentions_datadir(p.o[i].val))
                s = DD_UNRESOLVED;
            else s = DD_REAL;
            if (s > st || st == DD_NONE) st = s;
        }
    }
    return st;
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

/* The RPC client reaches a test node only when -regtest is in effect (it picks the regtest port
 * by default, bitcoin-cli.cpp), an explicit test -datadir or -conf names where its settings come
 * from (the default conf may carry an rpcport of the real node), no -conf or -datadir is anything
 * else, and no -rpcport or -rpcconnect points back at a production node. */
static bool rpc_is_test_client(const struct cmdv *v)
{
    int dd = opt_dir_state(v, "-datadir"), conf = opt_dir_state(v, "-conf");
    if (!is_regtest(v)) return false;
    if (dd != DD_NONE && dd != DD_TEST) return false;
    if (conf != DD_NONE && conf != DD_TEST) return false;
    if (dd == DD_NONE && conf == DD_NONE) return false;
    for (int pass = 0; pass < 2; pass++) {
        struct popts p;
        parse_opts(v, pass == 1, &p);
        for (int i = 0; i < p.n; i++) {
            if (strcmp(p.o[i].name, "-rpcport") == 0) {
                long port = atol(p.o[i].val);
                if (port == 8023 || port == 8232 || port == 8233 || (port >= 8033 && port <= 8035))
                    return false;
            } else if (strcmp(p.o[i].name, "-rpcconnect") == 0) {
                const char *h = p.o[i].val;
                if (strcmp(h, "127.0.0.1") != 0 && strcmp(h, "localhost") != 0 &&
                    strcmp(h, "::1") != 0)
                    return false;
            }
        }
    }
    return true;
}


/* The command line carries a -regtest word (not in a comment, not inside a longer path): a
 * client held in a variable (C="zclassic-cli -regtest ..."; $C z_sendmany) is then a regtest
 * client. Set by ag_eval_bash. */
static bool g_regtest_hint;

static bool regtest_word_in(const char *s)
{
    char q = '\0';
    for (size_t i = 0; s[i]; i++) {
        char ch = s[i];
        if (q == '\0' && ch == '\\') {
            if (s[i + 1]) i++;
        } else if (q == '\0' && ch == '#' && (i == 0 || strchr(" \t\n;&|(", s[i - 1]))) {
            while (s[i] && s[i] != '\n') i++;
            if (!s[i]) break;
        } else if (q == '\0' && (ch == '\'' || ch == '"')) {
            q = ch;
        } else if (q == ch) {
            q = '\0';
        } else if (ch == '-' && strncmp(s + i, "-regtest", 8) == 0 &&
                   (i == 0 || strchr(" \t\n\"'=", s[i - 1])) &&
                   (s[i + 8] == '\0' || strchr(" \t\n\"';=&|", s[i + 8]))) {
            return true;
        }
    }
    return false;
}

/* Set by seg_run while a segment runs behind xargs: the words xargs reads from stdin follow the
 * command's own, so a client whose method word is missing (or is xargs' replace string) takes its
 * method from the data. g_xrepl is the replace string of -I/-i/-J, "" when there is none. */
static bool g_xargs;
static char g_xrepl[32];

static bool is_client_name(const char *cmd)
{
    static const char *const clients[] = {"zclassic-cli", "zcash-cli"};
    return IN_LIST(cmd, clients);
}

/* The word in the method position is not a method name: it is a variable or substitution, or the
 * replace string of xargs, so the method comes from somewhere the guard cannot read. */
static bool method_word_opaque(const char *w)
{
    return w[0] == '$' || w[0] == '`' || strstr(w, "$(") != NULL ||
           (g_xargs && g_xrepl[0] && strstr(w, g_xrepl) != NULL);
}

/* -stdin is on under both parses: zclassic-cli then appends stdin lines to its arguments, and
 * with no method word of its own the first line becomes the method (bitcoin-cli.cpp). */
static bool stdin_effective(const struct cmdv *v)
{
    struct popts strict, lax;
    parse_opts(v, false, &strict);
    parse_opts(v, true, &lax);
    return popts_bool(&strict, "-stdin", false) || popts_bool(&lax, "-stdin", false);
}

/* guard.spend_or_key_export: a spend or key-export method outside -regtest, also when the method
 * is not visible on the command line (-stdin, xargs, a variable, a substitution). */
static const char *check_rpc(const struct cmdv *v)
{
    int i, j;
    bool hidden = false;
    if (strcmp(v->cmd, "curl") == 0 || strcmp(v->cmd, "wget") == 0) return check_http(v);
    i = method_index(v, false);
    j = method_index(v, true);
    if ((i >= 0 && !is_method(v->a[i], strlen(v->a[i]))) ||
        (j >= 0 && !is_method(v->a[j], strlen(v->a[j])))) {
        /* a word is there; it is only a problem when it hides the method */
        if (is_client_name(v->cmd) &&
            ((i >= 0 && method_word_opaque(v->a[i])) || (j >= 0 && method_word_opaque(v->a[j]))))
            hidden = true;
    }
    if (is_client_name(v->cmd) && i < 0 && j < 0 && !info_only(v) &&
        (g_xargs || stdin_effective(v)))
        hidden = true;
    if (!hidden && (i < 0 || !is_method(v->a[i], strlen(v->a[i]))) &&
        (j < 0 || !is_method(v->a[j], strlen(v->a[j]))))
        return NULL;
    if (v->cmd[0] == '$' && g_regtest_hint) return NULL;
    return rpc_is_test_client(v) ? NULL : R_SPEND;
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
    if (!IN_LIST(v->cmd, node_progs) || is_regtest(v)) return NULL;
    if (opt_dir_state(v, "-datadir") == DD_TEST) return NULL;
    for (int i = 0; i < v->na; i++)
        if (is_reindex_arg(v->a[i])) return R_REINDEX;
    return NULL;
}

/* guard.datadir for programs: an explicit -datadir must be a test temp directory, and a daemon
 * with neither -datadir nor -regtest would open the default node datadir. */
static const char *check_daemon_datadir(const struct cmdv *v)
{
    static const char *const daemons[] = {"zclassicd", "zcashd"};
    int dd;
    if (!IN_LIST(v->cmd, node_progs)) return NULL;
    dd = opt_dir_state(v, "-datadir");
    if (dd == DD_TEST) return NULL;
    if (dd == DD_UNRESOLVED) return is_regtest(v) ? NULL : R_DATADIR;
    if (dd == DD_REAL) return R_DATADIR;
    if (IN_LIST(v->cmd, daemons) && !is_regtest(v) && !info_only(v)) return R_DATADIR;
    return NULL;
}

/* guard.hosted_ci: gh workflow run, gh run rerun, and API workflow dispatches. */
/* gh api that writes (PATCH, POST, PUT, DELETE, or fields, which make it a POST) to the ref of
 * master: it moves or deletes master without `git push`. */
static const char *gh_api_master(const struct cmdv *v)
{
    static const char *const writes[] = {"PATCH", "POST", "PUT", "DELETE"};
    const char *method = NULL;
    bool fields = false, master = false;
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if ((strcmp(a, "-X") == 0 || strcmp(a, "--method") == 0) && i + 1 < v->na)
            method = v->a[++i];
        else if (strncmp(a, "--method=", 9) == 0) method = a + 9;
        else if (strncmp(a, "-X", 2) == 0 && a[2]) method = a + 2;
        else if (strcmp(a, "-f") == 0 || strcmp(a, "-F") == 0 || strcmp(a, "--field") == 0 ||
                 strcmp(a, "--raw-field") == 0 || strcmp(a, "--input") == 0)
            fields = true;
        if (strstr(a, "heads/master") != NULL) master = true;
    }
    if (!master) return NULL;
    if (!method) return fields ? R_PUSH : NULL;
    for (size_t k = 0; k < sizeof writes / sizeof writes[0]; k++)
        if (strcasecmp(method, writes[k]) == 0) return R_PUSH;
    return NULL;
}

static const char *check_gh(const struct cmdv *v)
{
    const char *pos[2] = {"", ""};
    int np = 0;
    if (strcmp(v->cmd, "gh") != 0) return NULL;
    if (v->na > 0 && strcmp(v->a[0], "api") == 0 && gh_api_master(v)) return R_PUSH;
    for (int i = 0; i < v->na; i++) {
        if (strstr(v->a[i], "/dispatches") || strstr(v->a[i], "/rerun") ||
            strstr(v->a[i], "repository_dispatch"))
            return R_CI; /* gh api: dispatch, rerun and rerun-failed-jobs endpoints */
        if (v->a[i][0] != '-' && np < 2) pos[np++] = v->a[i];
    }
    if (strcmp(pos[0], "workflow") == 0 && (strcmp(pos[1], "run") == 0 || strcmp(pos[1], "enable") == 0))
        return R_CI;
    return strcmp(pos[0], "run") == 0 && strcmp(pos[1], "rerun") == 0 ? R_CI : NULL;
}

/* ---- writers: only the written operand counts --------------------- */

enum wkind { W_NONE, W_ALL, W_DEST, W_SED, W_SQL, W_TAR, W_FIND, W_DL, W_UNZIP };

static bool is_all_writer(const char *cmd)
{
    static const char *const names[] = {
        "rm", "rmdir", "mv", "truncate", "dd", "shred", "chmod", "chown", "touch",
        "tee", "vi", "vim", "nano", "emacs", "ed", "sudoedit", "unlink", "mkdir", "chgrp"};
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

/* tar --remove-files deletes the operands it archives. */
static bool tar_removes(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++)
        if (strcmp(v->a[i], "--remove-files") == 0) return true;
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
    if (strcmp(v->cmd, "unzip") == 0) return W_UNZIP;
    if (strcmp(v->cmd, "sed") == 0 && sed_inplace(v)) return W_SED;
    if (strcmp(v->cmd, "find") == 0 && find_writes(v)) return W_FIND;
    if (strcmp(v->cmd, "tar") == 0 && tar_removes(v)) return W_TAR;
    if (strcmp(v->cmd, "tar") == 0 && tar_extracts(v)) return W_TAR;
    return W_NONE;
}

/* A relative operand: after cd into a datadir it names a file inside it. */
static bool relative_word(const char *t)
{
    return t[0] && !strchr("-/~$", t[0]) && strspn(t, "0123456789") != strlen(t);
}

/* True when t names the variable of a for loop that iterates a datadir ($d or ${d}). */
static bool uses_loopvar(const char *t)
{
    size_t n = strlen(g_loopvar);
    if (n == 0) return false;
    for (const char *p = strchr(t, '$'); p; p = strchr(p + 1, '$')) {
        const char *q = p[1] == '{' ? p + 2 : p + 1;
        if (strncmp(q, g_loopvar, n) == 0 && !is_word_char(q[n])) return true;
    }
    return false;
}

/* cwd/t as a new string (the relative operand t resolved against the tracked directory). */
static char *join_cwd(const char *cwd, const char *t)
{
    size_t a = strlen(cwd), b = strlen(t);
    char *s = malloc(a + b + 2); // raw-alloc-ok:build-tool
    if (!s) {
        g_complex = true;
        return NULL;
    }
    memcpy(s, cwd, a);
    s[a] = '/';
    memcpy(s + a + 1, t, b + 1);
    return s;
}

/* One path operand (braces already expanded). anc: the operand is deleted or moved, so a path
 * that is an ancestor of a datadir (or a glob that could reach one) counts too. */
static const char *tgt_one(const struct cmdv *v, const char *t, bool anc)
{
    const char *r = path_rule(t);
    char *joined = NULL;
    struct fpath f;
    if (r) return r;
    if (v->cwd[0] && relative_word(t)) {
        joined = join_cwd(v->cwd, t);
        if (joined) r = path_rule(joined);
    }
    if (!r) {
        if (fold_path(joined ? joined : t, &f) && path_hits(&f, anc)) r = R_DATADIR;
        fold_free(&f);
    }
    free(joined);
    if (r) return r;
    if (uses_loopvar(t)) return R_DATADIR;
    return v->in_dd && relative_word(t) ? R_DATADIR : NULL;
}

static const char *tgt(const struct cmdv *v, const char *t, bool anc)
{
    struct alts al = {{NULL}, 0};
    const char *r = NULL;
    brace_expand(t, &al, 0);
    for (int i = 0; !r && i < al.n; i++) r = tgt_one(v, al.v[i], anc);
    alts_free(&al);
    return r;
}

static const char *target_rule(const struct cmdv *v, const char *t)
{
    return tgt(v, t, false);
}

static bool is_deleter(const char *cmd)
{
    static const char *const names[] = {"rm", "rmdir", "unlink", "shred"};
    return IN_LIST(cmd, names);
}

static bool is_recursive(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++)
        if (strcmp(v->a[i], "--recursive") == 0 || short_group_has(v->a[i], 'R') ||
            short_group_has(v->a[i], 'r'))
            return true;
    return false;
}

/* The operands of mv, minus the destination (the last one, or the -t DIR argument). */
static const char *mv_sources(const struct cmdv *v)
{
    const char *ops[64];
    int n = 0, cnt;
    bool tdir = false;
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (short_group_has(a, 't') || strcmp(a, "--target-directory") == 0) {
            tdir = true;
            i++;
        } else if (strncmp(a, "--target-directory=", 19) == 0) {
            tdir = true;
        } else if (a[0] != '-' || !a[1]) {
            if (n < 64) ops[n++] = a;
            else g_complex = true;
        }
    }
    cnt = tdir ? n : n - 1;
    for (int k = 0; k < cnt; k++) {
        const char *r = tgt(v, ops[k], true);
        if (r) return r;
    }
    return NULL;
}

/* The path operands of find: the words before the first expression. */
static const char *find_roots(const struct cmdv *v)
{
    int i = 0;
    while (i < v->na && (strcmp(v->a[i], "-H") == 0 || strcmp(v->a[i], "-L") == 0 ||
                         strcmp(v->a[i], "-P") == 0))
        i++;
    for (; i < v->na && v->a[i][0] != '-' && v->a[i][0] != '(' && v->a[i][0] != '!'; i++) {
        const char *r = tgt(v, v->a[i], true);
        if (r) return r;
    }
    return NULL;
}

/* find that deletes or rewrites what it walks: -delete, or -exec of a deleter or mover. */
static bool find_destroys(const struct cmdv *v)
{
    static const char *const execs[] = {"-exec", "-execdir", "-ok", "-okdir"};
    static const char *const bad[] = {"rm", "rmdir", "unlink", "shred", "mv", "chmod", "chown",
                                      "chgrp"};
    for (int i = 0; i < v->na; i++) {
        if (strcmp(v->a[i], "-delete") == 0) return true;
        if (IN_LIST(v->a[i], execs) && i + 1 < v->na && IN_LIST(base_name(v->a[i + 1]), bad))
            return true;
    }
    return false;
}

/* The last non-option operand of v, or NULL. */
static const char *last_operand(const struct cmdv *v)
{
    for (int i = v->na - 1; i >= 0; i--)
        if (v->a[i][0] != '-' || !v->a[i][1]) return v->a[i];
    return NULL;
}

static const char *wr_all(const struct cmdv *v)
{
    bool dd = strcmp(v->cmd, "dd") == 0;
    const char *r = NULL, *last;
    for (int i = 0; i < v->na; i++) {
        if (dd && strncmp(v->a[i], "of=", 3) != 0) continue; /* dd: only of= is written */
        r = target_rule(v, v->a[i]);
        if (r) return r;
    }
    if (is_deleter(v->cmd) || (strcmp(v->cmd, "find") == 0 && find_destroys(v)) ||
        ((strcmp(v->cmd, "chmod") == 0 || strcmp(v->cmd, "chown") == 0 ||
          strcmp(v->cmd, "chgrp") == 0) && is_recursive(v))) {
        if (strcmp(v->cmd, "find") == 0) {
            r = find_roots(v);
        } else {
            for (int i = 0; !r && i < v->na; i++)
                if (v->a[i][0] != '-' || !v->a[i][1]) r = tgt(v, v->a[i], true);
        }
        if (r) return r;
    }
    if (strcmp(v->cmd, "mv") == 0) {
        r = mv_sources(v);
        if (r) return r;
        last = last_operand(v);
        if (last && is_py_name(last)) return R_PYTHON;
    }
    if (strcmp(v->cmd, "tee") == 0)
        for (int i = 0; i < v->na; i++)
            if (v->a[i][0] != '-' && is_py_name(v->a[i])) return R_PYTHON;
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
    if (dest && is_py_name(dest)) return R_PYTHON;
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

/* unzip -d DIR (or -dDIR): the extraction directory; without it, the current directory. */
static const char *wr_unzip(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (strcmp(a, "-d") == 0 && i + 1 < v->na) return target_rule(v, v->a[i + 1]);
        if (strncmp(a, "-d", 2) == 0 && a[2] && !strchr("o", a[2])) {
            const char *r = target_rule(v, a + 2);
            if (r) return r;
        }
    }
    return v->in_dd ? R_DATADIR : NULL;
}

static const char *check_writer_paths(const struct cmdv *v)
{
    switch (writer_kind(v)) {
    case W_NONE: return NULL;
    case W_DEST: return wr_dest(v);
    case W_SED: return wr_sed(v);
    case W_SQL: return wr_sql(v);
    case W_DL: return wr_dl(v);
    case W_UNZIP: return wr_unzip(v);
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

/* Scan words a[i..] joined by spaces as one command line (ssh, eval, powershell -Command);
 * ps selects the PowerShell scanner. */
static const char *eval_joined_as(const struct cmdv *v, int i, bool ps)
{
    size_t total = 1, used = 0;
    char *buf;
    const char *r;
    for (int k = i; k < v->na; k++) total += strlen(v->a[k]) + 1;
    buf = malloc(total); // raw-alloc-ok:build-tool
    if (!buf) {
        g_complex = true;
        return NULL;
    }
    for (int k = i; k < v->na; k++) {
        size_t n = strlen(v->a[k]);
        if (k > i) buf[used++] = ' ';
        memcpy(buf + used, v->a[k], n);
        used += n;
    }
    buf[used] = '\0';
    r = ps ? ps_eval(buf, used, v->depth + 1) : eval_buf(buf, used, v->depth + 1);
    free(buf);
    return r;
}

static const char *eval_joined(const struct cmdv *v, int i)
{
    return eval_joined_as(v, i, false);
}

static bool is_ps_name(const char *cmd)
{
    return strcasecmp(cmd, "powershell") == 0 || strcasecmp(cmd, "pwsh") == 0;
}

/* powershell / pwsh: scan the -Command text (or the first positional word) as PowerShell. An
 * -EncodedCommand cannot be read, so it is too complex to check. */
static const char *nested_ps(const struct cmdv *v)
{
    static const char *const valued[] = {"-ep", "-executionpolicy", "-wd", "-workingdirectory",
                                         "-inputformat", "-outputformat", "-version",
                                         "-windowstyle"};
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        char low[24];
        size_t n = strlen(a);
        if (a[0] != '-') return eval_joined_as(v, i, true);
        if (n >= sizeof low) continue;
        for (size_t k = 0; k <= n; k++) low[k] = (char)tolower((unsigned char)a[k]);
        if (strcmp(low, "-c") == 0 || strcmp(low, "-command") == 0 ||
            strcmp(low, "-commandwithargs") == 0)
            return eval_joined_as(v, i + 1, true);
        if (strcmp(low, "-e") == 0 || strncmp(low, "-enc", 4) == 0) return R_COMPLEX;
        if (IN_LIST(low, valued)) i++;
    }
    return NULL;
}

/* cmd /c TEXT: the command text scans like PowerShell (rd, del, move, %APPDATA% paths). */
static const char *nested_cmdexe(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        size_t n = strlen(a);
        /* /c /k, Git Bash's //c //k, and glued switches (/d/c, /s/c) */
        if (n >= 2 && (a[0] == '/') && (a[n - 2] == '/') && strchr("cCkK", a[n - 1]))
            return eval_joined_as(v, i + 1, true);
    }
    return NULL;
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

/* sh/bash read their script from stdin when there is no -c and no script file operand, or with
 * -s (`bash -s args`) or a lone `-`. */
static bool shell_stdin_is_script(const struct cmdv *v)
{
    bool s_flag = false;
    int i = 0;
    for (; i < v->na && v->a[i][0] == '-' && v->a[i][1]; i++) {
        if (strcmp(v->a[i], "--") == 0) {
            i++;
            break;
        }
        if (short_group_has(v->a[i], 'c')) return false;
        if (short_group_has(v->a[i], 's')) s_flag = true;
        if (strcmp(v->a[i], "-o") == 0 || strcmp(v->a[i], "+o") == 0) i++;
    }
    return i >= v->na || s_flag || strcmp(v->a[i], "-") == 0;
}

/* A shell that reads its script from stdin: a here-string is scanned as commands, and so is the
 * literal text of an echo, printf or cat of a heredoc that feeds it through a pipe. Any other
 * producer (base64 -d | sh, curl | sh, cat file | sh) cannot be read, so it is too complex.
 * check_opts: false for ssh, where the remote command (a shell) is not in v->a. */
static const char *shell_stdin_text(const struct cmdv *v, bool check_opts)
{
    const struct gctx *c = v->c;
    const char *r = NULL;
    int si;
    if (!c || v->sg < c->segs || v->sg >= c->segs + c->nsegs) return NULL;
    si = (int)(v->sg - c->segs);
    for (int k = 0; !r && k < c->nhs; k++)
        if (c->hstr_seg[k] == si) r = eval_buf(c->hstr[k], strlen(c->hstr[k]), v->depth + 1);
    if (r) return r;
    if (!v->sg->pipe_in || v->sg->hd_has || !v->ch) return NULL;
    if (check_opts && !shell_stdin_is_script(v)) return NULL;
    if (!v->ch->prod_lit) return R_COMPLEX;
    return v->ch->prod ? eval_buf(v->ch->prod, strlen(v->ch->prod), v->depth + 1) : NULL;
}

static const char *check_nested(const struct cmdv *v)
{
    bool script = false;
    const char *r = NULL;
    if (is_shell_name(v->cmd)) r = nested_shell(v, &script);
    else if (strcmp(v->cmd, "ssh") == 0) r = nested_ssh(v, &script);
    else if (strcmp(v->cmd, "eval") == 0) return eval_joined(v, 0);
    else if (is_ps_name(v->cmd)) return nested_ps(v);
    else if (strcmp(v->cmd, "cmd") == 0) return nested_cmdexe(v);
    else return NULL;
    if (r || !script) return r;
    r = eval_here(v);
    if (r) return r;
    return shell_stdin_text(v, is_shell_name(v->cmd));
}

/* nc, ncat, socat, telnet aimed at a mainnet RPC or P2P port (8232, 8233): the request body comes
 * from stdin or a file, so a spend or key-export method in it cannot be read. -z only probes. */
static const char *check_raw_rpc(const struct cmdv *v)
{
    static const char *const tools[] = {"nc", "ncat", "netcat", "socat", "telnet"};
    if (!IN_LIST(v->cmd, tools)) return NULL;
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (strcmp(a, "-z") == 0 || short_group_has(a, 'z')) return NULL;
    }
    for (int i = 0; i < v->na; i++)
        for (const char *p = v->a[i]; (p = strstr(p, "823")) != NULL; p++)
            if ((p[3] == '2' || p[3] == '3') && !isdigit((unsigned char)p[4]) &&
                (p == v->a[i] || !isdigit((unsigned char)p[-1])))
                return R_SPEND;
    return NULL;
}

/* ln -s <datadir or ancestor> link: a later `rm -r link/` deletes the target's contents. */
static const char *check_symlink(const struct cmdv *v)
{
    int last = -1;
    bool sym = false;
    if (strcmp(v->cmd, "ln") != 0) return NULL;
    for (int i = 0; i < v->na; i++)
        if (strcmp(v->a[i], "--symbolic") == 0 || short_group_has(v->a[i], 's')) sym = true;
    if (!sym) return NULL;
    for (int i = 0; i < v->na; i++)
        if (v->a[i][0] != '-' || !v->a[i][1]) last = i;
    for (int i = 0; i < last; i++) {
        const char *r;
        if ((v->a[i][0] != '-' || !v->a[i][1]) && (r = tgt(v, v->a[i], true)) != NULL) return r;
    }
    return NULL;
}

/* Inline code of perl, node, ruby and the like that names a datadir next to a deleting or
 * writing call (rmtree, rmSync, unlink, File.delete, writeFile ...). */
static bool word_run_destroys(const char *s)
{
    static const char *const verbs[] = {"rm", "unlink", "remove", "delete", "write", "rename",
                                        "move", "truncate", "chmod", "chown", "system", "exec",
                                        "spawn", "popen"};
    for (size_t i = 0; s[i];) {
        size_t j = i;
        while (is_word_char(s[j])) j++;
        for (size_t k = 0; j > i && k < sizeof verbs / sizeof verbs[0]; k++)
            if (strncasecmp(s + i, verbs[k], strlen(verbs[k])) == 0) return true;
        i = j > i ? j : i + 1;
    }
    return false;
}

static const char *check_interp(const struct cmdv *v)
{
    static const char *const interps[] = {"perl", "node", "nodejs", "ruby", "php", "lua", "deno",
                                          "bun", "osascript"};
    if (!IN_LIST(v->cmd, interps)) return NULL;
    for (int i = 0; i < v->na; i++)
        if (mentions_datadir(v->a[i]) && word_run_destroys(v->a[i])) return R_DATADIR;
    return NULL;
}

typedef const char *(*check_fn)(const struct cmdv *);

static const check_fn checks[] = {
    check_python,       check_git,          check_export,  check_rpc, check_gh,
    check_reindex_args, check_daemon_datadir, check_writer_paths, check_nested,
    check_raw_rpc,      check_symlink,      check_interp,
};

/* A refusal is returned; a warning is remembered in *warn and dropped, so a warning never hides
 * a refusal later in the same command. */
static const char *pick(const char *r, const char **warn)
{
    if (r && ag_rule_is_warning(r)) {
        if (!*warn) *warn = r;
        return NULL;
    }
    return r;
}

/* ---- the working directory and variables of one command chain ---------------------------- */


/* A path that starts at a root, so a cd to it replaces the tracked directory. */
static bool rooted_word(const char *t)
{
    return strchr("/~$%\\", t[0]) != NULL || (isalpha((unsigned char)t[0]) && t[1] == ':');
}

/* cd to t: the tracked directory becomes t, or t below it, folded ('..' applied). */
static void cd_to(char *cwd, const char *t)
{
    char *joined = NULL;
    struct fpath f;
    if (strcmp(t, "-") == 0 || !t[0]) {
        cwd[0] = '\0';
        return;
    }
    if (cwd[0] && !rooted_word(t)) joined = join_cwd(cwd, t);
    if (!fold_path(joined ? joined : t, &f) || !fold_render(&f, cwd, CWD_CAP)) cwd[0] = '\0';
    fold_free(&f);
    free(joined);
}

/* Track a cd into a directory along the command chain (also pushd, popd, Set-Location). */
static void track_cd(const struct cmdv *v, char *cwd)
{
    int i;
    if (strcmp(v->cmd, "popd") == 0) {
        cwd[0] = '\0';
        return;
    }
    if (strcmp(v->cmd, "cd") != 0 && strcmp(v->cmd, "pushd") != 0) return;
    i = first_word(v->a, v->na, 0);
    cd_to(cwd, i < 0 ? "~" : v->a[i]);
}

/* A redirect or other plain path word: the datadir, workflow and vendor rules, also for a
 * relative word resolved against the tracked directory. */
static const char *path_rule_cwd(const char *cwd, const char *w)
{
    const char *r = path_rule(w);
    char *j;
    if (r) return r;
    if (cwd[0] && relative_word(w)) {
        j = join_cwd(cwd, w);
        r = j ? path_rule(j) : NULL;
        free(j);
        if (r) return r;
        if (mentions_datadir(cwd)) return R_DATADIR;
    }
    return NULL;
}

static void var_set(const char *name, size_t nl, const char *val)
{
    int k;
    if (nl == 0 || nl >= sizeof g_vars[0].name) return;
    for (k = 0; k < g_nvars; k++)
        if (strlen(g_vars[k].name) == nl && memcmp(g_vars[k].name, name, nl) == 0) break;
    if (k == g_nvars) {
        if (g_nvars >= MAX_VARS) {
            g_complex = true;
            return;
        }
        g_nvars++;
        memcpy(g_vars[k].name, name, nl);
        g_vars[k].name[nl] = '\0';
    }
    if (strlen(val) >= VAR_VAL) /* too long to keep: keep what matters */
        snprintf(g_vars[k].val, VAR_VAL, "%s", mentions_datadir(val) ? "~/.zclassic" : "/opaque");
    else
        memcpy(g_vars[k].val, val, strlen(val) + 1);
}

static const char *var_get(const char *name, size_t nl)
{
    for (int k = 0; k < g_nvars; k++)
        if (strlen(g_vars[k].name) == nl && memcmp(g_vars[k].name, name, nl) == 0)
            return g_vars[k].val;
    return NULL;
}

struct sbuf {
    char *p;
    size_t n, cap;
};

static void sb_add(struct sbuf *b, const char *s, size_t n)
{
    if (!b->p && b->cap == (size_t)-1) return; /* failed earlier */
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 64;
        char *np;
        while (nc < b->n + n + 1) nc *= 2;
        np = realloc(b->p, nc); // raw-alloc-ok:build-tool
        if (!np) {
            free(b->p);
            b->p = NULL;
            b->cap = (size_t)-1;
            g_complex = true;
            return;
        }
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

/* Name at s (after '$' or '${'): its length, or 0 when s does not start a variable name. */
static size_t var_name_len(const char *s)
{
    size_t n = 0;
    if (!isalpha((unsigned char)*s) && *s != '_') return 0;
    while (is_word_char(s[n])) n++;
    return n;
}

/* w with the $NAME and ${NAME} of recorded variables replaced; NULL when nothing changed. */
static char *expand_vars(const char *w)
{
    struct sbuf b = {NULL, 0, 0};
    bool changed = false;
    if (g_nvars == 0 || !strchr(w, '$')) return NULL;
    for (const char *p = w; *p;) {
        if (*p == '$') {
            bool brace = p[1] == '{';
            const char *s = p + 1 + (brace ? 1 : 0);
            size_t nl = var_name_len(s);
            const char *val = nl && (!brace || s[nl] == '}') ? var_get(s, nl) : NULL;
            if (val) {
                sb_add(&b, val, strlen(val));
                p = s + nl + (brace ? 1 : 0);
                changed = true;
                continue;
            }
        }
        sb_add(&b, p++, 1);
    }
    if (!changed || !b.p || b.cap == (size_t)-1) {
        if (b.cap != (size_t)-1) free(b.p);
        return NULL;
    }
    return b.p;
}

/* NAME=value (value expanded with what is known): record it. */
static void record_assign(const char *w)
{
    const char *eq = strchr(w, '=');
    char *x = expand_vars(eq + 1);
    var_set(w, (size_t)(eq - w), x ? x : eq + 1);
    free(x);
}

/* The words of one segment after variable expansion. A word that is exactly one variable
 * holding several words splits into them (C="zclassic-cli -regtest"; $C getinfo). */
struct xw {
    char **w;
    int n, cap;
    char **own;
    int nown, capown;
};

static bool xw_grow(char ***arr, int *cap, int n)
{
    if (n < *cap) return true;
    int nc = *cap ? *cap * 2 : 16;
    char **na = realloc(*arr, (size_t)nc * sizeof **arr); // raw-alloc-ok:build-tool
    if (!na) {
        g_complex = true;
        return false;
    }
    *arr = na;
    *cap = nc;
    return true;
}

static bool xw_push(struct xw *x, char *s, bool owned)
{
    if (x->n >= MAX_WORDS) {
        g_complex = true;
        if (owned) free(s);
        return false;
    }
    if ((owned && !xw_grow(&x->own, &x->capown, x->nown)) || !xw_grow(&x->w, &x->cap, x->n)) {
        if (owned) free(s);
        return false;
    }
    if (owned) x->own[x->nown++] = s;
    x->w[x->n++] = s;
    return true;
}

static void xw_free(struct xw *x)
{
    for (int i = 0; i < x->nown; i++) free(x->own[i]);
    free(x->own);
    free(x->w);
}

/* Split text on blanks into owned words. */
static void xw_split(struct xw *x, const char *val)
{
    for (const char *p = val; *p;) {
        size_t n;
        char *d;
        while (*p == ' ' || *p == '\t') p++;
        n = strcspn(p, " \t");
        if (!n) break;
        d = malloc(n + 1); // raw-alloc-ok:build-tool
        if (!d) {
            g_complex = true;
            return;
        }
        memcpy(d, p, n);
        d[n] = '\0';
        if (!xw_push(x, d, true)) return;
        p += n;
    }
}

static bool xw_build(const struct gctx *c, const struct gseg *sg, struct xw *x)
{
    memset(x, 0, sizeof *x);
    for (int i = 0; i < sg->nw; i++) {
        char *w = c->words[sg->w0 + i], *e = expand_vars(w);
        const char *name = w[0] == '$' ? w + 1 + (w[1] == '{' ? 1 : 0) : NULL;
        size_t nl = name ? var_name_len(name) : 0;
        bool whole = nl && (w[1] != '{' ? name[nl] == '\0' : (name[nl] == '}' && !name[nl + 1]));
        if (e && whole && strpbrk(e, " \t")) {
            xw_split(x, e);
            free(e);
        } else if (e) {
            xw_push(x, e, true);
        } else {
            xw_push(x, w, false);
        }
    }
    return true;
}

static bool is_decl_cmd(const char *cmd)
{
    static const char *const decl[] = {"export", "declare", "typeset", "readonly", "local"};
    return IN_LIST(cmd, decl);
}

/* `for VAR in <list>`: when the list names a datadir, the body's $VAR operands do too. */
static void note_for_loop(const struct cmdv *v)
{
    if (strcmp(v->cmd, "for") != 0 || v->na < 3 || strcmp(v->a[1], "in") != 0) return;
    for (int i = 2; i < v->na; i++) {
        if (!mentions_datadir(v->a[i])) continue;
        snprintf(g_loopvar, sizeof g_loopvar, "%s", v->a[0]);
        return;
    }
}

/* Windows spells programs python.exe, git.exe, zclassic-cli.exe: drop the suffix in place. */
static void strip_exe(char *word)
{
    size_t n = strlen(word);
    if (n > 4 && strcasecmp(word + n - 4, ".exe") == 0) word[n - 4] = '\0';
}

/* Does any word of the segment (or a here-string it reads) name a datadir? */
static bool seg_names_datadir(const struct gctx *c, int si, const struct xw *x, bool *hs_dd)
{
    bool any = false;
    *hs_dd = false;
    for (int k = 0; k < c->nhs; k++)
        if (c->hstr_seg[k] == si && mentions_datadir(c->hstr[k])) *hs_dd = true;
    for (int k = 0; k < x->n; k++)
        if (mentions_datadir(x->w[k])) any = true;
    return any || *hs_dd;
}

/* The replace string xargs words w[from..to) set (-I STR, -ISTR, -i, -J STR, --replace[=STR]). */
static void note_xargs_repl(char **w, int from, int to)
{
    for (int k = from; k < to; k++) {
        const char *a = w[k];
        const char *s = NULL;
        if (strcmp(a, "-I") == 0 || strcmp(a, "-J") == 0) s = k + 1 < to ? w[k + 1] : "";
        else if (strncmp(a, "-I", 2) == 0 || strncmp(a, "-J", 2) == 0) s = a + 2;
        else if (strcmp(a, "-i") == 0 || strcmp(a, "--replace") == 0) s = "{}";
        else if (strncmp(a, "-i", 2) == 0) s = a + 2;
        else if (strncmp(a, "--replace=", 10) == 0) s = a + 10;
        if (s) snprintf(g_xrepl, sizeof g_xrepl, "%s", s);
    }
}

/* ---- what a pipeline producer prints and where it looks ----------------------------------- */

/* A name pattern (find -name, Get-ChildItem -Filter) that can match a datadir or wallet name.
 * A pattern that opens with a wildcard (*.dat) is too generic to count on its own. */
static bool pattern_names_datadir(const char *p)
{
    static const char *const names[] = {"zclassic", ".zclassic", ".zclassic-c23", ".zcash-params",
                                        "zcashparams", "wallet.dat"};
    if (!p[0] || strchr("*?[", p[0])) return false;
    for (size_t k = 0; k < sizeof names / sizeof names[0]; k++)
        if (glob_match(p, names[k])) return true;
    return false;
}

/* A search root outside every test location: an absolute path or a variable. */
static bool loose_root(const char *root)
{
    return rooted_word(root) && !is_test_dir(root);
}

/* find whose roots or name patterns reach a datadir (or a folder holding one). */
static bool find_hit(const struct cmdv *v)
{
    bool loose = false;
    int i = 0;
    while (i < v->na && (strcmp(v->a[i], "-H") == 0 || strcmp(v->a[i], "-L") == 0 ||
                         strcmp(v->a[i], "-P") == 0))
        i++;
    if (find_roots(v)) return true;
    for (; i < v->na && v->a[i][0] != '-' && v->a[i][0] != '(' && v->a[i][0] != '!'; i++)
        if (loose_root(v->a[i])) loose = true;
    for (int k = 0; k + 1 < v->na; k++) {
        const char *a = v->a[k], *p = v->a[k + 1];
        if (strcmp(a, "-name") == 0 || strcmp(a, "-iname") == 0) {
            if (loose && pattern_names_datadir(p)) return true;
        } else if (strcmp(a, "-path") == 0 || strcmp(a, "-ipath") == 0 ||
                   strcmp(a, "-wholename") == 0) {
            if (mentions_datadir(p)) return true;
        }
    }
    return false;
}

/* A command that prints paths of a datadir place: ls, echo or realpath of it or of a glob that
 * could reach one, or a find that searches such a place. */
static bool producer_hit(const struct cmdv *v)
{
    static const char *const lists[] = {"ls", "dir", "vdir", "echo", "printf", "realpath",
                                        "readlink", "stat"};
    if (strcmp(v->cmd, "find") == 0) return find_hit(v);
    if (!IN_LIST(v->cmd, lists)) return false;
    for (int i = 0; i < v->na; i++)
        if (v->a[i][0] != '-' && tgt(v, v->a[i], false)) return true;
    return false;
}

static void prod_set(struct chain *ch, char *text)
{
    free(ch->prod);
    ch->prod = text;
    ch->prod_lit = text != NULL;
}

/* printf FORMAT ARGS rendered: %s %b %d... take the arguments in turn (the format is reused while
 * arguments remain), \n and \t become characters. */
static char *printf_render(const char *fmt, char **args, int nargs)
{
    struct sbuf b = {NULL, 0, 0};
    int ai = 0;
    bool conv;
    do {
        conv = false;
        for (const char *p = fmt; *p; p++) {
            if (*p == '\\' && p[1]) {
                p++;
                if (*p == 'n') sb_add(&b, "\n", 1);
                else if (*p == 't') sb_add(&b, "\t", 1);
                else sb_add(&b, p, 1);
            } else if (*p == '%' && p[1] == '%') {
                sb_add(&b, "%", 1);
                p++;
            } else if (*p == '%') {
                const char *q = p + 1;
                while (*q && !isalpha((unsigned char)*q)) q++;
                if (!*q) {
                    sb_add(&b, p, strlen(p));
                    break;
                }
                conv = true;
                if (ai < nargs) {
                    sb_add(&b, args[ai], strlen(args[ai]));
                    ai++;
                }
                p = q;
            } else {
                sb_add(&b, p, 1);
            }
        }
    } while (conv && ai < nargs && b.cap != (size_t)-1);
    if (b.cap == (size_t)-1) return NULL;
    return b.p ? b.p : strdup(""); // raw-alloc-ok:build-tool
}

/* echo text with the two-character \n made a newline (echo -e and a shell reading it agree). */
static char *echo_render(char **w, int n)
{
    struct sbuf b = {NULL, 0, 0};
    for (int i = 0; i < n; i++) {
        if (i) sb_add(&b, " ", 1);
        for (const char *p = w[i]; *p; p++) {
            if (p[0] == '\\' && p[1] == 'n') {
                sb_add(&b, "\n", 1);
                p++;
            } else {
                sb_add(&b, p, 1);
            }
        }
    }
    if (b.cap == (size_t)-1) return NULL;
    return b.p ? b.p : strdup(""); // raw-alloc-ok:build-tool
}

/* The text a segment prints when that is known without running anything: echo and printf of
 * literal words, and cat of its own heredoc or here-string. Caller frees; NULL otherwise. */
static char *literal_output(const struct gctx *c, int si, char **w, int n)
{
    struct pinfo pi = {false};
    const struct gseg *sg = &c->segs[si];
    int ci = find_cmd(w, n, &pi), k;
    const char *cmd;
    if (ci < 0) return NULL;
    cmd = base_name(w[ci]);
    k = ci + 1;
    if (strcmp(cmd, "echo") == 0) {
        while (k < n && w[k][0] == '-' && w[k][1] && strspn(w[k] + 1, "neE") == strlen(w[k] + 1))
            k++;
        return echo_render(w + k, n - k);
    }
    if (strcmp(cmd, "printf") == 0) {
        while (k < n && w[k][0] == '-' && w[k][1]) k += strcmp(w[k], "-v") == 0 ? 2 : 1;
        return k < n ? printf_render(w[k], w + k + 1, n - k - 1) : NULL;
    }
    if (strcmp(cmd, "cat") == 0) {
        struct sbuf b = {NULL, 0, 0};
        for (; k < n; k++)
            if (w[k][0] != '-') return NULL; /* a file operand */
        if (sg->hd_has) {
            sb_add(&b, c->src + sg->hd_off, sg->hd_len);
        } else {
            for (int h = 0; h < c->nhs; h++)
                if (c->hstr_seg[h] == si) {
                    sb_add(&b, c->hstr[h], strlen(c->hstr[h]));
                    sb_add(&b, "\n", 1);
                }
        }
        if (b.cap == (size_t)-1) return NULL;
        return b.p;
    }
    return NULL;
}

/* A `while read` loop that takes its lines from a pipeline naming or searching a datadir place
 * (find ~ -name x | while read f; do rm "$f"; done): its read variables name that place. A
 * here-string read (read -r D <<< ~/.zclassic) records the variable. */
static void note_read(const struct gctx *c, int si, const struct cmdv *v, const struct xw *x,
                      int ci, struct chain *ch)
{
    static const char *const valued = " -p -d -n -N -t -u -a ";
    char names[MAX_READ_VARS][40];
    int nn = 0;
    bool in_while = false;
    for (int j = 0; j < ci; j++)
        if (strcmp(x->w[j], "while") == 0 || strcmp(x->w[j], "until") == 0) in_while = true;
    for (int i = 0; i < v->na; i++) {
        if (v->a[i][0] == '-' && v->a[i][1]) {
            if (opt_takes_arg(valued, v->a[i])) i++;
        } else if (nn < MAX_READ_VARS) {
            snprintf(names[nn++], sizeof names[0], "%s", v->a[i]);
        }
    }
    if (nn == 0) snprintf(names[nn++], sizeof names[0], "REPLY");
    for (int k = 0; k < c->nhs; k++) {
        if (c->hstr_seg[k] != si) continue;
        for (int j = 0; j < nn; j++) var_set(names[j], strlen(names[j]), c->hstr[k]);
        break;
    }
    if (in_while && c->segs[si].pipe_in && (ch->pipe_dd || ch->pipe_hit)) {
        ch->loop_fed = true;
        ch->nread = nn;
        for (int j = 0; j < nn; j++)
            snprintf(ch->read_vars[j], sizeof ch->read_vars[0], "%s", names[j]);
    }
}

/* t refers to the variable name ($name or ${name}). */
static bool refs_var(const char *t, const char *name)
{
    size_t n = strlen(name);
    for (const char *p = strchr(t, '$'); p; p = strchr(p + 1, '$')) {
        const char *q = p[1] == '{' ? p + 2 : p + 1;
        if (strncmp(q, name, n) == 0 && !is_word_char(q[n])) return true;
    }
    return false;
}

/* A command that deletes, moves or re-owns what its operands name. */
static bool is_destroyer(const char *cmd)
{
    static const char *const names[] = {"mv", "chmod", "chown", "chgrp"};
    return is_deleter(cmd) || IN_LIST(cmd, names);
}

/* Inside a loop fed by a datadir place: a destroyer whose operand is a read variable. */
static bool loop_destroys(const struct cmdv *v, const struct chain *ch)
{
    if (!ch->loop_fed || !is_destroyer(v->cmd)) return false;
    for (int i = 0; i < v->na; i++)
        for (int j = 0; j < ch->nread; j++)
            if (refs_var(v->a[i], ch->read_vars[j])) return true;
    return false;
}

static const char *seg_run(const struct gctx *c, int si, int depth, struct chain *ch,
                           struct xw *x, bool hs_dd, bool *hit)
{
    const struct gseg *sg = &c->segs[si];
    struct pinfo pi = {false};
    const char *r = NULL, *warn = NULL;
    struct cmdv v;
    bool xargs = false;
    int ci = find_cmd(x->w, x->n, &pi);
    *hit = false;
    if (pi.id_assign) return R_IDENT;
    if (ci < 0) return NULL;
    strip_exe(x->w[ci]);
    g_xargs = false;
    g_xrepl[0] = '\0';
    for (int j = 0; j < ci; j++)
        if (strcmp(base_name(x->w[j]), "xargs") == 0) {
            xargs = g_xargs = true;
            note_xargs_repl(x->w, j + 1, ci);
        }
    v = (struct cmdv){c, sg, base_name(x->w[ci]), x->w + ci + 1, x->n - ci - 1, x->w, x->n,
                      depth, false, ch->cwd, ch};
    track_cd(&v, ch->cwd);
    v.in_dd = ch->cwd[0] && mentions_datadir(ch->cwd);
    if (is_decl_cmd(v.cmd))
        for (int k = 0; k < v.na; k++)
            if (is_assign(v.a[k])) record_assign(v.a[k]);
    note_for_loop(&v);
    if (strcmp(v.cmd, "done") == 0) ch->loop_fed = false;
    if (strcmp(v.cmd, "read") == 0) note_read(c, si, &v, x, ci, ch);
    /* xargs <writer> takes its targets from stdin: a datadir named upstream is a datadir write,
     * and so is a destroyer fed by a producer that lists or searches a datadir place */
    if (xargs && (ch->pipe_dd || hs_dd) && writer_kind(&v) != W_NONE) return R_DATADIR;
    if (xargs && ch->pipe_hit && is_destroyer(v.cmd)) return R_DATADIR;
    if (loop_destroys(&v, ch)) return R_DATADIR;
    *hit = producer_hit(&v);
    for (size_t k = 0; !r && k < sizeof checks / sizeof checks[0]; k++)
        r = pick(checks[k](&v), &warn);
    return r ? r : warn;
}

static const char *seg_check(const struct gctx *c, int si, int depth, struct chain *ch)
{
    const struct gseg *sg = &c->segs[si];
    struct xw x;
    const char *r;
    bool hs_dd, dd, hit;
    for (int j = 0; j < sg->nw && is_assign(c->words[sg->w0 + j]); j++)
        record_assign(c->words[sg->w0 + j]);
    if (!xw_build(c, sg, &x)) return NULL;
    if (!sg->pipe_in) {
        ch->pipe_dd = false;
        ch->pipe_hit = false;
        prod_set(ch, NULL);
    }
    dd = seg_names_datadir(c, si, &x, &hs_dd);
    r = seg_run(c, si, depth, ch, &x, hs_dd, &hit);
    if (dd) ch->pipe_dd = true;
    if (hit) ch->pipe_hit = true;
    prod_set(ch, literal_output(c, si, x.w, x.n)); /* what the next segment of a pipe reads */
    xw_free(&x);
    return r;
}

/* Redirect targets of segment si (variables expanded; a relative target resolves against the
 * tracked directory). */
static const char *redir_check(const struct gctx *c, int si, const struct chain *ch)
{
    for (int i = 0; i < c->nredir; i++) {
        char *x;
        const char *w, *r;
        if (c->redir_seg[i] != si) continue;
        x = expand_vars(c->redir[i]);
        w = x ? x : c->redir[i];
        r = path_rule_cwd(ch->cwd, w);
        if (!r && is_py_name(w)) r = R_PYTHON;
        free(x);
        if (r) return r;
    }
    return NULL;
}

static const char *eval_buf(const char *s, size_t len, int depth)
{
    struct gctx *c;
    struct chain ch;
    const char *r = NULL, *warn = NULL;
    if (depth > MAX_NEST) {
        g_complex = true;
        return NULL;
    }
    c = calloc(1, sizeof *c); // raw-alloc-ok:build-tool
    if (!c) {
        g_complex = true;
        return NULL;
    }
    c->arena = malloc(len * 2 + 16); // raw-alloc-ok:build-tool
    if (!c->arena) {
        g_complex = true;
        free(c);
        return NULL;
    }
    memset(&ch, 0, sizeof ch);
    c->src = s;
    tokenize(c, s, len);
    for (int i = 0; !r && i < c->nsegs; i++) {
        r = pick(redir_check(c, i, &ch), &warn);
        if (!r) r = pick(seg_check(c, i, depth, &ch), &warn);
    }
    for (int i = 0; !r && i < c->nsubs; i++)
        r = pick(eval_buf(s + c->subs[i].off, c->subs[i].len, depth + 1), &warn);
    free(ch.prod);
    free(c->arena);
    free(c);
    return r ? r : warn;
}

/* A cap hit beats a warning (the unchecked part may hold a refusal), never a refusal. */
static const char *finish(const char *r)
{
    return g_complex && (!r || ag_rule_is_warning(r)) ? R_COMPLEX : r;
}

static void reset_state(void)
{
    g_complex = false;
    g_loopvar[0] = '\0';
    g_nvars = 0;
}

const char *ag_eval_bash(const char *cmd)
{
    reset_state();
    g_regtest_hint = regtest_word_in(cmd);
    return finish(eval_buf(cmd, strlen(cmd), 0));
}

/* ---- PowerShell and cmd.exe ---------------------------------------------------------------
 * The PowerShell tool is a second shell on Windows. Its words split at ; | & newline and
 * ( ) { } outside quotes, quotes are ' (data) and " (data, except $( ) bodies, which scan as
 * commands), the escape is the backtick, and backslashes stay in the word (they are paths). The
 * program rules are the Bash ones (python, git, gh, zclassic-cli, zclassicd), run on the
 * lower-cased command name; the PowerShell deleters and writers add the datadir, vendor and
 * workflow path checks, and the destroyers (Remove-Item, Move-Item) also refuse an ancestor of a
 * datadir. A pipeline or parenthesised segment that names a datadir into a deleter with no path of
 * its own is refused, and Start-Process unwraps to the program it starts.
 *
 * `$name = expr` (a string, Join-Path, `a + b`, an earlier variable) is recorded and expanded in
 * later words. Join-Path and `a + b` segments, [IO.File]/[IO.Directory] writes and deletes, and
 * the PowerShell web cmdlets are judged as whole statements (ps_note_facts). A delete whose
 * statement mentions APPDATA, ApplicationData, HOME or the profile together with a Zclassic or
 * ZcashParams name is refused when the path cannot be resolved. Known limits: functions, aliases,
 * splatting and `$d += x` are not tracked, and a pipeline into Set-Content (Get-Content a |
 * Set-Content b) checks b only. */

struct psseg {
    char **w;
    int n, cap;
    bool pend_redir;
    const char *r;    /* first refusal found in this scan */
    const char *warn; /* first warning, reported only when there is no refusal */
    char cwd[CWD_CAP];
    int depth;
    bool pipe_dd;  /* a segment of this statement names a datadir */
    bool pipe_hit; /* a segment of this statement lists or searches a place that holds one */
    bool open_eval; /* [scriptblock]::Create seen: the literal text of the next segment is code */
    bool saw_pipe; /* a | came earlier in this statement */
    bool open_writer; /* a deleter or writer with no path operand: a later segment feeds it */
    bool open_anc;    /* the writer is a .NET Delete or Move: a folder that holds a datadir counts too */
    bool st_del, st_base, st_name; /* statement facts: a deleter, a base folder, a datadir name */
    bool st_web, st_meth;          /* statement facts: a web call, a spend or export method */
    char pend_var[40];             /* `$name =` seen, its expression follows in the next segment */
};

static void ps_note(struct psseg *s, const char *r)
{
    if (!r) return;
    if (ag_rule_is_warning(r)) {
        if (!s->warn) s->warn = r;
    } else if (!s->r) {
        s->r = r;
    }
}

static bool ps_push(struct psseg *s, char *wd)
{
    if (s->n == s->cap) {
        int nc = s->cap ? s->cap * 2 : 16;
        char **nw = realloc(s->w, (size_t)nc * sizeof *nw); // raw-alloc-ok:build-tool
        if (!nw) {
            free(wd);
            g_complex = true;
            return false;
        }
        s->w = nw;
        s->cap = nc;
    }
    s->w[s->n++] = wd;
    return true;
}

static bool ps_in(const char *cmd, const char *const *list, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(cmd, list[i]) == 0) return true;
    return false;
}
#define PS_IN(c, arr) ps_in((c), (arr), sizeof(arr) / sizeof((arr)[0]))

/* The value of a -Name or -Name:value parameter (case-insensitive), or NULL. */
static const char *ps_param(char **a, int na, const char *const *names, size_t nn)
{
    for (int i = 0; i < na; i++) {
        size_t len = strcspn(a[i], ":");
        char low[32];
        if (a[i][0] != '-' || len >= sizeof low) continue;
        for (size_t k = 0; k < len; k++) low[k] = (char)tolower((unsigned char)a[i][k]);
        low[len] = '\0';
        if (!ps_in(low, names, nn)) continue;
        if (a[i][len] == ':' && a[i][len + 1]) return a[i] + len + 1;
        if (i + 1 < na) return a[i + 1];
    }
    return NULL;
}

/* True when the command names no path of its own (no operand, or only $_ / $PSItem), so it acts
 * on what the pipeline hands it. A parameter that takes a value (-Include x) is not an operand. */
static bool ps_takes_stdin(const struct cmdv *v)
{
    static const char *const valued[] = {"-include", "-exclude", "-filter", "-stream", "-encoding",
                                         "-credential", "-value", "-name", "-itemtype", "-destination",
                                         "-destinationpath"};
    bool any = false, skip = false;
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (a[0] == '-' && a[1]) {
            char low[24];
            size_t n = strcspn(a, ":");
            skip = false;
            if (n >= sizeof low) continue;
            for (size_t k = 0; k < n; k++) low[k] = (char)tolower((unsigned char)a[k]);
            low[n] = '\0';
            if (a[n] != ':' && PS_IN(low, valued)) skip = true;
            if (a[n] == ':' && strcmp(low, "-path") != 0 && strcmp(low, "-literalpath") != 0)
                continue;
            if (a[n] == ':' && a[n + 1]) any = true;
            continue;
        }
        if (strncasecmp(a, "$_", 2) == 0 || strncasecmp(a, "$psitem", 7) == 0) return true;
        if (!skip) any = true;
        skip = false;
    }
    return !any;
}

static const char *const ps_del[] = {"remove-item", "ri", "del", "erase", "rd", "rmdir", "rm",
                                     "clear-content", "clc", "unlink", "shred"};
static const char *const ps_wr[] = {"set-content", "sc", "add-content", "ac", "out-file",
                                    "tee-object", "tee", "new-item", "ni", "mkdir", "md",
                                    "move-item", "mi", "move", "mv", "rename-item", "rni",
                                    "ren", "set-itemproperty", "touch", "truncate"};
static const char *const ps_mv[] = {"move-item", "mi", "move", "mv", "rename-item", "rni", "ren"};

/* Remove-Item and Move-Item style commands: the sources count with the ancestor rule, so
 * deleting or moving a folder that holds a datadir (~, %APPDATA%, C:\Users\x) is refused. */
static const char *ps_destroy(const char *name, const struct cmdv *v)
{
    static const char *const pparams[] = {"-path", "-literalpath"};
    static const char *const dparams[] = {"-destination", "-destinationpath"};
    bool is_del = PS_IN(name, ps_del), is_mv = PS_IN(name, ps_mv);
    int last = -1;
    const char *p, *r;
    if (!is_del && !is_mv) return NULL;
    if ((p = ps_param(v->a, v->na, pparams, 2)) != NULL && (r = tgt(v, p, true)) != NULL)
        return r;
    if (is_mv && !ps_param(v->a, v->na, dparams, 2)) /* the last operand is the destination */
        for (int i = 0; i < v->na; i++)
            if (v->a[i][0] != '-') last = i;
    for (int i = 0; i < v->na; i++)
        if (v->a[i][0] != '-' && i != last && (r = tgt(v, v->a[i], true)) != NULL) return r;
    return NULL;
}

static const char *ps_writer(const char *name, struct cmdv *v)
{
    static const char *const cp[] = {"copy-item", "copy", "cp", "cpi", "xcopy", "robocopy"};
    static const char *const dparams[] = {"-destination", "-destinationpath"};
    static const char *const oparams[] = {"-outfile", "-o"};
    static const char *const web[] = {"invoke-webrequest", "iwr", "invoke-restmethod", "irm",
                                      "curl", "wget"};
    bool is_del = PS_IN(name, ps_del), is_wr = PS_IN(name, ps_wr);
    const char *r;
    if (is_del || is_wr) {
        for (int i = 0; i < v->na; i++) {
            if (v->a[i][0] == '-' && !strchr(v->a[i], ':')) continue;
            if ((r = target_rule(v, v->a[i])) != NULL) return r;
            if (is_wr && is_py_name(v->a[i])) return R_PYTHON;
        }
        return ps_destroy(name, v);
    }
    if (PS_IN(name, cp)) {
        const char *dest = ps_param(v->a, v->na, dparams, 2);
        for (int i = 0; !dest && i < v->na; i++) /* else the last positional */
            if (v->a[v->na - 1 - i][0] != '-' && v->a[v->na - 1 - i][0] != '/')
                dest = v->a[v->na - 1 - i];
        if (!dest) return NULL;
        if (is_py_name(dest)) return R_PYTHON;
        return target_rule(v, dest);
    }
    if (PS_IN(name, web)) {
        const char *out = ps_param(v->a, v->na, oparams, 2);
        return out ? target_rule(v, out) : NULL;
    }
    if (strcmp(name, "expand-archive") == 0 || strcmp(name, "unzip") == 0) {
        const char *d = ps_param(v->a, v->na, dparams, 2);
        return d ? target_rule(v, d) : (v->in_dd ? R_DATADIR : NULL);
    }
    return NULL;
}

/* Start-Process <program> -ArgumentList ...: the program rules apply to the program started. */
static const char *ps_start_process(const struct cmdv *v)
{
    static const char *const fparams[] = {"-filepath"};
    const char *prog = ps_param(v->a, v->na, fparams, 1), *warn = NULL, *r = NULL;
    int k = -1;
    char *pl;
    struct cmdv sv;
    size_t n;
    if (!prog)
        for (int i = 0; k < 0 && i < v->na; i++)
            if (v->a[i][0] != '-') k = i;
    if (!prog && k >= 0) prog = v->a[k];
    if (!prog) return NULL;
    prog = base_name(prog);
    for (const char *p = prog; *p; p++)
        if (*p == '\\') prog = p + 1;
    n = strlen(prog);
    pl = malloc(n + 1); // raw-alloc-ok:build-tool
    if (!pl) {
        g_complex = true;
        return NULL;
    }
    for (size_t i = 0; i <= n; i++) pl[i] = (char)tolower((unsigned char)prog[i]);
    strip_exe(pl);
    sv = *v;
    sv.cmd = pl;
    sv.a = v->a + (k >= 0 ? k + 1 : 0);
    sv.na = v->na - (k >= 0 ? k + 1 : 0);
    {
        /* -ArgumentList takes one string or a comma list: split it into the program's words */
        struct xw xs;
        memset(&xs, 0, sizeof xs);
        for (int i = 0; i < sv.na; i++) {
            const char *a = sv.a[i];
            if (i > 0 && (strcasecmp(sv.a[i - 1], "-argumentlist") == 0 ||
                          strcasecmp(sv.a[i - 1], "-args") == 0)) {
                char *cp = strdup(a); // raw-alloc-ok:build-tool
                if (!cp) {
                    g_complex = true;
                    break;
                }
                for (char *p = cp; *p; p++)
                    if (*p == ',') *p = ' ';
                xw_split(&xs, cp);
                free(cp);
            } else {
                xw_push(&xs, (char *)a, false);
            }
        }
        sv.a = xs.w;
        sv.na = xs.n;
        for (size_t i = 0; !r && i < sizeof checks / sizeof checks[0]; i++)
            r = pick(checks[i](&sv), &warn);
        xw_free(&xs);
    }
    free(pl);
    return r ? r : warn;
}

/* ---- PowerShell values: variables, Join-Path and string concatenation ---------------------- */

/* w with the $name and ${name} of recorded variables replaced (PowerShell names are not case
 * sensitive, so they are kept and looked up in lower case); NULL when nothing changed. */
static char *ps_expand(const char *w)
{
    struct sbuf b = {NULL, 0, 0};
    bool changed = false;
    if (g_nvars == 0 || !strchr(w, '$')) return NULL;
    for (const char *p = w; *p;) {
        if (*p == '$') {
            bool brace = p[1] == '{';
            const char *s = p + 1 + (brace ? 1 : 0);
            size_t nl = var_name_len(s);
            const char *val = NULL;
            if (nl && nl < sizeof g_vars[0].name && (!brace || s[nl] == '}')) {
                char low[sizeof g_vars[0].name];
                for (size_t k = 0; k < nl; k++) low[k] = (char)tolower((unsigned char)s[k]);
                val = var_get(low, nl);
            }
            if (val && !(s[nl] == ':' && !brace)) {
                sb_add(&b, val, strlen(val));
                p = s + nl + (brace ? 1 : 0);
                changed = true;
                continue;
            }
        }
        sb_add(&b, p++, 1);
    }
    if (!changed || !b.p || b.cap == (size_t)-1) {
        if (b.cap != (size_t)-1) free(b.p);
        return NULL;
    }
    return b.p;
}

/* A word shaped like a cmdlet name (Get-Item): it is a command, not part of a value. */
static bool cmdlet_like(const char *w)
{
    const char *d = strchr(w, '-');
    if (!d || d == w || !d[1]) return false;
    for (const char *p = w; *p; p++)
        if (!isalpha((unsigned char)*p) && p != d) return false;
    return true;
}

/* The string value of `first` plus the words w[from..n) as one expression: Join-Path A B joins
 * with a backslash, `A + B` concatenates, a leading cmdlet name is dropped and the rest joins with
 * a backslash. *cmd is set when a cmdlet name was dropped (the words then only name what the
 * command reads, so the value is not a path that is itself deleted). Caller frees; NULL when
 * there is nothing. */
static char *ps_value(char **w, int n, int from, const char *first, bool *cmd)
{
    struct sbuf b = {NULL, 0, 0};
    const char *pc[64];
    int np = 0, start = 0;
    bool plus = false, dropped = false;
    if (first && *first) pc[np++] = first;
    for (int i = from; i < n && np < 64; i++) pc[np++] = w[i];
    if (cmd) *cmd = false;
    if (np == 0) return NULL;
    if (strcasecmp(pc[0], "join-path") == 0 || cmdlet_like(pc[0])) {
        dropped = true;
        start = 1;
    }
    if (dropped && cmd && strcasecmp(pc[0], "join-path") != 0) *cmd = true;
    for (int i = 0; i < np; i++)
        if (strcmp(pc[i], "+") == 0) plus = true;
    for (int i = start; i < np; i++) {
        if (strcmp(pc[i], "+") == 0) continue;
        if (dropped && pc[i][0] == '-') continue;
        if (b.n && !plus) sb_add(&b, "\\", 1);
        sb_add(&b, pc[i], strlen(pc[i]));
    }
    return b.cap == (size_t)-1 ? NULL : b.p;
}

/* `$name = expr`, `$name=expr` and `$name =expr` at the start of a segment: record the variable
 * and drop the words it consumed. An assignment whose expression starts in a later
 * (parenthesised) segment leaves the name pending in s->pend_var. */
static void ps_assign(struct psseg *s)
{
    const char *w0, *rest, *first;
    char *fx;
    size_t nl;
    char low[sizeof g_vars[0].name];
    int from;
    char *val;
    if (s->n == 0) return;
    w0 = s->w[0];
    if (w0[0] != '$' || !(nl = var_name_len(w0 + 1)) || nl >= sizeof low) return;
    for (size_t k = 0; k < nl; k++) low[k] = (char)tolower((unsigned char)w0[1 + k]);
    low[nl] = '\0';
    rest = w0 + 1 + nl;
    if (*rest == '=') {
        first = rest + 1;
        from = 1;
    } else if (!*rest && s->n > 1 && s->w[1][0] == '=') {
        first = s->w[1] + 1;
        from = 2;
    } else {
        return;
    }
    for (int i = from; i < s->n; i++) { /* the expression sees the variables known so far */
        char *x = ps_expand(s->w[i]);
        if (x) {
            free(s->w[i]);
            s->w[i] = x;
        }
    }
    fx = *first ? ps_expand(first) : NULL;
    val = ps_value(s->w, s->n, from, fx ? fx : first, NULL);
    free(fx);
    if (val && ci_has(val, "getfolderpath")) {
        /* [Environment]::GetFolderPath('ApplicationData'): the folder name is the next segment
         * (the parenthesis splits it), and becomes the value of the variable */
        free(val);
        val = NULL;
    }
    if (!val) { /* `$d = and the expression follows in the next segment */
        snprintf(s->pend_var, sizeof s->pend_var, "%s", low);
    } else {
        var_set(low, nl, val);
        free(val);
    }
    for (int i = 0; i < s->n; i++) free(s->w[i]); /* the consumed words are not a command */
    s->n = 0;
}

/* Replace each word that holds a recorded variable by its value. */
static void ps_expand_words(struct psseg *s)
{
    for (int i = 0; i < s->n; i++) {
        char *x = ps_expand(s->w[i]);
        if (x) {
            free(s->w[i]);
            s->w[i] = x;
        }
    }
}

/* ---- statement-level facts: a deleter or a web call somewhere in the statement ------------- */

static bool ci_has(const char *s, const char *needle)
{
    size_t n = strlen(needle);
    for (; *s; s++)
        if (strncasecmp(s, needle, n) == 0) return true;
    return false;
}

/* The word names a folder that holds a datadir: %APPDATA%, $env:APPDATA, ApplicationData (the
 * GetFolderPath name), the profile or home. */
static bool ps_base_word(const char *w)
{
    static const char *const t[] = {"appdata", "applicationdata", "userprofile", "$home",
                                    "$env:home", "homepath", "~"};
    for (size_t k = 0; k < sizeof t / sizeof t[0]; k++)
        if (ci_has(w, t[k])) return true;
    return false;
}

/* The word has a component that is a datadir name on its own: Zclassic, ZcashParams, .zclassic*,
 * .zcash-params or a Windows 8.3 short name (ZCLASS~1). A scratch directory under a temp or test
 * location does not count. */
static bool ps_name_word(const char *w)
{
    const char *p = w;
    size_t n = 0;
    bool hit = false;
    while (next_comp(&p, &n)) {
        if (comp_is_ci(p, n, "zclassic") || comp_is_ci(p, n, "zcashparams") ||
            comp_starts_ci(p, n, ".zclassic") || comp_starts_ci(p, n, ".zcash-params") ||
            (comp_starts_ci(p, n, "zclass~") && n == 8) || (comp_starts_ci(p, n, "zcashp~") && n == 8))
            hit = true;
        p += n;
    }
    return hit && !is_test_dir(w);
}

/* Any run of word characters in w is a spend or key-export method name. */
static bool ps_word_has_method(const char *w)
{
    for (size_t i = 0; w[i];) {
        size_t j = i;
        while (is_word_char(w[j])) j++;
        if (j > i && is_method(w + i, j - i)) return true;
        i = j > i ? j : i + 1;
    }
    return false;
}

static bool ps_web_word(const char *w)
{
    static const char *const names[] = {"iwr", "irm", "curl", "wget", "invoke-webrequest",
                                        "invoke-restmethod", "curl.exe", "wget.exe"};
    for (size_t k = 0; k < sizeof names / sizeof names[0]; k++)
        if (strcasecmp(w, names[k]) == 0) return true;
    return ci_has(w, "webclient") || ci_has(w, "httpclient") || ci_has(w, "webrequest") ||
           ci_has(w, "restmethod");
}

/* A command that deletes: a PowerShell deleter, or a .NET Delete/Move (System.IO.File/Directory). */
static bool ps_delete_word(const char *w)
{
    char *lc = strdup(w); // raw-alloc-ok:build-tool
    bool r;
    if (!lc) {
        g_complex = true;
        return false;
    }
    for (char *p = lc; *p; p++) *p = (char)tolower((unsigned char)*p);
    strip_exe(lc);
    r = PS_IN(lc, ps_del) || (strstr(lc, "io.") && (strstr(lc, "::delete") || strstr(lc, "::move"))) ||
        ends_ci(lc, ".delete") || ends_ci(lc, ".moveto") || ends_ci(lc, ".deletefolder") ||
        ends_ci(lc, ".deletefile") || ends_ci(lc, ".movefolder") || ends_ci(lc, ".movefile");
    free(lc);
    return r;
}

/* A .NET System.IO static call that writes or deletes its first argument. */
static bool ps_dotnet_writer(const char *w)
{
    static const char *const verbs[] = {"::delete", "::move", "::copy", "::create", "::writeall",
                                        "::appendall", "::replace", "::openwrite", "::setattributes",
                                        "::appendtext", "::createtext"};
    if (!ci_has(w, "[io.") && !ci_has(w, "[system.io.")) return false;
    for (size_t k = 0; k < sizeof verbs / sizeof verbs[0]; k++)
        if (ci_has(w, verbs[k])) return true;
    return false;
}

/* Fold the facts of the segment's words into the statement flags, then judge the statement. */
static void ps_note_facts(struct psseg *s)
{
    for (int i = 0; i < s->n; i++) {
        const char *w = s->w[i];
        if (ps_delete_word(w)) s->st_del = true;
        if (ps_base_word(w)) s->st_base = true;
        if (ps_name_word(w)) s->st_name = true;
        if (ps_web_word(w)) s->st_web = true;
        if (ps_word_has_method(w)) s->st_meth = true;
    }
    if (s->st_del && s->st_base && s->st_name) ps_note(s, R_DATADIR);
    if (s->st_web && s->st_meth) ps_note(s, R_SPEND);
}

/* A listing cmdlet (Get-ChildItem, gci, dir, ls, Get-Item) whose path is a datadir or a folder
 * that holds one (an ancestor), or whose -Filter/-Include names one (Zcl*, wallet.dat) under a
 * search root outside the test locations. What it lists then feeds a deleter downstream. */
static bool ps_lister_hit(const struct psseg *s)
{
    static const char *const listers[] = {"get-childitem", "gci", "dir", "ls", "get-item", "gi"};
    static const char *const valued[] = {"-exclude", "-depth", "-attributes", "-stream",
                                         "-readcount"};
    struct gseg zero;
    struct cmdv cv;
    char low[24];
    const char *pats[8], *roots[16];
    int np = 0, nr = 0;
    bool loose = false;
    size_t n;
    if (s->n < 2) return false;
    n = strlen(s->w[0]);
    if (n >= sizeof low) return false;
    for (size_t k = 0; k <= n; k++) low[k] = (char)tolower((unsigned char)s->w[0][k]);
    if (!PS_IN(low, listers)) return false;
    memset(&zero, 0, sizeof zero);
    cv = (struct cmdv){NULL, &zero, "", NULL, 0, NULL, 0, s->depth, false, s->cwd, NULL};
    for (int i = 1; i < s->n; i++) {
        const char *a = s->w[i];
        if (a[0] == '-' && a[1]) {
            size_t len = strcspn(a, ":");
            const char *val = a[len] == ':' && a[len + 1] ? a + len + 1 : NULL;
            char pn[24];
            if (len >= sizeof pn) continue;
            for (size_t k = 0; k < len; k++) pn[k] = (char)tolower((unsigned char)a[k]);
            pn[len] = '\0';
            if (!val && (PS_IN(pn, valued) || strcmp(pn, "-filter") == 0 ||
                         strcmp(pn, "-include") == 0 || strcmp(pn, "-path") == 0 ||
                         strcmp(pn, "-literalpath") == 0) &&
                i + 1 < s->n)
                val = s->w[++i];
            if (!val) continue;
            if ((strcmp(pn, "-filter") == 0 || strcmp(pn, "-include") == 0) && np < 8) pats[np++] = val;
            else if ((strcmp(pn, "-path") == 0 || strcmp(pn, "-literalpath") == 0) && nr < 16)
                roots[nr++] = val;
        } else if (nr < 16) {
            roots[nr++] = a;
        }
    }
    for (int i = 0; i < nr; i++) {
        if (tgt(&cv, roots[i], true)) return true;
        if (loose_root(roots[i])) loose = true;
    }
    for (int i = 0; loose && i < np; i++)
        if (pattern_names_datadir(pats[i])) return true;
    return false;
}

static const char *ps_seg(struct psseg *s)
{
    static const char *const checks_ps[] = {"cd", "sl", "set-location", "chdir", "pushd",
                                            "push-location", "popd", "pop-location"};
    static const char *const starts[] = {"start-process", "start", "saps"};
    char *lc;
    struct cmdv v;
    struct gseg zero;
    int ci = 0;
    const char *name, *r = NULL, *warn = NULL;
    size_t n;
    if (s->n == 0) return NULL;
    if (strncasecmp(s->w[0], "$env:", 5) == 0 && s->n > 1 && strcmp(s->w[1], "=") == 0) {
        static const char *const ids[] = {"git_author_name", "git_author_email",
                                          "git_committer_name", "git_committer_email", "email"};
        for (size_t k = 0; k < sizeof ids / sizeof ids[0]; k++)
            if (strcasecmp(s->w[0] + 5, ids[k]) == 0) return R_IDENT;
    }
    while (ci < s->n && strcmp(s->w[ci], ".") == 0) ci++;
    if (ci >= s->n) return NULL;
    name = s->w[ci];
    for (const char *p = name; *p; p++)
        if (*p == '/' || *p == '\\') name = p + 1;
    n = strlen(name);
    lc = malloc(n + 1); // raw-alloc-ok:build-tool
    if (!lc) {
        g_complex = true;
        return NULL;
    }
    for (size_t k = 0; k <= n; k++) lc[k] = (char)tolower((unsigned char)name[k]);
    strip_exe(lc);
    memset(&zero, 0, sizeof zero);
    v = (struct cmdv){NULL, &zero, lc, s->w + ci + 1, s->n - ci - 1, s->w + ci, s->n - ci,
                      s->depth, s->cwd[0] && mentions_datadir(s->cwd), s->cwd, NULL};
    if (PS_IN(lc, checks_ps)) {
        struct cmdv cdv = v;
        cdv.cmd = lc[0] == 'p' && lc[1] == 'o' ? "popd" : "cd";
        track_cd(&cdv, s->cwd);
    } else if (strcmp(lc, "iex") == 0 || strcmp(lc, "invoke-expression") == 0) {
        /* no literal text (iex (decode ...), $x | iex, iex $cmd): the code cannot be read */
        r = v.na == 0 || v.a[0][0] == '$' ? R_COMPLEX : eval_joined_as(&v, 0, true);
    } else if (PS_IN(lc, starts)) {
        r = ps_start_process(&v);
    } else if (ps_dotnet_writer(lc)) {
        /* [IO.Directory]::Delete(path, ...): the path is the next segment (the paren splits) */
        s->open_writer = true;
        s->open_anc = true;
    } else if ((PS_IN(lc, ps_del) || PS_IN(lc, ps_wr)) && ps_takes_stdin(&v)) {
        /* no path of its own: the pipeline (Get-ChildItem <datadir> | Remove-Item) or a later
         * parenthesised segment (Remove-Item (Get-Item <datadir>)) carries the target */
        s->open_writer = true;
        if ((s->pipe_dd || s->pipe_hit) && s->saw_pipe) r = R_DATADIR;
    } else {
        r = ps_writer(lc, &v);
    }
    r = pick(r, &warn);
    for (size_t k = 0; !r && k < sizeof checks / sizeof checks[0]; k++)
        r = pick(checks[k](&v), &warn);
    free(lc);
    return r ? r : warn;
}

/* A new statement (; newline &) forgets the pipeline and the statement facts. */
#define PS_NEW_STATEMENT(st) \
    ((st).pipe_dd = (st).saw_pipe = (st).open_writer = (st).open_anc = (st).st_del = (st).st_base = \
         (st).st_name = (st).st_web = (st).st_meth = (st).pipe_hit = (st).open_eval = false, \
     (st).pend_var[0] = '\0')

/* End the current segment: scan its words, then drop them. */
static void ps_end_seg(struct psseg *s)
{
    bool names = false, fed = s->open_writer, cmd = false, hit, sb_here = false;
    char *val;
    char pend[sizeof s->pend_var];
    memcpy(pend, s->pend_var, sizeof pend);
    s->pend_var[0] = '\0';
    for (int i = 0; i < s->n; i++)
        if (ci_has(s->w[i], "scriptblock]::create")) sb_here = true;
    ps_assign(s);          /* `$d = expr` records d and consumes its words */
    ps_expand_words(s);    /* known variables are replaced by their value */
    if (s->open_eval && !sb_here && s->n > 0) {
        /* the literal argument of [scriptblock]::Create is code: scan it, or give up when it is
         * computed */
        for (int i = 0; i < s->n; i++)
            ps_note(s, s->w[i][0] == '$' ? R_COMPLEX
                                         : ps_eval(s->w[i], strlen(s->w[i]), s->depth + 1));
        s->open_eval = false;
    }
    if (sb_here) s->open_eval = true;
    hit = ps_lister_hit(s);
    if (pend[0] && s->n > 0) {
        /* the expression of a `$d =` that ended the previous segment */
        val = ps_value(s->w, s->n, 0, NULL, &cmd);
        if (val) {
            var_set(pend, strlen(pend), val);
            free(val);
        }
    } else if (pend[0] && !s->pend_var[0]) {
        memcpy(s->pend_var, pend, sizeof pend); /* an empty segment: keep waiting */
    }
    for (int i = 0; i < s->n; i++)
        if (mentions_datadir(s->w[i])) names = true;
    /* the value of a Join-Path or `a + b` segment names a datadir though no word does */
    val = s->n > 0 ? ps_value(s->w, s->n, 0, NULL, &cmd) : NULL;
    if (val) {
        if (mentions_datadir(val)) names = true;
        if (fed && s->open_anc && !cmd) { /* [IO.Directory]::Delete("<ancestor of a datadir>") */
            struct gseg zero;
            struct cmdv cv;
            memset(&zero, 0, sizeof zero);
            cv = (struct cmdv){NULL, &zero, "", NULL, 0, NULL, 0, s->depth, false, s->cwd, NULL};
            ps_note(s, tgt(&cv, val, true));
        }
        free(val);
    }
    if (fed && s->open_anc && !s->r) { /* the arguments of a .NET call: a, b, c */
        struct gseg zero;
        struct cmdv cv;
        memset(&zero, 0, sizeof zero);
        cv = (struct cmdv){NULL, &zero, "", NULL, 0, NULL, 0, s->depth, false, s->cwd, NULL};
        for (int i = 0; i < s->n; i++) {
            char *cp = strdup(s->w[i]); // raw-alloc-ok:build-tool
            if (!cp) {
                g_complex = true;
                break;
            }
            for (char *t = strtok(cp, ","); t; t = strtok(NULL, ","))
                if (t[0] != '$' || strncasecmp(t, "$env:", 5) == 0 || strncasecmp(t, "$home", 5) == 0)
                    ps_note(s, tgt(&cv, t, true));
            free(cp);
        }
    }
    if (s->n > 0) ps_note_facts(s);
    if (!s->r) ps_note(s, ps_seg(s));
    if ((names || hit) && fed) ps_note(s, R_DATADIR);
    if (names) s->pipe_dd = true;
    if (hit) s->pipe_hit = true;
    for (int i = 0; i < s->n; i++) free(s->w[i]);
    s->n = 0;
    s->pend_redir = false;
}

/* End the current word (text in buf[0..n), quoted: it was quoted so may be empty). */
static void ps_end_word(struct psseg *s, char *buf, size_t *n, bool *quoted)
{
    char *wd;
    if (*n == 0 && !*quoted) return;
    buf[*n] = '\0';
    wd = strdup(buf); // raw-alloc-ok:build-tool
    *n = 0;
    *quoted = false;
    if (!wd) {
        g_complex = true;
        return;
    }
    if (s->pend_redir) {
        if (!s->r) {
            char *ex = ps_expand(wd);
            const char *r = path_rule_cwd(s->cwd, ex ? ex : wd);
            free(ex);
            if (!r && is_py_name(wd)) r = R_PYTHON;
            ps_note(s, r);
        }
        s->pend_redir = false;
        free(wd);
        return;
    }
    ps_push(s, wd);
}

/* The word names zclassic-cli or zcash-cli (any folder, any case, with or without .exe). */
static bool ps_client_word(const char *w)
{
    const char *name = w;
    char low[24];
    size_t n;
    for (const char *p = w; *p; p++)
        if (*p == '/' || *p == '\\') name = p + 1;
    n = strlen(name);
    if (n >= sizeof low) return false;
    for (size_t k = 0; k <= n; k++) low[k] = (char)tolower((unsigned char)name[k]);
    strip_exe(low);
    return is_client_name(low);
}

/* A $( ) subexpression starting at s[i] == '$': its body scans as commands; returns the index
 * past the closing parenthesis. */
static size_t ps_subexpr(struct psseg *st, const char *s, size_t len, size_t i)
{
    size_t j = i + 2;
    int depth = 1;
    while (j < len && depth > 0) {
        if (s[j] == '(') depth++;
        else if (s[j] == ')') depth--;
        j++;
    }
    if (!st->r)
        ps_note(st, ps_eval(s + i + 2, (j > i + 2 ? j - 1 : j) - (i + 2), st->depth + 1));
    return j;
}

static const char *ps_eval(const char *s, size_t len, int depth)
{
    struct psseg st;
    char *buf;
    size_t n = 0, i = 0;
    bool quoted = false;
    if (depth > MAX_NEST) {
        g_complex = true;
        return NULL;
    }
    memset(&st, 0, sizeof st);
    st.depth = depth;
    buf = malloc(len + 1); // raw-alloc-ok:build-tool
    if (!buf) {
        g_complex = true;
        return NULL;
    }
    while (i < len) {
        char ch = s[i];
        if (ch == ' ' || ch == '\t' || ch == '\r') {
            ps_end_word(&st, buf, &n, &quoted);
            i++;
        } else if (ch == '#' && n == 0 && !quoted) {
            while (i < len && s[i] != '\n') i++;
        } else if (ch == '\'') {
            quoted = true;
            for (i++; i < len; i++) {
                if (s[i] == '\'' && i + 1 < len && s[i + 1] == '\'') i++;
                else if (s[i] == '\'') break;
                buf[n++] = s[i];
            }
            i++;
        } else if (ch == '"') {
            quoted = true;
            for (i++; i < len && s[i] != '"'; i++) {
                if (s[i] == '`' && i + 1 < len) {
                    buf[n++] = s[++i];
                } else if (s[i] == '$' && i + 1 < len && s[i + 1] == '(') {
                    size_t e = ps_subexpr(&st, s, len, i);
                    while (i < e && i < len) buf[n++] = s[i++];
                    i--;
                } else {
                    buf[n++] = s[i];
                }
            }
            i++;
        } else if (ch == '`' && i + 1 < len) {
            buf[n++] = s[i + 1];
            quoted = true;
            i += 2;
        } else if (ch == '$' && i + 1 < len && s[i + 1] == '(') { /* $( ) stays in the word */
            size_t e = ps_subexpr(&st, s, len, i);
            while (i < e && i < len) buf[n++] = s[i++];
        } else if (ch == '$' && i + 1 < len && s[i + 1] == '{') {
            while (i < len && s[i] != '}') buf[n++] = s[i++];
            if (i < len) buf[n++] = s[i++];
        } else if (ch == '>') {
            if (n > 0 && strspn(buf, "0123456789") == n && !quoted) n = 0; /* 2> */
            ps_end_word(&st, buf, &n, &quoted);
            while (i < len && s[i] == '>') i++;
            if (i < len && s[i] == '&') { /* 2>&1: no file */
                i++;
                while (i < len && isdigit((unsigned char)s[i])) i++;
            } else {
                st.pend_redir = true;
            }
        } else if (strchr(";|&\n(){}", ch)) {
            ps_end_word(&st, buf, &n, &quoted);
            if (ch == '(' && st.n > 0 && ps_client_word(st.w[0])) {
                /* zclassic-cli ('dump' + 'privkey'): the method is an expression, so it is hidden */
                char *mark = strdup("$(expression)"); // raw-alloc-ok:build-tool
                if (mark) ps_push(&st, mark);
                else g_complex = true;
            }
            if (!(ch == '&' && st.n == 0)) { /* a leading & is the call operator */
                ps_end_seg(&st);
                if (ch == '|' && i + 1 < len && s[i + 1] == '|') {
                    i++; /* || chains, no pipe */
                    st.pipe_dd = st.pipe_hit = st.saw_pipe = st.open_writer = st.open_anc = false;
                } else if (ch == '|') {
                    st.saw_pipe = true;
                }
                else if (ch != '(' && ch != ')' && ch != '{' && ch != '}')
                    PS_NEW_STATEMENT(st); /* ; newline & end the statement */
            }
            i++;
        } else {
            buf[n++] = ch;
            i++;
        }
    }
    ps_end_word(&st, buf, &n, &quoted);
    ps_end_seg(&st);
    free(st.w);
    free(buf);
    return st.r ? st.r : st.warn;
}

const char *ag_eval_ps(const char *cmd)
{
    g_complex = false;
    g_nvars = 0;
    g_xargs = false;
    g_xrepl[0] = '\0';
    g_loopvar[0] = '\0';
    g_regtest_hint = regtest_word_in(cmd);
    return finish(ps_eval(cmd, strlen(cmd), 0));
}

const char *ag_eval_path(const char *tool, const char *path, const char *content)
{
    const char *r, *warn = NULL;
    if (!path) return NULL;
    r = path_rule(path);
    if (r && !ag_rule_is_warning(r)) return r;
    warn = r; /* a warning must not hide a refusal below */
    if (is_py_name(path)) return R_PYTHON;
    if (content && strcmp(tool, "Write") == 0 && strncmp(content, "#!", 2) == 0) {
        size_t eol = strcspn(content, "\n");
        for (size_t i = 0; i + 6 <= eol; i++)
            if (memcmp(content + i, "python", 6) == 0) return R_PYTHON;
    }
    if (warn) return warn;
    return is_sealed_path(path) ? R_SEAL : NULL;
}

bool ag_rule_is_warning(const char *rule)
{
    return rule && (strcmp(rule, R_SEAL) == 0 || strcmp(rule, R_SELF) == 0);
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
        {R_SELF, "This is the agent guard or its hook entry: editing or deleting it can switch the "
                 "guard off without a notice, so confirm the change is intended"},
        {R_COMPLEX, "The command is too large, too deeply nested or encoded to check, and an "
                    "unchecked tail could hide a refused action: split it into smaller "
                    "commands"},
        {R_SEAL, "This file is in the sealed consensus set. Consensus does not change; a "
                 "reviewed unseal is the only way (doc/agent/UNSEAL.md)"},
    };
    for (size_t i = 0; rule && i < sizeof table / sizeof table[0]; i++)
        if (strcmp(table[i].rule, rule) == 0) return table[i].why;
    return "refused";
}
