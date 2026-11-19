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
 * heredoc piped into sh, bash, dash, zsh, ksh, mksh, fish, powershell - (or read through <( ) or source) is scanned as commands (printf and echo -e escapes decoded); any other producer feeding a
 * shell's stdin is guard.too_complex. Spend and key-export names count only in the method position
 * (first word after the RPC client, or a JSON-RPC "method" value in a request body).
 *
 * Options of zclassicd and zclassic-cli are read the way ParseParameters reads them: up to the
 * first word that is not an option, the last value wins, -noX is X=0 (see parse_opts).
 *
 * Known limits (not closed, one per line; README.md lists more, and says why none is a boundary):
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
 *   ls -a ~ | grep zcl | xargs rm        a producer filtered by grep, sed or awk is not read
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
#include "rules_int.h"

#define MAX_NEST 8
#define MAX_WORDS 32768
#define MAX_SEGS 8192
#define MAX_REDIR 4096
#define MAX_SUBS 2048
#define MAX_HD 4

/* Set when any cap or depth limit drops input: the verdict is then guard.too_complex, never
 * allow (a guard that skips the tail of a long command fails open). */
static bool g_complex;

/* Name of the variable of a `for VAR in <datadir>` loop seen earlier in the command, else "". */
static char g_loopvar[48];

/* `NAME=value` assignments seen earlier in the same command (Bash tool calls share no shell
 * state, so a variable can only come from the command itself). Values are stored expanded. */
#define MAX_VARS 512
#define VAR_VAL 512
static struct {
    char name[40];
    char val[VAR_VAL];
} g_vars[MAX_VARS];
static int g_nvars;

#define MAX_HS 8
#define CWD_CAP 512

/* The working directory the hook reports for the call ("" when unknown): where a top-level
 * command starts. */
static char g_hook_cwd[CWD_CAP];

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
    struct {
        int seg; /* the segment the <( ) is an operand of; -1 when that segment is empty */
        size_t off, len;
    } psub[MAX_SUBS]; /* process substitutions <( ) */
    int npsub;
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
        int before = t->c->nsegs;
        tk_end_seg(t);
        if (ch == '<') {
            struct gctx *c = t->c;
            size_t e = skip_paren(t->s, t->len, t->i + 2, 0);
            size_t end = e > t->i + 2 && t->s[e - 1] == ')' ? e - 1 : e;
            if (c->npsub >= MAX_SUBS) {
                g_complex = true;
            } else {
                c->psub[c->npsub].seg = c->nsegs > before ? before : -1;
                c->psub[c->npsub].off = t->i + 2;
                c->psub[c->npsub].len = end > t->i + 2 ? end - (t->i + 2) : 0;
                c->npsub++;
            }
        }
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
        if (strncmp(w, names[i], strlen(names[i])) == 0) return ag_agent_identity(w + strlen(names[i]));
    if (strncmp(w, "GIT_CONFIG_PARAMETERS=", 22) == 0)
        return mentions_identity_key(w + 22) && ag_agent_identity(w + 22);
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
    {"env", " -u -C -P ", 0},
    {"builtin", " ", 0},
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
    /* Win32 ignores trailing dots on a name: Zclassic. is Zclassic (a name of dots only is kept) */
    while (*n > 1 && p[*n - 1] == '.' && p[*n - 2] != '.') (*n)--;
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

/* The scan state of mentions_datadir: the components seen since the last path start (pre), and
 * whether an AppData folder (or macOS Application Support) came before. */
struct ddscan {
    const char *pre[16];
    size_t prl[16];
    int np;
    bool appdata;
    int mac; /* 1 after Library, 2 after Application, then Support sets appdata */
};

/* A separator that starts a new word or option value (= , space, quote, paren) starts a new path:
 * of=$HOME/.zclassic, "$(echo ~/.zclassic)". A ")/" is a computed base: $(mktemp -d)/.zclassic. */
static void dd_gap(struct ddscan *d, const char *g, const char *end)
{
    for (; g < end; g++) {
        if (strchr("= ,\t\n\"'()`;|&<>", *g)) d->np = 0;
        if (g[0] == ')' && g[1] == '/') {
            d->pre[0] = ")";
            d->prl[0] = 1;
            d->np = 1;
        }
    }
}

/* .zclassic* or .zcash-params in a place where the node keeps them (see rules_home.c). */
static bool dd_dotname(const struct ddscan *d, const char *p, size_t n)
{
    if (!comp_starts_ci(p, n, ".zclassic") && !comp_starts_ci(p, n, ".zcash-params")) return false;
    return d->np > 16 || ag_dd_name_in_home(d->pre, d->prl, d->np);
}

/* Zclassic or ZcashParams below AppData, and the Windows 8.3 short names ZCLASS~1, ZCASHP~1. */
static bool dd_appname(const struct ddscan *d, const char *p, size_t n)
{
    if (!d->appdata) return false;
    if (comp_is_ci(p, n, "zclassic") || comp_is_ci(p, n, "zcashparams")) return true;
    return n == 8 && (comp_starts_ci(p, n, "zclass~") || comp_starts_ci(p, n, "zcashp~")) &&
           isdigit((unsigned char)p[7]);
}

static void dd_track(struct ddscan *d, const char *p, size_t n)
{
    if (comp_is_appdata(p, n)) d->appdata = true;
    if (d->mac == 2 && comp_is_ci(p, n, "support")) d->appdata = true;
    d->mac = comp_is_ci(p, n, "library")                         ? 1
             : (d->mac == 1 && comp_is_ci(p, n, "application")) ? 2
                                                                 : 0;
    if (d->np < 16) {
        d->pre[d->np] = p;
        d->prl[d->np] = n;
    }
    d->np++;
}

/* ~/.zclassic*, ~/.zcash-params, %APPDATA%/Zclassic or %APPDATA%/ZcashParams, and on macOS
 * ~/Library/Application Support/Zclassic or .../ZcashParams (the path words split at the space,
 * so the two-word name is three components). The dot-names count only in a home position
 * (ag_dd_name_in_home): /tmp/zt/.zclassic and $D/.zclassic are test copies. */
static bool mentions_datadir(const char *w)
{
    struct ddscan d;
    const char *p = w, *prev_end = w;
    size_t n = 0;
    memset(&d, 0, sizeof d);
    while (next_comp(&p, &n)) {
        dd_gap(&d, prev_end, p);
        if (dd_dotname(&d, p, n) || dd_appname(&d, p, n)) return true;
        dd_track(&d, p, n);
        p += n;
        prev_end = p;
    }
    return false;
}

static bool is_vendor_path(const char *w)
{
    return ag_path_has(w, "zcutil/tools/vendor", true) || ag_path_has(w, "src/c23/vendor", true) ||
           ag_path_has(w, "src/c23/services/vendor", true);
}

static bool is_workflow_path(const char *w)
{
    return ag_path_has(w, ".github/workflows", true);
}

/* The sealed consensus set (zcutil/consensus.seal): edits warn, they do not refuse. */
static bool is_sealed_path(const char *w)
{
    static const char *const dirs[] = {"src/consensus", "src/primitives", "src/pow"};
    static const char *const files[] = {
        "src/pow.cpp", "src/pow.h", "src/script/interpreter.cpp", "src/script/interpreter.h",
        "src/script/script.cpp", "src/script/script.h", "src/chainparams.cpp",
        "src/zcash/JoinSplit.cpp", "src/zcash/JoinSplit.hpp", "src/zcash/Note.cpp",
        "src/zcash/Note.hpp", "src/zcash/NoteEncryption.cpp", "src/zcash/NoteEncryption.hpp",
        "src/zcash/Proof.cpp", "src/zcash/Proof.hpp", "src/zcash/Address.cpp",
        "src/zcash/Address.hpp", "src/zcash/IncrementalMerkleTree.cpp",
        "src/zcash/IncrementalMerkleTree.hpp"};
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        if (ag_path_has(w, dirs[i], true))
            return strcmp(dirs[i], "src/pow") != 0 || !ag_path_has(w, "src/pow/tromp", true);
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++)
        if (ag_path_has(w, files[i], false)) return true;
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
    char buf[1024];
    size_t n = strlen(w);
    if (n >= sizeof buf) return ends_ci(w, ".py") || ends_ci(w, ".pyw") || ends_ci(w, ".pyi");
    memcpy(buf, w, n + 1);
    /* Win32 drops trailing dots and spaces from a name and ignores a ::$DATA stream suffix */
    if (n > 7 && strcasecmp(buf + n - 7, "::$DATA") == 0) buf[n -= 7] = 0;
    while (n > 1 && (buf[n - 1] == '.' || buf[n - 1] == ' ')) buf[--n] = 0;
    return ends_ci(buf, ".py") || ends_ci(buf, ".pyw") || ends_ci(buf, ".pyi");
}

/* The guard's own switches: the hook settings, the hook entry and the binaries. A
 * change there can switch the guard off without a notice, so it asks first. Its sources are an
 * ordinary tree: they only take effect when the binary is rebuilt. */
static bool is_guard_path(const char *w)
{
    static const char *const files[] = {
        ".claude/settings.json", ".claude/settings.local.json", "zcutil/bin/zcl-agent-guard",
        "zcutil/bin/zcl-agent-guard.exe", "zcutil/bin/zcl-agent-guard-selftest",
        "zcutil/bin/zcl-agent-guard-selftest.exe", "zcutil/agent/guard/zcl-agent-guard.sh", "zcutil/agent/guard"};
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++)
        if (ag_path_has(w, files[i], false)) return true;
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
    if (f->n >= MAX_COMPS) /* deeper than any datadir place: a long word, not a path to judge */
        return false;
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
    return has_glob(pc) ? ag_glob_match(pc, tc) : strcmp(pc, tc) == 0;
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

/* A component that is the scratch word itself or the word with a separator or digit after it:
 * tmp, tmp.Ab12 (mktemp), tmp-1, temp2; not tmpfoo or template. */
static bool comp_scratch(const char *c, size_t n, const char *word)
{
    size_t m = strlen(word);
    return comp_starts_ci(c, n, word) && (n == m || strchr(".-_0123456789", c[m]) != NULL);
}

/* A -datadir value that is a throwaway test directory: under a temp location, a test*, tmp*
 * or mktemp name. An unresolved variable is not one (it may hold a node datadir), and neither
 * is an empty value. Never a node datadir. */
static bool is_test_dir(const char *v)
{
    const char *p = v;
    size_t n = 0;
    if (mentions_datadir(v) || !v[0]) return false;
    if (ag_starts_tmpvar(v) || strncmp(v, "$(mktemp", 8) == 0 || strncmp(v, "`mktemp", 7) == 0)
        return true;
    while (next_comp(&p, &n)) {
        if (comp_scratch(p, n, "tmp") || comp_scratch(p, n, "temp") ||
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

/* python, pythonw, python3.12, pip, pip3, pipx, py (the Windows launcher), and the other
 * interpreters pypy, pypy3, graalpy, jython; any letter case, because command lookup on Windows
 * (Git Bash) ignores case and Python3.exe is python3.exe. */
static bool is_python_cmd(const char *cmd)
{
    static const char *const stems[] = {"python", "pip", "pypy", "graalpy", "jython"};
    if (strcasecmp(cmd, "pipx") == 0 || strcasecmp(cmd, "py") == 0 || strcasecmp(cmd, "pyw") == 0)
        return true;
    for (size_t i = 0; i < sizeof stems / sizeof stems[0]; i++) {
        size_t n = strlen(stems[i]);
        const char *rest;
        if (strncasecmp(cmd, stems[i], n) != 0) continue;
        rest = cmd + n;
        if (strcasecmp(rest, "w") == 0) return true; /* pythonw */
        if (strspn(rest, "0123456789.") == strlen(rest)) return true;
    }
    return false;
}

/* `python3 --version` and `-V`: asking whether an interpreter exists runs no Python code. */
static bool version_probe(const char *first, const struct cmdv *v)
{
    return is_python_cmd(first) && v->na == 1 &&
           (strcmp(v->a[0], "--version") == 0 || strcmp(v->a[0], "-V") == 0);
}

/* python, pipx, pip, uv run/pip/tool, and an executed *.py file. */
static const char *check_python(const struct cmdv *v)
{
    static const char *const tools[] = {"ipython", "ipython3", "pytest", "py.test", "jupyter",
                                        "jupyter-lab", "jupyter-notebook", "uvx"};
    static const char *const runners[] = {"conda", "mamba", "micromamba", "poetry", "pipenv",
                                          "pdm", "hatch", "rye"};
    char first[48];
    size_t n = strcspn(v->cmd, " \t");
    /* env -S "python3 -c 1" leaves the whole string as the command word */
    snprintf(first, sizeof first, "%.*s", (int)(n < sizeof first ? n : sizeof first - 1), v->cmd);
    if (version_probe(first, v)) return NULL;
    if (is_python_cmd(first) || is_py_name(first)) return R_PYTHON;
    if (IN_LIST(first, tools)) return R_PYTHON;
    if (IN_LIST(first, runners))
        for (int i = 0; i < v->na; i++)
            if (is_python_cmd(base_name(v->a[i])) || is_py_name(v->a[i])) return R_PYTHON;
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
    if (k[n] == '=' && !ag_agent_identity(k + n + 1)) return false; /* an owner or person override */
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
    return unset || (np > k + 1 && ag_agent_identity(pos[k + 1]));
}

/* git config that writes a key with a side effect on identity or pushes: remote.<n>.push and
 * remote.<n>.mirror set the refspec a bare push uses, and an alias whose text sets an identity
 * key runs it later. Returns the rule id or NULL. */
static const char *config_sets_hazard(char **a, int na, int depth)
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
    if (strncmp(key, "alias.", 6) == 0 && pos[k + 1][0] == '!') /* a shell alias runs as a command */
        return eval_buf(pos[k + 1] + 1, strlen(pos[k + 1] + 1), depth + 1);
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

/* Set when a `git init` ran earlier in the command: the repository is a fresh one, a test fixture,
 * not the owner's. */
static bool g_git_init;

/* The git call works in a scratch repository: after a `git init` in the same command, with -C
 * <test directory>, or with the working directory in a test location. Setting an identity there
 * (git config user.name t) is how test fixtures commit; the rule is about the owner's repository. */
static bool git_in_scratch(const struct cmdv *v, int si)
{
    if (g_git_init) return true;
    if (v->cwd && v->cwd[0] && is_test_dir(v->cwd)) return true;
    for (int i = 0; i + 1 < (si < 0 ? v->na : si); i++)
        if (strcmp(v->a[i], "-C") == 0 && is_test_dir(v->a[i + 1])) return true;
    return false;
}

/* The value of a --author option at v->a[i] (glued, or the next word); NULL for any other word. */
static const char *author_value(const struct cmdv *v, int i)
{
    if (strncmp(v->a[i], "--author=", 9) == 0) return v->a[i] + 9;
    if (strcmp(v->a[i], "--author") == 0) return i + 1 < v->na ? v->a[i + 1] : "";
    return NULL;
}

/* The identity rule: -c user.name=..., `git config user.*` and `git commit --author`, except in a
 * scratch repository. bad is set by git_subcommand for a -c identity override. */
static const char *git_identity_rule(const struct cmdv *v, int si, bool bad)
{
    const char *sub;
    if (git_in_scratch(v, si)) return NULL;
    if (bad) return R_IDENT;
    if (si < 0) return NULL;
    sub = v->a[si];
    if (strcmp(sub, "config") == 0 && config_sets_identity(v->a + si + 1, v->na - si - 1))
        return R_IDENT;
    if (strcmp(sub, "commit") != 0) return NULL;
    for (int i = si + 1; i < v->na; i++) {
        const char *av = author_value(v, i);
        if (av && ag_agent_identity(av)) return R_IDENT;
    }
    return NULL;
}

/* git -c alias.x='!cmd' x: the alias body is a command line. */
static const char *git_alias_rule(const struct cmdv *v, int si)
{
    for (int i = 0; i + 1 < (si < 0 ? v->na : si); i++) {
        const char *kv = v->a[i + 1], *eq = strchr(kv, '=');
        if (strcmp(v->a[i], "-c") == 0 && strncasecmp(kv, "alias.", 6) == 0 && eq && eq[1] == '!') {
            const char *r = eval_buf(eq + 2, strlen(eq + 2), v->depth + 1);
            if (r) return r;
        }
    }
    return NULL;
}

static const char *check_git(const struct cmdv *v)
{
    bool bad = false;
    int si;
    const char *sub, *r;
    if (strcmp(v->cmd, "git") != 0) return NULL;
    si = git_subcommand(v->a, v->na, &bad);
    r = git_identity_rule(v, si, bad);
    if (!r) r = git_alias_rule(v, si);
    if (r || si < 0) return r;
    sub = v->a[si];
    if (strcmp(sub, "init") == 0) g_git_init = true;
    if (strcmp(sub, "push") == 0 || strcmp(sub, "send-pack") == 0)
        return ag_push_rule(v->a + si + 1, v->na - si - 1, v->cwd[0] ? v->cwd : g_hook_cwd);
    if (strcmp(sub, "config") == 0)
        return config_sets_hazard(v->a + si + 1, v->na - si - 1, v->depth);
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

static bool g_regtest_hint; /* set by ag_eval_bash and ag_eval_ps: the text carries -regtest */

/* A request that carries a spend or export method is a test call when -regtest is explicit or a
 * word names a numeric non-production port (the regtest node listens on 18023). */
static bool http_is_test(char **w, int n)
{
    if (g_regtest_hint) return true;
    for (int i = 0; i < n; i++) {
        long port = ag_word_port(w[i]);
        if (port > 0 && !ag_prod_port(port)) return true;
    }
    return false;
}

static const char *check_http(const struct cmdv *v)
{
    if (http_is_test(v->a, v->na)) return NULL;
    for (int i = 0; i < v->na; i++) {
        const char *b = ag_body_arg(v->a, v->na, i);
        if (b && strcmp(b, "@-") == 0 && v->ch && v->sg->pipe_in && v->ch->prod_lit &&
            v->ch->prod && ag_payload_has_method(v->ch->prod))
            return R_SPEND; /* echo '{"method":...}' | curl -d @- */
        if (b && ag_payload_has_method(b)) return R_SPEND;
    }
    if (v->sg->hd_has && ag_body_has_method(v->c->src + v->sg->hd_off, v->sg->hd_len))
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

/* An option value that is, or may be, a real node's: written without a value, empty, or naming
 * a datadir place. Anything else (a variable, a path, a test directory) is the caller's own. */
static bool opt_dir_real(const struct cmdv *v, const char *name)
{
    for (int pass = 0; pass < 2; pass++) {
        struct popts p;
        parse_opts(v, pass == 1, &p);
        for (int i = 0; i < p.n; i++)
            if (strcmp(p.o[i].name, name) == 0 &&
                (!p.o[i].eq || !p.o[i].val[0] || mentions_datadir(p.o[i].val)))
                return true;
    }
    return false;
}

/* The RPC client reaches a test node when -regtest is in effect (it then uses the regtest RPC
 * port and the regtest wallet, bitcoin-cli.cpp), no -datadir or -conf names a real node's place,
 * and no -rpcport or -rpcconnect points back at a production node. A -datadir held in a variable
 * is the script's own (the usual `-regtest -datadir="$dd"` of the qa scripts); with no -datadir at
 * all the client reads the default conf, which a real node rarely gives an rpcport. This is a
 * guard against mistakes: the one thing it must catch is a send or key export with no -regtest. */
static bool rpc_is_test_client(const struct cmdv *v)
{
    if (!is_regtest(v)) return false;
    if (opt_dir_real(v, "-datadir") || opt_dir_real(v, "-conf")) return false;
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
                    strcmp(h, "::1") != 0 && !is_unresolved(h))
                    return false;
            }
        }
    }
    return true;
}


/* The command line carries a -regtest word (not in a comment, not inside a longer path): a
 * client held in a variable (C="zclassic-cli -regtest ..."; $C z_sendmany) is then a regtest
 * client. Set by ag_eval_bash. */

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
    if (strcmp(w, "$@") == 0 || strcmp(w, "$*") == 0) return false; /* a wrapper function's passthrough */
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
    if ((i >= 0 && !ag_is_method(v->a[i], strlen(v->a[i]))) ||
        (j >= 0 && !ag_is_method(v->a[j], strlen(v->a[j])))) {
        /* a word is there; it is only a problem when it hides the method */
        if (is_client_name(v->cmd) &&
            ((i >= 0 && method_word_opaque(v->a[i])) || (j >= 0 && method_word_opaque(v->a[j]))))
            hidden = true;
    }
    if (is_client_name(v->cmd) && i < 0 && j < 0 && !info_only(v) &&
        (g_xargs || stdin_effective(v)))
        hidden = true;
    if (!hidden && (i < 0 || !ag_is_method(v->a[i], strlen(v->a[i]))) &&
        (j < 0 || !ag_is_method(v->a[j], strlen(v->a[j]))))
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
    /* -regtest keeps its files in <datadir>/regtest: any datadir that is not a node place is fine */
    if (dd == DD_REAL) return is_regtest(v) && !opt_dir_real(v, "-datadir") ? NULL : R_DATADIR;
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

/* perl and ruby option words that ask for an in-place edit: -i, -pi, -i.bak, -0pi. */
static bool script_inplace(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (a[0] != '-' || a[1] == '-' || !a[1]) continue;
        for (const char *c = a + 1; *c; c++) {
            if (*c == 'i') return true;
            if (strchr("MImeE", *c)) break; /* the rest of the word is that option's value */
        }
    }
    return false;
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
        if (IN_LIST(v->a[i], execs) && i + 1 < v->na) { /* -exec sed -i, -exec patch */
            const char *w = base_name(v->a[i + 1]);
            if (strcmp(w, "patch") == 0) return true;
            if (strcmp(w, "sed") == 0)
                for (int k = i + 2; k < v->na; k++)
                    if (strncmp(v->a[k], "--in-place", 10) == 0 || short_group_has(v->a[k], 'i'))
                        return true;
        }
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

/* sed -i, perl -pi -e, perl -i.bak, ruby -i: an in-place edit of the file operands. */
static bool inplace_edit(const struct cmdv *v)
{
    if (strcmp(v->cmd, "sed") == 0) return sed_inplace(v);
    return (strcmp(v->cmd, "perl") == 0 || strcmp(v->cmd, "ruby") == 0) && script_inplace(v);
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
    if (inplace_edit(v)) return W_SED;
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
        if (strncmp(q, g_loopvar, n) == 0 && !ag_is_word_char(q[n])) return true;
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
        while (j < len && ag_is_word_char(s[j])) j++;
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

/* Scan text as shell commands, or as PowerShell when ps. */
static const char *eval_text(bool ps, const char *s, size_t len, int depth)
{
    return ps ? ps_eval(s, len, depth) : eval_buf(s, len, depth);
}

static const char *eval_here_as(const struct cmdv *v, bool ps)
{
    if (!v->sg->hd_has) return NULL;
    return eval_text(ps, v->c->src + v->sg->hd_off, v->sg->hd_len, v->depth + 1);
}

static const char *eval_here(const struct cmdv *v)
{
    return eval_here_as(v, false);
}

static bool is_shell_name(const char *cmd)
{
    static const char *const shells[] = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "ash"};
    return IN_LIST(cmd, shells);
}

/* A shell -c string that holds the replace string of an `xargs -I` that precedes it
 * (echo 'rm -rf ~/.zclassic' | xargs -I{} sh -c '{}'): the literal producer text is
 * substituted, one line at a time, and scanned. */
static const char *xargs_subst(const struct cmdv *v, const char *cmdstr)
{
    const char *r = NULL, *line;
    size_t rl = strlen(g_xrepl);
    if (!g_xargs || !rl || !strstr(cmdstr, g_xrepl) || !v->ch || !v->ch->prod_lit || !v->ch->prod)
        return NULL;
    line = v->ch->prod;
    while (!r && *line) {
        size_t n = strcspn(line, "\n");
        struct sbuf b = {NULL, 0, 0};
        if (n) {
            for (const char *p = cmdstr; *p;) {
                if (strncmp(p, g_xrepl, rl) == 0) {
                    sb_add(&b, line, n);
                    p += rl;
                } else {
                    sb_add(&b, p++, 1);
                }
            }
            if (b.p) r = eval_buf(b.p, b.n, v->depth + 1);
            else g_complex = true;
            free(b.p);
        }
        line += n + (line[n] ? 1 : 0);
    }
    return r;
}

/* sh/bash: scan the -c string. *script is set when stdin is the script
 * (no -c), so a heredoc body is scanned as commands. */
static const char *nested_shell(const struct cmdv *v, bool *script)
{
    *script = true;
    for (int i = 0; i < v->na && v->a[i][0] == '-'; i++) {
        if (short_group_has(v->a[i], 'c') && i + 1 < v->na) {
            const char *r = xargs_subst(v, v->a[i + 1]);
            *script = false;
            return r ? r : eval_buf(v->a[i + 1], strlen(v->a[i + 1]), v->depth + 1);
        }
        if (strcmp(v->a[i], "-o") == 0 || strcmp(v->a[i], "+o") == 0) i++;
    }
    return NULL;
}

static char *literal_output(const struct gctx *c, int si, char **w, int n);

/* A shell that reads its script from <( ... ): the producer is scanned when it is a literal
 * echo, printf or heredoc cat, and is too complex otherwise (bash <(curl URL)). */
static const char *procsub_scripts(const struct cmdv *v)
{
    const struct gctx *c = v->c;
    const char *r = NULL;
    int si;
    if (!c || v->sg < c->segs || v->sg >= c->segs + c->nsegs) return NULL;
    si = (int)(v->sg - c->segs);
    for (int k = 0; !r && k < c->npsub; k++) {
        struct gctx *c2;
        char *text = NULL;
        if (c->psub[k].seg != si) continue;
        c2 = calloc(1, sizeof *c2); // raw-alloc-ok:build-tool
        if (!c2) {
            g_complex = true;
            return R_COMPLEX;
        }
        c2->arena = malloc(c->psub[k].len * 2 + 16); // raw-alloc-ok:build-tool
        if (!c2->arena) {
            free(c2);
            g_complex = true;
            return R_COMPLEX;
        }
        c2->src = c->src + c->psub[k].off;
        tokenize(c2, c2->src, c->psub[k].len);
        if (c2->nsegs == 1 && c2->nsubs == 0 && c2->npsub == 0)
            text = literal_output(c2, 0, c2->words, c2->nwords);
        r = text ? eval_buf(text, strlen(text), v->depth + 1) : R_COMPLEX;
        free(text);
        free(c2->arena);
        free(c2);
    }
    return r;
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
    i++; /* the destination */
    /* `ssh host -- cmd`: a `--` after the destination ends ssh's options; the rest is the remote
     * command, scanned exactly like the form without it */
    if (i < v->na && strcmp(v->a[i], "--") == 0) i++;
    *script = i >= v->na;
    if (i >= v->na) return NULL;
    *script = is_shell_name(base_name(v->a[i]));
    return eval_joined(v, i);
}

/* sh/bash read their script from stdin when there is no -c and no script file operand, or with
 * -s (`bash -s args`) or a lone `-`. source and . read it from /dev/stdin or `-`. */
static bool shell_stdin_is_script(const struct cmdv *v)
{
    bool s_flag = false;
    int i = 0;
    if (strcmp(v->cmd, "source") == 0 || strcmp(v->cmd, ".") == 0)
        return v->na == 0 || strcmp(v->a[0], "/dev/stdin") == 0 ||
               strcmp(v->a[0], "/dev/fd/0") == 0 || strcmp(v->a[0], "-") == 0;
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
 * check_opts: false for ssh and PowerShell, where the options are not shell options.
 * ps: the script is PowerShell. */
static const char *shell_stdin_text(const struct cmdv *v, bool check_opts, bool ps)
{
    const struct gctx *c = v->c;
    const char *r = NULL;
    int si;
    if (!c || v->sg < c->segs || v->sg >= c->segs + c->nsegs) return NULL;
    si = (int)(v->sg - c->segs);
    for (int k = 0; !r && k < c->nhs; k++)
        if (c->hstr_seg[k] == si) r = eval_text(ps, c->hstr[k], strlen(c->hstr[k]), v->depth + 1);
    if (r) return r;
    if (!v->sg->pipe_in || v->sg->hd_has || !v->ch) return NULL;
    if (check_opts && !shell_stdin_is_script(v)) return NULL;
    if (!v->ch->prod_lit) return R_COMPLEX;
    return v->ch->prod ? eval_text(ps, v->ch->prod, strlen(v->ch->prod), v->depth + 1) : NULL;
}

/* powershell reads its script from stdin with no command at all, a lone `-`, `-Command -` or
 * `-File -`. */
static bool ps_wants_stdin(const struct cmdv *v)
{
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        if (strcmp(a, "-") == 0) return true;
        if (a[0] != '-') return false; /* a command or file operand */
        if (strcasecmp(a, "-command") == 0 || strcasecmp(a, "-c") == 0 ||
            strcasecmp(a, "-file") == 0 || strcasecmp(a, "-f") == 0)
            return i + 1 >= v->na || strcmp(v->a[i + 1], "-") == 0;
        if (strcasecmp(a, "-ep") == 0 || strcasecmp(a, "-executionpolicy") == 0 ||
            strcasecmp(a, "-wd") == 0 || strcasecmp(a, "-workingdirectory") == 0 ||
            strcasecmp(a, "-inputformat") == 0 || strcasecmp(a, "-outputformat") == 0 ||
            strcasecmp(a, "-version") == 0 || strcasecmp(a, "-windowstyle") == 0)
            i++;
    }
    return true;
}

static const char *ps_stdin_text(int depth);

static const char *check_nested(const struct cmdv *v)
{
    bool script = false;
    const char *r = NULL;
    if (is_shell_name(v->cmd)) r = nested_shell(v, &script);
    else if (strcmp(v->cmd, "source") == 0 || strcmp(v->cmd, ".") == 0) script = true;
    else if (strcmp(v->cmd, "ssh") == 0) r = nested_ssh(v, &script);
    else if (strcmp(v->cmd, "eval") == 0) return eval_joined(v, 0);
    else if (is_ps_name(v->cmd)) {
        r = nested_ps(v);
        if (r || !ps_wants_stdin(v)) return r;
        if (!v->ch) return ps_stdin_text(v->depth);
        r = eval_here_as(v, true);
        return r ? r : shell_stdin_text(v, false, true);
    } else if (strcmp(v->cmd, "cmd") == 0) return nested_cmdexe(v);
    else return NULL;
    if (r || !script) return r;
    r = eval_here(v);
    if (r) return r;
    if (strcmp(v->cmd, "ssh") != 0 && shell_stdin_is_script(v)) r = procsub_scripts(v);
    if (r) return r;
    return shell_stdin_text(v, strcmp(v->cmd, "ssh") != 0, false);
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
        while (ag_is_word_char(s[j])) j++;
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

/* awk 'BEGIN{system("rm -rf ~/.zclassic")}': the literal string given to system( runs as a
 * command. */
static const char *check_awk(const struct cmdv *v)
{
    static const char *const names[] = {"awk", "gawk", "mawk", "nawk"};
    if (!IN_LIST(v->cmd, names)) return NULL;
    for (int i = 0; i < v->na; i++) {
        for (const char *p = v->a[i]; (p = strstr(p, "system(")) != NULL;) {
            struct sbuf b = {NULL, 0, 0};
            const char *r = NULL;
            char q;
            p += 7;
            while (*p == ' ') p++;
            q = *p;
            if (q != '"' && q != '\'') continue;
            for (p++; *p && *p != q; p++) {
                if (*p == '\\' && p[1]) p++;
                sb_add(&b, p, 1);
            }
            if (b.p) r = eval_buf(b.p, b.n, v->depth + 1);
            free(b.p);
            if (r) return r;
        }
    }
    return NULL;
}

/* Recipe lines of makefile text (a tab line, or the text after `target: ;`) run as commands. */
static const char *make_recipes(const char *t, size_t n, int depth)
{
    const char *r = NULL;
    for (size_t i = 0; !r && i < n;) {
        size_t e = i;
        const char *line = t + i, *rec = NULL, *semi;
        while (e < n && t[e] != '\n') e++;
        semi = memchr(line, ';', e - i);
        if (line[0] == '\t') rec = line + 1;
        else if (semi && memchr(line, ':', (size_t)(semi - line))) rec = semi + 1;
        if (rec) {
            while (rec < t + e && strchr("@-+ \t", *rec)) rec++;
            r = eval_buf(rec, (size_t)(t + e - rec), depth + 1);
        }
        i = e + 1;
    }
    return r;
}
/* Run fn over the text a command reads from stdin: its here-strings, its heredoc, and the literal
 * producer of a pipe. An opaque producer gives R_COMPLEX when opaque_complex. */
static const char *scan_stdin_texts(const struct cmdv *v, const char *(*fn)(const char *, size_t, int),
                                    bool opaque_complex)
{
    const struct gctx *c = v->c;
    const char *r = NULL;
    int si;
    if (!c || v->sg < c->segs || v->sg >= c->segs + c->nsegs) return NULL;
    si = (int)(v->sg - c->segs);
    for (int k = 0; !r && k < c->nhs; k++)
        if (c->hstr_seg[k] == si) r = fn(c->hstr[k], strlen(c->hstr[k]), v->depth);
    if (!r && v->sg->hd_has) r = fn(c->src + v->sg->hd_off, v->sg->hd_len, v->depth);
    if (!r && v->sg->pipe_in && v->ch) {
        if (v->ch->prod_lit && v->ch->prod) r = fn(v->ch->prod, strlen(v->ch->prod), v->depth);
        else if (opaque_complex) r = R_COMPLEX;
    }
    return r;
}

/* make -f /dev/stdin (or -f -) reads its makefile from a here-string, heredoc or pipe. */
static const char *check_make(const struct cmdv *v)
{
    bool stdin_mk = false;
    if (strcmp(v->cmd, "make") != 0 && strcmp(v->cmd, "gmake") != 0) return NULL;
    for (int i = 0; i + 1 < v->na; i++)
        if ((strcmp(v->a[i], "-f") == 0 || strcmp(v->a[i], "--file") == 0) &&
            (strcmp(v->a[i + 1], "/dev/stdin") == 0 || strcmp(v->a[i + 1], "-") == 0))
            stdin_mk = true;
    return stdin_mk ? scan_stdin_texts(v, make_recipes, true) : NULL;
}

/* A unified diff that names a protected path (vendor, workflows, a datadir) in its headers. */
static const char *patch_text_rule(const char *t, size_t n, int depth)
{
    (void)depth;
    for (size_t i = 0; i < n;) {
        size_t e = i;
        while (e < n && t[e] != '\n') e++;
        if (e - i > 4 && (strncmp(t + i, "+++ ", 4) == 0 || strncmp(t + i, "--- ", 4) == 0 ||
                          strncmp(t + i, "diff ", 5) == 0)) {
            char *ln = malloc(e - i + 1); // raw-alloc-ok:build-tool
            const char *r = NULL;
            if (!ln) {
                g_complex = true;
                return R_COMPLEX;
            }
            memcpy(ln, t + i, e - i);
            ln[e - i] = '\0';
            for (char *tok = strtok(ln, " \t"); !r && tok; tok = strtok(NULL, " \t"))
                if (!(r = path_rule(tok)) && strlen(tok) > 2 && (tok[0] == 'a' || tok[0] == 'b') &&
                    tok[1] == '/')
                    r = path_rule(tok + 2);
            free(ln);
            if (r && !ag_rule_is_warning(r)) return r;
        }
        i = e + 1;
    }
    return NULL;
}

/* patch, git apply and git am write the files a diff names: a path operand or --directory or
 * --include that is protected, and the file headers of a diff given on stdin as text. A diff read
 * from a file is not read. */
static const char *check_patch(const struct cmdv *v)
{
    int first = 0;
    const char *r;
    if (strcmp(v->cmd, "git") == 0) {
        bool bad = false;
        int si = git_subcommand(v->a, v->na, &bad);
        if (si < 0 || (strcmp(v->a[si], "apply") != 0 && strcmp(v->a[si], "am") != 0)) return NULL;
        first = si + 1;
    } else if (strcmp(v->cmd, "patch") != 0) {
        return NULL;
    }
    for (int i = first; i < v->na; i++) {
        const char *a = v->a[i], *eq = strncmp(a, "--", 2) == 0 ? strchr(a, '=') : NULL;
        if ((r = path_rule(eq ? eq + 1 : a)) != NULL && !ag_rule_is_warning(r)) return r;
    }
    return scan_stdin_texts(v, patch_text_rule, false);
}



/* A wallet.dat name (wallet.dat, wallet.dat.bak, wallet-2024.dat). */
static bool is_wallet_file(const char *w)
{
    const char *b = w;
    for (const char *p = w; *p; p++)
        if (*p == '/' || *p == '\\') b = p + 1;
    return strncasecmp(b, "wallet", 6) == 0 && ci_has(b, ".dat");
}

/* Copying a wallet.dat out of a datadir exports every key it holds: the source of cp, rsync, scp,
 * install and Copy-Item may not be a wallet file in a datadir. (A copy INTO a datadir is the
 * datadir rule.) */
static const char *check_wallet_copy(const struct cmdv *v)
{
    static const char *const copiers[] = {"cp", "rsync", "scp", "install", "copy-item", "copy",
                                          "cpi", "xcopy", "robocopy"};
    int last = -1;
    if (!IN_LIST(v->cmd, copiers)) return NULL;
    for (int i = 0; i < v->na; i++)
        if (v->a[i][0] != '-' || !v->a[i][1]) last = i;
    for (int i = 0; i < v->na; i++) {
        const char *a = v->a[i];
        bool dest = i == last && last > 0;
        if (a[0] == '-' && a[1]) {
            /* a PowerShell -Destination value or a cp -t directory is the destination */
            if (strcasecmp(a, "-destination") == 0 || strcmp(a, "-t") == 0) i++;
            continue;
        }
        if (!dest && is_wallet_file(a) && tgt(v, a, false)) return R_SPEND;
    }
    return NULL;
}

typedef const char *(*check_fn)(const struct cmdv *);

static const check_fn checks[] = {
    check_python,       check_git,          check_export,  check_rpc, check_gh,
    check_reindex_args, check_daemon_datadir, check_writer_paths, check_nested,
    check_raw_rpc,      check_symlink,      check_interp,  check_awk, check_make,
    check_wallet_copy,  check_patch,
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


/* Name at s (after '$' or '${'): its length, or 0 when s does not start a variable name. */
static size_t var_name_len(const char *s)
{
    size_t n = 0;
    if (!isalpha((unsigned char)*s) && *s != '_') return 0;
    while (ag_is_word_char(s[n])) n++;
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
        /* the operand of a shell -c stays one word: sh -c "$x" runs the whole string */
        bool c_arg = i > 0 && short_group_has(c->words[sg->w0 + i - 1], 'c');
        if (e && whole && !c_arg && strpbrk(e, " \t")) {
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
        if (!mentions_datadir(v->a[i]) && !tgt(v, v->a[i], false)) continue;
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

/* Make word i of x the owned copy s. */
static void xw_replace(struct xw *x, int i, char *s)
{
    if (!xw_grow(&x->own, &x->capown, x->nown)) {
        free(s);
        return;
    }
    x->own[x->nown++] = s;
    x->w[i] = s;
}

/* The command word names its program in a way the guard can see through: "$(which rm)" and
 * `command -v rm` run rm; ZCLASSIC-CLI is zclassic-cli on a case-insensitive Windows file
 * system. */
static void resolve_command_word(struct xw *x, int ci)
{
    static const char *const prefixes[] = {"$(which ", "$(command -v ", "$(type -p ",
                                           "$(type -P ", "`which ", "`command -v "};
    const char *w = x->w[ci];
    char *b;
    for (size_t k = 0; k < sizeof prefixes / sizeof prefixes[0]; k++) {
        size_t pl = strlen(prefixes[k]);
        if (strncmp(w, prefixes[k], pl) == 0) {
            size_t n = strcspn(w + pl, ")` ");
            char *d = malloc(n + 1); // raw-alloc-ok:build-tool
            if (!d) {
                g_complex = true;
                return;
            }
            memcpy(d, w + pl, n);
            d[n] = '\0';
            xw_replace(x, ci, d);
            break;
        }
    }
    b = (char *)base_name(x->w[ci]);
    if (strncasecmp(b, "zclassic", 8) == 0 || strncasecmp(b, "zcash", 5) == 0)
        for (; *b; b++) *b = (char)tolower((unsigned char)*b);
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
        if (ag_glob_match(p, names[k])) return true;
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

/* Append the backslash escape at p (p points past the backslash); returns the pointer past it.
 * This is the "simple encodings" step: a command spelled \x72\x6d and piped to a shell is scanned
 * as the command it is (the decoding is in rules_esc.c). */
static const char *sb_escape(struct sbuf *b, const char *p, bool echo)
{
    char c = 0;
    size_t n = 0;
    p = ag_esc_one(p, echo, &c, &n);
    if (n) sb_add(b, &c, 1);
    return p;
}

/* The argument of a printf conversion: %b decodes the argument's own escapes, others copy it. */
static void sb_add_arg(struct sbuf *b, char conv, const char *arg)
{
    if (conv != 'b') {
        sb_add(b, arg, strlen(arg));
        return;
    }
    for (const char *a = arg; *a;) {
        if (*a == '\\' && a[1]) a = sb_escape(b, a + 1, true);
        else sb_add(b, a++, 1);
    }
}

/* printf FORMAT ARGS rendered: %s %b %d... take the arguments in turn (the format is reused while
 * arguments remain); backslash escapes (n, t, xHH, octal) become characters. */
static char *printf_render(const char *fmt, char **args, int nargs)
{
    struct sbuf b = {NULL, 0, 0};
    int ai = 0;
    bool conv;
    do {
        conv = false;
        for (const char *p = fmt; *p; p++) {
            if (*p == '\\' && p[1]) {
                p = sb_escape(&b, p + 1, false) - 1;
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
                if (ai < nargs) sb_add_arg(&b, *q, args[ai++]);
                p = q;
            } else {
                sb_add(&b, p, 1);
            }
        }
    } while (conv && ai < nargs && b.cap != (size_t)-1);
    if (b.cap == (size_t)-1) return NULL;
    return b.p ? b.p : strdup(""); // raw-alloc-ok:build-tool
}

/* echo text with the two-character \n made a newline (echo -e and a shell reading it agree); with
 * -e (interp) every printf-style escape is decoded, which is how `echo -e '\x72m ...' | sh` spells
 * a command. */
static char *echo_render(char **w, int n, bool interp)
{
    struct sbuf b = {NULL, 0, 0};
    for (int i = 0; i < n; i++) {
        if (i) sb_add(&b, " ", 1);
        for (const char *p = w[i]; *p;) {
            if (interp && p[0] == '\\' && p[1]) {
                p = sb_escape(&b, p + 1, true);
            } else if (p[0] == '\\' && p[1] == 'n') {
                sb_add(&b, "\n", 1);
                p += 2;
            } else {
                sb_add(&b, p++, 1);
            }
        }
    }
    if (b.cap == (size_t)-1) return NULL;
    return b.p ? b.p : strdup(""); // raw-alloc-ok:build-tool
}

/* Index of the first word of echo's text past its -n -e -E options; *interp is set by -e. */
static int echo_options(char **w, int n, int k, bool *interp)
{
    while (k < n && w[k][0] == '-' && w[k][1] && strspn(w[k] + 1, "neE") == strlen(w[k] + 1)) {
        if (strchr(w[k] + 1, 'e')) *interp = true;
        k++;
    }
    return k;
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
        bool interp = false;
        k = echo_options(w, n, k, &interp);
        return echo_render(w + k, n - k, interp);
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
    /* while read d; do ...; done <<< ~/.zclassic: the here-string belongs to the `done` segment */
    for (int k = 0; in_while && k < c->nhs; k++) {
        int hs = c->hstr_seg[k];
        if (hs <= si || hs >= c->nsegs || c->segs[hs].nw < 1 ||
            strcmp(c->words[c->segs[hs].w0], "done") != 0 || !mentions_datadir(c->hstr[k]))
            continue;
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
        if (strncmp(q, name, n) == 0 && !ag_is_word_char(q[n])) return true;
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
    resolve_command_word(x, ci);
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

/* A finding in the text of a script being written is a note, never a refusal: the script may
 * hold a test fixture, a regtest call, a quoted example, and what matters is running it, which the
 * Bash or PowerShell scan covers. g_note holds the last note for the hook to print on stderr. */
static char g_note[256];

static void note_content(const char *rule)
{
    snprintf(g_note, sizeof g_note,
             "script text holds something the guard would refuse if run (%s); allowed, because the "
             "script is checked when it runs",
             rule);
}

/* Scan written script text (sh, or PowerShell when ps): a note on a finding, no refusal, and the
 * caller's cap flag is left alone (a script may hold eval "$x"). Returns NULL. */
static void scan_script_content(bool ps, const char *text, size_t len, int depth)
{
    bool saved = g_complex;
    const char *r = eval_text(ps, text, len, depth);
    g_complex = saved;
    if (r && strcmp(r, R_COMPLEX) != 0) note_content(r);
}

/* A script file name: running it later is how a written script becomes commands. */
static bool is_script_name(const char *w)
{
    return ends_ci(w, ".sh") || ends_ci(w, ".bash") || ends_ci(w, ".zsh") || ends_ci(w, ".ps1") ||
           ends_ci(w, ".cmd") || ends_ci(w, ".bat");
}

/* echo "..." > x.sh (or printf, or cat <<EOF > x.sh): the literal text written to
 * a script file is scanned, and a finding is only a note (see note_content). */
static const char *script_write_check(const struct gctx *c, int si, int depth)
{
    const struct gseg *sg = &c->segs[si];
    for (int k = 0; k < c->nredir; k++) {
        char *text;
        bool ps;
        if (c->redir_seg[k] != si || !is_script_name(c->redir[k])) continue;
        text = literal_output(c, si, (char **)(c->words + sg->w0), sg->nw);
        if (!text) continue;
        ps = !(ends_ci(c->redir[k], ".sh") || ends_ci(c->redir[k], ".bash") ||
               ends_ci(c->redir[k], ".zsh"));
        scan_script_content(ps, text, strlen(text), depth + 1);
        free(text);
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
    if (depth == 0) snprintf(ch.cwd, sizeof ch.cwd, "%s", g_hook_cwd);
    c->src = s;
    tokenize(c, s, len);
    for (int i = 0; !r && i < c->nsegs; i++) {
        r = pick(redir_check(c, i, &ch), &warn);
        if (!r) r = pick(seg_check(c, i, depth, &ch), &warn);
        if (!r) r = pick(script_write_check(c, i, depth), &warn);
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
    g_note[0] = 0;
    g_complex = false;
    g_loopvar[0] = '\0';
    g_nvars = 0;
    g_git_init = false;
}

const char *ag_note(void)
{
    return g_note[0] ? g_note : NULL;
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
    bool st_cli, st_qmeth, st_test; /* statement facts: an RPC client word, a quoted method word,
                                       a numeric non-production port (the regtest node's) */
    bool cmd_web, cmd_rpc, cmd_qmeth; /* the whole text: a web call, a local production RPC port
                                         (or a variable port), a quoted method word */
    char pend_var[40];             /* `$name =` seen, its expression follows in the next segment */
    bool prod_lit;                 /* the previous segment of a pipe printed literal text: prod */
    char prod[2048];
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
            /* -ArgumentList is also the second positional: Start-Process prog 'args' */
            if ((i > 0 && (strcasecmp(sv.a[i - 1], "-argumentlist") == 0 ||
                           strcasecmp(sv.a[i - 1], "-args") == 0)) ||
                (i == 0 && k >= 0 && a[0] != '-')) {
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

/* Set-Variable d value, Set-Variable -Name d -Value value, New-Variable (and the sv, nv
 * aliases): record the variable and drop the words. False when the segment is not one, or the
 * name or value is not a plain word. */
static bool ps_set_variable(struct psseg *s)
{
    static const char *const cmds[] = {"set-variable", "sv", "new-variable", "nv"};
    static const char *const valued[] = {"-scope", "-option", "-description", "-visibility"};
    char lw[16], low[sizeof g_vars[0].name];
    const char *name = NULL, *value = NULL;
    char *x;
    int pos = 0;
    size_t nl;
    if (strlen(s->w[0]) >= sizeof lw) return false;
    for (size_t k = 0; k <= strlen(s->w[0]); k++) lw[k] = (char)tolower((unsigned char)s->w[0][k]);
    if (!PS_IN(lw, cmds)) return false;
    for (int i = 1; i < s->n; i++) {
        const char *a = s->w[i];
        if (a[0] == '-' && a[1]) {
            char pn[16];
            size_t n = strlen(a);
            if (n >= sizeof pn) continue;
            for (size_t k = 0; k <= n; k++) pn[k] = (char)tolower((unsigned char)a[k]);
            if (strcmp(pn, "-name") == 0 && i + 1 < s->n) name = s->w[++i];
            else if (strcmp(pn, "-value") == 0 && i + 1 < s->n) value = s->w[++i];
            else if (PS_IN(pn, valued)) i++;
        } else if (pos++ == 0) {
            name = a;
        } else if (pos == 2) {
            value = a;
        }
    }
    if (!name || !value) return false;
    if (name[0] == '$') name++;
    nl = strlen(name);
    if (!nl || nl >= sizeof low) return false;
    for (size_t k = 0; k <= nl; k++) low[k] = (char)tolower((unsigned char)name[k]);
    x = ps_expand(value);
    var_set(low, nl, x ? x : value);
    free(x);
    for (int i = 0; i < s->n; i++) free(s->w[i]);
    s->n = 0;
    return true;
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
    const char *nm;
    if (s->n == 0) return;
    if (ps_set_variable(s)) return;
    w0 = s->w[0];
    if (w0[0] != '$') return;
    if (w0[1] == '{') { /* ${name} = expr */
        nm = w0 + 2;
        nl = strcspn(nm, "}");
        if (!nl || nm[nl] != '}') return;
        rest = nm + nl + 1;
    } else {
        nm = w0 + 1;
        if (!(nl = var_name_len(nm))) return;
        rest = nm + nl;
    }
    if (nl >= sizeof low) return;
    for (size_t k = 0; k < nl; k++) low[k] = (char)tolower((unsigned char)nm[k]);
    low[nl] = '\0';
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

/* w with each $('a'+'b') subexpression made of quoted strings joined by + replaced by the joined
 * text ("$env:APPDATA\$('Zcl'+'assic')" names Zclassic); NULL when nothing changed. */
static char *ps_fold_concat(const char *w)
{
    struct sbuf b = {NULL, 0, 0};
    bool changed = false;
    if (!strstr(w, "$(")) return NULL;
    for (const char *p = w; *p;) {
        struct sbuf part = {NULL, 0, 0};
        const char *q = p + 2;
        bool ok = p[0] == '$' && p[1] == '(';
        while (ok) {
            char qc;
            while (*q == ' ') q++;
            qc = *q;
            if (qc != '\'' && qc != '"') {
                ok = false;
                break;
            }
            for (q++; *q && *q != qc; q++) sb_add(&part, q, 1);
            if (!*q) {
                ok = false;
                break;
            }
            q++;
            while (*q == ' ') q++;
            if (*q == '+') {
                q++;
                continue;
            }
            ok = *q == ')';
            break;
        }
        if (ok && part.p) {
            sb_add(&b, part.p, part.n);
            p = q + 1;
            changed = true;
        } else {
            sb_add(&b, p++, 1);
        }
        free(part.p);
    }
    if (!changed || !b.p || b.cap == (size_t)-1) {
        if (b.cap != (size_t)-1) free(b.p);
        return NULL;
    }
    return b.p;
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
        x = ps_fold_concat(s->w[i]);
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

/* A quoted string was read: note it when it is a spend or export method. */
static void ps_quote_seen(struct psseg *s, const char *q, size_t n)
{
    if (ag_quoted_method(q, n)) s->st_qmeth = s->cmd_qmeth = true;
}

/* A request posted to a local production RPC port (or a variable port) in a text that holds a spend
 * or export method as a quoted word: the usual @{method='dumpprivkey'} | ConvertTo-Json body, which
 * the statement facts cannot see (the hashtable's ; ends the statement). */
static void ps_judge_command(struct psseg *s)
{
    if (!s->r && s->cmd_web && s->cmd_rpc && s->cmd_qmeth && !g_regtest_hint) s->r = R_SPEND;
}

static bool ps_client_word(const char *w);

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

/* The port facts of one word: a numeric non-production port (the regtest node's) makes the
 * statement a test call; a production port or a port held in a variable on this machine makes the
 * text a post to a local RPC port. */
static void ps_note_port(struct psseg *s, const char *w)
{
    long port = ag_word_port(w);
    if (port > 0 && !ag_prod_port(port)) s->st_test = true;
    if ((port == -2 || ag_prod_port(port)) && ag_local_host(w)) s->cmd_rpc = true;
}

/* A web call or an RPC client call whose text carries a spend or export method is a test call only
 * with -regtest or a numeric non-production port. */
static void ps_judge_spend(struct psseg *s)
{
    bool web = s->st_web && s->st_meth, cli = s->st_cli && s->st_qmeth;
    if (!g_regtest_hint && !s->st_test && (web || cli)) ps_note(s, R_SPEND);
}

/* Fold the facts of the segment's words into the statement flags, then judge the statement. */
static void ps_note_facts(struct psseg *s)
{
    for (int i = 0; i < s->n; i++) {
        const char *w = s->w[i];
        if (ps_delete_word(w)) s->st_del = true;
        if (ps_base_word(w)) s->st_base = true;
        if (ps_name_word(w)) s->st_name = true;
        if (ps_web_word(w)) s->st_web = s->cmd_web = true;
        if (ag_word_has_method(w)) s->st_meth = true;
        if (ps_client_word(w)) s->st_cli = true;
        ps_note_port(s, w);
    }
    if (s->st_del && s->st_base && s->st_name) ps_note(s, R_DATADIR);
    ps_judge_spend(s);
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

/* `$env:GIT_AUTHOR_NAME = 'Claude'`: an identity variable set to a name of the tool itself (see
 * rules_ident.c). */
static bool ps_env_identity(const struct psseg *s)
{
    static const char *const ids[] = {"git_author_name", "git_author_email",
                                      "git_committer_name", "git_committer_email", "email"};
    size_t nl;
    bool assign, agent = false;
    if (strncasecmp(s->w[0], "$env:", 5) != 0) return false;
    nl = strcspn(s->w[0] + 5, "=");
    assign = s->w[0][5 + nl] == '=' || (s->n > 1 && s->w[1][0] == '=');
    for (int i = 0; assign && i < s->n; i++)
        agent = agent || ag_agent_identity(i == 0 ? s->w[0] + 5 + nl : s->w[i]);
    for (size_t k = 0; assign && agent && k < sizeof ids / sizeof ids[0]; k++)
        if (strlen(ids[k]) == nl && strncasecmp(s->w[0] + 5, ids[k], nl) == 0) return true;
    return false;
}

static const char *ps_seg_inner(struct psseg *s)
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
    if (ps_env_identity(s)) return R_IDENT;
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
     (st).st_cli = (st).st_qmeth = (st).st_test = false, \
     (st).prod_lit = false, (st).pend_var[0] = '\0')

/* The text a segment prints when it is a lone word ('script text') or echo, Write-Output or
 * Write-Host of words: what the next segment of a pipe reads (`'text' | powershell -`). */
static void ps_set_prod(struct psseg *s)
{
    static const char *const printers[] = {"echo", "write-output", "write-host", "write"};
    char lw[16];
    int k = 0;
    size_t used = 0;
    if (s->n == 0) return;
    s->prod_lit = false;
    if (strlen(s->w[0]) < sizeof lw) {
        for (size_t i = 0; i <= strlen(s->w[0]); i++) lw[i] = (char)tolower((unsigned char)s->w[0][i]);
        if (PS_IN(lw, printers)) k = 1;
    }
    if (k == 0 && (s->n > 1 || cmdlet_like(s->w[0]))) return;
    s->prod[0] = '\0';
    for (int i = k; i < s->n; i++) {
        size_t n = strlen(s->w[i]);
        if (used + n + 2 >= sizeof s->prod) return; /* too long to keep: stays not literal */
        if (i > k) s->prod[used++] = ' ';
        memcpy(s->prod + used, s->w[i], n);
        used += n;
        s->prod[used] = '\0';
    }
    s->prod_lit = true;
}

/* The segment being scanned, so a nested powershell can read what is piped into it. */
static struct psseg *g_ps;

static const char *ps_seg(struct psseg *s)
{
    struct psseg *prev = g_ps;
    const char *r;
    g_ps = s;
    r = ps_seg_inner(s);
    g_ps = prev;
    return r;
}

/* `<literal> | powershell -Command -`: the piped text is the script; anything computed cannot be
 * read. */
static const char *ps_stdin_text(int depth)
{
    if (!g_ps || !g_ps->saw_pipe) return NULL;
    if (!g_ps->prod_lit) return R_COMPLEX;
    return ps_eval(g_ps->prod, strlen(g_ps->prod), depth + 1);
}

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
    ps_set_prod(s);
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
    if (depth == 0) snprintf(st.cwd, sizeof st.cwd, "%s", g_hook_cwd);
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
            size_t qs = n;
            quoted = true;
            for (i++; i < len; i++) {
                if (s[i] == '\'' && i + 1 < len && s[i + 1] == '\'') i++;
                else if (s[i] == '\'') break;
                buf[n++] = s[i];
            }
            ps_quote_seen(&st, buf + qs, n - qs);
            i++;
        } else if (ch == '"') {
            size_t qs = n;
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
            ps_quote_seen(&st, buf + qs, n - qs);
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
    ps_judge_command(&st);
    free(st.w);
    free(buf);
    return st.r ? st.r : st.warn;
}

const char *ag_eval_ps(const char *cmd)
{
    g_note[0] = 0;
    g_complex = false;
    g_nvars = 0;
    g_git_init = false;
    g_ps = NULL;
    g_xargs = false;
    g_xrepl[0] = '\0';
    g_loopvar[0] = '\0';
    g_regtest_hint = regtest_word_in(cmd);
    return finish(ps_eval(cmd, strlen(cmd), 0));
}

void ag_set_cwd(const char *cwd)
{
    snprintf(g_hook_cwd, sizeof g_hook_cwd, "%s", cwd ? cwd : "");
}

static const char *eval_path_abs(const char *tool, const char *path, const char *content);

/* A relative file_path is resolved against the working directory the hook reports. Written
 * script content (.sh, .ps1, .cmd, .bat) is scanned as commands, since the script runs later. */
const char *ag_eval_path(const char *tool, const char *path, const char *content)
{
    char *joined = NULL;
    const char *r, *warn = NULL;
    g_note[0] = 0;
    if (!path) return NULL;
    if (g_hook_cwd[0] && relative_word(path)) joined = join_cwd(g_hook_cwd, path);
    r = eval_path_abs(tool, joined ? joined : path, content);
    free(joined);
    if (r && !ag_rule_is_warning(r)) return r;
    warn = r;
    if (content && strcmp(tool, "Write") == 0 && is_script_name(path)) {
        bool sh = ends_ci(path, ".sh") || ends_ci(path, ".bash") || ends_ci(path, ".zsh");
        reset_state();
        scan_script_content(!sh, content, strlen(content), 0);
    }
    return warn;
}

static const char *eval_path_abs(const char *tool, const char *path, const char *content)
{
    const char *r, *warn = NULL;
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

void ag_mark_complex(void)
{
    g_complex = true;
}
