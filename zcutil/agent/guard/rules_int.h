/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * zcl-agent-guard: the small pure helpers that rules.c calls and that live in their own files
 * (rules_esc.c, rules_net.c, rules_push.c, rules_home.c). Not an interface of the guard. */

#ifndef ZCL_AGENT_GUARD_RULES_INT_H
#define ZCL_AGENT_GUARD_RULES_INT_H

#include <stdbool.h>
#include <stddef.h>

/* One backslash escape of printf (echo true: of echo -e), p pointing past the backslash. At most one
 * decoded byte goes to out and *n says how many (0 for a NUL or an unusable escape); returns the
 * pointer past the escape. An unknown escape keeps its character. */
const char *ag_esc_one(const char *p, bool echo, char *out, size_t *n);

/* The TCP port a URL or host:port word names: -1 none, -2 a variable. */
long ag_word_port(const char *w);
/* A mainnet RPC or P2P port of a node. */
bool ag_prod_port(long port);
/* The word names this machine: 127.0.0.1, localhost, [::1], 0.0.0.0. */
bool ag_local_host(const char *w);

/* rules_push.c: the git state of one command (working directory as written, branch put on by a
 * checkout or switch) and the `git push` rule. dash_c is the value of `git -C` or NULL; the result
 * is R_PUSH or NULL. */
void ag_git_state_reset(const char *hook_cwd);
void ag_git_note_cd(char **a, int na);
void ag_git_note_branch(const char *sub, char **a, int na);
const char *ag_push_rule(char **a, int na, const char *dash_c);

/* The components before a .zclassic* or .zcash-params* name put it where the node keeps its data. */
bool ag_dd_name_in_home(const char *const *pre, const size_t *prl, int np);

/* rules_rpc.c: spend and key-export method names. */
bool ag_is_word_char(char ch);
bool ag_is_method(const char *s, size_t n);
bool ag_body_has_method(const char *s, size_t len);
bool ag_payload_has_method(const char *s);
bool ag_word_has_method(const char *w);
const char *ag_body_arg(char **a, int na, int i);

/* rules_glob.c: shell glob match of pattern p against s, case-insensitive. */
bool ag_glob_match(const char *p, const char *s);

/* rules_path.c: pat (lower case, '/' separated) occurs in w at a component boundary, whatever the
 * spelling of w (case, backslashes, '.', '..'). */
bool ag_path_has(const char *w, const char *pat, bool dir_mode);

/* rules.c: a helper ran out of memory or hit a cap: the verdict can no longer be "allow". */
void ag_mark_complex(void);

/* rules_ident.c: the git identity value names the tool (Claude, a bot, an agent), not a person. */
bool ag_agent_identity(const char *v);
bool ag_is_sealed_path(const char *w);
bool ag_is_identity_key(const char *k);
bool ag_is_identity_env(const char *w);
bool ag_mentions_identity_key(const char *s);

/* rules_home.c: $TMPDIR, $env:TEMP, $work, $dd...: the variable names a scratch place. */
bool ag_starts_tmpvar(const char *v);
/* rules_rpc.c: a quoted string that is, or starts with, a spend or export method name. */
bool ag_quoted_method(const char *q, size_t n);

/* rules.c: leave a note on stderr for an allowed call (see ag_note). */
void ag_note_text(const char *text);

#endif
