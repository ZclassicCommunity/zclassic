/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard_rules.h@9a191ef7b, Apache-2.0, changed (zclassicd's rules;
 * see zcutil/tools/NOTICE). zcl-agent-guard rule engine interface (rules.c). */

#ifndef ZCL_AGENT_GUARD_RULES_H
#define ZCL_AGENT_GUARD_RULES_H

#include <stdbool.h>

#define R_DATADIR "guard.datadir"
#define R_REINDEX "guard.reindex"
#define R_SPEND "guard.spend_or_key_export"
#define R_PYTHON "guard.python"
#define R_IDENT "guard.git_identity"
#define R_PUSH "guard.git_push"
#define R_CI "guard.hosted_ci"
#define R_VENDOR "guard.vendor_edit"
#define R_SEAL "guard.consensus_seal" /* a warning, never a refusal */
#define R_SELF "guard.self_protect"   /* a warning: an edit of the guard or its hook entry */
#define R_COMPLEX "guard.too_complex" /* a cap was hit: the call cannot be checked */

/* Each returns the rule id the call breaks, or NULL when the call is allowed. */
const char *ag_eval_bash(const char *cmd);
/* A PowerShell command (the PowerShell tool on Windows). */
const char *ag_eval_ps(const char *cmd);
const char *ag_eval_path(const char *tool, const char *path, const char *content);
/* The working directory the hook reports for the call (NULL or "" when unknown): where a Bash or
 * PowerShell command starts and what a relative Write or Edit path is joined to. */
void ag_set_cwd(const char *cwd);

/* True for a rule that warns on stderr and still allows the call. */
bool ag_rule_is_warning(const char *rule);
/* The AGENTS.md rule text for a rule id. */
const char *ag_rule_text(const char *rule);

#endif
