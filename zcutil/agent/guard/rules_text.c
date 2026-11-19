/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard_rules.c@9a191ef7b, Apache-2.0, changed (zclassicd's rules; see
 * zcutil/tools/NOTICE). zcl-agent-guard: the rule ids that only warn and the AGENTS.md text of each
 * rule (split out of rules.c). */

#include <stdbool.h>
#include <string.h>

#include "rules.h"

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
