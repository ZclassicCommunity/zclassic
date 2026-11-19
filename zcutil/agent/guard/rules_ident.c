/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * zcl-agent-guard: is a git identity value one an agent must not commit as? Commits are authored by
 * the repository owner, and the fleet makes them with `git -c user.name=... -c user.email=... commit`
 * on hosts that carry no identity, so an override is ordinary work. The mistake the rule exists for
 * is a commit authored as the tool itself (Claude <noreply@anthropic.com>, a bot or agent name). */

#include <stdbool.h>
#include <string.h>
#include <strings.h>

#include "rules_int.h"

bool ag_agent_identity(const char *v)
{
    static const char *const names[] = {"claude", "anthropic", "codex", "openai", "chatgpt", "gpt-",
                                        "gemini", "copilot", "cursor", "deepseek", "glm-", "qwen",
                                        "llama", "mistral", "grok", "assistant", "agent", "-bot",
                                        "bot@", "[bot]", "noreply@anthropic"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        size_t m = strlen(names[i]);
        for (const char *p = v; *p; p++)
            if (strncasecmp(p, names[i], m) == 0) return true;
    }
    return false;
}
