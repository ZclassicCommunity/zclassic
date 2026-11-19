/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * zcl-agent-guard: is a git identity value one an agent must not commit as? Commits are authored by
 * the repository owner, and the fleet makes them with `git -c user.name=... -c user.email=... commit`
 * on hosts that carry no identity, so an override is ordinary work. The mistake the rule exists for
 * is a commit authored as the tool itself (Claude <noreply@anthropic.com>, a bot or agent name). */

#include <ctype.h>
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

bool ag_is_identity_key(const char *k)
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

/* True when s (any case) contains an identity config key: user.name, user.email, author.*,
 * committer.* (GIT_CONFIG_PARAMETERS carries "'user.name=x'" style text). */
bool ag_mentions_identity_key(const char *s)
{
    static const char *const keys[] = {"user.name", "user.email", "author.", "committer."};
    for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++) {
        size_t m = strlen(keys[k]);
        for (size_t i = 0; s[i]; i++)
            if (strncasecmp(s + i, keys[k], m) == 0) return true;
    }
    return false;
}

bool ag_is_identity_env(const char *w)
{
    static const char *const names[] = {
        "GIT_AUTHOR_NAME=", "GIT_AUTHOR_EMAIL=", "GIT_COMMITTER_NAME=",
        "GIT_COMMITTER_EMAIL=", "EMAIL="};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (strncmp(w, names[i], strlen(names[i])) == 0) return ag_agent_identity(w + strlen(names[i]));
    if (strncmp(w, "GIT_CONFIG_PARAMETERS=", 22) == 0)
        return ag_mentions_identity_key(w + 22) && ag_agent_identity(w + 22);
    if (strncmp(w, "GIT_CONFIG_KEY_", 15) == 0) {
        const char *p = w + 15;
        while (isdigit((unsigned char)*p)) p++;
        return *p == '=' && p > w + 15 && ag_is_identity_key(p + 1);
    }
    return false;
}
