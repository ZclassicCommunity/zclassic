/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * One row of the zcl-agent-guard self-test table: a call and the rule it must hit. */

#ifndef ZCL_AGENT_GUARD_CASES_H
#define ZCL_AGENT_GUARD_CASES_H

#include <stddef.h>

struct tcase {
    char kind;          /* 'B' bash, 'S' PowerShell, 'P' path */
    const char *tool;   /* P: tool name */
    const char *input;  /* B: command, P: file path */
    const char *extra;  /* P: Write content, else NULL */
    const char *want;   /* rule id, or NULL for allow */
};

#define B(cmd, want) {'B', NULL, cmd, NULL, want}
#define P(tool, path, want) {'P', tool, path, NULL, want}
#define S(cmd, want) {'S', NULL, cmd, NULL, want}

extern const struct tcase extra_cases[];
extern const size_t n_extra_cases;

#endif
