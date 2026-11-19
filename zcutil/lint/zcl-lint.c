/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Derived from Z23 tools/lint/lintc gates (see NOTICE); modified, not a verbatim copy.
 *
 * usage: zcl-lint [--root DIR] <rule>|all [--update-baseline]
 *   rules: see rules.def (no-new-jq no-new-bash banned-str md-links vendor no-python doc-claims doc-paths version-facts victory)
 * This file is only the driver. The rules live in rules/<rule>.c, the shared helpers in lintlib.{c,h}, and
 * the rule table in rules.def.
 * Baselines: <root>/zcutil/lint/<rule>.txt, rows "<path><TAB><count>", sorted by path (bytewise).
 * A ratchet rule fails when a path's count rises or a path appears that is not in the baseline;
 * a count that falls passes and tells you to lower the baseline (--update-baseline, shrink-only:
 * it refuses to write while anything rose, and only creates a missing baseline from scratch).
 * Exit: 0 clean, 1 findings, 2 usage, internal error or hollow scan (nothing was scanned).
 */
#define _POSIX_C_SOURCE 200809L
#include "lintlib.h"

#include <stdio.h>
#include <string.h>

#define LINT_RULE(name, fn, baseline) int fn(bool update);
#include "rules.def"
#undef LINT_RULE

struct rule { const char *name; int (*fn)(bool update); bool baseline; };
static const struct rule rules[] = {
#define LINT_RULE(name, fn, baseline) { name, fn, baseline },
#include "rules.def"
#undef LINT_RULE
};
#define NRULES (sizeof rules / sizeof rules[0])

static void usage(void)
{
    fputs("usage: zcl-lint [--root DIR] ", stderr);
    for (size_t i = 0; i < NRULES; i++) fprintf(stderr, "%s|", rules[i].name);
    fputs("all [--update-baseline]\n", stderr);
}

int main(int argc, char **argv)
{
    const char *want = NULL;
    bool update = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--root") && i + 1 < argc) lint_root = argv[++i];
        else if (!strcmp(argv[i], "--update-baseline")) update = true;
        else if (!want && argv[i][0] != '-') want = argv[i];
        else { want = NULL; break; }
    }
    if (!want) { usage(); return 2; }
    bool all = !strcmp(want, "all");
    if (all && update) { fprintf(stderr, "zcl-lint: --update-baseline needs one rule, not all\n"); return 2; }
    int rc = 0, ran = 0;
    for (size_t i = 0; i < NRULES; i++)
        if (all || !strcmp(want, rules[i].name)) {
            if (update && !rules[i].baseline) { fprintf(stderr, "zcl-lint: %s has no baseline\n", rules[i].name); return 2; }
            ran++;
        }
    if (!ran) { fprintf(stderr, "zcl-lint: unknown rule '%s'\n", want); return 2; }
    lint_load_tracked();
    for (size_t i = 0; i < NRULES; i++) {
        if (!all && strcmp(want, rules[i].name)) continue;
        int r = rules[i].fn(update);
        if (r > rc) rc = r;
    }
    return rc;
}
