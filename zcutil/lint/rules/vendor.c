/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_hardening_ratchet.c, gate_no_new_bash.c and gate_markdown_links.c
 * @1f5d0f69448c4811884b2c918ae0723ab24830da, and (helper semantics) Z23 tools/lint/lintc/lib.c and
 * tools/lint/strip_c_comments.awk@9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim. See NOTICE.
 */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under a POSIX-only mask */
#endif
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int lint_rule_vendor(bool update)
{
    (void)update; /* no baseline; the driver refuses --update-baseline for this rule */
    int bad = 0, n = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!lint_has_suffix(lint_files[i], "Z23_SOURCE.tsv")) continue;
        char dir[600];
        if (strlen(lint_files[i]) >= sizeof dir) { printf("FAIL vendor: path too long to check: %.80s...\n", lint_files[i]); bad++; continue; }
        snprintf(dir, sizeof dir, "%s", lint_files[i]);
        *strrchr(dir, '/') = '\0';
        char own[700];
        snprintf(own, sizeof own, "%s/tools/check-vendor.sh", dir);        /* a root with its own checker */
        char *script = lint_rootpath(lint_is_tracked(own) ? own : "src/c23/tools/check-vendor.sh");
        char *target = lint_rootpath(lint_is_tracked(own) ? dir : lint_files[i]);
        n++;
        char *argv[] = { "sh", "--", script, target, NULL };
        int bad_run = lint_run_argv(argv, false);
        free(script);
        free(target);
        if (bad_run) { printf("FAIL vendor: %s does not match its vendored tree\n", lint_files[i]); bad++; }
    }
    if (!n) { printf("FAIL vendor: no Z23_SOURCE.tsv manifest is tracked\n"); return 2; }
    if (!bad) printf("vendor: ok (%d manifests)\n", n);
    return bad ? 1 : 0;
}
