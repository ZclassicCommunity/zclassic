/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_hardening_ratchet.c, gate_no_new_bash.c and gate_markdown_links.c
 * @1f5d0f69448c4811884b2c918ae0723ab24830da, and (helper semantics) Z23 tools/lint/lintc/lib.c and
 * tools/lint/strip_c_comments.awk@9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim. See NOTICE.
 */
#define _POSIX_C_SOURCE 200809L
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
        char dir[600], cmd[2400];
        snprintf(dir, sizeof dir, "%s", lint_files[i]);
        *strrchr(dir, '/') = '\0';
        char own[700];
        snprintf(own, sizeof own, "%s/tools/check-vendor.sh", dir);        /* a root with its own checker */
        if (lint_is_tracked(own)) snprintf(cmd, sizeof cmd, "sh '%s/%s' '%s/%s'", lint_root, own, lint_root, dir);
        else snprintf(cmd, sizeof cmd, "sh '%s/src/c23/tools/check-vendor.sh' '%s/%s'", lint_root, lint_root, lint_files[i]);
        n++;
        if (lint_run(cmd)) { printf("FAIL vendor: %s does not match its vendored tree\n", lint_files[i]); bad++; }
    }
    if (!n) { printf("FAIL vendor: no Z23_SOURCE.tsv manifest is tracked\n"); return 2; }
    if (!bad) printf("vendor: ok (%d manifests)\n", n);
    return bad ? 1 : 0;
}
