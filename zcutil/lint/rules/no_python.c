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
#include <sys/stat.h>
#include <string.h>

int lint_rule_no_python(bool update)
{
    (void)update; /* no baseline */
    char *p = lint_rootpath("zcutil/check-no-python.sh");
    struct stat st;
    bool have = stat(p, &st) == 0;
    free(p);
    if (!have) { printf("FAIL no-python: zcutil/check-no-python.sh not present, nothing scanned\n"); return 2; }
    char *script = lint_rootpath("zcutil/check-no-python.sh");
    char *argv[] = { "sh", "--", script, NULL };
    int rc = lint_run_argv(argv, false);
    free(script);
    return rc;
}
