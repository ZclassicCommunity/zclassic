/* zcl-lint filesize: line-count bands for maintained C, C++ and header files.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from Z23 tools/file_size_policy.c@9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim.
 *
 * Bands: up to 800 lines is the target; 801..1500 is the allowed buffer (counted, advisory); above 1500 is over
 * the hard limit and may only exist as a baseline row (zcutil/lint/filesize.txt, "<path><TAB><lines>") that
 * only shrinks. A new file over the limit, or a baselined file that grew, fails.
 * Scope: src/ (not vendored trees), wallet/src/, qa/ and zcutil/ (not vendor/).
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include "../lintlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILESIZE_TARGET 800L
#define FILESIZE_LIMIT 1500L

static bool in_shape_scope(const char *p)
{
    if (!lint_is_c_source(p) || lint_is_vendored(p)) return false;
    return lint_has_prefix(p, "src/") || lint_has_prefix(p, "wallet/src/") || lint_has_prefix(p, "qa/") || lint_has_prefix(p, "zcutil/");
}

static long count_lines(const char *txt, size_t len)
{
    long n = 0;
    for (size_t i = 0; i < len; i++)
        if (txt[i] == '\n') n++;
    if (len && txt[len - 1] != '\n') n++;
    return n;
}

int lint_rule_filesize(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0, buffer = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!in_shape_scope(lint_files[i])) continue;
        size_t len = 0;
        char *txt = lint_slurp(lint_files[i], &len);
        if (!txt) continue;
        scanned++;
        long n = count_lines(txt, len);
        if (n > FILESIZE_LIMIT) lint_rows_add(&cur, lint_files[i], n);
        else if (n > FILESIZE_TARGET) buffer++;
        free(txt);
    }
    int rc = lint_ratchet("filesize", "line counts of files over the 1500-line limit", &cur, scanned, update);
    if (rc == 0 && !update) printf("filesize: %zu file(s) sit in the 801..1500 buffer band (advisory, target is 800)\n", buffer);
    return rc;
}
