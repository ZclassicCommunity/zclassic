/* zcl-lint: small ratchet gates for the zclassicd tree. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see LICENSE.z23, NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_hardening_ratchet.c, gate_no_new_bash.c and gate_markdown_links.c
 * @1f5d0f69448c4811884b2c918ae0723ab24830da, and (helper semantics) Z23 tools/lint/lintc/lib.c and
 * tools/lint/strip_c_comments.awk@9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim. See NOTICE.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool word_at(const char *s, const char *w)
{
    size_t k = strlen(w);
    if (strncmp(s, w, k) != 0) return false;
    return !(isalnum((unsigned char)s[k]) || s[k] == '_');
}

static long count_word_lines(char *txt, const char *w)
{
    long hits = 0;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        for (char *p = strstr(line, w); p; p = strstr(p + 1, w)) {
            bool left = p == line || !(isalnum((unsigned char)p[-1]) || p[-1] == '_' || p[-1] == '-');
            if (left && word_at(p, w)) { hits++; break; }
        }
    }
    return hits;
}

int lint_rule_no_new_jq(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (lint_is_vendored(lint_files[i]) || lint_has_prefix(lint_files[i], "zcutil/lint/") || !lint_is_shell_file(lint_files[i])) continue;
        char *txt = lint_slurp(lint_files[i], NULL);
        if (!txt) continue;
        scanned++;
        long n = count_word_lines(txt, "jq");
        if (n) lint_rows_add(&cur, lint_files[i], n);
        free(txt);
    }
    return lint_ratchet("no-new-jq", "lines mentioning jq in shell scripts", &cur, scanned, update);
}
