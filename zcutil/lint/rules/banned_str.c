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

static long count_banned(char *s)
{
    static const char *const ban[] = { "strcpy", "strcat", "sprintf", "vsprintf", "gets" };
    long hits = 0;
    for (size_t i = 0; s[i];) {
        if (!lint_idc((unsigned char)s[i])) { i++; continue; }
        size_t b = i;
        while (lint_idc((unsigned char)s[i])) i++;
        size_t j = i;
        while (s[j] == ' ' || s[j] == '\t') j++;
        bool member = (b >= 1 && s[b - 1] == '.') || (b >= 2 && s[b - 2] == '-' && s[b - 1] == '>');
        if (s[j] != '(' || member) continue;
        for (size_t k = 0; k < sizeof ban / sizeof ban[0]; k++)
            if (strlen(ban[k]) == i - b && memcmp(ban[k], s + b, i - b) == 0) hits++;
    }
    return hits;
}

int lint_rule_banned_str(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!lint_is_c_source(lint_files[i]) || lint_is_vendored(lint_files[i])) continue;
        char *txt = lint_slurp(lint_files[i], NULL);
        if (!txt) continue;
        scanned++;
        long n = 0;
        bool blk = false;
        for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
            bool okline = strstr(line, "lint-ok:") != NULL;
            lint_scrub_c_line(line, &blk);
            if (!okline) n += count_banned(line);
        }
        if (n) lint_rows_add(&cur, lint_files[i], n);
        free(txt);
    }
    return lint_ratchet("banned-str", "calls to strcpy, strcat, sprintf, vsprintf, gets", &cur, scanned, update);
}
