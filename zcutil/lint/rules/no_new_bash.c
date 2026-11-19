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

/* Constructs that dash and busybox ash reject or treat differently. One hit per line at most. */
static bool line_has_bashism(const char *l)
{
    while (*l == ' ' || *l == '\t') l++;
    if (*l == '#' || *l == '\0') return false;
    static const char *const marks[] = { "[[ ", " ]]", "<(", ">(", "${!", "&>", "|&", "BASH_", "$RANDOM", "$BASHPID",
                                         "mapfile ", "readarray ", "shopt ", "declare -", "typeset -", "echo -e ", "read -a ",
                                         "read -p ", "[ -v " };
    for (size_t i = 0; i < sizeof marks / sizeof marks[0]; i++)
        if (strstr(l, marks[i])) return true;
    for (const char *p = strstr(l, "${"); p; p = strstr(p + 1, "${")) {          /* ${v//x/y}  ${v^^}  ${v,,}  ${v:1:2} */
        const char *q = p + 2;
        while (isalnum((unsigned char)*q) || *q == '_') q++;
        if (*q == '/' || *q == '^' || *q == ',') return true;
        if (*q == ':' && !strchr("-=+?", q[1]) && q[1]) return true;
    }
    if (lint_has_prefix(l, "source ") || lint_has_prefix(l, "function ") || lint_has_prefix(l, "((")) return true;
    for (const char *p = strstr(l, "=("); p; p = strstr(p + 1, "=("))               /* name=(a b)  array literal */
        if (p > l && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) return true;
    return false;
}

int lint_rule_no_new_bash(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (lint_is_vendored(lint_files[i]) || lint_has_prefix(lint_files[i], "zcutil/lint/") || !lint_is_shell_file(lint_files[i])) continue;
        char *txt = lint_slurp(lint_files[i], NULL);
        if (!txt) continue;
        scanned++;
        long n = lint_shebang_is_bash(txt) ? 1 : 0;
        for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n"))
            if (line_has_bashism(line)) n++;
        if (n) lint_rows_add(&cur, lint_files[i], n);
        free(txt);
    }
    return lint_ratchet("no-new-bash", "bash shebang and bashism lines in shell scripts", &cur, scanned, update);
}
