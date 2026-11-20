/* zcl-lint version-facts: every hard-coded release version must agree with configure.ac. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from Z23 tools/lint/lintc/gate_no_stale_pinned_facts.c@9a191ef7b1184e14d9116362dff7def64cd300e3,
 * modified (the pinned fact is the node version), not verbatim; see zcutil/tools/NOTICE.
 *
 * configure.ac defines _CLIENT_VERSION_{MAJOR,MINOR,REVISION,BUILD}; build N < 25 renders as "<rev>-beta(N+1)",
 * N < 50 as "<rev>-rc(N-24)", N == 50 as the plain release, above that as "<rev>-(N-50)". The canonical string
 * M.m.R[-suffix] must equal wallet/src/version.h APP_VERSION and every version token in the release and
 * packaging scripts: the files under wallet/contrib/release, wallet/res/Info.plist, the .sh files of wallet/tests/e2e and zcutil.
 * Checked tokens: M.m.R-betaN / M.m.R-rcN anywhere, a bare betaN / rcN suffix (e.g. a volume name), and the
 * plain M.m.R of CFBundleShortVersionString. No baseline: a mismatch is a stale release fact and fails with
 * file:line. A missing or unparsable configure.ac or version.h is a hollow scan (exit 2).
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The integer in "define(NAME, <int>)" of configure.ac text; -1 when absent. */
static long def_value(const char *txt, const char *name)
{
    char pat[96];
    snprintf(pat, sizeof pat, "define(%s,", name);
    const char *p = strstr(txt, pat);
    while (p && p != txt && p[-1] != '\n') p = strstr(p + 1, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ') p++;
    if (!isdigit((unsigned char)*p)) return -1;
    return atol(p);
}

static bool canonical(char *ver, size_t cap, char *suffix, size_t scap, char *plain, size_t pcap)
{
    char *ac = lint_slurp("configure.ac", NULL);
    if (!ac) return false;
    long ma = def_value(ac, "_CLIENT_VERSION_MAJOR"), mi = def_value(ac, "_CLIENT_VERSION_MINOR");
    long re = def_value(ac, "_CLIENT_VERSION_REVISION"), b = def_value(ac, "_CLIENT_VERSION_BUILD");
    free(ac);
    if (ma < 0 || mi < 0 || re < 0 || b < 0) return false;
    suffix[0] = '\0';
    if (b < 25) snprintf(suffix, scap, "-beta%ld", b + 1);
    else if (b < 50) snprintf(suffix, scap, "-rc%ld", b - 24);
    else if (b > 50) snprintf(suffix, scap, "-%ld", b - 50);
    snprintf(plain, pcap, "%ld.%ld.%ld", ma, mi, re);
    snprintf(ver, cap, "%s%s", plain, suffix);
    return true;
}

static bool checked_file(const char *p)
{
    if (lint_is_vendored(p)) return false;
    if (lint_has_prefix(p, "wallet/contrib/release/") || !strcmp(p, "wallet/res/Info.plist")) return true;
    if (lint_has_prefix(p, "wallet/tests/e2e/") && lint_has_suffix(p, ".sh")) return true;
    return lint_has_prefix(p, "zcutil/") && !strchr(p + 7, '/') && lint_has_suffix(p, ".sh");
}

/* Version tokens of one line against the canonical string. Returns the number of mismatches. */
static int check_line(const char *path, long ln, const char *l, const char *ver, const char *suffix, const char *plain)
{
    int bad = 0;
    for (const char *p = l; *p; p++) {
        bool at_start = p == l || !(isalnum((unsigned char)p[-1]) || p[-1] == '.' || p[-1] == '_');
        if (isdigit((unsigned char)*p) && (p == l || !(isdigit((unsigned char)p[-1]) || p[-1] == '.'))) {
            char *e1, *e2, *e3;
            strtol(p, &e1, 10);
            if (*e1 != '.') continue;
            strtol(e1 + 1, &e2, 10);
            if (e2 == e1 + 1 || *e2 != '.') continue;
            strtol(e2 + 1, &e3, 10);
            if (e3 == e2 + 1) continue;
            const char *end = e3;
            if (!strncmp(end, "-beta", 5) || !strncmp(end, "-rc", 3)) {
                end += end[1] == 'b' ? 5 : 3;
                while (isdigit((unsigned char)*end)) end++;
                if (isalnum((unsigned char)*end)) { p = end - 1; continue; }
                size_t n = (size_t)(end - p);
                if (n != strlen(ver) || strncmp(p, ver, n)) {
                    printf("FAIL version-facts: %s:%ld: %.*s, configure.ac says %s\n", path, ln, (int)n, p, ver);
                    bad++;
                }
                p = end - 1;
            } else p = e3 - 1;
        } else if (at_start && (!strncmp(p, "beta", 4) || !strncmp(p, "rc", 2)) && p > l && p[-1] == '-') {
            /* a "-betaN" not preceded by a dotted version, e.g. a volume name ZClassic-beta13 */
            const char *d = p + (p[0] == 'b' ? 4 : 2), *e = d;
            while (isdigit((unsigned char)*e)) e++;
            if (e == d || isalnum((unsigned char)*e)) continue;
            size_t n = (size_t)(e - p);
            if (n + 1 != strlen(suffix) || strncmp(p, suffix + 1, n)) {
                printf("FAIL version-facts: %s:%ld: %.*s, configure.ac says %s\n", path, ln, (int)n, p, suffix[0] ? suffix + 1 : "(release)");
                bad++;
            }
            p = e - 1;
        }
    }
    const char *k = strstr(l, "CFBundleShortVersionString");
    if (k) {
        const char *s = strstr(k, "<string>");
        if (s) {
            s += 8;
            size_t n = strcspn(s, "<");
            if (n != strlen(plain) || strncmp(s, plain, n)) {
                printf("FAIL version-facts: %s:%ld: CFBundleShortVersionString %.*s, configure.ac says %s\n", path, ln, (int)n, s, plain);
                bad++;
            }
        }
    }
    return bad;
}

int lint_rule_version_facts(bool update)
{
    (void)update; /* no baseline; the driver refuses --update-baseline for this rule */
    char ver[128], suffix[32], plain[64];
    if (!canonical(ver, sizeof ver, suffix, sizeof suffix, plain, sizeof plain)) {
        printf("FAIL version-facts: hollow scan (configure.ac missing or without _CLIENT_VERSION_* defines)\n");
        return 2;
    }
    int bad = 0;
    size_t files = 0;
    char *vh = lint_slurp("wallet/src/version.h", NULL);
    if (!vh) {
        printf("FAIL version-facts: hollow scan (wallet/src/version.h is missing)\n");
        return 2;
    }
    files++;
    const char *a = strstr(vh, "APP_VERSION");
    const char *q = a ? strchr(a, '"') : NULL;
    if (!q) { printf("FAIL version-facts: wallet/src/version.h: no APP_VERSION string\n"); bad++; }
    else {
        q++;
        size_t n = strcspn(q, "\"");
        if (n != strlen(ver) || strncmp(q, ver, n)) {
            printf("FAIL version-facts: wallet/src/version.h: APP_VERSION %.*s, configure.ac says %s\n", (int)n, q, ver);
            bad++;
        }
    }
    free(vh);
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!checked_file(lint_files[i])) continue;
        char *txt = lint_slurp(lint_files[i], NULL);
        if (!txt) continue;
        files++;
        long ln = 0;
        for (char *l = txt; l && *l;) {
            char *nl = strchr(l, '\n');
            if (nl) *nl = '\0';
            ln++;
            bad += check_line(lint_files[i], ln, l, ver, suffix, plain);
            l = nl ? nl + 1 : NULL;
        }
        free(txt);
    }
    if (bad) return 1;
    printf("version-facts: ok (%s, %zu files)\n", ver, files);
    return 0;
}
