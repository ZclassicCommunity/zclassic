/* zcl-lint kpi: the tree-health scoreboard and its floor. C, libc only, gnu17-clean.
 *
 * Copyright 2026 Rhett Creighton - Apache License 2.0 (see ../LICENSE.z23, ../NOTICE).
 * Derived from Z23 cognition/modules/kpi/include/kpi/kpi.h and tools/lint/gate_kpi_floor.c
 * @9a191ef7b1184e14d9116362dff7def64cd300e3; modified, not verbatim. See zcutil/tools/NOTICE.
 *
 * Every metric is read from an artefact that already exists (the tracked file list, a rule baseline, the
 * lessons file, the impact-rule checker) and is UNAVAILABLE, never 0, when that artefact cannot be read: "0" means
 * "looked and found none", UNAVAILABLE means "could not look" (exit 2, because a gate that cannot look is not a
 * pass). zcutil/lint/kpi-floor.txt holds one row per metric, "<metric><TAB><floor>". A metric above its floor
 * fails with the old and new value. The floor only shrinks: `--update-baseline` (alias `--tighten`) lowers
 * floors to today, refuses while anything is worse or unavailable, and creates the file when it is missing.
 * Rule-baseline metrics sum the baseline file (a ceiling), so editing a baseline upward trips this floor too.
 */
#define _POSIX_C_SOURCE 200809L
#include "../lintlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KPI_FLOOR_FILE "zcutil/lint/kpi-floor.txt"
#define KPI_COMPLEXITY_CAP 15L

enum { M_PYTHON, M_HOSTED_CI, M_SHELL_LINES, M_BASH_LINES, M_JQ, M_BANNED, M_OVER_1500, M_COMPLEXITY, M_UNDOC_FLAGS,
       M_MD_LINKS, M_DOC_PATHS, M_SECRET_LOG, M_UNREG_TESTS, M_UNMAPPED, M_LESSONS_OPEN, M_COUNT };

static const char *const names[M_COUNT] = {
    "python_files", "hosted_ci_files", "shell_lines", "bash_lines", "jq_uses", "banned_str", "files_over_1500",
    "complexity_debt", "undocumented_flags", "broken_md_links", "doc_path_debt", "secret_log_sites",
    "unregistered_tests", "unmapped_paths", "tracked_lessons_open",
};

struct metric { long v; bool ok; const char *why; };

static void set(struct metric *m, long v) { m->v = v; m->ok = true; m->why = NULL; }
static void unavailable(struct metric *m, const char *why) { m->v = -1; m->ok = false; m->why = why; }

enum row_mode { ROWS_SUM, ROWS_COUNT, ROWS_DEBT };

/* Rows of a rule baseline or undocumented-flag list: sum of the last numeric field, the row count, or the sum
 * above the complexity cap. A missing file or a row without a number is UNAVAILABLE. */
static void from_rows(struct metric *m, const char *rel, enum row_mode mode, bool numeric)
{
    char *txt = lint_slurp(rel, NULL);
    if (!txt) { unavailable(m, "source file unreadable"); return; }
    long total = 0;
    bool bad = false;
    for (char *line = strtok(txt, "\n"); line && !bad; line = strtok(NULL, "\n")) {
        if (line[0] == '#' || line[0] == '\0' || line[0] == '\r') continue;
        if (!numeric || mode == ROWS_COUNT) { total++; continue; }
        char *tab = strrchr(line, '\t');
        char *end = NULL;
        long v = tab ? strtol(tab + 1, &end, 10) : 0;
        if (!tab || end == tab + 1) { bad = true; break; }
        total += mode == ROWS_DEBT ? (v > KPI_COMPLEXITY_CAP ? v - KPI_COMPLEXITY_CAP : 0) : v;
    }
    free(txt);
    if (bad) unavailable(m, "malformed baseline row");
    else set(m, total);
}

static bool is_hosted_ci(const char *p)
{
    return lint_has_prefix(p, ".github/workflows/") || lint_has_prefix(p, ".circleci/") || !strcmp(p, ".gitlab-ci.yml") ||
           !strcmp(p, ".travis.yml") || !strcmp(p, "azure-pipelines.yml") || !strcmp(p, "appveyor.yml") || !strcmp(p, "Jenkinsfile");
}

static long count_lines(const char *txt, size_t len)
{
    long n = 0;
    for (size_t i = 0; i < len; i++)
        if (txt[i] == '\n') n++;
    if (len && txt[len - 1] != '\n') n++;
    return n;
}

static void from_tree(struct metric *m)
{
    if (!lint_nfiles) {
        unavailable(&m[M_PYTHON], "no tracked files");
        unavailable(&m[M_HOSTED_CI], "no tracked files");
        unavailable(&m[M_SHELL_LINES], "no tracked files");
        return;
    }
    long py = 0, ci = 0, sh = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        const char *p = lint_files[i];
        if (lint_has_suffix(p, ".py") || lint_has_suffix(p, ".pyw")) py++;
        if (is_hosted_ci(p)) ci++;
        if (lint_is_vendored(p) || !lint_is_shell_file(p)) continue;
        size_t len = 0;
        char *txt = lint_slurp(p, &len);
        if (!txt) continue; /* tracked but deleted in the work tree: not shell we can count */
        sh += count_lines(txt, len);
        free(txt);
    }
    set(&m[M_PYTHON], py);
    set(&m[M_HOSTED_CI], ci);
    set(&m[M_SHELL_LINES], sh);
}

static void from_lessons(struct metric *m)
{
    char *txt = lint_slurp("doc/agent/LESSONS.md", NULL);
    if (!txt) { unavailable(m, "doc/agent/LESSONS.md unreadable"); return; }
    long n = 0;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n"))
        if (lint_has_prefix(line, "OPEN ")) n++;
    free(txt);
    set(m, n);
}

/* Tracked test sources (<dir>/<prefix>*<suffix>) that the build makefile never names. The makefile names a test
 * as test/x.cpp or gtest/x.cpp, i.e. the tracked path without its "src/". */
static bool unregistered_in(const char *dir, const char *prefix, const char *suffix, const char *makefile, long *out)
{
    char *mk = lint_slurp(makefile, NULL);
    if (!mk) return false;
    size_t dl = strlen(dir);
    long n = 0, seen = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        const char *p = lint_files[i];
        if (!lint_has_prefix(p, dir) || strchr(p + dl, '/')) continue;
        if (!lint_has_prefix(p + dl, prefix) || !lint_has_suffix(p, suffix)) continue;
        seen++;
        if (!strstr(mk, p + 4)) n++;
    }
    free(mk);
    if (!seen) return false;
    *out = n;
    return true;
}

static void from_tests(struct metric *m)
{
    long a = 0, b = 0;
    if (!unregistered_in("src/test/", "", "_tests.cpp", "src/Makefile.test.include", &a) ||
        !unregistered_in("src/gtest/", "test_", ".cpp", "src/Makefile.gtest.include", &b)) {
        unavailable(m, "test makefile or test sources not found");
        return;
    }
    set(m, a + b);
}

/* `zcl-dev check-rules` is the one authority on impact-rule coverage; count its "no rule matches" lines. */
static void from_check_rules(struct metric *m)
{
#ifdef _WIN32
    unavailable(m, "zcl-dev check-rules is not run from the Windows build of zcl-lint");
#else
    char *bin = lint_rootpath("zcutil/bin/zcl-dev");
    FILE *t = fopen(bin, "rb");
    if (!t) { free(bin); unavailable(m, "zcutil/bin/zcl-dev not built"); return; }
    fclose(t);
    size_t n = strlen(lint_root) + strlen(bin) + 64;
    char *cmd = lint_xrealloc(NULL, n);
    snprintf(cmd, n, "cd \"%s\" && \"%s\" check-rules 2>&1", lint_root, bin);
    FILE *p = popen(cmd, "r");
    free(cmd);
    free(bin);
    if (!p) { unavailable(m, "cannot run zcl-dev check-rules"); return; }
    char line[1024];
    long unmapped = 0, lines = 0;
    while (fgets(line, sizeof line, p)) {
        lines++;
        if (strstr(line, "FAIL: no rule matches")) unmapped++;
    }
    int st = pclose(p);
    if (st == 0 && lines > 0) set(m, 0);
    else if (unmapped > 0) set(m, unmapped);
    else unavailable(m, "zcl-dev check-rules did not run to a verdict");
#endif
}

static void collect(struct metric *m)
{
    from_tree(m);
    from_rows(&m[M_BASH_LINES], "zcutil/lint/no-new-bash.txt", ROWS_SUM, true);
    from_rows(&m[M_JQ], "zcutil/lint/no-new-jq.txt", ROWS_SUM, true);
    from_rows(&m[M_BANNED], "zcutil/lint/banned-str.txt", ROWS_SUM, true);
    from_rows(&m[M_OVER_1500], "zcutil/lint/filesize.txt", ROWS_COUNT, true);
    from_rows(&m[M_COMPLEXITY], "zcutil/lint/complexity.txt", ROWS_DEBT, true);
    from_rows(&m[M_UNDOC_FLAGS], "zcutil/dev/gen/flags-undocumented.txt", ROWS_COUNT, false);
    from_rows(&m[M_MD_LINKS], "zcutil/lint/md-links.txt", ROWS_SUM, true);
    from_rows(&m[M_DOC_PATHS], "zcutil/lint/doc-paths.txt", ROWS_SUM, true);
    from_rows(&m[M_SECRET_LOG], "zcutil/lint/secretlog.txt", ROWS_SUM, true);
    from_tests(&m[M_UNREG_TESTS]);
    from_check_rules(&m[M_UNMAPPED]);
    from_lessons(&m[M_LESSONS_OPEN]);
}

/* Floors: -1 for a metric with no row. Returns false when the file is missing; exits 2 on a malformed row. */
static bool load_floors(long *floor_v)
{
    for (int i = 0; i < M_COUNT; i++) floor_v[i] = -1;
    char *txt = lint_slurp(KPI_FLOOR_FILE, NULL);
    if (!txt) return false;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        if (line[0] == '#' || line[0] == '\0') continue;
        char *tab = strchr(line, '\t'), *end = NULL;
        long v = tab ? strtol(tab + 1, &end, 10) : -1;
        int k = -1;
        if (tab) {
            *tab = '\0';
            for (int i = 0; i < M_COUNT; i++)
                if (!strcmp(line, names[i])) k = i;
        }
        if (k < 0 || end == tab + 1 || v < 0) {
            fprintf(stderr, "zcl-lint: kpi floor: bad row in %s\n", KPI_FLOOR_FILE);
            exit(2);
        }
        floor_v[k] = v;
    }
    free(txt);
    return true;
}

static int write_floors(const struct metric *m, const long *floor_v)
{
    char *path = lint_rootpath(KPI_FLOOR_FILE);
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "zcl-lint: kpi: cannot write %s\n", path); free(path); return 2; }
    fputs("# zcl-lint kpi floor: the worst value each tree-health metric may have. Shrink-only: a floor is lowered\n"
          "# (zcl-lint kpi --tighten) when a metric improves, never raised. See doc/agent/KPI.md.\n", f);
    for (int i = 0; i < M_COUNT; i++)
        fprintf(f, "%s\t%ld\n", names[i], floor_v[i] >= 0 && floor_v[i] < m[i].v ? floor_v[i] : m[i].v);
    int rc = fclose(f) ? 2 : 0;
    free(path);
    return rc;
}

struct verdict { int bad, missing, lower, rose; };

static void print_table(const struct metric *m, const long *floor_v, bool have, struct verdict *v)
{
    printf("%-22s %12s %10s  status\n", "metric", "now", "floor");
    for (int i = 0; i < M_COUNT; i++) {
        char now[32], fl[32];
        const char *st = "ok";
        if (m[i].ok) snprintf(now, sizeof now, "%ld", m[i].v);
        else snprintf(now, sizeof now, "UNAVAILABLE");
        if (floor_v[i] >= 0) snprintf(fl, sizeof fl, "%ld", floor_v[i]);
        else snprintf(fl, sizeof fl, "-");
        if (!m[i].ok) { st = "UNAVAILABLE"; v->missing++; }
        else if (have && floor_v[i] < 0) { st = "no floor"; v->bad++; }
        else if (have && m[i].v > floor_v[i]) { st = "WORSE"; v->rose++; }
        else if (have && m[i].v < floor_v[i]) { st = "better"; v->lower++; }
        printf("%-22s %12s %10s  %s\n", names[i], now, fl, st);
    }
}

static void print_findings(const struct metric *m, const long *floor_v, bool have)
{
    for (int i = 0; i < M_COUNT; i++) {
        if (!m[i].ok) printf("UNAVAILABLE kpi: %s: %s (could not look, so no verdict)\n", names[i], m[i].why);
        else if (have && floor_v[i] >= 0 && m[i].v > floor_v[i]) printf("FAIL kpi: %s: %ld, floor %ld (rose)\n", names[i], m[i].v, floor_v[i]);
        else if (have && floor_v[i] < 0) printf("FAIL kpi: %s has no row in %s\n", names[i], KPI_FLOOR_FILE);
    }
}

/* --update-baseline / --tighten: write only when nothing is unavailable, worse or unrowed. */
static int tighten(const struct metric *m, const long *floor_v, bool have, const struct verdict *v)
{
    if (v->missing) { printf("kpi: floor NOT updated: %d metric(s) unavailable\n", v->missing); return 2; }
    if (v->rose || v->bad) { printf("kpi: floor NOT updated: a metric is worse or has no row (the floor only shrinks)\n"); return 1; }
    if (have && !v->lower) { printf("kpi: floor already tight\n"); return 0; }
    int rc = write_floors(m, floor_v);
    if (!rc) printf("kpi: floor %s\n", have ? "lowered" : "created");
    return rc;
}

int lint_rule_kpi(bool update)
{
    struct metric m[M_COUNT];
    collect(m);
    long floor_v[M_COUNT];
    bool have = load_floors(floor_v);
    struct verdict v = { 0, 0, 0, 0 };
    print_table(m, floor_v, have, &v);
    print_findings(m, floor_v, have);
    if (update) return tighten(m, floor_v, have, &v);
    if (v.missing) return 2;
    if (!have) { printf("FAIL kpi: no floor %s (create it with: zcl-lint kpi --update-baseline)\n", KPI_FLOOR_FILE); return 1; }
    if (v.rose || v.bad) return 1;
    if (v.lower) printf("kpi: ok, but the floor can be lowered (%d metric(s) improved): run zcl-lint kpi --tighten\n", v.lower);
    else printf("kpi: ok\n");
    return 0;
}
