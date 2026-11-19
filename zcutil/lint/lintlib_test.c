/* Unit test of the lintlib comment and string stripping. Copyright 2026 Rhett Creighton - MIT. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under POSIX-only masks; ignored elsewhere */
#include "lintlib.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int fails;

static void want_sh(const char *in, const char *out, char q0, char qend)
{
    char buf[256], q = q0;
    snprintf(buf, sizeof buf, "%s", in);
    lint_scrub_sh_line(buf, &q);
    if (strcmp(buf, out) || q != qend) { printf("FAIL sh '%s' -> '%s' (q=%d)\n", in, buf, q); fails++; }
}

static void want_c(const char *in, const char *out, bool b0, bool bend)
{
    char buf[256];
    bool b = b0;
    snprintf(buf, sizeof buf, "%s", in);
    lint_scrub_c_line(buf, &b);
    if (strcmp(buf, out) || b != bend) { printf("FAIL c '%s' -> '%s'\n", in, buf); fails++; }
}

/* A root and a tracked file name that carry quotes and shell syntax load as data and run nothing. */
static void want_quoted_names(void)
{
    char tmpl[] = "/tmp/lintlib-test.XXXXXX", root[256], file[300], mark[300];
    if (!mkdtemp(tmpl)) { puts("FAIL mkdtemp"); fails++; return; }
    snprintf(root, sizeof root, "%s/q';touch PWNED;'", tmpl);
    snprintf(file, sizeof file, "%s/a';touch PWNED;'.txt", root);
    snprintf(mark, sizeof mark, "%s/PWNED", root);
    char *mk[] = { "mkdir", root, NULL }, *gi[] = { "git", "-C", root, "init", "-q", NULL };
    char *tc[] = { "touch", file, NULL }, *ga[] = { "git", "-C", root, "add", "-A", NULL };
    lint_root = root;
    if (lint_run_argv(mk, true) || lint_run_argv(gi, true) || lint_run_argv(tc, true) || lint_run_argv(ga, true)) {
        puts("FAIL quoted names: fixture repository");
        fails++;
    } else {
        lint_load_tracked();
        if (lint_nfiles != 1 || strcmp(lint_files[0], "a';touch PWNED;'.txt")) { puts("FAIL quoted names: tracked list"); fails++; }
        if (access(mark, F_OK) == 0) { puts("FAIL quoted names: a name reached a shell"); fails++; }
    }
    char *rm[] = { "rm", "-rf", tmpl, NULL };
    lint_run_argv(rm, true);
}

int main(void)
{
    want_sh("echo hi # jq here", "echo hi          ", 0, 0);
    want_sh("echo 'a # b' jq", "echo         jq", 0, 0);
    want_sh("echo \"say \\\" # x\" ok", "echo              ok", 0, 0);
    want_sh("a=$#; jq", "a=$#; jq", 0, 0);
    want_sh("echo 'open", "echo      ", 0, '\'');
    want_sh("still open' jq", "            jq", '\'', 0);
    want_c("x = strcpy(a); // sprintf", "x = strcpy(a);           ", false, false);
    want_c("s = \"gets(\"; /* a", "s = \"     \";     ", false, true);
    want_c("b */ gets(x)", "     gets(x)", true, false);
    {
        char *ok_argv[] = { "sh", "-c", "[ \"$1\" = \"a'b;c\" ]", "sh", "a'b;c", NULL };
        char *no_argv[] = { "sh", "-c", "[ \"$1\" = x ]", "sh", "a'b;c", NULL };
        if (lint_run_argv(ok_argv, true) != 0) { puts("FAIL argv quote kept as data"); fails++; }
        if (lint_run_argv(no_argv, true) != 1) { puts("FAIL argv failure status"); fails++; }
    }
    want_quoted_names();
    if (!lint_idc('_') || lint_idc('-')) { puts("FAIL idc"); fails++; }
    puts(fails ? "lintlib-test: FAILED" : "lintlib-test: ok");
    return fails != 0;
}
