/* Unit test of the lintlib comment and string stripping. Copyright 2026 Rhett Creighton - MIT. */
#define _POSIX_C_SOURCE 200809L
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

/* lint_win_quote_argv: the CreateProcess command line, compared byte for byte. */
static void want_q(char *const argv[], size_t cap, const char *out, int len)
{
    char buf[2100];
    int got = lint_win_quote_argv(argv, buf, cap);
    if (got != len || (len >= 0 && strcmp(buf, out))) { printf("FAIL quote '%s' -> '%s' (%d, want %d)\n", argv[0], len >= 0 ? buf : "", got, len); fails++; }
}

#define Q1(arg, out) want_q((char *[]){ arg, NULL }, 2100, out, (int)strlen(out))

static void want_quoting(void)
{
    static char big[1000];
    memset(big, 'a', 999);
    big[999] = '\0';
    Q1("word", "word");
    Q1("", "\"\"");
    Q1("a b", "\"a b\"");
    Q1("a\tb", "\"a\tb\"");
    Q1("a\"b", "\"a\\\"b\"");
    Q1("trailing\\", "trailing\\");
    Q1("\\\"", "\"\\\\\\\"\"");
    Q1("C:\\Program Files\\x", "\"C:\\Program Files\\x\"");
    Q1("a b\\", "\"a b\\\\\"");
    Q1("a\\\\b", "a\\\\b");
    Q1("%PATH%", "%PATH%");
    Q1("a&b|c<d>e^f", "a&b|c<d>e^f");
    Q1("!x", "!x");
    Q1("it's", "\"it's\"");
    Q1("*.py", "\"*.py\"");
    Q1("HEAD~1", "\"HEAD~1\"");
    want_q((char *[]){ "git", "-C", "a b", "ls-files", "-z", NULL }, 2100, "git -C \"a b\" ls-files -z", 24);
    want_q((char *[]){ big, NULL }, 1000, big, 999);
    want_q((char *[]){ big, NULL }, 999, NULL, -1);
    want_q((char *[]){ "abc", "d", NULL }, 5, NULL, -1);
    want_q((char *[]){ "a b", NULL }, 5, NULL, -1);
    want_q((char *[]){ "x", NULL }, 0, NULL, -1);
}

int main(void)
{
    want_quoting();
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
