/* Unit test of the lintlib comment and string stripping. Copyright 2026 Rhett Creighton - MIT. */
#include "lintlib.h"

#include <stdio.h>
#include <string.h>

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
    if (!lint_idc('_') || lint_idc('-')) { puts("FAIL idc"); fails++; }
    puts(fails ? "lintlib-test: FAILED" : "lintlib-test: ok");
    return fails != 0;
}
