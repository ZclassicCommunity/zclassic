/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * zcl-agent-guard: is a .zclassic* or .zcash-params name where the node keeps its data? The path
 * components before the name (pre[0..np)) put it there when there are none (a relative name, after a
 * cd), or when they are the user's home, /home/<u>, /Users/<u>, /root, or the Windows spellings of
 * those (C:/Users/<u>, /c/Users/<u>, /mnt/c/Users/<u>). A name below a temp or test directory or an
 * unknown variable ($D/.zclassic) is somebody's scratch copy, not the node's. */

#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>

#include "rules_int.h"

static bool is_ci(const char *c, size_t n, const char *name)
{
    return strlen(name) == n && strncasecmp(c, name, n) == 0;
}

static bool starts_ci(const char *c, size_t n, const char *pre)
{
    size_t m = strlen(pre);
    return n >= m && strncasecmp(c, pre, m) == 0;
}

/* A component that names the user's home: ~, $HOME, ${HOME}, %USERPROFILE%, $env:USERPROFILE... */
static bool comp_is_home(const char *c, size_t n)
{
    static const char *const names[] = {"$home", "${home", "$userprofile", "${userprofile",
        "%userprofile%", "$env:userprofile", "${env:userprofile", "$env:home", "${env:home",
        "$homepath", "%homepath%", "$env:homepath", "$env{home}"};
    if (n >= 1 && c[0] == '~') return true;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (starts_ci(c, n, names[i])) return true;
    return false;
}

/* Index past leading "." and ".." components. */
static int skip_relative(const char *const *pre, const size_t *prl, int np)
{
    int i = 0;
    while (i < np && ((prl[i] == 1 && pre[i][0] == '.') ||
                      (prl[i] == 2 && pre[i][0] == '.' && pre[i][1] == '.')))
        i++;
    return i;
}

/* Index past a /mnt prefix and a one-letter drive (C:/, /c/, /mnt/c/). */
static int skip_drive(const char *const *pre, const size_t *prl, int np, int i)
{
    if (np - i >= 1 && is_ci(pre[i], prl[i], "mnt")) i++;
    if (np - i >= 1 && prl[i] == 1 && isalpha((unsigned char)pre[i][0])) i++;
    return i;
}

/* ${HOME:-/root}/.zclassic splits at : and / into "${HOME", "-", "root}". */
static bool braced_default(const char *const *pre, const size_t *prl, int i)
{
    return pre[i][0] == '$' && prl[i] > 1 && pre[i][1] == '{' && prl[i + 1] == 1 &&
           pre[i + 1][0] == '-' && comp_is_home(pre[i], prl[i]);
}

bool ag_dd_name_in_home(const char *const *pre, const size_t *prl, int np)
{
    int i = skip_relative(pre, prl, np);
    if (i == np) return true;
    i = skip_drive(pre, prl, np, i);
    switch (np - i) {
    case 1: return comp_is_home(pre[i], prl[i]) || is_ci(pre[i], prl[i], "root");
    case 2:
        return is_ci(pre[i], prl[i], "home") || is_ci(pre[i], prl[i], "users") ||
               comp_is_home(pre[i], prl[i]);
    case 3: return braced_default(pre, prl, i);
    default: return false;
    }
}

/* $TMPDIR, ${TMP}, $TEMP, $env:TEMP...: the variable names a temp location; and a variable whose
 * name says it is a scratch place ($work, $WORKDIR, $tmp_node, $testdir, $dd, $scratch, $sandbox,
 * $fixture): qa scripts keep their throwaway datadirs there, and a real datadir variable is
 * called $HOME, $DATADIR or $ZCL_DATADIR. */
bool ag_starts_tmpvar(const char *v)
{
    static const char *const vars[] = {"TMPDIR", "TMP", "TEMP", "TEMPDIR", "RUNNER_TEMP"};
    static const char *const hints[] = {"tmp", "temp", "test", "work", "scratch", "sandbox",
                                        "fixture", "regtest"};
    const char *p = v + 1;
    char name[40];
    size_t nl = 0;
    if (v[0] != '$') return false;
    if (*p == '{') p++;
    if (strncasecmp(p, "env:", 4) == 0) p += 4;
    for (size_t i = 0; i < sizeof vars / sizeof vars[0]; i++) {
        size_t n = strlen(vars[i]);
        if (strncasecmp(p, vars[i], n) == 0 && !isalnum((unsigned char)p[n]) && p[n] != '_')
            return true;
    }
    for (; nl + 1 < sizeof name && (isalnum((unsigned char)p[nl]) || p[nl] == '_'); nl++)
        name[nl] = (char)tolower((unsigned char)p[nl]);
    name[nl] = '\0';
    if (strcmp(name, "dd") == 0) return true;
    for (size_t i = 0; i < sizeof hints / sizeof hints[0]; i++)
        if (strstr(name, hints[i])) return true;
    return false;
}
