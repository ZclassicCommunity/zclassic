/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * zcl-agent-guard: which port and host a URL or host:port word names. A request that carries a spend
 * or key-export method is a test call when -regtest is explicit or the port is not a production
 * node's (the regtest node listens on 18023). */

#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>

#include "rules_int.h"

/* The word looks like a host or URL: scheme://, localhost, [v6], or digit.digit (an IPv4 address).
 * user:pass, a time and a path do not. */
static bool host_like(const char *w)
{
    if (strstr(w, "://") || strstr(w, "localhost") || strchr(w, '[')) return true;
    for (const char *p = w; *p; p++)
        if (isdigit((unsigned char)p[0]) && p[1] == '.' && isdigit((unsigned char)p[2])) return true;
    return false;
}

/* The digits after a ':' at p, as a port when they end the word or a URL path; -1 otherwise. */
static long port_after_colon(const char *p)
{
    const char *q = p + 1;
    long n = 0;
    int d = 0;
    if (*q == '$') return -2;
    for (; isdigit((unsigned char)*q) && d < 6; q++, d++) n = n * 10 + (*q - '0');
    if (d > 0 && (*q == '\0' || strchr("/?#\"' \t", *q))) return n;
    return -1;
}

long ag_word_port(const char *w)
{
    if (!host_like(w)) return -1;
    for (const char *p = w; *p; p++) {
        long port;
        if (*p != ':' || p[1] == '/') continue;
        port = port_after_colon(p);
        if (port != -1) return port;
    }
    return -1;
}

bool ag_prod_port(long port)
{
    return port == 8023 || port == 8232 || port == 8233 || port == 8332 ||
           (port >= 8033 && port <= 8035);
}

static bool has_ci(const char *s, const char *needle)
{
    size_t n = strlen(needle);
    for (; *s; s++)
        if (strncasecmp(s, needle, n) == 0) return true;
    return false;
}

bool ag_local_host(const char *w)
{
    static const char *const names[] = {"127.0.0.1", "localhost", "[::1]", "0.0.0.0"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (has_ci(w, names[i])) return true;
    return false;
}
