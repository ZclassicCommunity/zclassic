/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard_rules.c@9a191ef7b, Apache-2.0, changed (zclassicd's rules; see
 * zcutil/tools/NOTICE). zcl-agent-guard: spend and key-export method names in an RPC request body or
 * a word (split out of rules.c). */

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "rules_int.h"

bool ag_is_word_char(char ch)
{
    return isalnum((unsigned char)ch) || ch == '_';
}

bool ag_is_method(const char *s, size_t n)
{
    static const char *const methods[] = {
        "sendtoaddress", "sendfrom", "sendmany", "z_sendmany", "z_shieldcoinbase",
        "z_mergetoaddress", "sendrawtransaction", "dumpprivkey", "dumpwallet",
        "z_exportkey", "z_exportwallet", "z_exportviewingkey", "backupwallet",
        "walletpassphrase", "walletpassphrasechange", "encryptwallet"};
    for (size_t k = 0; k < sizeof methods / sizeof methods[0]; k++)
        if (strlen(methods[k]) == n && memcmp(s, methods[k], n) == 0) return true;
    return false;
}

/* A JSON-RPC body: a "method" key whose value is a refused method. */
static bool body_has_method_raw(const char *s, size_t len)
{
    static const char *const skip = "\"'\\ \t\n";
    for (size_t i = 1; i + 6 <= len; i++) {
        size_t j = i + 6, k;
        if (memcmp(s + i, "method", 6) != 0 || !strchr("\"'\\", s[i - 1])) continue;
        while (j < len && strchr(skip, s[j])) j++;
        if (j >= len || s[j] != ':') continue;
        j++;
        while (j < len && strchr(skip, s[j])) j++;
        for (k = j; k < len && ag_is_word_char(s[k]); k++) {}
        if (ag_is_method(s + j, k - j)) return true;
    }
    return false;
}

/* A JSON body with its unicode escapes (backslash, u, four hex digits) decoded: the node's UniValue
 * decodes them, so a method name may be spelled with them. Only the ASCII range matters. */
static char *decode_u_escapes(const char *s, size_t len, size_t *outn)
{
    char *d;
    size_t n = 0;
    if (!memchr(s, '\\', len)) return NULL;
    d = malloc(len + 1); // raw-alloc-ok:build-tool
    if (!d) {
        ag_mark_complex();
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '\\' && i + 5 < len && s[i + 1] == 'u' && isxdigit((unsigned char)s[i + 2]) &&
            isxdigit((unsigned char)s[i + 3]) && isxdigit((unsigned char)s[i + 4]) &&
            isxdigit((unsigned char)s[i + 5])) {
            char hex[5] = {s[i + 2], s[i + 3], s[i + 4], s[i + 5], '\0'};
            unsigned long cp = strtoul(hex, NULL, 16);
            d[n++] = cp < 0x80 && cp ? (char)cp : '?';
            i += 5;
        } else {
            d[n++] = s[i];
        }
    }
    d[n] = '\0';
    *outn = n;
    return d;
}

bool ag_body_has_method(const char *s, size_t len)
{
    size_t n = 0;
    char *d;
    bool hit;
    if (body_has_method_raw(s, len)) return true;
    d = decode_u_escapes(s, len, &n);
    if (!d) return false;
    hit = body_has_method_raw(d, n);
    free(d);
    return hit;
}

/* The whole payload is a bare method name (curl -d z_sendmany). */
static bool bare_method(const char *s)
{
    size_t n = strlen(s);
    while (n && strchr("\"' \t\n", *s)) {
        s++;
        n--;
    }
    while (n && strchr("\"' \t\n", s[n - 1])) n--;
    return n && ag_is_method(s, n);
}

bool ag_payload_has_method(const char *s)
{
    return ag_body_has_method(s, strlen(s)) || bare_method(s);
}

/* Any run of word characters in w is a spend or key-export method name. */
static bool word_has_method_raw(const char *w)
{
    for (size_t i = 0; w[i];) {
        size_t j = i;
        while (ag_is_word_char(w[j])) j++;
        if (j > i && ag_is_method(w + i, j - i)) return true;
        i = j > i ? j : i + 1;
    }
    return false;
}

bool ag_word_has_method(const char *w)
{
    size_t n = 0;
    char *d;
    bool hit;
    if (word_has_method_raw(w)) return true;
    d = decode_u_escapes(w, strlen(w), &n);
    if (!d) return false;
    hit = word_has_method_raw(d);
    free(d);
    return hit;
}

static bool is_body_flag(const char *w)
{
    static const char *const flags[] = {"-d", "--data", "--data-raw", "--data-binary",
                                        "--data-ascii", "--json", "--post-data",
                                        "--body-data"};
    for (size_t i = 0; i < sizeof flags / sizeof flags[0]; i++)
        if (strcmp(w, flags[i]) == 0) return true;
    return false;
}

/* The request body argument of a curl/wget flag at a[i]: the next word, the
 * text after '=', or the text glued to -d; NULL when a[i] carries no body. */
const char *ag_body_arg(char **a, int na, int i)
{
    const char *eq;
    if (is_body_flag(a[i])) return i + 1 < na ? a[i + 1] : NULL;
    if (strncmp(a[i], "--", 2) == 0) {
        eq = strchr(a[i], '=');
        if (!eq || (size_t)(eq - a[i]) > 16) return NULL;
        return strncmp(a[i], "--data", 6) == 0 || strncmp(a[i], "--post-data", 11) == 0 ||
                       strncmp(a[i], "--json", 6) == 0 || strncmp(a[i], "--body-data", 11) == 0
                   ? eq + 1
                   : NULL;
    }
    return strncmp(a[i], "-d", 2) == 0 && a[i][2] ? a[i] + 2 : NULL;
}

/* A quoted string that is a spend or export method, or starts with one (-ArgumentList 'dumpprivkey
 * t1'): the method held in a hashtable (method='dumpprivkey') or an argument array. */
bool ag_quoted_method(const char *q, size_t n)
{
    size_t i = 0, j;
    while (i < n && (q[i] == ' ' || q[i] == '\t')) i++;
    for (j = i; j < n && ag_is_word_char(q[j]); j++) {}
    return j > i && ag_is_method(q + i, j - i);
}

/* SQL text that writes: a write verb, or PRAGMA with an assignment (sqlq / sqlite3 on a datadir). */
bool ag_sql_has_write(const char *s, size_t len)
{
    static const char *const verbs[] = {"insert", "update", "delete", "drop", "alter",
                                        "create", "replace", "vacuum", "attach", "pragma"};
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && ag_is_word_char(s[j])) j++;
        if (j == i) {
            i++;
            continue;
        }
        for (size_t k = 0; k < sizeof verbs / sizeof verbs[0]; k++) {
            if (strlen(verbs[k]) != j - i || strncasecmp(s + i, verbs[k], j - i) != 0) continue;
            if (k < 9 || memchr(s + j, '=', len - j)) return true;
        }
        i = j;
    }
    return false;
}
