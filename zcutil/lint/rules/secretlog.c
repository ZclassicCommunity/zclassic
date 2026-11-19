/* zcl-lint secretlog: custody rule. Log and print calls in the node and wallet sources must not mention
 * secret-bearing names in their argument expressions.
 *
 * Copyright 2026 Rhett Creighton - MIT (zclassicd).
 * Derived from Z23 tools/lint/lintc/gate_secret_printf_fences.c and gate_wallet_log_privacy*
 * @9a191ef7b1184e14d9116362dff7def64cd300e3 (rule shape); modified, not verbatim. See zcutil/lint/NOTICE.
 *
 * Scope: C and C++ under src/ and wallet/src/, minus vendored code and the unit-test trees (src/test, src/gtest).
 * Calls: LogPrintf LogPrint printf fprintf qDebug and std::cout statements. Comments and string literals are
 * blanked first, so only the argument expressions count. Override with `// log-ok: reason` on any line of the call.
 * Findings are listed as file:line before the ratchet verdict; a nonzero baseline is a custody finding to review.
 */
#define _POSIX_C_SOURCE 200809L
#include "../lintlib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Names that must match a whole identifier (case-sensitive). */
static const char *const exact_names[] = {
    "strWalletPass", "SecureString", "CKey", "GetPrivKey", "vchSecret", "ExtendedSpendingKey", "SpendingKey",
    "EncodeSecret", "EncodeSpendingKey" };
/* Words that match an identifier when they are one of its camelCase or snake_case words (case-insensitive). */
static const char *const word_names[] = { "seed", "mnemonic", "passphrase" };
static const char *const call_names[] = { "LogPrintf", "LogPrint", "printf", "fprintf", "qDebug" };

static bool in_scope(const char *p)
{
    if (lint_is_vendored(p) || !lint_is_c_source(p)) return false;
    if (lint_has_prefix(p, "src/test/") || lint_has_prefix(p, "src/gtest/")) return false;
    return lint_has_prefix(p, "src/") || lint_has_prefix(p, "wallet/src/");
}

/* Is `w` (lowercase) one of the words of identifier [s, s+n)? Words split at '_', digits and camelCase humps;
 * a run of capitals is one word. */
static bool has_word(const char *s, size_t n, const char *w)
{
    size_t k = strlen(w), i = 0;
    while (i < n) {
        while (i < n && (s[i] == '_' || isdigit((unsigned char)s[i]))) i++;
        size_t st = i;
        if (i < n && isupper((unsigned char)s[i])) {
            i++;
            if (i < n && isupper((unsigned char)s[i]))
                while (i < n && isupper((unsigned char)s[i]) && !(i + 1 < n && islower((unsigned char)s[i + 1]))) i++;
        }
        while (i < n && islower((unsigned char)s[i])) i++;
        if (i == st) { i++; continue; }
        if (i - st == k) {
            size_t j;
            for (j = 0; j < k; j++) if (tolower((unsigned char)s[st + j]) != w[j]) break;
            if (j == k) return true;
        }
    }
    return false;
}

static bool secret_token(const char *s, size_t n)
{
    for (size_t i = 0; i < sizeof exact_names / sizeof exact_names[0]; i++)
        if (strlen(exact_names[i]) == n && !memcmp(s, exact_names[i], n)) return true;
    if (n > 11 && !memcmp(s + n - 11, "SpendingKey", 11)) return true;   /* SaplingExtendedSpendingKey, SproutSpendingKey */
    for (size_t i = 0; i < sizeof word_names / sizeof word_names[0]; i++)
        if (has_word(s, n, word_names[i])) return true;
    return false;
}

/* Is a secret mentioned in the argument text [a, a+n)? (comments and strings already blanked) */
static bool args_secret(const char *a, size_t n)
{
    for (size_t i = 0; i < n;) {
        if (lint_idc((unsigned char)a[i]) && !isdigit((unsigned char)a[i])) {
            size_t j = i;
            while (j < n && lint_idc((unsigned char)a[j])) j++;
            if (secret_token(a + i, j - i)) return true;
            if (j - i == 6 && !memcmp(a + i, "HexStr", 6)) {
                size_t k = j;
                while (k < n && isspace((unsigned char)a[k])) k++;
                if (k < n && a[k] == '(') {
                    k++;
                    while (k < n && isspace((unsigned char)a[k])) k++;
                    if (k + 3 <= n && !memcmp(a + k, "key", 3)) return true;
                }
            }
            i = j;
        } else i++;
    }
    return false;
}

static long line_of(const char *txt, size_t off)
{
    long l = 1;
    for (size_t i = 0; i < off; i++) if (txt[i] == '\n') l++;
    return l;
}

/* A call or std::cout statement starts at s[i]; returns the name length. */
static bool call_at(const char *s, size_t i, size_t *namelen, bool *is_cout)
{
    *is_cout = false;
    if (i && (lint_idc((unsigned char)s[i - 1]) || s[i - 1] == '.' || s[i - 1] == '>')) return false;
    if (i && s[i - 1] == ':') return false;   /* qualified names are handled at the "std" start */
    if (!strncmp(s + i, "std::cout", 9) || !strncmp(s + i, "std::cerr", 9)) { *namelen = 9; *is_cout = true; return true; }
    /* bare cout/cerr after `using namespace std` */
    if ((!strncmp(s + i, "cout", 4) || !strncmp(s + i, "cerr", 4)) && !lint_idc((unsigned char)s[i + 4])) {
        *namelen = 4; *is_cout = true; return true;
    }
    for (size_t c = 0; c < sizeof call_names / sizeof call_names[0]; c++) {
        size_t k = strlen(call_names[c]);
        if (!strncmp(s + i, call_names[c], k) && !lint_idc((unsigned char)s[i + k])) {
            size_t j = i + k;
            while (s[j] == ' ' || s[j] == '\t') j++;
            if (s[j] != '(') return false;
            *namelen = k;
            return true;
        }
    }
    return false;
}

/* Does any raw line overlapping [from, to) carry "log-ok:"? */
static bool raw_line_ok(const char *raw, size_t from, size_t to)
{
    size_t ls = from;
    while (ls > 0 && raw[ls - 1] != '\n') ls--;
    size_t le = to;
    while (raw[le] && raw[le] != '\n') le++;
    for (size_t i = ls; i + 7 <= le; i++) if (!strncmp(raw + i, "log-ok:", 7)) return true;
    return false;
}

static long scan_file(const char *path, const char *raw, const char *scrub)
{
    long hits = 0;
    size_t len = strlen(scrub);
    for (size_t i = 0; i < len; i++) {
        size_t nl;
        bool cout;
        if (!call_at(scrub, i, &nl, &cout)) continue;
        size_t a = i + nl, e;
        if (cout) {
            for (e = a; e < len && scrub[e] != ';'; e++) {}
        } else {
            while (scrub[a] != '(') a++;
            int depth = 0;
            for (e = a; e < len; e++) {
                if (scrub[e] == '(') depth++;
                else if (scrub[e] == ')' && --depth == 0) break;
            }
        }
        if (e > len) e = len;
        if (args_secret(scrub + a, e - a) && !raw_line_ok(raw, i, e)) {
            printf("secretlog: %s:%ld: secret-bearing name in a log or print call\n", path, line_of(raw, i));
            hits++;
        }
        i = a;
    }
    return hits;
}

int lint_rule_secretlog(bool update)
{
    struct lint_rows cur = { NULL, 0, 0 };
    size_t scanned = 0;
    for (size_t i = 0; i < lint_nfiles; i++) {
        if (!in_scope(lint_files[i])) continue;
        char *raw = lint_slurp(lint_files[i], NULL);
        if (!raw) continue;
        scanned++;
        char *scrub = lint_xstrdup(raw);
        bool blk = false;
        for (char *ln = scrub; *ln;) {
            char *nlp = strchr(ln, '\n');
            if (nlp) *nlp = '\0';
            lint_scrub_c_line(ln, &blk);
            if (!nlp) break;
            *nlp = '\n';
            ln = nlp + 1;
        }
        long n = scan_file(lint_files[i], raw, scrub);
        if (n) lint_rows_add(&cur, lint_files[i], n);
        free(raw);
        free(scrub);
    }
    return lint_ratchet("secretlog", "secret-bearing names in log or print calls", &cur, scanned, update);
}
