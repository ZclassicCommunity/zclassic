// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * KEY-1 guard (C23; replaces the former qa/key1-guard.py).
 *
 * Protects the wallet on-disk serialization surface and the wallet-summary RPC
 * surface from ever leaking a shielded secret. The HARD KEY INVARIANT: no
 * viewing / incoming-viewing / spending key, seed, ivk/fvk/nsk/ask/ovk/dk, note
 * plaintext (rcm/rho/d/memo) or nullifier-secret may be serialized to a new
 * on-disk artifact or emitted by any new RPC. The only new datum is a
 * non-invertible CAmount.
 *
 * Scans, by file and pattern (robust to line drift):
 *   - the SerializationOp bodies of SproutNoteData, SaplingNoteData and CWalletTx
 *     in src/wallet/wallet.h
 *   - every Read or Write call line in src/wallet/walletdb.cpp
 *   - the bodies of getwalletsummary / waitwalletchange in src/wallet/rpcwallet.cpp
 *     (if present)
 * and flags any whole identifier of the DENYLIST. Three pre-existing key-adjacent
 * serialized lines are ALLOWLISTED by exact (whitespace-free) text, so any new
 * occurrence, even of the same tokens on a different line, still trips the guard.
 * walletdb.cpp legitimately defines the audited encrypted-key store, so its
 * key-bearing Read or Write call lines are pinned in qa/key1-walletdb-baseline.txt and
 * only NEW ones fail; regenerate with --write-baseline and review the diff.
 *
 * usage: key1-guard [--root DIR] [--self-test | --write-baseline]
 *   exit 0 clean, 1 violation, 2 setup error (missing file, drifted pin)
 */
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const DENYLIST[] = {
    "SpendingKey", "ExpandedSpendingKey", "SaplingExtendedSpendingKey", "SproutSpendingKey",
    "FullViewingKey", "SaplingFullViewingKey", "IncomingViewingKey", "ViewingKey",
    "CKey", "CPrivKey", "vchPrivKey", "HDSeed", "RawHDSeed", "seed",
    "ivk", "fvk", "nsk", "ask", "ovk", "dk", "rcm", "rho",
    "SaplingNotePlaintext", "SproutNotePlaintext", "memo",
};
#define N_DENY (sizeof DENYLIST / sizeof DENYLIST[0])

static const struct { const char *region, *text; } ALLOWLIST[] = {
    {"SaplingNoteData", "READWRITE(ivk);"},
    {"SaplingNoteData", "READWRITE(nullifier);"},
    {"SproutNoteData", "READWRITE(nullifier);"},
};
#define N_ALLOW (sizeof ALLOWLIST / sizeof ALLOWLIST[0])

typedef struct { const char *p; size_t n; } span;   // a non-owning text range

static bool is_ident(int c) { return isalnum((unsigned char)c) || c == '_'; }

// Whitespace-free copy of a line, for layout-robust literal comparison.
static char *normalize(span l)
{
    char *o = malloc(l.n + 1);
    if (!o) { fprintf(stderr, "key1-guard: out of memory\n"); exit(2); }
    size_t k = 0;
    for (size_t i = 0; i < l.n; i++)
        if (!isspace((unsigned char)l.p[i]))
            o[k++] = l.p[i];
    o[k] = '\0';
    return o;
}

static span strip(span l)
{
    while (l.n && isspace((unsigned char)*l.p)) { l.p++; l.n--; }
    while (l.n && isspace((unsigned char)l.p[l.n - 1])) l.n--;
    return l;
}

static bool starts_with(span l, const char *s) { size_t n = strlen(s); return l.n >= n && !memcmp(l.p, s, n); }

// Does `tok` occur in `l` as a whole identifier? Tokens with an uppercase letter match
// case-sensitively, the short lowercase fragments (ivk, seed, dk, ...) case-insensitively.
static bool has_token(span l, const char *tok)
{
    size_t tn = strlen(tok);
    bool exact = false;
    for (size_t i = 0; i < tn; i++)
        exact |= isupper((unsigned char)tok[i]) != 0;
    for (size_t i = 0; i + tn <= l.n; i++) {
        size_t k = 0;
        for (; k < tn; k++) {
            int a = (unsigned char)l.p[i + k], b = (unsigned char)tok[k];
            if (exact ? a != b : tolower(a) != tolower(b)) break;
        }
        if (k != tn) continue;
        if (i > 0 && is_ident(l.p[i - 1])) continue;
        if (i + tn < l.n && is_ident(l.p[i + tn])) continue;
        return true;
    }
    return false;
}

// Names of the denylisted tokens present in a line, comma separated, "" when none.
static const char *hits(span l, char *buf, size_t cap)
{
    size_t k = 0;
    buf[0] = '\0';
    for (size_t t = 0; t < N_DENY; t++)
        if (has_token(l, DENYLIST[t])) {
            int w = snprintf(buf + k, cap - k, "%s%s", k ? "," : "", DENYLIST[t]);
            if (w < 0 || (size_t)w >= cap - k) break;
            k += (size_t)w;
        }
    return buf;
}

static bool is_allowlisted(const char *region, span line)
{
    char *nl = normalize(line);
    bool ok = false;
    for (size_t i = 0; i < N_ALLOW && !ok; i++) {
        char *want = normalize((span){ALLOWLIST[i].text, strlen(ALLOWLIST[i].text)});
        ok = !strcmp(ALLOWLIST[i].region, region) && !strcmp(want, nl);
        free(want);
    }
    free(nl);
    return ok;
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0;
    char *b = malloc(cap);
    while (b) {
        size_t r = fread(b + n, 1, cap - n - 1, f);
        n += r;
        if (r == 0) break;
        if (n + 1 >= cap) { cap *= 2; b = realloc(b, cap); }
    }
    fclose(f);
    if (b) b[n] = '\0';
    return b;
}

// Position of `word` at an identifier boundary in [from, end), or NULL.
static const char *find_word(const char *from, const char *word)
{
    size_t wn = strlen(word);
    for (const char *p = strstr(from, word); p; p = strstr(p + 1, word))
        if ((p == from || !is_ident(p[-1])) && !is_ident(p[wn]))
            return p;
    return NULL;
}

static const char *skip_ws(const char *p) { while (isspace((unsigned char)*p)) p++; return p; }

// Body between the first '{' at/after `p` and its matching '}'.
static bool brace_body(const char *p, span *out)
{
    const char *open = strchr(p, '{');
    if (!open) return false;
    int depth = 0;
    for (const char *q = open; *q; q++) {
        if (*q == '{') depth++;
        else if (*q == '}' && --depth == 0) { *out = (span){open + 1, (size_t)(q - open - 1)}; return true; }
    }
    return false;
}

// Body of class NAME's SerializationOp (first one after "class NAME").
static bool serializationop_body(const char *text, const char *name, span *out)
{
    size_t nn = strlen(name);
    for (const char *c = find_word(text, "class"); c; c = find_word(c + 5, "class")) {
        const char *q = c + 5;
        if (!isspace((unsigned char)*q)) continue;
        q = skip_ws(q);
        if (strncmp(q, name, nn) || is_ident(q[nn])) continue;
        const char *s = q + nn;
        for (const char *sp = find_word(s, "SerializationOp"); sp; sp = find_word(sp + 1, "SerializationOp")) {
            if (*skip_ws(sp + 15) == '(')
                return brace_body(sp + 15, out);
        }
        return false;
    }
    return false;
}

// Body of "UniValue NAME(" ... "{...}", false when the function does not exist.
static bool rpc_body(const char *text, const char *name, span *out)
{
    size_t nn = strlen(name);
    for (const char *u = find_word(text, "UniValue"); u; u = find_word(u + 8, "UniValue")) {
        const char *q = u + 8;
        if (!isspace((unsigned char)*q)) continue;
        q = skip_ws(q);
        if (strncmp(q, name, nn) || is_ident(q[nn])) continue;
        if (*skip_ws(q + nn) == '(')
            return brace_body(q + nn, out);
    }
    return false;
}

// Is this a Read<Cap>...( / Write<Cap>...( line?
static bool is_readwrite_line(span l)
{
    for (size_t i = 0; i < l.n; i++) {
        if (i > 0 && is_ident(l.p[i - 1])) continue;
        size_t k = 0;
        if (l.n - i > 4 && !memcmp(l.p + i, "Read", 4)) k = i + 4;
        else if (l.n - i > 5 && !memcmp(l.p + i, "Write", 5)) k = i + 5;
        else continue;
        if (k >= l.n || !isupper((unsigned char)l.p[k])) continue;
        while (k < l.n && is_ident(l.p[k])) k++;
        while (k < l.n && isspace((unsigned char)l.p[k])) k++;
        if (k < l.n && l.p[k] == '(') return true;
    }
    return false;
}

static bool next_line(span *rest, span *line)
{
    if (!rest->n) return false;
    const char *nl = memchr(rest->p, 0x0a, rest->n);
    size_t l = nl ? (size_t)(nl - rest->p) : rest->n;
    *line = (span){rest->p, l};
    size_t adv = nl ? l + 1 : l;
    rest->p += adv;
    rest->n -= adv;
    return true;
}

// Declares the iteration state in the enclosing block; use at most once per block.
#define FOR_EACH_LINE(body, line) span rest_##line = (body); span line; while (next_line(&rest_##line, &line))

static int g_viol;

static void violation(const char *region, span line, const char *tokens)
{
    if (!g_viol)
        fprintf(stderr, "KEY-1 guard: FAIL -- key-leak violation(s):\n");
    g_viol++;
    span s = strip(line);
    fprintf(stderr, "  [%s] %.*s  -> denylisted: %s\n", region, (int)s.n, s.p, tokens);
}

// One SerializationOp-style region: skip blanks and // comments, honour the allowlist.
static void scan_region(const char *region, const char *allow_region, span body)
{
    char tok[512];
    FOR_EACH_LINE(body, line) {
        span s = strip(line);
        if (!s.n || starts_with(s, "//")) continue;
        if (allow_region && is_allowlisted(allow_region, line)) continue;
        if (*hits(line, tok, sizeof tok)) violation(region, line, tok);
    }
}

static bool in_baseline(const char *baseline, const char *norm)
{
    size_t n = strlen(norm);
    for (const char *p = baseline; p && *p;) {
        const char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && !memcmp(p, norm, n)) return true;
        p = e ? e + 1 : NULL;
    }
    return false;
}

static int self_test(const char *wallet_h)
{
    span body;
    if (!serializationop_body(wallet_h, "SaplingNoteData", &body)) {
        fprintf(stderr, "KEY-1 guard: class SaplingNoteData / SerializationOp not found\n");
        return 2;
    }
    // The REAL SaplingNoteData body plus a poisoned line, scanned like the real region.
    char *copy = malloc(body.n + 64);
    if (!copy) return 2;
    memcpy(copy, body.p, body.n);
    snprintf(copy + body.n, 64, "\n        READWRITE(SpendingKey);\n");
    span poisoned = {copy, strlen(copy)};
    int poison = 0, other = 0;
    char tok[512];
    FOR_EACH_LINE(poisoned, line) {
        span s = strip(line);
        if (!s.n || starts_with(s, "//") || is_allowlisted("SaplingNoteData", line)) continue;
        if (*hits(line, tok, sizeof tok)) {
            if (strstr(tok, "SpendingKey")) poison++;
            else { other++; fprintf(stderr, "[self-test] allowlisted line wrongly flagged: %.*s\n", (int)s.n, s.p); }
        }
    }
    free(copy);
    puts("[self-test] injected 'READWRITE(SpendingKey);' into a copy of the");
    puts("[self-test] real SaplingNoteData.SerializationOp body.");
    if (other) { puts("[self-test] FAIL: the allowlist pinning is broken"); return 1; }
    if (poison != 1) { puts("[self-test] FAIL: guard did NOT catch the injected SpendingKey"); return 1; }
    puts("[self-test] PASS: guard reported the poison (and only the poison)");
    return 0;
}

int main(int argc, char **argv)
{
    const char *root = ".";
    bool selftest = false, write_baseline = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--self-test")) selftest = true;
        else if (!strcmp(argv[i], "--write-baseline")) write_baseline = true;
        else if (!strcmp(argv[i], "--root") && i + 1 < argc) root = argv[++i];
        else { fprintf(stderr, "usage: key1-guard [--root DIR] [--self-test | --write-baseline]\n"); return 2; }
    }
    char p_h[4096], p_db[4096], p_rpc[4096], p_base[4096];
    snprintf(p_h, sizeof p_h, "%s/src/wallet/wallet.h", root);
    snprintf(p_db, sizeof p_db, "%s/src/wallet/walletdb.cpp", root);
    snprintf(p_rpc, sizeof p_rpc, "%s/src/wallet/rpcwallet.cpp", root);
    snprintf(p_base, sizeof p_base, "%s/qa/key1-walletdb-baseline.txt", root);
    char *wallet_h = read_file(p_h), *walletdb = read_file(p_db), *rpcwallet = read_file(p_rpc);
    if (!wallet_h || !walletdb || !rpcwallet) {
        fprintf(stderr, "KEY-1 guard: missing file %s\n", !wallet_h ? p_h : !walletdb ? p_db : p_rpc);
        return 2;
    }
    if (selftest) return self_test(wallet_h);

    span sapling, sprout, cwtx;
    if (!serializationop_body(wallet_h, "SaplingNoteData", &sapling) ||
        !serializationop_body(wallet_h, "SproutNoteData", &sprout) ||
        !serializationop_body(wallet_h, "CWalletTx", &cwtx)) {
        fprintf(stderr, "KEY-1 guard: a guarded class or its SerializationOp was not found in %s\n", p_h);
        return 2;
    }
    // Every pinned line must still exist verbatim, so the pins keep tracking the serializer.
    for (size_t i = 0; i < N_ALLOW; i++) {
        span body = !strcmp(ALLOWLIST[i].region, "SaplingNoteData") ? sapling : sprout;
        char *want = normalize((span){ALLOWLIST[i].text, strlen(ALLOWLIST[i].text)});
        bool present = false;
        FOR_EACH_LINE(body, line) {
            char *nl = normalize(line);
            present |= !strcmp(nl, want);
            free(nl);
        }
        free(want);
        if (!present) {
            fprintf(stderr, "KEY-1 guard: allowlisted line vanished from %s: '%s'\n"
                            "  (pins must track the real serializer; update the guard)\n",
                    ALLOWLIST[i].region, ALLOWLIST[i].text);
            return 2;
        }
    }

    if (write_baseline) {
        FILE *f = fopen(p_base, "w");
        if (!f) { fprintf(stderr, "KEY-1 guard: cannot write %s\n", p_base); return 2; }
        fputs("# KEY-1 baseline: the whitespace-free key-bearing Read*/Write* lines of\n"
              "# src/wallet/walletdb.cpp (the audited key store). Only lines NOT listed fail the guard.\n"
              "# Regenerate with: key1-guard --write-baseline, and review the diff.\n", f);
        span all = {walletdb, strlen(walletdb)};
        char tok[512];
        FOR_EACH_LINE(all, line) {
            span s = strip(line);
            if (!s.n || starts_with(s, "//") || !is_readwrite_line(line) || !*hits(line, tok, sizeof tok)) continue;
            char *nl = normalize(line);
            fprintf(f, "%s\n", nl);
            free(nl);
        }
        fclose(f);
        printf("KEY-1 guard: wrote %s\n", p_base);
        return 0;
    }

    scan_region("SproutNoteData.SerializationOp", "SproutNoteData", sprout);
    scan_region("SaplingNoteData.SerializationOp", "SaplingNoteData", sapling);
    scan_region("CWalletTx.SerializationOp", "CWalletTx", cwtx);

    char *baseline = read_file(p_base);
    if (!baseline) {
        fprintf(stderr, "KEY-1 guard: missing %s (create it with --write-baseline)\n", p_base);
        return 2;
    }
    span all = {walletdb, strlen(walletdb)};
    char tok[512];
    FOR_EACH_LINE(all, line) {
        span s = strip(line);
        if (!s.n || starts_with(s, "//") || !is_readwrite_line(line)) continue;
        if (!*hits(line, tok, sizeof tok)) continue;
        char *nl = normalize(line);
        bool known = in_baseline(baseline, nl);
        free(nl);
        if (!known) violation("walletdb.cpp", line, tok);
    }

    static const char *const rpcs[] = {"getwalletsummary", "waitwalletchange"};
    for (size_t i = 0; i < 2; i++) {
        span body;
        if (!rpc_body(rpcwallet, rpcs[i], &body)) continue;
        char region[64];
        snprintf(region, sizeof region, "%s()", rpcs[i]);
        scan_region(region, NULL, body);
    }

    if (g_viol) {
        fputs("\nHARD KEY INVARIANT: no key/seed/ivk/fvk/nsk/ask/ovk/dk/rcm/rho/\n"
              "note-plaintext/memo may be serialized or RPC-emitted by these\n"
              "regions. Only a non-invertible CAmount may be added.\n", stderr);
        return 1;
    }
    puts("KEY-1 guard: PASS -- no denylisted token serialized or RPC-emitted");
    puts("  scanned: SproutNoteData/SaplingNoteData/CWalletTx SerializationOp,");
    puts("           walletdb.cpp Read*/Write*, getwalletsummary/waitwalletchange");
    return 0;
}
