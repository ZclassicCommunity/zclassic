// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * mockrpc: localhost JSON-RPC stand-in for zclassicd (C23; replaces mockrpc.py).
 *
 * The wallet's only network primitive is Connection::doRPC, which POSTs plain HTTP
 * (Basic auth, JSON-RPC 1.0) and reads parsed["result"] off the reply, so a localhost
 * responder that answers each "method" with a canned "result" is a zero-product-change
 * drop-in for the daemon, reusable by every test layer (widget tests, the mocke2e lane).
 *
 *   cc -std=c2x -O2 -Wall -Wextra -o mockrpc wallet/tests/mock/mockrpc.c
 *   MOCK_PORT=18232 MOCK_SCENARIO=funded-synced MOCK_LOG=/tmp/mockrpc.requests.log ./mockrpc
 *
 * Environment: MOCK_PORT (18232), MOCK_SCENARIO (funded-synced), MOCK_LOG (file next to
 * the binary: mockrpc.requests.log), MOCK_FIXTURES (directory next to the binary:
 * fixtures). It listens on 127.0.0.1 only, ignores Basic auth, answers one request at a
 * time, appends every request body (compacted to one line) to MOCK_LOG, and stops on
 * SIGTERM/SIGINT or GET /__shutdown. GET anything else is a health read.
 *
 * Per method, first hit wins: <fixtures>/<scenario>/<method>.json (the bare RESULT
 * value; the server wraps it), then the built-in DEFAULTS, then -32601 Method not found.
 * Malformed request JSON gets -32700 Parse error. getwalletsummary is derived from the
 * scenario's z_gettotalbalance (absent: -32601, which the GUI treats as an old daemon).
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_REQUEST (1u << 20)

static const struct { const char *method, *result; } DEFAULTS[] = {
    {"dumpprivkey", "\"Ky5gd0MOCKtPriVkEYpLaCeHoLdErForTestsOnly1111111111111\""},
    {"z_exportkey", "\"secret-extended-key-main1MOCKzExtSpendKeyPlaceholder0000\""},
    {"importprivkey", "null"},
    {"z_importkey", "null"},
    // The wallet defaults receive/reply-to to Sapling, so this MUST be a zs address.
    {"z_getnewaddress", "\"zs1newmockaddr0sapling000000000000000000000000000000000000000000000000\""},
    {"getnewaddress", "\"t1NewMockTransparentAddr000000000000\""},
    {"z_getoperationstatus", "[]"},
    {"z_sendmany", "\"opid-00000000-0000-0000-0000-00000000mock\""},
    {"z_listreceivedbyaddress", "[]"},
    {"getnetworksolps", "0"},
    {"stop", "\"ZClassic server stopping\""},
};

static volatile sig_atomic_t g_stop;
static const char *g_scenario, *g_fixtures, *g_log;
static unsigned g_port;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

typedef struct { char *p; size_t n, cap; } buf;

static bool buf_add(buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->n + n + 1) cap *= 2;
        char *q = realloc(b->p, cap);
        if (!q) return false;
        b->p = q;
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
    return true;
}
static bool buf_str(buf *b, const char *s) { return buf_add(b, s, strlen(s)); }

// Append s as a JSON string literal (with quotes).
static bool buf_json_string(buf *b, const char *s, size_t n)
{
    bool ok = buf_str(b, "\"");
    for (size_t i = 0; i < n && ok; i++) {
        unsigned char c = (unsigned char)s[i];
        char t[8];
        if (c == '"' || c == '\\') { t[0] = '\\'; t[1] = (char)c; ok = buf_add(b, t, 2); }
        else if (c < 0x20) { snprintf(t, sizeof t, "\\u%04x", c); ok = buf_add(b, t, 6); }
        else ok = buf_add(b, s + i, 1);
    }
    return ok && buf_str(b, "\"");
}

// ---- a minimal JSON reader: just enough to find top-level members and validate shape ----

static const char *skip_ws(const char *p, const char *e) { while (p < e && isspace((unsigned char)*p)) p++; return p; }

// End of the JSON value starting at p (strings, objects, arrays, scalars); NULL when malformed.
static const char *value_end(const char *p, const char *e, int depth)
{
    if (depth > 64 || p >= e) return NULL;
    if (*p == '"') {
        for (p++; p < e; p++) {
            if (*p == '\\') p++;
            else if (*p == '"') return p + 1;
        }
        return NULL;
    }
    if (*p == '{' || *p == '[') {
        char close = *p == '{' ? '}' : ']';
        bool object = *p == '{';
        p = skip_ws(p + 1, e);
        if (p < e && *p == close) return p + 1;
        for (;;) {
            if (object) {
                if (p >= e || *p != '"') return NULL;
                p = value_end(p, e, depth + 1);
                if (!p) return NULL;
                p = skip_ws(p, e);
                if (p >= e || *p != ':') return NULL;
                p = skip_ws(p + 1, e);
            }
            p = value_end(p, e, depth + 1);
            if (!p) return NULL;
            p = skip_ws(p, e);
            if (p >= e) return NULL;
            if (*p == close) return p + 1;
            if (*p != ',') return NULL;
            p = skip_ws(p + 1, e);
        }
    }
    const char *s = p;
    while (p < e && !strchr(",:]} \t\r\n", *p)) p++;
    return p > s ? p : NULL;
}

// Locate member `key` of the top-level object in [p, e); sets *vs/*ve to its raw value.
// Returns 1 found, 0 absent, -1 not a (well-formed) object.
static int object_member(const char *p, const char *e, const char *key, const char **vs, const char **ve)
{
    p = skip_ws(p, e);
    if (p >= e || *p != '{') return -1;
    const char *end = value_end(p, e, 0);
    if (!end || skip_ws(end, e) != e) return -1;
    size_t kn = strlen(key);
    int found = 0;
    p = skip_ws(p + 1, end);
    while (p < end && *p != '}') {
        const char *ke = value_end(p, end, 1);
        const char *ks = p;
        p = skip_ws(ke, end) + 1;          // past ':'
        p = skip_ws(p, end);
        const char *vend = value_end(p, end, 1);
        if (!found && ke - ks == (ptrdiff_t)kn + 2 && !memcmp(ks + 1, key, kn)) {
            *vs = p;
            *ve = vend;
            found = 1;
        }
        p = skip_ws(vend, end);
        if (*p == ',') p = skip_ws(p + 1, end);
    }
    return found;
}

// ---- fixtures ----

static char *read_all(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    buf b = {0};
    char tmp[4096];
    size_t r;
    while ((r = fread(tmp, 1, sizeof tmp, f)) > 0)
        if (!buf_add(&b, tmp, r)) { free(b.p); fclose(f); return NULL; }
    fclose(f);
    if (!b.p && !buf_str(&b, "")) return NULL;
    while (b.n && isspace((unsigned char)b.p[b.n - 1])) b.p[--b.n] = '\0';
    *len = b.n;
    return b.p;
}

static bool safe_method(const char *m) { if (!*m) return false; for (; *m; m++) if (!isalnum((unsigned char)*m) && *m != '_') return false; return true; }

// The bare result for a method: scenario file beats DEFAULTS. Caller frees *out.
static bool lookup(const char *method, char **out, size_t *len)
{
    *out = NULL;
    if (!safe_method(method)) return false;
    char path[4096];
    if ((size_t)snprintf(path, sizeof path, "%s/%s/%s.json", g_fixtures, g_scenario, method) < sizeof path) {
        *out = read_all(path, len);
        if (*out) return true;
    }
    for (size_t i = 0; i < sizeof DEFAULTS / sizeof DEFAULTS[0]; i++)
        if (!strcmp(DEFAULTS[i].method, method)) {
            *out = strdup(DEFAULTS[i].result);
            *len = strlen(DEFAULTS[i].result);
            return *out != NULL;
        }
    return false;
}

// ---- request handling ----

static void log_request(const char *body, size_t n)
{
    FILE *f = fopen(g_log, "a");
    if (!f) { fprintf(stderr, "mockrpc: could not write log %s: %s\n", g_log, strerror(errno)); return; }
    bool in_str = false;
    for (size_t i = 0; i < n; i++) {
        char c = body[i];
        if (in_str) {
            fputc(c, f);
            if (c == '\\' && i + 1 < n) fputc(body[++i], f);
            else if (c == '"') in_str = false;
        } else if (c == '"') {
            in_str = true;
            fputc(c, f);
        } else if (!isspace((unsigned char)c)) {
            fputc(c, f);
        }
    }
    fputc('\n', f);
    fclose(f);
}

static void envelope(buf *out, const char *result, const char *error, const char *id, size_t idn)
{
    buf_str(out, "{\"result\": ");
    buf_str(out, result);
    buf_str(out, ", \"error\": ");
    buf_str(out, error);
    buf_str(out, ", \"id\": ");
    if (id) buf_add(out, id, idn); else buf_str(out, "null");
    buf_str(out, "}");
}

static void rpc_error(buf *out, int code, const char *fmt_msg, const char *arg, size_t argn, const char *id, size_t idn)
{
    buf e = {0};
    char head[64];
    snprintf(head, sizeof head, "{\"code\": %d, \"message\": ", code);
    buf_str(&e, head);
    buf m = {0};
    buf_str(&m, fmt_msg);
    if (arg) buf_add(&m, arg, argn);
    buf_json_string(&e, m.p ? m.p : "", m.n);
    buf_str(&e, "}");
    envelope(out, "null", e.p, id, idn);
    free(e.p);
    free(m.p);
}

// getwalletsummary derived from z_gettotalbalance, like the real RPC's three displayed totals.
static bool wallet_summary(buf *out, const char *id, size_t idn)
{
    char *bal;
    size_t bn;
    if (!lookup("z_gettotalbalance", &bal, &bn)) return false;
    const char *v[3][2] = {{0}};
    static const char *const keys[3] = {"transparent", "private", "total"};
    bool is_obj = true;
    for (int i = 0; i < 3 && is_obj; i++) {
        int r = object_member(bal, bal + bn, keys[i], &v[i][0], &v[i][1]);
        if (r < 0) is_obj = false;
    }
    if (!is_obj) { free(bal); return false; }
    buf r = {0};
    buf_str(&r, "{");
    static const char *const names[3] = {"transparent", "private", "total"};
    for (int i = 0; i < 3; i++) {
        if (i == 1) buf_str(&r, "\"transparentunconfirmed\": \"0.00\", \"transparentimmature\": \"0.00\", ");
        buf_str(&r, "\""); buf_str(&r, names[i]); buf_str(&r, "\": ");
        if (v[i][0]) buf_add(&r, v[i][0], (size_t)(v[i][1] - v[i][0])); else buf_str(&r, "\"0.00\"");
        buf_str(&r, ", ");
    }
    buf_str(&r, "\"shieldedcached\": true, \"txcount\": 0, \"height\": 0, \"bestblockhash\": \"");
    for (int i = 0; i < 32; i++) buf_str(&r, "00");
    buf_str(&r, "\"}");
    envelope(out, r.p, "null", id, idn);
    free(r.p);
    free(bal);
    return true;
}

static void handle_post(const char *body, size_t n, buf *out)
{
    log_request(body, n);                      // Basic auth is ignored: record and dispatch
    const char *ms, *me, *is = NULL, *ie = NULL;
    int rm = object_member(body, body + n, "method", &ms, &me);
    if (rm < 0) {
        envelope(out, "null", "{\"code\": -32700, \"message\": \"Parse error\"}", NULL, 0);
        return;
    }
    object_member(body, body + n, "id", &is, &ie);
    size_t idn = is ? (size_t)(ie - is) : 0;
    char method[256] = "";
    if (rm == 1 && me - ms >= 2 && *ms == '"' && (size_t)(me - ms) - 2 < sizeof method) {
        memcpy(method, ms + 1, (size_t)(me - ms) - 2);
        method[(size_t)(me - ms) - 2] = '\0';
    }
    if (!strcmp(method, "getwalletsummary") && wallet_summary(out, is, idn)) return;
    char *res;
    size_t rn;
    if (!lookup(method, &res, &rn)) {
        rpc_error(out, -32601, "Method not found: ", method, strlen(method), is, idn);
        return;
    }
    envelope(out, res, "null", is, idn);
    free(res);
}

static void send_response(int fd, int code, const char *body, size_t n)
{
    char head[160];
    int h = snprintf(head, sizeof head,
                     "HTTP/1.0 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                     code, code == 200 ? "OK" : "Bad Request", n);
    const char *parts[2] = {head, body};
    size_t lens[2] = {(size_t)h, n};
    for (int i = 0; i < 2; i++)
        for (size_t off = 0; off < lens[i];) {
            ssize_t w = send(fd, parts[i] + off, lens[i] - off, 0);
            if (w <= 0) return;
            off += (size_t)w;
        }
}

// Read one request (head + Content-Length body). Returns false when the client went away.
static bool read_request(int fd, buf *req, size_t *head_len, size_t *body_len)
{
    char tmp[4096];
    for (;;) {
        char *end = req->p ? strstr(req->p, "\r\n\r\n") : NULL;
        if (end) {
            *head_len = (size_t)(end - req->p) + 4;
            size_t cl = 0;
            for (char *l = req->p; l < end;) {
                char *nl = strstr(l, "\r\n");
                if (!nl) nl = end;
                if (!strncasecmp(l, "content-length:", 15)) cl = (size_t)strtoul(l + 15, NULL, 10);
                l = nl + 2;
            }
            if (cl > MAX_REQUEST) return false;
            *body_len = cl;
            if (req->n >= *head_len + cl) return true;
        }
        if (req->n > MAX_REQUEST) return false;
        ssize_t r = recv(fd, tmp, sizeof tmp, 0);
        if (r <= 0 || !buf_add(req, tmp, (size_t)r)) return false;
    }
}

static void serve(int fd)
{
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    buf req = {0}, out = {0};
    size_t hl = 0, bl = 0;
    if (read_request(fd, &req, &hl, &bl)) {
        if (!strncmp(req.p, "POST ", 5)) {
            handle_post(req.p + hl, bl, &out);
            send_response(fd, 200, out.p, out.n);
        } else if (!strncmp(req.p, "GET /__shutdown", 15)) {
            const char *m = "{\"ok\": true, \"stopping\": true}";
            send_response(fd, 200, m, strlen(m));
            g_stop = 1;
        } else {
            buf_str(&out, "{\"ok\": true, \"scenario\": ");
            buf_json_string(&out, g_scenario, strlen(g_scenario));
            char num[48];
            snprintf(num, sizeof num, ", \"port\": %u, \"log\": ", g_port);
            buf_str(&out, num);
            buf_json_string(&out, g_log, strlen(g_log));
            buf_str(&out, "}");
            send_response(fd, 200, out.p, out.n);
        }
    }
    free(req.p);
    free(out.p);
    close(fd);
}

static char *dir_default(const char *argv0, const char *leaf)
{
    const char *slash = strrchr(argv0, '/');
    size_t dn = slash ? (size_t)(slash - argv0) : 1;
    char *p = malloc(dn + strlen(leaf) + 3);
    if (!p) return NULL;
    if (slash) { memcpy(p, argv0, dn); p[dn] = '\0'; } else strcpy(p, ".");
    strcat(p, "/");
    strcat(p, leaf);
    return p;
}

int main(int argc, char **argv)
{
    (void)argc;
    const char *e;
    g_port = (e = getenv("MOCK_PORT")) && *e ? (unsigned)strtoul(e, NULL, 10) : 18232;
    g_scenario = (e = getenv("MOCK_SCENARIO")) && *e ? e : "funded-synced";
    g_log = (e = getenv("MOCK_LOG")) && *e ? e : dir_default(argv[0], "mockrpc.requests.log");
    g_fixtures = (e = getenv("MOCK_FIXTURES")) && *e ? e : dir_default(argv[0], "fixtures");
    if (!g_log || !g_fixtures || g_port == 0 || g_port > 65535) {
        fprintf(stderr, "mockrpc: bad configuration\n");
        return 2;
    }
    char scen[4096];
    snprintf(scen, sizeof scen, "%s/%s", g_fixtures, g_scenario);
    if (access(scen, R_OK) != 0)
        fprintf(stderr, "mockrpc: WARNING scenario dir not found: %s (only DEFAULTS will answer)\n", scen);

    struct sigaction sa = {.sa_handler = on_signal};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);                   // a client that hangs up must not kill the mock

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (ls < 0 || setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        perror("mockrpc: socket");
        return 1;
    }
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)g_port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) != 0 || listen(ls, 16) != 0) {
        fprintf(stderr, "mockrpc: cannot listen on 127.0.0.1:%u: %s\n", g_port, strerror(errno));
        return 1;
    }
    fprintf(stderr, "mockrpc: listening on 127.0.0.1:%u  scenario=%s  log=%s\n", g_port, g_scenario, g_log);
    fflush(stderr);
    while (!g_stop) {
        struct pollfd p = {.fd = ls, .events = POLLIN};
        int r = poll(&p, 1, 200);
        if (r > 0 && (p.revents & POLLIN)) {
            int c = accept(ls, NULL, NULL);
            if (c >= 0) serve(c);
        }
    }
    close(ls);
    fprintf(stderr, "mockrpc: stopped\n");
    return 0;
}
