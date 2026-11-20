// Copyright (c) 2014 Wladimir J. van der Laan
// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * generate-seeds: turn contrib/seeds/nodes_main.txt and nodes_test.txt into
 * src/chainparamsseeds.h (C23; replaces the former generate-seeds.py).
 *
 *   cc -std=c2x -O2 -Wall -Wextra -o generate-seeds contrib/seeds/generate-seeds.c
 *   ./generate-seeds contrib/seeds > src/chainparamsseeds.h
 *
 * Input lines (a '#' starts a comment, blank lines are ignored):
 *   <ip>  <ip>:<port>  [<ipv6>]  [<ipv6>]:<port>
 *   <16-char base32>.onion[:<port>]        (Tor v2 onion, OnionCat form)
 *   0xDDBBCCAA                             (IPv4, old little-endian pnSeeds form)
 *
 * Every entry becomes a SeedSpec6: 16 address bytes (IPv4 and onion addresses
 * wrapped in an IPv6 address) and a port. The output bytes are identical to the
 * old script's. Addresses that do not fit 16 bytes (Tor v3 onions) are rejected
 * with an error, never silently dropped.
 */
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t PCH_IPV4[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
static const uint8_t PCH_ONIONCAT[6] = {0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43};

static const char *g_file = "";
static unsigned g_line = 0;

static int fail(const char *what, const char *text)
{
    fprintf(stderr, "generate-seeds: %s:%u: %s: '%s'\n", g_file, g_line, what, text);
    return -1;
}

// RFC 4648 base32, case-insensitive, no padding accepted: exactly 16 chars -> 10 bytes.
static int onion_to_bytes(const char *name, size_t len, uint8_t out[10])
{
    if (len != 16)
        return -1;
    uint64_t acc = 0;
    unsigned bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        int c = toupper((unsigned char)name[i]), v;
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= '2' && c <= '7')
            v = c - '2' + 26;
        else
            return -1;
        acc = (acc << 5) | (uint64_t)v;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out[n++] = (uint8_t)(acc >> bits);
            acc &= ((uint64_t)1 << bits) - 1;
        }
    }
    return n == 10 ? 0 : -1;
}

// Parse an unsigned decimal in [0, max]; the whole string must be consumed.
static int parse_uint(const char *s, size_t len, unsigned long max, unsigned long *out)
{
    if (len == 0 || len > 10)
        return -1;
    unsigned long v = 0;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)s[i]))
            return -1;
        v = v * 10 + (unsigned long)(s[i] - '0');
    }
    if (v > max)
        return -1;
    *out = v;
    return 0;
}

static int hex_digit(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_ipv4(const char *s, size_t len, uint8_t out[4])
{
    size_t start = 0;
    int parts = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || s[i] == '.') {
            unsigned long v;
            if (parts >= 4 || parse_uint(s + start, i - start, 255, &v))
                return -1;
            out[parts++] = (uint8_t)v;
            start = i + 1;
        }
    }
    return parts == 4 ? 0 : -1;
}

// Colon-separated hex groups with at most one "::" (no embedded IPv4, as before).
static int parse_ipv6(const char *s, size_t len, uint8_t out[16])
{
    uint8_t head[16], tail[16];
    size_t nh = 0, nt = 0;
    int seen_gap = 0;
    size_t i = 0;
    if (len >= 2 && s[0] == ':' && s[1] == ':') {
        seen_gap = 1;
        i = 2;
    } else if (len >= 1 && s[0] == ':') {
        return -1;
    }
    while (i < len) {
        size_t j = i;
        unsigned v = 0;
        while (j < len && s[j] != ':') {
            int d = hex_digit(s[j]);
            if (d < 0 || j - i >= 4)
                return -1;
            v = v * 16 + (unsigned)d;
            j++;
        }
        if (j == i)
            return -1;
        uint8_t *dst = seen_gap ? tail : head;
        size_t *n = seen_gap ? &nt : &nh;
        if (*n + 2 > 16)
            return -1;
        dst[(*n)++] = (uint8_t)(v >> 8);
        dst[(*n)++] = (uint8_t)(v & 0xff);
        if (j == len)
            break;
        if (j + 1 < len && s[j + 1] == ':') {   // "::"
            if (seen_gap)
                return -1;
            seen_gap = 1;
            i = j + 2;
        } else {
            i = j + 1;
            if (i == len)
                return -1;                        // trailing single ':'
        }
    }
    size_t total = nh + nt;
    if ((!seen_gap && total != 16) || (seen_gap && total >= 16))
        return -1;
    memset(out, 0, 16);
    memcpy(out, head, nh);
    memcpy(out + 16 - nt, tail, nt);
    return 0;
}

static int name_to_ipv6(const char *host, size_t len, uint8_t out[16])
{
    if (len > 6 && memcmp(host + len - 6, ".onion", 6) == 0) {
        memcpy(out, PCH_ONIONCAT, 6);
        if (onion_to_bytes(host, len - 6, out + 6))
            return fail("not a 16-character (Tor v2) onion address", host);
        return 0;
    }
    if (memchr(host, '.', len)) {
        memcpy(out, PCH_IPV4, 12);
        return parse_ipv4(host, len, out + 12) ? fail("bad IPv4 address", host) : 0;
    }
    if (memchr(host, ':', len))
        return parse_ipv6(host, len, out) ? fail("bad IPv6 address", host) : 0;
    if (len >= 2 && host[0] == '0' && host[1] == 'x') {
        if (len != 10)
            return fail("0x form needs exactly 8 hex digits", host);
        uint8_t b[4];
        for (int k = 0; k < 4; k++) {
            int hi = hex_digit(host[2 + 2 * k]), lo = hex_digit(host[3 + 2 * k]);
            if (hi < 0 || lo < 0)
                return fail("bad hex digit", host);
            b[3 - k] = (uint8_t)(hi * 16 + lo);   // little-endian: reversed
        }
        memcpy(out, PCH_IPV4, 12);
        memcpy(out + 12, b, 4);
        return 0;
    }
    return fail("could not parse address", host);
}

// <host>, <host>:<port>, [<ipv6>], [<ipv6>]:<port>, or a bare IPv6 (more than one ':').
static int parse_spec(char *s, unsigned defaultport, uint8_t host[16], unsigned *port)
{
    const char *h = s, *p = NULL;
    size_t hl;
    size_t len = strlen(s);
    if (s[0] == '[') {
        char *close = strchr(s, ']');
        if (!close)
            return fail("missing ']'", s);
        h = s + 1;
        hl = (size_t)(close - h);
        if (close[1] == ':')
            p = close + 2;
        else if (close[1] != '\0')
            return fail("junk after ']'", s);
        if (hl == 0 || strspn(h, "0123456789abcdefABCDEF:") < hl)
            return fail("bad bracketed IPv6 address", s);
    } else {
        size_t colons = 0;
        for (size_t i = 0; i < len; i++)
            colons += s[i] == ':';
        if (colons > 1) {
            hl = len;
        } else {
            char *c = strchr(s, ':');
            hl = c ? (size_t)(c - s) : len;
            if (c)
                p = c + 1;
        }
    }
    *port = defaultport;
    if (p && *p) {
        unsigned long v;
        if (parse_uint(p, strlen(p), 65535, &v) || v == 0)
            return fail("bad port", s);
        *port = (unsigned)v;
    }
    char tmp[256];
    if (hl == 0 || hl >= sizeof tmp)
        return fail("bad host", s);
    memcpy(tmp, h, hl);
    tmp[hl] = '\0';
    return name_to_ipv6(tmp, hl, host);
}

static int process_nodes(FILE *out, const char *path, const char *structname, unsigned defaultport)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "generate-seeds: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    g_file = path;
    g_line = 0;
    fprintf(out, "static SeedSpec6 %s[] = {\n", structname);
    char line[1024];
    int first = 1, rc = 0;
    while (fgets(line, sizeof line, f)) {
        g_line++;
        if (!strchr(line, '\n') && !feof(f)) {
            rc = fail("line too long", "");
            break;
        }
        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';
        char *b = line;
        while (isspace((unsigned char)*b))
            b++;
        size_t n = strlen(b);
        while (n && isspace((unsigned char)b[n - 1]))
            b[--n] = '\0';
        if (!n)
            continue;
        uint8_t host[16];
        unsigned port;
        if (parse_spec(b, defaultport, host, &port)) {
            rc = -1;
            break;
        }
        if (!first)
            fputs(",\n", out);
        first = 0;
        fputs("    {{", out);
        for (int i = 0; i < 16; i++)
            fprintf(out, "%s0x%02x", i ? "," : "", host[i]);
        fprintf(out, "}, %u}", port);
    }
    if (ferror(f)) {
        fprintf(stderr, "generate-seeds: read error on %s\n", path);
        rc = -1;
    }
    fclose(f);
    fputs("\n};\n", out);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dir with nodes_main.txt and nodes_test.txt>\n", argv[0]);
        return 1;
    }
    char path[4096];
    FILE *g = stdout;
    fputs("#ifndef BITCOIN_CHAINPARAMSSEEDS_H\n"
          "#define BITCOIN_CHAINPARAMSSEEDS_H\n"
          "/**\n"
          " * List of fixed seed nodes for the bitcoin network\n"
          " * AUTOGENERATED by contrib/seeds/generate-seeds.c\n"
          " *\n"
          " * Each line contains a 16-byte IPv6 address and a port.\n"
          " * IPv4 as well as onion addresses are wrapped inside a IPv6 address accordingly.\n"
          " */\n", g);
    if ((size_t)snprintf(path, sizeof path, "%s/nodes_main.txt", argv[1]) >= sizeof path)
        return 1;
    if (process_nodes(g, path, "pnSeed6_main", 8033))
        return 1;
    fputs("\n", g);
    if ((size_t)snprintf(path, sizeof path, "%s/nodes_test.txt", argv[1]) >= sizeof path)
        return 1;
    if (process_nodes(g, path, "pnSeed6_test", 18033))
        return 1;
    fputs("#endif // BITCOIN_CHAINPARAMSSEEDS_H\n", g);
    if (fflush(g) || ferror(g)) {
        fprintf(stderr, "generate-seeds: write error\n");
        return 1;
    }
    return 0;
}
