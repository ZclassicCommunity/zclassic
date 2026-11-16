/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Standalone (no C++, no daemon) check of the C23 Equihash bridge against
 * real headers, for any platform the vendored code is compiled on (used to
 * run the verifier natively on Windows/MinGW, where the daemon is not built
 * in this unit).
 *
 *   eh_headers_check <headers.hex> [max_headers]
 *
 * <headers.hex>: one network-serialized block header per line, hex
 * (getblockheader <hash> false). For each header and every BLAKE2b batch
 * tier the host supports, requires: the real solution verifies, and a
 * one-bit mutation of the solution does not. Exit status 0 only if all hold.
 *
 * Build (from src/c23/equihash):
 *   V=vendor/core/modules/crypto
 *   cc -std=gnu17 -O2 -include glue/zc23_eh_namespace.h -iquote glue \
 *      -iquote $V/include -iquote . test/eh_headers_check.c zc23_equihash.c \
 *      $V/src/blake2b.c $V/src/blake2b_avx2.c $V/src/equihash.c \
 *      $V/src/simd_dispatch.c -o eh_headers_check
 */

#include "zc23_equihash.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* nVersion(4) prev(32) merkle(32) finalsapling(32) nTime(4) nBits(4) nNonce(32) */
#define HEADER_INPUT_LEN 140

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Returns the decoded length, or (size_t)-1 on a malformed line. */
static size_t unhex(const char *s, size_t slen, unsigned char *out, size_t cap)
{
    if (slen % 2 != 0 || slen / 2 > cap)
        return (size_t)-1;
    for (size_t i = 0; i < slen / 2; i++) {
        int hi = hexval((unsigned char)s[2 * i]), lo = hexval((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return (size_t)-1;
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return slen / 2;
}

/* Parse header: 140 committed bytes, CompactSize solution length, solution. */
static int parse_header(const unsigned char *raw, size_t len, const unsigned char **sol, size_t *sol_len)
{
    if (len < HEADER_INPUT_LEN + 1)
        return 0;
    size_t p = HEADER_INPUT_LEN;
    uint64_t n = raw[p++];
    if (n == 0xfd) {
        if (p + 2 > len) return 0;
        n = (uint64_t)raw[p] | (uint64_t)raw[p + 1] << 8;
        p += 2;
    } else if (n >= 0xfe) {
        return 0; /* no zclassicd solution is that large */
    }
    if (p + n != len)
        return 0;
    *sol = raw + p;
    *sol_len = (size_t)n;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <headers.hex> [max_headers]\n", argv[0]);
        return 2;
    }
    long max_headers = argc > 2 ? atol(argv[2]) : -1;
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 2;
    }

    int tiers[3], ntiers = 0;
    for (int t = 0; t <= 2; t++)
        if (zc23_equihash_select_tier(t) == t)
            tiers[ntiers++] = t;
    zc23_equihash_select_tier(-1);

    static char line[8192];
    static unsigned char raw[4096];
    unsigned long n = 0, n200 = 0, n192 = 0, bad_real = 0, bad_mut = 0, malformed = 0;
    clock_t c0 = clock();
    while (fgets(line, sizeof(line), f)) {
        size_t l = strcspn(line, "\r\n");
        if (l == 0)
            continue;
        if (max_headers >= 0 && (long)n >= max_headers)
            break;
        size_t rl = unhex(line, l, raw, sizeof(raw));
        const unsigned char *sol = NULL;
        size_t sol_len = 0;
        if (rl == (size_t)-1 || !parse_header(raw, rl, &sol, &sol_len)) {
            malformed++;
            n++;
            continue;
        }
        unsigned nn, kk;
        if (sol_len == 1344) { nn = 200; kk = 9; n200++; }
        else if (sol_len == 400) { nn = 192; kk = 7; n192++; }
        else { malformed++; n++; continue; }

        unsigned char mut[1344];
        memcpy(mut, sol, sol_len);
        size_t bit = (n * 2654435761u) % (sol_len * 8);
        mut[bit / 8] ^= (unsigned char)(1u << (bit % 8));

        for (int i = 0; i < ntiers; i++) {
            zc23_equihash_select_tier(tiers[i]);
            int r = zc23_equihash_verify(nn, kk, raw, HEADER_INPUT_LEN, sol, sol_len);
            if (r != ZC23_EH_VALID) {
                bad_real++;
                fprintf(stderr, "REAL REJECTED line=%lu tier=%s r=%d\n", n, zc23_equihash_tier_name(), r);
            }
            int m = zc23_equihash_verify(nn, kk, raw, HEADER_INPUT_LEN, mut, sol_len);
            if (m != ZC23_EH_INVALID) {
                bad_mut++;
                fprintf(stderr, "MUTANT NOT REJECTED line=%lu bit=%zu tier=%s r=%d\n", n, bit, zc23_equihash_tier_name(), m);
            }
        }
        zc23_equihash_select_tier(-1);
        n++;
    }
    fclose(f);
    double secs = (double)(clock() - c0) / CLOCKS_PER_SEC;
    printf("eh_headers_check: headers=%lu (200,9)=%lu (192,7)=%lu malformed=%lu tiers=%d real_rejected=%lu mutants_accepted=%lu cpu_secs=%.1f\n",
           n, n200, n192, malformed, ntiers, bad_real, bad_mut, secs);
    for (int i = 0; i < ntiers; i++) {
        zc23_equihash_select_tier(tiers[i]);
        printf("  tier %d: %s\n", tiers[i], zc23_equihash_tier_name());
    }
    return (bad_real == 0 && bad_mut == 0 && malformed == 0 && n > 0) ? 0 : 1;
}
