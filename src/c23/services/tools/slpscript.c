/* slpscript: print SLP Token Type 1 OP_RETURN scripts as hex, built by the
 * vendored Z23 builder, and classify outputs with the wallet token guard.
 *
 * A test tool (qa/zcash/wallet_tokenguard_e2e.sh compiles it). Not installed,
 * not linked into any zclassic binary.
 *
 *   slpscript genesis <ticker> <name> <mint_baton_vout> <quantity>
 *   slpscript genesisdec <ticker> <name> <decimals> <mint_baton_vout> <quantity>
 *   slpscript mint    <token_id_hex> <mint_baton_vout> <quantity>
 *   slpscript send    <token_id_hex> <quantity> [<quantity> ...]
 *   slpscript roles   <num_vout> <script_hex>
 *
 * <token_id_hex> is the genesis txid as RPC prints it (64 hex digits). SLP
 * stores exactly those bytes, in that order.
 * `roles` prints one line per protected vout: "<vout> token" or "<vout> baton". */

#include "zcl_token_guard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Returns the number of bytes decoded, or (size_t)-1 on bad input. */
static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s);
    if (n % 2 != 0 || n / 2 > cap)
        return (size_t)-1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval((unsigned char)s[2 * i]);
        int lo = hexval((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return (size_t)-1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return n / 2;
}

static int print_script(const uint8_t *buf, size_t len)
{
    if (len == 0) {
        fprintf(stderr, "slpscript: the builder refused these arguments\n");
        return 1;
    }
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
    return 0;
}

static int usage(void)
{
    fprintf(stderr,
            "usage: slpscript genesis <ticker> <name> <mint_baton_vout> <quantity>\n"
            "       slpscript mint <token_id_hex> <mint_baton_vout> <quantity>\n"
            "       slpscript send <token_id_hex> <quantity> [<quantity> ...]\n"
            "       slpscript roles <num_vout> <script_hex>\n");
    return 2;
}

int main(int argc, char **argv)
{
    uint8_t buf[1024];
    uint8_t id[32];

    if (argc < 2)
        return usage();

    if (strcmp(argv[1], "genesis") == 0 && argc == 6) {
        return print_script(buf, zcl_token_guard_build_genesis(
            buf, sizeof(buf), argv[2], argv[3], "", NULL, 0,
            (uint8_t)strtoul(argv[4], NULL, 10), strtoull(argv[5], NULL, 10)));
    }
    if (strcmp(argv[1], "genesisdec") == 0 && argc == 7) {
        return print_script(buf, zcl_token_guard_build_genesis(
            buf, sizeof(buf), argv[2], argv[3], "", NULL,
            (uint8_t)strtoul(argv[4], NULL, 10),
            (uint8_t)strtoul(argv[5], NULL, 10), strtoull(argv[6], NULL, 10)));
    }
    if (strcmp(argv[1], "mint") == 0 && argc == 5) {
        if (unhex(argv[2], id, sizeof(id)) != 32)
            return usage();
        return print_script(buf, zcl_token_guard_build_mint(
            buf, sizeof(buf), id, (uint8_t)strtoul(argv[3], NULL, 10),
            strtoull(argv[4], NULL, 10)));
    }
    if (strcmp(argv[1], "send") == 0 && argc >= 4 && argc <= 4 + 19) {
        uint64_t q[20];
        int n = argc - 3;
        if (unhex(argv[2], id, sizeof(id)) != 32)
            return usage();
        for (int i = 0; i < n; i++)
            q[i] = strtoull(argv[3 + i], NULL, 10);
        return print_script(buf, zcl_token_guard_build_send(buf, sizeof(buf), id, q, n));
    }
    if (strcmp(argv[1], "roles") == 0 && argc == 4) {
        uint8_t roles[ZCL_TOKEN_GUARD_MAX_VOUT + 1];
        uint8_t txid[32];
        size_t num_vout = (size_t)strtoul(argv[2], NULL, 10);
        size_t len = unhex(argv[3], buf, sizeof(buf));
        if (len == (size_t)-1)
            return usage();
        memset(roles, 0, sizeof(roles));
        memset(txid, 0, sizeof(txid));
        zcl_token_guard_roles(buf, len, txid, num_vout, roles, sizeof(roles));
        for (size_t i = 0; i < sizeof(roles); i++) {
            if (roles[i] == ZCL_TOKEN_ROLE_TOKEN)
                printf("%zu token\n", i);
            else if (roles[i] == ZCL_TOKEN_ROLE_MINT_BATON)
                printf("%zu baton\n", i);
        }
        return 0;
    }
    return usage();
}
