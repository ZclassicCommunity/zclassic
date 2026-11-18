/* znamscript: print ZNAM OP_RETURN scripts as hex, built by the vendored Z23
 * builder, and decode them with the vendored Z23 parser.
 *
 * A test tool (qa/rpc-tests/znam_index.sh compiles it). Not installed, not
 * linked into any zclassic binary.
 *
 *   znamscript register <name> <type> <value>
 *   znamscript update   <name> <type> <value>
 *   znamscript record   <name> <type> <value>      (SET_RECORD)
 *   znamscript transfer <name> <new_owner>
 *   znamscript renew    <name>
 *   znamscript text     <name> <key> <value>       (SET_TEXT)
 *   znamscript parse    <script_hex>               prints "command name type value" or "invalid"
 *
 * <type> is onion zaddr taddr btc ltc doge content, or 1..7. Prints nothing
 * and exits 1 when the vendored builder refuses (invalid name, over 223 bytes). */

#include "zcl_znam_index.h"

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

static int type_of(const char *s)
{
    static const char *const names[] = {"", "onion", "zaddr", "taddr", "btc", "ltc", "doge", "content"};
    for (int i = 1; i <= 7; i++)
        if (strcmp(s, names[i]) == 0)
            return i;
    if (s[0] >= '1' && s[0] <= '7' && s[1] == '\0')
        return s[0] - '0';
    return 0;
}

static int emit(int cmd, const char *name, int type, const char *value, const char *owner,
                const char *key, const char *text)
{
    uint8_t buf[512];
    size_t n = zcl_znam_build(cmd, name, (uint8_t)type, value, owner, key, text, buf, sizeof(buf));
    if (n == 0)
        return 1;
    for (size_t i = 0; i < n; i++)
        printf("%02x", buf[i]);
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 5 && (!strcmp(argv[1], "register") || !strcmp(argv[1], "update") || !strcmp(argv[1], "record"))) {
        int cmd = !strcmp(argv[1], "register") ? ZCL_ZNAM_CMD_REGISTER
                : !strcmp(argv[1], "update")   ? ZCL_ZNAM_CMD_UPDATE
                                               : ZCL_ZNAM_CMD_SET_RECORD;
        int type = type_of(argv[3]);
        if (type == 0)
            return 2;
        return emit(cmd, argv[2], type, argv[4], NULL, NULL, NULL);
    }
    if (argc == 4 && !strcmp(argv[1], "transfer"))
        return emit(ZCL_ZNAM_CMD_TRANSFER, argv[2], 0, NULL, argv[3], NULL, NULL);
    if (argc == 3 && !strcmp(argv[1], "renew"))
        return emit(ZCL_ZNAM_CMD_RENEW, argv[2], 0, NULL, NULL, NULL, NULL);
    if (argc == 5 && !strcmp(argv[1], "text"))
        return emit(ZCL_ZNAM_CMD_SET_TEXT, argv[2], 0, NULL, NULL, argv[3], argv[4]);
    if (argc == 3 && !strcmp(argv[1], "parse")) {
        size_t n = strlen(argv[2]);
        if (n % 2 || n / 2 > 1024)
            return 2;
        uint8_t buf[1024];
        for (size_t i = 0; i < n / 2; i++) {
            int hi = hexval((unsigned char)argv[2][2 * i]), lo = hexval((unsigned char)argv[2][2 * i + 1]);
            if (hi < 0 || lo < 0)
                return 2;
            buf[i] = (uint8_t)(hi * 16 + lo);
        }
        struct zcl_znam_parsed m;
        if (!zcl_znam_parse_message(buf, n / 2, &m)) {
            printf("invalid\n");
            return 0;
        }
        switch (m.command) {
        case ZCL_ZNAM_CMD_TRANSFER: printf("%d %s %s\n", m.command, m.name, m.new_owner); break;
        case ZCL_ZNAM_CMD_RENEW: printf("%d %s\n", m.command, m.name); break;
        case ZCL_ZNAM_CMD_SET_TEXT: printf("%d %s %s %s\n", m.command, m.name, m.text_key, m.text_value); break;
        default: printf("%d %s %d %s\n", m.command, m.name, m.target_type, m.target_value); break;
        }
        return 0;
    }
    fprintf(stderr, "usage: see the header of znamscript.c\n");
    return 2;
}
