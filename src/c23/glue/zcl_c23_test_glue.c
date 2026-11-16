/* zclassicd-owned TEST-ONLY glue for standalone builds (no daemon, no
 * libsodium, no OpenSSL). NEVER linked into zclassicd. Provides the same
 * seams as zcl_c23_glue.c:
 *   - RNG from the OS CSPRNG (BCryptGenRandom on Windows, /dev/urandom
 *     elsewhere), abort() on failure
 *   - memory_cleanse via volatile stores
 *   - logging to stderr, counted, off unless ZCL_C23_TEST_LOG=1
 *   - network id "main" unless ZCL_C23_TEST_NETWORK is set */
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "base/log_level.h"
#include "chain/chainparams.h"
#include "zcl_c23_glue.h"

void memory_cleanse(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--)
        *v++ = 0;
}

void GetRandBytes(unsigned char *b, size_t n)
{
    if (n == 0)
        return;
    if (!b)
        abort();
#ifdef _WIN32
    if (BCryptGenRandom(NULL, b, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        abort();
#else
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd < 0)
        abort();
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r <= 0)
            abort();
        got += (size_t)r;
    }
    close(fd);
#endif
}

atomic_ulong zcl_c23_test_log_lines;

enum zcl_log_level zcl_log_level_get(void)
{
    const char *e = getenv("ZCL_C23_TEST_LOG");
    return (e && e[0] == '1') ? ZCL_LOG_INFO : ZCL_LOG_OFF;
}

void zcl_log_level_set(enum zcl_log_level level)
{
    (void)level;
}

void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
{
    (void)level;
    va_list ap;
    atomic_fetch_add(&zcl_c23_test_log_lines, 1);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void zcl_c23_log_sink(const char *line)
{
    fputs(line, stderr);
}

bool zcl_c23_log_category_enabled(void)
{
    return false;
}

void zcl_c23_log_refresh(void)
{
}

void zcl_c23_network_id(char *buf, size_t cap)
{
    const char *e = getenv("ZCL_C23_TEST_NETWORK");
    if (!buf || cap == 0)
        return;
    snprintf(buf, cap, "%s", e ? e : "main");
}

const struct chain_params *chain_params_get(void)
{
    static _Thread_local char id[32];
    static _Thread_local struct chain_params cp;
    zcl_c23_network_id(id, sizeof(id));
    cp.strNetworkID = id;
    return &cp;
}
