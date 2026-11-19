/* Copyright 2026 The Zclassic developers - MIT License
 *
 * TEST-ONLY seams for the standalone Sprout prover tests (no daemon). The
 * daemon build links src/c23/glue instead; never link this into zclassicd.
 * Logging goes to stderr only when SPROUT_TEST_LOG=1. */

#include "base/log_level.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* OS CSPRNG; abort() on failure, as the daemon's GetRandBytes does. */
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

void memory_cleanse(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--)
        *v++ = 0;
}

enum zcl_log_level zcl_log_level_get(void)
{
    const char *e = getenv("SPROUT_TEST_LOG");
    return (e && e[0] == '1') ? ZCL_LOG_ALL : ZCL_LOG_OFF;
}

void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
{
    (void)level;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
