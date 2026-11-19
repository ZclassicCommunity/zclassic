/* zclassicd-owned PRODUCTION glue for the vendored Z23 set. Needs libsodium,
 * OpenSSL libcrypto and the three C++ seams in zcl_c23_log.cpp. Standalone
 * builds without those (Windows msys tests) use zcl_c23_test_glue.c instead;
 * never link both.
 *
 *  - memory_cleanse -> OPENSSL_cleanse (same primitive as src/support/cleanse.cpp)
 *  - GetRandBytes   -> libsodium randombytes_buf; sodium_init() is ensured here
 *                      and any failure abort()s (a missing CSPRNG is never survivable)
 *  - zcl_log_*      -> LogPrintStr, silent unless -debug=zc23 (call
 *                      zcl_c23_log_refresh() after the command line is parsed)
 *  - chain_params_get -> Params().NetworkIDString() via the C++ seam
 * C symbol names do not collide with the C++ (mangled) GetRandBytes /
 * memory_cleanse of zclassicd. */
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <sodium.h>

#include "base/log_level.h"
#include "chain/chainparams.h"
#include "zcl_c23_glue.h"

void memory_cleanse(void *ptr, size_t len)
{
    OPENSSL_cleanse(ptr, len);
}

static atomic_bool g_sodium_ready;

void GetRandBytes(unsigned char *buf, size_t num)
{
    if (!atomic_load_explicit(&g_sodium_ready, memory_order_acquire)) {
        if (sodium_init() < 0) {
            fputs("zc23: FATAL libsodium initialisation failed\n", stderr);
            abort();
        }
        atomic_store_explicit(&g_sodium_ready, true, memory_order_release);
    }
    if (num == 0)
        return;
    if (!buf) {
        fputs("zc23: FATAL GetRandBytes(NULL)\n", stderr);
        abort();
    }
    randombytes_buf(buf, num); /* libsodium aborts internally if the OS CSPRNG fails */
}

static atomic_bool g_log_enabled;

void zcl_c23_log_refresh(void)
{
    atomic_store_explicit(&g_log_enabled, zcl_c23_log_category_enabled(), memory_order_relaxed);
}

enum zcl_log_level zcl_log_level_get(void)
{
    return atomic_load_explicit(&g_log_enabled, memory_order_relaxed) ? ZCL_LOG_INFO
                                                                     : ZCL_LOG_OFF;
}

void zcl_log_level_set(enum zcl_log_level level)
{
    atomic_store_explicit(&g_log_enabled, level != ZCL_LOG_OFF, memory_order_relaxed);
}

void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
{
    (void)level;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof(buf))
        memcpy(buf + sizeof(buf) - 5, "...\n", 5);
    zcl_c23_log_sink(buf);
}

const struct chain_params *chain_params_get(void)
{
    static _Thread_local char id[32];
    static _Thread_local struct chain_params cp;
    zcl_c23_network_id(id, sizeof(id));
    cp.strNetworkID = id;
    return &cp;
}
