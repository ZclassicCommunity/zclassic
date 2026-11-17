/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * zclassicd glue for the vendored Z23 Equihash verifier: replaces Z23's
 * platform/modules/util/include/util/log_macros.h for the files under
 * src/c23/equihash/vendor only. Only the macros those files use are defined
 * (LOG_FAIL in equihash.c, LOG_ERR in blake2b.c); the others are provided
 * with the same return semantics so a future vendored blob still compiles.
 *
 * Every line goes to zc23_equihash_log(), which forwards to a sink that
 * zclassicd installs (pow.cpp routes it to LogPrint("pow", ...), the category
 * the C++ verifier already logs its rejects under). With no sink installed
 * nothing is printed. Uses the GNU ", ##__VA_ARGS__" form, not __VA_OPT__,
 * so it also builds with the release toolchains (GCC 9 in gnu17 mode). */

#ifndef ZC23_EQUIHASH_GLUE_LOG_MACROS_H
#define ZC23_EQUIHASH_GLUE_LOG_MACROS_H

#ifdef __cplusplus
extern "C" {
#endif

/* MinGW GCC's plain "printf" archetype is the MSVCRT one, which rejects
 * the C99 %zu the vendored files use; the formatting itself is done by
 * vsnprintf in zc23_equihash.c. */
#if defined(__MINGW32__) && !defined(__clang__)
#define ZC23_EH_PRINTF_ARCHETYPE gnu_printf
#else
#define ZC23_EH_PRINTF_ARCHETYPE printf
#endif

/* Defined in src/c23/equihash/zc23_equihash.c. */
void zc23_equihash_log(const char *domain, const char *func, int line,
                       const char *fmt, ...)
    __attribute__((format(ZC23_EH_PRINTF_ARCHETYPE, 4, 5)));

#ifdef __cplusplus
}
#endif

#define ZC23_EH_LOG_LINE(domain, fmt, ...) \
    zc23_equihash_log((domain), __func__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_WARN(domain, fmt, ...)  do { ZC23_EH_LOG_LINE(domain, fmt, ##__VA_ARGS__); } while (0)
#define LOG_INFO(domain, fmt, ...)  do { ZC23_EH_LOG_LINE(domain, fmt, ##__VA_ARGS__); } while (0)
#define LOG_ERROR(domain, fmt, ...) do { ZC23_EH_LOG_LINE(domain, fmt, ##__VA_ARGS__); } while (0)
#define LOG_FAIL(domain, fmt, ...)  do { ZC23_EH_LOG_LINE(domain, fmt, ##__VA_ARGS__); return false; } while (0)
#define LOG_ERR(domain, fmt, ...)   do { ZC23_EH_LOG_LINE(domain, fmt, ##__VA_ARGS__); return -1; } while (0)
#define LOG_NULL(domain, fmt, ...)  do { ZC23_EH_LOG_LINE(domain, fmt, ##__VA_ARGS__); return NULL; } while (0)

#endif /* ZC23_EQUIHASH_GLUE_LOG_MACROS_H */
