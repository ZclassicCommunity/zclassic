/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Forwarding header plus source-origin stamp. The LOG_* / GUARD* macros live
 * in platform/modules/base (the in-tree dependency sink: it references
 * nothing but libc). ~63% of the tree includes this path, so it stays put.
 *
 * Every ERROR-rank macro reached through this header appends a trailing
 * `origin=<basename>:<line>` token, so `grep -a -m1 'origin=' node.log`
 * lands on the first real fault instead of the first incidental
 * `file.c:123` string in ambient instrumentation. LOG_WARN / LOG_INFO are
 * unchanged, and so is every byte base emits before the token.
 *
 * The stamp lives here, not in base/log_macros.h, on purpose: base is a
 * content-addressed package whose root is pinned (through sha3) by the
 * sealed core, so editing base would move the core seal. This header is
 * outside every package and outside core/, and it is the include path most
 * of the tree already uses. Code that includes base/log_macros.h directly
 * keeps the base format (which already carries file:line and function
 * mid-line); include this header to get the trailing token. */

#ifndef ZCL_LOG_MACROS_FORWARD_H
#define ZCL_LOG_MACROS_FORWARD_H

#include <string.h>

#include "base/log_macros.h"

/* Bare filename of a __FILE__ path. Checks both separators unconditionally
 * (never a platform #ifdef) so a path built on one host still yields a
 * bare filename when logged from a binary that ran on another. */
static inline const char *zcl_log_origin_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');
    if (bslash && (!slash || bslash > slash))
        slash = bslash;
    return slash ? slash + 1 : path;
}

/* ── Explicit-name variants (_IN) ────────────────────────────────────
 *
 * Every LOG_* / GUARD* macro prints __func__. A long error ladder cannot be
 * split under the cyclomatic cap by moving its log calls into a helper,
 * because the line would then name the helper. The _IN forms take the
 * function name as a leading string-literal argument `fn` and emit exactly
 * what the plain macro emits when called from `fn` (file:line differ, as
 * after any edit). The plain macros below name __func__ directly.
 *
 *   LOG_WARN_IN(fn, domain, fmt, ...)
 *   LOG_INFO_IN(fn, domain, fmt, ...)
 *   LOG_ERROR_IN(fn, domain, fmt, ...)
 *
 * RULE: a helper returns a status and the original function keeps every
 * control-flow log. LOG_FAIL, LOG_ERR, LOG_NULL, LOG_RETURN and GUARD* each
 * return from the function that holds them, so none has an _IN form: only
 * plain log lines may move into a helper, and the original function does the
 * returning. `z23-lint check-split-preserved` counts LOG_X_IN("F", args) as
 * LOG_X(args) inside F, and only for the names above (see its header). */

/* One ERROR-rank line naming fn: the exact base body
 * "[domain] file:line fn(): msg" followed by " origin=<basename>:<line>". */
#define ZCL_LOG_ERROR_ORIGIN_IN(fn, domain, fmt, ...) \
    ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): " fmt " origin=%s:%d\n", \
            (domain), __FILE__, __LINE__, (fn) __VA_OPT__(,) __VA_ARGS__, \
            zcl_log_origin_basename(__FILE__), __LINE__)

#define ZCL_LOG_ERROR_ORIGIN(domain, fmt, ...) \
    ZCL_LOG_ERROR_ORIGIN_IN(__func__, domain, fmt __VA_OPT__(,) __VA_ARGS__)

/* Non-returning WARN/INFO: the base body with no origin token. */
#define ZCL_LOG_LEVEL_IN(level, fn, domain, fmt, ...) \
    ZCL_LOG_EMIT_AT(level, "[%s] %s:%d %s(): " fmt "\n", \
            (domain), __FILE__, __LINE__, (fn) __VA_OPT__(,) __VA_ARGS__)

#undef LOG_WARN_IN
#define LOG_WARN_IN(fn, domain, fmt, ...) do { \
    ZCL_LOG_LEVEL_IN(ZCL_LOG_WARN, fn, domain, fmt __VA_OPT__(,) __VA_ARGS__); \
} while (0)
#undef LOG_INFO_IN
#define LOG_INFO_IN(fn, domain, fmt, ...) do { \
    ZCL_LOG_LEVEL_IN(ZCL_LOG_INFO, fn, domain, fmt __VA_OPT__(,) __VA_ARGS__); \
} while (0)
#undef LOG_ERROR_IN
#define LOG_ERROR_IN(fn, domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN_IN(fn, domain, fmt __VA_OPT__(,) __VA_ARGS__); \
} while (0)

/* The plain macros: LOG_WARN, LOG_INFO and LOG_ERROR are their _IN form named
 * by __func__; the returning and guard forms log through ZCL_LOG_ERROR_ORIGIN
 * (which names __func__ at the expansion site) and then return. */
#undef LOG_WARN
#define LOG_WARN(domain, fmt, ...) \
    LOG_WARN_IN(__func__, domain, fmt __VA_OPT__(,) __VA_ARGS__)
#undef LOG_INFO
#define LOG_INFO(domain, fmt, ...) \
    LOG_INFO_IN(__func__, domain, fmt __VA_OPT__(,) __VA_ARGS__)
#undef LOG_ERROR
#define LOG_ERROR(domain, fmt, ...) \
    LOG_ERROR_IN(__func__, domain, fmt __VA_OPT__(,) __VA_ARGS__)
#undef LOG_FAIL
#define LOG_FAIL(domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
    return false; \
} while (0)
#undef LOG_ERR
#define LOG_ERR(domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
    return -1; \
} while (0)
#undef LOG_NULL
#define LOG_NULL(domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
    return NULL; \
} while (0)
#undef LOG_RETURN
#define LOG_RETURN(val, domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
    return (val); \
} while (0)
#undef GUARD
#define GUARD(cond, domain, fmt, ...) do { \
    if (!(cond)) { \
        ZCL_LOG_ERROR_ORIGIN(domain, "GUARD FAILED: " fmt __VA_OPT__(,) __VA_ARGS__); \
        return false; \
    } \
} while (0)
#undef GUARD_NOT_NULL
#define GUARD_NOT_NULL(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_ERROR_ORIGIN(domain, "%s is NULL", (label)); \
        return false; \
    } \
} while (0)
#undef GUARD_NOT_NULL_RET_NULL
#define GUARD_NOT_NULL_RET_NULL(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_ERROR_ORIGIN(domain, "%s is NULL", (label)); \
        return NULL; \
    } \
} while (0)
#undef GUARD_NOT_NULL_ERR
#define GUARD_NOT_NULL_ERR(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_ERROR_ORIGIN(domain, "%s is NULL", (label)); \
        return -1; \
    } \
} while (0)

#endif /* ZCL_LOG_MACROS_FORWARD_H */
