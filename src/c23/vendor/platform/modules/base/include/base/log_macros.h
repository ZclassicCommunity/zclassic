/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Error return macros that force logging at every failure site.
 *
 * An agent that writes `return -1;` in a command handler or `return false;`
 * in a service function provides zero diagnostic info. These macros
 * make the logged version SHORTER than the silent version, so the
 * path of least resistance is the correct one.
 *
 * Usage:
 *   // Instead of: return false;
 *   LOG_FAIL("wallet", "key not found: pubkey_hash=%s", hex);
 *
 *   // Instead of: return -1;
 *   LOG_ERR("command", "rpc backend unreachable: method=%s", method);
 *
 *   // Instead of: return NULL;
 *   LOG_NULL("sync", "malloc failed for %d headers", count);
 */

#ifndef ZCL_LOG_MACROS_H
#define ZCL_LOG_MACROS_H

#include <stdio.h>

#include "base/format_attribute.h"
#include "base/log_level.h"

/* Malformed inputs are the expected hot path in fuzz binaries. Keep the
 * LOG_* return/control-flow contracts, but do not let millions of expected
 * rejects backpressure libFuzzer through stderr. A variadic function call
 * (rather than a no-op macro) preserves argument evaluation and format
 * checking. Normal builds go through zcl_log_emit_at() (log_level.c), which
 * prepends the ISO-8601 UTC timestamp + level token to every line. */
#ifdef ZCL_FUZZ_QUIET_LOG_MACROS
static inline ZCL_PRINTF_LIKE(1, 2)
void zcl_fuzz_discard_log(const char *fmt, ...)
{
    (void)fmt;
}
#define ZCL_LOG_RAW(...) zcl_fuzz_discard_log(__VA_ARGS__)
#define ZCL_LOG_DO_EMIT(level, ...) zcl_fuzz_discard_log(__VA_ARGS__)
#else
#define ZCL_LOG_RAW(...) ((void)fprintf(stderr, __VA_ARGS__))
#define ZCL_LOG_DO_EMIT(level, ...) zcl_log_emit_at((level), __VA_ARGS__)
#endif

/* Opt-in level gate (see util/log_level.h): the calling macro passes its
 * own level STRUCTURALLY (ZCL_LOG_ERROR, ZCL_LOG_WARN, ...) — nothing here
 * parses the rendered text. Default level is ZCL_LOG_ALL, so `level >=
 * zcl_log_level_get()` is true for every call site until -loglevel=
 * raises the floor: zero behavior change unless the flag is passed. A
 * suppressed line skips the emission entirely (timestamp, prefix, and its
 * vararg formatting cost), same as the fuzz-quiet path above. Every
 * emitted line is one flockfile'd sequence:
 *   YYYY-MM-DDTHH:MM:SSZ LEVEL [domain] file:line func(): msg
 */
#define ZCL_LOG_EMIT_AT(level, ...) do { \
    if ((level) >= zcl_log_level_get()) \
        ZCL_LOG_DO_EMIT((level), __VA_ARGS__); \
} while (0)

/* Back-compat alias: the historical unconditional-emit name, kept at
 * ZCL_LOG_ERROR rank (the LOG_FAIL/LOG_ERR/LOG_NULL/GUARD* rank below). */
#define ZCL_LOG_EMIT(...) ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, __VA_ARGS__)

/* ── Core: log context + return ──────────────────────────────────── */

/* Log error and return false. Use in functions returning bool. */
#define LOG_FAIL(domain, fmt, ...) do { \
    ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): " fmt "\n", \
            (domain), __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__); \
    return false; \
} while (0)

/* Log error and return -1. Use in command handlers / int-returning funcs. */
#define LOG_ERR(domain, fmt, ...) do { \
    ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): " fmt "\n", \
            (domain), __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__); \
    return -1; \
} while (0)

/* Log error and return NULL. Use in pointer-returning functions. */
#define LOG_NULL(domain, fmt, ...) do { \
    ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): " fmt "\n", \
            (domain), __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__); \
    return NULL; \
} while (0)

/* Log error and return a custom value. */
#define LOG_RETURN(val, domain, fmt, ...) do { \
    ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): " fmt "\n", \
            (domain), __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__); \
    return (val); \
} while (0)

/* ── Non-returning level logs ────────────────────────────────────
 *
 * The macros above LOG-and-RETURN (for error sites). These LOG and
 * CONTINUE — for the common case of a diagnostic that must NOT abort
 * the caller: progress, best-effort cleanup, and warnings on a
 * log-and-continue path. They replace raw `fprintf(stderr, ...)` (often
 * marked `// obs-ok:`) so node.log is uniform and `zclassic23 getnodelog` can
 * filter by level.
 *
 * Same `[domain] file:line func():` body the returning macros use; the
 * timestamp + level token prefix comes from ZCL_LOG_EMIT_AT (via
 * zcl_log_emit_at), and nodelog_controller parses that prefix
 * positionally (` WARN ` → warn, ` ERROR ` → error, ...).
 *
 *   // Instead of: fprintf(stderr, "[net] short write peer=%d\n", id);
 *   LOG_WARN("net", "short write peer=%d", id);
 */

/* Explicit-name forms of the three non-returning logs. LOG_X_IN(fn, ...)
 * prints exactly the line LOG_X prints from a function named fn (file:line
 * differ, as after any edit). RULE: only these three non-returning forms
 * have an _IN form. The returning macros above (LOG_FAIL, LOG_ERR, LOG_NULL,
 * LOG_RETURN, GUARD*) return from the function that holds them, so they
 * cannot move into a helper. A helper split out of a function logs through
 * LOG_X_IN("orig", ...) so the line keeps the original function's name. */

/* Log a warning and continue (no return). Names fn. */
#define LOG_WARN_IN(fn, domain, fmt, ...) do { \
    ZCL_LOG_EMIT_AT(ZCL_LOG_WARN, "[%s] %s:%d %s(): " fmt "\n", \
            (domain), __FILE__, __LINE__, (fn) __VA_OPT__(,) __VA_ARGS__); \
} while (0)

/* Log an informational line and continue (no return). Names fn. */
#define LOG_INFO_IN(fn, domain, fmt, ...) do { \
    ZCL_LOG_EMIT_AT(ZCL_LOG_INFO, "[%s] %s:%d %s(): " fmt "\n", \
            (domain), __FILE__, __LINE__, (fn) __VA_OPT__(,) __VA_ARGS__); \
} while (0)

/* Log an ERROR-level line and continue (no return). Names fn; no origin
 * token (the base ERROR body is the same as WARN/INFO). The returning error
 * macros above (LOG_ERR/LOG_FAIL/LOG_NULL) abort the caller; this one is for
 * a diagnostic that must record ERROR-severity context yet fall through to a
 * caller-chosen result (e.g. a bool capture that returns its own flag, or a
 * best-effort path that logs every number before continuing). Completes the
 * non-returning WARN/INFO pair at ERROR rank. */
#define LOG_ERROR_IN(fn, domain, fmt, ...) do { \
    ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): " fmt "\n", \
            (domain), __FILE__, __LINE__, (fn) __VA_OPT__(,) __VA_ARGS__); \
} while (0)

/* The plain forms: each is its _IN form named by __func__, so the body above
 * is the only copy of each. */
#define LOG_WARN(domain, fmt, ...) \
    LOG_WARN_IN(__func__, domain, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_INFO(domain, fmt, ...) \
    LOG_INFO_IN(__func__, domain, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERROR(domain, fmt, ...) \
    LOG_ERROR_IN(__func__, domain, fmt __VA_OPT__(,) __VA_ARGS__)

/* ── Guards: check condition, log + return on failure ─────────── */

/* Guard: if condition is false, log and return false. */
#define GUARD(cond, domain, fmt, ...) do { \
    if (!(cond)) { \
        ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): GUARD FAILED: " fmt "\n", \
                (domain), __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__); \
        return false; \
    } \
} while (0)

/* Guard: if pointer is NULL, log and return false. */
#define GUARD_NOT_NULL(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): %s is NULL\n", \
                (domain), __FILE__, __LINE__, __func__, (label)); \
        return false; \
    } \
} while (0)

/* Guard: if pointer is NULL, log and return NULL. */
#define GUARD_NOT_NULL_RET_NULL(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): %s is NULL\n", \
                (domain), __FILE__, __LINE__, __func__, (label)); \
        return NULL; \
    } \
} while (0)

/* Guard: if pointer is NULL, log and return -1. */
#define GUARD_NOT_NULL_ERR(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): %s is NULL\n", \
                (domain), __FILE__, __LINE__, __func__, (label)); \
        return -1; \
    } \
} while (0)

#endif /* ZCL_LOG_MACROS_H */
