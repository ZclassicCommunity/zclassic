/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Opt-in log-level filter consulted by ZCL_LOG_EMIT_AT (log_macros.h) at
 * every LOG_* / GUARD* call site. The level is passed structurally by the
 * calling macro (LOG_WARN passes ZCL_LOG_WARN, LOG_FAIL passes
 * ZCL_LOG_ERROR, ...) — nothing here ever parses a log line's text.
 *
 * Default is ZCL_LOG_ALL (numerically == ZCL_LOG_INFO): every line emits,
 * zero behavior change unless -loglevel=<level> is passed on argv (wired
 * in engine/entry/main.c, right after ParseParameters()).
 *
 * LogPrintStr() (util.c) and the raw LogPrintf(...) call sites it backs
 * are NOT gated by this filter — only the structured LOG_* / GUARD* macros
 * are. Those legacy printf lines remain the volume the filter does not
 * cover; see platform/modules/base/include/base/log_macros.h.
 *
 * The emitted line FORMAT is produced by zcl_log_emit_at() below:
 * "YYYY-MM-DDTHH:MM:SSZ LEVEL [domain] file:line func(): msg" — a single
 * ISO-8601 UTC timestamp + level token prefix so nodelog_controller.c can
 * parse time/level positionally instead of sniffing rendered text.
 */

#ifndef ZCL_LOG_LEVEL_H
#define ZCL_LOG_LEVEL_H

#include <stdbool.h>

#include "base/format_attribute.h"

enum zcl_log_level {
    ZCL_LOG_ALL   = 0, /* alias of ZCL_LOG_INFO: the default, emits every LOG_* site */
    ZCL_LOG_INFO  = 0,
    ZCL_LOG_WARN  = 1,
    ZCL_LOG_ERROR = 2,
    ZCL_LOG_FATAL = 3,
    ZCL_LOG_OFF   = 4, /* higher than any real level: suppresses everything */
};

/* Set the process-wide minimum emit level. Atomic; safe from any thread. */
void zcl_log_level_set(enum zcl_log_level level);

/* Get the current minimum emit level. Atomic; safe from any thread. */
enum zcl_log_level zcl_log_level_get(void);

/* Parse one of "all", "info", "warn", "error", "fatal", "off"
 * (case-sensitive, matches getnodelog's `level` param and the -loglevel=
 * flag). Returns false and leaves *out untouched for anything else —
 * callers must treat an unrecognized value as "keep the current level",
 * never as a reason to abort boot. */
bool zcl_log_level_from_string(const char *s, enum zcl_log_level *out);

/* Emit one structured LOG_* line to stderr: "YYYY-MM-DDTHH:MM:SSZ LEVEL "
 * prefix, then the caller's formatted body, as a single flockfile'd
 * sequence so lines from different threads never interleave. Called only
 * by ZCL_LOG_EMIT_AT (log_macros.h) after the level gate passes — do not
 * call directly; use the LOG_* / GUARD* macros. */
void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
    ZCL_PRINTF_LIKE(2, 3);

#endif /* ZCL_LOG_LEVEL_H */
