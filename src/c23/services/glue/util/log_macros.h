/* zclassicd glue for the vendored Z23 service parsers (src/c23/services).
 *
 * Stands in for Z23's util/log_macros.h, which needs __VA_OPT__ (C23) and the
 * Z23 logger. The release toolchain compiles this code as gnu11/gnu17, and the
 * wallet calls the parser on every wallet transaction that has an OP_RETURN
 * output, on bytes an outside party chose: a rejected or oversized field is a
 * normal negative result, not something to write to debug.log. The arguments
 * are type-checked by the compiler and never evaluated. */
#ifndef ZCL_SERVICES_GLUE_UTIL_LOG_MACROS_H
#define ZCL_SERVICES_GLUE_UTIL_LOG_MACROS_H

#include <stdio.h>

#define ZCL_SERVICES_LOG_DISCARD(...) \
    do { if (0) { (void)printf(__VA_ARGS__); } } while (0)

#define LOG_WARN(domain, ...)  ZCL_SERVICES_LOG_DISCARD(__VA_ARGS__)
#define LOG_ERROR(domain, ...) ZCL_SERVICES_LOG_DISCARD(__VA_ARGS__)
#define LOG_INFO(domain, ...)  ZCL_SERVICES_LOG_DISCARD(__VA_ARGS__)
#define LOG_DEBUG(domain, ...) ZCL_SERVICES_LOG_DISCARD(__VA_ARGS__)

#endif
