/* zclassicd-owned. Minimal log sink for libzcl_c23_hash.a, which is linked into
 * every program that carries libbitcoin_crypto (zclassicd, zclassic-cli,
 * zclassic-tx, the tests, libzcashconsensus) and therefore cannot depend on
 * util.cpp/LogPrintStr the way zcl_c23_glue.c does.
 *
 * The only vendored log sites reachable from here are the SHA-256 self-test
 * mismatch (also reported to the caller through zcl_c23_sha256_autodetect and
 * logged by init) and a length check this glue never enables. Both are ERROR
 * rank and go to stderr.
 *
 * zcl_c23_hash_names.h renames the two entry points for this library, so it
 * does not collide with the definitions in zcl_c23_glue.c (libzcl_c23.a). */
#include "zcl_c23_hash_names.h"

#include "base/log_level.h"

#include <stdarg.h>
#include <stdio.h>

enum zcl_log_level zcl_log_level_get(void)
{
    return ZCL_LOG_ERROR;
}

void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
{
    (void)level;
    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
}
