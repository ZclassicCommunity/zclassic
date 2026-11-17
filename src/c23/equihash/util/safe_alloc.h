/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * zclassicd glue for the vendored Z23 Equihash verifier: replaces Z23's
 * platform/modules/util/include/util/safe_alloc.h (a forwarder to
 * base/safe_alloc.h) for the files under src/c23/equihash/vendor only.
 *
 * Policy difference from Z23, on purpose: an allocation failure ABORTS the
 * process instead of returning NULL. The vendored verifier turns a NULL into
 * "invalid solution", and zclassicd turns an invalid solution into DoS 100 and
 * a permanently failed block index entry. A transient out-of-memory must never
 * become a consensus reject, so it ends the process exactly as the C++
 * verifier does today (operator new -> new_handler_terminate, init.cpp). */

#ifndef ZC23_EQUIHASH_GLUE_SAFE_ALLOC_H
#define ZC23_EQUIHASH_GLUE_SAFE_ALLOC_H

#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Defined in src/c23/equihash/zc23_equihash.c. Never returns. */
void zc23_equihash_oom(const char *label, size_t bytes) __attribute__((noreturn));

static inline void *zcl_malloc(size_t size, const char *label)
{
    void *p = malloc(size ? size : 1);
    if (!p)
        zc23_equihash_oom(label, size);
    return p;
}

static inline void *zcl_calloc(size_t count, size_t size, const char *label)
{
    void *p = calloc(count ? count : 1, size ? size : 1);
    if (!p)
        zc23_equihash_oom(label, count * size);
    return p;
}

static inline void *zcl_realloc(void *ptr, size_t size, const char *label)
{
    void *p = realloc(ptr, size ? size : 1);
    if (!p)
        zc23_equihash_oom(label, size);
    return p;
}

#ifdef __cplusplus
}
#endif

#endif /* ZC23_EQUIHASH_GLUE_SAFE_ALLOC_H */
