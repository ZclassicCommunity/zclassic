/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Checked allocation wrappers. Every malloc/calloc/realloc in
 * application code should use these instead of raw libc calls.
 *
 * Why: raw malloc returns NULL silently. These log the failure with
 * context (size, label, file, line) to stderr (and thus node.log via
 * the redirect) so OOM is observable. An agent writing `malloc(n)`
 * instead of `zcl_malloc(n, "label")` will be caught by `make lint`.
 */

#ifndef ZCL_SAFE_ALLOC_H
#define ZCL_SAFE_ALLOC_H

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ── Allocation fault injection ─────────────────────────
 *
 * Inactive by default. When armed with a label, the next checked allocation
 * with that exact label returns NULL once and clears the hook. The caller must
 * keep the label string alive until it fires or is cleared. */
void zcl_alloc_fault_fail_next(const char *label);
/* Fail the Nth (1-based) checked allocation carrying `label`, letting the
 * first N-1 through, then clear the hook. zcl_alloc_fault_fail_next(l) is
 * exactly zcl_alloc_fault_fail_nth(l, 1). This is what reaches a cleanup
 * path that unwinds ALREADY-ALLOCATED siblings — failing the first
 * allocation of a label only ever runs those unwind loops zero times. */
void zcl_alloc_fault_fail_nth(const char *label, unsigned n);
void zcl_alloc_fault_clear(void);
const char *zcl_alloc_fault_armed_label(void);
bool zcl_alloc_fault_should_fail(const char *label);

/* ── Allocation failures seen on this thread ────────────────────────
 *
 * Counts every checked allocation that returned NULL on the calling thread,
 * real or injected. A step whose result is a plain false can read this before
 * and after: if the count moved, the failure may be local memory rather than
 * anything about the data it was looking at. */
uint64_t zcl_alloc_failure_count(void);
void zcl_alloc_note_failure(void);

/* ── Checked allocators ─────────────────────────────────────────── */

/* Returns NULL on failure, but logs + emits event first.
 * Use when graceful degradation is possible. */
static inline void *zcl_malloc_impl(size_t size, const char *label,
                                     const char *file, int line)
{
    if (size > 0 && zcl_alloc_fault_should_fail(label)) {
        fprintf(stderr, "zcl_malloc INJECTED FAILURE: %zu bytes for '%s' at %s:%d\n",
                size, label, file, line);
        zcl_alloc_note_failure();
        return NULL;
    }
    void *p = malloc(size);
    if (!p && size > 0) {
        fprintf(stderr, "zcl_malloc FAILED: %zu bytes for '%s' at %s:%d\n",
                size, label, file, line);
        zcl_alloc_note_failure();
    }
    return p;
}

static inline void *zcl_calloc_impl(size_t count, size_t size,
                                     const char *label,
                                     const char *file, int line)
{
    if (count > 0 && size > 0 && zcl_alloc_fault_should_fail(label)) {
        fprintf(stderr, "zcl_calloc INJECTED FAILURE: %zu x %zu bytes for '%s' at %s:%d\n",
                count, size, label, file, line);
        zcl_alloc_note_failure();
        return NULL;
    }
    void *p = calloc(count, size);
    if (!p && count > 0 && size > 0) {
        fprintf(stderr, "zcl_calloc FAILED: %zu x %zu bytes for '%s' at %s:%d\n",
                count, size, label, file, line);
        zcl_alloc_note_failure();
    }
    return p;
}

/* Checked realloc — never leaks the original pointer on failure.
 * Returns NULL on failure; original ptr is NOT freed (caller decides). */
static inline void *zcl_realloc_impl(void *ptr, size_t size,
                                      const char *label,
                                      const char *file, int line)
{
    if (size > 0 && zcl_alloc_fault_should_fail(label)) {
        fprintf(stderr, "zcl_realloc INJECTED FAILURE: %zu bytes for '%s' at %s:%d\n",
                size, label, file, line);
        zcl_alloc_note_failure();
        return NULL;
    }
    void *p = realloc(ptr, size);
    if (!p && size > 0) {
        fprintf(stderr, "zcl_realloc FAILED: %zu bytes for '%s' at %s:%d\n",
                size, label, file, line);
        zcl_alloc_note_failure();
    }
    return p;
}

/* Convenience macros that inject __FILE__ and __LINE__ automatically. */
#define zcl_malloc(size, label)        zcl_malloc_impl((size), (label), __FILE__, __LINE__)
#define zcl_calloc(count, size, label) zcl_calloc_impl((count), (size), (label), __FILE__, __LINE__)
#define zcl_realloc(ptr, size, label)  zcl_realloc_impl((ptr), (size), (label), __FILE__, __LINE__)

/* Abort variant — use when there is no reasonable fallback.
 * Prefer zcl_malloc + NULL check when graceful degradation is possible. */
static inline void *zcl_malloc_or_die_impl(size_t size, const char *label,
                                            const char *file, int line)
{
    void *p = malloc(size);
    if (!p && size > 0) {
        fprintf(stderr, "FATAL: zcl_malloc_or_die: %zu bytes for '%s' at %s:%d\n",
                size, label, file, line);
        abort();
    }
    return p;
}

#define zcl_malloc_or_die(size, label) \
    zcl_malloc_or_die_impl((size), (label), __FILE__, __LINE__)

/* Checked strdup — every duplicate-string allocation in app code should
 * use this instead of raw libc strdup, mirroring the discipline already
 * enforced for malloc/calloc/realloc. Returns NULL on failure with
 * logged context. Tolerates a NULL input (returns NULL silently — the
 * caller already knows there's no source string). */
static inline char *zcl_strdup_impl(const char *s, const char *label,
                                     const char *file, int line)
{
    if (!s) return NULL;
    char *out = strdup(s);
    if (!out) {
        fprintf(stderr, "zcl_strdup FAILED: %zu bytes for '%s' at %s:%d\n",
                strlen(s) + 1, label, file, line);
    }
    return out;
}

#define zcl_strdup(s, label) zcl_strdup_impl((s), (label), __FILE__, __LINE__)

#endif /* ZCL_SAFE_ALLOC_H */
