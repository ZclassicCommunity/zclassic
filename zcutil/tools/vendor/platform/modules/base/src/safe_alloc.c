/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Checked allocation wrappers (zcl_malloc/zcl_calloc/zcl_realloc) plus the
 * single-shot allocation-fault injection hook the chaos harness arms —
 * armed either on the next allocation carrying a label or on the Nth.
 * See platform/modules/base/include/base/safe_alloc.h for the contract. */

#include "base/safe_alloc.h"

#include <stdatomic.h>
#include <string.h>

static _Atomic(const char *) g_alloc_fault_site = NULL;
/* Matching allocations to let through before the armed one fails. */
static _Atomic(unsigned) g_alloc_fault_skip = 0;

void zcl_alloc_fault_fail_next(const char *label)
{
    zcl_alloc_fault_fail_nth(label, 1);
}

void zcl_alloc_fault_fail_nth(const char *label, unsigned n)
{
    atomic_store(&g_alloc_fault_skip, n > 0 ? n - 1 : 0);
    atomic_store(&g_alloc_fault_site, label && *label ? label : NULL);
}

void zcl_alloc_fault_clear(void)
{
    atomic_store(&g_alloc_fault_site, NULL);
    atomic_store(&g_alloc_fault_skip, 0);
}

const char *zcl_alloc_fault_armed_label(void)
{
    return atomic_load(&g_alloc_fault_site);
}

static _Thread_local uint64_t g_alloc_failures_this_thread;

uint64_t zcl_alloc_failure_count(void)
{
    return g_alloc_failures_this_thread;
}

void zcl_alloc_note_failure(void)
{
    g_alloc_failures_this_thread++;
}

bool zcl_alloc_fault_should_fail(const char *label)
{
    if (!label || !*label) return false;
    const char *armed = atomic_load(&g_alloc_fault_site);
    if (!armed || strcmp(armed, label) != 0) return false;
    /* Burn one of the "let it through" credits, if any remain. */
    unsigned skip = atomic_load(&g_alloc_fault_skip);
    while (skip > 0) {
        if (atomic_compare_exchange_weak(&g_alloc_fault_skip, &skip, skip - 1))
            return false;
    }
    return atomic_compare_exchange_strong(&g_alloc_fault_site, &armed, NULL);
}
