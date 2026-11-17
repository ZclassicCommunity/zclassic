/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Glue between zclassicd and the vendored Z23 Equihash verifier. No vendored
 * file is edited; this file only calls the Z23 primitive the same way Z23's
 * own consensus predicate does (core/consensus/src/equihash.c at the pin):
 * equihash_params_init -> equihash_initialise_state ("ZcashPoW" || LE32 N ||
 * LE32 K personalization, digest (512/N)*N/8) -> blake2b_update(header bytes
 * and nonce) -> equihash_is_valid_solution. */

#include "zc23_equihash.h"

#include "crypto/blake2b.h"
#include "crypto/equihash.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

_Static_assert(sizeof(eh_index) == 4, "Equihash index must be 32-bit");

static _Atomic(zc23_equihash_log_sink) g_log_sink = NULL;

void zc23_equihash_set_log_sink(zc23_equihash_log_sink sink)
{
    atomic_store_explicit(&g_log_sink, sink, memory_order_release);
}

void zc23_equihash_log(const char *domain, const char *func, int line,
                       const char *fmt, ...)
{
    zc23_equihash_log_sink sink = atomic_load_explicit(&g_log_sink, memory_order_acquire);
    if (!sink)
        return;

    char body[384];
    va_list ap;
    va_start(ap, fmt);
    int nbody = vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (nbody < 0)
        body[0] = '\0';

    char out[512];
    int nout = snprintf(out, sizeof(out), "[%s] %s:%d %s", domain ? domain : "?",
                        func ? func : "?", line, body);
    if (nout < 0)
        return;
    sink(out);
}

void zc23_equihash_oom(const char *label, size_t bytes)
{
    fprintf(stderr, "zclassicd: out of memory in the C23 Equihash verifier (%zu bytes for %s); aborting\n",
            bytes, label ? label : "?");
    fflush(stderr);
    abort();
}

static bool zc23_equihash_params_known(unsigned int n, unsigned int k)
{
    return (n == 200 && k == 9) || (n == 192 && k == 7) ||
           (n == 96 && k == 5) || (n == 48 && k == 5);
}

int zc23_equihash_verify(unsigned int n, unsigned int k,
                         const unsigned char *input, size_t input_len,
                         const unsigned char *soln, size_t soln_len)
{
    if (!zc23_equihash_params_known(n, k) || !equihash_params_supported(n, k))
        return ZC23_EH_UNSUPPORTED;
    if ((input == NULL && input_len != 0) || (soln == NULL && soln_len != 0))
        return ZC23_EH_ERROR;

    struct equihash_params p;
    equihash_params_init(&p, n, k);

    /* Same early length reject as the C++ verifier (Equihash<N,K>::
     * IsValidSolution returns false before touching the hash). The vendored
     * function performs the identical check; doing it here first keeps a
     * wrong-length solution off the vendored log path. */
    if (soln_len != p.solution_width)
        return ZC23_EH_INVALID;

    struct blake2b_ctx state;
    if (equihash_initialise_state(&p, &state) != 0)
        return ZC23_EH_ERROR;
    if (input_len != 0 && blake2b_update(&state, input, input_len) != 0)
        return ZC23_EH_ERROR;

    return equihash_is_valid_solution(&p, &state, soln, soln_len) ? ZC23_EH_VALID
                                                                  : ZC23_EH_INVALID;
}

int zc23_equihash_select_tier(int tier)
{
    enum blake2b_batch_impl which;
    switch (tier) {
    case 0: which = BLAKE2B_BATCH_IMPL_SCALAR; break;
    case 1: which = BLAKE2B_BATCH_IMPL_AVX2; break;
    case 2: which = BLAKE2B_BATCH_IMPL_AVX512; break;
    default: which = BLAKE2B_BATCH_IMPL_AUTO; break;
    }
    return equihash_blake2b_batch_select_impl(which);
}

const char *zc23_equihash_tier_name(void)
{
    return equihash_blake2b_batch_implementation();
}
