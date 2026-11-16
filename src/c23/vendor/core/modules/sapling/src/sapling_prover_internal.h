/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wire layout of the compact Sapling merkle authentication path, shared by the
 * backend-independent parser in sapling_prover_c23.c and by whichever proving
 * backend translation unit the build selected. Private to core/modules/sapling/src so
 * the layout has exactly one definition without widening the public API.
 */

#ifndef ZCL_SAPLING_PROVER_INTERNAL_H
#define ZCL_SAPLING_PROVER_INTERNAL_H

#include "sapling/incremental_merkle_tree.h"

#include <stdbool.h>
#include <stddef.h>

/* depth (1) || SAPLING_MERKLE_DEPTH x (sibling (32) || direction bit (1)) */
#define SAPLING_COMPACT_WITNESS_LEN \
    ((size_t)(1 + SAPLING_MERKLE_DEPTH * 33))

/* Mark a freshly initialised backend ready without running the self-test.
 * Only params_init.c calls it, for parameter files whose identical bytes
 * already passed the self-test in this process; false unless the backend is
 * initialised and untested. */
bool zclassic_sapling_prover_adopt_verified(void);

#endif
