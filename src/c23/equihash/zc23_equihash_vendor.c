/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Builds the vendored Z23 equihash.c (byte-identical, never edited) inside
 * libzcl_c23.a with the Equihash verifier's two policy overrides:
 *
 *  - safe_alloc: an allocation failure aborts the process (see
 *    util/safe_alloc.h). The vendored verifier would turn a NULL into "invalid
 *    solution", and zclassicd turns that into DoS 100 and a permanently failed
 *    block index entry; a transient out-of-memory must never become a
 *    consensus reject.
 *  - log_macros: reject/error lines go to the sink pow.cpp installs
 *    (zc23_equihash_set_log_sink) instead of the generic C23 logger.
 *
 * The rest of libzcl_c23.a uses the generic headers, so these two overrides
 * must apply to this one translation unit only. The glue headers below are
 * found beside this file; pre-defining the include guards of the vendored
 * forwarding headers makes equihash.c's #include "util/safe_alloc.h" and
 * "util/log_macros.h" expand to nothing afterwards. equihash.c itself is NOT
 * listed in libzcl_c23_a_SOURCES; it is compiled only through this file. */

#define ZCL_SAFE_ALLOC_FORWARD_H
#define ZCL_LOG_MACROS_FORWARD_H
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include "../vendor/core/modules/crypto/src/equihash.c"
