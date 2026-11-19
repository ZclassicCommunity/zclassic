/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * C ABI between zclassicd (C++) and the vendored Z23 Equihash verifier
 * (src/c23/equihash/vendor, byte-identical to Z23; see Z23_SOURCE.tsv).
 * This header is the only one C++ code includes; the vendored headers are
 * never put on the C++ include path. */

#ifndef ZC23_EQUIHASH_H
#define ZC23_EQUIHASH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ZC23_EH_INVALID = 0,      /* the solution does not verify */
    ZC23_EH_VALID = 1,        /* the solution verifies */
    ZC23_EH_UNSUPPORTED = -1, /* (n,k) is not one this verifier was vendored for */
    ZC23_EH_ERROR = -2        /* internal failure (BLAKE2b init/update); NOT a verdict */
};

/* Verify an Equihash solution.
 *
 *   n, k      parameter set; (200,9), (192,7), (96,5) and (48,5) are supported.
 *   input     the header bytes the solution commits to, i.e. the serialized
 *             CEquihashInput (nVersion .. nBits) followed by the 32-byte nNonce
 *             (140 bytes for a zclassicd header).
 *   soln      the minimal-encoded solution (CBlockHeader::nSolution bytes).
 *
 * Returns ZC23_EH_VALID or ZC23_EH_INVALID, or a negative value that the
 * caller must treat as "no verdict" (fall back to the C++ verifier), never as
 * a reject. Allocation failure aborts the process (see glue/util/safe_alloc.h).
 * Thread-safe: no shared mutable state apart from the one-time CPU feature
 * probe, which the vendored code publishes with release/acquire atomics. */
int zc23_equihash_verify(unsigned int n, unsigned int k,
                         const unsigned char *input, size_t input_len,
                         const unsigned char *soln, size_t soln_len);

/* Install the sink that receives the vendored code's reject/error lines (one
 * formatted line, no trailing newline). NULL silences them (the default). */
typedef void (*zc23_equihash_log_sink)(const char *line);
void zc23_equihash_set_log_sink(zc23_equihash_log_sink sink);

/* Batched-BLAKE2b tier control, for the differential tests and the benchmark
 * only. tier: -1 automatic (CPUID-driven), 0 scalar, 1 4-way (AVX2/NEON),
 * 2 8-way (AVX-512F). A request is narrowed to what the host can execute.
 * Returns the tier actually installed. Not thread-safe against concurrent
 * verification; production code never calls it. */
int zc23_equihash_select_tier(int tier);

/* Name of the installed tier, e.g. "AVX-512 (8-way)", "AVX2 (4-way)", "scalar". */
const char *zc23_equihash_tier_name(void);

#ifdef __cplusplus
}
#endif

#endif /* ZC23_EQUIHASH_H */
