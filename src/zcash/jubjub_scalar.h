/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_JUBJUB_SCALAR_H
#define ZCL_JUBJUB_SCALAR_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Reduce a 64-byte little-endian integer modulo the Jubjub scalar order.
 * The input and output may overlap. No allocation or secret-dependent indexing.
 * Candidate implementation: production callers still use the Rust oracle. */
void zcl_jubjub_to_scalar(const unsigned char *input, unsigned char *result);
#ifdef __cplusplus
}
#endif
#endif
