/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Jubjub scalar field arithmetic for Sapling. */

#ifndef ZCL_SAPLING_JUBJUB_H
#define ZCL_SAPLING_JUBJUB_H

#include <stdint.h>
#include <stddef.h>

/* Reduce a 64-byte (512-bit) input to a Jubjub scalar (mod r).
 * Equivalent to zclassic_to_scalar.
 * r = 6554484396890773809930967563523245729705921265872317281365359162392183254199
 *   = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
 * Output is 32 bytes, little-endian. */
void jubjub_to_scalar(const unsigned char *input, unsigned char *result);

#endif
