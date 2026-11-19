/* zclassicd glue for the vendored Z23 service parsers (src/c23/services).
 *
 * Stands in for Z23's core/uint256.h: the vendored SLP parser only needs the
 * 32-byte container. Layout matches Z23 (a bare byte array, no padding).
 * C only: this directory must never be on a C++ include path. */
#ifndef ZCL_SERVICES_GLUE_CORE_UINT256_H
#define ZCL_SERVICES_GLUE_CORE_UINT256_H

#include <stdint.h>

struct uint256 {
    uint8_t data[32];
};

#endif
