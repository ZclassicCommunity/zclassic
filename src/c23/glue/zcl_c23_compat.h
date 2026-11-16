/* zclassicd-owned. Force-included (-include) into every vendored Z23 .c so the
 * set builds as -std=c23 where available and as -std=gnu17 on GCC 9.4,
 * mingw-w64 9.3 and Apple clang. Z23 uses the C23 keywords alignas and
 * static_assert and the C23 bool/true/false without including the headers
 * that provide them before C23. This header changes no vendored byte.
 * It is NOT a place for behaviour; only spelling and platform contracts. */
#ifndef ZCL_C23_COMPAT_H
#define ZCL_C23_COMPAT_H

#include <assert.h>
#include <limits.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Platform contracts the vendored code relies on. Fail the build, never
 * silently miscompute. */
_Static_assert(CHAR_BIT == 8, "z23 vendor: 8-bit bytes required");
_Static_assert(sizeof(void *) == 8,
               "z23 vendor: 64-bit target required (unsigned __int128 limbs)");
#ifndef __SIZEOF_INT128__
#error "z23 vendor: compiler must provide __int128 (64-bit gcc/clang)"
#endif
_Static_assert(sizeof(unsigned __int128) == 16, "z23 vendor: __int128 must be 16 bytes");
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "z23 vendor: little-endian host required (limb arrays are memcpy-ed)"
#endif
_Static_assert(sizeof(size_t) == 8, "z23 vendor: 64-bit size_t required");
_Static_assert(sizeof(long long) == 8, "z23 vendor: 64-bit long long required");

#endif /* ZCL_C23_COMPAT_H */
