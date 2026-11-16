/* zclassicd-owned. Forwards the C/C++ seam in zcl_c23_sha256.h to the vendored
 * Z23 SHA-256. No hashing logic lives here. */
#include "zcl_c23_hash_names.h" /* first: renames the vendored externals */

#include "zcl_c23_sha256.h"


#include "crypto/sha256.h" /* the VENDORED Z23 header (see Makefile.am include order) */

#include <stddef.h>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

_Static_assert(sizeof(struct zcl_c23_sha256_state) == sizeof(struct sha256_ctx),
               "zcl_c23_sha256_state must match Z23 sha256_ctx");
_Static_assert(_Alignof(struct zcl_c23_sha256_state) == _Alignof(struct sha256_ctx),
               "zcl_c23_sha256_state alignment must match Z23 sha256_ctx");
_Static_assert(offsetof(struct zcl_c23_sha256_state, s) == offsetof(struct sha256_ctx, s),
               "sha256 state offset: s");
_Static_assert(offsetof(struct zcl_c23_sha256_state, buf) == offsetof(struct sha256_ctx, buf),
               "sha256 state offset: buf");
_Static_assert(offsetof(struct zcl_c23_sha256_state, bytes) == offsetof(struct sha256_ctx, bytes),
               "sha256 state offset: bytes");
_Static_assert(sizeof(((struct sha256_ctx *)0)->s) == 32 && sizeof(((struct sha256_ctx *)0)->buf) == 64,
               "sha256 state member sizes");

/* The two structs are member-for-member identical (asserted above); this
 * library is built with -fno-strict-aliasing. */
static inline struct sha256_ctx *ctx_of(struct zcl_c23_sha256_state *st)
{
    return (struct sha256_ctx *)(void *)st;
}

void zcl_c23_sha256_init(struct zcl_c23_sha256_state *st)
{
    sha256_init(ctx_of(st));
}

void zcl_c23_sha256_write(struct zcl_c23_sha256_state *st, const unsigned char *data, size_t len)
{
    sha256_write(ctx_of(st), data, len);
}

void zcl_c23_sha256_finalize(struct zcl_c23_sha256_state *st, unsigned char hash[32])
{
    sha256_finalize(ctx_of(st), hash);
}

void zcl_c23_sha256_midstate(struct zcl_c23_sha256_state *st, unsigned char hash[32])
{
    /* enforce_compression = 0: the caller (CSHA256::FinalizeNoPadding) keeps
     * zclassicd's own length check and its std::length_error. */
    (void)sha256_finalize_no_padding(ctx_of(st), hash, 0);
}

int zcl_c23_sha256_autodetect(void)
{
    const int installed = sha256_select_impl(SHA256_IMPL_AUTO);
    if (!sha256_selftest())
        return 0;
#if defined(__x86_64__) || defined(__i386__)
    /* The vendored probe (detect_sha_ni) runs the known-answer test itself
     * and, on a mismatch, quietly installs the portable transform, so
     * sha256_selftest() above then finds nothing to test and passes. Report
     * that case here: the CPU advertises SHA (CPUID.(EAX=7,ECX=0):EBX[29])
     * but the portable backend was installed. */
    unsigned int eax, ebx, ecx, edx;
    if (installed == SHA256_IMPL_PORTABLE &&
        __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) && ((ebx >> 29) & 1u))
        return 0;
#else
    (void)installed;
#endif
    return 1;
}

const char *zcl_c23_sha256_backend_name(void)
{
    return sha256_implementation();
}

enum zcl_c23_sha256_backend zcl_c23_sha256_select(enum zcl_c23_sha256_backend which)
{
    enum sha256_impl want = which == ZCL_C23_SHA256_PORTABLE ? SHA256_IMPL_PORTABLE
                          : which == ZCL_C23_SHA256_HARDWARE ? SHA256_IMPL_SHANI
                                                             : SHA256_IMPL_AUTO;
    return sha256_select_impl(want) == SHA256_IMPL_SHANI ? ZCL_C23_SHA256_HARDWARE
                                                         : ZCL_C23_SHA256_PORTABLE;
}

/* The vendored implementation, compiled as part of this translation unit:
 * the bytes under vendor/ are untouched, but no object, .deps or .dirstamp
 * file is written into vendor/ by an in-tree build (check-vendor.sh rejects
 * unlisted files there), and the forwarders above inline into it. */
#include "../vendor/core/modules/crypto/src/sha256.c"
