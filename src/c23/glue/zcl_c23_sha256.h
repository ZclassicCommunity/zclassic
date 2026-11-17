/* zclassicd-owned. C/C++ seam between crypto/sha256.cpp (CSHA256) and the
 * vendored Z23 SHA-256 (vendor/core/modules/crypto/src/sha256.c).
 *
 * The Z23 header is named crypto/sha256.h, like zclassicd's own, so C++ code
 * must never see the vendored include path. C++ includes ONLY this header.
 *
 * Consensus note: every backend (portable C, Intel SHA-NI, ARMv8 SHA) computes
 * FIPS 180-4 SHA-256. A hardware backend is installed only after its
 * compression function reproduced the portable result for a known block; the
 * choice changes speed, never output. gtest/test_sha256_differential.cpp
 * proves equality against the former C++ implementation with each backend
 * forced. */
#ifndef ZCL_C23_SHA256_H
#define ZCL_C23_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Same members, order and layout as Z23's struct sha256_ctx (checked with
 * static assertions in zcl_c23_sha256.c) and as CSHA256 had before. */
struct zcl_c23_sha256_state {
    uint32_t s[8];
    unsigned char buf[64];
    size_t bytes;
};

void zcl_c23_sha256_init(struct zcl_c23_sha256_state *st);
void zcl_c23_sha256_write(struct zcl_c23_sha256_state *st, const unsigned char *data, size_t len);
/* Pads, absorbs the length and writes the 32-byte digest. */
void zcl_c23_sha256_finalize(struct zcl_c23_sha256_state *st, unsigned char hash[32]);
/* Writes the eight chaining words big-endian, no padding (SHA256Compress). */
void zcl_c23_sha256_midstate(struct zcl_c23_sha256_state *st, unsigned char hash[32]);

/* Backends the dispatcher can install. HARDWARE is SHA-NI on x86 and the
 * ARMv8 SHA extension on arm64. */
enum zcl_c23_sha256_backend {
    ZCL_C23_SHA256_AUTO = -1,
    ZCL_C23_SHA256_PORTABLE = 0,
    ZCL_C23_SHA256_HARDWARE = 1
};

/* Probes the CPU, runs the known-answer self-test and installs the fastest
 * verified backend. Returns 1 when the self-test passed (or there was nothing
 * to test) and 0 when a hardware backend was present but disagreed with the
 * portable code and was disabled. Safe to call more than once and from several
 * threads; the selection is also made on first use if this was never called. */
int zcl_c23_sha256_autodetect(void);

/* Name of the installed backend: "SHA-NI (hardware)", "ARMv8 SHA (hardware)"
 * or "portable C". */
const char *zcl_c23_sha256_backend_name(void);

/* Test and benchmark hook. Requests a backend and returns the one actually
 * installed (HARDWARE is only a request: it falls back to PORTABLE when the
 * CPU lacks it or it failed the self-test). Not for production code and not
 * to be called while other threads are hashing. */
enum zcl_c23_sha256_backend zcl_c23_sha256_select(enum zcl_c23_sha256_backend which);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_C23_SHA256_H */
