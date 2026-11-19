/* Batched Sapling incoming-viewing-key key agreement (see
 * c23/glue/zcl_c23_sapling_scan.c). C and C++ includable; part of the shim's
 * ABI namespace (zcl_c23_*), not renamed by zcl_c23_symbol_prefix.h. */
#ifndef ZCL_C23_SAPLING_SCAN_H
#define ZCL_C23_SAPLING_SCAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Idempotent, thread-safe one-time init of the C23 core's shared state (the
 * same warm-up every librustzcash_* entry point performs). */
void zcl_c23_compat_warm(void);

typedef struct zcl_c23_sapling_scan_ctx zcl_c23_sapling_scan_ctx;

/* Prepare the shared per-output state for epk: decompress once, multiply by
 * the cofactor once, build the multiple tables sized for about expected_ivks
 * keys. Returns NULL when the fast path is unavailable (allocation failure or
 * failed self-check): the caller must then use librustzcash_sapling_ka_agree
 * per key. A non-NULL context for an undecodable epk is valid: every key then
 * reports ok = 0, exactly as librustzcash_sapling_ka_agree returns false. */
zcl_c23_sapling_scan_ctx *zcl_c23_sapling_scan_begin(const uint8_t epk[32],
                                                     size_t expected_ivks);

/* For i < n: ok[i] = 1 and dh[32*i..] = the bytes
 * librustzcash_sapling_ka_agree(epk, ivks + 32*i, ...) writes, or ok[i] = 0
 * exactly when it returns false (dh[32*i..] untouched). May be called any
 * number of times with any n; a const context is safe to share read-only. */
void zcl_c23_sapling_scan_agree(const zcl_c23_sapling_scan_ctx *ctx,
                                const uint8_t *ivks, size_t n,
                                uint8_t *dh, uint8_t *ok);

void zcl_c23_sapling_scan_end(zcl_c23_sapling_scan_ctx *ctx);

#ifdef __cplusplus
}
#endif
#endif
