/* zclassicd-owned. Private to libzcl_c23_hash.a: include FIRST in each of its
 * translation units, before any vendored header.
 *
 * Z23 exports plain C names. Two of them (sha256_init, sha256_finalize) are
 * already defined, extern "C" and with other signatures, by zclassicd's
 * src/sha256.cpp (the helper behind SHA256::hashString), and the log entry
 * points are also defined by zcl_c23_glue.c for the full libzcl_c23.a. These
 * macros give this library's copies their own names, so it links next to
 * both without duplicate symbols. The vendored bytes are untouched. */
#ifndef ZCL_C23_HASH_NAMES_H
#define ZCL_C23_HASH_NAMES_H

#define sha256_init                zcl_c23h_sha256_init
#define sha256_write               zcl_c23h_sha256_write
#define sha256_finalize            zcl_c23h_sha256_finalize
#define sha256_finalize_no_padding zcl_c23h_sha256_finalize_no_padding
#define sha256_selftest            zcl_c23h_sha256_selftest
#define sha256_implementation      zcl_c23h_sha256_implementation
#define sha256_shani_available     zcl_c23h_sha256_shani_available
#define sha256_select_impl         zcl_c23h_sha256_select_impl
#define sha256_cpuid_allows_shani  zcl_c23h_sha256_cpuid_allows_shani

#define zcl_log_level_get          zcl_c23h_log_level_get
#define zcl_log_level_set          zcl_c23h_log_level_set
#define zcl_log_level_from_string  zcl_c23h_log_level_from_string
#define zcl_log_emit_at            zcl_c23h_log_emit_at

#endif /* ZCL_C23_HASH_NAMES_H */
