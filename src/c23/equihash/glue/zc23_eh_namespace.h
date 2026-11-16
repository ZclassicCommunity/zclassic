/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Force-included (-include) into every file of libzc23_equihash.a.
 *
 * libsodium (depends) exports its internal reference BLAKE2b with the SAME
 * unprefixed names Z23 uses (blake2b_init, blake2b_init_param,
 * blake2b_init_salt_personal, blake2b_init_key, blake2b_update,
 * blake2b_final, blake2b) but different signatures and state layout.
 * Linking both is a duplicate-definition error at best and, with a
 * different link order, a silent cross-binding of sodium's internals to
 * Z23's functions. Every external symbol the vendored files define is
 * therefore renamed into a zc23eh_ namespace here, without editing a
 * vendored byte. The list is checked by check-vendor.sh against `nm`. */

#ifndef ZC23_EH_NAMESPACE_H
#define ZC23_EH_NAMESPACE_H

/* crypto/blake2b.c */
#define blake2b                          zc23eh_blake2b
#define blake2b_init                     zc23eh_blake2b_init
#define blake2b_init_key                 zc23eh_blake2b_init_key
#define blake2b_init_param               zc23eh_blake2b_init_param
#define blake2b_init_salt_personal       zc23eh_blake2b_init_salt_personal
#define blake2b_update                   zc23eh_blake2b_update
#define blake2b_final                    zc23eh_blake2b_final

/* crypto/blake2b_avx2.c */
#define equihash_generate_hash_batch4          zc23eh_equihash_generate_hash_batch4
#define equihash_generate_hash_batch8          zc23eh_equihash_generate_hash_batch8
#define equihash_blake2b_batch_select_impl     zc23eh_equihash_blake2b_batch_select_impl
#define equihash_blake2b_batch_implementation  zc23eh_equihash_blake2b_batch_implementation

/* crypto/equihash.c */
#define equihash_params_init             zc23eh_equihash_params_init
#define equihash_params_supported        zc23eh_equihash_params_supported
#define equihash_solution_params         zc23eh_equihash_solution_params
#define equihash_initialise_state        zc23eh_equihash_initialise_state
#define equihash_is_valid_solution       zc23eh_equihash_is_valid_solution
#define equihash_basic_solve             zc23eh_equihash_basic_solve
#define eh_expand_array                  zc23eh_eh_expand_array
#define eh_compress_array                zc23eh_eh_compress_array
#define eh_index_to_array                zc23eh_eh_index_to_array
#define eh_array_to_index                zc23eh_eh_array_to_index
#define eh_get_indices_from_minimal      zc23eh_eh_get_indices_from_minimal
#define eh_get_minimal_from_indices      zc23eh_eh_get_minimal_from_indices

/* crypto/simd_dispatch.c */
#define simd_cpu_words_probe             zc23eh_simd_cpu_words_probe
#define simd_avx2_usable                 zc23eh_simd_avx2_usable
#define simd_avx512f_usable              zc23eh_simd_avx512f_usable
#define simd_avx512_dq_vl_usable         zc23eh_simd_avx512_dq_vl_usable
#define simd_avx512_ifma_usable          zc23eh_simd_avx512_ifma_usable
#define simd_host_has_avx2               zc23eh_simd_host_has_avx2
#define simd_host_has_avx512f            zc23eh_simd_host_has_avx512f
#define simd_host_has_avx512_dq_vl       zc23eh_simd_host_has_avx512_dq_vl
#define simd_host_has_avx512_ifma        zc23eh_simd_host_has_avx512_ifma

#endif /* ZC23_EH_NAMESPACE_H */
