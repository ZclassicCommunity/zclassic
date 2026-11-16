/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZIP 32 Sapling HD key derivation — pure C23 implementation. */

#ifndef ZCL_SAPLING_ZIP32_H
#define ZCL_SAPLING_ZIP32_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define ZIP32_HARDENED_KEY_LIMIT 0x80000000u

struct zip32_expsk {
    uint8_t ask[32]; /* spending key scalar (Fs, LE) */
    uint8_t nsk[32]; /* nullifier key scalar (Fs, LE) */
    uint8_t ovk[32]; /* outgoing viewing key */
};

struct zip32_fvk {
    uint8_t ak[32];  /* spending verification key (Jubjub compressed) */
    uint8_t nk[32];  /* nullifier verification key (Jubjub compressed) */
    uint8_t ovk[32]; /* outgoing viewing key */
};

struct zip32_xsk {
    uint8_t depth;
    uint32_t parent_fvk_tag;
    uint32_t child_index;
    uint8_t chain_code[32];
    struct zip32_expsk expsk;
    uint8_t dk[32]; /* diversifier key */
};

struct zip32_xfvk {
    uint8_t depth;
    uint32_t parent_fvk_tag;
    uint32_t child_index;
    uint8_t chain_code[32];
    struct zip32_fvk fvk;
    uint8_t dk[32]; /* diversifier key */
};

/* Derive the master extended spending key from a wallet seed:
 * I = BLAKE2b-512("ZcashIP32Sapling", seed); sk_m = I[0..32] expands to
 * (ask, nsk, ovk) via PRF^expand and chain_code = I[32..64]. depth = 0.
 * The seed is the single root of trust — same seed always yields the same
 * key tree. (Caller cleanses the seed; this routine cleanses I internally.) */
void zip32_xsk_master(struct zip32_xsk *xsk,
                      const uint8_t *seed, size_t seed_len);

/* Derive child extended spending key at index `i`. If
 * i >= ZIP32_HARDENED_KEY_LIMIT the derivation is HARDENED (mixes the
 * parent's secret expsk into the PRF, so the child cannot be derived from
 * the parent's viewing key); otherwise it is non-hardened (mixes only the
 * parent's fvk, so zip32_xfvk_derive can mirror it on the public side).
 * Sets child->depth = parent->depth + 1 and records parent_fvk_tag. */
void zip32_xsk_derive(struct zip32_xsk *child,
                      const struct zip32_xsk *parent,
                      uint32_t i);

/* Project a spending key to its viewing key: copies depth/tag/index/
 * chain_code/dk and derives fvk = (ak, nk, ovk) from expsk (ak = ask·G,
 * nk = nsk·H). One-way — the xfvk can view but not spend. The resulting
 * xfvk derives the SAME non-hardened children as the xsk (that is the
 * point of non-hardened derivation). */
void zip32_xsk_to_xfvk(struct zip32_xfvk *xfvk,
                        const struct zip32_xsk *xsk);

/* Derive a child extended full viewing key — NON-HARDENED ONLY. Returns
 * false (and logs) if i >= ZIP32_HARDENED_KEY_LIMIT, because hardened
 * children require the secret expsk which an xfvk does not hold. On success
 * the child matches zip32_xsk_to_xfvk(zip32_xsk_derive(parent_xsk, i)). */
bool zip32_xfvk_derive(struct zip32_xfvk *child,
                        const struct zip32_xfvk *parent,
                        uint32_t i);

/* Find the DEFAULT diversifier for a diversifier key: the lowest index
 * j >= 0 whose FF1-AES256(dk, j) decrypts to a valid diversifier (one whose
 * group_hash g_d is not the identity). Equivalent to zip32_diversifier with
 * j = 0. Returns false only if the whole 2^88 index space is exhausted. */
bool zip32_default_diversifier(const uint8_t dk[32], uint8_t diversifier[11]);

/* Find the next valid diversifier at or after index `j` (88-bit LE counter).
 * Encrypts j under FF1-AES256(dk) and tests validity; on a miss it
 * increments j and retries. On success `diversifier` holds the valid 11-byte
 * value and `j` is left at the index that produced it (so the caller can
 * resume from j+1). Returns false only on full index-space exhaustion. */
bool zip32_diversifier(const uint8_t dk[32],
                       uint8_t j[11], uint8_t diversifier[11]);

/* Derive the default Sapling payment address from an xfvk: picks the
 * default diversifier from xfvk->dk, then pk_d = ivk · g_d(diversifier)
 * where ivk = CRH^ivk(ak, nk). (diversifier, pk_d) together are the
 * spendable shielded address. Returns false if no diversifier is valid or
 * the curve op fails. */
bool zip32_xfvk_address(const struct zip32_xfvk *xfvk,
                         uint8_t diversifier[11], uint8_t pk_d[32]);

#endif
