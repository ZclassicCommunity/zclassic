/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZIP 32 Sapling HD key derivation — pure C23 implementation. */

#include "sapling/zip32.h"
#include "sapling/sapling.h"
#include "sapling/fr.h"
#include "sapling/ff1.h"
#include "crypto/blake2b.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <string.h>

static const uint8_t ZIP32_MASTER_PERSONAL[16] =
    {'Z','c','a','s','h','I','P','3','2','S','a','p','l','i','n','g'};
static const uint8_t ZIP32_EXPAND_PERSONAL[16] =
    {'Z','c','a','s','h','_','E','x','p','a','n','d','S','e','e','d'};
static const uint8_t ZIP32_FVFP_PERSONAL[16] =
    {'Z','c','a','s','h','S','a','p','l','i','n','g','F','V','F','P'};

/* PRF^expand(sk, t) = BLAKE2b-512("Zcash_ExpandSeed", sk || t) */
static void prf_expand(uint8_t out[64], const uint8_t *sk, size_t sk_len,
                       const uint8_t *t, size_t t_len)
{
    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 64, NULL, 0, NULL,
                               ZIP32_EXPAND_PERSONAL);
    blake2b_update(&ctx, sk, sk_len);
    blake2b_update(&ctx, t, t_len);
    blake2b_final(&ctx, out, 64);
}

/* PRF^expand with multiple concatenated inputs */
static void prf_expand_vec(uint8_t out[64], const uint8_t *sk, size_t sk_len,
                           const uint8_t **parts, const size_t *part_lens,
                           size_t n_parts)
{
    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 64, NULL, 0, NULL,
                               ZIP32_EXPAND_PERSONAL);
    blake2b_update(&ctx, sk, sk_len);
    for (size_t i = 0; i < n_parts; i++)
        blake2b_update(&ctx, parts[i], part_lens[i]);
    blake2b_final(&ctx, out, 64);
}

/* Derive expanded spending key from 32-byte spending key */
static void expsk_from_spending_key(struct zip32_expsk *expsk,
                                     const uint8_t sk[32])
{
    uint8_t digest[64];

    /* ask = Fs::to_uniform(PRF^expand(sk, 0x00)) */
    uint8_t tag0 = 0x00;
    prf_expand(digest, sk, 32, &tag0, 1);
    struct fs ask_fs;
    fs_to_uniform(&ask_fs, digest);
    fs_to_bytes(expsk->ask, &ask_fs);

    /* nsk = Fs::to_uniform(PRF^expand(sk, 0x01)) */
    uint8_t tag1 = 0x01;
    prf_expand(digest, sk, 32, &tag1, 1);
    struct fs nsk_fs;
    fs_to_uniform(&nsk_fs, digest);
    fs_to_bytes(expsk->nsk, &nsk_fs);

    /* ovk = PRF^expand(sk, 0x02)[0..32] */
    uint8_t tag2 = 0x02;
    prf_expand(digest, sk, 32, &tag2, 1);
    memcpy(expsk->ovk, digest, 32);

    memory_cleanse(digest, sizeof(digest));
    memory_cleanse(&ask_fs, sizeof(ask_fs));
    memory_cleanse(&nsk_fs, sizeof(nsk_fs));
}

/* Derive FVK from expanded spending key */
static void fvk_from_expsk(struct zip32_fvk *fvk,
                            const struct zip32_expsk *expsk)
{
    sapling_ask_to_ak(expsk->ask, fvk->ak);
    sapling_nsk_to_nk(expsk->nsk, fvk->nk);
    memcpy(fvk->ovk, expsk->ovk, 32);
}

/* FVK fingerprint: BLAKE2b-256("ZcashSaplingFVFP", ak || nk || ovk) */
static void fvk_fingerprint(uint8_t fp[32],
                             const struct zip32_fvk *fvk)
{
    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, ZIP32_FVFP_PERSONAL);
    blake2b_update(&ctx, fvk->ak, 32);
    blake2b_update(&ctx, fvk->nk, 32);
    blake2b_update(&ctx, fvk->ovk, 32);
    blake2b_final(&ctx, fp, 32);
}

/* FVK tag: first 4 bytes of fingerprint (as little-endian u32) */
static uint32_t fvk_tag(const struct zip32_fvk *fvk)
{
    uint8_t fp[32];
    fvk_fingerprint(fp, fvk);
    uint32_t tag = (uint32_t)fp[0] | ((uint32_t)fp[1] << 8) |
                   ((uint32_t)fp[2] << 16) | ((uint32_t)fp[3] << 24);
    memory_cleanse(fp, sizeof(fp));
    return tag;
}

/* Derive child expanded spending key: ask_child = ask_parent + to_uniform(prf(i_l, 0x13))
 * nsk_child = nsk_parent + to_uniform(prf(i_l, 0x14))
 * ovk_child = prf(i_l, [0x15, parent_ovk])[0..32] */
static void expsk_derive_child(struct zip32_expsk *child,
                                const struct zip32_expsk *parent,
                                const uint8_t i_l[32])
{
    uint8_t digest[64];

    /* ask_child = parent.ask + to_uniform(prf(i_l, 0x13)) */
    uint8_t tag13 = 0x13;
    prf_expand(digest, i_l, 32, &tag13, 1);
    struct fs i_ask, parent_ask, child_ask;
    fs_to_uniform(&i_ask, digest);
    fs_from_bytes(&parent_ask, parent->ask);
    fs_add(&child_ask, &parent_ask, &i_ask);
    fs_to_bytes(child->ask, &child_ask);

    /* nsk_child = parent.nsk + to_uniform(prf(i_l, 0x14)) */
    uint8_t tag14 = 0x14;
    prf_expand(digest, i_l, 32, &tag14, 1);
    struct fs i_nsk, parent_nsk, child_nsk;
    fs_to_uniform(&i_nsk, digest);
    fs_from_bytes(&parent_nsk, parent->nsk);
    fs_add(&child_nsk, &parent_nsk, &i_nsk);
    fs_to_bytes(child->nsk, &child_nsk);

    /* ovk_child = prf(i_l, [0x15, parent_ovk])[0..32] */
    uint8_t tag15_ovk[33];
    tag15_ovk[0] = 0x15;
    memcpy(tag15_ovk + 1, parent->ovk, 32);
    prf_expand(digest, i_l, 32, tag15_ovk, 33);
    memcpy(child->ovk, digest, 32);

    memory_cleanse(digest, sizeof(digest));
    memory_cleanse(&i_ask, sizeof(i_ask));
    memory_cleanse(&parent_ask, sizeof(parent_ask));
    memory_cleanse(&child_ask, sizeof(child_ask));
    memory_cleanse(&i_nsk, sizeof(i_nsk));
    memory_cleanse(&parent_nsk, sizeof(parent_nsk));
    memory_cleanse(&child_nsk, sizeof(child_nsk));
}

/* Derive diversifier key: dk = prf(sk, 0x10)[0..32] */
static void dk_master(uint8_t dk[32], const uint8_t sk[32])
{
    uint8_t digest[64];
    uint8_t tag = 0x10;
    prf_expand(digest, sk, 32, &tag, 1);
    memcpy(dk, digest, 32);
    memory_cleanse(digest, sizeof(digest));
}

static void dk_derive_child(uint8_t child_dk[32], const uint8_t *i_l,
                              const uint8_t parent_dk[32])
{
    uint8_t tag_dk[33];
    tag_dk[0] = 0x16;
    memcpy(tag_dk + 1, parent_dk, 32);
    uint8_t digest[64];
    prf_expand(digest, i_l, 32, tag_dk, 33);
    memcpy(child_dk, digest, 32);
    memory_cleanse(digest, sizeof(digest));
}

/* Serialize FVK to 96 bytes: ak(32) || nk(32) || ovk(32) */
static void fvk_to_bytes(uint8_t out[96],
                          const struct zip32_fvk *fvk)
{
    memcpy(out, fvk->ak, 32);
    memcpy(out + 32, fvk->nk, 32);
    memcpy(out + 64, fvk->ovk, 32);
}

/* Serialize expsk to 96 bytes: ask(32) || nsk(32) || ovk(32) */
static void expsk_to_bytes(uint8_t out[96],
                            const struct zip32_expsk *expsk)
{
    memcpy(out, expsk->ask, 32);
    memcpy(out + 32, expsk->nsk, 32);
    memcpy(out + 64, expsk->ovk, 32);
}

void zip32_xsk_master(struct zip32_xsk *xsk,
                      const uint8_t *seed, size_t seed_len)
{
    struct blake2b_ctx ctx;
    uint8_t i_master[64];

    blake2b_init_salt_personal(&ctx, 64, NULL, 0, NULL, ZIP32_MASTER_PERSONAL);
    blake2b_update(&ctx, seed, seed_len);
    blake2b_final(&ctx, i_master, 64);

    const uint8_t *sk_m = i_master;

    xsk->depth = 0;
    xsk->parent_fvk_tag = 0;
    xsk->child_index = 0;
    memcpy(xsk->chain_code, i_master + 32, 32);
    expsk_from_spending_key(&xsk->expsk, sk_m);
    dk_master(xsk->dk, sk_m);
    memory_cleanse(i_master, sizeof(i_master));
}

void zip32_xsk_derive(struct zip32_xsk *child,
                      const struct zip32_xsk *parent,
                      uint32_t i)
{
    struct zip32_fvk fvk;
    fvk_from_expsk(&fvk, &parent->expsk);

    uint8_t tmp[64];
    uint8_t le_i[4] = {
        (uint8_t)(i & 0xff), (uint8_t)((i >> 8) & 0xff),
        (uint8_t)((i >> 16) & 0xff), (uint8_t)((i >> 24) & 0xff)
    };

    if (i >= ZIP32_HARDENED_KEY_LIMIT) {
        /* Hardened: PRF^expand(chain_code, 0x11 || expsk_bytes || dk || le_i) */
        uint8_t expsk_bytes[96];
        expsk_to_bytes(expsk_bytes, &parent->expsk);

        uint8_t tag = 0x11;
        const uint8_t *parts[] = { &tag, expsk_bytes, parent->dk, le_i };
        size_t lens[] = { 1, 96, 32, 4 };
        prf_expand_vec(tmp, parent->chain_code, 32, parts, lens, 4);
        memory_cleanse(expsk_bytes, sizeof(expsk_bytes));
    } else {
        /* Non-hardened: PRF^expand(chain_code, 0x12 || fvk_bytes || dk || le_i) */
        uint8_t fvk_bytes[96];
        fvk_to_bytes(fvk_bytes, &fvk);

        uint8_t tag = 0x12;
        const uint8_t *parts[] = { &tag, fvk_bytes, parent->dk, le_i };
        size_t lens[] = { 1, 96, 32, 4 };
        prf_expand_vec(tmp, parent->chain_code, 32, parts, lens, 4);
        memory_cleanse(fvk_bytes, sizeof(fvk_bytes));
    }

    const uint8_t *i_l = tmp;

    child->depth = parent->depth + 1;
    child->parent_fvk_tag = fvk_tag(&fvk);
    child->child_index = i;
    memcpy(child->chain_code, tmp + 32, 32);
    expsk_derive_child(&child->expsk, &parent->expsk, i_l);
    dk_derive_child(child->dk, i_l, parent->dk);
    memory_cleanse(tmp, sizeof(tmp));
    memory_cleanse(&fvk, sizeof(fvk));
}

void zip32_xsk_to_xfvk(struct zip32_xfvk *xfvk,
                        const struct zip32_xsk *xsk)
{
    xfvk->depth = xsk->depth;
    xfvk->parent_fvk_tag = xsk->parent_fvk_tag;
    xfvk->child_index = xsk->child_index;
    memcpy(xfvk->chain_code, xsk->chain_code, 32);
    fvk_from_expsk(&xfvk->fvk, &xsk->expsk);
    memcpy(xfvk->dk, xsk->dk, 32);
}

/* FVK child derivation */
static void fvk_derive_child(struct zip32_fvk *child,
                               const struct zip32_fvk *parent,
                               const uint8_t i_l[32])
{
    uint8_t digest[64];

    /* i_ask = to_uniform(prf(i_l, 0x13)) */
    uint8_t tag13 = 0x13;
    prf_expand(digest, i_l, 32, &tag13, 1);
    struct fs i_ask;
    fs_to_uniform(&i_ask, digest);
    uint8_t i_ask_bytes[32];
    fs_to_bytes(i_ask_bytes, &i_ask);

    /* ak_child = SpendingKeyGenerator * i_ask + parent.ak */
    uint8_t i_ak[32];
    sapling_ask_to_ak(i_ask_bytes, i_ak);
    struct jub_point ak_parent, ak_i, ak_child;
    jub_from_bytes(&ak_parent, parent->ak);
    jub_from_bytes(&ak_i, i_ak);
    jub_add(&ak_child, &ak_i, &ak_parent);
    jub_to_bytes(child->ak, &ak_child);

    /* i_nsk = to_uniform(prf(i_l, 0x14)) */
    uint8_t tag14 = 0x14;
    prf_expand(digest, i_l, 32, &tag14, 1);
    struct fs i_nsk;
    fs_to_uniform(&i_nsk, digest);
    uint8_t i_nsk_bytes[32];
    fs_to_bytes(i_nsk_bytes, &i_nsk);

    /* nk_child = ProofGenerationKey * i_nsk + parent.nk */
    uint8_t i_nk[32];
    sapling_nsk_to_nk(i_nsk_bytes, i_nk);
    struct jub_point nk_parent, nk_i, nk_child;
    jub_from_bytes(&nk_parent, parent->nk);
    jub_from_bytes(&nk_i, i_nk);
    jub_add(&nk_child, &nk_i, &nk_parent);
    jub_to_bytes(child->nk, &nk_child);

    /* ovk_child */
    uint8_t tag15_ovk[33];
    tag15_ovk[0] = 0x15;
    memcpy(tag15_ovk + 1, parent->ovk, 32);
    prf_expand(digest, i_l, 32, tag15_ovk, 33);
    memcpy(child->ovk, digest, 32);

    memory_cleanse(digest, sizeof(digest));
    memory_cleanse(&i_ask, sizeof(i_ask));
    memory_cleanse(i_ask_bytes, sizeof(i_ask_bytes));
    memory_cleanse(&i_nsk, sizeof(i_nsk));
    memory_cleanse(i_nsk_bytes, sizeof(i_nsk_bytes));
}

bool zip32_xfvk_derive(struct zip32_xfvk *child,
                        const struct zip32_xfvk *parent,
                        uint32_t i)
{
    if (i >= ZIP32_HARDENED_KEY_LIMIT)
        LOG_FAIL("zip32",
                 "xfvk_derive: child index %u >= hardened limit %u",
                 i, ZIP32_HARDENED_KEY_LIMIT);

    uint8_t fvk_bytes[96];
    fvk_to_bytes(fvk_bytes, &parent->fvk);

    uint8_t le_i[4] = {
        (uint8_t)(i & 0xff), (uint8_t)((i >> 8) & 0xff),
        (uint8_t)((i >> 16) & 0xff), (uint8_t)((i >> 24) & 0xff)
    };

    uint8_t tag = 0x12;
    const uint8_t *parts[] = { &tag, fvk_bytes, parent->dk, le_i };
    size_t lens[] = { 1, 96, 32, 4 };
    uint8_t tmp[64];
    prf_expand_vec(tmp, parent->chain_code, 32, parts, lens, 4);

    const uint8_t *i_l = tmp;

    child->depth = parent->depth + 1;
    child->parent_fvk_tag = fvk_tag(&parent->fvk);
    child->child_index = i;
    memcpy(child->chain_code, tmp + 32, 32);
    fvk_derive_child(&child->fvk, &parent->fvk, i_l);
    dk_derive_child(child->dk, i_l, parent->dk);
    memory_cleanse(tmp, sizeof(tmp));
    memory_cleanse(fvk_bytes, sizeof(fvk_bytes));

    return true;
}

/* Diversifier derivation via FF1 */
static bool diversifier_index_increment(uint8_t j[11])
{
    for (int k = 0; k < 11; k++) {
        j[k]++;
        if (j[k] != 0)
            return true;
    }
    LOG_FAIL("zip32",
             "diversifier_index_increment: 2^88 diversifier space exhausted");
}

bool zip32_diversifier(const uint8_t dk[32],
                       uint8_t j[11], uint8_t diversifier[11])
{
    for (;;) {
        uint8_t d[11];
        memcpy(d, j, 11);
        ff1_aes256_encrypt(dk, NULL, 0, d, 88);
        memcpy(diversifier, d, 11);

        if (sapling_check_diversifier(diversifier))
            return true;

        if (!diversifier_index_increment(j))
            LOG_FAIL("zip32",
                     "zip32_diversifier: no valid diversifier found in the whole index space");
    }
}

bool zip32_default_diversifier(const uint8_t dk[32], uint8_t diversifier[11])
{
    uint8_t j[11] = {0};
    return zip32_diversifier(dk, j, diversifier);
}

bool zip32_xfvk_address(const struct zip32_xfvk *xfvk,
                         uint8_t diversifier[11], uint8_t pk_d[32])
{
    if (!zip32_default_diversifier(xfvk->dk, diversifier))
        LOG_FAIL("zip32", "xfvk_address: zip32_default_diversifier failed");

    /* Compute ivk from ak, nk */
    uint8_t ivk[32];
    sapling_crh_ivk(xfvk->fvk.ak, xfvk->fvk.nk, ivk);

    /* pk_d = ivk * g_d(diversifier) */
    bool ok = sapling_ivk_to_pkd(ivk, diversifier, pk_d);
    memory_cleanse(ivk, sizeof(ivk));
    return ok;
}
