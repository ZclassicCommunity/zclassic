/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * PHGR13 differential gate, C half: the hook API of phgr13_c23.h on top of the
 * files zclassicd builds. The vendored bn254.c is included verbatim below (so its
 * static packing function is reachable) and the shim zcl_c23_phgr13.c is linked
 * unmodified. The strict verify entry, with the C++ lead-byte check, is in
 * phgr13_adapter_cpp.cpp. Test-only. */
#include "phgr13_c23.h"

#include "bn254.c" /* vendored, verbatim */

#include "zcl_c23_phgr13.h"

struct zc23_phgr13_vk {
    struct ppzksnark_vk vk; /* a second parse, for export only */
};

zc23_phgr13_vk *zc23_phgr13_vk_load(const uint8_t *data, size_t len)
{
    /* production load: installs the process-wide key */
    if (!zcl_c23_phgr13_load_vk(data, len))
        return NULL;
    zc23_phgr13_vk *h = calloc(1, sizeof *h);
    if (!h)
        return NULL;
    if (!ppzksnark_vk_read(&h->vk, data, len)) {
        free(h);
        return NULL;
    }
    return h;
}

void zc23_phgr13_vk_free(zc23_phgr13_vk *vk)
{
    if (!vk)
        return;
    ppzksnark_vk_free(&vk->vk);
    free(vk);
}

static void put_g1(uint8_t out[64], const struct bn_g1 *p)
{
    if (bn_g1_is_identity(p)) {
        memset(out, 0, 64);
        return;
    }
    struct bn_fq x, y;
    bn_g1_to_affine(&x, &y, p);
    bn_fq_to_bytes_be(out, &x);
    bn_fq_to_bytes_be(out + 32, &y);
}

static void put_g2(uint8_t out[128], const struct bn_g2 *p)
{
    if (bn_g2_is_identity(p)) {
        memset(out, 0, 128);
        return;
    }
    struct bn_fq2 x, y;
    bn_g2_to_affine(&x, &y, p);
    bn_fq_to_bytes_be(out, &x.c0);
    bn_fq_to_bytes_be(out + 32, &x.c1);
    bn_fq_to_bytes_be(out + 64, &y.c0);
    bn_fq_to_bytes_be(out + 96, &y.c1);
}

/* The decoders production uses (ppzksnark_proof_read calls exactly these). */
bool zc23_phgr13_g1_decode(const uint8_t in[ZC23_PHGR13_G1_SIZE], uint8_t out_xy[64])
{
    struct bn_g1 p;
    if (!bn_g1_decompress(&p, in))
        return false;
    put_g1(out_xy, &p);
    return true;
}

bool zc23_phgr13_g2_decode(const uint8_t in[ZC23_PHGR13_G2_SIZE], uint8_t out_xy[128])
{
    struct bn_g2 p;
    if (!bn_g2_decompress(&p, in))
        return false;
    put_g2(out_xy, &p);
    return true;
}

bool zc23_phgr13_fq2_sqrt(const uint8_t a[64], uint8_t out[64])
{
    struct bn_fq2 x, r;
    if (!bn_fq_from_bytes_be(&x.c0, a) || !bn_fq_from_bytes_be(&x.c1, a + 32))
        return false;
    if (!bn_fq2_sqrt(&r, &x))
        return false;
    bn_fq_to_bytes_be(out, &r.c0);
    bn_fq_to_bytes_be(out + 32, &r.c1);
    return true;
}

/* The vendored packing function itself, fed the byte layout
 * sprout_verify_phgr13 builds (rt || h_sig || nf1 || mac1 || nf2 || mac2 ||
 * cm1 || cm2 || vpub_old LE || vpub_new LE). */
void zc23_phgr13_pack_inputs(uint64_t out[9][4],
                             const uint8_t rt[32], const uint8_t h_sig[32],
                             const uint8_t nf1[32], const uint8_t nf2[32],
                             const uint8_t mac1[32], const uint8_t mac2[32],
                             const uint8_t cm1[32], const uint8_t cm2[32],
                             uint64_t vpub_old, uint64_t vpub_new)
{
    uint8_t input[272];
    memcpy(input, rt, 32);
    memcpy(input + 32, h_sig, 32);
    memcpy(input + 64, nf1, 32);
    memcpy(input + 96, mac1, 32);
    memcpy(input + 128, nf2, 32);
    memcpy(input + 160, mac2, 32);
    memcpy(input + 192, cm1, 32);
    memcpy(input + 224, cm2, 32);
    for (int i = 0; i < 8; i++) {
        input[256 + i] = (uint8_t)(vpub_old >> (i * 8));
        input[264 + i] = (uint8_t)(vpub_new >> (i * 8));
    }
    uint64_t pi[16][4];
    size_t n = 0;
    bn254_multipack_be(pi, &n, input, 272);
    for (size_t i = 0; i < 9 && i < n; i++)
        memcpy(out[i], pi[i], 32);
}

size_t zc23_phgr13_vk_export(const zc23_phgr13_vk *vk, uint8_t *out, size_t cap)
{
    if (!vk)
        return 0;
    size_t need = 5 * 128 + 2 * 64 + vk->vk.ic_len * 64;
    if (cap < need)
        return 0;
    uint8_t *o = out;
    put_g2(o, &vk->vk.alpha_a_g2); o += 128;
    put_g1(o, &vk->vk.alpha_b_g1); o += 64;
    put_g2(o, &vk->vk.alpha_c_g2); o += 128;
    put_g2(o, &vk->vk.gamma_g2); o += 128;
    put_g1(o, &vk->vk.gamma_beta_g1); o += 64;
    put_g2(o, &vk->vk.gamma_beta_g2); o += 128;
    put_g2(o, &vk->vk.rc_z_g2); o += 128;
    for (size_t i = 0; i < vk->vk.ic_len; i++, o += 64)
        put_g1(o, &vk->vk.ic[i]);
    return need;
}

/* The shim's verify with no C++ lead-byte check in front of it. */
bool zc23_phgr13_verify_z23_raw(const zc23_phgr13_vk *vk,
                                const uint8_t proof[ZC23_PHGR13_PROOF_SIZE],
                                const uint8_t rt[32], const uint8_t h_sig[32],
                                const uint8_t nf1[32], const uint8_t nf2[32],
                                const uint8_t mac1[32], const uint8_t mac2[32],
                                const uint8_t cm1[32], const uint8_t cm2[32],
                                uint64_t vpub_old, uint64_t vpub_new)
{
    (void)vk;
    return zcl_c23_phgr13_verify(proof, rt, h_sig, mac1, mac2, nf1, nf2, cm1, cm2, vpub_old, vpub_new);
}

/* The decode-only half the C++ side calls under ProofVerifier::Disabled(). */
bool zc23_adapter_decode_only(const uint8_t proof[ZC23_PHGR13_PROOF_SIZE])
{
    return zcl_c23_phgr13_proof_decodes(proof);
}
