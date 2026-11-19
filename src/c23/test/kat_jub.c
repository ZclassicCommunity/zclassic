/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). See kat_jub.h. */
#include "kat_jub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/blake2b.h"
#include "sapling/fr.h"
#include "sapling/sapling.h"

const uint8_t KAT_Q_LE[32] = {0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
                              0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73};
const uint8_t KAT_R_LE[32] = {0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
                              0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e};
const uint8_t KAT_P_BE[48] = {0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
                              0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
                              0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab};

static struct jub_point G_SPEND, G_VRAND;
static bool g_ready;

static void die(const char *m)
{
    fprintf(stderr, "kat_jub: %s\n", m);
    exit(2);
}

void kat_gen_mul(enum kat_gen g, const uint8_t s[32], uint8_t out[32])
{
    if (g == KAT_GEN_SPEND_AUTH)
        sapling_ask_to_ak(s, out);
    else if (!sapling_value_commit(0, s, out))
        die("sapling_value_commit failed");
}

void kat_jub_init(void)
{
    if (g_ready)
        return;
    uint8_t one[32] = {1}, e[32];
    kat_gen_mul(KAT_GEN_SPEND_AUTH, one, e);
    if (!jub_from_bytes(&G_SPEND, e))
        die("spend-auth generator does not decode");
    kat_gen_mul(KAT_GEN_VALUE_RAND, one, e);
    if (!jub_from_bytes(&G_VRAND, e))
        die("value-randomness generator does not decode");
    g_ready = true;
}

bool kat_point_add(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    struct jub_point pa, pb, s;
    if (!jub_from_bytes(&pa, a) || !jub_from_bytes(&pb, b))
        return false;
    jub_add(&s, &pa, &pb);
    jub_to_bytes(out, &s);
    return true;
}

static void fs_load(struct fs *f, const uint8_t a[32])
{
    if (!fs_from_bytes(f, a))
        die("scalar >= r passed to a scalar helper");
}

void kat_fs_add(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    struct fs x, y, z;
    fs_load(&x, a);
    fs_load(&y, b);
    fs_add(&z, &x, &y);
    fs_to_bytes(out, &z);
}

void kat_fs_mul(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    struct fs x, y, z;
    fs_load(&x, a);
    fs_load(&y, b);
    fs_mul(&z, &x, &y);
    fs_to_bytes(out, &z);
}

void kat_fs_negate(const uint8_t a[32], uint8_t out[32])
{
    struct fs x, z;
    fs_load(&x, a);
    fs_neg(&z, &x);
    fs_to_bytes(out, &z);
}

bool kat_fs_canonical(const uint8_t a[32])
{
    struct fs x;
    return fs_from_bytes(&x, a);
}

void kat_hstar(const uint8_t rbar[32], const uint8_t *msg, size_t msg_len, uint8_t c[32])
{
    static const uint8_t personal[16] = {'Z', 'c', 'a', 's', 'h', '_', 'R', 'e',
                                         'd', 'J', 'u', 'b', 'j', 'u', 'b', 'H'};
    struct blake2b_ctx ctx;
    uint8_t digest[64];
    if (blake2b_init_salt_personal(&ctx, 64, NULL, 0, NULL, personal) != 0 || blake2b_update(&ctx, rbar, 32) != 0 ||
        blake2b_update(&ctx, msg, msg_len) != 0 || blake2b_final(&ctx, digest, 64) != 0)
        die("blake2b failed");
    struct fs f;
    fs_to_uniform(&f, digest);
    fs_to_bytes(c, &f);
}

bool kat_rj_verify(const uint8_t vk[32], const uint8_t msg[64], const uint8_t sig[64], enum kat_gen g)
{
    kat_jub_init();
    struct jub_point v, r, cv, sg, sum, res;
    struct fs s;
    if (!jub_from_bytes(&v, vk) || !jub_from_bytes(&r, sig))
        return false;
    if (!fs_from_bytes(&s, sig + 32))
        return false;
    uint8_t c[32];
    kat_hstar(sig, msg, 64, c);
    jub_scalar_mul(&cv, &v, c);
    jub_scalar_mul(&sg, g == KAT_GEN_SPEND_AUTH ? &G_SPEND : &G_VRAND, sig + 32);
    jub_neg(&sg, &sg);
    jub_add(&sum, &cv, &r);
    jub_add(&sum, &sum, &sg);
    jub_mul_by_cofactor(&res, &sum);
    return jub_is_identity(&res);
}

void kat_rj_sign_with(const uint8_t sk[32], const uint8_t msg[64], const uint8_t rbar[32], const uint8_t n[32],
                      uint8_t sig[64])
{
    uint8_t c[32], csk[32];
    kat_hstar(rbar, msg, 64, c);
    kat_fs_mul(c, sk, csk);
    memcpy(sig, rbar, 32);
    kat_fs_add(n, csk, sig + 32);
}

bool kat_enc_y_plus_q(const uint8_t enc[32], uint8_t out[32])
{
    uint8_t y[32];
    memcpy(y, enc, 32);
    uint8_t sign = y[31] & 0x80;
    y[31] &= 0x7f;
    unsigned carry = 0;
    for (int i = 0; i < 32; i++) {
        unsigned v = (unsigned)y[i] + KAT_Q_LE[i] + carry;
        out[i] = (uint8_t)v;
        carry = v >> 8;
    }
    if (carry || (out[31] & 0x80))
        return false;
    out[31] |= sign;
    return true;
}

bool kat_bls_x_plus_p(const uint8_t in[48], uint8_t out[48])
{
    uint8_t flags = in[0] & 0xe0;
    uint8_t x[48];
    memcpy(x, in, 48);
    x[0] &= 0x1f;
    unsigned carry = 0;
    for (int i = 47; i >= 0; i--) {
        unsigned v = (unsigned)x[i] + KAT_P_BE[i] + carry;
        out[i] = (uint8_t)v;
        carry = v >> 8;
    }
    if (carry || (out[0] & 0xe0))
        return false;
    out[0] |= flags;
    return true;
}
