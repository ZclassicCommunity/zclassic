/* Copyright 2026 The Zclassic developers - MIT License
 *
 * Cross-check: the streaming prover (sprout_prove.c) and Z23's own
 * groth16_prove() (vendored groth16_prover.c, which parses the WHOLE
 * proving key with groth16_pk_read) must emit the SAME 192 bytes for the
 * same circuit, witness and blinding factors r, s. Both RNG seams are
 * test-only (SPROUT_PROVER_TESTING / ZCL_TESTING) and fed the same bytes.
 * Also checks that the Z23 proof verifies.
 *
 * usage: test_sprout_crosscheck <sprout-groth16.params>
 * Memory: loads the full key the way groth16_pk_read requires (~2 GB). */

#include "../sprout_circuit.h"
#include "../sprout_prover.h"
#include "sapling/bls12_381.h"
#include "sapling/groth16_prover.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sprout.h"
#include "sprout_test_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* r, then s: canonical, top bit clear, so both provers accept them as is. */
static const uint8_t k_blind[2][32] = {
    { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0xcc, 0xdd, 0xee, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67,
      0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0x10, 0x21 },
    { 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5,
      0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0x01, 0x10, 0x23, 0x32, 0x45, 0x54,
      0x67, 0x76, 0x89, 0x98, 0xab, 0xba, 0xcd, 0xdc, 0xef, 0x3e },
};

struct rng_state {
    int next;
};

static bool fixed_rng(void *user, uint8_t *out, size_t n)
{
    struct rng_state *s = user;
    if (n != 32 || s->next > 1)
        return false;
    memcpy(out, k_blind[s->next++], 32);
    return true;
}

static void g1c(uint8_t out[48], const struct g1_point *p)
{
    struct fp x, y;
    g1_to_affine(&x, &y, p);
    fp_to_bytes(out, &x);
    out[0] = (uint8_t)((out[0] & 0x1f) | 0x80);
    if (fp_lexicographically_largest(&y))
        out[0] |= 0x20;
}

static void g2c(uint8_t out[96], const struct g2_point *p)
{
    struct fp2 x, y;
    g2_to_affine(&x, &y, p);
    fp_to_bytes(out, &x.c1);
    fp_to_bytes(out + 48, &x.c0);
    out[0] = (uint8_t)((out[0] & 0x1f) | 0x80);
    if (fp2_lexicographically_largest(&y))
        out[0] |= 0x20;
}

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <sprout-groth16.params>\n", argv[0]);
        return 2;
    }
    /* vector 2: both inputs real-valued */
    const uint8_t *p = sprout_test_vectors + 2 * 2716;
    uint8_t phi[32], rt[32], hs[32], sk[2][32], rho[2][32], r[2][32];
    uint8_t auth[2][SPROUT_AUTH_LEN], pk[2][32], orr[2][32];
    uint64_t iv[2], ov[2];
    memcpy(phi, p, 32); p += 32;
    memcpy(rt, p, 32); p += 32;
    memcpy(hs, p, 32); p += 32;
    for (size_t i = 0; i < 2; i++) {
        memcpy(auth[i], p, SPROUT_AUTH_LEN); p += SPROUT_AUTH_LEN;
        p += 32;
        iv[i] = rd64(p); p += 8;
        memcpy(rho[i], p, 32); p += 32;
        memcpy(r[i], p, 32); p += 32;
        memcpy(sk[i], p, 32); p += 32;
    }
    for (size_t i = 0; i < 2; i++) {
        memcpy(pk[i], p, 32); p += 32;
        ov[i] = rd64(p); p += 8;
        p += 32;
        memcpy(orr[i], p, 32); p += 32;
    }
    uint64_t vold = rd64(p); p += 8;
    uint64_t vnew = rd64(p); p += 8;

    /* streaming prover with fixed r, s */
    struct rng_state rs1 = { 0 };
    zc23_sprout_set_test_rng(fixed_rng, &rs1);
    uint8_t mine[192];
    enum zc23_sprout_status st = zc23_sprout_prove_status(
        mine, phi, rt, hs, sk[0], iv[0], rho[0], r[0], auth[0], sk[1], iv[1],
        rho[1], r[1], auth[1], pk[0], ov[0], orr[0], pk[1], ov[1], orr[1],
        vold, vnew, argv[1], NULL);
    zc23_sprout_set_test_rng(NULL, NULL);
    printf("streaming prover: %s\n", zc23_sprout_status_str(st));
    if (st != ZC23_SPROUT_OK)
        return 1;

    /* Z23 groth16_prove over the fully loaded key */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("cannot open params\n");
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    rewind(f);
    uint8_t *buf = len > 0 ? malloc((size_t)len) : NULL;
    if (!buf || fread(buf, 1, (size_t)len, f) != (size_t)len) {
        printf("cannot read params\n");
        fclose(f);
        free(buf);
        return 1;
    }
    fclose(f);
    struct groth16_pk gpk;
    bool ok = groth16_pk_read(&gpk, buf, (size_t)len);
    free(buf);
    if (!ok) {
        printf("groth16_pk_read failed\n");
        return 1;
    }

    struct sprout_js_witness w;
    memset(&w, 0, sizeof w);
    memcpy(w.phi, phi, 32);
    memcpy(w.rt, rt, 32);
    memcpy(w.h_sig, hs, 32);
    for (size_t i = 0; i < 2; i++) {
        memcpy(w.in[i].a_sk, sk[i], 32);
        memcpy(w.in[i].rho, rho[i], 32);
        memcpy(w.in[i].r, r[i], 32);
        w.in[i].value = iv[i];
        if (!sprout_parse_auth(auth[i], &w.in[i]))
            return 1;
        memcpy(w.out[i].a_pk, pk[i], 32);
        memcpy(w.out[i].r, orr[i], 32);
        w.out[i].value = ov[i];
    }
    w.vpub_old = vold;
    w.vpub_new = vnew;
    struct constraint_system cs;
    cs_init(&cs);
    if (!sprout_synthesize(&cs, &w))
        return 1;
    struct rng_state rs2 = { 0 };
    groth16_set_test_rng_hook(fixed_rng, &rs2);
    struct groth16_proof gp;
    ok = groth16_prove(&gpk, &cs, &gp);
    groth16_set_test_rng_hook(NULL, NULL);
    cs_free(&cs);
    groth16_pk_free(&gpk);
    printf("Z23 groth16_prove: %s\n", ok ? "ok" : "FAILED");
    if (!ok)
        return 1;
    uint8_t theirs[192];
    g1c(theirs, &gp.a);
    g2c(theirs + 48, &gp.b);
    g1c(theirs + 144, &gp.c);

    struct sprout_js_public pub;
    sprout_compute_public(&w, &pub);
    struct groth16_vk vk;
    memset(&vk, 0, sizeof vk);
    for (size_t i = 0; i < ZCL_EMBEDDED_VK_COUNT; i++)
        if (strcmp(zcl_embedded_vks[i].name, "sprout-groth16") == 0)
            ok = groth16_vk_read_raw(&vk, zcl_embedded_vks[i].bytes,
                                     zcl_embedded_vks[i].len);
    sprout_set_vk(&vk);
    bool v_theirs = sprout_verify_groth16(theirs, rt, hs, pub.mac[0],
                                          pub.mac[1], pub.nf[0], pub.nf[1],
                                          pub.cm[0], pub.cm[1], vold, vnew);
    bool v_mine = sprout_verify_groth16(mine, rt, hs, pub.mac[0], pub.mac[1],
                                        pub.nf[0], pub.nf[1], pub.cm[0],
                                        pub.cm[1], vold, vnew);
    bool same = memcmp(mine, theirs, 192) == 0;
    printf("Z23 proof verifies: %d; streaming proof verifies: %d; "
           "byte-identical: %d\n", (int)v_theirs, (int)v_mine, (int)same);
    free(vk.ic);
    printf("%s\n", (v_theirs && v_mine && same) ? "PASSED" : "FAILED");
    return (v_theirs && v_mine && same) ? 0 : 1;
}
