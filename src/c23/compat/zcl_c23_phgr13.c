/* zclassicd-owned. See zcl_c23_phgr13.h. Thin shim over the vendored Z23 PHGR13
 * verifier; it adds no verification logic of its own. */
#include "zcl_c23_phgr13.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "sapling/bn254.h"
#include "sapling/bn254_accel.h"

/* The installed key. sprout_phgr_set_vk keeps the pointer it is given, so the
 * struct lives on the heap for the life of the process. It is written once at
 * startup (ZC_LoadParams, before any validation thread verifies a proof) under
 * g_vk_mu; verifiers read the pointer inside bn254.c without a lock. */
static pthread_mutex_t g_vk_mu = PTHREAD_MUTEX_INITIALIZER;
static struct ppzksnark_vk *g_vk;

static bool vk_equal(const struct ppzksnark_vk *a, const struct ppzksnark_vk *b)
{
    if (a->ic_len != b->ic_len)
        return false;
    if (memcmp(&a->alpha_a_g2, &b->alpha_a_g2, sizeof a->alpha_a_g2) ||
        memcmp(&a->alpha_b_g1, &b->alpha_b_g1, sizeof a->alpha_b_g1) ||
        memcmp(&a->alpha_c_g2, &b->alpha_c_g2, sizeof a->alpha_c_g2) ||
        memcmp(&a->gamma_g2, &b->gamma_g2, sizeof a->gamma_g2) ||
        memcmp(&a->gamma_beta_g1, &b->gamma_beta_g1, sizeof a->gamma_beta_g1) ||
        memcmp(&a->gamma_beta_g2, &b->gamma_beta_g2, sizeof a->gamma_beta_g2) ||
        memcmp(&a->rc_z_g2, &b->rc_z_g2, sizeof a->rc_z_g2))
        return false;
    return a->ic_len == 0 ||
           memcmp(a->ic, b->ic, a->ic_len * sizeof(struct bn_g1)) == 0;
}

bool zcl_c23_phgr13_load_vk(const unsigned char *data, size_t len)
{
    if (!data || len == 0)
        return false;
    struct ppzksnark_vk *vk = calloc(1, sizeof *vk);
    if (!vk)
        return false;
    if (!ppzksnark_vk_read(vk, data, len) || !vk->ic || vk->ic_len < 2) {
        ppzksnark_vk_free(vk);
        free(vk);
        return false;
    }
    /* Select the CPU path (BMI2+ADX or portable) now, on the loading thread,
     * so the first proof does not race for it. The engine and the Frobenius
     * table are once-initialised inside bn254.c; this only makes the order
     * deterministic. */
    (void)bn254_accel_implementation();

    pthread_mutex_lock(&g_vk_mu);
    if (g_vk && vk_equal(g_vk, vk)) {
        pthread_mutex_unlock(&g_vk_mu);
        ppzksnark_vk_free(vk);
        free(vk);
        return true;
    }
    g_vk = vk; /* a replaced key is leaked on purpose: see the header */
    sprout_phgr_set_vk(vk);
    pthread_mutex_unlock(&g_vk_mu);
    return true;
}

bool zcl_c23_phgr13_vk_loaded(void)
{
    return sprout_phgr_vk_loaded();
}

bool zcl_c23_phgr13_proof_decodes(const unsigned char proof[ZCL_C23_PHGR13_PROOF_SIZE])
{
    struct ppzksnark_proof gp;
    return ppzksnark_proof_read(&gp, proof);
}

bool zcl_c23_phgr13_verify(const unsigned char proof[ZCL_C23_PHGR13_PROOF_SIZE],
                           const unsigned char *rt,
                           const unsigned char *h_sig,
                           const unsigned char *mac1,
                           const unsigned char *mac2,
                           const unsigned char *nf1,
                           const unsigned char *nf2,
                           const unsigned char *cm1,
                           const unsigned char *cm2,
                           uint64_t vpub_old, uint64_t vpub_new)
{
    return sprout_verify_phgr13(proof, rt, h_sig, mac1, mac2, nf1, nf2, cm1, cm2,
                                vpub_old, vpub_new);
}
