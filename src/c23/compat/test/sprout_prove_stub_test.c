/* zclassicd-owned. TEST-ONLY stand-in for the C23 Sprout prover
 * (c23/sprout_prover/sprout_prove.c, another unit). Linked only by the
 * standalone compat smoke build when the real prover is not linked. NEVER
 * linked into zclassicd: the daemon build links the real prover (WIRING.md).
 *
 * set_params_path records the path like the real one; proving aborts with a
 * clear message rather than producing anything. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool zc23_sprout_prover_set_params_path(const char *utf8_path);
void zc23_sprout_prove(
    unsigned char *proof_out, const unsigned char *phi, const unsigned char *rt,
    const unsigned char *h_sig, const unsigned char *in_sk1, uint64_t in_value1,
    const unsigned char *in_rho1, const unsigned char *in_r1,
    const unsigned char *in_auth1, const unsigned char *in_sk2,
    uint64_t in_value2, const unsigned char *in_rho2, const unsigned char *in_r2,
    const unsigned char *in_auth2, const unsigned char *out_pk1,
    uint64_t out_value1, const unsigned char *out_r1,
    const unsigned char *out_pk2, uint64_t out_value2,
    const unsigned char *out_r2, uint64_t vpub_old, uint64_t vpub_new);

/* Exposed so the smoke test can confirm what init recorded. */
char zcl_c23_test_sprout_path[4096];

bool zc23_sprout_prover_set_params_path(const char *utf8_path)
{
    if (!utf8_path || !utf8_path[0] ||
        strlen(utf8_path) >= sizeof(zcl_c23_test_sprout_path))
        return false;
    memcpy(zcl_c23_test_sprout_path, utf8_path, strlen(utf8_path) + 1);
    return true;
}

void zc23_sprout_prove(
    unsigned char *proof_out, const unsigned char *phi, const unsigned char *rt,
    const unsigned char *h_sig, const unsigned char *in_sk1, uint64_t in_value1,
    const unsigned char *in_rho1, const unsigned char *in_r1,
    const unsigned char *in_auth1, const unsigned char *in_sk2,
    uint64_t in_value2, const unsigned char *in_rho2, const unsigned char *in_r2,
    const unsigned char *in_auth2, const unsigned char *out_pk1,
    uint64_t out_value1, const unsigned char *out_r1,
    const unsigned char *out_pk2, uint64_t out_value2,
    const unsigned char *out_r2, uint64_t vpub_old, uint64_t vpub_new)
{
    (void)proof_out; (void)phi; (void)rt; (void)h_sig; (void)in_sk1;
    (void)in_value1; (void)in_rho1; (void)in_r1; (void)in_auth1; (void)in_sk2;
    (void)in_value2; (void)in_rho2; (void)in_r2; (void)in_auth2; (void)out_pk1;
    (void)out_value1; (void)out_r1; (void)out_pk2; (void)out_value2;
    (void)out_r2; (void)vpub_old; (void)vpub_new;
    fputs("zc23_sprout_prove: TEST STUB linked (c23/sprout_prover not built "
          "into this binary); aborting\n", stderr);
    abort();
}
