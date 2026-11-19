/* Copyright 2026 The Zclassic developers - MIT License
 *
 * End-to-end test of the C23 Sprout prover against the real
 * sprout-groth16.params:
 *   1. the four sapling-crypto witnesses (dummy and real-valued inputs) prove
 *      and the proofs VERIFY under Z23's sprout_verify_groth16 with the
 *      compiled-in (published) Sprout Groth16 verifying key, using the
 *      vectors' own expected nf/cm/mac as public inputs;
 *   2. two real-valued notes in a depth-29 SHA-256 tree built here prove and
 *      verify, through the void drop-in zc23_sprout_prove();
 *   3. negative cases emit no proof: unbalanced values, wrong path, wrong key
 *      (all UNSATISFIED), a malformed auth blob (BAD_AUTH), the wrong
 *      parameter file (PARAMS_FORMAT), a missing one (PARAMS_IO); a verified
 *      proof with one bit flipped is rejected by the verifier.
 * Timing and peak memory are printed, never asserted.
 *
 * usage: test_sprout_prover <path/to/sprout-groth16.params>
 *                           [<path/to/a/different/params/file>] */

#include "../sprout_prover.h"
#include "../sprout_circuit.h"
#include "sapling/bls12_381.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sprout.h"
#include "sprout_test_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

static int g_fail = 0;
#define CHECK(c, ...)                                                          \
    do {                                                                       \
        if (!(c)) {                                                            \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                        \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
            g_fail++;                                                          \
        }                                                                      \
    } while (0)

/* Threads of this process (Linux only; -1 elsewhere). Every proof must join
 * its workers, so a count above 1 after a proof is a leak. */
static int live_threads(void)
{
#ifdef __linux__
    FILE *f = fopen("/proc/self/status", "r");
    char line[128];
    int n = -1;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "Threads: %d", &n) == 1)
            break;
    if (f)
        fclose(f);
    return n;
#else
    return -1;
#endif
}

static double peak_mib(void)
{
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc))
        return (double)pmc.PeakWorkingSetSize / (1024.0 * 1024.0);
    return -1.0;
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0)
        return (double)ru.ru_maxrss / 1024.0; /* KiB on Linux */
    return -1.0;
#endif
}

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* A JoinSplit in ABI form. */
struct abi_js {
    uint8_t phi[32], rt[32], h_sig[32];
    uint8_t sk[2][32], rho[2][32], r[2][32], auth[2][ZC23_SPROUT_AUTH_SIZE];
    uint64_t in_value[2];
    uint8_t pk[2][32], out_r[2][32];
    uint64_t out_value[2];
    uint64_t vpub_old, vpub_new;
    /* expected public outputs */
    uint8_t nf[2][32], cm[2][32], mac[2][32];
};

static const uint8_t *parse_vector(const uint8_t *p, struct abi_js *j)
{
    memset(j, 0, sizeof *j);
    memcpy(j->phi, p, 32); p += 32;
    memcpy(j->rt, p, 32); p += 32;
    memcpy(j->h_sig, p, 32); p += 32;
    for (size_t i = 0; i < 2; i++) {
        memcpy(j->auth[i], p, ZC23_SPROUT_AUTH_SIZE); p += ZC23_SPROUT_AUTH_SIZE;
        p += 32; /* a_pk */
        j->in_value[i] = rd64(p); p += 8;
        memcpy(j->rho[i], p, 32); p += 32;
        memcpy(j->r[i], p, 32); p += 32;
        memcpy(j->sk[i], p, 32); p += 32;
    }
    for (size_t i = 0; i < 2; i++) {
        memcpy(j->pk[i], p, 32); p += 32;
        j->out_value[i] = rd64(p); p += 8;
        p += 32;
        memcpy(j->out_r[i], p, 32); p += 32;
    }
    j->vpub_old = rd64(p); p += 8;
    j->vpub_new = rd64(p); p += 8;
    memcpy(j->nf[0], p, 32); p += 32;
    memcpy(j->nf[1], p, 32); p += 32;
    memcpy(j->cm[0], p, 32); p += 32;
    memcpy(j->cm[1], p, 32); p += 32;
    memcpy(j->mac[0], p, 32); p += 32;
    memcpy(j->mac[1], p, 32); p += 32;
    return p;
}

static enum zc23_sprout_status prove(const struct abi_js *j, uint8_t proof[192],
                                     const char *path,
                                     struct zc23_sprout_prove_stats *st)
{
    return zc23_sprout_prove_status(
        proof, j->phi, j->rt, j->h_sig, j->sk[0], j->in_value[0], j->rho[0],
        j->r[0], j->auth[0], j->sk[1], j->in_value[1], j->rho[1], j->r[1],
        j->auth[1], j->pk[0], j->out_value[0], j->out_r[0], j->pk[1],
        j->out_value[1], j->out_r[1], j->vpub_old, j->vpub_new, path, st);
}

static bool verify(const struct abi_js *j, const uint8_t proof[192])
{
    return sprout_verify_groth16(proof, j->rt, j->h_sig, j->mac[0], j->mac[1],
                                 j->nf[0], j->nf[1], j->cm[0], j->cm[1],
                                 j->vpub_old, j->vpub_new);
}

static bool all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= p[i];
    return acc == 0;
}

static void print_stats(const char *label, enum zc23_sprout_status s,
                        const struct zc23_sprout_prove_stats *st)
{
    printf("%-22s status=%-10s total=%.2fs (synth %.2f, qap %.2f, stream+msm %.2f, "
           "verify %.3f; H %.2f) threads=%u peak=%.0f MiB\n",
           label, s == ZC23_SPROUT_OK ? "ok" : zc23_sprout_status_str(s),
           st->total_s, st->synth_s, st->qap_s, st->msm_s, st->verify_s, st->h_s,
           st->threads, peak_mib());
}

/* ── a real depth-29 tree with two notes ──────────────────────────── */

static uint8_t g_empty[SPROUT_TREE_DEPTH + 1][32];

static void node_hash(size_t level, uint64_t index, const uint8_t leaf[2][32],
                      const uint64_t pos[2], uint8_t out[32])
{
    bool has0 = (pos[0] >> level) == index, has1 = (pos[1] >> level) == index;
    if (!has0 && !has1) {
        memcpy(out, g_empty[level], 32);
        return;
    }
    if (level == 0) {
        memcpy(out, has0 ? leaf[0] : leaf[1], 32);
        return;
    }
    uint8_t blk[64];
    node_hash(level - 1, 2 * index, leaf, pos, blk);
    node_hash(level - 1, 2 * index + 1, leaf, pos, blk + 32);
    sprout_sha256_compress(blk, out);
}

static void build_auth(const uint8_t leaf[2][32], const uint64_t pos[2],
                       size_t which, uint8_t auth[ZC23_SPROUT_AUTH_SIZE])
{
    /* librustzcash layout: depth, then siblings ROOT-first, then position. */
    auth[0] = SPROUT_TREE_DEPTH;
    uint8_t *p = auth + 1;
    for (size_t k = 0; k < SPROUT_TREE_DEPTH; k++) {
        size_t level = SPROUT_TREE_DEPTH - 1 - k;
        p[0] = 32;
        node_hash(level, (pos[which] >> level) ^ 1u, leaf, pos, p + 1);
        p += 33;
    }
    for (size_t i = 0; i < 8; i++)
        p[i] = (uint8_t)(pos[which] >> (8 * i));
}

static void fill(uint8_t *b, size_t n, uint8_t seed)
{
    uint32_t x = 0x9e3779b9u ^ seed;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        b[i] = (uint8_t)x;
    }
}

static void make_real(struct abi_js *j)
{
    memset(j, 0, sizeof *j);
    memset(g_empty[0], 0, 32);
    for (size_t l = 1; l <= SPROUT_TREE_DEPTH; l++) {
        uint8_t blk[64];
        memcpy(blk, g_empty[l - 1], 32);
        memcpy(blk + 32, g_empty[l - 1], 32);
        sprout_sha256_compress(blk, g_empty[l]);
    }
    fill(j->phi, 32, 1);
    j->phi[0] &= 0x0f; /* phi is 252 bits */
    fill(j->h_sig, 32, 2);
    for (size_t i = 0; i < 2; i++) {
        fill(j->sk[i], 32, (uint8_t)(10 + i));
        j->sk[i][0] &= 0x0f; /* a_sk is 252 bits */
        fill(j->rho[i], 32, (uint8_t)(20 + i));
        fill(j->r[i], 32, (uint8_t)(30 + i));
        fill(j->pk[i], 32, (uint8_t)(40 + i));
        fill(j->out_r[i], 32, (uint8_t)(50 + i));
    }
    j->in_value[0] = 250000000ull; /* 2.5 ZCL */
    j->in_value[1] = 1234567ull;
    j->vpub_old = 0;
    j->out_value[0] = 200000000ull;
    j->out_value[1] = 1234567ull;
    j->vpub_new = 50000000ull; /* leaves the Sprout pool */

    /* Two notes at positions that exercise both swap directions on many
     * layers, in an otherwise empty depth-29 tree. */
    uint8_t leaf[2][32];
    const uint64_t pos[2] = { 0x15a5a5aull, 0x0c3c3c3ull };
    for (size_t i = 0; i < 2; i++)
        sprout_input_note_commitment(j->sk[i], j->in_value[i], j->rho[i],
                                     j->r[i], leaf[i]);
    node_hash(SPROUT_TREE_DEPTH, 0, leaf, pos, j->rt);
    for (size_t i = 0; i < 2; i++)
        build_auth(leaf, pos, i, j->auth[i]);

    /* expected public outputs from the native mirror */
    struct sprout_js_witness w;
    memset(&w, 0, sizeof w);
    memcpy(w.phi, j->phi, 32);
    memcpy(w.rt, j->rt, 32);
    memcpy(w.h_sig, j->h_sig, 32);
    for (size_t i = 0; i < 2; i++) {
        memcpy(w.in[i].a_sk, j->sk[i], 32);
        memcpy(w.in[i].rho, j->rho[i], 32);
        memcpy(w.in[i].r, j->r[i], 32);
        w.in[i].value = j->in_value[i];
        CHECK(sprout_parse_auth(j->auth[i], &w.in[i]), "build_auth layout");
        memcpy(w.out[i].a_pk, j->pk[i], 32);
        memcpy(w.out[i].r, j->out_r[i], 32);
        w.out[i].value = j->out_value[i];
    }
    struct sprout_js_public pub;
    sprout_compute_public(&w, &pub);
    for (size_t i = 0; i < 2; i++) {
        CHECK(memcmp(pub.root[i], j->rt, 32) == 0, "real tree: note %zu root", i);
        memcpy(j->nf[i], pub.nf[i], 32);
        memcpy(j->cm[i], pub.cm[i], 32);
        memcpy(j->mac[i], pub.mac[i], 32);
    }
}

static void install_vk(struct groth16_vk *vk)
{
    memset(vk, 0, sizeof *vk);
    const struct zcl_embedded_vk *e = NULL;
    for (size_t i = 0; i < ZCL_EMBEDDED_VK_COUNT; i++)
        if (strcmp(zcl_embedded_vks[i].name, "sprout-groth16") == 0)
            e = &zcl_embedded_vks[i];
    CHECK(e != NULL, "embedded sprout-groth16 VK missing");
    if (!e)
        exit(1);
    CHECK(groth16_vk_read_raw(vk, e->bytes, e->len), "embedded VK parse");
    sprout_set_vk(vk);
}

static void expect_no_proof(const char *label, enum zc23_sprout_status got,
                            enum zc23_sprout_status want, const uint8_t proof[192])
{
    printf("%-22s status=%s\n", label, zc23_sprout_status_str(got));
    CHECK(got == want, "%s: got %s want %s", label, zc23_sprout_status_str(got),
          zc23_sprout_status_str(want));
    CHECK(all_zero(proof, 192), "%s: proof bytes emitted", label);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <sprout-groth16.params> [<other.params>]\n",
                argv[0]);
        return 2;
    }
    const char *params = argv[1];
    const char *wrong_params = argc > 2 ? argv[2] : NULL;

    struct groth16_vk vk;
    install_vk(&vk);

    uint8_t proof[192];
    struct zc23_sprout_prove_stats st;
    enum zc23_sprout_status s;

    /* 1. the sapling-crypto witnesses */
    const uint8_t *p = sprout_test_vectors;
    const uint8_t *end = p + sizeof sprout_test_vectors;
    struct abi_js keep;
    memset(&keep, 0, sizeof keep);
    for (size_t n = 0; p < end; n++) {
        struct abi_js j;
        p = parse_vector(p, &j);
        if (n == 2)
            keep = j;
        char label[32];
        snprintf(label, sizeof label, "vector %zu", n);
        s = prove(&j, proof, params, &st);
        print_stats(label, s, &st);
        CHECK(s == ZC23_SPROUT_OK, "%s: %s", label, zc23_sprout_status_str(s));
        if (n == 0)
            printf("  shape: constraints=%zu inputs=%zu aux=%zu | params h=%zu "
                   "l=%zu a=%zu b=%zu\n", st.num_constraints, st.num_inputs,
                   st.num_aux, st.h_len, st.l_len, st.a_len, st.b_len);
        bool ok = verify(&j, proof);
        CHECK(ok, "%s: proof does not verify under sprout_verify_groth16", label);
        if (n == 0 && ok) {
            proof[150] ^= 0x01; /* flip one bit of C */
            CHECK(!verify(&j, proof), "bit-flipped proof verified");
            proof[150] ^= 0x01;
            uint8_t nf0 = j.nf[0][0];
            j.nf[0][0] ^= 0x01;
            CHECK(!verify(&j, proof), "proof verified with a wrong nullifier");
            j.nf[0][0] = nf0;
        }
    }

    /* 2. real-valued notes in a real depth-29 tree, via the void ABI */
    struct abi_js real;
    make_real(&real);
    CHECK(zc23_sprout_prover_set_params_path(params), "set params path");
    memset(proof, 0xaa, sizeof proof);
    zc23_sprout_prove(proof, real.phi, real.rt, real.h_sig, real.sk[0],
                      real.in_value[0], real.rho[0], real.r[0], real.auth[0],
                      real.sk[1], real.in_value[1], real.rho[1], real.r[1],
                      real.auth[1], real.pk[0], real.out_value[0], real.out_r[0],
                      real.pk[1], real.out_value[1], real.out_r[1],
                      real.vpub_old, real.vpub_new);
    bool real_ok = verify(&real, proof);
    printf("%-22s verify=%d peak=%.0f MiB\n", "real tree (ABI)", (int)real_ok,
           peak_mib());
    CHECK(real_ok, "real-tree proof does not verify");

    /* 3. negative cases (no proof emitted) */
    struct abi_js m = real;
    m.vpub_new += 1;
    s = prove(&m, proof, params, NULL);
    expect_no_proof("unbalanced", s, ZC23_SPROUT_UNSATISFIED, proof);

    m = real;
    m.auth[0][1 + 33 * 20 + 1 + 3] ^= 0x10; /* a sibling byte */
    s = prove(&m, proof, params, NULL);
    expect_no_proof("wrong path", s, ZC23_SPROUT_UNSATISFIED, proof);

    m = real;
    m.auth[1][1 + 33 * SPROUT_TREE_DEPTH] ^= 0x01; /* position bit 0 */
    s = prove(&m, proof, params, NULL);
    expect_no_proof("wrong position", s, ZC23_SPROUT_UNSATISFIED, proof);

    m = real;
    m.sk[1][31] ^= 0x01;
    s = prove(&m, proof, params, NULL);
    expect_no_proof("wrong key", s, ZC23_SPROUT_UNSATISFIED, proof);

    m = real;
    /* lhs wraps mod 2^64 while rhs is adjusted to match the wrapped sum:
     * the circuit's 64-bit lhs check must still reject (zcash/zcash#854). */
    m.in_value[0] = UINT64_MAX - 5u;
    m.vpub_new = real.vpub_new + (UINT64_MAX - 5u) - real.in_value[0];
    s = prove(&m, proof, params, NULL);
    expect_no_proof("value overflow", s, ZC23_SPROUT_UNSATISFIED, proof);

    m = real;
    m.auth[0][0] = 28;
    s = prove(&m, proof, params, NULL);
    expect_no_proof("auth depth byte", s, ZC23_SPROUT_BAD_AUTH, proof);

    m = real;
    m.auth[1][1 + 33 * 5] = 31;
    s = prove(&m, proof, params, NULL);
    expect_no_proof("auth inner length", s, ZC23_SPROUT_BAD_AUTH, proof);

    s = prove(&keep, proof, "this/file/does/not/exist.params", NULL);
    expect_no_proof("missing params", s, ZC23_SPROUT_PARAMS_IO, proof);

    if (wrong_params) {
        s = prove(&keep, proof, wrong_params, NULL);
        expect_no_proof("wrong params file", s, ZC23_SPROUT_PARAMS_FORMAT, proof);
    }

    {
        int th = live_threads();
        printf("threads alive after the proofs: %d\n", th);
        CHECK(th == -1 || th == 1, "worker threads left running: %d", th);
    }
    free(vk.ic);
    printf("peak working set %.0f MiB\n", peak_mib());
    printf("%s (%d failures)\n", g_fail ? "FAILED" : "PASSED", g_fail);
    return g_fail ? 1 : 0;
}
