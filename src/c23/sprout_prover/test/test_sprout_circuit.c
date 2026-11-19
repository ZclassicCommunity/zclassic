/* Copyright 2026 The Zclassic developers - MIT License
 *
 * Circuit-level KAT for the C23 Sprout JoinSplit circuit, against the four
 * witnesses sapling-crypto's own test_sprout_constraints uses:
 *   - the native PRF/commitment mirror reproduces the expected nf/cm/mac,
 *   - every synthesized A*B=C row is satisfied,
 *   - the shape is the reference one (1989085 constraints, 10 inputs incl. ONE),
 *   - the nine pre-allocated inputs equal the verifier's own packing
 *     (multipack_bytes_to_fr_be),
 *   - every one of three single-field mutations makes the system unsatisfied.
 * No parameter file is needed. */

#include "../sprout_circuit.h"
#include "sapling/bls12_381.h"
#include "sapling/fr.h"
#include "sprout_test_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

struct expected {
    uint8_t nf[2][32], cm[2][32], mac[2][32];
};

static const uint8_t *parse_vector(const uint8_t *p, struct sprout_js_witness *w,
                                   struct expected *e)
{
    memset(w, 0, sizeof *w);
    memcpy(w->phi, p, 32); p += 32;
    memcpy(w->rt, p, 32); p += 32;
    memcpy(w->h_sig, p, 32); p += 32;
    for (size_t i = 0; i < 2; i++) {
        if (!sprout_parse_auth(p, &w->in[i]))
            return NULL;
        p += SPROUT_AUTH_LEN;
        p += 32; /* a_pk, unused */
        w->in[i].value = rd64(p); p += 8;
        memcpy(w->in[i].rho, p, 32); p += 32;
        memcpy(w->in[i].r, p, 32); p += 32;
        memcpy(w->in[i].a_sk, p, 32); p += 32;
    }
    for (size_t i = 0; i < 2; i++) {
        memcpy(w->out[i].a_pk, p, 32); p += 32;
        w->out[i].value = rd64(p); p += 8;
        p += 32; /* rho, derived in circuit */
        memcpy(w->out[i].r, p, 32); p += 32;
    }
    w->vpub_old = rd64(p); p += 8;
    w->vpub_new = rd64(p); p += 8;
    memcpy(e->nf[0], p, 32); p += 32;
    memcpy(e->nf[1], p, 32); p += 32;
    memcpy(e->cm[0], p, 32); p += 32;
    memcpy(e->cm[1], p, 32); p += 32;
    memcpy(e->mac[0], p, 32); p += 32;
    memcpy(e->mac[1], p, 32); p += 32;
    return p;
}

static bool synth_satisfied(const struct sprout_js_witness *w, size_t *ncons,
                            size_t *nvars, size_t *nin, size_t *bad,
                            struct fr inputs_out[SPROUT_NUM_INPUTS])
{
    struct constraint_system cs;
    cs_init(&cs);
    bool ok = sprout_synthesize(&cs, w);
    *ncons = cs.num_constraints;
    *nvars = cs.num_vars;
    *nin = cs.num_inputs;
    if (inputs_out)
        for (size_t i = 0; i < SPROUT_NUM_INPUTS && i + 1 < cs.num_vars; i++)
            inputs_out[i] = cs.witness[1 + i];
    if (inputs_out) {
        /* census: the memory floor of the stored rows */
        size_t terms = 0, nonempty = 0;
        for (size_t i = 0; i < cs.num_constraints; i++) {
            const struct linear_combination *l[3] = {
                &cs.constraints[i].a, &cs.constraints[i].b, &cs.constraints[i].c };
            for (size_t k = 0; k < 3; k++) {
                terms += l[k]->num_terms;
                nonempty += l[k]->num_terms != 0;
            }
        }
        printf("  rows: %zu LC terms in %zu non-empty LCs (%.0f MiB of terms)\n",
               terms, nonempty,
               (double)terms * sizeof(struct lc_term) / (1024.0 * 1024.0));
    }
    bool sat = ok && cs_is_satisfied(&cs, bad);
    cs_free(&cs);
    return sat;
}

int main(void)
{
    const uint8_t *p = sprout_test_vectors;
    const uint8_t *end = p + sizeof sprout_test_vectors;
    size_t n = 0;
    while (p < end) {
        struct sprout_js_witness w;
        struct expected e;
        p = parse_vector(p, &w, &e);
        CHECK(p != NULL && p <= end, "vector %zu parse", n);
        if (!p || p > end)
            break;

        struct sprout_js_public pub;
        sprout_compute_public(&w, &pub);
        for (size_t i = 0; i < 2; i++) {
            CHECK(memcmp(pub.nf[i], e.nf[i], 32) == 0, "v%zu nf%zu", n, i);
            CHECK(memcmp(pub.cm[i], e.cm[i], 32) == 0, "v%zu cm%zu", n, i);
            CHECK(memcmp(pub.mac[i], e.mac[i], 32) == 0, "v%zu mac%zu", n, i);
            CHECK(w.in[i].value == 0 || memcmp(pub.root[i], w.rt, 32) == 0,
                  "v%zu root%zu", n, i);
        }

        size_t ncons, nvars, nin, bad;
        struct fr inputs[SPROUT_NUM_INPUTS];
        clock_t t0 = clock();
        bool sat = synth_satisfied(&w, &ncons, &nvars, &nin, &bad, inputs);
        double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;
        printf("vector %zu: values in=(%llu,%llu) out=(%llu,%llu) vpub=(%llu,%llu) "
               "constraints=%zu inputs=%zu aux=%zu satisfied=%d (bad=%zu) %.2fs\n",
               n, (unsigned long long)w.in[0].value,
               (unsigned long long)w.in[1].value,
               (unsigned long long)w.out[0].value,
               (unsigned long long)w.out[1].value,
               (unsigned long long)w.vpub_old, (unsigned long long)w.vpub_new,
               ncons, nin, nvars - nin - 1, (int)sat, bad, secs);
        CHECK(sat, "v%zu unsatisfied at %zu", n, bad);
        CHECK(ncons == SPROUT_NUM_CONSTRAINTS, "v%zu constraints %zu", n, ncons);
        CHECK(nin == SPROUT_NUM_INPUTS, "v%zu inputs %zu", n, nin);

        /* Inputs equal the verifier's packing. */
        uint8_t buf[272];
        memcpy(buf, w.rt, 32);
        memcpy(buf + 32, w.h_sig, 32);
        memcpy(buf + 64, e.nf[0], 32);
        memcpy(buf + 96, e.mac[0], 32);
        memcpy(buf + 128, e.nf[1], 32);
        memcpy(buf + 160, e.mac[1], 32);
        memcpy(buf + 192, e.cm[0], 32);
        memcpy(buf + 224, e.cm[1], 32);
        for (size_t i = 0; i < 8; i++) {
            buf[256 + i] = (uint8_t)(w.vpub_old >> (8 * i));
            buf[264 + i] = (uint8_t)(w.vpub_new >> (8 * i));
        }
        uint64_t limbs[16][4];
        size_t nl = 0;
        multipack_bytes_to_fr_be(limbs, &nl, buf, sizeof buf);
        CHECK(nl == SPROUT_NUM_INPUTS, "packing count %zu", nl);
        for (size_t i = 0; i < nl && i < SPROUT_NUM_INPUTS; i++) {
            uint8_t le[32], mine[32];
            for (size_t j = 0; j < 32; j++)
                le[j] = (uint8_t)(limbs[i][j / 8] >> (8 * (j % 8)));
            fr_to_bytes(mine, &inputs[i]);
            CHECK(memcmp(le, mine, 32) == 0, "v%zu input %zu differs", n, i);
        }

        if (w.in[0].value != 0 && w.in[1].value != 0) {
            /* Mutations: each must leave the system unsatisfied. */
            struct sprout_js_witness m = w;
            m.vpub_new += 1; /* unbalanced */
            CHECK(!synth_satisfied(&m, &ncons, &nvars, &nin, &bad, NULL),
                  "unbalanced witness satisfied");
            printf("  mutation unbalanced: first bad row %zu\n", bad);

            m = w;
            size_t vi = w.in[0].value ? 0 : 1;
            m.in[vi].sibling[3][7] ^= 0x01; /* wrong path */
            CHECK(!synth_satisfied(&m, &ncons, &nvars, &nin, &bad, NULL),
                  "wrong path satisfied (value=%llu)",
                  (unsigned long long)w.in[vi].value);
            printf("  mutation wrong path: first bad row %zu\n", bad);

            m = w;
            m.in[vi].a_sk[31] ^= 0x01; /* wrong key */
            CHECK(!synth_satisfied(&m, &ncons, &nvars, &nin, &bad, NULL),
                  "wrong key satisfied");
            printf("  mutation wrong key: first bad row %zu\n", bad);
        }
        if (w.in[0].value == 0 && n == 0) {
            /* Consensus semantics, not a bug: a zero-value (dummy) input's
             * path is not enforced (enforce bit may be 0), so a garbage path
             * must still be SATISFIED. Pins that we did not over-constrain. */
            struct sprout_js_witness m = w;
            m.in[0].sibling[5][1] ^= 0x80;
            CHECK(synth_satisfied(&m, &ncons, &nvars, &nin, &bad, NULL),
                  "dummy-note garbage path unsatisfied at %zu", bad);
        }
        n++;
    }
    CHECK(n == 4, "expected 4 vectors, parsed %zu", n);
    printf("%s (%d failures)\n", g_fail ? "FAILED" : "PASSED", g_fail);
    return g_fail ? 1 : 0;
}
