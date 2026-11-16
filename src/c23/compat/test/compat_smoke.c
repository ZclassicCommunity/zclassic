/* zclassicd-owned. TEST-ONLY standalone smoke test of the librustzcash C ABI
 * shim (c23/compat). No daemon, no Rust. Build: compat/test/build-smoke.sh.
 *
 * usage: compat_smoke <params-dir> [--force-full-set]
 *
 * Checks (each prints PASS/FAIL; exit status is the failure count, capped):
 *   init with the real parameter files (UTF-16 paths on Windows)
 *   a mainnet Sprout Groth16 JoinSplit (height 476970) verifies, and Rust's
 *     reject cases (bit flips, vpub +1, proof infinity flag) do not
 *   the testnet Spend and Output of src/zcbenchmarks.cpp verify, and Rust's
 *     reject cases (bit flips, cm/anchor + q, proof infinity flag) do not
 *   sapling_key_components.json rows 0..2: every derived column
 *   ZIP-32 test vectors of src/gtest/test_zip32.cpp through the 169-byte ABI
 *   witness codec: 1065 -> 1057 bit order, statuses in Rust's order
 *   end to end: spend proof from a 1065-byte witness at position 5, output
 *     proof, spend sig, binding sig, all accepted by the verifier; Rust-only
 *     cases (zero-value spend under any anchor, position >= 2^32, wrong
 *     valueBalance, INT64_MIN, zero-description binding signature)
 *   batch API
 * Timings are printed, never asserted. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#endif

#include "librustzcash.h"
#include "witness_codec.h"

#include "crypto/blake2b.h"
#include "sapling/sapling_prover.h"

#include "sprout_tx476970.h"

#ifdef ZCL_C23_COMPAT_TESTING
void zcl_c23_test_force_full_set_fallback(bool on);
#endif
extern char zcl_c23_test_sprout_path[4096];

static int g_fail;
static int g_pass;

static void check(bool ok, const char *what)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    fflush(stdout);
    if (ok)
        g_pass++;
    else
        g_fail++;
}

static double now_s(void)
{
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
        fprintf(stderr, "timespec_get failed\n");
        exit(99);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Direct byte order (ParseHex). */
static void hex(uint8_t *out, size_t n, const char *s)
{
    if (strlen(s) != 2 * n) {
        fprintf(stderr, "hex length mismatch: want %zu bytes\n", n);
        exit(99);
    }
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "bad hex\n");
            exit(99);
        }
        out[i] = (uint8_t)(hi << 4 | lo);
    }
}

/* uint256 SetHex / uint256S order: the string is big-endian display. */
static void hex_rev(uint8_t out[32], const char *s)
{
    uint8_t t[32];
    hex(t, 32, s);
    for (int i = 0; i < 32; i++)
        out[i] = t[31 - i];
}

static void rand_bytes(uint8_t *b, size_t n)
{
    /* Test-only randomness: the glue's OS CSPRNG through generate_r. */
    uint8_t r[32];
    for (size_t i = 0; i < n; i += 32) {
        librustzcash_sapling_generate_r(r);
        memcpy(b + i, r, n - i < 32 ? n - i : 32);
    }
}

/* A random canonical Fr element (< 2^254 < q). */
static void rand_fr(uint8_t out[32])
{
    rand_bytes(out, 32);
    out[31] &= 0x3f;
}

/* out = a + q (a < q, so no 256-bit overflow). */
static void add_q(uint8_t out[32], const uint8_t a[32])
{
    static const uint8_t Q[32] = {
        0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe,
        0xff, 0x02, 0xa4, 0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8,
        0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73};
    unsigned c = 0;
    for (int i = 0; i < 32; i++) {
        unsigned s = (unsigned)a[i] + Q[i] + c;
        out[i] = (uint8_t)s;
        c = s >> 8;
    }
}

static void prf_expand(uint8_t out[64], const uint8_t sk[32], const uint8_t *t,
                       size_t tlen)
{
    static const uint8_t P[16] = {'Z', 'c', 'a', 's', 'h', '_', 'E', 'x',
                                  'p', 'a', 'n', 'd', 'S', 'e', 'e', 'd'};
    struct blake2b_ctx c;
    if (blake2b_init_salt_personal(&c, 64, NULL, 0, NULL, P) != 0 ||
        blake2b_update(&c, sk, 32) != 0 || blake2b_update(&c, t, tlen) != 0 ||
        blake2b_final(&c, out, 64) != 0) {
        fprintf(stderr, "blake2b failed\n");
        exit(99);
    }
}

/* ---------------------------------------------------------------------- */

static const char *const HASHES[3] = {
    "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c",
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028",
    "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a"};
static const char *const NAMES[3] = {"sapling-spend.params",
                                     "sapling-output.params",
                                     "sprout-groth16.params"};

/* Build the three paths as zclassicd does (path::native(): UTF-16 on
 * Windows, bytes elsewhere; length in code units, no terminator) and call
 * init. Returns the elapsed seconds. */
static double do_init(const char *dir, const char *const names[3],
                      const char *const hashes[3])
{
    codeunit *paths[3];
    size_t lens[3];
    for (int i = 0; i < 3; i++) {
        char p[4096];
        int n = snprintf(p, sizeof(p), "%s/%s", dir, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(p)) {
            fprintf(stderr, "path too long\n");
            exit(99);
        }
#if defined(_WIN32)
        int w = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, -1, NULL, 0);
        if (w <= 0) {
            fprintf(stderr, "UTF-8 path conversion failed\n");
            exit(99);
        }
        paths[i] = malloc((size_t)w * sizeof(codeunit));
        if (!paths[i] ||
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, -1,
                                (wchar_t *)paths[i], w) != w) {
            fprintf(stderr, "UTF-8 path conversion failed\n");
            exit(99);
        }
        lens[i] = (size_t)w - 1; /* code units, no terminator: like path::native() */
#else
        paths[i] = malloc(strlen(p) + 1);
        if (paths[i])
            memcpy(paths[i], p, strlen(p) + 1);
        if (!paths[i]) {
            fprintf(stderr, "oom\n");
            exit(99);
        }
        lens[i] = strlen(p);
#endif
    }
    double t0 = now_s();
    librustzcash_init_zksnark_params(paths[0], lens[0], hashes[0],
                                     paths[1], lens[1], hashes[1],
                                     paths[2], lens[2], hashes[2]);
    double t1 = now_s();
    for (int i = 0; i < 3; i++)
        free(paths[i]);
    return t1 - t0;
}

static void test_init(const char *dir, bool force_full)
{
#ifdef ZCL_C23_COMPAT_TESTING
    zcl_c23_test_force_full_set_fallback(force_full);
#else
    (void)force_full;
#endif
    double dt = do_init(dir, NAMES, HASHES);
    check(zcl_c23_params_initialized(), "init_zksnark_params completed");
    char want[4200];
    snprintf(want, sizeof(want), "%s/sprout-groth16.params", dir);
    check(strcmp(zcl_c23_test_sprout_path, want) == 0 ||
              /* Windows: the shim converts the UTF-16 path back to UTF-8 */
              strstr(zcl_c23_test_sprout_path, "sprout-groth16.params") != NULL,
          "sprout params path handed to the Sprout prover");
    printf("TIME init_zksnark_params %.3f ms; proving status after init: %s\n",
           dt * 1e3, zcl_c23_proving_status());
}

/* Each case must end in abort() (Rust panic). Returns only if it did not. */
static void run_abort_case(const char *dir, int which)
{
    uint8_t z32[32] = {0}, out[32], proof[192] = {0}, big[32], key169[169];
    memset(big, 0xff, 32);
    big[31] = 0x0f; /* >= r */
    switch (which) {
    case 1: { /* rustzcash.rs:252-254 spend hash mismatch */
        const char *h[3] = {HASHES[1], HASHES[1], HASHES[2]};
        do_init(dir, NAMES, h);
        break;
    }
    case 2: { /* rustzcash.rs:219 File::open(output).expect */
        const char *n[3] = {NAMES[0], "no-such-file.params", NAMES[2]};
        do_init(dir, n, HASHES);
        break;
    }
    case 3: /* pedersen_hash.rs:16 assert!(num < 63) */
        librustzcash_merkle_hash(63, z32, z32, out);
        break;
    case 4: /* rustzcash.rs uses SAPLING_SPEND_VK.unwrap() without init */
    {
        void *v = librustzcash_sapling_verification_ctx_init();
        uint8_t sig[64] = {0};
        librustzcash_sapling_check_spend(v, z32, z32, z32, z32, proof, sig, z32);
        break;
    }
    case 5: { /* rustzcash.rs:1471 assert_eq!(witness[0], 32) */
        do_init(dir, NAMES, HASHES);
        uint8_t ask[32], ak[32], nsk[32], rcm[32], ar[32], d[11], cv[32], rk[32];
        uint8_t w[ZCL_C23_WITNESS_SERIALIZED_LEN] = {0};
        librustzcash_sapling_generate_r(ask);
        librustzcash_sapling_generate_r(nsk);
        librustzcash_sapling_generate_r(rcm);
        librustzcash_sapling_generate_r(ar);
        librustzcash_ask_to_ak(ask, ak);
        hex(d, 11, "f19d9b797e39f337445839");
        w[0] = 31;
        void *c = librustzcash_sapling_proving_ctx_init();
        librustzcash_sapling_spend_proof(c, ak, nsk, d, rcm, ar, 1, z32, w, cv, rk, proof);
        break;
    }
    case 6: { /* SynthesisError::AssignmentMissing for an invalid diversifier
               * in the Output circuit -> create_random_proof(..).expect */
        do_init(dir, NAMES, HASHES);
        struct { uint8_t pk_d[32]; } k;
        hex_rev(k.pk_d, "1574ae41e876d7e3149fc2d3265155a945c46765f131a18cebf7c4aab0d24cdb");
        uint8_t esk[32], rcm[32], cv[32], d[11] = {0};
        librustzcash_sapling_generate_r(esk);
        librustzcash_sapling_generate_r(rcm);
        for (int i = 0; i < 256 && librustzcash_check_diversifier(d); i++)
            d[0] = (uint8_t)i;
        if (librustzcash_check_diversifier(d))
            return;
        void *c = librustzcash_sapling_proving_ctx_init();
        librustzcash_sapling_output_proof(c, esk, d, k.pk_d, rcm, 1, cv, proof);
        break;
    }
    case 7: /* zip32 ExtendedSpendingKey::read(..).expect: ask >= r */
        memset(key169, 0, sizeof(key169));
        memcpy(key169 + 41, big, 32);
        librustzcash_zip32_xsk_derive(key169, 0, key169);
        break;
    case 8: /* zip32 ExtendedFullViewingKey::read(..).expect: ak not on curve */
        memset(key169, 0, sizeof(key169));
        memset(key169 + 41, 0xff, 31);
        key169[41 + 31] = 0x7f; /* y >= q */
        librustzcash_zip32_xfvk_derive(key169, 0x80000000u, key169);
        break;
    case 9: { /* ak = identity: Spend circuit ak.assert_not_small_order ->
               * DivisionByZero -> expect panics */
        do_init(dir, NAMES, HASHES);
        uint8_t ak[32] = {1}, nsk[32], rcm[32], ar[32], d[11], cv[32], rk[32];
        uint8_t w[ZCL_C23_WITNESS_SERIALIZED_LEN];
        librustzcash_sapling_generate_r(nsk);
        librustzcash_sapling_generate_r(rcm);
        librustzcash_sapling_generate_r(ar);
        hex(d, 11, "f19d9b797e39f337445839");
        w[0] = 32;
        for (size_t k = 0; k < 32; k++) {
            w[1 + k * 33] = 32;
            memset(w + 2 + k * 33, 0, 32);
        }
        memset(w + 1 + 33 * 32, 0, 8);
        void *c = librustzcash_sapling_proving_ctx_init();
        librustzcash_sapling_spend_proof(c, ak, nsk, d, rcm, ar, 0, z32, w, cv, rk, proof);
        break;
    }
    case 10: /* Sprout proving goes to the separately linked prover */
        do_init(dir, NAMES, HASHES);
        {
            uint8_t auth[966] = {0};
            librustzcash_sprout_prove(proof, z32, z32, z32, z32, 0, z32, z32, auth,
                                      z32, 0, z32, z32, auth, z32, 0, z32, z32, 0,
                                      z32, 0, 0);
        }
        break;
    default:
        break;
    }
    printf("ABORT-CASE %d returned without aborting\n", which);
}

/* Testnet tx abbd823cbd3d4e3b52023599d81a96b74817e95ce5bb58354f979156bd22ecc8,
 * src/zcbenchmarks.cpp benchmark_verify_sapling_spend / _output. */
static const char SPEND_HEX[] =
    "8c6cf86bbb83bf0d075e5bd9bb4b5cd56141577be69f032880b11e26aa32aa5ef09fd00899e4b469fb11f38e9d09dc0379f0b11c23b5fe541765f76695120a03f0261d32af5d2a2b1e5c9a04200cd87d574dc42349de9790012ce560406a8a876a1e54cfcdc0eb74998abec2a9778330eeb2a0ac0e41d0c9ed5824fbd0dbf7da930ab299966ce333fd7bc1321dada0817aac5444e02c754069e218746bf879d5f2a20a8b028324fb2c73171e63336686aa5ec2e6e9a08eb18b87c14758c572f4531ccf6b55d09f44beb8b47563be4eff7a52598d80959dd9c9fee5ac4783d8370cb7d55d460053d3e067b5f9fe75ff2722623fb1825fcba5e9593d4205b38d1f502ff03035463043bd393a5ee039ce75a5d54f21b395255df6627ef96751566326f7d4a77d828aa21b1827282829fcbc42aad59cdb521e1a3aaa08b99ea8fe7fff0a04da31a52260fc6daeccd79bb877bdd8506614282258e15b3fe74bf71a93f4be3b770119edf99a317b205eea7d5ab800362b97384273888106c77d633600";
static const char SPEND_SIGHASH[] =
    "2dbf83fe7b88a7cbd80fac0c719483906bb9a0c4fc69071e4780d5f2c76e592c";
static const char OUTPUT_HEX[] =
    "edd742af18857e5ec2d71d346a7fe2ac97c137339bd5268eea86d32e0ff4f38f76213fa8cfed3347ac4e8572dd88aff395c0c10a59f8b3f49d2bc539ed6c726667e29d4763f914ddd0abf1cdfa84e44de87c233434c7e69b8b5b8f4623c8aa444163425bae5cef842972fed66046c1c6ce65c866ad894d02e6e6dcaae7a962d9f2ef95757a09c486928e61f0f7aed90ad0a542b0d3dc5fe140dfa7626b9315c77e03b055f19cbacd21a866e46f06c00e0c7792b2a590a611439b510a9aaffcf1073bad23e712a9268b36888e3727033eee2ab4d869f54a843f93b36ef489fb177bf74b41a9644e5d2a0a417c6ac1c8869bc9b83273d453f878ed6fd96b82a5939903f7b64ecaf68ea16e255a7fb7cc0b6d8b5608a1c6b0ed3024cc62c2f0f9c5cfc7b431ae6e9d40815557aa1d010523f9e1960de77b2274cb6710d229d475c87ae900183206ba90cb5bbc8ec0df98341b82726c705e0308ca5dc08db4db609993a1046dfb43dfd8c760be506c0bed799bb2205fc29dc2e654dce731034a23b0aaf6da0199248702ee0523c159f41f4cbfff6c35ace4dd9ae834e44e09c76a0cbdda1d3f6a2c75ad71212daf9575ab5f09ca148718e667f29ddf18c8a330a86ace18a86e89454653902aa393c84c6b694f27d0d42e24e7ac9fe34733de5ec15f5066081ce912c62c1a804a2bb4dedcef7cc80274f6bb9e89e2fce91dc50d6a73c8aefb9872f1cf3524a92626a0b8f39bbf7bf7d96ca2f770fc04d7f457021c536a506a187a93b2245471ddbfb254a71bc4a0d72c8d639a31c7b1920087ffca05c24214157e2e7b28184e91989ef0b14f9b34c3dc3cc0ac64226b9e337095870cb0885737992e120346e630a416a9b217679ce5a778fb15779c136bcecca5efe79012013d77d90b4e99dd22c8f35bc77121716e160d05bd30d288ee8886390ee436f85bdc9029df888a3a3326d9d4ddba5cb5318b3274928829d662e96fea1d601f7a306251ed8c6cc4e5a3a7a98c35a3650482a0eee08f3b4c2da9b22947c96138f1505c2f081f8972d429f3871f32bef4aaa51aa6945df8e9c9760531ac6f627d17c1518202818a91ca304fb4037875c666060597976144fcbbc48a776a2c61beb9515fa8f3ae6d3a041d320a38a8ac75cb47bb9c866ee497fc3cd13299970c4b369c1c2ceb4220af082fbecdd8114492a8e4d713b5a73396fd224b36c1185bd5e20d683e6c8db35346c47ae7401988255da7cfffdced5801067d4d296688ee8fe424b4a8a69309ce257eefb9345ebfda3f6de46bb11ec94133e1f72cd7ac54934d6cf17b3440800e70b80ebc7c7bfc6fb0fc2c";

struct spend { uint8_t cv[32], anchor[32], nf[32], rk[32], proof[192], sig[64]; };
struct output { uint8_t cv[32], cm[32], epk[32], proof[192]; };

static bool do_spend(const struct spend *s, const uint8_t sighash[32])
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    bool ok = librustzcash_sapling_check_spend(ctx, s->cv, s->anchor, s->nf, s->rk,
                                               s->proof, s->sig, sighash);
    librustzcash_sapling_verification_ctx_free(ctx);
    return ok;
}

static bool do_output(const struct output *o)
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    bool ok = librustzcash_sapling_check_output(ctx, o->cv, o->cm, o->epk, o->proof);
    librustzcash_sapling_verification_ctx_free(ctx);
    return ok;
}

static void test_testnet_vectors(void)
{
    uint8_t raw[384];
    hex(raw, sizeof(raw), SPEND_HEX);
    struct spend s;
    memcpy(s.cv, raw, 32);
    memcpy(s.anchor, raw + 32, 32);
    memcpy(s.nf, raw + 64, 32);
    memcpy(s.rk, raw + 96, 32);
    memcpy(s.proof, raw + 128, 192);
    memcpy(s.sig, raw + 320, 64);
    uint8_t sighash[32];
    hex_rev(sighash, SPEND_SIGHASH);

    uint8_t oraw[948];
    hex(oraw, sizeof(oraw), OUTPUT_HEX);
    struct output o;
    memcpy(o.cv, oraw, 32);
    memcpy(o.cm, oraw + 32, 32);
    memcpy(o.epk, oraw + 64, 32);
    memcpy(o.proof, oraw + 64 + 32 + 580 + 80, 192);

    check(do_spend(&s, sighash), "testnet spend verifies (check_spend)");
    check(do_output(&o), "testnet output verifies (check_output)");

    /* Timing: per-proof verification (reported, not asserted). */
    const int N = 20;
    double t0 = now_s();
    bool all = true;
    for (int i = 0; i < N; i++)
        all &= do_spend(&s, sighash);
    double t1 = now_s();
    for (int i = 0; i < N; i++)
        all &= do_output(&o);
    double t2 = now_s();
    check(all, "repeated verification stays true");
    printf("TIME check_spend %.3f ms/call, check_output %.3f ms/call (N=%d)\n",
           (t1 - t0) * 1e3 / N, (t2 - t1) * 1e3 / N, N);

    /* Rust reject cases on the spend. */
    struct spend m;
    uint8_t sh2[32];
    m = s; m.cv[3] ^= 1;       check(!do_spend(&m, sighash), "spend: cv bit flip rejected");
    m = s; m.anchor[3] ^= 1;   check(!do_spend(&m, sighash), "spend: anchor bit flip rejected");
    m = s; m.nf[3] ^= 1;       check(!do_spend(&m, sighash), "spend: nullifier bit flip rejected");
    m = s; m.rk[3] ^= 1;       check(!do_spend(&m, sighash), "spend: rk bit flip rejected");
    m = s; m.proof[100] ^= 1;  check(!do_spend(&m, sighash), "spend: proof bit flip rejected");
    m = s; m.sig[3] ^= 1;      check(!do_spend(&m, sighash), "spend: spendAuthSig R flip rejected");
    m = s; m.sig[40] ^= 1;     check(!do_spend(&m, sighash), "spend: spendAuthSig S flip rejected");
    memcpy(sh2, sighash, 32); sh2[0] ^= 1;
    check(!do_spend(&s, sh2), "spend: sighash flip rejected");
    m = s; add_q(m.anchor, s.anchor);
    check(!do_spend(&m, sighash), "spend: anchor + q rejected (rustzcash.rs:708-711)");
    for (int k = 0; k < 3; k++) {
        static const int off[3] = {0, 48, 144};
        m = s; m.proof[off[k]] |= 0x40;
        char msg[96];
        snprintf(msg, sizeof(msg), "spend: infinity flag in proof byte %d rejected", off[k]);
        check(!do_spend(&m, sighash), msg);
    }
    /* A clean infinity encoding for A (0xc0 then zeros). */
    m = s; memset(m.proof, 0, 48); m.proof[0] = 0xc0;
    check(!do_spend(&m, sighash), "spend: clean infinity A rejected");

    /* Rust reject cases on the output. */
    struct output n;
    n = o; n.cv[3] ^= 1;      check(!do_output(&n), "output: cv bit flip rejected");
    n = o; n.cm[3] ^= 1;      check(!do_output(&n), "output: cm bit flip rejected");
    n = o; n.epk[3] ^= 1;     check(!do_output(&n), "output: epk bit flip rejected");
    n = o; n.proof[100] ^= 1; check(!do_output(&n), "output: proof bit flip rejected");
    n = o; add_q(n.cm, o.cm);
    check(!do_output(&n), "output: cm + q rejected (rustzcash.rs:822-825)");
    for (int k = 0; k < 3; k++) {
        static const int off[3] = {0, 48, 144};
        n = o; n.proof[off[k]] |= 0x40;
        char msg[96];
        snprintf(msg, sizeof(msg), "output: infinity flag in proof byte %d rejected", off[k]);
        check(!do_output(&n), msg);
    }
}

/* sapling_key_components.json rows 0..2. */
static const char *ROWS[3][14] = {
    {"0000000000000000000000000000000000000000000000000000000000000000", "06880e0df04583674f05d25dcf1119cf18f84420407823aa47a53e474aa14885", "056e5e74ac7e2d26018533275e42b081f53133ecb6eaeaf01cb60bdda04e1130", "3bd696b9e13851865ee47c1d03acb5034e224d6e4fa4ab7c17049bd91369d198", "2016f18efa0efd770776328095bad71f793a5d8c58c298303e27e10f38ec44f3", "bad63fbd78a919fb88fb25a7270e04302d067bac19153c388386e5f2779ecff7", "04924751145f0faa2d9d71a5549d563eb145e22e50a9add7dfcb03edd07c0bb7", "f19d9b797e39f337445839", "1574ae41e876d7e3149fc2d3265155a945c46765f131a18cebf7c4aab0d24cdb", "0", "0000000000000000000000061536ec550286898e778dcc0e98e4ac39ac6d1739", "396407ddf23e088f270608ce4fd4fec95018c0bcc2c614b97ed5703215f93ccb", "0", "6340ab472775d96762e77d00462360bf5e1d868fa2439ca19fecfd4f56d6fa44"},
    {"0101010101010101010101010101010101010101010101010101010101010101", "04530aaf312c514fb79437acd728ba60ba187707ec35735ee5ff8bbf295643c9", "08cdda39d6e9955649c653b2f46f2335f3ddc80c090f1f8c005f7bd0eac2ac11", "5be4d6c9799a801b72367d3c72723bf0c88b4ac82a39d792161b6dce1062943b", "1805e38a2e5fa481f8964bff4719131902c10152d3f20b0284ae27c5ff5eff82", "d215746c8a88a84745f64dff956758eeccb30a74988b7f4acf18b98b844d53c4", "06a468fc40c21874d7052223d9d06b9d2d198d41679010b58869b266443818c5", "aef180f6e34e354b888f81", "8bd30f0622a909ba96a2a31e831092b3cfd3e9680e9ab07ba6b7dd36a33eb1a6", "12227227834928555328", "064e80dd899f863802968bdfed6b55ab15708bf1266f0300b6751a6eeea08b47", "5069d4ca72ae539ab2311ca3cf6b260ee1892f45ac018b2edf85fb0b509378b5", "763714296", "939d2e4c1763372e1dc7ad1954318883d759b21a2ab4cd83aee257a7c3b09e67"},
    {"0202020202020202020202020202020202020202020202020202020202020202", "0317426a1ac16f06cb5cf861b7c1b747af1212d8d9f36a3d06780afe7e3d1cee", "0b7f11adab2e5e8ae4bf6b6e2150422ac6766e16fd38eae87548d75537713b1d", "498f1e499fd44f772268a7e596608eba840b81d581c302835bc9dd280e39f48b", "c664ca5dd168743a9ab1a0df74fcc3e8bec734ec9d62b80a9a85deb54e5783ab", "6ea0a84d9193abf4b69eaa3115ef24dec3aa8a92b7c09c164a2e59e05380d595", "0545954130ef3d209295d23ab96fbed17d2f3e5fa9c03650e73087dca3241c47", "7599f0bf9b57cd2dc299b6", "5a2f01087790d98dd8653c5c22c6444ded5eeeee188aef5df0284b5139171466", "6007711596147559040", "0aae3ba87d1d4a016c4da07c0adb11515b3e788b9eb977cb637c4c1bb5f27c14", "51f1554e9f8387aab001b1701766968240b7b7d532c37f16737f43980aa785db", "1527428592", "141dae598fb4f91c368494914d95c40811451fb931c7b3598049ff348f6a8fe9"},
};

struct keyrow {
    uint8_t sk[32], ask[32], nsk[32], ovk[32], ak[32], nk[32], ivk[32];
    uint8_t d[11], pk_d[32], r[32], cm[32], nf[32];
    uint64_t v, pos;
};

static void load_row(int i, struct keyrow *k)
{
    hex_rev(k->sk, ROWS[i][0]);
    hex_rev(k->ask, ROWS[i][1]);
    hex_rev(k->nsk, ROWS[i][2]);
    hex_rev(k->ovk, ROWS[i][3]);
    hex_rev(k->ak, ROWS[i][4]);
    hex_rev(k->nk, ROWS[i][5]);
    hex_rev(k->ivk, ROWS[i][6]);
    hex(k->d, 11, ROWS[i][7]);
    hex_rev(k->pk_d, ROWS[i][8]);
    k->v = strtoull(ROWS[i][9], NULL, 10);
    hex_rev(k->r, ROWS[i][10]);
    hex_rev(k->cm, ROWS[i][11]);
    k->pos = strtoull(ROWS[i][12], NULL, 10);
    hex_rev(k->nf, ROWS[i][13]);
}

static void test_key_components(void)
{
    for (int i = 0; i < 3; i++) {
        struct keyrow k;
        load_row(i, &k);
        uint8_t h[64], t, x[32], y[32];
        char msg[128];
        bool ok = true;

        t = 0; prf_expand(h, k.sk, &t, 1); librustzcash_to_scalar(h, x);
        ok &= memcmp(x, k.ask, 32) == 0;
        t = 1; prf_expand(h, k.sk, &t, 1); librustzcash_to_scalar(h, x);
        ok &= memcmp(x, k.nsk, 32) == 0;
        t = 2; prf_expand(h, k.sk, &t, 1);
        ok &= memcmp(h, k.ovk, 32) == 0;
        snprintf(msg, sizeof(msg), "row %d: to_scalar -> ask, nsk; ovk", i);
        check(ok, msg);

        librustzcash_ask_to_ak(k.ask, x);
        librustzcash_nsk_to_nk(k.nsk, y);
        snprintf(msg, sizeof(msg), "row %d: ask_to_ak, nsk_to_nk", i);
        check(memcmp(x, k.ak, 32) == 0 && memcmp(y, k.nk, 32) == 0, msg);

        librustzcash_crh_ivk(k.ak, k.nk, x);
        snprintf(msg, sizeof(msg), "row %d: crh_ivk", i);
        check(memcmp(x, k.ivk, 32) == 0, msg);

        /* zcash/prf.cpp default_diversifier: first valid
         * BLAKE2b-512("Zcash_ExpandSeed", sk || 3 || i)[0..11]. */
        uint8_t blob[2], d[11];
        bool found = false;
        for (int c = 0; c < 256 && !found; c++) {
            blob[0] = 3; blob[1] = (uint8_t)c;
            prf_expand(h, k.sk, blob, 2);
            memcpy(d, h, 11);
            found = librustzcash_check_diversifier(d);
        }
        snprintf(msg, sizeof(msg), "row %d: check_diversifier finds default_d", i);
        check(found && memcmp(d, k.d, 11) == 0, msg);

        snprintf(msg, sizeof(msg), "row %d: ivk_to_pkd", i);
        check(librustzcash_ivk_to_pkd(k.ivk, k.d, x) && memcmp(x, k.pk_d, 32) == 0, msg);

        snprintf(msg, sizeof(msg), "row %d: compute_cm", i);
        check(librustzcash_sapling_compute_cm(k.d, k.pk_d, k.v, k.r, x) &&
                  memcmp(x, k.cm, 32) == 0, msg);
        snprintf(msg, sizeof(msg), "row %d: compute_nf", i);
        check(librustzcash_sapling_compute_nf(k.d, k.pk_d, k.v, k.r, k.ak, k.nk,
                                              k.pos, x) &&
                  memcmp(x, k.nf, 32) == 0, msg);

        /* Key agreement consistency: [esk][8]pk_d == [ivk][8]epk. */
        uint8_t esk[32], epk[32], s1[32], s2[32];
        librustzcash_sapling_generate_r(esk);
        bool ka = librustzcash_sapling_ka_derivepublic(k.d, esk, epk) &&
                  librustzcash_sapling_ka_agree(k.pk_d, esk, s1) &&
                  librustzcash_sapling_ka_agree(epk, k.ivk, s2) &&
                  memcmp(s1, s2, 32) == 0;
        snprintf(msg, sizeof(msg), "row %d: ka_derivepublic / ka_agree agree", i);
        check(ka, msg);

        /* Rust's false cases on wallet inputs (D8, D9). */
        uint8_t big[32];
        memset(big, 0xff, 32);
        big[31] = 0x0f; /* >= r, < 2^252 */
        snprintf(msg, sizeof(msg), "row %d: scalar >= r rejected by cm/nf/ka", i);
        check(!librustzcash_sapling_compute_cm(k.d, k.pk_d, k.v, big, x) &&
                  !librustzcash_sapling_compute_nf(k.d, k.pk_d, k.v, big, k.ak, k.nk, 0, x) &&
                  !librustzcash_sapling_ka_agree(k.pk_d, big, x) &&
                  !librustzcash_sapling_ka_derivepublic(k.d, big, x), msg);
        uint8_t badpt[32];
        memcpy(badpt, k.pk_d, 32);
        badpt[31] = (uint8_t)((badpt[31] & 0x80) | 0x7f);
        memset(badpt + 24, 0xff, 7); /* y >= q */
        snprintf(msg, sizeof(msg), "row %d: undecodable pk_d / ak / nk rejected", i);
        check(!librustzcash_sapling_compute_cm(k.d, badpt, k.v, k.r, x) &&
                  !librustzcash_sapling_compute_nf(k.d, k.pk_d, k.v, k.r, badpt, k.nk, 0, x) &&
                  !librustzcash_sapling_compute_nf(k.d, k.pk_d, k.v, k.r, k.ak, badpt, 0, x) &&
                  !librustzcash_sapling_ka_agree(badpt, esk, x), msg);
    }
    /* (0, -1): on the curve, order 2: not prime order -> compute_cm false,
     * but ka_agree accepts any curve point (rustzcash.rs:579-582). */
    uint8_t neg1[32] = {0}, x[32], one_s[32] = {1};
    /* y = q - 1, little-endian */
    static const uint8_t QM1[32] = {
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe,
        0xff, 0x02, 0xa4, 0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8,
        0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73};
    memcpy(neg1, QM1, 32);
    struct keyrow k;
    load_row(0, &k);
    check(!librustzcash_sapling_compute_cm(k.d, neg1, 0, k.r, x),
          "pk_d of order 2 rejected (as_prime_order)");
    check(librustzcash_sapling_ka_agree(neg1, one_s, x),
          "ka_agree accepts a small-order point (Rust: any point)");
    /* identity with the sign bit set (x = 0, sign 1): accepted (pre-ZIP-216) */
    uint8_t id_signed[32] = {1};
    id_signed[31] = 0x80;
    check(librustzcash_sapling_compute_cm(k.d, id_signed, 0, k.r, x),
          "pk_d = identity with sign bit decodes and is prime order (accepted)");
}

static void test_zip32(void)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)i;
    uint8_t m[169], m1[169], m12h[169], x[32];
    librustzcash_zip32_xsk_master(seed, 32, m);
    bool ok = m[0] == 0 && memcmp(m + 1, "\0\0\0\0\0\0\0\0", 8) == 0;
    hex_rev(x, "8e661820750d557e8b34733ebf7ecdfdf31c6d27724fb47aa372bf034b7c94d0");
    ok &= memcmp(m + 9, x, 32) == 0;
    hex_rev(x, "06257454c907f6510ba1c1830ebf60657760a8869ee968a2b93260d3930cc0b6");
    ok &= memcmp(m + 41, x, 32) == 0;
    hex_rev(x, "06ea21888a749fd38eb443d20a030abd2e6e997f5db4f984bd1f2f3be8ed0482");
    ok &= memcmp(m + 73, x, 32) == 0;
    hex_rev(x, "21fb4adfa42183848306ffb27719f27d76cf9bb81d023c93d4b9230389845839");
    ok &= memcmp(m + 105, x, 32) == 0;
    hex_rev(x, "72a196f93e8abc0935280ea2a96fa57d6024c9913e0f9fb3af96775bb77cc177");
    ok &= memcmp(m + 137, x, 32) == 0;
    check(ok, "zip32: master key fields");

    /* xfvk of an xsk, as SaplingExtendedSpendingKey::ToXFVK builds it. */
    #define TO_XFVK(xsk, xfvk) do { memcpy(xfvk, xsk, 41); \
        librustzcash_ask_to_ak((xsk) + 41, (xfvk) + 41); \
        librustzcash_nsk_to_nk((xsk) + 73, (xfvk) + 73); \
        memcpy((xfvk) + 105, (xsk) + 105, 64); } while (0)
    uint8_t fv[169], j0[11] = {0}, jr[11], addr[43];
    TO_XFVK(m, fv);
    static const uint8_t D_M[11] = {0xd8, 0x62, 0x1b, 0x98, 0x1c, 0xf3, 0x00, 0xe9, 0xd4, 0xcc, 0x89};
    check(librustzcash_zip32_xfvk_address(fv, j0, jr, addr) && memcmp(addr, D_M, 11) == 0,
          "zip32: master default address diversifier (FF1 bit order)");

    librustzcash_zip32_xsk_derive(m, 1, m1);
    ok = m1[0] == 1;
    ok &= m1[1] == 0x14 && m1[2] == 0xc2 && m1[3] == 0x71 && m1[4] == 0x3a; /* tag 0x3a71c214 LE */
    ok &= m1[5] == 1 && m1[6] == 0 && m1[7] == 0 && m1[8] == 0;
    hex_rev(x, "e6bcda05678a43fad229334ef0b795a590e7c50590baf0d9b9031a690c114701");
    ok &= memcmp(m1 + 9, x, 32) == 0;
    hex_rev(x, "0c357a2655b4b8d761794095df5cb402d3ba4a428cf6a88e7c2816a597c12b28");
    ok &= memcmp(m1 + 41, x, 32) == 0;
    hex_rev(x, "01ba6bff1018fd4eac04da7e3f2c6be9c229e662c5c4d1d6fc1ecafd8829a3e7");
    ok &= memcmp(m1 + 73, x, 32) == 0;
    hex_rev(x, "7474a4c518551bd82f14a7f7365a8ffa403c50cfeffedf026ada8688fc81135f");
    ok &= memcmp(m1 + 105, x, 32) == 0;
    hex_rev(x, "dcb4c170d878510e96c4a74192d7eecde9c9912b00b99a12ec91d7a232e84de0");
    ok &= memcmp(m1 + 137, x, 32) == 0;
    check(ok, "zip32: m/1 fields, tag written little-endian");
    TO_XFVK(m1, fv);
    static const uint8_t D_M1[11] = {0x8b, 0x41, 0x38, 0x32, 0x0d, 0xfa, 0xfd, 0x7b, 0x39, 0x97, 0x81};
    check(librustzcash_zip32_xfvk_address(fv, j0, jr, addr) && memcmp(addr, D_M1, 11) == 0,
          "zip32: m/1 default address");

    librustzcash_zip32_xsk_derive(m1, 2u | 0x80000000u, m12h);
    ok = m12h[0] == 2 && m12h[1] == 0xdb && m12h[2] == 0x99 && m12h[3] == 0x9e && m12h[4] == 0x07;
    ok &= m12h[5] == 2 && m12h[8] == 0x80;
    hex_rev(x, "35d4a883737742ca41a4baa92323bdb3c93dcb3b462a26b039971bedf415ce97");
    ok &= memcmp(m12h + 9, x, 32) == 0;
    hex_rev(x, "0dc6e4fe846bda925c82e632980434e17b51dac81fc4821fa71334ee3c11e88b");
    ok &= memcmp(m12h + 41, x, 32) == 0;
    hex_rev(x, "0c99a63a275c1c66734761cfb9c62fe9bd1b953f579123d3d0e769c59d057837");
    ok &= memcmp(m12h + 73, x, 32) == 0;
    hex_rev(x, "bc1328fc5eb693e18875c5149d06953b11d39447ebd6e38c023c22962e1881cf");
    ok &= memcmp(m12h + 105, x, 32) == 0;
    hex_rev(x, "377bb062dce7e0dcd8a0054d0ca4b4d1481b3710bfa1df12ca46ff9e9fa1eda3");
    ok &= memcmp(m12h + 137, x, 32) == 0;
    check(ok, "zip32: m/1/2' (hardened) fields");
    TO_XFVK(m12h, fv);
    hex_rev(x, "4138cffdf7200e52d4e9f4384481b4a4c4d070493a5e401e4ffa850f5a92c5a6");
    ok = memcmp(fv + 41, x, 32) == 0;
    hex_rev(x, "11eee22577304f660cc036bc84b3fc88d1ec50ae8a4d657beb6b211659304e30");
    ok &= memcmp(fv + 73, x, 32) == 0;
    static const uint8_t D_M12H[11] = {0xe8, 0xd0, 0x37, 0x93, 0xcd, 0xd2, 0xba, 0xcc, 0x9c, 0x70, 0x41};
    ok &= librustzcash_zip32_xfvk_address(fv, j0, jr, addr) && memcmp(addr, D_M12H, 11) == 0;
    check(ok, "zip32: m/1/2' xfvk ak, nk and default address");

    uint8_t c3[169];
    check(!librustzcash_zip32_xfvk_derive(fv, 3u | 0x80000000u, c3),
          "zip32: hardened derivation from an xfvk returns false");
    check(librustzcash_zip32_xfvk_derive(fv, 3, c3), "zip32: m/1/2'/3 from xfvk");
    ok = c3[0] == 3 && c3[1] == 0x48 && c3[2] == 0xc1 && c3[3] == 0x83 && c3[4] == 0x75 && c3[5] == 3;
    hex_rev(x, "e8e7d6a74a5a1c05be41baec7998d91f7b3603a4c0af495b0d43ba81cf7b938d");
    ok &= memcmp(c3 + 9, x, 32) == 0;
    hex_rev(x, "a3a697bdda9d648d32a97553de4754b2fac866d726d3f2c436259c507bc585b1");
    ok &= memcmp(c3 + 41, x, 32) == 0;
    hex_rev(x, "4f66c0814b769963f3bf1bc001270b50edabb27de042fc8a5607d2029e0488db");
    ok &= memcmp(c3 + 73, x, 32) == 0;
    hex_rev(x, "f61a699934dc78441324ef628b4b4721611571e8ee3bd591eb3d4b1cfae0b969");
    ok &= memcmp(c3 + 105, x, 32) == 0;
    hex_rev(x, "6ee53b1261f2c9c0f7359ab236f87b52a0f1b0ce43305cdad92ebb63c350cbbe");
    ok &= memcmp(c3 + 137, x, 32) == 0;
    static const uint8_t D_C3[11] = {0x03, 0x0f, 0xfb, 0x26, 0x3a, 0x93, 0x9e, 0x23, 0x0e, 0x96, 0xdd};
    ok &= librustzcash_zip32_xfvk_address(c3, j0, jr, addr) && memcmp(addr, D_C3, 11) == 0;
    check(ok, "zip32: m/1/2'/3 xfvk fields and default address");

    /* Non-hardened xsk and xfvk derivations agree (zip32 lib.rs tests). */
    uint8_t x3[169], fx3[169];
    librustzcash_zip32_xsk_derive(m12h, 3, x3);
    TO_XFVK(x3, fx3);
    check(memcmp(fx3, c3, 169) == 0, "zip32: xsk_derive(3) projects to xfvk_derive(3)");

    /* xfvk_address from a non-zero j: the returned j is >= the input j and
     * its diversifier is valid; resuming from j_ret returns the same address. */
    uint8_t j5[11] = {5}, jr2[11], addr2[43];
    ok = librustzcash_zip32_xfvk_address(c3, j5, jr, addr) && jr[0] >= 5 &&
         librustzcash_check_diversifier(addr) &&
         librustzcash_zip32_xfvk_address(c3, jr, jr2, addr2) &&
         memcmp(jr, jr2, 11) == 0 && memcmp(addr, addr2, 43) == 0;
    check(ok, "zip32: xfvk_address from j = 5");
    #undef TO_XFVK
}

/* ---------------------------------------------------------------------- */

struct path {
    uint8_t sib[32][32]; /* by level, leaf level 0 */
};

static void fold(const struct path *p, const uint8_t leaf[32], uint64_t pos,
                 uint8_t root[32])
{
    uint8_t cur[32], nxt[32];
    memcpy(cur, leaf, 32);
    for (size_t i = 0; i < 32; i++) {
        if ((pos >> i) & 1)
            librustzcash_merkle_hash(i, p->sib[i], cur, nxt);
        else
            librustzcash_merkle_hash(i, cur, p->sib[i], nxt);
        memcpy(cur, nxt, 32);
    }
    memcpy(root, cur, 32);
}

/* zclassicd MerklePath serialization: 0x20, root-level sibling first. */
static void serialize_path(const struct path *p, uint64_t pos,
                           uint8_t w[ZCL_C23_WITNESS_SERIALIZED_LEN])
{
    w[0] = 32;
    for (size_t k = 0; k < 32; k++) {
        w[1 + k * 33] = 32;
        memcpy(w + 2 + k * 33, p->sib[31 - k], 32);
    }
    for (int i = 0; i < 8; i++)
        w[1 + 33 * 32 + (size_t)i] = (uint8_t)(pos >> (8 * i));
}

static void test_witness_codec(const struct path *p, uint64_t pos)
{
    uint8_t w[ZCL_C23_WITNESS_SERIALIZED_LEN], c[ZCL_C23_WITNESS_COMPACT_LEN];
    uint8_t back[ZCL_C23_WITNESS_SERIALIZED_LEN];
    uint64_t got = 0;
    size_t bad = 99;
    serialize_path(p, pos, w);
    bool ok = zcl_c23_witness_to_compact(w, c, &got, &bad) == ZCL_C23_WITNESS_OK &&
              got == pos && c[0] == 32;
    for (size_t i = 0; ok && i < 32; i++)
        ok = memcmp(c + 1 + i * 33, p->sib[i], 32) == 0 &&
             c[1 + i * 33 + 32] == ((pos >> i) & 1);
    check(ok, "witness: 1065 -> 1057, compact entry i = serialized 31-i, bit = (pos>>i)&1");
    check(zcl_c23_witness_from_compact(c, pos, back) && memcmp(back, w, sizeof(w)) == 0,
          "witness: 1057 -> 1065 round trip");

    uint8_t m[ZCL_C23_WITNESS_SERIALIZED_LEN];
    memcpy(m, w, sizeof(w)); m[0] = 31;
    check(zcl_c23_witness_to_compact(m, c, &got, &bad) == ZCL_C23_WITNESS_PANIC_DEPTH,
          "witness: depth byte != 32 -> panic status (rustzcash.rs:1471)");
    memcpy(m, w, sizeof(w)); m[1 + 5 * 33] = 31;
    check(zcl_c23_witness_to_compact(m, c, &got, &bad) == ZCL_C23_WITNESS_PANIC_INNER_LEN &&
              bad == 5, "witness: inner length != 32 -> panic status at entry 5 (:1480)");
    memcpy(m, w, sizeof(w)); memset(m + 2 + 3 * 33, 0xff, 32); m[1 + 5 * 33] = 31;
    check(zcl_c23_witness_to_compact(m, c, &got, &bad) ==
              ZCL_C23_WITNESS_NONCANONICAL_SIBLING && bad == 3,
          "witness: sibling >= q at entry 3 reported before the bad length at 5 (Rust order)");
}

static void test_end_to_end(void)
{
    struct keyrow a, b;
    load_row(0, &a); /* spender */
    load_row(1, &b); /* recipient */
    const uint64_t value = 1000, out_value = 600;
    const int64_t vb = (int64_t)(value - out_value);
    const uint64_t pos = 5;

    uint8_t rcm[32], ar[32], cm[32], anchor[32];
    librustzcash_sapling_generate_r(rcm);
    librustzcash_sapling_generate_r(ar);
    check(librustzcash_sapling_compute_cm(a.d, a.pk_d, value, rcm, cm), "e2e: note cm");
    struct path p;
    for (int i = 0; i < 32; i++)
        rand_fr(p.sib[i]);
    fold(&p, cm, pos, anchor);
    test_witness_codec(&p, pos);
    uint8_t w[ZCL_C23_WITNESS_SERIALIZED_LEN];
    serialize_path(&p, pos, w);

    /* A context that never proves anything: no proving session, binding sig
     * over zero descriptions (Rust returns true; bsk = 0, bvk = identity). */
    uint8_t sighash[32], sig0[64];
    rand_bytes(sighash, 32);
    void *z = librustzcash_sapling_proving_ctx_init();
    check(z != NULL, "proving_ctx_init never returns NULL");
    check(strcmp(zcl_c23_proving_status(), "pair_armed") != 0 &&
              strcmp(zcl_c23_proving_status(), "full_set") != 0,
          "lazy proving: no proving keys loaded by ctx_init alone");
    check(!librustzcash_sapling_binding_sig(z, 1, sighash, sig0),
          "binding_sig, zero descriptions, valueBalance 1 -> false");
    check(librustzcash_sapling_binding_sig(z, 0, sighash, sig0),
          "binding_sig, zero descriptions, valueBalance 0 -> true");
    void *vz = librustzcash_sapling_verification_ctx_init();
    check(librustzcash_sapling_final_check(vz, 0, sig0, sighash),
          "final_check accepts the zero-description binding sig");
    librustzcash_sapling_verification_ctx_free(vz);
    librustzcash_sapling_proving_ctx_free(z);

    void *ctx = librustzcash_sapling_proving_ctx_init();
    uint8_t cv[32], rk[32], proof[192];
    double t0 = now_s();
    bool sp = librustzcash_sapling_spend_proof(ctx, a.ak, a.nsk, a.d, rcm, ar, value,
                                               anchor, w, cv, rk, proof);
    double t1 = now_s();
    check(sp, "e2e: spend_proof from a 1065-byte witness at position 5");
    printf("TIME spend_proof (first, includes proving session: SHA-512 pin + "
           "self-test) %.1f ms; proving status now: %s\n",
           (t1 - t0) * 1e3, zcl_c23_proving_status());

    uint8_t esk[32], rcm2[32], cv_o[32], proof_o[192], epk[32], cm_o[32];
    librustzcash_sapling_generate_r(esk);
    librustzcash_sapling_generate_r(rcm2);
    t0 = now_s();
    bool op = librustzcash_sapling_output_proof(ctx, esk, b.d, b.pk_d, rcm2, out_value,
                                                cv_o, proof_o);
    t1 = now_s();
    check(op, "e2e: output_proof");
    printf("TIME output_proof %.1f ms\n", (t1 - t0) * 1e3);
    check(librustzcash_sapling_ka_derivepublic(b.d, esk, epk) &&
              librustzcash_sapling_compute_cm(b.d, b.pk_d, out_value, rcm2, cm_o),
          "e2e: epk and output cm");

    uint8_t nf[32], ssig[64], bsig[64];
    check(librustzcash_sapling_compute_nf(a.d, a.pk_d, value, rcm, a.ak, a.nk, pos, nf),
          "e2e: nullifier");
    check(librustzcash_sapling_spend_sig(a.ask, ar, sighash, ssig), "e2e: spend_sig");
    check(!librustzcash_sapling_binding_sig(ctx, vb + 1, sighash, bsig),
          "e2e: binding_sig with a wrong valueBalance -> false (rustzcash.rs:1337)");
    check(!librustzcash_sapling_binding_sig(ctx, INT64_MIN, sighash, bsig),
          "e2e: binding_sig with INT64_MIN -> false (rustzcash.rs:1326-1329)");
    check(librustzcash_sapling_binding_sig(ctx, vb, sighash, bsig), "e2e: binding_sig");

    void *v = librustzcash_sapling_verification_ctx_init();
    check(librustzcash_sapling_check_spend(v, cv, anchor, nf, rk, proof, ssig, sighash),
          "e2e: our spend verifies");
    check(librustzcash_sapling_check_output(v, cv_o, cm_o, epk, proof_o),
          "e2e: our output verifies");
    check(!librustzcash_sapling_final_check(v, vb - 1, bsig, sighash),
          "e2e: final_check with valueBalance - 1 -> false");
    check(librustzcash_sapling_final_check(v, vb, bsig, sighash),
          "e2e: final_check (binding sig) accepts");
    librustzcash_sapling_verification_ctx_free(v);

    /* The vendored Z23 facade agrees on the same descriptions. */
    void *zv = zclassic_sapling_verification_ctx_init();
    check(zv && zclassic_sapling_check_spend(zv, cv, anchor, nf, rk, proof, ssig, sighash) &&
              zclassic_sapling_check_output(zv, cv_o, cm_o, epk, proof_o) &&
              zclassic_sapling_final_check(zv, vb, bsig, sighash),
          "e2e: Z23 facade accepts the same bundle");
    zclassic_sapling_verification_ctx_free(zv);

    /* Batch API over the same bundle plus one bad spend (nullifier changed:
     * every non-pairing check passes, the pairing fails). */
    zcl_c23_batch *bt = zcl_c23_batch_new(2, 1);
    void *bv = librustzcash_sapling_verification_ctx_init();
    uint8_t nf_bad[32];
    memcpy(nf_bad, nf, 32);
    nf_bad[0] ^= 1;
    bool qa = bt &&
              zcl_c23_batch_add_spend(bt, bv, cv, anchor, nf, rk, proof, ssig, sighash) == ZCL_C23_ITEM_QUEUED &&
              zcl_c23_batch_add_output(bt, bv, cv_o, cm_o, epk, proof_o) == ZCL_C23_ITEM_QUEUED;
    check(qa, "batch: spend and output queued");
    check(qa && zcl_c23_batch_verify(bt, NULL, NULL) && zcl_c23_batch_verify_each(bt, NULL, NULL),
          "batch: combined and per-proof verification accept");
    check(qa && librustzcash_sapling_final_check(bv, vb, bsig, sighash),
          "batch: ctx bvk accumulated by add_* closes the binding sig");
    bool bo = true;
    size_t bi = 99;
    check(qa && zcl_c23_batch_add_spend(bt, bv, cv, anchor, nf_bad, rk, proof, ssig, sighash) == ZCL_C23_ITEM_QUEUED &&
              !zcl_c23_batch_verify(bt, &bo, &bi) && !bo && bi == 1,
          "batch: a bad spend is named by index after the combined check fails");
    uint8_t pinf[192];
    memcpy(pinf, proof, 192);
    pinf[48] |= 0x40;
    check(qa && zcl_c23_batch_add_spend(bt, bv, cv, anchor, nf, rk, pinf, ssig, sighash) == ZCL_C23_ITEM_FULL,
          "batch: capacity enforced before any work");
    zcl_c23_batch_clear(bt);
    check(qa && zcl_c23_batch_add_spend(bt, bv, cv, anchor, nf, rk, pinf, ssig, sighash) == ZCL_C23_ITEM_REJECT,
          "batch: infinity-flag proof rejected at add");
    zcl_c23_batch_free(bt);
    librustzcash_sapling_verification_ctx_free(bv);
    librustzcash_sapling_proving_ctx_free(ctx);

    /* Rust's false for a non-canonical sibling (rustzcash.rs:1489-1492). */
    uint8_t wb[ZCL_C23_WITNESS_SERIALIZED_LEN];
    memcpy(wb, w, sizeof(wb));
    memset(wb + 2 + 7 * 33, 0xff, 32);
    ctx = librustzcash_sapling_proving_ctx_init();
    memset(rk, 0, 32);
    check(!librustzcash_sapling_spend_proof(ctx, a.ak, a.nsk, a.d, rcm, ar, value, anchor,
                                            wb, cv, rk, proof),
          "e2e: spend_proof with a sibling >= q -> false");
    uint8_t rk_expect[32];
    {
        /* rk was written before the witness check, as in Rust (:1455-1457). */
        void *t = librustzcash_sapling_proving_ctx_init();
        uint8_t cv2[32], pr2[192];
        uint8_t anchor_bad[32];
        add_q(anchor_bad, anchor);
        memset(rk_expect, 0, 32);
        check(!librustzcash_sapling_spend_proof(t, a.ak, a.nsk, a.d, rcm, ar, value,
                                                anchor_bad, w, cv2, rk_expect, pr2),
              "e2e: spend_proof with anchor + q -> false (:1460-1463)");
        librustzcash_sapling_proving_ctx_free(t);
    }
    check(memcmp(rk, rk_expect, 32) == 0 && (rk[0] | rk[1] | rk[2]) != 0,
          "e2e: rk is written even when spend_proof later returns false");
    /* Rust's false for a non-zero value spent under the wrong anchor. */
    uint8_t other[32];
    rand_fr(other);
    check(!librustzcash_sapling_spend_proof(ctx, a.ak, a.nsk, a.d, rcm, ar, value, other,
                                            w, cv, rk, proof),
          "e2e: value != 0 with an anchor the path does not fold to -> false");
    /* Scalar range checks (Rust Fs::from_repr). */
    uint8_t big[32];
    memset(big, 0xff, 32);
    big[31] = 0x0f;
    check(!librustzcash_sapling_spend_proof(ctx, a.ak, big, a.d, rcm, ar, value, anchor, w, cv, rk, proof) &&
              !librustzcash_sapling_spend_proof(ctx, a.ak, a.nsk, a.d, big, ar, value, anchor, w, cv, rk, proof) &&
              !librustzcash_sapling_spend_proof(ctx, a.ak, a.nsk, a.d, rcm, big, value, anchor, w, cv, rk, proof) &&
              !librustzcash_sapling_output_proof(ctx, big, b.d, b.pk_d, rcm2, 1, cv_o, proof_o) &&
              !librustzcash_sapling_output_proof(ctx, esk, b.d, b.pk_d, big, 1, cv_o, proof_o) &&
              !librustzcash_sapling_spend_sig(big, ar, sighash, ssig) &&
              !librustzcash_sapling_spend_sig(a.ask, big, sighash, ssig),
          "e2e: nsk/rcm/ar/esk/ask >= r rejected by spend_proof, output_proof, spend_sig");
    librustzcash_sapling_proving_ctx_free(ctx);

    /* Rust's TRUE for a zero-value spend under an arbitrary anchor: the
     * circuit only enforces (root - anchor) * value == 0. */
    uint8_t cm0[32], anchor0[32], cv0[32], rk0[32], proof0[192], nf0[32], sig0b[64];
    check(librustzcash_sapling_compute_cm(a.d, a.pk_d, 0, rcm, cm0), "e2e: zero-value note cm");
    rand_fr(anchor0);
    ctx = librustzcash_sapling_proving_ctx_init();
    t0 = now_s();
    bool zp = librustzcash_sapling_spend_proof(ctx, a.ak, a.nsk, a.d, rcm, ar, 0, anchor0,
                                               w, cv0, rk0, proof0);
    t1 = now_s();
    check(zp, "e2e: zero-value spend under an unrelated anchor proves (Rust parity)");
    printf("TIME spend_proof (warm session) %.1f ms\n", (t1 - t0) * 1e3);
    v = librustzcash_sapling_verification_ctx_init();
    check(zp && librustzcash_sapling_compute_nf(a.d, a.pk_d, 0, rcm, a.ak, a.nk, pos, nf0) &&
              librustzcash_sapling_spend_sig(a.ask, ar, sighash, sig0b) &&
              librustzcash_sapling_check_spend(v, cv0, anchor0, nf0, rk0, proof0, sig0b, sighash),
          "e2e: the zero-value spend verifies under that anchor");
    librustzcash_sapling_verification_ctx_free(v);

    /* position >= 2^32: the circuit sees 32 position bits, Rust's
     * self-verification uses the 64-bit nullifier -> false (per-spend
     * self-verify, rustzcash.rs:1505-1588). */
    uint8_t w64[ZCL_C23_WITNESS_SERIALIZED_LEN];
    serialize_path(&p, pos | (UINT64_C(1) << 32), w64);
    check(!librustzcash_sapling_spend_proof(ctx, a.ak, a.nsk, a.d, rcm, ar, value, anchor,
                                            w64, cv, rk, proof),
          "e2e: position >= 2^32 fails the per-spend self-verification -> false");
    librustzcash_sapling_proving_ctx_free(ctx);
    printf("INFO proving status after all contexts freed: %s\n", zcl_c23_proving_status());
}

/* ---------------------------------------------------------------------- */
/* Sprout Groth16 verification on a real mainnet JoinSplit.                */

struct rd { const uint8_t *p; size_t n, off; };

static const uint8_t *rd_take(struct rd *r, size_t k)
{
    if (r->off + k > r->n) {
        fprintf(stderr, "tx parse overrun\n");
        exit(99);
    }
    const uint8_t *q = r->p + r->off;
    r->off += k;
    return q;
}

static uint64_t rd_le(struct rd *r, size_t k)
{
    const uint8_t *q = rd_take(r, k);
    uint64_t v = 0;
    for (size_t i = k; i-- > 0;)
        v = (v << 8) | q[i];
    return v;
}

static uint64_t rd_compact(struct rd *r)
{
    uint8_t c = rd_take(r, 1)[0];
    if (c < 253) return c;
    if (c == 253) return rd_le(r, 2);
    if (c == 254) return rd_le(r, 4);
    return rd_le(r, 8);
}

struct js {
    uint64_t vpub_old, vpub_new;
    uint8_t rt[32], nf1[32], nf2[32], cm1[32], cm2[32], seed[32], mac1[32],
        mac2[32], proof[192], pubkey[32], h_sig[32];
};

static bool js_verify(const struct js *j)
{
    return librustzcash_sprout_verify(j->proof, j->rt, j->h_sig, j->mac1, j->mac2,
                                      j->nf1, j->nf2, j->cm1, j->cm2,
                                      j->vpub_old, j->vpub_new);
}

static void test_sprout_verify(void)
{
    static uint8_t raw[sizeof(SPROUT_TX476970_HEX) / 2];
    const size_t n = (sizeof(SPROUT_TX476970_HEX) - 1) / 2;
    hex(raw, n, SPROUT_TX476970_HEX);
    struct rd r = {raw, n, 0};
    uint32_t header = (uint32_t)rd_le(&r, 4);
    (void)rd_le(&r, 4); /* nVersionGroupId */
    if (header != 0x80000004u) {
        check(false, "sprout: tx is v4 Sapling format");
        return;
    }
    for (uint64_t i = 0, vin = rd_compact(&r); i < vin; i++) {
        (void)rd_take(&r, 36);
        (void)rd_take(&r, (size_t)rd_compact(&r));
        (void)rd_take(&r, 4);
    }
    for (uint64_t i = 0, vout = rd_compact(&r); i < vout; i++) {
        (void)rd_take(&r, 8);
        (void)rd_take(&r, (size_t)rd_compact(&r));
    }
    (void)rd_take(&r, 4 + 4 + 8); /* lock time, expiry, valueBalance */
    if (rd_compact(&r) != 0 || rd_compact(&r) != 0) {
        check(false, "sprout: fixture has no Sapling descriptions");
        return;
    }
    if (rd_compact(&r) != 1) {
        check(false, "sprout: fixture has one JoinSplit");
        return;
    }
    struct js j;
    j.vpub_old = rd_le(&r, 8);
    j.vpub_new = rd_le(&r, 8);
    memcpy(j.rt, rd_take(&r, 32), 32);
    memcpy(j.nf1, rd_take(&r, 32), 32);
    memcpy(j.nf2, rd_take(&r, 32), 32);
    memcpy(j.cm1, rd_take(&r, 32), 32);
    memcpy(j.cm2, rd_take(&r, 32), 32);
    (void)rd_take(&r, 32); /* ephemeralKey */
    memcpy(j.seed, rd_take(&r, 32), 32);
    memcpy(j.mac1, rd_take(&r, 32), 32);
    memcpy(j.mac2, rd_take(&r, 32), 32);
    memcpy(j.proof, rd_take(&r, 192), 192);
    (void)rd_take(&r, 2 * 601); /* ciphertexts */
    memcpy(j.pubkey, rd_take(&r, 32), 32);
    (void)rd_take(&r, 64); /* joinSplitSig */
    check(r.off == n, "sprout: fixture parsed to the end");
    /* h_sig = BLAKE2b-256("ZcashComputehSig", randomSeed || nf1 || nf2 ||
     * joinSplitPubKey), as zclassicd computes it (primitives/transaction.cpp). */
    static const uint8_t P[16] = {'Z', 'c', 'a', 's', 'h', 'C', 'o', 'm',
                                  'p', 'u', 't', 'e', 'h', 'S', 'i', 'g'};
    struct blake2b_ctx c;
    if (blake2b_init_salt_personal(&c, 32, NULL, 0, NULL, P) != 0 ||
        blake2b_update(&c, j.seed, 32) != 0 || blake2b_update(&c, j.nf1, 32) != 0 ||
        blake2b_update(&c, j.nf2, 32) != 0 || blake2b_update(&c, j.pubkey, 32) != 0 ||
        blake2b_final(&c, j.h_sig, 32) != 0) {
        fprintf(stderr, "blake2b failed\n");
        exit(99);
    }
    check(js_verify(&j), "sprout: mainnet 476970 Groth16 JoinSplit verifies");
    const int N = 10;
    double t0 = now_s();
    bool all = true;
    for (int i = 0; i < N; i++)
        all &= js_verify(&j);
    double t1 = now_s();
    check(all, "sprout: repeated verification stays true");
    printf("TIME sprout_verify %.3f ms/call (N=%d)\n", (t1 - t0) * 1e3 / N, N);

    struct js m;
    m = j; m.proof[100] ^= 1; check(!js_verify(&m), "sprout: proof bit flip rejected");
    m = j; m.rt[5] ^= 1;      check(!js_verify(&m), "sprout: rt bit flip rejected");
    m = j; m.mac2[5] ^= 1;    check(!js_verify(&m), "sprout: mac2 bit flip rejected");
    m = j; m.vpub_old += 1;   check(!js_verify(&m), "sprout: vpub_old + 1 rejected");
    m = j; m.vpub_new += 1;   check(!js_verify(&m), "sprout: vpub_new + 1 rejected");
    for (int k = 0; k < 3; k++) {
        static const int off[3] = {0, 48, 144};
        m = j; m.proof[off[k]] |= 0x40;
        char msg[96];
        snprintf(msg, sizeof(msg), "sprout: infinity flag in proof byte %d rejected", off[k]);
        check(!js_verify(&m), msg);
    }
}

static void test_misc(void)
{
    uint8_t u[32], want[32] = {1};
    librustzcash_tree_uncommitted(u);
    check(memcmp(u, want, 32) == 0, "tree_uncommitted = Fr::one()");

    /* EmptyRoot(1) of src/test/data/merkle_roots_empty_sapling.json[1]. */
    uint8_t e1[32], r[32];
    librustzcash_merkle_hash(0, u, u, e1);
    hex(r, 32, "817de36ab2d57feb077634bca77819c8e0bd298c04f6fed0e6a83cc1356ca155");
    check(memcmp(e1, r, 32) == 0, "merkle_hash(0, 1, 1) = empty root at depth 1");

    const int N = 2000;
    double t0 = now_s();
    for (int i = 0; i < N; i++)
        librustzcash_merkle_hash((size_t)(i % 32), e1, u, e1);
    double t1 = now_s();
    printf("TIME merkle_hash %.2f us/call (N=%d)\n", (t1 - t0) * 1e6 / N, N);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *dir = argc > 1 ? argv[1] : getenv("ZCASH_PARAMS");
#if defined(_WIN32)
    /* argv is in the ANSI code page; take the UTF-16 command line so a
     * non-ASCII parameter directory reaches the test intact. */
    static char wdir[4096];
    int wargc = 0;
    LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (wargv && wargc > 1) {
        if (WideCharToMultiByte(CP_UTF8, 0, wargv[1], -1, wdir, sizeof(wdir), NULL, NULL) <= 0) {
            fputs("argv conversion failed\n", stderr);
            return 2;
        }
        dir = wdir;
    }
    if (wargv)
        LocalFree(wargv);
#endif
    if (!dir) {
        fprintf(stderr, "usage: %s <params-dir> [--force-full-set]\n", argv[0]);
        return 2;
    }
    if (argc > 3 && strcmp(argv[2], "--abort-case") == 0) {
        run_abort_case(dir, atoi(argv[3]));
        return 0; /* the driver treats a normal exit as a failure */
    }
    bool force_full = argc > 2 && strcmp(argv[2], "--force-full-set") == 0;
    test_misc();
    test_init(dir, force_full);
    test_testnet_vectors();
    test_sprout_verify();
    test_key_components();
    test_zip32();
    test_end_to_end();
    printf("RESULT pass=%d fail=%d\n", g_pass, g_fail);
    return g_fail > 100 ? 100 : g_fail;
}
