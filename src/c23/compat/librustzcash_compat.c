/* zclassicd-owned. The librustzcash C ABI (librustzcash.h beside this file)
 * implemented on the vendored Z23 C23 core.
 *
 * This file is the ONLY place where a Z23 boolean becomes a zclassicd verdict.
 * Each function reproduces librustzcash at 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5
 * input for input: the same boolean, the same outputs written, abort() where
 * Rust panics (workspace Cargo.toml [profile.release] panic = 'abort'). Every
 * check carries the rustzcash.rs line it reproduces. Line numbers refer to
 * librustzcash/src/rustzcash.rs at the pin (1711 lines).
 *
 * Checks that Z23 lacks and that are restored here (plan section 3, report 01
 * divergence register):
 *   D3   Groth16 proof with the infinity flag in A, B or C   -> false
 *   D8   compute_cm / compute_nf input validation and canonical re-encoding
 *   D9   ka_agree / ka_derivepublic scalar range checks
 *   D11  spend_sig scalar range checks
 *   D13  spend_proof: Rust witness format, sibling/scalar/point checks,
 *        per-proof self-verification, Rust's abort points
 *   D14  output_proof: esk/rcm/pk_d checks, bvk accumulation
 *   D15  binding_sig: valueBalance consistency check, INT64_MIN reject,
 *        zero-description signing
 *   D6   init: Rust path ABI, full-file BLAKE2b-512 check of all three files,
 *        failure policy (abort), proving keys resident from init
 *   --   calls made before init: false or abort exactly where Rust unwraps
 *   D7   merkle_hash depth >= 63 aborts
 *   D12/D17 contexts are never NULL
 *   D20  lazily initialised constants and CPU dispatch warmed before use
 *
 * Secret handling: scalar range checks on keys use the constant-time
 * comparisons of witness_codec.c and only their verdict is branched on,
 * exactly as Rust returns false on the same condition. Key-dependent
 * multiplications go through jub_scalar_mul (constant-time table lookups).
 * Secret temporaries are wiped with memory_cleanse. */

/* POSIX declarations (open, fstat, O_CLOEXEC) under -std=c23 as well; the
 * same guard file_stream.c uses. Darwin and glibc both expose them at 2008. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GLIBC__)
#include <malloc.h>
#elif defined(__APPLE__)
#include <malloc/malloc.h>
#endif

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* The ABI symbols must stay exported when the library is built with
 * -fvisibility=hidden (WIRING.md). Visibility is fixed by the first
 * declaration, so the pragma wraps the header. PE/COFF has no ELF visibility. */
#if !defined(_WIN32)
#pragma GCC visibility push(default)
#endif
#include "librustzcash.h"
#if !defined(_WIN32)
#pragma GCC visibility pop
#endif

#include "witness_codec.h"
#include "zip32_codec.h"

#include "base/log_level.h"
#include "crypto/blake2b.h"
#include "crypto/simd_dispatch.h"
#include "sapling/bls12_381.h"
#include "sapling/bn254_accel.h"
#include "sapling/fr.h"
#include "sapling/fr_accel.h"
#include "sapling/groth16_prover.h"
#include "sapling/jubjub.h"
#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/pedersen_hash.h"
#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "sapling/sapling_prover.h"
#include "sapling/sprout.h"
#include "sapling/zip32.h"
#include "support/cleanse.h"

/* Sprout proving lives in c23/sprout_prover (another unit). It is linked as an
 * ordinary external symbol; standalone builds without it link
 * compat/test/sprout_prove_stub_test.c instead (WIRING.md). Including the
 * prover's header when it exists makes a signature drift a compile error. */
#if defined(__has_include)
#if __has_include("../sprout_prover/sprout_prover.h")
#include "../sprout_prover/sprout_prover.h"
#define ZCL_C23_HAVE_SPROUT_PROVER_H 1
#endif
#endif
#ifndef ZCL_C23_HAVE_SPROUT_PROVER_H
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
#endif

/* RedJubjub generator indices of sapling.c (documented in sapling.h). */
#define ZCL_GEN_VALUE_COMMITMENT_RANDOMNESS 4
#define ZCL_GEN_SPENDING_KEY 5

#define GROTH_PROOF_SIZE 192u /* rustzcash.rs:672-674 */

/* Canonical BLAKE2b-512 digests of the Zcash ceremony files. zclassicd passes
 * exactly these (init.cpp ZC_LoadParams, gtest/main.cpp, test_bitcoin.cpp).
 * Z23's SHA-512 pins (params_init.c) cover the same files; this was verified
 * by hashing the local files (plan, spot check S9). */
static const char SAPLING_SPEND_B2[] =
    "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63"
    "991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
static const char SAPLING_OUTPUT_B2[] =
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60b"
    "f593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
static const char SPROUT_GROTH16_B2[] =
    "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfef"
    "d5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";

/* Exact sizes of those files. A file of another size cannot have the pinned
 * digest, so refusing it at init never rejects a file Rust would accept. */
#define SAPLING_SPEND_SIZE UINT64_C(47958396)
#define SAPLING_OUTPUT_SIZE UINT64_C(3592860)
#define SPROUT_GROTH16_SIZE UINT64_C(725523612)

/* ------------------------------------------------------------------------ */
/* Failure helpers                                                           */
/* ------------------------------------------------------------------------ */

/* Rust panic under panic = 'abort': message on stderr, then abort. */
__attribute__((noreturn, cold)) static void zcl_panic(const char *msg)
{
    fprintf(stderr, "librustzcash (C23): %s\n", msg);
    fflush(stderr);
    abort();
}

/* ------------------------------------------------------------------------ */
/* Warm-up of every lazily initialised vendored constant (plan section 3).   */
/* ------------------------------------------------------------------------ */

static atomic_bool g_warm;
static pthread_once_t g_warm_once = PTHREAD_ONCE_INIT;
static struct jub_point G_VALUE;      /* ValueCommitmentValue */
static struct jub_point G_VALUE_RAND; /* ValueCommitmentRandomness */

static void point_from_xy(struct jub_point *p, const struct fr *x,
                          const struct fr *y)
{
    p->x = *x;
    p->y = *y;
    fr_one(&p->z);
    fr_mul(&p->t, x, y);
}

static void warm_body(void)
{
    /* Montgomery multiply dispatch: fr_avx512.c init_dispatch() installs both
     * the Fr and the Fp pointer behind a plain static (racy if first used by
     * two threads at once). bn254_accel.c has the same pattern. */
    uint64_t a4[4] = {1, 0, 0, 0}, r4[4];
    uint64_t a6[6] = {1, 0, 0, 0, 0, 0}, r6[6];
    fr_mont_mul_accel(r4, a4, a4);
    fp_mont_mul_accel(r6, a6, a6);
    bn_fq_mont_mul_accel(r4, a4, a4);
    (void)fr_accel_implementation();
    (void)bn254_accel_implementation();
    (void)simd_host_has_avx2();

    /* Fixed generators (pthread_once in sapling.c) and FR_JUB_D (fr.c
     * ensure_jub_params, a plain static bool): ask_to_ak runs the generator
     * derivation, jub_from_bytes runs ensure_jub_params. */
    uint8_t one[32] = {1};
    uint8_t ak[32];
    sapling_ask_to_ak(one, ak);
    struct jub_point p;
    if (!jub_from_bytes(&p, ak))
        zcl_panic("warm-up: the SpendingKey generator multiple failed to decode");

    /* Pedersen generator and chunk tables (pthread_once in pedersen_hash.c). */
    uint8_t zero[32] = {0}, h[32];
    pedersen_merkle_hash(0, zero, zero, h);

    /* The two value-commitment generators as points, for binding_sig. */
    struct fr x, y;
    sapling_value_commit_value_generator(&x, &y);
    point_from_xy(&G_VALUE, &x, &y);
    sapling_value_commit_randomness_generator(&x, &y);
    point_from_xy(&G_VALUE_RAND, &x, &y);

    atomic_store_explicit(&g_warm, true, memory_order_release);
}

static inline void warm(void)
{
    if (__builtin_expect(!atomic_load_explicit(&g_warm, memory_order_acquire), 0)) {
        if (pthread_once(&g_warm_once, warm_body) != 0)
            zcl_panic("pthread_once failed during warm-up");
    }
}

/* ------------------------------------------------------------------------ */
/* Init state                                                                */
/* ------------------------------------------------------------------------ */

static atomic_bool g_init;

/* The Sapling proving keys exactly as init read them: the whole bytes of the
 * spend and output parameter files whose BLAKE2b-512 matched the caller's
 * digests (rustzcash.rs:229-232 and :272-273 keep the parsed Parameters for
 * the life of the process). Z23's prover parses these bytes per proof
 * (groth16_pk_read). Published once by init with release order; a second
 * init (Rust: "Caller is responsible for calling this function once")
 * replaces the set and deliberately leaks the old one, because a proof on
 * another thread may still be reading it. */
struct zcl_pk_set {
    uint8_t *spend;
    size_t spend_len;
    uint8_t *output;
    size_t output_len;
};
static _Atomic(struct zcl_pk_set *) g_pks;

/* Rust reads SAPLING_*_VK / SPROUT_GROTH16_VK / *_PARAMS with unwrap()/expect()
 * (rustzcash.rs:780, :859, :1128, :1225, :1545, :1069-1071), which panics when
 * init_zksnark_params has not run. Each caller places require_init() exactly
 * where Rust evaluates that unwrap, after the input checks that return false
 * first, so a call made before init gets Rust's false or Rust's abort. */
static inline void require_init(void)
{
    if (__builtin_expect(!atomic_load_explicit(&g_init, memory_order_acquire), 0))
        zcl_panic("parameters should have been initialized "
                  "(librustzcash_init_zksnark_params was not called)");
}

/* Before init, Rust's check_spend / check_output run every input check and
 * Proof::read, returning false on any failure, and panic only at the
 * verifying-key unwrap (rustzcash.rs:780, :859). Z23's prepare functions stop
 * at a NULL verifying key just before their Proof::read, so on this cold path
 * the compiled-in verifying keys are published first (idempotent, under
 * Z23's params mutex; init publishes the same keys) and prepare then runs
 * Rust's whole check sequence. The verdict stays gated by require_init(),
 * placed where Rust unwraps. Never reached by zclassicd, which inits first. */
__attribute__((cold, noinline)) static void preinit_vks(void)
{
    if (!sapling_install_embedded_vks())
        zcl_panic("compiled-in Sapling/Sprout verifying keys failed their "
                  "integrity check");
}

bool zcl_c23_params_initialized(void)
{
    return atomic_load_explicit(&g_init, memory_order_acquire);
}

static void prime_parsed_keys(void);

/* The prover thread budget is one process-wide value that every proof reads
 * when it starts. A caller that proves several things at once (the transaction
 * builder) divides it among the proofs for the duration of the batch so the
 * total stays at the budget. g_budget_raw is what the node configured (0 = the
 * vendored automatic default); g_budget_depth counts the batches in flight and
 * g_budget_workers is the split in force while any is. */
static pthread_mutex_t g_budget_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned g_budget_raw;
static unsigned g_budget_depth;
static unsigned g_budget_workers = 1;

/* The configured total, resolving the automatic default. Under g_budget_mu. */
static unsigned budget_total_locked(void)
{
    if (g_budget_raw)
        return g_budget_raw;
    groth16_prover_set_threads(0);
    return groth16_prover_threads();
}

/* Publishes the per-proof budget for the batches now in flight (the whole
 * budget when none). Under g_budget_mu. */
static unsigned budget_apply_locked(void)
{
    unsigned total = budget_total_locked();
    unsigned per = total;
    if (g_budget_depth > 0 && g_budget_workers > 1) {
        per = total / g_budget_workers;
        if (per == 0)
            per = 1;
    }
    groth16_prover_set_threads(g_budget_raw == 0 && per == total ? 0 : per);
    return per;
}

void zcl_c23_set_prover_threads(unsigned n)
{
    pthread_mutex_lock(&g_budget_mu);
    g_budget_raw = n;
    (void)budget_apply_locked();
    pthread_mutex_unlock(&g_budget_mu);
}

unsigned zcl_c23_prover_budget_enter(unsigned concurrent_proofs)
{
    prime_parsed_keys();
    pthread_mutex_lock(&g_budget_mu);
    if (g_budget_depth++ == 0)
        g_budget_workers = concurrent_proofs ? concurrent_proofs : 1;
    else if (concurrent_proofs > g_budget_workers)
        g_budget_workers = concurrent_proofs;
    unsigned per = budget_apply_locked();
    pthread_mutex_unlock(&g_budget_mu);
    return per;
}

void zcl_c23_prover_budget_leave(void)
{
    pthread_mutex_lock(&g_budget_mu);
    if (g_budget_depth > 0 && --g_budget_depth == 0)
        g_budget_workers = 1;
    (void)budget_apply_locked();
    pthread_mutex_unlock(&g_budget_mu);
}

unsigned zcl_c23_prover_budget(void)
{
    pthread_mutex_lock(&g_budget_mu);
    unsigned total = budget_total_locked();
    (void)budget_apply_locked();
    pthread_mutex_unlock(&g_budget_mu);
    return total;
}

/* ------------------------------------------------------------------------ */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------ */

static inline bool lt_r(const uint8_t s[32]) { return zcl_c23_lt_fs_modulus(s) != 0; }
static inline bool lt_q(const uint8_t s[32]) { return zcl_c23_lt_fr_modulus(s) != 0; }

/* bellman groth16/mod.rs:55-97 Proof::read decodes A, B, C with into_affine;
 * a set infinity flag (bit 0x40 of the first byte of each compressed point)
 * either fails pairing ec.rs:805-815 (UnexpectedInformation, when any other
 * bit is set) or decodes to the identity, which Proof::read rejects ("point at
 * infinity"). Z23's g1/g2_from_compressed accept both (bls12_381.c
 * g1_from_compressed / g2_from_compressed). Every other compressed-encoding
 * rule (compression bit, x < p, subgroup) Z23 enforces as Rust does. */
static inline bool proof_has_infinity_flag(const uint8_t proof[GROTH_PROOF_SIZE])
{
    return ((proof[0] | proof[48] | proof[144]) & 0x40u) != 0;
}

static void le_bytes_to_limbs(uint64_t out[4], const uint8_t b[32])
{
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | b[8 * i + j];
        out[i] = v;
    }
}

/* Affine coordinates of a decoded point as canonical little-endian limbs, the
 * representation groth16_verify takes for public inputs (into_xy in Rust). */
static void point_xy_limbs(const struct jub_point *p, uint64_t x_out[4],
                           uint64_t y_out[4])
{
    struct fr x, y;
    uint8_t b[32];
    jub_get_x(&x, p);
    jub_get_y(&y, p);
    fr_to_bytes(b, &x);
    le_bytes_to_limbs(x_out, b);
    fr_to_bytes(b, &y);
    le_bytes_to_limbs(y_out, b);
}

/* compute_value_balance, rustzcash.rs:871-895: None for INT64_MIN
 * (checked_abs), else [|v|] ValueCommitmentValue, negated when v < 0. */
static bool value_balance_point(int64_t v, struct jub_point *out)
{
    if (v == INT64_MIN)
        return false;
    uint64_t abs = v < 0 ? (uint64_t)(-v) : (uint64_t)v;
    uint8_t s[32] = {0};
    for (int i = 0; i < 8; i++)
        s[i] = (uint8_t)(abs >> (8 * i));
    jub_scalar_mul(out, &G_VALUE, s);
    if (v < 0)
        jub_neg(out, out);
    return true;
}

#if !defined(_WIN32)
/* strdup is not declared under strict -std=c23 on every libc. NULL on OOM.
 * (POSIX only: Windows paths go through wide_to_utf8.) */
static char *dup_cstr(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d)
        memcpy(d, s, n);
    return d;
}
#endif

static void generate_r_or_abort(uint8_t out[32])
{
    /* rustzcash.rs:454 OsRng::new().expect("should be able to construct RNG").
     * Z23 returns false and zeroes `out` on RNG failure; using a zero scalar
     * would leak keys, so this aborts as Rust does. */
    if (!sapling_generate_r(out))
        zcl_panic("should be able to construct RNG");
}

/* ------------------------------------------------------------------------ */
/* Stateless key and note functions                                          */
/* ------------------------------------------------------------------------ */

void librustzcash_to_scalar(const unsigned char *input, unsigned char *result)
{
    /* rustzcash.rs:339-354 Fs::to_uniform(input[0..64]) written LE. */
    jubjub_to_scalar(input, result);
}

void librustzcash_ask_to_ak(const unsigned char *ask, unsigned char *result)
{
    /* rustzcash.rs:356-367 [read_fs(ask)] SpendingKeyGenerator, no range
     * check; the full 256-bit integer multiplies. */
    warm();
    sapling_ask_to_ak(ask, result);
}

void librustzcash_nsk_to_nk(const unsigned char *nsk, unsigned char *result)
{
    /* rustzcash.rs:369-380 [read_fs(nsk)] ProofGenerationKey. */
    warm();
    sapling_nsk_to_nk(nsk, result);
}

void librustzcash_crh_ivk(const unsigned char *ak, const unsigned char *nk,
                          unsigned char *result)
{
    /* rustzcash.rs:382-402 BLAKE2s("Zcashivk", ak || nk) raw bytes, h[31] &= 7. */
    sapling_crh_ivk(ak, nk, result);
}

bool librustzcash_check_diversifier(const unsigned char *diversifier)
{
    /* rustzcash.rs:404-408 g_d(d).is_some(): group_hash.rs:17-46. */
    warm();
    return sapling_check_diversifier(diversifier);
}

bool librustzcash_ivk_to_pkd(const unsigned char *ivk,
                             const unsigned char *diversifier,
                             unsigned char *result)
{
    warm();
    /* rustzcash.rs:416 read_fs(ivk): no range check. */
    /* rustzcash.rs:418-428 g_d invalid -> false; else [ivk] g_d. */
    struct jub_point g_d, pk_d;
    if (!sapling_diversifier_to_gd(&g_d, diversifier))
        return false;
    jub_scalar_mul(&pk_d, &g_d, ivk);
    jub_to_bytes(result, &pk_d);
    return true;
}

void librustzcash_tree_uncommitted(unsigned char *result)
{
    /* rustzcash.rs:282-291 Note::uncommitted() = Fr::one(). */
    sapling_uncommitted(result);
}

void librustzcash_merkle_hash(size_t depth, const unsigned char *a,
                              const unsigned char *b, unsigned char *result)
{
    /* pedersen_hash.rs:16 Personalization::MerkleTree(num): assert!(num < 63).
     * Z23 would silently use depth & 63. zclassicd passes depth < 32. */
    if (depth >= 63)
        zcl_panic("assertion failed: num < 63 (merkle_hash depth)");
    warm();
    /* rustzcash.rs:303-330 a, b read_le (no range check), 255 LE bits each. */
    pedersen_merkle_hash(depth, a, b, result);
}

void librustzcash_sapling_generate_r(unsigned char *result)
{
    /* rustzcash.rs:450-466 64 OsRng bytes, Fs::to_uniform. */
    generate_r_or_abort(result);
}

/* priv_get_note, rustzcash.rs:469-505, without the g_d step (reached by the
 * Z23 commitment call, which returns false for an invalid diversifier). All
 * failures are `return Err(())`, so the order of the pure checks does not
 * affect the result. */
static bool note_inputs_ok(const unsigned char *pk_d, const unsigned char *r,
                           uint8_t pk_d_canonical[32])
{
    /* rustzcash.rs:481-489 Point::read(pk_d) + as_prime_order */
    if (!zcl_c23_point_prime_order_canonical(pk_d, pk_d_canonical))
        return false;
    /* rustzcash.rs:492-495 Fs::from_repr(read_fs(r)) */
    return lt_r(r);
}

bool librustzcash_sapling_compute_nf(const unsigned char *diversifier,
                                     const unsigned char *pk_d,
                                     const uint64_t value,
                                     const unsigned char *r,
                                     const unsigned char *ak,
                                     const unsigned char *nk,
                                     const uint64_t position,
                                     unsigned char *result)
{
    warm();
    uint8_t pk_d_c[32], ak_c[32], nk_c[32];
    /* rustzcash.rs:519-522 priv_get_note */
    if (!note_inputs_ok(pk_d, r, pk_d_c))
        return false;
    /* rustzcash.rs:524-532 ak: Point::read + as_prime_order */
    if (!zcl_c23_point_prime_order_canonical(ak, ak_c))
        return false;
    /* rustzcash.rs:534-542 nk: Point::read + as_prime_order */
    if (!zcl_c23_point_prime_order_canonical(nk, nk_c))
        return false;
    /* rustzcash.rs:544-548 nf = BLAKE2s("Zcash_nf", nk.write() || rho.write()),
     * rho = cm_full(value || g_d.write() || pk_d.write(), r) + [position] G;
     * primitives/mod.rs:191-249. The canonical encodings go to Z23, which
     * hashes the bytes it is given. g_d invalid -> false (:476-479). */
    return sapling_compute_nf(diversifier, pk_d_c, value, r, ak_c, nk_c,
                              position, result);
}

bool librustzcash_sapling_compute_cm(const unsigned char *diversifier,
                                     const unsigned char *pk_d,
                                     const uint64_t value,
                                     const unsigned char *r,
                                     unsigned char *result)
{
    warm();
    uint8_t pk_d_c[32];
    /* rustzcash.rs:561-564 priv_get_note */
    if (!note_inputs_ok(pk_d, r, pk_d_c))
        return false;
    /* rustzcash.rs:566-569 note.cm(): x of cm_full_point, LE; invalid g_d
     * (:476-479) -> false inside the Z23 call, result left unwritten. */
    return sapling_compute_cm(diversifier, pk_d_c, value, r, result);
}

bool librustzcash_sapling_ka_agree(const unsigned char *p,
                                   const unsigned char *sk,
                                   unsigned char *result)
{
    warm();
    /* rustzcash.rs:579-582 Point::read(p): any curve point, no order check */
    struct jub_point pt, out;
    if (!jub_from_bytes(&pt, p))
        return false;
    /* rustzcash.rs:585-588 Fs::from_repr(read_fs(sk)) */
    if (!lt_r(sk))
        return false;
    /* rustzcash.rs:591-598 [sk] ([8] p), canonical write */
    jub_mul_by_cofactor(&pt, &pt);
    jub_scalar_mul(&out, &pt, sk);
    jub_to_bytes(result, &out);
    memory_cleanse(&out, sizeof(out));
    return true;
}

bool librustzcash_sapling_ka_derivepublic(const unsigned char *diversifier,
                                          const unsigned char *esk,
                                          unsigned char *result)
{
    warm();
    /* rustzcash.rs:612-615 g_d invalid -> false */
    struct jub_point g_d, out;
    if (!sapling_diversifier_to_gd(&g_d, diversifier))
        return false;
    /* rustzcash.rs:618-621 Fs::from_repr(read_fs(esk)) */
    if (!lt_r(esk))
        return false;
    /* rustzcash.rs:623-626 [esk] g_d */
    jub_scalar_mul(&out, &g_d, esk);
    jub_to_bytes(result, &out);
    return true;
}

/* ------------------------------------------------------------------------ */
/* Parameters                                                                */
/* ------------------------------------------------------------------------ */

/* Rust's CStr::to_str().expect("hash should be a valid string"),
 * rustzcash.rs:202-215: the bytes up to NUL must be UTF-8. */
static bool utf8_valid(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned c = *p;
        size_t n;
        uint32_t cp;
        if (c < 0x80) { p++; continue; }
        else if (c >= 0xc2 && c <= 0xdf) { n = 1; cp = c & 0x1f; }
        else if (c >= 0xe0 && c <= 0xef) { n = 2; cp = c & 0x0f; }
        else if (c >= 0xf0 && c <= 0xf4) { n = 3; cp = c & 0x07; }
        else return false;
        for (size_t i = 1; i <= n; i++) {
            if ((p[i] & 0xc0) != 0x80)
                return false;
            cp = (cp << 6) | (p[i] & 0x3f);
        }
        if ((n == 2 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) ||
            (n == 3 && (cp < 0x10000 || cp > 0x10ffff)))
            return false;
        p += n + 1;
    }
    return true;
}

static void check_hash_arg(const char *h)
{
    if (!h || !utf8_valid(h))
        zcl_panic("hash should be a valid string");
}

#if defined(_WIN32)
typedef wchar_t zcl_pchar;
#define ZCL_PSEP_IS(c) ((c) == L'\\' || (c) == L'/')
#else
typedef char zcl_pchar;
#define ZCL_PSEP_IS(c) ((c) == '/')
#endif
_Static_assert(sizeof(zcl_pchar) == sizeof(codeunit),
               "codeunit must match the platform path character");

/* Copy a (pointer, length) path into a NUL-terminated buffer. Rust builds an
 * OsStr from exactly `len` units; an interior NUL makes File::open fail, and
 * the caller's expect turns that into a panic with `open_msg`. */
static zcl_pchar *path_copy(const codeunit *p, size_t len, const char *open_msg)
{
    if (!p || len == 0)
        zcl_panic(open_msg);
    if (len > SIZE_MAX / sizeof(zcl_pchar) - 1)
        zcl_panic(open_msg);
    zcl_pchar *out = malloc((len + 1) * sizeof(zcl_pchar));
    if (!out)
        zcl_panic("out of memory copying a parameter path");
    for (size_t i = 0; i < len; i++) {
        if (p[i] == 0)
            zcl_panic(open_msg);
        out[i] = (zcl_pchar)p[i];
    }
    out[len] = 0;
    return out;
}

/* An open parameter file. */
#if defined(_WIN32)
typedef HANDLE zcl_fh;
#else
typedef int zcl_fh;
#endif

/* rustzcash.rs:218-220 File::open(..).expect(..). Rust's std::fs::File::open
 * opens with read access only; on Windows it shares read, write and delete
 * and passes FILE_FLAG_BACKUP_SEMANTICS, so a directory opens there and the
 * read that follows fails (as it does on POSIX). */
static zcl_fh open_or_panic(const zcl_pchar *path, const char *open_msg)
{
#if defined(_WIN32)
    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE)
        zcl_panic(open_msg);
    return h;
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        zcl_panic(open_msg);
    return fd;
#endif
}

/* The file is only read; a failing close cannot change bytes already hashed,
 * and Rust's drop of a File ignores the close result as well. */
static void fh_close(zcl_fh h)
{
#if defined(_WIN32)
    (void)CloseHandle(h);
#else
    (void)close(h);
#endif
}

/* One read: > 0 bytes read, 0 at end of file, -1 on an error. EINTR is
 * retried, as Rust's BufReader and io::copy do. */
static long long fh_read(zcl_fh h, uint8_t *buf, size_t cap)
{
#if defined(_WIN32)
    DWORD want = cap > (size_t)(1u << 30) ? (DWORD)(1u << 30) : (DWORD)cap;
    DWORD got = 0;
    if (!ReadFile(h, buf, want, &got, NULL))
        return -1;
    return (long long)got;
#else
    for (;;) {
        ssize_t n = read(h, buf, cap);
        if (n >= 0)
            return (long long)n;
        if (errno != EINTR)
            return -1;
    }
#endif
}

#define ZCL_READ_CHUNK ((size_t)1 << 20) /* Rust: BufReader::with_capacity(1 MiB) */

/* rustzcash.rs:222-250 plus hashreader.rs: every byte of the file goes
 * through BLAKE2b-512 (Blake2b::new(64), unkeyed), and into_hash renders the
 * digest as lowercase hex ("{:02x}"). keep_cap > 0 also keeps the first
 * keep_cap bytes in memory: for a file whose digest is the canonical one,
 * that is the whole file, and it becomes the proving key. */
struct hash_job {
    zcl_fh fh;
    size_t keep_cap;
    uint8_t *kept; /* out: malloc'd, keep_cap bytes, NULL when keep_cap == 0 */
    uint64_t len;  /* out: bytes read */
    char hex[129]; /* out: lowercase hex digest */
    bool io_ok;    /* out: read to end of file without an I/O error */
};

static void *hash_job_run(void *arg)
{
    static const char HEX[] = "0123456789abcdef";
    struct hash_job *j = arg;
    struct blake2b_ctx b;
    uint8_t d[64];
    j->io_ok = false;
    j->len = 0;
    j->hex[0] = 0;
    if (blake2b_init(&b, sizeof(d)) != 0)
        zcl_panic("internal: BLAKE2b-512 initialisation failed");
    if (j->keep_cap) {
        j->kept = malloc(j->keep_cap);
        if (!j->kept)
            zcl_panic("out of memory reading a Sapling parameter file");
    }
    uint8_t *scratch = malloc(ZCL_READ_CHUNK);
    if (!scratch)
        zcl_panic("out of memory reading a parameter file");
    for (;;) {
        uint8_t *dst = scratch;
        size_t cap = ZCL_READ_CHUNK;
        if (j->len < j->keep_cap) {
            dst = j->kept + j->len;
            cap = j->keep_cap - (size_t)j->len;
            if (cap > ZCL_READ_CHUNK)
                cap = ZCL_READ_CHUNK;
        }
        long long n = fh_read(j->fh, dst, cap);
        if (n < 0)
            goto out;
        if (n == 0)
            break;
        if (blake2b_update(&b, dst, (size_t)n) != 0)
            zcl_panic("internal: BLAKE2b-512 update failed");
        j->len += (uint64_t)n;
    }
    if (blake2b_final(&b, d, sizeof(d)) != 0)
        zcl_panic("internal: BLAKE2b-512 finalisation failed");
    for (size_t i = 0; i < sizeof(d); i++) {
        j->hex[2 * i] = HEX[d[i] >> 4];
        j->hex[2 * i + 1] = HEX[d[i] & 15];
    }
    j->hex[128] = 0;
    j->io_ok = true;
out:
    free(scratch);
    return NULL;
}

/* UTF-16 -> UTF-8; NULL when the input is not valid UTF-16 (lone surrogate). */
#if defined(_WIN32)
static char *wide_to_utf8(const wchar_t *w)
{
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, NULL, 0,
                                NULL, NULL);
    if (n <= 0)
        return NULL;
    char *out = malloc((size_t)n);
    if (!out)
        zcl_panic("out of memory converting a parameter path");
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, out, n, NULL,
                            NULL) != n) {
        free(out);
        return NULL;
    }
    return out;
}
#endif

void librustzcash_init_zksnark_params(
    const codeunit *spend_path, size_t spend_path_len, const char *spend_hash,
    const codeunit *output_path, size_t output_path_len, const char *output_hash,
    const codeunit *sprout_path, size_t sprout_path_len, const char *sprout_hash)
{
    static const char SPEND_OPEN[] = "couldn't load Sapling spend parameters file";
    static const char OUTPUT_OPEN[] = "couldn't load Sapling output parameters file";
    static const char SPROUT_OPEN[] = "couldn't load Sprout groth16 parameters file";
    /* rustzcash.rs:229-232: both Parameters::read calls carry the "spend"
     * message in Rust (sic). */
    static const char SPEND_READ[] = "couldn't deserialize Sapling spend parameters file";
    static const char OUTPUT_READ[] = "couldn't deserialize Sapling spend parameters file";
    static const char SPROUT_READ[] = "couldn't deserialize Sprout Groth16 verifying key";
    static const char SPEND_BAD[] =
        "Sapling spend parameter file is not correct, please clean your "
        "`~/.zcash-params/` and re-run `fetch-params`.";
    static const char OUTPUT_BAD[] =
        "Sapling output parameter file is not correct, please clean your "
        "`~/.zcash-params/` and re-run `fetch-params`.";
    static const char SPROUT_BAD[] =
        "Sprout groth16 parameter file is not correct, please clean your "
        "`~/.zcash-params/` and re-run `fetch-params`.";

    /* rustzcash.rs:200 lazy_static::initialize(&JUBJUB): every lazily built
     * vendored constant and the CPU dispatch, before any validation thread
     * exists (plan section 3, D20). */
    warm();

    /* rustzcash.rs:202-215 the three hash strings must be valid UTF-8. */
    check_hash_arg(spend_hash);
    check_hash_arg(output_hash);
    check_hash_arg(sprout_hash);

    /* rustzcash.rs:141-149 (Unix bytes) / :174-179 (Windows UTF-16) paths;
     * rustzcash.rs:218-220 File::open(..).expect(..), all three, in this
     * order, before anything is read. Any file name and any directories. */
    zcl_pchar *sp = path_copy(spend_path, spend_path_len, SPEND_OPEN);
    zcl_pchar *op = path_copy(output_path, output_path_len, OUTPUT_OPEN);
    zcl_pchar *gp = path_copy(sprout_path, sprout_path_len, SPROUT_OPEN);
    struct hash_job jobs[3];
    memset(jobs, 0, sizeof(jobs));
    jobs[0].fh = open_or_panic(sp, SPEND_OPEN);
    jobs[1].fh = open_or_panic(op, OUTPUT_OPEN);
    jobs[2].fh = open_or_panic(gp, SPROUT_OPEN);
    jobs[0].keep_cap = (size_t)SAPLING_SPEND_SIZE;
    jobs[1].keep_cap = (size_t)SAPLING_OUTPUT_SIZE;
    jobs[2].keep_cap = 0; /* :234-238 only the Sprout VK is kept; proving reopens the path */

    /* rustzcash.rs:222-250 read every byte of the three files through
     * BLAKE2b-512. Rust reads them one after another; the digests do not
     * depend on the order, so the 692 MiB Sprout file is hashed on a second
     * thread while this one reads the Sapling pair. */
    pthread_t sprout_thread;
    bool threaded = pthread_create(&sprout_thread, NULL, hash_job_run, &jobs[2]) == 0;
    hash_job_run(&jobs[0]);
    hash_job_run(&jobs[1]);
    if (threaded) {
        if (pthread_join(sprout_thread, NULL) != 0)
            zcl_panic("pthread_join failed while hashing the Sprout parameters");
    } else {
        hash_job_run(&jobs[2]);
    }
    for (int i = 0; i < 3; i++)
        fh_close(jobs[i].fh);

    /* rustzcash.rs:229-250: a read error panics, spend first. (A truncated
     * or otherwise malformed file makes Rust's Parameters::read panic with
     * the same message; here it reaches the digest check below and panics
     * with the "not correct" message. Both are aborts.) */
    if (!jobs[0].io_ok)
        zcl_panic(SPEND_READ);
    if (!jobs[1].io_ok)
        zcl_panic(OUTPUT_READ);
    if (!jobs[2].io_ok)
        zcl_panic(SPROUT_READ);

    /* rustzcash.rs:252-262: into_hash() != caller string -> panic, in this
     * order. Plain string equality, as Rust's String != String. */
    if (strcmp(jobs[0].hex, spend_hash) != 0)
        zcl_panic(SPEND_BAD);
    if (strcmp(jobs[1].hex, output_hash) != 0)
        zcl_panic(OUTPUT_BAD);
    if (strcmp(jobs[2].hex, sprout_hash) != 0)
        zcl_panic(SPROUT_BAD);

    /* Each file now has the caller's digest. Rust would go on to use the
     * verifying keys parsed from these files (:264-279) whatever the digest;
     * the C23 engine has the canonical ceremony keys compiled in, so it
     * accepts only the canonical digests, which are the only ones zclassicd
     * passes (init.cpp ZC_LoadParams, gtest/main.cpp, test_bitcoin.cpp). A
     * caller that passes other digests together with matching files is the
     * one case where Rust accepts and this build aborts. */
    if (strcmp(spend_hash, SAPLING_SPEND_B2) != 0 ||
        strcmp(output_hash, SAPLING_OUTPUT_B2) != 0 ||
        strcmp(sprout_hash, SPROUT_GROTH16_B2) != 0)
        zcl_panic("the C23 build accepts only the canonical Zcash parameter "
                  "files (a non-canonical BLAKE2b digest was passed)");
    /* A canonical digest fixes the length; anything else is a broken read. */
    if (jobs[0].len != SAPLING_SPEND_SIZE || jobs[1].len != SAPLING_OUTPUT_SIZE ||
        jobs[2].len != SPROUT_GROTH16_SIZE)
        zcl_panic("internal: canonical parameter file read with the wrong length");

    /* rustzcash.rs:264-279 publish the verifying keys. Here: the compiled-in
     * keys, which are the leading bytes of the canonical files just verified
     * (Z23 also checks them against SHA-256 pins). */
    if (!sapling_install_embedded_vks())
        zcl_panic("compiled-in Sapling/Sprout verifying keys failed their "
                  "integrity check");

    char *sprout_utf8 = NULL;
#if defined(_WIN32)
    sprout_utf8 = wide_to_utf8(gp);
    if (!sprout_utf8)
        zcl_panic(SPROUT_OPEN);
#else
    sprout_utf8 = dup_cstr(gp);
    if (!sprout_utf8)
        zcl_panic("out of memory copying a parameter path");
#endif
    /* rustzcash.rs:274 SPROUT_GROTH16_PARAMS_PATH = Some(sprout_path). */
    if (!zc23_sprout_prover_set_params_path(sprout_utf8))
        zcl_panic(SPROUT_OPEN);

    /* rustzcash.rs:272-273 SAPLING_SPEND_PARAMS / SAPLING_OUTPUT_PARAMS. */
    struct zcl_pk_set *set = malloc(sizeof(*set));
    if (!set)
        zcl_panic("out of memory publishing the Sapling proving keys");
    set->spend = jobs[0].kept;
    set->spend_len = (size_t)jobs[0].len;
    set->output = jobs[1].kept;
    set->output_len = (size_t)jobs[1].len;
    /* A previous set (second init) is leaked on purpose, see g_pks. */
    atomic_store_explicit(&g_pks, set, memory_order_release);

    free(sprout_utf8);
    free(sp);
    free(op);
    free(gp);
    atomic_store_explicit(&g_init, true, memory_order_release);
}

/* Diagnostics kept for ABI stability: "none" before init, "resident" after
 * (the proving keys are held from init, as in Rust). Nothing is refused at
 * proof time any more, so the last refusal is always NULL. */
const char *zcl_c23_proving_status(void)
{
    return atomic_load_explicit(&g_pks, memory_order_acquire) ? "resident" : "none";
}

const char *zcl_c23_proving_last_refusal(void)
{
    return NULL;
}

static const struct zcl_pk_set *pks_get(void)
{
    const struct zcl_pk_set *s = atomic_load_explicit(&g_pks, memory_order_acquire);
    if (!s || !s->spend || !s->output)
        zcl_panic("parameters should have been initialized "
                  "(Sapling proving keys absent)");
    return s;
}


/* ------------------------------------------------------------------------ */
/* Verification                                                              */
/* ------------------------------------------------------------------------ */

void *librustzcash_sapling_verification_ctx_init(void)
{
    /* rustzcash.rs:655-663 Box::new({bvk: zero}); allocation failure aborts. */
    warm();
    struct sapling_verification_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx)
        zcl_panic("out of memory allocating a Sapling verification context");
    sapling_verification_ctx_init(ctx);
    return ctx;
}

void librustzcash_sapling_verification_ctx_free(void *ctx)
{
    /* rustzcash.rs:665-670 drop(Box::from_raw(ctx)). NULL is accepted. */
    free(ctx);
}

static inline struct sapling_verification_ctx *vctx_get(void *ctx)
{
    if (!ctx)
        zcl_panic("NULL Sapling verification context");
    return ctx;
}

bool librustzcash_sapling_check_spend(void *ctx, const unsigned char *cv,
                                      const unsigned char *anchor,
                                      const unsigned char *nullifier,
                                      const unsigned char *rk,
                                      const unsigned char *zkproof,
                                      const unsigned char *spendAuthSig,
                                      const unsigned char *sighashValue)
{
    /* Before init: see preinit_vks. */
    if (__builtin_expect(!atomic_load_explicit(&g_init, memory_order_acquire), 0))
        preinit_vks();
    warm();
    struct sapling_verification_ctx *v = vctx_get(ctx);
    struct groth16_proof proof;
    uint64_t pub[7][4];
    /* sapling_spend_prepare reproduces, in order (sapling.c):
     *   rustzcash.rs:688-691 cv Point::read -> false
     *   rustzcash.rs:693-695 cv small order -> false
     *   rustzcash.rs:698-704 bvk += cv
     *   rustzcash.rs:708-711 anchor Fr::from_repr -> false
     *   rustzcash.rs:722-729 rk Point::read / small order -> false
     *   rustzcash.rs:732-745 RedJubjub verify over rk_raw || sighash with
     *                        SpendingKeyGenerator (S < r, R decodes,
     *                        cofactored equation) -> false
     *   rustzcash.rs:748-770 public inputs [rk.x, rk.y, cv.x, cv.y, anchor,
     *                        LE-multipacked nf (2 scalars)]
     *   rustzcash.rs:773-776 Proof::read (on curve, subgroup) -> false */
    if (!sapling_spend_prepare(v, cv, anchor, nullifier, rk, zkproof,
                               spendAuthSig, sighashValue, &proof, pub))
        return false;
    /* rustzcash.rs:773-776 Proof::read also rejects the point at infinity in
     * A, B, C (bellman groth16/mod.rs:63-90, pairing ec.rs:805-815). */
    if (proof_has_infinity_flag(zkproof))
        return false;
    /* rustzcash.rs:779-789 verify_proof(SAPLING_SPEND_VK) == Ok(true) */
    require_init(); /* rustzcash.rs:780 SAPLING_SPEND_VK.expect(..) */
    return sapling_spend_groth16_one(&proof, (const uint64_t (*)[4])pub);
}

bool librustzcash_sapling_check_output(void *ctx, const unsigned char *cv,
                                       const unsigned char *cm,
                                       const unsigned char *ephemeralKey,
                                       const unsigned char *zkproof)
{
    /* Before init: see preinit_vks. */
    if (__builtin_expect(!atomic_load_explicit(&g_init, memory_order_acquire), 0))
        preinit_vks();
    warm();
    struct sapling_verification_ctx *v = vctx_get(ctx);
    struct groth16_proof proof;
    uint64_t pub[5][4];
    /* sapling_output_prepare reproduces, in order (sapling.c):
     *   rustzcash.rs:801-804 cv Point::read -> false
     *   rustzcash.rs:806-808 cv small order -> false
     *   rustzcash.rs:811-818 bvk -= cv
     *   rustzcash.rs:822-825 cm Fr::from_repr -> false
     *   rustzcash.rs:828-835 epk Point::read / small order -> false
     *   rustzcash.rs:838-849 public inputs [cv.x, cv.y, epk.x, epk.y, cm]
     *   rustzcash.rs:852-855 Proof::read (on curve, subgroup) -> false */
    if (!sapling_output_prepare(v, cv, cm, ephemeralKey, zkproof, &proof, pub))
        return false;
    /* rustzcash.rs:852-855 Proof::read rejects infinity (see check_spend). */
    if (proof_has_infinity_flag(zkproof))
        return false;
    /* rustzcash.rs:858-868 verify_proof(SAPLING_OUTPUT_VK) == Ok(true) */
    require_init(); /* rustzcash.rs:859 SAPLING_OUTPUT_VK.expect(..) */
    return sapling_output_groth16_one(&proof, (const uint64_t (*)[4])pub);
}

bool librustzcash_sapling_final_check(void *ctx, int64_t valueBalance,
                                      const unsigned char *bindingSig,
                                      const unsigned char *sighashValue)
{
    warm();
    /* sapling_final_check reproduces rustzcash.rs:897-941:
     *   :908-911 compute_value_balance; INT64_MIN -> false
     *   :914-915 bvk = ctx.bvk - [valueBalance] G_v
     *   :918-922 message = bvk.write() || sighash
     *   :931-938 RedJubjub verify with ValueCommitmentRandomness
     * (no params are read, so no init requirement, as in Rust). */
    return sapling_final_check(vctx_get(ctx), valueBalance, bindingSig,
                               sighashValue);
}

bool librustzcash_sprout_verify(const unsigned char *proof,
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
    warm();
    /* rustzcash.rs:1121-1124 Proof::read (infinity flag, then on-curve and
     * subgroup) returns false before :1127-1128 unwraps SPROUT_GROTH16_VK;
     * before init only that panics (cold path). */
    if (__builtin_expect(!atomic_load_explicit(&g_init, memory_order_acquire), 0)) {
        struct groth16_proof gp;
        if (proof_has_infinity_flag(proof) || !groth16_proof_read(&gp, proof))
            return false;
        require_init();
    }
    /* rustzcash.rs:1121-1124 Proof::read rejects infinity in A, B, C. */
    if (proof_has_infinity_flag(proof))
        return false;
    /* sprout_verify_groth16 (sprout.c) reproduces rustzcash.rs:1106-1137:
     * input bytes rt || h_sig || nf1 || mac1 || nf2 || mac2 || cm1 || cm2 ||
     * vpub_old LE || vpub_new LE, MSB-first multipack, Proof::read,
     * input-count check, verify_proof(SPROUT_GROTH16_VK). */
    return sprout_verify_groth16(proof, rt, h_sig, mac1, mac2, nf1, nf2, cm1,
                                 cm2, vpub_old, vpub_new);
}

/* ------------------------------------------------------------------------ */
/* Batch-capable verification (zcl_c23_*)                                    */
/* ------------------------------------------------------------------------ */

struct zcl_c23_batch {
    size_t cap_s, cap_o, n_s, n_o;
    struct groth16_proof *sp;
    uint64_t (*spub)[4]; /* 7 rows per spend */
    struct groth16_proof *op;
    uint64_t (*opub)[4]; /* 5 rows per output */
};

zcl_c23_batch *zcl_c23_batch_new(size_t max_spends, size_t max_outputs)
{
    const size_t cs = max_spends ? max_spends : 1;
    const size_t co = max_outputs ? max_outputs : 1;
    if (cs > SIZE_MAX / (7 * sizeof(uint64_t[4])) ||
        co > SIZE_MAX / (7 * sizeof(uint64_t[4])))
        return NULL;
    zcl_c23_batch *b = calloc(1, sizeof(*b));
    if (!b)
        return NULL;
    b->sp = calloc(cs, sizeof(*b->sp));
    b->spub = calloc(cs * 7, sizeof(*b->spub));
    b->op = calloc(co, sizeof(*b->op));
    b->opub = calloc(co * 5, sizeof(*b->opub));
    if (!b->sp || !b->spub || !b->op || !b->opub) {
        zcl_c23_batch_free(b);
        return NULL;
    }
    b->cap_s = max_spends;
    b->cap_o = max_outputs;
    return b;
}

void zcl_c23_batch_free(zcl_c23_batch *b)
{
    if (!b)
        return;
    free(b->sp);
    free(b->spub);
    free(b->op);
    free(b->opub);
    free(b);
}

void zcl_c23_batch_clear(zcl_c23_batch *b)
{
    if (b)
        b->n_s = b->n_o = 0;
}

size_t zcl_c23_batch_spends(const zcl_c23_batch *b) { return b ? b->n_s : 0; }
size_t zcl_c23_batch_outputs(const zcl_c23_batch *b) { return b ? b->n_o : 0; }

enum zcl_c23_item_status zcl_c23_batch_add_spend(
    zcl_c23_batch *b, void *ctx, const unsigned char *cv,
    const unsigned char *anchor, const unsigned char *nullifier,
    const unsigned char *rk, const unsigned char *zkproof,
    const unsigned char *spendAuthSig, const unsigned char *sighashValue)
{
    if (!b || b->n_s >= b->cap_s)
        return ZCL_C23_ITEM_FULL;
    require_init();
    warm();
    /* Same sequence as librustzcash_sapling_check_spend up to the pairing. */
    if (!sapling_spend_prepare(vctx_get(ctx), cv, anchor, nullifier, rk,
                               zkproof, spendAuthSig, sighashValue,
                               &b->sp[b->n_s], &b->spub[b->n_s * 7]))
        return ZCL_C23_ITEM_REJECT;
    if (proof_has_infinity_flag(zkproof))
        return ZCL_C23_ITEM_REJECT;
    b->n_s++;
    return ZCL_C23_ITEM_QUEUED;
}

enum zcl_c23_item_status zcl_c23_batch_add_output(
    zcl_c23_batch *b, void *ctx, const unsigned char *cv,
    const unsigned char *cm, const unsigned char *ephemeralKey,
    const unsigned char *zkproof)
{
    if (!b || b->n_o >= b->cap_o)
        return ZCL_C23_ITEM_FULL;
    require_init();
    warm();
    if (!sapling_output_prepare(vctx_get(ctx), cv, cm, ephemeralKey, zkproof,
                                &b->op[b->n_o], &b->opub[b->n_o * 5]))
        return ZCL_C23_ITEM_REJECT;
    if (proof_has_infinity_flag(zkproof))
        return ZCL_C23_ITEM_REJECT;
    b->n_o++;
    return ZCL_C23_ITEM_QUEUED;
}

static void batch_bad(bool *bad_is_output, size_t *bad_index, bool is_out,
                      size_t i)
{
    if (bad_is_output)
        *bad_is_output = is_out;
    if (bad_index)
        *bad_index = i;
}

bool zcl_c23_batch_verify_each(const zcl_c23_batch *b, bool *bad_is_output,
                               size_t *bad_index)
{
    if (!b)
        zcl_panic("NULL batch");
    for (size_t i = 0; i < b->n_s; i++) {
        if (!sapling_spend_groth16_one(&b->sp[i],
                                       (const uint64_t (*)[4])&b->spub[i * 7])) {
            batch_bad(bad_is_output, bad_index, false, i);
            return false;
        }
    }
    for (size_t i = 0; i < b->n_o; i++) {
        if (!sapling_output_groth16_one(&b->op[i],
                                        (const uint64_t (*)[4])&b->opub[i * 5])) {
            batch_bad(bad_is_output, bad_index, true, i);
            return false;
        }
    }
    return true;
}

bool zcl_c23_batch_verify(const zcl_c23_batch *b, bool *bad_is_output,
                          size_t *bad_index)
{
    if (!b)
        zcl_panic("NULL batch");
    bool ok = true;
    if (b->n_s > 0 &&
        !sapling_spend_groth16_batch(b->sp, (const uint64_t (*)[4])b->spub, b->n_s))
        ok = false;
    if (ok && b->n_o > 0 &&
        !sapling_output_groth16_batch(b->op, (const uint64_t (*)[4])b->opub, b->n_o))
        ok = false;
    if (ok)
        return true;
    /* A combined reject never rejects a set the per-proof sweep accepts
     * (sapling.h batch contract); the sweep names the first failure. */
    return zcl_c23_batch_verify_each(b, bad_is_output, bad_index);
}

/* ------------------------------------------------------------------------ */
/* Proving                                                                   */
/* ------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------ */
/* Shared parsed proving keys                                               */
/* ------------------------------------------------------------------------ */

/* Z23's sapling_create_*_proof parse the raw proving key (groth16_pk_read)
 * inside every proof: about 72 MB of curve points for a spend and 5 MB for an
 * output, rebuilt and checked point by point per proof, so the proofs of one
 * transaction that run at the same time each carry a private copy. Here the
 * key is parsed once, on the first proof, and every proof of every proving
 * context reads that one copy (a proof only reads the key). It lives while any
 * proving context does and is freed with the last, so a wallet that is not
 * sending holds none of it, and the heap is handed back to the system then.
 *
 * The proof is assembled from the same vendored steps that
 * sapling_create_spend_proof and sapling_create_output_proof run (synthesize,
 * groth16_prove, serialize), so the proofs are the same ones; a key that
 * cannot be parsed falls back to those functions. TEMPORARY: once Z23 provides
 * the *_parsed variants of those two functions this block calls them instead
 * and drops its own assembly. */
static pthread_mutex_t g_pk_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned g_pctx_live;                 /* live proving contexts; g_pk_mu */
static struct groth16_pk g_pk_spend, g_pk_output;
static bool g_pk_spend_ok, g_pk_output_ok;   /* parsed and resident; g_pk_mu */

/* Returns freed heap to the operating system after a batch of proofs. The
 * proofs allocate several 10 MB buffers per proof on several threads, and the
 * allocator keeps what it is given back (per-thread arenas) until asked. */
static void release_heap_memory(void)
{
#if defined(__GLIBC__)
    (void)malloc_trim(0);
#elif defined(__APPLE__)
    (void)malloc_zone_pressure_relief(NULL, 0);
#endif
}

static const struct groth16_pk *parsed_key(struct groth16_pk *slot, bool *ok,
                                           const uint8_t *raw, size_t len)
{
    pthread_mutex_lock(&g_pk_mu);
    if (!*ok && g_pctx_live > 0 && groth16_pk_read(slot, raw, len))
        *ok = true;
    const struct groth16_pk *key = *ok ? slot : NULL;
    pthread_mutex_unlock(&g_pk_mu);
    return key;
}

/* True while the shared parsed proving keys are resident (a proving context is
 * alive and a proof has parsed them). For diagnostics and tests. */
bool zcl_c23_proving_keys_parsed(void)
{
    pthread_mutex_lock(&g_pk_mu);
    bool resident = g_pk_spend_ok || g_pk_output_ok;
    pthread_mutex_unlock(&g_pk_mu);
    return resident;
}

static void pctx_live_add(void)
{
    pthread_mutex_lock(&g_pk_mu);
    g_pctx_live++;
    pthread_mutex_unlock(&g_pk_mu);
}

static void pctx_live_drop(void)
{
    bool last = false;
    pthread_mutex_lock(&g_pk_mu);
    if (g_pctx_live > 0 && --g_pctx_live == 0) {
        if (g_pk_spend_ok)
            groth16_pk_free(&g_pk_spend);
        if (g_pk_output_ok)
            groth16_pk_free(&g_pk_output);
        g_pk_spend_ok = g_pk_output_ok = false;
        last = true;
    }
    pthread_mutex_unlock(&g_pk_mu);
    if (last)
        release_heap_memory();
}

/* Parses both keys now if a proving context is alive. The transaction builder
 * calls it (through zcl_c23_prover_budget_enter) before its workers start, so
 * the parse has the whole thread budget and no worker waits on it. */
static void prime_parsed_keys(void)
{
    const struct zcl_pk_set *pks = atomic_load_explicit(&g_pks, memory_order_acquire);
    if (!pks || !pks->spend || !pks->output)
        return;
    (void)parsed_key(&g_pk_spend, &g_pk_spend_ok, pks->spend, pks->spend_len);
    (void)parsed_key(&g_pk_output, &g_pk_output_ok, pks->output, pks->output_len);
}

/* The 192-byte proof: A (G1, 48) || B (G2, 96) || C (G1, 48), each compressed
 * (bit 7 set, bit 6 infinity, bit 5 y sign), as sapling_circuit.c writes it. */
static void proof_write(uint8_t out[GROTH_PROOF_SIZE],
                        const struct groth16_proof *proof)
{
    struct fp ax, ay, cx, cy;
    struct fp2 bx, by;
    g1_to_affine(&ax, &ay, &proof->a);
    fp_to_bytes(out, &ax);
    out[0] &= 0x1F;
    out[0] |= 0x80;
    if (fp_lexicographically_largest(&ay))
        out[0] |= 0x20;
    g2_to_affine(&bx, &by, &proof->b);
    fp_to_bytes(out + 48, &bx.c1);
    fp_to_bytes(out + 96, &bx.c0);
    out[48] &= 0x1F;
    out[48] |= 0x80;
    if (fp2_lexicographically_largest(&by))
        out[48] |= 0x20;
    g1_to_affine(&cx, &cy, &proof->c);
    fp_to_bytes(out + 144, &cx);
    out[144] &= 0x1F;
    out[144] |= 0x80;
    if (fp_lexicographically_largest(&cy))
        out[144] |= 0x20;
}

/* Proves a synthesized circuit against a parsed key and wipes the witness. */
static bool prove_system(const struct groth16_pk *key,
                         struct constraint_system *cs, bool synthesized,
                         uint8_t out[GROTH_PROOF_SIZE])
{
    struct groth16_proof gp;
    bool ok = synthesized && groth16_prove(key, cs, &gp);
    if (ok)
        proof_write(out, &gp);
    if (cs->witness)
        memory_cleanse(cs->witness, cs->cap_vars * sizeof(struct fr));
    cs_free(cs);
    return ok;
}

static bool spend_proof_make(const struct zcl_pk_set *pks,
                             const struct sapling_spend_witness *wit,
                             const struct sapling_spend_inputs *pub,
                             uint8_t out[GROTH_PROOF_SIZE])
{
    const struct groth16_pk *key =
        parsed_key(&g_pk_spend, &g_pk_spend_ok, pks->spend, pks->spend_len);
    if (!key)
        return sapling_create_spend_proof(pks->spend, pks->spend_len, wit, pub,
                                          out);
    struct constraint_system cs;
    cs_init(&cs);
    return prove_system(key, &cs, sapling_spend_synthesize(&cs, wit, pub), out);
}

static bool output_proof_make(const struct zcl_pk_set *pks,
                              const struct sapling_output_witness *wit,
                              const struct sapling_output_inputs *pub,
                              uint8_t out[GROTH_PROOF_SIZE])
{
    const struct groth16_pk *key =
        parsed_key(&g_pk_output, &g_pk_output_ok, pks->output, pks->output_len);
    if (!key)
        return sapling_create_output_proof(pks->output, pks->output_len, wit,
                                           pub, out);
    struct constraint_system cs;
    cs_init(&cs);
    return prove_system(key, &cs, sapling_output_synthesize(&cs, wit, pub), out);
}

#define PCTX_MAGIC UINT64_C(0x7a63323370637478) /* "zc23pctx" */

/* rustzcash.rs:1140-1143 SaplingProvingContext { bsk: Fs, bvk: Point }. The
 * proving keys are not per context: init holds them for the process, as Rust
 * does (see g_pks). */
struct zcl_pctx {
    uint64_t magic;
    struct fs bsk;
    struct jub_point bvk;
};

static struct zcl_pctx *pctx_get(const void *ctx)
{
    struct zcl_pctx *c = (struct zcl_pctx *)ctx;
    if (!c || c->magic != PCTX_MAGIC)
        zcl_panic("invalid Sapling proving context");
    return c;
}

void *librustzcash_sapling_proving_ctx_init(void)
{
    /* rustzcash.rs:1615-1623 Box::new({bsk: 0, bvk: zero}); never NULL. */
    warm();
    struct zcl_pctx *c = calloc(1, sizeof(*c));
    if (!c)
        zcl_panic("out of memory allocating a Sapling proving context");
    c->magic = PCTX_MAGIC;
    fs_zero(&c->bsk);
    jub_identity(&c->bvk);
    pctx_live_add();
    return c;
}

void librustzcash_sapling_proving_ctx_free(void *ctx)
{
    /* rustzcash.rs:1625-1628 drop(Box::from_raw(ctx)). NULL is accepted. */
    if (!ctx)
        return;
    struct zcl_pctx *c = pctx_get(ctx);
    memory_cleanse(c, sizeof(*c));
    free(c);
    pctx_live_drop();
}

/* Folds the value-commitment accumulators of `src` into `dst`: bsk adds and bvk
 * adds, exactly what proving the src descriptions on dst would have done (both
 * sums are commutative and associative). Lets the independent proofs of one
 * transaction run on private contexts, in parallel, and still produce the one
 * binding signature. src is left as it was; free it separately. */
void zcl_c23_sapling_proving_ctx_merge(void *dst, const void *src)
{
    struct zcl_pctx *d = pctx_get(dst);
    const struct zcl_pctx *s = pctx_get(src);
    fs_add(&d->bsk, &d->bsk, &s->bsk);
    jub_add(&d->bvk, &d->bvk, &s->bvk);
}

/* Rust's self-verification of a fresh spend proof, rustzcash.rs:1549-1588,
 * with Rust's public inputs: rk (computed), cv, the caller's anchor, and the
 * nullifier computed from the FULL 64-bit position (:1505-1515). */
static bool spend_self_verify(const uint8_t proof[GROTH_PROOF_SIZE],
                              const struct jub_point *rk, const uint8_t cv[32],
                              const uint8_t anchor[32], const uint8_t nf[32])
{
    if (proof_has_infinity_flag(proof))
        return false;
    struct groth16_proof gp;
    if (!groth16_proof_read(&gp, proof))
        return false;
    struct jub_point cvp;
    if (!jub_from_bytes(&cvp, cv))
        return false;
    uint64_t pub[7][4];
    point_xy_limbs(rk, pub[0], pub[1]);   /* :1551-1556 */
    point_xy_limbs(&cvp, pub[2], pub[3]); /* :1557-1561 */
    le_bytes_to_limbs(pub[4], anchor);    /* :1562 */
    size_t n = 0;
    multipack_bytes_to_fr(&pub[5], &n, nf, 32); /* :1565-1573 */
    if (n != 2)
        zcl_panic("assertion failed: nullifier.len() == 2");
    return sapling_spend_groth16_one(&gp, (const uint64_t (*)[4])pub);
}

bool librustzcash_sapling_spend_proof(void *ctx, const unsigned char *ak,
                                      const unsigned char *nsk,
                                      const unsigned char *diversifier,
                                      const unsigned char *rcm,
                                      const unsigned char *ar,
                                      const uint64_t value,
                                      const unsigned char *anchor,
                                      const unsigned char *witness,
                                      unsigned char *cv, unsigned char *rk,
                                      unsigned char *zkproof)
{
    warm();
    struct zcl_pctx *c = pctx_get(ctx);
    bool ok = false;
    uint8_t rcv[32], ak_c[32], nk[32], rk_bytes[32], nf[32];
    uint8_t compact[ZCL_C23_WITNESS_COMPACT_LEN];
    uint8_t proof[GROTH_PROOF_SIZE];
    struct fs rcv_fs;
    struct jub_point g_d, rk_pt, ak_pt;
    struct sapling_spend_witness wit;
    struct sapling_spend_inputs pub;
    memset(&wit, 0, sizeof(wit));
    memset(&pub, 0, sizeof(pub));

    /* rustzcash.rs:1380-1392 rcv = Fs::rand(OsRng); ctx.bsk += rcv, BEFORE
     * any input is validated. */
    generate_r_or_abort(rcv);
    if (!fs_from_bytes(&rcv_fs, rcv))
        zcl_panic("internal: generated rcv is not canonical");
    fs_add(&c->bsk, &c->bsk, &rcv_fs);

    /* rustzcash.rs:1401-1410 ak: Point::read + as_prime_order -> false */
    if (!zcl_c23_point_prime_order_canonical(ak, ak_c))
        goto out;
    /* rustzcash.rs:1413-1416 nsk: Fs::from_repr -> false */
    if (!lt_r(nsk))
        goto out;
    /* rustzcash.rs:1425-1434 into_payment_address: invalid g_d -> false */
    if (!sapling_diversifier_to_gd(&g_d, diversifier))
        goto out;
    /* rustzcash.rs:1437-1440 rcm: Fs::from_repr -> false */
    if (!lt_r(rcm))
        goto out;
    /* rustzcash.rs:1443-1446 ar: Fs::from_repr -> false */
    if (!lt_r(ar))
        goto out;
    /* rustzcash.rs:1449-1457 rk = ak + [ar] SpendingKeyGenerator, written to
     * rk_out before the anchor and witness checks. */
    if (!sapling_compute_rk(ak_c, ar, rk_bytes))
        zcl_panic("internal: rk computation failed on a validated ak");
    memcpy(rk, rk_bytes, 32);
    /* rustzcash.rs:1460-1463 anchor: Fr::from_repr -> false */
    if (!lt_q(anchor))
        goto out;
    /* rustzcash.rs:1467-1528 the serialized MerklePath. */
    uint64_t position = 0;
    size_t bad = 0;
    switch (zcl_c23_witness_to_compact(witness, compact, &position, &bad)) {
    case ZCL_C23_WITNESS_OK:
        break;
    case ZCL_C23_WITNESS_PANIC_DEPTH: /* :1471 assert_eq! */
        zcl_panic("assertion failed: witness[0] == SAPLING_TREE_DEPTH");
    case ZCL_C23_WITNESS_PANIC_INNER_LEN: /* :1480 assert_eq! */
        zcl_panic("assertion failed: witness[0] == 32 (auth path entry)");
    case ZCL_C23_WITNESS_NONCANONICAL_SIBLING: /* :1489-1492 */
    default:
        goto out;
    }

    /* rustzcash.rs:1545 SAPLING_SPEND_PARAMS.as_ref().unwrap(), evaluated as
     * an argument of create_random_proof, so before synthesis: every check
     * above returns false before init, everything below panics. */
    require_init();
    const struct zcl_pk_set *pks = pks_get();

    /* rustzcash.rs:1531-1547 create_random_proof(..).expect("proving should
     * not fail"). Rust's Spend circuit calls ak.assert_not_small_order
     * (sapling-crypto circuit/sapling/mod.rs, ecc.rs:95-122), whose
     * assert_nonzero (num.rs:318-345) returns SynthesisError::DivisionByZero
     * for the identity, the only prime-order point of small order; the
     * expect then panics. */
    if (!jub_from_bytes(&ak_pt, ak_c))
        zcl_panic("internal: canonical ak failed to decode");
    if (jub_is_identity(&ak_pt))
        zcl_panic("proving should not fail (ak is the identity)");

    memcpy(wit.ak, ak_c, 32);
    memcpy(wit.nsk, nsk, 32);
    memcpy(wit.ar, ar, 32);
    wit.value = value;
    memcpy(wit.diversifier, diversifier, 11);
    memcpy(wit.rcm, rcm, 32);
    memcpy(wit.rcv, rcv, 32);
    if (!sapling_spend_parse_witness(compact, sizeof(compact), &wit))
        zcl_panic("internal: converted witness rejected by the Z23 parser");
    /* Fills wit.pk_d = [ivk] g_d with ivk = CRH(ak, nk) (primitives/mod.rs
     * ViewingKey::into_payment_address) and folds the path. */
    if (!sapling_spend_derive_public(&wit, &pub))
        zcl_panic("internal: Z23 rejected a validated spend witness");
    /* The circuit enforces (root - anchor) * value == 0 ("conditionally
     * enforce correct root", circuit/sapling/mod.rs). For value != 0 and a
     * path that does not fold to `anchor` the instance is unsatisfiable,
     * Rust proves anyway and its self-verify fails (:1576-1588): false. For
     * value == 0 any anchor is provable and Rust returns true. */
    if (value != 0 && memcmp(pub.anchor, anchor, 32) != 0)
        goto out;
    memcpy(pub.anchor, anchor, 32);

    if (!spend_proof_make(pks, &wit, &pub, proof))
        zcl_panic("proving should not fail");

    /* rustzcash.rs:1505-1515 nf from the FULL u64 position (the circuit uses
     * only the low 32 bits, so position >= 2^32 fails the self-verify, as in
     * Rust). nk = [nsk] ProofGenerationKey. */
    sapling_nsk_to_nk(nsk, nk);
    if (!sapling_compute_nf(diversifier, wit.pk_d, value, rcm, ak_c, nk,
                            position, nf))
        zcl_panic("internal: nullifier computation failed on validated inputs");
    if (!jub_from_bytes(&rk_pt, rk_bytes))
        zcl_panic("internal: rk failed to decode");
    /* rustzcash.rs:1549-1588 self-verification against SAPLING_SPEND_VK. */
    if (!spend_self_verify(proof, &rk_pt, pub.cv, anchor, nf))
        goto out;

    /* rustzcash.rs:1591-1600 ctx.bvk += cv */
    struct jub_point cvp;
    if (!jub_from_bytes(&cvp, pub.cv))
        zcl_panic("internal: cv failed to decode");
    jub_add(&c->bvk, &c->bvk, &cvp);
    /* rustzcash.rs:1603-1610 write cv and the proof */
    memcpy(cv, pub.cv, 32);
    memcpy(zkproof, proof, GROTH_PROOF_SIZE);
    ok = true;

out:
    memory_cleanse(rcv, sizeof(rcv));
    memory_cleanse(&rcv_fs, sizeof(rcv_fs));
    memory_cleanse(&wit, sizeof(wit));
    memory_cleanse(&pub, sizeof(pub));
    memory_cleanse(nk, sizeof(nk));
    memory_cleanse(compact, sizeof(compact));
    return ok;
}

bool librustzcash_sapling_output_proof(void *ctx, const unsigned char *esk,
                                       const unsigned char *diversifier,
                                       const unsigned char *pk_d,
                                       const unsigned char *rcm,
                                       const uint64_t value, unsigned char *cv,
                                       unsigned char *zkproof)
{
    warm();
    struct zcl_pctx *c = pctx_get(ctx);
    bool ok = false;
    uint8_t pk_d_c[32], rcv[32];
    uint8_t proof[GROTH_PROOF_SIZE];
    struct fs rcv_fs, neg;
    struct jub_point g_d, cvp;
    struct sapling_output_witness wit;
    struct sapling_output_inputs pub;
    memset(&wit, 0, sizeof(wit));
    memset(&pub, 0, sizeof(pub));
    memset(rcv, 0, sizeof(rcv));
    memset(&rcv_fs, 0, sizeof(rcv_fs));
    memset(&neg, 0, sizeof(neg));

    /* rustzcash.rs:1157-1160 esk: Fs::from_repr -> false */
    if (!lt_r(esk))
        goto out;
    /* rustzcash.rs:1166-1175 pk_d: Point::read + as_prime_order -> false */
    if (!zcl_c23_point_prime_order_canonical(pk_d, pk_d_c))
        goto out;
    /* rustzcash.rs:1187-1190 rcm: Fs::from_repr -> false */
    if (!lt_r(rcm))
        goto out;
    /* rustzcash.rs:1195-1205 rcv = Fs::rand; ctx.bsk -= rcv */
    generate_r_or_abort(rcv);
    if (!fs_from_bytes(&rcv_fs, rcv))
        zcl_panic("internal: generated rcv is not canonical");
    fs_neg(&neg, &rcv_fs);
    fs_add(&c->bsk, &c->bsk, &neg);

    /* rustzcash.rs:1224 SAPLING_OUTPUT_PARAMS.as_ref().unwrap(), evaluated as
     * an argument of create_random_proof, after the bsk update and before
     * synthesis (which is where an invalid diversifier panics). */
    require_init();
    const struct zcl_pk_set *pks = pks_get();

    /* rustzcash.rs:1223-1227 create_random_proof(..).expect: the Output
     * circuit witnesses g_d through payment_address.g_d(), None for an
     * invalid diversifier -> SynthesisError::AssignmentMissing -> panic.
     * (Rust never checks the diversifier before this point.) */
    if (!sapling_diversifier_to_gd(&g_d, diversifier))
        zcl_panic("proving should not fail (invalid diversifier)");

    wit.value = value;
    memcpy(wit.diversifier, diversifier, 11);
    memcpy(wit.pk_d, pk_d_c, 32);
    memcpy(wit.rcm, rcm, 32);
    memcpy(wit.esk, esk, 32);
    memcpy(wit.rcv, rcv, 32);
    struct jub_point epk;
    jub_scalar_mul(&epk, &g_d, esk);
    jub_to_bytes(pub.epk, &epk);
    if (!sapling_value_commit(value, rcv, pub.cv) ||
        !sapling_compute_cm(diversifier, pk_d_c, value, rcm, pub.cm))
        zcl_panic("internal: output public inputs failed on validated inputs");

    if (!output_proof_make(pks, &wit, &pub, proof))
        zcl_panic("proving should not fail");

    /* rustzcash.rs:1235-1245 ctx.bvk -= cv (no self-verification in Rust) */
    if (!jub_from_bytes(&cvp, pub.cv))
        zcl_panic("internal: cv failed to decode");
    jub_neg(&cvp, &cvp);
    jub_add(&c->bvk, &c->bvk, &cvp);
    /* rustzcash.rs:1230-1232 and :1248-1250 write the proof and cv */
    memcpy(zkproof, proof, GROTH_PROOF_SIZE);
    memcpy(cv, pub.cv, 32);
    ok = true;

out:
    memory_cleanse(rcv, sizeof(rcv));
    memory_cleanse(&rcv_fs, sizeof(rcv_fs));
    memory_cleanse(&neg, sizeof(neg));
    memory_cleanse(&wit, sizeof(wit));
    memory_cleanse(&pub, sizeof(pub));
    return ok;
}

bool librustzcash_sapling_spend_sig(const unsigned char *ask,
                                    const unsigned char *ar,
                                    const unsigned char *sighash,
                                    unsigned char *result)
{
    warm();
    /* rustzcash.rs:1263-1266 ar: Fs::from_repr -> false */
    if (!lt_r(ar))
        return false;
    /* rustzcash.rs:1269-1272 ask: PrivateKey::read (Fs::from_repr) -> false */
    if (!lt_r(ask))
        return false;
    /* rustzcash.rs:1275 rsk = ask + ar (mod r) */
    struct fs ask_fs, ar_fs, rsk_fs;
    uint8_t rsk[32];
    if (!fs_from_bytes(&ask_fs, ask) || !fs_from_bytes(&ar_fs, ar))
        zcl_panic("internal: range-checked scalar rejected");
    fs_add(&rsk_fs, &ask_fs, &ar_fs);
    fs_to_bytes(rsk, &rsk_fs);
    /* rustzcash.rs:1278-1299 rk = [rsk] G_spend; sign rk.write() || sighash
     * with OsRng: redjubjub.rs:73-103. redjubjub_sign derives vk = [rsk] G and
     * hashes T || vk || sighash and Rbar || vk || sighash, the same bytes. Its
     * only failure is the CSPRNG, where Rust's OsRng::new().expect panics. */
    bool ok = redjubjub_sign(rsk, sighash, 32, result, ZCL_GEN_SPENDING_KEY);
    memory_cleanse(&ask_fs, sizeof(ask_fs));
    memory_cleanse(&ar_fs, sizeof(ar_fs));
    memory_cleanse(&rsk_fs, sizeof(rsk_fs));
    memory_cleanse(rsk, sizeof(rsk));
    if (!ok)
        zcl_panic("should be able to construct RNG");
    return true;
}

bool librustzcash_sapling_binding_sig(const void *ctx, int64_t valueBalance,
                                      const unsigned char *sighash,
                                      unsigned char *result)
{
    warm();
    const struct zcl_pctx *c = pctx_get(ctx);
    uint8_t bsk[32], bvk_bytes[32], tmp_bytes[32];
    struct jub_point bvk, vb, tmp;

    /* rustzcash.rs:1312-1319 bvk = [bsk] ValueCommitmentRandomness */
    fs_to_bytes(bsk, &c->bsk);
    jub_scalar_mul(&bvk, &G_VALUE_RAND, bsk);
    jub_to_bytes(bvk_bytes, &bvk);

    /* rustzcash.rs:1326-1329 compute_value_balance; INT64_MIN -> false */
    if (!value_balance_point(valueBalance, &vb)) {
        memory_cleanse(bsk, sizeof(bsk));
        return false;
    }
    /* rustzcash.rs:1332-1339 ctx.bvk - [valueBalance] G_v must equal bvk */
    jub_neg(&vb, &vb);
    jub_add(&tmp, &c->bvk, &vb);
    jub_to_bytes(tmp_bytes, &tmp);
    if (memcmp(tmp_bytes, bvk_bytes, 32) != 0) {
        memory_cleanse(bsk, sizeof(bsk));
        return false;
    }
    /* rustzcash.rs:1343-1360 sign bvk.write() || sighash with
     * ValueCommitmentRandomness; redjubjub_sign recomputes vk = [bsk] G, the
     * same bvk. Works with zero descriptions (bsk = 0, bvk = identity). */
    bool ok = redjubjub_sign(bsk, sighash, 32, result,
                             ZCL_GEN_VALUE_COMMITMENT_RANDOMNESS);
    memory_cleanse(bsk, sizeof(bsk));
    if (!ok)
        zcl_panic("should be able to construct RNG");
    return true;
}

void librustzcash_sprout_prove(
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
    /* rustzcash.rs:1068-1072 SPROUT_GROTH16_PARAMS_PATH.expect(..) */
    require_init();
    warm();
    /* rustzcash.rs:943-1089: the C23 Sprout prover (c23/sprout_prover) takes
     * the identical argument list and maps Rust's asserts/expects to abort. */
    zc23_sprout_prove(proof_out, phi, rt, h_sig, in_sk1, in_value1, in_rho1,
                      in_r1, in_auth1, in_sk2, in_value2, in_rho2, in_r2,
                      in_auth2, out_pk1, out_value1, out_r1, out_pk2,
                      out_value2, out_r2, vpub_old, vpub_new);
}

/* ------------------------------------------------------------------------ */
/* ZIP-32                                                                    */
/* ------------------------------------------------------------------------ */

void librustzcash_zip32_xsk_master(const unsigned char *seed, size_t seedlen,
                                   unsigned char *xsk_master)
{
    /* rustzcash.rs:1630-1642, zip32 lib.rs:403-420 */
    warm();
    struct zip32_xsk x;
    zip32_xsk_master(&x, seed, seedlen);
    zcl_c23_xsk_write(&x, xsk_master);
    memory_cleanse(&x, sizeof(x));
}

void librustzcash_zip32_xsk_derive(const unsigned char *xsk_parent, uint32_t i,
                                   unsigned char *xsk_i)
{
    warm();
    struct zip32_xsk parent, child;
    /* rustzcash.rs:1650-1651 ExtendedSpendingKey::read(..).expect(..) */
    if (!zcl_c23_xsk_parse(xsk_parent, &parent))
        zcl_panic("valid ExtendedSpendingKey");
    /* rustzcash.rs:1652-1657, zip32 lib.rs:463-495: hardened iff i >= 2^31;
     * depth + 1 wraps (u8, release profile has no overflow checks). */
    zip32_xsk_derive(&child, &parent, i);
    zcl_c23_xsk_write(&child, xsk_i);
    memory_cleanse(&parent, sizeof(parent));
    memory_cleanse(&child, sizeof(child));
}

bool librustzcash_zip32_xfvk_derive(const unsigned char *xfvk_parent,
                                    uint32_t i, unsigned char *xfvk_i)
{
    warm();
    struct zip32_xfvk parent, child;
    /* rustzcash.rs:1666-1667 ExtendedFullViewingKey::read(..).expect(..),
     * BEFORE the hardened check. */
    if (!zcl_c23_xfvk_parse(xfvk_parent, &parent))
        zcl_panic("valid ExtendedFullViewingKey");
    /* rustzcash.rs:1670-1673, zip32 lib.rs:548-551: hardened -> false */
    if (i >= ZIP32_HARDENED_KEY_LIMIT)
        return false;
    if (!zip32_xfvk_derive(&child, &parent, i))
        zcl_panic("internal: non-hardened xfvk derivation failed");
    /* rustzcash.rs:1675-1676 */
    zcl_c23_xfvk_write(&child, xfvk_i);
    return true;
}

bool librustzcash_zip32_xfvk_address(const unsigned char *xfvk,
                                     const unsigned char *j,
                                     unsigned char *j_ret,
                                     unsigned char *addr_ret)
{
    warm();
    struct zip32_xfvk x;
    /* rustzcash.rs:1688-1689 ExtendedFullViewingKey::read(..).expect(..) */
    if (!zcl_c23_xfvk_parse(xfvk, &x))
        zcl_panic("valid ExtendedFullViewingKey");
    /* rustzcash.rs:1690-1695, zip32 lib.rs:313-332 and :574-586: from index
     * j, FF1-AES256(dk) the 88-bit LE index, increment j (LE bytes, wrapping)
     * until g_d is valid; exhaustion -> false. */
    uint8_t jj[11], d[11], ivk[32], pk_d[32];
    memcpy(jj, j, 11);
    if (!zip32_diversifier(x.dk, jj, d))
        return false;
    /* into_payment_address: pk_d = [ivk] g_d, ivk = CRH(ak.write(), nk.write())
     * (primitives/mod.rs:87-120); the parsed ak, nk are canonical. */
    sapling_crh_ivk(x.fvk.ak, x.fvk.nk, ivk);
    struct jub_point g_d, p;
    if (!sapling_diversifier_to_gd(&g_d, d))
        zcl_panic("internal: FF1 diversifier lost validity");
    jub_scalar_mul(&p, &g_d, ivk);
    jub_to_bytes(pk_d, &p);
    memory_cleanse(ivk, sizeof(ivk));
    /* rustzcash.rs:1697-1708 j_ret = j, addr = d || pk_d */
    memcpy(j_ret, jj, 11);
    memcpy(addr_ret, d, 11);
    memcpy(addr_ret + 11, pk_d, 32);
    return true;
}
