/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling key operations — pure C23 implementation.
 * group_hash, key derivation, commitment, nullifier, RedJubjub, verification context. */
#include <stdio.h>
#include <inttypes.h>
#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "sapling/sapling_prover.h"
#include "sapling/params_init.h"
#include "sapling/pedersen_hash.h"
#include "sapling/note_encryption.h"
#include "sapling/jubjub.h"
#include "sapling/bls12_381.h"
#include "crypto/blake2s.h"
#include "crypto/blake2b.h"
#include "crypto/random_secret.h"
#include "core/random.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
/* Global verifying keys — set by sapling_init_vk() at startup */
static struct groth16_vk *sapling_spend_vk = NULL;
static struct groth16_vk *sapling_output_vk = NULL;
/* URS: first 64 bytes of BLAKE2s input for group_hash (rigidity constant) */
static const uint8_t GH_FIRST_BLOCK[] =
    "096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";
bool group_hash(struct jub_point *result,
                const uint8_t *tag, size_t tag_len,
                const uint8_t personalization[8])
{
    struct blake2s_ctx ctx;
    uint8_t hash[32];

    blake2s_init_personal(&ctx, 32, personalization);
    blake2s_update(&ctx, GH_FIRST_BLOCK, 64);
    blake2s_update(&ctx, tag, tag_len);
    blake2s_final(&ctx, hash, 32);

    /* group_hash is probabilistic: ~50% of tags fail to decode. Callers
     * (find_group_hash) drive the retry loop — bare `false` here is the
     * "miss, try next counter" signal and is NOT an error. Logging every
     * miss would generate hundreds of spurious entries at startup. */
    if (!jub_from_bytes(result, hash))
        return false;

    jub_mul_by_cofactor(result, result);

    return !jub_is_identity(result);
}

/* find_group_hash: try counter bytes until group_hash succeeds */
static bool find_group_hash(struct jub_point *result,
                             const uint8_t *m, size_t m_len,
                             const uint8_t personalization[8])
{
    uint8_t tag[256];
    if (m_len + 1 > sizeof(tag))
        LOG_FAIL("sapling",
                 "find_group_hash: tag buffer too small: m_len=%zu max=%zu",
                 m_len, sizeof(tag) - 1);
    memcpy(tag, m, m_len);
    tag[m_len] = 0;

    for (int i = 0; i < 256; i++) {
        tag[m_len] = (uint8_t)i;
        /* group_hash is allowed to miss — bit-string to curve is probabilistic.
         * Only the full exhaustion of all 256 counters is an error worth logging. */
        if (group_hash(result, tag, m_len + 1, personalization))
            return true;
    }
    LOG_FAIL("sapling",
             "find_group_hash: exhausted all 256 counters (personalization '%.8s')",
             (const char *)personalization);
}

/* Fixed generators, lazily computed */
enum {
    GEN_PROOF_GENERATION_KEY = 0,
    GEN_NOTE_COMMITMENT_RANDOMNESS = 1,
    GEN_NULLIFIER_POSITION = 2,
    GEN_VALUE_COMMITMENT_VALUE = 3,
    GEN_VALUE_COMMITMENT_RANDOMNESS = 4,
    GEN_SPENDING_KEY = 5,
    GEN_MAX = 6
};

static struct jub_point fixed_generators[GEN_MAX];
/* Written once, by pthread_once: every reader of fixed_generators[] passes
 * through ensure_fixed_generators(), so it sees the finished table and no
 * thread can race the derivation. */
static pthread_once_t fixed_generators_once = PTHREAD_ONCE_INIT;

/* One row per GEN_* generator: the name that appears in the abort message, the
 * find_group_hash message, and the 8-byte personalization. Designated
 * initializers key each row to its own enum index, so a row cannot silently
 * drift onto the wrong generator and a seventh generator is one new row. */
static const struct {
    const char *name;     /* appears in the abort message */
    const char *tag;      /* "" or a single byte, per the Zcash spec */
    const char *personal; /* exactly 8 bytes */
} FIXED_GENERATOR_SPEC[GEN_MAX] = {
    [GEN_PROOF_GENERATION_KEY]        = { "ProofGenerationKey",        "",  "Zcash_H_" },
    [GEN_NOTE_COMMITMENT_RANDOMNESS]  = { "NoteCommitmentRandomness",  "r", "Zcash_PH" },
    [GEN_NULLIFIER_POSITION]          = { "NullifierPosition",         "",  "Zcash_J_" },
    [GEN_VALUE_COMMITMENT_VALUE]      = { "ValueCommitmentValue",      "v", "Zcash_cv" },
    [GEN_VALUE_COMMITMENT_RANDOMNESS] = { "ValueCommitmentRandomness", "r", "Zcash_cv" },
    [GEN_SPENDING_KEY]                = { "SpendingKey",               "",  "Zcash_G_" },
};

/* Derive every fixed generator or abort: these are hard-coded inputs with
 * hard-coded personalizations; failure means the Jubjub group_hash machinery
 * is broken and every subsequent scalar mul would silently produce garbage. */
static void fixed_generators_init(void)
{
    for (size_t i = 0; i < GEN_MAX; i++) {
        const char *tag = FIXED_GENERATOR_SPEC[i].tag;
        if (find_group_hash(&fixed_generators[i], (const uint8_t *)tag,
                            strlen(tag),
                            (const uint8_t *)FIXED_GENERATOR_SPEC[i].personal))
            continue;
        fprintf(stderr, "[sapling] %s:%d %s(): "  // obs-ok:helper-context-logged
                "find_group_hash failed for fixed generator '%s' — "
                "refusing to run with zero-initialized generator\n",
                __FILE__, __LINE__, __func__, FIXED_GENERATOR_SPEC[i].name);
        abort(); // abort-ok: a zero-initialized fixed generator makes every later scalar mul silently produce garbage commitments
    }
}

static void ensure_fixed_generators(void)
{
    pthread_once(&fixed_generators_once, fixed_generators_init);
}

bool sapling_check_diversifier(const uint8_t diversifier[11])
{
    struct jub_point g_d;
    return group_hash(&g_d, diversifier, 11,
                      (const uint8_t *)"Zcash_gd");
}

bool sapling_diversifier_to_gd(struct jub_point *g_d, const uint8_t diversifier[11])
{
    return group_hash(g_d, diversifier, 11,
                      (const uint8_t *)"Zcash_gd");
}

void sapling_ask_to_ak(const uint8_t ask[32], uint8_t ak[32])
{
    ensure_fixed_generators();
    struct jub_point result;
    jub_scalar_mul(&result, &fixed_generators[GEN_SPENDING_KEY], ask);
    jub_to_bytes(ak, &result);
}

void sapling_nsk_to_nk(const uint8_t nsk[32], uint8_t nk[32])
{
    ensure_fixed_generators();
    struct jub_point result;
    jub_scalar_mul(&result, &fixed_generators[GEN_PROOF_GENERATION_KEY], nsk);
    jub_to_bytes(nk, &result);
}

bool sapling_compute_rk(const uint8_t ak[32], const uint8_t ar[32],
                          uint8_t rk[32])
{
    ensure_fixed_generators();
    struct jub_point ak_pt;
    if (!jub_from_bytes(&ak_pt, ak))
        LOG_FAIL("sapling", "compute_rk: jub_from_bytes(ak) failed");
    struct jub_point ar_G;
    jub_scalar_mul(&ar_G, &fixed_generators[GEN_SPENDING_KEY], ar);
    struct jub_point rk_pt;
    jub_add(&rk_pt, &ak_pt, &ar_G);
    jub_to_bytes(rk, &rk_pt);
    return true;
}

void sapling_spend_auth_generator(struct fr *x, struct fr *y)
{
    ensure_fixed_generators();
    jub_get_x(x, &fixed_generators[GEN_SPENDING_KEY]);
    jub_get_y(y, &fixed_generators[GEN_SPENDING_KEY]);
}

void sapling_proof_gen_key_generator(struct fr *x, struct fr *y)
{
    ensure_fixed_generators();
    jub_get_x(x, &fixed_generators[GEN_PROOF_GENERATION_KEY]);
    jub_get_y(y, &fixed_generators[GEN_PROOF_GENERATION_KEY]);
}

void sapling_value_commit_value_generator(struct fr *x, struct fr *y)
{
    ensure_fixed_generators();
    jub_get_x(x, &fixed_generators[GEN_VALUE_COMMITMENT_VALUE]);
    jub_get_y(y, &fixed_generators[GEN_VALUE_COMMITMENT_VALUE]);
}

void sapling_value_commit_randomness_generator(struct fr *x, struct fr *y)
{
    ensure_fixed_generators();
    jub_get_x(x, &fixed_generators[GEN_VALUE_COMMITMENT_RANDOMNESS]);
    jub_get_y(y, &fixed_generators[GEN_VALUE_COMMITMENT_RANDOMNESS]);
}

void sapling_note_commit_randomness_generator(struct fr *x, struct fr *y)
{
    ensure_fixed_generators();
    jub_get_x(x, &fixed_generators[GEN_NOTE_COMMITMENT_RANDOMNESS]);
    jub_get_y(y, &fixed_generators[GEN_NOTE_COMMITMENT_RANDOMNESS]);
}

void sapling_nullifier_position_generator(struct fr *x, struct fr *y)
{
    ensure_fixed_generators();
    jub_get_x(x, &fixed_generators[GEN_NULLIFIER_POSITION]);
    jub_get_y(y, &fixed_generators[GEN_NULLIFIER_POSITION]);
}

void sapling_crh_ivk(const uint8_t ak[32], const uint8_t nk[32], uint8_t ivk[32])
{
    struct blake2s_ctx ctx;
    blake2s_init_personal(&ctx, 32, (const uint8_t *)"Zcashivk");
    blake2s_update(&ctx, ak, 32);
    blake2s_update(&ctx, nk, 32);
    blake2s_final(&ctx, ivk, 32);
    /* ctx absorbed ak||nk — cleanse the spent hash context */
    memory_cleanse(&ctx, sizeof(ctx));
    /* Drop top 5 bits so it can be interpreted as Fs scalar */
    ivk[31] &= 0x07;
}

bool sapling_ivk_to_pkd(const uint8_t ivk[32], const uint8_t diversifier[11],
                         uint8_t pk_d[32])
{
    struct jub_point g_d;
    if (!sapling_diversifier_to_gd(&g_d, diversifier))
        LOG_FAIL("sapling", "ivk_to_pkd: diversifier_to_gd failed (invalid d)");

    struct jub_point result;
    jub_scalar_mul(&result, &g_d, ivk);
    jub_to_bytes(pk_d, &result);
    return true;
}

bool sapling_ka_agree(const uint8_t p[32], const uint8_t sk[32], uint8_t result[32])
{
    struct jub_point point;
    if (!jub_from_bytes(&point, p))
        LOG_FAIL("sapling", "ka_agree: jub_from_bytes(peer point) failed");

    /* Multiply by cofactor 8 first */
    jub_mul_by_cofactor(&point, &point);

    /* Then multiply by sk */
    struct jub_point out;
    jub_scalar_mul(&out, &point, sk);

    jub_to_bytes(result, &out);
    return true;
}

bool sapling_ka_derivepublic(const uint8_t diversifier[11], const uint8_t esk[32],
                              uint8_t result[32])
{
    struct jub_point g_d;
    if (!sapling_diversifier_to_gd(&g_d, diversifier))
        LOG_FAIL("sapling", "ka_derivepublic: diversifier_to_gd failed (invalid d)");

    struct jub_point out;
    jub_scalar_mul(&out, &g_d, esk);
    jub_to_bytes(result, &out);
    return true;
}

/* Pedersen hash with NoteCommitment personalization (all 6 bits set) */
static void pedersen_note_commitment(const uint8_t *data, size_t data_len,
                                      struct jub_point *result)
{
    /* Extract all bits from data */
    size_t nbits = data_len * 8;

    /* Personalization bits: NoteCommitment = [1,1,1,1,1,1] */
    uint8_t bits[6 + 8 * 576]; /* 6 personal + up to 576 data bits */
    int pos = 0;

    for (int i = 0; i < 6; i++)
        bits[pos++] = 1;

    for (size_t i = 0; i < nbits; i++) {
        int byte_idx = (int)(i / 8);
        int bit_idx = (int)(i % 8);
        bits[pos++] = (data[byte_idx] >> bit_idx) & 1;
    }

    /* Use the same Pedersen hash engine but with NoteCommitment personalization.
     * We need a version that takes raw bits. For now, we implement the same
     * scalar accumulation + generator multiplication as pedersen_merkle_hash
     * but with the NoteCommitment personalization already encoded in bits[]. */

    /* The pedersen_hash function from Rust takes personalization bits prepended
     * to the data bits, then processes in 3-bit chunks across generators.
     * Our pedersen_merkle_hash hardcodes MerkleTree personalization.
     * We need a generic version. */

    /* Call the generic Pedersen hash with pre-assembled bits */
    extern void pedersen_hash_bits(const uint8_t *bits, int nbits,
                                    struct jub_point *result);
    pedersen_hash_bits(bits, pos, result);
}

bool sapling_note_commitment_point(const uint8_t diversifier[11],
                                    const uint8_t pk_d[32],
                                    uint64_t value, const uint8_t rcm[32],
                                    struct jub_point *cm_out)
{
    if (!cm_out)
        LOG_FAIL("sapling", "note_commitment_point: NULL output point");
    ensure_fixed_generators();

    /* Note contents: value(8 LE) || g_d(32) || pk_d(32) = 72 bytes */
    uint8_t note_contents[72];
    for (int i = 0; i < 8; i++)
        note_contents[i] = (uint8_t)(value >> (i * 8));
    struct jub_point g_d;
    if (!sapling_diversifier_to_gd(&g_d, diversifier))
        LOG_FAIL("sapling",
                 "note_commitment_point: diversifier_to_gd failed (invalid d)");
    jub_to_bytes(note_contents + 8, &g_d);
    memcpy(note_contents + 40, pk_d, 32);

    /* cm_full = PedersenHash(NoteCommitment, contents) + [rcm] G_rcm */
    struct jub_point hash_pt, rcm_point;
    pedersen_note_commitment(note_contents, 72, &hash_pt);
    jub_scalar_mul(&rcm_point,
                   &fixed_generators[GEN_NOTE_COMMITMENT_RANDOMNESS], rcm);
    jub_add(cm_out, &hash_pt, &rcm_point);
    return true;
}

bool sapling_compute_cm(const uint8_t diversifier[11], const uint8_t pk_d[32],
                         uint64_t value, const uint8_t rcm[32],
                         uint8_t cm[32])
{
    struct jub_point cm_pt;
    if (!sapling_note_commitment_point(diversifier, pk_d, value, rcm, &cm_pt))
        LOG_FAIL("sapling", "compute_cm: note_commitment_point failed");
    struct fr x_coord;                  /* cm == cm_full.x, the tree leaf */
    jub_get_x(&x_coord, &cm_pt);
    fr_to_bytes(cm, &x_coord);
    return true;
}

bool sapling_compute_nf(const uint8_t diversifier[11], const uint8_t pk_d[32],
                         uint64_t value, const uint8_t rcm[32],
                         const uint8_t ak_bytes[32], const uint8_t nk_bytes[32],
                         uint64_t position, uint8_t nf[32])
{
    ensure_fixed_generators();
    (void)ak_bytes; /* ak used only for viewing key construction, nf needs nk */

    /* The note-commitment point — the same body sapling_compute_cm() publishes
     * the x-coordinate of, so the nullifier can never be computed over a
     * different note than the commitment the tree stores. */
    struct jub_point cm_pt;
    if (!sapling_note_commitment_point(diversifier, pk_d, value, rcm, &cm_pt))
        LOG_FAIL("sapling", "compute_nf: note_commitment_point failed");

    /* rho = cm_full_point + position * NullifierPosition */
    uint8_t pos_bytes[32] = {0};
    for (int i = 0; i < 8; i++)
        pos_bytes[i] = (uint8_t)(position >> (i * 8));

    struct jub_point pos_point;
    jub_scalar_mul(&pos_point, &fixed_generators[GEN_NULLIFIER_POSITION], pos_bytes);

    struct jub_point rho;
    jub_add(&rho, &cm_pt, &pos_point);

    /* nf = BLAKE2s("Zcash_nf", nk || rho_compressed) */
    uint8_t rho_bytes[32];
    jub_to_bytes(rho_bytes, &rho);

    struct blake2s_ctx ctx;
    blake2s_init_personal(&ctx, 32, (const uint8_t *)"Zcash_nf");
    blake2s_update(&ctx, nk_bytes, 32);
    blake2s_update(&ctx, rho_bytes, 32);
    blake2s_final(&ctx, nf, 32);
    return true;
}

/* --- RedJubjub signature verification --- */

/* H* = BLAKE2b-512("Zcash_RedJubjubH", a || b) → reduce to Fs via to_uniform */
static void h_star(const uint8_t *a, size_t a_len,
                    const uint8_t *b, size_t b_len,
                    const uint8_t *c, size_t c_len,
                    uint8_t scalar[32])
{
    static const uint8_t personal[16] = {'Z','c','a','s','h','_','R','e','d','J','u','b','j','u','b','H'};
    uint8_t digest[64];
    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 64, NULL, 0, NULL, personal);
    blake2b_update(&ctx, a, a_len);
    blake2b_update(&ctx, b, b_len);
    if (c && c_len > 0)
        blake2b_update(&ctx, c, c_len);
    blake2b_final(&ctx, digest, 64);
    jubjub_to_scalar(digest, scalar);
    /* Cleanse the spent hash context and digest (absorbed signing inputs) */
    memory_cleanse(&ctx, sizeof(ctx));
    memory_cleanse(digest, sizeof(digest));
}

/* Check if point has small order: [8]*p == identity */
static bool is_small_order(const uint8_t point_bytes[32])
{
    struct jub_point p;
    if (!jub_from_bytes(&p, point_bytes))
        return true;
    struct jub_point cofactored;
    jub_mul_by_cofactor(&cofactored, &p);
    return jub_is_identity(&cofactored);
}

bool redjubjub_verify(const uint8_t vk_bytes[32],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sig_rbar[32],
                       const uint8_t sig_sbar[32],
                       int generator_idx)
{
    ensure_fixed_generators();

    /* Deserialize vk */
    struct jub_point vk;
    if (!jub_from_bytes(&vk, vk_bytes))
        LOG_FAIL("redjubjub", "jub_from_bytes(vk) failed");

    /* Deserialize R */
    struct jub_point R;
    if (!jub_from_bytes(&R, sig_rbar))
        LOG_FAIL("redjubjub", "jub_from_bytes(R) failed");

    /* c = H*(Rbar || vk_bytes || msg) per Zcash spec §5.4.7 */
    uint8_t c_scalar[32];
    h_star(sig_rbar, 32, vk_bytes, 32, msg, msg_len, c_scalar);

    /* Canonical-S check: S must be < Fs (Jubjub subgroup order). Zcash
     * consensus mirrors the Rust implementation's Fs::from_repr check;
     * non-canonical S otherwise round-trips but would make the sig
     * malleable and could split consensus with zcashd. */
    {
        struct fs s_canon;
        if (!fs_from_bytes(&s_canon, sig_sbar))
            LOG_FAIL("redjubjub", "S >= Fs order (non-canonical signature)");
    }

    /* Verify: [8] * (R + c*vk - S*G) == 0
     * Equivalently: [8] * (-S*G + R + c*vk) == 0 */

    /* c * vk */
    struct jub_point c_vk;
    jub_scalar_mul(&c_vk, &vk, c_scalar);

    /* S * G */
    struct jub_point s_g;
    jub_scalar_mul(&s_g, &fixed_generators[generator_idx], sig_sbar);

    /* -S*G */
    struct jub_point neg_s_g;
    jub_neg(&neg_s_g, &s_g);

    /* R + c*vk + (-S*G) */
    struct jub_point sum;
    jub_add(&sum, &R, &c_vk);
    jub_add(&sum, &sum, &neg_s_g);

    /* [8] * sum */
    struct jub_point result;
    jub_mul_by_cofactor(&result, &sum);

    return jub_is_identity(&result);
}

/* --- Sapling verification context --- */

void sapling_verification_ctx_init(struct sapling_verification_ctx *ctx)
{
    jub_identity(&ctx->bvk);
}

/* Extract Jubjub point affine (x, y) as raw Fr limbs (4 x uint64_t each).
 * Jubjub base field = BLS12-381 Fr, so coordinates are Fr elements. */
static void jub_to_affine_raw(uint64_t out_x[4], uint64_t out_y[4],
                                const struct jub_point *p)
{
    struct fr z_inv;
    fr_inv(&z_inv, &p->z);
    struct fr x_aff, y_aff;
    fr_mul(&x_aff, &p->x, &z_inv);
    fr_mul(&y_aff, &p->y, &z_inv);

    /* Convert from Montgomery to raw via fr_to_bytes then re-read as limbs */
    uint8_t buf[32];
    fr_to_bytes(buf, &x_aff);
    for (int i = 0; i < 4; i++) {
        out_x[i] = 0;
        for (int j = 0; j < 8; j++)
            out_x[i] |= (uint64_t)buf[i * 8 + j] << (8 * j);
    }
    fr_to_bytes(buf, &y_aff);
    for (int i = 0; i < 4; i++) {
        out_y[i] = 0;
        for (int j = 0; j < 8; j++)
            out_y[i] |= (uint64_t)buf[i * 8 + j] << (8 * j);
    }
}

/* Read 32 LE bytes as raw Fr limbs */
static void bytes_le_to_fr_raw(uint64_t out[4], const uint8_t bytes[32])
{
    for (int i = 0; i < 4; i++) {
        out[i] = 0;
        for (int j = 0; j < 8; j++)
            out[i] |= (uint64_t)bytes[i * 8 + j] << (8 * j);
    }
}

void sapling_set_spend_vk(struct groth16_vk *vk) { sapling_spend_vk = vk; }
void sapling_set_output_vk(struct groth16_vk *vk) { sapling_output_vk = vk; }

#ifdef ZCL_TESTING
/* Published-VK read-back (see sapling.h). */
const struct groth16_vk *sapling_test_published_spend_vk(void) { return sapling_spend_vk; }
const struct groth16_vk *sapling_test_published_output_vk(void) { return sapling_output_vk; }

/* ── Test-ONLY deterministic RNG hook (see sapling.h) ─────────────
 *
 * Compiled ONLY under -DZCL_TESTING. The production node binary does
 * not contain this symbol or the branch below at all: sapling_generate_r()
 * there is byte-identical to the pre-hook code (always zcl_random_secret_bytes
 * → GetRandBytes → kernel CSPRNG). Even in a ZCL_TESTING build the hook
 * defaults to NULL, so nothing diverts the prover RNG until a test
 * explicitly installs a deterministic source and then clears it. */
#include <stdatomic.h>
static _Atomic(sapling_test_rng_fn) g_sapling_test_rng_fn = NULL;
static void *g_sapling_test_rng_user = NULL;
void sapling_set_test_rng_hook(sapling_test_rng_fn fn, void *user)
{
    /* Publish user before fn so a concurrent reader that observes a
     * non-NULL fn also observes the matching user pointer. */
    g_sapling_test_rng_user = user;
    atomic_store_explicit(&g_sapling_test_rng_fn, fn, memory_order_release);
}

/* RedJubjub signing-nonce hook (see sapling.h). Separate from the note-RNG
 * hook so the two seams stay independently controllable; both default NULL. */
static _Atomic(sapling_test_rng_fn) g_redjubjub_test_rng_fn = NULL;
static void *g_redjubjub_test_rng_user = NULL;
void redjubjub_set_test_rng_hook(sapling_test_rng_fn fn, void *user)
{
    g_redjubjub_test_rng_user = user;
    atomic_store_explicit(&g_redjubjub_test_rng_fn, fn, memory_order_release);
}
#endif /* ZCL_TESTING */

/* Fill the RedJubjub nonce seed T: the test hook when installed, else the
 * production CSPRNG. Byte-identical to zcl_random_secret_bytes when no hook. */
static bool redjubjub_nonce_bytes(uint8_t *out, size_t n, const char *label)
{
#ifdef ZCL_TESTING
    sapling_test_rng_fn hook =
        atomic_load_explicit(&g_redjubjub_test_rng_fn, memory_order_acquire);
    if (hook)
        return hook(g_redjubjub_test_rng_user, out, n);
#endif
    return zcl_random_secret_bytes(out, n, label);
}

bool sapling_generate_r(uint8_t result[32])
{
    uint8_t buf[64];
    bool ok;
#ifdef ZCL_TESTING
    sapling_test_rng_fn hook =
        atomic_load_explicit(&g_sapling_test_rng_fn, memory_order_acquire);
    if (hook)
        ok = hook(g_sapling_test_rng_user, buf, 64);
    else
        ok = zcl_random_secret_bytes(buf, 64, "sapling_r");
#else
    ok = zcl_random_secret_bytes(buf, 64, "sapling_r");
#endif
    if (!ok) {
        memset(result, 0, 32);
        /* buf holds partial/full RNG output unused on error — cleanse like the success path */
        memory_cleanse(buf, 64);
        return false;
    }
    struct fs r;
    fs_to_uniform(&r, buf);
    fs_to_bytes(result, &r);
    memory_cleanse(buf, 64);
    return true;
}

/* Prepare a spend: run every non-Groth16 gate in the EXACT order and with the
 * EXACT early-returns of sapling_check_spend, fold cv into bvk, decode the
 * proof, and build the 7 public inputs. sapling_check_spend is literally
 * prepare()+groth16_verify below, so the consensus verdict is byte-identical;
 * the background batch path reuses this so its accept set matches per-proof. */
bool sapling_spend_prepare(struct sapling_verification_ctx *ctx,
                           const uint8_t cv[32], const uint8_t anchor[32],
                           const uint8_t nullifier[32], const uint8_t rk[32],
                           const uint8_t zkproof[192],
                           const uint8_t spend_auth_sig[64],
                           const uint8_t sighash[32],
                           struct groth16_proof *proof_out,
                           uint64_t (*pub_out)[4])
{
    ensure_fixed_generators();

    /* Deserialize cv */
    struct jub_point cv_point;
    if (!jub_from_bytes(&cv_point, cv))
        LOG_FAIL("sapling", "check_spend: jub_from_bytes(cv) failed");

    /* Small order check */
    if (is_small_order(cv))
        LOG_FAIL("sapling", "check_spend: cv is small-order (attack or malformed tx)");

    /* Accumulate cv into bvk */
    jub_add(&ctx->bvk, &ctx->bvk, &cv_point);

    /* anchor must be a canonical Fr encoding (< r), as zclassicd's
     * Fr::from_repr requires. */
    struct fr anchor_fr;
    if (!fr_from_bytes(&anchor_fr, anchor))
        LOG_FAIL("sapling", "check_spend: anchor is not a canonical Fr encoding");

    /* Small order check on rk */
    if (is_small_order(rk))
        LOG_FAIL("sapling", "check_spend: rk is small-order (attack or malformed tx)");

    /* Verify spend_auth_sig over sighash with rk as verification key */
    if (!redjubjub_verify(rk, sighash, 32,
                           spend_auth_sig, spend_auth_sig + 32,
                           GEN_SPENDING_KEY))
        LOG_FAIL("sapling", "check_spend: redjubjub_verify(spend_auth_sig) rejected");

    /* Groth16 proof verification (7 public inputs).
     * Fail-closed: a NULL spend VK means sapling_init_params never ran (or
     * was torn down) — continuing would silently accept every zkproof. */
    if (!sapling_spend_vk)
        LOG_FAIL("sapling", "sapling_spend_vk is NULL (params not loaded)");

    if (!groth16_proof_read(proof_out, zkproof))
        LOG_FAIL("sapling", "groth16_proof_read(spend) failed");

    /* Public inputs: rk.x, rk.y, cv.x, cv.y, anchor, nullifier_pack[0..1] */
    struct jub_point rk_point;
    if (!jub_from_bytes(&rk_point, rk))
        LOG_FAIL("sapling", "jub_from_bytes(rk) failed for spend proof");
    jub_to_affine_raw(pub_out[0], pub_out[1], &rk_point);
    jub_to_affine_raw(pub_out[2], pub_out[3], &cv_point);
    bytes_le_to_fr_raw(pub_out[4], anchor);

    /* Nullifier: bytes_to_bits_le → compute_multipacking (2 Fr scalars) */
    size_t n_packed;
    multipack_bytes_to_fr((uint64_t (*)[4])&pub_out[5], &n_packed,
                           nullifier, 32);
    return true;
}

bool sapling_spend_groth16_one(const struct groth16_proof *proof,
                               const uint64_t (*pub)[4])
{
    if (!sapling_spend_vk)
        LOG_FAIL("sapling", "sapling_spend_vk is NULL (params not loaded)");
    if (!groth16_verify(sapling_spend_vk, proof, pub, 7))
        LOG_FAIL("sapling", "groth16_verify(spend) rejected proof");
    return true;
}

bool sapling_spend_groth16_batch(const struct groth16_proof *proofs,
                                 const uint64_t (*pub)[4], size_t n_proofs)
{
    if (!sapling_spend_vk)
        LOG_FAIL("sapling", "sapling_spend_vk is NULL (params not loaded)");
    if (n_proofs == 0)
        return true;
    return groth16_batch_verify(sapling_spend_vk, proofs, pub, 7, n_proofs);
}

bool sapling_check_spend(struct sapling_verification_ctx *ctx,
                          const uint8_t cv[32],
                          const uint8_t anchor[32],
                          const uint8_t nullifier[32],
                          const uint8_t rk[32],
                          const uint8_t zkproof[192],
                          const uint8_t spend_auth_sig[64],
                          const uint8_t sighash[32])
{
    struct groth16_proof proof;
    uint64_t public_input[7][4];
    if (!sapling_spend_prepare(ctx, cv, anchor, nullifier, rk, zkproof,
                               spend_auth_sig, sighash, &proof, public_input))
        return false;
    return sapling_spend_groth16_one(&proof, public_input);
}

/* Prepare an output: run every non-Groth16 gate in the EXACT order/early-return
 * of sapling_check_output, fold -cv into bvk, decode the proof, build the 5
 * public inputs. sapling_check_output == prepare()+groth16_verify below. */
bool sapling_output_prepare(struct sapling_verification_ctx *ctx,
                            const uint8_t cv[32], const uint8_t cm[32],
                            const uint8_t epk[32], const uint8_t zkproof[192],
                            struct groth16_proof *proof_out,
                            uint64_t (*pub_out)[4])
{
    /* Deserialize cv */
    struct jub_point cv_point;
    if (!jub_from_bytes(&cv_point, cv))
        LOG_FAIL("sapling", "check_output: jub_from_bytes(cv) failed");

    /* Small order check */
    if (is_small_order(cv))
        LOG_FAIL("sapling", "check_output: cv is small-order (attack or malformed tx)");

    /* Subtract cv from bvk (outputs are negative) */
    struct jub_point neg_cv;
    jub_neg(&neg_cv, &cv_point);
    jub_add(&ctx->bvk, &ctx->bvk, &neg_cv);

    /* cm must be a canonical Fr encoding (< r), as zclassicd's
     * Fr::from_repr requires; Groth16 would reduce cm and cm + r alike. */
    struct fr cm_fr;
    if (!fr_from_bytes(&cm_fr, cm))
        LOG_FAIL("sapling", "check_output: cm is not a canonical Fr encoding");

    /* Small order check on epk */
    if (is_small_order(epk))
        LOG_FAIL("sapling", "check_output: epk is small-order (attack or malformed tx)");

    /* Groth16 proof verification (5 public inputs).
     * Fail-closed: a NULL output VK means sapling_init_params never ran —
     * continuing would silently accept every zkproof. */
    if (!sapling_output_vk)
        LOG_FAIL("sapling", "sapling_output_vk is NULL (params not loaded)");

    if (!groth16_proof_read(proof_out, zkproof))
        LOG_FAIL("sapling", "groth16_proof_read(output) failed");

    /* Public inputs: cv.x, cv.y, epk.x, epk.y, cm */
    jub_to_affine_raw(pub_out[0], pub_out[1], &cv_point);

    struct jub_point epk_point;
    if (!jub_from_bytes(&epk_point, epk))
        LOG_FAIL("sapling", "jub_from_bytes(epk) failed for output proof");
    jub_to_affine_raw(pub_out[2], pub_out[3], &epk_point);

    bytes_le_to_fr_raw(pub_out[4], cm);
    return true;
}

bool sapling_output_groth16_one(const struct groth16_proof *proof,
                                const uint64_t (*pub)[4])
{
    if (!sapling_output_vk)
        LOG_FAIL("sapling", "sapling_output_vk is NULL (params not loaded)");
    if (!groth16_verify(sapling_output_vk, proof, pub, 5))
        LOG_FAIL("sapling", "groth16_verify(output) rejected proof");
    return true;
}

bool sapling_output_groth16_batch(const struct groth16_proof *proofs,
                                  const uint64_t (*pub)[4], size_t n_proofs)
{
    if (!sapling_output_vk)
        LOG_FAIL("sapling", "sapling_output_vk is NULL (params not loaded)");
    if (n_proofs == 0)
        return true;
    return groth16_batch_verify(sapling_output_vk, proofs, pub, 5, n_proofs);
}

bool sapling_check_output(struct sapling_verification_ctx *ctx,
                           const uint8_t cv[32],
                           const uint8_t cm[32],
                           const uint8_t epk[32],
                           const uint8_t zkproof[192])
{
    struct groth16_proof proof;
    uint64_t public_input[5][4];
    if (!sapling_output_prepare(ctx, cv, cm, epk, zkproof, &proof, public_input))
        return false;
    return sapling_output_groth16_one(&proof, public_input);
}

bool sapling_final_check(struct sapling_verification_ctx *ctx,
                          int64_t value_balance,
                          const uint8_t binding_sig[64],
                          const uint8_t sighash[32])
{
    ensure_fixed_generators();

    /* Compute value balance point: value_balance * ValueCommitmentValue */
    struct jub_point value_pt;
    if (value_balance == 0) {
        jub_identity(&value_pt);
    } else {
        /* Rust uses checked_abs() which fails for INT64_MIN */
        if (value_balance == INT64_MIN)
            LOG_FAIL("sapling",
                     "final_check: value_balance == INT64_MIN (rejected to match Rust checked_abs)");
        uint64_t abs_val;
        bool negate;
        if (value_balance > 0) {
            abs_val = (uint64_t)value_balance;
            negate = false;
        } else {
            abs_val = (uint64_t)(-value_balance);
            negate = true;
        }
        uint8_t scalar[32] = {0};
        for (int i = 0; i < 8; i++)
            scalar[i] = (uint8_t)(abs_val >> (i * 8));

        jub_scalar_mul(&value_pt, &fixed_generators[GEN_VALUE_COMMITMENT_VALUE], scalar);
        if (negate)
            jub_neg(&value_pt, &value_pt);
    }

    /* bvk = bvk - value_balance */
    struct jub_point neg_value_pt;
    jub_neg(&neg_value_pt, &value_pt);
    struct jub_point final_bvk;
    jub_add(&final_bvk, &ctx->bvk, &neg_value_pt);

    /* Verify binding sig: vk = bvk, msg = sighash */
    uint8_t bvk_bytes[32];
    jub_to_bytes(bvk_bytes, &final_bvk);

    return redjubjub_verify(bvk_bytes, sighash, 32,
                             binding_sig, binding_sig + 32,
                             GEN_VALUE_COMMITMENT_RANDOMNESS);
}

/* --- RedJubjub signing --- */

bool redjubjub_sign(const uint8_t sk[32],
                     const uint8_t *msg, size_t msg_len,
                     uint8_t sig_out[64],
                     int generator_idx)
{
    ensure_fixed_generators();

    /* T = random 80 bytes — fed straight into BLAKE2b for the
     * deterministic-style RedJubjub nonce; an all-zero T from a failed
     * RNG would make r predictable and leak the signing key. */
    uint8_t T[80];
    if (!redjubjub_nonce_bytes(T, sizeof(T), "redjubjub_T")) {
        memory_cleanse(T, sizeof(T));
        return false;
    }

    /* r = H*(T || vk || msg) where vk = sk * G */
    struct jub_point vk_point;
    jub_scalar_mul(&vk_point, &fixed_generators[generator_idx], sk);
    uint8_t vk_bytes[32];
    jub_to_bytes(vk_bytes, &vk_point);

    /* r = to_scalar(BLAKE2b-512("Zcash_RedJubjubH", T || vk_bytes || msg)) */
    static const uint8_t personal[16] = {'Z','c','a','s','h','_','R','e','d','J','u','b','j','u','b','H'};
    uint8_t digest[64] = {0};
    struct blake2b_ctx bctx;
    blake2b_init_salt_personal(&bctx, 64, NULL, 0, NULL, personal);
    blake2b_update(&bctx, T, sizeof(T));
    blake2b_update(&bctx, vk_bytes, 32);
    blake2b_update(&bctx, msg, msg_len);
    blake2b_final(&bctx, digest, 64);
    /* bctx absorbed T (nonce seed) || vk || msg — cleanse the spent context */
    memory_cleanse(&bctx, sizeof(bctx));

    uint8_t r_scalar[32];
    jubjub_to_scalar(digest, r_scalar);
    /* digest held BLAKE2b-512(T(nonce seed) || vk || msg); last read above —
     * cleanse to keep intermediate nonce material from leaking */
    memory_cleanse(digest, sizeof(digest));

    /* R = r * G */
    struct jub_point R_point;
    jub_scalar_mul(&R_point, &fixed_generators[generator_idx], r_scalar);
    uint8_t Rbar[32];
    jub_to_bytes(Rbar, &R_point);

    /* c = H*(Rbar || vk_bytes || msg) per Zcash spec §5.4.7 */
    uint8_t c_scalar[32];
    h_star(Rbar, 32, vk_bytes, 32, msg, msg_len, c_scalar);

    /* S = r + c * sk (mod Fs) */
    struct fs r_fs, c_fs, sk_fs, product, S_fs;
    fs_from_bytes(&r_fs, r_scalar);
    fs_from_bytes(&c_fs, c_scalar);
    fs_from_bytes(&sk_fs, sk);
    fs_mul(&product, &c_fs, &sk_fs);
    fs_add(&S_fs, &r_fs, &product);

    uint8_t Sbar[32];
    fs_to_bytes(Sbar, &S_fs);

    memcpy(sig_out, Rbar, 32);
    memcpy(sig_out + 32, Sbar, 32);

    /* Cleanse secret intermediates */
    memory_cleanse(T, sizeof(T));
    memory_cleanse(r_scalar, sizeof(r_scalar));
    memory_cleanse(c_scalar, sizeof(c_scalar));
    memory_cleanse(&r_fs, sizeof(r_fs));
    memory_cleanse(&c_fs, sizeof(c_fs));
    memory_cleanse(&sk_fs, sizeof(sk_fs));
    memory_cleanse(&product, sizeof(product));
    memory_cleanse(&S_fs, sizeof(S_fs));

    return true;
}

/* --- Value commitment --- */

bool sapling_value_commit(uint64_t value, const uint8_t rcv[32],
                           uint8_t cv_out[32])
{
    ensure_fixed_generators();

    /* cv = value * G_v + rcv * G_rcv */
    uint8_t val_scalar[32] = {0};
    for (int i = 0; i < 8; i++)
        val_scalar[i] = (uint8_t)(value >> (i * 8));

    struct jub_point val_pt, rcv_pt, cv_pt;
    jub_scalar_mul(&val_pt, &fixed_generators[GEN_VALUE_COMMITMENT_VALUE], val_scalar);
    jub_scalar_mul(&rcv_pt, &fixed_generators[GEN_VALUE_COMMITMENT_RANDOMNESS], rcv);
    jub_add(&cv_pt, &val_pt, &rcv_pt);
    jub_to_bytes(cv_out, &cv_pt);
    return true;
}

/* True when any of rcm, rcv, esk could not be drawn. */
static bool sapling_output_scalars_draw_failed(uint8_t rcm[32], uint8_t rcv[32],
                                               uint8_t esk[32])
{
    /* Generate random scalars */
    return !sapling_generate_r(rcm) || !sapling_generate_r(rcv) ||
        !sapling_generate_r(esk);
}

/* 3. Build note plaintext: d(11) + value(8) + rcm(32) + memo(512) = 563 bytes
 * With leading byte 0x01 (Sapling) = 564 bytes */
static void sapling_fill_note_plaintext(uint8_t plaintext[564],
                                        const uint8_t to_d[11],
                                        uint64_t value, const uint8_t rcm[32],
                                        const uint8_t memo[512])
{
    plaintext[0] = 0x01; /* Sapling note type */
    memcpy(plaintext + 1, to_d, 11);
    for (int i = 0; i < 8; i++)
        plaintext[12 + i] = (uint8_t)(value >> (i * 8));
    memcpy(plaintext + 20, rcm, 32);
    if (memo)
        memcpy(plaintext + 52, memo, 512);
    else
        memset(plaintext + 52, 0xF6, 512);
}

/* Call the output prover when a proving key is loaded; zero od_proof otherwise.
 * Returns false when proving fails. */
static bool sapling_fill_output_proof(
    uint64_t value,
    const uint8_t to_d[11], const uint8_t to_pk_d[32],
    const uint8_t rcm[32], const uint8_t esk[32], const uint8_t rcv[32],
    const uint8_t od_cv[32], const uint8_t od_epk[32], const uint8_t od_cm[32],
    struct sapling_output_witness *wit,
    uint8_t od_proof[192], size_t *pk_len_out, bool *proved)
{
    memset(wit, 0, sizeof(*wit));
    *pk_len_out = 0;
    *proved = false;

    /* Generate Groth16 output proof */
    size_t pk_len = 0;
    const uint8_t *pk_data = sapling_get_output_pk(&pk_len);
    *pk_len_out = pk_len;
    if (pk_data && pk_len > 0) {
        memset(wit, 0, sizeof(*wit));
        wit->value = value;
        memcpy(wit->diversifier, to_d, 11);
        memcpy(wit->pk_d, to_pk_d, 32);
        memcpy(wit->rcm, rcm, 32);
        memcpy(wit->esk, esk, 32);
        memcpy(wit->rcv, rcv, 32);

        struct sapling_output_inputs pub;
        memcpy(pub.cv, od_cv, 32);
        memcpy(pub.epk, od_epk, 32);
        memcpy(pub.cm, od_cm, 32);

        *proved = sapling_create_output_proof(pk_data, pk_len, wit, &pub, od_proof);
        return *proved;
    } else {
        memset(od_proof, 0, 192);
    }
    return true;
}

/* Return rcv for binding signature accumulation */
static void sapling_store_rcv_out(uint8_t *rcv_out, const uint8_t rcv[32])
{
    if (rcv_out)
        memcpy(rcv_out, rcv, 32);
}

/* --- Build output description --- */

bool sapling_build_output_description(
    const uint8_t ovk[32],
    const uint8_t to_d[11], const uint8_t to_pk_d[32],
    uint64_t value, const uint8_t memo[512],
    uint8_t od_cv[32], uint8_t od_cm[32], uint8_t od_epk[32],
    uint8_t od_enc[580], uint8_t od_out[80], uint8_t od_proof[192],
    uint8_t rcv_out[32])
{
    uint8_t rcm[32], rcv[32], esk[32];
    if (sapling_output_scalars_draw_failed(rcm, rcv, esk))
        LOG_FAIL("sapling", "build_output_description: sapling_generate_r failed (RNG hygiene)");

    /* Compute note commitment: cm */
    if (!sapling_compute_cm(to_d, to_pk_d, value, rcm, od_cm))
        LOG_FAIL("sapling", "build_output_description: sapling_compute_cm failed");

    /* Compute value commitment: cv = value*G_v + rcv*G_rcv */
    if (!sapling_value_commit(value, rcv, od_cv))
        LOG_FAIL("sapling", "build_output_description: sapling_value_commit failed (value=%" PRIu64 ")",
                 value);

    /* Compute ephemeral public key: epk = esk * g_d(diversifier) */
    if (!sapling_ka_derivepublic(to_d, esk, od_epk))
        LOG_FAIL("sapling", "build_output_description: sapling_ka_derivepublic failed");

    /* Encrypt note for recipient */
    /* 1. DH agreement: dhsecret = esk * pk_d */
    uint8_t dhsecret[32];
    if (!sapling_ka_agree(to_pk_d, esk, dhsecret))
        LOG_FAIL("sapling", "build_output_description: sapling_ka_agree failed");

    /* 2. KDF: key = BLAKE2b("Zcash_SaplingKDF", dhsecret || epk) */
    uint8_t enc_key[32];
    if (!sapling_kdf(enc_key, dhsecret, od_epk))
        LOG_FAIL("sapling", "build_output_description: sapling_kdf failed");

    uint8_t plaintext[564];
    sapling_fill_note_plaintext(plaintext, to_d, value, rcm, memo);

    /* 4. Encrypt: enc_ciphertext = AEAD(key, plaintext) → 580 bytes */
    if (!sapling_note_encrypt(enc_key, plaintext, 564, od_enc))
        LOG_FAIL("sapling", "build_output_description: sapling_note_encrypt failed");

    /* Encrypt outgoing plaintext (for sender recovery via ovk) */
    /* 1. Outgoing plaintext: pk_d(32) + esk(32) = 64 bytes */
    uint8_t out_plaintext[64];
    memcpy(out_plaintext, to_pk_d, 32);
    memcpy(out_plaintext + 32, esk, 32);

    /* 2. OCK: ock = PRF(ovk || cv || cm || epk) */
    uint8_t ock[32];
    if (!sapling_prf_ock(ock, ovk, od_cv, od_cm, od_epk))
        LOG_FAIL("sapling", "build_output_description: sapling_prf_ock failed");

    /* 3. Encrypt outgoing: out_ciphertext = AEAD(ock, out_plaintext) → 80 bytes */
    if (!sapling_out_encrypt(ock, out_plaintext, 64, od_out))
        LOG_FAIL("sapling", "build_output_description: sapling_out_encrypt failed");

    struct sapling_output_witness wit;
    size_t pk_len = 0;
    bool proved = false;
    if (!sapling_fill_output_proof(value, to_d, to_pk_d, rcm, esk, rcv,
                                   od_cv, od_epk, od_cm, &wit, od_proof,
                                   &pk_len, &proved)) {
        memset(plaintext, 0, 564);
        memset(rcm, 0, 32);
        memset(rcv, 0, 32);
        memset(esk, 0, 32);
        LOG_FAIL("sapling",
                 "build_output_description: sapling_create_output_proof failed (pk_len=%zu)",
                 pk_len);
    }
    if (proved)
        memory_cleanse(&wit, sizeof(wit));

    sapling_store_rcv_out(rcv_out, rcv);

    /* Cleanse secrets */
    memset(plaintext, 0, 564);
    memset(rcm, 0, 32);
    memset(rcv, 0, 32);
    memset(esk, 0, 32);
    memset(dhsecret, 0, 32);
    memset(enc_key, 0, 32);
    memset(out_plaintext, 0, 64);
    memset(ock, 0, 32);

    return true;
}

/* --- canonical prover-backed spend description builder --- */

bool sapling_build_spend_with_ctx(
    void *proving_ctx,
    const uint8_t ask[32], const uint8_t nsk[32],
    const uint8_t diversifier[11], const uint8_t pk_d[32],
    const uint8_t rcm[32], uint64_t value, uint64_t position,
    const uint8_t anchor[32],
    const uint8_t *witness_path, size_t witness_len,
    uint8_t sd_cv[32], uint8_t sd_nullifier[32],
    uint8_t sd_rk[32], uint8_t sd_zkproof[192],
    uint8_t ar_out[32])
{
    /* Generate randomness ar for re-randomized verification key */
    if (!sapling_generate_r(ar_out))
        LOG_FAIL("sapling", "build_spend_with_ctx: sapling_generate_r(ar) failed (RNG hygiene)");

    /* Derive ak and nk from ask and nsk */
    uint8_t ak[32], nk[32];
    sapling_ask_to_ak(ask, ak);
    sapling_nsk_to_nk(nsk, nk);

    /* Compute nullifier */
    if (!sapling_compute_nf(diversifier, pk_d, value, rcm,
                             ak, nk, position, sd_nullifier)) {
        memory_cleanse(ak, sizeof(ak));
        memory_cleanse(nk, sizeof(nk));
        LOG_FAIL("sapling", "build_spend_with_ctx: sapling_compute_nf failed");
    }

    /* Call the pinned canonical prover for spend proof (cv, rk, zkproof). The
     * `witness_len` passed through here gates the merkle-path parse
     * in zclassic_sapling_spend_proof. */
    if (!zclassic_sapling_spend_proof(
            proving_ctx, ak, nsk, diversifier, rcm, ar_out,
            value, anchor, witness_path, witness_len,
            sd_cv, sd_rk, sd_zkproof)) {
        memset(ar_out, 0, 32);
        memory_cleanse(ak, sizeof(ak));
        memory_cleanse(nk, sizeof(nk));
        LOG_FAIL("sapling",
                 "build_spend_with_ctx: zclassic_sapling_spend_proof failed (value=%" PRIu64 " position=%" PRIu64 ")",
                 value, position);
    }

    /* Derived ak/nk fully consumed by the prover — cleanse before return */
    memory_cleanse(ak, sizeof(ak));
    memory_cleanse(nk, sizeof(nk));
    return true;
}

/* --- canonical prover-backed output description builder --- */

bool sapling_build_output_with_ctx(
    void *proving_ctx,
    const uint8_t ovk[32],
    const uint8_t to_d[11], const uint8_t to_pk_d[32],
    uint64_t value, const uint8_t memo[512],
    uint8_t od_cv[32], uint8_t od_cm[32], uint8_t od_epk[32],
    uint8_t od_enc[580], uint8_t od_out[80], uint8_t od_proof[192])
{
    /* Generate random scalars */
    uint8_t rcm[32], esk[32];
    if (!sapling_generate_r(rcm) || !sapling_generate_r(esk))
        LOG_FAIL("sapling", "build_output_with_ctx: sapling_generate_r failed (RNG hygiene)");

    /* The pinned canonical prover generates cv and zkproof with internal rcv. */
    if (!zclassic_sapling_output_proof(proving_ctx, esk, to_d, to_pk_d,
                                            rcm, value, od_cv, od_proof)) {
        memset(rcm, 0, 32);
        memset(esk, 0, 32);
        LOG_FAIL("sapling",
                 "build_output_with_ctx: zclassic_sapling_output_proof failed (value=%" PRIu64 ")",
                 value);
    }

    /* Compute note commitment: cm (our C23 implementation) */
    if (!sapling_compute_cm(to_d, to_pk_d, value, rcm, od_cm)) {
        memset(rcm, 0, 32);
        memset(esk, 0, 32);
        LOG_FAIL("sapling", "build_output_with_ctx: sapling_compute_cm failed");
    }

    /* Compute ephemeral public key: epk = esk * g_d(diversifier) */
    if (!sapling_ka_derivepublic(to_d, esk, od_epk)) {
        memset(rcm, 0, 32);
        memset(esk, 0, 32);
        LOG_FAIL("sapling", "build_output_with_ctx: sapling_ka_derivepublic failed");
    }

    /* Encrypt note for recipient */
    uint8_t dhsecret[32];
    if (!sapling_ka_agree(to_pk_d, esk, dhsecret)) {
        memset(rcm, 0, 32);
        memset(esk, 0, 32);
        LOG_FAIL("sapling", "build_output_with_ctx: sapling_ka_agree failed");
    }

    uint8_t enc_key[32];
    if (!sapling_kdf(enc_key, dhsecret, od_epk)) {
        memset(rcm, 0, 32);
        memset(esk, 0, 32);
        memset(dhsecret, 0, 32);
        LOG_FAIL("sapling", "build_output_with_ctx: sapling_kdf failed");
    }

    /* Build note plaintext */
    uint8_t plaintext[564];
    plaintext[0] = 0x01;
    memcpy(plaintext + 1, to_d, 11);
    for (int i = 0; i < 8; i++)
        plaintext[12 + i] = (uint8_t)(value >> (i * 8));
    memcpy(plaintext + 20, rcm, 32);
    if (memo)
        memcpy(plaintext + 52, memo, 512);
    else
        memset(plaintext + 52, 0xF6, 512);

    if (!sapling_note_encrypt(enc_key, plaintext, 564, od_enc)) {
        memset(rcm, 0, 32);
        memset(esk, 0, 32);
        memset(plaintext, 0, 564);
        LOG_FAIL("sapling", "build_output_with_ctx: sapling_note_encrypt failed");
    }

    /* Encrypt outgoing plaintext */
    uint8_t out_plaintext[64];
    memcpy(out_plaintext, to_pk_d, 32);
    memcpy(out_plaintext + 32, esk, 32);

    uint8_t ock[32];
    if (!sapling_prf_ock(ock, ovk, od_cv, od_cm, od_epk)) {
        memset(rcm, 0, 32);
        memset(esk, 0, 32);
        memset(plaintext, 0, 564);
        LOG_FAIL("sapling", "build_output_with_ctx: sapling_prf_ock failed");
    }

    if (!sapling_out_encrypt(ock, out_plaintext, 64, od_out)) {
        memset(rcm, 0, 32);
        memset(esk, 0, 32);
        memset(plaintext, 0, 564);
        LOG_FAIL("sapling", "build_output_with_ctx: sapling_out_encrypt failed");
    }

    /* Cleanse secrets */
    memset(plaintext, 0, 564);
    memset(rcm, 0, 32);
    memset(esk, 0, 32);
    memset(dhsecret, 0, 32);
    memset(enc_key, 0, 32);
    memset(out_plaintext, 0, 64);
    memset(ock, 0, 32);

    return true;
}

/* --- Binding signature generation --- */

bool sapling_create_binding_sig(const uint8_t bsk[32],
                                 const uint8_t sighash[32],
                                 uint8_t binding_sig_out[64])
{
    ensure_fixed_generators();

    /* Sign sighash with bsk using ValueCommitmentRandomness generator */
    return redjubjub_sign(bsk, sighash, 32, binding_sig_out,
                           GEN_VALUE_COMMITMENT_RANDOMNESS);
}
