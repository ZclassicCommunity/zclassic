/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * golden_replay: replay the src/test/data/c23_golden goldens against any library
 * that exports the librustzcash_* C ABI (the Rust librustzcash.a, or the C23
 * replacement). Plain C, no JSON. See FORMAT.md for the file format.
 *
 *   golden_replay --dir <c23_golden> --params <zcash params dir> [--prove] [--file <name>]
 *
 * Deterministic records must match byte for byte. Records whose verdict is
 * ABORT run in a forked child that must die from a signal. Nondeterministic
 * functions are checked by property (FORMAT.md). --prove re-runs the Sapling
 * and Sprout provers (slow); without it, proving records only have their
 * recorded outputs re-verified.
 *
 * Exit status: 0 all records match, 1 mismatches, 2 usage or I/O error.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* The librustzcash.h header is C++-only (unguarded extern "C"); these are the
 * same declarations for C (codeunit is uint8_t on non-Windows). */
typedef uint8_t codeunit;
void librustzcash_to_scalar(const unsigned char *input, unsigned char *result);
void librustzcash_ask_to_ak(const unsigned char *ask, unsigned char *result);
void librustzcash_nsk_to_nk(const unsigned char *nsk, unsigned char *result);
void librustzcash_crh_ivk(const unsigned char *ak, const unsigned char *nk, unsigned char *result);
bool librustzcash_check_diversifier(const unsigned char *diversifier);
bool librustzcash_ivk_to_pkd(const unsigned char *ivk, const unsigned char *diversifier, unsigned char *result);
void librustzcash_init_zksnark_params(const codeunit *spend_path, size_t spend_path_len, const char *spend_hash,
                                      const codeunit *output_path, size_t output_path_len, const char *output_hash,
                                      const codeunit *sprout_path, size_t sprout_path_len, const char *sprout_hash);
void librustzcash_tree_uncommitted(unsigned char *result);
void librustzcash_merkle_hash(size_t depth, const unsigned char *a, const unsigned char *b, unsigned char *result);
bool librustzcash_sapling_spend_sig(const unsigned char *ask, const unsigned char *ar, const unsigned char *sighash,
                                    unsigned char *result);
void *librustzcash_sapling_proving_ctx_init(void);
bool librustzcash_sapling_spend_proof(void *ctx, const unsigned char *ak, const unsigned char *nsk,
                                      const unsigned char *diversifier, const unsigned char *rcm,
                                      const unsigned char *ar, const uint64_t value, const unsigned char *anchor,
                                      const unsigned char *witness, unsigned char *cv, unsigned char *rk,
                                      unsigned char *zkproof);
bool librustzcash_sapling_output_proof(void *ctx, const unsigned char *esk, const unsigned char *diversifier,
                                       const unsigned char *pk_d, const unsigned char *rcm, const uint64_t value,
                                       unsigned char *cv, unsigned char *zkproof);
bool librustzcash_sapling_binding_sig(const void *ctx, int64_t valueBalance, const unsigned char *sighash,
                                      unsigned char *result);
void librustzcash_sapling_proving_ctx_free(void *);
void *librustzcash_sapling_verification_ctx_init(void);
bool librustzcash_sapling_check_spend(void *ctx, const unsigned char *cv, const unsigned char *anchor,
                                      const unsigned char *nullifier, const unsigned char *rk,
                                      const unsigned char *zkproof, const unsigned char *spendAuthSig,
                                      const unsigned char *sighashValue);
bool librustzcash_sapling_check_output(void *ctx, const unsigned char *cv, const unsigned char *cm,
                                       const unsigned char *ephemeralKey, const unsigned char *zkproof);
bool librustzcash_sapling_final_check(void *ctx, int64_t valueBalance, const unsigned char *bindingSig,
                                      const unsigned char *sighashValue);
void librustzcash_sapling_verification_ctx_free(void *);
bool librustzcash_sapling_compute_nf(const unsigned char *diversifier, const unsigned char *pk_d, const uint64_t value,
                                     const unsigned char *r, const unsigned char *ak, const unsigned char *nk,
                                     const uint64_t position, unsigned char *result);
bool librustzcash_sapling_compute_cm(const unsigned char *diversifier, const unsigned char *pk_d, const uint64_t value,
                                     const unsigned char *r, unsigned char *result);
bool librustzcash_sapling_ka_agree(const unsigned char *p, const unsigned char *sk, unsigned char *result);
bool librustzcash_sapling_ka_derivepublic(const unsigned char *diversifier, const unsigned char *esk,
                                          unsigned char *result);
void librustzcash_sapling_generate_r(unsigned char *result);
void librustzcash_sprout_prove(unsigned char *proof_out, const unsigned char *phi, const unsigned char *rt,
                               const unsigned char *h_sig, const unsigned char *in_sk1, uint64_t in_value1,
                               const unsigned char *in_rho1, const unsigned char *in_r1, const unsigned char *in_auth1,
                               const unsigned char *in_sk2, uint64_t in_value2, const unsigned char *in_rho2,
                               const unsigned char *in_r2, const unsigned char *in_auth2, const unsigned char *out_pk1,
                               uint64_t out_value1, const unsigned char *out_r1, const unsigned char *out_pk2,
                               uint64_t out_value2, const unsigned char *out_r2, uint64_t vpub_old, uint64_t vpub_new);
bool librustzcash_sprout_verify(const unsigned char *proof, const unsigned char *rt, const unsigned char *h_sig,
                                const unsigned char *mac1, const unsigned char *mac2, const unsigned char *nf1,
                                const unsigned char *nf2, const unsigned char *cm1, const unsigned char *cm2,
                                uint64_t vpub_old, uint64_t vpub_new);
void librustzcash_zip32_xsk_master(const unsigned char *seed, size_t seedlen, unsigned char *xsk_master);
void librustzcash_zip32_xsk_derive(const unsigned char *xsk_parent, uint32_t i, unsigned char *xsk_i);
bool librustzcash_zip32_xfvk_derive(const unsigned char *xfvk_parent, uint32_t i, unsigned char *xfvk_i);
bool librustzcash_zip32_xfvk_address(const unsigned char *xfvk, const unsigned char *j, unsigned char *j_ret,
                                     unsigned char *addr_ret);

#define MAXTOK 64
typedef struct {
    char *t[MAXTOK];
    int n;
    unsigned long lineno;
    char *base; /* owned copy of the line, NULL if none */
} Toks;

static const char *g_file = "";
static unsigned long g_records, g_mismatch, g_skipped;
static bool g_prove;
static const char *g_params = NULL;

static void fail(const Toks *k, const char *what)
{
    g_mismatch++;
    if (g_mismatch <= 50)
        fprintf(stderr, "MISMATCH %s:%lu (%s) %s\n", g_file, k->lineno, k->n > 2 ? k->t[2] : "?", what);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
/* Decode exactly n bytes; aborts the run on malformed data (a corrupt golden). */
static void hexn(const Toks *k, int i, unsigned char *out, size_t n)
{
    if (i >= k->n) {
        fprintf(stderr, "%s:%lu: missing field %d\n", g_file, k->lineno, i);
        exit(2);
    }
    const char *s = k->t[i];
    if (strlen(s) != 2 * n) {
        fprintf(stderr, "%s:%lu: field %d has %zu hex chars, want %zu\n", g_file, k->lineno, i, strlen(s), 2 * n);
        exit(2);
    }
    for (size_t j = 0; j < n; j++) {
        int h = hexval(s[2 * j]), l = hexval(s[2 * j + 1]);
        if (h < 0 || l < 0) {
            fprintf(stderr, "%s:%lu: bad hex in field %d\n", g_file, k->lineno, i);
            exit(2);
        }
        out[j] = (unsigned char)(h * 16 + l);
    }
}
static uint64_t u64f(const Toks *k, int i)
{
    if (i >= k->n) {
        fprintf(stderr, "%s:%lu: missing field %d\n", g_file, k->lineno, i);
        exit(2);
    }
    errno = 0;
    char *e = NULL;
    unsigned long long v = strtoull(k->t[i], &e, 10);
    if (errno || !e || *e) {
        fprintf(stderr, "%s:%lu: bad integer field %d\n", g_file, k->lineno, i);
        exit(2);
    }
    return (uint64_t)v;
}
static int64_t i64f(const Toks *k, int i)
{
    errno = 0;
    char *e = NULL;
    long long v = strtoll(k->t[i], &e, 10);
    if (errno || !e || *e) {
        fprintf(stderr, "%s:%lu: bad integer field %d\n", g_file, k->lineno, i);
        exit(2);
    }
    return (int64_t)v;
}
static bool eqhex(const Toks *k, int i, const unsigned char *b, size_t n)
{
    static const char *d = "0123456789abcdef";
    const char *s = k->t[i];
    if (strlen(s) != 2 * n) return false;
    for (size_t j = 0; j < n; j++)
        if (s[2 * j] != d[b[j] >> 4] || s[2 * j + 1] != d[b[j] & 15]) return false;
    return true;
}
static bool is(const Toks *k, int i, const char *s) { return i < k->n && strcmp(k->t[i], s) == 0; }
static const char *tf(bool b) { return b ? "T" : "F"; }

/* Expect the child to die from a signal (Rust panic=abort). */
typedef void (*abort_fn)(const Toks *);
static void expect_abort(const Toks *k, abort_fn fn)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, 2);
        fn(k);
        _exit(0);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0)
        if (errno != EINTR) {
            perror("waitpid");
            exit(2);
        }
    if (!WIFSIGNALED(st)) fail(k, "expected ABORT, call returned");
}

/* ---- per-function replays; t[0]="C", t[1]=id, t[2]=label, inputs from t[3] ---- */

static void ab_to_scalar(const Toks *k)
{
    unsigned char in[64], o[32];
    hexn(k, 3, in, 64);
    librustzcash_to_scalar(in, o);
}
static void r_to_scalar(const Toks *k)
{
    if (is(k, 4, "ABORT")) return expect_abort(k, ab_to_scalar);
    unsigned char in[64], o[32];
    hexn(k, 3, in, 64);
    librustzcash_to_scalar(in, o);
    if (!is(k, 4, "OK") || !eqhex(k, 5, o, 32)) fail(k, "to_scalar");
}
static void r_ask_to_ak(const Toks *k)
{
    unsigned char in[32], o[32];
    hexn(k, 3, in, 32);
    librustzcash_ask_to_ak(in, o);
    if (!is(k, 4, "OK") || !eqhex(k, 5, o, 32)) fail(k, "ask_to_ak");
}
static void r_nsk_to_nk(const Toks *k)
{
    unsigned char in[32], o[32];
    hexn(k, 3, in, 32);
    librustzcash_nsk_to_nk(in, o);
    if (!is(k, 4, "OK") || !eqhex(k, 5, o, 32)) fail(k, "nsk_to_nk");
}
static void r_crh_ivk(const Toks *k)
{
    unsigned char a[32], n[32], o[32];
    hexn(k, 3, a, 32);
    hexn(k, 4, n, 32);
    librustzcash_crh_ivk(a, n, o);
    if (!is(k, 5, "OK") || !eqhex(k, 6, o, 32)) fail(k, "crh_ivk");
}
static void r_check_diversifier(const Toks *k)
{
    unsigned char d[11];
    hexn(k, 3, d, 11);
    if (!is(k, 4, tf(librustzcash_check_diversifier(d)))) fail(k, "check_diversifier");
}
static void r_ivk_to_pkd(const Toks *k)
{
    unsigned char ivk[32], d[11], o[32];
    hexn(k, 3, ivk, 32);
    hexn(k, 4, d, 11);
    bool ok = librustzcash_ivk_to_pkd(ivk, d, o);
    if (!is(k, 5, tf(ok)) || (ok && !eqhex(k, 6, o, 32))) fail(k, "ivk_to_pkd");
}
static void r_tree_uncommitted(const Toks *k)
{
    unsigned char o[32];
    librustzcash_tree_uncommitted(o);
    if (!is(k, 3, "OK") || !eqhex(k, 4, o, 32)) fail(k, "tree_uncommitted");
}
static void ab_merkle(const Toks *k)
{
    unsigned char a[32], b[32], o[32];
    hexn(k, 4, a, 32);
    hexn(k, 5, b, 32);
    librustzcash_merkle_hash((size_t)u64f(k, 3), a, b, o);
}
static void r_merkle_hash(const Toks *k)
{
    if (is(k, 6, "ABORT")) return expect_abort(k, ab_merkle);
    unsigned char a[32], b[32], o[32];
    hexn(k, 4, a, 32);
    hexn(k, 5, b, 32);
    librustzcash_merkle_hash((size_t)u64f(k, 3), a, b, o);
    if (!is(k, 6, "OK") || !eqhex(k, 7, o, 32)) fail(k, "merkle_hash");
}
static void r_compute_cm(const Toks *k)
{
    unsigned char d[11], p[32], r[32], o[32];
    hexn(k, 3, d, 11);
    hexn(k, 4, p, 32);
    hexn(k, 6, r, 32);
    bool ok = librustzcash_sapling_compute_cm(d, p, u64f(k, 5), r, o);
    if (!is(k, 7, tf(ok)) || (ok && !eqhex(k, 8, o, 32))) fail(k, "compute_cm");
}
static void r_compute_nf(const Toks *k)
{
    unsigned char d[11], p[32], r[32], ak[32], nk[32], o[32];
    hexn(k, 3, d, 11);
    hexn(k, 4, p, 32);
    hexn(k, 6, r, 32);
    hexn(k, 7, ak, 32);
    hexn(k, 8, nk, 32);
    bool ok = librustzcash_sapling_compute_nf(d, p, u64f(k, 5), r, ak, nk, u64f(k, 9), o);
    if (!is(k, 10, tf(ok)) || (ok && !eqhex(k, 11, o, 32))) fail(k, "compute_nf");
}
static void r_ka_agree(const Toks *k)
{
    unsigned char p[32], s[32], o[32];
    hexn(k, 3, p, 32);
    hexn(k, 4, s, 32);
    bool ok = librustzcash_sapling_ka_agree(p, s, o);
    if (!is(k, 5, tf(ok)) || (ok && !eqhex(k, 6, o, 32))) fail(k, "ka_agree");
}
static void r_ka_derivepublic(const Toks *k)
{
    unsigned char d[11], s[32], o[32];
    hexn(k, 3, d, 11);
    hexn(k, 4, s, 32);
    bool ok = librustzcash_sapling_ka_derivepublic(d, s, o);
    if (!is(k, 5, tf(ok)) || (ok && !eqhex(k, 6, o, 32))) fail(k, "ka_derivepublic");
}
/* Jubjub r, little-endian, for the generate_r range property. */
static const unsigned char JUBJUB_R_LE[32] = {
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e};
static bool lt_r(const unsigned char *x)
{
    for (int i = 31; i >= 0; i--) {
        if (x[i] < JUBJUB_R_LE[i]) return true;
        if (x[i] > JUBJUB_R_LE[i]) return false;
    }
    return false;
}
static void r_generate_r(const Toks *k)
{
    unsigned char o[32], rec[32];
    librustzcash_sapling_generate_r(o);
    hexn(k, 4, rec, 32);
    if (!is(k, 3, "OK") || !lt_r(o) || !lt_r(rec) || !is(k, 5, "T")) fail(k, "generate_r range");
}
static void r_spend_sig(const Toks *k)
{
    unsigned char ask[32], ar[32], sh[32], o[64];
    hexn(k, 3, ask, 32);
    hexn(k, 4, ar, 32);
    hexn(k, 5, sh, 32);
    bool ok = librustzcash_sapling_spend_sig(ask, ar, sh, o);
    if (!is(k, 6, tf(ok))) fail(k, "spend_sig verdict");
    /* The signature itself is randomized; FORMAT.md describes the verify-under-rk check,
     * which needs a RedJubjub verifier outside this ABI (left to the C23 KAT). */
}
static void r_xsk_master(const Toks *k)
{
    size_t n = (size_t)u64f(k, 3);
    unsigned char *seed = malloc(n ? n : 1), o[169];
    if (!seed) {
        perror("malloc");
        exit(2);
    }
    if (n) hexn(k, 4, seed, n);
    else if (!is(k, 4, "~")) fail(k, "empty seed must be ~");
    librustzcash_zip32_xsk_master(seed, n, o);
    free(seed);
    if (!is(k, 5, "OK") || !eqhex(k, 6, o, 169)) fail(k, "xsk_master");
}
static void ab_xsk_derive(const Toks *k)
{
    unsigned char p[169], o[169];
    hexn(k, 3, p, 169);
    librustzcash_zip32_xsk_derive(p, (uint32_t)u64f(k, 4), o);
}
static void r_xsk_derive(const Toks *k)
{
    if (is(k, 5, "ABORT")) return expect_abort(k, ab_xsk_derive);
    unsigned char p[169], o[169];
    hexn(k, 3, p, 169);
    librustzcash_zip32_xsk_derive(p, (uint32_t)u64f(k, 4), o);
    if (!is(k, 5, "OK") || !eqhex(k, 6, o, 169)) fail(k, "xsk_derive");
}
static void ab_xfvk_derive(const Toks *k)
{
    unsigned char p[169], o[169];
    hexn(k, 3, p, 169);
    (void)librustzcash_zip32_xfvk_derive(p, (uint32_t)u64f(k, 4), o);
}
static void r_xfvk_derive(const Toks *k)
{
    if (is(k, 5, "ABORT")) return expect_abort(k, ab_xfvk_derive);
    unsigned char p[169], o[169];
    hexn(k, 3, p, 169);
    bool ok = librustzcash_zip32_xfvk_derive(p, (uint32_t)u64f(k, 4), o);
    if (!is(k, 5, tf(ok)) || (ok && !eqhex(k, 6, o, 169))) fail(k, "xfvk_derive");
}
static void ab_xfvk_address(const Toks *k)
{
    unsigned char x[169], j[11], jr[11], a[43];
    hexn(k, 3, x, 169);
    hexn(k, 4, j, 11);
    (void)librustzcash_zip32_xfvk_address(x, j, jr, a);
}
static void r_xfvk_address(const Toks *k)
{
    if (is(k, 5, "ABORT")) return expect_abort(k, ab_xfvk_address);
    unsigned char x[169], j[11], jr[11], a[43];
    hexn(k, 3, x, 169);
    hexn(k, 4, j, 11);
    bool ok = librustzcash_zip32_xfvk_address(x, j, jr, a);
    if (!is(k, 5, tf(ok)) || (ok && (!eqhex(k, 6, jr, 11) || !eqhex(k, 7, a, 43)))) fail(k, "xfvk_address");
}
static void init_from(const Toks *k)
{
    char s[4096], o[4096], g[4096];
    if (snprintf(s, sizeof s, "%s/%s", g_params, k->t[3]) >= (int)sizeof s ||
        snprintf(o, sizeof o, "%s/%s", g_params, k->t[5]) >= (int)sizeof o ||
        snprintf(g, sizeof g, "%s/%s", g_params, k->t[7]) >= (int)sizeof g) {
        fprintf(stderr, "path too long\n");
        exit(2);
    }
    librustzcash_init_zksnark_params((const codeunit *)s, strlen(s), k->t[4], (const codeunit *)o, strlen(o), k->t[6],
                                     (const codeunit *)g, strlen(g), k->t[8]);
}
static void r_init_params(const Toks *k)
{
    if (is(k, 9, "ABORT")) return expect_abort(k, init_from);
    if (!is(k, 9, "OK")) fail(k, "init verdict");
    /* The OK case is the canonical init, already done by main(). */
}
static void r_ctx_trivial(const Toks *k)
{
    (void)k; /* lifecycle covered by every proving / verification record */
}

static bool v_spend(void *ctx, const Toks *k, int i)
{
    unsigned char cv[32], an[32], nf[32], rk[32], pr[192], sig[64], sh[32];
    hexn(k, i, cv, 32);
    hexn(k, i + 1, an, 32);
    hexn(k, i + 2, nf, 32);
    hexn(k, i + 3, rk, 32);
    hexn(k, i + 4, pr, 192);
    hexn(k, i + 5, sig, 64);
    hexn(k, i + 6, sh, 32);
    return librustzcash_sapling_check_spend(ctx, cv, an, nf, rk, pr, sig, sh);
}
static bool v_output(void *ctx, const Toks *k, int i)
{
    unsigned char cv[32], cm[32], epk[32], pr[192];
    hexn(k, i, cv, 32);
    hexn(k, i + 1, cm, 32);
    hexn(k, i + 2, epk, 32);
    hexn(k, i + 3, pr, 192);
    return librustzcash_sapling_check_output(ctx, cv, cm, epk, pr);
}
static void r_check_spend(const Toks *k)
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    bool ok = v_spend(ctx, k, 3);
    librustzcash_sapling_verification_ctx_free(ctx);
    if (!is(k, 10, tf(ok))) fail(k, "check_spend");
}
static void r_check_output(const Toks *k)
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    bool ok = v_output(ctx, k, 3);
    librustzcash_sapling_verification_ctx_free(ctx);
    if (!is(k, 7, tf(ok))) fail(k, "check_output");
}
static void sprout_v(const Toks *k, int i, bool *ok)
{
    unsigned char pr[192], f[8][32];
    hexn(k, i, pr, 192);
    for (int j = 0; j < 8; j++) hexn(k, i + 1 + j, f[j], 32);
    *ok = librustzcash_sprout_verify(pr, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], u64f(k, i + 9), u64f(k, i + 10));
}
static void r_sprout_verify(const Toks *k)
{
    bool ok;
    sprout_v(k, 3, &ok);
    if (!is(k, 14, tf(ok))) fail(k, "sprout_verify");
}

/* spend_proof: inputs t[3..10]; verdict t[11]; outputs cv rk proof t[12..14];
 * derived nf sighash sig rust_check t[15..18]. */
static bool spend_proof_call(const Toks *k, unsigned char *cv, unsigned char *rk, unsigned char *pr)
{
    unsigned char ak[32], nsk[32], d[11], rcm[32], ar[32], an[32], w[1065];
    hexn(k, 3, ak, 32);
    hexn(k, 4, nsk, 32);
    hexn(k, 5, d, 11);
    hexn(k, 6, rcm, 32);
    hexn(k, 7, ar, 32);
    hexn(k, 9, an, 32);
    hexn(k, 10, w, 1065);
    void *ctx = librustzcash_sapling_proving_ctx_init();
    bool ok = librustzcash_sapling_spend_proof(ctx, ak, nsk, d, rcm, ar, u64f(k, 8), an, w, cv, rk, pr);
    librustzcash_sapling_proving_ctx_free(ctx);
    return ok;
}
static void ab_spend_proof(const Toks *k)
{
    unsigned char cv[32], rk[32], pr[192];
    (void)spend_proof_call(k, cv, rk, pr);
}
static void r_spend_proof(const Toks *k)
{
    if (is(k, 11, "ABORT")) return expect_abort(k, ab_spend_proof);
    bool reaches_prover = strncmp(k->t[2], "valid:", 6) == 0 || strncmp(k->t[2], "prove:", 6) == 0 ||
                          is(k, 11, "T");
    if (!reaches_prover || g_prove) {
        unsigned char cv[32], rk[32], pr[192];
        bool ok = spend_proof_call(k, cv, rk, pr);
        if (!is(k, 11, tf(ok))) fail(k, "spend_proof verdict");
    } else {
        g_skipped++;
    }
    if (is(k, 11, "T") && !is(k, 17, "-")) {
        /* Re-verify the Rust-made proof with the derived nf/sighash/sig. */
        unsigned char cv[32], an[32], nf[32], rk[32], pr[192], sig[64], sh[32];
        hexn(k, 12, cv, 32);
        hexn(k, 9, an, 32);
        hexn(k, 15, nf, 32);
        hexn(k, 13, rk, 32);
        hexn(k, 14, pr, 192);
        hexn(k, 17, sig, 64);
        hexn(k, 16, sh, 32);
        void *ctx = librustzcash_sapling_verification_ctx_init();
        bool v = librustzcash_sapling_check_spend(ctx, cv, an, nf, rk, pr, sig, sh);
        librustzcash_sapling_verification_ctx_free(ctx);
        if (!is(k, 18, tf(v))) fail(k, "Rust-made spend re-verify");
    }
}
/* output_proof: inputs t[3..7]; verdict t[8]; cv proof t[9..10]; derived cm epk check t[11..13]. */
static bool output_proof_call(const Toks *k, unsigned char *cv, unsigned char *pr)
{
    unsigned char esk[32], d[11], pkd[32], rcm[32];
    hexn(k, 3, esk, 32);
    hexn(k, 4, d, 11);
    hexn(k, 5, pkd, 32);
    hexn(k, 6, rcm, 32);
    void *ctx = librustzcash_sapling_proving_ctx_init();
    bool ok = librustzcash_sapling_output_proof(ctx, esk, d, pkd, rcm, u64f(k, 7), cv, pr);
    librustzcash_sapling_proving_ctx_free(ctx);
    return ok;
}
static void ab_output_proof(const Toks *k)
{
    unsigned char cv[32], pr[192];
    (void)output_proof_call(k, cv, pr);
}
static void r_output_proof(const Toks *k)
{
    if (is(k, 8, "ABORT")) return expect_abort(k, ab_output_proof);
    bool reaches_prover = strncmp(k->t[2], "valid:", 6) == 0 || strncmp(k->t[2], "prove:", 6) == 0 ||
                          is(k, 8, "T");
    if (!reaches_prover || g_prove) {
        unsigned char cv[32], pr[192];
        bool ok = output_proof_call(k, cv, pr);
        if (!is(k, 8, tf(ok))) fail(k, "output_proof verdict");
    } else {
        g_skipped++;
    }
    if (is(k, 8, "T") && !is(k, 13, "-")) {
        unsigned char cv[32], cm[32], epk[32], pr[192];
        hexn(k, 9, cv, 32);
        hexn(k, 10, pr, 192);
        hexn(k, 11, cm, 32);
        hexn(k, 12, epk, 32);
        void *ctx = librustzcash_sapling_verification_ctx_init();
        bool v = librustzcash_sapling_check_output(ctx, cv, cm, epk, pr);
        librustzcash_sapling_verification_ctx_free(ctx);
        if (!is(k, 13, tf(v))) fail(k, "Rust-made output re-verify");
    }
}
/* sprout_prove: 21 inputs t[3..23]; verdict t[24]; proof t[25]; derived t[26..31]; verify t[32]. */
static void sprout_prove_call(const Toks *k, unsigned char *proof)
{
    unsigned char phi[32], rt[32], hs[32], sk1[32], rho1[32], r1[32], a1[966], sk2[32], rho2[32], r2[32], a2[966];
    unsigned char pk1[32], or1[32], pk2[32], or2[32];
    hexn(k, 3, phi, 32);
    hexn(k, 4, rt, 32);
    hexn(k, 5, hs, 32);
    hexn(k, 6, sk1, 32);
    hexn(k, 8, rho1, 32);
    hexn(k, 9, r1, 32);
    hexn(k, 10, a1, 966);
    hexn(k, 11, sk2, 32);
    hexn(k, 13, rho2, 32);
    hexn(k, 14, r2, 32);
    hexn(k, 15, a2, 966);
    hexn(k, 16, pk1, 32);
    hexn(k, 18, or1, 32);
    hexn(k, 19, pk2, 32);
    hexn(k, 21, or2, 32);
    librustzcash_sprout_prove(proof, phi, rt, hs, sk1, u64f(k, 7), rho1, r1, a1, sk2, u64f(k, 12), rho2, r2, a2, pk1,
                              u64f(k, 17), or1, pk2, u64f(k, 20), or2, u64f(k, 22), u64f(k, 23));
}
static void ab_sprout_prove(const Toks *k)
{
    unsigned char proof[192];
    sprout_prove_call(k, proof);
}
static void r_sprout_prove(const Toks *k)
{
    if (is(k, 24, "ABORT")) return expect_abort(k, ab_sprout_prove);
    if (!is(k, 24, "OK")) fail(k, "sprout_prove verdict");
    unsigned char pr[192], rt[32], hs[32], f[6][32];
    hexn(k, 25, pr, 192);
    hexn(k, 4, rt, 32);
    hexn(k, 5, hs, 32);
    for (int j = 0; j < 6; j++) hexn(k, 26 + j, f[j], 32);
    /* derived order nf1 nf2 mac1 mac2 cm1 cm2; verify order mac1 mac2 nf1 nf2 cm1 cm2 */
    bool v = librustzcash_sprout_verify(pr, rt, hs, f[2], f[3], f[0], f[1], f[4], f[5], u64f(k, 22), u64f(k, 23));
    if (!is(k, 32, tf(v))) fail(k, "Rust-made Sprout re-verify");
    if (g_prove) {
        unsigned char np[192];
        sprout_prove_call(k, np);
        bool nv = librustzcash_sprout_verify(np, rt, hs, f[2], f[3], f[0], f[1], f[4], f[5], u64f(k, 22), u64f(k, 23));
        if (!is(k, 32, tf(nv))) fail(k, "re-proved Sprout verdict");
    } else {
        g_skipped++;
    }
}

/* ---- bundle files ---- */

typedef struct {
    Toks *lines;
    size_t n, cap;
} Bundle;

static void tok_free(Toks *k)
{
    free(k->base);
    k->base = NULL;
    k->n = 0;
}

static void replay_vbundle(Bundle *b)
{
    void *ctx = librustzcash_sapling_verification_ctx_init();
    for (size_t i = 1; i + 1 < b->n; i++) {
        Toks *k = &b->lines[i];
        bool ok;
        int vi;
        if (is(k, 0, "S")) {
            ok = v_spend(ctx, k, 1);
            vi = 8;
        } else if (is(k, 0, "O")) {
            ok = v_output(ctx, k, 1);
            vi = 5;
        } else if (is(k, 0, "F")) {
            unsigned char sig[64], sh[32];
            hexn(k, 2, sig, 64);
            hexn(k, 3, sh, 32);
            ok = librustzcash_sapling_final_check(ctx, i64f(k, 1), sig, sh);
            vi = 4;
        } else {
            fail(k, "unknown bundle line");
            continue;
        }
        if (!is(k, vi, tf(ok))) fail(k, "bundle step verdict");
    }
    librustzcash_sapling_verification_ctx_free(ctx);
}

/* Prove bundles. Recompute nf/cm/epk from the inputs to verify the new bundle. */
static void replay_pbundle(Bundle *b)
{
    if (!g_prove) {
        g_skipped++;
        return;
    }
    void *ctx = librustzcash_sapling_proving_ctx_init();
    enum { MAXD = 8 };
    unsigned char scv[MAXD][32], srk[MAXD][32], spr[MAXD][192], san[MAXD][32], snf[MAXD][32], ssig[MAXD][64];
    unsigned char ocv[MAXD][32], opr[MAXD][192], ocm[MAXD][32], oepk[MAXD][32], sh[32], bsig[64];
    int ns = 0, no = 0, nss = 0;
    bool all = true;
    int64_t vb = 0;
    const Toks *vline = NULL;
    for (size_t i = 1; i + 1 < b->n; i++) {
        Toks *k = &b->lines[i];
        if (is(k, 0, "PS") && ns < MAXD) {
            unsigned char ak[32], nsk[32], d[11], rcm[32], ar[32], w[1065], nk[32], ivk[32], pkd[32];
            hexn(k, 1, ak, 32);
            hexn(k, 2, nsk, 32);
            hexn(k, 3, d, 11);
            hexn(k, 4, rcm, 32);
            hexn(k, 5, ar, 32);
            hexn(k, 7, san[ns], 32);
            hexn(k, 8, w, 1065);
            bool ok = librustzcash_sapling_spend_proof(ctx, ak, nsk, d, rcm, ar, u64f(k, 6), san[ns], w, scv[ns], srk[ns],
                                                       spr[ns]);
            if (!is(k, 9, tf(ok))) fail(k, "PS verdict");
            all = all && ok;
            if (ok) {
                uint64_t pos = 0;
                for (int j = 0; j < 8; j++) pos |= (uint64_t)w[1057 + j] << (8 * j);
                librustzcash_nsk_to_nk(nsk, nk);
                librustzcash_crh_ivk(ak, nk, ivk);
                if (!librustzcash_ivk_to_pkd(ivk, d, pkd) ||
                    !librustzcash_sapling_compute_nf(d, pkd, u64f(k, 6), rcm, ak, nk, pos, snf[ns]))
                    fail(k, "nf recompute");
            }
            ns++;
        } else if (is(k, 0, "PO") && no < MAXD) {
            unsigned char esk[32], d[11], pkd[32], rcm[32];
            hexn(k, 1, esk, 32);
            hexn(k, 2, d, 11);
            hexn(k, 3, pkd, 32);
            hexn(k, 4, rcm, 32);
            bool ok = librustzcash_sapling_output_proof(ctx, esk, d, pkd, rcm, u64f(k, 5), ocv[no], opr[no]);
            if (!is(k, 6, tf(ok))) fail(k, "PO verdict");
            all = all && ok;
            if (ok && (!librustzcash_sapling_compute_cm(d, pkd, u64f(k, 5), rcm, ocm[no]) ||
                       !librustzcash_sapling_ka_derivepublic(d, esk, oepk[no])))
                fail(k, "cm/epk recompute");
            no++;
        } else if (is(k, 0, "SS") && nss < MAXD) {
            unsigned char ask[32], ar[32];
            hexn(k, 1, ask, 32);
            hexn(k, 2, ar, 32);
            hexn(k, 3, sh, 32);
            bool ok = librustzcash_sapling_spend_sig(ask, ar, sh, ssig[nss]);
            if (!is(k, 4, tf(ok))) fail(k, "SS verdict");
            all = all && ok;
            nss++;
        } else if (is(k, 0, "PB")) {
            vb = i64f(k, 1);
            hexn(k, 2, sh, 32);
            bool ok = librustzcash_sapling_binding_sig(ctx, vb, sh, bsig);
            if (!is(k, 3, tf(ok))) fail(k, "PB verdict");
            all = all && ok;
        } else if (is(k, 0, "V")) {
            vline = k;
        } else {
            fail(k, "unknown prove-bundle line or too many descriptions");
        }
    }
    librustzcash_sapling_proving_ctx_free(ctx);
    if (!vline) return;
    if (!all) {
        if (!is(vline, 1, "-")) fail(vline, "V should be '-' after a failed step");
        return;
    }
    void *v = librustzcash_sapling_verification_ctx_init();
    bool vok = true;
    for (int i = 0; i < ns; i++)
        vok = librustzcash_sapling_check_spend(v, scv[i], san[i], snf[i], srk[i], spr[i], ssig[i], sh) && vok;
    for (int i = 0; i < no; i++) vok = librustzcash_sapling_check_output(v, ocv[i], ocm[i], oepk[i], opr[i]) && vok;
    vok = librustzcash_sapling_final_check(v, vb, bsig, sh) && vok;
    librustzcash_sapling_verification_ctx_free(v);
    if (!is(vline, 1, tf(vok))) fail(vline, "V verdict");
}

/* ---- driver ---- */

typedef void (*rec_fn)(const Toks *);
static const struct {
    const char *file;
    rec_fn fn;
    int bundle; /* 0 single, 1 verification bundles, 2 prove bundles */
} FILES[] = {
    {"to_scalar.golden", r_to_scalar, 0},
    {"ask_to_ak.golden", r_ask_to_ak, 0},
    {"nsk_to_nk.golden", r_nsk_to_nk, 0},
    {"crh_ivk.golden", r_crh_ivk, 0},
    {"check_diversifier.golden", r_check_diversifier, 0},
    {"ivk_to_pkd.golden", r_ivk_to_pkd, 0},
    {"tree_uncommitted.golden", r_tree_uncommitted, 0},
    {"merkle_hash.golden", r_merkle_hash, 0},
    {"sapling_compute_cm.golden", r_compute_cm, 0},
    {"sapling_compute_nf.golden", r_compute_nf, 0},
    {"sapling_ka_agree.golden", r_ka_agree, 0},
    {"sapling_ka_derivepublic.golden", r_ka_derivepublic, 0},
    {"sapling_generate_r.golden", r_generate_r, 0},
    {"sapling_spend_sig.golden", r_spend_sig, 0},
    {"zip32_xsk_master.golden", r_xsk_master, 0},
    {"zip32_xsk_derive.golden", r_xsk_derive, 0},
    {"zip32_xfvk_derive.golden", r_xfvk_derive, 0},
    {"zip32_xfvk_address.golden", r_xfvk_address, 0},
    {"init_zksnark_params.golden", r_init_params, 0},
    {"sapling_proving_ctx_init.golden", r_ctx_trivial, 0},
    {"sapling_proving_ctx_free.golden", r_ctx_trivial, 0},
    {"sapling_verification_ctx_init.golden", r_ctx_trivial, 0},
    {"sapling_verification_ctx_free.golden", r_ctx_trivial, 0},
    {"sapling_spend_proof.golden", r_spend_proof, 0},
    {"sapling_output_proof.golden", r_output_proof, 0},
    {"sapling_binding_sig.golden", NULL, 2},
    {"sprout_prove.golden", r_sprout_prove, 0},
    {"sapling_check_spend.golden", r_check_spend, 0},
    {"sapling_check_output.golden", r_check_output, 0},
    {"sapling_final_check.golden", NULL, 1},
    {"sprout_verify.golden", r_sprout_verify, 0},
};

static bool tokenize(char *line, Toks *k)
{
    size_t len = strlen(line);
    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = 0;
    char *copy = strdup(line);
    if (!copy) {
        perror("strdup");
        exit(2);
    }
    k->n = 0;
    k->base = copy;
    char *save = NULL;
    for (char *p = strtok_r(copy, " ", &save); p; p = strtok_r(NULL, " ", &save)) {
        if (k->n == MAXTOK) {
            free(copy);
            k->base = NULL;
            k->n = 0;
            return false;
        }
        k->t[k->n++] = p;
    }
    if (k->n == 0) {
        free(copy);
        k->base = NULL;
    }
    return true;
}

static int replay_file(const char *dir, const char *name, rec_fn fn, int bundle)
{
    char path[4096];
    if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path) return 2;
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return 2;
    }
    g_file = name;
    unsigned long before = g_mismatch, recs = 0;
    char *line = NULL;
    size_t cap = 0;
    unsigned long lineno = 0;
    Bundle b = {NULL, 0, 0};
    while (getline(&line, &cap, f) >= 0) {
        lineno++;
        if (line[0] == '#' || line[0] == '@' || line[0] == '\n') continue;
        Toks k;
        if (!tokenize(line, &k)) {
            fprintf(stderr, "%s:%lu: too many fields\n", name, lineno);
            exit(2);
        }
        k.lineno = lineno;
        if (k.n == 0) continue;
        if (bundle == 0) {
            if (!is(&k, 0, "C")) {
                fprintf(stderr, "%s:%lu: expected C record\n", name, lineno);
                exit(2);
            }
            fn(&k);
            recs++;
            tok_free(&k);
            continue;
        }
        if (b.n == b.cap) {
            b.cap = b.cap ? 2 * b.cap : 16;
            Toks *nl = realloc(b.lines, b.cap * sizeof(Toks));
            if (!nl) {
                perror("realloc");
                exit(2);
            }
            b.lines = nl;
        }
        b.lines[b.n++] = k;
        if (is(&k, 0, "E")) {
            if (!is(&b.lines[0], 0, "B")) {
                fprintf(stderr, "%s:%lu: bundle without B\n", name, lineno);
                exit(2);
            }
            /* A bundle step recorded as ABORT or '-' cannot be replayed in-process. */
            bool has_abort = false;
            for (size_t i = 0; i < b.n; i++)
                for (int j = 0; j < b.lines[i].n; j++)
                    if (strcmp(b.lines[i].t[j], "ABORT") == 0) has_abort = true;
            if (has_abort) g_skipped++;
            else if (bundle == 1) replay_vbundle(&b);
            else replay_pbundle(&b);
            recs++;
            for (size_t i = 0; i < b.n; i++) tok_free(&b.lines[i]);
            b.n = 0;
        }
    }
    free(line);
    free(b.lines);
    if (ferror(f)) {
        fprintf(stderr, "read error on %s\n", path);
        fclose(f);
        return 2;
    }
    fclose(f);
    g_records += recs;
    printf("%-40s %7lu records %s\n", name, recs, g_mismatch == before ? "ok" : "MISMATCH");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    const char *dir = NULL, *only = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dir") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--params") && i + 1 < argc) g_params = argv[++i];
        else if (!strcmp(argv[i], "--file") && i + 1 < argc) only = argv[++i];
        else if (!strcmp(argv[i], "--prove")) g_prove = true;
        else {
            fprintf(stderr, "usage: golden_replay --dir <c23_golden> --params <dir> [--prove] [--file <name>]\n");
            return 2;
        }
    }
    if (!dir || !g_params) {
        fprintf(stderr, "usage: golden_replay --dir <c23_golden> --params <dir> [--prove] [--file <name>]\n");
        return 2;
    }
    /* Canonical init (same as src/init.cpp); a failure aborts the process. */
    Toks k = {{0}, 0, 0, NULL};
    static char sf[] = "sapling-spend.params", of[] = "sapling-output.params", gf[] = "sprout-groth16.params";
    static char sh[] = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
    static char oh[] = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
    static char gh[] = "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";
    k.t[3] = sf; k.t[4] = sh; k.t[5] = of; k.t[6] = oh; k.t[7] = gf; k.t[8] = gh;
    k.n = 9;
    init_from(&k);

    for (size_t i = 0; i < sizeof FILES / sizeof FILES[0]; i++) {
        if (only && strcmp(only, FILES[i].file) != 0) continue;
        if (replay_file(dir, FILES[i].file, FILES[i].fn, FILES[i].bundle) != 0) return 2;
    }
    printf("records %lu, mismatches %lu, skipped (proving not re-run or ABORT bundle) %lu\n", g_records, g_mismatch,
           g_skipped);
    return g_mismatch ? 1 : 0;
}
