/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * TEST-ONLY (unit U4). Shared helpers for the standalone librustzcash ABI
 * known-answer and mutation suite in src/c23/test. Nothing here is linked into
 * zclassicd.
 *
 * The programs built from this directory link EITHER the C23 shim
 * (src/c23/compat, the default) OR the Rust librustzcash.a (KAT_RUST=1, Linux
 * only, used on the build host to obtain Rust's verdicts). The ABI is declared
 * here in plain C. When the C23 header is on the include path
 * (KAT_C23_HEADER), it is included too, so any signature drift between this
 * file and the shim is a compile error (compatible redeclaration). */
#ifndef ZCL_C23_KAT_COMMON_H
#define ZCL_C23_KAT_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if defined(KAT_C23_HEADER)
#include "librustzcash.h"
#else
#if defined(WIN32) || defined(_WIN32)
typedef uint16_t codeunit;
#else
typedef uint8_t codeunit;
#endif
#endif

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

/* ---- canonical parameter hashes (src/init.cpp) ---- */
extern const char KAT_SPEND_HASH[];
extern const char KAT_OUTPUT_HASH[];
extern const char KAT_SPROUT_HASH[];

/* ---- tokenized lines ---- */
#define KAT_MAXTOK 64
typedef struct {
    char *t[KAT_MAXTOK];
    int n;
    unsigned long lineno;
    char *base; /* owned copy of the line */
} KatToks;

/* Reads one line (any length) into *buf (grown as needed). Returns false at EOF. */
bool kat_read_line(FILE *f, char **buf, size_t *cap);
/* Splits on single spaces into an owned copy. Exits 2 on too many fields. */
void kat_tokenize(const char *line, unsigned long lineno, KatToks *k);
void kat_toks_free(KatToks *k);

/* Field access; malformed data exits the program with status 2 (corrupt input). */
extern const char *kat_cur_file;
void kat_hexn(const KatToks *k, int i, unsigned char *out, size_t n);
uint64_t kat_u64(const KatToks *k, int i);
int64_t kat_i64(const KatToks *k, int i);
bool kat_eqhex(const KatToks *k, int i, const unsigned char *b, size_t n);
bool kat_is(const KatToks *k, int i, const char *s);
const char *kat_tf(bool b);
void kat_tohex(char *out, const unsigned char *b, size_t n); /* out needs 2n+1 */
bool kat_parse_hex(const char *s, unsigned char *out, size_t n);
void *kat_xmalloc(size_t n);

/* ---- params / init ---- */
/* Calls librustzcash_init_zksnark_params with <dir>/<name> paths (UTF-16 on
 * Windows). Exits 2 if a path does not fit. */
void kat_init_params(const char *dir, const char *spend_name, const char *spend_hash, const char *output_name,
                     const char *output_hash, const char *sprout_name, const char *sprout_hash);
void kat_init_canonical(const char *dir);

/* ---- isolation (ABORT records) ----
 * kat_isolate runs fn(arg) in a separate process. POSIX: fork. Windows: the
 * program is re-executed with the environment variables KAT_CHILD_FILE and
 * KAT_CHILD_LINE set, and the program's main must then run only that record
 * (directly, via kat_in_child()) and exit 0.
 * Returns:
 *   KAT_CHILD_RETURNED  the call returned and the child exited 0
 *   KAT_CHILD_ABORTED   the child died from SIGABRT (abort())
 *   KAT_CHILD_CRASHED   the child died from another signal / exception
 *   KAT_CHILD_ERROR     the child exited with a nonzero status (setup error)
 * *detail gets the signal number or exit code. */
enum kat_child { KAT_CHILD_RETURNED = 0, KAT_CHILD_ABORTED, KAT_CHILD_CRASHED, KAT_CHILD_ERROR };
void kat_isolation_setup(int argc, char **argv);
bool kat_in_child(void);
const char *kat_child_file(void);
unsigned long kat_child_line(void);
enum kat_child kat_isolate(const char *file, unsigned long lineno, void (*fn)(void *), void *arg, long *detail);
const char *kat_child_str(enum kat_child c);

/* Monotonic clock in seconds. */
double kat_now(void);

#endif
