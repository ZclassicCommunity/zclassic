/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Note encryption for Sprout and Sapling shielded transactions.
 * Sprout: Curve25519 DH + BLAKE2b KDF + ChaCha20-Poly1305 AEAD.
 * Sapling: Jubjub DH + BLAKE2b KDF + ChaCha20-Poly1305 AEAD. */

#ifndef ZCL_SAPLING_NOTE_ENCRYPTION_H
#define ZCL_SAPLING_NOTE_ENCRYPTION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sapling/constants.h"

/* KDF contract (all three derive the 32-byte ChaCha20-Poly1305 key):
 *
 * Every ciphertext in this module is sealed with the SAME fixed zero nonce
 * (see note_encryption.c). That is safe ONLY because the derived key is
 * unique per message — uniqueness comes from the fresh ephemeral secret
 * esk that feeds dhsecret/epk. The KDF is the binding step: it mixes the
 * DH shared secret with the public ephemeral key (and, for Sprout, hSig
 * and pk_enc) under a domain-separating BLAKE2b personalization, so the
 * AEAD key cannot be steered by an attacker who does not know esk. If esk
 * ever repeats (RNG failure), the key repeats, the (key, zero-nonce) pair
 * repeats, and confidentiality + integrity both collapse — hence the
 * esk-reuse guard in the .c. These return false only on a BLAKE2b init
 * failure (degenerate personalization length); on success `key` holds the
 * 32-byte symmetric key. */

/* Sprout KDF: BLAKE2b-256("ZcashKDF" || nonce, hSig || dhsecret || epk || pk_enc) */
bool sprout_kdf(uint8_t key[32],
                const uint8_t hsig[32],
                const uint8_t dhsecret[32],
                const uint8_t epk[32],
                const uint8_t pk_enc[32],
                uint8_t nonce);

/* Sapling KDF: BLAKE2b-256("Zcash_SaplingKDF", dhsecret || epk).
 * dhsecret = sapling_ka_agree(pk_d, esk) for the sender (or ivk, epk for
 * the recipient). This is the key for the note enc_ciphertext (enc field). */
bool sapling_kdf(uint8_t key[32],
                 const uint8_t dhsecret[32],
                 const uint8_t epk[32]);

/* Sapling outgoing cipher key: BLAKE2b-256("Zcash_Derive_ock", ovk || cv || cm || epk).
 * Keyed by the SENDER's outgoing viewing key (ovk), this derives the key
 * for the out_ciphertext that lets the sender (or an ovk holder) later
 * recover pk_d and esk and thus re-derive the note they sent. It does NOT
 * depend on the recipient's secret, so anyone with ovk can open it. */
bool sapling_prf_ock(uint8_t key[32],
                     const uint8_t ovk[32],
                     const uint8_t cv[32],
                     const uint8_t cm[32],
                     const uint8_t epk[32]);

/* Sprout note encryption context */
struct sprout_note_encryption {
    uint8_t esk[32];
    uint8_t epk[32];
    uint8_t nonce;
};

/* Initialize with random ephemeral key */
bool sprout_note_encryption_init(struct sprout_note_encryption *ctx);

/* Initialize with specific ephemeral key (for testing) */
void sprout_note_encryption_init_with_esk(struct sprout_note_encryption *ctx,
                                           const uint8_t esk[32]);

/* Encrypt a Sprout note plaintext. The ctx->nonce (0,1,...) selects a
 * DISTINCT KDF personalization per call, so the AEAD key differs for each
 * of a JoinSplit's outputs even though epk is shared — this is what keeps
 * the fixed zero AEAD nonce safe across the (≤2) outputs of one tx. nonce
 * auto-increments; encrypting past nonce 254 is rejected (one tx's budget).
 * plaintext: ZC_NOTEPLAINTEXT_SIZE bytes
 * ciphertext: ZC_NOTEPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES bytes
 * Returns false on KDF/nonce-budget failure. */
bool sprout_note_encrypt(struct sprout_note_encryption *ctx,
                         const uint8_t hsig[32],
                         const uint8_t pk_enc[32],
                         const uint8_t *plaintext, size_t plen,
                         uint8_t *ciphertext);

/* Decrypt a Sprout note ciphertext. Like the Sapling variant, returns
 * true ONLY if the Poly1305 tag authenticates — the same nonce passed
 * to the matching sprout_note_encrypt call must be supplied to reproduce
 * the KDF key. On false the plaintext is not trustworthy.
 * sk_enc: recipient's secret encryption key (clamped Curve25519 scalar)
 * ciphertext: plen + NOTEENCRYPTION_AUTH_BYTES bytes
 * plaintext: plen bytes output */
bool sprout_note_decrypt(const uint8_t sk_enc[32],
                         const uint8_t epk[32],
                         const uint8_t hsig[32],
                         const uint8_t pk_enc[32],
                         uint8_t nonce,
                         const uint8_t *ciphertext, size_t clen,
                         uint8_t *plaintext);

/* Sapling note encryption. ChaCha20-Poly1305 AEAD under the fixed zero
 * nonce; appends a 16-byte (NOTEENCRYPTION_AUTH_BYTES) Poly1305 tag.
 * key: pre-derived symmetric key from sapling_kdf (MUST be fresh — see KDF
 *      contract above; reuse with the zero nonce is a two-time pad)
 * plaintext: ZC_SAPLING_ENCCIPHERTEXT_SIZE - NOTEENCRYPTION_AUTH_BYTES bytes
 * ciphertext: ZC_SAPLING_ENCCIPHERTEXT_SIZE bytes */
bool sapling_note_encrypt(const uint8_t key[32],
                          const uint8_t *plaintext, size_t plen,
                          uint8_t *ciphertext);

/* Sapling note decryption / trial decryption.
 * Returns true ONLY if the Poly1305 tag authenticates under `key` — i.e.
 * the AEAD both decrypts AND verifies. Wallet scanning relies on this:
 * deriving `key` from a candidate ivk and feeding a foreign note's
 * ciphertext returns false (tag mismatch), so a successful return is
 * proof the note was addressed to this viewing key. On false, `plaintext`
 * is not trustworthy. clen must include the trailing 16-byte tag. */
bool sapling_note_decrypt(const uint8_t key[32],
                          const uint8_t *ciphertext, size_t clen,
                          uint8_t *plaintext);

/* Sapling outgoing ciphertext encryption.
 * key: pre-derived from sapling_prf_ock
 * plaintext: ZC_SAPLING_OUTCIPHERTEXT_SIZE - NOTEENCRYPTION_AUTH_BYTES bytes (64)
 * ciphertext: ZC_SAPLING_OUTCIPHERTEXT_SIZE bytes (80) */
bool sapling_out_encrypt(const uint8_t key[32],
                         const uint8_t *plaintext, size_t plen,
                         uint8_t *ciphertext);

bool sapling_out_decrypt(const uint8_t key[32],
                         const uint8_t *ciphertext, size_t clen,
                         uint8_t *plaintext);

#endif
