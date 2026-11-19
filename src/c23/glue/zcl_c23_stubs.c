/* zclassicd-owned. Fail-closed stand-ins for the Z23 note-encryption entry
 * points that vendor sapling.c references from sapling_build_output_* only.
 * zclassicd never calls those builders (it has libsodium NoteEncryption), so
 * these are dead code; if ever reached they refuse rather than produce a
 * ciphertext. note_encryption.c (chacha20poly1305, curve25519) is NOT vendored. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sapling/note_encryption.h"

bool sapling_kdf(uint8_t key[32], const uint8_t dhsecret[32], const uint8_t epk[32])
{
    (void)key; (void)dhsecret; (void)epk;
    return false;
}

bool sapling_prf_ock(uint8_t key[32], const uint8_t ovk[32], const uint8_t cv[32],
                     const uint8_t cm[32], const uint8_t epk[32])
{
    (void)key; (void)ovk; (void)cv; (void)cm; (void)epk;
    return false;
}

bool sapling_note_encrypt(const uint8_t key[32], const uint8_t *plaintext, size_t plen,
                          uint8_t *ciphertext)
{
    (void)key; (void)plaintext; (void)plen; (void)ciphertext;
    return false;
}

bool sapling_out_encrypt(const uint8_t key[32], const uint8_t *plaintext, size_t plen,
                         uint8_t *ciphertext)
{
    (void)key; (void)plaintext; (void)plen; (void)ciphertext;
    return false;
}
