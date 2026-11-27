// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The wallet's recovery phrase: its 32-byte HD seed written as 24 words from the
// BIP39 English list, with the BIP39 checksum (the first 8 bits of SHA-256 of the
// seed). The 32 bytes are the seed itself: there is no PBKDF2 step and no
// passphrase, so an existing wallet's seed, and every key derived from it, keeps
// working. Keys that come from the seed:
//   Sapling      m/32'/coin_type'/account'   (ZIP32, unchanged)
//   transparent  m/44'/coin_type'/0'/0/index (BIP32/BIP44, secp256k1)
#ifndef ZCLASSIC_WALLET_PHRASE_H
#define ZCLASSIC_WALLET_PHRASE_H

#include "zcash/zip32.h"

#include <string>

namespace phrase {

static const size_t SEED_BYTES = 32;
static const size_t WORDS = 24;

// The 24 words for a 32-byte seed, separated by single spaces. Empty when the
// seed is not 32 bytes long.
std::string FromSeed(const RawHDSeed& seed);

// Parse a phrase: words separated by any whitespace, any letter case. On success
// fills seedOut and returns true; otherwise returns false and says why in err.
bool ToSeed(const std::string& words, RawHDSeed& seedOut, std::string& err);

// The keypath of transparent key number index, and the index of a keypath
// ("m/44'/<coin>'/0'/0/<index>"); -1 when the keypath is not one of ours.
std::string TransparentKeypath(uint32_t coinType, uint32_t index);
int64_t TransparentIndex(const std::string& keypath, uint32_t coinType);

} // namespace phrase

#endif // ZCLASSIC_WALLET_PHRASE_H
