// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The wallet side of the recovery phrase (wallet/phrase.h): transparent keys that
// come from the HD seed, a key pool that only hands out such keys, which addresses
// the phrase covers, and the restore that swaps in a phrase's seed and rescans.
#ifndef ZCLASSIC_WALLET_WALLETPHRASE_H
#define ZCLASSIC_WALLET_WALLETPHRASE_H

#include "zcash/zip32.h"

#include <string>
#include <vector>

class CKey;
class CKeyMetadata;
class CWallet;

// The next transparent key from the seed (m/44'/coin'/0'/0/i, skipping keys the
// wallet already holds), with its keypath and seed fingerprint in meta. False when
// the wallet has no 32-byte seed it can read; the caller then makes a random key.
// Needs cs_wallet.
bool DeriveTransparentKey(const CWallet& wallet, CKey& secret, CKeyMetadata& meta);

// True when a key with this metadata comes from the wallet's current seed.
bool KeyFromPhrase(const CWallet& wallet, const CKeyMetadata& meta);

// Take keys that do not come from the seed out of the key pool (they stay in the
// wallet; only the pool stops handing them out) and top the pool up with derived
// keys. Runs at start-up; a no-op when every pool key is derived already.
void KeepKeyPoolOnPhrase(CWallet& wallet);

// The wallet's own spendable addresses (transparent ones in the address book,
// Sapling and Sprout) whose keys do not come from the current seed.
std::vector<std::string> AddressesNotInPhrase(const CWallet& wallet);

struct PhraseRestoreResult {
    std::vector<std::string> transparent;   // derived t-addresses with history
    std::vector<std::string> sapling;       // derived Sapling addresses with notes
};

// Make seed the wallet's seed (the old one is kept as a retired record), refill the
// key pool from it, derive Sapling accounts, rescan from startHeight and keep
// deriving while the newest derived addresses turn out used. Every key already in
// the wallet stays. Needs an unencrypted wallet; throws std::runtime_error.
PhraseRestoreResult RestoreFromPhrase(CWallet& wallet, const HDSeed& seed, int startHeight);

#endif // ZCLASSIC_WALLET_WALLETPHRASE_H
