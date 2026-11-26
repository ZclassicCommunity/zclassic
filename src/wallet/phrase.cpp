// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "wallet/phrase.h"
#include "wallet/bip39_english.h"

#include "crypto/sha256.h"
#include "support/cleanse.h"

#include <cctype>
#include <cstring>
#include <vector>

namespace phrase {

static int WordIndex(const std::string& word)
{
    int lo = 0, hi = 2047;   // the list is sorted
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int c = strcmp(word.c_str(), BIP39_ENGLISH[mid]);
        if (c == 0) return mid;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return -1;
}

static unsigned char Checksum(const unsigned char* seed)
{
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(seed, SEED_BYTES).Finalize(hash);
    unsigned char first = hash[0];
    memory_cleanse(hash, sizeof(hash));
    return first;
}

// Bit i of the 264-bit string seed || checksum, most significant bit first.
static int BitAt(const unsigned char* seed, unsigned char check, size_t i)
{
    unsigned char byte = i < 8 * SEED_BYTES ? seed[i / 8] : check;
    return (byte >> (7 - i % 8)) & 1;
}

std::string FromSeed(const RawHDSeed& seed)
{
    if (seed.size() != SEED_BYTES) return std::string();
    const unsigned char check = Checksum(seed.data());
    std::string out;
    for (size_t w = 0; w < WORDS; w++) {
        int index = 0;
        for (size_t b = 0; b < 11; b++)
            index = (index << 1) | BitAt(seed.data(), check, w * 11 + b);
        if (w) out += ' ';
        out += BIP39_ENGLISH[index];
    }
    return out;
}

bool ToSeed(const std::string& words, RawHDSeed& seedOut, std::string& err)
{
    std::vector<int> indexes;
    std::string word;
    for (size_t i = 0; i <= words.size(); i++) {
        unsigned char c = i < words.size() ? (unsigned char)words[i] : ' ';
        if (!isspace(c)) { word += (char)tolower(c); continue; }
        if (word.empty()) continue;
        int index = WordIndex(word);
        if (index < 0) {
            err = "word " + std::to_string(indexes.size() + 1) + " is not in the word list";
            return false;
        }
        indexes.push_back(index);
        word.clear();
    }
    if (indexes.size() != WORDS) {
        err = "a recovery phrase has 24 words, this one has " + std::to_string(indexes.size());
        return false;
    }
    unsigned char bits[SEED_BYTES + 1] = {0};   // seed || checksum, 264 bits
    for (size_t w = 0; w < WORDS; w++)
        for (size_t b = 0; b < 11; b++)
            if ((indexes[w] >> (10 - b)) & 1) {
                size_t i = w * 11 + b;
                bits[i / 8] |= 1 << (7 - i % 8);
            }
    const bool ok = Checksum(bits) == bits[SEED_BYTES];
    if (ok) seedOut.assign(bits, bits + SEED_BYTES);
    memory_cleanse(bits, sizeof(bits));
    if (!ok) err = "the words do not check out; look for a typo";
    return ok;
}

std::string TransparentKeypath(uint32_t coinType, uint32_t index)
{
    return "m/44'/" + std::to_string(coinType) + "'/0'/0/" + std::to_string(index);
}

int64_t TransparentIndex(const std::string& keypath, uint32_t coinType)
{
    const std::string prefix = "m/44'/" + std::to_string(coinType) + "'/0'/0/";
    if (keypath.compare(0, prefix.size(), prefix) != 0 || keypath.size() == prefix.size()
            || keypath.size() - prefix.size() > 10)
        return -1;
    int64_t index = 0;
    for (size_t i = prefix.size(); i < keypath.size(); i++) {
        if (!isdigit((unsigned char)keypath[i])) return -1;
        index = index * 10 + (keypath[i] - '0');
    }
    return index < 0x80000000LL ? index : -1;
}

} // namespace phrase
