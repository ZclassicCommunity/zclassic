// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The recovery phrase: BIP39 words and checksum for the 32-byte seed, and the
// transparent keys derived from the seed.
#include <gtest/gtest.h>

#include "chainparams.h"
#include "key.h"
#include "main.h"
#include "random.h"
#include "wallet/phrase.h"
#include "wallet/wallet.h"
#include "wallet/walletphrase.h"

namespace {

RawHDSeed Filled(unsigned char byte) { return RawHDSeed(32, byte); }

std::string Repeat(const std::string& word, int n, const std::string& last)
{
    std::string out;
    for (int i = 0; i < n; i++) out += word + " ";
    return out + last;
}

} // namespace

// The 256-bit entropy vectors of BIP39 (trezor/python-mnemonic vectors.json).
TEST(wallet_phrase, Bip39Vectors) {
    EXPECT_EQ(phrase::FromSeed(Filled(0x00)), Repeat("abandon", 23, "art"));
    EXPECT_EQ(phrase::FromSeed(Filled(0x7f)),
        "legal winner thank year wave sausage worth useful legal winner thank year "
        "wave sausage worth useful legal winner thank year wave sausage worth title");
    EXPECT_EQ(phrase::FromSeed(Filled(0x80)),
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
        "amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless");
    EXPECT_EQ(phrase::FromSeed(Filled(0xff)), Repeat("zoo", 23, "vote"));
}

TEST(wallet_phrase, RoundTripAndTolerantInput) {
    for (int i = 0; i < 64; i++) {
        RawHDSeed seed(32);
        GetRandBytes(seed.data(), seed.size());
        RawHDSeed back;
        std::string err;
        ASSERT_TRUE(phrase::ToSeed(phrase::FromSeed(seed), back, err)) << err;
        EXPECT_TRUE(back == seed);
    }
    RawHDSeed back;
    std::string err;
    EXPECT_TRUE(phrase::ToSeed("  ZOO zoo zoo zoo zoo zoo\nzoo zoo zoo zoo zoo zoo\tzoo zoo zoo zoo "
                               "zoo zoo zoo zoo zoo zoo zoo Vote \n", back, err)) << err;
    EXPECT_TRUE(back == Filled(0xff));
}

TEST(wallet_phrase, RejectsBadPhrases) {
    RawHDSeed out;
    std::string err;
    EXPECT_FALSE(phrase::ToSeed(Repeat("abandon", 22, "art"), out, err));
    EXPECT_NE(err.find("24 words"), std::string::npos);
    EXPECT_FALSE(phrase::ToSeed(Repeat("abandon", 23, "artz"), out, err));
    EXPECT_NE(err.find("word 24"), std::string::npos);
    EXPECT_FALSE(phrase::ToSeed(Repeat("abandon", 23, "abandon"), out, err));   // checksum
    EXPECT_NE(err.find("typo"), std::string::npos);
    EXPECT_TRUE(out.empty());
    EXPECT_EQ(phrase::FromSeed(RawHDSeed(16, 0)), "");   // only 32-byte seeds have a phrase
}

TEST(wallet_phrase, TransparentKeypaths) {
    EXPECT_EQ(phrase::TransparentKeypath(147, 7), "m/44'/147'/0'/0/7");
    EXPECT_EQ(phrase::TransparentIndex("m/44'/147'/0'/0/7", 147), 7);
    EXPECT_EQ(phrase::TransparentIndex("m/44'/147'/0'/0/2147483647", 147), 2147483647);
    EXPECT_EQ(phrase::TransparentIndex("m/44'/147'/0'/0/2147483648", 147), -1);
    EXPECT_EQ(phrase::TransparentIndex("m/44'/1'/0'/0/7", 147), -1);
    EXPECT_EQ(phrase::TransparentIndex("m/32'/147'/7'", 147), -1);
    EXPECT_EQ(phrase::TransparentIndex("m/44'/147'/0'/0/", 147), -1);
    EXPECT_EQ(phrase::TransparentIndex("m/44'/147'/0'/0/7x", 147), -1);
    EXPECT_EQ(phrase::TransparentIndex("", 147), -1);
}

// Keys come from m/44'/coin'/0'/0/i in order, skip keys already held, and are
// marked as covered by the phrase; a random key is not.
TEST(wallet_phrase, DerivesTransparentKeysFromTheSeed) {
    SelectParams(CBaseChainParams::MAIN);
    CWallet wallet;
    LOCK2(cs_main, wallet.cs_wallet);
    wallet.SetMinVersion(FEATURE_LATEST);   // compressed keys, as every real wallet
    CKey key;
    CKeyMetadata meta(1);
    EXPECT_FALSE(DeriveTransparentKey(wallet, key, meta));   // no seed yet

    RawHDSeed raw = Filled(0x01);
    HDSeed seed(raw);
    ASSERT_TRUE(wallet.LoadHDSeed(seed));
    CHDChain chain;
    chain.seedFp = seed.Fingerprint();
    wallet.SetHDChain(chain, true);

    CExtKey master, step, chainKey, expected;
    master.SetMaster(raw.data(), raw.size());
    ASSERT_TRUE(master.Derive(step, 44 | 0x80000000) && step.Derive(chainKey, 147 | 0x80000000));
    ASSERT_TRUE(chainKey.Derive(step, 0 | 0x80000000) && step.Derive(chainKey, 0));
    for (unsigned int i = 0; i < 3; i++) {
        ASSERT_TRUE(chainKey.Derive(expected, i));
        CPubKey pub = wallet.GenerateNewKey();
        EXPECT_EQ(pub, expected.key.GetPubKey()) << "index " << i;
        const CKeyMetadata& m = wallet.mapKeyMetadata[pub.GetID()];
        EXPECT_EQ(m.hdKeypath, phrase::TransparentKeypath(147, i));
        EXPECT_EQ(m.seedFp, seed.Fingerprint());
        EXPECT_TRUE(KeyFromPhrase(wallet, m));
    }

    // A key the wallet already holds is skipped, not handed out twice.
    ASSERT_TRUE(chainKey.Derive(expected, 4));
    ASSERT_TRUE(wallet.AddKeyPubKey(expected.key, expected.key.GetPubKey()));
    ASSERT_TRUE(chainKey.Derive(expected, 3));
    EXPECT_EQ(wallet.GenerateNewKey(), expected.key.GetPubKey());
    ASSERT_TRUE(chainKey.Derive(expected, 5));
    EXPECT_EQ(wallet.GenerateNewKey(), expected.key.GetPubKey());

    CKey random;
    random.MakeNewKey(true);
    ASSERT_TRUE(wallet.AddKeyPubKey(random, random.GetPubKey()));
    EXPECT_FALSE(KeyFromPhrase(wallet, wallet.mapKeyMetadata[random.GetPubKey().GetID()]));
}

// The same words give the same keys in another wallet.
TEST(wallet_phrase, SamePhraseSameKeys) {
    SelectParams(CBaseChainParams::MAIN);
    RawHDSeed raw;
    std::string err;
    ASSERT_TRUE(phrase::ToSeed(Repeat("zoo", 23, "vote"), raw, err));
    CPubKey first[2];
    for (int w = 0; w < 2; w++) {
        CWallet wallet;
        LOCK2(cs_main, wallet.cs_wallet);
        wallet.SetMinVersion(FEATURE_LATEST);
        HDSeed seed(raw);
        ASSERT_TRUE(wallet.LoadHDSeed(seed));
        first[w] = wallet.GenerateNewKey();
    }
    EXPECT_EQ(first[0], first[1]);
}
