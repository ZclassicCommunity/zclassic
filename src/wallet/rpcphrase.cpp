// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// RPCs for the wallet's recovery phrase (wallet/phrase.h, wallet/walletphrase.h).
#include "init.h"
#include "main.h"
#include "rpc/server.h"
#include "wallet/phrase.h"
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#include "wallet/walletphrase.h"

#include <univalue.h>

bool EnsureWalletIsAvailable(bool avoidException);

static UniValue z_getphraseinfo(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "z_getphraseinfo\n"
            "\nWhether the wallet's seed can be shown as a 24-word recovery phrase, and which\n"
            "of the wallet's own addresses the phrase does not cover. Shows no secret.\n"
            "\nResult:\n"
            "{\n"
            "  \"available\": true|false,   (boolean) z_getrecoveryphrase can show the phrase now\n"
            "  \"fingerprint\": \"hex\",      (string) the seed's fingerprint\n"
            "  \"not_covered\": [ \"addr\" ]  (array) spendable addresses whose keys do not come from the phrase:\n"
            "                              keys made before the phrase existed, imported keys, Sprout keys\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_getphraseinfo", "")
            + HelpExampleRpc("z_getphraseinfo", ""));

    UniValue result(UniValue::VOBJ);
    HDSeed seed;
    bool available;
    {
        LOCK(pwalletMain->cs_wallet);
        available = pwalletMain->GetHDSeed(seed) && seed.RawSeed().size() == phrase::SEED_BYTES;
        result.pushKV("available", UniValue(available));   // a plain bool would print as 1
        result.pushKV("fingerprint", pwalletMain->GetHDChain().seedFp.GetHex());
    }
    UniValue missing(UniValue::VARR);
    for (const std::string& addr : AddressesNotInPhrase(*pwalletMain))
        missing.push_back(addr);
    result.pushKV("not_covered", missing);
    return result;
}

static UniValue z_getrecoveryphrase(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "z_getrecoveryphrase\n"
            "\nReveals the wallet's 24-word recovery phrase (BIP39 English words and checksum;\n"
            "the words are the 32-byte HD seed itself). Anyone with these words can spend the\n"
            "funds at every address the phrase covers (see z_getphraseinfo).\n"
            "\nResult:\n"
            "{\n"
            "  \"phrase\": \"word1 ... word24\",  (string) the recovery phrase\n"
            "  \"fingerprint\": \"hex\"           (string) the seed's fingerprint\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_getrecoveryphrase", "")
            + HelpExampleRpc("z_getrecoveryphrase", ""));

    LOCK(pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    HDSeed seed;
    if (!pwalletMain->GetHDSeed(seed))
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet has no HD seed");
    const std::string words = phrase::FromSeed(seed.RawSeed());
    if (words.empty())
        throw JSONRPCError(RPC_WALLET_ERROR, "This wallet's seed cannot be written as a recovery phrase");
    UniValue result(UniValue::VOBJ);
    result.pushKV("phrase", words);
    result.pushKV("fingerprint", seed.Fingerprint().GetHex());
    return result;
}

static UniValue z_restorefromphrase(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "z_restorefromphrase \"phrase\" ( startheight )\n"
            "\nMakes a 24-word recovery phrase this wallet's seed and finds its addresses:\n"
            "derives transparent and Sapling keys from it, rescans the chain (this can take a\n"
            "long time) and derives more while the newest ones turn out used. Every key the\n"
            "wallet already holds stays; new addresses come from the phrase from now on.\n"
            "The previous seed is kept in the wallet file as a retired record.\n"
            "\nArguments:\n"
            "1. \"phrase\"        (string, required) the 24 words, separated by spaces\n"
            "2. startheight     (numeric, optional, default=0) block height to start the rescan from\n"
            "\nResult:\n"
            "{\n"
            "  \"fingerprint\": \"hex\",        (string) the new seed's fingerprint\n"
            "  \"transparent\": [ \"addr\" ],   (array) transparent addresses from the phrase with history\n"
            "  \"sapling\": [ \"addr\" ]        (array) Sapling addresses from the phrase with notes\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_restorefromphrase", "\"abandon abandon ... art\"")
            + HelpExampleRpc("z_restorefromphrase", "\"abandon abandon ... art\", 0"));

    EnsureWalletIsUnlocked();
    RawHDSeed raw;
    std::string err;
    if (!phrase::ToSeed(params[0].get_str(), raw, err))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid recovery phrase: " + err);
    const int startHeight = params.size() > 1 ? params[1].get_int() : 0;
    const HDSeed seed(raw);
    PhraseRestoreResult found;
    try {
        found = RestoreFromPhrase(*pwalletMain, seed, startHeight);
    } catch (const std::runtime_error& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, std::string("Restore failed: ") + e.what());
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("fingerprint", seed.Fingerprint().GetHex());
    UniValue t(UniValue::VARR), z(UniValue::VARR);
    for (const std::string& a : found.transparent) t.push_back(a);
    for (const std::string& a : found.sapling) z.push_back(a);
    result.pushKV("transparent", t);
    result.pushKV("sapling", z);
    return result;
}

static const CRPCCommand commands[] =
{   //  category              name                       actor (function)          okSafeMode
    //  --------------------- -------------------------  ------------------------  ----------
    { "wallet",             "z_getphraseinfo",         &z_getphraseinfo,         true  },
    { "wallet",             "z_getrecoveryphrase",     &z_getrecoveryphrase,     true  },
    { "wallet",             "z_restorefromphrase",     &z_restorefromphrase,     false },
};

void RegisterPhraseRPCCommands(CRPCTable& tableRPC)
{
    for (const CRPCCommand& command : commands)
        tableRPC.appendCommand(command.name, &command);
}
