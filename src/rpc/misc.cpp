// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/filesystem.hpp>

#include <fstream>
#include <cstring>
#include <functional>

#include <univalue.h>

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif

#include "zcash/Address.hpp"

using namespace std;

/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/
UniValue getinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total Zclassic balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", CLIENT_VERSION));
    obj.push_back(Pair("protocolversion", PROTOCOL_VERSION));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
        obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));
    }
#endif
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("timeoffset",    GetTimeOffset()));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : string())));
    obj.push_back(Pair("difficulty",    (double)GetDifficulty()));
    obj.push_back(Pair("testnet",       Params().TestnetToBeDeprecatedFieldRPC()));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("keypoololdest", pwalletMain->GetOldestKeyPoolTime()));
        obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    }
    if (pwalletMain && pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
#endif
    obj.push_back(Pair("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK())));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        if (pwalletMain && pwalletMain->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        if (pwalletMain && pwalletMain->GetCScript(scriptID, subscript)) {
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(Pair("script", GetTxnOutputType(whichType)));
            obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
            UniValue a(UniValue::VARR);
            for (const CTxDestination& addr : addresses) {
                a.push_back(EncodeDestination(addr));
            }
            obj.push_back(Pair("addresses", a));
            if (whichType == TX_MULTISIG)
                obj.push_back(Pair("sigsrequired", nRequired));
        }
        return obj;
    }
};
#endif

UniValue validateaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress \"zclassicaddress\"\n"
            "\nReturn information about the given Zclassic address.\n"
            "\nArguments:\n"
            "1. \"zclassicaddress\"     (string, required) The Zclassic address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,         (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"zclassicaddress\",   (string) The Zclassic address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,          (boolean) If the address is yours or not\n"
            "  \"isscript\" : true|false,        (boolean) If the key is a script\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,    (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is the default account\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    CTxDestination dest = DecodeDestination(params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

#ifdef ENABLE_WALLET
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", (mine & ISMINE_SPENDABLE) ? true : false));
        ret.push_back(Pair("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true: false));
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
        ret.pushKVs(detail);
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest].name));
#endif
    }
    return ret;
}


class DescribePaymentAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    UniValue operator()(const libzcash::InvalidEncoding &zaddr) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const libzcash::SproutPaymentAddress &zaddr) const {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("type", "sprout"));
        obj.push_back(Pair("payingkey", zaddr.a_pk.GetHex()));
        obj.push_back(Pair("transmissionkey", zaddr.pk_enc.GetHex()));
#ifdef ENABLE_WALLET
        if (pwalletMain) {
            obj.push_back(Pair("ismine", pwalletMain->HaveSproutSpendingKey(zaddr)));
        }
#endif
        return obj;
    }

    UniValue operator()(const libzcash::SaplingPaymentAddress &zaddr) const {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("type", "sapling"));
        obj.push_back(Pair("diversifier", HexStr(zaddr.d)));
        obj.push_back(Pair("diversifiedtransmissionkey", zaddr.pk_d.GetHex()));
#ifdef ENABLE_WALLET
        if (pwalletMain) {
            libzcash::SaplingIncomingViewingKey ivk;
            libzcash::SaplingFullViewingKey fvk;
            bool isMine = pwalletMain->GetSaplingIncomingViewingKey(zaddr, ivk) &&
                pwalletMain->GetSaplingFullViewingKey(ivk, fvk) &&
                pwalletMain->HaveSaplingSpendingKey(fvk);
            obj.push_back(Pair("ismine", isMine));
        }
#endif
        return obj;
    }
};

UniValue z_validateaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_validateaddress \"zaddr\"\n"
            "\nReturn information about the given z address.\n"
            "\nArguments:\n"
            "1. \"zaddr\"     (string, required) The z address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,      (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"zaddr\",         (string) The z address validated\n"
            "  \"type\" : \"xxxx\",             (string) \"sprout\" or \"sapling\"\n"
            "  \"ismine\" : true|false,       (boolean) If the address is yours or not\n"
            "  \"payingkey\" : \"hex\",         (string) [sprout] The hex value of the paying key, a_pk\n"
            "  \"transmissionkey\" : \"hex\",   (string) [sprout] The hex value of the transmission key, pk_enc\n"
            "  \"diversifier\" : \"hex\",       (string) [sapling] The hex value of the diversifier, d\n"
            "  \"diversifiedtransmissionkey\" : \"hex\", (string) [sapling] The hex value of pk_d\n"

            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_validateaddress", "\"zcWsmqT4X2V4jgxbgiCzyrAfRT1vi1F4sn7M5Pkh66izzw8Uk7LBGAH3DtcSMJeUb2pi3W4SQF8LMKkU2cUuVP68yAGcomL\"")
            + HelpExampleRpc("z_validateaddress", "\"zcWsmqT4X2V4jgxbgiCzyrAfRT1vi1F4sn7M5Pkh66izzw8Uk7LBGAH3DtcSMJeUb2pi3W4SQF8LMKkU2cUuVP68yAGcomL\"")
        );


#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain->cs_wallet);
#else
    LOCK(cs_main);
#endif

    string strAddress = params[0].get_str();
    auto address = DecodePaymentAddress(strAddress);
    bool isValid = IsValidPaymentAddress(address);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        ret.push_back(Pair("address", strAddress));
        UniValue detail = boost::apply_visitor(DescribePaymentAddressVisitor(), address);
        ret.pushKVs(detail);
    }
    return ret;
}


/**
 * Used by addmultisigaddress / createmultisig:
 */
CScript _createmultisig_redeemScript(const UniValue& params)
{
    int nRequired = params[0].get_int();
    const UniValue& keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %u keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();
#ifdef ENABLE_WALLET
        // Case 1: Bitcoin address and we have full public key:
        CTxDestination dest = DecodeDestination(ks);
        if (pwalletMain && IsValidDestination(dest)) {
            const CKeyID *keyID = boost::get<CKeyID>(&dest);
            if (!keyID) {
                throw std::runtime_error(strprintf("%s does not refer to a key", ks));
            }
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(*keyID, vchPubKey)) {
                throw std::runtime_error(strprintf("no full public key for address %s", ks));
            }
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
        if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }
    CScript result = GetScriptForMultisig(nRequired, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw runtime_error(
                strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE));

    return result;
}

UniValue createmultisig(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
    {
        string msg = "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"       (string, required) A json array of keys which are Zclassic addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"key\"    (string) Zclassic address or hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 addresses\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"t16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"t171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"t16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"t171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(params);
    CScriptID innerID(inner);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", EncodeDestination(innerID)));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}

UniValue verifymessage(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage \"zclassicaddress\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"zclassicaddress\"    (string, required) The Zclassic address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"t14oHp2v54vfmdgQ3v3SNuQga8JKHTNi2a1\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"t14oHp2v54vfmdgQ3v3SNuQga8JKHTNi2a1\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"t14oHp2v54vfmdgQ3v3SNuQga8JKHTNi2a1\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = boost::get<CKeyID>(&destination);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == *keyID);
}

UniValue setmocktime(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw runtime_error("setmocktime for regression testing (-regtest mode) only");

    // cs_vNodes is locked and node send/receive times are updated
    // atomically with the time change to prevent peers from being
    // disconnected because we think we haven't communicated with them
    // in a long time.
    LOCK2(cs_main, cs_vNodes);

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));
    SetMockTime(params[0].get_int64());

    uint64_t t = GetTime();
    BOOST_FOREACH(CNode* pnode, vNodes) {
        pnode->nLastSend = pnode->nLastRecv = t;
    }

    return NullUniValue;
}

/**
 * Securely shred a file using DoD 5220.22-M style overwrite pattern
 * 
 * SECURITY: This function performs a secure wipe by:
 * 1. Overwriting the entire file with 0xFF (all 1s)
 * 2. Overwriting the entire file with 0xAA (10101010 pattern)
 * 3. Overwriting the entire file with 0x00 (all 0s)
 * 4. Flushing to disk after each pass
 * 5. Renaming to obscure original filename
 * 6. Deleting the file
 * 
 * @param filepath The path to the file to securely destroy
 * @param progressCallback Optional callback for progress updates (0-100)
 * @return true if successful, false otherwise
 */
static bool SecureShredFile(const boost::filesystem::path& filepath, 
                            std::function<void(int)> progressCallback = nullptr)
{
    try {
        // Open file immediately with read+write access to avoid TOCTOU race condition
        // This also acquires an exclusive handle to the file
#ifdef WIN32
        // Windows: Open with exclusive access to lock the file
        HANDLE hFile = CreateFileW(
            filepath.wstring().c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,  // No sharing - exclusive access
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND) {
                return false;  // File doesn't exist
            }
            return false;  // Could not open/lock file
        }
        
        // Get file size using the open handle (avoids TOCTOU)
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            CloseHandle(hFile);
            return false;
        }
        
        uintmax_t size = static_cast<uintmax_t>(fileSize.QuadPart);
        
        if (size == 0) {
            // Empty file, just close and delete it
            CloseHandle(hFile);
            boost::filesystem::remove(filepath);
            return true;
        }
        
        // Allocate buffer for overwriting (use 64KB chunks for efficiency)
        const size_t BUFFER_SIZE = 65536;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        
        // Three-pass overwrite pattern (DoD 5220.22-M inspired)
        const unsigned char patterns[3] = {
            0xFF,  // Pass 1: All 1s (11111111)
            0xAA,  // Pass 2: Alternating (10101010)
            0x00   // Pass 3: All 0s (00000000)
        };
        
        // Total work = 3 passes * fileSize
        uintmax_t totalWork = size * 3;
        uintmax_t completedWork = 0;
        
        for (int pass = 0; pass < 3; pass++) {
            // Fill buffer with current pattern
            std::memset(&buffer[0], patterns[pass], BUFFER_SIZE);
            
            // Seek to beginning of file
            LARGE_INTEGER zero;
            zero.QuadPart = 0;
            if (!SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN)) {
                CloseHandle(hFile);
                return false;
            }
            
            // Overwrite entire file
            uintmax_t remaining = size;
            while (remaining > 0) {
                DWORD toWrite = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : static_cast<DWORD>(remaining);
                DWORD bytesWritten;
                if (!WriteFile(hFile, &buffer[0], toWrite, &bytesWritten, NULL) || bytesWritten != toWrite) {
                    CloseHandle(hFile);
                    return false;
                }
                remaining -= bytesWritten;
                completedWork += bytesWritten;
                
                // Report progress
                if (progressCallback) {
                    int percent = static_cast<int>((completedWork * 100) / totalWork);
                    progressCallback(percent);
                }
            }
            
            // Flush to disk using the SAME handle we wrote to
            if (!FlushFileBuffers(hFile)) {
                CloseHandle(hFile);
                return false;
            }
        }
        
        // Close the file handle BEFORE rename/delete
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
        
#else
        // POSIX: Open with exclusive lock
        int fd = open(filepath.string().c_str(), O_RDWR);
        if (fd < 0) {
            if (errno == ENOENT) {
                return false;  // File doesn't exist
            }
            return false;  // Could not open file
        }
        
        // Acquire exclusive lock on the file
        struct flock fl;
        fl.l_type = F_WRLCK;     // Exclusive write lock
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;            // Lock entire file
        
        if (fcntl(fd, F_SETLK, &fl) < 0) {
            // Could not acquire lock - file may be in use
            close(fd);
            return false;
        }
        
        // Get file size using fstat on the open descriptor (avoids TOCTOU)
        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            return false;
        }
        
        uintmax_t size = static_cast<uintmax_t>(st.st_size);
        
        if (size == 0) {
            // Empty file, just close and delete it
            close(fd);
            boost::filesystem::remove(filepath);
            return true;
        }
        
        // Allocate buffer for overwriting (use 64KB chunks for efficiency)
        const size_t BUFFER_SIZE = 65536;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        
        // Three-pass overwrite pattern (DoD 5220.22-M inspired)
        const unsigned char patterns[3] = {
            0xFF,  // Pass 1: All 1s (11111111)
            0xAA,  // Pass 2: Alternating (10101010)
            0x00   // Pass 3: All 0s (00000000)
        };
        
        // Total work = 3 passes * fileSize
        uintmax_t totalWork = size * 3;
        uintmax_t completedWork = 0;
        
        for (int pass = 0; pass < 3; pass++) {
            // Fill buffer with current pattern
            std::memset(&buffer[0], patterns[pass], BUFFER_SIZE);
            
            // Seek to beginning of file
            if (lseek(fd, 0, SEEK_SET) < 0) {
                close(fd);
                return false;
            }
            
            // Overwrite entire file
            uintmax_t remaining = size;
            while (remaining > 0) {
                size_t toWrite = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : static_cast<size_t>(remaining);
                ssize_t bytesWritten = write(fd, &buffer[0], toWrite);
                if (bytesWritten < 0 || static_cast<size_t>(bytesWritten) != toWrite) {
                    close(fd);
                    return false;
                }
                remaining -= bytesWritten;
                completedWork += bytesWritten;
                
                // Report progress
                if (progressCallback) {
                    int percent = static_cast<int>((completedWork * 100) / totalWork);
                    progressCallback(percent);
                }
            }
            
            // Flush to disk using the SAME file descriptor we wrote to
            if (fsync(fd) < 0) {
                close(fd);
                return false;
            }
        }
        
        // Release the lock and close the file descriptor BEFORE rename/delete
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
        fd = -1;
        
#endif

        // Rename to obscure original filename before deletion
        boost::filesystem::path obscuredPath = filepath.parent_path() / "00000000000000000000000000000000";
        
        // Handle case where obscured name already exists
        int counter = 0;
        boost::filesystem::path finalObscuredPath = obscuredPath;
        while (boost::filesystem::exists(finalObscuredPath)) {
            finalObscuredPath = filepath.parent_path() / 
                ("00000000000000000000000000000000_" + std::to_string(counter++));
        }

        boost::filesystem::rename(filepath, finalObscuredPath);

        // Delete the file
        boost::filesystem::remove(finalObscuredPath);

        return true;

    } catch (const boost::filesystem::filesystem_error& e) {
        return false;
    } catch (const std::exception& e) {
        return false;
    }
}

UniValue shredlogs(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "shredlogs\n"
            "\nSecurely destroy debug.log and db.log files in the data directory.\n"
            "\nThis command performs a secure 3-pass overwrite before deletion:\n"
            "  Pass 1: Overwrite with 0xFF (all 1s)\n"
            "  Pass 2: Overwrite with 0xAA (10101010 pattern)\n"
            "  Pass 3: Overwrite with 0x00 (all 0s)\n"
            "\nAfter overwriting, files are renamed to obscure the original filename,\n"
            "then deleted. Shredding is important because the debug.log file may contain \n"
            "sensitive transaction metadata, it should ONLY be used for debugging.\n"
            "\nWARNING: This operation is irreversible!\n"
            "\nResult:\n"
            "{\n"
            "  \"debug.log\": { \"status\": \"shredded\"|\"not found\"|\"failed\", \"size\": n, \"progress\": 100 },\n"
            "  \"db.log\": { \"status\": \"shredded\"|\"not found\"|\"failed\", \"size\": n, \"progress\": 100 }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("shredlogs", "")
            + HelpExampleRpc("shredlogs", "")
        );

    UniValue result(UniValue::VOBJ);
    boost::filesystem::path dataDir = GetDataDir();

    // Temporarily disable debug log file writing
    bool wasLoggingToFile = fPrintToDebugLog;
    fPrintToDebugLog = false;

    // Shred debug.log
    boost::filesystem::path debugLogPath = dataDir / "debug.log";
    UniValue debugResult(UniValue::VOBJ);
    
    if (boost::filesystem::exists(debugLogPath)) {
        uintmax_t fileSize = boost::filesystem::file_size(debugLogPath);
        debugResult.push_back(Pair("size", (int64_t)fileSize));
        
        int lastProgress = -1;
        auto progressCb = [&lastProgress, &debugResult](int progress) {
            lastProgress = progress;
        };
        
        if (SecureShredFile(debugLogPath, progressCb)) {
            debugResult.push_back(Pair("status", "shredded"));
            debugResult.push_back(Pair("progress", 100));
        } else {
            debugResult.push_back(Pair("status", "failed"));
            debugResult.push_back(Pair("progress", lastProgress));
        }
    } else {
        debugResult.push_back(Pair("status", "not found"));
        debugResult.push_back(Pair("size", 0));
        debugResult.push_back(Pair("progress", 0));
    }
    result.push_back(Pair("debug.log", debugResult));

    // Shred db.log
    boost::filesystem::path dbLogPath = dataDir / "db.log";
    UniValue dbResult(UniValue::VOBJ);
    
    if (boost::filesystem::exists(dbLogPath)) {
        uintmax_t fileSize = boost::filesystem::file_size(dbLogPath);
        dbResult.push_back(Pair("size", (int64_t)fileSize));
        
        int lastProgress = -1;
        auto progressCb = [&lastProgress](int progress) {
            lastProgress = progress;
        };
        
        if (SecureShredFile(dbLogPath, progressCb)) {
            dbResult.push_back(Pair("status", "shredded"));
            dbResult.push_back(Pair("progress", 100));
        } else {
            dbResult.push_back(Pair("status", "failed"));
            dbResult.push_back(Pair("progress", lastProgress));
        }
    } else {
        dbResult.push_back(Pair("status", "not found"));
        dbResult.push_back(Pair("size", 0));
        dbResult.push_back(Pair("progress", 0));
    }
    result.push_back(Pair("db.log", dbResult));

    // DO NOT re-enable logging - keep it disabled so no new debug.log is created

    return result;
}

UniValue shredonion(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "shredonion\n"
            "\nSecurely destroy the Tor onion service private key file.\n"
            "\nThis command securely wipes the 'onion_v3_private_key' file\n"
            "in the data directory using a 3-pass overwrite pattern:\n"
            "  Pass 1: Overwrite with 0xFF (all 1s)\n"
            "  Pass 2: Overwrite with 0xAA (10101010 pattern)\n"
            "  Pass 3: Overwrite with 0x00 (all 0s)\n"
            "\nAfter overwriting, the file is renamed to obscure the original\n"
            "filename, then deleted.\n"
            "\nWARNING: This operation is irreversible! Your node will generate\n"
            "a new .onion address on next restart with Tor enabled.\n"
            "\nResult:\n"
            "{\n"
            "  \"onion_v3_private_key\": { \"status\": \"shredded\"|\"not found\"|\"failed\", \"size\": n, \"progress\": 100 }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("shredonion", "")
            + HelpExampleRpc("shredonion", "")
        );

    UniValue result(UniValue::VOBJ);
    boost::filesystem::path dataDir = GetDataDir();
    boost::filesystem::path onionKeyPath = dataDir / "onion_v3_private_key";

    UniValue onionResult(UniValue::VOBJ);

    if (boost::filesystem::exists(onionKeyPath)) {
        uintmax_t fileSize = boost::filesystem::file_size(onionKeyPath);
        onionResult.push_back(Pair("size", (int64_t)fileSize));
        
        int lastProgress = -1;
        auto progressCb = [&lastProgress](int progress) {
            lastProgress = progress;
        };
        
        if (SecureShredFile(onionKeyPath, progressCb)) {
            onionResult.push_back(Pair("status", "shredded"));
            onionResult.push_back(Pair("progress", 100));
        } else {
            onionResult.push_back(Pair("status", "failed"));
            onionResult.push_back(Pair("progress", lastProgress));
        }
    } else {
        onionResult.push_back(Pair("status", "not found"));
        onionResult.push_back(Pair("size", 0));
        onionResult.push_back(Pair("progress", 0));
    }
    
    result.push_back(Pair("onion_v3_private_key", onionResult));

    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getinfo",                &getinfo,                true  }, /* uses wallet if enabled */
    { "util",               "validateaddress",        &validateaddress,        true  }, /* uses wallet if enabled */
    { "util",               "z_validateaddress",      &z_validateaddress,      true  }, /* uses wallet if enabled */
    { "util",               "createmultisig",         &createmultisig,         true  },
    { "util",               "verifymessage",          &verifymessage,          true  },
    
    /* Privacy commands */
    { "privacy",            "shredlogs",              &shredlogs,              true  },
    { "privacy",            "shredonion",             &shredonion,             true  },

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            true  },
};

void RegisterMiscRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
