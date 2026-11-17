// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Wallet token guard: outputs that carry ZSLP tokens or a mint baton must
// never be picked as ordinary funds. The SLP messages here are built with
// the vendored Z23 builder (through c23/services/glue/zcl_token_guard.h),
// the same code that built the messages on mainnet.

#include <gtest/gtest.h>

#include "script/standard.h" // coincontrol.h needs CTxDestination and does not include it
#include "chain.h"
#include "chainparams.h"
#include "coincontrol.h"
#include "core_io.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "primitives/block.h"
#include "random.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "streams.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "version.h"
#include "clientversion.h"
#include "wallet/asyncrpcoperation_sendmany.h"
#include "wallet/tokenguard.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "zcash/Address.hpp"

#include "c23/services/glue/zcl_token_guard.h"

#include <boost/filesystem.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

extern UniValue listunspent(const UniValue& params, bool fHelp);
extern UniValue fundrawtransaction(const UniValue& params, bool fHelp);
extern UniValue z_shieldcoinbase(const UniValue& params, bool fHelp);
extern UniValue z_mergetoaddress(const UniValue& params, bool fHelp);
extern bool fExperimentalMode;

namespace {

const CAmount DUST = 546;

// ---- SLP message builders (vendored Z23 builder) -------------------------

CScript SlpGenesis(unsigned char baton, uint64_t qty)
{
    unsigned char buf[256];
    size_t n = zcl_token_guard_build_genesis(buf, sizeof(buf), "TG", "Token Guard", "", NULL, 0, baton, qty);
    EXPECT_GT(n, 0u);
    return CScript(buf, buf + n);
}

// SLP carries the token id in wire order: the byte-reverse of the internal txid.
std::vector<unsigned char> WireId(const uint256& txid)
{
    std::vector<unsigned char> v(txid.begin(), txid.end());
    std::reverse(v.begin(), v.end());
    return v;
}

CScript SlpMint(const uint256& genesisTxid, unsigned char baton, uint64_t qty)
{
    unsigned char buf[256];
    std::vector<unsigned char> id = WireId(genesisTxid);
    size_t n = zcl_token_guard_build_mint(buf, sizeof(buf), &id[0], baton, qty);
    EXPECT_GT(n, 0u);
    return CScript(buf, buf + n);
}

CScript SlpSend(const uint256& genesisTxid, const std::vector<uint64_t>& quantities)
{
    unsigned char buf[512];
    std::vector<unsigned char> id = WireId(genesisTxid);
    size_t n = zcl_token_guard_build_send(buf, sizeof(buf), &id[0], &quantities[0], (int)quantities.size());
    EXPECT_GT(n, 0u);
    return CScript(buf, buf + n);
}

CScript ScriptFromHex(const std::string& hex)
{
    std::vector<unsigned char> v = ParseHex(hex);
    return CScript(v.begin(), v.end());
}

std::string ScriptHex(const CScript& s)
{
    return HexStr(s.begin(), s.end());
}

// A transaction funded by somebody else: one input the wallet knows nothing about.
CMutableTransaction ForeignTx(const std::vector<CTxOut>& vout)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(GetRandHash(), 0);
    mtx.vout = vout;
    return mtx;
}

CMutableTransaction CoinbaseTx(int nHeight, const std::vector<CTxOut>& vout)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    mtx.vout = vout;
    return mtx;
}

std::vector<unsigned char> Roles(const CTransaction& tx)
{
    std::vector<unsigned char> v;
    TokenGuardClassify(tx, v);
    return v;
}

std::string RpcErrorMessage(const UniValue& objError)
{
    return find_value(objError, "message").get_str();
}

// ---- fixture -------------------------------------------------------------

class TokenGuardTest : public ::testing::Test {
protected:
    static const int CHAIN_HEIGHT = 200;

    CWallet* wallet;
    boost::filesystem::path pathDataDir;
    std::string strPreviousDataDir;
    std::string walletFile;
    CKeyID keyId;
    CScript scriptMine;
    CScript scriptOther;
    std::string addrMine;
    std::string addrOther;

    std::vector<CBlockIndex> chain;
    uint256 blockHash;
    uint256 dummyHash;
    bool fChainUp;

    // outpoints the guard must protect, and ordinary outpoints of this wallet
    std::set<COutPoint> protectedOutpoints;
    std::set<COutPoint> ordinaryOutpoints;
    CAmount nProtectedValue;
    CAmount nOrdinaryValue;

    // scenario txids
    uint256 txidFund, txidGenesis, txidMint, txidSend, txidNotSlp, txidLate;

    TokenGuardTest() : wallet(NULL), fChainUp(false), nProtectedValue(0), nOrdinaryValue(0) {}

    virtual void SetUp()
    {
        SelectParams(CBaseChainParams::REGTEST);

        // One Berkeley DB environment serves the whole gtest binary and stays
        // wherever the first wallet test opened it. Shut it down and start a
        // new one in a fresh temp datadir, so this test's wallet files live
        // where GetDataDir() says they do.
        ResetWalletEnvironment();
        pathDataDir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("zcl-tokenguard-%%%%-%%%%-%%%%");
        boost::filesystem::create_directories(pathDataDir);
        strPreviousDataDir = mapArgs.count("-datadir") ? mapArgs["-datadir"] : "";
        mapArgs["-datadir"] = pathDataDir.string();
        ClearDatadirCache();
        mapArgs["-keypool"] = "3";

        walletFile = boost::filesystem::unique_path("tokenguard-%%%%-%%%%.dat").string();
        wallet = OpenWallet(walletFile);

        CPubKey pubkey;
        ASSERT_TRUE(wallet->GetKeyFromPool(pubkey));
        keyId = pubkey.GetID();
        scriptMine = GetScriptForDestination(keyId);
        addrMine = EncodeDestination(keyId);

        CKey other;
        other.MakeNewKey(true);
        scriptOther = GetScriptForDestination(other.GetPubKey().GetID());
        addrOther = EncodeDestination(other.GetPubKey().GetID());

        dummyHash = GetRandHash();
    }

    virtual void TearDown()
    {
        pwalletMain = NULL;
        if (fChainUp) {
            LOCK(cs_main);
            chainActive.SetTip(NULL);
            mapBlockIndex.erase(blockHash);
        }
        delete wallet;
        wallet = NULL;
        ResetWalletEnvironment();
        boost::system::error_code ec;
        boost::filesystem::remove_all(pathDataDir, ec);
        mapArgs.erase("-keypool");
        mapArgs.erase("-zmergetoaddress");
        // Never leave -datadir unset: a later test that opens a wallet file
        // would then fall back to the user's real data directory.
        if (!strPreviousDataDir.empty())
            mapArgs["-datadir"] = strPreviousDataDir;
        ClearDatadirCache();
        fExperimentalMode = false;
    }

    // Close the Berkeley DB environment (flushing every wallet file) and
    // leave a fresh, unopened one behind. The next wallet that is opened
    // creates the environment in the then-current datadir, exactly as a
    // newly started process would.
    static void ResetWalletEnvironment()
    {
        bitdb.Flush(true);
        bitdb.Reset();
    }

    static CWallet* OpenWallet(const std::string& file)
    {
        CWallet* w = new CWallet(file);
        bool fFirstRun = true;
        EXPECT_EQ(DB_LOAD_OK, w->LoadWallet(fFirstRun));
        return w;
    }

    CTxOut Mine(CAmount nValue) const { return CTxOut(nValue, scriptMine); }
    CTxOut Data(const CScript& script) const { return CTxOut(0, script); }

    // Put txs in one block at height 0 of a CHAIN_HEIGHT-high chain (so
    // every tx is deeply confirmed and coinbase outputs are mature) and add
    // them to the wallet, on disk, the way a block connection would.
    void Confirm(const std::vector<CMutableTransaction>& txs)
    {
        CBlock block;
        for (size_t i = 0; i < txs.size(); i++)
            block.vtx.push_back(CTransaction(txs[i]));
        block.hashMerkleRoot = block.BuildMerkleTree();
        blockHash = block.GetHash();

        LOCK2(cs_main, wallet->cs_wallet);
        ASSERT_EQ(-1, chainActive.Height()) << "another test left a chain behind";
        chain.assign(CHAIN_HEIGHT + 1, CBlockIndex());
        chain[0] = CBlockIndex(block);
        BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(blockHash, &chain[0])).first;
        for (int h = 0; h <= CHAIN_HEIGHT; h++) {
            chain[h].nHeight = h;
            chain[h].pprev = h ? &chain[h - 1] : NULL;
            chain[h].phashBlock = h ? &dummyHash : &mi->first;
        }
        chainActive.SetTip(&chain[CHAIN_HEIGHT]);
        fChainUp = true;

        CWalletDB walletdb(wallet->strWalletFile);
        for (size_t i = 0; i < block.vtx.size(); i++) {
            CWalletTx wtx(wallet, block.vtx[i]);
            wtx.SetMerkleBranch(block);
            ASSERT_TRUE(wallet->AddToWallet(wtx, false, &walletdb));
        }
    }

    void Expect(const uint256& txid, unsigned int n, CAmount nValue, bool fProtected)
    {
        if (fProtected) {
            protectedOutpoints.insert(COutPoint(txid, n));
            nProtectedValue += nValue;
        } else {
            ordinaryOutpoints.insert(COutPoint(txid, n));
            nOrdinaryValue += nValue;
        }
    }

    // GENESIS, MINT and SEND transactions paying token dust, baton dust and
    // ordinary coins to ONE address of this wallet, plus look-alikes.
    void StandardScenario()
    {
        std::vector<CTxOut> v;

        // ordinary coins
        v.clear();
        v.push_back(Mine(1 * COIN));
        v.push_back(Mine(2 * COIN));
        CMutableTransaction fund = ForeignTx(v);

        // GENESIS: vout[1] = 1000 tokens, vout[2] = mint baton, vout[3] = ordinary change
        v.clear();
        v.push_back(Data(SlpGenesis(2, 1000)));
        v.push_back(Mine(DUST));
        v.push_back(Mine(DUST));
        v.push_back(Mine(COIN / 2));
        CMutableTransaction genesis = ForeignTx(v);
        txidGenesis = genesis.GetHash();

        // MINT: vout[1] = 500 tokens, vout[2] = ordinary, vout[3] = mint baton
        v.clear();
        v.push_back(Data(SlpMint(txidGenesis, 3, 500)));
        v.push_back(Mine(DUST));
        v.push_back(Mine(COIN / 4));
        v.push_back(Mine(DUST));
        CMutableTransaction mint = ForeignTx(v);

        // SEND: vout[1] = 400, vout[2] = 0 (zero quantity: still protected, as in Z23), vout[3] = 600, vout[4] = ordinary
        std::vector<uint64_t> q;
        q.push_back(400);
        q.push_back(0);
        q.push_back(600);
        v.clear();
        v.push_back(Data(SlpSend(txidGenesis, q)));
        v.push_back(Mine(DUST));
        v.push_back(Mine(DUST));
        v.push_back(Mine(DUST));
        v.push_back(Mine(COIN / 8));
        CMutableTransaction send = ForeignTx(v);

        // An OP_RETURN that is not an SLP message: its dust is ordinary dust.
        v.clear();
        v.push_back(Data(CScript() << OP_RETURN << ParseHex("68656c6c6f20776f726c64")));
        v.push_back(Mine(DUST));
        v.push_back(Mine(DUST));
        CMutableTransaction notSlp = ForeignTx(v);

        // The message is the first OP_RETURN but not vout[0] (the reading
        // that is not settled): quantities {7, 8} name vout[1] (the message
        // output itself, unspendable) and vout[2]. vout[0] is ordinary.
        q.clear();
        q.push_back(7);
        q.push_back(8);
        v.clear();
        v.push_back(Mine(DUST));
        v.push_back(Data(SlpSend(txidGenesis, q)));
        v.push_back(Mine(DUST));
        CMutableTransaction late = ForeignTx(v);

        txidFund = fund.GetHash();
        txidMint = mint.GetHash();
        txidSend = send.GetHash();
        txidNotSlp = notSlp.GetHash();
        txidLate = late.GetHash();

        std::vector<CMutableTransaction> txs;
        txs.push_back(fund);
        txs.push_back(genesis);
        txs.push_back(mint);
        txs.push_back(send);
        txs.push_back(notSlp);
        txs.push_back(late);
        Confirm(txs);

        Expect(txidFund, 0, 1 * COIN, false);
        Expect(txidFund, 1, 2 * COIN, false);
        Expect(txidGenesis, 1, DUST, true);
        Expect(txidGenesis, 2, DUST, true);
        Expect(txidGenesis, 3, COIN / 2, false);
        Expect(txidMint, 1, DUST, true);
        Expect(txidMint, 2, COIN / 4, false);
        Expect(txidMint, 3, DUST, true);
        Expect(txidSend, 1, DUST, true);
        Expect(txidSend, 2, DUST, true);
        Expect(txidSend, 3, DUST, true);
        Expect(txidSend, 4, COIN / 8, false);
        Expect(txidNotSlp, 1, DUST, false);
        Expect(txidNotSlp, 2, DUST, false);
        Expect(txidLate, 0, DUST, false);
        Expect(txidLate, 2, DUST, true);

        ASSERT_EQ(8u, protectedOutpoints.size());
        ASSERT_EQ(8u, ordinaryOutpoints.size());
    }

    // Create (not commit) a payment and return its inputs.
    bool Create(CWallet* w, CAmount nAmount, bool fSubtractFee, const CCoinControl* coinControl,
                std::set<COutPoint>& inputsRet, std::string& strFailRet)
    {
        std::vector<CRecipient> vecSend;
        CRecipient recipient = {scriptOther, nAmount, fSubtractFee};
        vecSend.push_back(recipient);
        CWalletTx wtx;
        CReserveKey reservekey(w);
        CAmount nFee = 0;
        int nChangePos = -1;
        strFailRet.clear();
        inputsRet.clear();
        bool ok = w->CreateTransaction(vecSend, wtx, reservekey, nFee, nChangePos, strFailRet, coinControl, true);
        if (ok) {
            for (size_t i = 0; i < wtx.vin.size(); i++)
                inputsRet.insert(wtx.vin[i].prevout);
        }
        return ok;
    }

    size_t CountProtected(const std::set<COutPoint>& inputs) const
    {
        size_t n = 0;
        for (std::set<COutPoint>::const_iterator it = inputs.begin(); it != inputs.end(); ++it)
            n += protectedOutpoints.count(*it);
        return n;
    }

    // Every automatic spend path of CWallet::CreateTransaction, on wallet w.
    void ExpectAutomaticSelectionProtected(CWallet* w)
    {
        std::set<COutPoint> inputs;
        std::string strFail;

        // Spend EVERYTHING that is ordinary, to the zatoshi. It succeeds, it
        // uses all nine ordinary outputs (non-SLP dust included, which shows
        // this test would notice dust being picked) and no protected one.
        ASSERT_TRUE(Create(w, nOrdinaryValue, true, NULL, inputs, strFail)) << strFail;
        EXPECT_EQ(ordinaryOutpoints, inputs);
        EXPECT_EQ(0u, CountProtected(inputs));

        // Selection is randomized: many targets, never a protected input.
        for (int i = 0; i < 60; i++) {
            CAmount nTarget = 1000 + (CAmount)GetRand(nOrdinaryValue - 200000);
            ASSERT_TRUE(Create(w, nTarget, false, NULL, inputs, strFail)) << strFail << " target " << nTarget;
            ASSERT_FALSE(inputs.empty());
            ASSERT_EQ(0u, CountProtected(inputs)) << "target " << nTarget;
        }

        // The wallet's balance still counts the token dust, so this amount
        // looks affordable; the error says why it is not.
        EXPECT_FALSE(Create(w, nOrdinaryValue + 1000, true, NULL, inputs, strFail));
        EXPECT_EQ(0u, strFail.find("Insufficient funds")) << strFail;
        EXPECT_NE(std::string::npos, strFail.find("7 token-bearing outputs holding 0.00003822")) << strFail;
        EXPECT_NE(std::string::npos, strFail.find("would burn the ZSLP tokens or mint baton")) << strFail;
    }
};

const int TokenGuardTest::CHAIN_HEIGHT;

// ---- classifier ----------------------------------------------------------

TEST(TokenGuardClassify, BuilderBytesArePinned)
{
    // What the vendored builder emits, byte for byte (empty fields are
    // OP_PUSHDATA1 0x00, as on mainnet).
    EXPECT_EQ("6a04534c500001010747454e455349530254470b546f6b656e2047756172644c004c0001000102080000"
              "0000000003e8",
              ScriptHex(SlpGenesis(2, 1000)));

    unsigned char id[32];
    for (int i = 0; i < 32; i++)
        id[i] = (unsigned char)i;
    unsigned char buf[256];
    size_t n = zcl_token_guard_build_mint(buf, sizeof(buf), id, 3, 500);
    EXPECT_EQ("6a04534c50000101044d494e5420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
              "01030800000000000001f4",
              HexStr(buf, buf + n));

    uint64_t q[3] = {400, 0, 600};
    n = zcl_token_guard_build_send(buf, sizeof(buf), id, q, 3);
    EXPECT_EQ("6a04534c500001010453454e4420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
              "080000000000000190080000000000000000080000000000000258",
              HexStr(buf, buf + n));

    // SEND takes 1..19 quantities; the builder refuses anything else.
    uint64_t many[20] = {0};
    EXPECT_EQ(0u, zcl_token_guard_build_send(buf, sizeof(buf), id, many, 0));
    EXPECT_EQ(0u, zcl_token_guard_build_send(buf, sizeof(buf), id, many, 20));
}

TEST(TokenGuardClassify, GenesisMintSend)
{
    CScript dust = GetScriptForDestination(CKeyID(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314"))));
    std::vector<CTxOut> v;

    // GENESIS with baton at vout[2]
    v.push_back(CTxOut(0, SlpGenesis(2, 1000)));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(COIN, dust));
    CTransaction genesis(ForeignTx(v));
    std::vector<unsigned char> r = Roles(genesis);
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_NONE, r[0]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_MINT_BATON, r[2]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[3]);
    EXPECT_EQ(TOKEN_ROLE_MINT_BATON, TokenGuardOutputRole(genesis, 2));
    EXPECT_EQ(TOKEN_ROLE_NONE, TokenGuardOutputRole(genesis, 99));

    // GENESIS without baton: only vout[1]
    v[0] = CTxOut(0, SlpGenesis(0, 1000));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[2]);

    // GENESIS of zero tokens with a baton: vout[1] is still assigned to the token
    // (quantity zero is protected, as in Z23) and so is the baton
    v[0] = CTxOut(0, SlpGenesis(3, 0));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[2]);
    EXPECT_EQ(TOKEN_ROLE_MINT_BATON, r[3]);

    // GENESIS of zero tokens without baton still protects vout[1]
    v[0] = CTxOut(0, SlpGenesis(0, 0));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[2]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[3]);

    // A baton index past the last output protects nothing extra and reads nothing out of range
    v[0] = CTxOut(0, SlpGenesis(200, 5));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[2]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[3]);

    // MINT with the baton moving to vout[3]
    v[0] = CTxOut(0, SlpMint(genesis.GetHash(), 3, 500));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[2]);
    EXPECT_EQ(TOKEN_ROLE_MINT_BATON, r[3]);

    // SEND: quantity i rides on vout[i+1]; a zero quantity is still protected
    // (as in Z23); quantities naming outputs that do not exist are ignored
    std::vector<uint64_t> q;
    q.push_back(400);
    q.push_back(0);
    q.push_back(600);
    q.push_back(9);
    q.push_back(9);
    v[0] = CTxOut(0, SlpSend(genesis.GetHash(), q));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[2]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[3]);

    // SEND with bytes after the last quantity still parses (mainnet has such
    // transactions) and is still protected
    CScript trailing = SlpSend(genesis.GetHash(), q);
    trailing << ParseHex("6e6f64652e6578616d706c65");
    v[0] = CTxOut(0, trailing);
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
}

TEST(TokenGuardClassify, ZeroQuantityOutputsAreProtected)
{
    // The reviewer's rule, and Z23's: an output the message assigns to the token
    // is protected whatever its quantity, so a zero-quantity slot of a SEND, and
    // the vout[1] of a GENESIS or MINT of zero, are never spent as ordinary funds.
    CScript dust = GetScriptForDestination(CKeyID(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314"))));
    std::vector<uint64_t> q;
    q.push_back(0);
    q.push_back(0);
    q.push_back(0);
    std::vector<CTxOut> v;
    v.push_back(CTxOut(0, SlpSend(GetRandHash(), q)));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    std::vector<unsigned char> r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_NONE, r[0]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[2]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[3]);

    v[0] = CTxOut(0, SlpMint(GetRandHash(), 0, 0));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[2]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[3]);

    // an output the message does not name stays ordinary
    v.push_back(CTxOut(DUST, dust));
    v[0] = CTxOut(0, SlpSend(GetRandHash(), q));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(5u, r.size());
    EXPECT_EQ(TOKEN_ROLE_NONE, r[4]);
}

TEST(TokenGuardClassify, MessagePositionUnion)
{
    CScript dust = GetScriptForDestination(CKeyID(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314"))));
    std::vector<uint64_t> q;
    q.push_back(7);
    q.push_back(8);
    q.push_back(9);
    CScript send = SlpSend(GetRandHash(), q);

    // Message at vout[0] (both readings agree).
    std::vector<CTxOut> v;
    v.push_back(CTxOut(0, send));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    std::vector<unsigned char> r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[2]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[3]);

    // Message is the first OP_RETURN but sits at vout[2]: protected under
    // the "first OP_RETURN at any position" reading, so protected here. The
    // message output itself is never reported as token-bearing.
    v.clear();
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(0, send));
    v.push_back(CTxOut(DUST, dust));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(4u, r.size());
    EXPECT_EQ(TOKEN_ROLE_NONE, r[0]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[2]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[3]);

    // Only the FIRST OP_RETURN is a candidate: a non-SLP OP_RETURN ahead of
    // an SLP one means no reading calls this an SLP transaction.
    v.clear();
    v.push_back(CTxOut(0, CScript() << OP_RETURN << ParseHex("00ff")));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(0, send));
    v.push_back(CTxOut(DUST, dust));
    EXPECT_TRUE(Roles(CTransaction(ForeignTx(v))).empty());
}

TEST(TokenGuardClassify, NotSlpIsNotAffected)
{
    CScript dust = GetScriptForDestination(CKeyID(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314"))));
    CScript good = SlpGenesis(2, 1000);

    std::vector<CScript> bad;
    // no OP_RETURN at all is covered below; these all start with OP_RETURN
    bad.push_back(CScript() << OP_RETURN);
    bad.push_back(CScript() << OP_RETURN << ParseHex("68656c6c6f"));
    // right lokad, nothing else
    bad.push_back(ScriptFromHex("6a04534c5000"));
    // truncated in the middle of the last field
    bad.push_back(CScript(good.begin(), good.end() - 3));
    // wrong lokad ("SLP\x01")
    {
        CScript s = good;
        s[5] = 0x01;
        bad.push_back(s);
    }
    // token type 2
    {
        CScript s = good;
        s[7] = 0x02;
        bad.push_back(s);
    }
    // unknown transaction type "GENESIX"
    {
        CScript s = good;
        s[15] = 'X';
        bad.push_back(s);
    }
    // the Z23 fuzz seed "truncated lokad"
    bad.push_back(ScriptFromHex("6a04534c"));
    // SEND with no quantities
    bad.push_back(ScriptFromHex("6a04534c500001010453454e4420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    // a P2PKH script that merely contains the bytes of a message is not an OP_RETURN
    {
        CScript s = dust;
        s.insert(s.end(), good.begin(), good.end());
        bad.push_back(s);
    }

    for (size_t i = 0; i < bad.size(); i++) {
        std::vector<CTxOut> v;
        v.push_back(CTxOut(0, bad[i]));
        v.push_back(CTxOut(DUST, dust));
        v.push_back(CTxOut(DUST, dust));
        v.push_back(CTxOut(DUST, dust));
        EXPECT_TRUE(Roles(CTransaction(ForeignTx(v))).empty()) << "case " << i << " " << ScriptHex(bad[i]);
    }

    // Control: the unmodified message in the same transaction shape IS protected.
    std::vector<CTxOut> v;
    v.push_back(CTxOut(0, good));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    EXPECT_EQ(3u, Roles(CTransaction(ForeignTx(v))).size());

    // No OP_RETURN output, one output, no outputs.
    v.clear();
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    EXPECT_TRUE(Roles(CTransaction(ForeignTx(v))).empty());
    v.clear();
    v.push_back(CTxOut(0, good));
    EXPECT_TRUE(Roles(CTransaction(ForeignTx(v))).empty());
    v.clear();
    EXPECT_TRUE(Roles(CTransaction(ForeignTx(v))).empty());
}

TEST(TokenGuardClassify, Z23FuzzSeeds)
{
    // tests/harness/fuzz_seeds/overlay/slp_*.bin in Z23 (first byte of each
    // seed file is the fuzz harness selector and is not part of the script).
    CScript dust = GetScriptForDestination(CKeyID(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314"))));
    std::vector<CTxOut> v;
    v.push_back(CTxOut(0, ScriptFromHex("6a04534c500001010747454e4553495303545354045465737400000108000800000000000003e8")));
    v.push_back(CTxOut(DUST, dust));
    v.push_back(CTxOut(DUST, dust));
    std::vector<unsigned char> r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(3u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_NONE, r[2]);

    v[0] = CTxOut(0, ScriptFromHex("6a04534c500001010453454e44204141414141414141414141414141414141414141414141414141414141414141"
                                   "080000000000000001080000000000000002"));
    r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(3u, r.size());
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[1]);
    EXPECT_EQ(TOKEN_ROLE_TOKEN, r[2]);
}

TEST(TokenGuardClassify, ManyOutputs)
{
    // The baton index is one byte, so nothing past vout[255] can be named.
    CScript dust = GetScriptForDestination(CKeyID(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314"))));
    std::vector<CTxOut> v;
    v.push_back(CTxOut(0, SlpGenesis(255, 1)));
    for (int i = 1; i < 400; i++)
        v.push_back(CTxOut(DUST, dust));
    std::vector<unsigned char> r = Roles(CTransaction(ForeignTx(v)));
    ASSERT_EQ(400u, r.size());
    for (size_t i = 0; i < r.size(); i++) {
        unsigned char want = i == 1 ? TOKEN_ROLE_TOKEN : i == 255 ? TOKEN_ROLE_MINT_BATON : TOKEN_ROLE_NONE;
        ASSERT_EQ(want, r[i]) << "vout " << i;
    }
}

// ---- wallet --------------------------------------------------------------

TEST_F(TokenGuardTest, ListUnspentAndBalanceUnchangedApartFromNewField)
{
    StandardScenario();

    // AvailableCoins is untouched: all sixteen outputs are there.
    std::vector<COutput> vCoins;
    wallet->AvailableCoins(vCoins, true, NULL, true, true);
    EXPECT_EQ(16u, vCoins.size());

    // The balance counts the token dust exactly as before.
    EXPECT_EQ(nOrdinaryValue + nProtectedValue, wallet->GetBalance());
    EXPECT_EQ(387500000 + 3 * DUST, nOrdinaryValue);
    EXPECT_EQ(8 * DUST, nProtectedValue);

    pwalletMain = wallet;
    UniValue list = listunspent(UniValue(UniValue::VARR), false);
    ASSERT_TRUE(list.isArray());
    ASSERT_EQ(16u, list.size());

    std::set<std::string> expectedKeys;
    expectedKeys.insert("txid");
    expectedKeys.insert("vout");
    expectedKeys.insert("generated");
    expectedKeys.insert("address");
    expectedKeys.insert("scriptPubKey");
    expectedKeys.insert("amount");
    expectedKeys.insert("confirmations");
    expectedKeys.insert("spendable");
    expectedKeys.insert("tokenbearing");

    CAmount nListed = 0;
    size_t nFlagged = 0;
    for (size_t i = 0; i < list.size(); i++) {
        const UniValue& o = list[i];
        std::vector<std::string> keys = o.getKeys();
        EXPECT_EQ(expectedKeys, std::set<std::string>(keys.begin(), keys.end()));
        // the new field is the last one: every pre-existing field keeps its position
        EXPECT_EQ("tokenbearing", keys.back());

        COutPoint outpoint(uint256S(find_value(o, "txid").get_str()), find_value(o, "vout").get_int());
        bool fExpected = protectedOutpoints.count(outpoint) != 0;
        EXPECT_TRUE(fExpected || ordinaryOutpoints.count(outpoint)) << outpoint.ToString();
        ASSERT_TRUE(find_value(o, "tokenbearing").isBool());
        EXPECT_EQ(fExpected, find_value(o, "tokenbearing").get_bool()) << outpoint.ToString();
        EXPECT_TRUE(find_value(o, "spendable").get_bool());
        EXPECT_EQ(addrMine, find_value(o, "address").get_str());
        nFlagged += fExpected ? 1 : 0;
        nListed += AmountFromValue(find_value(o, "amount"));
    }
    EXPECT_EQ(7u, nFlagged);
    EXPECT_EQ(wallet->GetBalance(), nListed);
}

TEST_F(TokenGuardTest, AutomaticSelectionNeverPicksTokenOutputs)
{
    StandardScenario();
    ExpectAutomaticSelectionProtected(wallet);
}

TEST_F(TokenGuardTest, OnlyTokenDustLeftGivesSensibleError)
{
    // A wallet that holds nothing but a token output and a baton.
    std::vector<CTxOut> v;
    v.push_back(Data(SlpGenesis(2, 1000)));
    v.push_back(Mine(DUST));
    v.push_back(Mine(DUST));
    std::vector<CMutableTransaction> txs;
    txs.push_back(ForeignTx(v));
    Confirm(txs);

    EXPECT_EQ(2 * DUST, wallet->GetBalance());

    std::set<COutPoint> inputs;
    std::string strFail;
    EXPECT_FALSE(Create(wallet, 600, false, NULL, inputs, strFail));
    EXPECT_EQ("Insufficient funds (2 token-bearing outputs holding 0.00001092 are protected and were not used: "
              "spending them as ordinary funds would burn the ZSLP tokens or mint baton they carry)",
              strFail);

    // z_sendmany gathers its own inputs (smallest first): nothing to gather.
    pwalletMain = wallet;
    std::vector<SendManyRecipient> recipients;
    recipients.push_back(SendManyRecipient(addrOther, 600, ""));
    CMutableTransaction mtx;
    std::shared_ptr<AsyncRPCOperation_sendmany> op(new AsyncRPCOperation_sendmany(boost::none, mtx, addrMine, recipients, {}, 1));
    TEST_FRIEND_AsyncRPCOperation_sendmany proxy(op);
    EXPECT_FALSE(proxy.find_utxos(false));
    EXPECT_FALSE(proxy.find_utxos(true));
    try {
        proxy.main_impl();
        ADD_FAILURE() << "z_sendmany found token dust to spend";
    } catch (const UniValue& objError) {
        std::string msg = RpcErrorMessage(objError);
        EXPECT_EQ(0u, msg.find("Could not find any non-coinbase UTXOs to spend.")) << msg;
        EXPECT_NE(std::string::npos, msg.find("token-bearing outputs holding 0.00001092")) << msg;
    }

    // z_mergetoaddress: nothing to merge either.
    fExperimentalMode = true;
    mapArgs["-zmergetoaddress"] = "1";
    UniValue from(UniValue::VARR);
    from.push_back("ANY_TADDR");
    UniValue params(UniValue::VARR);
    params.push_back(from);
    params.push_back(addrOther);
    try {
        z_mergetoaddress(params, false);
        ADD_FAILURE() << "z_mergetoaddress found token dust to merge";
    } catch (const UniValue& objError) {
        std::string msg = RpcErrorMessage(objError);
        EXPECT_EQ(0u, msg.find("Could not find any funds to merge.")) << msg;
        EXPECT_NE(std::string::npos, msg.find("2 token-bearing outputs holding 0.00001092")) << msg;
    }
}

TEST_F(TokenGuardTest, SendManyGathersOrdinaryCoinsOnly)
{
    StandardScenario();
    pwalletMain = wallet;

    std::vector<SendManyRecipient> recipients;
    recipients.push_back(SendManyRecipient(addrOther, COIN, ""));
    CMutableTransaction mtx;
    std::shared_ptr<AsyncRPCOperation_sendmany> op(new AsyncRPCOperation_sendmany(boost::none, mtx, addrMine, recipients, {}, 1));
    TEST_FRIEND_AsyncRPCOperation_sendmany proxy(op);
    ASSERT_TRUE(proxy.find_utxos(false));
    std::set<COutPoint> gathered = proxy.gathered_utxos();
    EXPECT_EQ(ordinaryOutpoints, gathered);
    EXPECT_EQ(0u, CountProtected(gathered));
}

TEST_F(TokenGuardTest, ExplicitInputsAreRefusedUnlessOverridden)
{
    StandardScenario();
    std::set<COutPoint> inputs;
    std::string strFail;
    const COutPoint coin(txidFund, 0);        // 1 ZCL, ordinary
    const COutPoint token(txidGenesis, 1);    // carries 1000 tokens
    const COutPoint baton(txidGenesis, 2);    // carries the mint baton

    // Coin control, "use exactly these inputs".
    {
        CCoinControl cc;
        cc.Select(coin);
        ASSERT_TRUE(Create(wallet, COIN / 2, false, &cc, inputs, strFail)) << strFail;
        EXPECT_EQ(1u, inputs.size());
        EXPECT_EQ(1u, inputs.count(coin));

        cc.Select(baton);
        EXPECT_FALSE(Create(wallet, COIN / 2, false, &cc, inputs, strFail));
        EXPECT_EQ(0u, strFail.find("Input " + txidGenesis.GetHex() + ":2 carries ZSLP tokens or a mint baton and is protected")) << strFail;
        EXPECT_NE(std::string::npos, strFail.find("request the token-input override explicitly")) << strFail;

        cc.fAllowTokenOutputs = true;
        ASSERT_TRUE(Create(wallet, COIN / 2, false, &cc, inputs, strFail)) << strFail;
        EXPECT_EQ(2u, inputs.size());
        EXPECT_EQ(1u, inputs.count(coin));
        EXPECT_EQ(1u, inputs.count(baton));
    }

    // Coin control, "these inputs plus whatever else is needed" (the preset
    // path, which does not go through AvailableCoins).
    {
        CCoinControl cc;
        cc.fAllowOtherInputs = true;
        cc.Select(token);
        EXPECT_FALSE(Create(wallet, COIN / 2, false, &cc, inputs, strFail));
        EXPECT_EQ(0u, strFail.find("Input " + txidGenesis.GetHex() + ":1 carries ZSLP tokens")) << strFail;

        // The override admits the ONE input that was named. Everything the
        // wallet adds on its own is still ordinary.
        cc.fAllowTokenOutputs = true;
        for (int i = 0; i < 20; i++) {
            ASSERT_TRUE(Create(wallet, 1000 + (CAmount)GetRand(3 * COIN), false, &cc, inputs, strFail)) << strFail;
            EXPECT_EQ(1u, inputs.count(token));
            EXPECT_EQ(1u, CountProtected(inputs));
            EXPECT_GE(inputs.size(), 2u);
        }
    }

    // CWallet::FundTransaction with a token input already in the transaction.
    {
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(token));
        mtx.vout.push_back(CTxOut(COIN / 2, scriptOther));
        CAmount nFee = 0;
        int nChangePos = -1;

        CMutableTransaction refused(mtx);
        EXPECT_FALSE(wallet->FundTransaction(refused, nFee, nChangePos, strFail));
        EXPECT_EQ(0u, strFail.find("Input " + txidGenesis.GetHex() + ":1 carries ZSLP tokens")) << strFail;

        CMutableTransaction allowed(mtx);
        ASSERT_TRUE(wallet->FundTransaction(allowed, nFee, nChangePos, strFail, true)) << strFail;
        inputs.clear();
        for (size_t i = 0; i < allowed.vin.size(); i++)
            inputs.insert(allowed.vin[i].prevout);
        EXPECT_EQ(1u, inputs.count(token));
        EXPECT_EQ(1u, CountProtected(inputs));
        EXPECT_GE(inputs.size(), 2u);

        // No inputs given: funded with ordinary coins only, flag or no flag.
        for (int pass = 0; pass < 2; pass++) {
            CMutableTransaction bare;
            bare.vout.push_back(CTxOut(nOrdinaryValue - COIN / 100, scriptOther));
            ASSERT_TRUE(wallet->FundTransaction(bare, nFee, nChangePos, strFail, pass == 1)) << strFail;
            inputs.clear();
            for (size_t i = 0; i < bare.vin.size(); i++)
                inputs.insert(bare.vin[i].prevout);
            EXPECT_FALSE(inputs.empty());
            EXPECT_EQ(0u, CountProtected(inputs));
        }
    }

    // The fundrawtransaction RPC: same thing through the public interface.
    {
        pwalletMain = wallet;
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(baton));
        mtx.vout.push_back(CTxOut(COIN / 2, scriptOther));

        UniValue params(UniValue::VARR);
        params.push_back(EncodeHexTx(mtx));
        try {
            fundrawtransaction(params, false);
            ADD_FAILURE() << "fundrawtransaction accepted a baton input without the override";
        } catch (const UniValue& objError) {
            std::string msg = RpcErrorMessage(objError);
            EXPECT_EQ(0u, msg.find("Input " + txidGenesis.GetHex() + ":2 carries ZSLP tokens")) << msg;
        }

        params.push_back(UniValue(false));
        try {
            fundrawtransaction(params, false);
            ADD_FAILURE() << "fundrawtransaction accepted a baton input with allowtokeninputs=false";
        } catch (const UniValue& objError) {
            std::string msg = RpcErrorMessage(objError);
            EXPECT_EQ(0u, msg.find("Input " + txidGenesis.GetHex() + ":2 carries ZSLP tokens")) << msg;
        }

        UniValue paramsAllow(UniValue::VARR);
        paramsAllow.push_back(EncodeHexTx(mtx));
        paramsAllow.push_back(UniValue(true));
        UniValue result;
        try {
            result = fundrawtransaction(paramsAllow, false);
        } catch (const UniValue& objError) {
            FAIL() << "fundrawtransaction with allowtokeninputs=true: " << RpcErrorMessage(objError);
        }
        CTransaction funded;
        ASSERT_TRUE(DecodeHexTx(funded, find_value(result, "hex").get_str()));
        inputs.clear();
        for (size_t i = 0; i < funded.vin.size(); i++)
            inputs.insert(funded.vin[i].prevout);
        EXPECT_EQ(1u, inputs.count(baton));
        EXPECT_EQ(1u, CountProtected(inputs));
        EXPECT_GE(inputs.size(), 2u);
    }

    // Locking and unlocking a token output changes nothing: the protection
    // does not live in the lock set.
    {
        LOCK2(cs_main, wallet->cs_wallet);
        COutPoint t(token);
        wallet->LockCoin(t);
        wallet->UnlockCoin(t);
        wallet->UnlockAllCoins();
    }
    ExpectAutomaticSelectionProtected(wallet);
}

TEST_F(TokenGuardTest, MergeToAddressSkipsTokenOutputs)
{
    StandardScenario();
    pwalletMain = wallet;
    fExperimentalMode = true;
    mapArgs["-zmergetoaddress"] = "1";

    for (int pass = 0; pass < 2; pass++) {
        {
            LOCK2(cs_main, wallet->cs_wallet);
            wallet->UnlockAllCoins();
        }
        UniValue from(UniValue::VARR);
        from.push_back(pass == 0 ? std::string("ANY_TADDR") : addrMine);
        UniValue params(UniValue::VARR);
        params.push_back(from);
        params.push_back(addrOther);

        UniValue result = z_mergetoaddress(params, false);
        EXPECT_EQ(9, find_value(result, "mergingUTXOs").get_int());
        EXPECT_EQ(nOrdinaryValue, AmountFromValue(find_value(result, "mergingTransparentValue")));
        EXPECT_EQ(0, find_value(result, "remainingUTXOs").get_int());

        // The operation locked exactly the inputs it will spend.
        std::vector<COutPoint> vLocked;
        {
            LOCK2(cs_main, wallet->cs_wallet);
            wallet->ListLockedCoins(vLocked);
        }
        std::set<COutPoint> locked(vLocked.begin(), vLocked.end());
        EXPECT_EQ(ordinaryOutpoints, locked);
    }
}

TEST_F(TokenGuardTest, ShieldCoinbaseSkipsTokenBearingCoinbase)
{
    // A coinbase transaction can carry an SLP message like any other.
    std::vector<CTxOut> v;
    v.push_back(Mine(10 * COIN));
    CMutableTransaction cbPlain = CoinbaseTx(1, v);

    v.clear();
    v.push_back(Data(SlpGenesis(2, 5)));
    v.push_back(Mine(6 * COIN));   // block reward output that also carries 5 tokens
    v.push_back(Mine(DUST));       // mint baton
    v.push_back(Mine(1 * COIN));   // ordinary
    CMutableTransaction cbToken = CoinbaseTx(2, v);

    std::vector<CMutableTransaction> txs;
    txs.push_back(cbPlain);
    txs.push_back(cbToken);
    Confirm(txs);

    protectedOutpoints.insert(COutPoint(cbToken.GetHash(), 1));
    protectedOutpoints.insert(COutPoint(cbToken.GetHash(), 2));

    EXPECT_EQ(17 * COIN + DUST, wallet->GetBalance());

    pwalletMain = wallet;
    std::string zaddr = EncodePaymentAddress(libzcash::SproutSpendingKey::random().address());
    UniValue params(UniValue::VARR);
    params.push_back("*");
    params.push_back(zaddr);
    UniValue result = z_shieldcoinbase(params, false);
    EXPECT_EQ(2, find_value(result, "shieldingUTXOs").get_int());
    EXPECT_EQ(11 * COIN, AmountFromValue(find_value(result, "shieldingValue")));
    EXPECT_EQ(0, find_value(result, "remainingUTXOs").get_int());

    std::vector<COutPoint> vLocked;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        wallet->ListLockedCoins(vLocked);
        wallet->UnlockAllCoins();
    }
    std::set<COutPoint> locked(vLocked.begin(), vLocked.end());
    EXPECT_EQ(2u, locked.size());
    EXPECT_EQ(1u, locked.count(COutPoint(cbPlain.GetHash(), 0)));
    EXPECT_EQ(1u, locked.count(COutPoint(cbToken.GetHash(), 3)));
    EXPECT_EQ(0u, CountProtected(locked));

    // Regtest lets coinbase be spent transparently: that path is guarded too.
    std::set<COutPoint> inputs;
    std::string strFail;
    ASSERT_TRUE(Create(wallet, 11 * COIN, true, NULL, inputs, strFail)) << strFail;
    EXPECT_EQ(2u, inputs.size());
    EXPECT_EQ(0u, CountProtected(inputs));
    EXPECT_FALSE(Create(wallet, 11 * COIN + 1000, true, NULL, inputs, strFail));
    EXPECT_NE(std::string::npos, strFail.find("2 token-bearing outputs holding 6.00000546")) << strFail;
}

TEST_F(TokenGuardTest, NothingIsPersistedAndABackupIsStillProtected)
{
    StandardScenario();

    // Computing the role does not change what would be written to wallet.dat.
    {
        LOCK2(cs_main, wallet->cs_wallet);
        CWalletTx copy = wallet->mapWallet[txidGenesis];
        copy.fTokenRolesCached = false;
        CDataStream before(SER_DISK, CLIENT_VERSION);
        before << copy;
        EXPECT_TRUE(copy.IsTokenBearingOutput(1));
        EXPECT_TRUE(copy.fTokenRolesCached);
        CDataStream after(SER_DISK, CLIENT_VERSION);
        after << copy;
        EXPECT_EQ(before.str(), after.str());
    }

    // Back the wallet file up and open the copy as a different wallet, as a
    // restore would. Nothing but the transactions came along, and the copy
    // protects the same outputs.
    boost::filesystem::path pathBackup = GetDataDir() / boost::filesystem::unique_path("tokenguard-backup-%%%%-%%%%.dat");
    ASSERT_TRUE(BackupWallet(*wallet, pathBackup.string()));

    // Close the original and tear the database environment down, so the copy
    // is opened the way a restore opens it: by a wallet that has never seen
    // the original, in an environment with no memory of it.
    delete wallet;
    wallet = NULL;
    ResetWalletEnvironment();
    ASSERT_TRUE(boost::filesystem::remove(GetDataDir() / walletFile));

    CWallet* restored = OpenWallet(pathBackup.filename().string());
    {
        LOCK2(cs_main, restored->cs_wallet);
        ASSERT_EQ(6u, restored->mapWallet.size());
        for (std::map<uint256, CWalletTx>::const_iterator it = restored->mapWallet.begin(); it != restored->mapWallet.end(); ++it)
            EXPECT_FALSE(it->second.fTokenRolesCached);
        std::vector<COutPoint> vLocked;
        restored->ListLockedCoins(vLocked);
        EXPECT_TRUE(vLocked.empty());
    }
    EXPECT_EQ(nOrdinaryValue + nProtectedValue, restored->GetBalance());

    std::vector<COutput> vCoins;
    restored->AvailableCoins(vCoins, true, NULL, true, true);
    ASSERT_EQ(16u, vCoins.size());
    size_t nFlagged = 0;
    for (size_t i = 0; i < vCoins.size(); i++) {
        COutPoint outpoint(vCoins[i].tx->GetHash(), vCoins[i].i);
        EXPECT_EQ(protectedOutpoints.count(outpoint) != 0, vCoins[i].tx->IsTokenBearingOutput(vCoins[i].i)) << outpoint.ToString();
        nFlagged += protectedOutpoints.count(outpoint);
    }
    EXPECT_EQ(7u, nFlagged);

    ExpectAutomaticSelectionProtected(restored);
    delete restored;
}

TEST_F(TokenGuardTest, CacheFollowsTheTransactionNotTheObject)
{
    // A CWalletTx whose transaction is replaced in place (CreateTransaction
    // does that to wtxNew) must not answer from the old transaction.
    std::vector<CTxOut> v;
    v.push_back(Data(SlpGenesis(2, 1000)));
    v.push_back(Mine(DUST));
    v.push_back(Mine(DUST));
    CWalletTx wtx(wallet, CTransaction(ForeignTx(v)));
    EXPECT_TRUE(wtx.IsTokenBearingOutput(1));
    EXPECT_TRUE(wtx.IsTokenBearingOutput(2));
    EXPECT_FALSE(wtx.IsTokenBearingOutput(0));
    EXPECT_FALSE(wtx.IsTokenBearingOutput(3));

    v[0] = Data(CScript() << OP_RETURN << ParseHex("00"));
    *static_cast<CTransaction*>(&wtx) = CTransaction(ForeignTx(v));
    EXPECT_FALSE(wtx.IsTokenBearingOutput(1));
    EXPECT_FALSE(wtx.IsTokenBearingOutput(2));

    v[0] = Data(SlpGenesis(0, 1));
    *static_cast<CTransaction*>(&wtx) = CTransaction(ForeignTx(v));
    EXPECT_TRUE(wtx.IsTokenBearingOutput(1));
    EXPECT_FALSE(wtx.IsTokenBearingOutput(2));
}

} // namespace
