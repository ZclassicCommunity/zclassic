// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The wallet loader (CWalletDB::ReadKeyValue, "tx" records) checks every stored
// transaction with CheckTransaction(). One of the 413 historical oversize
// mainnet transactions (consensus/oversize_grandfather.h) is already in the
// chain, so a wallet holding it must load cleanly and must not be forced into a
// rescan. Anything else above the limit keeps the old behaviour: the record is
// skipped with a non-critical error and -rescan is set. The strict standalone
// path (mempool, relay, RPC) still rejects the historical transaction.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/oversize_grandfather.h"
#include "consensus/validation.h"
#include "main.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "streams.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "zcash/Proof.hpp"

#include <boost/filesystem.hpp>

#include <cctype>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

const char* const OVERSIZE_478544_TXID = "e3eeb123a79945cc74e6107422b124dc130ddd4b61fe5c74087317c256c79700";
const unsigned int OVERSIZE_478544_SIZE = 125811;

std::string ReadTestData(const std::string& name)
{
    std::vector<std::string> dirs;
    if (const char* env = getenv("ZCL_TEST_DATA_DIR"))
        dirs.push_back(env);
    for (const char* d : {"test/data", "src/test/data", "../src/test/data", "../../src/test/data"})
        dirs.push_back(d);
    for (const std::string& d : dirs) {
        std::ifstream in((d + "/" + name).c_str(), std::ios::in | std::ios::binary);
        if (in.good()) {
            std::stringstream ss;
            ss << in.rdbuf();
            return ss.str();
        }
    }
    ADD_FAILURE() << "cannot find test data file " << name << " (set ZCL_TEST_DATA_DIR)";
    return std::string();
}

// Block 478544, 125811 bytes, in the grandfather table.
CTransaction LoadOversize478544()
{
    std::string hex = ReadTestData("oversize_tx_478544.hex");
    while (!hex.empty() && isspace((unsigned char)hex.back()))
        hex.pop_back();
    CTransaction tx;
    EXPECT_TRUE(IsHex(hex));
    std::vector<unsigned char> raw = ParseHex(hex);
    CDataStream ss(raw, SER_NETWORK, PROTOCOL_VERSION);
    ss >> tx;
    EXPECT_TRUE(ss.empty());
    return tx;
}

// A transparent transaction whose one scriptSig is padded so it serializes to
// exactly nSize bytes. It is not in the grandfather table.
CTransaction PaddedTransparentTx(unsigned int nSize)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vin[0].scriptSig = CScript();
    for (int i = 0; i < 8; i++) {
        unsigned int cur = ::GetSerializeSize(CTransaction(mtx), SER_NETWORK, PROTOCOL_VERSION);
        if (cur == nSize)
            break;
        size_t len = mtx.vin[0].scriptSig.size() + nSize - cur;
        mtx.vin[0].scriptSig = CScript();
        mtx.vin[0].scriptSig.insert(mtx.vin[0].scriptSig.end(), len, OP_NOP);
    }
    CTransaction tx(mtx);
    EXPECT_EQ(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION), nSize);
    return tx;
}

} // namespace

class WalletOversizeTest : public ::testing::Test {
protected:
    boost::filesystem::path pathDataDir;
    std::string strPreviousDataDir;
    int nWallets = 0;

    void SetUp() override
    {
        SelectParams(CBaseChainParams::MAIN); // the table is a mainnet fact

        // One Berkeley DB environment serves the whole gtest binary. Restart it
        // in a fresh temp datadir so the wallet files live where GetDataDir() says.
        ResetWalletEnvironment();
        pathDataDir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("zcl-walletoversize-%%%%-%%%%-%%%%");
        boost::filesystem::create_directories(pathDataDir);
        strPreviousDataDir = mapArgs.count("-datadir") ? mapArgs["-datadir"] : "";
        mapArgs["-datadir"] = pathDataDir.string();
        ClearDatadirCache();
        mapArgs.erase("-rescan");
    }

    void TearDown() override
    {
        ResetWalletEnvironment();
        boost::system::error_code ec;
        boost::filesystem::remove_all(pathDataDir, ec);
        mapArgs.erase("-rescan");
        if (!strPreviousDataDir.empty())
            mapArgs["-datadir"] = strPreviousDataDir;
        ClearDatadirCache();
        SelectParams(CBaseChainParams::REGTEST); // the network the other wallet tests select
    }

    static void ResetWalletEnvironment()
    {
        bitdb.Flush(true);
        bitdb.Reset();
    }

    // Create a wallet file holding one "tx" record for tx, as the wallet writes it.
    std::string StoreTx(const CTransaction& tx)
    {
        std::string file = strprintf("w%d.dat", nWallets++);
        {
            CWallet w(file);
            bool fFirstRun = true;
            EXPECT_EQ(DB_LOAD_OK, w.LoadWallet(fFirstRun));
            CWalletTx wtx(&w, tx);
            CWalletDB db(file);
            EXPECT_TRUE(db.WriteTx(tx.GetHash(), wtx));
        }
        bitdb.Flush(false);
        return file;
    }
};

// (a) A stored historical oversize transaction loads cleanly: no non-critical
// error, present in mapWallet, and no rescan requested.
TEST_F(WalletOversizeTest, grandfathered_tx_loads_without_rescan)
{
    CTransaction tx = LoadOversize478544();
    ASSERT_EQ(tx.GetHash().GetHex(), OVERSIZE_478544_TXID);
    ASSERT_EQ(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION), OVERSIZE_478544_SIZE);
    ASSERT_TRUE(IsOversizeGrandfathered(tx.GetHash(), OVERSIZE_478544_SIZE));

    std::string file = StoreTx(tx);
    ASSERT_FALSE(GetBoolArg("-rescan", false)) << "storing must not request a rescan";

    CWallet loaded(file);
    bool fFirstRun = false;
    EXPECT_EQ(DB_LOAD_OK, loaded.LoadWallet(fFirstRun));
    EXPECT_FALSE(GetBoolArg("-rescan", false)) << "loading requested a rescan";
    LOCK(loaded.cs_wallet);
    ASSERT_EQ(1u, loaded.mapWallet.size());
    ASSERT_TRUE(loaded.mapWallet.count(tx.GetHash()));
    EXPECT_EQ(OVERSIZE_478544_TXID, loaded.mapWallet[tx.GetHash()].GetHash().GetHex());
}

// (b) An oversize transaction that is not in the table behaves as before: the
// record is rejected (non-critical error, dropped) and -rescan is set. One
// case has the grandfathered size but another txid.
TEST_F(WalletOversizeTest, unlisted_oversize_tx_is_still_rejected)
{
    for (unsigned int nSize : {MAX_TX_SIZE_AFTER_SAPLING + 1, OVERSIZE_478544_SIZE}) {
        mapArgs.erase("-rescan");
        CTransaction tx = PaddedTransparentTx(nSize);
        ASSERT_FALSE(IsOversizeGrandfathered(tx.GetHash(), nSize));
        std::string file = StoreTx(tx);
        ASSERT_FALSE(GetBoolArg("-rescan", false));

        CWallet loaded(file);
        bool fFirstRun = false;
        EXPECT_EQ(DB_NONCRITICAL_ERROR, loaded.LoadWallet(fFirstRun)) << nSize;
        EXPECT_TRUE(GetBoolArg("-rescan", false)) << nSize;
        LOCK(loaded.cs_wallet);
        EXPECT_EQ(0u, loaded.mapWallet.size()) << nSize;
    }
}

// Control for (b): a transaction exactly at the limit is a normal wallet
// record and loads cleanly.
TEST_F(WalletOversizeTest, transaction_at_the_limit_loads)
{
    CTransaction tx = PaddedTransparentTx(MAX_TX_SIZE_AFTER_SAPLING);
    std::string file = StoreTx(tx);
    CWallet loaded(file);
    bool fFirstRun = false;
    EXPECT_EQ(DB_LOAD_OK, loaded.LoadWallet(fFirstRun));
    EXPECT_FALSE(GetBoolArg("-rescan", false));
    LOCK(loaded.cs_wallet);
    EXPECT_EQ(1u, loaded.mapWallet.size());
}

// (c) The strict standalone path still rejects the historical transaction,
// both CheckTransaction and the first gate of AcceptToMemoryPool.
TEST_F(WalletOversizeTest, strict_paths_still_reject_grandfathered_tx)
{
    CTransaction tx = LoadOversize478544();
    ASSERT_EQ(tx.GetHash().GetHex(), OVERSIZE_478544_TXID);

    auto verifier = libzcash::ProofVerifier::Disabled();
    {
        CValidationState state;
        EXPECT_FALSE(CheckTransaction(tx, state, verifier));
        EXPECT_EQ("bad-txns-oversize", state.GetRejectReason());
    }
    {
        CValidationState state;
        EXPECT_FALSE(CheckTransaction(tx, state, verifier, false));
        EXPECT_EQ("bad-txns-oversize", state.GetRejectReason());
    }
    {
        CValidationState state;
        EXPECT_TRUE(CheckTransaction(tx, state, verifier, true)) << state.GetRejectReason();
    }
    {
        CTxMemPool pool(CFeeRate(0));
        CValidationState state;
        bool fMissingInputs = false;
        LOCK(cs_main);
        EXPECT_FALSE(AcceptToMemoryPool(pool, state, tx, false, &fMissingInputs));
        EXPECT_EQ("bad-txns-oversize", state.GetRejectReason());
        EXPECT_FALSE(fMissingInputs) << "the size rule must fire before any input lookup";
        EXPECT_EQ(0u, pool.size());
    }
}
