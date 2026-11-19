// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// BackupWallet: the copy is verified and renamed into place, never written
// straight onto the destination.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "key.h"
#include "pubkey.h"
#include "util.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <boost/filesystem.hpp>

#include <fstream>
#include <iterator>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = boost::filesystem;

namespace {

std::string Slurp(const fs::path& p)
{
    std::ifstream in(p.string().c_str(), std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void Spit(const fs::path& p, const std::string& s)
{
    std::ofstream out(p.string().c_str(), std::ios::binary | std::ios::trunc);
    out << s;
}

size_t CountTmp(const fs::path& dir)
{
    size_t n = 0;
    for (fs::directory_iterator it(dir), end; it != end; ++it)
        if (it->path().filename().string().find(".tmp.") != std::string::npos)
            n++;
    return n;
}

class BackupWalletTest : public ::testing::Test {
protected:
    fs::path dataDir, outDir;
    std::string prevDataDir, walletFile;
    CWallet* wallet = NULL;

    void SetUp() override
    {
        SelectParams(CBaseChainParams::REGTEST);
        bitdb.Flush(true);
        bitdb.Reset();
        dataDir = fs::temp_directory_path() / UniquePath("zcl-backupwallet-%%%%-%%%%-%%%%");
        outDir = dataDir / "out";
        fs::create_directories(outDir);
        prevDataDir = mapArgs.count("-datadir") ? mapArgs["-datadir"] : "";
        mapArgs["-datadir"] = dataDir.string();
        ClearDatadirCache();
        mapArgs["-keypool"] = "5";
        walletFile = "backupwallet-test.dat";
        wallet = new CWallet(walletFile);
        bool fFirstRun = true;
        ASSERT_EQ(DB_LOAD_OK, wallet->LoadWallet(fFirstRun));
        CPubKey pk;
        ASSERT_TRUE(wallet->GetKeyFromPool(pk));
    }

    void TearDown() override
    {
        chmod(outDir.string().c_str(), 0700);
        delete wallet;
        wallet = NULL;
        bitdb.Flush(true);
        bitdb.Reset();
        boost::system::error_code ec;
        fs::remove_all(dataDir, ec);
        mapArgs.erase("-keypool");
        if (!prevDataDir.empty())
            mapArgs["-datadir"] = prevDataDir;
        ClearDatadirCache();
    }
};

} // namespace

TEST_F(BackupWalletTest, NewFileIsByteIdenticalAndLeavesNoTemporary)
{
    fs::path dest = outDir / "copy.dat";
    ASSERT_TRUE(BackupWallet(*wallet, dest.string()));
    std::string src = Slurp(GetDataDir() / walletFile);
    EXPECT_FALSE(src.empty());
    EXPECT_EQ(src, Slurp(dest));
    EXPECT_EQ(0u, CountTmp(outDir));
}

TEST_F(BackupWalletTest, ExistingFileIsReplaced)
{
    fs::path dest = outDir / "copy.dat";
    Spit(dest, "stale backup");
    ASSERT_TRUE(BackupWallet(*wallet, dest.string()));
    EXPECT_EQ(Slurp(GetDataDir() / walletFile), Slurp(dest));
    EXPECT_EQ(0u, CountTmp(outDir));
}

TEST_F(BackupWalletTest, DirectoryDestinationUsesTheWalletFileName)
{
    ASSERT_TRUE(BackupWallet(*wallet, outDir.string()));
    EXPECT_EQ(Slurp(GetDataDir() / walletFile), Slurp(outDir / walletFile));
    EXPECT_EQ(0u, CountTmp(outDir));
}

TEST_F(BackupWalletTest, MissingDirectoryFailsWithoutTemporary)
{
    fs::path dest = outDir / "nope" / "copy.dat";
    EXPECT_FALSE(BackupWallet(*wallet, dest.string()));
    EXPECT_FALSE(fs::exists(outDir / "nope"));
    EXPECT_EQ(0u, CountTmp(outDir));
}

TEST_F(BackupWalletTest, ReadOnlyDirectoryFailsAndKeepsOldFile)
{
    fs::path dest = outDir / "copy.dat";
    Spit(dest, "old backup");
    ASSERT_EQ(0, chmod(outDir.string().c_str(), 0500));
    if (access(outDir.string().c_str(), W_OK) == 0) {
        chmod(outDir.string().c_str(), 0700);
        return; // permissions not enforced for this user (this gtest has no GTEST_SKIP)
    }
    EXPECT_FALSE(BackupWallet(*wallet, dest.string()));
    chmod(outDir.string().c_str(), 0700);
    EXPECT_EQ("old backup", Slurp(dest));
    EXPECT_EQ(0u, CountTmp(outDir));
}

TEST_F(BackupWalletTest, BackupOntoTheWalletItselfIsRefused)
{
    bitdb.Flush(true);
    std::string before = Slurp(GetDataDir() / walletFile);
    EXPECT_FALSE(BackupWallet(*wallet, (GetDataDir() / walletFile).string()));
    EXPECT_FALSE(BackupWallet(*wallet, GetDataDir().string()));
    EXPECT_EQ(before, Slurp(GetDataDir() / walletFile));
    EXPECT_EQ(0u, CountTmp(GetDataDir()));
}
