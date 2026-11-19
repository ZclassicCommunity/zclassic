// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// banlist.dat: round trip, expiry, and fail-open handling of damaged files.

#include "banlist.h"
#include "chainparams.h"
#include "net.h"
#include "random.h"
#include "netbase.h"
#include "test/test_bitcoin.h"
#include "util.h"
#include "utiltime.h"

#include <fstream>
#include <iterator>

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

namespace fs = boost::filesystem;

namespace {

/** Isolated datadir for banlist.dat; the ban list is process-global, so it is emptied around every test. */
struct BanTestingSetup : public BasicTestingSetup {
    fs::path dir;

    BanTestingSetup()
    {
        ClearDatadirCache();
        dir = GetTempPath() / strprintf("net_ban_tests_%lu_%i", (unsigned long)GetTime(), (int)GetRand(100000));
        fs::create_directories(dir);
        mapArgs["-datadir"] = dir.string();
        CNode::ClearBanned();
    }
    ~BanTestingSetup()
    {
        CNode::ClearBanned();
        mapArgs.erase("-datadir");
        ClearDatadirCache();
        fs::remove_all(dir);
    }

    fs::path File() const { return dir / "banlist.dat"; }
    fs::path Bad() const { return dir / "banlist.dat.bad"; }

    std::vector<char> Slurp() const
    {
        std::ifstream in(File().string().c_str(), std::ios::binary);
        return std::vector<char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    void Spit(const std::vector<char>& v) const
    {
        std::ofstream out(File().string().c_str(), std::ios::binary | std::ios::trunc);
        out.write(v.empty() ? "" : &v[0], v.size());
    }
};

banmap_t SampleBans()
{
    const int64_t now = GetTime();
    banmap_t m;
    m[CSubNet("1.2.3.4/32")] = now + 1000;
    m[CSubNet("2001:db8::1/128")] = now + 2000;
    m[CSubNet("10.0.0.0/24")] = now + 3000;
    return m;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(net_ban_tests, BanTestingSetup)

BOOST_AUTO_TEST_CASE(roundtrip)
{
    banmap_t in = SampleBans(), out;
    CBanDB db;
    BOOST_CHECK(db.Write(in));
    BOOST_CHECK(fs::exists(File()));
    BOOST_CHECK(db.Read(out));
    BOOST_CHECK(in == out);
    BOOST_CHECK(!fs::exists(Bad()));
}

BOOST_AUTO_TEST_CASE(missing_file_is_empty_without_quarantine)
{
    banmap_t out;
    out[CSubNet("1.2.3.4/32")] = 1;
    CBanDB db;
    BOOST_CHECK(db.Read(out));
    BOOST_CHECK(out.empty());
    BOOST_CHECK(!fs::exists(Bad()));
}

BOOST_AUTO_TEST_CASE(expired_entry_is_not_restored)
{
    const int64_t now = GetTime();
    banmap_t in;
    in[CSubNet("1.2.3.4/32")] = now - 10;
    in[CSubNet("10.0.0.0/24")] = now + 1000;
    CBanDB db;
    BOOST_CHECK(db.Write(in));

    banmap_t out;
    BOOST_CHECK(db.Read(out));
    CNode::SetBanned(out);
    BOOST_CHECK_EQUAL(CNode::SweepBanned(), 1U);
    CNode::GetBanned(out);
    BOOST_CHECK_EQUAL(out.size(), 1U);
    BOOST_CHECK(out.count(CSubNet("10.0.0.0/24")));
    BOOST_CHECK(CNode::fBanlistDirty); // the sweep changed the list
}

BOOST_AUTO_TEST_CASE(flipped_byte_is_quarantined)
{
    CBanDB db;
    BOOST_CHECK(db.Write(SampleBans()));
    std::vector<char> v = Slurp();
    v[v.size() / 2] ^= 0x01;
    Spit(v);

    banmap_t out = SampleBans();
    BOOST_CHECK(!db.Read(out));
    BOOST_CHECK(out.empty());
    BOOST_CHECK(fs::exists(Bad()));
    BOOST_CHECK(!fs::exists(File()));
}

BOOST_AUTO_TEST_CASE(truncated_file_is_empty)
{
    CBanDB db;
    BOOST_CHECK(db.Write(SampleBans()));
    std::vector<char> v = Slurp();
    for (size_t cut : {size_t(0), size_t(5), size_t(20), v.size() - 1}) {
        Spit(std::vector<char>(v.begin(), v.begin() + cut));
        banmap_t out = SampleBans();
        BOOST_CHECK(!db.Read(out));
        BOOST_CHECK(out.empty());
        BOOST_CHECK(fs::exists(Bad()));
        fs::remove(Bad());
    }
}

BOOST_AUTO_TEST_CASE(wrong_network_is_empty)
{
    CBanDB db;
    SelectParams(CBaseChainParams::TESTNET);
    BOOST_CHECK(db.Write(SampleBans()));
    SelectParams(CBaseChainParams::MAIN);

    banmap_t out;
    BOOST_CHECK(!db.Read(out));
    BOOST_CHECK(out.empty());
    BOOST_CHECK(fs::exists(Bad()));
}

BOOST_AUTO_TEST_CASE(ban_dump_clear_reload)
{
    CNetAddr addr("1.2.3.4");
    CNode::Ban(addr, 3600);
    BOOST_CHECK(CNode::IsBanned(addr));
    DumpBanlist();
    BOOST_CHECK(fs::exists(File()));

    CNode::ClearBanned();
    BOOST_CHECK(!CNode::IsBanned(addr));

    banmap_t loaded;
    CBanDB db;
    BOOST_CHECK(db.Read(loaded));
    CNode::SetBanned(loaded);
    BOOST_CHECK(CNode::IsBanned(addr));
}

BOOST_AUTO_TEST_CASE(unban_is_persisted)
{
    CNetAddr addr("1.2.3.4");
    CNode::Ban(addr, 3600);
    DumpBanlist();
    BOOST_CHECK(CNode::Unban(addr));
    DumpBanlist();

    banmap_t loaded;
    CBanDB db;
    BOOST_CHECK(db.Read(loaded));
    BOOST_CHECK(loaded.empty());
}

BOOST_AUTO_TEST_CASE(dirty_flag)
{
    CNetAddr addr("1.2.3.4");
    CNode::fBanlistDirty = false;
    CNode::Ban(addr, 3600);
    BOOST_CHECK(CNode::fBanlistDirty);
    DumpBanlist();
    BOOST_CHECK(!CNode::fBanlistDirty);

    BOOST_CHECK(CNode::Unban(addr));
    BOOST_CHECK(CNode::fBanlistDirty);
    DumpBanlist();
    BOOST_CHECK(!CNode::fBanlistDirty);

    BOOST_CHECK(!CNode::Unban(addr)); // nothing removed: nothing to write
    BOOST_CHECK(!CNode::fBanlistDirty);

    CNode::ClearBanned();
    BOOST_CHECK(CNode::fBanlistDirty);
    DumpBanlist();
    BOOST_CHECK(!CNode::fBanlistDirty);
}

BOOST_AUTO_TEST_SUITE_END()
