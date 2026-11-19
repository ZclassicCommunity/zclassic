// Copyright (c) 2012-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "addrman.h"
#include "test/test_bitcoin.h"
#include <string>
#include <boost/test/unit_test.hpp>

#include "chainparams.h"
#include "hash.h"
#include "net.h"
#include "random.h"
#include "util.h"
#include "utiltime.h"

#include <climits>
#include <fstream>
#include <iterator>
#include <set>

#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>

using namespace std;

class CAddrManTest : public CAddrMan
{
    uint64_t state;

public:
    CAddrManTest()
    {
        state = 1;
    }

    //! Ensure that bucket placement is always the same for testing purposes.
    void MakeDeterministic()
    {
        nKey.SetNull();
        seed_insecure_rand(true);
    }

    int RandomInt(int nMax)
    {
        state = (CHashWriter(SER_GETHASH, 0) << state).GetHash().GetCheapHash();
        return (unsigned int)(state % nMax);
    }

    CAddrInfo* Find(const CNetAddr& addr, int* pnId = NULL)
    {
        return CAddrMan::Find(addr, pnId);
    }

    CAddrInfo* Create(const CAddress& addr, const CNetAddr& addrSource, int* pnId = NULL)
    {
        return CAddrMan::Create(addr, addrSource, pnId);
    }

    void Delete(int nId)
    {
        CAddrMan::Delete(nId);
    }
};

BOOST_FIXTURE_TEST_SUITE(addrman_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(addrman_simple)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    // Test 1: Does Addrman respond correctly when empty.
    BOOST_CHECK(addrman.size() == 0);
    CAddrInfo addr_null = addrman.Select();
    BOOST_CHECK(addr_null.ToString() == "[::]:0");

    // Test 2: Does Addrman::Add work as expected.
    CService addr1 = CService("250.1.1.1", 8333);
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 1);
    CAddrInfo addr_ret1 = addrman.Select();
    BOOST_CHECK(addr_ret1.ToString() == "250.1.1.1:8333");

    // Test 3: Does IP address deduplication work correctly.
    //  Expected dup IP should not be added.
    CService addr1_dup = CService("250.1.1.1", 8333);
    addrman.Add(CAddress(addr1_dup), source);
    BOOST_CHECK(addrman.size() == 1);


    // Test 5: New table has one addr and we add a diff addr we should
    //  have two addrs.
    CService addr2 = CService("250.1.1.2", 8333);
    addrman.Add(CAddress(addr2), source);
    BOOST_CHECK(addrman.size() == 2);

    // Test 6: AddrMan::Clear() should empty the new table.
    addrman.Clear();
    BOOST_CHECK(addrman.size() == 0);
    CAddrInfo addr_null2 = addrman.Select();
    BOOST_CHECK(addr_null2.ToString() == "[::]:0");
}

BOOST_AUTO_TEST_CASE(addrman_ports)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    BOOST_CHECK(addrman.size() == 0);

    // Test 7; Addr with same IP but diff port does not replace existing addr.
    CService addr1 = CService("250.1.1.1", 8333);
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 1);

    CService addr1_port = CService("250.1.1.1", 8334);
    addrman.Add(CAddress(addr1_port), source);
    BOOST_CHECK(addrman.size() == 1);
    CAddrInfo addr_ret2 = addrman.Select();
    BOOST_CHECK(addr_ret2.ToString() == "250.1.1.1:8333");

    // Test 8: Add same IP but diff port to tried table, it doesn't get added.
    //  Perhaps this is not ideal behavior but it is the current behavior.
    addrman.Good(CAddress(addr1_port));
    BOOST_CHECK(addrman.size() == 1);
    bool newOnly = true;
    CAddrInfo addr_ret3 = addrman.Select(newOnly);
    BOOST_CHECK(addr_ret3.ToString() == "250.1.1.1:8333");
}


BOOST_AUTO_TEST_CASE(addrman_select)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    // Test 9: Select from new with 1 addr in new.
    CService addr1 = CService("250.1.1.1", 8333);
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 1);

    bool newOnly = true;
    CAddrInfo addr_ret1 = addrman.Select(newOnly);
    BOOST_CHECK(addr_ret1.ToString() == "250.1.1.1:8333");

    // Test 10: move addr to tried, select from new expected nothing returned.
    addrman.Good(CAddress(addr1));
    BOOST_CHECK(addrman.size() == 1);
    CAddrInfo addr_ret2 = addrman.Select(newOnly);
    BOOST_CHECK(addr_ret2.ToString() == "[::]:0");

    CAddrInfo addr_ret3 = addrman.Select();
    BOOST_CHECK(addr_ret3.ToString() == "250.1.1.1:8333");

    BOOST_CHECK(addrman.size() == 1);


    // Add three addresses to new table.
    CService addr2 = CService("250.3.1.1", 8333);
    CService addr3 = CService("250.3.2.2", 9999);
    CService addr4 = CService("250.3.3.3", 9999);

    addrman.Add(CAddress(addr2), CService("250.3.1.1", 8333));
    addrman.Add(CAddress(addr3), CService("250.3.1.1", 8333));
    addrman.Add(CAddress(addr4), CService("250.4.1.1", 8333));

    // Add three addresses to tried table.
    CService addr5 = CService("250.4.4.4", 8333);
    CService addr6 = CService("250.4.5.5", 7777);
    CService addr7 = CService("250.4.6.6", 8333);

    addrman.Add(CAddress(addr5), CService("250.3.1.1", 8333));
    addrman.Good(CAddress(addr5));
    addrman.Add(CAddress(addr6), CService("250.3.1.1", 8333));
    addrman.Good(CAddress(addr6));
    addrman.Add(CAddress(addr7), CService("250.1.1.3", 8333));
    addrman.Good(CAddress(addr7));

    // Test 11: 6 addrs + 1 addr from last test = 7.
    BOOST_CHECK(addrman.size() == 7);

    // Test 12: Select pulls from new and tried regardless of port number.
    // The sequence follows the overridden RandomInt alone (Select_ draws no
    // other randomness): tried 250.4.4.4 and 250.4.6.6, new 250.3.2.2:9999.
    BOOST_CHECK(addrman.Select().ToString() == "250.4.4.4:8333");
    BOOST_CHECK(addrman.Select().ToString() == "250.4.6.6:8333");
    BOOST_CHECK(addrman.Select().ToString() == "250.3.2.2:9999");
    BOOST_CHECK(addrman.Select().ToString() == "250.4.4.4:8333");
}

BOOST_AUTO_TEST_CASE(addrman_new_collisions)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    BOOST_CHECK(addrman.size() == 0);

    for (unsigned int i = 1; i < 18; i++) {
        CService addr = CService("250.1.1." + boost::to_string(i));
        addrman.Add(CAddress(addr), source);

        //Test 13: No collision in new table yet.
        BOOST_CHECK(addrman.size() == i);
    }

    //Test 14: new table collision!
    CService addr1 = CService("250.1.1.18");
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 17);

    CService addr2 = CService("250.1.1.19");
    addrman.Add(CAddress(addr2), source);
    BOOST_CHECK(addrman.size() == 18);
}

BOOST_AUTO_TEST_CASE(addrman_tried_collisions)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    BOOST_CHECK(addrman.size() == 0);

    for (unsigned int i = 1; i < 80; i++) {
        CService addr = CService("250.1.1." + boost::to_string(i));
        addrman.Add(CAddress(addr), source);
        addrman.Good(CAddress(addr));

        //Test 15: No collision in tried table yet.
        BOOST_TEST_MESSAGE(addrman.size());
        BOOST_CHECK(addrman.size() == i);
    }

    //Test 16: tried table collision!
    CService addr1 = CService("250.1.1.80");
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 79);

    CService addr2 = CService("250.1.1.81");
    addrman.Add(CAddress(addr2), source);
    BOOST_CHECK(addrman.size() == 80);
}

BOOST_AUTO_TEST_CASE(addrman_find)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    BOOST_CHECK(addrman.size() == 0);

    CAddress addr1 = CAddress(CService("250.1.2.1", 8333));
    CAddress addr2 = CAddress(CService("250.1.2.1", 9999));
    CAddress addr3 = CAddress(CService("251.255.2.1", 8333));

    CNetAddr source1 = CNetAddr("250.1.2.1");
    CNetAddr source2 = CNetAddr("250.1.2.2");

    addrman.Add(addr1, source1);
    addrman.Add(addr2, source2);
    addrman.Add(addr3, source1);

    // Test 17: ensure Find returns an IP matching what we searched on.
    CAddrInfo* info1 = addrman.Find(addr1);
    BOOST_CHECK(info1);
    if (info1)
        BOOST_CHECK(info1->ToString() == "250.1.2.1:8333");

    // Test 18; Find does not discriminate by port number.
    CAddrInfo* info2 = addrman.Find(addr2);
    BOOST_CHECK(info2);
    if (info2)
        BOOST_CHECK(info2->ToString() == info1->ToString());

    // Test 19: Find returns another IP matching what we searched on.
    CAddrInfo* info3 = addrman.Find(addr3);
    BOOST_CHECK(info3);
    if (info3)
        BOOST_CHECK(info3->ToString() == "251.255.2.1:8333");
}

BOOST_AUTO_TEST_CASE(addrman_create)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    BOOST_CHECK(addrman.size() == 0);

    CAddress addr1 = CAddress(CService("250.1.2.1", 8333));
    CNetAddr source1 = CNetAddr("250.1.2.1");

    int nId;
    CAddrInfo* pinfo = addrman.Create(addr1, source1, &nId);

    // Test 20: The result should be the same as the input addr.
    BOOST_CHECK(pinfo->ToString() == "250.1.2.1:8333");

    CAddrInfo* info2 = addrman.Find(addr1);
    BOOST_CHECK(info2->ToString() == "250.1.2.1:8333");
}


BOOST_AUTO_TEST_CASE(addrman_delete)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    BOOST_CHECK(addrman.size() == 0);

    CAddress addr1 = CAddress(CService("250.1.2.1", 8333));
    CNetAddr source1 = CNetAddr("250.1.2.1");

    int nId;
    addrman.Create(addr1, source1, &nId);

    // Test 21: Delete should actually delete the addr.
    BOOST_CHECK(addrman.size() == 1);
    addrman.Delete(nId);
    BOOST_CHECK(addrman.size() == 0);
    CAddrInfo* info2 = addrman.Find(addr1);
    BOOST_CHECK(info2 == NULL);
}

BOOST_AUTO_TEST_CASE(addrman_getaddr)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    // Test 22: Sanity check, GetAddr should never return anything if addrman
    //  is empty.
    BOOST_CHECK(addrman.size() == 0);
    vector<CAddress> vAddr1 = addrman.GetAddr();
    BOOST_CHECK(vAddr1.size() == 0);

    CAddress addr1 = CAddress(CService("250.250.2.1", 8333));
    addr1.nTime = GetAdjustedTime(); // Set time so isTerrible = false
    CAddress addr2 = CAddress(CService("250.251.2.2", 9999));
    addr2.nTime = GetAdjustedTime();
    CAddress addr3 = CAddress(CService("251.252.2.3", 8333));
    addr3.nTime = GetAdjustedTime();
    CAddress addr4 = CAddress(CService("252.253.3.4", 8333));
    addr4.nTime = GetAdjustedTime();
    CAddress addr5 = CAddress(CService("252.254.4.5", 8333));
    addr5.nTime = GetAdjustedTime();
    CNetAddr source1 = CNetAddr("250.1.2.1");
    CNetAddr source2 = CNetAddr("250.2.3.3");

    // Test 23: Ensure GetAddr works with new addresses.
    addrman.Add(addr1, source1);
    addrman.Add(addr2, source2);
    addrman.Add(addr3, source1);
    addrman.Add(addr4, source2);
    addrman.Add(addr5, source1);

    // GetAddr returns 23% of addresses, 23% of 5 is 1 rounded down.
    BOOST_CHECK(addrman.GetAddr().size() == 1); 

    // Test 24: Ensure GetAddr works with new and tried addresses.
    addrman.Good(CAddress(addr1));
    addrman.Good(CAddress(addr2));
    BOOST_CHECK(addrman.GetAddr().size() == 1);

    // Test 25: Ensure GetAddr still returns 23% when addrman has many addrs.
    for (unsigned int i = 1; i < (8 * 256); i++) {
        int octet1 = i % 256;
        int octet2 = (i / 256) % 256;
        int octet3 = (i / (256 * 2)) % 256;
        string strAddr = boost::to_string(octet1) + "." + boost::to_string(octet2) + "." + boost::to_string(octet3) + ".23";
        CAddress addr = CAddress(CService(strAddr));
        
        // Ensure that for all addrs in addrman, isTerrible == false.
        addr.nTime = GetAdjustedTime();
        addrman.Add(addr, CNetAddr(strAddr));
        if (i % 8 == 0)
            addrman.Good(addr);
    }
    vector<CAddress> vAddr = addrman.GetAddr();

    size_t percent23 = (addrman.size() * 23) / 100;
    BOOST_CHECK(vAddr.size() == percent23);
    BOOST_CHECK(vAddr.size() == 461);
    // (Addrman.size() < number of addresses added) due to address collisons.
    BOOST_CHECK(addrman.size() == 2007);
}


BOOST_AUTO_TEST_CASE(caddrinfo_get_tried_bucket)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CAddress addr1 = CAddress(CService("250.1.1.1", 8333));
    CAddress addr2 = CAddress(CService("250.1.1.1", 9999));

    CNetAddr source1 = CNetAddr("250.1.1.1");


    CAddrInfo info1 = CAddrInfo(addr1, source1);

    uint256 nKey1 = (uint256)(CHashWriter(SER_GETHASH, 0) << 1).GetHash();
    uint256 nKey2 = (uint256)(CHashWriter(SER_GETHASH, 0) << 2).GetHash();


    BOOST_CHECK(info1.GetTriedBucket(nKey1) == 40);

    // Test 26: Make sure key actually randomizes bucket placement. A fail on
    //  this test could be a security issue.
    BOOST_CHECK(info1.GetTriedBucket(nKey1) != info1.GetTriedBucket(nKey2));

    // Test 27: Two addresses with same IP but different ports can map to
    //  different buckets because they have different keys.
    CAddrInfo info2 = CAddrInfo(addr2, source1);

    BOOST_CHECK(info1.GetKey() != info2.GetKey());
    BOOST_CHECK(info1.GetTriedBucket(nKey1) != info2.GetTriedBucket(nKey1));

    set<int> buckets;
    for (int i = 0; i < 255; i++) {
        CAddrInfo infoi = CAddrInfo(
            CAddress(CService("250.1.1." + boost::to_string(i))),
            CNetAddr("250.1.1." + boost::to_string(i)));
        int bucket = infoi.GetTriedBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 28: IP addresses in the same group (\16 prefix for IPv4) should
    //  never get more than 8 buckets
    BOOST_CHECK(buckets.size() == 8);

    buckets.clear();
    for (int j = 0; j < 255; j++) {
        CAddrInfo infoj = CAddrInfo(
            CAddress(CService("250." + boost::to_string(j) + ".1.1")),
            CNetAddr("250." + boost::to_string(j) + ".1.1"));
        int bucket = infoj.GetTriedBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 29: IP addresses in the different groups should map to more than
    //  8 buckets.
    BOOST_CHECK(buckets.size() == 160);
}

BOOST_AUTO_TEST_CASE(caddrinfo_get_new_bucket)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CAddress addr1 = CAddress(CService("250.1.2.1", 8333));
    CAddress addr2 = CAddress(CService("250.1.2.1", 9999));

    CNetAddr source1 = CNetAddr("250.1.2.1");

    CAddrInfo info1 = CAddrInfo(addr1, source1);

    uint256 nKey1 = (uint256)(CHashWriter(SER_GETHASH, 0) << 1).GetHash();
    uint256 nKey2 = (uint256)(CHashWriter(SER_GETHASH, 0) << 2).GetHash();

    BOOST_CHECK(info1.GetNewBucket(nKey1) == 786);

    // Test 30: Make sure key actually randomizes bucket placement. A fail on
    //  this test could be a security issue.
    BOOST_CHECK(info1.GetNewBucket(nKey1) != info1.GetNewBucket(nKey2));

    // Test 31: Ports should not affect bucket placement in the addr
    CAddrInfo info2 = CAddrInfo(addr2, source1);
    BOOST_CHECK(info1.GetKey() != info2.GetKey());
    BOOST_CHECK(info1.GetNewBucket(nKey1) == info2.GetNewBucket(nKey1));

    set<int> buckets;
    for (int i = 0; i < 255; i++) {
        CAddrInfo infoi = CAddrInfo(
            CAddress(CService("250.1.1." + boost::to_string(i))),
            CNetAddr("250.1.1." + boost::to_string(i)));
        int bucket = infoi.GetNewBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 32: IP addresses in the same group (\16 prefix for IPv4) should
    //  always map to the same bucket.
    BOOST_CHECK(buckets.size() == 1);

    buckets.clear();
    for (int j = 0; j < 4 * 255; j++) {
        CAddrInfo infoj = CAddrInfo(CAddress(
                                        CService(
                                            boost::to_string(250 + (j / 255)) + "." + boost::to_string(j % 256) + ".1.1")),
            CNetAddr("251.4.1.1"));
        int bucket = infoj.GetNewBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 33: IP addresses in the same source groups should map to no more
    //  than 64 buckets.
    BOOST_CHECK(buckets.size() <= 64);

    buckets.clear();
    for (int p = 0; p < 255; p++) {
        CAddrInfo infoj = CAddrInfo(
            CAddress(CService("250.1.1.1")),
            CNetAddr("250." + boost::to_string(p) + ".1.1"));
        int bucket = infoj.GetNewBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 34: IP addresses in the different source groups should map to more
    //  than 64 buckets.
    BOOST_CHECK(buckets.size() > 64);
}
// A table that holds a single address must return it on every selection and
// without delay: the old random probing gave up empty about one time in twenty
// and slept for up to 20 seconds under the lock while doing so.
BOOST_AUTO_TEST_CASE(addrman_select_sparse_table)
{
    CAddrMan addrman; // randomly keyed, as in the node
    CAddress addr(CService("250.7.7.7", 8033), NODE_NETWORK);
    addr.nTime = GetAdjustedTime();
    BOOST_CHECK(addrman.Add(addr, CNetAddr("250.1.2.3")));
    BOOST_CHECK_EQUAL(addrman.size(), 1u);

    const int64_t nStart = GetTimeMillis();
    for (int i = 0; i < 2000; i++) {
        CAddrInfo got = addrman.Select();
        BOOST_REQUIRE_EQUAL(got.ToString(), addr.ToString());
    }
    BOOST_CHECK_MESSAGE(GetTimeMillis() - nStart < 5000, "2000 selections took " << (GetTimeMillis() - nStart) << " ms");

    // the same once the address has moved to the tried table
    addrman.Good(addr);
    for (int i = 0; i < 2000; i++)
        BOOST_REQUIRE_EQUAL(addrman.Select().ToString(), addr.ToString());
    // and a new-only selection finds nothing there, at once
    BOOST_CHECK_EQUAL(addrman.Select(true).ToString(), CAddrInfo().ToString());
}

// ---- peers.dat salvage -------------------------------------------------------------------

namespace {

/** Isolated datadir for peers.dat; restores the process-wide datadir state afterwards. */
struct PeersDatDir {
    boost::filesystem::path dir;

    PeersDatDir()
    {
        ClearDatadirCache();
        dir = GetTempPath() / strprintf("addrman_salvage_%lu_%i", (unsigned long)GetTime(), (int)GetRand(100000));
        boost::filesystem::create_directories(dir);
        mapArgs["-datadir"] = dir.string();
    }
    ~PeersDatDir()
    {
        mapArgs.erase("-datadir");
        ClearDatadirCache();
        boost::filesystem::remove_all(dir);
    }

    boost::filesystem::path File() const { return dir / "peers.dat"; }
    boost::filesystem::path Corrupt() const { return dir / "peers.dat.corrupt"; }

    std::vector<char> Slurp(const boost::filesystem::path& p) const
    {
        std::ifstream in(p.string().c_str(), std::ios::binary);
        return std::vector<char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    void Spit(const std::vector<char>& v) const
    {
        std::ofstream out(File().string().c_str(), std::ios::binary | std::ios::trunc);
        out.write(v.empty() ? "" : &v[0], v.size());
    }
    void Spit(const std::vector<char>& v, size_t n) const { Spit(std::vector<char>(v.begin(), v.begin() + n)); }
};

/** The records of a peers.dat image, parsed independently of CAddrMan. */
struct PeersImage {
    std::vector<char> raw;
    int nNew, nTried;
    size_t recSize, recStart;
    std::vector<CAddrInfo> recs;

    explicit PeersImage(const std::vector<char>& rawIn) : raw(rawIn), nNew(0), nTried(0), recSize(0), recStart(50)
    {
        CDataStream ss(&raw[4], &raw[0] + raw.size(), SER_DISK, CLIENT_VERSION);
        unsigned char ver, keySize;
        uint256 key;
        int nUB;
        ss >> ver >> keySize >> key >> nNew >> nTried >> nUB;
        for (int i = 0; i < nNew + nTried; i++) {
            size_t before = ss.size();
            CAddrInfo info;
            ss >> info;
            recSize = before - ss.size();
            recs.push_back(info);
        }
    }
    size_t Offset(size_t record) const { return recStart + record * recSize; }
};

CAddress SaltAddr(int i)
{
    CAddress a(CService(strprintf("%u.%u.1.1", 20 + (i % 100), 1 + i / 100), 8033), NODE_NETWORK);
    a.nTime = GetAdjustedTime() - 100;
    return a;
}

CNetAddr SaltSource(int i)
{
    return CNetAddr(strprintf("%u.%u.9.9", 130 + (i % 60), 1 + i / 60));
}

/** 500 addresses, 100 of them tried; written to peers.dat. */
void WriteSampleAddrman(CAddrManTest& am)
{
    am.MakeDeterministic();
    for (int i = 0; i < 500; i++)
        am.Add(SaltAddr(i), SaltSource(i));
    for (int i = 0; i < 500; i += 5)
        am.Good(SaltAddr(i));
    CAddrDB adb;
    BOOST_REQUIRE(adb.Write(am));
}

std::set<std::string> Held(const CAddrMan& am, bool* pAnyTried = NULL)
{
    std::set<std::string> s;
    bool tried = false;
    BOOST_FOREACH (const CAddrInfo& e, am.GetEntries()) {
        s.insert(e.ToStringIPPort());
        tried = tried || e.IsTried();
    }
    if (pAnyTried)
        *pAnyTried = tried;
    return s;
}

std::set<std::string> Prefix(const PeersImage& img, size_t n)
{
    std::set<std::string> s;
    for (size_t i = 0; i < n && i < img.recs.size(); i++)
        s.insert(img.recs[i].ToStringIPPort());
    return s;
}

/** Serialize/Unserialize assert on and re-derive the internal counters: a damaged table would fail here. */
void CheckConsistent(const CAddrMan& am)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << am;
    CAddrMan back;
    ss >> back;
    BOOST_CHECK_EQUAL(back.size(), am.size());
}

} // namespace

BOOST_AUTO_TEST_CASE(addrman_salvage_intact_file_unchanged)
{
    PeersDatDir dir;
    CAddrManTest am;
    WriteSampleAddrman(am);

    CAddrMan loaded;
    CAddrDB adb;
    BOOST_CHECK(adb.Read(loaded));
    BOOST_CHECK_EQUAL(loaded.size(), am.size());
    BOOST_CHECK(Held(loaded) == Held(am));
    size_t nTriedBefore = 0, nTriedAfter = 0;
    BOOST_FOREACH (const CAddrInfo& e, am.GetEntries()) nTriedBefore += e.IsTried();
    BOOST_FOREACH (const CAddrInfo& e, loaded.GetEntries()) nTriedAfter += e.IsTried();
    BOOST_CHECK(nTriedBefore > 0);
    BOOST_CHECK_EQUAL(nTriedBefore, nTriedAfter); // tried flags survive an intact file
    BOOST_CHECK(!boost::filesystem::exists(dir.Corrupt()));
}

BOOST_AUTO_TEST_CASE(addrman_salvage_truncated)
{
    PeersDatDir dir;
    CAddrManTest am;
    WriteSampleAddrman(am);
    const PeersImage img(dir.Slurp(dir.File()));
    BOOST_REQUIRE(img.nNew > 20 && img.nTried > 10);
    const size_t nBucketStart = img.Offset(img.nNew + img.nTried);

    struct Cut { size_t offset; size_t complete; const char* where; };
    const Cut cuts[] = {
        {img.Offset(10) + img.recSize / 2, 10, "inside the new section"},
        {img.Offset(img.nNew + 3) + 7, (size_t)img.nNew + 3, "inside the tried section"},
        {nBucketStart + 100, (size_t)(img.nNew + img.nTried), "inside the bucket section"},
        {img.raw.size() - 1, (size_t)(img.nNew + img.nTried), "one byte short"},
    };
    BOOST_FOREACH (const Cut& c, cuts) {
        dir.Spit(img.raw, c.offset);
        CAddrMan loaded;
        CAddrDB adb;
        BOOST_CHECK_MESSAGE(adb.Read(loaded), "salvage " << c.where);
        bool anyTried = true;
        BOOST_CHECK_MESSAGE(Held(loaded, &anyTried) == Prefix(img, c.complete), "records kept " << c.where
                            << ": " << loaded.size() << " of " << c.complete);
        BOOST_CHECK(!anyTried);
        CheckConsistent(loaded);
        BOOST_CHECK(boost::filesystem::exists(dir.Corrupt()));
        BOOST_CHECK(!boost::filesystem::exists(dir.File()));
        std::cout << "salvage " << c.where << ": kept " << loaded.size() << " of " << (img.nNew + img.nTried) << std::endl;
        boost::filesystem::remove(dir.Corrupt());
    }
}

BOOST_AUTO_TEST_CASE(addrman_salvage_flipped_byte)
{
    PeersDatDir dir;
    CAddrManTest am;
    WriteSampleAddrman(am);
    const PeersImage img(dir.Slurp(dir.File()));

    const size_t k = 300; // a record in the middle of the file
    std::vector<char> bad = img.raw;
    bad[img.Offset(k) + 3] ^= 0x40;
    dir.Spit(bad);

    CAddrMan loaded;
    CAddrDB adb;
    BOOST_CHECK(adb.Read(loaded));
    bool anyTried = true;
    std::set<std::string> held = Held(loaded, &anyTried);
    BOOST_CHECK(!anyTried);
    BOOST_FOREACH (const std::string& s, Prefix(img, k))
        BOOST_CHECK_MESSAGE(held.count(s), "record before the flipped one lost: " << s);
    BOOST_CHECK(dir.Slurp(dir.Corrupt()) == bad); // the damaged bytes are kept as found
    BOOST_CHECK(!boost::filesystem::exists(dir.File()));
    CheckConsistent(loaded);
    std::cout << "salvage after a flipped byte in record " << k << ": kept " << loaded.size() << " of " << img.recs.size() << std::endl;
}

BOOST_AUTO_TEST_CASE(addrman_salvage_refuses_foreign_and_tiny_files)
{
    PeersDatDir dir;
    CAddrManTest am;
    WriteSampleAddrman(am);
    std::vector<char> raw = dir.Slurp(dir.File());

    std::vector<char> foreign = raw;
    foreign[0] ^= 0x01; // wrong network magic
    dir.Spit(foreign);
    CAddrMan loaded;
    CAddrDB adb;
    BOOST_CHECK(!adb.Read(loaded));
    BOOST_CHECK_EQUAL(loaded.size(), 0u);
    BOOST_CHECK(dir.Slurp(dir.File()) == foreign); // untouched, not renamed
    BOOST_CHECK(!boost::filesystem::exists(dir.Corrupt()));

    dir.Spit(raw, 31);
    BOOST_CHECK(!adb.Read(loaded));
    dir.Spit(raw, 0);
    BOOST_CHECK(!adb.Read(loaded));
    BOOST_CHECK(!boost::filesystem::exists(dir.Corrupt()));
}

BOOST_AUTO_TEST_CASE(addrman_salvage_hostile_header)
{
    PeersDatDir dir;
    const int badCounts[] = {INT_MAX, -1};
    BOOST_FOREACH (int nNew, badCounts) {
        for (unsigned char keySize : {(unsigned char)32, (unsigned char)31}) {
            CDataStream ss(SER_DISK, CLIENT_VERSION);
            ss << FLATDATA(Params().MessageStart());
            ss << (unsigned char)1 << keySize;
            for (int i = 0; i < keySize; i++)
                ss << (unsigned char)i;
            ss << nNew << (int)0 << (int)((1 << 10) ^ (1 << 30));
            ss << Hash(ss.begin(), ss.end());
            dir.Spit(std::vector<char>(ss.begin(), ss.end()));

            CAddrMan loaded;
            CAddrDB adb;
            BOOST_CHECK(!adb.Read(loaded));
            BOOST_CHECK_EQUAL(loaded.size(), 0u);
        }
    }
}

BOOST_AUTO_TEST_CASE(addrman_salvage_random_corruption)
{
    PeersDatDir dir;
    CAddrManTest am;
    WriteSampleAddrman(am);
    const std::vector<char> raw = dir.Slurp(dir.File());

    uint64_t state = 0x2545F4914F6CDD1DULL; // fixed seed: the same 2000 corruptions every run
    size_t nSalvaged = 0, nRefused = 0;
    for (int iter = 0; iter < 2000; iter++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        std::vector<char> bad = raw;
        bad[(state >> 33) % bad.size()] ^= (char)(1 + ((state >> 20) % 255));
        dir.Spit(bad);

        CAddrMan loaded;
        CAddrDB adb;
        if (adb.Read(loaded)) {
            nSalvaged++;
            bool anyTried = false;
            Held(loaded, &anyTried);
            BOOST_REQUIRE(!anyTried); // one flipped byte always breaks the checksum, so every entry is demoted
            CheckConsistent(loaded);
        } else {
            nRefused++;
            BOOST_REQUIRE_EQUAL(loaded.size(), 0u);
        }
        boost::filesystem::remove(dir.Corrupt());
    }
    std::cout << "2000 single-byte corruptions: " << nSalvaged << " salvaged, " << nRefused << " refused" << std::endl;
    BOOST_CHECK(nSalvaged > 1500);
}

BOOST_AUTO_TEST_SUITE_END()
