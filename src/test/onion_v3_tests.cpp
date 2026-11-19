// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Identity of v3 onion addresses (CNetAddr carries them in a side vector, the
// 16-byte ip field is zero). These tests pin down that two different v3
// addresses are different everywhere an address is compared, hashed, grouped,
// matched against a subnet or ban, looked up as "local", and that the legacy
// 16-byte wire/disk form never carries one (it has no room for 32 bytes).

#include "addrman.h"
#include "clientversion.h"
#include "net.h"
#include "netbase.h"
#include "protocol.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "version.h"

#include <set>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std;

// Two real v3 addresses (checksum and version byte valid). Their 32-byte keys
// start with different leading bits (0xEE.. and 0x24..).
static const char* const ONION_A = "53iroqdss55ogk35gw7253nmg6izwkz4obuf572i3zckwntzafljc3qd.onion";
static const char* const ONION_B = "esjehhby2wjrgxb6ht3syvxibwazrxjigds7dexdiohbzjjgmvxdp4yd.onion";

static const unsigned char ZERO16[16] = {0};
// The IPv4-mapped 0.0.0.0 that the code already uses for "no address"
// (GetLocalAddress, PushVersion): invalid and unroutable on every peer.
static const unsigned char PLACEHOLDER16[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0};

static vector<unsigned char> Bytes(const CDataStream& ss)
{
    return vector<unsigned char>(ss.begin(), ss.end());
}

BOOST_FIXTURE_TEST_SUITE(onion_v3_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(v3_identity)
{
    CNetAddr a(ONION_A), b(ONION_B), none;
    BOOST_REQUIRE(a.IsTor() && a.IsValid());
    BOOST_REQUIRE(b.IsTor() && b.IsValid());

    // equal to itself and to a re-parse, different from every other v3
    BOOST_CHECK(a == a);
    BOOST_CHECK(a == CNetAddr(ONION_A));
    BOOST_CHECK(!(a != CNetAddr(ONION_A)));
    BOOST_CHECK(a != b);
    BOOST_CHECK(!(a == b));
    BOOST_CHECK((a < b) != (b < a));
    BOOST_CHECK(!(a < a));

    // and never equal to the unspecified address "::" (all-zero ip field)
    BOOST_CHECK(a != none);
    BOOST_CHECK(none != a);
    BOOST_CHECK((a < none) != (none < a));

    // a v3 address is not a v2 (OnionCat) address either
    CNetAddr v2("5wyqrzbvrdsumnok.onion");
    BOOST_CHECK(a != v2);

    // hash and group tell them apart
    BOOST_CHECK(a.GetHash() != b.GetHash());
    BOOST_CHECK(a.GetHash() != none.GetHash());
    BOOST_CHECK(a.GetGroup() != b.GetGroup());
    BOOST_CHECK(a.GetGroup() == CNetAddr(ONION_A).GetGroup());
    BOOST_CHECK(a.GetGroup()[0] == NET_ONION);
    BOOST_CHECK(a.GetGroup() != none.GetGroup());

    // usable as a set/map key: two entries, not one
    set<CNetAddr> s;
    s.insert(a);
    s.insert(b);
    s.insert(CNetAddr(ONION_A));
    BOOST_CHECK_EQUAL(s.size(), 2U);
    BOOST_CHECK(s.count(a) == 1 && s.count(b) == 1 && s.count(none) == 0);

    // CService: same rules, port included
    CService sa(a, 8033), sa2(a, 8034), sb(b, 8033);
    BOOST_CHECK(sa == CService(a, 8033));
    BOOST_CHECK(sa != sa2);
    BOOST_CHECK(sa != sb);
    BOOST_CHECK(sa.GetKey() != sb.GetKey());
    BOOST_CHECK(sa.GetKey() == CService(a, 8033).GetKey());
    BOOST_CHECK(sa.GetKey() != sa2.GetKey());
}

BOOST_AUTO_TEST_CASE(v3_roundtrip_and_reuse)
{
    CNetAddr a(ONION_A), b(ONION_B);
    BOOST_CHECK_EQUAL(a.ToString(), string(ONION_A));
    BOOST_CHECK_EQUAL(a.ToStringIP(), string(ONION_A));
    BOOST_CHECK_EQUAL(b.ToStringIP(), string(ONION_B));
    BOOST_CHECK(CNetAddr(a.ToStringIP()) == a);
    BOOST_CHECK_EQUAL(CService(a, 8033).ToString(), string(ONION_A) + ":8033");
    BOOST_CHECK(CService(string(ONION_B) + ":8033", 0) == CService(b, 8033));

    // Re-initialising or re-setting an address that held a v3 key must not
    // leave the key behind.
    CNetAddr x(a);
    x.Init();
    BOOST_CHECK(!x.IsTor());
    BOOST_CHECK(x == CNetAddr());
    CNetAddr y(a);
    const unsigned char v4[4] = {1, 2, 3, 4};
    y.SetRaw(NET_IPV4, v4);
    BOOST_CHECK(!y.IsTor());
    BOOST_CHECK(y.IsIPv4());
    BOOST_CHECK(y == CNetAddr("1.2.3.4"));
    BOOST_CHECK_EQUAL(y.ToString(), "1.2.3.4");
    // a copy keeps the key and is independent
    CNetAddr c(a);
    c.SetIP(b);
    BOOST_CHECK(c == b);
    BOOST_CHECK(a == CNetAddr(ONION_A));
}

BOOST_AUTO_TEST_CASE(v3_not_local_because_another_is)
{
    CNetAddr a(ONION_A), b(ONION_B);
    {
        LOCK(cs_mapLocalHost);
        mapLocalHost.clear();
        LocalServiceInfo info;
        info.nScore = LOCAL_MANUAL;
        info.nPort = 8033;
        mapLocalHost[a] = info;
    }
    // our own onion is local, another onion is not, "::" is not
    BOOST_CHECK(IsLocal(CService(a, 8033)));
    BOOST_CHECK(!IsLocal(CService(b, 8033)));
    BOOST_CHECK(!IsLocal(CService(CNetAddr(), 8033)));
    BOOST_CHECK(!CNetAddr(ONION_B).IsLocal());
    {
        LOCK(cs_mapLocalHost);
        // a second own onion is a second entry
        LocalServiceInfo info;
        info.nScore = LOCAL_MANUAL;
        info.nPort = 8033;
        mapLocalHost[b] = info;
        BOOST_CHECK_EQUAL(mapLocalHost.size(), 2U);
    }
    RemoveLocal(CService(a, 8033));
    BOOST_CHECK(!IsLocal(CService(a, 8033)));
    BOOST_CHECK(IsLocal(CService(b, 8033)));
    RemoveLocal(CService(b, 8033));
    {
        LOCK(cs_mapLocalHost);
        BOOST_CHECK(mapLocalHost.empty());
    }
}

BOOST_AUTO_TEST_CASE(v3_subnet_and_ban)
{
    CNetAddr a(ONION_A), b(ONION_B);
    // an entry for one v3 matches that address only
    CSubNet sa(a.ToString());
    BOOST_CHECK(sa.IsValid());
    BOOST_CHECK(sa.Match(a));
    BOOST_CHECK(!sa.Match(b));
    BOOST_CHECK(!sa.Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!sa.Match(CNetAddr("2a00:1450::1")));
    BOOST_CHECK(sa == CSubNet(a.ToString()));
    BOOST_CHECK(sa != CSubNet(b.ToString()));
    // the form Ban() builds
    CSubNet sa128(a.ToString() + "/128");
    BOOST_CHECK(sa128.IsValid() && sa128.Match(a) && !sa128.Match(b));
    // the form ToString() prints (listbanned) parses back to the same entry,
    // so "setban <that> remove" works; any wider mask is refused
    BOOST_CHECK_EQUAL(sa128.ToString(), a.ToString() + "/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    CSubNet back(sa128.ToString());
    BOOST_CHECK(back.IsValid() && back == sa128 && back == sa);
    BOOST_CHECK(back.Match(a) && !back.Match(b));
    BOOST_CHECK(!CSubNet(a.ToString() + "/64").IsValid());
    BOOST_CHECK(!CSubNet(a.ToString() + "/0").IsValid());
    BOOST_CHECK(!CSubNet(a.ToString() + "/ffff:ffff::").IsValid());
    BOOST_CHECK(!CSubNet(a.ToString() + "/" + b.ToString()).IsValid());
    // no ordinary subnet, "::/0" included, swallows a v3 address
    BOOST_CHECK(!CSubNet("::/0").Match(a));
    BOOST_CHECK(!CSubNet("::").Match(a));
    BOOST_CHECK(!CSubNet("1.2.3.0/24").Match(a));
    // and a v3 entry does not match the unspecified address
    BOOST_CHECK(!sa.Match(CNetAddr()));

    CNode::ClearBanned();
    CNode::Ban(a);
    BOOST_CHECK(CNode::IsBanned(a));
    BOOST_CHECK(!CNode::IsBanned(b));
    BOOST_CHECK(!CNode::IsBanned(CNetAddr("1.2.3.4")));
    CNode::ClearBanned();
    CNode::Ban(CNetAddr("1.2.3.4"));
    BOOST_CHECK(!CNode::IsBanned(a));
    BOOST_CHECK(!CNode::IsBanned(b));
    CNode::ClearBanned();
}

BOOST_AUTO_TEST_CASE(v3_wire_form_is_never_zeros)
{
    CNetAddr a(ONION_A);
    CService sa(a, 8033);

    // CService / CAddress: 16 ip bytes + port; never the all-zero "::"
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << sa;
    vector<unsigned char> w = Bytes(ss);
    BOOST_REQUIRE_EQUAL(w.size(), 18U);
    BOOST_CHECK(memcmp(&w[0], ZERO16, 16) != 0);
    BOOST_CHECK(memcmp(&w[0], PLACEHOLDER16, 16) == 0);
    BOOST_CHECK(w[16] == 0x1f && w[17] == 0x61); // 8033, network order

    CDataStream sn(SER_NETWORK, PROTOCOL_VERSION);
    sn << a;
    w = Bytes(sn);
    BOOST_REQUIRE_EQUAL(w.size(), 16U);
    BOOST_CHECK(memcmp(&w[0], PLACEHOLDER16, 16) == 0);

    CAddress addr(sa, NODE_NETWORK);
    addr.nTime = 1700000000;
    CDataStream sc(SER_NETWORK, PROTOCOL_VERSION);
    sc << addr;
    w = Bytes(sc);
    BOOST_REQUIRE_EQUAL(w.size(), 4U + 8U + 18U);
    BOOST_CHECK(memcmp(&w[12], PLACEHOLDER16, 16) == 0);

    // what a peer reads back is an invalid, unroutable address, not a v3
    CAddress back;
    sc >> back;
    BOOST_CHECK(!back.IsTor());
    BOOST_CHECK(!back.IsValid());
    BOOST_CHECK(!back.IsRoutable());
}

BOOST_AUTO_TEST_CASE(v4_v6_wire_form_unchanged)
{
    // The exact bytes: 12-byte IPv4 mapping prefix + address, port big endian.
    CDataStream s4(SER_NETWORK, PROTOCOL_VERSION);
    s4 << CService("1.2.3.4", 8033);
    static const unsigned char want4[18] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
                                            1, 2, 3, 4, 0x1f, 0x61};
    vector<unsigned char> w = Bytes(s4);
    BOOST_REQUIRE_EQUAL(w.size(), 18U);
    BOOST_CHECK(memcmp(&w[0], want4, 18) == 0);

    CDataStream s6(SER_NETWORK, PROTOCOL_VERSION);
    s6 << CService("2a00:1450::1", 8033);
    static const unsigned char want6[18] = {0x2a, 0x00, 0x14, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                                            0x1f, 0x61};
    w = Bytes(s6);
    BOOST_REQUIRE_EQUAL(w.size(), 18U);
    BOOST_CHECK(memcmp(&w[0], want6, 18) == 0);

    // the unroutable placeholder and "::" keep their own bytes
    CDataStream s0(SER_NETWORK, PROTOCOL_VERSION);
    s0 << CService("0.0.0.0", 0) << CNetAddr();
    w = Bytes(s0);
    BOOST_REQUIRE_EQUAL(w.size(), 18U + 16U);
    BOOST_CHECK(memcmp(&w[0], PLACEHOLDER16, 16) == 0);
    BOOST_CHECK(memcmp(&w[18], ZERO16, 16) == 0);

    // reading into an object that held a v3 address replaces it fully
    CService x(CNetAddr(ONION_A), 1);
    CDataStream r(SER_NETWORK, PROTOCOL_VERSION);
    r << CService("1.2.3.4", 8033);
    r >> x;
    BOOST_CHECK(!x.IsTor());
    BOOST_CHECK(x == CService("1.2.3.4", 8033));
    BOOST_CHECK_EQUAL(x.ToString(), "1.2.3.4:8033");
}

BOOST_AUTO_TEST_CASE(v3_not_relayed_to_peers)
{
    CAddress v3(CService(CNetAddr(ONION_A), 8033), NODE_NETWORK);
    v3.nTime = GetAdjustedTime();
    CAddress v4(CService("8.8.8.8", 8033), NODE_NETWORK);
    v4.nTime = GetAdjustedTime();

    CNode node(INVALID_SOCKET, CAddress(CService("8.8.4.4", 8033), NODE_NETWORK));
    node.PushAddress(v3);
    BOOST_CHECK(node.vAddrToSend.empty());
    node.PushAddress(v4);
    BOOST_CHECK_EQUAL(node.vAddrToSend.size(), 1U);
    BOOST_CHECK(node.vAddrToSend[0] == v4);
}

BOOST_AUTO_TEST_CASE(v3_not_stored_in_addrman)
{
    CAddrMan addrman;
    CAddress v3(CService(CNetAddr(ONION_A), 8033), NODE_NETWORK);
    v3.nTime = GetAdjustedTime();
    CNetAddr src("250.1.2.3");
    BOOST_CHECK(!addrman.Add(v3, src));
    BOOST_CHECK(addrman.size() == 0);
    vector<CAddress> vAddr;
    vAddr.push_back(v3);
    BOOST_CHECK(!addrman.Add(vAddr, src));
    BOOST_CHECK(addrman.size() == 0);

    // a v4 address learned from a peer we reached by onion is stored, with a
    // source that is not a v3 (the file has no way to hold one)
    CAddress v4(CService("250.9.9.9", 8033), NODE_NETWORK);
    v4.nTime = GetAdjustedTime();
    BOOST_CHECK(addrman.Add(v4, CNetAddr(ONION_B)));
    BOOST_CHECK(addrman.size() == 1);

    // the serialized form (peers.dat) has no v3 in it and reads back
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << addrman;
    CAddrMan back;
    ss >> back;
    BOOST_CHECK(back.size() == 1);
    CAddrInfo got = back.Select();
    BOOST_CHECK_EQUAL(got.ToString(), v4.ToString());
    BOOST_CHECK(!got.IsTor());
}

BOOST_AUTO_TEST_SUITE_END()
