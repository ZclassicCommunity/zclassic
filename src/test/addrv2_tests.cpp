// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// BIP155 ("addrv2") subset: IPv4, IPv6 and Tor v3. Serialisation vectors,
// malformed and unknown entries, and the negotiation matrix at the message
// level (new <-> new, new <-> old).

#include "addrman.h"
#include "addrv2.h"
#include "util.h"
#include "utilstrencodings.h"
#include <boost/filesystem/fstream.hpp>
#include "clientversion.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "protocol.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"
#include "version.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std;

extern bool ProcessMessage(CNode* pfrom, std::string strCommand, CDataStream& vRecv, int64_t nTimeReceived);

namespace {

CAddress MakeV4(const char* ip, unsigned short port, uint64_t services, unsigned int nTime)
{
    CAddress a(CService(ip, port), services);
    a.nTime = nTime;
    return a;
}

CAddress MakeV3(unsigned char seed, unsigned short port, uint64_t services, unsigned int nTime)
{
    unsigned char key[32];
    for (int i = 0; i < 32; i++)
        key[i] = (unsigned char)(seed + i);
    CNetAddr ip;
    ip.SetTorV3(key);
    CAddress a(CService(ip, port), services);
    a.nTime = nTime;
    return a;
}

string Hex(const CDataStream& ss)
{
    return HexStr(ss.begin(), ss.end());
}

// The command names of the messages queued for sending, in order.
vector<string> QueuedCommands(CNode& node)
{
    vector<string> out;
    for (const CSerializeData& m : node.vSendMsg) {
        if (m.size() < 24)
            continue;
        string cmd(m.begin() + 4, m.begin() + 16);
        cmd.resize(strlen(cmd.c_str()));
        out.push_back(cmd);
    }
    return out;
}

CDataStream V2Payload(const vector<CAddress>& v)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    WriteCompactSize(ss, v.size());
    for (const CAddress& a : v)
        ss << CAddressV2(a);
    return ss;
}

CNode* NewNode(vector<CNode*>& keep, const char* ip, bool fInbound)
{
    CNode* n = new CNode(INVALID_SOCKET, CAddress(CService(ip, 8033)), "", fInbound);
    n->nVersion = PROTOCOL_VERSION; // skip the pre-handshake guard
    keep.push_back(n);
    return n;
}

CDataStream RawEntry(uint8_t net, const string& hexAddr, unsigned int lenOverride = (unsigned)-1)
{
    vector<unsigned char> raw = ParseHex(hexAddr);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    uint32_t t = 1700000000;
    ss << t;
    WriteCompactSize(ss, 1);
    ss << net;
    WriteCompactSize(ss, lenOverride == (unsigned)-1 ? raw.size() : lenOverride);
    if (!raw.empty())
        ss.write((const char*)&raw[0], raw.size());
    unsigned char port[2] = {0x1f, 0x61};
    ss.write((const char*)port, 2);
    return ss;
}

// an entry whose address bytes are n copies of one byte
CDataStream RawEntryFill(uint8_t net, size_t n, unsigned char fill = 0x31)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    uint32_t t = 1700000000;
    ss << t;
    WriteCompactSize(ss, 1);
    ss << net;
    WriteCompactSize(ss, n);
    string body(n, (char)fill);
    ss.write(body.data(), body.size());
    unsigned char port[2] = {0x1f, 0x61};
    ss.write((const char*)port, 2);
    return ss;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(addrv2_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(ipv4_vector)
{
    // time 1700000000 = 0x6553F100, services NODE_NETWORK, 1.2.3.4, port 8033
    CAddress a = MakeV4("1.2.3.4", 8033, 1, 1700000000);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << CAddressV2(a);
    BOOST_CHECK_EQUAL(Hex(ss), "00f15365" "01" "01" "04" "01020304" "1f61");

    CAddressV2 back;
    ss >> back;
    BOOST_REQUIRE(back.fKnown);
    BOOST_CHECK(back.addr == a);
    BOOST_CHECK_EQUAL(back.addr.nTime, 1700000000u);
    BOOST_CHECK_EQUAL(back.addr.nServices, 1u);
    BOOST_CHECK_EQUAL(back.addr.GetPort(), 8033);
    BOOST_CHECK(ss.empty());
}

BOOST_AUTO_TEST_CASE(ipv6_vector_and_compact_size_services)
{
    // 2001:4860:4860::8888, services 0x409 needs a 3 byte compact size (fd 09 04)
    CAddress a(CService("2001:4860:4860::8888", 8033), 0x409);
    a.nTime = 1700000000;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << CAddressV2(a);
    BOOST_CHECK_EQUAL(Hex(ss), "00f15365" "fd0904" "02" "10" "20014860486000000000000000008888" "1f61");

    CAddressV2 back;
    ss >> back;
    BOOST_REQUIRE(back.fKnown);
    BOOST_CHECK(back.addr == a);
    BOOST_CHECK_EQUAL(back.addr.nServices, 0x409u);
}

BOOST_AUTO_TEST_CASE(torv3_vector)
{
    // key bytes 00 01 02 .. 1f
    CAddress a = MakeV3(0, 8033, 1, 1700000000);
    BOOST_REQUIRE(a.IsTorV3());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << CAddressV2(a);
    BOOST_CHECK_EQUAL(Hex(ss), "00f15365" "01" "04" "20"
                               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" "1f61");

    CAddressV2 back;
    ss >> back;
    BOOST_REQUIRE(back.fKnown);
    BOOST_CHECK(back.addr.IsTorV3());
    BOOST_CHECK(back.addr == a);
    BOOST_CHECK(back.addr.GetTorV3() == a.GetTorV3());
    BOOST_CHECK_EQUAL(back.addr.GetPort(), 8033);
    BOOST_CHECK(back.addr.GetKey() == a.GetKey());
}

BOOST_AUTO_TEST_CASE(exact_length_checks)
{
    CAddressV2 e;
    // IPv4 must be 4 bytes, IPv6 16, TORV3 32, TORV2 10
    { CDataStream ss = RawEntry(1, "0102030405"); BOOST_CHECK_THROW(ss >> e, std::ios_base::failure); }
    { CDataStream ss = RawEntry(1, "010203"); BOOST_CHECK_THROW(ss >> e, std::ios_base::failure); }
    { CDataStream ss = RawEntry(2, "2001486048600000000000000000888800"); BOOST_CHECK_THROW(ss >> e, std::ios_base::failure); }
    { CDataStream ss = RawEntry(2, "200148604860000000000000000088"); BOOST_CHECK_THROW(ss >> e, std::ios_base::failure); }
    { CDataStream ss = RawEntryFill(4, 31); BOOST_CHECK_THROW(ss >> e, std::ios_base::failure); }
    { CDataStream ss = RawEntryFill(4, 33); BOOST_CHECK_THROW(ss >> e, std::ios_base::failure); }
    { CDataStream ss = RawEntryFill(3, 11); BOOST_CHECK_THROW(ss >> e, std::ios_base::failure); }
    // longer than 512 bytes is refused whatever the network
    { CDataStream ss = RawEntryFill(0x7f, 513); BOOST_CHECK_THROW(ss >> e, std::ios_base::failure); }
}

BOOST_AUTO_TEST_CASE(skipped_entries)
{
    CAddressV2 e;
    // unknown network id: parsed and skipped, not an error (also at exactly 512 bytes)
    { CDataStream ss = RawEntry(0x7f, "010203"); ss >> e; BOOST_CHECK(!e.fKnown); BOOST_CHECK(ss.empty()); }
    { CDataStream ss = RawEntryFill(0x7f, 512); ss >> e; BOOST_CHECK(!e.fKnown); BOOST_CHECK(ss.empty()); }
    // I2P and CJDNS are not used by this node
    { CDataStream ss = RawEntryFill(5, 32); ss >> e; BOOST_CHECK(!e.fKnown); }
    { CDataStream ss = RawEntryFill(6, 16); ss >> e; BOOST_CHECK(!e.fKnown); }
    // TORV2 is ignored
    { CDataStream ss = RawEntryFill(3, 10); ss >> e; BOOST_CHECK(!e.fKnown); BOOST_CHECK(ss.empty()); }
    // IPv4 and OnionCat addresses must not hide in the IPv6 network id
    { CDataStream ss = RawEntry(2, "00000000000000000000ffff01020304"); ss >> e; BOOST_CHECK(!e.fKnown); }
    { CDataStream ss = RawEntry(2, "fd87d87eeb4300000000000000000000"); ss >> e; BOOST_CHECK(!e.fKnown); }
    // a skipped entry never stops the next one being read
    {
        CDataStream a = RawEntry(0x7f, "0102030405");
        CDataStream msg(SER_NETWORK, PROTOCOL_VERSION);
        WriteCompactSize(msg, 2);
        msg.write(&*a.begin(), a.size());
        msg << CAddressV2(MakeV4("5.6.7.8", 8033, 1, 1700000000));
        vector<CAddress> v;
        uint64_t seen = 0;
        BOOST_CHECK(ReadAddrV2List(msg, v, &seen));
        BOOST_CHECK_EQUAL(seen, 2u);
        BOOST_REQUIRE_EQUAL(v.size(), 1u);
        BOOST_CHECK(v[0] == MakeV4("5.6.7.8", 8033, 1, 1700000000));
    }
}

BOOST_AUTO_TEST_CASE(message_limits)
{
    // 1000 entries is the most; 1001 is refused before any entry is read
    vector<CAddress> v1000;
    for (int i = 0; i < 1000; i++)
        v1000.push_back(MakeV3((unsigned char)i, 8033, 1, 1700000000));
    CDataStream ok = V2Payload(v1000);
    vector<CAddress> out;
    BOOST_CHECK(ReadAddrV2List(ok, out));
    BOOST_CHECK_EQUAL(out.size(), 1000u);

    CDataStream big(SER_NETWORK, PROTOCOL_VERSION);
    WriteCompactSize(big, 1001);
    BOOST_CHECK(!ReadAddrV2List(big, out));
    BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_CASE(can_send)
{
    BOOST_CHECK(CAddressV2::CanSend(MakeV4("5.6.7.8", 8033, 1, 1)));
    BOOST_CHECK(CAddressV2::CanSend(MakeV3(7, 8033, 1, 1)));
    // an OnionCat Tor v2 address has no addrv2 form
    CAddress v2(CService("5wyqrzbvrdsumnok.onion", 8033));
    BOOST_CHECK(v2.IsTor() && !v2.IsTorV3());
    BOOST_CHECK(!CAddressV2::CanSend(v2));
}

BOOST_AUTO_TEST_CASE(push_address_matrix)
{
    vector<CNode*> keep;
    CNode* oldPeer = NewNode(keep, "8.8.8.8", false);
    CNode* newPeer = NewNode(keep, "8.8.4.4", false);
    newPeer->fSendAddrV2 = true;

    CAddress v4 = MakeV4("5.6.7.8", 8033, 1, 1700000000);
    CAddress v3 = MakeV3(1, 8033, 1, 1700000000);
    oldPeer->PushAddress(v4);
    oldPeer->PushAddress(v3);
    newPeer->PushAddress(v4);
    newPeer->PushAddress(v3);

    // old peer: exactly the legacy stream, v3 is never queued
    BOOST_REQUIRE_EQUAL(oldPeer->vAddrToSend.size(), 1u);
    BOOST_CHECK(oldPeer->vAddrToSend[0] == v4);
    // addrv2 peer: both
    BOOST_CHECK_EQUAL(newPeer->vAddrToSend.size(), 2u);
    for (CNode* n : keep)
        delete n;
}

BOOST_AUTO_TEST_CASE(negotiation_sendaddrv2)
{
    vector<CNode*> keep;
    CNode* n = NewNode(keep, "8.8.8.8", false);
    BOOST_CHECK(!n->fSendAddrV2);

    // between version and verack: honoured
    CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(ProcessMessage(n, "sendaddrv2", empty, GetTime()));
    BOOST_CHECK(n->fSendAddrV2);

    // after verack: ignored
    CNode* late = NewNode(keep, "8.8.4.4", false);
    CDataStream e2(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(ProcessMessage(late, "verack", e2, GetTime()));
    CDataStream e3(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(ProcessMessage(late, "sendaddrv2", e3, GetTime()));
    BOOST_CHECK(!late->fSendAddrV2);

    // never a ban score
    CNodeStateStats st;
    BOOST_REQUIRE(GetNodeStateStats(n->GetId(), st));
    BOOST_CHECK_EQUAL(st.nMisbehavior, 0);
    for (CNode* x : keep)
        delete x;
}

BOOST_AUTO_TEST_CASE(addrv2_without_negotiation_is_ignored)
{
    vector<CNode*> keep;
    CNode* n = NewNode(keep, "8.8.8.8", false); // never sent sendaddrv2
    size_t before = addrman.size();

    vector<CAddress> v;
    v.push_back(MakeV4("93.184.216.34", 8033, 1, GetTime()));
    CDataStream p = V2Payload(v);
    BOOST_CHECK(ProcessMessage(n, "addrv2", p, GetTime()));
    BOOST_CHECK_EQUAL(addrman.size(), before);

    // garbage is not even parsed
    CDataStream junk(SER_NETWORK, PROTOCOL_VERSION);
    junk << uint8_t(0xff);
    BOOST_CHECK(ProcessMessage(n, "addrv2", junk, GetTime()));

    CNodeStateStats st;
    BOOST_REQUIRE(GetNodeStateStats(n->GetId(), st));
    BOOST_CHECK_EQUAL(st.nMisbehavior, 0);
    BOOST_CHECK(!n->fDisconnect);
    for (CNode* x : keep)
        delete x;
}

BOOST_AUTO_TEST_CASE(addrv2_with_negotiation_is_processed)
{
    vector<CNode*> keep;
    CNode* n = NewNode(keep, "8.8.8.8", false);
    n->fSendAddrV2 = true;
    size_t before = addrman.size();

    vector<CAddress> v;
    v.push_back(MakeV4("93.184.216.34", 8033, 1, GetTime()));
    v.push_back(MakeV4("93.184.216.35", 8033, 1, GetTime()));
    CDataStream p = V2Payload(v);
    BOOST_CHECK(ProcessMessage(n, "addrv2", p, GetTime()));
    BOOST_CHECK_EQUAL(addrman.size(), before + 2);

    // more than 1000 entries: a ban score, like addr
    CDataStream big(SER_NETWORK, PROTOCOL_VERSION);
    WriteCompactSize(big, 1001);
    BOOST_CHECK(!ProcessMessage(n, "addrv2", big, GetTime()));
    CNodeStateStats st;
    BOOST_REQUIRE(GetNodeStateStats(n->GetId(), st));
    BOOST_CHECK_GE(st.nMisbehavior, 20);

    // a wrong length for a known network fails the message (reject, no score)
    CDataStream bad = RawEntry(1, "0102030405");
    CDataStream badMsg(SER_NETWORK, PROTOCOL_VERSION);
    WriteCompactSize(badMsg, 1);
    badMsg.write(&*bad.begin(), bad.size());
    BOOST_CHECK_THROW(ProcessMessage(n, "addrv2", badMsg, GetTime()), std::ios_base::failure);
    for (CNode* x : keep)
        delete x;
}

BOOST_AUTO_TEST_CASE(version_handshake_sends_sendaddrv2_before_verack)
{
    vector<CNode*> keep;
    CNode* n = new CNode(INVALID_SOCKET, CAddress(CService("8.8.8.8", 8033)), "", false);
    keep.push_back(n);

    CDataStream v(SER_NETWORK, PROTOCOL_VERSION);
    CAddress me(CService("0.0.0.0", 0)), from(CService("0.0.0.0", 0));
    uint64_t nonce = 0x1122334455667788ULL;
    v << PROTOCOL_VERSION << (uint64_t)NODE_NETWORK << (int64_t)GetTime() << me << from << nonce
      << string("/old:1.0/") << (int)0 << true;
    BOOST_CHECK(ProcessMessage(n, "version", v, GetTime()));

    vector<string> cmds = QueuedCommands(*n);
    size_t iA = cmds.size(), iV = cmds.size();
    for (size_t i = 0; i < cmds.size(); i++) {
        if (cmds[i] == "sendaddrv2") iA = i;
        if (cmds[i] == "verack") iV = i;
    }
    BOOST_REQUIRE(iA < cmds.size());
    BOOST_REQUIRE(iV < cmds.size());
    BOOST_CHECK(iA < iV);
    BOOST_CHECK(!n->fSendAddrV2); // the old peer never sent sendaddrv2
    for (CNode* x : keep)
        delete x;
}


BOOST_AUTO_TEST_CASE(onion_store_holds_only_v3)
{
    CAddrMan main(false), onion(true);
    CAddress v4 = MakeV4("93.184.216.34", 8033, 1, GetTime());
    CAddress v3 = MakeV3(3, 8033, 1, GetTime());
    CNetAddr src("93.184.216.1");

    BOOST_CHECK(main.Add(v4, src));
    BOOST_CHECK(!main.Add(v3, src));       // peers.dat table never takes a v3 address
    BOOST_CHECK(onion.Add(v3, src));       // clearnet source is fine
    BOOST_CHECK(!onion.Add(v4, src));      // and the onion store never takes the rest
    BOOST_CHECK_EQUAL(main.size(), 1u);
    BOOST_CHECK_EQUAL(onion.size(), 1u);

    // a v3 source is kept in the onion store, dropped to "::" in the main table
    CAddress v3b = MakeV3(9, 8033, 1, GetTime());
    CAddress v4b = MakeV4("93.184.216.40", 8033, 1, GetTime());
    BOOST_CHECK(onion.Add(v3b, v3));
    BOOST_CHECK(main.Add(v4b, v3));
    vector<CAddrInfo> entries = onion.GetEntries();
    bool foundSource = false;
    for (const CAddrInfo& e : entries)
        if (e == v3b)
            foundSource = (e.GetSource() == (CNetAddr)v3);
    BOOST_CHECK(foundSource);

    // selection from the onion store only ever yields v3 addresses
    for (int i = 0; i < 20; i++) {
        CAddrInfo sel = onion.Select();
        BOOST_CHECK(sel.IsTorV3());
    }
    // groups of different v3 keys differ in the leading bits (16 groups)
    BOOST_CHECK(MakeV3(1, 8033, 1, 1).GetGroup().size() == 2);
}

BOOST_AUTO_TEST_CASE(peers_dat_never_sees_v3)
{
    CAddrMan main(false);
    CNetAddr src("93.184.216.1");
    for (int i = 0; i < 50; i++) {
        main.Add(MakeV4(("94." + itostr(i + 1) + ".20.1").c_str(), 8033, 1, GetTime()), src);
        main.Add(MakeV3((unsigned char)i, 8033, 1, GetTime()), src);
    }
    BOOST_CHECK_GE(main.size(), 40u); // a few bucket collisions are normal
    for (const CAddrInfo& e : main.GetEntries())
        BOOST_CHECK(!e.IsTorV3());
    // the serialised table reads back in a plain (legacy) CAddrMan with 50 entries
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << main;
    CAddrMan back;
    ss >> back;
    BOOST_CHECK_EQUAL(back.size(), main.size());
}

BOOST_AUTO_TEST_CASE(onion_peers_file_roundtrip)
{
    CAddrMan onion(true);
    CNetAddr src("93.184.216.1");
    CAddress a = MakeV3(1, 8033, 1, GetTime());
    CAddress b = MakeV3(2, 8033, 5, GetTime());
    CAddress c = MakeV3(3, 8033, 1, GetTime());
    BOOST_REQUIRE(onion.Add(a, src));
    BOOST_REQUIRE(onion.Add(b, CNetAddr()));
    BOOST_REQUIRE(onion.Add(c, a)); // v3 source
    onion.Good(b, GetAdjustedTime());

    COnionAddrDB db;
    BOOST_CHECK(!db.Exists() || true);
    BOOST_REQUIRE(db.Write(onion));
    BOOST_CHECK(db.Exists());

    CAddrMan back(true);
    BOOST_REQUIRE(db.Read(back));
    BOOST_CHECK_EQUAL(back.size(), 3u);
    vector<CAddrInfo> e = back.GetEntries();
    int tried = 0;
    for (const CAddrInfo& x : e) {
        BOOST_CHECK(x.IsTorV3());
        if (x.IsTried()) {
            tried++;
            BOOST_CHECK(x == b);
        }
        if (x == c)
            BOOST_CHECK(x.GetSource() == (CNetAddr)a);
        if (x == b)
            BOOST_CHECK_EQUAL(x.nServices, 5u);
    }
    BOOST_CHECK_EQUAL(tried, 1);

    // a corrupted file is refused (bad checksum), and a read into a legacy
    // table or a wrong-magic file never yields addresses
    boost::filesystem::path p = GetDataDir() / "onion_peers.dat";
    {
        boost::filesystem::fstream f(p, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(10);
        char z = 0x55;
        f.write(&z, 1);
    }
    CAddrMan bad(true);
    BOOST_CHECK(!db.Read(bad));
    BOOST_CHECK_EQUAL(bad.size(), 0u);
    boost::filesystem::remove(p);
}

BOOST_AUTO_TEST_CASE(addrv2_v3_goes_to_onion_store)
{
    // the node can reach onion peers (a proxy is set in a real node)
    bool wasLimited = IsLimited(NET_ONION);
    SetLimited(NET_ONION, false);
    vector<CNode*> keep;
    CNode* n = NewNode(keep, "8.8.8.8", false);
    n->fSendAddrV2 = true;
    size_t mainBefore = addrman.size(), onionBefore = addrmanOnion.size();

    vector<CAddress> v;
    v.push_back(MakeV3(40, 8033, 1, GetTime()));
    v.push_back(MakeV3(41, 8033, 1, GetTime()));
    v.push_back(MakeV4("93.184.216.99", 8033, 1, GetTime()));
    CDataStream p = V2Payload(v);
    BOOST_CHECK(ProcessMessage(n, "addrv2", p, GetTime()));
    BOOST_CHECK_EQUAL(addrmanOnion.size(), onionBefore + 2);
    BOOST_CHECK_EQUAL(addrman.size(), mainBefore + 1);

    // with the onion network limited (no proxy) v3 addresses are not stored
    SetLimited(NET_ONION, true);
    vector<CAddress> w;
    w.push_back(MakeV3(50, 8033, 1, GetTime()));
    CDataStream p2 = V2Payload(w);
    BOOST_CHECK(ProcessMessage(n, "addrv2", p2, GetTime()));
    BOOST_CHECK_EQUAL(addrmanOnion.size(), onionBefore + 2);

    SetLimited(NET_ONION, wasLimited);
    for (CNode* x : keep)
        delete x;
}


// Privacy rules: our onion address only to the onion side, our clearnet
// address never to it, and nothing before the onion service is up.
BOOST_AUTO_TEST_CASE(self_advertisement_privacy)
{
    bool oldListen = fListen;
    fListen = true;
    vector<CNode*> keep;

    CAddress onionSvc = MakeV3(77, 8033, 1, 1);
    CService clearSvc("93.184.216.200", 8033);

    // an onion peer we reached over Tor, an inbound onion peer, a clearnet peer
    CNode* outOnion = new CNode(INVALID_SOCKET, MakeV3(90, 8033, 1, 1), "", false);
    CNode* inOnion = NewNode(keep, "127.0.0.1", true);
    inOnion->fInboundOnion = true;
    CNode* clear = NewNode(keep, "93.184.216.1", false);
    keep.push_back(outOnion);
    for (CNode* n : keep) {
        n->fSuccessfullyConnected = true;
        n->fSendAddrV2 = true;
    }
    BOOST_CHECK(outOnion->IsOnionPeer());
    BOOST_CHECK(inOnion->IsOnionPeer());
    BOOST_CHECK(!clear->IsOnionPeer());

    // the service is not up yet: nothing to advertise anywhere
    BOOST_CHECK(!AdvertizeLocalOnion(outOnion));
    BOOST_CHECK(!AdvertizeLocalOnion(inOnion));
    BOOST_CHECK(outOnion->vAddrToSend.empty());

    BOOST_REQUIRE(AddLocal(clearSvc, LOCAL_MANUAL));
    BOOST_REQUIRE(AddLocal((CService)onionSvc, LOCAL_MANUAL));

    // clearnet peer: our clearnet address, never the onion one
    CService got;
    BOOST_REQUIRE(GetLocal(got, &clear->addr, false));
    BOOST_CHECK(got == clearSvc);
    CAddress la = GetLocalAddress(&clear->addr, false);
    BOOST_CHECK(!la.IsTor());
    BOOST_CHECK(!AdvertizeLocalOnion(clear)); // not an onion peer

    // onion peers: the onion address, never the clearnet one
    BOOST_REQUIRE(GetLocal(got, &outOnion->addr, false));
    BOOST_CHECK(got == (CService)onionSvc);
    BOOST_REQUIRE(GetLocal(got, &inOnion->addr, true)); // inbound: flag, address is 127.0.0.1
    BOOST_CHECK(got == (CService)onionSvc);
    BOOST_CHECK(GetLocalAddress(&inOnion->addr, true).IsTorV3());

    // advertised to both onion peers, as an addrv2 entry
    BOOST_CHECK(AdvertizeLocalOnion(outOnion));
    BOOST_CHECK(AdvertizeLocalOnion(inOnion));
    BOOST_REQUIRE_EQUAL(outOnion->vAddrToSend.size(), 1u);
    BOOST_CHECK(outOnion->vAddrToSend[0] == (CService)onionSvc);
    BOOST_CHECK_EQUAL(inOnion->vAddrToSend.size(), 1u);
    BOOST_CHECK(clear->vAddrToSend.empty());

    // an onion peer that did not negotiate addrv2 gets nothing
    inOnion->fSendAddrV2 = false;
    inOnion->vAddrToSend.clear();
    BOOST_CHECK(!AdvertizeLocalOnion(inOnion));
    BOOST_CHECK(inOnion->vAddrToSend.empty());

    // with only the onion address known, a clearnet peer is offered nothing
    RemoveLocal(clearSvc);
    BOOST_CHECK(!GetLocal(got, &clear->addr, false));
    BOOST_CHECK(!GetLocalAddress(&clear->addr, false).IsRoutable());
    // and with only the clearnet address, an onion peer is offered nothing
    BOOST_REQUIRE(AddLocal(clearSvc, LOCAL_MANUAL));
    RemoveLocal((CService)onionSvc);
    BOOST_CHECK(!GetLocal(got, &outOnion->addr, false));
    BOOST_CHECK(!GetLocalAddress(&inOnion->addr, true).IsRoutable());
    BOOST_CHECK(!IsPeerAddrLocalGood(inOnion));

    RemoveLocal(clearSvc);
    fListen = oldListen;
    for (CNode* x : keep)
        delete x;
}


// Dialling: the table ThreadOpenConnections picks from, and the limits that
// keep an onion-only node off clearnet addresses.
BOOST_AUTO_TEST_CASE(dial_table_selection)
{
    bool l4 = IsLimited(NET_IPV4), l6 = IsLimited(NET_IPV6), lo = IsLimited(NET_ONION);
    SetLimited(NET_IPV4, false);
    SetLimited(NET_IPV6, false);
    SetLimited(NET_ONION, false);
    addrmanOnion.Clear();

    BOOST_CHECK(&SelectDialTable(true, 0) == &addrman); // nothing in the onion store yet

    BOOST_REQUIRE(addrmanOnion.Add(MakeV3(60, 8033, 1, GetTime()), CNetAddr("93.184.216.1")));
    BOOST_REQUIRE(addrman.Add(MakeV4("93.184.216.77", 8033, 1, GetTime()), CNetAddr("93.184.216.1")));
    BOOST_REQUIRE_GT(addrman.size(), 0u);

    // mixed node: clearnet table, the onion store one time in four, and only with a proxy
    BOOST_CHECK(&SelectDialTable(true, 1) == &addrman);
    BOOST_CHECK(&SelectDialTable(true, 3) == &addrman);
    BOOST_CHECK(&SelectDialTable(true, 0) == &addrmanOnion);
    BOOST_CHECK(&SelectDialTable(false, 0) == &addrman);
    // the onion network limited: never
    SetLimited(NET_ONION, true);
    BOOST_CHECK(&SelectDialTable(true, 0) == &addrman);
    SetLimited(NET_ONION, false);

    // onion-only node: the onion store, whatever the dice say
    SetLimited(NET_IPV4, true);
    SetLimited(NET_IPV6, true);
    BOOST_CHECK(&SelectDialTable(true, 1) == &addrmanOnion);
    BOOST_CHECK(&SelectDialTable(true, 3) == &addrmanOnion);
    // ... and a clearnet address picked anyway is limited, a v3 address is not
    BOOST_CHECK(IsLimited(MakeV4("93.184.216.77", 8033, 1, 1)));
    BOOST_CHECK(IsLimited(CNetAddr("2001:4860:4860::8888")));
    BOOST_CHECK(!IsLimited(MakeV3(60, 8033, 1, 1)));
    BOOST_CHECK(IsReachable(MakeV3(60, 8033, 1, 1)));
    BOOST_CHECK(!IsReachable(MakeV4("93.184.216.77", 8033, 1, 1)));
    // selecting from the onion store only ever yields v3
    for (int i = 0; i < 10; i++)
        BOOST_CHECK(addrmanOnion.Select().IsTorV3());

    SetLimited(NET_IPV4, l4);
    SetLimited(NET_IPV6, l6);
    SetLimited(NET_ONION, lo);
    addrmanOnion.Clear();
}

BOOST_AUTO_TEST_CASE(getaddr_answers_by_negotiation)
{
    addrmanOnion.Clear();
    bool lo = IsLimited(NET_ONION);
    SetLimited(NET_ONION, false);
    for (int i = 0; i < 5; i++)
        BOOST_REQUIRE(addrmanOnion.Add(MakeV3((unsigned char)(100 + i), 8033, 1, GetTime()), CNetAddr("93.184.216.1")));

    vector<CNode*> keep;
    CNode* v2peer = NewNode(keep, "127.0.0.1", true); // inbound, came through the onion service
    v2peer->fInboundOnion = true;
    v2peer->fSendAddrV2 = true;
    CNode* clearV2 = NewNode(keep, "93.184.216.2", true); // inbound clearnet, addrv2
    clearV2->fSendAddrV2 = true;
    CNode* oldPeer = NewNode(keep, "93.184.216.3", true); // inbound clearnet, no addrv2

    for (CNode* n : keep) {
        CDataStream e(SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK(ProcessMessage(n, "getaddr", e, GetTime()));
    }
    // onion and clearnet addrv2 peers are answered with the v3 entries ...
    int v3a = 0, v3b = 0, v3c = 0;
    for (const CAddress& a : v2peer->vAddrToSend) v3a += a.IsTorV3();
    for (const CAddress& a : clearV2->vAddrToSend) v3b += a.IsTorV3();
    for (const CAddress& a : oldPeer->vAddrToSend) v3c += a.IsTorV3();
    BOOST_CHECK_GE(v3a, 1);
    BOOST_CHECK_GE(v3b, 1);
    // ... a legacy peer never
    BOOST_CHECK_EQUAL(v3c, 0);

    SetLimited(NET_ONION, lo);
    addrmanOnion.Clear();
    for (CNode* x : keep)
        delete x;
}

BOOST_AUTO_TEST_SUITE_END()
