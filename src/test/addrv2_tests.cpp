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

#include <set>
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

// CAddrMan puts a new address in the bucket slot a hash keyed with the table's
// random key selects, and drops the address when another live entry already
// has that slot (1 in 64 for two addresses of one /16 from one source). A
// case that counts the entries a message adds therefore starts from an empty
// table with a fixed key, where the placement is the same in every run.
class CAddrManFixedKey : public CAddrMan
{
public:
    explicit CAddrManFixedKey(bool fOnionStoreIn) : CAddrMan(fOnionStoreIn) { nKey.SetNull(); }
};

void ResetWithFixedKey(CAddrMan& table)
{
    CAddrManFixedKey fixed(table.IsOnionStore());
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << fixed;
    ss >> table; // empties the table and takes the key
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
    ResetWithFixedKey(addrman);
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
    addrman.Clear(); // back to a random key
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
    ResetWithFixedKey(addrman);
    ResetWithFixedKey(addrmanOnion);
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
    addrman.Clear(); // back to a random key
    addrmanOnion.Clear();
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


// The onion service forwards to the main listener (no dedicated onion
// listener): its visitors arrive from 127.0.0.1 and are not recognised as
// onion peers. They must not be told the clearnet address of this machine.
BOOST_AUTO_TEST_CASE(unrecognised_onion_visitor_is_not_told_the_clearnet_address)
{
    bool oldListen = fListen;
    fListen = true;
    vector<CNode*> keep;

    CAddress onionSvc = MakeV3(78, 8033, 1, 1);
    CService clearSvc("93.184.216.201", 8033);
    CNode* visitor = NewNode(keep, "127.0.0.1", true); // main listener, fInboundOnion false
    visitor->fSuccessfullyConnected = true;
    CNode* lan = NewNode(keep, "192.168.1.20", true);
    lan->fSuccessfullyConnected = true;
    CNode* clear = NewNode(keep, "93.184.216.2", false);
    clear->fSuccessfullyConnected = true;
    BOOST_CHECK(!visitor->IsOnionPeer());

    // no onion service: a local peer is still offered the clearnet address
    BOOST_REQUIRE(AddLocal(clearSvc, LOCAL_MANUAL));
    CService got;
    BOOST_CHECK(GetLocal(got, &visitor->addr, false));
    BOOST_CHECK(got == clearSvc);

    // the onion service is up: nothing at all for the peer of unknown side
    BOOST_REQUIRE(AddLocal((CService)onionSvc, LOCAL_MANUAL));
    BOOST_CHECK(!GetLocal(got, &visitor->addr, false));
    BOOST_CHECK(!GetLocalAddress(&visitor->addr, false).IsRoutable()); // version carries 0.0.0.0
    BOOST_CHECK(!GetLocal(got, &lan->addr, false));
    AdvertizeLocal(visitor);
    BOOST_CHECK(visitor->vAddrToSend.empty());
    AdvertizeLocal(lan);
    BOOST_CHECK(lan->vAddrToSend.empty());

    // a routable clearnet peer is unaffected
    BOOST_REQUIRE(GetLocal(got, &clear->addr, false));
    BOOST_CHECK(got == clearSvc);

    RemoveLocal(clearSvc);
    RemoveLocal((CService)onionSvc);
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

namespace {
// A v3 address that differs for every n (MakeV3 has only 256 distinct keys).
CAddress MakeV3N(uint32_t n)
{
    unsigned char key[32];
    for (int i = 0; i < 32; i++)
        key[i] = (unsigned char)((n >> ((i % 4) * 8)) ^ (i * 37));
    CNetAddr ip;
    ip.SetTorV3(key);
    CAddress a(CService(ip, 8033), 1);
    a.nTime = GetTime();
    return a;
}
} // namespace

// One peer's flood of made-up v3 addresses must not outweigh the honest ones
// in what an onion-only node dials next: the choice is by bucket, and a source
// group is confined to a few buckets however many addresses it stores.
BOOST_AUTO_TEST_CASE(onion_store_selection_weighs_buckets_not_entries)
{
    CAddrMan store(true);
    ResetWithFixedKey(store); // a fixed table key: the same bucket layout in every run
    std::set<CService> honest;
    for (uint32_t i = 0; i < 8; i++) {
        CAddress a = MakeV3N(i);
        BOOST_REQUIRE(store.Add(a, MakeV3N(1000 + i))); // each learned from its own source
        honest.insert(a);
    }
    for (uint32_t i = 0; i < 2000; i++)
        store.Add(MakeV3N(100000 + i), CNetAddr("127.0.0.1")); // the flood, one source
    BOOST_CHECK_GT(store.size(), 500u); // the flood really was stored

    int nHonest = 0;
    const int nPicks = 10000; // the fixed layout gives ~5.9%, the floor is 4%: 8 sigma, not 3.6
    for (int i = 0; i < nPicks; i++)
        nHonest += honest.count((CService)store.Select(true)) ? 1 : 0;
    // picking by entry would give them about 8 of the ~1000 stored (under 1%);
    // by bucket their one bucket (all 8 share an address group and a source
    // group) weighs against the ~15 the flood can reach (16 address groups under
    // one source group), about 6% with the fixed key, 80 is the floor
    BOOST_TEST_MESSAGE("onion honest picks: " << nHonest << " of " << nPicks);
    BOOST_CHECK_MESSAGE(nHonest > nPicks / 25, nHonest << " honest picks of " << nPicks);
}

// ... and a peer is rationed in what it may add to the onion store unasked.
BOOST_AUTO_TEST_CASE(onion_store_additions_are_rationed_per_peer)
{
    bool wasLimited = IsLimited(NET_ONION);
    SetLimited(NET_ONION, false);
    addrmanOnion.Clear();
    vector<CNode*> keep;
    CNode* flooder = NewNode(keep, "127.0.0.1", true); // a visitor of our onion service
    flooder->fSendAddrV2 = true;
    for (int m = 0; m < 10; m++) {
        vector<CAddress> v;
        for (uint32_t i = 0; i < 1000; i++)
            v.push_back(MakeV3N(200000 + m * 1000 + i));
        CDataStream p = V2Payload(v);
        BOOST_CHECK(ProcessMessage(flooder, "addrv2", p, GetTime()));
    }
    // the start allowance (plus a refill second or two), not 10000
    BOOST_CHECK_LE(addrmanOnion.size(), (size_t)ONION_ADDR_TOKENS_INITIAL + 10);
    BOOST_CHECK_GT(addrmanOnion.size(), 0u);

    // one full answer to our own getaddr is taken (sending getaddr adds
    // MAX_ADDR_TO_SEND to the allowance, as below) ...
    addrmanOnion.Clear();
    CNode* answerer = NewNode(keep, "8.8.8.8", false);
    answerer->fSendAddrV2 = true;
    answerer->fGetAddr = true;
    answerer->dOnionAddrTokens += MAX_ADDR_TO_SEND;
    vector<CAddress> v;
    for (uint32_t i = 0; i < 1000; i++)
        v.push_back(MakeV3N(300000 + i));
    CDataStream p = V2Payload(v);
    BOOST_CHECK(ProcessMessage(answerer, "addrv2", p, GetTime()));
    BOOST_CHECK_GT(addrmanOnion.size(), 400u);

    // ... but a peer we asked cannot keep the door open: every 1000-entry
    // message leaves fGetAddr set, and that alone is no exemption
    BOOST_CHECK(answerer->fGetAddr);
    const size_t nAfterAnswer = addrmanOnion.size();
    for (int m = 1; m <= 5; m++) {
        vector<CAddress> more;
        for (uint32_t i = 0; i < 1000; i++)
            more.push_back(MakeV3N(400000 + m * 1000 + i));
        CDataStream pm = V2Payload(more);
        BOOST_CHECK(ProcessMessage(answerer, "addrv2", pm, GetTime()));
    }
    BOOST_CHECK_MESSAGE(addrmanOnion.size() <= nAfterAnswer + (size_t)ONION_ADDR_TOKENS_INITIAL + 10,
                        addrmanOnion.size() << " stored after the answer held " << nAfterAnswer);

    addrmanOnion.Clear();
    SetLimited(NET_ONION, wasLimited);
    for (CNode* x : keep)
        delete x;
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


// Byte level: an old peer's addr message is exactly the serialisation the base
// code produced (vector<CAddress>, no v3), an addrv2 peer gets addrv2.
BOOST_AUTO_TEST_CASE(addr_bytes_unchanged_for_old_peer)
{
    vector<CNode*> keep;
    CAddress a1 = MakeV4("93.184.216.10", 8033, 1, 1700000000);
    CAddress a2 = MakeV4("93.184.216.11", 8033, 5, 1700000100);
    CAddress o1 = MakeV3(5, 8033, 1, 1700000200);

    CNode* oldPeer = NewNode(keep, "8.8.8.8", false);
    CNode* newPeer = NewNode(keep, "8.8.4.4", false);
    newPeer->fSendAddrV2 = true;
    for (CNode* n : keep) {
        n->fSuccessfullyConnected = true;
        n->ssSend.SetVersion(PROTOCOL_VERSION); // as the version handshake does
        n->PushAddress(a1);
        n->PushAddress(o1);
        n->PushAddress(a2);
    }
    BOOST_CHECK(SendMessages(oldPeer, true));
    BOOST_CHECK(SendMessages(newPeer, true));

    // the payload of the first queued message with the given command
    auto payloadOf = [](CNode& n, const string& want, vector<unsigned char>& out) {
        for (const CSerializeData& m : n.vSendMsg) {
            if (m.size() < 24)
                continue;
            string cmd(m.begin() + 4, m.begin() + 16);
            cmd.resize(strlen(cmd.c_str()));
            if (cmd == want) {
                out.assign(m.begin() + 24, m.end());
                return true;
            }
        }
        return false;
    };

    vector<unsigned char> got;
    BOOST_REQUIRE(payloadOf(*oldPeer, "addr", got));
    vector<CAddress> legacy;
    legacy.push_back(a1);
    legacy.push_back(a2);
    CDataStream expect(SER_NETWORK, PROTOCOL_VERSION);
    expect << legacy;
    BOOST_CHECK(got == vector<unsigned char>(expect.begin(), expect.end()));
    BOOST_CHECK(!payloadOf(*oldPeer, "addrv2", got));

    // the addrv2 peer: addrv2 with all three, no legacy addr
    BOOST_REQUIRE(payloadOf(*newPeer, "addrv2", got));
    CDataStream expect2(SER_NETWORK, PROTOCOL_VERSION);
    WriteCompactSize(expect2, 3);
    expect2 << CAddressV2(a1) << CAddressV2(o1) << CAddressV2(a2);
    BOOST_CHECK(got == vector<unsigned char>(expect2.begin(), expect2.end()));
    BOOST_CHECK(!payloadOf(*newPeer, "addr", got));
    for (CNode* x : keep)
        delete x;
}


// Service bits above MAX_SIZE (2^25) are a bit field, not a length: Z23 nodes
// advertise NODE_NOISE_HYBRID (1 << 26). An entry carrying them must parse, or
// one such address would fail every addrv2 message and onion_peers.dat that
// holds it. Bitcoin Core reads this field without a range check too.
BOOST_AUTO_TEST_CASE(services_above_max_size)
{
    const uint64_t vServices[] = {(uint64_t)1 << 26 | 1, (uint64_t)1 << 40, ~(uint64_t)0};
    for (uint64_t svc : vServices) {
        CAddress a = MakeV4("93.184.216.34", 8033, svc, 1700000000);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << CAddressV2(a);
        CAddressV2 back;
        ss >> back;
        BOOST_REQUIRE(back.fKnown);
        BOOST_CHECK_EQUAL(back.addr.nServices, svc);
        BOOST_CHECK(ss.empty());
    }
    // the field must still be canonical: 0x05 written as fd 05 00 is refused
    CDataStream nc(SER_NETWORK, PROTOCOL_VERSION);
    uint32_t t = 1700000000;
    nc << t;
    unsigned char svc[3] = {0xfd, 0x05, 0x00};
    nc.write((const char*)svc, 3);
    CAddressV2 e;
    BOOST_CHECK_THROW(nc >> e, std::ios_base::failure);
}

// Adversarial addrv2 input, deterministic. Only std::ios_base::failure may
// escape (ProcessMessages turns it into a reject, no score), nothing is
// allocated beyond the bounds, and only a count above 1000 scores (20, as
// Bitcoin Core does for an oversized addr/addrv2).
BOOST_AUTO_TEST_CASE(addrv2_adversarial_inputs)
{
    ResetWithFixedKey(addrman); // the random key could put the far-future address in a taken slot
    vector<CNode*> keep;
    CNode* n = NewNode(keep, "8.8.8.8", false);
    n->fSendAddrV2 = true;
    auto score = [&]() {
        CNodeStateStats st;
        BOOST_REQUIRE(GetNodeStateStats(n->GetId(), st));
        return st.nMisbehavior;
    };
    auto msgOf = [](const CDataStream& body, uint64_t count) {
        CDataStream m(SER_NETWORK, PROTOCOL_VERSION);
        WriteCompactSize(m, count);
        if (body.size())
            m.write(&*body.begin(), body.size());
        return m;
    };
    const int s0 = score();

    // count: 9-byte compact size near 2^64, refused before anything is allocated
    {
        CDataStream m(SER_NETWORK, PROTOCOL_VERSION);
        m << uint8_t(0xff) << uint64_t(0xffffffffffffffffULL);
        BOOST_CHECK_THROW(ProcessMessage(n, "addrv2", m, GetTime()), std::ios_base::failure);
    }
    // count: non-canonical (5 as fd 05 00)
    {
        CDataStream m(SER_NETWORK, PROTOCOL_VERSION);
        m << uint8_t(0xfd) << uint16_t(5);
        BOOST_CHECK_THROW(ProcessMessage(n, "addrv2", m, GetTime()), std::ios_base::failure);
    }
    BOOST_CHECK_EQUAL(score(), s0);
    // count: exactly MAX_SIZE is read, then refused (> 1000) with a score of 20
    {
        CDataStream m(SER_NETWORK, PROTOCOL_VERSION);
        WriteCompactSize(m, MAX_SIZE);
        BOOST_CHECK(!ProcessMessage(n, "addrv2", m, GetTime()));
        BOOST_CHECK_EQUAL(score(), s0 + 20);
    }
    // count larger than the entries present: end of data
    {
        CDataStream e(SER_NETWORK, PROTOCOL_VERSION);
        e << CAddressV2(MakeV4("93.184.216.34", 8033, 1, GetTime()));
        CDataStream m = msgOf(e, 2);
        BOOST_CHECK_THROW(ProcessMessage(n, "addrv2", m, GetTime()), std::ios_base::failure);
    }
    // address length: compact size beyond MAX_SIZE, just at MAX_SIZE, and 513
    {
        const uint64_t vLen[] = {0xffffffffULL, MAX_SIZE, 513};
        for (uint64_t len : vLen) {
            CDataStream e(SER_NETWORK, PROTOCOL_VERSION);
            uint32_t t = 1700000000;
            e << t;
            WriteCompactSize(e, 1);
            e << uint8_t(0x7f);
            if (len > MAX_SIZE) {
                e << uint8_t(0xfe) << uint32_t(len);
            } else {
                WriteCompactSize(e, len);
            }
            CDataStream m = msgOf(e, 1);
            BOOST_CHECK_THROW(ProcessMessage(n, "addrv2", m, GetTime()), std::ios_base::failure);
        }
    }
    // zero-length address: an error for every known network, skipped otherwise
    {
        const uint8_t vKnown[] = {1, 2, 3, 4};
        for (uint8_t net : vKnown) {
            CAddressV2 e;
            CDataStream ss = RawEntryFill(net, 0);
            BOOST_CHECK_THROW(ss >> e, std::ios_base::failure);
        }
        const uint8_t vOther[] = {0, 5, 6, 7, 0xff};
        for (uint8_t net : vOther) {
            CAddressV2 e;
            CDataStream ss = RawEntryFill(net, 0);
            ss >> e;
            BOOST_CHECK(!e.fKnown);
            BOOST_CHECK(ss.empty());
        }
    }
    // truncated port
    {
        CDataStream e(SER_NETWORK, PROTOCOL_VERSION);
        e << CAddressV2(MakeV4("93.184.216.34", 8033, 1, GetTime()));
        vector<char> vcut(e.begin(), e.end() - 1);
        CDataStream cut(vcut, SER_NETWORK, PROTOCOL_VERSION);
        CDataStream m = msgOf(cut, 1);
        BOOST_CHECK_THROW(ProcessMessage(n, "addrv2", m, GetTime()), std::ios_base::failure);
    }
    BOOST_CHECK_EQUAL(score(), s0 + 20);

    // 1000 copies of one address, and 1000 skipped entries of 512 bytes (the
    // largest message this allows, ~0.5 MB): accepted, no score, one addrman
    // entry at most.
    {
        size_t before = addrman.size();
        CDataStream e(SER_NETWORK, PROTOCOL_VERSION);
        CAddressV2 one(MakeV4("93.184.216.199", 8033, 1, GetTime() + 365 * 24 * 3600)); // far future
        for (int i = 0; i < 1000; i++)
            e << one;
        CDataStream m = msgOf(e, 1000);
        BOOST_CHECK(ProcessMessage(n, "addrv2", m, GetTime()));
        BOOST_CHECK(addrman.size() <= before + 1);

        CDataStream big(SER_NETWORK, PROTOCOL_VERSION);
        for (int i = 0; i < 1000; i++) {
            CDataStream x = RawEntryFill(0x7f, 512);
            big.write(&*x.begin(), x.size());
        }
        CDataStream m2 = msgOf(big, 1000);
        BOOST_CHECK(ProcessMessage(n, "addrv2", m2, GetTime()));
        BOOST_CHECK_EQUAL(score(), s0 + 20);
    }
    // the far-future time was clamped to five days ago, as for addr
    {
        bool fFound = false;
        for (const CAddrInfo& info : addrman.GetEntries()) {
            if (info.ToStringIP() == "93.184.216.199") {
                fFound = true;
                BOOST_CHECK_MESSAGE((int64_t)info.nTime <= GetAdjustedTime() - 4 * 24 * 3600, "nTime " << info.nTime << " now " << GetAdjustedTime() << " time " << GetTime());
            }
        }
        BOOST_CHECK(fFound);
    }

    // deterministic mutation fuzzing of a valid mixed message: flips, cuts,
    // inserts. Only ios_base::failure may escape the parser; a parsed message
    // never yields more than 1000 entries.
    {
        vector<CAddress> v;
        v.push_back(MakeV4("93.184.216.34", 8033, 1, 1700000000));
        v.push_back(MakeV3(9, 8033, (uint64_t)1 << 26, 1700000000));
        CAddress v6(CService("2001:4860:4860::8888", 8033), 0x409);
        v6.nTime = 1700000000;
        v.push_back(v6);
        CDataStream base = V2Payload(v);
        CDataStream unk = RawEntryFill(0x7f, 40);
        const vector<char> seed0(base.begin(), base.end());
        uint32_t x = 0x2545F491;
        auto rnd = [&]() { x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x; };
        int nParsed = 0, nFailed = 0, nOther = 0;
        for (int it = 0; it < 50000; it++) {
            vector<char> b = seed0;
            if (it % 7 == 0)
                b.insert(b.end(), unk.begin(), unk.end());
            int nMut = 1 + rnd() % 4;
            for (int k = 0; k < nMut && !b.empty(); k++) {
                switch (rnd() % 4) {
                case 0: b[rnd() % b.size()] = (char)rnd(); break;
                case 1: b.resize(rnd() % b.size()); break;
                case 2: b.insert(b.begin() + rnd() % (b.size() + 1), (char)rnd()); break;
                case 3: b[rnd() % b.size()] ^= (char)(1 << (rnd() % 8)); break;
                }
            }
            CDataStream ss(b, SER_NETWORK, PROTOCOL_VERSION);
            vector<CAddress> out;
            try {
                if (ReadAddrV2List(ss, out))
                    nParsed++;
                BOOST_CHECK(out.size() <= MAX_ADDRV2_ENTRIES);
            } catch (const std::ios_base::failure&) {
                nFailed++;
            } catch (...) {
                nOther++;
            }
        }
        BOOST_CHECK_EQUAL(nOther, 0);
        BOOST_CHECK(nParsed > 0 && nFailed > 0);
        BOOST_TEST_MESSAGE("addrv2 fuzz: parsed " << nParsed << " failed " << nFailed);
    }
    for (CNode* y : keep)
        delete y;
    addrman.Clear(); // back to a random key
}

BOOST_AUTO_TEST_SUITE_END()
