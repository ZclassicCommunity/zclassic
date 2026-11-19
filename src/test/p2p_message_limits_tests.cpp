// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Behavioural tests that pin the size caps and ban scores of the P2P message
// handlers. Every case feeds a complete wire message (header, checksum,
// payload) to a CNode through the public ProcessMessages() and reads the ban
// score back with GetNodeStateStats(). Only handlers that reject before they
// touch the chain are exercised, so the tests stay fast and need no blocks.
//
// Pinned today (not a statement about what the limits should be):
//   inv / getdata  > MAX_INV_SZ (50000)           -> +20
//   addr           > 1000                          -> +20
//   headers        > MAX_HEADERS_RESULTS (160)     -> +20
//   filteradd data > MAX_SCRIPT_ELEMENT_SIZE (520) -> +100
//   filteradd without filterload                   -> +100
//   filterload failing IsWithinSizeConstraints     -> +100
//

#include "addrman.h"
#include "arith_uint256.h"
#include "bloom.h"
#include "chainparams.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "primitives/block.h"
#include "protocol.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "utiltime.h"
#include "version.h"

#include <string.h>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

CService PeerAddr(uint32_t i)
{
    struct in_addr s;
    s.s_addr = 0x0a0b0000u | (i & 0xffff); // never a real peer: nothing connects
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

struct LimitsFixture : public TestingSetup {
    std::vector<CNode*> nodes;
    uint64_t savedServices;

    LimitsFixture() : savedServices(nLocalServices.load())
    {
        CNode::ClearBanned();
        nLocalServices = savedServices | NODE_BLOOM; // filterload/filteradd are served only with NODE_BLOOM
    }

    ~LimitsFixture()
    {
        for (CNode* n : nodes)
            delete n; // the destructor runs FinalizeNode
        nodes.clear();
        nLocalServices = savedServices;
        addrman.Clear();
        CNode::ClearBanned();
    }

    CNode* NewPeer(bool fInbound)
    {
        CNode* n = new CNode(INVALID_SOCKET, CAddress(PeerAddr((uint32_t)nodes.size() + 1)), "", fInbound);
        nodes.push_back(n); // InitializeNode ran in the constructor
        n->nVersion = PROTOCOL_VERSION;
        n->fSuccessfullyConnected = true;
        n->fRelayTxes = true;
        return n;
    }

    /** Queue one complete, well-formed wire message on the node. */
    static void Queue(CNode* node, const std::string& cmd, const CDataStream& payload)
    {
        CMessageHeader hdr(Params().MessageStart(), cmd.c_str(), payload.size());
        uint256 h = Hash(payload.begin(), payload.end());
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &h, sizeof(nChecksum));
        hdr.nChecksum = nChecksum;

        CDataStream hs(SER_NETWORK, PROTOCOL_VERSION);
        hs << hdr;
        BOOST_REQUIRE_EQUAL(hs.size(), 24u);

        node->vRecvMsg.push_back(CNetMessage(Params().MessageStart(), SER_NETWORK, PROTOCOL_VERSION));
        CNetMessage& m = node->vRecvMsg.back();
        BOOST_REQUIRE_EQUAL(m.readHeader(&hs[0], hs.size()), 24);
        if (payload.size() > 0)
            BOOST_REQUIRE_EQUAL((unsigned)m.readData(&payload[0], payload.size()), payload.size());
        m.nTime = GetTimeMicros();
        BOOST_REQUIRE(m.complete());
    }

    /** Process everything queued (ProcessMessages handles one message per call). */
    static void Drain(CNode* node)
    {
        for (int i = 0; i < 16 && !node->vRecvMsg.empty() && !node->fDisconnect; i++)
            BOOST_CHECK_NO_THROW(ProcessMessages(node));
    }

    static void Send(CNode* node, const std::string& cmd, const CDataStream& payload)
    {
        Queue(node, cmd, payload);
        Drain(node);
    }

    static int Score(CNode* node)
    {
        CNodeStateStats st;
        BOOST_REQUIRE(GetNodeStateStats(node->GetId(), st));
        return st.nMisbehavior;
    }
};

CDataStream InvPayload(size_t n)
{
    std::vector<CInv> v;
    v.reserve(n);
    for (size_t i = 0; i < n; i++)
        v.push_back(CInv(MSG_TX, ArithToUint256(arith_uint256(i + 1))));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << v;
    return ss;
}

CDataStream AddrPayload(size_t n)
{
    std::vector<CAddress> v;
    v.reserve(n);
    for (size_t i = 0; i < n; i++) {
        struct in_addr s;
        s.s_addr = htonl(0x5db8d800u + (uint32_t)i); // 93.184.x.y, routable
        CAddress a(CService(CNetAddr(s), 8033));
        a.nTime = (unsigned int)GetTime();
        v.push_back(a);
    }
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << v;
    return ss;
}

CDataStream FilterLoadPayload(size_t nBytes, uint32_t nHashFuncs)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    std::vector<unsigned char> data(nBytes, 0);
    ss << data << nHashFuncs << (uint32_t)0 << (unsigned char)BLOOM_UPDATE_NONE;
    return ss;
}

CDataStream FilterAddPayload(size_t nBytes)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    std::vector<unsigned char> data(nBytes, 0x42);
    ss << data;
    return ss;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2p_message_limits_tests, LimitsFixture)

BOOST_AUTO_TEST_CASE(harness_delivers_a_message)
{
    // sanity of the harness itself: a plain ping is consumed and scores nothing
    CNode* n = NewPeer(true);
    CDataStream p(SER_NETWORK, PROTOCOL_VERSION);
    p << (uint64_t)0x1122334455667788ULL;
    Queue(n, "ping", p);
    BOOST_CHECK(ProcessMessages(n));
    BOOST_CHECK(n->vRecvMsg.empty());
    BOOST_CHECK_EQUAL(Score(n), 0);
}

BOOST_AUTO_TEST_CASE(inv_cap)
{
    CNode* atCap = NewPeer(true);
    Send(atCap, "inv", InvPayload(MAX_INV_SZ));
    BOOST_CHECK_EQUAL(Score(atCap), 0);

    CNode* over = NewPeer(true);
    Send(over, "inv", InvPayload(MAX_INV_SZ + 1));
    BOOST_CHECK_EQUAL(Score(over), 20);
}

BOOST_AUTO_TEST_CASE(getdata_cap)
{
    // At the cap the request is accepted and served at once: none of the
    // 50000 transactions is known, so a "notfound" reply is queued (nSendSize > 0).
    // Over the cap the handler refuses before touching the request: no reply.
    CNode* atCap = NewPeer(true);
    Queue(atCap, "getdata", InvPayload(MAX_INV_SZ));
    BOOST_CHECK(ProcessMessages(atCap));
    BOOST_CHECK_EQUAL(Score(atCap), 0);
    BOOST_CHECK_GT(atCap->nSendSize, 0u);
    BOOST_CHECK(atCap->vRecvGetData.empty());

    CNode* over = NewPeer(true);
    Queue(over, "getdata", InvPayload(MAX_INV_SZ + 1));
    BOOST_CHECK(ProcessMessages(over));
    BOOST_CHECK_EQUAL(Score(over), 20);
    BOOST_CHECK_EQUAL(over->nSendSize, 0u);
    BOOST_CHECK(over->vRecvGetData.empty());
}

BOOST_AUTO_TEST_CASE(addr_cap)
{
    CNode* atCap = NewPeer(true);
    Send(atCap, "addr", AddrPayload(1000));
    BOOST_CHECK_EQUAL(Score(atCap), 0);

    CNode* over = NewPeer(true);
    Send(over, "addr", AddrPayload(1001));
    BOOST_CHECK_EQUAL(Score(over), 20);
}

BOOST_AUTO_TEST_CASE(headers_cap)
{
    // The cap is checked on the claimed count, before any header is read. A body
    // holding fewer headers than claimed stops at "end of data": no score from the
    // handler when the claim is within the cap, +20 when it is over.
    CBlockHeader genesis = Params().GenesisBlock();
    CDataStream one(SER_NETWORK, PROTOCOL_VERSION);
    one << genesis;
    WriteCompactSize(one, 0); // tx count

    auto claim = [&](size_t n) {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        WriteCompactSize(ss, n);
        ss.write(&one[0], one.size());
        return ss;
    };

    CNode* atCap = NewPeer(false);
    Send(atCap, "headers", claim(MAX_HEADERS_RESULTS));
    BOOST_CHECK_EQUAL(Score(atCap), 0);

    CNode* over = NewPeer(false);
    Send(over, "headers", claim(MAX_HEADERS_RESULTS + 1));
    BOOST_CHECK_EQUAL(Score(over), 20);

    // a huge claim is refused the same way, without allocating
    CNode* huge = NewPeer(false);
    Send(huge, "headers", claim(MAX_SIZE));
    BOOST_CHECK_EQUAL(Score(huge), 20);

    // one known header (the genesis block) is a normal, unscored answer
    CNode* ok = NewPeer(false);
    Send(ok, "headers", claim(1));
    BOOST_CHECK_EQUAL(Score(ok), 0);
}

BOOST_AUTO_TEST_CASE(filteradd_cap)
{
    CBloomFilter bf(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    CDataStream load(SER_NETWORK, PROTOCOL_VERSION);
    load << bf;

    CNode* atCap = NewPeer(true);
    Send(atCap, "filterload", load);
    BOOST_REQUIRE_EQUAL(Score(atCap), 0);
    BOOST_REQUIRE(atCap->pfilter != NULL);
    Send(atCap, "filteradd", FilterAddPayload(MAX_SCRIPT_ELEMENT_SIZE));
    BOOST_CHECK_EQUAL(Score(atCap), 0);

    CNode* over = NewPeer(true);
    Send(over, "filterload", load);
    BOOST_REQUIRE_EQUAL(Score(over), 0);
    Send(over, "filteradd", FilterAddPayload(MAX_SCRIPT_ELEMENT_SIZE + 1));
    BOOST_CHECK_EQUAL(Score(over), 100);
}

BOOST_AUTO_TEST_CASE(filteradd_without_filterload)
{
    // FINDING: the "filteradd without a filter loaded -> +100" branch in main.cpp
    // (the else of "if (pfrom->pfilter)") is unreachable: the CNode constructor
    // always allocates a default CBloomFilter, which is a full, match-everything
    // filter. A filteradd on a fresh peer is therefore absorbed and scores nothing.
    // This pins today's behaviour; it is not a statement that it is right.
    CNode* n = NewPeer(true);
    BOOST_REQUIRE(n->pfilter != NULL);
    CBloomFilter* before = n->pfilter;
    Send(n, "filteradd", FilterAddPayload(8));
    BOOST_CHECK_EQUAL(Score(n), 0);
    BOOST_CHECK(n->pfilter == before);
}

BOOST_AUTO_TEST_CASE(filterload_size_constraints)
{
    // exactly at both limits: accepted, and the filter is replaced
    CNode* atCap = NewPeer(true);
    
    Send(atCap, "filterload", FilterLoadPayload(MAX_BLOOM_FILTER_SIZE, MAX_HASH_FUNCS));
    BOOST_CHECK_EQUAL(Score(atCap), 0);
    BOOST_CHECK(atCap->pfilter != NULL);

    // one byte too many: scored, and the peer's filter is left as it was
    CNode* big = NewPeer(true);
    CBloomFilter* bigBefore = big->pfilter;
    Send(big, "filterload", FilterLoadPayload(MAX_BLOOM_FILTER_SIZE + 1, 1));
    BOOST_CHECK_EQUAL(Score(big), 100);
    BOOST_CHECK(big->pfilter == bigBefore);

    // one hash function too many
    CNode* hashes = NewPeer(true);
    CBloomFilter* hashesBefore = hashes->pfilter;
    Send(hashes, "filterload", FilterLoadPayload(16, MAX_HASH_FUNCS + 1));
    BOOST_CHECK_EQUAL(Score(hashes), 100);
    BOOST_CHECK(hashes->pfilter == hashesBefore);
}

BOOST_AUTO_TEST_CASE(filter_messages_refused_without_node_bloom)
{
    nLocalServices = savedServices & ~(uint64_t)NODE_BLOOM;

    CNode* a = NewPeer(true);
    CBloomFilter* aBefore = a->pfilter;
    Send(a, "filterload", FilterLoadPayload(16, 1));
    BOOST_CHECK_EQUAL(Score(a), 100);
    BOOST_CHECK(a->pfilter == aBefore);

    CNode* b = NewPeer(true);
    Send(b, "filteradd", FilterAddPayload(8));
    BOOST_CHECK_EQUAL(Score(b), 100);
}

BOOST_AUTO_TEST_CASE(repeated_getaddr_queues_nothing)
{
    // fill the address manager so the first answer is not empty
    std::vector<CAddress> pool;
    CDataStream ps = AddrPayload(400);
    ps >> pool;
    addrman.Add(pool, CNetAddr(PeerAddr(0)), 0);
    BOOST_REQUIRE_GT(addrman.size(), 20u);

    CNode* n = NewPeer(true);
    CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
    Send(n, "getaddr", empty);
    BOOST_CHECK_GT(n->vAddrToSend.size(), 0u);
    BOOST_CHECK(n->fSentAddr);
    BOOST_CHECK_EQUAL(Score(n), 0);

    // the queued answer is flushed by SendMessages in real life; emulate that
    n->vAddrToSend.clear();
    Send(n, "getaddr", empty);
    BOOST_CHECK_EQUAL(n->vAddrToSend.size(), 0u);
    BOOST_CHECK_EQUAL(Score(n), 0);

    // an outbound peer is never answered at all
    CNode* out = NewPeer(false);
    Send(out, "getaddr", empty);
    BOOST_CHECK_EQUAL(out->vAddrToSend.size(), 0u);
}

BOOST_AUTO_TEST_CASE(ping_with_truncated_body)
{
    // A ping needs an 8-byte nonce. Shorter bodies must be dropped without a
    // crash, an escaping exception or a ban score. (The reject reply goes to a
    // dummy socket, so the node may end up disconnected; that is the harness.)
    for (size_t len = 0; len < 8; len++) {
        CNode* n = NewPeer(true);
        CDataStream p(SER_NETWORK, PROTOCOL_VERSION);
        for (size_t i = 0; i < len; i++)
            p << (unsigned char)(0xa0 + i);
        Queue(n, "ping", p);
        BOOST_CHECK_NO_THROW(ProcessMessages(n));
        BOOST_CHECK_EQUAL(Score(n), 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
