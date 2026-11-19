// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Serve-side guards of the getblocks, getheaders and mempool handlers
// (p2pserve.cpp). Every case feeds complete wire messages to a CNode through
// ProcessMessages(), as p2p_message_limits_tests does, and reads the reply
// queue, the disconnect flag and the ban score back.
//
//   locator of MAX_LOCATOR_SZ (101) entries -> served
//   locator of 102 entries                  -> fDisconnect, ban score 0, nothing served
//   mempool, again at +10 s, again at +61 s -> inv, nothing, inv (whitelisted: inv every time)
//   CChain::GetLocator at height 5,000,000  -> fewer than 101 entries
//

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "p2pserve.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "uint256.h"
#include "utiltime.h"
#include "version.h"

#include <string.h>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

CService ServePeerAddr(uint32_t i)
{
    struct in_addr s;
    s.s_addr = 0x0a0c0000u | (i & 0xffff); // never a real peer: nothing connects
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

uint256 FakeHash(uint32_t i)
{
    return ArithToUint256(arith_uint256(0x5e5e0000u + i));
}

struct ServeFixture : public TestingSetup {
    std::vector<CNode*> nodes;
    std::vector<CBlockIndex*> fakeBlocks;
    CBlockIndex* savedTip;

    ServeFixture() : savedTip(NULL)
    {
        CNode::ClearBanned();
        LOCK(cs_main);
        savedTip = chainActive.Tip();
    }

    ~ServeFixture()
    {
        for (CNode* n : nodes)
            delete n; // the destructor runs FinalizeNode
        nodes.clear();
        {
            LOCK(cs_main);
            chainActive.SetTip(savedTip);
            for (CBlockIndex* p : fakeBlocks) {
                mapBlockIndex.erase(p->GetBlockHash());
                delete p;
            }
            fakeBlocks.clear();
        }
        mempool.clear();
        SetMockTime(0);
        CNode::ClearBanned();
    }

    CNode* NewPeer(bool fInbound)
    {
        CNode* n = new CNode(INVALID_SOCKET, CAddress(ServePeerAddr((uint32_t)nodes.size() + 1)), "", fInbound);
        nodes.push_back(n); // InitializeNode ran in the constructor
        n->nVersion = PROTOCOL_VERSION;
        n->fSuccessfullyConnected = true;
        n->fRelayTxes = true;
        return n;
    }

    /** Append n index-only blocks (no block data) to the active chain; undone by the destructor. */
    void ExtendActiveChain(int n)
    {
        LOCK(cs_main);
        CBlockIndex* prev = chainActive.Tip();
        for (int i = 0; i < n; i++) {
            CBlockIndex* p = new CBlockIndex();
            p->pprev = prev;
            p->nHeight = prev->nHeight + 1;
            p->nTime = prev->nTime + 150;
            p->nStatus = BLOCK_VALID_TREE;
            BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(FakeHash(1000 + i), p)).first;
            p->phashBlock = &mi->first;
            p->BuildSkip();
            fakeBlocks.push_back(p);
            prev = p;
        }
        chainActive.SetTip(prev);
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

    /** Deliver one message and process it (ProcessMessages handles one message per call). */
    static void Send(CNode* node, const std::string& cmd, const CDataStream& payload)
    {
        Queue(node, cmd, payload);
        BOOST_CHECK_NO_THROW(ProcessMessages(node));
        // a handler that sets fDisconnect leaves the receive buffer to CloseSocketDisconnect
        if (!node->fDisconnect)
            BOOST_CHECK(node->vRecvMsg.empty());
    }

    /**
     * A reply on the dummy socket fails to send and sets fDisconnect; the
     * queued bytes stay in nSendSize. Clear the flag so the next request is
     * processed, as a live connection would be.
     */
    static void Rearm(CNode* node)
    {
        node->fDisconnect = false;
    }

    static int Score(CNode* node)
    {
        CNodeStateStats st;
        BOOST_REQUIRE(GetNodeStateStats(node->GetId(), st));
        return st.nMisbehavior;
    }
};

/** getblocks/getheaders payload: a locator of n entries whose last entry is the genesis block. */
CDataStream LocatorPayload(size_t n)
{
    std::vector<uint256> have;
    for (size_t i = 0; i + 1 < n; i++)
        have.push_back(FakeHash((uint32_t)i));
    have.push_back(Params().GenesisBlock().GetHash());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << CBlockLocator(have) << uint256();
    return ss;
}

void AddMempoolTx()
{
    CMutableTransaction m;
    m.vin.push_back(CTxIn(COutPoint(FakeHash(77), 0), CScript() << OP_1));
    m.vout.push_back(CTxOut(1234, CScript() << OP_TRUE));
    TestMemPoolEntryHelper entry;
    BOOST_REQUIRE(mempool.addUnchecked(m.GetHash(), entry.FromTx(m)));
    BOOST_REQUIRE_EQUAL(mempool.size(), 1u);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2pserve_tests, ServeFixture)

BOOST_AUTO_TEST_CASE(getblocks_locator_at_cap_is_served)
{
    ExtendActiveChain(3);
    CNode* n = NewPeer(true);
    Send(n, "getblocks", LocatorPayload(MAX_LOCATOR_SZ));
    BOOST_CHECK(!n->fDisconnect);
    BOOST_CHECK_EQUAL(Score(n), 0);
    // the fork point is genesis: the three blocks above it are announced
    BOOST_CHECK_EQUAL(n->vInventoryToSend.size(), 3u);
}

BOOST_AUTO_TEST_CASE(getblocks_locator_over_cap_disconnects_without_ban)
{
    ExtendActiveChain(3);
    CNode* n = NewPeer(true);
    Send(n, "getblocks", LocatorPayload(MAX_LOCATOR_SZ + 1));
    BOOST_CHECK(n->fDisconnect);
    BOOST_CHECK_EQUAL(Score(n), 0);
    BOOST_CHECK_EQUAL(n->vInventoryToSend.size(), 0u);
}

BOOST_AUTO_TEST_CASE(getheaders_locator_cap)
{
    // In the test chain the node is in initial block download, so getheaders
    // is not answered at the cap either; what is pinned is that the cap alone
    // decides the disconnect, before the handler takes cs_main.
    CNode* atCap = NewPeer(true);
    Send(atCap, "getheaders", LocatorPayload(MAX_LOCATOR_SZ));
    BOOST_CHECK(!atCap->fDisconnect);
    BOOST_CHECK_EQUAL(Score(atCap), 0);

    CNode* over = NewPeer(true);
    Send(over, "getheaders", LocatorPayload(MAX_LOCATOR_SZ + 1));
    BOOST_CHECK(over->fDisconnect);
    BOOST_CHECK_EQUAL(Score(over), 0);
    BOOST_CHECK_EQUAL(over->nSendSize, 0u);
}

BOOST_AUTO_TEST_CASE(mempool_request_cooldown)
{
    AddMempoolTx();
    const int64_t t0 = 1700000000;
    CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
    CNode* n = NewPeer(true);

    SetMockTime(t0);
    Send(n, "mempool", empty);
    size_t afterFirst = n->nSendSize;
    BOOST_CHECK_GT(afterFirst, 0u);
    Rearm(n);

    SetMockTime(t0 + 10);
    Send(n, "mempool", empty);
    BOOST_CHECK_EQUAL(n->nSendSize, afterFirst); // ignored: no inv
    BOOST_CHECK(!n->fDisconnect);
    BOOST_CHECK_EQUAL(Score(n), 0);

    SetMockTime(t0 + 61);
    Send(n, "mempool", empty);
    BOOST_CHECK_GT(n->nSendSize, afterFirst);
    BOOST_CHECK_EQUAL(Score(n), 0);
}

BOOST_AUTO_TEST_CASE(mempool_cooldown_exempts_whitelisted_peers)
{
    AddMempoolTx();
    const int64_t t0 = 1700000000;
    CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
    CNode* n = NewPeer(true);
    n->fWhitelisted = true;

    SetMockTime(t0);
    Send(n, "mempool", empty);
    size_t afterFirst = n->nSendSize;
    BOOST_CHECK_GT(afterFirst, 0u);
    Rearm(n);

    SetMockTime(t0 + 10);
    Send(n, "mempool", empty);
    BOOST_CHECK_GT(n->nSendSize, afterFirst);
    BOOST_CHECK_EQUAL(Score(n), 0);
}

BOOST_AUTO_TEST_CASE(mempool_cooldown_window)
{
    BOOST_CHECK(!MempoolRequestInCooldown(0, 1700000000));         // never served
    BOOST_CHECK(MempoolRequestInCooldown(1000, 1000));
    BOOST_CHECK(MempoolRequestInCooldown(1000, 1000 + MEMPOOL_REQUEST_COOLDOWN - 1));
    BOOST_CHECK(!MempoolRequestInCooldown(1000, 1000 + MEMPOOL_REQUEST_COOLDOWN));
    BOOST_CHECK(!MempoolRequestInCooldown(1000, 999));             // clock went backwards
}

BOOST_AUTO_TEST_CASE(honest_locator_fits_the_cap)
{
    // A chain of height 5,000,000. Only the heights an honest locator visits
    // (10 single steps, then doubling steps, then genesis) hold an index
    // entry; every other slot of the chain is empty. If GetLocator stepped to
    // any other height it would stop there before genesis, which the checks
    // below catch, so the count is GetLocator's own over a full-height chain.
    const int nTip = 5000000;
    std::vector<int> heights;
    for (int h = nTip, nStep = 1; ; ) {
        heights.push_back(h);
        if (h == 0)
            break;
        h = std::max(h - nStep, 0);
        if (heights.size() > 10)
            nStep *= 2;
    }
    std::vector<CBlockIndex> idx(heights.size());
    std::vector<uint256> hashes(heights.size());
    for (size_t i = heights.size(); i-- > 0; ) {
        hashes[i] = FakeHash(heights[i]);
        idx[i].nHeight = heights[i];
        idx[i].phashBlock = &hashes[i];
        idx[i].pprev = (i + 1 < heights.size()) ? &idx[i + 1] : NULL;
    }
    CChain chain;
    chain.SetTip(&idx[0]);
    BOOST_REQUIRE_EQUAL(chain.Height(), nTip);

    CBlockLocator loc = chain.GetLocator();
    BOOST_TEST_MESSAGE("GetLocator at height " << nTip << ": " << loc.vHave.size() << " entries");
    BOOST_CHECK_LT(loc.vHave.size(), (size_t)MAX_LOCATOR_SZ);
    BOOST_REQUIRE_EQUAL(loc.vHave.size(), hashes.size());
    BOOST_CHECK(loc.vHave == hashes);
    BOOST_CHECK(loc.vHave.back() == FakeHash(0)); // reached genesis
}

BOOST_AUTO_TEST_SUITE_END()
