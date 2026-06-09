// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Unit tests for the C-HYBRID on-chain collections (group/child) protocol —
// the closed/owner-authorized membership rule (R-NFT1, spec-v2):
//   * a child GENESIS carries an optional 32-byte group_id field (a CLAIM), AND
//   * to be an AUTHORIZED member it MUST also spend a live parent-token UTXO or
//     baton of that group on one of its inputs (the authorization, burned).
//
// These exercise the same in-process CZSLPStore harness the existing zslp gtests
// use (ApplyTransaction with synthetic vin / parsed messages / vout-address
// closures). Forgery-safety / determinism cases:
//   1. ChildAuthorizedWhenParentOutpointSpent
//   2. ChildClaimedButUnauthorizedWhenNoParentInput
//   3. ChildNamingNonexistentGroupNotAuthorized
//   4. UnauthorizedChildCreditsNobodyForMembership
//   5. AuthorityOutpointConsumedNoReplay
//   6. TwoIndexersAgreeOnMembership
//   7. ReorgRestoresPreMembershipState
//   8. LegacyGenesisParsesByteIdentical
//   9. GroupPushMustBe32Bytes
//   10. IntraBlockParentTx1ChildTx2
//   11. WindowedMembersDeterministicAndBounded
// Plus parser/bridge round-trips for the group_id wire field.

#include <gtest/gtest.h>

// NB: do NOT include "zslp/slp.h" here — it pulls in the plain-C `struct uint256`
// (uint256_c.h), which collides with the C++ `class uint256` from uint256.h and
// breaks uint256 ctor/operator== lookup. This test uses only the C++ wrappers
// (ZSLPBuildGenesis/ZSLPParseScript via zslpmsg.h) and the store types, so the C
// parser header is not needed. (test_zslp.cpp avoids the clash the other way: it
// includes ONLY slp.h and never uint256.h.)
#include "zslp/zslpmsg.h"
#include "zslp/zslpstore.h"
#include "primitives/transaction.h"
#include "uint256.h"

#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace {

uint256 HashFromByte(uint8_t b)
{
    std::vector<unsigned char> v(32, 0);
    v[0] = b;
    return uint256(v);
}

CZSLPToken MakeToken(const uint256& id, const std::string& ticker,
                     int64_t height, uint8_t baton = 0)
{
    CZSLPToken t;
    t.tokenId = id;
    t.ticker = ticker;
    t.name = ticker + " Token";
    t.decimals = 0;
    t.mintBatonVout = baton;
    t.genesisHeight = height;
    return t;
}

CZSLPStore* NewMemStore()
{
    return new CZSLPStore("zslp-coll-test", 1 << 20, /*fMemory=*/true, /*fWipe=*/true);
}

typedef std::map<int32_t, std::string> AddrMap;

std::function<std::string(int32_t)> AddrOf(const AddrMap& m)
{
    return [m](int32_t n) -> std::string {
        AddrMap::const_iterator it = m.find(n);
        return it == m.end() ? std::string() : it->second;
    };
}

CZSLPParsedMsg GenMsg(int64_t initialQty, int32_t batonVout = 0)
{
    CZSLPParsedMsg m;
    m.type = ZSLP_MSG_GENESIS;
    m.initialQuantity = initialQty;
    m.mintBatonVout = batonVout;
    return m;
}

// A GENESIS that CLAIMS membership in `group` (the parsed/meta group fields the
// indexer would fill from an on-chain group_id push).
CZSLPParsedMsg GenMsgGroup(int64_t initialQty, const uint256& group,
                           int32_t batonVout = 0)
{
    CZSLPParsedMsg m = GenMsg(initialQty, batonVout);
    m.hasGroup = true;
    m.groupId = group;
    return m;
}

COutPoint OutPoint(const uint256& txid, uint32_t n) { return COutPoint(txid, n); }

bool ApplyTx(CZSLPStore* s, const uint256& blk, int64_t height,
             const std::vector<COutPoint>& vin, const CZSLPParsedMsg* msg,
             const uint256& txid, const CZSLPToken* genesisMeta,
             const AddrMap& addrs, int32_t voutCount)
{
    s->ConnectBlockBegin(blk);
    bool ok = s->ApplyTransaction(vin, msg, txid, height, genesisMeta,
                                  AddrOf(addrs), voutCount);
    s->ConnectBlockEnd(height, blk);
    return ok;
}

// Genesis a COLLECTION PARENT with a baton (vout2) + `units` quantity at vout1,
// owned by `addr`. Returns nothing; the parent token id is `tid`.
void GenesisParent(CZSLPStore* s, const uint256& blk, int64_t height,
                   const uint256& tid, const std::string& addr, int64_t units)
{
    CZSLPToken meta = MakeToken(tid, "GRP", height, /*baton=*/2);
    CZSLPParsedMsg gm = GenMsg(units, /*batonVout=*/2);
    AddrMap a; a[1] = addr; // baton at vout2 (empty addr)
    ASSERT_TRUE(ApplyTx(s, blk, height, {}, &gm, tid, &meta, a, /*voutCount=*/3));
}

// Build the genesisMeta a child GENESIS would carry (token row template) with
// the group claim already populated, matching what CZSLPIndexer::ParseTx fills.
CZSLPToken ChildMeta(const uint256& childId, int64_t height, const uint256& group)
{
    CZSLPToken meta = MakeToken(childId, "CHILD", height);
    meta.hasGroup = true;
    meta.groupId = group;
    return meta;
}

bool IsMember(CZSLPStore* s, const uint256& group, const uint256& child)
{
    // Windowed enumerator: ask for the full set (from=0, count=ZSLP_LIST_MAX);
    // test collections are tiny, so this is the whole membership set.
    std::vector<uint256> members;
    s->GetCollectionMembers(group, /*from=*/0, /*count=*/ZSLP_LIST_MAX, members);
    for (size_t i = 0; i < members.size(); ++i)
        if (members[i] == child)
            return true;
    return false;
}

} // namespace

// ── 1. Child authorized when it spends a parent unit ───────────────

TEST(ZSLPCollections, ChildAuthorizedWhenParentOutpointSpent)
{
    CZSLPStore* s = NewMemStore();
    uint256 group = HashFromByte(0x11);
    uint256 child = HashFromByte(0x12);
    std::string owner = "t1Owner", recip = "t1Child";

    // Collection parent: 5 units at (group,1), baton at (group,2).
    GenesisParent(s, HashFromByte(0xA0), 10, group, owner, 5);

    // Child GENESIS names group AND spends a parent unit (group,1) as authority.
    CZSLPToken meta = ChildMeta(child, 11, group);
    CZSLPParsedMsg cm = GenMsgGroup(1, group);
    AddrMap a; a[1] = recip;
    std::vector<COutPoint> vin = { OutPoint(group, 1) }; // burn one parent unit
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0xA1), 11, vin, &cm, child, &meta, a, 2));

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(child, got));
    EXPECT_TRUE(got.hasGroup);
    EXPECT_EQ(got.groupId, group);
    EXPECT_TRUE(got.groupAuthorized);
    EXPECT_TRUE(IsMember(s, group, child));

    // The burned parent unit is gone (consume-before-create); the child unit
    // exists at (child,1).
    CZSLPTokenUtxo u;
    EXPECT_FALSE(s->GetUtxo(group, 1, u));   // authority unit burned
    ASSERT_TRUE(s->GetUtxo(child, 1, u));     // child NFT minted
    EXPECT_EQ(u.amount, 1);
    delete s;
}

// ── 2. Names the group but spends no parent input => claimed, NOT member ──

TEST(ZSLPCollections, ChildClaimedButUnauthorizedWhenNoParentInput)
{
    CZSLPStore* s = NewMemStore();
    uint256 group = HashFromByte(0x21);
    uint256 child = HashFromByte(0x22);

    GenesisParent(s, HashFromByte(0xB0), 10, group, "t1Owner", 5);

    // Child names the group but spends NO group outpoint (unrelated prevout).
    CZSLPToken meta = ChildMeta(child, 11, group);
    CZSLPParsedMsg cm = GenMsgGroup(1, group);
    AddrMap a; a[1] = "t1Squatter";
    std::vector<COutPoint> vin = { OutPoint(HashFromByte(0xCC), 0) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0xB1), 11, vin, &cm, child, &meta, a, 2));

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(child, got));
    EXPECT_TRUE(got.hasGroup);            // claim recorded
    EXPECT_FALSE(got.groupAuthorized);    // but NOT authorized
    EXPECT_FALSE(IsMember(s, group, child)); // absent from the members index
    delete s;
}

// ── 3. Naming a non-existent group is never authorized ──────────────

TEST(ZSLPCollections, ChildNamingNonexistentGroupNotAuthorized)
{
    CZSLPStore* s = NewMemStore();
    uint256 ghost = HashFromByte(0x31); // never genesised
    uint256 child = HashFromByte(0x32);

    CZSLPToken meta = ChildMeta(child, 11, ghost);
    CZSLPParsedMsg cm = GenMsgGroup(1, ghost);
    AddrMap a; a[1] = "t1Child";
    // Even if it spends something, the parent token doesn't exist.
    std::vector<COutPoint> vin = { OutPoint(HashFromByte(0xDD), 0) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0xC1), 11, vin, &cm, child, &meta, a, 2));

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(child, got));
    EXPECT_TRUE(got.hasGroup);
    EXPECT_FALSE(got.groupAuthorized);
    EXPECT_FALSE(IsMember(s, ghost, child));
    delete s;
}

// ── 4. A third party with no parent outpoint cannot forge membership ──

TEST(ZSLPCollections, UnauthorizedChildCreditsNobodyForMembership)
{
    CZSLPStore* s = NewMemStore();
    uint256 group = HashFromByte(0x41);
    uint256 honest = HashFromByte(0x42);
    uint256 forged = HashFromByte(0x43);

    GenesisParent(s, HashFromByte(0xD0), 10, group, "t1Owner", 2);

    // Owner mints an authorized child (spends a real parent unit).
    {
        CZSLPToken meta = ChildMeta(honest, 11, group);
        CZSLPParsedMsg cm = GenMsgGroup(1, group);
        AddrMap a; a[1] = "t1Owner";
        std::vector<COutPoint> vin = { OutPoint(group, 1) };
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0xD1), 11, vin, &cm, honest, &meta, a, 2));
    }
    // Attacker (no parent outpoint) tries to add a child to the SAME group.
    {
        CZSLPToken meta = ChildMeta(forged, 12, group);
        CZSLPParsedMsg cm = GenMsgGroup(1, group);
        AddrMap a; a[1] = "t1Attacker";
        std::vector<COutPoint> vin = { OutPoint(HashFromByte(0xEE), 7) };
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0xD2), 12, vin, &cm, forged, &meta, a, 2));
    }

    // Exactly ONE authorized member; the forgery is absent.
    std::vector<uint256> members;
    s->GetCollectionMembers(group, /*from=*/0, /*count=*/ZSLP_LIST_MAX, members);
    EXPECT_EQ(members.size(), 1u);
    EXPECT_TRUE(IsMember(s, group, honest));
    EXPECT_FALSE(IsMember(s, group, forged));

    CZSLPToken f;
    ASSERT_TRUE(s->GetToken(forged, f));
    EXPECT_FALSE(f.groupAuthorized);
    delete s;
}

// ── 5. One parent outpoint authorizes exactly one child (no replay) ──

TEST(ZSLPCollections, AuthorityOutpointConsumedNoReplay)
{
    CZSLPStore* s = NewMemStore();
    uint256 group = HashFromByte(0x51);
    uint256 child1 = HashFromByte(0x52);
    uint256 child2 = HashFromByte(0x53);

    GenesisParent(s, HashFromByte(0xF0), 10, group, "t1Owner", 1); // ONE unit

    // child1 spends the unit (group,1) => authorized; the unit is now burned.
    {
        CZSLPToken meta = ChildMeta(child1, 11, group);
        CZSLPParsedMsg cm = GenMsgGroup(1, group);
        AddrMap a; a[1] = "t1Owner";
        std::vector<COutPoint> vin = { OutPoint(group, 1) };
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0xF1), 11, vin, &cm, child1, &meta, a, 2));
    }
    // child2 tries to REUSE the SAME (now-burned) outpoint (group,1).
    {
        CZSLPToken meta = ChildMeta(child2, 12, group);
        CZSLPParsedMsg cm = GenMsgGroup(1, group);
        AddrMap a; a[1] = "t1Owner";
        std::vector<COutPoint> vin = { OutPoint(group, 1) }; // already spent
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0xF2), 12, vin, &cm, child2, &meta, a, 2));
    }

    EXPECT_TRUE(IsMember(s, group, child1));
    EXPECT_FALSE(IsMember(s, group, child2)); // replay yields no authorization

    CZSLPToken c2;
    ASSERT_TRUE(s->GetToken(child2, c2));
    EXPECT_FALSE(c2.groupAuthorized);
    delete s;
}

// ── 6. Two independent stores agree on membership bit-for-bit ───────

TEST(ZSLPCollections, TwoIndexersAgreeOnMembership)
{
    // The exact same block sequence replayed on two store instances must yield
    // identical groupId/groupAuthorized + identical 'g' membership.
    struct Step { uint256 blk; int64_t h; std::vector<COutPoint> vin;
                  CZSLPParsedMsg msg; uint256 txid; CZSLPToken meta;
                  bool haveMeta; AddrMap addrs; int32_t voutCount; };

    uint256 group = HashFromByte(0x61);
    uint256 a1 = HashFromByte(0x62), a2 = HashFromByte(0x63), un = HashFromByte(0x64);

    auto run = [&](CZSLPStore* s) {
        GenesisParent(s, HashFromByte(0x90), 10, group, "t1Owner", 5);
        // authorized child a1
        { CZSLPToken m = ChildMeta(a1, 11, group); CZSLPParsedMsg cm = GenMsgGroup(1, group);
          AddrMap a; a[1] = "t1A"; ApplyTx(s, HashFromByte(0x91), 11, { OutPoint(group,1) }, &cm, a1, &m, a, 2); }
        // unauthorized child un (no parent input)
        { CZSLPToken m = ChildMeta(un, 12, group); CZSLPParsedMsg cm = GenMsgGroup(1, group);
          AddrMap a; a[1] = "t1U"; ApplyTx(s, HashFromByte(0x92), 12, { OutPoint(HashFromByte(0x01),0) }, &cm, un, &m, a, 2); }
        // authorized child a2
        { CZSLPToken m = ChildMeta(a2, 13, group); CZSLPParsedMsg cm = GenMsgGroup(1, group);
          AddrMap a; a[1] = "t1B"; ApplyTx(s, HashFromByte(0x93), 13, { OutPoint(group,2) /*baton*/ }, &cm, a2, &m, a, 2); }
    };

    CZSLPStore* s1 = NewMemStore();
    CZSLPStore* s2 = NewMemStore();
    run(s1);
    run(s2);

    std::vector<uint256> m1, m2;
    s1->GetCollectionMembers(group, /*from=*/0, /*count=*/ZSLP_LIST_MAX, m1);
    s2->GetCollectionMembers(group, /*from=*/0, /*count=*/ZSLP_LIST_MAX, m2);
    ASSERT_EQ(m1.size(), m2.size());
    for (size_t i = 0; i < m1.size(); ++i)
        EXPECT_EQ(m1[i], m2[i]); // identical order (leveldb-key order)

    // a2 authorized via the BATON input (a baton is a valid authority too).
    EXPECT_TRUE(IsMember(s1, group, a1));
    EXPECT_TRUE(IsMember(s1, group, a2));
    EXPECT_FALSE(IsMember(s1, group, un));

    for (CZSLPStore* s : { s1, s2 }) {
        CZSLPToken t1, t2, tu;
        ASSERT_TRUE(s->GetToken(a1, t1)); ASSERT_TRUE(s->GetToken(a2, t2));
        ASSERT_TRUE(s->GetToken(un, tu));
        EXPECT_TRUE(t1.groupAuthorized);
        EXPECT_TRUE(t2.groupAuthorized);
        EXPECT_FALSE(tu.groupAuthorized);
    }
    delete s1; delete s2;
}

// ── 7. Reorg restores pre-membership state byte-identically ─────────

TEST(ZSLPCollections, ReorgRestoresPreMembershipState)
{
    CZSLPStore* s = NewMemStore();
    uint256 group = HashFromByte(0x71);
    uint256 child = HashFromByte(0x72);

    GenesisParent(s, HashFromByte(0xA0), 10, group, "t1Owner", 3);

    // Snapshot pre-child state.
    const int64_t preTokens = s->TokenCount();
    const int64_t preUtxos = s->UtxoCount();
    std::vector<uint256> preMembers;
    s->GetCollectionMembers(group, /*from=*/0, /*count=*/ZSLP_LIST_MAX, preMembers);
    EXPECT_EQ(preMembers.size(), 0u);
    int64_t preH; uint256 preBH; ASSERT_TRUE(s->ReadTip(preH, preBH));

    // Connect a block with an AUTHORIZED child (spends group,1 -> burned).
    uint256 blk = HashFromByte(0xA1);
    s->ConnectBlockBegin(blk);
    CZSLPToken meta = ChildMeta(child, 11, group);
    CZSLPParsedMsg cm = GenMsgGroup(1, group);
    AddrMap a; a[1] = "t1Child";
    ASSERT_TRUE(s->ApplyTransaction({ OutPoint(group, 1) }, &cm, child, 11, &meta,
                                    AddrOf(a), 2));
    s->ConnectBlockEnd(11, blk);

    // Post-connect: child is an authorized member, parent unit burned.
    EXPECT_TRUE(IsMember(s, group, child));
    EXPECT_EQ(s->TokenCount(), preTokens + 1);

    // Disconnect: 'g' row + child token row + burned unit all restored.
    ASSERT_TRUE(s->DisconnectBlock(blk, preH, preBH));

    EXPECT_EQ(s->TokenCount(), preTokens);
    EXPECT_EQ(s->UtxoCount(), preUtxos);
    CZSLPToken gone;
    EXPECT_FALSE(s->GetToken(child, gone)); // child row erased
    std::vector<uint256> postMembers;
    s->GetCollectionMembers(group, /*from=*/0, /*count=*/ZSLP_LIST_MAX, postMembers);
    EXPECT_EQ(postMembers.size(), 0u);      // 'g' row erased (no dangling member)
    EXPECT_FALSE(IsMember(s, group, child));
    // The burned authority unit is restored.
    CZSLPTokenUtxo u;
    ASSERT_TRUE(s->GetUtxo(group, 1, u));
    EXPECT_EQ(u.amount, 3);
    // Tip rewound.
    int64_t h; uint256 bh; ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, preH);
    EXPECT_EQ(bh, preBH);
    delete s;
}

// ── 10. Intra-block: parent in tx1, child in tx2, same block ───────

TEST(ZSLPCollections, IntraBlockParentTx1ChildTx2)
{
    CZSLPStore* s = NewMemStore();
    uint256 group = HashFromByte(0x81);
    uint256 child = HashFromByte(0x82);

    uint256 blk = HashFromByte(0x83);
    s->ConnectBlockBegin(blk);

    // tx1: collection parent genesis (5 units at vout1, baton vout2).
    CZSLPToken pmeta = MakeToken(group, "GRP", 20, /*baton=*/2);
    CZSLPParsedMsg pm = GenMsg(5, /*batonVout=*/2);
    AddrMap pa; pa[1] = "t1Owner";
    ASSERT_TRUE(s->ApplyTransaction({}, &pm, group, 20, &pmeta, AddrOf(pa), 3));

    // tx2 (same block): child spends the parent unit (group,1) created by tx1.
    CZSLPToken cmeta = ChildMeta(child, 20, group);
    CZSLPParsedMsg cm = GenMsgGroup(1, group);
    AddrMap ca; ca[1] = "t1Child";
    ASSERT_TRUE(s->ApplyTransaction({ OutPoint(group, 1) }, &cm, child, 20, &cmeta,
                                    AddrOf(ca), 2));

    s->ConnectBlockEnd(20, blk);

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(child, got));
    EXPECT_TRUE(got.groupAuthorized); // saw tx1's UTXO via per-tx commit
    EXPECT_TRUE(IsMember(s, group, child));
    delete s;
}

// ── 11. Windowed enumerator: from/count + huge-from boundedness ─────
//    GetCollectionMembers is now O(count) memory (skip `from`, take `count` IN
//    the prefix-scan). Assert the window slices the SAME deterministic leveldb-
//    key order (childTokenId ascending) the full scan returns, that a huge `from`
//    returns empty without an O(from) allocation (mirrors the ListTransfers
//    ListTransfersHugeFromIsBounded regression), and that CountCollectionMembers
//    counts the whole set without materializing ids.

TEST(ZSLPCollections, WindowedMembersDeterministicAndBounded)
{
    CZSLPStore* s = NewMemStore();
    uint256 group = HashFromByte(0x01);

    // Collection parent: a unit UTXO at (group,1) + a baton at (group,2). The
    // store accepts EITHER a live parent unit OR the baton as a valid authority
    // (see TwoIndexersAgreeOnMembership), so we author two distinct members from
    // two distinct authority outpoints: child A burns the unit (group,1), child B
    // burns the baton (group,2). Two members is enough to exercise from/count
    // slicing and ordering; the huge-from case proves O(count) boundedness.
    GenesisParent(s, HashFromByte(0xE0), 10, group, "t1Owner", 5);

    uint256 cA = HashFromByte(0x0A);
    uint256 cB = HashFromByte(0x0B);
    {
        CZSLPToken m = ChildMeta(cA, 11, group);
        CZSLPParsedMsg cm = GenMsgGroup(1, group);
        AddrMap a; a[1] = "t1A";
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0xE1), 11, { OutPoint(group, 1) },
                            &cm, cA, &m, a, 2));
    }
    {
        CZSLPToken m = ChildMeta(cB, 12, group);
        CZSLPParsedMsg cm = GenMsgGroup(1, group);
        AddrMap a; a[1] = "t1B";
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0xE2), 12, { OutPoint(group, 2) /*baton*/ },
                            &cm, cB, &m, a, 2));
    }

    // Full set (from=0, count=MAX) in deterministic leveldb-key order.
    std::vector<uint256> all;
    s->GetCollectionMembers(group, /*from=*/0, /*count=*/ZSLP_LIST_MAX, all);
    ASSERT_EQ(all.size(), 2u);
    EXPECT_EQ(s->CountCollectionMembers(group), 2u); // count == full-set size

    // count=1 from each offset returns exactly the same element the full set has
    // at that index (windowing slices, never reorders).
    std::vector<uint256> p0, p1, p2;
    s->GetCollectionMembers(group, /*from=*/0, /*count=*/1, p0);
    s->GetCollectionMembers(group, /*from=*/1, /*count=*/1, p1);
    s->GetCollectionMembers(group, /*from=*/2, /*count=*/1, p2);
    ASSERT_EQ(p0.size(), 1u);
    ASSERT_EQ(p1.size(), 1u);
    EXPECT_EQ(p0[0], all[0]);
    EXPECT_EQ(p1[0], all[1]);
    EXPECT_TRUE(p2.empty()); // from == total -> empty

    // count clamps to remaining: from=1,count=10 yields just the tail element.
    std::vector<uint256> tail;
    s->GetCollectionMembers(group, /*from=*/1, /*count=*/10, tail);
    ASSERT_EQ(tail.size(), 1u);
    EXPECT_EQ(tail[0], all[1]);

    // Huge `from` is bounded (no O(from) allocation): returns empty, no OOM.
    std::vector<uint256> huge;
    s->GetCollectionMembers(group, /*from=*/2000000000, /*count=*/10, huge);
    EXPECT_TRUE(huge.empty());

    // count<=0 returns empty (clamped).
    std::vector<uint256> zero;
    s->GetCollectionMembers(group, /*from=*/0, /*count=*/0, zero);
    EXPECT_TRUE(zero.empty());

    // An unknown group has zero members and a zero count.
    EXPECT_EQ(s->CountCollectionMembers(HashFromByte(0xFE)), 0u);
    delete s;
}
