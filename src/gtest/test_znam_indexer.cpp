// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Unit tests for the ZNAM (ZCL Names) store (CZNAMStore). ZNAM is a NON-consensus
// overlay: ownership is First-In-First-Served and the owner is the vin[0] P2PKH
// signer (derived by the indexer and passed to the store as ownerAddr). These
// tests drive the store's connect entry points directly — ConnectBlockBegin /
// ApplyRecord / ConnectBlockEnd, and DisconnectBlock for reorgs — the same calls
// the live indexer makes, with synthetic parsed messages and owner strings.
//
// Coverage:
//   - register/resolve round trip + expiry boundary
//   - FIFS conflict (second register of an active name is a no-op)
//   - authorization (UPDATE/TRANSFER/RENEW/SET_* only by the current owner)
//   - transfer (valid P2PKH new owner; invalid target is a no-op)
//   - grace + renew math and the MAX_REGISTRATION cap
//   - fresh re-registration resets all overlay records
//   - SET_TEXT deletion + printable-ASCII allowlist
//   - intra-block visibility (a later tx sees an earlier tx's claim)
//   - the reorg invariant: connect then disconnect restores byte-identical state
//   - determinism: two stores fed identical op streams end identical

#include <gtest/gtest.h>

#include "znam/znamstore.h"
#include "znam/znammsg.h"

#include "chainparams.h"
#include "key_io.h"
#include "pubkey.h"
#include "script/standard.h"
#include "uint256.h"

#include <string>
#include <vector>

namespace {

uint256 HashFromByte(uint8_t b)
{
    std::vector<unsigned char> v(32, 0);
    v[0] = b;
    return uint256(v);
}

CZNAMStore* NewMemStore()
{
    return new CZNAMStore("znam-test", 1 << 20, /*fMemory=*/true, /*fWipe=*/true);
}

// A valid transparent P2PKH address under the active CChainParams (for TRANSFER
// targets, the only field the store address-validates).
std::string MakeP2PKH(uint8_t fill)
{
    std::vector<unsigned char> h(20, fill);
    return EncodeDestination(CKeyID(uint160(h)));
}

ZNAMMessage RegMsg(const std::string& name, uint8_t type, const std::string& value)
{
    ZNAMMessage m;
    m.command = ZNAMMSG_REGISTER;
    m.name = name;
    m.targetType = type;
    m.targetValue = value;
    return m;
}

ZNAMMessage UpdMsg(const std::string& name, uint8_t type, const std::string& value)
{
    ZNAMMessage m;
    m.command = ZNAMMSG_UPDATE;
    m.name = name;
    m.targetType = type;
    m.targetValue = value;
    return m;
}

ZNAMMessage XferMsg(const std::string& name, const std::string& newOwner)
{
    ZNAMMessage m;
    m.command = ZNAMMSG_TRANSFER;
    m.name = name;
    m.newOwner = newOwner;
    return m;
}

ZNAMMessage RenewMsg(const std::string& name)
{
    ZNAMMessage m;
    m.command = ZNAMMSG_RENEW;
    m.name = name;
    return m;
}

ZNAMMessage RecMsg(const std::string& name, uint8_t type, const std::string& value)
{
    ZNAMMessage m;
    m.command = ZNAMMSG_SET_RECORD;
    m.name = name;
    m.targetType = type;
    m.targetValue = value;
    return m;
}

ZNAMMessage TextMsg(const std::string& name, const std::string& key, const std::string& value)
{
    ZNAMMessage m;
    m.command = ZNAMMSG_SET_TEXT;
    m.name = name;
    m.textKey = key;
    m.textValue = value;
    return m;
}

// Drive one record through the store inside its own single-tx block.
bool ApplyTx(CZNAMStore* s, const uint256& blk, int64_t height,
             const ZNAMMessage& msg, const std::string& owner,
             const uint256& txid, int32_t txIndex = 0)
{
    s->ConnectBlockBegin(blk);
    bool ok = s->ApplyRecord(msg, owner, txid, height, txIndex, blk);
    s->ConnectBlockEnd(height, blk);
    return ok;
}

int NameCount(CZNAMStore* s)
{
    std::vector<CZNAMName> v;
    return s->ListNames(0, ZNAM_LIST_MAX, v);
}

int HistoryCount(CZNAMStore* s, const std::string& name)
{
    std::vector<CZNAMHistory> v;
    return s->ListHistory(name, 0, ZNAM_LIST_MAX, v);
}

bool OwnerHasName(CZNAMStore* s, const std::string& owner, const std::string& name)
{
    std::vector<CZNAMName> v;
    s->ListOwnerNames(owner, 0, ZNAM_LIST_MAX, v);
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i].name == name) return true;
    return false;
}

} // namespace

TEST(ZNAMStore, RegisterResolveRoundTrip)
{
    CZNAMStore* s = NewMemStore();
    const int64_t h = 100;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0xB1), h,
                        RegMsg("alpha", ZNAM_TARGET_ONION, "abc.onion"),
                        "alice", HashFromByte(0x01)));

    CZNAMName rec;
    ASSERT_TRUE(s->GetName("alpha", rec));
    EXPECT_EQ(rec.ownerAddr, "alice");
    EXPECT_EQ(rec.registeredHeight, h);
    EXPECT_EQ(rec.expiryHeight, h + ZNAM_REGISTRATION_DURATION_BLOCKS);
    EXPECT_EQ((int)rec.primaryType, (int)ZNAM_TARGET_ONION);
    EXPECT_EQ(rec.primaryValue, "abc.onion");

    CZNAMResolvedName out;
    ASSERT_TRUE(s->ResolveName("alpha", h, out));
    EXPECT_EQ(out.name.ownerAddr, "alice");
    EXPECT_EQ(out.name.primaryValue, "abc.onion");

    // Active up to (but not including) expiryHeight.
    EXPECT_TRUE(s->ResolveName("alpha", rec.expiryHeight - 1, out));
    EXPECT_FALSE(s->ResolveName("alpha", rec.expiryHeight, out)); // expired => NXDOMAIN

    // Unregistered name resolves to nothing.
    EXPECT_FALSE(s->ResolveName("nope", h, out));
    delete s;
}

TEST(ZNAMStore, FIFSConflict)
{
    CZNAMStore* s = NewMemStore();
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x10), 100,
                        RegMsg("x", ZNAM_TARGET_ONION, "a.onion"),
                        "alice", HashFromByte(0x01)));
    // Second register of the still-active name: no-op, owner unchanged.
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x11), 101,
                        RegMsg("x", ZNAM_TARGET_ONION, "b.onion"),
                        "bob", HashFromByte(0x02)));

    CZNAMName rec;
    ASSERT_TRUE(s->GetName("x", rec));
    EXPECT_EQ(rec.ownerAddr, "alice");
    EXPECT_EQ(rec.primaryValue, "a.onion");

    // Both attempts are audited; the second is a logged no-op.
    std::vector<CZNAMHistory> hist;
    ASSERT_EQ(s->ListHistory("x", 0, 100, hist), 2);
    EXPECT_TRUE(hist[0].applied);
    EXPECT_FALSE(hist[1].applied);
    EXPECT_EQ(hist[1].ownerAddr, "bob");
    delete s;
}

TEST(ZNAMStore, UpdateAuthOnly)
{
    CZNAMStore* s = NewMemStore();
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x20), 100,
                        RegMsg("y", ZNAM_TARGET_ONION, "v1.onion"), "alice", HashFromByte(0x01)));
    // Owner update succeeds.
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x21), 101,
                        UpdMsg("y", ZNAM_TARGET_ZADDR, "zs1v2"), "alice", HashFromByte(0x02)));
    CZNAMName rec;
    ASSERT_TRUE(s->GetName("y", rec));
    EXPECT_EQ((int)rec.primaryType, (int)ZNAM_TARGET_ZADDR);
    EXPECT_EQ(rec.primaryValue, "zs1v2");
    // Non-owner update is a no-op.
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x22), 102,
                        UpdMsg("y", ZNAM_TARGET_TADDR, "t1evil"), "bob", HashFromByte(0x03)));
    ASSERT_TRUE(s->GetName("y", rec));
    EXPECT_EQ((int)rec.primaryType, (int)ZNAM_TARGET_ZADDR);
    EXPECT_EQ(rec.primaryValue, "zs1v2");
    delete s;
}

TEST(ZNAMStore, Transfer)
{
    SelectParams(CBaseChainParams::REGTEST);
    CZNAMStore* s = NewMemStore();
    const std::string alice = "alice"; // owner == derived signer string, stored verbatim
    const std::string bob = MakeP2PKH(0x07);
    ASSERT_FALSE(bob.empty());

    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x30), 100,
                        RegMsg("z", ZNAM_TARGET_ONION, "z.onion"), alice, HashFromByte(0x01)));
    // Transfer alice -> bob (valid P2PKH).
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x31), 101, XferMsg("z", bob), alice, HashFromByte(0x02)));
    CZNAMName rec;
    ASSERT_TRUE(s->GetName("z", rec));
    EXPECT_EQ(rec.ownerAddr, bob);
    EXPECT_TRUE(OwnerHasName(s, bob, "z"));
    EXPECT_FALSE(OwnerHasName(s, alice, "z"));

    // Transfer to an invalid (non-P2PKH) target is a no-op.
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x32), 102, XferMsg("z", "not-an-address"), bob, HashFromByte(0x03)));
    ASSERT_TRUE(s->GetName("z", rec));
    EXPECT_EQ(rec.ownerAddr, bob);

    // Old owner can no longer update; new owner can.
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x33), 103, UpdMsg("z", ZNAM_TARGET_ONION, "x.onion"), alice, HashFromByte(0x04)));
    ASSERT_TRUE(s->GetName("z", rec));
    EXPECT_EQ(rec.primaryValue, "z.onion"); // alice's update ignored
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x34), 104, UpdMsg("z", ZNAM_TARGET_ONION, "bob.onion"), bob, HashFromByte(0x05)));
    ASSERT_TRUE(s->GetName("z", rec));
    EXPECT_EQ(rec.primaryValue, "bob.onion");
    delete s;
}

TEST(ZNAMStore, GraceAndRenew)
{
    CZNAMStore* s = NewMemStore();
    const int64_t h0 = 100;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x40), h0,
                        RegMsg("g", ZNAM_TARGET_ONION, "g.onion"), "alice", HashFromByte(0x01)));
    CZNAMName rec;
    ASSERT_TRUE(s->GetName("g", rec));
    const int64_t expiry = rec.expiryHeight; // h0 + DURATION

    // At expiry: not active (NXDOMAIN), but in grace.
    CZNAMResolvedName out;
    EXPECT_FALSE(s->ResolveName("g", expiry, out));
    EXPECT_FALSE(CZNAMStore::IsActive(rec, expiry));
    EXPECT_TRUE(CZNAMStore::IsInGrace(rec, expiry));

    // A stranger cannot claim during grace.
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x41), expiry + 1,
                        RegMsg("g", ZNAM_TARGET_ONION, "evil.onion"), "mallory", HashFromByte(0x02)));
    ASSERT_TRUE(s->GetName("g", rec));
    EXPECT_EQ(rec.ownerAddr, "alice");

    // Owner renews during grace; expiry re-anchored to renewH + DURATION.
    const int64_t renewH = expiry + 1;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x42), renewH, RenewMsg("g"), "alice", HashFromByte(0x03)));
    ASSERT_TRUE(s->GetName("g", rec));
    EXPECT_EQ(rec.expiryHeight, renewH + ZNAM_REGISTRATION_DURATION_BLOCKS);
    EXPECT_TRUE(s->ResolveName("g", renewH, out)); // active again

    // After expiry + GRACE the name is free; a stranger may claim it.
    ASSERT_TRUE(s->GetName("g", rec));
    const int64_t freeH = rec.expiryHeight + ZNAM_GRACE_BLOCKS;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x43), freeH,
                        RegMsg("g", ZNAM_TARGET_ONION, "new.onion"), "carol", HashFromByte(0x04)));
    ASSERT_TRUE(s->GetName("g", rec));
    EXPECT_EQ(rec.ownerAddr, "carol");
    delete s;
}

TEST(ZNAMStore, MaxRegistrationCap)
{
    CZNAMStore* s = NewMemStore();
    const int64_t h = 100;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x50), h,
                        RegMsg("m", ZNAM_TARGET_ONION, "m.onion"), "alice", HashFromByte(0x01)));
    // Renew many times at the same height; expiry converges to the cap and never
    // exceeds h + MAX_REGISTRATION.
    for (int i = 0; i < 20; ++i) {
        std::vector<unsigned char> bh(32, 0); bh[0] = 0x60; bh[1] = (unsigned char)i;
        uint256 blk(bh);
        std::vector<unsigned char> tb(32, 0); tb[0] = 0x70; tb[1] = (unsigned char)i;
        uint256 txid(tb);
        ASSERT_TRUE(ApplyTx(s, blk, h, RenewMsg("m"), "alice", txid));
        CZNAMName rec;
        ASSERT_TRUE(s->GetName("m", rec));
        EXPECT_LE(rec.expiryHeight, h + ZNAM_MAX_REGISTRATION_BLOCKS);
    }
    CZNAMName rec;
    ASSERT_TRUE(s->GetName("m", rec));
    EXPECT_EQ(rec.expiryHeight, h + ZNAM_MAX_REGISTRATION_BLOCKS); // clamped to cap
    delete s;
}

TEST(ZNAMStore, ResetOnReRegister)
{
    CZNAMStore* s = NewMemStore();
    const int64_t h0 = 100;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x80), h0,
                        RegMsg("r", ZNAM_TARGET_ONION, "r.onion"), "alice", HashFromByte(0x01)));
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x81), h0 + 1,
                        RecMsg("r", ZNAM_TARGET_BTC, "bc1qexample"), "alice", HashFromByte(0x02)));
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x82), h0 + 2,
                        TextMsg("r", "url", "http://r.example"), "alice", HashFromByte(0x03)));
    std::string v;
    EXPECT_TRUE(s->GetRecord("r", ZNAM_TARGET_BTC, v));
    EXPECT_TRUE(s->GetTextRecord("r", "url", v));

    // Let it go fully free, then a new owner registers -> all overlay rows wiped.
    CZNAMName rec;
    ASSERT_TRUE(s->GetName("r", rec));
    const int64_t freeH = rec.expiryHeight + ZNAM_GRACE_BLOCKS;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x83), freeH,
                        RegMsg("r", ZNAM_TARGET_ONION, "bob-r.onion"), "bob", HashFromByte(0x04)));
    ASSERT_TRUE(s->GetName("r", rec));
    EXPECT_EQ(rec.ownerAddr, "bob");
    EXPECT_FALSE(s->GetRecord("r", ZNAM_TARGET_BTC, v)); // wiped
    EXPECT_FALSE(s->GetTextRecord("r", "url", v));        // wiped

    CZNAMResolvedName out;
    ASSERT_TRUE(s->ResolveName("r", freeH, out));
    EXPECT_EQ(out.records.size(), 0u);
    EXPECT_EQ(out.textRecords.size(), 0u);
    delete s;
}

TEST(ZNAMStore, SetTextDeletionAndAllowlist)
{
    CZNAMStore* s = NewMemStore();
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x90), 100,
                        RegMsg("t", ZNAM_TARGET_ONION, "t.onion"), "alice", HashFromByte(0x01)));
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x91), 101,
                        TextMsg("t", "email", "a@b.com"), "alice", HashFromByte(0x02)));
    std::string v;
    ASSERT_TRUE(s->GetTextRecord("t", "email", v));
    EXPECT_EQ(v, "a@b.com");

    // Empty value deletes the key.
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x92), 102,
                        TextMsg("t", "email", ""), "alice", HashFromByte(0x03)));
    EXPECT_FALSE(s->GetTextRecord("t", "email", v));

    // A key with a control byte is rejected (allowlist) -> no-op.
    std::string badKey = std::string("ba") + '\x01' + "d";
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x93), 103,
                        TextMsg("t", badKey, "x"), "alice", HashFromByte(0x04)));
    EXPECT_FALSE(s->GetTextRecord("t", badKey, v));

    // A value with a control byte is rejected -> no-op.
    std::string badVal = std::string("hi") + '\x07';
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x94), 104,
                        TextMsg("t", "note", badVal), "alice", HashFromByte(0x05)));
    EXPECT_FALSE(s->GetTextRecord("t", "note", v));
    delete s;
}

TEST(ZNAMStore, IntraBlockClaim)
{
    CZNAMStore* s = NewMemStore();
    const uint256 blk = HashFromByte(0xC0);
    const int64_t h = 100;
    s->ConnectBlockBegin(blk);
    // tx0 registers "foo"; tx1 in the SAME block updates it (same owner).
    ASSERT_TRUE(s->ApplyRecord(RegMsg("foo", ZNAM_TARGET_ONION, "v1.onion"),
                               "alice", HashFromByte(0x01), h, 0, blk));
    ASSERT_TRUE(s->ApplyRecord(UpdMsg("foo", ZNAM_TARGET_ZADDR, "zs1foo"),
                               "alice", HashFromByte(0x02), h, 1, blk));
    s->ConnectBlockEnd(h, blk);

    CZNAMName rec;
    ASSERT_TRUE(s->GetName("foo", rec));
    EXPECT_EQ((int)rec.primaryType, (int)ZNAM_TARGET_ZADDR); // update saw the claim
    EXPECT_EQ(rec.primaryValue, "zs1foo");
    delete s;
}

TEST(ZNAMStore, DisconnectEmptyBlock)
{
    CZNAMStore* s = NewMemStore();
    const uint256 blk = HashFromByte(0xE0);
    s->ConnectBlockBegin(blk);
    s->ConnectBlockEnd(50, blk); // no records
    int64_t h; uint256 bh;
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, 50);

    ASSERT_TRUE(s->DisconnectBlock(blk, 49, HashFromByte(0xEF)));
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, 49);
    EXPECT_EQ(bh, HashFromByte(0xEF));
    delete s;
}

TEST(ZNAMStore, ReorgRegisterRoundTrip)
{
    CZNAMStore* s = NewMemStore();
    // Base block at h=99 (empty) so the tip exists pre-reorg.
    uint256 baseBlk = HashFromByte(0xA0);
    s->ConnectBlockBegin(baseBlk);
    s->ConnectBlockEnd(99, baseBlk);
    EXPECT_EQ(NameCount(s), 0);

    // Connect a block that registers a fresh name.
    uint256 newBlk = HashFromByte(0xA1);
    ASSERT_TRUE(ApplyTx(s, newBlk, 100,
                        RegMsg("fresh", ZNAM_TARGET_ONION, "fresh.onion"), "alice", HashFromByte(0x01)));
    EXPECT_EQ(NameCount(s), 1);
    EXPECT_EQ(HistoryCount(s, "fresh"), 1);

    // Disconnect: the name is gone, tip rewound, history erased.
    ASSERT_TRUE(s->DisconnectBlock(newBlk, 99, baseBlk));
    CZNAMName rec;
    EXPECT_FALSE(s->GetName("fresh", rec));
    EXPECT_EQ(NameCount(s), 0);
    EXPECT_EQ(HistoryCount(s, "fresh"), 0);
    int64_t h; uint256 bh;
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, 99);
    EXPECT_EQ(bh, baseBlk);
    delete s;
}

TEST(ZNAMStore, ReorgTransferRoundTrip)
{
    SelectParams(CBaseChainParams::REGTEST);
    CZNAMStore* s = NewMemStore();
    const std::string alice = "alice";
    const std::string bob = MakeP2PKH(0x09);

    // Pre-state: "z" registered to alice at h=100 (base block).
    uint256 baseBlk = HashFromByte(0xB0);
    ASSERT_TRUE(ApplyTx(s, baseBlk, 100,
                        RegMsg("z", ZNAM_TARGET_ONION, "z.onion"), alice, HashFromByte(0x01)));
    const int preNames = NameCount(s);
    const int preHist = HistoryCount(s, "z");
    int64_t ph; uint256 pbh; ASSERT_TRUE(s->ReadTip(ph, pbh));

    // Connect a block transferring z -> bob.
    uint256 newBlk = HashFromByte(0xB1);
    ASSERT_TRUE(ApplyTx(s, newBlk, 101, XferMsg("z", bob), alice, HashFromByte(0x02)));
    CZNAMName rec;
    ASSERT_TRUE(s->GetName("z", rec));
    EXPECT_EQ(rec.ownerAddr, bob);
    EXPECT_TRUE(OwnerHasName(s, bob, "z"));

    // Disconnect: owner restored to alice byte-identically.
    ASSERT_TRUE(s->DisconnectBlock(newBlk, 100, baseBlk));
    ASSERT_TRUE(s->GetName("z", rec));
    EXPECT_EQ(rec.ownerAddr, alice);
    EXPECT_TRUE(OwnerHasName(s, alice, "z"));
    EXPECT_FALSE(OwnerHasName(s, bob, "z"));   // bob's reverse-index row gone
    EXPECT_EQ(NameCount(s), preNames);
    EXPECT_EQ(HistoryCount(s, "z"), preHist);  // transfer history row erased
    int64_t h; uint256 bh; ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, ph);
    EXPECT_EQ(bh, pbh);
    delete s;
}

// Determinism: two independent stores fed the identical op stream end identical.
TEST(ZNAMStore, DeterministicAcrossStores)
{
    SelectParams(CBaseChainParams::REGTEST);
    const std::string bob = MakeP2PKH(0x0B);

    struct Op { uint256 blk; int64_t h; ZNAMMessage msg; std::string owner; uint256 txid; };
    std::vector<Op> ops;
    ops.push_back({HashFromByte(0x01), 100, RegMsg("alpha", ZNAM_TARGET_ONION, "a.onion"), "alice", HashFromByte(0x11)});
    ops.push_back({HashFromByte(0x02), 101, RegMsg("beta", ZNAM_TARGET_ZADDR, "zs1b"), "carol", HashFromByte(0x12)});
    ops.push_back({HashFromByte(0x03), 102, RecMsg("alpha", ZNAM_TARGET_BTC, "bc1qa"), "alice", HashFromByte(0x13)});
    ops.push_back({HashFromByte(0x04), 103, TextMsg("alpha", "url", "http://a"), "alice", HashFromByte(0x14)});
    ops.push_back({HashFromByte(0x05), 104, XferMsg("beta", bob), "carol", HashFromByte(0x15)});
    ops.push_back({HashFromByte(0x06), 105, UpdMsg("alpha", ZNAM_TARGET_ONION, "a2.onion"), "alice", HashFromByte(0x16)});

    CZNAMStore* a = NewMemStore();
    CZNAMStore* b = NewMemStore();
    for (size_t i = 0; i < ops.size(); ++i) {
        ASSERT_TRUE(ApplyTx(a, ops[i].blk, ops[i].h, ops[i].msg, ops[i].owner, ops[i].txid));
        ASSERT_TRUE(ApplyTx(b, ops[i].blk, ops[i].h, ops[i].msg, ops[i].owner, ops[i].txid));
    }

    const char* names[] = {"alpha", "beta"};
    for (int n = 0; n < 2; ++n) {
        CZNAMName ra, rb;
        bool ha = a->GetName(names[n], ra);
        bool hb = b->GetName(names[n], rb);
        EXPECT_EQ(ha, hb);
        if (ha && hb) {
            EXPECT_EQ(ra.ownerAddr, rb.ownerAddr);
            EXPECT_EQ(ra.expiryHeight, rb.expiryHeight);
            EXPECT_EQ((int)ra.primaryType, (int)rb.primaryType);
            EXPECT_EQ(ra.primaryValue, rb.primaryValue);
        }
    }
    EXPECT_EQ(NameCount(a), NameCount(b));
    EXPECT_TRUE(OwnerHasName(a, bob, "beta"));
    EXPECT_TRUE(OwnerHasName(b, bob, "beta"));
    delete a;
    delete b;
}
