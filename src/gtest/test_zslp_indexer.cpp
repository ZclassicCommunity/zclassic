// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Unit tests for the ZSLP token store (CZSLPStore): put/get/list, balance
// accounting, and the reorg invariant — connecting then disconnecting a
// block must restore the store byte-for-byte to its prior state.
//
// These tests feed parsed messages directly to the store (no full chain),
// exercising the same code path the indexer drives.

#include <gtest/gtest.h>

#include "zslp/zslpstore.h"
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

CZSLPToken MakeToken(const uint256& id, const std::string& ticker,
                     int64_t height, uint8_t baton = 0)
{
    CZSLPToken t;
    t.tokenId = id;
    t.ticker = ticker;
    t.name = ticker + " Token";
    t.documentUrl = "https://example.com/" + ticker;
    t.decimals = 2;
    t.mintBatonVout = baton;
    t.genesisHeight = height;
    return t;
}

// Build an in-memory store (leveldb memenv) for a test.
CZSLPStore* NewMemStore()
{
    return new CZSLPStore("zslp-test", 1 << 20, /*fMemory=*/true, /*fWipe=*/true);
}

} // namespace

// ── Genesis put/get + balance + total_minted ───────────────────────

TEST(ZSLPStore, GenesisPutGet)
{
    CZSLPStore* s = NewMemStore();

    uint256 blk = HashFromByte(0x10);
    uint256 tid = HashFromByte(0xA1);
    std::string addr = "t1ExampleAddressAaa";

    s->ConnectBlockBegin(blk);
    CZSLPToken token = MakeToken(tid, "ABC", 100, /*baton=*/2);
    ASSERT_TRUE(s->ApplyGenesis(token, addr, tid, 1, 1000));
    s->ConnectBlockEnd(100, blk);

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(tid, got));
    EXPECT_EQ(got.tokenId, tid);
    EXPECT_EQ(got.ticker, "ABC");
    EXPECT_EQ(got.decimals, 2);
    EXPECT_EQ(got.genesisHeight, 100);
    EXPECT_EQ(got.totalMinted, 1000);
    EXPECT_EQ(got.mintBatonVout, 2);

    EXPECT_EQ(s->GetBalance(tid, addr), 1000);
    EXPECT_EQ(s->TokenCount(), 1);

    int64_t h; uint256 bh;
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, 100);
    EXPECT_EQ(bh, blk);

    delete s;
}

// ── Mint increases total_minted and balance ────────────────────────

TEST(ZSLPStore, MintAccounting)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0xB2);
    std::string addr = "t1MintRecipient";

    s->ConnectBlockBegin(HashFromByte(0x20));
    ASSERT_TRUE(s->ApplyGenesis(MakeToken(tid, "MNT", 200, 2), addr, tid, 1, 500));
    s->ConnectBlockEnd(200, HashFromByte(0x20));

    uint256 mintTx = HashFromByte(0xC3);
    s->ConnectBlockBegin(HashFromByte(0x21));
    ASSERT_TRUE(s->ApplyMint(tid, addr, mintTx, 201, 1, 250,
                             /*batonMoved=*/false, 2));
    s->ConnectBlockEnd(201, HashFromByte(0x21));

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(tid, got));
    EXPECT_EQ(got.totalMinted, 750);
    EXPECT_EQ(s->GetBalance(tid, addr), 750);
    delete s;
}

// ── Send credits recipients; list newest-first ─────────────────────

TEST(ZSLPStore, SendAndListTransfers)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0xD4);
    std::string a1 = "t1Sender";
    std::string a2 = "t1Recipient";

    s->ConnectBlockBegin(HashFromByte(0x30));
    ASSERT_TRUE(s->ApplyGenesis(MakeToken(tid, "SND", 300), a1, tid, 1, 1000));
    s->ConnectBlockEnd(300, HashFromByte(0x30));

    s->ConnectBlockBegin(HashFromByte(0x31));
    uint256 sendTx = HashFromByte(0xE5);
    ASSERT_TRUE(s->ApplySend(tid, a2, sendTx, 305, 1, 400));
    s->ConnectBlockEnd(305, HashFromByte(0x31));

    EXPECT_EQ(s->GetBalance(tid, a2), 400);

    std::vector<CZSLPTransfer> xfers;
    int n = s->ListTransfers(tid, 0, 100, xfers);
    EXPECT_EQ(n, 2);
    // Newest first: the SEND at height 305 should come before the genesis.
    ASSERT_EQ(xfers.size(), 2u);
    EXPECT_EQ(xfers[0].blockHeight, 305);
    EXPECT_EQ(xfers[0].txType, ZSLP_TX_SEND);
    EXPECT_EQ(xfers[1].blockHeight, 300);
    EXPECT_EQ(xfers[1].txType, ZSLP_TX_GENESIS);
    delete s;
}

// ── ListTokens bounding ────────────────────────────────────────────

TEST(ZSLPStore, ListTokensBounded)
{
    CZSLPStore* s = NewMemStore();
    for (int i = 0; i < 5; ++i) {
        uint256 tid = HashFromByte((uint8_t)(0x40 + i));
        s->ConnectBlockBegin(HashFromByte((uint8_t)(0x50 + i)));
        s->ApplyGenesis(MakeToken(tid, "T", 400 + i), "t1addr", tid, 1, 10);
        s->ConnectBlockEnd(400 + i, HashFromByte((uint8_t)(0x50 + i)));
    }
    EXPECT_EQ(s->TokenCount(), 5);

    std::vector<CZSLPToken> page;
    EXPECT_EQ(s->ListTokens(0, 2, page), 2);
    EXPECT_EQ(s->ListTokens(2, 2, page), 2);
    EXPECT_EQ(s->ListTokens(4, 10, page), 1);
    EXPECT_EQ(s->ListTokens(0, 0, page), 0);
    delete s;
}

// ── GetTokensForAddress (the listmytokens primitive) ───────────────

TEST(ZSLPStore, TokensForAddress)
{
    CZSLPStore* s = NewMemStore();
    uint256 t1 = HashFromByte(0x71);
    uint256 t2 = HashFromByte(0x72);
    std::string mine = "t1Mine";
    std::string other = "t1Other";

    s->ConnectBlockBegin(HashFromByte(0x80));
    ASSERT_TRUE(s->ApplyGenesis(MakeToken(t1, "AAA", 500), mine, t1, 1, 100));
    s->ConnectBlockEnd(500, HashFromByte(0x80));

    s->ConnectBlockBegin(HashFromByte(0x81));
    ASSERT_TRUE(s->ApplyGenesis(MakeToken(t2, "BBB", 501), other, t2, 1, 200));
    s->ConnectBlockEnd(501, HashFromByte(0x81));

    std::vector<std::pair<uint256, int64_t> > rows;
    s->GetTokensForAddress(mine, rows);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].first, t1);
    EXPECT_EQ(rows[0].second, 100);

    s->GetTokensForAddress(other, rows);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].first, t2);
    delete s;
}

// ── REORG INVARIANT: connect then disconnect == prior state ────────

TEST(ZSLPStore, ReorgGenesisRoundTrip)
{
    CZSLPStore* s = NewMemStore();

    // Pre-state: one token already present from an earlier block.
    uint256 baseBlk = HashFromByte(0x01);
    uint256 baseTok = HashFromByte(0x02);
    std::string baseAddr = "t1Base";
    s->ConnectBlockBegin(baseBlk);
    ASSERT_TRUE(s->ApplyGenesis(MakeToken(baseTok, "BASE", 10), baseAddr,
                                baseTok, 1, 5000));
    s->ConnectBlockEnd(10, baseBlk);

    const int64_t preCount = s->TokenCount();
    const int64_t preBaseBal = s->GetBalance(baseTok, baseAddr);

    // Connect a new block carrying a fresh genesis + a send of the base token.
    uint256 newBlk = HashFromByte(0x03);
    uint256 newTok = HashFromByte(0x04);
    std::string addrA = "t1New";
    s->ConnectBlockBegin(newBlk);
    ASSERT_TRUE(s->ApplyGenesis(MakeToken(newTok, "NEW", 11), addrA,
                                newTok, 1, 1000));
    uint256 sendTx = HashFromByte(0x05);
    ASSERT_TRUE(s->ApplySend(baseTok, addrA, sendTx, 11, 1, 1500));
    s->ConnectBlockEnd(11, newBlk);

    // Post-connect: state changed.
    EXPECT_EQ(s->TokenCount(), preCount + 1);
    EXPECT_EQ(s->GetBalance(newTok, addrA), 1000);
    EXPECT_EQ(s->GetBalance(baseTok, addrA), 1500);
    int64_t h; uint256 bh;
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, 11);
    EXPECT_EQ(bh, newBlk);

    // Disconnect (reorg) the new block; must restore the prior state exactly.
    ASSERT_TRUE(s->DisconnectBlock(newBlk, 10, baseBlk));

    EXPECT_EQ(s->TokenCount(), preCount);
    CZSLPToken gone;
    EXPECT_FALSE(s->GetToken(newTok, gone)); // new genesis erased
    EXPECT_EQ(s->GetBalance(newTok, addrA), 0); // its balance erased
    EXPECT_EQ(s->GetBalance(baseTok, addrA), 0); // send credit reversed
    EXPECT_EQ(s->GetBalance(baseTok, baseAddr), preBaseBal); // base untouched

    // The new token's transfer rows are gone; base token keeps only genesis.
    std::vector<CZSLPTransfer> xfers;
    EXPECT_EQ(s->ListTransfers(newTok, 0, 100, xfers), 0);
    EXPECT_EQ(s->ListTransfers(baseTok, 0, 100, xfers), 1);

    // Tip rewound.
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, 10);
    EXPECT_EQ(bh, baseBlk);

    delete s;
}

// ── REORG INVARIANT: mint baton + total_minted reversal ────────────

TEST(ZSLPStore, ReorgMintRoundTrip)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0x90);
    std::string addr = "t1MintAddr";

    s->ConnectBlockBegin(HashFromByte(0xA0));
    ASSERT_TRUE(s->ApplyGenesis(MakeToken(tid, "BAT", 20, /*baton=*/2), addr,
                                tid, 1, 1000));
    s->ConnectBlockEnd(20, HashFromByte(0xA0));

    CZSLPToken before;
    ASSERT_TRUE(s->GetToken(tid, before));
    const int64_t preMinted = before.totalMinted;
    const uint8_t preBaton = before.mintBatonVout;
    const int64_t preBal = s->GetBalance(tid, addr);

    // Mint more and move the baton to vout 3.
    uint256 mintBlk = HashFromByte(0xA1);
    uint256 mintTx = HashFromByte(0xA2);
    s->ConnectBlockBegin(mintBlk);
    ASSERT_TRUE(s->ApplyMint(tid, addr, mintTx, 21, 1, 500,
                             /*batonMoved=*/true, /*newBatonVout=*/3));
    s->ConnectBlockEnd(21, mintBlk);

    CZSLPToken mid;
    ASSERT_TRUE(s->GetToken(tid, mid));
    EXPECT_EQ(mid.totalMinted, preMinted + 500);
    EXPECT_EQ(mid.mintBatonVout, 3);
    EXPECT_EQ(s->GetBalance(tid, addr), preBal + 500);

    // Disconnect: total_minted, baton, and balance must all revert.
    ASSERT_TRUE(s->DisconnectBlock(mintBlk, 20, HashFromByte(0xA0)));

    CZSLPToken after;
    ASSERT_TRUE(s->GetToken(tid, after));
    EXPECT_EQ(after.totalMinted, preMinted);
    EXPECT_EQ(after.mintBatonVout, preBaton);
    EXPECT_EQ(s->GetBalance(tid, addr), preBal);
    delete s;
}

// ── Disconnecting a ZSLP-empty block is a safe tip rewind ──────────

TEST(ZSLPStore, DisconnectEmptyBlock)
{
    CZSLPStore* s = NewMemStore();
    uint256 blk = HashFromByte(0xF0);
    s->ConnectBlockBegin(blk);
    s->ConnectBlockEnd(50, blk); // no ZSLP records applied

    EXPECT_EQ(s->TokenCount(), 0);
    ASSERT_TRUE(s->DisconnectBlock(blk, 49, HashFromByte(0xEF)));

    int64_t h; uint256 bh;
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, 49);
    EXPECT_EQ(bh, HashFromByte(0xEF));
    delete s;
}
