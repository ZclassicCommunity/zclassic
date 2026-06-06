// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Unit tests for the ZSLP token store (CZSLPStore) under the real SLP
// Token-Type-1, UTXO-bound conservation model: token-carrying UTXOs are the
// source of truth, the per-address balance is a derived view, and a SEND/MINT
// can only move/issue tokens that exist on spent inputs (or, for MINT, with the
// mint baton on a spent input). This file drives the store's single conservation
// entry point ApplyTransaction(...) with synthetic vin / parsed messages /
// vout-address closures — the same path the live indexer drives.
//
// Coverage:
//   - genesis / mint / send accounting under conservation
//   - the reorg invariant: connecting then disconnecting a block restores the
//     store byte-for-byte (UTXOs, balances, tokens, transfers, tip)
//   - the FORGE-REJECTION suite: a SEND with no token input credits NOBODY; an
//     NFT (qty 1) cannot be duplicated by a forged SEND; an over-send burns its
//     inputs and creates nothing; a MINT without the baton input is rejected; a
//     non-SLP spend of a token UTXO burns it; intra-block spend visibility.

#include <gtest/gtest.h>

#include "zslp/zslpstore.h"
#include "primitives/transaction.h"
#include "uint256.h"

#include <functional>
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

// A vout-index -> address map for a tx, so ApplyTransaction can resolve
// recipient addresses without a real CTransaction. Index 0 is the OP_RETURN
// by convention (empty address).
typedef std::map<int32_t, std::string> AddrMap;

std::function<std::string(int32_t)> AddrOf(const AddrMap& m)
{
    return [m](int32_t n) -> std::string {
        AddrMap::const_iterator it = m.find(n);
        return it == m.end() ? std::string() : it->second;
    };
}

// Convenience: a GENESIS message.
CZSLPParsedMsg GenMsg(int64_t initialQty, int32_t batonVout = 0)
{
    CZSLPParsedMsg m;
    m.type = ZSLP_MSG_GENESIS;
    m.initialQuantity = initialQty;
    m.mintBatonVout = batonVout;
    return m;
}

// A MINT message.
CZSLPParsedMsg MintMsg(const uint256& tokenId, int64_t addQty, int32_t batonVout = 0)
{
    CZSLPParsedMsg m;
    m.type = ZSLP_MSG_MINT;
    m.tokenId = tokenId;
    m.additionalQuantity = addQty;
    m.mintBatonVout = batonVout;
    return m;
}

// A SEND message with up to a few output quantities. The parsed-message array
// is sized to the single canonical cap (ZSLP_SEND_MAX_OUTPUTS_STORE = 19); the
// parser rejects any SEND with more than that, so the store never sees a larger
// count. Tests that exercise the cap supply exactly 19 (valid) entries.
CZSLPParsedMsg SendMsg(const uint256& tokenId, const std::vector<int64_t>& outs)
{
    CZSLPParsedMsg m;
    m.type = ZSLP_MSG_SEND;
    m.tokenId = tokenId;
    m.numOutputs = (int)outs.size();
    for (size_t i = 0; i < outs.size() && i < (size_t)ZSLP_SEND_MAX_OUTPUTS_STORE; ++i)
        m.outputQuantities[i] = outs[i];
    return m;
}

// Drive a single transaction through the store inside its own connect block.
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

COutPoint OutPoint(const uint256& txid, uint32_t n) { return COutPoint(txid, n); }

} // namespace

// ── Genesis put/get + balance + total_minted + UTXO ────────────────

TEST(ZSLPStore, GenesisPutGet)
{
    CZSLPStore* s = NewMemStore();

    uint256 blk = HashFromByte(0x10);
    uint256 tid = HashFromByte(0xA1);
    std::string addr = "t1ExampleAddressAaa";

    CZSLPToken meta = MakeToken(tid, "ABC", 100, /*baton=*/2);
    CZSLPParsedMsg m = GenMsg(1000, /*batonVout=*/2);
    AddrMap addrs; addrs[1] = addr; // baton at vout 2 lands at empty addr
    ASSERT_TRUE(ApplyTx(s, blk, 100, {}, &m, tid, &meta, addrs, /*voutCount=*/3));

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(tid, got));
    EXPECT_EQ(got.tokenId, tid);
    EXPECT_EQ(got.ticker, "ABC");
    EXPECT_EQ(got.decimals, 2);
    EXPECT_EQ(got.genesisHeight, 100);
    EXPECT_EQ(got.totalMinted, 1000);
    EXPECT_EQ(got.mintBatonVout, 2); // baton UTXO live -> mirror shows it

    EXPECT_EQ(s->GetBalance(tid, addr), 1000);
    EXPECT_EQ(s->TokenCount(), 1);

    // One quantity UTXO at vout1 + one baton UTXO at vout2.
    EXPECT_EQ(s->UtxoCount(), 2);
    CZSLPTokenUtxo u1, u2;
    ASSERT_TRUE(s->GetUtxo(tid, 1, u1));
    EXPECT_EQ(u1.amount, 1000);
    EXPECT_FALSE(u1.isMintBaton);
    ASSERT_TRUE(s->GetUtxo(tid, 2, u2));
    EXPECT_EQ(u2.amount, 0);
    EXPECT_TRUE(u2.isMintBaton);

    int64_t h; uint256 bh;
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, 100);
    EXPECT_EQ(bh, blk);

    delete s;
}

// ── Mint requires the baton input; without it nothing is issued ─────

TEST(ZSLPStore, MintAccounting)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0xB2);
    std::string addr = "t1MintRecipient";

    // Genesis: 500 at vout1, baton at vout2.
    CZSLPToken meta = MakeToken(tid, "MNT", 200, 2);
    CZSLPParsedMsg gm = GenMsg(500, 2);
    AddrMap g; g[1] = addr;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x20), 200, {}, &gm, tid, &meta, g, 3));
    EXPECT_EQ(s->GetBalance(tid, addr), 500);

    // MINT spending the genesis baton (tid, vout2): +250, baton continues at vout2.
    uint256 mintTx = HashFromByte(0xC3);
    CZSLPParsedMsg mm = MintMsg(tid, 250, /*batonVout=*/2);
    AddrMap mo; mo[1] = addr;
    std::vector<COutPoint> vin = { OutPoint(tid, 2) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x21), 201, vin, &mm, mintTx, NULL, mo, 3));

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(tid, got));
    EXPECT_EQ(got.totalMinted, 750);
    EXPECT_EQ(s->GetBalance(tid, addr), 750);
    // Baton moved: genesis baton UTXO gone, new baton at the mint tx vout2.
    CZSLPTokenUtxo b;
    EXPECT_FALSE(s->GetUtxo(tid, 2, b));            // old baton consumed
    ASSERT_TRUE(s->GetUtxo(mintTx, 2, b));          // new baton at mint tx
    EXPECT_TRUE(b.isMintBaton);

    // Sibling negative: a MINT with NO baton input issues nothing.
    uint256 mintTx2 = HashFromByte(0xC4);
    CZSLPParsedMsg mm2 = MintMsg(tid, 1000, /*batonVout=*/2);
    AddrMap mo2; mo2[1] = addr;
    std::vector<COutPoint> noBaton = { OutPoint(HashFromByte(0xEE), 0) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x22), 202, noBaton, &mm2, mintTx2, NULL, mo2, 3));
    ASSERT_TRUE(s->GetToken(tid, got));
    EXPECT_EQ(got.totalMinted, 750);               // unchanged
    EXPECT_EQ(s->GetBalance(tid, addr), 750);      // unchanged
    EXPECT_FALSE(s->GetUtxo(mintTx2, 1, b));       // no quantity UTXO created
    delete s;
}

// ── Send moves only what spent inputs carry; list newest-first ─────

TEST(ZSLPStore, SendAndListTransfers)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0xD4);
    std::string a1 = "t1Sender";
    std::string a2 = "t1Recipient";

    // Genesis: 1000 -> a1 at (tid, vout1).
    CZSLPToken meta = MakeToken(tid, "SND", 300);
    CZSLPParsedMsg gm = GenMsg(1000);
    AddrMap g; g[1] = a1;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x30), 300, {}, &gm, tid, &meta, g, 2));
    EXPECT_EQ(s->GetBalance(tid, a1), 1000);

    // SEND spending (tid, vout1): 400 -> a2. (availIn-required) = 600 BURNED.
    uint256 sendTx = HashFromByte(0xE5);
    CZSLPParsedMsg sm = SendMsg(tid, {400});
    AddrMap so; so[1] = a2;
    std::vector<COutPoint> vin = { OutPoint(tid, 1) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x31), 305, vin, &sm, sendTx, NULL, so, 2));

    EXPECT_EQ(s->GetBalance(tid, a2), 400);
    EXPECT_EQ(s->GetBalance(tid, a1), 0);  // sender's UTXO consumed
    // Only the recipient's 400 UTXO is live now (the 600 difference was burned).
    EXPECT_EQ(s->UtxoCount(), 1);
    CZSLPTokenUtxo u;
    ASSERT_TRUE(s->GetUtxo(sendTx, 1, u));
    EXPECT_EQ(u.amount, 400);

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
        CZSLPToken meta = MakeToken(tid, "T", 400 + i);
        CZSLPParsedMsg gm = GenMsg(10);
        AddrMap g; g[1] = "t1addr";
        ApplyTx(s, HashFromByte((uint8_t)(0x50 + i)), 400 + i, {}, &gm, tid, &meta, g, 2);
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

    CZSLPToken m1 = MakeToken(t1, "AAA", 500);
    CZSLPParsedMsg g1 = GenMsg(100);
    AddrMap a1; a1[1] = mine;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x80), 500, {}, &g1, t1, &m1, a1, 2));

    CZSLPToken m2 = MakeToken(t2, "BBB", 501);
    CZSLPParsedMsg g2 = GenMsg(200);
    AddrMap a2; a2[1] = other;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x81), 501, {}, &g2, t2, &m2, a2, 2));

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

// ── REORG INVARIANT: genesis + send round-trip ─────────────────────

TEST(ZSLPStore, ReorgGenesisRoundTrip)
{
    CZSLPStore* s = NewMemStore();

    // Pre-state: one token already present, 5000 at baseAddr (baseTok, vout1).
    uint256 baseBlk = HashFromByte(0x01);
    uint256 baseTok = HashFromByte(0x02);
    std::string baseAddr = "t1Base";
    CZSLPToken bmeta = MakeToken(baseTok, "BASE", 10);
    CZSLPParsedMsg bg = GenMsg(5000);
    AddrMap bgaddr; bgaddr[1] = baseAddr;
    ASSERT_TRUE(ApplyTx(s, baseBlk, 10, {}, &bg, baseTok, &bmeta, bgaddr, 2));

    const int64_t preCount = s->TokenCount();
    const int64_t preBaseBal = s->GetBalance(baseTok, baseAddr);
    const int64_t preUtxos = s->UtxoCount();
    EXPECT_EQ(preBaseBal, 5000);

    // Connect ONE block carrying: a fresh genesis (txA), and a send of the base
    // token that spends (baseTok, vout1) -> 1500 to addrA + 3500 change to base.
    uint256 newBlk = HashFromByte(0x03);
    uint256 newTok = HashFromByte(0x04);
    std::string addrA = "t1New";
    s->ConnectBlockBegin(newBlk);

    // tx1: new genesis 1000 -> addrA.
    CZSLPToken nmeta = MakeToken(newTok, "NEW", 11);
    CZSLPParsedMsg ng = GenMsg(1000);
    AddrMap ngaddr; ngaddr[1] = addrA;
    ASSERT_TRUE(s->ApplyTransaction({}, &ng, newTok, 11, &nmeta,
                                    AddrOf(ngaddr), 2));

    // tx2: send base token; spends (baseTok,1)=5000, pays 1500->addrA, 3500->base.
    uint256 sendTx = HashFromByte(0x05);
    CZSLPParsedMsg sm = SendMsg(baseTok, {1500, 3500});
    AddrMap saddr; saddr[1] = addrA; saddr[2] = baseAddr;
    std::vector<COutPoint> vin = { OutPoint(baseTok, 1) };
    ASSERT_TRUE(s->ApplyTransaction(vin, &sm, sendTx, 11, NULL, AddrOf(saddr), 3));
    s->ConnectBlockEnd(11, newBlk);

    // Post-connect: state changed.
    EXPECT_EQ(s->TokenCount(), preCount + 1);
    EXPECT_EQ(s->GetBalance(newTok, addrA), 1000);
    EXPECT_EQ(s->GetBalance(baseTok, addrA), 1500);
    EXPECT_EQ(s->GetBalance(baseTok, baseAddr), 3500); // change back
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
    EXPECT_EQ(s->GetBalance(baseTok, baseAddr), preBaseBal); // base UTXO restored
    EXPECT_EQ(s->UtxoCount(), preUtxos); // exactly the base 5000 UTXO again
    CZSLPTokenUtxo bu;
    ASSERT_TRUE(s->GetUtxo(baseTok, 1, bu));
    EXPECT_EQ(bu.amount, 5000);

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

// ── REORG INVARIANT: mint via baton input round-trip ───────────────

TEST(ZSLPStore, ReorgMintRoundTrip)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0x90);
    std::string addr = "t1MintAddr";

    // Genesis: 1000 at vout1, baton at vout2.
    CZSLPToken meta = MakeToken(tid, "BAT", 20, /*baton=*/2);
    CZSLPParsedMsg gm = GenMsg(1000, 2);
    AddrMap g; g[1] = addr;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0xA0), 20, {}, &gm, tid, &meta, g, 3));

    CZSLPToken before;
    ASSERT_TRUE(s->GetToken(tid, before));
    const int64_t preMinted = before.totalMinted;
    const uint8_t preBaton = before.mintBatonVout;
    const int64_t preBal = s->GetBalance(tid, addr);
    const int64_t preUtxos = s->UtxoCount();
    EXPECT_EQ(preBaton, 2);

    // MINT spending the baton (tid,2): +500 at vout1, baton moves to vout3.
    uint256 mintBlk = HashFromByte(0xA1);
    uint256 mintTx = HashFromByte(0xA2);
    CZSLPParsedMsg mm = MintMsg(tid, 500, /*batonVout=*/3);
    AddrMap mo; mo[1] = addr;
    std::vector<COutPoint> vin = { OutPoint(tid, 2) };
    ASSERT_TRUE(ApplyTx(s, mintBlk, 21, vin, &mm, mintTx, NULL, mo, 4));

    CZSLPToken mid;
    ASSERT_TRUE(s->GetToken(tid, mid));
    EXPECT_EQ(mid.totalMinted, preMinted + 500);
    EXPECT_EQ(mid.mintBatonVout, 3);
    EXPECT_EQ(s->GetBalance(tid, addr), preBal + 500);

    // Disconnect: total_minted, baton mirror, balance, and UTXOs all revert.
    ASSERT_TRUE(s->DisconnectBlock(mintBlk, 20, HashFromByte(0xA0)));

    CZSLPToken after;
    ASSERT_TRUE(s->GetToken(tid, after));
    EXPECT_EQ(after.totalMinted, preMinted);
    EXPECT_EQ(after.mintBatonVout, preBaton);
    EXPECT_EQ(s->GetBalance(tid, addr), preBal);
    EXPECT_EQ(s->UtxoCount(), preUtxos);
    // The genesis baton UTXO is restored; the mint's new UTXOs erased.
    CZSLPTokenUtxo b;
    ASSERT_TRUE(s->GetUtxo(tid, 2, b));
    EXPECT_TRUE(b.isMintBaton);
    EXPECT_FALSE(s->GetUtxo(mintTx, 1, b));
    EXPECT_FALSE(s->GetUtxo(mintTx, 3, b));
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

// ─────────────────────── FORGE-REJECTION SUITE ────────────────────

// (a) A SEND of an existing token with NO token input credits NOBODY.
TEST(ZSLPStore, ForgeSendWithoutInputCreditsNobody)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0x21);
    std::string victim = "t1Victim";
    std::string attacker = "t1Attacker";

    CZSLPToken meta = MakeToken(tid, "REAL", 1000);
    CZSLPParsedMsg gm = GenMsg(1000);
    AddrMap g; g[1] = victim;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x30), 1000, {}, &gm, tid, &meta, g, 2));
    EXPECT_EQ(s->GetBalance(tid, victim), 1000);

    // Attacker broadcasts a SEND OP_RETURN crediting themselves 1000 — but holds
    // NO token input (vin references an unrelated, non-token prevout).
    uint256 forgeTx = HashFromByte(0x40);
    CZSLPParsedMsg sm = SendMsg(tid, {1000});
    AddrMap so; so[1] = attacker;
    std::vector<COutPoint> vin = { OutPoint(HashFromByte(0xCC), 0) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x31), 1001, vin, &sm, forgeTx, NULL, so, 2));

    EXPECT_EQ(s->GetBalance(tid, attacker), 0); // forgery created nothing
    EXPECT_EQ(s->GetBalance(tid, victim), 1000); // victim untouched
    CZSLPTokenUtxo u;
    EXPECT_FALSE(s->GetUtxo(forgeTx, 1, u));     // no UTXO minted out of thin air
    std::vector<CZSLPTransfer> xfers;
    EXPECT_EQ(s->ListTransfers(tid, 0, 100, xfers), 1); // only the genesis row
    delete s;
}

// (b) Over-send: availIn < requiredOut burns the inputs and creates NO outputs.
TEST(ZSLPStore, OverSendBurnsInputsNoOutputs)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0x22);
    std::string owner = "t1Owner";
    std::string dest = "t1Dest";

    CZSLPToken meta = MakeToken(tid, "OVR", 100);
    CZSLPParsedMsg gm = GenMsg(100);
    AddrMap g; g[1] = owner;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x32), 100, {}, &gm, tid, &meta, g, 2));
    EXPECT_EQ(s->GetBalance(tid, owner), 100);

    // SEND tries to pay out 9999 while only 100 is on the spent input.
    uint256 sendTx = HashFromByte(0x41);
    CZSLPParsedMsg sm = SendMsg(tid, {9999});
    AddrMap so; so[1] = dest;
    std::vector<COutPoint> vin = { OutPoint(tid, 1) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x33), 101, vin, &sm, sendTx, NULL, so, 2));

    EXPECT_EQ(s->GetBalance(tid, dest), 0);   // nothing created
    EXPECT_EQ(s->GetBalance(tid, owner), 0);  // input consumed (burned)
    EXPECT_EQ(s->UtxoCount(), 0);             // the 100 is gone, no output minted
    CZSLPTokenUtxo u;
    EXPECT_FALSE(s->GetUtxo(sendTx, 1, u));
    delete s;
}

// (c) MINT without the baton input issues nothing.
TEST(ZSLPStore, MintWithoutBatonRejected)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0x23);
    std::string addr = "t1MintC";

    CZSLPToken meta = MakeToken(tid, "NBT", 500, /*baton=*/2);
    CZSLPParsedMsg gm = GenMsg(500, 2);
    AddrMap g; g[1] = addr;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x34), 500, {}, &gm, tid, &meta, g, 3));

    // Spend the QUANTITY UTXO (vout1), not the baton, while quoting a MINT.
    uint256 mintTx = HashFromByte(0x42);
    CZSLPParsedMsg mm = MintMsg(tid, 10000, 2);
    AddrMap mo; mo[1] = addr;
    std::vector<COutPoint> vin = { OutPoint(tid, 1) }; // NOT the baton
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x35), 501, vin, &mm, mintTx, NULL, mo, 3));

    CZSLPToken got;
    ASSERT_TRUE(s->GetToken(tid, got));
    EXPECT_EQ(got.totalMinted, 500);            // no inflation
    CZSLPTokenUtxo u;
    EXPECT_FALSE(s->GetUtxo(mintTx, 1, u));      // no new UTXO created
    // The spent quantity UTXO was burned (consumed, not reissued).
    EXPECT_FALSE(s->GetUtxo(tid, 1, u));
    EXPECT_EQ(s->GetBalance(tid, addr), 0);
    // The baton UTXO at vout2 still exists (untouched).
    ASSERT_TRUE(s->GetUtxo(tid, 2, u));
    EXPECT_TRUE(u.isMintBaton);
    delete s;
}

// (d) An NFT (qty 1, dec 0, no baton) cannot be duplicated by a forged SEND.
TEST(ZSLPStore, NftCannotBeDuplicated)
{
    CZSLPStore* s = NewMemStore();
    uint256 nft = HashFromByte(0x24);
    std::string owner = "t1NftOwner";
    std::string buyer = "t1NftBuyer";
    std::string thief = "t1NftThief";

    // Genesis NFT: qty 1, decimals 0, NO baton.
    CZSLPToken meta = MakeToken(nft, "NFT", 700);
    meta.decimals = 0;
    CZSLPParsedMsg gm = GenMsg(1);
    AddrMap g; g[1] = owner;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x36), 700, {}, &gm, nft, &meta, g, 2));
    EXPECT_EQ(s->GetBalance(nft, owner), 1);
    EXPECT_EQ(s->UtxoCount(), 1);

    // Legit transfer: owner sends the single NFT UTXO to buyer.
    uint256 moveTx = HashFromByte(0x43);
    CZSLPParsedMsg sm = SendMsg(nft, {1});
    AddrMap so; so[1] = buyer;
    std::vector<COutPoint> vin = { OutPoint(nft, 1) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x37), 701, vin, &sm, moveTx, NULL, so, 2));
    EXPECT_EQ(s->GetBalance(nft, owner), 0);
    EXPECT_EQ(s->GetBalance(nft, buyer), 1);
    EXPECT_EQ(s->UtxoCount(), 1); // still exactly one live NFT UTXO

    // Forgery: a thief quotes the SAME tokenId in a SEND but does not hold the
    // (now buyer-owned) UTXO. Nothing is created — the NFT is not duplicated.
    uint256 forgeTx = HashFromByte(0x44);
    CZSLPParsedMsg fm = SendMsg(nft, {1});
    AddrMap fo; fo[1] = thief;
    std::vector<COutPoint> fvin = { OutPoint(HashFromByte(0xBB), 0) }; // not the NFT
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x38), 702, fvin, &fm, forgeTx, NULL, fo, 2));

    EXPECT_EQ(s->GetBalance(nft, thief), 0);
    EXPECT_EQ(s->GetBalance(nft, buyer), 1); // buyer still holds the one-and-only
    EXPECT_EQ(s->UtxoCount(), 1);            // exactly one live NFT UTXO, always
    delete s;
}

// (e) A non-SLP tx that spends a token UTXO burns it (derived balance drops).
TEST(ZSLPStore, NonSlpSpendBurnsUtxo)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0x25);
    std::string owner = "t1BurnOwner";

    CZSLPToken meta = MakeToken(tid, "BRN", 800);
    CZSLPParsedMsg gm = GenMsg(1000);
    AddrMap g; g[1] = owner;
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x39), 800, {}, &gm, tid, &meta, g, 2));
    EXPECT_EQ(s->GetBalance(tid, owner), 1000);
    EXPECT_EQ(s->UtxoCount(), 1);

    // A plain (non-SLP) transaction spends the token UTXO: msg == NULL.
    uint256 burnTx = HashFromByte(0x45);
    AddrMap bo; bo[1] = owner; // ordinary p2pkh outputs, but no SLP semantics
    std::vector<COutPoint> vin = { OutPoint(tid, 1) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0x3A), 801, vin, /*msg=*/NULL, burnTx,
                        NULL, bo, 2));

    EXPECT_EQ(s->GetBalance(tid, owner), 0); // tokens destroyed
    EXPECT_EQ(s->UtxoCount(), 0);            // UTXO erased
    CZSLPTokenUtxo u;
    EXPECT_FALSE(s->GetUtxo(tid, 1, u));
    delete s;
}

// (h) MULTI-TOKEN MIXED-INPUT SILENT BURN (G4): a SEND that spends a token-A
//     UTXO AND a token-B UTXO but declares ONLY token A in its OP_RETURN.
//     ApplyTransaction step (a) (zslpstore.cpp:437-446) consumes EVERY token
//     UTXO on the vin — both A and B. The SEND dispatch (:548-592) only
//     re-creates outputs for msg->tokenId (A). Token B is consumed and never
//     re-created => SILENTLY BURNED (credited to NOBODY). This documents +
//     guards that reality so a future change is forced to update the test.
//     The wallet-side defense that ensures normal coin-selection would NEVER
//     assemble such a tx (AvailableCoins fExcludeZSLPTokens via
//     ZSLPIsProtectedTokenOutpoint) is proven in
//     test_zslp_wallet.cpp::FundingFilterDropsUndeclaredTokenInput.
TEST(ZSLPStore, MixedInputSendBurnsUndeclaredTokenB)
{
    CZSLPStore* s = NewMemStore();
    uint256 tA = HashFromByte(0xA0), tB = HashFromByte(0xB0);
    std::string oA = "t1A", oB = "t1B", dest = "t1Dest";

    // Genesis token A: 1000 -> oA at (tA,1).
    {
        CZSLPToken mA = MakeToken(tA, "TA", 1);
        CZSLPParsedMsg g = GenMsg(1000);
        AddrMap a; a[1] = oA;
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0xA1), 1, {}, &g, tA, &mA, a, 2));
    }
    // Genesis token B: 500 -> oB at (tB,1).
    {
        CZSLPToken mB = MakeToken(tB, "TB", 2);
        CZSLPParsedMsg g = GenMsg(500);
        AddrMap b; b[1] = oB;
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0xB1), 2, {}, &g, tB, &mB, b, 2));
    }
    ASSERT_EQ(s->GetBalance(tA, oA), (int64_t)1000);
    ASSERT_EQ(s->GetBalance(tB, oB), (int64_t)500);
    const int64_t preUtxos = s->UtxoCount(); // 2 (tA,1) + (tB,1)

    // ONE SEND that declares ONLY token A (1000 -> dest at vout[1]) but spends
    // BOTH the token-A AND token-B UTXOs on its vin.
    uint256 sendTx = HashFromByte(0xC0);
    CZSLPParsedMsg sm = SendMsg(tA, {1000});
    AddrMap so; so[1] = dest;
    std::vector<COutPoint> vin = { OutPoint(tA, 1), OutPoint(tB, 1) };
    ASSERT_TRUE(ApplyTx(s, HashFromByte(0xC1), 3, vin, &sm, sendTx, NULL, so, 2));

    // Token A fully moved to dest.
    EXPECT_EQ(s->GetBalance(tA, dest), (int64_t)1000);
    EXPECT_EQ(s->GetBalance(tA, oA), (int64_t)0);
    // Token B's old UTXO is consumed.
    CZSLPTokenUtxo u;
    EXPECT_FALSE(s->GetUtxo(tB, 1, u));
    EXPECT_EQ(s->GetBalance(tB, oB), (int64_t)0);
    // Token B is credited to NOBODY — the silent burn.
    EXPECT_EQ(s->GetBalance(tB, dest), (int64_t)0);
    // No token-B UTXO exists anywhere now (no B output minted by the A-only SEND).
    EXPECT_FALSE(s->GetUtxo(sendTx, 1, u) && u.tokenId == tB);
    // Token B's declared supply is UNCHANGED but now UNRECOVERABLE (burned):
    // total_minted records issuance, not live balance.
    CZSLPToken tokB;
    ASSERT_TRUE(s->GetToken(tB, tokB));
    EXPECT_EQ(tokB.totalMinted, (int64_t)500);
    // Live UTXO set: only the new token-A UTXO at (sendTx,1). Both inputs were
    // consumed; only A was re-created => net one live UTXO (was 2).
    EXPECT_EQ(s->UtxoCount(), (int64_t)1);
    EXPECT_EQ(preUtxos, (int64_t)2);
    CZSLPTokenUtxo a1;
    ASSERT_TRUE(s->GetUtxo(sendTx, 1, a1));
    EXPECT_EQ(a1.amount, (int64_t)1000);
    EXPECT_EQ(a1.tokenId, tA);
    delete s;
}

// (f) Intra-block spend: a second tx spends a UTXO the FIRST tx created in the
//     SAME block. Requires per-tx commit visibility.
TEST(ZSLPStore, IntraBlockSpend)
{
    CZSLPStore* s = NewMemStore();
    uint256 tid = HashFromByte(0x26);
    std::string a = "t1IntraA";
    std::string b = "t1IntraB";

    uint256 blk = HashFromByte(0x50);
    s->ConnectBlockBegin(blk);

    // tx1: genesis 500 -> a at (tid, vout1).
    CZSLPToken meta = MakeToken(tid, "INB", 900);
    CZSLPParsedMsg gm = GenMsg(500);
    AddrMap ga; ga[1] = a;
    ASSERT_TRUE(s->ApplyTransaction({}, &gm, tid, 900, &meta, AddrOf(ga), 2));

    // tx2 (same block): spends (tid, vout1) created by tx1 -> 500 to b.
    uint256 sendTx = HashFromByte(0x46);
    CZSLPParsedMsg sm = SendMsg(tid, {500});
    AddrMap sb; sb[1] = b;
    std::vector<COutPoint> vin = { OutPoint(tid, 1) };
    ASSERT_TRUE(s->ApplyTransaction(vin, &sm, sendTx, 900, NULL, AddrOf(sb), 2));

    s->ConnectBlockEnd(900, blk);

    // tx2 must have SEEN tx1's UTXO and moved it: a==0, b==500.
    EXPECT_EQ(s->GetBalance(tid, a), 0);
    EXPECT_EQ(s->GetBalance(tid, b), 500);
    EXPECT_EQ(s->UtxoCount(), 1);
    CZSLPTokenUtxo u;
    ASSERT_TRUE(s->GetUtxo(sendTx, 1, u));
    EXPECT_EQ(u.amount, 500);
    EXPECT_FALSE(s->GetUtxo(tid, 1, u)); // tx1's UTXO consumed in-block
    delete s;
}

// (g) Reorg byte-identity across a burn/consume mix: a block with a valid send,
//     an invalid (over-send) burn, and a non-SLP burn must disconnect to the
//     exact pre-block state.
TEST(ZSLPStore, ReorgByteIdentityBurnConsumeMix)
{
    CZSLPStore* s = NewMemStore();

    // Pre-state: three independent token holdings from earlier blocks.
    uint256 tA = HashFromByte(0x60), tB = HashFromByte(0x61), tC = HashFromByte(0x62);
    std::string oA = "t1A", oB = "t1B", oC = "t1C", dest = "t1Dest";

    {
        CZSLPToken mA = MakeToken(tA, "TA", 1), mB = MakeToken(tB, "TB", 2),
                   mC = MakeToken(tC, "TC", 3);
        CZSLPParsedMsg g = GenMsg(1000);
        AddrMap a1; a1[1] = oA; AddrMap a2; a2[1] = oB; AddrMap a3; a3[1] = oC;
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0x70), 1, {}, &g, tA, &mA, a1, 2));
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0x71), 2, {}, &g, tB, &mB, a2, 2));
        ASSERT_TRUE(ApplyTx(s, HashFromByte(0x72), 3, {}, &g, tC, &mC, a3, 2));
    }

    // Snapshot the pre-block state.
    const int64_t preTokens = s->TokenCount();
    const int64_t preUtxos = s->UtxoCount();
    const int64_t preBalA = s->GetBalance(tA, oA);
    const int64_t preBalB = s->GetBalance(tB, oB);
    const int64_t preBalC = s->GetBalance(tC, oC);
    std::vector<CZSLPTransfer> preXA, preXB, preXC;
    s->ListTransfers(tA, 0, 100, preXA);
    s->ListTransfers(tB, 0, 100, preXB);
    s->ListTransfers(tC, 0, 100, preXC);
    int64_t preH; uint256 preBH;
    ASSERT_TRUE(s->ReadTip(preH, preBH));

    // Connect ONE block with three txs:
    uint256 blk = HashFromByte(0x73);
    s->ConnectBlockBegin(blk);

    // tx1 (valid send): spends (tA,1)=1000, pays 400->dest (600 burned).
    uint256 tx1 = HashFromByte(0x80);
    CZSLPParsedMsg s1 = SendMsg(tA, {400});
    AddrMap o1; o1[1] = dest;
    ASSERT_TRUE(s->ApplyTransaction({ OutPoint(tA, 1) }, &s1, tx1, 4, NULL,
                                    AddrOf(o1), 2));

    // tx2 (invalid over-send): spends (tB,1)=1000, asks 5000 -> all burned.
    uint256 tx2 = HashFromByte(0x81);
    CZSLPParsedMsg s2 = SendMsg(tB, {5000});
    AddrMap o2; o2[1] = dest;
    ASSERT_TRUE(s->ApplyTransaction({ OutPoint(tB, 1) }, &s2, tx2, 4, NULL,
                                    AddrOf(o2), 2));

    // tx3 (non-SLP burn): spends (tC,1)=1000 with NO SLP message.
    uint256 tx3 = HashFromByte(0x82);
    AddrMap o3; o3[1] = dest;
    ASSERT_TRUE(s->ApplyTransaction({ OutPoint(tC, 1) }, NULL, tx3, 4, NULL,
                                    AddrOf(o3), 2));

    s->ConnectBlockEnd(4, blk);

    // Post-connect sanity: everything moved/burned.
    EXPECT_EQ(s->GetBalance(tA, oA), 0);
    EXPECT_EQ(s->GetBalance(tA, dest), 400);
    EXPECT_EQ(s->GetBalance(tB, oB), 0);
    EXPECT_EQ(s->GetBalance(tB, dest), 0);  // invalid send created nothing
    EXPECT_EQ(s->GetBalance(tC, oC), 0);    // non-SLP burn

    // Disconnect: must restore byte-identical pre-block state.
    ASSERT_TRUE(s->DisconnectBlock(blk, preH, preBH));

    EXPECT_EQ(s->TokenCount(), preTokens);
    EXPECT_EQ(s->UtxoCount(), preUtxos);
    EXPECT_EQ(s->GetBalance(tA, oA), preBalA);
    EXPECT_EQ(s->GetBalance(tB, oB), preBalB);
    EXPECT_EQ(s->GetBalance(tC, oC), preBalC);
    EXPECT_EQ(s->GetBalance(tA, dest), 0);  // no residue at dest
    // The original UTXOs are restored exactly.
    CZSLPTokenUtxo u;
    ASSERT_TRUE(s->GetUtxo(tA, 1, u)); EXPECT_EQ(u.amount, 1000);
    ASSERT_TRUE(s->GetUtxo(tB, 1, u)); EXPECT_EQ(u.amount, 1000);
    ASSERT_TRUE(s->GetUtxo(tC, 1, u)); EXPECT_EQ(u.amount, 1000);
    // The block's created UTXOs are gone.
    EXPECT_FALSE(s->GetUtxo(tx1, 1, u));
    // Transfer logs restored.
    std::vector<CZSLPTransfer> xA, xB, xC;
    EXPECT_EQ((size_t)s->ListTransfers(tA, 0, 100, xA), preXA.size());
    EXPECT_EQ((size_t)s->ListTransfers(tB, 0, 100, xB), preXB.size());
    EXPECT_EQ((size_t)s->ListTransfers(tC, 0, 100, xC), preXC.size());
    // Tip rewound.
    int64_t h; uint256 bh;
    ASSERT_TRUE(s->ReadTip(h, bh));
    EXPECT_EQ(h, preH);
    EXPECT_EQ(bh, preBH);
    delete s;
}
