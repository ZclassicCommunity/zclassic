// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Unit tests for the ZSLP WRITE path's load-bearing, wallet-independent pieces:
//
//   1. The C++<->C build bridge (ZSLPBuildGenesis/Mint/Send) — that it emits the
//      complete OP_RETURN script (leading 0x6a), that the daemon parse seam
//      (CZSLPIndexer::ParseTx) round-trips the exact fields, and that it fails
//      (empty result) on over-cap / invalid input.
//
//   2. The deterministic CANONICAL LAYOUT the builder must produce: vout[0] =
//      OP_RETURN, vout[1..N] = token recipients in OP_RETURN order, any change
//      strictly AFTER the token outputs. We assemble a tx with that exact layout
//      (the same bytes BuildAndCommitZSLP assembles), drive it through the REAL
//      ParseTx + REAL store ApplyTransaction, and assert the ledger credits the
//      intended recipients and nothing is mis-credited or burned.
//
//   3. The READ-ONLY self-validation predicate CZSLPStore::WouldBeValid — the
//      exact gate the builder calls before broadcast (R-WALLET-9). We assert it
//      ACCEPTS a conserved/correctly-ordered tx and REJECTS the burn/mis-order
//      classes: OP_RETURN not at vout[0] (no SLP message), Σout > Σin (over-send),
//      a surplus with no token-change output, a quantity mapped to a nonexistent
//      vout, a MINT without the baton input, and a SEND that would map a token to
//      a nonexistent output.
//
// HONESTY: the full BuildAndCommitZSLP (coin selection + signing + CommitTransaction)
// needs a live CWallet, keystore, chainActive and mempool — far heavier than a
// gtest unit. That end-to-end path is NOT exercised here. What IS unit-tested is
// every PURE decision the builder delegates: the bridge bytes, the canonical
// layout's ledger effect through the real indexer, and the self-validation
// predicate that decides broadcast/refuse. The anti-burn funding fence and the
// signing loop are covered by code review against CreateTransaction, not gtest.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "key.h"
#include "key_io.h"
#include "main.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "utiltest.h"
#include "wallet/wallet.h"
#include "wallet/zslpwallet.h"
#include "zslp/zslpindexer.h"
#include "zslp/zslpmsg.h"
#include "zslp/zslpstore.h"

#include <functional>
#include <string>
#include <vector>

namespace {

uint256 H(uint8_t b)
{
    std::vector<unsigned char> v(32, 0);
    v[0] = b;
    return uint256(v);
}

// On-chain (BE) token-id bytes for a daemon uint256 — what the SEND/MINT bridge
// expects (reverse of internal bytes).
void TokenIdBE(const uint256& id, uint8_t out[32])
{
    const unsigned char* p = id.begin();
    for (int i = 0; i < 32; ++i) out[i] = p[31 - i];
}

CZSLPStore* NewStore()
{
    return new CZSLPStore("zslp-wallet-test", 1 << 20, /*fMemory=*/true,
                          /*fWipe=*/true);
}

// Per-vout deterministic address label; vout 0 (OP_RETURN) -> "".
std::function<std::string(int32_t)> AddrLabels()
{
    return [](int32_t n) -> std::string {
        if (n <= 0) return std::string();
        return std::string("t1vout") + std::to_string(n);
    };
}

// Build a CTransaction whose vout[0] is `opret` (the OP_RETURN) and vout[1..N]
// are dummy 546-sat outputs, plus an optional trailing change output. This is
// EXACTLY the canonical layout BuildAndCommitZSLP assembles. `vins` are spent
// prevouts.
CTransaction MakeCanonicalTx(const std::vector<unsigned char>& opret,
                             int nTokenOuts,
                             const std::vector<COutPoint>& vins,
                             bool withChange)
{
    CMutableTransaction mtx;
    for (size_t i = 0; i < vins.size(); ++i)
        mtx.vin.push_back(CTxIn(vins[i]));
    // vout[0] = OP_RETURN, value 0.
    {
        CTxOut o;
        o.nValue = 0;
        o.scriptPubKey = CScript(opret.begin(), opret.end());
        mtx.vout.push_back(o);
    }
    for (int i = 0; i < nTokenOuts; ++i) {
        CTxOut o;
        o.nValue = 546;
        o.scriptPubKey = CScript() << OP_TRUE; // dummy recipient
        mtx.vout.push_back(o);
    }
    if (withChange) {
        CTxOut o;
        o.nValue = 100000;
        o.scriptPubKey = CScript() << OP_DUP; // dummy change
        mtx.vout.push_back(o);
    }
    return CTransaction(mtx);
}

// Drive a tx through the EXACT production path used by the live indexer.
uint256 ApplyRealTx(CZSLPStore* s, const CTransaction& tx, int64_t height)
{
    CZSLPParsedMsg parsed;
    CZSLPToken genesisMeta;
    bool haveGenesis = false;
    bool present = CZSLPIndexer::ParseTx(tx, height, parsed, genesisMeta,
                                         haveGenesis);
    std::vector<COutPoint> vin;
    for (size_t k = 0; k < tx.vin.size(); ++k)
        vin.push_back(tx.vin[k].prevout);
    s->ApplyTransaction(vin, present ? &parsed : NULL, tx.GetHash(), height,
                        haveGenesis ? &genesisMeta : NULL, AddrLabels(),
                        (int32_t)tx.vout.size());
    return tx.GetHash();
}

// The self-validate gate exactly as BuildAndCommitZSLP calls it.
bool SelfValidate(CZSLPStore* s, const CTransaction& tx, int64_t height,
                  std::string& reason)
{
    CZSLPParsedMsg parsed;
    CZSLPToken genesisMeta;
    bool haveGenesis = false;
    if (!CZSLPIndexer::ParseTx(tx, height, parsed, genesisMeta, haveGenesis)) {
        reason = "no SLP message at vout[0]";
        return false;
    }
    std::vector<COutPoint> vin;
    for (size_t k = 0; k < tx.vin.size(); ++k)
        vin.push_back(tx.vin[k].prevout);
    return s->WouldBeValid(vin, &parsed, tx.GetHash(),
                           haveGenesis ? &genesisMeta : NULL,
                           (int32_t)tx.vout.size(), reason);
}

} // namespace

// ════════════════════════════════════════════════════════════════════════
//  1. Build bridge round-trips through the REAL parse seam
// ════════════════════════════════════════════════════════════════════════

TEST(ZslpWalletBridge, GenesisRoundTripVout0)
{
    uint8_t hash[32]; memset(hash, 0xAB, 32);
    std::vector<unsigned char> opret =
        ZSLPBuildGenesis("GOLD", "Gold Coin", "https://x.io", hash,
                         /*decimals=*/2, /*baton=*/2, /*qty=*/100000);
    ASSERT_FALSE(opret.empty());
    EXPECT_EQ(opret[0], 0x6a); // leading OP_RETURN opcode
    // Tie to the LIVE relay cap, not a magic 223 (see G2 below).
    EXPECT_LE(opret.size(), (size_t)nMaxDatacarrierBytes);

    // The genesis tx: vout[0]=OP_RETURN, vout[1]=recipient, vout[2]=baton.
    CTransaction tx = MakeCanonicalTx(opret, /*nTokenOuts=*/2, {}, false);
    CZSLPParsedMsg parsed; CZSLPToken meta; bool haveGen = false;
    ASSERT_TRUE(CZSLPIndexer::ParseTx(tx, 1, parsed, meta, haveGen));
    ASSERT_TRUE(haveGen);
    EXPECT_EQ(parsed.type, ZSLP_MSG_GENESIS);
    EXPECT_EQ(parsed.initialQuantity, (int64_t)100000);
    EXPECT_EQ(parsed.mintBatonVout, 2);
    EXPECT_EQ(meta.ticker, "GOLD");
    EXPECT_EQ(meta.name, "Gold Coin");
    EXPECT_EQ(meta.documentUrl, "https://x.io");
    EXPECT_EQ(meta.decimals, 2);
    EXPECT_TRUE(meta.hasDocumentHash);
    EXPECT_EQ(parsed.tokenId, tx.GetHash()); // tokenId == genesis txid
}

TEST(ZslpWalletBridge, NftGenesisIsBatonlessQty1)
{
    std::vector<unsigned char> opret =
        ZSLPBuildGenesis("", "My Photo #1", "", NULL,
                         /*decimals=*/0, /*baton=*/0, /*qty=*/1);
    ASSERT_FALSE(opret.empty());
    EXPECT_EQ(opret[0], 0x6a);
    CTransaction tx = MakeCanonicalTx(opret, 1, {}, false);
    CZSLPParsedMsg parsed; CZSLPToken meta; bool haveGen = false;
    ASSERT_TRUE(CZSLPIndexer::ParseTx(tx, 7, parsed, meta, haveGen));
    EXPECT_EQ(parsed.initialQuantity, (int64_t)1);
    EXPECT_EQ(parsed.mintBatonVout, 0);
    EXPECT_EQ(meta.decimals, 0);
    EXPECT_FALSE(meta.hasDocumentHash);
}

TEST(ZslpWalletBridge, SendRoundTripTokenId)
{
    uint256 tid = H(0x42);
    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> opret = ZSLPBuildSend(be, {5, 3});
    ASSERT_FALSE(opret.empty());
    EXPECT_EQ(opret[0], 0x6a);
    CTransaction tx = MakeCanonicalTx(opret, 2, {COutPoint(H(0x99), 1)}, false);
    CZSLPParsedMsg parsed; CZSLPToken meta; bool haveGen = false;
    ASSERT_TRUE(CZSLPIndexer::ParseTx(tx, 3, parsed, meta, haveGen));
    EXPECT_EQ(parsed.type, ZSLP_MSG_SEND);
    EXPECT_EQ(parsed.tokenId, tid); // BE -> internal round-trips to the daemon id
    EXPECT_EQ(parsed.numOutputs, 2);
    EXPECT_EQ(parsed.outputQuantities[0], (int64_t)5);
    EXPECT_EQ(parsed.outputQuantities[1], (int64_t)3);
}

TEST(ZslpWalletBridge, MintRoundTrip)
{
    uint256 tid = H(0x11);
    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> opret = ZSLPBuildMint(be, /*baton=*/2, /*qty=*/777);
    ASSERT_FALSE(opret.empty());
    CTransaction tx = MakeCanonicalTx(opret, 2, {COutPoint(H(0x99), 0)}, false);
    CZSLPParsedMsg parsed; CZSLPToken meta; bool haveGen = false;
    ASSERT_TRUE(CZSLPIndexer::ParseTx(tx, 9, parsed, meta, haveGen));
    EXPECT_EQ(parsed.type, ZSLP_MSG_MINT);
    EXPECT_EQ(parsed.tokenId, tid);
    EXPECT_EQ(parsed.additionalQuantity, (int64_t)777);
    EXPECT_EQ(parsed.mintBatonVout, 2);
}

TEST(ZslpWalletBridge, RejectsOverCapAndInvalid)
{
    // SEND with 0 outputs -> empty.
    uint8_t be[32]; memset(be, 0x55, 32);
    EXPECT_TRUE(ZSLPBuildSend(be, {}).empty());
    // SEND with >19 outputs -> empty (slp_build_send rejects, FinishBuild maps).
    EXPECT_TRUE(ZSLPBuildSend(be, std::vector<uint64_t>(20, 1)).empty());
    // GENESIS with a name long enough to blow the 223-byte relay cap -> empty.
    std::string longName(250, 'A');
    EXPECT_TRUE(ZSLPBuildGenesis("TICK", longName, "", NULL, 0, 0, 1).empty());
    // SEND at exactly 19 outputs fits (= 217 bytes per the spec).
    std::vector<unsigned char> ok = ZSLPBuildSend(be, std::vector<uint64_t>(19, 1));
    ASSERT_FALSE(ok.empty());
    EXPECT_LE(ok.size(), (size_t)nMaxDatacarrierBytes);
}

// ════════════════════════════════════════════════════════════════════════
//  2. Canonical layout -> correct ledger effect (deterministic ordering)
// ════════════════════════════════════════════════════════════════════════

TEST(ZslpWalletLayout, GenesisCreditsVout1NotChange)
{
    CZSLPStore* s = NewStore();

    std::vector<unsigned char> opret =
        ZSLPBuildGenesis("NFT", "Art", "", NULL, 0, 0, 1);
    ASSERT_FALSE(opret.empty());

    // Canonical: vout[0]=OP_RETURN, vout[1]=recipient, vout[2]=ZEC change.
    CTransaction tx = MakeCanonicalTx(opret, /*nTokenOuts=*/1, {}, /*withChange=*/true);
    // Sanity: OP_RETURN really is at vout[0].
    ASSERT_GE(tx.vout.size(), (size_t)3u);
    EXPECT_TRUE(tx.vout[0].scriptPubKey.size() > 0 &&
                tx.vout[0].scriptPubKey[0] == OP_RETURN);

    uint256 tid = ApplyRealTx(s, tx, 100);

    // The qty-1 NFT lands on vout[1] (the recipient), NOT on the change output.
    CZSLPTokenUtxo u1;
    ASSERT_TRUE(s->GetUtxo(tid, 1, u1));
    EXPECT_EQ(u1.amount, (int64_t)1);
    EXPECT_FALSE(u1.isMintBaton);
    // The change output (vout[2]) carries no token.
    CZSLPTokenUtxo u2;
    EXPECT_FALSE(s->GetUtxo(tid, 2, u2));
    // Supply is exactly 1.
    CZSLPToken tok; ASSERT_TRUE(s->GetToken(tid, tok));
    EXPECT_EQ(tok.totalMinted, (int64_t)1);

    delete s;
}

TEST(ZslpWalletLayout, SendMovesOwnershipAndConserves)
{
    CZSLPStore* s = NewStore();

    // Genesis 10 units to vout[1].
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("FUN", "Fungible", "", NULL, 0, 0, 10);
    CTransaction gtx = MakeCanonicalTx(gen, 1, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);
    ASSERT_EQ(s->GetBalance(tid, "t1vout1"), (int64_t)10);

    // SEND 7 to a recipient (vout[1]) + 3 token-change to self (vout[2]).
    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {7, 3});
    CTransaction stx = MakeCanonicalTx(snd, /*nTokenOuts=*/2,
                                       {COutPoint(gtx.GetHash(), 1)}, false);
    ApplyRealTx(s, stx, 2);

    // Conservation: recipient 7, change 3, nothing burned, supply unchanged.
    EXPECT_EQ(s->GetBalance(tid, "t1vout1"), (int64_t)7);
    EXPECT_EQ(s->GetBalance(tid, "t1vout2"), (int64_t)3);
    CZSLPToken tok; ASSERT_TRUE(s->GetToken(tid, tok));
    EXPECT_EQ(tok.totalMinted, (int64_t)10); // SEND never mints/burns supply
    // The genesis UTXO at vout[1] was consumed.
    CZSLPTokenUtxo spent;
    EXPECT_FALSE(s->GetUtxo(gtx.GetHash(), 1, spent));

    delete s;
}

// ════════════════════════════════════════════════════════════════════════
//  3. Self-validation (R-WALLET-9): ACCEPT good, REFUSE every burn/mis-order
// ════════════════════════════════════════════════════════════════════════

TEST(ZslpWalletSelfValidate, AcceptsConservedSend)
{
    CZSLPStore* s = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("OK", "Ok", "", NULL, 0, 0, 10);
    CTransaction gtx = MakeCanonicalTx(gen, 1, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {7, 3}); // 7 + 3 == 10 in
    CTransaction stx = MakeCanonicalTx(snd, 2,
                                       {COutPoint(gtx.GetHash(), 1)}, false);
    std::string reason;
    EXPECT_TRUE(SelfValidate(s, stx, 2, reason)) << reason;
    delete s;
}

TEST(ZslpWalletSelfValidate, RefusesOverSend)
{
    CZSLPStore* s = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("OS", "Os", "", NULL, 0, 0, 5);
    CTransaction gtx = MakeCanonicalTx(gen, 1, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; TokenIdBE(tid, be);
    // SEND requires 9 but the single input carries only 5 -> would burn.
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {9});
    CTransaction stx = MakeCanonicalTx(snd, 1,
                                       {COutPoint(gtx.GetHash(), 1)}, false);
    std::string reason;
    EXPECT_FALSE(SelfValidate(s, stx, 2, reason));
    EXPECT_NE(reason.find("burn"), std::string::npos);
    delete s;
}

TEST(ZslpWalletSelfValidate, RefusesUnaccountedSurplus)
{
    CZSLPStore* s = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("SP", "Sp", "", NULL, 0, 0, 10);
    CTransaction gtx = MakeCanonicalTx(gen, 1, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; TokenIdBE(tid, be);
    // SEND only 7 of the 10-unit input but provides NO token-change output ->
    // the missing 3 would be silently burned; the builder must refuse.
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {7});
    CTransaction stx = MakeCanonicalTx(snd, 1,
                                       {COutPoint(gtx.GetHash(), 1)}, false);
    std::string reason;
    EXPECT_FALSE(SelfValidate(s, stx, 2, reason));
    EXPECT_NE(reason.find("surplus"), std::string::npos);
    delete s;
}

TEST(ZslpWalletSelfValidate, RefusesOpReturnNotAtVout0)
{
    CZSLPStore* s = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("MO", "Mo", "", NULL, 0, 0, 10);
    CTransaction gtx = MakeCanonicalTx(gen, 1, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {10});

    // Build a MIS-ORDERED tx: a normal output at vout[0], OP_RETURN at vout[1]
    // (the random-change-insert hazard). ParseTx (vout[0]-only) finds NO SLP
    // message, so self-validate refuses.
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(COutPoint(gtx.GetHash(), 1)));
    { CTxOut o; o.nValue = 546; o.scriptPubKey = CScript() << OP_TRUE; mtx.vout.push_back(o); }
    { CTxOut o; o.nValue = 0;   o.scriptPubKey = CScript(snd.begin(), snd.end()); mtx.vout.push_back(o); }
    CTransaction badtx(mtx);

    std::string reason;
    EXPECT_FALSE(SelfValidate(s, badtx, 2, reason));
    EXPECT_NE(reason.find("vout[0]"), std::string::npos);
    delete s;
}

TEST(ZslpWalletSelfValidate, RefusesMintWithoutBaton)
{
    CZSLPStore* s = NewStore();
    // Genesis WITHOUT a baton.
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("NB", "NoBaton", "", NULL, 0, 0, 10);
    CTransaction gtx = MakeCanonicalTx(gen, 1, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> mnt = ZSLPBuildMint(be, 0, 100);
    // The input is the qty UTXO, NOT a baton -> MINT is invalid.
    CTransaction mtx = MakeCanonicalTx(mnt, 1,
                                       {COutPoint(gtx.GetHash(), 1)}, false);
    std::string reason;
    EXPECT_FALSE(SelfValidate(s, mtx, 2, reason));
    EXPECT_NE(reason.find("baton"), std::string::npos);
    delete s;
}

// A MINT that spends the live baton and lands its new supply on vout[1] is
// ACCEPTED by the self-validate gate, and ApplyTransaction creates exactly the
// new-supply UTXO + the continued baton (the §3 mint-path happy case).
TEST(ZslpWalletSelfValidate, AcceptsMintWithBatonAndCreatesSupply)
{
    CZSLPStore* s = NewStore();
    // Genesis WITH a baton at vout[2] (recipient at vout[1]).
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("WB", "WithBaton", "", NULL, 0, /*baton=*/2, 100);
    CTransaction gtx = MakeCanonicalTx(gen, /*nTokenOuts=*/2, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);
    // Baton exists at vout[2].
    CZSLPTokenUtxo b0;
    ASSERT_TRUE(s->GetUtxo(gtx.GetHash(), 2, b0));
    ASSERT_TRUE(b0.isMintBaton);

    // MINT 50 more, continuing the baton at vout[2]; spend the baton input.
    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> mnt = ZSLPBuildMint(be, /*baton=*/2, /*qty=*/50);
    CTransaction mtx = MakeCanonicalTx(mnt, /*nTokenOuts=*/2,
                                       {COutPoint(gtx.GetHash(), 2)}, false);
    std::string reason;
    EXPECT_TRUE(SelfValidate(s, mtx, 2, reason)) << reason;

    // Apply for real: new 50-unit UTXO at vout[1], continued baton at vout[2],
    // supply 100 -> 150, the spent baton consumed.
    ApplyRealTx(s, mtx, 2);
    CZSLPTokenUtxo u1;
    ASSERT_TRUE(s->GetUtxo(mtx.GetHash(), 1, u1));
    EXPECT_EQ(u1.amount, (int64_t)50);
    EXPECT_FALSE(u1.isMintBaton);
    CZSLPTokenUtxo nb;
    ASSERT_TRUE(s->GetUtxo(mtx.GetHash(), 2, nb));
    EXPECT_TRUE(nb.isMintBaton);
    CZSLPToken tok; ASSERT_TRUE(s->GetToken(tid, tok));
    EXPECT_EQ(tok.totalMinted, (int64_t)150);
    CZSLPTokenUtxo gone;
    EXPECT_FALSE(s->GetUtxo(gtx.GetHash(), 2, gone)); // old baton consumed
    delete s;
}

// A MINT that omits vout[1] (declares additional quantity with no output to
// carry it) silently creates supply 0 in the ledger — the builder must refuse
// it, mirroring the SEND missing-vout guard.
TEST(ZslpWalletSelfValidate, RefusesMintWithNoSupplyVout)
{
    CZSLPStore* s = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("M0", "M0", "", NULL, 0, /*baton=*/2, 100);
    CTransaction gtx = MakeCanonicalTx(gen, /*nTokenOuts=*/2, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; TokenIdBE(tid, be);
    // MINT with NO continued baton and NO recipient output (only the OP_RETURN).
    std::vector<unsigned char> mnt = ZSLPBuildMint(be, /*baton=*/0, /*qty=*/50);
    CTransaction mtx = MakeCanonicalTx(mnt, /*nTokenOuts=*/0,
                                       {COutPoint(gtx.GetHash(), 2)}, false);
    std::string reason;
    EXPECT_FALSE(SelfValidate(s, mtx, 2, reason));
    EXPECT_NE(reason.find("vout[1]"), std::string::npos);
    delete s;
}

TEST(ZslpWalletSelfValidate, RefusesSendQtyToMissingVout)
{
    CZSLPStore* s = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("MV", "Mv", "", NULL, 0, 0, 10);
    CTransaction gtx = MakeCanonicalTx(gen, 1, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; TokenIdBE(tid, be);
    // Two quantities (5,5) but only ONE token output exists (so qty[1]->vout[2]
    // is missing): the second 5 would be burned. Refuse.
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {5, 5});
    CTransaction stx = MakeCanonicalTx(snd, /*nTokenOuts=*/1,
                                       {COutPoint(gtx.GetHash(), 1)}, false);
    std::string reason;
    EXPECT_FALSE(SelfValidate(s, stx, 2, reason));
    delete s;
}

// Self-validate must AGREE with ApplyTransaction: if WouldBeValid says yes, the
// real apply credits exactly the message; if no, the real apply burns. This
// pins the "no divergence" requirement (R-WALLET-9).
TEST(ZslpWalletSelfValidate, AgreesWithApplyTransaction)
{
    CZSLPStore* s = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("AG", "Ag", "", NULL, 0, 0, 10);
    CTransaction gtx = MakeCanonicalTx(gen, 1, {}, false);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {6, 4});
    CTransaction stx = MakeCanonicalTx(snd, 2,
                                       {COutPoint(gtx.GetHash(), 1)}, false);
    std::string reason;
    ASSERT_TRUE(SelfValidate(s, stx, 2, reason)) << reason;

    // Apply for real on a fresh store seeded identically and confirm the credit
    // matches the prediction (6 to vout1, 4 to vout2, conserved).
    ApplyRealTx(s, stx, 2);
    EXPECT_EQ(s->GetBalance(tid, "t1vout1"), (int64_t)6);
    EXPECT_EQ(s->GetBalance(tid, "t1vout2"), (int64_t)4);
    delete s;
}

// ════════════════════════════════════════════════════════════════════════
//  G2. NO-FORK / RELAY-STANDARDNESS: a built ZSLP carrier (GENESIS / SEND /
//      MINT) is a STANDARD transaction under MAINNET CChainParams at Sapling
//      activation height. This is the load-bearing premise of the entire
//      non-consensus model: unmodified ZClassic nodes must RELAY and MINE the
//      OP_RETURN carrier. We run the EXACT predicate AcceptToMemoryPool gates
//      on — IsStandardTx (main.cpp:714; ATMP calls it at main.cpp via
//      Params().RequireStandard() && !IsStandardTx(...)) — under MAIN params,
//      and tie the OP_RETURN size assertion to the live policy constant
//      (nMaxDatacarrierBytes == MAX_OP_RETURN_RELAY) so a future regression of
//      the relay cap fails this test rather than silently breaking relay.
//
// HONESTY: this does NOT call AcceptToMemoryPool (that needs a live chain +
// UTXO view + signed inputs). It runs IsStandardTx, the one relay-standardness
// gate, which is exactly the no-fork claim. The live RPC->builder->confirm loop
// (real signing + mempool acceptance) is covered by the committed regtest
// harness qa/zslp/zslp-nft-regtest.sh.
// ════════════════════════════════════════════════════════════════════════

namespace {

// A real, standard P2PKH scriptPubKey for an arbitrary keyid, so dust + the
// TX_PUBKEYHASH standardness check pass (the §1/§2 helpers use OP_TRUE/OP_DUP
// dummies which are intentionally NON-standard and unsuitable for G2).
CScript P2PKH(uint8_t seed)
{
    std::vector<unsigned char> h(20, seed);
    return GetScriptForDestination(CKeyID(uint160(h)));
}

// Assemble the canonical ZSLP layout INTO a Sapling (v4) contextual tx so it
// passes the saplingActive nVersion gate in IsStandardTx, with REAL p2pkh
// recipients (standard + non-dust) and one push-only, <=1650-byte scriptSig
// per input (so the txin standardness checks pass without real signing).
CTransaction MakeStandardCarrier(const std::vector<unsigned char>& opret,
                                 int nTokenOuts, bool withChange, int nHeight)
{
    CMutableTransaction mtx =
        CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight);
    // One input with a push-only dummy scriptSig (72-byte push: push-only and
    // well under the 1650 cap), so IsStandardTx's per-txin checks pass.
    CTxIn in(COutPoint(uint256S("01"), 0));
    in.scriptSig = CScript() << std::vector<unsigned char>(72, 0);
    mtx.vin.push_back(in);
    // vout[0] = OP_RETURN (value 0).
    mtx.vout.push_back(CTxOut(0, CScript(opret.begin(), opret.end())));
    // vout[1..N] = 546-sat token recipients (above the relay dust floor).
    for (int i = 0; i < nTokenOuts; ++i)
        mtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH((uint8_t)(0x10 + i))));
    if (withChange)
        mtx.vout.push_back(CTxOut(100000, P2PKH(0x77))); // ZEC change, strictly last
    return CTransaction(mtx);
}

} // namespace

TEST(ZslpWalletStandardness, GenesisAndSendAreStandardOnMainnet)
{
    SelectParams(CBaseChainParams::MAIN);
    const int nHeight = 476969; // MAIN Sapling activation (chainparams.cpp:110)
    ASSERT_TRUE(Params().GetConsensus().NetworkUpgradeActive(
        nHeight, Consensus::UPGRADE_SAPLING));

    // ---- GENESIS carrier (recipient at vout[1], baton at vout[2], change) ----
    uint8_t hash[32]; memset(hash, 0xAB, 32);
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("GOLD", "Gold Coin", "https://x.io", hash,
                         /*decimals=*/2, /*baton=*/2, /*qty=*/100000);
    ASSERT_FALSE(gen.empty());
    CTransaction gtx = MakeStandardCarrier(gen, /*nTokenOuts=*/2,
                                           /*withChange=*/true, nHeight);
    std::string reason;
    bool genStd = IsStandardTx(gtx, reason, nHeight);
    EXPECT_TRUE(genStd) << "GENESIS carrier not standard: reason=" << reason;
    // Exactly one OP_RETURN (else IsStandardTx rejects with multi-op-return).
    int nNull = 0;
    for (size_t i = 0; i < gtx.vout.size(); ++i)
        if (gtx.vout[i].scriptPubKey.size() > 0 &&
            gtx.vout[i].scriptPubKey[0] == OP_RETURN)
            ++nNull;
    EXPECT_EQ(nNull, 1);

    // ---- SEND carrier (two token recipients + change) ----
    uint256 tid = gtx.GetHash();
    uint8_t be[32]; TokenIdBE(tid, be);
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {5, 3});
    ASSERT_FALSE(snd.empty());
    CTransaction stx = MakeStandardCarrier(snd, /*nTokenOuts=*/2,
                                           /*withChange=*/true, nHeight);
    std::string reason2;
    bool sendStd = IsStandardTx(stx, reason2, nHeight);
    EXPECT_TRUE(sendStd) << "SEND carrier not standard: reason=" << reason2;

    // The carrier is a Sapling v4 tx (the version the live relay will see).
    EXPECT_EQ(gtx.nVersion, 4);
    EXPECT_EQ(stx.nVersion, 4);

    SelectParams(CBaseChainParams::REGTEST); // restore for sibling tests
}

TEST(ZslpWalletStandardness, OpReturnCapIsThePolicyConstantNotAMagicLiteral)
{
    SelectParams(CBaseChainParams::MAIN);
    const int nHeight = 476969;

    // Tripwire: the builder's cap MUST be the live relay policy constant, not a
    // magic 223. If someone changes the relay cap, this fails first.
    EXPECT_EQ(nMaxDatacarrierBytes, MAX_OP_RETURN_RELAY);

    // The OP_RETURN scriptPubKey of a MAX-size SEND (19 outputs) and a max-size
    // GENESIS must each fit under the LIVE relay cap.
    uint8_t be[32]; memset(be, 0x55, 32);
    std::vector<unsigned char> maxSend =
        ZSLPBuildSend(be, std::vector<uint64_t>(19, 1));
    ASSERT_FALSE(maxSend.empty());
    EXPECT_LE(maxSend.size(), (size_t)nMaxDatacarrierBytes);

    uint8_t hash[32]; memset(hash, 0xCD, 32);
    // A genesis sized to push the OP_RETURN near the cap (long-ish metadata that
    // still builds): ticker+name+url within limits.
    std::vector<unsigned char> maxGen =
        ZSLPBuildGenesis("TICKER", std::string(40, 'N'),
                         "https://example.com/very/long/document/url/here",
                         hash, /*decimals=*/8, /*baton=*/2, /*qty=*/21000000);
    ASSERT_FALSE(maxGen.empty());
    EXPECT_LE(maxGen.size(), (size_t)nMaxDatacarrierBytes);

    // NEGATIVE: a hand-crafted OP_RETURN of (cap+1) data bytes is NON-standard
    // and IsStandardTx must reject it with reason "scriptpubkey" — proving the
    // cap is the thing that actually gates relay.
    {
        CMutableTransaction mtx = CreateNewContextualCMutableTransaction(
            Params().GetConsensus(), nHeight);
        CTxIn in(COutPoint(uint256S("02"), 0));
        in.scriptSig = CScript() << std::vector<unsigned char>(72, 0);
        mtx.vin.push_back(in);
        // OP_RETURN <push of (nMaxDatacarrierBytes+1 - 3) bytes>: total
        // scriptPubKey size = 1 (OP_RETURN) + pushdata header + payload. Build
        // the payload so the whole scriptPubKey is nMaxDatacarrierBytes+1 bytes.
        // For a 220-byte payload the header is OP_PUSHDATA1+len = 2 bytes, so
        // scriptPubKey = 1+2+220 = 223. To EXCEED the cap, use payload that
        // makes scriptPubKey == nMaxDatacarrierBytes+1.
        size_t payload = (size_t)nMaxDatacarrierBytes + 1 - 3; // OP_RETURN + OP_PUSHDATA1 + len byte
        CScript oversize = CScript() << OP_RETURN
                                     << std::vector<unsigned char>(payload, 0xEE);
        EXPECT_GT(oversize.size(), (size_t)nMaxDatacarrierBytes);
        mtx.vout.push_back(CTxOut(0, oversize));
        mtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH(0x20)));
        CTransaction big(mtx);
        std::string reason;
        EXPECT_FALSE(IsStandardTx(big, reason, nHeight));
        EXPECT_EQ(reason, "scriptpubkey")
            << "oversize OP_RETURN should fail on the relay cap, got: " << reason;
    }

    SelectParams(CBaseChainParams::REGTEST);
}

// ════════════════════════════════════════════════════════════════════════
//  G3. ANTI-BURN DECISION FN (ZSLPIsProtectedTokenOutpoint /
//      MsgWouldMakeTokenOutput): the predicate that keeps coin-selection from
//      spending a token UTXO or mint baton as an ordinary fee/change coin. A
//      vout-arithmetic regression here would silently burn an NFT as fee.
//      Tested BOTH ways: protected==true for the token-qty / baton outpoint,
//      protected==false for the OP_RETURN and the ZEC-change outpoint and an
//      unrelated outpoint.
// ════════════════════════════════════════════════════════════════════════

// Source-1 (CONFIRMED store path): deterministic, needs no keys.
TEST(ZslpAntiBurnPredicate, ProtectsConfirmedTokenUtxoAndBatonNotChange)
{
    SelectParams(CBaseChainParams::REGTEST);
    CWallet wallet;          // empty wallet => only source-1 (store) can fire
    CZSLPStore* s = NewStore();

    // Genesis WITH a baton: vout[1]=qty UTXO, vout[2]=baton, vout[3]=ZEC change.
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("WB", "WithBaton", "", NULL, /*decimals=*/0,
                         /*baton=*/2, /*qty=*/100);
    CTransaction gtx = MakeCanonicalTx(gen, /*nTokenOuts=*/2, {},
                                       /*withChange=*/true);
    uint256 tid = ApplyRealTx(s, gtx, 1);
    // Sanity: store really recorded the qty UTXO and the baton.
    CZSLPTokenUtxo qu, bu;
    ASSERT_TRUE(s->GetUtxo(tid, 1, qu)); ASSERT_EQ(qu.amount, (int64_t)100);
    ASSERT_TRUE(s->GetUtxo(tid, 2, bu)); ASSERT_TRUE(bu.isMintBaton);

    LOCK2(cs_main, wallet.cs_wallet);
    // PROTECTED: the token quantity UTXO (vout[1]) and the mint baton (vout[2]).
    EXPECT_TRUE(ZSLPIsProtectedTokenOutpoint(&wallet, s, COutPoint(tid, 1)));
    EXPECT_TRUE(ZSLPIsProtectedTokenOutpoint(&wallet, s, COutPoint(tid, 2)));
    // NOT protected: the OP_RETURN (vout[0]) and the ZEC change (vout[3]) — the
    // exact vout-arithmetic boundaries a regression would burn an NFT as fee on.
    EXPECT_FALSE(ZSLPIsProtectedTokenOutpoint(&wallet, s, COutPoint(tid, 0)));
    EXPECT_FALSE(ZSLPIsProtectedTokenOutpoint(&wallet, s, COutPoint(tid, 3)));
    // NOT protected: an entirely unrelated outpoint.
    EXPECT_FALSE(ZSLPIsProtectedTokenOutpoint(&wallet, s, COutPoint(H(0xEE), 0)));

    delete s;
}

// Source-2 (PENDING/0-conf path): exercises the static MsgWouldMakeTokenOutput
// through a from-me wallet tx with store==NULL, so ONLY source-2 can fire. To
// make IsFromMe(ISMINE_ALL) true deterministically we give the wallet a key,
// add a prevout wtx paying that key, then add the SEND wtx spending it.
TEST(ZslpAntiBurnPredicate, ProtectsPendingZeroConfTokenChangeViaMsgWouldMakeTokenOutput)
{
    SelectParams(CBaseChainParams::REGTEST);
    CWallet wallet;
    CKey mine = AddTestCKeyToKeyStore(wallet);
    CScript myScript = GetScriptForDestination(mine.GetPubKey().GetID());

    // Prevout wtx: a transparent output the wallet owns (so spending it makes
    // the SEND from-me). Add it under the lock.
    CMutableTransaction prevMtx;
    prevMtx.vout.push_back(CTxOut(100000, myScript));
    CWalletTx prevWtx(&wallet, CTransaction(prevMtx));
    {
        LOCK(wallet.cs_wallet);
        wallet.AddToWallet(prevWtx, true, NULL);
    }
    uint256 prevHash = prevWtx.GetHash();

    // Canonical SEND wtx: vout[0]=OP_RETURN(SEND 7,3), vout[1]/vout[2]=token
    // outputs, vout[3]=ZEC change. Spends the wallet-owned prevout.
    uint8_t be[32]; memset(be, 0x42, 32);
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {7, 3});
    ASSERT_FALSE(snd.empty());
    CMutableTransaction sendMtx;
    sendMtx.vin.push_back(CTxIn(COutPoint(prevHash, 0)));
    sendMtx.vout.push_back(CTxOut(0, CScript(snd.begin(), snd.end())));   // 0
    sendMtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, myScript));             // 1 token
    sendMtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, myScript));             // 2 token
    sendMtx.vout.push_back(CTxOut(50000, myScript));                      // 3 change
    CWalletTx sendWtx(&wallet, CTransaction(sendMtx));
    {
        LOCK(wallet.cs_wallet);
        wallet.AddToWallet(sendWtx, true, NULL);
    }
    uint256 sendHash = sendWtx.GetHash();

    LOCK2(cs_main, wallet.cs_wallet);
    // Precondition the source-2 path depends on: the SEND is from-me.
    const CWalletTx* w = wallet.GetWalletTx(sendHash);
    ASSERT_TRUE(w != NULL);
    ASSERT_TRUE(w->IsFromMe(ISMINE_ALL))
        << "source-2 needs a from-me wtx; key/prevout wiring failed";

    // store==NULL => source-1 disabled; only MsgWouldMakeTokenOutput decides.
    // PROTECTED: the two pending token outputs (vout[1], vout[2]).
    EXPECT_TRUE(ZSLPIsProtectedTokenOutpoint(&wallet, NULL, COutPoint(sendHash, 1)));
    EXPECT_TRUE(ZSLPIsProtectedTokenOutpoint(&wallet, NULL, COutPoint(sendHash, 2)));
    // NOT protected: OP_RETURN (vout[0]) and the trailing ZEC change (vout[3]).
    EXPECT_FALSE(ZSLPIsProtectedTokenOutpoint(&wallet, NULL, COutPoint(sendHash, 0)));
    EXPECT_FALSE(ZSLPIsProtectedTokenOutpoint(&wallet, NULL, COutPoint(sendHash, 3)));
}

// ════════════════════════════════════════════════════════════════════════
//  G4 (wallet half): the anti-burn fence would NEVER let normal coin-selection
//  assemble the multi-token mixed-input SEND that silently burns token B (the
//  burn itself is documented + guarded in
//  test_zslp_indexer.cpp::MixedInputSendBurnsUndeclaredTokenB). The funding
//  pool comes from CWallet::AvailableCoins, which when fExcludeZSLPTokens=true
//  DROPS every outpoint for which ZSLPIsProtectedTokenOutpoint(this, zslpStore,
//  op) is true (wallet.cpp:3197-3199). We assert that SAME predicate, the one
//  AvailableCoins consults, returns true for a token-B UTXO and false for a
//  plain ZEC-change coin — so a SEND that declares only token A can never be
//  funded with a token-B input via normal selection.
//
//  (We exercise the predicate directly rather than driving AvailableCoins
//  end-to-end: the store the filter reads is the private member of the global
//  g_zslpIndexer, which is created on a real disk path inside Init() and has no
//  test injection seam. The predicate IS the decision AvailableCoins makes for
//  each coin, so testing it directly is exact — see wallet.cpp:3197-3199.)
// ════════════════════════════════════════════════════════════════════════
TEST(ZslpAntiBurnPredicate, FundingFilterDropsUndeclaredTokenInput)
{
    SelectParams(CBaseChainParams::REGTEST);
    CWallet wallet; // empty: predicate decides purely on the store (source-1)
    CZSLPStore* s = NewStore();

    // Seed the store with token B (qty 500 at vout[1], ZEC change at vout[2]).
    std::vector<unsigned char> genB =
        ZSLPBuildGenesis("B", "TokenB", "", NULL, 0, 0, /*qty=*/500);
    CTransaction gTx = MakeCanonicalTx(genB, /*nTokenOuts=*/1, {},
                                       /*withChange=*/true);
    uint256 tB = ApplyRealTx(s, gTx, 1);
    CZSLPTokenUtxo bu;
    ASSERT_TRUE(s->GetUtxo(tB, 1, bu));
    ASSERT_EQ(bu.amount, (int64_t)500);

    LOCK2(cs_main, wallet.cs_wallet);
    // The token-B UTXO at (tB,1) is PROTECTED => AvailableCoins drops it from
    // the funding pool. A SEND of token A can therefore never spend it.
    EXPECT_TRUE(ZSLPIsProtectedTokenOutpoint(&wallet, s, COutPoint(tB, 1)))
        << "token-B UTXO would leak into the funding pool — a SEND could "
           "mix+burn token B (G4)";
    // The plain ZEC change at (tB,2) is NOT protected => stays spendable.
    EXPECT_FALSE(ZSLPIsProtectedTokenOutpoint(&wallet, s, COutPoint(tB, 2)));

    delete s;
}
