// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Unit tests for the NFT SELL pillar's load-bearing, wallet-independent pieces
// (mechanism A', doc/nft/NFT_SELL_DESIGN.md). The full RPC path (live CWallet,
// keypool, mempool, blob store) is exercised by the committed regtest harness
// qa/zslp/nft-sell-regtest.sh. What IS unit-tested here is every PURE decision
// the offer builder/verifier delegates:
//
//   1. THE TEMPLATE: vout[0] is the EXISTING ZSLP SEND encoder ZSLPBuildSend(BE,
//      {1}); vout[1] is the buyer's dust at the fee-rate-derived floor; vout[2]
//      is the seller payout. The REAL parse seam (CZSLPIndexer::ParseTx) reads
//      vout[0] as a SEND for tokenId crediting vout[1], and the REAL read-only
//      conservation gate (CZSLPStore::WouldBeValid) ACCEPTS the swap (availIn=1,
//      requiredOut=1) and REJECTS a recipient-redirect/over-map.
//
//   2. SIGHASH ALL|ANYONECANPAY: the seller signs ONLY vin[0] over the COMPLETE
//      3-output set. We sign with real keys, then prove (a) the signature
//      VERIFIES against the unmodified template, (b) editing vout[2] price or
//      vout[1] recipient BREAKS VerifyScript (the seller's commitment is
//      un-editable), and (c) APPENDING a buyer funding input (vin[1]) does NOT
//      break vin[0] (ANYONECANPAY zeroes the prevouts hash).
//
//   3. IsStandardTx: the assembled swap tx is RELAY-STANDARD on MAINNET at
//      Sapling height — the no-fork premise (unmodified nodes relay+mine it).
//
// HONESTY: the offer-blob (de)serializer and the nft_verifyoffer field-mismatch
// reasons live in rpc/nftoffer.cpp behind ENABLE_WALLET and need a live wallet
// to drive end-to-end; they are covered by the regtest harness, not here.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "coins.h"
#include "consensus/upgrades.h"
#include "core_io.h"
#include "key.h"
#include "key_io.h"
#include "keystore.h"
#include "main.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"
#include "uint256.h"
#include "wallet/zslpwallet.h"
#include "zslp/zslpindexer.h"
#include "zslp/zslpmsg.h"
#include "zslp/zslpstore.h"

#ifdef ENABLE_WALLET
#include "rpc/nftoffer.h"   // CNftOfferBlob / NftVerifyResult / NftVerify (E-1)
#endif

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

CZSLPStore* NewStore()
{
    return new CZSLPStore("nft-offer-test", 1 << 20, /*fMemory=*/true,
                          /*fWipe=*/true);
}

std::function<std::string(int32_t)> AddrLabels()
{
    return [](int32_t n) -> std::string {
        if (n <= 0) return std::string();
        return std::string("t1vout") + std::to_string(n);
    };
}

// Drive a tx through the EXACT production indexer path (parse + apply).
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

// The self-validate gate, exactly as nft_makeoffer/nft_takeoffer call it.
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

// Assemble the EXACT 3-output sell template nft_makeoffer builds: vout[0] =
// ZSLPBuildSend(BE,{1}), vout[1] = buyer NFT dust, vout[2] = seller payout. The
// NFT outpoint is vin[0]; `fundingOps` are appended as vin[1..].
CMutableTransaction MakeSellTemplate(const uint256& tokenId,
                                     const COutPoint& nftOutpoint,
                                     const CScript& buyerScript, CAmount dust,
                                     const CScript& payoutScript, CAmount price,
                                     const std::vector<COutPoint>& fundingOps)
{
    uint8_t be[32]; ZSLPTokenIdToBE(tokenId, be);
    std::vector<unsigned char> opret = ZSLPBuildSend(be, {1});

    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = 4;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.vin.push_back(CTxIn(nftOutpoint));
    for (size_t i = 0; i < fundingOps.size(); ++i)
        mtx.vin.push_back(CTxIn(fundingOps[i]));
    mtx.vout.push_back(CTxOut(0, CScript(opret.begin(), opret.end()))); // vout[0]
    mtx.vout.push_back(CTxOut(dust, buyerScript));                       // vout[1]
    mtx.vout.push_back(CTxOut(price, payoutScript));                     // vout[2]
    return mtx;
}

CScript P2PKH(uint8_t seed)
{
    std::vector<unsigned char> h(20, seed);
    return GetScriptForDestination(CKeyID(uint160(h)));
}

} // namespace

// ════════════════════════════════════════════════════════════════════════
//  1. TEMPLATE -> correct ledger effect (vout[0]=SEND encoder, credits vout[1])
// ════════════════════════════════════════════════════════════════════════

TEST(NftOfferTemplate, Vout0IsSendEncoderCreditingVout1)
{
    CZSLPStore* s = NewStore();

    // Genesis an NFT (qty 1) to vout[1].
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("", "Art #1", "", NULL, /*dec=*/0, /*baton=*/0, /*qty=*/1);
    ASSERT_FALSE(gen.empty());
    CMutableTransaction gmtx;
    gmtx.vout.push_back(CTxOut(0, CScript(gen.begin(), gen.end())));
    gmtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH(0x01)));
    CTransaction gtx(gmtx);
    uint256 tid = ApplyRealTx(s, gtx, 1);
    CZSLPTokenUtxo nftRec;
    ASSERT_TRUE(s->GetUtxo(tid, 1, nftRec));
    ASSERT_EQ(nftRec.amount, (int64_t)1);

    // Build the sell template spending the NFT (gtx:1).
    CScript buyer = P2PKH(0xBB), payout = P2PKH(0xAA);
    CMutableTransaction swap = MakeSellTemplate(
        tid, COutPoint(gtx.GetHash(), 1), buyer, SLP_TOKEN_DUST, payout,
        /*price=*/100000000, /*fundingOps=*/{COutPoint(H(0x77), 0)});
    CTransaction swapTx(swap);

    // vout[0] parses as a SEND for tid crediting vout[1] with qty 1.
    CZSLPParsedMsg parsed; CZSLPToken meta; bool haveGen = false;
    ASSERT_TRUE(CZSLPIndexer::ParseTx(swapTx, 2, parsed, meta, haveGen));
    EXPECT_EQ(parsed.type, ZSLP_MSG_SEND);
    EXPECT_EQ(parsed.tokenId, tid);
    EXPECT_EQ(parsed.numOutputs, 1);
    EXPECT_EQ(parsed.outputQuantities[0], (int64_t)1);

    // Conservation gate ACCEPTS (availIn=1 from vin[0]=NFT, requiredOut=1).
    std::string why;
    EXPECT_TRUE(SelfValidate(s, swapTx, 2, why)) << why;

    // Applying it for real moves the NFT to vout[1] (the buyer) and conserves.
    ApplyRealTx(s, swapTx, 2);
    CZSLPTokenUtxo moved;
    ASSERT_TRUE(s->GetUtxo(swapTx.GetHash(), 1, moved));
    EXPECT_EQ(moved.amount, (int64_t)1);
    EXPECT_EQ(moved.address, std::string("t1vout1")); // the buyer's vout[1]
    // The seller's old NFT UTXO is consumed (no double-ownership).
    CZSLPTokenUtxo spent;
    EXPECT_FALSE(s->GetUtxo(gtx.GetHash(), 1, spent));
    // The payout output (vout[2]) carries no token.
    CZSLPTokenUtxo none;
    EXPECT_FALSE(s->GetUtxo(swapTx.GetHash(), 2, none));

    delete s;
}

TEST(NftOfferTemplate, ConservationRejectsRedirectedSecondCredit)
{
    // A SEND that names TWO credits ({1,1}) but the NFT input only carries 1
    // unit must be REJECTED by WouldBeValid (the buyer must never be promised a
    // credit the input can't cover). This pins the verifyoffer conservation arm.
    CZSLPStore* s = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("", "Art", "", NULL, 0, 0, /*qty=*/1);
    CMutableTransaction gmtx;
    gmtx.vout.push_back(CTxOut(0, CScript(gen.begin(), gen.end())));
    gmtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH(0x01)));
    CTransaction gtx(gmtx);
    uint256 tid = ApplyRealTx(s, gtx, 1);

    uint8_t be[32]; ZSLPTokenIdToBE(tid, be);
    std::vector<unsigned char> opret = ZSLPBuildSend(be, {1, 1}); // over-credit
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(COutPoint(gtx.GetHash(), 1)));
    mtx.vout.push_back(CTxOut(0, CScript(opret.begin(), opret.end())));
    mtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH(0xBB)));
    mtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH(0xCC)));
    CTransaction tx(mtx);
    std::string why;
    EXPECT_FALSE(SelfValidate(s, tx, 2, why)); // availIn 1 < requiredOut 2
    delete s;
}

// ════════════════════════════════════════════════════════════════════════
//  2. SIGHASH ALL|ANYONECANPAY: seller pins ALL outputs, only inputs are open
// ════════════════════════════════════════════════════════════════════════

namespace {
// Sign vin[0] of `mtx` over scriptPubKey `spk`/`amount` with sighash `sht`.
bool SignVin0(const CKeyStore& ks, CMutableTransaction& mtx, const CScript& spk,
              CAmount amount, int sht, uint32_t branchId)
{
    return SignSignature(ks, spk, mtx, 0, amount, SigHashType(sht), branchId);
}

// Verify vin[i] of `tx` against `spk`/`amount`.
bool CheckVin(const CTransaction& tx, unsigned i, const CScript& spk,
              CAmount amount, uint32_t branchId)
{
    ScriptError serr = SCRIPT_ERR_OK;
    return VerifyScript(tx.vin[i].scriptSig, spk, STANDARD_SCRIPT_VERIFY_FLAGS,
                        TransactionSignatureChecker(&tx, i, amount), branchId,
                        &serr);
}
} // namespace

TEST(NftOfferSighash, AllAnyonecanpayPinsOutputsButOpensInputs)
{
    SelectParams(CBaseChainParams::REGTEST);
    uint32_t branchId = NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId;

    // Seller key + the NFT-bearing P2PKH the offer spends at vin[0].
    CBasicKeyStore keystore;
    CKey sellerKey; sellerKey.MakeNewKey(true);
    keystore.AddKeyPubKey(sellerKey, sellerKey.GetPubKey());
    CScript nftSpk = GetScriptForDestination(sellerKey.GetPubKey().GetID());
    const CAmount nftValue = SLP_TOKEN_DUST;

    uint256 tid = H(0x42);
    CScript buyer = P2PKH(0xBB), payout = P2PKH(0xAA);
    const CAmount price = 250000000;

    // --- (a) seller signs ONLY vin[0] over the complete 3-output set ---
    CMutableTransaction offer = MakeSellTemplate(
        tid, COutPoint(H(0x10), 0), buyer, SLP_TOKEN_DUST, payout, price, {});
    ASSERT_TRUE(SignVin0(keystore, offer, nftSpk, nftValue,
                         SIGHASH_ALL | SIGHASH_ANYONECANPAY, branchId));
    EXPECT_TRUE(CheckVin(CTransaction(offer), 0, nftSpk, nftValue, branchId))
        << "seller's ALL|ANYONECANPAY signature must verify on the template";

    // --- (b) BUYER APPENDS a funding input (vin[1]) -> vin[0] still verifies ---
    // ANYONECANPAY zeroes hashPrevouts/hashSequence, so adding inputs does not
    // invalidate the seller's signature. (No output edit -> hashOutputs intact.)
    CMutableTransaction filled = offer; // keep the seller's signed scriptSig
    filled.vin.push_back(CTxIn(COutPoint(H(0x99), 3))); // buyer funding input
    EXPECT_TRUE(CheckVin(CTransaction(filled), 0, nftSpk, nftValue, branchId))
        << "appending a buyer funding input must NOT break the seller's vin[0]";

    // --- (c) TAMPER vout[2] price DOWN -> vin[0] VerifyScript FAILS ---
    {
        CMutableTransaction tampered = offer;
        tampered.vout[2].nValue = price - 1; // shave a satoshi off the payout
        EXPECT_FALSE(CheckVin(CTransaction(tampered), 0, nftSpk, nftValue, branchId))
            << "lowering the payout must break the seller's ALL signature";
    }

    // --- (d) TAMPER vout[1] recipient -> vin[0] VerifyScript FAILS ---
    {
        CMutableTransaction tampered = offer;
        tampered.vout[1].scriptPubKey = P2PKH(0xEE); // redirect the NFT
        EXPECT_FALSE(CheckVin(CTransaction(tampered), 0, nftSpk, nftValue, branchId))
            << "redirecting the NFT recipient must break the seller's ALL signature";
    }

    SelectParams(CBaseChainParams::REGTEST);
}

// SINGLE|ANYONECANPAY would NOT pin the payout (it commits vin[0] only to
// vout[0]=OP_RETURN), proving the design's §0 rejection: only ALL fits ZSLP.
TEST(NftOfferSighash, SingleWouldFailToPinThePayout)
{
    SelectParams(CBaseChainParams::REGTEST);
    uint32_t branchId = NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId;

    CBasicKeyStore keystore;
    CKey k; k.MakeNewKey(true);
    keystore.AddKeyPubKey(k, k.GetPubKey());
    CScript nftSpk = GetScriptForDestination(k.GetPubKey().GetID());
    const CAmount nftValue = SLP_TOKEN_DUST;

    CMutableTransaction offer = MakeSellTemplate(
        H(0x42), COutPoint(H(0x10), 0), P2PKH(0xBB), SLP_TOKEN_DUST,
        P2PKH(0xAA), 250000000, {});
    ASSERT_TRUE(SignVin0(keystore, offer, nftSpk, nftValue,
                         SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, branchId));
    // Under SINGLE, vin[0] is committed only to vout[0] (the OP_RETURN), so
    // editing the payout vout[2] does NOT break the signature — exactly why
    // SINGLE is unusable for this template (the payout is unpinned). ALL is
    // required (test above). Demonstrate the gap:
    CMutableTransaction tampered = offer;
    tampered.vout[2].nValue = 1; // gut the payout
    EXPECT_TRUE(CheckVin(CTransaction(tampered), 0, nftSpk, nftValue, branchId))
        << "SINGLE leaves the payout editable — the §0 reason ALL is mandatory";

    SelectParams(CBaseChainParams::REGTEST);
}

// ════════════════════════════════════════════════════════════════════════
//  3. IsStandardTx: the swap tx is RELAY-STANDARD on MAINNET (no-fork premise)
// ════════════════════════════════════════════════════════════════════════

TEST(NftOfferStandardness, SwapTxIsStandardOnMainnet)
{
    SelectParams(CBaseChainParams::MAIN);
    const int nHeight = 476969; // MAIN Sapling activation
    ASSERT_TRUE(Params().GetConsensus().NetworkUpgradeActive(
        nHeight, Consensus::UPGRADE_SAPLING));

    uint256 tid = H(0x42);
    // Two real P2PKH outputs (buyer dust + payout); one funding input. Use a
    // push-only 72-byte dummy scriptSig per input so the per-txin standardness
    // checks pass without real signing (mirrors test_zslp_wallet's G2 helper).
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(
        Params().GetConsensus(), nHeight);
    uint8_t be[32]; ZSLPTokenIdToBE(tid, be);
    std::vector<unsigned char> opret = ZSLPBuildSend(be, {1});
    ASSERT_FALSE(opret.empty());

    CTxIn nftIn(COutPoint(uint256S("01"), 1));
    nftIn.scriptSig = CScript() << std::vector<unsigned char>(72, 0);
    mtx.vin.push_back(nftIn);
    CTxIn fundIn(COutPoint(uint256S("02"), 0));
    fundIn.scriptSig = CScript() << std::vector<unsigned char>(72, 0);
    mtx.vin.push_back(fundIn);

    mtx.vout.push_back(CTxOut(0, CScript(opret.begin(), opret.end())));   // vout[0]
    mtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH(0xBB)));              // vout[1]
    mtx.vout.push_back(CTxOut(100000000, P2PKH(0xAA)));                  // vout[2]
    CTransaction swap(mtx);

    std::string reason;
    EXPECT_TRUE(IsStandardTx(swap, reason, nHeight))
        << "swap carrier not standard: reason=" << reason;
    EXPECT_EQ(swap.nVersion, 4);

    // Exactly one OP_RETURN (else IsStandardTx rejects multi-op-return).
    int nNull = 0;
    for (size_t i = 0; i < swap.vout.size(); ++i)
        if (swap.vout[i].scriptPubKey.size() > 0 &&
            swap.vout[i].scriptPubKey[0] == OP_RETURN)
            ++nNull;
    EXPECT_EQ(nNull, 1);

    SelectParams(CBaseChainParams::REGTEST); // restore for sibling tests
}

// The fee-rate-derived dust floor for vout[1] is never below the 546 SLP
// convention (so older relays that assume that floor still accept the offer).
TEST(NftOfferTemplate, DustFloorNeverBelow546)
{
    CScript p = P2PKH(0xBB);
    CTxOut probe(0, p);
    CAmount floor = probe.GetDustThreshold(::minRelayTxFee);
    CAmount D = std::max((CAmount)SLP_TOKEN_DUST, floor);
    EXPECT_GE(D, (CAmount)SLP_TOKEN_DUST);
}

#ifdef ENABLE_WALLET
// ════════════════════════════════════════════════════════════════════════
//  4. THE REAL nft_verifyoffer CORE (E-1): drive the now-exposed NftVerify
//     instead of hand-rolling the checks. NftVerify reads the live UTXO set
//     (pcoinsTip) + chainActive + a ZSLP store under cs_main, so we install a
//     synthetic coins view holding the NFT prevout, a fake tip, and a store
//     seeded with the qty-1 NFT, then assemble + SIGN the exact 3-output
//     ALL|ANYONECANPAY template (MakeSellTemplate, which already uses the REAL
//     ZSLPBuildSend encoder) and assert the verifier's real verdict.
//
//  COVERED here (unit-reachable): the decode, output-shape, vout[0] SEND parse +
//  token-id match, vout[1]/vout[2] address+price re-derivation, the LIVE-UTXO +
//  cryptographic ALL|ANYONECANPAY backstop on vin[0], the expiry-bound check,
//  and the WouldBeValid conservation arm — i.e. the entire nft_verifyoffer
//  safety core, exercised through the REAL function (no hand-rolled copy).
//
//  NOT reachable as a unit (covered by qa/zslp/nft-sell-regtest.sh, noted in
//  coverageHonesty): nft_makeoffer's wallet-side template ASSEMBLY (keypool /
//  ZSLPFindWalletTokenUtxos), nft_takeoffer's overshoot-ack gate + fundingInputs
//  selection (both need a live CWallet/keystore + EnsureWalletIsUnlocked), and
//  the offer-blob (de)serializer over a live store. The fundingInputs anti-burn
//  PREDICATE (ZSLPIsProtectedTokenOutpoint) is already unit-gated in
//  test_zslp_wallet.cpp (ZslpAntiBurnPredicate.*), so it is not duplicated here.
// ════════════════════════════════════════════════════════════════════════

namespace {

// Minimal empty coins backing store; the cache layered above holds our coin.
class NftFakeCoinsView : public CCoinsView {
public:
    bool GetSproutAnchorAt(const uint256&, SproutMerkleTree&) const { return false; }
    bool GetSaplingAnchorAt(const uint256&, SaplingMerkleTree&) const { return false; }
    bool GetNullifier(const uint256&, ShieldedType) const { return false; }
    bool GetCoins(const uint256&, CCoins&) const { return false; }
    bool HaveCoins(const uint256&) const { return false; }
    uint256 GetBestBlock() const { return uint256(); }
    uint256 GetBestAnchor(ShieldedType) const { return uint256(); }
    bool BatchWrite(CCoinsMap&, const uint256&, const uint256&, const uint256&,
                    CAnchorsSproutMap&, CAnchorsSaplingMap&, CNullifiersMap&,
                    CNullifiersMap) { return false; }
    bool GetStats(CCoinsStats&) const { return false; }
};

// RAII: install pcoinsTip = &cache and a synthetic max-work tip for the test;
// restore both on teardown so sibling tests see a clean global state.
class NftChainStateGuard {
public:
    NftChainStateGuard(CCoinsViewCache* cache, int height) {
        savedTip_ = pcoinsTip;
        pcoinsTip = cache;
        fakeTip_.nChainWork = ~arith_uint256(0);
        fakeTip_.nTime = GetTime();
        fakeTip_.nHeight = height;
        chainActive.SetTip(&fakeTip_);
    }
    ~NftChainStateGuard() {
        chainActive.SetTip(NULL);
        pcoinsTip = savedTip_;
    }
private:
    CCoinsViewCache* savedTip_;
    CBlockIndex fakeTip_;
};

// Seed one spendable coin (the NFT dust UTXO) at outpoint `op` into `cache`.
void SeedCoin(CCoinsViewCache& cache, const COutPoint& op, const CScript& spk,
              CAmount value, int height) {
    CCoinsModifier c = cache.ModifyCoins(op.hash);
    c->fCoinBase = false;
    c->nHeight = height;
    c->nVersion = 1;
    if ((size_t)op.n >= c->vout.size())
        c->vout.resize(op.n + 1);
    c->vout[op.n] = CTxOut(value, spk);
}

// Build the seller-signed offer blob exactly as nft_makeoffer ships it:
// the 3-output template, vin[0] signed ALL|ANYONECANPAY, serialized to offerHex.
CNftOfferBlob MakeSignedOffer(const CKeyStore& ks, const CScript& nftSpk,
                              CAmount nftValue, uint32_t branchId,
                              const uint256& tokenId,
                              const COutPoint& nftOp,
                              const std::string& buyerAddr,
                              const std::string& payoutAddr, CAmount price,
                              uint32_t expiryHeight) {
    CScript buyerScript = ZSLPScriptForTAddr(buyerAddr);
    CScript payoutScript = ZSLPScriptForTAddr(payoutAddr);
    CMutableTransaction mtx = MakeSellTemplate(
        tokenId, nftOp, buyerScript, SLP_TOKEN_DUST, payoutScript, price, {});
    mtx.nExpiryHeight = expiryHeight;
    EXPECT_TRUE(SignSignature(ks, nftSpk, mtx, 0, nftValue,
                              SigHashType(SIGHASH_ALL | SIGHASH_ANYONECANPAY),
                              branchId));
    CNftOfferBlob blob;
    blob.tokenId = tokenId;
    blob.priceZat = price;
    blob.payoutAddr = payoutAddr;
    blob.buyerNftAddr = buyerAddr;
    blob.expiryHeight = expiryHeight;
    blob.offerHex = EncodeHexTx(CTransaction(mtx));
    return blob;
}

bool HasReason(const NftVerifyResult& r, const std::string& needle) {
    for (size_t i = 0; i < r.reasons.size(); ++i)
        if (r.reasons[i].find(needle) != std::string::npos) return true;
    return false;
}

// Mint a qty-1 NFT into a store + return (tokenId, nftScript so the carrier UTXO
// is a P2PKH the seller key controls, and the genesis NFT outpoint).
struct SeededNft { CZSLPStore* store; uint256 tokenId; COutPoint nftOp; };

SeededNft SeedNftStore(const CKey& sellerKey, const CScript& nftSpk) {
    SeededNft out;
    out.store = NewStore();
    std::vector<unsigned char> gen =
        ZSLPBuildGenesis("", "Art #1", "", NULL, 0, 0, /*qty=*/1);
    CMutableTransaction gmtx;
    gmtx.vout.push_back(CTxOut(0, CScript(gen.begin(), gen.end())));
    gmtx.vout.push_back(CTxOut(SLP_TOKEN_DUST, nftSpk)); // vout[1] = NFT carrier
    CTransaction gtx(gmtx);
    out.tokenId = ApplyRealTx(out.store, gtx, 1);
    out.nftOp = COutPoint(gtx.GetHash(), 1);
    return out;
}

} // namespace

TEST(NftVerifyReal, AcceptsAWellFormedSignedOffer)
{
    SelectParams(CBaseChainParams::REGTEST);
    // Sign with the SAME branch id NftVerify recomputes for nextHeight (tip 10
    // => nextHeight 11), so the seller's signature validly verifies under the
    // verifier's epoch (REGTEST has Sapling at NO_ACTIVATION by default).
    uint32_t branchId = CurrentEpochBranchId(11, Params().GetConsensus());

    CBasicKeyStore ks;
    CKey sellerKey; sellerKey.MakeNewKey(true);
    ks.AddKeyPubKey(sellerKey, sellerKey.GetPubKey());
    CScript nftSpk = GetScriptForDestination(sellerKey.GetPubKey().GetID());

    SeededNft nft = SeedNftStore(sellerKey, nftSpk);

    // Real buyer/payout t-addrs (so NftAddrFromScript round-trips through the
    // SAME script<->addr helper the verifier uses).
    CKey buyerKey; buyerKey.MakeNewKey(true);
    CKey payoutKey; payoutKey.MakeNewKey(true);
    std::string buyerAddr = EncodeDestination(buyerKey.GetPubKey().GetID());
    std::string payoutAddr = EncodeDestination(payoutKey.GetPubKey().GetID());

    CNftOfferBlob blob = MakeSignedOffer(
        ks, nftSpk, SLP_TOKEN_DUST, branchId, nft.tokenId, nft.nftOp,
        buyerAddr, payoutAddr, /*price=*/100000000, /*expiry=*/0);

    NftFakeCoinsView base;
    CCoinsViewCache cache(&base);
    SeedCoin(cache, nft.nftOp, nftSpk, SLP_TOKEN_DUST, 1);

    NftChainStateGuard guard(&cache, /*tipHeight=*/10);
    LOCK(cs_main);
    NftVerifyResult r;
    NftVerify(nft.store, blob, r);
    EXPECT_TRUE(r.ok) << (r.reasons.empty() ? std::string("(no reasons)")
                                            : r.reasons[0]);
    EXPECT_EQ(r.tokenId, nft.tokenId);
    EXPECT_EQ(r.priceZat, (int64_t)100000000);
    EXPECT_EQ(r.buyerNftAddr, buyerAddr);
    EXPECT_EQ(r.payoutAddr, payoutAddr);

    delete nft.store;
}

TEST(NftVerifyReal, RejectsPriceTamperViaSellerSignature)
{
    SelectParams(CBaseChainParams::REGTEST);
    // Sign with the SAME branch id NftVerify recomputes for nextHeight (tip 10
    // => nextHeight 11), so the seller's signature validly verifies under the
    // verifier's epoch (REGTEST has Sapling at NO_ACTIVATION by default).
    uint32_t branchId = CurrentEpochBranchId(11, Params().GetConsensus());
    CBasicKeyStore ks;
    CKey sellerKey; sellerKey.MakeNewKey(true);
    ks.AddKeyPubKey(sellerKey, sellerKey.GetPubKey());
    CScript nftSpk = GetScriptForDestination(sellerKey.GetPubKey().GetID());
    SeededNft nft = SeedNftStore(sellerKey, nftSpk);
    CKey buyerKey; buyerKey.MakeNewKey(true);
    CKey payoutKey; payoutKey.MakeNewKey(true);
    std::string buyerAddr = EncodeDestination(buyerKey.GetPubKey().GetID());
    std::string payoutAddr = EncodeDestination(payoutKey.GetPubKey().GetID());

    CNftOfferBlob blob = MakeSignedOffer(
        ks, nftSpk, SLP_TOKEN_DUST, branchId, nft.tokenId, nft.nftOp,
        buyerAddr, payoutAddr, 100000000, 0);

    // Tamper the payout DOWN after signing: re-decode, shave vout[2], re-encode.
    CMutableTransaction mtx;
    { CTransaction t; ASSERT_TRUE(DecodeHexTx(t, blob.offerHex)); mtx = CMutableTransaction(t); }
    mtx.vout[2].nValue -= 1;
    blob.offerHex = EncodeHexTx(CTransaction(mtx));
    // blob.priceZat still advertises the ORIGINAL price -> both the value-match
    // arm AND the cryptographic backstop must fire.

    NftFakeCoinsView base;
    CCoinsViewCache cache(&base);
    SeedCoin(cache, nft.nftOp, nftSpk, SLP_TOKEN_DUST, 1);
    NftChainStateGuard guard(&cache, 10);
    LOCK(cs_main);
    NftVerifyResult r;
    NftVerify(nft.store, blob, r);
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(HasReason(r, "seller signature does not validly bind"))
        << "the ALL|ANYONECANPAY backstop must reject a payout edit";

    delete nft.store;
}

TEST(NftVerifyReal, RejectsRecipientRedirectViaSellerSignature)
{
    SelectParams(CBaseChainParams::REGTEST);
    // Sign with the SAME branch id NftVerify recomputes for nextHeight (tip 10
    // => nextHeight 11), so the seller's signature validly verifies under the
    // verifier's epoch (REGTEST has Sapling at NO_ACTIVATION by default).
    uint32_t branchId = CurrentEpochBranchId(11, Params().GetConsensus());
    CBasicKeyStore ks;
    CKey sellerKey; sellerKey.MakeNewKey(true);
    ks.AddKeyPubKey(sellerKey, sellerKey.GetPubKey());
    CScript nftSpk = GetScriptForDestination(sellerKey.GetPubKey().GetID());
    SeededNft nft = SeedNftStore(sellerKey, nftSpk);
    CKey buyerKey; buyerKey.MakeNewKey(true);
    CKey payoutKey; payoutKey.MakeNewKey(true);
    std::string buyerAddr = EncodeDestination(buyerKey.GetPubKey().GetID());
    std::string payoutAddr = EncodeDestination(payoutKey.GetPubKey().GetID());

    CNftOfferBlob blob = MakeSignedOffer(
        ks, nftSpk, SLP_TOKEN_DUST, branchId, nft.tokenId, nft.nftOp,
        buyerAddr, payoutAddr, 100000000, 0);

    // Redirect the NFT recipient (vout[1]) to an attacker after signing.
    CMutableTransaction mtx;
    { CTransaction t; ASSERT_TRUE(DecodeHexTx(t, blob.offerHex)); mtx = CMutableTransaction(t); }
    mtx.vout[1].scriptPubKey = P2PKH(0xEE);
    blob.offerHex = EncodeHexTx(CTransaction(mtx));

    NftFakeCoinsView base;
    CCoinsViewCache cache(&base);
    SeedCoin(cache, nft.nftOp, nftSpk, SLP_TOKEN_DUST, 1);
    NftChainStateGuard guard(&cache, 10);
    LOCK(cs_main);
    NftVerifyResult r;
    NftVerify(nft.store, blob, r);
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(HasReason(r, "seller signature does not validly bind"));

    delete nft.store;
}

TEST(NftVerifyReal, RejectsExpiredOrExpiringSoonOffer)
{
    SelectParams(CBaseChainParams::REGTEST);
    // Sign with the SAME branch id NftVerify recomputes for nextHeight (tip 10
    // => nextHeight 11), so the seller's signature validly verifies under the
    // verifier's epoch (REGTEST has Sapling at NO_ACTIVATION by default).
    uint32_t branchId = CurrentEpochBranchId(11, Params().GetConsensus());
    CBasicKeyStore ks;
    CKey sellerKey; sellerKey.MakeNewKey(true);
    ks.AddKeyPubKey(sellerKey, sellerKey.GetPubKey());
    CScript nftSpk = GetScriptForDestination(sellerKey.GetPubKey().GetID());
    SeededNft nft = SeedNftStore(sellerKey, nftSpk);
    CKey buyerKey; buyerKey.MakeNewKey(true);
    CKey payoutKey; payoutKey.MakeNewKey(true);
    std::string buyerAddr = EncodeDestination(buyerKey.GetPubKey().GetID());
    std::string payoutAddr = EncodeDestination(payoutKey.GetPubKey().GetID());

    // tip is height 10 (=> nextHeight 11). An expiry at 12 is within
    // nextHeight+TX_EXPIRING_SOON_THRESHOLD (=14) -> "expiring too soon".
    const uint32_t expiry = 12;
    CNftOfferBlob blob = MakeSignedOffer(
        ks, nftSpk, SLP_TOKEN_DUST, branchId, nft.tokenId, nft.nftOp,
        buyerAddr, payoutAddr, 100000000, expiry);

    NftFakeCoinsView base;
    CCoinsViewCache cache(&base);
    SeedCoin(cache, nft.nftOp, nftSpk, SLP_TOKEN_DUST, 1);
    NftChainStateGuard guard(&cache, /*tipHeight=*/10);
    LOCK(cs_main);
    NftVerifyResult r;
    NftVerify(nft.store, blob, r);
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(HasReason(r, "expired or expiring too soon"));

    delete nft.store;
}

TEST(NftVerifyReal, RejectsWhenNftOutpointIsNotLive)
{
    SelectParams(CBaseChainParams::REGTEST);
    // Sign with the SAME branch id NftVerify recomputes for nextHeight (tip 10
    // => nextHeight 11), so the seller's signature validly verifies under the
    // verifier's epoch (REGTEST has Sapling at NO_ACTIVATION by default).
    uint32_t branchId = CurrentEpochBranchId(11, Params().GetConsensus());
    CBasicKeyStore ks;
    CKey sellerKey; sellerKey.MakeNewKey(true);
    ks.AddKeyPubKey(sellerKey, sellerKey.GetPubKey());
    CScript nftSpk = GetScriptForDestination(sellerKey.GetPubKey().GetID());
    SeededNft nft = SeedNftStore(sellerKey, nftSpk);
    CKey buyerKey; buyerKey.MakeNewKey(true);
    CKey payoutKey; payoutKey.MakeNewKey(true);
    std::string buyerAddr = EncodeDestination(buyerKey.GetPubKey().GetID());
    std::string payoutAddr = EncodeDestination(payoutKey.GetPubKey().GetID());

    CNftOfferBlob blob = MakeSignedOffer(
        ks, nftSpk, SLP_TOKEN_DUST, branchId, nft.tokenId, nft.nftOp,
        buyerAddr, payoutAddr, 100000000, 0);

    // Coins view is EMPTY -> vin[0] prevout is not live (spent / never existed).
    NftFakeCoinsView base;
    CCoinsViewCache cache(&base);
    NftChainStateGuard guard(&cache, 10);
    LOCK(cs_main);
    NftVerifyResult r;
    NftVerify(nft.store, blob, r);
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(HasReason(r, "not a live"));

    delete nft.store;
}

TEST(NftVerifyReal, RejectsBuyerAddrAndPriceFieldLies)
{
    // The header is ADVISORY: NftVerify re-derives buyerNftAddr/priceZat from
    // offerHex and must flag a header that lies about them (independently of the
    // signature, which still validly binds the REAL outputs).
    SelectParams(CBaseChainParams::REGTEST);
    // Sign with the SAME branch id NftVerify recomputes for nextHeight (tip 10
    // => nextHeight 11), so the seller's signature validly verifies under the
    // verifier's epoch (REGTEST has Sapling at NO_ACTIVATION by default).
    uint32_t branchId = CurrentEpochBranchId(11, Params().GetConsensus());
    CBasicKeyStore ks;
    CKey sellerKey; sellerKey.MakeNewKey(true);
    ks.AddKeyPubKey(sellerKey, sellerKey.GetPubKey());
    CScript nftSpk = GetScriptForDestination(sellerKey.GetPubKey().GetID());
    SeededNft nft = SeedNftStore(sellerKey, nftSpk);
    CKey buyerKey; buyerKey.MakeNewKey(true);
    CKey payoutKey; payoutKey.MakeNewKey(true);
    CKey otherKey; otherKey.MakeNewKey(true);
    std::string buyerAddr = EncodeDestination(buyerKey.GetPubKey().GetID());
    std::string payoutAddr = EncodeDestination(payoutKey.GetPubKey().GetID());

    CNftOfferBlob blob = MakeSignedOffer(
        ks, nftSpk, SLP_TOKEN_DUST, branchId, nft.tokenId, nft.nftOp,
        buyerAddr, payoutAddr, 100000000, 0);
    // Lie in the advisory header (tx itself untouched + still validly signed).
    blob.buyerNftAddr = EncodeDestination(otherKey.GetPubKey().GetID());
    blob.priceZat = 999;

    NftFakeCoinsView base;
    CCoinsViewCache cache(&base);
    SeedCoin(cache, nft.nftOp, nftSpk, SLP_TOKEN_DUST, 1);
    NftChainStateGuard guard(&cache, 10);
    LOCK(cs_main);
    NftVerifyResult r;
    NftVerify(nft.store, blob, r);
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(HasReason(r, "NFT recipient"));
    EXPECT_TRUE(HasReason(r, "payout) value"));

    delete nft.store;
}
#endif // ENABLE_WALLET

// ════════════════════════════════════════════════════════════════════════
//  5. E-4 (no-fork PROOF): each representative ZSLP/NFT OP_RETURN carrier is
//     RELAY-STANDARD on MAINNET under the DEFAULT -datacarriersize, so old
//     unmodified nodes relay + mine it. This converts the "no consensus fork"
//     claim from a 223-byte builder assert to a policy-level proof against the
//     real IsStandardTx path. (The OFFER carrier is covered above by
//     NftOfferStandardness.SwapTxIsStandardOnMainnet; here we add GENESIS +
//     SEND and pin the datacarrier policy explicitly.)
// ════════════════════════════════════════════════════════════════════════

namespace {
// A representative ZSLP carrier tx (vout[0]=OP_RETURN op, then real outputs) with
// push-only dummy scriptSigs so per-input standardness passes without signing.
CTransaction MakeCarrierTx(const std::vector<unsigned char>& opret,
                           const std::vector<CTxOut>& tokenOuts, int nHeight) {
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(
        Params().GetConsensus(), nHeight);
    CTxIn in(COutPoint(uint256S("01"), 0));
    in.scriptSig = CScript() << std::vector<unsigned char>(72, 0);
    mtx.vin.push_back(in);
    mtx.vout.push_back(CTxOut(0, CScript(opret.begin(), opret.end())));
    for (size_t i = 0; i < tokenOuts.size(); ++i)
        mtx.vout.push_back(tokenOuts[i]);
    return CTransaction(mtx);
}
} // namespace

TEST(NftNoForkStandardness, GenesisIsStandardOnMainnetDefaultDatacarrier)
{
    SelectParams(CBaseChainParams::MAIN);
    // The policy knob is at its shipped default (223 = MAX_OP_RETURN_RELAY).
    ASSERT_EQ(nMaxDatacarrierBytes, (unsigned)MAX_OP_RETURN_RELAY);
    const int nHeight = 476969; // MAIN Sapling activation

    // A realistic NFT genesis: name + 32-byte document_hash (the heaviest common
    // NFT mint), which is what zslp_genesis nft=true ships.
    uint8_t docHash[32]; memset(docHash, 0x5A, 32);
    std::vector<unsigned char> gen = ZSLPBuildGenesis(
        "ART", "My Photo #1 — a longish display name", "ipfs://Qm-some-cid",
        docHash, /*decimals=*/0, /*baton=*/0, /*qty=*/1);
    ASSERT_FALSE(gen.empty());
    // The OP_RETURN scriptPubKey must fit the relay cap (the no-fork premise).
    CScript opScript(gen.begin(), gen.end());
    EXPECT_LE(opScript.size(), (size_t)nMaxDatacarrierBytes);

    std::vector<CTxOut> outs;
    outs.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH(0x01))); // vout[1] token recipient
    CTransaction tx = MakeCarrierTx(gen, outs, nHeight);

    std::string reason;
    EXPECT_TRUE(IsStandardTx(tx, reason, nHeight))
        << "genesis carrier not relay-standard: " << reason;

    SelectParams(CBaseChainParams::REGTEST);
}

TEST(NftNoForkStandardness, SendIsStandardOnMainnetDefaultDatacarrier)
{
    SelectParams(CBaseChainParams::MAIN);
    ASSERT_EQ(nMaxDatacarrierBytes, (unsigned)MAX_OP_RETURN_RELAY);
    const int nHeight = 476969;

    uint8_t be[32]; memset(be, 0x42, 32);
    // A max-fanout SEND (the largest SEND OP_RETURN the builder emits) still fits.
    std::vector<unsigned char> snd = ZSLPBuildSend(be, {1});
    ASSERT_FALSE(snd.empty());
    CScript opScript(snd.begin(), snd.end());
    EXPECT_LE(opScript.size(), (size_t)nMaxDatacarrierBytes);

    std::vector<CTxOut> outs;
    outs.push_back(CTxOut(SLP_TOKEN_DUST, P2PKH(0x02))); // vout[1] recipient
    CTransaction tx = MakeCarrierTx(snd, outs, nHeight);

    std::string reason;
    EXPECT_TRUE(IsStandardTx(tx, reason, nHeight))
        << "send carrier not relay-standard: " << reason;

    SelectParams(CBaseChainParams::REGTEST);
}

// Belt-and-braces: the builder's own 223-byte ceiling matches the relay policy
// constant, so a carrier that the builder accepts can never exceed -datacarriersize.
TEST(NftNoForkStandardness, BuilderCeilingMatchesRelayPolicy)
{
    EXPECT_EQ((unsigned)MAX_OP_RETURN_RELAY, (unsigned)223);
    EXPECT_EQ(nMaxDatacarrierBytes, (unsigned)MAX_OP_RETURN_RELAY);
}
