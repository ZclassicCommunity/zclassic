// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Unit tests for the ZNAM (ZCL Names) indexer's OWNER-DERIVATION trust boundary
// — the First-In-First-Served (FIFS) seam where the indexer decides WHO owns a
// name. Ownership is the vin[0] P2PKH signer, recovered from the connecting
// block's undo data. These three static seams are the entire boundary:
//
//   * CZNAMIndexer::ExtractP2PKHOwnerFromScript — a prevout scriptPubKey maps to
//     an owner ONLY if it is a clean transparent P2PKH (a CKeyID destination).
//     P2SH / bare-multisig / bare-pubkey-with-no-clean-keyid / OP_RETURN(null)
//     all yield NO owner (the record becomes a deterministic overlay no-op).
//   * CZNAMIndexer::GetOwnerForTransaction — composes the above with the
//     undo-data indexing: coinbase (txIndex < 1), missing/short undo, and an
//     empty prevout vector all yield NO owner.
//   * CZNAMIndexer::ParseTx — scans vout ASCENDING and honors the FIRST script
//     ZNAMParseScript accepts (a record at vout[2] is found; with two ZNAM
//     outputs the earlier vout wins).
//
// These are pure functions of their inputs (no chain state / no pcoinsTip), so
// they are driven directly here with hand-built scripts + a synthetic
// CBlockUndo, mirroring the regtest helpers in test_znam_indexer.cpp.

#include <gtest/gtest.h>

#include "znam/znamindexer.h"
#include "znam/znammsg.h"

#include "chainparams.h"
#include "key_io.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "undo.h"

#include <string>
#include <vector>

namespace {

// A clean transparent P2PKH scriptPubKey for a deterministic key-hash (the ONLY
// shape ExtractP2PKHOwnerFromScript must accept). Mirrors test_znam_indexer.cpp's
// MakeP2PKH but returns the SCRIPT (the prevout we feed the owner seam).
CScript MakeP2PKHScript(uint8_t fill)
{
    std::vector<unsigned char> h(20, fill);
    return GetScriptForDestination(CKeyID(uint160(h)));
}

std::string MakeP2PKHAddr(uint8_t fill)
{
    std::vector<unsigned char> h(20, fill);
    return EncodeDestination(CKeyID(uint160(h)));
}

// A P2SH scriptPubKey (HASH160 <20> EQUAL) — a CScriptID destination, NOT P2PKH.
CScript MakeP2SHScript(uint8_t fill)
{
    std::vector<unsigned char> h(20, fill);
    return GetScriptForDestination(CScriptID(uint160(h)));
}

// A 33-byte data push with an INVALID pubkey header (0x01). It is the right
// LENGTH for the TX_PUBKEY template (33..65), so Solver matches a bare-pubkey
// script, but CPubKey::IsValid() then fails (header 0x01 => length 0), so
// ExtractDestination yields nothing — exactly the realistic "this prevout has
// no clean P2PKH owner" case. (A size-valid bare pubkey WOULD map to a CKeyID;
// we model the ownerless branch, which is the boundary the indexer must drop.)
CScript MakeBarePubkeyScriptNoOwner()
{
    std::vector<unsigned char> fake(33, 0x11);
    fake[0] = 0x01; // not 2/3/4/6/7 => CPubKey GetLen == 0 => invalid
    return CScript() << fake << OP_CHECKSIG;
}

// A bare 1-of-2 multisig scriptPubKey (multiple addresses => no single owner).
CScript MakeBareMultisigScript()
{
    // Two size-valid-looking compressed pubkeys (header 0x02/0x03, 33 bytes).
    std::vector<unsigned char> k1(33, 0x02); k1[0] = 0x02;
    std::vector<unsigned char> k2(33, 0x03); k2[0] = 0x03;
    return CScript() << OP_1 << k1 << k2 << OP_2 << OP_CHECKMULTISIG;
}

// An OP_RETURN (null-data) scriptPubKey — never a spendable owner.
CScript MakeOpReturnScript()
{
    std::vector<unsigned char> payload(8, 0xAB);
    return CScript() << OP_RETURN << payload;
}

// Build a CBlockUndo whose vtxundo[txIndex-1].vprevout[0] is `prevScript`.
// vtxundo excludes the coinbase, so a block-tx at index `txIndex` maps to
// vtxundo[txIndex-1]; we pad the lower slots with empty CTxUndo entries.
CBlockUndo MakeUndoWithPrevout(int32_t txIndex, const CScript& prevScript)
{
    CBlockUndo bu;
    for (int32_t i = 0; i < txIndex; ++i) {
        CTxUndo tu;
        if (i == txIndex - 1) {
            CTxInUndo in;
            in.txout = CTxOut(100000, prevScript);
            tu.vprevout.push_back(in);
        }
        bu.vtxundo.push_back(tu);
    }
    return bu;
}

// A minimal tx with one vin (so GetOwnerForTransaction's vin[0] notion is valid)
// and the supplied outputs.
CTransaction MakeTx(const std::vector<CTxOut>& vout)
{
    CMutableTransaction mtx;
    CTxIn in;
    in.prevout = COutPoint(uint256S("01"), 0);
    mtx.vin.push_back(in);
    mtx.vout = vout;
    return CTransaction(mtx);
}

// A ZNAM REGISTER OP_RETURN scriptPubKey (the bytes the parser accepts).
CScript MakeZNAMRegisterScript(const std::string& name)
{
    std::vector<unsigned char> raw =
        ZNAMBuildRegister(name, ZNAM_TARGET_ONION, "abcdefghij234567.onion");
    return CScript(raw.begin(), raw.end());
}

} // namespace

// ── ExtractP2PKHOwnerFromScript: only clean P2PKH yields an owner ─────

TEST(ZNAMIndexerOwner, ExtractP2PKHAcceptsCleanP2PKH)
{
    SelectParams(CBaseChainParams::REGTEST);
    std::string owner;
    EXPECT_TRUE(CZNAMIndexer::ExtractP2PKHOwnerFromScript(MakeP2PKHScript(0x42), owner));
    EXPECT_EQ(owner, MakeP2PKHAddr(0x42));
}

TEST(ZNAMIndexerOwner, ExtractP2PKHRejectsP2SH)
{
    SelectParams(CBaseChainParams::REGTEST);
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::ExtractP2PKHOwnerFromScript(MakeP2SHScript(0x55), owner));
    EXPECT_EQ(owner, "sentinel"); // unchanged on failure
}

TEST(ZNAMIndexerOwner, ExtractP2PKHRejectsBareMultisig)
{
    SelectParams(CBaseChainParams::REGTEST);
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::ExtractP2PKHOwnerFromScript(MakeBareMultisigScript(), owner));
    EXPECT_EQ(owner, "sentinel");
}

TEST(ZNAMIndexerOwner, ExtractP2PKHRejectsBarePubkeyWithoutCleanKeyId)
{
    SelectParams(CBaseChainParams::REGTEST);
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::ExtractP2PKHOwnerFromScript(MakeBarePubkeyScriptNoOwner(), owner));
    EXPECT_EQ(owner, "sentinel");
}

TEST(ZNAMIndexerOwner, ExtractP2PKHRejectsOpReturnNull)
{
    SelectParams(CBaseChainParams::REGTEST);
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::ExtractP2PKHOwnerFromScript(MakeOpReturnScript(), owner));
    EXPECT_EQ(owner, "sentinel");
}

TEST(ZNAMIndexerOwner, ExtractP2PKHRejectsEmptyScript)
{
    SelectParams(CBaseChainParams::REGTEST);
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::ExtractP2PKHOwnerFromScript(CScript(), owner));
    EXPECT_EQ(owner, "sentinel");
}

// ── GetOwnerForTransaction: coinbase + undo-shape boundaries ─────────

TEST(ZNAMIndexerOwner, GetOwnerCoinbaseIsOwnerless)
{
    SelectParams(CBaseChainParams::REGTEST);
    // Even with perfectly good undo, txIndex < 1 (the coinbase) is never an owner.
    CTransaction tx = MakeTx(std::vector<CTxOut>(1, CTxOut(0, MakeOpReturnScript())));
    CBlockUndo bu = MakeUndoWithPrevout(1, MakeP2PKHScript(0x42));
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::GetOwnerForTransaction(tx, /*txIndex=*/0, bu, owner));
    EXPECT_EQ(owner, "sentinel");
}

TEST(ZNAMIndexerOwner, GetOwnerMissingUndoIsOwnerless)
{
    SelectParams(CBaseChainParams::REGTEST);
    CTransaction tx = MakeTx(std::vector<CTxOut>(1, CTxOut(0, MakeOpReturnScript())));
    // Empty undo (e.g. read failure / genesis) => no owner for ANY txIndex.
    CBlockUndo empty;
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::GetOwnerForTransaction(tx, /*txIndex=*/1, empty, owner));
    EXPECT_EQ(owner, "sentinel");
}

TEST(ZNAMIndexerOwner, GetOwnerShortUndoIsOwnerless)
{
    SelectParams(CBaseChainParams::REGTEST);
    CTransaction tx = MakeTx(std::vector<CTxOut>(1, CTxOut(0, MakeOpReturnScript())));
    // Undo has slot 0 only (vtxundo.size()==1); a tx at index 3 maps to slot 2,
    // which is out of range => ownerless (no crash).
    CBlockUndo bu = MakeUndoWithPrevout(1, MakeP2PKHScript(0x42));
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::GetOwnerForTransaction(tx, /*txIndex=*/3, bu, owner));
    EXPECT_EQ(owner, "sentinel");
}

TEST(ZNAMIndexerOwner, GetOwnerEmptyPrevoutVectorIsOwnerless)
{
    SelectParams(CBaseChainParams::REGTEST);
    CTransaction tx = MakeTx(std::vector<CTxOut>(1, CTxOut(0, MakeOpReturnScript())));
    // The matching vtxundo slot exists but carries NO prevouts => ownerless.
    CBlockUndo bu;
    bu.vtxundo.push_back(CTxUndo()); // slot 0, empty vprevout, for txIndex 1
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::GetOwnerForTransaction(tx, /*txIndex=*/1, bu, owner));
    EXPECT_EQ(owner, "sentinel");
}

TEST(ZNAMIndexerOwner, GetOwnerCleanP2PKHPrevoutYieldsOwner)
{
    SelectParams(CBaseChainParams::REGTEST);
    CTransaction tx = MakeTx(std::vector<CTxOut>(1, CTxOut(0, MakeOpReturnScript())));
    // txIndex 2 maps to vtxundo[1]; that prevout is a clean P2PKH => owner found.
    CBlockUndo bu = MakeUndoWithPrevout(2, MakeP2PKHScript(0x77));
    std::string owner;
    EXPECT_TRUE(CZNAMIndexer::GetOwnerForTransaction(tx, /*txIndex=*/2, bu, owner));
    EXPECT_EQ(owner, MakeP2PKHAddr(0x77));
}

TEST(ZNAMIndexerOwner, GetOwnerNonP2PKHPrevoutIsOwnerless)
{
    SelectParams(CBaseChainParams::REGTEST);
    CTransaction tx = MakeTx(std::vector<CTxOut>(1, CTxOut(0, MakeOpReturnScript())));
    // A P2SH prevout signer is not a P2PKH owner => the record is ownerless.
    CBlockUndo bu = MakeUndoWithPrevout(1, MakeP2SHScript(0x99));
    std::string owner = "sentinel";
    EXPECT_FALSE(CZNAMIndexer::GetOwnerForTransaction(tx, /*txIndex=*/1, bu, owner));
    EXPECT_EQ(owner, "sentinel");
}

// ── ParseTx: first-accepted-vout (ascending) ─────────────────────────

TEST(ZNAMIndexerOwner, ParseTxFindsRecordAtVout2)
{
    SelectParams(CBaseChainParams::REGTEST);
    // vout[0] = ordinary P2PKH, vout[1] = ordinary P2PKH, vout[2] = ZNAM record.
    std::vector<CTxOut> vout;
    vout.push_back(CTxOut(1000, MakeP2PKHScript(0x01)));
    vout.push_back(CTxOut(1000, MakeP2PKHScript(0x02)));
    vout.push_back(CTxOut(0, MakeZNAMRegisterScript("found-at-two")));
    CTransaction tx = MakeTx(vout);

    ZNAMMessage parsed;
    int32_t recordVout = -1;
    ASSERT_TRUE(CZNAMIndexer::ParseTx(tx, parsed, recordVout));
    EXPECT_EQ(recordVout, 2);
    EXPECT_EQ((int)parsed.command, (int)ZNAMMSG_REGISTER);
    EXPECT_EQ(parsed.name, "found-at-two");
}

TEST(ZNAMIndexerOwner, ParseTxFirstZNAMOutputWins)
{
    SelectParams(CBaseChainParams::REGTEST);
    // Two ZNAM records: the EARLIER vout (index 1) must win (ascending scan).
    std::vector<CTxOut> vout;
    vout.push_back(CTxOut(1000, MakeP2PKHScript(0x01)));
    vout.push_back(CTxOut(0, MakeZNAMRegisterScript("first-wins")));
    vout.push_back(CTxOut(0, MakeZNAMRegisterScript("second-loses")));
    CTransaction tx = MakeTx(vout);

    ZNAMMessage parsed;
    int32_t recordVout = -1;
    ASSERT_TRUE(CZNAMIndexer::ParseTx(tx, parsed, recordVout));
    EXPECT_EQ(recordVout, 1);
    EXPECT_EQ(parsed.name, "first-wins");
}

TEST(ZNAMIndexerOwner, ParseTxNoRecordReturnsFalse)
{
    SelectParams(CBaseChainParams::REGTEST);
    std::vector<CTxOut> vout;
    vout.push_back(CTxOut(1000, MakeP2PKHScript(0x01)));
    vout.push_back(CTxOut(0, MakeOpReturnScript())); // non-ZNAM OP_RETURN
    CTransaction tx = MakeTx(vout);

    ZNAMMessage parsed;
    int32_t recordVout = -99;
    EXPECT_FALSE(CZNAMIndexer::ParseTx(tx, parsed, recordVout));
    EXPECT_EQ(recordVout, -99); // untouched on no-match
}
