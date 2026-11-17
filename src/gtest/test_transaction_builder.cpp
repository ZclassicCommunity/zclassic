#include "chainparams.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "key_io.h"
#include "main.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "streams.h"
#include "version.h"
#include "zcash/Note.hpp"
#include "zcash/NoteEncryption.hpp"
#include "zcash/Zcash.h"
#include "rpc/protocol.h"
#include "transaction_builder.h"
#include "utiltest.h"
#include "zcash/Address.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>

#include "librustzcash.h"

// ContextualCheckTransaction() returns true without looking at the transaction
// while the node is in initial block download, and a gtest process with no chain
// is "in IBD". Every proof check below therefore passes this predicate, so the
// consensus Sapling verification path really runs.
static bool NotInitialBlockDownload() { return false; }

static bool SaplingConsensusCheck(const CTransaction& tx, int nHeight, std::string& reason)
{
    CValidationState state;
    bool ok = ContextualCheckTransaction(tx, state, nHeight, 100, NotInitialBlockDownload);
    reason = state.GetRejectReason();
    return ok;
}

// A one-spend, one-output Sapling transaction made by hand with the same calls
// TransactionBuilder::Build() makes. The proofs are made once; Finish() then
// lets a test change the transaction BEFORE the sighash is computed and signs
// the spend authorization over the final sighash. The sighash covers the
// zkproofs, anchors and valueBalance, so corrupting a built transaction after
// signing always fails at the spendAuthSig first; re-signing is what makes a
// rejection attributable to the proof, the anchor or the binding signature.
// The binding signature is always made for the honest valueBalance.
struct HandBuiltSapling {
    const Consensus::Params& consensusParams;
    int nHeight;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 alpha;
    void* ctx;
    CMutableTransaction mtx;
    CAmount honestValueBalance;

    HandBuiltSapling(
        const Consensus::Params& consensusParamsIn,
        int nHeightIn,
        const libzcash::SaplingExpandedSpendingKey& expskIn,
        const libzcash::SaplingNote& note,
        const SaplingMerkleTree& tree,
        const libzcash::SaplingPaymentAddress& to,
        CAmount outValue)
        : consensusParams(consensusParamsIn), nHeight(nHeightIn), expsk(expskIn),
          ctx(librustzcash_sapling_proving_ctx_init())
    {
        mtx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);
        auto fvk = expsk.full_viewing_key();
        auto witness = tree.witness();
        auto nf = note.nullifier(fvk, witness.position());
        EXPECT_TRUE(static_cast<bool>(nf));

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << witness.path();
        std::vector<unsigned char> path(ss.begin(), ss.end());

        librustzcash_sapling_generate_r(alpha.begin());
        uint256 anchor = tree.root();

        SpendDescription sdesc;
        EXPECT_TRUE(librustzcash_sapling_spend_proof(
            ctx,
            fvk.ak.begin(),
            expsk.nsk.begin(),
            note.d.data(),
            note.r.begin(),
            alpha.begin(),
            note.value(),
            anchor.begin(),
            path.data(),
            sdesc.cv.begin(),
            sdesc.rk.begin(),
            sdesc.zkproof.data()));
        sdesc.anchor = anchor;
        sdesc.nullifier = *nf;
        mtx.vShieldedSpend.push_back(sdesc);

        libzcash::SaplingNote outNote(to, outValue);
        auto cm = outNote.cm();
        EXPECT_TRUE(static_cast<bool>(cm));
        std::array<unsigned char, ZC_MEMO_SIZE> memo = {};
        libzcash::SaplingNotePlaintext notePlaintext(outNote, memo);
        auto res = notePlaintext.encrypt(outNote.pk_d);
        EXPECT_TRUE(static_cast<bool>(res));
        auto enc = res.get();
        auto encryptor = enc.second;

        OutputDescription odesc;
        EXPECT_TRUE(librustzcash_sapling_output_proof(
            ctx,
            encryptor.get_esk().begin(),
            outNote.d.data(),
            outNote.pk_d.begin(),
            outNote.r.begin(),
            outNote.value(),
            odesc.cv.begin(),
            odesc.zkproof.begin()));
        odesc.cm = *cm;
        odesc.ephemeralKey = encryptor.get_epk();
        odesc.encCiphertext = enc.first;
        libzcash::SaplingOutgoingPlaintext outPlaintext(outNote.pk_d, encryptor.get_esk());
        odesc.outCiphertext = outPlaintext.encrypt(fvk.ovk, odesc.cv, odesc.cm, encryptor);
        mtx.vShieldedOutput.push_back(odesc);

        honestValueBalance = note.value() - outValue;
        mtx.valueBalance = honestValueBalance;
    }

    ~HandBuiltSapling() { librustzcash_sapling_proving_ctx_free(ctx); }

    template <typename Mutation>
    CTransaction Finish(Mutation mutate) const
    {
        CMutableTransaction tx(mtx);
        mutate(tx);
        CScript scriptCode;
        uint256 dataToBeSigned = SignatureHash(
            scriptCode, tx, NOT_AN_INPUT, SigHashType(), 0,
            CurrentEpochBranchId(nHeight, consensusParams));
        EXPECT_TRUE(librustzcash_sapling_spend_sig(
            expsk.ask.begin(),
            alpha.begin(),
            dataToBeSigned.begin(),
            tx.vShieldedSpend[0].spendAuthSig.data()));
        EXPECT_TRUE(librustzcash_sapling_binding_sig(
            ctx,
            honestValueBalance,
            dataToBeSigned.begin(),
            tx.bindingSig.data()));
        return CTransaction(tx);
    }
};

TEST(TransactionBuilder, Invoke)
{
    auto consensusParams = RegtestActivateSapling();

    CBasicKeyStore keystore;
    CKey tsk = AddTestCKeyToKeyStore(keystore);
    auto scriptPubKey = GetScriptForDestination(tsk.GetPubKey().GetID());

    auto sk_from = libzcash::SaplingSpendingKey::random();
    auto fvk_from = sk_from.full_viewing_key();

    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto fvk = sk.full_viewing_key();
    auto ivk = fvk.in_viewing_key();
    libzcash::diversifier_t d = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    auto pk = *ivk.address(d);

    // Create a shielding transaction from transparent to Sapling
    // 0.0005 t-ZEC in, 0.0004 z-ZEC out, 0.0001 t-ZEC fee
    auto builder1 = TransactionBuilder(consensusParams, 1, &keystore);
    builder1.AddTransparentInput(COutPoint(), scriptPubKey, 50000);
    builder1.AddSaplingOutput(fvk_from.ovk, pk, 40000, {});
    auto tx1 = builder1.Build().GetTxOrThrow();

    EXPECT_EQ(tx1.vin.size(), 1);
    EXPECT_EQ(tx1.vout.size(), 0);
    EXPECT_EQ(tx1.vjoinsplit.size(), 0);
    EXPECT_EQ(tx1.vShieldedSpend.size(), 0);
    EXPECT_EQ(tx1.vShieldedOutput.size(), 1);
    EXPECT_EQ(tx1.valueBalance, -40000);

    CValidationState state;
    EXPECT_TRUE(ContextualCheckTransaction(tx1, state, 2, 0, NotInitialBlockDownload));
    EXPECT_EQ(state.GetRejectReason(), "");

    // Prepare to spend the note that was just created
    auto maybe_pt = libzcash::SaplingNotePlaintext::decrypt(
        tx1.vShieldedOutput[0].encCiphertext, ivk, tx1.vShieldedOutput[0].ephemeralKey, tx1.vShieldedOutput[0].cm);
    ASSERT_EQ(static_cast<bool>(maybe_pt), true);
    auto maybe_note = maybe_pt.get().note(ivk);
    ASSERT_EQ(static_cast<bool>(maybe_note), true);
    auto note = maybe_note.get();
    SaplingMerkleTree tree;
    tree.append(tx1.vShieldedOutput[0].cm);
    auto anchor = tree.root();
    auto witness = tree.witness();

    // Create a Sapling-only transaction
    // 0.0004 z-ZEC in, 0.00025 z-ZEC out, 0.0001 t-ZEC fee, 0.00005 z-ZEC change
    auto builder2 = TransactionBuilder(consensusParams, 2);
    builder2.AddSaplingSpend(expsk, note, anchor, witness);
    // Check that trying to add a different anchor fails
    // TODO: the following check can be split out in to another test
    ASSERT_THROW(builder2.AddSaplingSpend(expsk, note, uint256(), witness), UniValue);

    builder2.AddSaplingOutput(fvk.ovk, pk, 25000, {});
    auto tx2 = builder2.Build().GetTxOrThrow();

    EXPECT_EQ(tx2.vin.size(), 0);
    EXPECT_EQ(tx2.vout.size(), 0);
    EXPECT_EQ(tx2.vjoinsplit.size(), 0);
    EXPECT_EQ(tx2.vShieldedSpend.size(), 1);
    EXPECT_EQ(tx2.vShieldedOutput.size(), 2);
    EXPECT_EQ(tx2.valueBalance, 10000);

    EXPECT_TRUE(ContextualCheckTransaction(tx2, state, 3, 0, NotInitialBlockDownload));
    EXPECT_EQ(state.GetRejectReason(), "");

    // Revert to default
    RegtestDeactivateSapling();
}

TEST(TransactionBuilder, ThrowsOnTransparentInputWithoutKeyStore)
{
    SelectParams(CBaseChainParams::REGTEST);
    auto consensusParams = Params().GetConsensus();

    auto builder = TransactionBuilder(consensusParams, 1);
    ASSERT_THROW(builder.AddTransparentInput(COutPoint(), CScript(), 1), std::runtime_error);
}

TEST(TransactionBuilder, RejectsInvalidTransparentOutput)
{
    SelectParams(CBaseChainParams::REGTEST);
    auto consensusParams = Params().GetConsensus();

    // Default CTxDestination type is an invalid address
    CTxDestination taddr;
    auto builder = TransactionBuilder(consensusParams, 1);
    ASSERT_THROW(builder.AddTransparentOutput(taddr, 50), UniValue);
}

TEST(TransactionBuilder, RejectsInvalidTransparentChangeAddress)
{
    SelectParams(CBaseChainParams::REGTEST);
    auto consensusParams = Params().GetConsensus();

    // Default CTxDestination type is an invalid address
    CTxDestination taddr;
    auto builder = TransactionBuilder(consensusParams, 1);
    ASSERT_THROW(builder.SendChangeTo(taddr), UniValue);
}

TEST(TransactionBuilder, FailsWithNegativeChange)
{
    auto consensusParams = RegtestActivateSapling();

    // Generate dummy Sapling address
    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto fvk = sk.full_viewing_key();
    auto pa = sk.default_address();

    // Set up dummy transparent address
    CBasicKeyStore keystore;
    CKey tsk = AddTestCKeyToKeyStore(keystore);
    auto tkeyid = tsk.GetPubKey().GetID();
    auto scriptPubKey = GetScriptForDestination(tkeyid);
    CTxDestination taddr = tkeyid;

    auto testNote = GetTestSaplingNote(pa, 59999);

    // Fail if there is only a Sapling output
    // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
    auto builder = TransactionBuilder(consensusParams, 1);
    builder.AddSaplingOutput(fvk.ovk, pa, 50000, {});
    EXPECT_EQ("Change cannot be negative", builder.Build().GetError());

    // Fail if there is only a transparent output
    // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
    builder = TransactionBuilder(consensusParams, 1, &keystore);
    builder.AddTransparentOutput(taddr, 50000);
    EXPECT_EQ("Change cannot be negative", builder.Build().GetError());

    // Fails if there is insufficient input
    // 0.0005 t-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
    builder.AddSaplingSpend(expsk, testNote.note, testNote.tree.root(), testNote.tree.witness());
    EXPECT_EQ("Change cannot be negative", builder.Build().GetError());

    // Succeeds if there is sufficient input
    builder.AddTransparentInput(COutPoint(), scriptPubKey, 1);
    EXPECT_TRUE(builder.Build().IsTx());

    // Revert to default
    RegtestDeactivateSapling();
}

TEST(TransactionBuilder, ChangeOutput)
{
    auto consensusParams = RegtestActivateSapling();

    // Generate dummy Sapling address
    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto pa = sk.default_address();

    auto testNote = GetTestSaplingNote(pa, 25000);

    // Generate change Sapling address
    auto sk2 = libzcash::SaplingSpendingKey::random();
    auto fvkOut = sk2.full_viewing_key();
    auto zChangeAddr = sk2.default_address();

    // Set up dummy transparent address
    CBasicKeyStore keystore;
    CKey tsk = AddTestCKeyToKeyStore(keystore);
    auto tkeyid = tsk.GetPubKey().GetID();
    auto scriptPubKey = GetScriptForDestination(tkeyid);
    CTxDestination taddr = tkeyid;

    // No change address and no Sapling spends
    {
        auto builder = TransactionBuilder(consensusParams, 1, &keystore);
        builder.AddTransparentInput(COutPoint(), scriptPubKey, 25000);
        EXPECT_EQ("Could not determine change address", builder.Build().GetError());
    }

    // Change to the same address as the first Sapling spend
    {
        auto builder = TransactionBuilder(consensusParams, 1, &keystore);
        builder.AddTransparentInput(COutPoint(), scriptPubKey, 25000);
        builder.AddSaplingSpend(expsk, testNote.note, testNote.tree.root(), testNote.tree.witness());
        auto tx = builder.Build().GetTxOrThrow();

        EXPECT_EQ(tx.vin.size(), 1);
        EXPECT_EQ(tx.vout.size(), 0);
        EXPECT_EQ(tx.vjoinsplit.size(), 0);
        EXPECT_EQ(tx.vShieldedSpend.size(), 1);
        EXPECT_EQ(tx.vShieldedOutput.size(), 1);
        EXPECT_EQ(tx.valueBalance, -15000);
    }

    // Change to a Sapling address
    {
        auto builder = TransactionBuilder(consensusParams, 1, &keystore);
        builder.AddTransparentInput(COutPoint(), scriptPubKey, 25000);
        builder.SendChangeTo(zChangeAddr, fvkOut.ovk);
        auto tx = builder.Build().GetTxOrThrow();

        EXPECT_EQ(tx.vin.size(), 1);
        EXPECT_EQ(tx.vout.size(), 0);
        EXPECT_EQ(tx.vjoinsplit.size(), 0);
        EXPECT_EQ(tx.vShieldedSpend.size(), 0);
        EXPECT_EQ(tx.vShieldedOutput.size(), 1);
        EXPECT_EQ(tx.valueBalance, -15000);
    }

    // Change to a transparent address
    {
        auto builder = TransactionBuilder(consensusParams, 1, &keystore);
        builder.AddTransparentInput(COutPoint(), scriptPubKey, 25000);
        builder.SendChangeTo(taddr);
        auto tx = builder.Build().GetTxOrThrow();

        EXPECT_EQ(tx.vin.size(), 1);
        EXPECT_EQ(tx.vout.size(), 1);
        EXPECT_EQ(tx.vjoinsplit.size(), 0);
        EXPECT_EQ(tx.vShieldedSpend.size(), 0);
        EXPECT_EQ(tx.vShieldedOutput.size(), 0);
        EXPECT_EQ(tx.valueBalance, 0);
        EXPECT_EQ(tx.vout[0].nValue, 15000);
    }

    // Revert to default
    RegtestDeactivateSapling();
}

TEST(TransactionBuilder, SetFee)
{
    auto consensusParams = RegtestActivateSapling();

    // Generate dummy Sapling address
    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto fvk = sk.full_viewing_key();
    auto pa = sk.default_address();

    auto testNote = GetTestSaplingNote(pa, 50000);

    // Default fee
    {
        auto builder = TransactionBuilder(consensusParams, 1);
        builder.AddSaplingSpend(expsk, testNote.note, testNote.tree.root(), testNote.tree.witness());
        builder.AddSaplingOutput(fvk.ovk, pa, 25000, {});
        auto tx = builder.Build().GetTxOrThrow();

        EXPECT_EQ(tx.vin.size(), 0);
        EXPECT_EQ(tx.vout.size(), 0);
        EXPECT_EQ(tx.vjoinsplit.size(), 0);
        EXPECT_EQ(tx.vShieldedSpend.size(), 1);
        EXPECT_EQ(tx.vShieldedOutput.size(), 2);
        EXPECT_EQ(tx.valueBalance, 10000);
    }

    // Configured fee
    {
        auto builder = TransactionBuilder(consensusParams, 1);
        builder.AddSaplingSpend(expsk, testNote.note, testNote.tree.root(), testNote.tree.witness());
        builder.AddSaplingOutput(fvk.ovk, pa, 25000, {});
        builder.SetFee(20000);
        auto tx = builder.Build().GetTxOrThrow();

        EXPECT_EQ(tx.vin.size(), 0);
        EXPECT_EQ(tx.vout.size(), 0);
        EXPECT_EQ(tx.vjoinsplit.size(), 0);
        EXPECT_EQ(tx.vShieldedSpend.size(), 1);
        EXPECT_EQ(tx.vShieldedOutput.size(), 2);
        EXPECT_EQ(tx.valueBalance, 20000);
    }

    // Revert to default
    RegtestDeactivateSapling();
}

TEST(TransactionBuilder, CheckSaplingTxVersion)
{
    SelectParams(CBaseChainParams::REGTEST);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, Consensus::NetworkUpgrade::ALWAYS_ACTIVE);
    auto consensusParams = Params().GetConsensus();

    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto pk = sk.default_address();

    // Cannot add Sapling outputs to a non-Sapling transaction
    auto builder = TransactionBuilder(consensusParams, 1);
    try {
        builder.AddSaplingOutput(uint256(), pk, 12345, {});
    } catch (std::runtime_error const & err) {
        EXPECT_EQ(err.what(), std::string("TransactionBuilder cannot add Sapling output to pre-Sapling transaction"));
    } catch(...) {
        FAIL() << "Expected std::runtime_error";
    }

    // Cannot add Sapling spends to a non-Sapling transaction
    libzcash::SaplingNote note(pk, 50000);
    SaplingMerkleTree tree;
    try {
        builder.AddSaplingSpend(expsk, note, uint256(), tree.witness());
    } catch (std::runtime_error const & err) {
        EXPECT_EQ(err.what(), std::string("TransactionBuilder cannot add Sapling spend to pre-Sapling transaction"));
    } catch(...) {
        FAIL() << "Expected std::runtime_error";
    }

    // Revert to default
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
}

// The builder's proofs and signatures are verified by the consensus path, and
// corruptions of the finished transaction are rejected by it.
TEST(TransactionBuilder, BuiltProofsVerifyAndCorruptionsAreRejected)
{
    auto consensusParams = RegtestActivateSapling();

    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto fvk = sk.full_viewing_key();
    auto pa = sk.default_address();
    auto testNote = GetTestSaplingNote(pa, 50000);

    // 0.0005 z-ZEC in, 0.00025 z-ZEC out, 0.0001 fee, 0.00015 z-ZEC change:
    // one spend proof, two output proofs, one spendAuthSig, one bindingSig.
    auto builder = TransactionBuilder(consensusParams, 1);
    builder.AddSaplingSpend(expsk, testNote.note, testNote.tree.root(), testNote.tree.witness());
    builder.AddSaplingOutput(fvk.ovk, pa, 25000, {});
    auto tx = builder.Build().GetTxOrThrow();
    ASSERT_EQ(tx.vShieldedSpend.size(), 1);
    ASSERT_EQ(tx.vShieldedOutput.size(), 2);

    std::string reason;
    EXPECT_TRUE(SaplingConsensusCheck(tx, 2, reason));
    EXPECT_EQ(reason, "");

    // The same corrupted transaction is waved through unverified under the IBD
    // predicate; this is the hole the checks above and below close for this test.
    {
        CMutableTransaction mtx(tx);
        mtx.vShieldedSpend[0].zkproof[100] ^= 0x01;
        CValidationState state;
        EXPECT_TRUE(ContextualCheckTransaction(CTransaction(mtx), state, 2, 100, []() { return true; }));
    }

    // bindingSig and spendAuthSig are not covered by the sighash. A flipped bit
    // in the bindingSig leaves every description valid and must fail the final
    // check; a flipped bit in the spendAuthSig is a spend description failure.
    for (size_t off : {0, 31, 32, 63}) {
        CMutableTransaction mtx(tx);
        mtx.bindingSig[off] ^= 0x01;
        EXPECT_FALSE(SaplingConsensusCheck(CTransaction(mtx), 2, reason)) << "bindingSig byte " << off;
        EXPECT_EQ(reason, "bad-txns-sapling-binding-signature-invalid");
    }
    for (size_t off : {0, 31, 32, 63}) {
        CMutableTransaction mtx(tx);
        mtx.vShieldedSpend[0].spendAuthSig[off] ^= 0x01;
        EXPECT_FALSE(SaplingConsensusCheck(CTransaction(mtx), 2, reason)) << "spendAuthSig byte " << off;
        EXPECT_EQ(reason, "bad-txns-sapling-spend-description-invalid");
    }

    // Everything else is covered by the sighash, so any change to the finished
    // transaction is rejected, the first failing element being the spendAuthSig.
    // (HandBuiltAndResigned below isolates the proofs, anchor and valueBalance.)
    for (size_t off : {5, 100, 170}) {
        CMutableTransaction mtx(tx);
        mtx.vShieldedSpend[0].zkproof[off] ^= 0x01;
        EXPECT_FALSE(SaplingConsensusCheck(CTransaction(mtx), 2, reason)) << "spend proof byte " << off;
        EXPECT_EQ(reason, "bad-txns-sapling-spend-description-invalid");
    }
    for (size_t i = 0; i < 2; i++) {
        CMutableTransaction mtx(tx);
        mtx.vShieldedOutput[i].zkproof[100] ^= 0x01;
        EXPECT_FALSE(SaplingConsensusCheck(CTransaction(mtx), 2, reason)) << "output " << i;
        EXPECT_EQ(reason, "bad-txns-sapling-spend-description-invalid");
    }
    {
        CMutableTransaction mtx(tx);
        mtx.vShieldedSpend[0].anchor = uint256S("01");
        EXPECT_FALSE(SaplingConsensusCheck(CTransaction(mtx), 2, reason));
        EXPECT_EQ(reason, "bad-txns-sapling-spend-description-invalid");
    }
    {
        CMutableTransaction mtx(tx);
        mtx.valueBalance += 1;
        EXPECT_FALSE(SaplingConsensusCheck(CTransaction(mtx), 2, reason));
        EXPECT_EQ(reason, "bad-txns-sapling-spend-description-invalid");
    }

    RegtestDeactivateSapling();
}

// Flipped proof byte, wrong anchor and wrong valueBalance, with the spend
// authorization re-signed over the final sighash, so that the only thing that
// can fail is the spend proof, the output proof, or the binding signature.
TEST(TransactionBuilder, HandBuiltAndResignedCorruptionsAreRejected)
{
    auto consensusParams = RegtestActivateSapling();

    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto pa = sk.default_address();
    auto testNote = GetTestSaplingNote(pa, 50000);
    std::string reason;

    HandBuiltSapling hb(consensusParams, 1, expsk, testNote.note, testNote.tree, pa, 30000);

    // Control: untouched, it is accepted, so the rejections are not artefacts.
    {
        auto tx = hb.Finish([](CMutableTransaction&) {});
        ASSERT_EQ(tx.vShieldedSpend.size(), 1);
        ASSERT_EQ(tx.vShieldedOutput.size(), 1);
        EXPECT_EQ(tx.valueBalance, 20000);
        EXPECT_TRUE(SaplingConsensusCheck(tx, 2, reason));
        EXPECT_EQ(reason, "");
    }

    // Spend proof: one flipped bit in each group element (A: bytes 0-47,
    // B: 48-143, C: 144-191). Signatures are valid for the mutated transaction.
    for (size_t off : {5, 100, 170}) {
        auto tx = hb.Finish([off](CMutableTransaction& m) { m.vShieldedSpend[0].zkproof[off] ^= 0x01; });
        EXPECT_FALSE(SaplingConsensusCheck(tx, 2, reason)) << "spend proof byte " << off;
        EXPECT_EQ(reason, "bad-txns-sapling-spend-description-invalid");
    }

    // Output proof: the spend description is valid, so the reject reason names
    // the output.
    for (size_t off : {5, 100, 170}) {
        auto tx = hb.Finish([off](CMutableTransaction& m) { m.vShieldedOutput[0].zkproof[off] ^= 0x01; });
        EXPECT_FALSE(SaplingConsensusCheck(tx, 2, reason)) << "output proof byte " << off;
        EXPECT_EQ(reason, "bad-txns-sapling-output-description-invalid");
    }

    // Wrong anchor: a different, well-formed tree root (the root after one more
    // commitment). The spend proof was made for the real root.
    {
        SaplingMerkleTree other = testNote.tree;
        other.append(testNote.note.cm().get());
        uint256 wrongAnchor = other.root();
        ASSERT_NE(wrongAnchor, testNote.tree.root());
        auto tx = hb.Finish([wrongAnchor](CMutableTransaction& m) { m.vShieldedSpend[0].anchor = wrongAnchor; });
        EXPECT_FALSE(SaplingConsensusCheck(tx, 2, reason));
        EXPECT_EQ(reason, "bad-txns-sapling-spend-description-invalid");
    }

    // Wrong valueBalance: the transaction claims one zatoshi more / less than
    // the value commitments balance to. Both descriptions stay valid; the
    // binding signature (made for the honest balance) must not verify.
    for (CAmount delta : {1, -1}) {
        auto tx = hb.Finish([delta](CMutableTransaction& m) { m.valueBalance += delta; });
        EXPECT_EQ(tx.valueBalance, 20000 + delta);
        EXPECT_FALSE(SaplingConsensusCheck(tx, 2, reason)) << "delta " << delta;
        EXPECT_EQ(reason, "bad-txns-sapling-binding-signature-invalid");
    }

    RegtestDeactivateSapling();
}

// Proofs of one transaction are made by several workers at once, each on its
// own proving context, and the contexts are merged before the binding
// signature. This builds transactions of every shape the worker split treats
// differently (several spends, a lone spend with many outputs, outputs only)
// under several thread budgets, and requires each to pass full consensus
// verification (every proof and the binding signature), keep the order of its
// descriptions, and decrypt to the amounts that were asked for.
namespace {
struct ManySpends {
    std::vector<libzcash::SaplingNote> notes;
    std::vector<SaplingWitness> witnesses;
    uint256 anchor;
};

ManySpends MakeManySpends(const libzcash::SaplingPaymentAddress& pa, size_t n, CAmount each)
{
    ManySpends m;
    SaplingMerkleTree tree;
    for (size_t i = 0; i < n; i++) {
        libzcash::SaplingNote note(pa, each + CAmount(i));
        tree.append(note.cm().get());
        for (auto& w : m.witnesses) {
            w.append(note.cm().get());
        }
        m.notes.push_back(note);
        m.witnesses.push_back(tree.witness());
    }
    m.anchor = tree.root();
    return m;
}
} // namespace

TEST(TransactionBuilder, ConcurrentProofsVerifyForEveryShapeAndBudget)
{
    auto consensusParams = RegtestActivateSapling();

    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto fvk = sk.full_viewing_key();
    auto ivk = fvk.in_viewing_key();
    auto pa = sk.default_address();
    auto other = libzcash::SaplingSpendingKey::random().default_address();

    struct Shape { size_t spends, outputs; };
    const Shape shapes[] = {{1, 6}, {3, 1}, {5, 4}};
    for (unsigned budget : {1u, 8u}) {
        zcl_c23_set_prover_threads(budget);
        for (const Shape& s : shapes) {
            SCOPED_TRACE(testing::Message() << "budget " << budget << " spends " << s.spends << " outputs " << s.outputs);
            const CAmount each = 100000;
            auto many = MakeManySpends(pa, s.spends, each);
            CAmount in = 0;
            for (auto& n : many.notes) in += n.value();

            auto builder = TransactionBuilder(consensusParams, 1);
            builder.SetFee(10000);
            for (size_t i = 0; i < s.spends; i++) {
                builder.AddSaplingSpend(expsk, many.notes[i], many.anchor, many.witnesses[i]);
            }
            CAmount sent = 0;
            for (size_t j = 0; j < s.outputs; j++) {
                CAmount v = 1000 * CAmount(j + 1);
                builder.AddSaplingOutput(fvk.ovk, other, v, {});
                sent += v;
            }
            auto tx = builder.Build().GetTxOrThrow();

            ASSERT_EQ(tx.vShieldedSpend.size(), s.spends);
            ASSERT_EQ(tx.vShieldedOutput.size(), s.outputs + 1); // + change to the first spend's address
            EXPECT_EQ(tx.valueBalance, 10000);

            std::string reason;
            EXPECT_TRUE(SaplingConsensusCheck(tx, 2, reason)) << reason;
            EXPECT_EQ(reason, "");

            // Spends keep their order: nullifier i belongs to note i.
            for (size_t i = 0; i < s.spends; i++) {
                auto nf = many.notes[i].nullifier(fvk, many.witnesses[i].position());
                ASSERT_TRUE(static_cast<bool>(nf));
                EXPECT_EQ(tx.vShieldedSpend[i].nullifier, *nf);
            }
            // Outputs keep their order: output j opens to the j-th amount for
            // the recipient, the last one is the change to us.
            for (size_t j = 0; j < s.outputs; j++) {
                auto pt = libzcash::SaplingNotePlaintext::decrypt(
                    tx.vShieldedOutput[j].encCiphertext,
                    libzcash::SaplingSpendingKey::random().full_viewing_key().in_viewing_key(),
                    tx.vShieldedOutput[j].ephemeralKey, tx.vShieldedOutput[j].cm);
                EXPECT_FALSE(static_cast<bool>(pt)); // not decryptable by a stranger
            }
            auto change = libzcash::SaplingNotePlaintext::decrypt(
                tx.vShieldedOutput[s.outputs].encCiphertext, ivk,
                tx.vShieldedOutput[s.outputs].ephemeralKey, tx.vShieldedOutput[s.outputs].cm);
            ASSERT_TRUE(static_cast<bool>(change));
            EXPECT_EQ(CAmount(change.get().value()), in - sent - 10000);
        }
    }
    zcl_c23_set_prover_threads(0);

    RegtestDeactivateSapling();
}

// Outputs only (a transparent input shielded to several recipients) takes the
// output-only worker split.
TEST(TransactionBuilder, ConcurrentOutputProofsVerify)
{
    auto consensusParams = RegtestActivateSapling();

    CBasicKeyStore keyStore;
    CKey tsk = AddTestCKeyToKeyStore(keyStore);
    auto scriptPubKey = GetScriptForDestination(tsk.GetPubKey().GetID());
    auto sk = libzcash::SaplingSpendingKey::random();
    auto fvk = sk.full_viewing_key();
    auto pa = sk.default_address();

    for (unsigned budget : {1u, 8u}) {
        zcl_c23_set_prover_threads(budget);
        SCOPED_TRACE(testing::Message() << "budget " << budget);
        auto builder = TransactionBuilder(consensusParams, 1, &keyStore);
        builder.SetFee(10000);
        builder.AddTransparentInput(COutPoint(), scriptPubKey, 100000);
        builder.SendChangeTo(pa, fvk.ovk);
        builder.AddSaplingOutput(fvk.ovk, pa, 20000, {});
        builder.AddSaplingOutput(fvk.ovk, pa, 30000, {});
        builder.AddSaplingOutput(fvk.ovk, pa, 10000, {});
        auto tx = builder.Build().GetTxOrThrow();
        ASSERT_EQ(tx.vShieldedSpend.size(), 0);
        ASSERT_EQ(tx.vShieldedOutput.size(), 4); // three payments + change
        EXPECT_EQ(tx.valueBalance, -90000);
        std::string reason;
        EXPECT_TRUE(SaplingConsensusCheck(tx, 2, reason)) << reason;
        EXPECT_EQ(reason, "");
    }
    zcl_c23_set_prover_threads(0);

    RegtestDeactivateSapling();
}
