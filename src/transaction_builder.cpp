// Copyright (c) 2018 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transaction_builder.h"

#include "main.h"
#include "pubkey.h"
#include "rpc/protocol.h"
#include "script/sign.h"

#include <boost/variant.hpp>
#include <librustzcash.h>

#include <algorithm>
#include <atomic>
#include <system_error>
#include <thread>
#include <vector>

SpendDescriptionInfo::SpendDescriptionInfo(
    libzcash::SaplingExpandedSpendingKey expsk,
    libzcash::SaplingNote note,
    uint256 anchor,
    SaplingWitness witness) : expsk(expsk), note(note), anchor(anchor), witness(witness)
{
    librustzcash_sapling_generate_r(alpha.begin());
}

TransactionBuilderResult::TransactionBuilderResult(const CTransaction& tx) : maybeTx(tx) {}

TransactionBuilderResult::TransactionBuilderResult(const std::string& error) : maybeError(error) {}

bool TransactionBuilderResult::IsTx() { return maybeTx != boost::none; }

bool TransactionBuilderResult::IsError() { return maybeError != boost::none; }

CTransaction TransactionBuilderResult::GetTxOrThrow() {
    if (maybeTx) {
        return maybeTx.get();
    } else {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build transaction: " + GetError());
    }
}

std::string TransactionBuilderResult::GetError() {
    if (maybeError) {
        return maybeError.get();
    } else {
        // This can only happen if isTx() is true in which case we should not call getError()
        throw std::runtime_error("getError() was called in TransactionBuilderResult, but the result was not initialized as an error.");
    }
}

TransactionBuilder::TransactionBuilder(
    const Consensus::Params& consensusParams,
    int nHeight,
    CKeyStore* keystore) : consensusParams(consensusParams), nHeight(nHeight), keystore(keystore)
{
    mtx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);
}

void TransactionBuilder::SetExpiryHeight(uint32_t nExpiryHeight)
{
    if (nExpiryHeight < nHeight || nExpiryHeight <= 0 || nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD) {
        throw std::runtime_error("TransactionBuilder::SetExpiryHeight: invalid expiry height");
    }
    mtx.nExpiryHeight = nExpiryHeight;
}

void TransactionBuilder::AddSaplingSpend(
    libzcash::SaplingExpandedSpendingKey expsk,
    libzcash::SaplingNote note,
    uint256 anchor,
    SaplingWitness witness)
{
    // Sanity check: cannot add Sapling spend to pre-Sapling transaction
    if (mtx.nVersion < SAPLING_TX_VERSION) {
        throw std::runtime_error("TransactionBuilder cannot add Sapling spend to pre-Sapling transaction");
    }

    // Consistency check: all anchors must equal the first one
    if (spends.size() > 0 && spends[0].anchor != anchor) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Anchor does not match previously-added Sapling spends.");
    }

    spends.emplace_back(expsk, note, anchor, witness);
    mtx.valueBalance += note.value();
}

void TransactionBuilder::AddSaplingOutput(
    uint256 ovk,
    libzcash::SaplingPaymentAddress to,
    CAmount value,
    std::array<unsigned char, ZC_MEMO_SIZE> memo)
{
    // Sanity check: cannot add Sapling output to pre-Sapling transaction
    if (mtx.nVersion < SAPLING_TX_VERSION) {
        throw std::runtime_error("TransactionBuilder cannot add Sapling output to pre-Sapling transaction");
    }

    auto note = libzcash::SaplingNote(to, value);
    outputs.emplace_back(ovk, note, memo);
    mtx.valueBalance -= value;
}

void TransactionBuilder::AddTransparentInput(COutPoint utxo, CScript scriptPubKey, CAmount value)
{
    if (keystore == nullptr) {
        throw std::runtime_error("Cannot add transparent inputs to a TransactionBuilder without a keystore");
    }

    mtx.vin.emplace_back(utxo);
    tIns.emplace_back(scriptPubKey, value);
}

void TransactionBuilder::AddTransparentOutput(CTxDestination& to, CAmount value)
{
    if (!IsValidDestination(to)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid output address, not a valid taddr.");
    }

    CScript scriptPubKey = GetScriptForDestination(to);
    CTxOut out(value, scriptPubKey);
    mtx.vout.push_back(out);
}

void TransactionBuilder::SetFee(CAmount fee)
{
    this->fee = fee;
}

void TransactionBuilder::SendChangeTo(libzcash::SaplingPaymentAddress changeAddr, uint256 ovk)
{
    zChangeAddr = std::make_pair(ovk, changeAddr);
    tChangeAddr = boost::none;
}

void TransactionBuilder::SendChangeTo(CTxDestination& changeAddr)
{
    if (!IsValidDestination(changeAddr)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid change address, not a valid taddr.");
    }

    tChangeAddr = changeAddr;
    zChangeAddr = boost::none;
}

namespace {

// A proof job is not yet made, made, or failed. A worker that stops early after
// another proof failed leaves its jobs kNotProved, so the reported failure is
// always one that really happened.
enum { kNotProved = 0, kProved = 1, kProofFailed = 2 };

struct SpendProofJob {
    const SpendDescriptionInfo* info = nullptr;
    std::vector<unsigned char> witness;
    SpendDescription sdesc;
    int state = kNotProved;
};

struct OutputProofJob {
    const OutputDescriptionInfo* info = nullptr;
    boost::optional<libzcash::SaplingNotePlaintextEncryptionResult> enc;
    OutputDescription odesc;
    int state = kNotProved;
};

bool ProveSpend(void* ctx, SpendProofJob& job)
{
    const SpendDescriptionInfo& spend = *job.info;
    return librustzcash_sapling_spend_proof(
        ctx,
        spend.expsk.full_viewing_key().ak.begin(),
        spend.expsk.nsk.begin(),
        spend.note.d.data(),
        spend.note.r.begin(),
        spend.alpha.begin(),
        spend.note.value(),
        spend.anchor.begin(),
        job.witness.data(),
        job.sdesc.cv.begin(),
        job.sdesc.rk.begin(),
        job.sdesc.zkproof.data());
}

bool ProveOutput(void* ctx, OutputProofJob& job)
{
    const OutputDescriptionInfo& output = *job.info;
    auto& encryptor = job.enc.get().second;
    return librustzcash_sapling_output_proof(
        ctx,
        encryptor.get_esk().begin(),
        output.note.d.data(),
        output.note.pk_d.begin(),
        output.note.r.begin(),
        output.note.value(),
        job.odesc.cv.begin(),
        job.odesc.zkproof.begin());
}

/**
 * Makes every spend and output proof, setting each job's `ok`, and folds the
 * value-commitment accumulators of all of them into `ctx`.
 *
 * The proofs run on a few workers at once. The prover thread budget is divided
 * among the workers for the duration, so the total thread count stays what
 * -proverthreads asked for. Measured on 8 threads: one proof alone scales to
 * only about 4.5x (its circuit synthesis is single threaded), and the best
 * split is about two threads per proof (budget / 2 workers), whether the
 * transaction has 20 spends or 50 outputs. The spend proof (about 7 outputs
 * long) is the critical path, so one spend with a couple of outputs stays on
 * this thread with the whole budget, and a lone spend with many outputs gets
 * one worker for the spend and one for the outputs. A budget below four, or a
 * transaction with nothing to overlap, is made on this thread on `ctx` itself.
 */
size_t ProofWorkers(size_t nSpends, size_t nOutputs, size_t budget)
{
    size_t want = nSpends > 0 ? nSpends + (nOutputs > 3 ? 1 : 0) : nOutputs;
    return std::min(want, budget / 2);
}

void ProveSaplingDescriptions(void* ctx, std::vector<SpendProofJob>& spendJobs, std::vector<OutputProofJob>& outputJobs)
{
    const size_t nSpends = spendJobs.size();
    const size_t nTasks = nSpends + outputJobs.size();
    const size_t nWorkers = ProofWorkers(nSpends, outputJobs.size(), zcl_c23_prover_budget());

    auto runTask = [&](void* wctx, size_t t) {
        if (t < nSpends) {
            spendJobs[t].state = ProveSpend(wctx, spendJobs[t]) ? kProved : kProofFailed;
        } else {
            OutputProofJob& job = outputJobs[t - nSpends];
            job.state = ProveOutput(wctx, job) ? kProved : kProofFailed;
        }
    };

    if (nWorkers <= 1) {
        for (size_t t = 0; t < nTasks; t++) {
            runTask(ctx, t);
            if ((t < nSpends ? spendJobs[t].state : outputJobs[t - nSpends].state) != kProved) {
                break; // the first failure ends the build, as it always has
            }
        }
        return;
    }

    struct BudgetSplit {
        explicit BudgetSplit(unsigned workers) { zcl_c23_prover_budget_enter(workers); }
        ~BudgetSplit() { zcl_c23_prover_budget_leave(); }
    } split(nWorkers);

    std::atomic<size_t> next(0);
    std::atomic<bool> failed(false);
    std::vector<void*> workerCtx(nWorkers, nullptr);
    auto worker = [&](size_t w) {
        try {
            workerCtx[w] = librustzcash_sapling_proving_ctx_init();
            for (;;) {
                size_t t = next.fetch_add(1);
                if (t >= nTasks || failed.load()) {
                    break;
                }
                runTask(workerCtx[w], t);
                bool ok = (t < nSpends ? spendJobs[t].state : outputJobs[t - nSpends].state) == kProved;
                if (!ok) {
                    failed.store(true);
                }
            }
        } catch (...) {
            failed.store(true);
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(nWorkers - 1);
    for (size_t w = 1; w < nWorkers; w++) {
        try {
            threads.emplace_back(worker, w);
        } catch (const std::system_error&) {
            // Could not start a thread: the others take its share.
            workerCtx[w] = nullptr;
        }
    }
    worker(0);
    for (std::thread& th : threads) {
        th.join();
    }

    for (void* wctx : workerCtx) {
        if (wctx) {
            zcl_c23_sapling_proving_ctx_merge(ctx, wctx);
            librustzcash_sapling_proving_ctx_free(wctx);
        }
    }
}

} // namespace

TransactionBuilderResult TransactionBuilder::Build()
{
    //
    // Consistency checks
    //

    // Valid change
    CAmount change = mtx.valueBalance - fee;
    for (auto tIn : tIns) {
        change += tIn.value;
    }
    for (auto tOut : mtx.vout) {
        change -= tOut.nValue;
    }
    if (change < 0) {
        return TransactionBuilderResult("Change cannot be negative");
    }

    //
    // Change output
    //

    if (change > 0) {
        // Send change to the specified change address. If no change address
        // was set, send change to the first Sapling address given as input.
        if (zChangeAddr) {
            AddSaplingOutput(zChangeAddr->first, zChangeAddr->second, change);
        } else if (tChangeAddr) {
            // tChangeAddr has already been validated.
            AddTransparentOutput(tChangeAddr.value(), change);
        } else if (!spends.empty()) {
            auto fvk = spends[0].expsk.full_viewing_key();
            auto note = spends[0].note;
            libzcash::SaplingPaymentAddress changeAddr(note.d, note.pk_d);
            AddSaplingOutput(fvk.ovk, changeAddr, change);
        } else {
            return TransactionBuilderResult("Could not determine change address");
        }
    }
    //
    // Sapling spends and outputs
    //
    // Everything that needs no proof is prepared here, in order, on this
    // thread. The Groth16 proofs are the cost (about 0.6 s per spend and 0.09 s
    // per output) and are independent of each other, so they are made by a few
    // workers at once, each on its own proving context that is merged into the
    // transaction's context afterwards. The descriptions are appended in the
    // original order.
    //

    std::vector<SpendProofJob> spendJobs(spends.size());
    for (size_t i = 0; i < spends.size(); i++) {
        const SpendDescriptionInfo& spend = spends[i];
        auto cm = spend.note.cm();
        auto nf = spend.note.nullifier(
            spend.expsk.full_viewing_key(), spend.witness.position());
        if (!cm || !nf) {
            return TransactionBuilderResult("Spend is invalid");
        }

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << spend.witness.path();
        spendJobs[i].info = &spend;
        spendJobs[i].witness.assign(ss.begin(), ss.end());
        spendJobs[i].sdesc.anchor = spend.anchor;
        spendJobs[i].sdesc.nullifier = *nf;
    }

    std::vector<OutputProofJob> outputJobs(outputs.size());
    for (size_t i = 0; i < outputs.size(); i++) {
        const OutputDescriptionInfo& output = outputs[i];
        auto cm = output.note.cm();
        if (!cm) {
            return TransactionBuilderResult("Output is invalid");
        }

        libzcash::SaplingNotePlaintext notePlaintext(output.note, output.memo);

        auto res = notePlaintext.encrypt(output.note.pk_d);
        if (!res) {
            return TransactionBuilderResult("Failed to encrypt note");
        }
        outputJobs[i].info = &output;
        outputJobs[i].enc = res;
        outputJobs[i].odesc.cm = *cm;
    }

    auto ctx = librustzcash_sapling_proving_ctx_init();
    ProveSaplingDescriptions(ctx, spendJobs, outputJobs);
    for (const SpendProofJob& job : spendJobs) {
        if (job.state == kProofFailed) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Spend proof failed");
        }
    }
    for (const OutputProofJob& job : outputJobs) {
        if (job.state == kProofFailed) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Output proof failed");
        }
    }
    // A job still unproved here means a worker died before reaching it; never
    // build a transaction around a default-constructed description.
    for (const SpendProofJob& job : spendJobs) {
        if (job.state != kProved) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Spend proof failed");
        }
    }
    for (const OutputProofJob& job : outputJobs) {
        if (job.state != kProved) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Output proof failed");
        }
    }

    for (const SpendProofJob& job : spendJobs) {
        mtx.vShieldedSpend.push_back(job.sdesc);
    }
    for (OutputProofJob& job : outputJobs) {
        const OutputDescriptionInfo& output = *job.info;
        OutputDescription& odesc = job.odesc;
        auto enc = job.enc.get();
        auto encryptor = enc.second;

        odesc.ephemeralKey = encryptor.get_epk();
        odesc.encCiphertext = enc.first;

        libzcash::SaplingOutgoingPlaintext outPlaintext(output.note.pk_d, encryptor.get_esk());
        odesc.outCiphertext = outPlaintext.encrypt(
            output.ovk,
            odesc.cv,
            odesc.cm,
            encryptor);
        mtx.vShieldedOutput.push_back(odesc);
    }

    //
    // Signatures
    //

    auto consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);

    // Empty output script.
    uint256 dataToBeSigned;
    CScript scriptCode;
    try {
        dataToBeSigned = SignatureHash(scriptCode, mtx, NOT_AN_INPUT, SigHashType(), 0, consensusBranchId);
    } catch (std::logic_error ex) {
        librustzcash_sapling_proving_ctx_free(ctx);
        return TransactionBuilderResult("Could not construct signature hash: " + std::string(ex.what()));
    }

    // Create Sapling spendAuth and binding signatures
    for (size_t i = 0; i < spends.size(); i++) {
        librustzcash_sapling_spend_sig(
            spends[i].expsk.ask.begin(),
            spends[i].alpha.begin(),
            dataToBeSigned.begin(),
            mtx.vShieldedSpend[i].spendAuthSig.data());
    }
    librustzcash_sapling_binding_sig(
        ctx,
        mtx.valueBalance,
        dataToBeSigned.begin(),
        mtx.bindingSig.data());

    librustzcash_sapling_proving_ctx_free(ctx);

    // Transparent signatures
    CTransaction txNewConst(mtx);
    for (int nIn = 0; nIn < mtx.vin.size(); nIn++) {
        auto tIn = tIns[nIn];
        SignatureData sigdata;
        bool signSuccess = ProduceSignature(
            TransactionSignatureCreator(
                keystore, &txNewConst, nIn, tIn.value, SigHashType()),
            tIn.scriptPubKey, sigdata, consensusBranchId);

        if (!signSuccess) {
            return TransactionBuilderResult("Failed to sign transaction");
        } else {
            UpdateTransaction(mtx, nIn, sigdata);
        }
    }

    return TransactionBuilderResult(CTransaction(mtx));
}
