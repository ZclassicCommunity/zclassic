// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "asyncrpcoperation_senddatafile.h"
#include "asyncrpcqueue.h"
#include "amount.h"
#include "consensus/consensus.h"
#include "core_io.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "miner.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"

#include <array>
#include <string>

using namespace libzcash;

extern UniValue sendrawtransaction(const UniValue& params, bool fHelp);

// Each ZDC1 frame output carries a tiny "data dust" value. This is conceptual
// dust the sender pays to themselves (the from z-addr is also the data
// recipient in the common case); change returns to the from z-addr. We keep it
// well above the network dust threshold but small.
static const CAmount SENDDATAFILE_OUTPUT_VALUE = 1000; // 0.00001 ZCL per frame

// ── Exact on-wire sizes for the single-tx broadcastability guard ─────────────
// These match primitives/transaction.h byte-for-byte; if a struct changes, the
// guard stays correct because it is conservative (over-estimates, never under).
//   SpendDescription  = cv32 + anchor32 + nullifier32 + rk32 + zkproof192 +
//                       spendAuthSig64                                   = 384
//   OutputDescription = cv32 + cm32 + ephemeralKey32 + encCiphertext580 +
//                       outCiphertext80 + zkproof192                     = 948
// Envelope: header4 + nVersionGroupId4 + locktime4 + expiryHeight4 +
//   valueBalance8 + bindingSig64 + a generous slab for the three count
//   varints, the empty vin/vout/vJoinSplit vectors, and serialization slack.
static const size_t ZDC_SPEND_DESC_BYTES   = 384;
static const size_t ZDC_OUTPUT_DESC_BYTES  = 948;
static const size_t ZDC_TX_ENVELOPE_BYTES  = 256;  // conservative fixed overhead

// Conservatively project the serialized tx size for nSpends shielded inputs and
// nOutputs shielded outputs (data frames + the 1 change output). Over-estimates.
static size_t ZdcProjectedTxSize(size_t nSpends, size_t nOutputs) {
    return ZDC_TX_ENVELOPE_BYTES
         + nSpends  * ZDC_SPEND_DESC_BYTES
         + nOutputs * ZDC_OUTPUT_DESC_BYTES;
}

AsyncRPCOperation_senddatafile::AsyncRPCOperation_senddatafile(
        TransactionBuilder builder,
        CMutableTransaction contextualTx,
        std::string fromAddress,
        std::string toAddress,
        std::vector<std::vector<unsigned char> > frames,
        uint64_t transferId,
        std::string fingerprintHex,
        int minDepth,
        CAmount fee,
        UniValue contextInfo) :
        fee_(fee), mindepth_(minDepth), fromaddress_(fromAddress), toaddress_(toAddress),
        frames_(frames), transferId_(transferId), fingerprintHex_(fingerprintHex),
        builder_(builder), contextinfo_(contextInfo)
{
    assert(fee_ >= 0);
    if (minDepth < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be negative");
    }
    if (minDepth == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be zero when sending from a zaddr");
    }
    if (fromAddress.size() == 0 || toAddress.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "From and to addresses are required");
    }
    if (frames_.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No data frames to send");
    }

    // Resolve and validate the FROM Sapling address + spending key. The key is
    // used only to spend/sign within the wallet; it is never exported.
    auto fromAddr = DecodePaymentAddress(fromAddress);
    if (!IsValidPaymentAddress(fromAddr) ||
        boost::get<libzcash::SaplingPaymentAddress>(&fromAddr) == nullptr) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
            "fromaddress must be a Sapling z-address (the data channel rides on Sapling memos)");
    }
    auto fromSapling = boost::get<libzcash::SaplingPaymentAddress>(fromAddr);
    if (!pwalletMain->GetSaplingExtendedSpendingKey(fromSapling, spendingKey_)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
            "No spending key found for fromaddress (cannot send a data file from a watch-only address)");
    }

    // Resolve and validate the TO Sapling address.
    auto toAddr = DecodePaymentAddress(toAddress);
    if (!IsValidPaymentAddress(toAddr) ||
        boost::get<libzcash::SaplingPaymentAddress>(&toAddr) == nullptr) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
            "toaddress must be a Sapling z-address");
    }
    toPaymentAddress_ = boost::get<libzcash::SaplingPaymentAddress>(toAddr);
}

AsyncRPCOperation_senddatafile::~AsyncRPCOperation_senddatafile() {
}

void AsyncRPCOperation_senddatafile::main() {
    if (isCancelled())
        return;

    set_state(OperationStatus::EXECUTING);
    start_execution_clock();

    bool success = false;

#ifdef ENABLE_MINING
    GenerateBitcoins(false, 0, Params());
#endif

    try {
        success = main_impl();
    } catch (const UniValue& objError) {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        set_error_code(code);
        set_error_message(message);
    } catch (const std::runtime_error& e) {
        set_error_code(-1);
        set_error_message("runtime error: " + std::string(e.what()));
    } catch (const std::logic_error& e) {
        set_error_code(-1);
        set_error_message("logic error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        set_error_code(-1);
        set_error_message("general exception: " + std::string(e.what()));
    } catch (...) {
        set_error_code(-2);
        set_error_message("unknown error");
    }

#ifdef ENABLE_MINING
    GenerateBitcoins(GetBoolArg("-gen", false), GetArg("-genproclimit", 1), Params());
#endif

    stop_execution_clock();

    if (success) {
        set_state(OperationStatus::SUCCESS);
    } else {
        set_state(OperationStatus::FAILED);
    }

    std::string s = strprintf("%s: z_senddatafile finished (status=%s", getId(), getStateAsString());
    if (success) {
        s += strprintf(", txid=%s)\n", tx_.GetHash().ToString());
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }
    LogPrintf("%s", s);
}

bool AsyncRPCOperation_senddatafile::find_unspent_notes(CAmount target) {
    std::vector<CSproutNotePlaintextEntry> sproutEntries;
    std::vector<SaplingNoteEntry> saplingEntries;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetFilteredNotes(sproutEntries, saplingEntries, fromaddress_, mindepth_);
    }

    // Sapling-only channel.
    for (auto& entry : saplingEntries) {
        z_sapling_inputs_.push_back(entry);
    }

    if (z_sapling_inputs_.empty()) {
        return false;
    }

    // Biggest notes first, to minimise the spend count.
    std::sort(z_sapling_inputs_.begin(), z_sapling_inputs_.end(),
        [](SaplingNoteEntry i, SaplingNoteEntry j) -> bool {
            return i.note.value() > j.note.value();
        });

    return true;
}

bool AsyncRPCOperation_senddatafile::main_impl() {
    // Each frame is one Sapling output carrying the 512-byte ZDC1 frame as its
    // memo. The total value we must fund = N * per-output value + fee.
    const size_t nFrames = frames_.size();
    CAmount sendAmount = (CAmount)nFrames * SENDDATAFILE_OUTPUT_VALUE;
    CAmount targetAmount = sendAmount + fee_;

    if (!find_unspent_notes(targetAmount)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            "Insufficient shielded funds: no spendable Sapling notes found for fromaddress");
    }

    // Derive the keys: expsk to spend, ovk (its own outgoing viewing key) so the
    // sender can later decrypt its own outputs (and so the from z-addr can read
    // the memos it sent — needed for z_getdatatransfer on the sender side).
    SaplingExpandedSpendingKey expsk = spendingKey_.expsk;
    uint256 ovk = expsk.full_viewing_key().ovk;

    // Select notes until we cover the target.
    std::vector<SaplingOutPoint> ops;
    std::vector<SaplingNote> notes;
    CAmount sum = 0;
    for (auto& t : z_sapling_inputs_) {
        ops.push_back(t.op);
        notes.push_back(t.note);
        sum += t.note.value();
        if (sum >= targetAmount) {
            break;
        }
    }
    if (sum < targetAmount) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient shielded funds: have %s, need %s (%u frames * %s + fee %s)",
                FormatMoney(sum), FormatMoney(targetAmount), (unsigned)nFrames,
                FormatMoney(SENDDATAFILE_OUTPUT_VALUE), FormatMoney(fee_)));
    }

    // Fetch the Sapling anchor + witnesses for the selected notes.
    uint256 anchor;
    std::vector<boost::optional<SaplingWitness>> witnesses;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetSaplingNoteWitnesses(ops, witnesses, anchor);
    }

    builder_.SetFee(fee_);

    // Add Sapling spends.
    for (size_t i = 0; i < notes.size(); i++) {
        if (!witnesses[i]) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Missing witness for Sapling note");
        }
        builder_.AddSaplingSpend(expsk, notes[i], anchor, witnesses[i].get());
    }

    // Change returns to the FROM z-addr (privacy-preserving: stays shielded).
    builder_.SendChangeTo(
        boost::get<libzcash::SaplingPaymentAddress>(DecodePaymentAddress(fromaddress_)), ovk);

    // Add one Sapling output per ZDC1 frame, all to the SAME recipient z-addr.
    // This is the whole reason z_sendmany cannot do it: it would reject the
    // duplicate recipient. Here the builder happily emits N outputs to one addr.
    for (size_t i = 0; i < frames_.size(); i++) {
        if (frames_[i].size() != ZC_MEMO_SIZE) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                strprintf("Internal: frame %u is not %u bytes", (unsigned)i, (unsigned)ZC_MEMO_SIZE));
        }
        std::array<unsigned char, ZC_MEMO_SIZE> memo;
        std::copy(frames_[i].begin(), frames_[i].end(), memo.begin());
        builder_.AddSaplingOutput(ovk, toPaymentAddress_, SENDDATAFILE_OUTPUT_VALUE, memo);
    }

    // SINGLE-TX BROADCASTABILITY GUARD (reject BEFORE proving, never after).
    //
    // The RPC layer already caps the file so the FRAME count fits one tx, but the
    // tx also carries one SpendDescription per selected input note plus a change
    // output. An unusual UTXO set (many small notes) could push an otherwise
    // in-cap transfer over MAX_TX_SIZE_AFTER_SAPLING. TransactionBuilder::Build()
    // does NOT check size — it would compute every Groth proof and only then fail
    // at AcceptToMemoryPool with an opaque "bad-txns-oversize". So we project the
    // serialized size from the ACTUAL spend + output counts here, conservatively,
    // and throw a clear actionable error if it would not broadcast — before any
    // proving work is done.
    {
        size_t nSpends  = notes.size();
        size_t nOutputs = frames_.size() + 1; // +1 for the change output to fromaddr
        size_t projected = ZdcProjectedTxSize(nSpends, nOutputs);
        if (projected > MAX_TX_SIZE_AFTER_SAPLING) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("transfer would not broadcast: projected tx size %u bytes "
                          "(%u input notes + %u outputs) exceeds the consensus limit "
                          "%u. Send a smaller file, or consolidate small notes first.",
                          (unsigned)projected, (unsigned)nSpends, (unsigned)nOutputs,
                          (unsigned)MAX_TX_SIZE_AFTER_SAPLING));
        }
    }

    // Build + broadcast.
    auto buildResult = builder_.Build();
    auto tx = buildResult.GetTxOrThrow();
    tx_ = tx;

    if (!testmode) {
        UniValue params = UniValue(UniValue::VARR);
        params.push_back(EncodeHexTx(tx_));
        UniValue sendResultValue = sendrawtransaction(params, false);
        if (sendResultValue.isNull()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "sendrawtransaction did not return an error or a txid.");
        }
    }

    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("txid", tx_.GetHash().ToString()));
    o.push_back(Pair("transfer_id", strprintf("%016x", transferId_)));
    o.push_back(Pair("fingerprint", fingerprintHex_));
    o.push_back(Pair("frames", (int)nFrames));
    set_result(o);
    return true;
}

UniValue AsyncRPCOperation_senddatafile::getStatus() const {
    UniValue v = AsyncRPCOperation::getStatus();
    if (contextinfo_.isNull()) {
        return v;
    }
    UniValue obj = v.get_obj();
    obj.push_back(Pair("method", "z_senddatafile"));
    obj.push_back(Pair("params", contextinfo_));
    return obj;
}
