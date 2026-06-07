// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// AsyncRPCOperation_senddatafile — the dedicated async op behind z_senddatafile.
//
// WHY A DEDICATED OP (not z_sendmany): a data transfer chunks one file into N
// ZDC1 frames, each of which becomes ONE Sapling output MEMO to the SAME
// recipient z-addr. z_sendmany's RPC layer rejects duplicate recipients
// (rpcwallet.cpp "duplicated address"); the async op / TransactionBuilder do
// NOT, so we emit all N same-recipient AddSaplingOutput calls in ONE tx here.
//
// The op encodes the (already pre-validated, ENCRYPTED) ZDC1 frames into Sapling
// outputs, selects + spends the wallet's Sapling notes of the from z-addr,
// builds + broadcasts the tx, and reports {txid, transfer_id, fingerprint,
// frames}. The crypto and framing all live in the codec (datachannel/zdc); this
// op only maps frames -> memos and drives the existing Sapling send machinery.
//
// KEYS NEVER LEAVE THE WALLET: the per-transfer ZDC1 key is generated and
// consumed in the RPC layer (returned to the caller, who chose to create it);
// the wallet's Sapling spending key is used only to spend/sign, never exported.

#ifndef ASYNCRPCOPERATION_SENDDATAFILE_H
#define ASYNCRPCOPERATION_SENDDATAFILE_H

#include "asyncrpcoperation.h"
#include "amount.h"
#include "primitives/transaction.h"
#include "transaction_builder.h"
#include "zcash/Address.hpp"
#include "wallet.h"

#include <array>
#include <string>
#include <vector>

#include <univalue.h>

// Default transaction fee if caller does not specify one. Matches z_sendmany.
#define SENDDATAFILE_DEFAULT_MINERS_FEE   10000

class AsyncRPCOperation_senddatafile : public AsyncRPCOperation {
public:
    AsyncRPCOperation_senddatafile(
        TransactionBuilder builder,
        CMutableTransaction contextualTx,
        std::string fromAddress,
        std::string toAddress,
        // The already-encoded, already-encrypted 512-byte ZDC1 frames. Each
        // frame becomes one Sapling output memo (1:1, 512 == ZC_MEMO_SIZE).
        std::vector<std::vector<unsigned char> > frames,
        uint64_t transferId,
        std::string fingerprintHex,
        int minDepth,
        CAmount fee = SENDDATAFILE_DEFAULT_MINERS_FEE,
        UniValue contextInfo = NullUniValue);
    virtual ~AsyncRPCOperation_senddatafile();

    AsyncRPCOperation_senddatafile(AsyncRPCOperation_senddatafile const&) = delete;
    AsyncRPCOperation_senddatafile(AsyncRPCOperation_senddatafile&&) = delete;
    AsyncRPCOperation_senddatafile& operator=(AsyncRPCOperation_senddatafile const&) = delete;
    AsyncRPCOperation_senddatafile& operator=(AsyncRPCOperation_senddatafile&&) = delete;

    virtual void main();

    virtual UniValue getStatus() const;

    bool testmode = false;  // Set to true to disable sending txs and generating proofs

private:
    UniValue contextinfo_;

    uint32_t consensusBranchId_;
    CAmount fee_;
    int mindepth_;
    std::string fromaddress_;
    std::string toaddress_;
    libzcash::SaplingPaymentAddress toPaymentAddress_;
    libzcash::SaplingExtendedSpendingKey spendingKey_;
    std::vector<std::vector<unsigned char> > frames_;
    uint64_t transferId_;
    std::string fingerprintHex_;

    std::vector<SaplingNoteEntry> z_sapling_inputs_;

    TransactionBuilder builder_;
    CTransaction tx_;

    bool find_unspent_notes(CAmount target);
    bool main_impl();
};

#endif /* ASYNCRPCOPERATION_SENDDATAFILE_H */
