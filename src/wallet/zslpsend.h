// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Wallet side of ZSLP token creation, minting, sending and burning (stage 2 of
// the token work; stage 1 is the read-only index, doc/zslp.md).
//
// What it does, in this order, for every token transaction:
//  1. needs the token index switched on AND at the chain tip (the index decides
//     which outputs are valid tokens; a stale index could name a spent output);
//  2. takes token inputs only from this wallet's own CONFIRMED outputs that the
//     index lists as valid unspent outputs of that one token (a mint baton only
//     for a MINT; never another token's output, never an unconfirmed one: Z23
//     also refuses to spend a token output before it has a confirmation);
//  3. lays the outputs out as src/zslp/zslpbuild.h describes, and lets the
//     ordinary wallet code add ZCL inputs for the fee. Token-bearing outputs of
//     any other token or baton stay out of that selection (the wallet token
//     guard, src/wallet/tokenguard.h, is NOT switched off for them);
//  4. before anything is broadcast, runs the built and signed transaction
//     through the same validity rules the index uses (ZslpIndex::EvaluateTx):
//     it must be VALID, name the expected token, spend exactly the intended
//     token outputs, carry exactly the intended quantities, burn nothing that was
//     not asked for, and be a standard transaction;
//  5. only then commits it (which broadcasts).
//
// Transparent addresses only. Nothing here is consensus; no wallet.dat format changes.

#ifndef BITCOIN_WALLET_ZSLPSEND_H
#define BITCOIN_WALLET_ZSLPSEND_H

#include "amount.h"
#include "uint256.h"
#include "zslp/zslpbuild.h"

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class CWallet;

namespace zslp {

class ZslpService;

/** Why a request failed, so the RPC layer can pick the right error code. */
enum WalletErrKind {
    ERRK_NONE = 0,
    ERRK_PARAM,      //! the request itself is wrong
    ERRK_STATE,      //! the index is off, not synced, or the wallet cannot sign
    ERRK_TOKEN_FUNDS,//! not enough confirmed token balance (or no baton)
    ERRK_ZCL_FUNDS,  //! not enough ordinary ZCL for the fee and the dust outputs
    ERRK_INTERNAL    //! the built transaction failed its own checks: nothing was sent
};

struct TokenTxResult {
    std::string kind;          //! "send", "genesis", "mint", "burn"
    uint256 txid;
    uint256 token;
    bool broadcast;            //! false for a dry run
    CAmount fee;               //! zatoshi
    uint64_t units;            //! tokens sent / created / minted / burned (base units)
    uint64_t tokenChange;      //! token units returned to this wallet (SEND, BURN)
    uint64_t burned;           //! token units destroyed (BURN only)
    unsigned int decimals;
    unsigned int tokenInputs;
    std::string changeAddress; //! where the token change goes ("" when none)
    std::string hex;           //! the signed transaction (a dry run only)
    TokenTxResult() : broadcast(false), fee(0), units(0), tokenChange(0), burned(0), decimals(0), tokenInputs(0) {}
};

struct SendRequest {
    uint256 token;
    std::vector<std::pair<std::string, std::string> > to; //! address, decimal amount string
    int minconf;
    CAmount fee;      //! zatoshi; -1 = the wallet's normal fee
    bool dryRun;
    SendRequest() : minconf(1), fee(-1), dryRun(false) {}
};

struct GenesisRequest {
    std::string ticker, name, documentUrl, documentHashHex;
    unsigned int decimals;
    std::string quantity;       //! decimal string, with `decimals` fractional digits allowed
    bool hasBaton;              //! false: fixed supply (no baton)
    std::string batonAddress;   //! "" = a fresh wallet address (Z23's choice)
    std::string address;        //! initial tokens; "" = a fresh wallet address
    CAmount fee;
    bool dryRun;
    GenesisRequest() : decimals(0), hasBaton(true), fee(-1), dryRun(false) {}
};

struct MintRequest {
    uint256 token;
    std::string quantity;
    bool hasBaton;              //! false: no new baton (the supply is closed for good)
    std::string batonAddress;   //! "" = the address of the baton being spent (Z23's choice)
    std::string address;        //! minted tokens; "" = a fresh wallet address
    int minconf;
    CAmount fee;
    bool dryRun;
    MintRequest() : hasBaton(true), minconf(1), fee(-1), dryRun(false) {}
};

struct BurnRequest {
    uint256 token;
    std::string quantity;
    int minconf;
    CAmount fee;
    bool dryRun;
    BurnRequest() : minconf(1), fee(-1), dryRun(false) {}
};

/** Each returns true and fills `res`, or returns false with `err` and `kind`; on false nothing was broadcast and
 *  no wallet state changed. The caller has already required an unlocked wallet. */
bool WalletTokenSend(CWallet* wallet, ZslpService& svc, const SendRequest& req, TokenTxResult& res,
                     std::string& err, WalletErrKind& kind);
bool WalletTokenGenesis(CWallet* wallet, ZslpService& svc, const GenesisRequest& req, TokenTxResult& res,
                        std::string& err, WalletErrKind& kind);
bool WalletTokenMint(CWallet* wallet, ZslpService& svc, const MintRequest& req, TokenTxResult& res,
                     std::string& err, WalletErrKind& kind);
bool WalletTokenBurn(CWallet* wallet, ZslpService& svc, const BurnRequest& req, TokenTxResult& res,
                     std::string& err, WalletErrKind& kind);

} // namespace zslp

#endif // BITCOIN_WALLET_ZSLPSEND_H
