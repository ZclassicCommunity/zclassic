// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM (ZCL Names) write path — wallet-side helpers shared by the name_* write
// RPCs. The transaction builder itself (BuildAndCommitZNAM + ZNAMBuildReq) lives
// in wallet.h (a friend of CWallet, for the private SelectCoins seam). This
// header only carries the owner-input finder the RPCs share.
//
// NON-consensus: a name write is an ordinary transparent payment carrying one
// ZNAM OP_RETURN at vout[0]; unchanged ZClassic nodes relay and mine it. The
// builder's job is to pin the OWNER's UTXO at vin[0] (the FIFS signer the indexer
// reads) and keep token/NFT UTXOs out of the fee coins (anti-burn).

#ifndef BITCOIN_WALLET_ZNAMWALLET_H
#define BITCOIN_WALLET_ZNAMWALLET_H

#include "primitives/transaction.h" // COutPoint
#include "script/script.h"          // CScript

#include <string>

class CWallet;

/**
 * Find a PLAIN (non-token/NFT), spendable, confirmed wallet UTXO to pin at vin[0]
 * as the ZNAM owner signer. Picks the largest-value such coin (fewest extra
 * funding inputs). Excludes coinbase (cannot fund a transparent tx) and token/NFT
 * UTXOs (anti-burn). Requires cs_main + w->cs_wallet.
 *
 * `ownerAddr` is IN/OUT: if non-empty on input, only coins at that address match;
 * if EMPTY on input (name_register's "pick any owner" default), any plain coin
 * matches and `ownerAddr` is set to the chosen coin's address on success.
 * Returns false with `err` set if no matching plain spendable coin exists.
 */
bool ZNAMFindOwnerInput(CWallet* w, std::string& ownerAddr,
                        COutPoint& out, CScript& outScript, std::string& err);

#endif // BITCOIN_WALLET_ZNAMWALLET_H
