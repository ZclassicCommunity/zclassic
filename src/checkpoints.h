// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKPOINTS_H
#define BITCOIN_CHECKPOINTS_H

#include "uint256.h"

#include <map>
#include <string>

class CBlockIndex;
class CChainParams;
struct CCheckpointData;

/**
 * Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{

//! Return conservative estimate of total number of blocks, 0 if unknown
int GetTotalBlocksEstimate(const CCheckpointData& data);

//! Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
CBlockIndex* GetLastCheckpoint(const CCheckpointData& data);

//! Returns false only if there is a checkpoint at nHeight and hash does not
//! match it. A block presented at a checkpoint height with a different hash is
//! a forgery and must be rejected (eclipse / bootstrap lock-in).
bool CheckBlock(const CCheckpointData& data, int nHeight, const uint256& hash);

double GuessVerificationProgress(const CCheckpointData& data, CBlockIndex* pindex, bool fSigchecks = true);

//! Validate the compiled fast-sync anchor against the checkpoint set and digest fields.
bool ValidateFastSyncAnchor(const CChainParams& chainparams, std::string& strError);

} //namespace Checkpoints

#endif // BITCOIN_CHECKPOINTS_H
