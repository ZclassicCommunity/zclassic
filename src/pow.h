// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include "consensus/params.h"
#include "crypto/RandomX/randomx.h"
#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class CChainParams;
class uint256;
class arith_uint256;
class uint256;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(arith_uint256 bnAvg,
                                       int64_t nLastBlockTime, int64_t nFirstBlockTime,
                                       const Consensus::Params&,
                                       int nextHeight);

/** Check whether the Equihash solution in a block header is valid */
bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
arith_uint256 GetBlockProof(const CBlockIndex& block);

/** RandomX functions **/
bool IsRandomXLightInit();
void InitRandomXLightCache(const int32_t& height);
void KeyBlockChanged(const uint256& new_block);
void CheckIfKeyShouldChange(const uint256& check_block);
void DeallocateRandomXLightCache();
uint256 GetCurrentKeyBlock();
uint256 GetKeyBlock(const uint32_t& nHeight);
randomx_vm* GetMyMachineMining();
randomx_vm* GetMyMachineValidating();

/** Check whether a block hash satisfies the prog-proof-of-work requirement specified by nBits */
bool CheckRandomXProofOfWork(const CBlockHeader& block, unsigned int nBits, const Consensus::Params&);

/** Return the time it would take to redo the work difference between from and to, assuming the current hashrate corresponds to the difficulty at tip, in seconds. */
int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params&);

#endif // BITCOIN_POW_H
