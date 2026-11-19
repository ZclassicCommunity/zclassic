// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include "consensus/params.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class CChainParams;
class uint256;
class arith_uint256;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(arith_uint256 bnAvg,
                                       int64_t nLastBlockTime, int64_t nFirstBlockTime,
                                       const Consensus::Params&,
                                       int nextHeight);

/** Which Equihash verifier CheckEquihashSolution uses for (200,9) and (192,7).
 *  (48,5) and (96,5) always use the C++ verifier. */
enum class EquihashImpl : int {
    CPP = 0, //!< zcashd C++ Equihash<N,K>::IsValidSolution (src/crypto/equihash.cpp)
    C23 = 1, //!< vendored Z23 C23 verifier with batched SIMD BLAKE2b (src/c23/equihash)
};
/** Default verifier; hidden debug option -equihashimpl=cpp|c23 overrides it.
 *  C23 is the default because a replay of all 3,321,801 mainnet headers
 *  (heights 0..3321800, plus one single-bit mutant of each) gave zero
 *  C++/C23 disagreements (unit p1-equihash report). */
static const EquihashImpl DEFAULT_EQUIHASH_IMPL = EquihashImpl::C23;
/** Default for the hidden debug option -equihashmemo (positive-result memo). */
static const bool DEFAULT_EQUIHASH_MEMO = true;

/** Read -equihashimpl, -equihashdifferential and -equihashmemo. Idempotent;
 *  also done lazily by the first Equihash check. Call after ParseParameters. */
void InitEquihashOptions();
void SetEquihashImplementation(EquihashImpl impl);
EquihashImpl GetEquihashImplementation();
/** Differential mode runs both verifiers on (200,9)/(192,7), logs and counts
 *  any disagreement, and returns the C++ verdict. */
void SetEquihashDifferential(bool fEnable);
void SetEquihashMemoEnabled(bool fEnable);
bool GetEquihashMemoEnabled();

struct EquihashVerifierStats {
    uint64_t nVerifications; //!< full CheckEquihashSolution evaluations
    uint64_t nMemoHits;      //!< CheckEquihashSolutionMemo calls answered by the memo
    uint64_t nDisagreements; //!< differential-mode C++/C23 disagreements
};
EquihashVerifierStats GetEquihashVerifierStats();

/** Check whether the Equihash solution in a block header is valid (always
 *  evaluates the verifier; never consults the memo). */
bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams&);

/** Same check with an explicit verifier and no differential mode, for tests
 *  and benchmarks. */
bool CheckEquihashSolutionWith(const CBlockHeader *pblock, const CChainParams&, EquihashImpl impl);

/** CheckEquihashSolution with the process-wide positive-result memo
 *  (equihashmemo.h): a header whose hash was already verified VALID in this
 *  process returns true without re-running the verifier. A false result is
 *  never memoised, so every reject is a fresh evaluation. */
bool CheckEquihashSolutionMemo(const CBlockHeader *pblock, const CChainParams&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
arith_uint256 GetBlockProof(const CBlockIndex& block);

/** Return the time it would take to redo the work difference between from and to, assuming the current hashrate corresponds to the difficulty at tip, in seconds. */
int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params&);

#endif // BITCOIN_POW_H
