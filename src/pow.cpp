// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "c23/equihash/zc23_equihash.h"
#include "chain.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "equihashmemo.h"
#include "primitives/block.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"

#include "sodium.h"

#include <atomic>
#include <mutex>

/**
 * Manually increase difficulty by a multiplier. Note that because of the use of compact bits, this will 
 * only be an approx increase, not a 100% precise increase.
 */
unsigned int IncreaseDifficultyBy(unsigned int nBits, int64_t multiplier, const Consensus::Params& params) {
    arith_uint256 target;
    target.SetCompact(nBits);
    target /= multiplier;
    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    if (target > pow_limit) {
        target = pow_limit;
    }
    return target.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;
    
    int nHeight = pindexLast->nHeight + 1;

    // For upgrade mainnet forks, we'll adjust the difficulty down for the first nPowAveragingWindow blocks
    if (params.scaleDifficultyAtUpgradeFork &&
        (nHeight >= params.vUpgrades[Consensus::UPGRADE_DIFFADJ].nActivationHeight &&
         nHeight < params.vUpgrades[Consensus::UPGRADE_DIFFADJ].nActivationHeight + params.nPowAveragingWindow) ||
            (nHeight >= params.vUpgrades[Consensus::UPGRADE_BUTTERCUP].nActivationHeight &&
             nHeight < params.vUpgrades[Consensus::UPGRADE_BUTTERCUP].nActivationHeight + params.nPowAveragingWindow)) {
        
        if (pblock && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.PoWTargetSpacing(nHeight) * 12) {
            // If > 30 mins, allow min difficulty
            LogPrintf("Returning level 1 difficulty\n");
            return nProofOfWorkLimit;
        } else if (pblock && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.PoWTargetSpacing(nHeight) * 6) {
            // If > 15 mins, allow low estimate difficulty
            unsigned int difficulty = IncreaseDifficultyBy(nProofOfWorkLimit, 128, params);
            LogPrintf("Returning level 2 difficulty\n");
            return difficulty;
        } else if (pblock && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.PoWTargetSpacing(nHeight) * 2) {
            // If > 5 mins, allow high estimate difficulty
            unsigned int difficulty = IncreaseDifficultyBy(nProofOfWorkLimit, 256, params);
            LogPrintf("Returning level 3 difficulty\n");
            return difficulty;
        } else {
            // If < 5 mins, fall through, and return the normal difficulty.
            LogPrintf("Falling through\n");
        }
    }
    
    {
        // Comparing to pindexLast->nHeight with >= because this function
        // returns the work required for the block after pindexLast.
        if (params.nPowAllowMinDifficultyBlocksAfterHeight != boost::none &&
            pindexLast->nHeight >= params.nPowAllowMinDifficultyBlocksAfterHeight.get())
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 6 * block interval minutes
            // then allow mining of a min-difficulty block.
            if (pblock && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.PoWTargetSpacing(pindexLast->nHeight + 1) * 6)
                return nProofOfWorkLimit;
        }
    }

    // Find the first block in the averaging interval
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot {0};
    for (int i = 0; pindexFirst && i < params.nPowAveragingWindow; i++) {
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
    }

    // Check we have enough blocks
    if (pindexFirst == NULL)
        return nProofOfWorkLimit;

    arith_uint256 bnAvg {bnTot / params.nPowAveragingWindow};

    return CalculateNextWorkRequired(bnAvg, pindexLast->GetMedianTimePast(), pindexFirst->GetMedianTimePast(), params, pindexLast->nHeight + 1);
}

unsigned int CalculateNextWorkRequired(arith_uint256 bnAvg,
                                       int64_t nLastBlockTime, int64_t nFirstBlockTime,
                                       const Consensus::Params& params,
                                       int nextHeight)
{
    int64_t averagingWindowTimespan = params.AveragingWindowTimespan(nextHeight);
    int64_t minActualTimespan = params.MinActualTimespan(nextHeight);
    int64_t maxActualTimespan = params.MaxActualTimespan(nextHeight);
    // Limit adjustment step
    // Use medians to prevent time-warp attacks
    int64_t nActualTimespan = nLastBlockTime - nFirstBlockTime;
    LogPrint("pow", "  nActualTimespan = %d  before dampening\n", nActualTimespan);
    nActualTimespan = averagingWindowTimespan + (nActualTimespan - averagingWindowTimespan)/4;
    LogPrint("pow", "  nActualTimespan = %d  before bounds\n", nActualTimespan);

    if (nActualTimespan < minActualTimespan) {
        nActualTimespan = minActualTimespan;
    }
    if (nActualTimespan > maxActualTimespan) {
        nActualTimespan = maxActualTimespan;
    }

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew {bnAvg};
    bnNew /= averagingWindowTimespan;
    bnNew *= nActualTimespan;

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    /// debug print
    LogPrint("pow", "GetNextWorkRequired RETARGET\n");
    LogPrint("pow", "params.AveragingWindowTimespan(%d) = %d    nActualTimespan = %d\n", nextHeight, averagingWindowTimespan, nActualTimespan);
    LogPrint("pow", "Current average: %08x  %s\n", bnAvg.GetCompact(), bnAvg.ToString());
    LogPrint("pow", "After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

namespace {

std::once_flag g_equihashOptionsOnce;
std::atomic<int> g_equihashImpl{(int)DEFAULT_EQUIHASH_IMPL};
std::atomic<bool> g_equihashDifferential{false};
std::atomic<bool> g_equihashMemoEnabled{DEFAULT_EQUIHASH_MEMO};
std::atomic<uint64_t> g_equihashVerifications{0};
std::atomic<uint64_t> g_equihashMemoHits{0};
std::atomic<uint64_t> g_equihashDisagreements{0};

void EquihashC23LogSink(const char* line)
{
    // Same category as the C++ verifier's own reject diagnostics.
    LogPrint("pow", "%s\n", line);
}

void LoadEquihashOptionsOnce()
{
    std::call_once(g_equihashOptionsOnce, []() {
        zc23_equihash_set_log_sink(EquihashC23LogSink);
        const std::string strDefault = (DEFAULT_EQUIHASH_IMPL == EquihashImpl::C23) ? "c23" : "cpp";
        const std::string strImpl = GetArg("-equihashimpl", strDefault);
        if (strImpl == "c23") {
            g_equihashImpl = (int)EquihashImpl::C23;
        } else if (strImpl == "cpp") {
            g_equihashImpl = (int)EquihashImpl::CPP;
        } else {
            LogPrintf("Unknown -equihashimpl=%s; using %s\n", strImpl, strDefault);
            g_equihashImpl = (int)DEFAULT_EQUIHASH_IMPL;
        }
        g_equihashDifferential = GetBoolArg("-equihashdifferential", false);
        g_equihashMemoEnabled = GetBoolArg("-equihashmemo", DEFAULT_EQUIHASH_MEMO);
    });
}

// Derive n, k from the solution size as the block header does not specify parameters used.
// In the future, we could pass in the block height and call EquihashN() and EquihashK()
// to perform a contextual check against the parameters in use at a given block height.
bool EquihashParamsFromSolutionSize(size_t nSolSize, unsigned int& n, unsigned int& k)
{
    if (nSolSize == 1344) { // mainnet and testnet genesis
        n = 200;
        k = 9;
    } else if (nSolSize == 36) { // regtest genesis
        n = 48;
        k = 5;
    } else if (nSolSize == 68) {
        n = 96;
        k = 5;
    } else if (nSolSize == 400) {
        n = 192;
        k = 7;
    } else {
        return false;
    }
    return true;
}

// The zcashd C++ verifier, unchanged.
bool VerifyEquihashCpp(unsigned int n, unsigned int k, const CDataStream& ss,
                       const std::vector<unsigned char>& solution)
{
    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (const unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, solution, isValid);
    return isValid;
}

// The C23 verifier is wired only for the two mainnet/testnet parameter sets.
// (48,5) and (96,5) (regtest) always use the C++ verifier.
bool EquihashC23Eligible(unsigned int n, unsigned int k)
{
    return (n == 200 && k == 9) || (n == 192 && k == 7);
}

bool CheckEquihashSolutionImpl(const CBlockHeader* pblock, EquihashImpl impl, bool fDifferential)
{
    unsigned int n, k;
    size_t nSolSize = pblock->nSolution.size();
    if (!EquihashParamsFromSolutionSize(nSolSize, n, k)) {
        return error("%s: Unsupported solution size of %d", "CheckEquihashSolution", nSolSize);
    }

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    bool isValid;
    if (EquihashC23Eligible(n, k) && (impl == EquihashImpl::C23 || fDifferential)) {
        const int c23 = zc23_equihash_verify(n, k,
                                             (const unsigned char*)&ss[0], ss.size(),
                                             pblock->nSolution.data(), pblock->nSolution.size());
        if (fDifferential || c23 < 0) {
            // The C++ verifier is the reference: in differential mode its
            // verdict is the one returned, and a C23 "no verdict" (internal
            // error, never a reject) falls back to it.
            const bool cpp = VerifyEquihashCpp(n, k, ss, pblock->nSolution);
            if (c23 < 0) {
                LogPrintf("CheckEquihashSolution(): C23 verifier gave no verdict (%d) for %s; used the C++ verifier\n",
                          c23, pblock->GetHash().ToString());
            } else if ((c23 == ZC23_EH_VALID) != cpp) {
                g_equihashDisagreements++;
                LogPrintf("ERROR: CheckEquihashSolution(): C++ and C23 Equihash verifiers DISAGREE on %s (n=%u k=%u): C++ %s, C23 %s; using the C++ verdict\n",
                          pblock->GetHash().ToString(), n, k,
                          cpp ? "valid" : "invalid", c23 == ZC23_EH_VALID ? "valid" : "invalid");
            }
            isValid = cpp;
        } else {
            isValid = (c23 == ZC23_EH_VALID);
        }
    } else {
        isValid = VerifyEquihashCpp(n, k, ss, pblock->nSolution);
    }

    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
}

} // namespace

void InitEquihashOptions()
{
    LoadEquihashOptionsOnce();
}

void SetEquihashImplementation(EquihashImpl impl)
{
    LoadEquihashOptionsOnce();
    g_equihashImpl = (int)impl;
}

EquihashImpl GetEquihashImplementation()
{
    LoadEquihashOptionsOnce();
    return (EquihashImpl)g_equihashImpl.load();
}

void SetEquihashDifferential(bool fEnable)
{
    LoadEquihashOptionsOnce();
    g_equihashDifferential = fEnable;
}

void SetEquihashMemoEnabled(bool fEnable)
{
    LoadEquihashOptionsOnce();
    g_equihashMemoEnabled = fEnable;
}

bool GetEquihashMemoEnabled()
{
    LoadEquihashOptionsOnce();
    return g_equihashMemoEnabled.load();
}

EquihashVerifierStats GetEquihashVerifierStats()
{
    EquihashVerifierStats s;
    s.nVerifications = g_equihashVerifications.load();
    s.nMemoHits = g_equihashMemoHits.load();
    s.nDisagreements = g_equihashDisagreements.load();
    return s;
}

bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams& params)
{
    LoadEquihashOptionsOnce();
    g_equihashVerifications++;
    return CheckEquihashSolutionImpl(pblock, (EquihashImpl)g_equihashImpl.load(),
                                     g_equihashDifferential.load());
}

bool CheckEquihashSolutionWith(const CBlockHeader *pblock, const CChainParams& params, EquihashImpl impl)
{
    return CheckEquihashSolutionImpl(pblock, impl, false);
}

bool CheckEquihashSolutionMemo(const CBlockHeader *pblock, const CChainParams& params)
{
    LoadEquihashOptionsOnce();
    const bool fMemo = g_equihashMemoEnabled.load();
    const bool fLog = LogAcceptCategory("equihash");
    if (!fMemo && !fLog)
        return CheckEquihashSolution(pblock, params);

    // The key is computed here from the header itself, never taken from the
    // caller, so a hit can only ever stand for these exact header bytes.
    const uint256 hash = pblock->GetHash();
    if (fMemo && GetEquihashMemo().Contains(hash)) {
        g_equihashMemoHits++;
        LogPrint("equihash", "equihash-check %s memo-hit\n", hash.ToString());
        return true;
    }
    const bool fValid = CheckEquihashSolution(pblock, params);
    if (fValid && fMemo)
        GetEquihashMemo().Insert(hash); // only TRUE results are ever memoised
    LogPrint("equihash", "equihash-check %s verified %s\n", hash.ToString(), fValid ? "valid" : "invalid");
    return fValid;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return error("CheckProofOfWork(): nBits below minimum work");

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return error("CheckProofOfWork(): hash doesn't match nBits");

    return true;
}

arith_uint256 GetBlockProof(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.PoWTargetSpacing(tip.nHeight)) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}
