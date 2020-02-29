// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"

#include "sodium.h"
// RandomX
#include "crypto/RandomX/randomx.h"
#include "main.h"

static randomx_flags flags;
static uint256 key_block;
static randomx_cache *myCache;
static randomx_vm *myMachineMining;
static randomx_vm *myMachineValidating;
static bool fLightCacheInited = false;

bool IsRandomXLightInit()
{
    return fLightCacheInited;
}

void InitRandomXLightCache(const int32_t& height) {
    if (fLightCacheInited)
        return;

    key_block = GetKeyBlock(height);

    flags = randomx_get_flags();
    myCache = randomx_alloc_cache(flags);
    randomx_init_cache(myCache, &key_block, sizeof uint256());
    myMachineMining = randomx_create_vm(flags, myCache, NULL);
    myMachineValidating = randomx_create_vm(flags, myCache, NULL);
    fLightCacheInited = true;
}

void KeyBlockChanged(const uint256& new_block) {
    key_block = new_block;

    DeallocateRandomXLightCache();

    myCache = randomx_alloc_cache(flags);
    randomx_init_cache(myCache, &key_block, sizeof uint256());
    myMachineMining = randomx_create_vm(flags, myCache, NULL);
    myMachineValidating = randomx_create_vm(flags, myCache, NULL);
    fLightCacheInited = true;
}

uint256 GetCurrentKeyBlock() {
    return key_block;
}

randomx_vm* GetMyMachineMining() {
    return myMachineMining;
}

randomx_vm* GetMyMachineValidating() {
    return myMachineValidating;
}

void CheckIfKeyShouldChange(const uint256& check_block)
{
    if (check_block != key_block)
        KeyBlockChanged(check_block);
}

void DeallocateRandomXLightCache() {
    if (!fLightCacheInited)
        return;

    randomx_destroy_vm(myMachineMining);
    randomx_destroy_vm(myMachineValidating);
    randomx_release_cache(myCache);
    fLightCacheInited = false;
}

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
#define KEY_CHANGE 2048
#define SWITCH_KEY 64

uint256 GetKeyBlock(const uint32_t& nHeight)
{
    static uint256 current_key_block;

    auto remainer = nHeight % KEY_CHANGE;

    auto first_check = nHeight - remainer;
    auto second_check = nHeight - KEY_CHANGE - remainer;

    if (nHeight > nHeight - remainer + SWITCH_KEY) {
        if (chainActive.Height() > first_check)
            current_key_block = chainActive[first_check]->GetBlockHash();
    } else {
        if (chainActive.Height() > second_check)
            current_key_block = chainActive[second_check]->GetBlockHash();
    }

    if (current_key_block == uint256())
        current_key_block = chainActive[0]->GetBlockHash();

    return current_key_block;
}

bool CheckRandomXProofOfWork(const CBlockHeader& block, unsigned int nBits, const Consensus::Params& params)
{
    if(!IsRandomXLightInit())
        InitRandomXLightCache(block.nHeight);

    // This will check if the key block needs to change and will take down the cache and vm, and spin up the new ones
    CheckIfKeyShouldChange(GetKeyBlock(block.nHeight));

    // Create the eth_boundary from the nBits
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        //std::cout << fNegative << " " << (bnTarget == 0) << " " << fOverflow << " " << (bnTarget > UintToArith256(params.powLimit)) << "\n";
        return false;
    }

    uint256 hash_blob = block.GetRandomXHeaderHash();

    char hash[RANDOMX_HASH_SIZE];

    randomx_calculate_hash(GetMyMachineValidating(), &hash_blob, sizeof uint256(), hash);

    auto uint256Hash = uint256S(hash);

    // Check proof of work matches claimed amount
    return UintToArith256(uint256Hash) < bnTarget;

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

bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams& params)
{
    // Derive n, k from the solution size as the block header does not specify parameters used.
    // In the future, we could pass in the block height and call EquihashN() and EquihashK()
    // to perform a contextual check against the parameters in use at a given block height.
    unsigned int n, k;
    size_t nSolSize = pblock->nSolution.size();
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
        return error("%s: Unsupported solution size of %d", __func__, nSolSize);
    }

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CBlockhashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
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
