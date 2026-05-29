// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"

#include "chainparams.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "main.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <stdint.h>

#include <boost/foreach.hpp>

namespace Checkpoints {

    /**
     * How many times slower we expect checking transactions after the last
     * checkpoint to be (from checking signatures, which is skipped up to the
     * last checkpoint). This number is a compromise, as it can't be accurate
     * for every system. When reindexing from a fast disk with a slow CPU, it
     * can be up to 20, while when downloading from a slow network with a
     * fast multicore CPU, it won't be much higher than 1.
     */
    static const double SIGCHECK_VERIFICATION_FACTOR = 5.0;

    //! Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(const CCheckpointData& data, CBlockIndex *pindex, bool fSigchecks) {
        if (pindex==NULL)
            return 0.0;

        int64_t nNow = time(NULL);

        double fSigcheckVerificationFactor = fSigchecks ? SIGCHECK_VERIFICATION_FACTOR : 1.0;
        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkpoint, and
        // fSigcheckVerificationFactor per transaction after.

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->GetBlockTime())/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int GetTotalBlocksEstimate(const CCheckpointData& data)
    {
        const MapCheckpoints& checkpoints = data.mapCheckpoints;

        if (checkpoints.empty())
            return 0;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const CCheckpointData& data)
    {
        const MapCheckpoints& checkpoints = data.mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            BlockMap::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    static std::string FastSyncAnchorPayload(const CChainParams& chainparams, const CFastSyncAnchorData& anchor)
    {
        return strprintf("zclassic-fastsync-anchor-v1|%s|%d|%s",
            chainparams.NetworkIDString(),
            anchor.nHeight,
            anchor.hashBlock.ToString());
    }

    static uint256 HashAnchorSha256(const std::string& payload)
    {
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write((const unsigned char*)payload.data(), payload.size()).Finalize(hash);
        return uint256S("0x" + HexStr(hash, hash + CSHA256::OUTPUT_SIZE));
    }

    static uint256 HashAnchorSha3(const std::string& payload)
    {
        unsigned char hash[SHA3_256::OUTPUT_SIZE];
        SHA3_256().Write((const unsigned char*)payload.data(), payload.size()).Finalize(hash);
        return uint256S("0x" + HexStr(hash, hash + SHA3_256::OUTPUT_SIZE));
    }

    bool ValidateFastSyncAnchor(const CChainParams& chainparams, std::string& strError)
    {
        const MapCheckpoints& checkpoints = chainparams.Checkpoints().mapCheckpoints;

        BOOST_FOREACH(const CFastSyncAnchorData& anchor, chainparams.FastSyncAnchors())
        {
            if (anchor.nHeight < 0 || anchor.hashBlock.IsNull()) {
                continue;
            }

            // Every shipped anchor MUST carry a UTXO-set commitment: it is the
            // only thing that detects a forged imported chainstate after a peer
            // fast-sync (a malicious server can serve real headers matching
            // height+hash plus a forged chainstate/). A null commitment here
            // would silently disable that check, so refuse to start.
            if (anchor.hashChainstateSerialized.IsNull()) {
                strError = strprintf(
                    "Fast-sync anchor at height %d (block %s) has no chainstate commitment; refusing to start",
                    anchor.nHeight,
                    anchor.hashBlock.ToString());
                return false;
            }

            MapCheckpoints::const_iterator checkpoint = checkpoints.find(anchor.nHeight);
            if (checkpoint == checkpoints.end()) {
                strError = strprintf(
                    "Fast-sync anchor height %d (block %s) is not present in the checkpoint set",
                    anchor.nHeight,
                    anchor.hashBlock.ToString());
                return false;
            }

            if (checkpoint->second != anchor.hashBlock) {
                strError = strprintf(
                    "Fast-sync anchor hash mismatch at height %d: anchor=%s checkpoint=%s",
                    anchor.nHeight,
                    anchor.hashBlock.ToString(),
                    checkpoint->second.ToString());
                return false;
            }

            const std::string payload = FastSyncAnchorPayload(chainparams, anchor);
            const uint256 hashSha256 = HashAnchorSha256(payload);
            if (hashSha256 != anchor.hashAnchorSha256) {
                strError = strprintf(
                    "Fast-sync SHA-256 anchor digest mismatch at height %d (block %s): computed=%s expected=%s",
                    anchor.nHeight,
                    anchor.hashBlock.ToString(),
                    hashSha256.ToString(),
                    anchor.hashAnchorSha256.ToString());
                return false;
            }

            const uint256 hashSha3 = HashAnchorSha3(payload);
            if (hashSha3 != anchor.hashAnchorSha3) {
                strError = strprintf(
                    "Fast-sync SHA3-256 anchor digest mismatch at height %d (block %s): computed=%s expected=%s",
                    anchor.nHeight,
                    anchor.hashBlock.ToString(),
                    hashSha3.ToString(),
                    anchor.hashAnchorSha3.ToString());
                return false;
            }
        }

        return true;
    }

} // namespace Checkpoints
