// Wallet checkpoint bookkeeping that is not part of the write itself (CWallet::SetBestChain).
#include "wallet/wallet.h"

#include "chain.h"
#include "main.h"
#include "util.h"
#include "utiltime.h"

#include <algorithm>

namespace {
//! Write the checkpoint when the node has caught up (the tip reached the best known header) and the last one
//! is more than this many blocks behind the tip. After a snapshot sync or a long catch-up the blocks are
//! connected after wallet start-up, and the periodic checkpoint (hourly, about 48 blocks) would leave the file far behind.
const int CHECKPOINT_CATCHUP_LAG_BLOCKS = 100;
//! At most one such attempt in this many seconds.
const int64_t CHECKPOINT_CATCHUP_MIN_INTERVAL = 600;
} // namespace

void CWallet::NoteCheckpointResult(bool fWritten)
{
    if (fWritten) {
        fCheckpointFailed = false;
        return;
    }
    // The reason is logged by SetBestChainINTERNAL. Keep it visible: the file stays at its last checkpoint.
    fCheckpointFailed = true;
    ++nCheckpointFailures;
    LogPrintf("%s: the wallet checkpoint could not be written (failure %d since start); wallet.dat stays at height %d\n",
              __func__, nCheckpointFailures.load(), nCheckpointHeight.load());
}

void CWallet::CheckpointIfLagging(const CBlockIndex* pindex)
{
    // -testsetchaininterval is a test hook that decides when checkpoints happen.
    if (!pindex || mapArgs.count("-testsetchaininterval")) return;
    if (pindex->nHeight - std::max(nCheckpointHeight.load(), 0) <= CHECKPOINT_CATCHUP_LAG_BLOCKS) return;
    const int64_t nNow = GetTime();
    if (nNow < nTimeCatchupCheckpoint.load() + CHECKPOINT_CATCHUP_MIN_INTERVAL) return;
    // The wallet followed every block in memory (ChainTip, under cs_main), so at this tip it is consistent with
    // the chain: the same single-transaction checkpoint as the periodic one. Not while the node is still behind
    // the best header (a long sync would rewrite the wallet at every attempt).
    LOCK(cs_main);
    if (!chainActive.Tip() || (pindexBestHeader && chainActive.Height() < pindexBestHeader->nHeight)) return;
    nTimeCatchupCheckpoint = nNow;
    LogPrintf("%s: the node caught up %d blocks past the last wallet checkpoint; writing it now\n", __func__,
              chainActive.Height() - std::max(nCheckpointHeight.load(), 0));
    // The chain state reaches the disk first, as at shutdown: a crash must not leave the wallet ahead of the chain
    // on disk (the next start would drop its note state and rescan). cs_wallet is taken only by SetBestChain, after
    // the flush (the periodic path takes cs_LastBlockFile before cs_wallet).
    FlushStateToDisk();
    SetBestChain(chainActive.GetLocator());
}
