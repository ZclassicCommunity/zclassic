// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "syncphase.h"

#include <string.h>

namespace {

/** The IBD answer, identical to ClassifySyncPhase (main.cpp) for an IBD node. */
const char* ClassifyDuringIbd(const SyncInputs& in)
{
    if (in.nConnections <= 0) return "waiting_for_peers";
    if (in.nHeaders > in.nBlocks) return "downloading_blocks";
    return "downloading_headers";
}

/** An old tip is believable only when every peer is at our height and has been connected a while. */
bool QuietChainIsSynced(const SyncInputs& in)
{
    return in.connectedForSeconds >= SYNC_QUIET_CHAIN_CONNECTED_SECONDS;
}

/** The answer for a node whose IBD latch is already false. */
const char* ClassifyAfterIbd(const SyncInputs& in)
{
    if (in.nConnections <= 0) return "waiting_for_peers";
    if (in.nBestPeerHeight > in.nBlocks + SYNC_PEER_SLACK_BLOCKS) return "downloading_blocks";
    if (in.nBestPeerHeight < 0) return "downloading_headers";
    if (in.tipAgeSeconds <= SYNC_TIP_FRESH_SECONDS) return "synced";
    if (QuietChainIsSynced(in)) return "synced";
    return "downloading_blocks";
}

} // namespace

const char* ClassifySyncPhaseV2(const SyncInputs& in)
{
    if (in.reindexing) return "reindexing";
    if (in.importing) return "importing";
    if (in.ibd) return ClassifyDuringIbd(in);
    return ClassifyAfterIbd(in);
}

bool IsSyncedV2(const SyncInputs& in)
{
    return strcmp(ClassifySyncPhaseV2(in), "synced") == 0;
}
