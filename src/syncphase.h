// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SYNCPHASE_H
#define BITCOIN_SYNCPHASE_H

#include <stdint.h>

/**
 * A stricter "is this node synced" classifier than ClassifySyncPhase (main.cpp). It is pure
 * (no locks, no globals) and read-only: it never feeds IsInitialBlockDownload() or any
 * validation or relay decision. After a snapshot replay the IBD latch can be false while the
 * node is still hundreds of blocks behind its peers; this looks at tip age and peer heights too.
 */

/** A tip younger than this counts as fresh (12 block intervals of 150 s). */
static const int64_t SYNC_TIP_FRESH_SECONDS = 12 * 150;
/** A peer this many blocks ahead of us (or fewer) does not count as being ahead. */
static const int SYNC_PEER_SLACK_BLOCKS = 2;
/** A quiet chain (old tip, peers at our height) is trusted only after this long connected. */
static const int64_t SYNC_QUIET_CHAIN_CONNECTED_SECONDS = 60;

struct SyncInputs {
    bool ibd = false;           //! IsInitialBlockDownload()
    bool reindexing = false;
    bool importing = false;
    int nConnections = 0;
    int nOutboundConnected = 0;
    int nBlocks = 0;
    int nHeaders = 0;
    int nBestPeerHeight = -1;   //! best starting height of a handshaken outbound peer, -1 unknown
    int64_t tipAgeSeconds = 0;
    int64_t connectedForSeconds = 0; //! how long the longest-connected such peer has been connected
};

/** One of reindexing, importing, waiting_for_peers, downloading_headers, downloading_blocks, synced. */
const char* ClassifySyncPhaseV2(const SyncInputs& in);

/** True when ClassifySyncPhaseV2 answers "synced". */
bool IsSyncedV2(const SyncInputs& in);

#endif // BITCOIN_SYNCPHASE_H
