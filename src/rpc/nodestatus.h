// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_NODESTATUS_H
#define BITCOIN_RPC_NODESTATUS_H

#include "syncphase.h"

#include <stdint.h>

class UniValue;

/** One optional index (zslp or znam) as getnodestatus reports it. */
struct NodeIndexStatus {
    bool enabled = false;
    bool synced = false;
    int indexedHeight = -1;
};

/** Everything getnodestatus reports, gathered without holding any lock (see rpc/nodestatus.cpp). */
struct NodeStatusInputs {
    SyncInputs sync;
    int nInbound = 0;
    int nOutbound = 0;
    uint64_t mempoolSize = 0;
    uint64_t mempoolBytes = 0;
    int64_t uptimeSeconds = 0;
    bool txindex = false;
    NodeIndexStatus zslp;
    NodeIndexStatus znam;
    int64_t datadirFreeBytes = -1;
};

/** The pure part of getnodestatus: inputs to JSON. */
UniValue BuildNodeStatus(const NodeStatusInputs& in);

#endif // BITCOIN_RPC_NODESTATUS_H
