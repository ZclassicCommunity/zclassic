// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PSERVE_H
#define BITCOIN_P2PSERVE_H

// Serve-side handlers of the getblocks, getheaders and mempool P2P messages,
// moved out of ProcessMessage. They answer requests from the local chain and
// mempool; none of them validates or accepts a block or a transaction.

#include <stdint.h>

struct CBlockLocator;
class CChainParams;
class CDataStream;
class CNode;

/**
 * Most entries a getblocks or getheaders locator may carry. An honest locator
 * (CChain::GetLocator) has 10 entries plus one per doubling step back to
 * genesis: under 40 even at height 5,000,000. A longer one is not served and
 * the peer is disconnected without a ban score.
 */
static const unsigned int MAX_LOCATOR_SZ = 101;

/** Seconds during which a second mempool request from the same peer is ignored (whitelisted peers are exempt). */
static const int64_t MEMPOOL_REQUEST_COOLDOWN = 60;

/** True, with a net log line and pfrom->fDisconnect set, when the locator has more than MAX_LOCATOR_SZ entries. */
bool LocatorOverCap(CNode* pfrom, const CBlockLocator& locator, const char* strCommand);

/** True when a mempool request at nNow falls inside the cooldown of the one served at nLastServed (0: never). */
bool MempoolRequestInCooldown(int64_t nLastServed, int64_t nNow);

/** Answer a getblocks request: queue block invs after the locator's fork point. Takes cs_main. */
void ServeGetBlocks(CNode* pfrom, CDataStream& vRecv, const CChainParams& chainparams);

/** Answer a getheaders request with up to MAX_HEADERS_RESULTS headers. Takes cs_main. */
void ServeGetHeaders(CNode* pfrom, CDataStream& vRecv);

/** Queue invs for the mempool, filtered by the peer's bloom filter. Caller holds cs_main and pfrom->cs_filter. */
void ServeMempool(CNode* pfrom, int currentHeight);

#endif // BITCOIN_P2PSERVE_H
