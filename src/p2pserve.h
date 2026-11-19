// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PSERVE_H
#define BITCOIN_P2PSERVE_H

// Serve-side handlers of the getblocks, getheaders and mempool P2P messages,
// moved out of ProcessMessage. They answer requests from the local chain and
// mempool; none of them validates or accepts a block or a transaction.

class CChainParams;
class CDataStream;
class CNode;

/** Answer a getblocks request: queue block invs after the locator's fork point. Takes cs_main. */
void ServeGetBlocks(CNode* pfrom, CDataStream& vRecv, const CChainParams& chainparams);

/** Answer a getheaders request with up to MAX_HEADERS_RESULTS headers. Takes cs_main. */
void ServeGetHeaders(CNode* pfrom, CDataStream& vRecv);

/** Queue invs for the mempool, filtered by the peer's bloom filter. Caller holds cs_main and pfrom->cs_filter. */
void ServeMempool(CNode* pfrom, int currentHeight);

#endif // BITCOIN_P2PSERVE_H
