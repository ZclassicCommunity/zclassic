// Copyright (c) 2025 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SNAPSHOT_H
#define BITCOIN_SNAPSHOT_H

#include "serialize.h"
#include "uint256.h"
#include "sync.h"
#include "net.h"

#include <string>
#include <vector>
#include <map>

static const unsigned int SNAPSHOT_CHUNK_SIZE = 52428800; // 50 MB
static const unsigned int SNAPSHOT_CURRENT_HEIGHT = 2879438;

/** Information about a single snapshot chunk */
struct CSnapshotChunkInfo
{
    uint32_t nChunkNumber;
    uint256 hashChunk;        // SHA256 hash of chunk data
    uint64_t nSize;           // Size in bytes

    CSnapshotChunkInfo() : nChunkNumber(0), nSize(0) {}
    CSnapshotChunkInfo(uint32_t nChunkNumberIn, const uint256& hashIn, uint64_t nSizeIn)
        : nChunkNumber(nChunkNumberIn), hashChunk(hashIn), nSize(nSizeIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nChunkNumber);
        READWRITE(hashChunk);
        READWRITE(nSize);
    }
};

/** Complete snapshot manifest */
struct CSnapshotManifest
{
    uint32_t nBlockHeight;
    uint64_t nTimestamp;
    uint64_t nTotalSize;
    std::vector<CSnapshotChunkInfo> vChunks;

    CSnapshotManifest() : nBlockHeight(0), nTimestamp(0), nTotalSize(0) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nBlockHeight);
        READWRITE(nTimestamp);
        READWRITE(nTotalSize);
        READWRITE(vChunks);
    }

    uint32_t GetChunkCount() const { return vChunks.size(); }
    bool IsValid() const;
};

/** P2P message: request snapshot chunk */
class CGetSnapshotChunk
{
public:
    uint32_t nChunkNumber;

    CGetSnapshotChunk() : nChunkNumber(0) {}
    explicit CGetSnapshotChunk(uint32_t nChunkNumberIn) : nChunkNumber(nChunkNumberIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nChunkNumber);
    }
};

/** P2P message: snapshot chunk data response */
class CSnapshotChunk
{
public:
    uint32_t nChunkNumber;
    std::vector<unsigned char> vData;

    CSnapshotChunk() : nChunkNumber(0) {}
    CSnapshotChunk(uint32_t nChunkNumberIn, const std::vector<unsigned char>& vDataIn)
        : nChunkNumber(nChunkNumberIn), vData(vDataIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nChunkNumber);
        READWRITE(vData);
    }
};

/** Snapshot download state tracking */
class CSnapshotDownloadState
{
private:
    std::map<uint32_t, bool> mapChunksReceived;  // chunk number -> received
    std::map<uint32_t, int64_t> mapChunkRequests; // chunk number -> request time
    uint32_t nTotalChunks;

    // Progress tracking
    int64_t nDownloadStartTime;
    int64_t nLastProgressTime;
    uint32_t nLastProgressCount;

public:
    CSnapshotDownloadState() : nTotalChunks(0), nDownloadStartTime(0), nLastProgressTime(0), nLastProgressCount(0) {}
    explicit CSnapshotDownloadState(uint32_t nTotalChunksIn) : nTotalChunks(nTotalChunksIn), nDownloadStartTime(0), nLastProgressTime(0), nLastProgressCount(0) {}

    void MarkChunkReceived(uint32_t nChunk);
    bool IsChunkReceived(uint32_t nChunk) const;
    bool IsComplete() const;
    uint32_t GetNextChunkToRequest() const;
    uint32_t GetReceivedCount() const;
    void RecordChunkRequest(uint32_t nChunk, int64_t nTime);
    bool HasRecentRequest(uint32_t nChunk, int64_t nNow) const;
    void LogProgress(); // Print progress for users
};

/** Snapshot storage and retrieval */
class CSnapshotStore
{
private:
    boost::filesystem::path pathSnapshotDir;
    CSnapshotManifest manifest;

public:
    CSnapshotStore();

    bool Initialize(uint32_t nHeight);
    bool LoadManifest();
    bool SaveManifest(const CSnapshotManifest& manifestIn);

    bool HasChunk(uint32_t nChunk) const;
    bool SaveChunk(uint32_t nChunk, const std::vector<unsigned char>& vData);
    bool LoadChunk(uint32_t nChunk, std::vector<unsigned char>& vData) const;
    bool VerifyChunk(uint32_t nChunk, const std::vector<unsigned char>& vData) const;

    const CSnapshotManifest& GetManifest() const { return manifest; }
    boost::filesystem::path GetSnapshotDir() const { return pathSnapshotDir; }

    bool ExtractSnapshot(const boost::filesystem::path& dataDir);
    bool CleanupChunks();
};

/** Rate limiting for snapshot chunk serving (server-side DDoS protection) */
class CSnapshotRateLimiter
{
private:
    // Per-peer rate limiting
    struct PeerRequestInfo {
        std::deque<int64_t> requestTimes;        // Recent request timestamps
        std::map<uint32_t, int64_t> servedChunks; // chunk -> last serve time
        int64_t nLastRequestTime;
        uint32_t nTotalRequests;
        bool bIsBanned;
        int64_t nBanUntil;

        PeerRequestInfo() : nLastRequestTime(0), nTotalRequests(0), bIsBanned(false), nBanUntil(0) {}
    };

    mutable CCriticalSection cs_rateLimiter;
    std::map<CNetAddr, PeerRequestInfo> mapPeerRequests;

    // Global rate limiting
    uint32_t nActiveTransfers;
    int64_t nTotalBytesServed;
    int64_t nLastResetTime;

    // Configurable limits (GENEROUS defaults - help new users bootstrap fast!)
    uint32_t nMaxChunksPerPeerPerMinute;  // Default: 30 (1 every 2 sec, 1.5 GB/min max)
    uint32_t nMaxConcurrentTransfers;     // Default: 25 (support many simultaneous users)
    uint32_t nMinSecondsBetweenRequests;  // Default: 2 seconds (just prevent instant spam)
    uint32_t nDuplicateChunkWindowSec;    // Default: 300 (5 min - prevent repeated requests)
    uint32_t nBanThreshold;               // Default: 100 requests/min (very high - severe abuse only)
    uint32_t nBanDurationSec;             // Default: 300 (5 min - short timeout)

public:
    CSnapshotRateLimiter();

    // Check if peer is allowed to request a chunk
    bool AllowRequest(const CNetAddr& addr, uint32_t nChunk, std::string& strError);

    // Record that we served a chunk to a peer
    void RecordServed(const CNetAddr& addr, uint32_t nChunk, uint64_t nBytes);

    // Complete a transfer (decrement active count)
    void CompleteTransfer();

    // Check if peer is banned
    bool IsBanned(const CNetAddr& addr);

    // Clean up old entries periodically
    void Cleanup();

    // Get stats for monitoring
    uint32_t GetActiveTransfers() const { return nActiveTransfers; }
    uint64_t GetTotalBytesServed() const { return nTotalBytesServed; }

    // Update limits from config
    void SetLimits(uint32_t maxChunksPerMin, uint32_t maxConcurrent, uint32_t minSecBetween);
};

/** Client-side respectful download coordinator */
class CSnapshotDownloadCoordinator
{
private:
    struct PeerDownloadState {
        int64_t nLastRequestTime;
        uint32_t nChunksRequested;
        uint32_t nChunksFailed;
        uint32_t nConsecutiveFailures;
        int64_t nBackoffUntil;

        PeerDownloadState() : nLastRequestTime(0), nChunksRequested(0),
                              nChunksFailed(0), nConsecutiveFailures(0), nBackoffUntil(0) {}
    };

    mutable CCriticalSection cs_coordinator;
    std::map<NodeId, PeerDownloadState> mapPeerStates;
    std::map<uint32_t, NodeId> mapChunkToNode;  // Track which peer we requested from

    CSnapshotDownloadState* pDownloadState;

    // Client-side limits (be respectful but efficient!)
    static const uint32_t MAX_CONCURRENT_PEER_REQUESTS = 12; // Download from multiple peers simultaneously
    static const uint32_t MIN_SECONDS_BETWEEN_REQUESTS = 3;  // Wait 3sec between requests (server allows 2)
    static const uint32_t REQUEST_TIMEOUT_SEC = 60;          // Timeout after 60 seconds

public:
    CSnapshotDownloadCoordinator(CSnapshotDownloadState* pState);

    // Select best peer to request next chunk from
    NodeId SelectPeerForNextChunk(const std::vector<NodeId>& vAvailablePeers, uint32_t& nChunkOut);

    // Record that we sent a request
    void RecordRequest(NodeId node, uint32_t nChunk);

    // Record successful chunk receipt
    void RecordSuccess(NodeId node, uint32_t nChunk);

    // Record failed chunk request (timeout or bad data)
    void RecordFailure(NodeId node, uint32_t nChunk);

    // Get backoff time for a peer (0 = ready, >0 = wait N seconds)
    int64_t GetPeerBackoff(NodeId node) const;

    // Check for timed-out requests and retry
    std::vector<std::pair<NodeId, uint32_t>> GetTimedOutRequests();

    // Clean up state for disconnected peer
    void RemovePeer(NodeId node);
};

/** Global snapshot manager */
extern CSnapshotStore* psnapshotstore;
extern CSnapshotRateLimiter* psnapshotratelimiter;

/** Initialize snapshot system */
bool InitSnapshotStore(uint32_t nHeight);

/** Check if we should advertise NODE_SNAPSHOT service */
bool CanServeSnapshots();

/** Get hardcoded manifest for current snapshot */
CSnapshotManifest GetHardcodedManifest();

/** Get hardcoded manifest for zcash params */
CSnapshotManifest GetHardcodedParamsManifest();

//
// UTXO Set Hash Calculation for Snapshot Verification
// Adapted from Bitcoin ABC (MIT License)
//

/** Calculate deterministic UTXO set hash at a given block */
uint256 CalculateUTXOSetHash(const uint256& blockHash);

/** Verify snapshot UTXO hash against hardcoded checkpoint */
bool VerifySnapshotUTXOHash(const uint256& blockHash, int nHeight);

#endif // BITCOIN_SNAPSHOT_H
