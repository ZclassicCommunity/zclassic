// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOOTSTRAP_H
#define BITCOIN_BOOTSTRAP_H

#include "protocol.h"
#include "streams.h"

#include <stdint.h>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

class CNode;

static const uint32_t BOOTSTRAP_SNAPSHOT_CHUNK_SIZE = 512 * 1024;
static const uint32_t BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE = 512 * 1024;

// Upper bounds for client-side acceptance of a peer-supplied manifest. A peer
// is untrusted until per-file SHA-256 verification succeeds, so without a cap
// a malicious peer can claim arbitrary nSnapshotBytes / nSize and fill the
// staging disk before the first hash mismatch is detected. These limits are
// generous relative to today's real snapshot size (a few GiB) but small enough
// that even an attacker maximizing them cannot exhaust a typical disk.
static const int64_t BOOTSTRAP_SNAPSHOT_MAX_TOTAL_BYTES = 200LL * 1024 * 1024 * 1024; // 200 GiB
static const int64_t BOOTSTRAP_SNAPSHOT_MAX_FILE_BYTES  = 32LL  * 1024 * 1024 * 1024; // 32 GiB
// Safety margin reserved over and above the manifest total when checking the
// staging directory's free space.
static const int64_t BOOTSTRAP_SNAPSHOT_DISK_SAFETY_MARGIN_BYTES = 1LL * 1024 * 1024 * 1024; // 1 GiB

// Default per-IP serve quota: bytes one address may download per 24h before the
// serving node throttles it, and the throttled rate to fall back to.
static const int64_t BOOTSTRAP_SERVE_DEFAULT_MAX_BYTES_PER_DAY = 100LL * 1024 * 1024 * 1024; // 100 GiB
static const int64_t BOOTSTRAP_SERVE_DEFAULT_THROTTLE_KBPS = 1024;                            // 1 MiB/s

bool BootstrapSnapshotPathsExist(const boost::filesystem::path& root);
bool IsBootstrapFreshChainDatadir(const boost::filesystem::path& data_dir, std::string& error);
bool ImportBootstrapDatadir(const boost::filesystem::path& source_root,
                            const boost::filesystem::path& data_dir,
                            bool force_backup,
                            std::string& error);
bool BootstrapFromPeer(const std::string& peer,
                       const boost::filesystem::path& data_dir,
                       std::string& error);

//! Effective bootstrap peer list: -bootstrappeer if set, else the compiled
//! per-network defaults (CChainParams::BootstrapPeers).
std::vector<std::string> GetBootstrapPeerList();

// --- Zcash parameter (.params) distribution over the bootstrap protocol ---
//! Compiled SHA-256 spec for one Zcash zk-SNARK parameter file. This is the
//! single source of truth used both by the bootstrap-snapshot protocol (which
//! verifies downloaded chunks) and by InitSanityCheck (which validates the
//! installed files at startup).
struct ZcashParamSpec {
    const char* name;
    const char* sha256hex;
};
//! Authoritative table of required zk-SNARK parameter files. Ordering is the
//! same order the bootstrap manifest advertises and serves them.
const std::vector<ZcashParamSpec>& GetZcashParamSpecs();

//! Build the manifest of zk-SNARK parameter files this node can serve (those
//! present in the params dir whose names/hashes match the compiled set).
bool GetZcashParamManifest(CBootstrapSnapshotManifest& manifest, std::string& error);
//! Read a bounded chunk from a served parameter file (indexed into the manifest).
bool ReadZcashParamChunk(const CBootstrapSnapshotChunkRequest& request,
                         CBootstrapSnapshotChunk& chunk,
                         std::string& error);
//! Download any missing/invalid Zcash parameters from `peer` into the params
//! dir, verifying each against its compiled SHA-256 before installing. The peer
//! is untrusted: only files matching a compiled hash are accepted.
bool FetchZcashParamsFromPeer(const std::string& peer, std::string& error);
//! True when every required compiled parameter file is present and hash-valid.
bool ZcashParamsPresentAndValid();

bool GetBootstrapSnapshotManifest(CBootstrapSnapshotManifest& manifest, std::string& error);
bool PreflightBootstrapSnapshotService(std::string& error);
bool ReadBootstrapSnapshotChunk(const CBootstrapSnapshotChunkRequest& request,
                                CBootstrapSnapshotChunk& chunk,
                                std::string& error);
bool ValidateBootstrapSnapshotManifest(const CBootstrapSnapshotManifest& manifest, std::string& error);
bool EnqueueBootstrapSnapshotChunkRequest(CNode* pfrom,
                                          const CBootstrapSnapshotChunkRequest& request,
                                          std::string& error);
//! Validate and queue a zk-SNARK parameter chunk request for later async serve.
//! Shares the per-peer queue cap, throttle, and quota path with snapshot chunks.
bool EnqueueBootstrapParamChunkRequest(CNode* pfrom,
                                       const CBootstrapSnapshotChunkRequest& request,
                                       std::string& error);
bool SendQueuedBootstrapSnapshotChunk(CNode* pto);

// Per-IP serve quota. Limits how many snapshot bytes one address can pull per
// rolling 24h window before the serving node throttles (or stops) it. These
// take an explicit current time so they are deterministic to test.
//! Returns true if a chunk may be served to `ip` at `now_ms`. When the address
//! is over its daily cap and throttling is disabled, returns false and sets
//! `stop` (so the caller can reject rather than defer).
bool BootstrapServeAllowChunk(const std::string& ip, bool whitelisted, int64_t now_ms, bool& stop);
//! Account `bytes` served to `ip` at `now_ms`, resetting the window when it rolls over.
void BootstrapServeChargeBytes(const std::string& ip, bool whitelisted, int64_t now_ms, uint64_t bytes);
//! Drop all tracked per-IP quota state (used by tests).
void ClearBootstrapServeQuota();

bool BuildBootstrapNetworkMessage(const char* command,
                                  const CDataStream& payload,
                                  CSerializeData& message,
                                  std::string& error);
bool DecodeBootstrapNetworkMessage(const CSerializeData& message,
                                   std::string& command,
                                   CDataStream& payload,
                                   std::string& error);

#endif // BITCOIN_BOOTSTRAP_H
