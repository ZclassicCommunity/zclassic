// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOOTSTRAP_H
#define BITCOIN_BOOTSTRAP_H

#include "net.h"
#include "protocol.h"
#include "streams.h"

#include <stdint.h>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

class CNode;

// Snapshot/param transfer chunk size. 1 MiB keeps the BSCHK/BSPCHK message well
// under MAX_PROTOCOL_MESSAGE_LENGTH (2 MiB) while halving the per-chunk round
// trips and serve-loop iterations versus 512 KiB. The server advertises this in
// the manifest's nChunkSize and the client sizes its requests from the manifest,
// so a client built with a larger value still downloads correctly from a server
// built with a smaller one.
static const uint32_t BOOTSTRAP_SNAPSHOT_CHUNK_SIZE = 1024 * 1024;
static const uint32_t BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE = 1024 * 1024;

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
// True if the datadir holds only a genesis-height chainstate (initialized but
// never synced past genesis); such a datadir carries no real chain.
bool IsGenesisOnlyChainDatadir(const boost::filesystem::path& data_dir, std::string& error);
// Move a genesis-only datadir's blocks/ and chainstate/ aside to a timestamped
// backup so a bootstrap snapshot can be imported into the now-fresh datadir.
// On success outBackup is set to the backup directory; the caller restores it
// with RestoreGenesisOnlyChainData if the bootstrap subsequently fails.
bool BackupGenesisOnlyChainData(const boost::filesystem::path& data_dir, boost::filesystem::path& outBackup, std::string& error);
// Move blocks/ and chainstate/ back from a BackupGenesisOnlyChainData backup into
// data_dir and remove the backup, undoing the move when a bootstrap attempt fails.
bool RestoreGenesisOnlyChainData(const boost::filesystem::path& data_dir, const boost::filesystem::path& backup, std::string& error);
// True if a bootstrap snapshot may be imported into data_dir: fresh, or a
// genesis-only datadir that was successfully backed up (side effect). When a
// backup was made, outBackupDir names it so the caller can remove it if the
// bootstrap subsequently fails.
bool BootstrapDatadirEligible(const boost::filesystem::path& data_dir, boost::filesystem::path& outBackupDir, std::string& error);
bool ImportBootstrapDatadir(const boost::filesystem::path& source_root,
                            const boost::filesystem::path& data_dir,
                            bool force_backup,
                            std::string& error);
bool BootstrapFromPeer(const std::string& peer,
                       const boost::filesystem::path& data_dir,
                       std::string& error);

//! Best-effort decentralized discovery of NODE_BOOTSTRAP peers from the active
//! network's DNS/fixed seeds, via a bounded bootstrap-handshake + getaddr/addr
//! probe. Strictly bounded, never hangs (respects per-message timeouts) and
//! returns an empty vector on any failure. Results are "ip:port" strings.
//! Invoked lazily by the init bootstrap loop only when the explicit/compiled
//! peers fail, so it costs nothing when a compiled peer already works.
std::vector<std::string> DiscoverBootstrapPeers();

//! Effective bootstrap peer list: all -bootstrappeer entries (repeatable) if
//! set, else the compiled per-network defaults (CChainParams::BootstrapPeers).
std::vector<std::string> GetBootstrapPeerList();

//! Auto-serve (-bootstrapserve=auto): activate serving from the immutable copy
//! this node retained when it fast-synced (data_dir/bootstrap-serve-source).
//! Returns true and points the serve machinery (-bootstrapsourcedir) at that
//! copy when it exists and still matches the compiled anchor; returns false
//! (with a reason) when there is nothing valid to serve — e.g. the node has not
//! bootstrapped yet, or the retained copy is for a stale anchor (in which case
//! it is removed). Lets every fast-synced node become a P2P bootstrap server.
bool SetupAutoBootstrapServe(const boost::filesystem::path& data_dir, std::string& error);

//! Option B: freeze this node's own live chainstate into the auto-serve dir
//! (data_dir/bootstrap-serve-source) and record a v2 ".meta" describing it (real
//! height/block hash + UTXO-set commitment), so the node can serve a trustless
//! self-snapshot at its own recent tip instead of the compiled anchor. The
//! served height/hash/commitment are derived from the copy itself, so the
//! published snapshot is internally consistent. Best-effort — callers must not
//! treat failure as fatal (the previous serve copy, if any, is left untouched).
//! minAdvanceBlocks>0 skips the (expensive) re-copy when the existing serve copy
//! is already within that many blocks of the tip; 0 forces a freeze.
bool FreezeLiveChainstateForServe(const boost::filesystem::path& data_dir, int minAdvanceBlocks, std::string& error);

//! GROWABLE v3 serve-extend: grow the retained anchor serve copy's BLOCK bundle
//! (blocks/blk+rev*.dat + blocks/index) up to this node's current live tip while
//! KEEPING its chainstate PINNED at the compiled fast-sync anchor (the chainstate is
//! hard-linked from the existing serve copy, never re-copied or re-hashed) and
//! recording a sibling ".blocktip" sidecar at the captured tip. Requires an existing
//! retained ".anchor" serve dir and a node out of IBD; leaves the previous serve dir
//! untouched on any failure. Best-effort — callers must not treat failure as fatal.
//! minAdvanceBlocks>0 skips the re-copy when the served bundle is already within that
//! many blocks of the tip; 0 forces an extend.
bool ExtendServedBlocksForServe(const boost::filesystem::path& data_dir, int minAdvanceBlocks, std::string& error);

//! GROWABLE v3: produce a retained ".anchor" serve dir on a node that synced from
//! genesis (and so has no fast-synced serve copy) by re-deriving the UTXO set at the
//! compiled anchor height from genesis into a scratch chainstate, self-checking it
//! against the compiled anchor commitment, installing it plus the live blocks/ tree,
//! and recording a ".blocktip" at the current tip. Trusts no peer (the commitment is
//! re-derived and compared to the compiled constant). Requires the active chain to be
//! past the anchor and out of IBD. Best-effort; init.cpp wires the call.
bool BuildAnchorServeSnapshotFromGenesis(const boost::filesystem::path& data_dir, std::string& error);

//! Path of the auto-serve directory (data_dir/bootstrap-serve-source), exposed so
//! init can point -bootstrapsourcedir at it before the first self-snapshot freeze.
boost::filesystem::path BootstrapAutoServeSourceDir(const boost::filesystem::path& data_dir);

//! Path of the GROWABLE v3 block-bundle tip sidecar (".blocktip", a sibling of the
//! serve dir, OUTSIDE it like ".anchor"/".meta"), exposed for init/serve wiring.
boost::filesystem::path BootstrapServeBlockTipPath(const boost::filesystem::path& sourcedir);

//! Drift guard: when serving a prepared anchor snapshot (-bootstrapserve with a
//! -bootstrapsourcedir that is NOT a v2 self-snapshot), returns false and sets
//! `warning` if the served chainstate tip matches no compiled fast-sync anchor —
//! the condition where anchor-mode clients would download the snapshot and only
//! then reject it. Returns true (no warning) when serving is off, nothing is
//! retained yet, the source is a v2 self-snapshot, or the tip matches an anchor.
bool BootstrapServeSnapshotMatchesCompiledAnchor(std::string& warning);

// --- Zcash parameter (.params) distribution over the bootstrap protocol ---
//! Compiled SHA-256 spec for one Zcash zk-SNARK parameter file. This is the
//! single source of truth used both by the bootstrap-snapshot protocol (which
//! verifies downloaded chunks) and by InitSanityCheck (which validates the
//! installed files at startup).
struct ZcashParamSpec {
    const char* name;
    const char* sha256hex;
    uint64_t nSize;
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

//! fAllowBuild=true (default): if the manifest/file-hash cache is cold, build it
//! inline (SHA-256 over the whole snapshot). Call with false on the net
//! message-handler thread so it never hashes multi-GiB inline — it returns "not
//! ready" until an off-thread warmer (init Preflight / the freeze task) rebuilds.
bool GetBootstrapSnapshotManifest(CBootstrapSnapshotManifest& manifest, std::string& error, bool fAllowBuild = true);
bool PreflightBootstrapSnapshotService(std::string& error);
//! fAllowBuild has the same meaning as for GetBootstrapSnapshotManifest: serving
//! a chunk needs the file-hash cache, and rebuilding it re-hashes the whole
//! multi-GiB snapshot. The net message-handler thread (SendQueuedBootstrapSnapshotChunk)
//! must pass false so a request arriving while the cache is cold (e.g. the
//! window between a freeze clearing the cache and the off-thread warmer
//! rebuilding it) returns "not ready" instead of stalling all peers.
bool ReadBootstrapSnapshotChunk(const CBootstrapSnapshotChunkRequest& request,
                                CBootstrapSnapshotChunk& chunk,
                                std::string& error,
                                bool fAllowBuild = true);
//! Validate a received manifest. fTrustlessAllowed=false (default) requires the
//! manifest to match the compiled fast-sync anchor (v1, or a v2 that equals the
//! anchor). fTrustlessAllowed=true additionally accepts a v2 self-snapshot at a
//! peer's own tip (its contents are verified after download, not here). The
//! gossip/CNode path must always pass false; only the explicit bootstrap driver
//! (and the server validating its own manifest) may pass true.
bool ValidateBootstrapSnapshotManifest(const CBootstrapSnapshotManifest& manifest, std::string& error, bool fTrustlessAllowed = false);

// --- Option B client side: trustless self-snapshot provisional accept ---------
//! Record that a v2 self-snapshot was just imported and awaits provisional
//! acceptance + background validation (a datadir-sibling marker, so it survives a
//! restart between install and verification).
bool WriteBootstrapTrustlessPending(const boost::filesystem::path& data_dir, int height, const uint256& hashBlock, const uint256& commitment);
bool BootstrapTrustlessPendingExists(const boost::filesystem::path& data_dir);
void BootstrapTrustlessPendingClear(const boost::filesystem::path& data_dir);
//! Anchor-mode counterpart: written (and fsync'd) BEFORE an imported snapshot's
//! chainstate is installed, so VerifyImportedBootstrapAnchor still runs on the next
//! start if a crash in the install->verify window lost the in-memory "bootstrap ran
//! this session" flag. Its presence — not an in-memory bool — gates the only
//! anchor-mode forgery check. See bootstrap.cpp / init.cpp AppInit2.
bool WriteBootstrapAnchorPending(const boost::filesystem::path& data_dir, int height, const uint256& hashBlock);
bool BootstrapAnchorPendingExists(const boost::filesystem::path& data_dir);
void BootstrapAnchorPendingClear(const boost::filesystem::path& data_dir);
//! Read the (height, hash) recorded in the anchor-pending marker. For a v3 growable
//! import this is the GROWN BUNDLE TIP (so the post-import forward-connect can find it
//! without relying on pindexBestHeader, which LoadBlockIndexDB leaves at the anchor for
//! an imported chainstate); for a v1 import it is the anchor itself. Returns false if
//! the marker is absent or malformed.
bool GetBootstrapAnchorPending(const boost::filesystem::path& data_dir, int& height, uint256& hashBlock);
//! Cheap provisional gate (integrity + checkpoints + tip PoW) run after a
//! trustless snapshot is imported and the chain databases are open. NOT full
//! trust — the background validator re-derives the UTXO set from genesis and
//! reindexes on mismatch. Returns the (height, block hash, commitment) to hand to
//! the background validator on success; commitment doubles as S_imported.
bool ProvisionalAcceptTrustlessSnapshot(const boost::filesystem::path& data_dir,
                                        int& outHeight, uint256& outHashBlock, uint256& outCommitment,
                                        std::string& error);
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

//! Process-wide aggregate serve caps (opt-in via -bootstrapservemaxtotalkbps /
//! -bootstrapservemaxpeers; default unlimited). AllowChunk returns false to DEFER when a
//! chunk of `wantBytes` to `nodeId` would exceed the global byte-rate or concurrent-peer
//! cap; Charge accounts a sent chunk and marks the peer actively-served. Whitelisted peers
//! bypass both. Declared for tests.
bool BootstrapServeGlobalAllow(NodeId nodeId, bool whitelisted, size_t wantBytes, int64_t now_ms);
void BootstrapServeGlobalCharge(NodeId nodeId, bool whitelisted, size_t bytes, int64_t now_ms);
//! Drop all aggregate-serve accounting state (used by tests).
void ClearBootstrapServeGlobal();

//! True when -bootstrapservemaxtotalkbps is set below the floor where its per-window byte
//! budget can hold a single chunk; fills in the configured value and the effective floor
//! (Kbit/s) for an operator warning. Returns false when unlimited (0) or above the floor.
bool BootstrapServeRateCapBelowFloor(int64_t& configuredKbps, int64_t& effectiveFloorKbps);

bool BuildBootstrapNetworkMessage(const char* command,
                                  const CDataStream& payload,
                                  CSerializeData& message,
                                  std::string& error);
bool DecodeBootstrapNetworkMessage(const CSerializeData& message,
                                   std::string& command,
                                   CDataStream& payload,
                                   std::string& error);

#endif // BITCOIN_BOOTSTRAP_H
