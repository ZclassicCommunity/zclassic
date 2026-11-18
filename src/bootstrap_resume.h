// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOOTSTRAP_RESUME_H
#define BITCOIN_BOOTSTRAP_RESUME_H

// Pure (socket-free, filesystem-free) decision logic for resuming an interrupted
// bootstrap snapshot download. Nothing in here trusts a staged file: every
// decision is a function of facts the caller measured (sizes, and a SHA-256 the
// caller computed against the manifest the peer served this run). The compiled
// chainstate commitment check that gates the import is unchanged and lives in
// init.cpp (VerifyImportedBootstrapAnchor).

#include "protocol.h"
#include "uint256.h"

#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <stdint.h>
#include <string>
#include <vector>

//! A staging directory is named BOOTSTRAP_STAGING_PREFIX + 16 hex digits of the
//! snapshot identity. Anything else with the prefix is a leftover of an older
//! (per-epoch named) attempt and is removed.
static const char* const BOOTSTRAP_STAGING_PREFIX = "bootstrap-peer-staging-";
//! File inside a staging directory recording which snapshot it belongs to.
static const char* const BOOTSTRAP_STAGING_MARKER = ".z23-staging";
static const int BOOTSTRAP_STAGING_MARKER_VERSION = 1;

//! Identity of the snapshot a staging directory belongs to: the chain anchor the
//! manifest commits to (network, anchor height/hash, the compiled anchor string
//! hashes, and for a v2 self-snapshot also its own chainstate commitment). It
//! deliberately EXCLUDES the file list and the growable v3 block-bundle tip: a
//! serving node appends block files as it grows, and those must not invalidate
//! the already-verified chainstate files. Per-file reuse is still decided
//! against the CURRENT manifest's per-file hashes, never against this identity.
uint256 BootstrapStagingIdentity(const CBootstrapSnapshotManifest& manifest);
//! Hash of the complete manifest (file list, hashes, sizes, bundle tip).
uint256 BootstrapManifestId(const CBootstrapSnapshotManifest& manifest);
//! "bootstrap-peer-staging-" + first 16 hex digits of the identity.
std::string BootstrapStagingDirName(const CBootstrapSnapshotManifest& manifest);

struct BootstrapStagingMarker {
    int nVersion;
    uint256 identity;
    uint256 manifestId;
    BootstrapStagingMarker() : nVersion(0) {}
};
std::string FormatBootstrapStagingMarker(const BootstrapStagingMarker& marker);
//! False for anything but a well-formed current-version marker with a non-null identity.
bool ParseBootstrapStagingMarker(const std::string& text, BootstrapStagingMarker& out);

enum BootstrapStagingVerdict {
    BSV_FRESH,                 //!< no staging directory: start clean
    BSV_REUSE_SAME_MANIFEST,   //!< same snapshot, byte-identical manifest
    BSV_REUSE_SAME_ANCHOR,     //!< same anchor, file list differs (server grew/rebuilt): reuse files that still match
    BSV_DISCARD_BAD_MARKER,    //!< directory without a valid marker: untrusted, discard
    BSV_DISCARD_OTHER_SNAPSHOT //!< marker names a different anchor/snapshot: discard
};
BootstrapStagingVerdict BootstrapDecideStagingReuse(bool dirExists, bool markerValid,
                                                    const BootstrapStagingMarker& marker,
                                                    const uint256& identity, const uint256& manifestId);
const char* BootstrapStagingVerdictName(BootstrapStagingVerdict v);

//! Facts a caller measured about one manifest file in a staging directory.
struct BootstrapStagedFileFacts {
    bool finalExists;    //!< staging/<path> exists
    uint64_t finalSize;
    bool finalHashOk;    //!< SHA-256 of the final file equals the manifest hash (only meaningful when sizes match)
    bool partExists;     //!< staging/<path>.part exists
    uint64_t partSize;
    BootstrapStagedFileFacts() : finalExists(false), finalSize(0), finalHashOk(false), partExists(false), partSize(0) {}
};
enum BootstrapStagedAction {
    BSA_KEEP,        //!< complete and verified: reuse as is
    BSA_FETCH_ALL,   //!< download from offset 0
    BSA_RESUME_PART  //!< download from resumeOffset, appending to the existing .part
};
struct BootstrapStagedDecision {
    BootstrapStagedAction action;
    uint64_t resumeOffset;
    bool discardFinal;  //!< delete the final-path file (corrupt/wrong size)
    bool discardPart;   //!< delete the .part (not resumable / superseded)
    BootstrapStagedDecision() : action(BSA_FETCH_ALL), resumeOffset(0), discardFinal(false), discardPart(false) {}
};
//! Where a download may continue inside a partially written file. Requests must be
//! aligned to chunkSize (the server rejects anything else), the trailing partial
//! chunk of a torn write is re-fetched, and at least the last chunk of a file is
//! always re-requested so even a full-size .part passes through the normal
//! verify-then-rename path. 0 means "start over".
uint64_t BootstrapResumeOffset(uint64_t partSize, uint64_t fileSize, uint32_t chunkSize);
BootstrapStagedDecision BootstrapDecideStagedFile(uint64_t fileSize, uint32_t chunkSize, const BootstrapStagedFileFacts& facts);

//! What a scan of a staging directory found (BootstrapResumeScan in bootstrap.cpp).
struct BootstrapResumeStats {
    size_t filesKept;       //!< complete, hash-verified files reused as is
    size_t filesResumed;    //!< partial files that continue from an aligned offset
    size_t filesMissing;    //!< files with nothing usable on disk
    size_t filesDiscarded;  //!< complete-looking files that failed verification (deleted)
    size_t strayRemoved;    //!< entries the manifest does not name (deleted)
    uint64_t bytesKept;
    uint64_t bytesResumed;
    uint64_t bytesHashed;   //!< bytes re-hashed to verify the kept files
    int64_t scanMillis;
    BootstrapResumeStats()
        : filesKept(0), filesResumed(0), filesMissing(0), filesDiscarded(0), strayRemoved(0),
          bytesKept(0), bytesResumed(0), bytesHashed(0), scanMillis(0) {}
};

//! Work shared by the parallel download streams. Files are claimed lazily so the
//! load balances itself, and a file claimed by a stream that then dies is handed
//! back for any other (or the reconnected) stream to pick up.
class BootstrapWorkQueue
{
public:
    explicit BootstrapWorkQueue(const std::vector<uint32_t>& pending);
    bool Claim(uint32_t& idx);
    //! Hand a claimed, unfinished file back (it is retried before untouched files).
    void Release(uint32_t idx);
    void Complete(uint32_t idx);
    bool AllDone() const;
    bool HasPending() const;
    size_t PendingCount() const;
    size_t ClaimedCount() const;
    size_t DoneCount() const;
    //! Record a failed hash verification of a file; returns the strikes so far.
    int AddStrike(uint32_t idx);
    //! After a failed verification a file is re-fetched from byte 0, never resumed.
    bool MustRestart(uint32_t idx) const;

private:
    mutable std::mutex mtx;
    std::deque<uint32_t> pending;
    std::set<uint32_t> claimed;
    std::map<uint32_t, int> strikes;
    size_t done;
};

//! Delay before reconnecting a stream after `consecutiveFailures` failures in a
//! row: 1s doubling to a 30s cap, with +-25% jitter derived from `jitterSeed` so
//! parallel streams do not retry in lockstep. 0 failures => 0.
int64_t BootstrapReconnectDelayMs(int consecutiveFailures, unsigned int jitterSeed);

//! Binary-unit size text, "10.43 GiB" (two decimals). The bootstrap used to print
//! GiB values labelled "GB".
std::string BootstrapFormatGiB(uint64_t bytes);
//! The progress line parsed by the GUI ("Bootstrap snapshot: NN%  X.XX / Y.YY GiB  Z.Z MiB/s  (N streams)").
//! streams <= 0 omits the stream suffix.
std::string BootstrapFormatProgressLine(int percent, uint64_t received, uint64_t total, double mibPerSec, int streams);

#endif // BITCOIN_BOOTSTRAP_RESUME_H
