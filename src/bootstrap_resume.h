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
#include <functional>
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
    //! Claim the first pending file `allowed` marks (indexed by file); false if none.
    bool ClaimAllowed(const std::vector<uint8_t>& allowed, uint32_t& idx);
    //! True if a pending file is marked in `allowed`.
    bool HasPendingAllowed(const std::vector<uint8_t>& allowed) const;
    //! Per file (0..nFiles-1): 1 if it is pending or claimed, i.e. not yet verified and in place.
    std::vector<uint8_t> UnfinishedMask(size_t nFiles) const;
    //! Per file: 1 if it is pending (not claimed by any stream): what a stream that connects now could be given.
    std::vector<uint8_t> PendingMask(size_t nFiles) const;
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
std::string BootstrapFormatProgressLine(int percent, uint64_t received, uint64_t total, double mibPerSec, int streams, int servers = 0);


//! Multi-peer scheduling for the parallel snapshot download. Pure decision logic
//! (no sockets, no files; time is passed in) so it is unit-testable. Streams are
//! numbered 0..n-1; peers are indices into the caller's peer list (0 = the peer
//! whose manifest was validated). The board never decides what is TRUSTED: every
//! byte still has to hash to the validated manifest; it only decides who asks whom.
struct BootstrapPeerPolicy {
    int64_t windowMs;         //!< rate measuring window
    int64_t stallMs;          //!< no bytes for this long and another peer is usable => move the stream
    double slowFraction;      //!< a peer slower than this share of the best per-stream rate loses a stream
    int64_t moveCooldownMs;   //!< a moved stream is not moved again for this long
    int64_t penaltyMs;        //!< a peer a stream was moved off is avoided for new assignments this long
    int64_t stealMinSeconds;  //!< steal the rest of a file only if finishing it elsewhere saves more than this
    double stealFactor;       //!< ... and the idle stream's peer is at least this much faster than the holder's
    int64_t failBackoffBaseMs;
    int64_t failBackoffMaxMs;
    int maxConnectsPerMinute;  //!< connection attempts one server may get in a minute (a refusing server is not hammered)
    BootstrapPeerPolicy()
        : windowMs(10000), stallMs(20000), slowFraction(0.5), moveCooldownMs(30000), penaltyMs(30000),
          stealMinSeconds(15), stealFactor(1.5), failBackoffBaseMs(2000), failBackoffMaxMs(60000), maxConnectsPerMinute(60) {}
};

struct BootstrapPeerSnapshot {
    int streams;           //!< streams currently attached
    uint64_t bytes;        //!< payload bytes received from this peer this attempt
    double mibps;          //!< aggregate rate (MiB/s) over the window
    bool ignored;          //!< served a different snapshot: never used
    bool partial;          //!< serves only the files it shares with the trusted manifest
    bool banned;           //!< served bytes that failed verification: not used again this attempt
    BootstrapPeerSnapshot() : streams(0), bytes(0), mibps(0), ignored(false), partial(false), banned(false) {}
};

enum BootstrapMoveReason { BMR_STALLED, BMR_SLOW, BMR_STEAL, BMR_UNUSABLE };
struct BootstrapMove {
    int stream;
    int peer; //!< the peer the stream was attached to when the move was decided (-1 unknown)
    BootstrapMoveReason reason;
};

class BootstrapPeerBoard
{
public:
    BootstrapPeerBoard(size_t nPeers, int nStreams, const BootstrapPeerPolicy& policy = BootstrapPeerPolicy());
    //! Peer for stream `s` to (re)connect to, or -1 if no peer is usable (all ignored or banned). It prefers a
    //! server that holds a pending file this stream may fetch (or has not answered yet: it has to be probed);
    //! `anyUseful` (optional) is set false when no server has anything for the stream, in which case the caller
    //! should wait instead of connecting.
    int Assign(int s, int64_t nowMs, bool* anyUseful = NULL);
    //! Where the board learns which files are not yet in place (a mask indexed by the trusted manifest).
    void SetUnfinishedSource(const std::function<std::vector<uint8_t>()>& fn);
    //! The same for the files nobody has claimed (what a new connection can be given); Assign looks at these.
    void SetPendingSource(const std::function<std::vector<uint8_t>()>& fn);
    void Attach(int s, int peer, int64_t nowMs);
    //! The stream's connection ended (any reason). The caller Releases its claimed files.
    void Detach(int s);
    //! The stream has nothing to do (queue empty) and could take over work.
    void SetIdle(int s, bool idle);
    void ConnectFailed(int peer, int64_t nowMs);
    void ConnectOk(int peer);
    void ManifestMismatch(int peer);
    //! The peer serves a different manifest but shares some files with the trusted one (it serves only those).
    void SetPartial(int peer, bool partial);
    //! Avoid assigning streams to `peer` until `untilMs` (it had nothing to give them).
    void Defer(int peer, int64_t untilMs);
    //! Payload bytes of `file` arrived on stream `s`.
    void NoteChunk(int s, uint32_t file, uint64_t bytes, int64_t nowMs);
    //! Stream `s` claimed `file` with `remaining` bytes to go; `resumed` = it continues bytes of unknown origin.
    void NoteClaim(int s, uint32_t file, uint64_t remaining, bool resumed);
    void NoteRelease(int s, uint32_t file);
    void NoteComplete(int s, uint32_t file);
    //! `file` failed verification while stream `s` fetched it. A peer that alone supplied the bytes is benched
    //! (unless that would leave a file unfinished with no other holder: `unfinished` is the board of files not yet
    //! in place, NULL = unknown). With several or unknown suppliers nobody is blamed: the file is pinned to ONE peer
    //! (the primary if it can serve it) and fetched again from byte 0 from it, so the next result names one server.
    //! Returns true if another usable peer remains (the failure then costs a retry, not the attempt).
    bool HashFailed(int s, uint32_t file, const std::vector<uint8_t>* unfinished = NULL);
    //! The peers' file lists: `has` is indexed by the trusted manifest (empty = serves every file).
    void SetPeerHas(int peer, const std::vector<uint8_t>& has);
    //! Remove from `mask` the files stream `s` must not fetch because they are pinned to another peer.
    void MaskPinned(int s, std::vector<uint8_t>& mask) const;
    //! True if every file marked in `unfinished` can still come from some usable peer.
    bool EveryFileHasHolder(const std::vector<uint8_t>& unfinished) const;
    //! Record a connection attempt to `peer`; false (and not recorded) if it already had its share this minute.
    bool AllowConnect(int peer, int64_t nowMs);
    //! Streams to move off their peer now (stalled, slow, or robbed by an idle stream). Marks them moved.
    std::vector<BootstrapMove> Rebalance(int64_t nowMs, const std::function<void(const BootstrapMove&)>& apply = std::function<void(const BootstrapMove&)>());
    BootstrapPeerSnapshot Peer(int peer, int64_t nowMs) const;
    size_t UsablePeers() const;
    int StreamPeer(int s) const; //!< attached peer or -1

private:
    struct Sample { int64_t t; uint64_t bytes; };
    struct StreamState {
        int peer; bool connected; bool idle; bool move; int64_t attachedMs; int64_t lastByteMs; int64_t lastMoveMs;
        uint64_t bytes; std::deque<Sample> samples; std::map<uint32_t, uint64_t> remaining;
        StreamState() : peer(-1), connected(false), idle(false), move(false), attachedMs(0), lastByteMs(0),
                        lastMoveMs(-((int64_t)1 << 40)), bytes(0) {}
    };
    struct PeerState {
        bool ignored, banned, partial; int strikes; int failures; int64_t cooldownUntilMs; int64_t penaltyUntilMs;
        uint64_t bytes; double lastPerStream; double lastAggregate;
        bool answered;                      // it has sent its manifest (the primary's was validated by the caller)
        int liarStrikes;                    // times it was among the suppliers of a file that a single pinned server then got right
        std::vector<uint8_t> has;           // files it can serve (indexed by trusted manifest); empty = all
        std::deque<int64_t> connects;       // times of recent connection attempts
        PeerState() : ignored(false), banned(false), partial(false), strikes(0), failures(0), cooldownUntilMs(0),
                      penaltyUntilMs(0), bytes(0), lastPerStream(-1), lastAggregate(-1), answered(false), liarStrikes(0) {}
    };
    static bool Usable(const PeerState& p) { return !p.ignored && !p.banned; }
    double StreamRate(const StreamState& st, int64_t nowMs, bool matureOnly) const; //!< bytes/s over the window; <0 if matureOnly and too young
    double PeerPerStreamRate(int peer, int64_t nowMs) const;        //!< mean over mature streams, <0 if none
    int AttachedLocked(int peer) const;                              //!< streams on `peer` not asked to move
    bool PeerHasLocked(int peer, uint32_t file) const;               //!< `peer` has answered and can serve `file`
    bool PinBlocksLocked(uint32_t file, int peer) const;             //!< `file` is pinned to another usable peer
    //! `peer` holds a file that is still to come (and, if `only`, is one of those) and `peer` may fetch
    bool HoldsWorkLocked(int peer, const std::vector<uint8_t>& unfinished, const std::map<uint32_t, uint64_t>* only) const;
    //! `peer` could take over from stream `victim`: answered, no failed connection since, not deferred, holds one
    //! of the files the victim still has
    bool ComparableLocked(int peer, const StreamState& victim, const std::vector<uint8_t>& unfinished, int64_t nowMs) const;
    //! `b` may be benched: another usable peer holds every file `b` could still serve (and `file`, if >= 0)
    bool CanBenchLocked(size_t b, const std::vector<uint8_t>* unfinished, int64_t file) const;
    bool PeerQuietLocked(int peer, int64_t nowMs) const;             //!< no stream of `peer` got a byte for stallMs
    bool OtherPeerFeedingLocked(int peer, int64_t nowMs) const;      //!< some other server delivered within stallMs
    double StreamLifeRate(const StreamState& st, int64_t nowMs) const;  //!< bytes per second since the stream attached

    mutable std::mutex mtx;
    BootstrapPeerPolicy pol;
    std::vector<PeerState> peers;
    std::vector<StreamState> streams;
    std::map<uint32_t, std::set<int> > contributors; //!< file -> peers that supplied its bytes (-1 = unknown origin)
    std::map<uint32_t, int> pinned;                  //!< file -> the one peer that fetches it again from byte 0 after a shared-blame failure
    std::map<uint32_t, std::set<int> > suspects;    //!< file -> the other suppliers of the attempt that failed, until the pinned fetch verifies
    std::function<std::vector<uint8_t>()> unfinishedFn;
    std::function<std::vector<uint8_t>()> pendingFn;
};

//! "host:port 2 streams 41.0 MiB/s 3.20 GiB, host2:port ..." for the log and getbootstrapinfo.
std::string BootstrapPeerSummary(const std::vector<std::string>& names, const std::vector<BootstrapPeerSnapshot>& snap);

#endif // BITCOIN_BOOTSTRAP_RESUME_H
