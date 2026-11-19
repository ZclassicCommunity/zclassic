// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrap_resume.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <stdio.h>
#include <string.h>

uint256 BootstrapStagingIdentity(const CBootstrapSnapshotManifest& manifest)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("z23-bootstrap-staging-identity-v1");
    ss << manifest.strNetwork;
    ss << manifest.nHeight;
    ss << manifest.hashBlock;
    ss << manifest.hashAnchorSha256;
    ss << manifest.hashAnchorSha3;
    // A v1/v3 snapshot's chainstate is pinned to a compiled anchor, which already
    // fixes it; a v2 self-snapshot has no such anchor, so its own commitment is part
    // of what it is.
    if (manifest.nVersion == 2)
        ss << manifest.hashChainstateSerialized;
    return ss.GetHash();
}

uint256 BootstrapManifestId(const CBootstrapSnapshotManifest& manifest)
{
    return SerializeHash(manifest);
}

std::string BootstrapStagingDirName(const CBootstrapSnapshotManifest& manifest)
{
    return std::string(BOOTSTRAP_STAGING_PREFIX) + BootstrapStagingIdentity(manifest).GetHex().substr(0, 16);
}

std::string FormatBootstrapStagingMarker(const BootstrapStagingMarker& marker)
{
    return strprintf("z23-bootstrap-staging %d\nidentity %s\nmanifest %s\n",
                     BOOTSTRAP_STAGING_MARKER_VERSION, marker.identity.GetHex(), marker.manifestId.GetHex());
}

bool ParseBootstrapStagingMarker(const std::string& text, BootstrapStagingMarker& out)
{
    out = BootstrapStagingMarker();
    if (text.size() > 512)
        return false;
    char magic[32] = {0};
    char idHex[80] = {0};
    char manHex[80] = {0};
    int version = 0;
    // Fixed-width conversions into bounded buffers; a trailing "\n" is optional.
    if (sscanf(text.c_str(), "%31s %d identity %79s manifest %79s", magic, &version, idHex, manHex) != 4)
        return false;
    if (strcmp(magic, "z23-bootstrap-staging") != 0 || version != BOOTSTRAP_STAGING_MARKER_VERSION)
        return false;
    if (strlen(idHex) != 64 || strlen(manHex) != 64 || !IsHex(idHex) || !IsHex(manHex))
        return false;
    out.nVersion = version;
    out.identity = uint256S(idHex);
    out.manifestId = uint256S(manHex);
    return !out.identity.IsNull();
}

BootstrapStagingVerdict BootstrapDecideStagingReuse(bool dirExists, bool markerValid,
                                                    const BootstrapStagingMarker& marker,
                                                    const uint256& identity, const uint256& manifestId)
{
    if (!dirExists)
        return BSV_FRESH;
    if (!markerValid)
        return BSV_DISCARD_BAD_MARKER;
    if (marker.identity != identity)
        return BSV_DISCARD_OTHER_SNAPSHOT;
    return marker.manifestId == manifestId ? BSV_REUSE_SAME_MANIFEST : BSV_REUSE_SAME_ANCHOR;
}

const char* BootstrapStagingVerdictName(BootstrapStagingVerdict v)
{
    switch (v) {
    case BSV_FRESH: return "fresh";
    case BSV_REUSE_SAME_MANIFEST: return "same manifest";
    case BSV_REUSE_SAME_ANCHOR: return "same anchor, manifest changed";
    case BSV_DISCARD_BAD_MARKER: return "no valid marker";
    case BSV_DISCARD_OTHER_SNAPSHOT: return "different snapshot";
    }
    return "unknown";
}

uint64_t BootstrapResumeOffset(uint64_t partSize, uint64_t fileSize, uint32_t chunkSize)
{
    if (chunkSize == 0 || fileSize == 0 || partSize == 0 || partSize > fileSize)
        return 0;
    const uint64_t aligned = (partSize / chunkSize) * chunkSize;
    const uint64_t lastChunkStart = ((fileSize - 1) / chunkSize) * chunkSize;
    return std::min(aligned, lastChunkStart);
}

BootstrapStagedDecision BootstrapDecideStagedFile(uint64_t fileSize, uint32_t chunkSize, const BootstrapStagedFileFacts& f)
{
    BootstrapStagedDecision d;
    if (f.finalExists) {
        if (f.finalSize == fileSize && f.finalHashOk) {
            d.action = BSA_KEEP;
            // A leftover .part next to a verified file is garbage.
            d.discardPart = f.partExists;
            return d;
        }
        // Present but wrong: never trusted, never counted. A .part sitting beside
        // a bad final file has no defined provenance either.
        d.discardFinal = true;
        d.discardPart = f.partExists;
        d.action = BSA_FETCH_ALL;
        return d;
    }
    if (f.partExists) {
        const uint64_t off = BootstrapResumeOffset(f.partSize, fileSize, chunkSize);
        if (off > 0) {
            d.action = BSA_RESUME_PART;
            d.resumeOffset = off;
            return d;
        }
        d.discardPart = true;
    }
    d.action = BSA_FETCH_ALL;
    return d;
}

BootstrapWorkQueue::BootstrapWorkQueue(const std::vector<uint32_t>& p) : pending(p.begin(), p.end()), done(0) {}

bool BootstrapWorkQueue::Claim(uint32_t& idx)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (pending.empty())
        return false;
    idx = pending.front();
    pending.pop_front();
    claimed.insert(idx);
    return true;
}

void BootstrapWorkQueue::Release(uint32_t idx)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (claimed.erase(idx) != 0)
        pending.push_front(idx);
}

void BootstrapWorkQueue::Complete(uint32_t idx)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (claimed.erase(idx) != 0)
        ++done;
}

bool BootstrapWorkQueue::AllDone() const
{
    std::lock_guard<std::mutex> lock(mtx);
    return pending.empty() && claimed.empty();
}

bool BootstrapWorkQueue::HasPending() const
{
    std::lock_guard<std::mutex> lock(mtx);
    return !pending.empty();
}

size_t BootstrapWorkQueue::PendingCount() const
{
    std::lock_guard<std::mutex> lock(mtx);
    return pending.size();
}

size_t BootstrapWorkQueue::ClaimedCount() const
{
    std::lock_guard<std::mutex> lock(mtx);
    return claimed.size();
}

size_t BootstrapWorkQueue::DoneCount() const
{
    std::lock_guard<std::mutex> lock(mtx);
    return done;
}

int BootstrapWorkQueue::AddStrike(uint32_t idx)
{
    std::lock_guard<std::mutex> lock(mtx);
    return ++strikes[idx];
}

bool BootstrapWorkQueue::MustRestart(uint32_t idx) const
{
    std::lock_guard<std::mutex> lock(mtx);
    std::map<uint32_t, int>::const_iterator it = strikes.find(idx);
    return it != strikes.end() && it->second > 0;
}

int64_t BootstrapReconnectDelayMs(int consecutiveFailures, unsigned int jitterSeed)
{
    if (consecutiveFailures <= 0)
        return 0;
    const int shift = std::min(consecutiveFailures - 1, 5);
    const int64_t base = std::min<int64_t>(30000, (int64_t)1000 << shift);
    const int64_t span = base / 2; // total jitter window = +-25%
    const int64_t jitter = span > 0 ? (int64_t)(jitterSeed % (unsigned int)(span + 1)) - span / 2 : 0;
    return base + jitter;
}

std::string BootstrapFormatGiB(uint64_t bytes)
{
    return strprintf("%.2f GiB", bytes / 1073741824.0);
}

std::string BootstrapFormatProgressLine(int percent, uint64_t received, uint64_t total, double mibPerSec, int streams, int servers)
{
    std::string line = strprintf("Bootstrap snapshot: %3d%%  %.2f / %.2f GiB  %.1f MiB/s",
                                 percent, received / 1073741824.0, total / 1073741824.0, mibPerSec);
    if (streams > 0 && servers > 1)
        line += strprintf("  (%d streams, %d servers)", streams, servers);
    else if (streams > 0)
        line += strprintf("  (%d streams)", streams);
    return line;
}

// ---- BootstrapPeerBoard ------------------------------------------------------------

BootstrapPeerBoard::BootstrapPeerBoard(size_t nPeers, int nStreams, const BootstrapPeerPolicy& policy)
    : pol(policy), peers(nPeers), streams(nStreams > 0 ? (size_t)nStreams : 0)
{
}

int BootstrapPeerBoard::AttachedLocked(int peer) const
{
    int n = 0;
    for (size_t i = 0; i < streams.size(); ++i)
        if (streams[i].peer == peer && !streams[i].move)
            ++n;
    return n;
}

double BootstrapPeerBoard::StreamLifeRate(const StreamState& st, int64_t nowMs) const
{
    const int64_t age = nowMs - st.attachedMs;
    if (!st.connected || age <= 0)
        return 0;
    return st.bytes * 1000.0 / age;
}

bool BootstrapPeerBoard::PeerQuietLocked(int peer, int64_t nowMs) const
{
    for (size_t i = 0; i < streams.size(); ++i) {
        const StreamState& st = streams[i];
        if (st.peer == peer && st.connected && nowMs - std::max(st.attachedMs, st.lastByteMs) <= pol.stallMs)
            return false;
    }
    return true;
}

double BootstrapPeerBoard::StreamRate(const StreamState& st, int64_t nowMs, bool matureOnly) const
{
    const int64_t age = nowMs - st.attachedMs;
    if (!st.connected || age <= 0)
        return -1;
    if (age < pol.windowMs) {
        if (matureOnly || age < 1000)
            return -1;
        return st.bytes * 1000.0 / age;
    }
    // bytes in the last window = total - total at the last sample at or before the window start
    uint64_t base = 0;
    for (std::deque<Sample>::const_iterator it = st.samples.begin(); it != st.samples.end(); ++it) {
        if (it->t > nowMs - pol.windowMs)
            break;
        base = it->bytes;
    }
    return (st.bytes - base) * 1000.0 / pol.windowMs;
}

double BootstrapPeerBoard::PeerPerStreamRate(int peer, int64_t nowMs) const
{
    double sum = 0;
    int n = 0;
    for (size_t i = 0; i < streams.size(); ++i) {
        const StreamState& st = streams[i];
        if (st.peer != peer || st.move || st.idle)
            continue;
        const double r = StreamRate(st, nowMs, true);
        if (r < 0)
            continue;
        sum += r;
        ++n;
    }
    return n ? sum / n : -1;
}

size_t BootstrapPeerBoard::UsablePeers() const
{
    std::lock_guard<std::mutex> lock(mtx);
    size_t n = 0;
    for (size_t i = 0; i < peers.size(); ++i)
        if (Usable(peers[i]))
            ++n;
    return n;
}

int BootstrapPeerBoard::StreamPeer(int s) const
{
    std::lock_guard<std::mutex> lock(mtx);
    return (s >= 0 && (size_t)s < streams.size() && streams[s].connected) ? streams[s].peer : -1;
}

int BootstrapPeerBoard::Assign(int s, int64_t nowMs)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (s < 0 || (size_t)s >= streams.size())
        return -1;
    // Known per-stream rate of each usable peer (live, else the last one seen).
    std::vector<double> rate(peers.size(), -1);
    double best = 0;
    for (size_t p = 0; p < peers.size(); ++p) {
        if (!Usable(peers[p]))
            continue;
        double r = PeerPerStreamRate((int)p, nowMs);
        if (r < 0)
            r = peers[p].lastPerStream;
        rate[p] = r;
        best = std::max(best, r);
    }
    int pick = -1;
    bool pickAvoid = true;
    double pickLoad = 0;
    for (size_t p = 0; p < peers.size(); ++p) {
        if (!Usable(peers[p]))
            continue;
        const bool avoid = nowMs < peers[p].cooldownUntilMs || nowMs < peers[p].penaltyUntilMs;
        const double factor = (rate[p] < 0 || best <= 0) ? 1.0 : std::max(0.05, rate[p] / best);
        const double load = (AttachedLocked((int)p) + 1) / factor;
        if (pick < 0 || (pickAvoid && !avoid) || (avoid == pickAvoid && load < pickLoad)) {
            pick = (int)p;
            pickAvoid = avoid;
            pickLoad = load;
        }
    }
    StreamState& st = streams[s];
    st.peer = pick; // reserved: concurrent Assign calls see this stream on its peer
    st.connected = false;
    st.move = false;
    return pick;
}

void BootstrapPeerBoard::Attach(int s, int peer, int64_t nowMs)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (s < 0 || (size_t)s >= streams.size() || peer < 0 || (size_t)peer >= peers.size())
        return;
    StreamState& st = streams[s];
    st.peer = peer;
    st.connected = true;
    st.idle = false;
    st.move = false;
    st.attachedMs = nowMs;
    st.lastByteMs = nowMs;
    st.bytes = 0;
    st.samples.clear();
    st.remaining.clear();
    st.lastMoveMs = nowMs;
}

void BootstrapPeerBoard::Detach(int s)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (s < 0 || (size_t)s >= streams.size())
        return;
    StreamState& st = streams[s];
    if (st.connected && st.peer >= 0) {
        const double r = StreamRate(st, st.lastByteMs, false);
        if (r > 0)
            peers[st.peer].lastPerStream = r;
    }
    st.peer = -1;
    st.connected = false;
    st.move = false;
    st.remaining.clear();
}

void BootstrapPeerBoard::SetIdle(int s, bool idle)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (s >= 0 && (size_t)s < streams.size())
        streams[s].idle = idle;
}

void BootstrapPeerBoard::ConnectFailed(int peer, int64_t nowMs)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (peer < 0 || (size_t)peer >= peers.size())
        return;
    PeerState& p = peers[peer];
    ++p.failures;
    const int shift = std::min(p.failures - 1, 16);
    p.cooldownUntilMs = nowMs + std::min<int64_t>(pol.failBackoffMaxMs, pol.failBackoffBaseMs << shift);
}

void BootstrapPeerBoard::ConnectOk(int peer)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (peer >= 0 && (size_t)peer < peers.size()) {
        peers[peer].failures = 0;
        peers[peer].cooldownUntilMs = 0;
    }
}

void BootstrapPeerBoard::ManifestMismatch(int peer)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (peer >= 0 && (size_t)peer < peers.size())
        peers[peer].ignored = true;
}

void BootstrapPeerBoard::NoteClaim(int s, uint32_t file, uint64_t remaining, bool resumed)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (s < 0 || (size_t)s >= streams.size())
        return;
    streams[s].remaining[file] = remaining;
    if (!resumed)
        contributors.erase(file);
    else if (contributors[file].empty())
        contributors[file].insert(-1); // a prefix of unknown origin is already on disk
}

void BootstrapPeerBoard::NoteChunk(int s, uint32_t file, uint64_t bytes, int64_t nowMs)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (s < 0 || (size_t)s >= streams.size())
        return;
    StreamState& st = streams[s];
    st.bytes += bytes;
    st.lastByteMs = nowMs;
    st.samples.push_back(Sample{nowMs, st.bytes});
    // keep one sample at or before the window start, drop the rest of the older ones
    while (st.samples.size() >= 2 && st.samples[1].t <= nowMs - pol.windowMs)
        st.samples.pop_front();
    std::map<uint32_t, uint64_t>::iterator it = st.remaining.find(file);
    if (it != st.remaining.end())
        it->second = it->second > bytes ? it->second - bytes : 0;
    if (st.peer >= 0) {
        peers[st.peer].bytes += bytes;
        contributors[file].insert(st.peer);
    }
}

void BootstrapPeerBoard::NoteRelease(int s, uint32_t file)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (s >= 0 && (size_t)s < streams.size())
        streams[s].remaining.erase(file);
}

void BootstrapPeerBoard::NoteComplete(int s, uint32_t file)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (s >= 0 && (size_t)s < streams.size())
        streams[s].remaining.erase(file);
    contributors.erase(file);
}

bool BootstrapPeerBoard::HashFailed(int s, uint32_t file)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::set<int> blamed;
    std::map<uint32_t, std::set<int> >::iterator it = contributors.find(file);
    if (it != contributors.end()) {
        blamed = it->second;
        contributors.erase(it); // the file is fetched again from byte 0
    }
    const int reporter = (s >= 0 && (size_t)s < streams.size()) ? streams[s].peer : -1;
    if (blamed.empty() && reporter >= 0)
        blamed.insert(reporter);
    const bool sole = blamed.size() == 1 && *blamed.begin() >= 0;
    for (std::set<int>::const_iterator b = blamed.begin(); b != blamed.end(); ++b) {
        if (*b < 0)
            continue;
        PeerState& p = peers[*b];
        ++p.strikes;
        bool otherUsable = false;
        for (size_t q = 0; q < peers.size(); ++q)
            if ((int)q != *b && Usable(peers[q]))
                otherUsable = true;
        // A peer that alone supplied a file that fails its own manifest is lying or broken: stop using it
        // (never the last usable peer: then the old strike limit ends the attempt). With mixed
        // suppliers the culprit is unknown, so it takes a second failure.
        if (otherUsable && (sole || p.strikes >= 2))
            p.banned = true;
    }
    for (size_t q = 0; q < peers.size(); ++q)
        if ((int)q != reporter && Usable(peers[q]))
            return true;
    return false;
}

BootstrapPeerSnapshot BootstrapPeerBoard::Peer(int peer, int64_t nowMs) const
{
    std::lock_guard<std::mutex> lock(mtx);
    BootstrapPeerSnapshot out;
    if (peer < 0 || (size_t)peer >= peers.size())
        return out;
    out.bytes = peers[peer].bytes;
    out.ignored = peers[peer].ignored;
    out.banned = peers[peer].banned;
    out.partial = peers[peer].partial;
    double rate = 0;
    for (size_t i = 0; i < streams.size(); ++i) {
        const StreamState& st = streams[i];
        if (st.peer != peer || !st.connected)
            continue;
        ++out.streams;
        const double r = StreamRate(st, nowMs, false);
        if (r > 0)
            rate += r;
    }
    out.mibps = rate / 1048576.0;
    return out;
}

std::vector<BootstrapMove> BootstrapPeerBoard::Rebalance(int64_t nowMs)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::vector<BootstrapMove> moves;
    size_t usable = 0;
    for (size_t p = 0; p < peers.size(); ++p)
        if (Usable(peers[p]))
            ++usable;
    if (usable == 0)
        return moves;

    // per-stream rate of each peer, and the best one
    std::vector<double> per(peers.size(), -1);
    for (size_t p = 0; p < peers.size(); ++p)
        if (Usable(peers[p]))
            per[p] = PeerPerStreamRate((int)p, nowMs);

    // A short window is noisy (a capped server hands out chunks in quanta): a server is judged slow only
    // when even its most generous estimate (window or average since attach) is slow, and another server fast
    // only by its most conservative one. A wrong move costs the stream's whole window in flight.
    std::vector<double> generous(peers.size(), -1), conservative(peers.size(), -1);
    for (size_t p = 0; p < peers.size(); ++p) {
        if (!Usable(peers[p]))
            continue;
        double sumG = 0, sumC = 0;
        int n = 0;
        for (size_t i = 0; i < streams.size(); ++i) {
            const StreamState& st = streams[i];
            if (st.peer != (int)p || st.move || st.idle)
                continue;
            const double rw = StreamRate(st, nowMs, true);
            if (rw < 0)
                continue;
            const double rl = StreamLifeRate(st, nowMs);
            sumG += std::max(rw, rl);
            sumC += std::min(rw, rl);
            ++n;
        }
        if (n) {
            generous[p] = sumG / n;
            conservative[p] = sumC / n;
        }
    }

    for (size_t i = 0; i < streams.size(); ++i) {
        StreamState& st = streams[i];
        if (!st.connected || st.move || st.peer < 0)
            continue;
        BootstrapMove mv;
        mv.stream = (int)i;
        if (!Usable(peers[st.peer])) {
            mv.reason = BMR_UNUSABLE;
        } else if (!st.idle && usable >= 2 && nowMs - std::max(st.attachedMs, st.lastByteMs) > pol.stallMs &&
                   PeerQuietLocked(st.peer, nowMs)) {
            // Only when the whole server is quiet: a server that feeds its other streams is merely
            // sharing a cap unevenly, and moving this stream costs its in-flight window for nothing.
            mv.reason = BMR_STALLED;
            peers[st.peer].penaltyUntilMs = nowMs + pol.penaltyMs;
        } else {
            continue;
        }
        st.move = true;
        st.lastMoveMs = nowMs;
        moves.push_back(mv);
    }

    // slow peers: one stream per peer per call, never the last stream of a peer (it keeps the rate measured)
    for (size_t p = 0; p < peers.size(); ++p) {
        if (!Usable(peers[p]) || generous[p] < 0 || AttachedLocked((int)p) < 2)
            continue;
        double bestOther = -1;
        for (size_t q = 0; q < peers.size(); ++q)
            if (q != p && Usable(peers[q]) && conservative[q] > bestOther)
                bestOther = conservative[q];
        if (bestOther <= 0 || generous[p] >= pol.slowFraction * bestOther)
            continue;
        for (size_t i = 0; i < streams.size(); ++i) {
            StreamState& st = streams[i];
            if (st.peer != (int)p || !st.connected || st.move || st.idle ||
                nowMs - st.lastMoveMs < pol.moveCooldownMs || StreamRate(st, nowMs, true) < 0)
                continue;
            BootstrapMove mv;
            mv.stream = (int)i;
            mv.reason = BMR_SLOW;
            st.move = true;
            st.lastMoveMs = nowMs;
            peers[p].penaltyUntilMs = nowMs + pol.penaltyMs;
            moves.push_back(mv);
            break;
        }
    }

    // work stealing: an idle stream takes over the unfinished files of a much slower holder
    bool haveIdle = false;
    for (size_t i = 0; i < streams.size(); ++i)
        if (streams[i].idle && !streams[i].connected)
            haveIdle = true;
    if (haveIdle) {
        int victim = -1;
        double victimSeconds = 0;
        for (size_t i = 0; i < streams.size(); ++i) {
            StreamState& st = streams[i];
            if (!st.connected || st.move || st.idle || st.peer < 0)
                continue;
            // Only another server can take the file over faster: the same server gives the idle stream no
            // more than the victim has, and the move would only throw away the victim's requests in flight.
            double bestRate = 0;
            for (size_t p = 0; p < peers.size(); ++p)
                if ((int)p != st.peer && Usable(peers[p]))
                    bestRate = std::max(bestRate, conservative[p]);
            uint64_t left = 0;
            for (std::map<uint32_t, uint64_t>::const_iterator f = st.remaining.begin(); f != st.remaining.end(); ++f)
                left += f->second;
            const double r = std::max(1.0, std::max(StreamRate(st, nowMs, false), StreamLifeRate(st, nowMs)));
            const double secs = left / r;
            if (secs > pol.stealMinSeconds && bestRate >= pol.stealFactor * r && secs > victimSeconds) {
                victim = (int)i;
                victimSeconds = secs;
            }
        }
        if (victim >= 0) {
            streams[victim].move = true;
            streams[victim].lastMoveMs = nowMs;
            BootstrapMove mv;
            mv.stream = victim;
            mv.reason = BMR_STEAL;
            moves.push_back(mv);
        }
    }
    return moves;
}

std::string BootstrapPeerSummary(const std::vector<std::string>& names, const std::vector<BootstrapPeerSnapshot>& snap)
{
    std::string out;
    for (size_t i = 0; i < snap.size() && i < names.size(); ++i) {
        if (!out.empty())
            out += ", ";
        out += strprintf("%s %d streams %.1f MiB/s %.2f GiB%s", names[i], snap[i].streams, snap[i].mibps,
                         snap[i].bytes / 1073741824.0, snap[i].ignored ? " (different snapshot, ignored)" : snap[i].banned ? " (banned)" : snap[i].partial ? " (shared files only)" : "");
    }
    return out;
}

bool BootstrapWorkQueue::ClaimAllowed(const std::vector<uint8_t>& allowed, uint32_t& idx)
{
    std::lock_guard<std::mutex> lock(mtx);
    for (std::deque<uint32_t>::iterator it = pending.begin(); it != pending.end(); ++it) {
        if (*it < allowed.size() && allowed[*it]) {
            idx = *it;
            pending.erase(it);
            claimed.insert(idx);
            return true;
        }
    }
    return false;
}

bool BootstrapWorkQueue::HasPendingAllowed(const std::vector<uint8_t>& allowed) const
{
    std::lock_guard<std::mutex> lock(mtx);
    for (std::deque<uint32_t>::const_iterator it = pending.begin(); it != pending.end(); ++it)
        if (*it < allowed.size() && allowed[*it])
            return true;
    return false;
}

void BootstrapPeerBoard::SetPartial(int peer, bool partial)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (peer >= 0 && (size_t)peer < peers.size())
        peers[peer].partial = partial;
}

void BootstrapPeerBoard::Defer(int peer, int64_t untilMs)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (peer >= 0 && (size_t)peer < peers.size())
        peers[peer].penaltyUntilMs = std::max(peers[peer].penaltyUntilMs, untilMs);
}
