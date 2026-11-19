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
    if (!peers.empty())
        peers[0].answered = true;
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

void BootstrapPeerBoard::SetUnfinishedSource(const std::function<std::vector<uint8_t>()>& fn)
{
    std::lock_guard<std::mutex> lock(mtx);
    unfinishedFn = fn;
}

bool BootstrapPeerBoard::PinBlocksLocked(uint32_t file, int peer) const
{
    std::map<uint32_t, int>::const_iterator it = pinned.find(file);
    if (it == pinned.end() || it->second == peer)
        return false;
    const int pin = it->second;
    // A pin on a peer that is gone or keeps failing to connect would hold the file for ever: it does not count then.
    return pin >= 0 && (size_t)pin < peers.size() && Usable(peers[pin]) && peers[pin].failures < 3;
}

bool BootstrapPeerBoard::HoldsWorkLocked(int peer, const std::vector<uint8_t>& unfinished, const std::map<uint32_t, uint64_t>* only) const
{
    if (only && !only->empty()) {
        for (std::map<uint32_t, uint64_t>::const_iterator it = only->begin(); it != only->end(); ++it)
            if (PeerHasLocked(peer, it->first) && !PinBlocksLocked(it->first, peer))
                return true;
        return false;
    }
    if (unfinished.empty())
        return true; // the board has no view of the queue
    for (size_t f = 0; f < unfinished.size(); ++f)
        if (unfinished[f] && PeerHasLocked(peer, (uint32_t)f) && !PinBlocksLocked((uint32_t)f, peer))
            return true;
    return false;
}

bool BootstrapPeerBoard::ComparableLocked(int peer, const StreamState& victim, const std::vector<uint8_t>& unfinished, int64_t nowMs) const
{
    if (peer < 0 || (size_t)peer >= peers.size() || peer == victim.peer)
        return false;
    const PeerState& p = peers[peer];
    // A server that never answered, failed to connect since, or is being avoided (deferred or just moved off),
    // or holds none of the files the victim still has, is no reason to move a stream: a stream sent to it
    // would get nothing or nothing at all.
    if (!Usable(p) || !p.answered || p.failures > 0 || nowMs < p.penaltyUntilMs)
        return false;
    return HoldsWorkLocked(peer, unfinished, &victim.remaining);
}

bool BootstrapPeerBoard::CanBenchLocked(size_t b, const std::vector<uint8_t>* unfinished, int64_t file) const
{
    bool anyOther = false;
    for (size_t q = 0; q < peers.size(); ++q)
        if (q != b && Usable(peers[q]))
            anyOther = true;
    if (!anyOther)
        return false;
    // Another usable server that has answered must hold every file `b` could still serve: a server that never
    // answered holds nothing as far as anyone knows.
    std::vector<uint32_t> need;
    if (file >= 0)
        need.push_back((uint32_t)file);
    for (size_t f = 0; unfinished && f < unfinished->size(); ++f)
        if ((*unfinished)[f] && PeerHasLocked((int)b, (uint32_t)f))
            need.push_back((uint32_t)f);
    for (size_t i = 0; i < need.size(); ++i) {
        bool other = false;
        for (size_t q = 0; q < peers.size() && !other; ++q)
            other = q != b && Usable(peers[q]) && PeerHasLocked((int)q, need[i]);
        if (!other)
            return false;
    }
    return true;
}

int BootstrapPeerBoard::Assign(int s, int64_t nowMs, bool* anyUseful)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (anyUseful)
        *anyUseful = true;
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
    // Servers that have something for this stream: one that has not answered yet (it must be probed) or that
    // holds a pending file the stream may fetch. When no server does, the caller waits instead of connecting.
    const std::vector<uint8_t> unfinished = unfinishedFn ? unfinishedFn() : std::vector<uint8_t>();
    std::vector<bool> useful(peers.size(), false);
    bool any = false;
    for (size_t p = 0; p < peers.size(); ++p) {
        if (!Usable(peers[p]))
            continue;
        useful[p] = !peers[p].answered || HoldsWorkLocked((int)p, unfinished, NULL);
        any = any || useful[p];
    }
    if (!any) {
        if (anyUseful)
            *anyUseful = false;
        for (size_t p = 0; p < peers.size(); ++p)
            useful[p] = Usable(peers[p]);
    }
    int pick = -1;
    bool pickAvoid = true;
    double pickLoad = 0;
    for (size_t p = 0; p < peers.size(); ++p) {
        if (!Usable(peers[p]) || !useful[p])
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
    p.lastPerStream = -1; // what it gave before it stopped answering says nothing about it now
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
    {
        // A file that failed with mixed suppliers and then verified when ONE server fetched it from byte 0: the
        // other suppliers of the failed attempt were the culprits. Two such files bench a server (never while it is
        // the only holder of a file still to come).
        std::map<uint32_t, int>::const_iterator pin = pinned.find(file);
        std::map<uint32_t, std::set<int> >::iterator sus = suspects.find(file);
        std::map<uint32_t, std::set<int> >::const_iterator con = contributors.find(file);
        if (pin != pinned.end() && sus != suspects.end() && con != contributors.end() && con->second.size() == 1 &&
            *con->second.begin() == pin->second) {
            const std::vector<uint8_t> unfinished = unfinishedFn ? unfinishedFn() : std::vector<uint8_t>();
            for (std::set<int>::const_iterator b = sus->second.begin(); b != sus->second.end(); ++b) {
                if (*b < 0 || (size_t)*b >= peers.size() || !Usable(peers[*b]))
                    continue;
                if (++peers[*b].liarStrikes >= 2 && CanBenchLocked((size_t)*b, unfinished.empty() ? NULL : &unfinished, -1))
                    peers[*b].banned = true;
            }
        }
        suspects.erase(file);
    }
    pinned.erase(file);
    if (s >= 0 && (size_t)s < streams.size())
        streams[s].remaining.erase(file);
    contributors.erase(file);
}

bool BootstrapPeerBoard::PeerHasLocked(int peer, uint32_t file) const
{
    if (peer < 0 || (size_t)peer >= peers.size())
        return false;
    if (!peers[peer].answered)
        return false; // a server that never sent its manifest holds nothing as far as we know
    const std::vector<uint8_t>& has = peers[peer].has;
    return has.empty() || (file < has.size() && has[file]);
}

void BootstrapPeerBoard::SetPeerHas(int peer, const std::vector<uint8_t>& has)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (peer >= 0 && (size_t)peer < peers.size()) {
        peers[peer].has = has;
        peers[peer].answered = true;
    }
}

bool BootstrapPeerBoard::EveryFileHasHolder(const std::vector<uint8_t>& unfinished) const
{
    std::lock_guard<std::mutex> lock(mtx);
    for (size_t f = 0; f < unfinished.size(); ++f) {
        if (!unfinished[f])
            continue;
        bool holder = false;
        for (size_t p = 0; p < peers.size() && !holder; ++p)
            holder = Usable(peers[p]) && PeerHasLocked((int)p, (uint32_t)f);
        if (!holder)
            return false;
    }
    return true;
}

bool BootstrapPeerBoard::AllowConnect(int peer, int64_t nowMs)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (peer < 0 || (size_t)peer >= peers.size())
        return false;
    std::deque<int64_t>& c = peers[peer].connects;
    while (!c.empty() && c.front() <= nowMs - 60000)
        c.pop_front();
    if ((int)c.size() >= pol.maxConnectsPerMinute)
        return false;
    c.push_back(nowMs);
    return true;
}

void BootstrapPeerBoard::MaskPinned(int s, std::vector<uint8_t>& mask) const
{
    std::lock_guard<std::mutex> lock(mtx);
    const int mine = (s >= 0 && (size_t)s < streams.size()) ? streams[s].peer : -1;
    for (std::map<uint32_t, int>::const_iterator it = pinned.begin(); it != pinned.end(); ++it) {
        const int pin = it->second;
        if (pin == mine || pin < 0 || (size_t)pin >= peers.size())
            continue;
        // A pin on a peer that is gone or keeps failing to connect would hold the file for ever: ignore it then.
        if (!Usable(peers[pin]) || peers[pin].failures >= 3)
            continue;
        if (it->first < mask.size())
            mask[it->first] = 0;
    }
}

bool BootstrapPeerBoard::HashFailed(int s, uint32_t file, const std::vector<uint8_t>* unfinished)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::set<int> blamed;
    std::map<uint32_t, std::set<int> >::iterator it = contributors.find(file);
    if (it != contributors.end()) {
        blamed = it->second;
        contributors.erase(it); // the file is fetched again from byte 0
    }
    pinned.erase(file);
    suspects.erase(file);
    const int reporter = (s >= 0 && (size_t)s < streams.size()) ? streams[s].peer : -1;
    if (blamed.empty() && reporter >= 0)
        blamed.insert(reporter);
    // One known supplier alone: it is the culprit. Several suppliers, or a prefix of unknown origin (a .part
    // from an earlier run, a torn write): the culprit cannot be told, so nobody is blamed and nobody is benched;
    // the file is fetched again from byte 0 from ONE peer, so the next result names one server.
    const bool sole = blamed.size() == 1 && *blamed.begin() >= 0;
    if (sole) {
        const size_t b = (size_t)*blamed.begin();
        peers[b].strikes++;
        // Never bench a peer that is the only holder of a file still to come: this covers the primary while it
        // is the only source of some pending file, and the last peer able to serve everything that remains.
        if (CanBenchLocked(b, unfinished, (int64_t)file))
            peers[b].banned = true;
    } else {
        int pick = -1;
        for (size_t q = 0; q < peers.size(); ++q) {
            if (!Usable(peers[q]) || !PeerHasLocked((int)q, file))
                continue;
            pick = (int)q; // the primary when it can serve the file, else the first that can
            break;
        }
        if (pick >= 0) {
            pinned[file] = pick;
            // If that one server gets it right, the others that supplied the failed attempt were the culprits.
            std::set<int> others;
            for (std::set<int>::const_iterator b = blamed.begin(); b != blamed.end(); ++b)
                if (*b >= 0 && *b != pick)
                    others.insert(*b);
            if (!others.empty())
                suspects[file] = others;
        }
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

std::vector<BootstrapMove> BootstrapPeerBoard::Rebalance(int64_t nowMs, const std::function<void(const BootstrapMove&)>& apply)
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
    const std::vector<uint8_t> unfinished = unfinishedFn ? unfinishedFn() : std::vector<uint8_t>();
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
        mv.peer = st.peer;
        if (!Usable(peers[st.peer])) {
            mv.reason = BMR_UNUSABLE;
        } else if (!st.idle && usable >= 2 && nowMs - std::max(st.attachedMs, st.lastByteMs) > pol.stallMs &&
                   PeerQuietLocked(st.peer, nowMs) &&
                   AttachedLocked(st.peer) >= 2) {
            // Only when the whole server is quiet: a server that feeds its other streams is merely
            // sharing a cap unevenly, and moving this stream costs its in-flight window for nothing.
            // And never its last stream: that one stays to see the server recover (its live rate is what lets the
            // others come back; a server that lost all its streams to a hiccup would never be compared again).
            mv.reason = BMR_STALLED;
            peers[st.peer].penaltyUntilMs = nowMs + pol.penaltyMs;
        } else {
            continue;
        }
        st.move = true;
        st.lastMoveMs = nowMs;
        moves.push_back(mv);
    }

    // slow peers: one stream per peer per call, never the last stream of a peer (it keeps the rate measured).
    // Only LIVE rates are compared, and only against a server that could really take the stream (it answered,
    // has not failed to connect since, is not being avoided, and holds one of the files the stream still has).
    for (size_t p = 0; p < peers.size(); ++p) {
        if (!Usable(peers[p]) || generous[p] < 0 || AttachedLocked((int)p) < 2)
            continue;
        for (size_t i = 0; i < streams.size(); ++i) {
            StreamState& st = streams[i];
            if (st.peer != (int)p || !st.connected || st.move || st.idle ||
                nowMs - st.lastMoveMs < pol.moveCooldownMs || StreamRate(st, nowMs, true) < 0)
                continue;
            double bestOther = -1;
            for (size_t q = 0; q < peers.size(); ++q)
                if (q != p && ComparableLocked((int)q, st, unfinished, nowMs) && conservative[q] > bestOther)
                    bestOther = conservative[q];
            if (bestOther <= 0 || generous[p] >= pol.slowFraction * bestOther)
                continue;
            BootstrapMove mv;
            mv.stream = (int)i;
            mv.peer = st.peer;
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
            // Only a stream that has had its whole measuring window and has not just been placed or moved is a
            // candidate: before that its rate says nothing (a stream with no byte yet would count as the slowest).
            if (!st.connected || st.move || st.idle || st.peer < 0 || StreamRate(st, nowMs, true) < 0 ||
                nowMs - st.lastMoveMs < pol.moveCooldownMs)
                continue;
            // Only another server can take the file over faster: the same server gives the idle stream no
            // more than the victim has, and the move would only throw away the victim's requests in flight.
            double bestRate = 0;
            for (size_t p = 0; p < peers.size(); ++p) {
                if (!ComparableLocked((int)p, st, unfinished, nowMs))
                    continue;
                // its live rate, else what it last gave a stream (its streams may have run out of files)
                const double r = conservative[p] > 0 ? conservative[p] : peers[p].lastPerStream;
                bestRate = std::max(bestRate, r);
            }
            uint64_t left = 0;
            for (std::map<uint32_t, uint64_t>::const_iterator f = st.remaining.begin(); f != st.remaining.end(); ++f)
                left += f->second;
            const double r = std::max(1.0, std::max(StreamRate(st, nowMs, false), StreamLifeRate(st, nowMs)));
            const double secs = left / r;
            // Time the idle stream would save by finishing the rest of the file itself (restarting costs the
            // victim's requests in flight, which this must outweigh): worth it only if it saves more than
            // stealMinSeconds and the other server is clearly faster.
            const double saved = secs - left / std::max(1.0, bestRate);
            if (saved > pol.stealMinSeconds && bestRate >= pol.stealFactor * r && saved > victimSeconds) {
                victim = (int)i;
                victimSeconds = saved;
            }
        }
        if (victim >= 0) {
            streams[victim].move = true;
            streams[victim].lastMoveMs = nowMs;
            peers[streams[victim].peer].penaltyUntilMs = nowMs + pol.penaltyMs; // the next assignment avoids it
            BootstrapMove mv;
            mv.stream = victim;
            mv.peer = streams[victim].peer;
            mv.reason = BMR_STEAL;
            moves.push_back(mv);
        }
    }
    // The caller flags for the connection a move is meant for are set under the lock that decided it, so a
    // stream that reconnected in the meantime is never cancelled by a decision about its old connection.
    if (apply)
        for (size_t i = 0; i < moves.size(); ++i)
            apply(moves[i]);
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

std::vector<uint8_t> BootstrapWorkQueue::UnfinishedMask(size_t nFiles) const
{
    std::lock_guard<std::mutex> lock(mtx);
    std::vector<uint8_t> mask(nFiles, 0);
    for (std::deque<uint32_t>::const_iterator it = pending.begin(); it != pending.end(); ++it)
        if (*it < nFiles)
            mask[*it] = 1;
    for (std::set<uint32_t>::const_iterator it = claimed.begin(); it != claimed.end(); ++it)
        if (*it < nFiles)
            mask[*it] = 1;
    return mask;
}
