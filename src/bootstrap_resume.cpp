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

std::string BootstrapFormatProgressLine(int percent, uint64_t received, uint64_t total, double mibPerSec, int streams)
{
    std::string line = strprintf("Bootstrap snapshot: %3d%%  %.2f / %.2f GiB  %.1f MiB/s",
                                 percent, received / 1073741824.0, total / 1073741824.0, mibPerSec);
    if (streams > 0)
        line += strprintf("  (%d streams)", streams);
    return line;
}
