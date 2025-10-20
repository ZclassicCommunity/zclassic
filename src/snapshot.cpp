// Copyright (c) 2025 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "snapshot.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "clientversion.h"
#include "coins.h"
#include "hash.h"
#include "main.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "streams.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

CSnapshotStore* psnapshotstore = NULL;
CSnapshotRateLimiter* psnapshotratelimiter = NULL;

bool CSnapshotManifest::IsValid() const
{
    if (nBlockHeight == 0) return false;
    if (vChunks.empty()) return false;
    if (nTotalSize == 0) return false;

    // Verify chunks are sequential
    for (size_t i = 0; i < vChunks.size(); i++) {
        if (vChunks[i].nChunkNumber != i) {
            LogPrintf("CSnapshotManifest::IsValid(): chunk %d has wrong number %d\n",
                     i, vChunks[i].nChunkNumber);
            return false;
        }
    }

    return true;
}

//
// CSnapshotDownloadState implementation
//

void CSnapshotDownloadState::MarkChunkReceived(uint32_t nChunk)
{
    if (nChunk < nTotalChunks) {
        mapChunksReceived[nChunk] = true;

        // Start timer on first chunk
        if (nDownloadStartTime == 0) {
            nDownloadStartTime = GetTime();
            nLastProgressTime = nDownloadStartTime;
            LogPrintf("Snapshot Download: Starting download of %d chunks (%.2f GB)...\n",
                     nTotalChunks, (nTotalChunks * SNAPSHOT_CHUNK_SIZE) / (1024.0 * 1024.0 * 1024.0));
        }

        // Log progress every 10 chunks or every 30 seconds
        uint32_t nReceived = GetReceivedCount();
        int64_t nNow = GetTime();
        bool bShouldLog = (nReceived % 10 == 0) || (nNow - nLastProgressTime >= 30);

        if (bShouldLog && nReceived > nLastProgressCount) {
            LogProgress();
            nLastProgressTime = nNow;
            nLastProgressCount = nReceived;
        }

        // Log completion message
        if (IsComplete()) {
            int64_t nTotalTime = nNow - nDownloadStartTime;
            LogPrintf("*** Snapshot Download Complete! ***\n");
            LogPrintf("Downloaded %d chunks (%.2f GB) in %d seconds\n",
                     nTotalChunks, (nTotalChunks * SNAPSHOT_CHUNK_SIZE) / (1024.0 * 1024.0 * 1024.0), nTotalTime);
            LogPrintf("Now extracting snapshot... (this may take 30-60 seconds)\n");
        }
    }
}

void CSnapshotDownloadState::LogProgress()
{
    uint32_t nReceived = GetReceivedCount();
    if (nReceived == 0 || nTotalChunks == 0) return;

    int64_t nNow = GetTime();
    double dPercent = (nReceived * 100.0) / nTotalChunks;
    uint64_t nBytesDownloaded = (uint64_t)nReceived * SNAPSHOT_CHUNK_SIZE;
    uint64_t nBytesTotal = (uint64_t)nTotalChunks * SNAPSHOT_CHUNK_SIZE;
    double dGBDownloaded = nBytesDownloaded / (1024.0 * 1024.0 * 1024.0);
    double dGBTotal = nBytesTotal / (1024.0 * 1024.0 * 1024.0);

    // Calculate ETA
    std::string strETA = "calculating...";
    if (nDownloadStartTime > 0 && nReceived > 0) {
        int64_t nElapsed = nNow - nDownloadStartTime;
        if (nElapsed > 0) {
            double dChunksPerSec = (double)nReceived / nElapsed;
            uint32_t nRemaining = nTotalChunks - nReceived;
            int64_t nETASeconds = (int64_t)(nRemaining / dChunksPerSec);

            if (nETASeconds < 60) {
                strETA = strprintf("%d seconds", nETASeconds);
            } else if (nETASeconds < 3600) {
                strETA = strprintf("%d minutes", nETASeconds / 60);
            } else {
                strETA = strprintf("%d hours %d minutes", nETASeconds / 3600, (nETASeconds % 3600) / 60);
            }
        }
    }

    LogPrintf("Snapshot Download: %d/%d chunks (%.1f%%) - %.2f/%.2f GB - ETA: %s\n",
             nReceived, nTotalChunks, dPercent, dGBDownloaded, dGBTotal, strETA);
}

bool CSnapshotDownloadState::IsChunkReceived(uint32_t nChunk) const
{
    auto it = mapChunksReceived.find(nChunk);
    return (it != mapChunksReceived.end() && it->second);
}

bool CSnapshotDownloadState::IsComplete() const
{
    for (uint32_t i = 0; i < nTotalChunks; i++) {
        if (!IsChunkReceived(i)) {
            return false;
        }
    }
    return true;
}

uint32_t CSnapshotDownloadState::GetNextChunkToRequest() const
{
    // Find first chunk we haven't received
    for (uint32_t i = 0; i < nTotalChunks; i++) {
        if (!IsChunkReceived(i)) {
            return i;
        }
    }
    return nTotalChunks; // All received
}

uint32_t CSnapshotDownloadState::GetReceivedCount() const
{
    uint32_t count = 0;
    for (const auto& pair : mapChunksReceived) {
        if (pair.second) count++;
    }
    return count;
}

void CSnapshotDownloadState::RecordChunkRequest(uint32_t nChunk, int64_t nTime)
{
    mapChunkRequests[nChunk] = nTime;
}

bool CSnapshotDownloadState::HasRecentRequest(uint32_t nChunk, int64_t nNow) const
{
    auto it = mapChunkRequests.find(nChunk);
    if (it == mapChunkRequests.end()) {
        return false;
    }
    // Consider request "recent" if within last 60 seconds
    return (nNow - it->second) < 60;
}

//
// CSnapshotStore implementation
//

CSnapshotStore::CSnapshotStore()
{
}

bool CSnapshotStore::Initialize(uint32_t nHeight)
{
    try {
        boost::filesystem::path dataDir = GetDataDir();
        pathSnapshotDir = dataDir / "snapshots" / std::to_string(nHeight);

        if (!boost::filesystem::exists(pathSnapshotDir)) {
            boost::filesystem::create_directories(pathSnapshotDir);
        }
    } catch (const boost::filesystem::filesystem_error& e) {
        LogPrintf("CSnapshotStore::Initialize(): Failed to create snapshot directory: %s\n", e.what());
        return false;
    }

    // Try to load existing manifest
    if (!LoadManifest()) {
        // If no manifest exists, create from hardcoded data
        manifest = GetHardcodedManifest();
        if (!manifest.IsValid()) {
            LogPrintf("CSnapshotStore::Initialize(): hardcoded manifest is invalid\n");
            return false;
        }
        SaveManifest(manifest);
    }

    LogPrintf("CSnapshotStore: initialized for height %d with %d chunks\n",
             nHeight, manifest.GetChunkCount());

    return true;
}

bool CSnapshotStore::LoadManifest()
{
    boost::filesystem::path manifestPath = pathSnapshotDir / "manifest.dat";

    if (!boost::filesystem::exists(manifestPath)) {
        return false;
    }

    try {
        CAutoFile file(fopen(manifestPath.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);
        if (file.IsNull()) {
            return false;
        }

        file >> manifest;

        if (!manifest.IsValid()) {
            LogPrintf("CSnapshotStore::LoadManifest(): loaded manifest is invalid\n");
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        LogPrintf("CSnapshotStore::LoadManifest(): error: %s\n", e.what());
        return false;
    }
}

bool CSnapshotStore::SaveManifest(const CSnapshotManifest& manifestIn)
{
    boost::filesystem::path manifestPath = pathSnapshotDir / "manifest.dat";

    try {
        CAutoFile file(fopen(manifestPath.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION);
        if (file.IsNull()) {
            LogPrintf("CSnapshotStore::SaveManifest(): failed to open file\n");
            return false;
        }

        file << manifestIn;
        manifest = manifestIn;

        return true;
    } catch (const std::exception& e) {
        LogPrintf("CSnapshotStore::SaveManifest(): error: %s\n", e.what());
        return false;
    }
}

bool CSnapshotStore::HasChunk(uint32_t nChunk) const
{
    if (nChunk >= manifest.GetChunkCount()) {
        return false;
    }

    boost::filesystem::path chunkPath = pathSnapshotDir /
        ("chunk-" + strprintf("%03d", nChunk) + ".dat");

    return boost::filesystem::exists(chunkPath);
}

bool CSnapshotStore::SaveChunk(uint32_t nChunk, const std::vector<unsigned char>& vData)
{
    if (nChunk >= manifest.GetChunkCount()) {
        LogPrintf("CSnapshotStore::SaveChunk(): invalid chunk number %d\n", nChunk);
        return false;
    }

    // Verify hash
    if (!VerifyChunk(nChunk, vData)) {
        LogPrintf("CSnapshotStore::SaveChunk(): chunk %d hash verification failed\n", nChunk);
        return false;
    }

    boost::filesystem::path chunkPath = pathSnapshotDir /
        ("chunk-" + strprintf("%03d", nChunk) + ".dat");

    try {
        boost::filesystem::ofstream file(chunkPath, std::ios::binary);
        if (!file) {
            LogPrintf("CSnapshotStore::SaveChunk(): failed to open file for chunk %d\n", nChunk);
            return false;
        }

        file.write((const char*)vData.data(), vData.size());
        file.close();

        LogPrint("snapshot", "SaveChunk: saved chunk %d (%d bytes)\n",
                nChunk, vData.size());

        return true;
    } catch (const std::exception& e) {
        LogPrintf("CSnapshotStore::SaveChunk(): error saving chunk %d: %s\n",
                 nChunk, e.what());
        return false;
    }
}

bool CSnapshotStore::LoadChunk(uint32_t nChunk, std::vector<unsigned char>& vData) const
{
    if (nChunk >= manifest.GetChunkCount()) {
        return false;
    }

    boost::filesystem::path chunkPath = pathSnapshotDir /
        ("chunk-" + strprintf("%03d", nChunk) + ".dat");

    if (!boost::filesystem::exists(chunkPath)) {
        return false;
    }

    try {
        boost::filesystem::ifstream file(chunkPath, std::ios::binary);
        if (!file) {
            return false;
        }

        // Get file size
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        vData.resize(size);
        file.read((char*)vData.data(), size);
        file.close();

        return true;
    } catch (const std::exception& e) {
        LogPrintf("CSnapshotStore::LoadChunk(): error loading chunk %d: %s\n",
                 nChunk, e.what());
        return false;
    }
}

bool CSnapshotStore::VerifyChunk(uint32_t nChunk, const std::vector<unsigned char>& vData) const
{
    if (nChunk >= manifest.vChunks.size()) {
        return false;
    }

    const CSnapshotChunkInfo& info = manifest.vChunks[nChunk];

    // Verify size
    if (vData.size() != info.nSize) {
        LogPrintf("CSnapshotStore::VerifyChunk(): chunk %d size mismatch: expected %d, got %d\n",
                 nChunk, info.nSize, vData.size());
        return false;
    }

    // Verify hash using SINGLE SHA-256 (not double like Hash() function)
    // The manifest hashes were created with sha256sum which is single SHA-256
    // SHA-256 produces big-endian output, but uint256 displays in little-endian,
    // so we need to reverse the bytes
    unsigned char hashBytes[32];
    CSHA256().Write(vData.data(), vData.size()).Finalize(hashBytes);

    // Reverse bytes for uint256 (big-endian to little-endian)
    uint256 hash;
    for (int i = 0; i < 32; i++) {
        *(hash.begin() + i) = hashBytes[31 - i];
    }

    if (hash != info.hashChunk) {
        LogPrintf("CSnapshotStore::VerifyChunk(): chunk %d hash mismatch\n", nChunk);
        LogPrintf("  Expected: %s\n", info.hashChunk.ToString());
        LogPrintf("  Got:      %s\n", hash.ToString());
        return false;
    }

    return true;
}

bool CSnapshotStore::ExtractSnapshot(const boost::filesystem::path& dataDir)
{
    LogPrintf("CSnapshotStore::ExtractSnapshot(): extracting snapshot to %s\n",
             dataDir.string());

    // Verify all chunks are present and valid
    for (uint32_t i = 0; i < manifest.GetChunkCount(); i++) {
        if (!HasChunk(i)) {
            LogPrintf("CSnapshotStore::ExtractSnapshot(): missing chunk %d\n", i);
            return false;
        }
    }

    // Create temporary combined file
    boost::filesystem::path tempFile = pathSnapshotDir / "snapshot-combined.tar.gz";

    try {
        boost::filesystem::ofstream outFile(tempFile, std::ios::binary);
        if (!outFile) {
            LogPrintf("CSnapshotStore::ExtractSnapshot(): failed to create combined file\n");
            return false;
        }

        // Concatenate all chunks
        for (uint32_t i = 0; i < manifest.GetChunkCount(); i++) {
            std::vector<unsigned char> vData;
            if (!LoadChunk(i, vData)) {
                LogPrintf("CSnapshotStore::ExtractSnapshot(): failed to load chunk %d\n", i);
                return false;
            }

            outFile.write((const char*)vData.data(), vData.size());

            LogPrintf("ExtractSnapshot: combined chunk %d/%d\n",
                     i + 1, manifest.GetChunkCount());
        }

        outFile.close();

        // Extract tarball using system tar command
        std::string cmd = "tar -xzf \"" + tempFile.string() + "\" -C \"" + dataDir.string() + "\"";
        LogPrintf("CSnapshotStore::ExtractSnapshot(): executing: %s\n", cmd);

        int result = system(cmd.c_str());
        if (result != 0) {
            LogPrintf("CSnapshotStore::ExtractSnapshot(): tar extraction failed with code %d\n", result);
            return false;
        }

        // Clean up combined file
        boost::filesystem::remove(tempFile);

        LogPrintf("CSnapshotStore::ExtractSnapshot(): successfully extracted snapshot\n");
        return true;

    } catch (const std::exception& e) {
        LogPrintf("CSnapshotStore::ExtractSnapshot(): error: %s\n", e.what());
        return false;
    }
}

bool CSnapshotStore::CleanupChunks()
{
    try {
        boost::filesystem::remove_all(pathSnapshotDir);
        LogPrintf("CSnapshotStore::CleanupChunks(): removed snapshot directory\n");
        return true;
    } catch (const std::exception& e) {
        LogPrintf("CSnapshotStore::CleanupChunks(): error: %s\n", e.what());
        return false;
    }
}

//
// Global functions
//

bool InitSnapshotStore(uint32_t nHeight)
{
    if (psnapshotstore != NULL) {
        delete psnapshotstore;
    }

    psnapshotstore = new CSnapshotStore();
    return psnapshotstore->Initialize(nHeight);
}

bool CanServeSnapshots()
{
    if (psnapshotstore == NULL) {
        return false;
    }

    // Check if we have all chunks
    const CSnapshotManifest& manifest = psnapshotstore->GetManifest();
    for (uint32_t i = 0; i < manifest.GetChunkCount(); i++) {
        if (!psnapshotstore->HasChunk(i)) {
            return false;
        }
    }

    // Only advertise if we're accepting connections
    if (!GetBoolArg("-listen", true)) {
        return false;
    }

    return true;
}

// Auto-generated snapshot manifest
// DO NOT EDIT - Generated by create-snapshot.sh

CSnapshotManifest GetHardcodedManifest()
{
    CSnapshotManifest manifest;

    manifest.nBlockHeight = 2879438;
    manifest.nTimestamp = 1760886990ULL;
    manifest.nTotalSize = 8953014312ULL;

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        0,
        uint256S("e38c36e582ceefdda0a62c0b5d900ae70d656fb08f5f9999ef580dfbd208a23c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        1,
        uint256S("d5407180ebec16c81a8e4bf74c9cf7fbdca20b72f45c027667b16f0c83432627"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        2,
        uint256S("b2a3cf86143db02d419eeaf77fb71bb3c2eaa93944511768afcb3465e486aca4"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        3,
        uint256S("8e2c6e2fd97573d0954b01ab5824959175b65faa9823cd61af264691aeb5f569"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        4,
        uint256S("bac389ff47bb8085416559a6732b840121622627263b8c4ddc35889c26eeeb99"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        5,
        uint256S("cfbbdda3ee7df41091f6386a415d0a0b7cf673aef77112440039f8116146f38f"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        6,
        uint256S("2508a27d2cbcb2f1140910408d0cc2858c2b027a73c5d43d8b43074f9cd6d044"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        7,
        uint256S("3b1d1a41aadfb4ba30f4fc206ce6da20531f593276f9f988798ccaf42b6bcd45"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        8,
        uint256S("5dd3589b6f31bcf8151159e606c6dd9eec8e72e83b75e10eeed46081d5ba6476"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        9,
        uint256S("58fe81496a9f0b860ecc9286f9cf6419f9289325a8781fa920a806e193ca742a"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        10,
        uint256S("727c9b44225d35b57bbfdbcaa4becc3a671ff63ac3485d147186898c157302b3"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        11,
        uint256S("b65c4ffbee3e1f1ab2edb91aa3d37800ccf86442dc0a33fe5d0c06e84181c5b9"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        12,
        uint256S("3b4b2a5514dca25af92b058551bd2d7d01d9d8a73c9514fe23068c29414e76f4"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        13,
        uint256S("dc2c5aa1852f6b19e93fb7bdcdbcb242f5b66ec6cd7de72b554067ec06cea524"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        14,
        uint256S("0f7496a4d3ab49e8c2ec06d4c383eec0b3fd14f99471d97acf21a8697b5e0f13"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        15,
        uint256S("55f519125cd225dcacd742097f364461b4e676326fbb86055886888e38bf46c3"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        16,
        uint256S("9f72efa68284ff81bea4b36b452169baf65340c7668c7f510abe4d47088acd30"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        17,
        uint256S("0e228ae7407b0bd7c39a19b41abac3cd5fe7c9eebb9b8d72333bbb06df834fb2"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        18,
        uint256S("d6047cbc29b11620f017ec89d8cc86a0d0258db0c55e90b50599e754b11fb91f"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        19,
        uint256S("68d6217a6a89381c06128e748500708ab226ea49b26ade8a803f1c009ace7068"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        20,
        uint256S("ed5bfc006acb01007858cde7d49eefec0c881d90cf879b2d98a13132dc9481b3"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        21,
        uint256S("2cea773273b37b21b1b5554b8a0e6f47097da7d0f144eda79a4f2902ed222d91"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        22,
        uint256S("5c6c09c53bf97aa6c54612288fe3f63183c8cdcbfea7865bee2ae34d7b1bc0cc"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        23,
        uint256S("a1b3c73ca152502fb05c9f429afd294d3c5746b4d063bbcbc8ca883b888f0f35"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        24,
        uint256S("2662599e9d9795508668252d5898d920e540ea45b1e735aba825988d9a061270"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        25,
        uint256S("d8d85f699408ca4f0e7ae31b91e6d37508468def47519b31c77785b75e7118e3"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        26,
        uint256S("d98717fb1aac8fa12b8db443011860e94d1770e238d26b80f5d98220c923326c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        27,
        uint256S("256b50e8bcf82eaae50acdba162fdfebd823da0b86812dd99602c5f961b47144"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        28,
        uint256S("c630d32e583d2f6aa38b89235d98dbff171818fef973604470fef8b04f61f348"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        29,
        uint256S("e98d32acc3acc34d85b846105a914a14af95892f5d7c98010030a385aa953747"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        30,
        uint256S("7ea2dc3340a7649404a4ace788558e13dd0591cb958d8a03b1b2d44a412e0cb4"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        31,
        uint256S("3a452b597869bed16f967ec038d909d08dd05a88e19b9d4a5a92e1571b774cf2"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        32,
        uint256S("78fd824527c3296b50378cc456198e0e30421b583876c49a61b955df2b0b8464"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        33,
        uint256S("2a0efcc5ab09b2193cba2d167938ff66f23987d39d833f4b619dd4908a4962dd"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        34,
        uint256S("aee149793d80d326b3122555ac9d37b68a8744bffe13fd8bd93983e5b59cdab6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        35,
        uint256S("4d228c9d298b60cfbe5b3d2de6a859b8209da933e0aa723b164ed1777bca95e9"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        36,
        uint256S("8f75532327d628fdfe4fd91804a95d3e9b4f59b19051b878880417ddcfc358f5"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        37,
        uint256S("a67206b51135837aa3b2c5655b2ddda2db0c6f55df5c14bc7ae0d8df38c0b2cc"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        38,
        uint256S("9ec6dad4f403a391d36b64238155c6f6bcfb3a1ff06dd9d90de6465bfafc9ae0"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        39,
        uint256S("b2effdb7eb30ad9cc370aae07d07f31ac17dff411b5c2948cadcd86dff8a668d"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        40,
        uint256S("6a788caffcb154750e6168ee6d84c483dc0a17cd5f75771bc1636645e1b7b651"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        41,
        uint256S("986da50c38ec19700bbb12279108087f0488836ccfc035b1b2b496c6b7f4e199"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        42,
        uint256S("263d101cd2aa377d16ab6b1010389d082d26bc5c0e30e5254cc51554ecbddff6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        43,
        uint256S("2401d94e829daaa0b3fae36dcb3349b7929825e867ad79b4758fa3f9f5e220cd"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        44,
        uint256S("9b3903c6faf8d9620e551630bd6503d6ed82662b9c38e816142da03c500ca3d8"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        45,
        uint256S("8b1cad0649ee5f5dc02cbfe29bce466118a4e5ef83e0fb3d00776fc198e065c6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        46,
        uint256S("c0abbfe48d05de579503fdc70b694952e29b43e6a6caff4ed89f67546e2e5d53"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        47,
        uint256S("55325c4b139ce800ea67f0ad0e32276d49df1f7bd5b1e12a7eceb52e3a8bd647"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        48,
        uint256S("84e0760c3d8157e8d6fcdb38ed9100652c61448e529ebd5c394165ec0afaaaea"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        49,
        uint256S("387ee373d5b4bdcb4ad37d611491721322ef5ebfed4b79004e439e53aeb3b798"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        50,
        uint256S("15627454c84d954f5505b03855402dfa828e6c4b466e436b978f7daf20c02d89"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        51,
        uint256S("88124b1891f4773103aabf7dd185274dd27024d9152a5a8d9d17c1c3f2e26050"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        52,
        uint256S("3245002534ae0bc65d6d81db199c4875bf9fbfe6619540747d92dd85947244e6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        53,
        uint256S("4ac0b23d1cae85034e60da6e011c2e888bf94f1233fe3b7c72d7aabca831a20c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        54,
        uint256S("b1173c397b77e0101703a02a1da9bcac7c22a0c2821fab4f5b87960b79361909"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        55,
        uint256S("40ecde451471d44b13f8530df30184c4ea80130c6971e48dd95e49d90ca80452"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        56,
        uint256S("a9c7775de64da2ad9d732563d210940210f07d7ad937b1ed6068552d981783c6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        57,
        uint256S("0dffbb1d004f09057b75443a4f37f84105a241ee2b11ad79c6d47d8ccfccc277"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        58,
        uint256S("ca4eec52ed96c2fd63c4819154c7ce8f0518603238cfdefd8242d159ede648e5"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        59,
        uint256S("c59fc48dfd40eb144ba98452ca260305934df689788726d8f9a1fe9c7907bc4b"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        60,
        uint256S("230cbb840409be367af840fb737bc855bd80c8841f542eae0f915b6773711b4e"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        61,
        uint256S("4a8032f1c0a5c28020dc32bb8b51ed2adad896d48a99f2f7aad28254477c98ac"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        62,
        uint256S("d406a7fb2c6bf9adf400c647b321a60c3e4f7f8d49673f0d1d9136947211e817"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        63,
        uint256S("554f409d010c727593ea0e29e6fcb521bc8a2572f6603bbc11b47c8f316988a9"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        64,
        uint256S("23ea989ed943382845313e158f4ec7ab826817598af62788fab9eb6c0515820a"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        65,
        uint256S("4628797d30551f27a164d489781b77b3ae221ddeadcc71da0fa55071959cf6ce"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        66,
        uint256S("6a0bf0aaf18bf9fd9fa117186be6e2880a210cc7484143c39e30b4544c5853f9"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        67,
        uint256S("0a02fbf7f3891513c01df52468afcfa94d72e990ce7106776bc3889a6d3a7a39"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        68,
        uint256S("c1c9d4bfd91b67c476ccfb6bc26911d4174d21809b75927b7bf6869828e8053a"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        69,
        uint256S("e73562096fb52cc3cffa5bc5a75b1a548d9b3f2f81238c7c5fa4f535f12d2911"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        70,
        uint256S("1cf30fc0d4a8499f287b19826e65e6fb333c06e76c53922f1f17cf96f961cbdf"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        71,
        uint256S("31d9bbb42fb71e9a7f7ddc2d2c8e846e72a369914e02dbfbd57fb57516467051"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        72,
        uint256S("e95ad01e6bf224d1fefb3c600eef235169c21bbe7f792416e90d50342d5f131c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        73,
        uint256S("3c4d6f58fe267d0b489d9e44ecc0d2cbbb1155edfd5dd300c9ab2db34591315c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        74,
        uint256S("6ef9ee05c05651ad676b29d76319b780db1b5a4623d2ec2173c68d2d078d5427"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        75,
        uint256S("ab2c84b8dd4ebe3c346e41d26cb90d9e3133625a82e2930928b09e4e3fdabab0"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        76,
        uint256S("4e7ea0a43158648e421fb9d3925d78d403f63963225739f995aec36085e1ff8b"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        77,
        uint256S("893416a8fb987d748cfe2fa3775beb7ce2e43ca04470f8687397d9e581f887ad"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        78,
        uint256S("2fc52590251c07e990df62bc7a35e587c9acf442d9c4cecc10eeaeee9068659b"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        79,
        uint256S("a9c7376205904591b77955a11c235e9339188750c4d0e59b5695616d1d2e589a"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        80,
        uint256S("a30b72f480dbffd2e5222f402e5072f6b16c71bcc5b7b0175d412f4e4b7e7ef3"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        81,
        uint256S("0e5cd004def0cc06dbb8299a2e9db9feab2849bd887639e0dd90fa9e4a2bd31f"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        82,
        uint256S("550403c8860f35af058471d47c8d16bc22e3ea9be4f2323822251baea18b1edd"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        83,
        uint256S("71def6e4d8a51257398dec201910c48bef57b08ec85f4b78097f98df98a4090b"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        84,
        uint256S("8f9f98c39d319a0a15f7284e95951c3bb3248ad77fe5b312beb08fdfbba2e105"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        85,
        uint256S("e8b8c15580542b55eca3ece1e327a32fdf1a282d99f87fe52fca8099ba87ba52"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        86,
        uint256S("44cc3d005f20552c7e4605fb5245ce7d3917af6debee94c1fd41f8b2b7f22d69"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        87,
        uint256S("7a87d5c39fce58749bd7504b0318edb0dfbde5ccb507145dfcd188b7bd1a8021"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        88,
        uint256S("afc0a40b277ea2549f500a8c7491932e13f211a02262d8be1c262890debc53f6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        89,
        uint256S("d322a021f54833ff529ebcb708c668a2b69495c4cff3ebec1e8e3359294f53e8"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        90,
        uint256S("1f7733351c0c68cd1bc3f47bf34897fc209ab1f2fafde3b6a153e7d61541aaf7"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        91,
        uint256S("74cdc6dd292386fdd4ac6fc699b6d72d7bfd0643ff25839e2db71218e4cc31f8"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        92,
        uint256S("9e0cb226a128ef1fc8d9b36eb8ace88175158cc29dc8c17b6a6b4c5e061112fa"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        93,
        uint256S("0b256226bd421b52c357a39eb5e754a7bd9b8c4f37f9582a981a6eba2fe36b08"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        94,
        uint256S("2af7ab13e097fe09a3bf5c4b1b873d4699819b4c9164f286c92151796d739433"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        95,
        uint256S("7d7e3f30ea6ded736ee370d9d2679a6396086e1e162ceacc6637b70557e16563"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        96,
        uint256S("eccd6e66a23c39dacd67bfa466a3f3d4b7d0871e147ec38195a76b5068b32306"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        97,
        uint256S("da3f8590607480af70c667efa0c3d5983b68338921bb3aeceb00e06c016f95d3"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        98,
        uint256S("8e0b21a52a5237974291988c366bc4d0ade40003ce322f877b6399d128e4bf63"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        99,
        uint256S("dab3d8d2d4421be9babe1668ac9ebfdfd9fba3465e2222ad743e255c3bdca240"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        100,
        uint256S("c04a79584ba6d7985f8f409909d465f73b3dc326735a0d593f400afcdbdc1c41"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        101,
        uint256S("8b0d76852bc194bfaf5ff64d318943274d79d392094e936cbbeba05f81f76332"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        102,
        uint256S("56155b3138e0c5860f456dfaefd386e6134bb26e20c5e05416a71dd1c6ae6d0e"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        103,
        uint256S("5e6e0c6e00bf0801d9ff2cee0aedd0936f3bc71bc0463127427e75646d090f91"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        104,
        uint256S("a333f7ca131bde238a1b7ca3c761f310c2cf3dcfb2eee824dbf9bf964dec80d8"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        105,
        uint256S("a318357d14fd22194806ae605030cc8aa917e1c98d3acdaad78ba089c4dbb390"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        106,
        uint256S("047db461a515e7cc14be2632e374a7923a058b8543b3469cf113f5048e074757"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        107,
        uint256S("80f8110f214696a1c11f7d8d40172719689254e402201496e1c67508470033fd"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        108,
        uint256S("b4da1aea1c3b8c6d440cbbfa0483b1af7385d4d8514a6832e11095ea4dc35d2c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        109,
        uint256S("383c86b3e43f256e425fa53bf5d1aef45600c8a567cc14c224e50e773f2f0cea"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        110,
        uint256S("5d880e24d51a3154df3138d2d46240d684c33e481c9418b778e75d56dd293e03"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        111,
        uint256S("41378fa23a82dd66032343056e63b591d8897b2114024d922fba450c3f8b6623"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        112,
        uint256S("47565fe962cad279f5aa8262f883dd21a551d9aa0a9ecada110bd8e1f08ab9e6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        113,
        uint256S("366a079cb3e902e867706f2d0170264a1796762bfc348c2d098e62c6b386ffb4"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        114,
        uint256S("abc74b8fe1fd8377a0469146661f1cbd88759813fa390818d0afdc1782421914"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        115,
        uint256S("f2bffa87dc9776f4639eb6002110366bd706e8ac57035abeb20f122c786a3470"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        116,
        uint256S("7a66fcb47d5d9d9bdc6070b48d6d0b0bf69a218b650eb110303bde43f28c899d"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        117,
        uint256S("2ad75290f043fad0d58edb10e658d44a719b206a7eb1dbee00ddafc8fa2c53e9"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        118,
        uint256S("f7509d851f7e7323351b9fdc2687bd0f29234f6085ecd0fc2ae4bc51051a2208"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        119,
        uint256S("4b1eb35ad7bc3e06be99cfede0e4c16b308ccae451223651abf9afc7c642df81"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        120,
        uint256S("11321c2f2360707a793419524fc4ccf1d00fab0d5dbf6a0e15f60aaa2977276e"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        121,
        uint256S("1d2674aaba4db787a41146e797d23401fd057df6cbda7c2b45035d0ce7e034d6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        122,
        uint256S("5794c28139a9222ce497a97475033e3234ebda6d8284859851e08d4e88ef77f0"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        123,
        uint256S("9971a2ae5884ea520870a0ab7c807c9a950ccb650173062e199a1eb718cd45bb"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        124,
        uint256S("79682e895f08a4192358c84c25c2659ca17a39dd0131673f6bc42b2d7a0ef255"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        125,
        uint256S("36476d9106de3ad7f70e97c2ca6ed7ce969febf5f87602c7c3bacc34aea6652d"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        126,
        uint256S("987e5bc27e8eb4523a6761f404c5326306392fbbafce1bfbde5cc0e5071c9267"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        127,
        uint256S("09d178c896e8859c03f79e7cf316686976892849087fe7a0870461b80182569c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        128,
        uint256S("1e6b8a636fd2fe1a7343dc4e4326a5d38449639c21e6767cb352fbdcb7ceae12"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        129,
        uint256S("351508b2af4cb6bc79f768303ac728611bb7a0ce89227c92fd5c18b62085e9be"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        130,
        uint256S("b059428265de73c2577031389d49244320b091920acc237b7570355023eb1268"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        131,
        uint256S("46de5a1f5c02f7027af3344c54b90f480a9f0b94191818f9461ca169ffd857f6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        132,
        uint256S("68f67cbf9f58984d4f0f9fbf8b15edabd22600726ac576bbebe512cf75008921"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        133,
        uint256S("6e8e0be5933f05d800ed13ffed9275b5fb312d6f7a481e72333835d7a9702b55"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        134,
        uint256S("c1e953945b2df9b4261d3e3b81db62a2412c48e98890bd53ff4173de3e3a17aa"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        135,
        uint256S("79afc3ade1f9b0c94cd9512d152cc41d64812c826cc5ce5b64b929c07713fe50"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        136,
        uint256S("1719378f17284dd461e7812d230797cfdebbb9d7ee6e1c0d2390a37401a0c582"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        137,
        uint256S("af81c62616164dfd190d094223ae0b2975076910d9fce52406ba3ddcc9b5cc3b"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        138,
        uint256S("02beabed5eb2d12c9567509a62a7e1e482794f845f8aff8966bb34c7ab05d9f4"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        139,
        uint256S("6f00a58676c0f1c3bab07b3039461a165012f6079245594a7e9e9156b6f2106e"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        140,
        uint256S("decf73bdb5e678fc64a4997bbb6abf8a918c2dbceb01333b63dd98659bd6eabd"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        141,
        uint256S("83e8e87758e9c4601b4ef6eef50e56aebb1afd0fb6d21db55692b9c674b42d52"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        142,
        uint256S("b9a507bca753b08ba32e8cc9df36978f6e597674f1416983c6a84e33e0b96b64"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        143,
        uint256S("2602937a1ff0412c37b727f19618db3280015c8effa7c1f65ec69095bfdfd4e6"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        144,
        uint256S("c2764e2c68524a6ae369f8e924baff134f1c888e187eba797dbe3de7dd46396b"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        145,
        uint256S("6aa680fe27da34f3e54ae1b2b7df455cb497f0b5974a261add9866fb8c26d94e"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        146,
        uint256S("55c6425cb9ebefc1f5a1221c160cb1b7ef950a1eed506645c96e76d926d88330"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        147,
        uint256S("c9c605ac0bb194a5276a2ac14892d57b52abfe9258285c7a8a27ebb56848d5f9"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        148,
        uint256S("e91072a472a257e3f387a3109c6e1521bbc73e26030985f8117313e3fac10fda"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        149,
        uint256S("5bb0242392e537c1b37a12e886806102c0254639ce6ec790a400f4e448314788"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        150,
        uint256S("031bf898502ee1a088233326a93ad878b09d51779534cd9600ee3e2548cf5aa5"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        151,
        uint256S("4d696947ac80f32ab8577cb1a00dcaba982148c0103eb72026b5fab6ddd77eca"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        152,
        uint256S("8276ab7f7193b7947160eb0946fc007bd3dc4ce32c92d9d2d7b4ee1a86a91b7f"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        153,
        uint256S("93f5778e30040d9df60b0fac08368b6ed1d7dd2e13b79b086722a8925a98e5d2"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        154,
        uint256S("3aae45aef62e87e1e2c09e2aab4923043771fe6e20a78c4f6ab5960c6dbe5542"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        155,
        uint256S("1f86e231039597aade4cc8136bd8a0fe44768b4d4b9e0d5335470ae3afdf7de5"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        156,
        uint256S("652e1520c9594caeadc3edf22ba91cd6e54f173bea593156d487ec02c1040016"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        157,
        uint256S("8969d9073dba3ff20af00eff6216bcbad60879ea4ff543f7672abd8575ec380a"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        158,
        uint256S("6c2aacb206f9359f3bbc5093ea6c3c69116a33eba8b7163b75b22665acb046a0"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        159,
        uint256S("b5999dbb40fbbda0a2b6be0d95069c4e937ed882b7184fb1d667ee9373265c80"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        160,
        uint256S("97ff53a2c18cd994f8021b7568af9afb6458cf7cafc1e3b82cb810bf641fe2af"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        161,
        uint256S("7a0d8412aea9a9e7d0e7bccc8a214cbb6ad66ffe75e7daa864418d82c92133d4"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        162,
        uint256S("65ba7f3449cda0f0a9af31e564db91ac12c384ed6df6258576736b6bd213dada"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        163,
        uint256S("86b92a4b560a6d46ab52bb672040b575b03c5b4d002281da54dd2127d6fb403f"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        164,
        uint256S("19434df675c1bee008ea9450e643c5d84ba48c0b3271f377c979aa75329b42a4"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        165,
        uint256S("09da3a2a3dba988c4d88f1dd59250fa9f6fade408d436e58f06846c1b813da4c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        166,
        uint256S("4fe41d008b49da7c23ca714081b0cbc121f6801b644ff59b7f50ccb70d762810"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        167,
        uint256S("fcc1252a2b3e25eb29c5750acb5b5b8c0e608bc0b3adf4aa3806fb32c3a1bde7"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        168,
        uint256S("f0261c4e5ce5c6169bf427c5a7cbe67e2209b3dd242c1e81283b41e512800896"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        169,
        uint256S("313b0350d7f46d3e5629515cb205ca19d0e5eef37d344e34c90616940b277170"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        170,
        uint256S("916f76fdc915398167419bec551a8697face9a1200e19cfd3e4fcd45b583f32f"),
        40118312ULL
    ));


    return manifest;
}
// Auto-generated params manifest
// DO NOT EDIT - Generated by create-params-snapshot.sh

CSnapshotManifest GetHardcodedParamsManifest()
{
    CSnapshotManifest manifest;

    manifest.nBlockHeight = 0; // Params are version-specific, not height-specific
    manifest.nTimestamp = 1760889827ULL;
    manifest.nTotalSize = 1624488461ULL;

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        0,
        uint256S("a46904a35985af803cc57ad3f32a4062f47181034b09aefb5e9aa026d759176a"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        1,
        uint256S("0b74c5a2dc84818f89647eb762dfacdc5f74fde601b15841b4916660432b0a4b"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        2,
        uint256S("cfe658eb76c7d90dc205c46f6b8e9b8428f4739ac7d35ae627e87b6e5adfd0e2"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        3,
        uint256S("4fc7126fa201f01d1d9b3b1f82c3c1f042e08e864da91adc598699555c9a8b13"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        4,
        uint256S("c86b18955df31669feeecf873142d595dfecf5bf15d852e06a21593cb90c31ca"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        5,
        uint256S("b4e63753c5fe732c2e7af36161c3cfeef5c4d90df7ed1586d695e3c68227ca99"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        6,
        uint256S("f5e134ff763f5aff24acb210e386886755b3124c5470f0d808e6f808ef2101d1"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        7,
        uint256S("3e86e8376d13ff15551206cd72ce27176b6bf9ef1101e57101c9dbb5aea06700"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        8,
        uint256S("08f25b63388e2944143501924f189b27255de993d3626ffaca5c1d3322c14089"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        9,
        uint256S("05912f9ab06fc9777b07116807aa7ea0b29fb7306e5971ef5bd929bb04ecd14a"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        10,
        uint256S("1f57bef4b8eb50d6891f82ac5f32579bab2b4cab7adb1ef7a8295fffaa5ac16e"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        11,
        uint256S("b4b65d27bb87a54ec8a9cac3b96d146e3bb12786750a318bfbbe6cfb0bfd9c37"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        12,
        uint256S("55adf7896737363688a160c3b16dad9a6cec9110dbbcf492d9e1878c6b3f5766"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        13,
        uint256S("f9e85550026030d149d16e54e554788fb1cc4b4794c0c4e3c3621b7507a15e01"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        14,
        uint256S("f774b63dc9efd500045d0e9f5fb29bc02e8ff664633b591e604a5a7bf0e4dfff"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        15,
        uint256S("5da0ce24fdb36c8910512ef642e5629a7149c4d0c3e1a2b48f64cf65dc59abd4"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        16,
        uint256S("f033d49e967867ef134230ec0317fc80ef8769a711aa3b270a0328c200cf7c14"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        17,
        uint256S("eed88f02d384a3ccd5c5f7d5a8ab64eb632042ac41ac8a34f4e72f2d3b8d93d3"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        18,
        uint256S("4d7616ef6d2a10103d279e7c67445dcb7ff2118a110849179539a23d056b6bf9"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        19,
        uint256S("1840f59366848a59f44306d51ac82588e6fa59f5fc1293f21eef3244345a3853"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        20,
        uint256S("6a4faa50032983f53acd1391c8f39bbae90c9acccb5e6a9b94d698cd6f3afabc"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        21,
        uint256S("5aa5caac0ace9586c909da3dc7724d6670769f60a93f2ba3925bf7ce70a64993"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        22,
        uint256S("daab4c9149d510611b340f6738abb0017f6f26f3f195e7026e0fc11dc807ad7b"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        23,
        uint256S("836d492c799d79d5f008247f16c8af62e73849fc0e5a264f455edcf305167de7"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        24,
        uint256S("97814dae6056a18c7a776ae35445a7fcad4b06581f6987b7d2c4700bd9ff5243"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        25,
        uint256S("c1f64f1b7c3f92ae9da0997ae9ddbfb3ad08ea55220054d626a25206a9404281"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        26,
        uint256S("94d7cf482692251f012db6b12aa9bd7619f35f7d49c82108b07d7162110cb7b0"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        27,
        uint256S("7c633ad18809ecc6ae6f106b69f9e0c1f41beacd5134eebdb676cf6d8aa1332c"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        28,
        uint256S("792491c4e05898f2fff3cfc59e06d1c5b46ec057f1bc41a941c7101e6640df89"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        29,
        uint256S("21c9578131d7309e280699cde2579055359a5332346ec905b57565d7056d7d95"),
        52428800ULL
    ));

    manifest.vChunks.push_back(CSnapshotChunkInfo(
        30,
        uint256S("1d3af3bd7366ddda8703cf6cbbaede45fb6e9dd710c1baf71a2c4ac22d1f4e04"),
        51624461ULL
    ));


    return manifest;
}

//
// CSnapshotRateLimiter implementation (Server-side DDoS protection)
//

CSnapshotRateLimiter::CSnapshotRateLimiter()
    : nActiveTransfers(0), nTotalBytesServed(0), nLastResetTime(GetTime())
{
    // Default limits - GENEROUS for bootstrap users, still protects against attacks
    nMaxChunksPerPeerPerMinute = 30;   // 1 chunk every 2 seconds (15 MB/sec avg throughput)
    nMaxConcurrentTransfers = 25;      // Allow many simultaneous downloads (generous)
    nMinSecondsBetweenRequests = 2;    // Just enough to prevent instant flooding
    nDuplicateChunkWindowSec = 300;    // Don't serve same chunk twice within 5 minutes
    nBanThreshold = 100;               // Very high - only ban severe abuse (>100/min)
    nBanDurationSec = 300;             // Shorter ban (5 minutes instead of 10)
}

bool CSnapshotRateLimiter::AllowRequest(const CNetAddr& addr, uint32_t nChunk, std::string& strError)
{
    LOCK(cs_rateLimiter);

    int64_t nNow = GetTime();
    PeerRequestInfo& info = mapPeerRequests[addr];

    // Check if peer is banned
    if (info.bIsBanned) {
        if (nNow < info.nBanUntil) {
            strError = strprintf("Peer banned until %d", info.nBanUntil);
            return false;
        }
        // Unban
        info.bIsBanned = false;
        info.nBanUntil = 0;
        info.requestTimes.clear();
    }

    // Check global concurrent transfer limit
    if (nActiveTransfers >= nMaxConcurrentTransfers) {
        strError = strprintf("Server at capacity (%d concurrent transfers)", nMaxConcurrentTransfers);
        return false;
    }

    // Check minimum time between requests from this peer
    if (info.nLastRequestTime > 0) {
        int64_t timeSinceLastRequest = nNow - info.nLastRequestTime;
        if (timeSinceLastRequest < nMinSecondsBetweenRequests) {
            strError = strprintf("Too fast - wait %d seconds between requests",
                               nMinSecondsBetweenRequests - timeSinceLastRequest);
            return false;
        }
    }

    // Check if we recently served this exact chunk to this peer (duplicate request)
    auto it = info.servedChunks.find(nChunk);
    if (it != info.servedChunks.end()) {
        int64_t timeSinceServed = nNow - it->second;
        if (timeSinceServed < nDuplicateChunkWindowSec) {
            strError = strprintf("Already served chunk %d to you %d seconds ago",
                               nChunk, timeSinceServed);
            return false;
        }
    }

    // Clean up old request times (only keep last 60 seconds)
    while (!info.requestTimes.empty() && (nNow - info.requestTimes.front()) > 60) {
        info.requestTimes.pop_front();
    }

    // Check requests per minute limit
    if (info.requestTimes.size() >= nMaxChunksPerPeerPerMinute) {
        strError = strprintf("Rate limit: max %d chunks per minute", nMaxChunksPerPeerPerMinute);

        // Check if this peer is abusing (way over limit)
        if (info.requestTimes.size() >= nBanThreshold) {
            info.bIsBanned = true;
            info.nBanUntil = nNow + nBanDurationSec;
            LogPrintf("CSnapshotRateLimiter: Banned peer %s for %d seconds (excessive requests)\n",
                     addr.ToString(), nBanDurationSec);
        }

        return false;
    }

    // Request is allowed
    info.requestTimes.push_back(nNow);
    info.nLastRequestTime = nNow;
    info.nTotalRequests++;
    nActiveTransfers++;

    return true;
}

void CSnapshotRateLimiter::RecordServed(const CNetAddr& addr, uint32_t nChunk, uint64_t nBytes)
{
    LOCK(cs_rateLimiter);

    int64_t nNow = GetTime();
    PeerRequestInfo& info = mapPeerRequests[addr];

    // Record that we served this chunk
    info.servedChunks[nChunk] = nNow;

    // Track total bandwidth
    nTotalBytesServed += nBytes;

    LogPrint("snapshot", "Served chunk %d (%d bytes) to %s\n", nChunk, nBytes, addr.ToString());
}

void CSnapshotRateLimiter::CompleteTransfer()
{
    LOCK(cs_rateLimiter);

    if (nActiveTransfers > 0) {
        nActiveTransfers--;
    }
}

bool CSnapshotRateLimiter::IsBanned(const CNetAddr& addr)
{
    LOCK(cs_rateLimiter);

    int64_t nNow = GetTime();
    auto it = mapPeerRequests.find(addr);

    if (it == mapPeerRequests.end()) {
        return false;
    }

    if (it->second.bIsBanned && nNow < it->second.nBanUntil) {
        return true;
    }

    return false;
}

void CSnapshotRateLimiter::Cleanup()
{
    LOCK(cs_rateLimiter);

    int64_t nNow = GetTime();

    // Remove entries for peers we haven't seen in 10 minutes
    for (auto it = mapPeerRequests.begin(); it != mapPeerRequests.end(); ) {
        if ((nNow - it->second.nLastRequestTime) > 600 &&
            !it->second.bIsBanned) {
            it = mapPeerRequests.erase(it);
        } else {
            ++it;
        }
    }

    // Reset bandwidth counter every hour
    if ((nNow - nLastResetTime) > 3600) {
        LogPrintf("CSnapshotRateLimiter: Served %d MB in last hour\n",
                 nTotalBytesServed / (1024 * 1024));
        nTotalBytesServed = 0;
        nLastResetTime = nNow;
    }
}

void CSnapshotRateLimiter::SetLimits(uint32_t maxChunksPerMin, uint32_t maxConcurrent, uint32_t minSecBetween)
{
    LOCK(cs_rateLimiter);

    nMaxChunksPerPeerPerMinute = maxChunksPerMin;
    nMaxConcurrentTransfers = maxConcurrent;
    nMinSecondsBetweenRequests = minSecBetween;

    LogPrintf("CSnapshotRateLimiter: Limits updated - %d chunks/min, %d concurrent, %d sec between\n",
             maxChunksPerMin, maxConcurrent, minSecBetween);
}

//
// CSnapshotDownloadCoordinator implementation (Client-side respectful downloading)
//

CSnapshotDownloadCoordinator::CSnapshotDownloadCoordinator(CSnapshotDownloadState* pState)
    : pDownloadState(pState)
{
}

NodeId CSnapshotDownloadCoordinator::SelectPeerForNextChunk(const std::vector<NodeId>& vAvailablePeers, uint32_t& nChunkOut)
{
    LOCK(cs_coordinator);

    if (vAvailablePeers.empty()) {
        LogPrintf("SELECT_PEER_DEBUG: No peers available\n");
        return -1;
    }

    if (!pDownloadState) {
        LogPrintf("SELECT_PEER_DEBUG: No download state\n");
        return -1;
    }

    int64_t nNow = GetTime();

    // Get next chunk we need
    nChunkOut = pDownloadState->GetNextChunkToRequest();
    LogPrintf("SELECT_PEER_DEBUG: Next chunk=%d, received=%d/%d, complete=%d, in_flight=%d\n",
             nChunkOut, pDownloadState->GetReceivedCount(), pDownloadState->GetReceivedCount(),
             pDownloadState->IsComplete() ? 1 : 0, mapChunkToNode.size());

    // Check if we already have all chunks
    if (pDownloadState->IsComplete()) {
        LogPrintf("SELECT_PEER_DEBUG: Download complete\n");
        return -1;
    }

    // Check if this chunk is already in-flight
    auto it = mapChunkToNode.find(nChunkOut);
    if (it != mapChunkToNode.end()) {
        // Already requested from someone, don't duplicate
        LogPrintf("SELECT_PEER_DEBUG: Chunk %d already in-flight to peer %d\n", nChunkOut, it->second);
        return -1;
    }

    // Check how many concurrent requests we have
    if (mapChunkToNode.size() >= MAX_CONCURRENT_PEER_REQUESTS) {
        return -1; // Too many concurrent requests already
    }

    // Find best peer to request from
    NodeId bestPeer = -1;
    int64_t oldestRequestTime = nNow;

    for (NodeId node : vAvailablePeers) {
        PeerDownloadState& state = mapPeerStates[node];

        // Skip if peer is in backoff
        if (state.nBackoffUntil > nNow) {
            continue;
        }

        // Skip if too soon since last request to this peer
        if ((nNow - state.nLastRequestTime) < MIN_SECONDS_BETWEEN_REQUESTS) {
            continue;
        }

        // Prefer peer we haven't used in a while (load balancing)
        if (bestPeer == -1 || state.nLastRequestTime < oldestRequestTime) {
            bestPeer = node;
            oldestRequestTime = state.nLastRequestTime;
        }
    }

    return bestPeer;
}

void CSnapshotDownloadCoordinator::RecordRequest(NodeId node, uint32_t nChunk)
{
    LOCK(cs_coordinator);

    int64_t nNow = GetTime();

    PeerDownloadState& state = mapPeerStates[node];
    state.nLastRequestTime = nNow;
    state.nChunksRequested++;

    // Track which peer we requested this chunk from
    mapChunkToNode[nChunk] = node;

    LogPrint("snapshot", "Requested chunk %d from peer %d\n", nChunk, node);
}

void CSnapshotDownloadCoordinator::RecordSuccess(NodeId node, uint32_t nChunk)
{
    LOCK(cs_coordinator);

    PeerDownloadState& state = mapPeerStates[node];

    // Reset failure counters on success
    state.nConsecutiveFailures = 0;
    state.nBackoffUntil = 0;

    // Remove from in-flight tracking
    mapChunkToNode.erase(nChunk);

    LogPrint("snapshot", "Successfully received chunk %d from peer %d\n", nChunk, node);
}

void CSnapshotDownloadCoordinator::RecordFailure(NodeId node, uint32_t nChunk)
{
    LOCK(cs_coordinator);

    int64_t nNow = GetTime();

    PeerDownloadState& state = mapPeerStates[node];
    state.nChunksFailed++;
    state.nConsecutiveFailures++;

    // Exponential backoff: 10s, 30s, 60s, 300s
    uint32_t backoffTime = 10;
    if (state.nConsecutiveFailures >= 4) {
        backoffTime = 300; // 5 minutes
    } else if (state.nConsecutiveFailures == 3) {
        backoffTime = 60;
    } else if (state.nConsecutiveFailures == 2) {
        backoffTime = 30;
    }

    state.nBackoffUntil = nNow + backoffTime;

    // Remove from in-flight tracking so we can retry
    mapChunkToNode.erase(nChunk);

    LogPrintf("CSnapshotDownloadCoordinator: Chunk %d failed from peer %d (failures: %d, backoff: %ds)\n",
             nChunk, node, state.nConsecutiveFailures, backoffTime);
}

int64_t CSnapshotDownloadCoordinator::GetPeerBackoff(NodeId node) const
{
    LOCK(cs_coordinator);

    int64_t nNow = GetTime();

    auto it = mapPeerStates.find(node);
    if (it == mapPeerStates.end()) {
        return 0;
    }

    if (it->second.nBackoffUntil > nNow) {
        return it->second.nBackoffUntil - nNow;
    }

    return 0;
}

std::vector<std::pair<NodeId, uint32_t>> CSnapshotDownloadCoordinator::GetTimedOutRequests()
{
    LOCK(cs_coordinator);

    std::vector<std::pair<NodeId, uint32_t>> vTimedOut;
    int64_t nNow = GetTime();

    for (auto it = mapChunkToNode.begin(); it != mapChunkToNode.end(); ) {
        uint32_t nChunk = it->first;
        NodeId node = it->second;

        auto stateIt = mapPeerStates.find(node);
        if (stateIt != mapPeerStates.end()) {
            int64_t timeSinceRequest = nNow - stateIt->second.nLastRequestTime;

            if (timeSinceRequest > REQUEST_TIMEOUT_SEC) {
                vTimedOut.push_back(std::make_pair(node, nChunk));
                it = mapChunkToNode.erase(it);
                LogPrintf("CSnapshotDownloadCoordinator: Chunk %d from peer %d timed out (%ds)\n",
                         nChunk, node, timeSinceRequest);
                continue;
            }
        }

        ++it;
    }

    return vTimedOut;
}

void CSnapshotDownloadCoordinator::RemovePeer(NodeId node)
{
    LOCK(cs_coordinator);

    // Remove peer state
    mapPeerStates.erase(node);

    // Remove any in-flight chunks from this peer
    for (auto it = mapChunkToNode.begin(); it != mapChunkToNode.end(); ) {
        if (it->second == node) {
            LogPrintf("CSnapshotDownloadCoordinator: Peer %d disconnected, chunk %d lost\n",
                     node, it->first);
            it = mapChunkToNode.erase(it);
        } else {
            ++it;
        }
    }
}

//
// UTXO Set Hash Calculation for Snapshot Verification
// Adapted from Bitcoin ABC (MIT License)
// Copyright (c) 2022 The Bitcoin Core developers
// Copyright (c) 2025 The ZClassic developers
//

/**
 * Warning: be very careful when changing this! Snapshot validation
 * commitments are reliant on the hash constructed by this function.
 *
 * If the construction of this hash is changed, it will invalidate
 * existing snapshots. This will force clients to do full sync instead.
 *
 * NOTE: This is currently a PLACEHOLDER implementation.
 * Full implementation requires accessing the coins database cursor.
 */

// Calculate deterministic UTXO set hash
// Uses ZClassic's existing CCoinsViewCache::GetStats() implementation
uint256 CalculateUTXOSetHash(const uint256& blockHash)
{
    LogPrintf("CalculateUTXOSetHash: Starting UTXO hash calculation at block %s\n",
              blockHash.GetHex());

    if (!pcoinsTip) {
        LogPrintf("ERROR: CalculateUTXOSetHash: pcoinsTip is NULL!\n");
        return uint256();
    }

    // Use ZClassic's existing GetStats() implementation
    // This iterates through the coins database and creates a deterministic hash
    CCoinsStats stats;
    FlushStateToDisk();  // Ensure all UTXO changes are written to disk first

    if (!pcoinsTip->GetStats(stats)) {
        LogPrintf("ERROR: CalculateUTXOSetHash: GetStats() failed!\n");
        return uint256();
    }

    // Verify we got stats for the expected block
    if (stats.hashBlock != blockHash) {
        LogPrintf("WARNING: CalculateUTXOSetHash: Block hash mismatch!\n");
        LogPrintf("  Expected: %s\n", blockHash.GetHex());
        LogPrintf("  Got:      %s\n", stats.hashBlock.GetHex());
    }

    LogPrintf("CalculateUTXOSetHash: Calculated hash %s\n", stats.hashSerialized.GetHex());
    LogPrintf("  Height: %d\n", stats.nHeight);
    LogPrintf("  Transactions: %lu\n", stats.nTransactions);
    LogPrintf("  Outputs: %lu\n", stats.nTransactionOutputs);
    LogPrintf("  Total amount: %s\n", FormatMoney(stats.nTotalAmount));

    return stats.hashSerialized;
}

// Verify snapshot UTXO hash against checkpoint
bool VerifySnapshotUTXOHash(const uint256& blockHash, int nHeight)
{
    LogPrintf("VerifySnapshotUTXOHash: Verifying snapshot at height %d, block %s\n",
              nHeight, blockHash.GetHex());

    // Get the snapshot checkpoints
    const SnapshotCheckpointData& checkpoints = Params().SnapshotCheckpoints();
    
    if (checkpoints.empty()) {
        LogPrintf("VerifySnapshotUTXOHash: No snapshot checkpoints configured\n");
        return true;  // No verification needed if no checkpoints
    }

    // Find matching checkpoint
    const CSnapshotCheckpoint* pCheckpoint = nullptr;
    for (const auto& checkpoint : checkpoints) {
        if (checkpoint.nHeight == nHeight && checkpoint.hashBlock == blockHash) {
            pCheckpoint = &checkpoint;
            break;
        }
    }

    if (!pCheckpoint) {
        LogPrintf("VerifySnapshotUTXOHash: No checkpoint found for height %d\n", nHeight);
        return true;  // No checkpoint for this height, skip verification
    }

    // Check if it's a placeholder (all zeros)
    if (pCheckpoint->hashUTXOSet == uint256()) {
        LogPrintf("VerifySnapshotUTXOHash: WARNING - Checkpoint has placeholder UTXO hash\n");
        LogPrintf("VerifySnapshotUTXOHash: Skipping verification (placeholder detected)\n");
        return true;  // Skip verification for placeholder
    }

    // Calculate actual UTXO hash
    uint256 actualUTXOHash = CalculateUTXOSetHash(blockHash);

    // Compare with checkpoint
    if (actualUTXOHash != pCheckpoint->hashUTXOSet) {
        LogPrintf("ERROR: VerifySnapshotUTXOHash: UTXO hash mismatch!\n");
        LogPrintf("  Expected: %s\n", pCheckpoint->hashUTXOSet.GetHex());
        LogPrintf("  Actual:   %s\n", actualUTXOHash.GetHex());
        LogPrintf("  Height:   %d\n", nHeight);
        LogPrintf("  Block:    %s\n", blockHash.GetHex());
        return false;
    }

    LogPrintf("VerifySnapshotUTXOHash: SUCCESS - UTXO hash matches checkpoint\n");
    LogPrintf("  Hash:     %s\n", actualUTXOHash.GetHex());
    LogPrintf("  Height:   %d\n", nHeight);
    
    return true;
}
