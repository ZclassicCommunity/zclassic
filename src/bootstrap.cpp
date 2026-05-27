// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrap.h"

#include "chainparams.h"
#include "compat.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "net.h"
#include "netbase.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <deque>
#include <exception>
#include <limits>
#include <map>
#include <set>
#include <stdio.h>
#include <string.h>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <sys/stat.h>
#if defined(WIN32)
#include <io.h>
#endif

static CCriticalSection cs_bootstrap_snapshot;
static boost::filesystem::path bootstrapSnapshotCacheSource;
static std::vector<CBootstrapSnapshotFile> bootstrapSnapshotCacheFiles;
static std::map<std::string, std::time_t> bootstrapSnapshotCacheMtimes;
static uint64_t bootstrapSnapshotCacheBytes = 0;
static const unsigned int BOOTSTRAP_MAX_REJECT_MESSAGE_LENGTH = 111;
// Per-message network timeout for bootstrap transfers. Independent of the much
// shorter default -timeout (nConnectTimeout, 5s) used for ordinary connects, so
// a fresh node does not need -timeout=... on the command line.
static const int BOOTSTRAP_NET_TIMEOUT_MS = 60000;

std::vector<std::string> GetBootstrapPeerList()
{
    if (mapArgs.count("-bootstrappeer")) {
        return std::vector<std::string>(1, mapArgs["-bootstrappeer"]);
    }
    return Params().BootstrapPeers();
}

static bool IsSafeBootstrapSnapshotPath(const boost::filesystem::path& relative);
static bool IsBootstrapSnapshotDataPath(const boost::filesystem::path& relative);
static bool HashBootstrapSnapshotFile(const boost::filesystem::path& path, uint256& hash, std::string& error);
static bool StatOpenBootstrapSnapshotFile(FILE* fp, uint64_t& size, std::time_t& mtime);
static FILE* OpenBootstrapSnapshotFile(const boost::filesystem::path& source,
                                       const CBootstrapSnapshotFile& file,
                                       const std::map<std::string, std::time_t>& mtimes,
                                       std::string& error);

static bool IsRetryableSocketError(int err)
{
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEINTR;
}

static bool WaitBootstrapSocket(SOCKET socket, bool write, int timeout_ms, std::string& error)
{
    if (!IsSelectableSocket(socket)) {
        error = "bootstrap socket is not selectable";
        return false;
    }

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(socket, &fdset);
    struct timeval timeout = MillisToTimeval(timeout_ms);
    const int ret = write ? select(socket + 1, NULL, &fdset, NULL, &timeout)
                          : select(socket + 1, &fdset, NULL, NULL, &timeout);
    if (ret > 0) {
        return true;
    }
    if (ret == 0) {
        error = write ? "bootstrap socket write timeout" : "bootstrap socket read timeout";
        return false;
    }

    error = strprintf("bootstrap socket select failed: %s", NetworkErrorString(WSAGetLastError()));
    return false;
}

static bool SendBootstrapBytes(SOCKET socket, const char* data, size_t size, int timeout_ms, std::string& error)
{
    size_t sent = 0;
    while (sent < size) {
        const ssize_t ret = send(socket, data + sent, size - sent, MSG_NOSIGNAL);
        if (ret > 0) {
            sent += ret;
            continue;
        }
        if (ret == 0) {
            error = "bootstrap socket closed while sending";
            return false;
        }

        const int err = WSAGetLastError();
        if (!IsRetryableSocketError(err)) {
            error = strprintf("bootstrap socket send failed: %s", NetworkErrorString(err));
            return false;
        }
        if (!WaitBootstrapSocket(socket, true, timeout_ms, error)) {
            return false;
        }
    }
    return true;
}

static bool RecvBootstrapBytes(SOCKET socket, char* data, size_t size, int timeout_ms, std::string& error)
{
    size_t received = 0;
    while (received < size) {
        const ssize_t ret = recv(socket, data + received, size - received, 0);
        if (ret > 0) {
            received += ret;
            continue;
        }
        if (ret == 0) {
            error = "bootstrap socket closed while receiving";
            return false;
        }

        const int err = WSAGetLastError();
        if (!IsRetryableSocketError(err)) {
            error = strprintf("bootstrap socket recv failed: %s", NetworkErrorString(err));
            return false;
        }
        if (!WaitBootstrapSocket(socket, false, timeout_ms, error)) {
            return false;
        }
    }
    return true;
}

bool BuildBootstrapNetworkMessage(const char* command, const CDataStream& payload, CSerializeData& message, std::string& error)
{
    message.clear();

    if (strlen(command) > CMessageHeader::COMMAND_SIZE) {
        error = "bootstrap message command is too long";
        return false;
    }
    if (payload.size() > MAX_PROTOCOL_MESSAGE_LENGTH) {
        error = strprintf("bootstrap message payload too large: %u", (unsigned int)payload.size());
        return false;
    }

    CMessageHeader header(Params().MessageStart(), command, payload.size());
    const uint256 hash = Hash(payload.begin(), payload.end());
    unsigned int nChecksum = 0;
    memcpy(&nChecksum, &hash, sizeof(nChecksum));
    header.nChecksum = nChecksum;

    try {
        CDataStream frame(SER_NETWORK, PROTOCOL_VERSION);
        frame << header;
        if (!payload.empty()) {
            frame.write((const char*)&payload[0], payload.size());
        }
        frame.GetAndClear(message);
    } catch (const std::exception& e) {
        error = strprintf("could not build bootstrap network message: %s", e.what());
        return false;
    }

    return true;
}

static bool SendBootstrapMessage(SOCKET socket, const char* command, const CDataStream& payload, int timeout_ms, std::string& error)
{
    CSerializeData message;
    if (!BuildBootstrapNetworkMessage(command, payload, message, error)) {
        return false;
    }
    if (message.empty()) {
        error = "bootstrap network message is empty";
        return false;
    }
    return SendBootstrapBytes(socket, &message[0], message.size(), timeout_ms, error);
}

static bool ReceiveBootstrapMessage(SOCKET socket, std::string& command, CDataStream& payload, int timeout_ms, std::string& error)
{
    CSerializeData headerBytes(CMessageHeader::HEADER_SIZE);
    if (!RecvBootstrapBytes(socket, &headerBytes[0], headerBytes.size(), timeout_ms, error)) {
        return false;
    }

    CMessageHeader header(Params().MessageStart());
    try {
        CDataStream headerStream(headerBytes, SER_NETWORK, PROTOCOL_VERSION);
        headerStream >> header;
    } catch (const std::exception& e) {
        error = strprintf("could not decode bootstrap message header: %s", e.what());
        return false;
    }

    if (!header.IsValid(Params().MessageStart())) {
        error = "bootstrap message header is invalid";
        return false;
    }
    if (header.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
        error = strprintf("bootstrap message payload too large: %u", header.nMessageSize);
        return false;
    }

    CSerializeData message = headerBytes;
    if (header.nMessageSize > 0) {
        const size_t offset = message.size();
        message.resize(offset + header.nMessageSize);
        if (!RecvBootstrapBytes(socket, &message[offset], header.nMessageSize, timeout_ms, error)) {
            return false;
        }
    }

    return DecodeBootstrapNetworkMessage(message, command, payload, error);
}

static bool ReceiveExpectedBootstrapMessage(SOCKET socket, const char* expected_command, CDataStream& payload, int timeout_ms, std::string& error)
{
    const int64_t deadline = GetTimeMillis() + timeout_ms;
    unsigned int unexpected_messages = 0;

    while (true) {
        const int64_t now = GetTimeMillis();
        if (now >= deadline) {
            error = strprintf("timed out waiting for bootstrap peer message %s", expected_command);
            return false;
        }

        std::string command;
        const int remaining_ms = std::max<int64_t>(1, deadline - now);
        if (!ReceiveBootstrapMessage(socket, command, payload, remaining_ms, error)) {
            return false;
        }

        if (command == expected_command) {
            return true;
        }
        if (command == "ping") {
            CDataStream pongPayload(SER_NETWORK, PROTOCOL_VERSION);
            if (!payload.empty()) {
                uint64_t nonce = 0;
                try {
                    payload >> nonce;
                } catch (const std::exception&) {
                    error = "bootstrap peer sent malformed ping";
                    return false;
                }
                if (!payload.empty()) {
                    error = "bootstrap peer ping message has trailing data";
                    return false;
                }
                pongPayload << nonce;
            }
            const int send_remaining_ms = std::max<int64_t>(1, deadline - GetTimeMillis());
            if (!SendBootstrapMessage(socket, "pong", pongPayload, send_remaining_ms, error)) {
                return false;
            }
            continue;
        }
        if (command == "pong" || command == "verack") {
            continue;
        }
        if (command == "reject") {
            std::string rejected;
            unsigned char code = 0;
            std::string reason;
            try {
                payload >> LIMITED_STRING(rejected, CMessageHeader::COMMAND_SIZE);
                payload >> code;
                payload >> LIMITED_STRING(reason, BOOTSTRAP_MAX_REJECT_MESSAGE_LENGTH);
            } catch (const std::exception&) {
                error = "bootstrap peer rejected request";
                return false;
            }
            error = strprintf("bootstrap peer rejected %s: %s", rejected, reason);
            return false;
        }

        if (++unexpected_messages > 16) {
            error = strprintf("too many unexpected bootstrap peer messages while waiting for %s", expected_command);
            return false;
        }
        LogPrint("net", "ignoring bootstrap peer message %s while waiting for %s\n", command, expected_command);
    }
}

bool DecodeBootstrapNetworkMessage(const CSerializeData& message, std::string& command, CDataStream& payload, std::string& error)
{
    command.clear();
    payload.clear();

    if (message.size() < CMessageHeader::HEADER_SIZE) {
        error = "bootstrap network message is shorter than header";
        return false;
    }

    try {
        CDataStream frame(message, SER_NETWORK, PROTOCOL_VERSION);
        CMessageHeader header(Params().MessageStart());
        frame >> header;

        if (!header.IsValid(Params().MessageStart())) {
            error = "bootstrap network message header is invalid";
            return false;
        }
        if (header.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
            error = strprintf("bootstrap network message is too large: %u", header.nMessageSize);
            return false;
        }
        if (frame.size() != header.nMessageSize) {
            error = strprintf("bootstrap network message size mismatch: header=%u payload=%u",
                header.nMessageSize,
                (unsigned int)frame.size());
            return false;
        }

        const uint256 hash = Hash(frame.begin(), frame.end());
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != header.nChecksum) {
            error = "bootstrap network message checksum mismatch";
            return false;
        }

        command = header.GetCommand();
        payload = CDataStream(frame.begin(), frame.end(), SER_NETWORK, PROTOCOL_VERSION);
    } catch (const std::exception& e) {
        error = strprintf("could not decode bootstrap network message: %s", e.what());
        return false;
    }

    return true;
}

static bool IsSafeBootstrapEntry(const boost::filesystem::path& path)
{
    boost::filesystem::file_status status = boost::filesystem::symlink_status(path);
    return boost::filesystem::is_directory(status) || boost::filesystem::is_regular_file(status);
}

static bool CopyBootstrapDirectory(const boost::filesystem::path& source, const boost::filesystem::path& destination, std::string& error)
{
    try {
        if (!boost::filesystem::is_directory(source)) {
            error = strprintf("bootstrap source is not a directory: %s", source.string());
            return false;
        }

        if (!IsSafeBootstrapEntry(source)) {
            error = strprintf("bootstrap source is not a regular directory: %s", source.string());
            return false;
        }

        boost::filesystem::create_directories(destination);

        boost::filesystem::recursive_directory_iterator end;
        for (boost::filesystem::recursive_directory_iterator it(source); it != end; ++it) {
            boost::this_thread::interruption_point();
            const boost::filesystem::path current = it->path();
            if (!IsSafeBootstrapEntry(current)) {
                error = strprintf("bootstrap source contains unsafe file type: %s", current.string());
                return false;
            }

            const boost::filesystem::path relative = boost::filesystem::relative(current, source);
            const boost::filesystem::path target = destination / relative;
            if (boost::filesystem::is_directory(current)) {
                boost::filesystem::create_directories(target);
            } else {
                boost::filesystem::create_directories(target.parent_path());
                boost::filesystem::copy_file(current, target);
            }
        }
    } catch (const boost::filesystem::filesystem_error& e) {
        error = e.what();
        return false;
    }
    return true;
}

bool BootstrapSnapshotPathsExist(const boost::filesystem::path& root)
{
    return boost::filesystem::is_directory(root / "blocks") &&
           boost::filesystem::is_directory(root / "blocks" / "index") &&
           boost::filesystem::is_directory(root / "chainstate");
}

bool IsBootstrapFreshChainDatadir(const boost::filesystem::path& data_dir, std::string& error)
{
    if (boost::filesystem::exists(data_dir / "blocks")) {
        error = strprintf("bootstrap peer download requires a fresh chain datadir; %s already exists", (data_dir / "blocks").string());
        return false;
    }
    if (boost::filesystem::exists(data_dir / "chainstate")) {
        error = strprintf("bootstrap peer download requires a fresh chain datadir; %s already exists", (data_dir / "chainstate").string());
        return false;
    }
    if (boost::filesystem::exists(data_dir / "bootstrap.dat")) {
        error = strprintf("bootstrap peer download requires a fresh chain datadir; %s already exists", (data_dir / "bootstrap.dat").string());
        return false;
    }

    try {
        if (boost::filesystem::is_directory(data_dir)) {
            boost::filesystem::directory_iterator end;
            for (boost::filesystem::directory_iterator it(data_dir); it != end; ++it) {
                if (boost::filesystem::is_regular_file(it->path())) {
                    const std::string filename = it->path().filename().string();
                    if (filename.size() == 12 &&
                        filename.substr(0, 3) == "blk" &&
                        filename.substr(8) == ".dat") {
                        error = strprintf("bootstrap peer download requires a fresh chain datadir; legacy block file exists: %s", it->path().string());
                        return false;
                    }
                }
            }
        }
    } catch (const boost::filesystem::filesystem_error& e) {
        error = e.what();
        return false;
    }

    return true;
}

bool ImportBootstrapDatadir(const boost::filesystem::path& source_root, const boost::filesystem::path& data_dir, bool force_backup, std::string& error)
{
    if (!BootstrapSnapshotPathsExist(source_root)) {
        error = strprintf("bootstrap source must contain blocks/, blocks/index/, and chainstate/: %s", source_root.string());
        return false;
    }

    const boost::filesystem::path blocks_dir = data_dir / "blocks";
    const boost::filesystem::path chainstate_dir = data_dir / "chainstate";
    const bool has_existing = boost::filesystem::exists(blocks_dir) || boost::filesystem::exists(chainstate_dir);
    if (has_existing && !force_backup) {
        error = strprintf("%s already has blocks/ or chainstate/; use -bootstrapforce to back it up before import", data_dir.string());
        return false;
    }

    try {
        boost::filesystem::create_directories(data_dir);
        const boost::filesystem::path staging = data_dir / strprintf("bootstrap-import-%d", GetTime());
        boost::filesystem::remove_all(staging);
        boost::filesystem::create_directories(staging);

        if (!CopyBootstrapDirectory(source_root / "blocks", staging / "blocks", error) ||
            !CopyBootstrapDirectory(source_root / "chainstate", staging / "chainstate", error)) {
            boost::filesystem::remove_all(staging);
            return false;
        }

        if (!BootstrapSnapshotPathsExist(staging)) {
            boost::filesystem::remove_all(staging);
            error = "staged bootstrap data is incomplete";
            return false;
        }

        if (has_existing) {
            const boost::filesystem::path backup = data_dir / strprintf("bootstrap-backup-%d", GetTime());
            boost::filesystem::create_directories(backup);
            if (boost::filesystem::exists(blocks_dir))
                boost::filesystem::rename(blocks_dir, backup / "blocks");
            if (boost::filesystem::exists(chainstate_dir))
                boost::filesystem::rename(chainstate_dir, backup / "chainstate");
            LogPrintf("Moved existing chain data to %s\n", backup.string());
        }

        boost::filesystem::rename(staging / "blocks", blocks_dir);
        boost::filesystem::rename(staging / "chainstate", chainstate_dir);
        boost::filesystem::remove_all(staging);
    } catch (const boost::filesystem::filesystem_error& e) {
        error = e.what();
        return false;
    }

    LogPrintf("Imported bootstrap chain data from %s\n", source_root.string());
    return true;
}

static bool WriteBootstrapChunkToFile(const boost::filesystem::path& path, const CBootstrapSnapshotChunk& chunk, FILE* file, std::string& error)
{
    if (fseek(file, chunk.nOffset, SEEK_SET) != 0) {
        error = strprintf("could not seek bootstrap staging file: %s", path.string());
        return false;
    }
    if (!chunk.vData.empty() && fwrite(&chunk.vData[0], 1, chunk.vData.size(), file) != chunk.vData.size()) {
        error = strprintf("could not write bootstrap chunk to %s", path.string());
        return false;
    }
    return true;
}

static bool VerifyBootstrapDownloadedFile(const boost::filesystem::path& path, const CBootstrapSnapshotFile& file, std::string& error)
{
    uint256 hash;
    if (!HashBootstrapSnapshotFile(path, hash, error)) {
        return false;
    }
    if (hash != file.hashSha256) {
        error = strprintf("bootstrap downloaded file hash mismatch for %s: computed=%s expected=%s",
            file.strPath,
            hash.ToString(),
            file.hashSha256.ToString());
        return false;
    }
    return true;
}

// Pipeline window: how many chunk requests the client keeps in flight at once.
// This hides per-chunk round-trip latency, which otherwise caps throughput on
// high-latency links. It must not exceed the server's per-peer queue limit
// (MAX_BOOTSTRAP_CHUNK_REQUESTS_PER_PEER in net.cpp).
static const size_t BOOTSTRAP_PIPELINE_DEPTH = 16;

static bool SendBootstrapChunkRequest(SOCKET socket, const CBootstrapSnapshotChunkRequest& request, int timeout_ms, std::string& error)
{
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << request;
    return SendBootstrapMessage(socket, NetMsgType::GETBSCHK, payload, timeout_ms, error);
}

// Zero-length files are never requested over the wire (they produce no chunks),
// so create and verify them directly in staging.
static bool CreateEmptyBootstrapFiles(const CBootstrapSnapshotManifest& manifest, const boost::filesystem::path& staging, std::string& error)
{
    for (size_t i = 0; i < manifest.vFiles.size(); ++i) {
        const CBootstrapSnapshotFile& file = manifest.vFiles[i];
        if (file.nSize != 0) {
            continue;
        }
        const boost::filesystem::path relative(file.strPath);
        if (!IsBootstrapSnapshotDataPath(relative)) {
            error = strprintf("bootstrap manifest has unsafe file path: %s", file.strPath);
            return false;
        }
        const boost::filesystem::path path = staging / relative;
        boost::filesystem::create_directories(path.parent_path());
        FILE* fp = fopen(path.string().c_str(), "wb");
        if (!fp) {
            error = strprintf("could not create bootstrap staging file: %s", path.string());
            return false;
        }
        fclose(fp);
        if (!VerifyBootstrapDownloadedFile(path, file, error)) {
            return false;
        }
    }
    return true;
}

// Download every file in the manifest into staging using a pipelined request
// window across the whole snapshot. Chunk requests are issued in file/offset
// order; the peer replies on a single ordered stream, so responses match the
// in-flight queue front-to-back. Files are verified (per-file SHA-256) and
// renamed from their .part path as their final chunk arrives.
static bool DownloadBootstrapSnapshot(SOCKET socket, const CBootstrapSnapshotManifest& manifest, const boost::filesystem::path& staging, int timeout_ms, const std::string& peer, std::string& error)
{
    LogPrintf("Bootstrap: downloading snapshot from peer %s: %u files, %llu bytes (height %d)\n",
        peer,
        (unsigned int)manifest.vFiles.size(),
        (unsigned long long)manifest.nSnapshotBytes,
        manifest.nHeight);

    if (!CreateEmptyBootstrapFiles(manifest, staging, error)) {
        return false;
    }

    std::vector<uint32_t> order;
    for (size_t i = 0; i < manifest.vFiles.size(); ++i) {
        if (manifest.vFiles[i].nSize > 0) {
            order.push_back((uint32_t)i);
        }
    }

    // Request cursor over (position in `order`, byte offset within that file).
    size_t reqPos = 0;
    uint64_t reqOffset = 0;
    auto nextRequest =
        [&](CBootstrapSnapshotChunkRequest& request) -> bool {
            while (reqPos < order.size()) {
                const CBootstrapSnapshotFile& f = manifest.vFiles[order[reqPos]];
                if (reqOffset >= f.nSize) {
                    ++reqPos;
                    reqOffset = 0;
                    continue;
                }
                request.nFileIndex = order[reqPos];
                request.nOffset = reqOffset;
                request.nLength = (uint32_t)std::min<uint64_t>(manifest.nChunkSize, f.nSize - reqOffset);
                reqOffset += request.nLength;
                return true;
            }
            return false;
        };

    std::deque<CBootstrapSnapshotChunkRequest> inflight;
    for (size_t i = 0; i < BOOTSTRAP_PIPELINE_DEPTH; ++i) {
        CBootstrapSnapshotChunkRequest request;
        if (!nextRequest(request)) {
            break;
        }
        if (!SendBootstrapChunkRequest(socket, request, timeout_ms, error)) {
            return false;
        }
        inflight.push_back(request);
    }

    FILE* fp = NULL;
    boost::filesystem::path open_path;
    boost::filesystem::path open_part;
    uint64_t received_total = 0;
    int last_logged_percent = -1;
    const int64_t download_started = GetTimeMillis();
    bool ok = true;

    while (ok && !inflight.empty()) {
        CDataStream chunkPayload(SER_NETWORK, PROTOCOL_VERSION);
        if (!ReceiveExpectedBootstrapMessage(socket, NetMsgType::BSCHK, chunkPayload, timeout_ms, error)) {
            ok = false;
            break;
        }

        CBootstrapSnapshotChunk chunk;
        try {
            chunkPayload >> chunk;
        } catch (const std::exception& e) {
            error = strprintf("could not decode bootstrap chunk: %s", e.what());
            ok = false;
            break;
        }

        const CBootstrapSnapshotChunkRequest request = inflight.front();
        inflight.pop_front();
        if (chunk.nFileIndex != request.nFileIndex ||
            chunk.nOffset != request.nOffset ||
            chunk.vData.size() != request.nLength) {
            error = "bootstrap peer returned an unexpected chunk";
            ok = false;
            break;
        }

        const CBootstrapSnapshotFile& file = manifest.vFiles[request.nFileIndex];
        if (!fp) {
            const boost::filesystem::path relative(file.strPath);
            if (!IsBootstrapSnapshotDataPath(relative)) {
                error = strprintf("bootstrap manifest has unsafe file path: %s", file.strPath);
                ok = false;
                break;
            }
            open_path = staging / relative;
            open_part = boost::filesystem::path(open_path.string() + ".part");
            boost::filesystem::create_directories(open_path.parent_path());
            fp = fopen(open_part.string().c_str(), "wb");
            if (!fp) {
                error = strprintf("could not create bootstrap staging file: %s", open_part.string());
                ok = false;
                break;
            }
        }

        if (!WriteBootstrapChunkToFile(open_part, chunk, fp, error)) {
            ok = false;
            break;
        }
        received_total += chunk.vData.size();

        // Finalize the file once its final chunk has been written.
        if (request.nOffset + request.nLength >= file.nSize) {
            FileCommit(fp);
            const bool closed = (fclose(fp) == 0);
            fp = NULL;
            if (!closed) {
                error = strprintf("could not close bootstrap staging file: %s", open_part.string());
                ok = false;
                break;
            }
            if (!VerifyBootstrapDownloadedFile(open_part, file, error)) {
                ok = false;
                break;
            }
            boost::filesystem::rename(open_part, open_path);
        }

        // Log on each whole-percent advance so an operator watching the console
        // (-printtoconsole) or debug.log sees steady progress during what can be
        // a multi-gigabyte transfer.
        const int percent = manifest.nSnapshotBytes > 0
            ? (int)((received_total * 100) / manifest.nSnapshotBytes)
            : 100;
        if (percent != last_logged_percent) {
            last_logged_percent = percent;
            const int64_t elapsed_ms = std::max<int64_t>(1, GetTimeMillis() - download_started);
            LogPrintf("Bootstrap: downloaded %d%% (%llu/%llu bytes, %.1f MB/s)\n",
                percent,
                (unsigned long long)received_total,
                (unsigned long long)manifest.nSnapshotBytes,
                (received_total / 1048576.0) / (elapsed_ms / 1000.0));
        }

        // Refill the pipeline window.
        CBootstrapSnapshotChunkRequest refill;
        if (nextRequest(refill)) {
            if (!SendBootstrapChunkRequest(socket, refill, timeout_ms, error)) {
                ok = false;
                break;
            }
            inflight.push_back(refill);
        }
    }

    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    return ok;
}

static bool BootstrapHandshake(SOCKET socket, const CService& peer_address, int timeout_ms, std::string& error)
{
    CAddress addrYou(peer_address, NODE_BOOTSTRAP);
    CAddress addrMe(CService("0.0.0.0", 0), nLocalServices);
    uint64_t nonce = 0;
    GetRandBytes((unsigned char*)&nonce, sizeof(nonce));

    CDataStream versionPayload(SER_NETWORK, INIT_PROTO_VERSION);
    versionPayload << PROTOCOL_VERSION << nLocalServices << GetTime() << addrYou << addrMe
                   << nonce << strSubVersion << 0 << true;
    if (!SendBootstrapMessage(socket, "version", versionPayload, timeout_ms, error)) {
        return false;
    }

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    if (!ReceiveExpectedBootstrapMessage(socket, "version", payload, timeout_ms, error)) {
        return false;
    }
    payload.SetVersion(INIT_PROTO_VERSION);

    int remoteVersion = 0;
    uint64_t remoteServices = 0;
    int64_t remoteTime = 0;
    CAddress remoteAddrMe;
    CAddress remoteAddrFrom;
    uint64_t remoteNonce = 0;
    std::string remoteSubVersion;
    int remoteStartingHeight = 0;
    bool remoteRelay = true;
    try {
        payload >> remoteVersion >> remoteServices >> remoteTime >> remoteAddrMe;
        if (!payload.empty()) {
            payload >> remoteAddrFrom >> remoteNonce;
        }
        if (!payload.empty()) {
            payload >> LIMITED_STRING(remoteSubVersion, MAX_SUBVERSION_LENGTH);
        }
        if (!payload.empty()) {
            payload >> remoteStartingHeight;
        }
        if (!payload.empty()) {
            payload >> remoteRelay;
        }
    } catch (const std::exception& e) {
        error = strprintf("could not decode bootstrap peer version: %s", e.what());
        return false;
    }
    if (!payload.empty()) {
        error = "bootstrap peer version message has trailing data";
        return false;
    }

    if (remoteVersion < MIN_PEER_PROTO_VERSION) {
        error = strprintf("bootstrap peer protocol version too old: %d", remoteVersion);
        return false;
    }
    if (!(remoteServices & NODE_BOOTSTRAP)) {
        error = "bootstrap peer does not advertise NODE_BOOTSTRAP";
        return false;
    }

    CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
    if (!SendBootstrapMessage(socket, "verack", empty, timeout_ms, error)) {
        return false;
    }
    if (!ReceiveExpectedBootstrapMessage(socket, "verack", payload, timeout_ms, error)) {
        return false;
    }
    if (!payload.empty()) {
        error = "bootstrap peer verack message is not empty";
        return false;
    }

    return true;
}

bool BootstrapFromPeer(const std::string& peer, const boost::filesystem::path& data_dir, std::string& error)
{
    if (!IsBootstrapFreshChainDatadir(data_dir, error)) {
        return false;
    }

    CService peerAddress;
    SOCKET socket = INVALID_SOCKET;
    bool proxyConnectionFailed = false;
    if (!ConnectSocketByName(peerAddress, socket, peer.c_str(), Params().GetDefaultPort(), nConnectTimeout, &proxyConnectionFailed)) {
        error = proxyConnectionFailed ? "bootstrap peer proxy connection failed" : strprintf("could not connect to bootstrap peer: %s", peer);
        return false;
    }

    const boost::filesystem::path staging = data_dir / strprintf("bootstrap-peer-staging-%d", GetTime());
    try {
        boost::filesystem::remove_all(staging);
        boost::filesystem::create_directories(staging);

        if (!BootstrapHandshake(socket, peerAddress, BOOTSTRAP_NET_TIMEOUT_MS, error)) {
            CloseSocket(socket);
            boost::filesystem::remove_all(staging);
            return false;
        }

        CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
        if (!SendBootstrapMessage(socket, NetMsgType::GETBSMAN, empty, BOOTSTRAP_NET_TIMEOUT_MS, error)) {
            CloseSocket(socket);
            boost::filesystem::remove_all(staging);
            return false;
        }

        CDataStream manifestPayload(SER_NETWORK, PROTOCOL_VERSION);
        if (!ReceiveExpectedBootstrapMessage(socket, NetMsgType::BSMAN, manifestPayload, BOOTSTRAP_NET_TIMEOUT_MS, error)) {
            CloseSocket(socket);
            boost::filesystem::remove_all(staging);
            return false;
        }

        CBootstrapSnapshotManifest manifest;
        try {
            manifestPayload >> manifest;
        } catch (const std::exception& e) {
            CloseSocket(socket);
            boost::filesystem::remove_all(staging);
            error = strprintf("could not decode bootstrap manifest: %s", e.what());
            return false;
        }

        if (!ValidateBootstrapSnapshotManifest(manifest, error)) {
            CloseSocket(socket);
            boost::filesystem::remove_all(staging);
            return false;
        }

        if (!DownloadBootstrapSnapshot(socket, manifest, staging, BOOTSTRAP_NET_TIMEOUT_MS, peer, error)) {
            CloseSocket(socket);
            boost::filesystem::remove_all(staging);
            return false;
        }

        CloseSocket(socket);

        if (!BootstrapSnapshotPathsExist(staging)) {
            boost::filesystem::remove_all(staging);
            error = "downloaded bootstrap snapshot is incomplete";
            return false;
        }
        if (!IsBootstrapFreshChainDatadir(data_dir, error)) {
            boost::filesystem::remove_all(staging);
            return false;
        }

        boost::filesystem::rename(staging / "blocks", data_dir / "blocks");
        boost::filesystem::rename(staging / "chainstate", data_dir / "chainstate");
        boost::filesystem::remove_all(staging);
    } catch (const boost::filesystem::filesystem_error& e) {
        CloseSocket(socket);
        boost::filesystem::remove_all(staging);
        error = e.what();
        return false;
    }

    LogPrintf("Downloaded bootstrap chain data from peer %s\n", peer);
    return true;
}

static bool IsSafeBootstrapSnapshotPath(const boost::filesystem::path& relative)
{
    if (relative.empty() || relative.is_absolute()) {
        return false;
    }

    for (boost::filesystem::path::const_iterator it = relative.begin(); it != relative.end(); ++it) {
        if (*it == "." || *it == "..") {
            return false;
        }
    }

    return true;
}

static bool IsBootstrapSnapshotDataPath(const boost::filesystem::path& relative)
{
    if (!IsSafeBootstrapSnapshotPath(relative)) {
        return false;
    }

    boost::filesystem::path::const_iterator it = relative.begin();
    return it != relative.end() && (*it == "blocks" || *it == "chainstate");
}

static bool HashBootstrapSnapshotFile(const boost::filesystem::path& path, uint256& hash, std::string& error)
{
    FILE* file = fopen(path.string().c_str(), "rb");
    if (!file) {
        error = strprintf("could not open bootstrap snapshot file for hashing: %s", path.string());
        return false;
    }

    CSHA256 hasher;
    unsigned char buffer[1024 * 1024];
    while (true) {
        size_t nRead = fread(buffer, 1, sizeof(buffer), file);
        if (nRead > 0) {
            hasher.Write(buffer, nRead);
        }
        if (nRead < sizeof(buffer)) {
            if (ferror(file)) {
                error = strprintf("error reading bootstrap snapshot file: %s", path.string());
                fclose(file);
                return false;
            }
            break;
        }
    }

    unsigned char digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    hash = uint256S("0x" + HexStr(digest, digest + CSHA256::OUTPUT_SIZE));
    fclose(file);
    return true;
}

static bool CollectBootstrapSnapshotFiles(const boost::filesystem::path& root,
                                          bool hash_files,
                                          std::vector<CBootstrapSnapshotFile>& files,
                                          std::map<std::string, std::time_t>& mtimes,
                                          uint64_t& total_bytes,
                                          std::string& error)
{
    files.clear();
    mtimes.clear();
    total_bytes = 0;

    if (!BootstrapSnapshotPathsExist(root)) {
        error = strprintf("bootstrap snapshot source is incomplete: %s", root.string());
        return false;
    }

    if (!IsSafeBootstrapEntry(root)) {
        error = strprintf("bootstrap snapshot source is unsafe: %s", root.string());
        return false;
    }

    try {
        boost::filesystem::recursive_directory_iterator end;
        for (boost::filesystem::recursive_directory_iterator it(root); it != end; ++it) {
            boost::this_thread::interruption_point();
            const boost::filesystem::path current = it->path();
            if (!IsSafeBootstrapEntry(current)) {
                error = strprintf("bootstrap snapshot source contains unsafe file type: %s", current.string());
                return false;
            }

            if (!boost::filesystem::is_regular_file(current)) {
                continue;
            }

            const boost::filesystem::path relative = boost::filesystem::relative(current, root);
            if (!IsBootstrapSnapshotDataPath(relative)) {
                error = strprintf("bootstrap snapshot source contains unsafe relative path: %s", relative.string());
                return false;
            }

            CBootstrapSnapshotFile file;
            file.strPath = relative.generic_string();
            file.nSize = boost::filesystem::file_size(current);
            if (hash_files && !HashBootstrapSnapshotFile(current, file.hashSha256, error)) {
                return false;
            }
            mtimes[file.strPath] = boost::filesystem::last_write_time(current);
            if (file.nSize > std::numeric_limits<uint64_t>::max() - total_bytes) {
                error = "bootstrap snapshot byte size overflow";
                return false;
            }
            files.push_back(file);
            total_bytes += file.nSize;
        }
    } catch (const boost::filesystem::filesystem_error& e) {
        error = e.what();
        return false;
    }

    std::sort(files.begin(), files.end(), [](const CBootstrapSnapshotFile& a, const CBootstrapSnapshotFile& b) {
        return a.strPath < b.strPath;
    });

    return true;
}

static bool GetBootstrapSnapshotFileList(const boost::filesystem::path& source, std::vector<CBootstrapSnapshotFile>& files, uint64_t& total_bytes, std::string& error)
{
    LOCK(cs_bootstrap_snapshot);

    if (bootstrapSnapshotCacheSource != source || bootstrapSnapshotCacheFiles.empty()) {
        if (!CollectBootstrapSnapshotFiles(source, true, bootstrapSnapshotCacheFiles, bootstrapSnapshotCacheMtimes, bootstrapSnapshotCacheBytes, error)) {
            return false;
        }
        bootstrapSnapshotCacheSource = source;
    }

    files = bootstrapSnapshotCacheFiles;
    total_bytes = bootstrapSnapshotCacheBytes;
    return true;
}

bool GetBootstrapSnapshotManifest(CBootstrapSnapshotManifest& manifest, std::string& error)
{
    if (!GetBoolArg("-bootstrapserve", false)) {
        error = "bootstrap snapshot service is not enabled";
        return false;
    }
    if (!mapArgs.count("-bootstrapsourcedir")) {
        error = "bootstrap snapshot service requires -bootstrapsourcedir";
        return false;
    }

    const boost::filesystem::path source = boost::filesystem::system_complete(mapArgs["-bootstrapsourcedir"]);
    if (!BootstrapSnapshotPathsExist(source)) {
        error = strprintf("bootstrap snapshot source is incomplete: %s", source.string());
        return false;
    }

    const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();
    if (anchor.nHeight < 0 || anchor.hashBlock.IsNull()) {
        error = "bootstrap snapshot service requires a compiled fast-sync anchor";
        return false;
    }

    manifest.SetNull();
    manifest.strNetwork = Params().NetworkIDString();
    manifest.nHeight = anchor.nHeight;
    manifest.hashBlock = anchor.hashBlock;
    manifest.hashAnchorSha256 = anchor.hashAnchorSha256;
    manifest.hashAnchorSha3 = anchor.hashAnchorSha3;
    if (!GetBootstrapSnapshotFileList(source, manifest.vFiles, manifest.nSnapshotBytes, error)) {
        return false;
    }
    manifest.nChunkSize = BOOTSTRAP_SNAPSHOT_CHUNK_SIZE;
    return true;
}

// --- Zcash zk-SNARK parameter distribution -------------------------------
//
// The parameter files are fixed and identical for every node, with hashes that
// also gate startup in InitSanityCheck. A fresh node can fetch them from a peer
// instead of an external download; because the expected SHA-256 of each file is
// compiled in, the serving peer is untrusted (only content matching a compiled
// hash is installed).

struct ZcashParamFile {
    const char* name;
    const char* sha256hex;
};

// Listed in compiled order, which is also the served manifest order.
static const ZcashParamFile ZCASH_PARAM_FILES[] = {
    {"sapling-output.params", "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"},
    {"sapling-spend.params",  "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13"},
    {"sprout-groth16.params", "b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50"},
    {"sprout-proving.key",    "8bc20a7f013b2b58970cddd2e7ea028975c88ae7ceb9259a5344a16bc2c0eef7"},
    {"sprout-verifying.key",  "4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82"},
};
static const size_t ZCASH_PARAM_FILE_COUNT = sizeof(ZCASH_PARAM_FILES) / sizeof(ZCASH_PARAM_FILES[0]);

static const ZcashParamFile* FindZcashParam(const std::string& name)
{
    for (size_t i = 0; i < ZCASH_PARAM_FILE_COUNT; ++i) {
        if (name == ZCASH_PARAM_FILES[i].name) {
            return &ZCASH_PARAM_FILES[i];
        }
    }
    return NULL;
}

static uint256 ZcashParamExpectedHash(const ZcashParamFile& param)
{
    return uint256S(std::string("0x") + param.sha256hex);
}

bool ZcashParamsPresentAndValid()
{
    const boost::filesystem::path dir = ZC_GetParamsDir();
    for (size_t i = 0; i < ZCASH_PARAM_FILE_COUNT; ++i) {
        if (!boost::filesystem::is_regular_file(dir / ZCASH_PARAM_FILES[i].name)) {
            return false;
        }
    }
    return true;
}

bool GetZcashParamManifest(CBootstrapSnapshotManifest& manifest, std::string& error)
{
    if (!GetBoolArg("-bootstrapserve", false)) {
        error = "bootstrap snapshot service is not enabled";
        return false;
    }

    const boost::filesystem::path dir = ZC_GetParamsDir();
    manifest.SetNull();
    manifest.strNetwork = Params().NetworkIDString();

    uint64_t total = 0;
    for (size_t i = 0; i < ZCASH_PARAM_FILE_COUNT; ++i) {
        const boost::filesystem::path path = dir / ZCASH_PARAM_FILES[i].name;
        if (!boost::filesystem::is_regular_file(path) || !IsSafeBootstrapEntry(path)) {
            continue; // only advertise parameter files we actually hold
        }
        CBootstrapSnapshotFile file;
        file.strPath = ZCASH_PARAM_FILES[i].name;
        file.nSize = boost::filesystem::file_size(path);
        file.hashSha256 = ZcashParamExpectedHash(ZCASH_PARAM_FILES[i]);
        if (file.nSize > std::numeric_limits<uint64_t>::max() - total) {
            error = "zcash parameter byte size overflow";
            return false;
        }
        manifest.vFiles.push_back(file);
        total += file.nSize;
    }

    if (manifest.vFiles.empty()) {
        error = "no zcash parameters available to serve";
        return false;
    }
    manifest.nSnapshotBytes = total;
    manifest.nChunkSize = BOOTSTRAP_SNAPSHOT_CHUNK_SIZE;
    return true;
}

bool ReadZcashParamChunk(const CBootstrapSnapshotChunkRequest& request, CBootstrapSnapshotChunk& chunk, std::string& error)
{
    if (!GetBoolArg("-bootstrapserve", false)) {
        error = "bootstrap snapshot service is not enabled";
        return false;
    }
    if (request.nLength == 0 || request.nLength > BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE) {
        error = strprintf("invalid zcash param chunk length: %u", request.nLength);
        return false;
    }

    CBootstrapSnapshotManifest manifest;
    if (!GetZcashParamManifest(manifest, error)) {
        return false;
    }
    if (request.nFileIndex >= manifest.vFiles.size()) {
        error = strprintf("zcash param chunk file index out of range: %u", request.nFileIndex);
        return false;
    }

    const CBootstrapSnapshotFile& file = manifest.vFiles[request.nFileIndex];
    if (!FindZcashParam(file.strPath)) {
        error = strprintf("unknown zcash param file: %s", file.strPath);
        return false;
    }

    const boost::filesystem::path path = ZC_GetParamsDir() / file.strPath;
    FILE* fp = fopen(path.string().c_str(), "rb");
    if (!fp) {
        error = strprintf("could not open zcash param file: %s", path.string());
        return false;
    }
    uint64_t file_size = 0;
    std::time_t file_mtime = 0;
    if (!StatOpenBootstrapSnapshotFile(fp, file_size, file_mtime) || file_size != file.nSize) {
        fclose(fp);
        error = strprintf("zcash param file changed: %s", file.strPath);
        return false;
    }
    if (request.nOffset > file.nSize || request.nLength > file.nSize - request.nOffset) {
        fclose(fp);
        error = "zcash param chunk range exceeds file size";
        return false;
    }
    if (request.nOffset % BOOTSTRAP_SNAPSHOT_CHUNK_SIZE != 0) {
        fclose(fp);
        error = "zcash param chunk offset is not aligned";
        return false;
    }
    const uint32_t expected_length = std::min<uint64_t>(BOOTSTRAP_SNAPSHOT_CHUNK_SIZE, file.nSize - request.nOffset);
    if (request.nLength != expected_length) {
        fclose(fp);
        error = strprintf("zcash param chunk length must be %u", expected_length);
        return false;
    }
    if (fseek(fp, request.nOffset, SEEK_SET) != 0) {
        fclose(fp);
        error = strprintf("could not seek zcash param file: %s", file.strPath);
        return false;
    }

    chunk.SetNull();
    chunk.nFileIndex = request.nFileIndex;
    chunk.nOffset = request.nOffset;
    chunk.vData.resize(request.nLength);
    const size_t nRead = fread(&chunk.vData[0], 1, request.nLength, fp);
    fclose(fp);
    if (nRead != request.nLength) {
        error = strprintf("could not read requested zcash param chunk: %s", file.strPath);
        return false;
    }
    return true;
}

static bool DownloadZcashParamFile(SOCKET socket, uint32_t file_index, uint64_t size, uint32_t chunk_size, const boost::filesystem::path& part_path, int timeout_ms, std::string& error)
{
    boost::filesystem::create_directories(part_path.parent_path());
    FILE* fp = fopen(part_path.string().c_str(), "wb");
    if (!fp) {
        error = strprintf("could not create zcash param staging file: %s", part_path.string());
        return false;
    }

    std::deque<CBootstrapSnapshotChunkRequest> inflight;
    uint64_t next_offset = 0;
    bool ok = true;

    // Prime the pipeline window.
    for (size_t i = 0; i < BOOTSTRAP_PIPELINE_DEPTH && next_offset < size; ++i) {
        CBootstrapSnapshotChunkRequest request;
        request.nFileIndex = file_index;
        request.nOffset = next_offset;
        request.nLength = (uint32_t)std::min<uint64_t>(chunk_size, size - next_offset);
        CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
        payload << request;
        if (!SendBootstrapMessage(socket, NetMsgType::GETBSPCHK, payload, timeout_ms, error)) {
            ok = false;
            break;
        }
        inflight.push_back(request);
        next_offset += request.nLength;
    }

    while (ok && !inflight.empty()) {
        CDataStream chunkPayload(SER_NETWORK, PROTOCOL_VERSION);
        if (!ReceiveExpectedBootstrapMessage(socket, NetMsgType::BSPCHK, chunkPayload, timeout_ms, error)) {
            ok = false;
            break;
        }
        CBootstrapSnapshotChunk chunk;
        try {
            chunkPayload >> chunk;
        } catch (const std::exception& e) {
            error = strprintf("could not decode zcash param chunk: %s", e.what());
            ok = false;
            break;
        }
        const CBootstrapSnapshotChunkRequest req = inflight.front();
        inflight.pop_front();
        if (chunk.nFileIndex != req.nFileIndex || chunk.nOffset != req.nOffset || chunk.vData.size() != req.nLength) {
            error = "zcash param peer returned an unexpected chunk";
            ok = false;
            break;
        }
        if (!WriteBootstrapChunkToFile(part_path, chunk, fp, error)) {
            ok = false;
            break;
        }
        if (next_offset < size) {
            CBootstrapSnapshotChunkRequest refill;
            refill.nFileIndex = file_index;
            refill.nOffset = next_offset;
            refill.nLength = (uint32_t)std::min<uint64_t>(chunk_size, size - next_offset);
            CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
            payload << refill;
            if (!SendBootstrapMessage(socket, NetMsgType::GETBSPCHK, payload, timeout_ms, error)) {
                ok = false;
                break;
            }
            inflight.push_back(refill);
            next_offset += refill.nLength;
        }
    }

    if (ok) {
        FileCommit(fp);
    }
    if (fclose(fp) != 0 && ok) {
        error = strprintf("could not close zcash param staging file: %s", part_path.string());
        return false;
    }
    return ok;
}

bool FetchZcashParamsFromPeer(const std::string& peer, std::string& error)
{
    const boost::filesystem::path dir = ZC_GetParamsDir();
    try {
        boost::filesystem::create_directories(dir);
    } catch (const boost::filesystem::filesystem_error& e) {
        error = e.what();
        return false;
    }

    CService peerAddress;
    SOCKET socket = INVALID_SOCKET;
    bool proxyConnectionFailed = false;
    if (!ConnectSocketByName(peerAddress, socket, peer.c_str(), Params().GetDefaultPort(), nConnectTimeout, &proxyConnectionFailed)) {
        error = proxyConnectionFailed ? "zcash param peer proxy connection failed" : strprintf("could not connect to zcash param peer: %s", peer);
        return false;
    }

    bool ok = true;
    try {
        if (!BootstrapHandshake(socket, peerAddress, BOOTSTRAP_NET_TIMEOUT_MS, error)) {
            CloseSocket(socket);
            return false;
        }

        CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
        CDataStream manifestPayload(SER_NETWORK, PROTOCOL_VERSION);
        if (!SendBootstrapMessage(socket, NetMsgType::GETBSPMAN, empty, BOOTSTRAP_NET_TIMEOUT_MS, error) ||
            !ReceiveExpectedBootstrapMessage(socket, NetMsgType::BSPMAN, manifestPayload, BOOTSTRAP_NET_TIMEOUT_MS, error)) {
            CloseSocket(socket);
            return false;
        }

        CBootstrapSnapshotManifest manifest;
        try {
            manifestPayload >> manifest;
        } catch (const std::exception& e) {
            CloseSocket(socket);
            error = strprintf("could not decode zcash param manifest: %s", e.what());
            return false;
        }
        if (manifest.nChunkSize == 0 || manifest.nChunkSize > BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE) {
            CloseSocket(socket);
            error = "zcash param manifest has invalid chunk size";
            return false;
        }

        for (size_t i = 0; i < ZCASH_PARAM_FILE_COUNT && ok; ++i) {
            const ZcashParamFile& param = ZCASH_PARAM_FILES[i];
            const boost::filesystem::path dest = dir / param.name;
            const uint256 expected = ZcashParamExpectedHash(param);

            // Skip files already present and valid.
            if (boost::filesystem::is_regular_file(dest)) {
                uint256 have;
                std::string hashError;
                if (HashBootstrapSnapshotFile(dest, have, hashError) && have == expected) {
                    continue;
                }
            }

            // Locate the file in the peer's manifest.
            uint32_t index = 0;
            uint64_t size = 0;
            bool found = false;
            for (uint32_t j = 0; j < manifest.vFiles.size(); ++j) {
                if (manifest.vFiles[j].strPath == param.name) {
                    index = j;
                    size = manifest.vFiles[j].nSize;
                    found = true;
                    break;
                }
            }
            if (!found) {
                error = strprintf("zcash param peer does not serve %s", param.name);
                ok = false;
                break;
            }

            LogPrintf("Zcash params: downloading %s (%llu bytes) from peer %s\n", param.name, (unsigned long long)size, peer);
            const boost::filesystem::path part = boost::filesystem::path(dest.string() + ".part");
            boost::filesystem::remove(part);
            if (!DownloadZcashParamFile(socket, index, size, manifest.nChunkSize, part, BOOTSTRAP_NET_TIMEOUT_MS, error)) {
                boost::filesystem::remove(part);
                ok = false;
                break;
            }

            uint256 have;
            if (!HashBootstrapSnapshotFile(part, have, error)) {
                boost::filesystem::remove(part);
                ok = false;
                break;
            }
            if (have != expected) {
                boost::filesystem::remove(part);
                error = strprintf("zcash param hash mismatch for %s: got %s expected %s", param.name, have.ToString(), expected.ToString());
                ok = false;
                break;
            }
            boost::filesystem::rename(part, dest);
            LogPrintf("Zcash params: installed %s\n", param.name);
        }
    } catch (const boost::filesystem::filesystem_error& e) {
        CloseSocket(socket);
        error = e.what();
        return false;
    }

    CloseSocket(socket);
    return ok;
}

bool PreflightBootstrapSnapshotService(std::string& error)
{
    CBootstrapSnapshotManifest manifest;
    if (!GetBootstrapSnapshotManifest(manifest, error)) {
        return false;
    }
    if (!ValidateBootstrapSnapshotManifest(manifest, error)) {
        return false;
    }
    if (manifest.vFiles.empty()) {
        error = "bootstrap snapshot manifest has no files";
        return false;
    }
    return true;
}

static bool StatOpenBootstrapSnapshotFile(FILE* fp, uint64_t& size, std::time_t& mtime)
{
#if defined(WIN32)
    struct _stat64 st;
    if (_fstat64(_fileno(fp), &st) != 0) {
        return false;
    }
#else
    struct stat st;
    if (fstat(fileno(fp), &st) != 0) {
        return false;
    }
#endif
    if (st.st_size < 0) {
        return false;
    }
    size = (uint64_t)st.st_size;
    mtime = st.st_mtime;
    return true;
}

static FILE* OpenBootstrapSnapshotFile(const boost::filesystem::path& source,
                                       const CBootstrapSnapshotFile& file,
                                       const std::map<std::string, std::time_t>& mtimes,
                                       std::string& error)
{
    const boost::filesystem::path relative(file.strPath);
    if (!IsBootstrapSnapshotDataPath(relative)) {
        error = strprintf("bootstrap snapshot manifest contains unsafe path: %s", file.strPath);
        return NULL;
    }

    const boost::filesystem::path path = source / relative;
    if (!boost::filesystem::is_regular_file(path) || !IsSafeBootstrapEntry(path)) {
        error = strprintf("bootstrap snapshot file is not a regular file: %s", path.string());
        return NULL;
    }
    std::map<std::string, std::time_t>::const_iterator mtime = mtimes.find(file.strPath);
    if (mtime == mtimes.end()) {
        error = strprintf("bootstrap snapshot file mtime missing from manifest cache: %s", file.strPath);
        return NULL;
    }

    FILE* fp = fopen(path.string().c_str(), "rb");
    if (!fp) {
        error = strprintf("could not open bootstrap snapshot file: %s", path.string());
        return NULL;
    }

    uint64_t file_size = 0;
    std::time_t file_mtime = 0;
    if (!StatOpenBootstrapSnapshotFile(fp, file_size, file_mtime)) {
        fclose(fp);
        error = strprintf("could not stat bootstrap snapshot file: %s", path.string());
        return NULL;
    }
    if (file_size != file.nSize) {
        fclose(fp);
        error = strprintf("bootstrap snapshot file size changed after manifest creation: %s", file.strPath);
        return NULL;
    }
    if (file_mtime != mtime->second) {
        fclose(fp);
        error = strprintf("bootstrap snapshot file changed after manifest creation: %s", file.strPath);
        return NULL;
    }
    return fp;
}

bool ReadBootstrapSnapshotChunk(const CBootstrapSnapshotChunkRequest& request, CBootstrapSnapshotChunk& chunk, std::string& error)
{
    if (!GetBoolArg("-bootstrapserve", false)) {
        error = "bootstrap snapshot service is not enabled";
        return false;
    }
    if (!mapArgs.count("-bootstrapsourcedir")) {
        error = "bootstrap snapshot service requires -bootstrapsourcedir";
        return false;
    }
    if (request.nLength == 0 || request.nLength > BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE) {
        error = strprintf("invalid bootstrap chunk length: %u", request.nLength);
        return false;
    }

    const boost::filesystem::path source = boost::filesystem::system_complete(mapArgs["-bootstrapsourcedir"]);
    std::vector<CBootstrapSnapshotFile> files;
    std::map<std::string, std::time_t> mtimes;
    {
        LOCK(cs_bootstrap_snapshot);
        if (bootstrapSnapshotCacheSource != source || bootstrapSnapshotCacheFiles.empty()) {
            if (!CollectBootstrapSnapshotFiles(source, true, bootstrapSnapshotCacheFiles, bootstrapSnapshotCacheMtimes, bootstrapSnapshotCacheBytes, error)) {
                return false;
            }
            bootstrapSnapshotCacheSource = source;
        }
        files = bootstrapSnapshotCacheFiles;
        mtimes = bootstrapSnapshotCacheMtimes;
    }
    if (request.nFileIndex >= files.size()) {
        error = strprintf("bootstrap chunk file index out of range: %u", request.nFileIndex);
        return false;
    }

    const CBootstrapSnapshotFile& file = files[request.nFileIndex];
    FILE* fp = OpenBootstrapSnapshotFile(source, file, mtimes, error);
    if (!fp) {
        return false;
    }
    if (request.nOffset > file.nSize || request.nLength > file.nSize - request.nOffset) {
        fclose(fp);
        error = "bootstrap chunk range exceeds file size";
        return false;
    }
    if (request.nOffset % BOOTSTRAP_SNAPSHOT_CHUNK_SIZE != 0) {
        fclose(fp);
        error = "bootstrap chunk offset is not aligned";
        return false;
    }
    const uint32_t expected_length = std::min<uint64_t>(BOOTSTRAP_SNAPSHOT_CHUNK_SIZE, file.nSize - request.nOffset);
    if (request.nLength != expected_length) {
        fclose(fp);
        error = strprintf("bootstrap chunk length must be %u", expected_length);
        return false;
    }
    if (fseek(fp, request.nOffset, SEEK_SET) != 0) {
        fclose(fp);
        error = strprintf("could not seek bootstrap snapshot file: %s", file.strPath);
        return false;
    }

    chunk.SetNull();
    chunk.nFileIndex = request.nFileIndex;
    chunk.nOffset = request.nOffset;
    chunk.vData.resize(request.nLength);
    const size_t nRead = fread(&chunk.vData[0], 1, request.nLength, fp);
    fclose(fp);
    if (nRead != request.nLength) {
        error = strprintf("could not read requested bootstrap snapshot chunk: %s", file.strPath);
        return false;
    }

    return true;
}

bool ValidateBootstrapSnapshotManifest(const CBootstrapSnapshotManifest& manifest, std::string& error)
{
    if (manifest.nVersion != 1) {
        error = "Bootstrap manifest has unsupported version";
        return false;
    }

    const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();
    if (manifest.strNetwork != Params().NetworkIDString() ||
        manifest.nHeight != anchor.nHeight ||
        manifest.hashBlock != anchor.hashBlock ||
        manifest.hashAnchorSha256 != anchor.hashAnchorSha256 ||
        manifest.hashAnchorSha3 != anchor.hashAnchorSha3) {
        error = "Bootstrap manifest does not match local fast-sync anchor";
        return false;
    }
    if (manifest.nChunkSize == 0 || manifest.nChunkSize > BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE) {
        error = "Bootstrap manifest has invalid chunk size";
        return false;
    }

    uint64_t total_bytes = 0;
    std::set<std::string> seen_paths;
    for (std::vector<CBootstrapSnapshotFile>::const_iterator it = manifest.vFiles.begin(); it != manifest.vFiles.end(); ++it) {
        const boost::filesystem::path relative(it->strPath);
        if (!IsBootstrapSnapshotDataPath(relative)) {
            error = strprintf("Bootstrap manifest has unsafe file path: %s", it->strPath);
            return false;
        }
        if (!seen_paths.insert(relative.generic_string()).second) {
            error = strprintf("Bootstrap manifest has duplicate file path: %s", it->strPath);
            return false;
        }
        if (it->hashSha256.IsNull()) {
            error = strprintf("Bootstrap manifest file is missing SHA-256: %s", it->strPath);
            return false;
        }
        if (it->nSize > std::numeric_limits<uint64_t>::max() - total_bytes) {
            error = "Bootstrap manifest byte size overflow";
            return false;
        }
        total_bytes += it->nSize;
    }

    if (total_bytes != manifest.nSnapshotBytes) {
        error = "Bootstrap manifest file sizes do not match total snapshot size";
        return false;
    }

    return true;
}

bool EnqueueBootstrapSnapshotChunkRequest(CNode* pfrom, const CBootstrapSnapshotChunkRequest& request, std::string& error)
{
    if (!GetBoolArg("-bootstrapserve", false)) {
        error = "bootstrap snapshot service is not enabled";
        return false;
    }
    if (request.nLength == 0 || request.nLength > BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE) {
        error = strprintf("invalid bootstrap chunk length: %u", request.nLength);
        return false;
    }
    if (request.nOffset % BOOTSTRAP_SNAPSHOT_CHUNK_SIZE != 0) {
        error = "bootstrap chunk offset is not aligned";
        return false;
    }

    if (!pfrom->QueueBootstrapChunkRequest(request)) {
        error = "too many pending bootstrap chunk requests";
        return false;
    }
    return true;
}

// --- Per-IP serve quota / throttle (bandwidth abuse limiting) ---

static const int64_t BOOTSTRAP_SERVE_WINDOW_MS = 24 * 60 * 60 * 1000LL;
static const size_t BOOTSTRAP_SERVE_MAX_TRACKED_IPS = 16384;

struct BootstrapServeQuota {
    int64_t windowStartMs;
    uint64_t bytesServed;
    int64_t nextAllowedMs;
    BootstrapServeQuota() : windowStartMs(0), bytesServed(0), nextAllowedMs(0) {}
};

static CCriticalSection cs_bootstrap_serve_quota;
static std::map<std::string, BootstrapServeQuota> bootstrapServeQuota;

static int64_t BootstrapServeMaxBytesPerDay()
{
    return GetArg("-bootstrapservemaxbytesperday", BOOTSTRAP_SERVE_DEFAULT_MAX_BYTES_PER_DAY);
}

static int64_t BootstrapServeThrottleKBps()
{
    return GetArg("-bootstrapservethrottlekbps", BOOTSTRAP_SERVE_DEFAULT_THROTTLE_KBPS);
}

void ClearBootstrapServeQuota()
{
    LOCK(cs_bootstrap_serve_quota);
    bootstrapServeQuota.clear();
}

bool BootstrapServeAllowChunk(const std::string& ip, bool whitelisted, int64_t now_ms, bool& stop)
{
    stop = false;
    const int64_t cap = BootstrapServeMaxBytesPerDay();
    if (whitelisted || cap <= 0) {
        return true;
    }

    LOCK(cs_bootstrap_serve_quota);
    std::map<std::string, BootstrapServeQuota>::iterator it = bootstrapServeQuota.find(ip);
    if (it == bootstrapServeQuota.end()) {
        return true; // nothing served to this address yet
    }
    BootstrapServeQuota& q = it->second;
    if (now_ms - q.windowStartMs >= BOOTSTRAP_SERVE_WINDOW_MS) {
        return true; // window has rolled over; the next charge resets it
    }
    if (q.bytesServed < (uint64_t)cap) {
        return true; // still under the daily cap
    }
    // Over the daily cap.
    if (BootstrapServeThrottleKBps() <= 0) {
        stop = true; // operator chose a hard stop instead of a slow trickle
        return false;
    }
    return now_ms >= q.nextAllowedMs; // throttled: serve only once the gap has elapsed
}

void BootstrapServeChargeBytes(const std::string& ip, bool whitelisted, int64_t now_ms, uint64_t bytes)
{
    const int64_t cap = BootstrapServeMaxBytesPerDay();
    if (whitelisted || cap <= 0) {
        return;
    }

    LOCK(cs_bootstrap_serve_quota);
    BootstrapServeQuota& q = bootstrapServeQuota[ip];
    if (q.windowStartMs == 0 || now_ms - q.windowStartMs >= BOOTSTRAP_SERVE_WINDOW_MS) {
        q.windowStartMs = now_ms;
        q.bytesServed = 0;
        q.nextAllowedMs = 0;
    }
    q.bytesServed += bytes;
    if (q.bytesServed >= (uint64_t)cap) {
        const int64_t kbps = BootstrapServeThrottleKBps();
        if (kbps > 0) {
            // Space out the next send so the over-cap rate approximates `kbps`.
            const int64_t delayMs = (int64_t)((bytes * 1000) / ((uint64_t)kbps * 1024));
            q.nextAllowedMs = now_ms + std::max<int64_t>(1, delayMs);
        }
    }

    // Bound memory: drop entries whose window has fully expired.
    if (bootstrapServeQuota.size() > BOOTSTRAP_SERVE_MAX_TRACKED_IPS) {
        for (std::map<std::string, BootstrapServeQuota>::iterator it = bootstrapServeQuota.begin(); it != bootstrapServeQuota.end();) {
            if (now_ms - it->second.windowStartMs >= BOOTSTRAP_SERVE_WINDOW_MS) {
                bootstrapServeQuota.erase(it++);
            } else {
                ++it;
            }
        }
    }
}

bool SendQueuedBootstrapSnapshotChunk(CNode* pto)
{
    CBootstrapSnapshotChunkRequest request;
    if (!pto->PopBootstrapChunkRequest(request)) {
        return true;
    }

    // Apply the per-IP daily serve quota only once we have a request to serve,
    // so peers with no bootstrap traffic never touch the quota lock.
    const std::string ip = pto->addr.ToStringIP();
    bool stop = false;
    if (!BootstrapServeAllowChunk(ip, pto->fWhitelisted, GetTimeMillis(), stop)) {
        if (stop) {
            LogPrint("net", "bootstrap serve quota exceeded for peer=%d (%s); rejecting chunk request\n", pto->id, ip);
            pto->PushMessage("reject", std::string(NetMsgType::GETBSCHK), REJECT_INVALID, std::string("bootstrap serve quota exceeded"));
        } else {
            // Throttled: put the request back and try again on a later cycle.
            pto->RequeueBootstrapChunkRequest(request);
        }
        return true;
    }

    CBootstrapSnapshotChunk chunk;
    std::string error;
    if (!ReadBootstrapSnapshotChunk(request, chunk, error)) {
        LogPrint("net", "could not read bootstrap snapshot chunk for peer=%d: %s\n", pto->id, error);
        pto->PushMessage("reject", std::string(NetMsgType::GETBSCHK), REJECT_INVALID, std::string("invalid bootstrap chunk request"));
        return true;
    }

    LogPrint("net", "sending bootstrap snapshot chunk file=%u offset=%llu bytes=%u peer=%d\n",
        chunk.nFileIndex,
        (unsigned long long)chunk.nOffset,
        (unsigned int)chunk.vData.size(),
        pto->id);
    pto->PushMessage(NetMsgType::BSCHK, chunk);
    BootstrapServeChargeBytes(ip, pto->fWhitelisted, GetTimeMillis(), chunk.vData.size());
    return true;
}
