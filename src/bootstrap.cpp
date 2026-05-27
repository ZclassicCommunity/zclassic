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
#include <exception>
#include <limits>
#include <set>
#include <stdio.h>
#include <string.h>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

static CCriticalSection cs_bootstrap_snapshot;
static boost::filesystem::path bootstrapSnapshotCacheSource;
static std::vector<CBootstrapSnapshotFile> bootstrapSnapshotCacheFiles;
static uint64_t bootstrapSnapshotCacheBytes = 0;
static const unsigned int BOOTSTRAP_MAX_REJECT_MESSAGE_LENGTH = 111;

static bool IsSafeBootstrapSnapshotPath(const boost::filesystem::path& relative);
static bool IsBootstrapSnapshotDataPath(const boost::filesystem::path& relative);
static bool HashBootstrapSnapshotFile(const boost::filesystem::path& path, uint256& hash, std::string& error);

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

static bool DownloadBootstrapFile(SOCKET socket, const CBootstrapSnapshotManifest& manifest, uint32_t file_index, const boost::filesystem::path& staging, int timeout_ms, std::string& error)
{
    const CBootstrapSnapshotFile& file = manifest.vFiles[file_index];
    const boost::filesystem::path relative(file.strPath);
    if (!IsBootstrapSnapshotDataPath(relative)) {
        error = strprintf("bootstrap manifest has unsafe file path: %s", file.strPath);
        return false;
    }

    const boost::filesystem::path path = staging / relative;
    const boost::filesystem::path part_path = boost::filesystem::path(path.string() + ".part");
    boost::filesystem::create_directories(path.parent_path());

    FILE* fp = fopen(part_path.string().c_str(), "wb");
    if (!fp) {
        error = strprintf("could not create bootstrap staging file: %s", part_path.string());
        return false;
    }

    uint64_t offset = 0;
    while (offset < file.nSize) {
        CBootstrapSnapshotChunkRequest request;
        request.nFileIndex = file_index;
        request.nOffset = offset;
        request.nLength = std::min<uint64_t>(manifest.nChunkSize, file.nSize - offset);

        CDataStream requestPayload(SER_NETWORK, PROTOCOL_VERSION);
        requestPayload << request;
        if (!SendBootstrapMessage(socket, NetMsgType::GETBSCHK, requestPayload, timeout_ms, error)) {
            fclose(fp);
            return false;
        }

        CDataStream chunkPayload(SER_NETWORK, PROTOCOL_VERSION);
        if (!ReceiveExpectedBootstrapMessage(socket, NetMsgType::BSCHK, chunkPayload, timeout_ms, error)) {
            fclose(fp);
            return false;
        }

        CBootstrapSnapshotChunk chunk;
        try {
            chunkPayload >> chunk;
        } catch (const std::exception& e) {
            fclose(fp);
            error = strprintf("could not decode bootstrap chunk: %s", e.what());
            return false;
        }

        if (chunk.nFileIndex != request.nFileIndex ||
            chunk.nOffset != request.nOffset ||
            chunk.vData.size() != request.nLength) {
            fclose(fp);
            error = "bootstrap peer returned an unexpected chunk";
            return false;
        }
        if (!WriteBootstrapChunkToFile(part_path, chunk, fp, error)) {
            fclose(fp);
            return false;
        }

        offset += request.nLength;
    }

    FileCommit(fp);
    if (fclose(fp) != 0) {
        error = strprintf("could not close bootstrap staging file: %s", part_path.string());
        return false;
    }

    if (!VerifyBootstrapDownloadedFile(part_path, file, error)) {
        return false;
    }

    boost::filesystem::rename(part_path, path);
    return true;
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

        if (!BootstrapHandshake(socket, peerAddress, nConnectTimeout, error)) {
            CloseSocket(socket);
            boost::filesystem::remove_all(staging);
            return false;
        }

        CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
        if (!SendBootstrapMessage(socket, NetMsgType::GETBSMAN, empty, nConnectTimeout, error)) {
            CloseSocket(socket);
            boost::filesystem::remove_all(staging);
            return false;
        }

        CDataStream manifestPayload(SER_NETWORK, PROTOCOL_VERSION);
        if (!ReceiveExpectedBootstrapMessage(socket, NetMsgType::BSMAN, manifestPayload, nConnectTimeout, error)) {
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

        for (uint32_t i = 0; i < manifest.vFiles.size(); ++i) {
            if (!DownloadBootstrapFile(socket, manifest, i, staging, nConnectTimeout, error)) {
                CloseSocket(socket);
                boost::filesystem::remove_all(staging);
                return false;
            }
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

static bool CollectBootstrapSnapshotFiles(const boost::filesystem::path& root, bool hash_files, std::vector<CBootstrapSnapshotFile>& files, uint64_t& total_bytes, std::string& error)
{
    files.clear();
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
        if (!CollectBootstrapSnapshotFiles(source, true, bootstrapSnapshotCacheFiles, bootstrapSnapshotCacheBytes, error)) {
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
    uint64_t total_bytes = 0;
    if (!GetBootstrapSnapshotFileList(source, files, total_bytes, error)) {
        return false;
    }
    if (request.nFileIndex >= files.size()) {
        error = strprintf("bootstrap chunk file index out of range: %u", request.nFileIndex);
        return false;
    }

    const CBootstrapSnapshotFile& file = files[request.nFileIndex];
    if (request.nOffset > file.nSize || request.nLength > file.nSize - request.nOffset) {
        error = "bootstrap chunk range exceeds file size";
        return false;
    }
    if (request.nOffset % BOOTSTRAP_SNAPSHOT_CHUNK_SIZE != 0) {
        error = "bootstrap chunk offset is not aligned";
        return false;
    }
    const uint32_t expected_length = std::min<uint64_t>(BOOTSTRAP_SNAPSHOT_CHUNK_SIZE, file.nSize - request.nOffset);
    if (request.nLength != expected_length) {
        error = strprintf("bootstrap chunk length must be %u", expected_length);
        return false;
    }

    const boost::filesystem::path relative(file.strPath);
    if (!IsBootstrapSnapshotDataPath(relative)) {
        error = strprintf("bootstrap snapshot manifest contains unsafe path: %s", file.strPath);
        return false;
    }

    const boost::filesystem::path path = source / relative;
    if (!boost::filesystem::is_regular_file(path) || !IsSafeBootstrapEntry(path)) {
        error = strprintf("bootstrap snapshot file is not a regular file: %s", path.string());
        return false;
    }

    FILE* fp = fopen(path.string().c_str(), "rb");
    if (!fp) {
        error = strprintf("could not open bootstrap snapshot file: %s", path.string());
        return false;
    }
    if (fseek(fp, request.nOffset, SEEK_SET) != 0) {
        fclose(fp);
        error = strprintf("could not seek bootstrap snapshot file: %s", path.string());
        return false;
    }

    chunk.SetNull();
    chunk.nFileIndex = request.nFileIndex;
    chunk.nOffset = request.nOffset;
    chunk.vData.resize(request.nLength);
    const size_t nRead = fread(&chunk.vData[0], 1, request.nLength, fp);
    fclose(fp);
    if (nRead != request.nLength) {
        error = strprintf("could not read requested bootstrap snapshot chunk: %s", path.string());
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

bool SendQueuedBootstrapSnapshotChunk(CNode* pto)
{
    CBootstrapSnapshotChunkRequest request;
    if (!pto->PopBootstrapChunkRequest(request)) {
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
    return true;
}
