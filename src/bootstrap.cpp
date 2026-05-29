// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrap.h"

#include "chainparams.h"
#include "coins.h"
#include "compat.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "pow.h"
#include "sync.h"
#include "txdb.h"
#include "ui_interface.h"
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
#else
#include <unistd.h>
#endif

// True when the persistent metrics screen owns the console. It clears and
// redraws the whole screen every second, so progress must go through
// uiInterface.InitMessage (which the screen renders on a managed line) rather
// than writing to stdout directly, or the two fight and flicker.
static bool BootstrapMetricsScreenActive()
{
#if defined(WIN32)
    const bool is_tty = (_isatty(_fileno(stdout)) != 0);
#else
    const bool is_tty = (isatty(fileno(stdout)) != 0);
#endif
    // Mirror exactly the condition under which AppInit2 starts the metrics
    // screen thread (see init.cpp). If these drift, progress is either routed
    // to InitMessage when no screen is running, or written to stdout while the
    // screen is redrawing (flicker).
    return (Params().NetworkIDString() != "regtest") &&
           GetBoolArg("-showmetrics", is_tty) &&
           !fPrintToConsole && !GetBoolArg("-daemon", false);
}

// Emit a single in-place-updating progress line to the console. On a TTY it
// rewrites one line (carriage return + clear-to-end-of-line), throttled so it
// does not flicker; when piped/redirected it prints occasional plain lines. The
// caller passes done=true for the final state, which always prints + newline.
static void EmitBootstrapProgress(const std::string& line, int percent, bool done, int64_t& last_emit_ms, int& last_emit_decile)
{
#if defined(WIN32)
    static const bool is_tty = (_isatty(_fileno(stdout)) != 0);
#else
    static const bool is_tty = (isatty(fileno(stdout)) != 0);
#endif
    if (is_tty) {
        const int64_t now = GetTimeMillis();
        if (!done && now - last_emit_ms < 200) {
            return; // throttle to ~5 updates/sec to avoid flicker
        }
        last_emit_ms = now;
        fprintf(stdout, "\r%s\x1b[K", line.c_str());
        if (done) {
            fprintf(stdout, "\n");
        }
    } else {
        // Not a terminal: avoid carriage-return spam; one plain line per 10%.
        const int decile = percent / 10;
        if (!done && decile == last_emit_decile) {
            return;
        }
        last_emit_decile = decile;
        fprintf(stdout, "%s\n", line.c_str());
    }
    fflush(stdout);
}

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

// Minimum sustained download rate for a bootstrap transfer. If a peer delivers
// less than this on average across a full throughput window, the download is
// aborted (it would otherwise hang init for hours/days). 32 KiB/s is far below
// any real link but well above a chunk-per-60s trickle (~8.7 KiB/s).
static const int64_t BOOTSTRAP_MIN_THROUGHPUT_BYTES_PER_SEC = 32 * 1024;
static const int64_t BOOTSTRAP_THROUGHPUT_WINDOW_MS = 60 * 1000;

// Windowed minimum-throughput watchdog for bootstrap downloads. The caller keeps
// windowStartMs/bytesAtWindowStart as locals, initialized to (download start
// time, 0), and calls this after each received chunk with the cumulative bytes
// received and the current time (GetTimeMillis()). Returns true => abort: a full
// BOOTSTRAP_THROUGHPUT_WINDOW_MS elapsed during which the peer delivered less
// than BOOTSTRAP_MIN_THROUGHPUT_BYTES_PER_SEC on average. On a healthy window it
// advances the window and returns false; before a window completes it returns
// false (lets the transfer ramp up). Exposed (non-static) for unit tests.
bool BootstrapDownloadTooSlow(int64_t& windowStartMs, uint64_t& bytesAtWindowStart,
                              uint64_t totalBytesReceived, int64_t nowMs)
{
    const int64_t elapsedMs = nowMs - windowStartMs;
    if (elapsedMs < BOOTSTRAP_THROUGHPUT_WINDOW_MS) {
        return false; // window not complete yet
    }
    const uint64_t bytesThisWindow = totalBytesReceived - bytesAtWindowStart;
    const uint64_t requiredBytes = (uint64_t)BOOTSTRAP_MIN_THROUGHPUT_BYTES_PER_SEC * (uint64_t)(elapsedMs / 1000);
    if (bytesThisWindow < requiredBytes) {
        return true; // sustained below the floor for a full window
    }
    windowStartMs = nowMs;
    bytesAtWindowStart = totalBytesReceived;
    return false;
}

// Forward declarations for the bootstrap-handshake/message helpers reused by
// decentralized discovery below; their definitions appear later in this file.
static bool BootstrapHandshake(SOCKET socket, const CService& peer_address, int timeout_ms, std::string& error);
static bool SendBootstrapMessage(SOCKET socket, const char* command, const CDataStream& payload, int timeout_ms, std::string& error);
static bool ReceiveExpectedBootstrapMessage(SOCKET socket, const char* expected_command, CDataStream& payload, int timeout_ms, std::string& error);

// --- Decentralized bootstrap-peer discovery ------------------------------
//
// A fresh node should not have to trust a single project-operated IP to
// fast-sync. As a best-effort fallback (only used when the explicit/compiled
// peers don't work — see the init bootstrap loop), we ask the network's
// existing DNS seeds (and, failing those, the compiled fixed seeds) for
// addresses, dial a few with the same lightweight bootstrap version handshake
// used for snapshot transfers, then run a getaddr/addr round-trip and keep any
// advertised peers that set the NODE_BOOTSTRAP service bit. Everything here is
// strictly bounded and best-effort: it never throws out, respects a short
// per-message timeout so it cannot hang init, and returns an empty vector on
// any failure. Safe to fast-sync from a discovered (untrusted) peer because the
// imported chainstate is verified against the compiled anchor + UTXO commitment.

// How many resolved seed/source addresses to dial looking for an addr reply.
static const size_t BOOTSTRAP_DISCOVERY_MAX_DIAL = 3;
// How many distinct DNS seeds to resolve before giving up on resolution.
static const size_t BOOTSTRAP_DISCOVERY_MAX_SEEDS = 3;
// Maximum NODE_BOOTSTRAP "ip:port" strings to return.
static const size_t BOOTSTRAP_DISCOVERY_MAX_RESULTS = 8;
// Cap on candidate addresses collected from seeds before dialing.
static const size_t BOOTSTRAP_DISCOVERY_MAX_CANDIDATES = 64;
// Per-dial timeout for the discovery handshake + getaddr/addr exchange. Kept
// well under the snapshot transfer timeout: discovery is a quick probe, not a
// transfer, and we may try several peers back to back during init.
static const int BOOTSTRAP_DISCOVERY_NET_TIMEOUT_MS = 10000;

// Run the bootstrap handshake against an already-connected socket, then issue
// a single getaddr and read one addr reply, appending NODE_BOOTSTRAP peers as
// "ip:port" strings to `out`. Best-effort: any failure just leaves `out`
// unchanged for this peer. Returns the number of new entries appended.
static size_t DiscoverBootstrapPeersFromSocket(SOCKET socket, const CService& peerAddress, std::vector<std::string>& out)
{
    std::string error;
    if (!BootstrapHandshake(socket, peerAddress, BOOTSTRAP_DISCOVERY_NET_TIMEOUT_MS, error)) {
        LogPrint("net", "bootstrap discovery: handshake with %s failed: %s\n", peerAddress.ToStringIPPort(), error);
        return 0;
    }

    CDataStream empty(SER_NETWORK, PROTOCOL_VERSION);
    if (!SendBootstrapMessage(socket, "getaddr", empty, BOOTSTRAP_DISCOVERY_NET_TIMEOUT_MS, error)) {
        LogPrint("net", "bootstrap discovery: getaddr to %s failed: %s\n", peerAddress.ToStringIPPort(), error);
        return 0;
    }

    CDataStream addrPayload(SER_NETWORK, PROTOCOL_VERSION);
    if (!ReceiveExpectedBootstrapMessage(socket, "addr", addrPayload, BOOTSTRAP_DISCOVERY_NET_TIMEOUT_MS, error)) {
        LogPrint("net", "bootstrap discovery: no addr reply from %s: %s\n", peerAddress.ToStringIPPort(), error);
        return 0;
    }

    std::vector<CAddress> vAddr;
    try {
        addrPayload >> vAddr;
    } catch (const std::exception& e) {
        LogPrint("net", "bootstrap discovery: malformed addr from %s: %s\n", peerAddress.ToStringIPPort(), e.what());
        return 0;
    }
    // Mirror the addr-message bound enforced by the normal net handler so a
    // misbehaving peer cannot make us iterate an enormous list.
    if (vAddr.size() > 1000) {
        LogPrint("net", "bootstrap discovery: oversized addr (%u) from %s\n", (unsigned int)vAddr.size(), peerAddress.ToStringIPPort());
        return 0;
    }

    size_t appended = 0;
    for (size_t i = 0; i < vAddr.size() && out.size() < BOOTSTRAP_DISCOVERY_MAX_RESULTS; ++i) {
        const CAddress& addr = vAddr[i];
        if (!(addr.nServices & NODE_BOOTSTRAP)) {
            continue;
        }
        if (!addr.IsValid()) {
            continue;
        }
        const std::string entry = addr.ToStringIPPort();
        if (std::find(out.begin(), out.end(), entry) != out.end()) {
            continue;
        }
        out.push_back(entry);
        ++appended;
    }
    return appended;
}

std::vector<std::string> DiscoverBootstrapPeers()
{
    std::vector<std::string> discovered;

    // Wrap the whole thing: discovery must never throw out of init.
    try {
        // 1) Gather candidate addresses from the active network's DNS seeds,
        //    falling back to the compiled fixed seeds. We do not consult addrman
        //    here because discovery runs in the pre-database init phase, before
        //    the peer DB / CNode machinery is up.
        std::vector<CService> candidates;

        const std::vector<CDNSSeedData>& vSeeds = Params().DNSSeeds();
        const int defaultPort = Params().GetDefaultPort();
        size_t seedsTried = 0;
        // Name proxies (e.g. Tor) cannot be resolved to raw addresses for a
        // direct dial; in that mode skip DNS resolution and rely on fixed seeds.
        if (!HaveNameProxy()) {
            for (size_t s = 0; s < vSeeds.size() &&
                                seedsTried < BOOTSTRAP_DISCOVERY_MAX_SEEDS &&
                                candidates.size() < BOOTSTRAP_DISCOVERY_MAX_CANDIDATES; ++s) {
                ++seedsTried;
                std::vector<CNetAddr> vIPs;
                if (!LookupHost(vSeeds[s].host.c_str(), vIPs, 0, true)) {
                    continue;
                }
                for (size_t i = 0; i < vIPs.size() && candidates.size() < BOOTSTRAP_DISCOVERY_MAX_CANDIDATES; ++i) {
                    if (vIPs[i].IsValid()) {
                        candidates.push_back(CService(vIPs[i], (unsigned short)defaultPort));
                    }
                }
            }
        }

        if (candidates.empty()) {
            const std::vector<SeedSpec6>& vFixed = Params().FixedSeeds();
            for (size_t i = 0; i < vFixed.size() && candidates.size() < BOOTSTRAP_DISCOVERY_MAX_CANDIDATES; ++i) {
                struct in6_addr ip;
                memcpy(&ip, vFixed[i].addr, sizeof(ip));
                CService svc(ip, vFixed[i].port);
                if (svc.IsValid()) {
                    candidates.push_back(svc);
                }
            }
        }

        if (candidates.empty()) {
            return discovered;
        }

        // 2) Dial a bounded number of candidates and harvest NODE_BOOTSTRAP
        //    peers from each one's addr reply, stopping early once we have
        //    enough results.
        size_t dialed = 0;
        for (size_t i = 0; i < candidates.size() &&
                           dialed < BOOTSTRAP_DISCOVERY_MAX_DIAL &&
                           discovered.size() < BOOTSTRAP_DISCOVERY_MAX_RESULTS; ++i) {
            const CService& target = candidates[i];
            if (!target.IsValid()) {
                continue;
            }
            ++dialed;

            SOCKET socket = INVALID_SOCKET;
            bool proxyConnectionFailed = false;
            if (!ConnectSocket(target, socket, nConnectTimeout, &proxyConnectionFailed)) {
                LogPrint("net", "bootstrap discovery: could not connect to %s\n", target.ToStringIPPort());
                continue;
            }

            DiscoverBootstrapPeersFromSocket(socket, target, discovered);
            CloseSocket(socket);
        }
    } catch (const std::exception& e) {
        LogPrint("net", "bootstrap discovery aborted: %s\n", e.what());
        return std::vector<std::string>();
    } catch (...) {
        return std::vector<std::string>();
    }

    if (!discovered.empty()) {
        LogPrintf("Bootstrap: discovered %u NODE_BOOTSTRAP peer(s) from network seeds\n", (unsigned int)discovered.size());
    }
    return discovered;
}

std::vector<std::string> GetBootstrapPeerList()
{
    // Explicit -bootstrappeer entries (repeatable) take precedence: the operator
    // asked for exactly these peers.
    std::map<std::string, std::vector<std::string> >::const_iterator it = mapMultiArgs.find("-bootstrappeer");
    if (it != mapMultiArgs.end() && !it->second.empty()) {
        return it->second;
    }
    // Backwards-compat: a single -bootstrappeer also lands in mapArgs.
    if (mapArgs.count("-bootstrappeer")) {
        return std::vector<std::string>(1, mapArgs["-bootstrappeer"]);
    }
    // Otherwise the compiled per-network defaults. Network discovery of
    // additional NODE_BOOTSTRAP peers (DiscoverBootstrapPeers) is invoked
    // lazily by the init bootstrap loop only if these fail, so we neither pay
    // its latency nor dial seed peers when a compiled peer already works.
    return Params().BootstrapPeers();
}

static bool IsSafeBootstrapSnapshotPath(const boost::filesystem::path& relative);
static bool IsBootstrapSnapshotDataPath(const boost::filesystem::path& relative);
static bool HashBootstrapSnapshotFile(const boost::filesystem::path& path, uint256& hash, std::string& error);
static bool StatOpenBootstrapSnapshotFile(FILE* fp, uint64_t& size, std::time_t& mtime);
// Shared chunk range/alignment/length validation for the two serve-read paths
// (ReadBootstrapSnapshotChunk, ReadZcashParamChunk). Both serve fixed-size
// chunks aligned to chunkSize; this captures the identical post-open checks
// (range within fileSize with no overflow, offset alignment, exact expected
// length). `label` selects the byte-identical error-string prefix used by each
// caller ("bootstrap" vs "zcash param").
static bool ValidateBootstrapChunkRange(uint64_t offset, uint64_t length, uint64_t fileSize,
                                        uint64_t chunkSize, const char* label, std::string& error);
static bool InstallStagedBootstrapChainData(const boost::filesystem::path& staging,
                                            const boost::filesystem::path& data_dir,
                                            std::string& error);

// Portable 64-bit seek. fseek()'s `long` second argument wraps on 32-bit
// platforms and on Windows (where `long` is 32 bits), so bootstrap files
// larger than 2 GiB would be truncated. Mirror the Windows-vs-POSIX split
// already used in StatOpenBootstrapSnapshotFile.
static bool BootstrapFseek64(FILE* fp, int64_t off)
{
#if defined(WIN32)
    return _fseeki64(fp, off, SEEK_SET) == 0;
#else
    return fseeko(fp, (off_t)off, SEEK_SET) == 0;
#endif
}
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

        boost::filesystem::path backup;
        if (has_existing) {
            backup = data_dir / boost::filesystem::unique_path(strprintf("bootstrap-backup-%d-%%%%-%%%%-%%%%", GetTime()));
            boost::filesystem::create_directories(backup);
            if (boost::filesystem::exists(blocks_dir))
                boost::filesystem::rename(blocks_dir, backup / "blocks");
            if (boost::filesystem::exists(chainstate_dir))
                boost::filesystem::rename(chainstate_dir, backup / "chainstate");
            LogPrintf("Moved existing chain data to %s\n", backup.string());
        }

        if (!InstallStagedBootstrapChainData(staging, data_dir, error)) {
            if (!backup.empty()) {
                try {
                    boost::filesystem::remove_all(blocks_dir);
                    boost::filesystem::remove_all(chainstate_dir);
                    if (boost::filesystem::exists(backup / "blocks"))
                        boost::filesystem::rename(backup / "blocks", blocks_dir);
                    if (boost::filesystem::exists(backup / "chainstate"))
                        boost::filesystem::rename(backup / "chainstate", chainstate_dir);
                    boost::filesystem::remove_all(backup);
                } catch (const boost::filesystem::filesystem_error& e) {
                    error = strprintf("%s; additionally failed to restore bootstrap backup: %s", error, e.what());
                }
            }
            boost::filesystem::remove_all(staging);
            return false;
        }
    } catch (const boost::filesystem::filesystem_error& e) {
        error = e.what();
        return false;
    }

    LogPrintf("Imported bootstrap chain data from %s\n", source_root.string());
    return true;
}

static bool InstallStagedBootstrapChainData(const boost::filesystem::path& staging,
                                            const boost::filesystem::path& data_dir,
                                            std::string& error)
{
    const boost::filesystem::path blocks_dir = data_dir / "blocks";
    const boost::filesystem::path chainstate_dir = data_dir / "chainstate";
    bool installed_blocks = false;
    bool installed_chainstate = false;

    try {
        if (!BootstrapSnapshotPathsExist(staging)) {
            error = "staged bootstrap data is incomplete";
            return false;
        }
        if (boost::filesystem::exists(blocks_dir) || boost::filesystem::exists(chainstate_dir)) {
            error = strprintf("%s already has blocks/ or chainstate/", data_dir.string());
            return false;
        }

        boost::filesystem::rename(staging / "blocks", blocks_dir);
        installed_blocks = true;
        boost::filesystem::rename(staging / "chainstate", chainstate_dir);
        installed_chainstate = true;
        boost::filesystem::remove_all(staging);
        return true;
    } catch (const boost::filesystem::filesystem_error& e) {
        try {
            if (installed_blocks)
                boost::filesystem::remove_all(blocks_dir);
            if (installed_chainstate)
                boost::filesystem::remove_all(chainstate_dir);
            boost::filesystem::remove_all(staging);
        } catch (const boost::filesystem::filesystem_error& cleanup) {
            error = strprintf("bootstrap install failed: %s; cleanup failed: %s", e.what(), cleanup.what());
            return false;
        }
        error = strprintf("bootstrap install failed: %s", e.what());
        return false;
    }
}

static bool WriteBootstrapChunkToFile(const boost::filesystem::path& path, const CBootstrapSnapshotChunk& chunk, FILE* file, std::string& error)
{
    if (!BootstrapFseek64(file, (int64_t)chunk.nOffset)) {
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

    // Refuse to start if the staging filesystem cannot fit the manifest plus
    // a safety margin. Cheaper to fail fast than to fill the disk and then
    // discover the last chunk's hash is wrong.
    try {
        boost::filesystem::create_directories(staging);
        boost::filesystem::space_info si = boost::filesystem::space(staging);
        const uint64_t need = manifest.nSnapshotBytes + (uint64_t)BOOTSTRAP_SNAPSHOT_DISK_SAFETY_MARGIN_BYTES;
        if (si.available < need) {
            error = strprintf(
                "insufficient free space in %s for bootstrap snapshot: need %llu bytes (including %lld safety margin), have %llu",
                staging.string(),
                (unsigned long long)need,
                (long long)BOOTSTRAP_SNAPSHOT_DISK_SAFETY_MARGIN_BYTES,
                (unsigned long long)si.available);
            return false;
        }
    } catch (const boost::filesystem::filesystem_error& e) {
        error = strprintf("could not query free space in bootstrap staging dir %s: %s", staging.string(), e.what());
        return false;
    }

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
    int64_t last_emit_ms = 0;
    int last_emit_decile = -1;
    const int64_t download_started = GetTimeMillis();
    int64_t throughputWindowStartMs = download_started;
    uint64_t throughputBytesAtWindowStart = 0;
    bool ok = true;

    while (ok && !inflight.empty()) {
        if (ShutdownRequested()) {
            error = "bootstrap snapshot download aborted: shutdown requested";
            ok = false;
            break;
        }
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

        if (BootstrapDownloadTooSlow(throughputWindowStartMs, throughputBytesAtWindowStart,
                                     received_total, GetTimeMillis())) {
            error = "bootstrap snapshot download too slow (peer stalled or throttling); aborting";
            ok = false;
            break;
        }

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
            const double mbps = (received_total / 1048576.0) / (elapsed_ms / 1000.0);
            LogPrintf("Bootstrap: downloaded %d%% (%llu/%llu bytes, %.1f MB/s)\n",
                percent,
                (unsigned long long)received_total,
                (unsigned long long)manifest.nSnapshotBytes,
                mbps);
            // Live progress. The snapshot download overlaps the metrics screen
            // thread, so when that owns the console feed it through InitMessage
            // (rendered cleanly on the screen's managed line); otherwise write a
            // throttled single line to stdout directly.
            const std::string progress = strprintf(
                "Bootstrap snapshot: %3d%%  %.2f / %.2f GB  %.1f MB/s",
                percent,
                received_total / 1073741824.0,
                manifest.nSnapshotBytes / 1073741824.0,
                mbps);
            if (BootstrapMetricsScreenActive()) {
                uiInterface.InitMessage(progress);
            } else {
                EmitBootstrapProgress(progress, percent, percent >= 100, last_emit_ms, last_emit_decile);
            }
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

// Path of the immutable snapshot copy an auto-serve node retains and serves.
// This dir must contain ONLY blocks/ and chainstate/ — the serve manifest
// scanner (CollectBootstrapSnapshotFiles) rejects any other entry as unsafe —
// so the anchor marker lives in a sibling file, not inside this directory.
static boost::filesystem::path AutoServeSourceDir(const boost::filesystem::path& data_dir)
{
    return data_dir / "bootstrap-serve-source";
}

boost::filesystem::path BootstrapAutoServeSourceDir(const boost::filesystem::path& data_dir)
{
    return AutoServeSourceDir(data_dir);
}

// Sibling marker recording which anchor the retained copy is for. Kept outside
// the serve dir so it is never picked up by the manifest file scan.
static boost::filesystem::path AutoServeMarkerPath(const boost::filesystem::path& data_dir)
{
    return data_dir / "bootstrap-serve-source.anchor";
}

// Identity string ("<height> <blockhash>") recorded alongside a retained
// auto-serve copy so a later run only serves it while it still matches one of the
// binary's compiled anchors. It records the anchor THIS node actually fast-synced
// from (the matched manifest's height/hash), NOT necessarily the current primary,
// so a node that synced from an older still-compiled anchor advertises the correct
// identity on a later run; it is matched against the full compiled anchor set.
static std::string AutoServeAnchorMarkerFor(int nHeight, const uint256& hashBlock)
{
    return strprintf("%d %s", nHeight, hashBlock.ToString());
}

// Parse the (height, block hash) recorded in the sibling ".anchor" marker beside a
// retained serve copy and return the compiled anchor it matches, or NULL when there
// is no marker / it parses badly / it matches no compiled anchor. Lets a node that
// fast-synced from a now-non-primary compiled anchor still advertise the CORRECT
// anchor identity rather than the binary's primary.
static const CFastSyncAnchorData* ResolveServedAnchorFromMarker(const boost::filesystem::path& source)
{
    const boost::filesystem::path markerPath =
        source.parent_path() / (source.filename().string() + ".anchor");
    FILE* mf = fopen(markerPath.string().c_str(), "r");
    if (!mf) return NULL;
    char buf[256] = {0};
    char* got = fgets(buf, sizeof(buf), mf);
    fclose(mf);
    if (!got) return NULL;
    int height = -1;
    char hashHex[160] = {0};
    if (sscanf(buf, "%d %159s", &height, hashHex) != 2) return NULL;
    return Params().FindFastSyncAnchor(height, uint256S(hashHex));
}

// Auto-serve (-bootstrapserve=auto): retain an immutable copy of the just-
// downloaded snapshot so this node can in turn serve it to other peers. Copied
// from the verified staging files (consistent, and not yet opened by LevelDB)
// before they are moved into the live datadir. Best-effort: a failure here must
// not block the node's own bootstrap.
static bool RetainAutoServeSourceFromStaging(const boost::filesystem::path& staging, const boost::filesystem::path& data_dir, int syncedHeight, const uint256& syncedHashBlock, std::string& error)
{
    const boost::filesystem::path serveSrc = AutoServeSourceDir(data_dir);
    LogPrintf("Auto-serve: retaining a serve copy of the bootstrap snapshot (one-time; uses extra disk)...\n");
    boost::filesystem::remove_all(serveSrc);
    boost::filesystem::create_directories(serveSrc);
    if (!CopyBootstrapDirectory(staging / "blocks", serveSrc / "blocks", error) ||
        !CopyBootstrapDirectory(staging / "chainstate", serveSrc / "chainstate", error)) {
        boost::filesystem::remove_all(serveSrc);
        return false;
    }
    if (!BootstrapSnapshotPathsExist(serveSrc)) {
        boost::filesystem::remove_all(serveSrc);
        error = "retained auto-serve copy is incomplete";
        return false;
    }
    const std::string marker = AutoServeAnchorMarkerFor(syncedHeight, syncedHashBlock);
    FILE* mf = fopen(AutoServeMarkerPath(data_dir).string().c_str(), "w");
    if (!mf) {
        boost::filesystem::remove_all(serveSrc);
        error = "could not write auto-serve anchor marker";
        return false;
    }
    fprintf(mf, "%s\n", marker.c_str());
    fclose(mf);
    LogPrintf("Auto-serve: retained snapshot at anchor %s for serving\n", marker);
    return true;
}

// --- Option B: self-snapshot at the node's own recent tip -----------------
//
// A serve dir produced by freezing this node's own chainstate (rather than a
// fast-synced copy at the compiled anchor) is described by a sibling ".meta"
// file recording the real frozen height/block hash and the UTXO-set commitment
// (hash_serialized) over its chainstate. When present, the snapshot is served as
// a version-2 manifest carrying that commitment, so a client running in
// trustless mode can integrity-check the download and then background-validate
// it — no compiled anchor needed. Absent ".meta" => fall back to the v1
// compiled-anchor serve. The meta is a sibling (never inside the serve dir) so
// the manifest file scan never picks it up.
// Defined later in this file; used by the freeze disk-preflight below.
static bool CollectBootstrapSnapshotFiles(const boost::filesystem::path& root,
                                          bool hash_files,
                                          std::vector<CBootstrapSnapshotFile>& files,
                                          std::map<std::string, std::time_t>& mtimes,
                                          uint64_t& total_bytes,
                                          std::string& error);

struct BootstrapServeMeta
{
    int nHeight;
    uint256 hashBlock;
    uint256 hashChainstateSerialized;
    BootstrapServeMeta() : nHeight(-1) {}
};

static boost::filesystem::path BootstrapServeMetaPath(const boost::filesystem::path& sourcedir)
{
    return sourcedir.parent_path() / (sourcedir.filename().string() + ".meta");
}

// Parse a bootstrap-serve meta record from an already-resolved sidecar/marker
// file: "<height> <blockhash> <chainstate-commitment>". Shared verbatim by the
// v2 self-snapshot ".meta" reader and the trustless pending-marker reader, which
// differ only in which path they open. Returns false on missing file, malformed
// content, or an out-of-range/null field.
static bool ParseBootstrapServeMetaFile(const boost::filesystem::path& metaPath, BootstrapServeMeta& meta)
{
    FILE* f = fopen(metaPath.string().c_str(), "r");
    if (!f) {
        return false;
    }
    char hbuf[128] = {0};
    char cbuf[128] = {0};
    int height = -1;
    const int n = fscanf(f, "%d %127s %127s", &height, hbuf, cbuf);
    fclose(f);
    if (n != 3) {
        return false;
    }
    meta.nHeight = height;
    meta.hashBlock = uint256S(hbuf);
    meta.hashChainstateSerialized = uint256S(cbuf);
    return meta.nHeight >= 0 && !meta.hashBlock.IsNull() && !meta.hashChainstateSerialized.IsNull();
}

static bool ReadBootstrapServeMeta(const boost::filesystem::path& sourcedir, BootstrapServeMeta& meta)
{
    return ParseBootstrapServeMetaFile(BootstrapServeMetaPath(sourcedir), meta);
}

// Freeze this node's live chainstate into the auto-serve directory and record a
// v2 ".meta" describing it. The served height/hash/commitment are derived from
// the COPY (by reopening it), not from the live tip, so the published snapshot
// is internally consistent even though the multi-GiB copy is taken without
// holding cs_main for its whole duration (which would stall the node). Any
// inconsistency in the hot copy is self-detected here (open / GetStats /
// best-block-in-index checks) and the freeze is abandoned, leaving the previous
// serve copy in place. Best-effort: callers must not treat failure as fatal.
bool FreezeLiveChainstateForServe(const boost::filesystem::path& data_dir, int minAdvanceBlocks, std::string& error)
{
    const boost::filesystem::path serveSrc = AutoServeSourceDir(data_dir);
    const boost::filesystem::path tmp = serveSrc.parent_path() / (serveSrc.filename().string() + ".new");
    const boost::filesystem::path blocksSrc = data_dir / "blocks";
    const boost::filesystem::path chainSrc = data_dir / "chainstate";

    if (!BootstrapSnapshotPathsExist(data_dir)) {
        error = "datadir has no blocks/chainstate to freeze";
        return false;
    }

    // Snapshot the current tip height under cs_main; bail while still in IBD.
    int tipHeight = -1;
    {
        LOCK(cs_main);
        if (chainActive.Tip() == NULL) {
            error = "no active chain tip to freeze";
            return false;
        }
        if (IsInitialBlockDownload()) {
            error = "node is still in initial block download; not freezing";
            return false;
        }
        tipHeight = chainActive.Height();
    }

    // Skip a needless re-copy when the existing serve copy is already within
    // minAdvanceBlocks of the tip (a full chain copy is expensive). minAdvance==0
    // forces a freeze (used by tests and the first activation).
    if (minAdvanceBlocks > 0 && BootstrapSnapshotPathsExist(serveSrc)) {
        BootstrapServeMeta existing;
        if (ReadBootstrapServeMeta(serveSrc, existing) &&
            tipHeight - existing.nHeight < minAdvanceBlocks) {
            error = strprintf("serve copy already within %d blocks of tip (height %d)",
                minAdvanceBlocks, existing.nHeight);
            return false;
        }
    }

    // Disk preflight: a freeze copy roughly doubles the on-disk chain size. Sum
    // only the blocks/ and chainstate/ trees (the datadir also holds wallet.dat,
    // .lock, peers.dat, etc. which are not part of the snapshot and would fail the
    // snapshot-path safety scan).
    uint64_t chainBytes = 0;
    try {
        const boost::filesystem::path roots[2] = { blocksSrc, chainSrc };
        for (int r = 0; r < 2; ++r) {
            boost::filesystem::recursive_directory_iterator end;
            for (boost::filesystem::recursive_directory_iterator it(roots[r]); it != end; ++it) {
                if (boost::filesystem::is_regular_file(it->path())) {
                    chainBytes += boost::filesystem::file_size(it->path());
                }
            }
        }
    } catch (const boost::filesystem::filesystem_error& e) {
        error = e.what();
        return false;
    }
    boost::filesystem::space_info si = boost::filesystem::space(data_dir);
    const uint64_t needed = chainBytes + (uint64_t)BOOTSTRAP_SNAPSHOT_DISK_SAFETY_MARGIN_BYTES;
    if ((uint64_t)si.available < needed) {
        error = strprintf("not enough free disk to freeze a serve copy: need ~%llu bytes, have %llu",
            (unsigned long long)needed, (unsigned long long)si.available);
        return false;
    }

    // Flush the in-memory coin cache so the on-disk chainstate matches the tip.
    // Held briefly.
    {
        LOCK(cs_main);
        FlushStateToDisk();
    }

    try {
        boost::filesystem::remove_all(tmp);
    } catch (const boost::filesystem::filesystem_error& e) {
        error = e.what();
        return false;
    }
    // Copy chainstate BEFORE blocks. The live node may connect a block during the
    // (unlocked, multi-GiB) copy; copying chainstate first guarantees the later,
    // newer blocks/ copy is at least as advanced as the frozen chainstate, so the
    // chainstate's best block always has its block + index data present in the
    // copied blocks/ tree. The reverse order could freeze a chainstate tip whose
    // block data was not captured, producing a serve copy that breaks clients.
    if (!CopyBootstrapDirectory(chainSrc, tmp / "chainstate", error) ||
        !CopyBootstrapDirectory(blocksSrc, tmp / "blocks", error)) {
        boost::filesystem::remove_all(tmp);
        return false;
    }
    if (!BootstrapSnapshotPathsExist(tmp)) {
        boost::filesystem::remove_all(tmp);
        error = "frozen serve copy is incomplete";
        return false;
    }

    // Derive height/hash/commitment from the COPY (reopen its chainstate). This
    // validates the hot copy: a torn/inconsistent leveldb either fails to open
    // or yields a best block we can't place in our index.
    BootstrapServeMeta meta;
    {
        CCoinsViewDB copydb(tmp / "chainstate", 1 << 23, false, false);
        const uint256 best = copydb.GetBestBlock();
        if (best.IsNull()) {
            boost::filesystem::remove_all(tmp);
            error = "frozen chainstate has no best block";
            return false;
        }
        {
            LOCK(cs_main);
            BlockMap::iterator it = mapBlockIndex.find(best);
            if (it == mapBlockIndex.end() || it->second == NULL) {
                boost::filesystem::remove_all(tmp);
                error = "frozen best block is not in this node's block index";
                return false;
            }
            meta.nHeight = it->second->nHeight;
        }
        CCoinsStats stats;
        if (!copydb.GetStats(stats)) {
            boost::filesystem::remove_all(tmp);
            error = "could not hash frozen chainstate";
            return false;
        }
        meta.hashBlock = best;
        meta.hashChainstateSerialized = stats.hashSerialized;
    } // copydb destructed here -> releases its leveldb lock before we serve

    // Atomic swap: replace the live serve dir with the validated copy, then write
    // the v2 meta and drop any stale v1 anchor marker.
    try {
        boost::filesystem::remove_all(serveSrc);
        boost::filesystem::rename(tmp, serveSrc);
    } catch (const boost::filesystem::filesystem_error& e) {
        boost::filesystem::remove_all(tmp);
        error = strprintf("could not install frozen serve copy: %s", e.what());
        return false;
    }

    // Write the v2 meta atomically: emit a temp sidecar, then rename it into
    // place. The serve dir was just swapped to a fresh self-snapshot at this
    // node's tip, which is NOT the compiled v1 anchor height; if the meta failed
    // to land, the next manifest build would fall through to the v1 anchor path
    // and advertise the compiled anchor while serving files from a non-anchor
    // height (clients download everything, then fail per-file SHA-256). So on any
    // meta-write failure we tear down the swapped serve dir entirely and drop the
    // marker, leaving the node serving nothing rather than mis-serving.
    const boost::filesystem::path metaPath = BootstrapServeMetaPath(serveSrc);
    const boost::filesystem::path metaTmp = metaPath.parent_path() / (metaPath.filename().string() + ".new");
    bool metaOk = false;
    FILE* mf = fopen(metaTmp.string().c_str(), "w");
    if (mf) {
        if (fprintf(mf, "%d %s %s\n", meta.nHeight, meta.hashBlock.ToString().c_str(),
                meta.hashChainstateSerialized.ToString().c_str()) > 0) {
            metaOk = (fflush(mf) == 0);
        }
        if (fclose(mf) != 0) {
            metaOk = false;
        }
    }
    if (metaOk) {
        try {
            boost::filesystem::rename(metaTmp, metaPath);
        } catch (const boost::filesystem::filesystem_error&) {
            metaOk = false;
        }
    }
    if (!metaOk) {
        // Could not establish a matching identity for the swapped snapshot. Remove
        // it (and any stale temp meta and marker) so the node serves nothing, and
        // invalidate the cached manifest so it is not served from the dropped dir.
        boost::filesystem::remove(metaTmp);
        boost::filesystem::remove_all(serveSrc);
        boost::filesystem::remove(AutoServeMarkerPath(data_dir));
        {
            LOCK(cs_bootstrap_snapshot);
            bootstrapSnapshotCacheSource.clear();
            bootstrapSnapshotCacheFiles.clear();
            bootstrapSnapshotCacheMtimes.clear();
            bootstrapSnapshotCacheBytes = 0;
        }
        error = "could not write serve meta file";
        return false;
    }
    boost::filesystem::remove(AutoServeMarkerPath(data_dir));

    // The serve dir changed; drop the cached manifest so it is rebuilt.
    {
        LOCK(cs_bootstrap_snapshot);
        bootstrapSnapshotCacheSource.clear();
        bootstrapSnapshotCacheFiles.clear();
        bootstrapSnapshotCacheMtimes.clear();
        bootstrapSnapshotCacheBytes = 0;
    }

    LogPrintf("Auto-serve: froze a self-snapshot at height %d (%s), commitment %s\n",
        meta.nHeight, meta.hashBlock.ToString(), meta.hashChainstateSerialized.ToString());
    return true;
}

bool SetupAutoBootstrapServe(const boost::filesystem::path& data_dir, std::string& error)
{
    const boost::filesystem::path serveSrc = AutoServeSourceDir(data_dir);

    // Option B: a self-snapshot serve dir (described by a sibling .meta) needs no
    // compiled anchor — it is served as a v2 manifest carrying its own commitment.
    {
        BootstrapServeMeta meta;
        if (BootstrapSnapshotPathsExist(serveSrc) && ReadBootstrapServeMeta(serveSrc, meta)) {
            mapArgs["-bootstrapsourcedir"] = serveSrc.string();
            mapArgs["-bootstrapserve"] = "1";
            LogPrintf("Auto-serve: serving self-snapshot at height %d (%s)\n",
                meta.nHeight, meta.hashBlock.ToString());
            return true;
        }
    }

    const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();
    if (anchor.nHeight < 0 || anchor.hashBlock.IsNull()) {
        error = "no compiled fast-sync anchor to serve";
        return false;
    }
    if (!BootstrapSnapshotPathsExist(serveSrc)) {
        // No serve dir: drop any orphaned marker so it can't confuse a later run.
        boost::filesystem::remove(AutoServeMarkerPath(data_dir));
        error = "no retained serve copy yet (node has not fast-synced a snapshot)";
        return false;
    }

    std::string got;
    FILE* mf = fopen(AutoServeMarkerPath(data_dir).string().c_str(), "r");
    if (mf) {
        char buf[256] = {0};
        if (fgets(buf, sizeof(buf), mf)) got = buf;
        fclose(mf);
    }
    while (!got.empty() && (got[got.size() - 1] == '\n' || got[got.size() - 1] == '\r' || got[got.size() - 1] == ' ')) {
        got.resize(got.size() - 1);
    }
    // Accept the retained copy if its recorded anchor matches ANY compiled anchor
    // (not just the primary), so a node that fast-synced at a still-supported older
    // anchor keeps serving it across an anchor bump. Only a copy matching no
    // compiled anchor is stale and removed (serving it would make clients download
    // then reject); this node can only produce a fresh one by fast-syncing again.
    if (ResolveServedAnchorFromMarker(serveSrc) == NULL) {
        LogPrintf("Auto-serve: retained serve copy is for an anchor no longer compiled in (\"%s\"); removing it\n", got);
        boost::filesystem::remove_all(serveSrc);
        boost::filesystem::remove(AutoServeMarkerPath(data_dir));
        error = "retained serve copy did not match any compiled anchor";
        return false;
    }

    // Point the existing serve machinery at the retained copy. NOTE: these
    // mapArgs writes are unsynchronized (mapArgs is a plain std::map). This is
    // safe only because the caller runs during init, before StartNode() creates
    // the message-handler threads that read these keys when serving — do not
    // call this after the net layer is up.
    mapArgs["-bootstrapsourcedir"] = serveSrc.string();
    mapArgs["-bootstrapserve"] = "1";
    return true;
}

// --- Option B client side: provisional accept of a trustless self-snapshot ----
//
// When a v2 self-snapshot is downloaded in -bootstrapmode=trustless, the manifest
// values (real height, block hash, UTXO commitment) are recorded in a pending
// marker so the post-database-open init step can run the provisional gate even
// across a restart between install and verification. The marker is a sibling file
// in the datadir; cleared once the background validator's durable state takes over.
static boost::filesystem::path BootstrapTrustlessPendingPath(const boost::filesystem::path& data_dir)
{
    return data_dir / "bootstrap-trustless-pending";
}

void WriteBootstrapTrustlessPending(const boost::filesystem::path& data_dir, int height, const uint256& hashBlock, const uint256& commitment)
{
    FILE* f = fopen(BootstrapTrustlessPendingPath(data_dir).string().c_str(), "w");
    if (!f) {
        LogPrintf("Trustless bootstrap: could not write pending marker\n");
        return;
    }
    fprintf(f, "%d %s %s\n", height, hashBlock.ToString().c_str(), commitment.ToString().c_str());
    fclose(f);
}

bool BootstrapTrustlessPendingExists(const boost::filesystem::path& data_dir)
{
    return boost::filesystem::exists(BootstrapTrustlessPendingPath(data_dir));
}

void BootstrapTrustlessPendingClear(const boost::filesystem::path& data_dir)
{
    boost::filesystem::remove(BootstrapTrustlessPendingPath(data_dir));
}

static bool ReadBootstrapTrustlessPending(const boost::filesystem::path& data_dir, BootstrapServeMeta& meta)
{
    return ParseBootstrapServeMetaFile(BootstrapTrustlessPendingPath(data_dir), meta);
}

// Cheap provisional gate run after a trustless snapshot is imported and the chain
// databases are open. It does NOT establish full trust — that is the background
// validator's job (it re-derives the UTXO set from genesis and reindexes on
// mismatch). The gate just rejects an obviously-bogus snapshot before the node
// spends time operating on it:
//   1. Integrity: the imported chainstate's hash_serialized equals the manifest's
//      advertised commitment, and the active tip matches the advertised height/hash.
//   2. Checkpoints: the imported chain agrees with every compiled checkpoint at or
//      below the tip (catches a chain that diverges before a checkpoint).
//   3. Proof of work: the tip header satisfies its target.
// On success, returns the (height, block hash, commitment) to hand to the
// background validator; the commitment doubles as S_imported.
bool ProvisionalAcceptTrustlessSnapshot(const boost::filesystem::path& data_dir,
                                        int& outHeight, uint256& outHashBlock, uint256& outCommitment,
                                        std::string& error)
{
    BootstrapServeMeta pending;
    if (!ReadBootstrapTrustlessPending(data_dir, pending)) {
        error = "no pending trustless snapshot to accept";
        return false;
    }

    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();
    if (tip == NULL) {
        error = "trustless accept: active chain is empty";
        return false;
    }
    if (chainActive.Height() != pending.nHeight || tip->GetBlockHash() != pending.hashBlock) {
        error = strprintf("trustless accept: imported tip %d/%s does not match manifest %d/%s",
            chainActive.Height(), tip->GetBlockHash().ToString(), pending.nHeight, pending.hashBlock.ToString());
        return false;
    }

    // (1) Integrity: chainstate content must equal the advertised commitment.
    CCoinsStats stats;
    if (!pcoinsTip->GetStats(stats)) {
        error = "trustless accept: could not hash imported chainstate";
        return false;
    }
    if (stats.hashSerialized != pending.hashChainstateSerialized) {
        error = strprintf("trustless accept: imported chainstate hash %s != advertised commitment %s",
            stats.hashSerialized.ToString(), pending.hashChainstateSerialized.ToString());
        return false;
    }

    // (2) Checkpoints: agree with every compiled checkpoint at or below the tip.
    const MapCheckpoints& checkpoints = Params().Checkpoints().mapCheckpoints;
    for (MapCheckpoints::const_iterator it = checkpoints.begin(); it != checkpoints.end(); ++it) {
        // Skip the genesis checkpoint: the genesis is already pinned by consensus
        // (the node refuses any other genesis), and some networks carry a stale
        // height-0 placeholder hash in the checkpoint table.
        if (it->first <= 0 || it->first > chainActive.Height()) {
            continue;
        }
        CBlockIndex* atCp = chainActive[it->first];
        if (atCp == NULL || atCp->GetBlockHash() != it->second) {
            error = strprintf("trustless accept: imported chain disagrees with checkpoint at height %d", it->first);
            return false;
        }
    }

    // (3) Proof of work on the tip header.
    if (!CheckProofOfWork(tip->GetBlockHash(), tip->nBits, Params().GetConsensus())) {
        error = "trustless accept: imported tip does not satisfy proof of work";
        return false;
    }

    outHeight = pending.nHeight;
    outHashBlock = pending.hashBlock;
    outCommitment = stats.hashSerialized;
    LogPrintf("Trustless bootstrap: provisional accept of snapshot at height %d (%s); background validation will confirm or reindex\n",
        outHeight, outHashBlock.ToString());
    return true;
}

bool BootstrapFromPeer(const std::string& peer, const boost::filesystem::path& data_dir, std::string& error)
{
    if (!IsBootstrapFreshChainDatadir(data_dir, error)) {
        return false;
    }

    // Option B: in trustless mode we may accept a peer's self-snapshot at its own
    // tip (verified after download + by background validation) rather than only a
    // snapshot matching the compiled anchor.
    const bool fTrustless = (GetArg("-bootstrapmode", "anchor") == "trustless");

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

        if (!ValidateBootstrapSnapshotManifest(manifest, error, fTrustless)) {
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
        socket = INVALID_SOCKET;

        if (!BootstrapSnapshotPathsExist(staging)) {
            boost::filesystem::remove_all(staging);
            error = "downloaded bootstrap snapshot is incomplete";
            return false;
        }
        if (!IsBootstrapFreshChainDatadir(data_dir, error)) {
            boost::filesystem::remove_all(staging);
            return false;
        }

        // Auto-serve: retain an immutable serve copy from the verified staging
        // files BEFORE they are moved into the datadir (so the copy is
        // consistent and not yet held open by LevelDB). Best-effort — a failure
        // must not block this node's own bootstrap.
        if (GetArg("-bootstrapserve", "") == "auto") {
            // Retaining a serve copy roughly doubles the on-disk chain size. Skip
            // it (rather than fill the disk) when there isn't room; the node still
            // bootstraps, it just won't serve.
            boost::filesystem::space_info si = boost::filesystem::space(data_dir);
            const uint64_t needed = manifest.nSnapshotBytes + (uint64_t)BOOTSTRAP_SNAPSHOT_DISK_SAFETY_MARGIN_BYTES;
            if ((uint64_t)si.available < needed) {
                LogPrintf("Auto-serve: not retaining a serve copy — need ~%llu bytes free, have %llu; this node will not serve\n",
                    (unsigned long long)needed, (unsigned long long)si.available);
            } else {
                std::string retain_error;
                // Record the identity of the anchor we actually fast-synced from
                // (the validated manifest's tip), so a later run advertises THIS
                // anchor — not necessarily the binary's primary — when it matches
                // a still-compiled anchor.
                if (!RetainAutoServeSourceFromStaging(staging, data_dir, manifest.nHeight, manifest.hashBlock, retain_error)) {
                    LogPrintf("Auto-serve: could not retain serve copy (continuing without serving): %s\n", retain_error);
                }
            }
        }

        if (!InstallStagedBootstrapChainData(staging, data_dir, error)) {
            return false;
        }

        // Option B: a v2 self-snapshot accepted in TRUSTLESS mode is accepted only
        // provisionally. Record the advertised height/hash/commitment so the
        // post-database-open init step can run the provisional gate and start
        // background validation (survives a restart between install and
        // verification). In anchor mode a v2 manifest only validates if it equals
        // the compiled anchor, so it goes through the normal anchor-verify path
        // (VerifyImportedBootstrapAnchor) instead — don't write the marker.
        if (fTrustless && manifest.nVersion >= 2) {
            WriteBootstrapTrustlessPending(data_dir, manifest.nHeight, manifest.hashBlock,
                manifest.hashChainstateSerialized);
        }
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

// Rebuild the in-memory snapshot manifest cache when it is cold or points at a
// different source. The caller MUST already hold cs_bootstrap_snapshot for the
// whole call: this reads and mutates the bootstrapSnapshotCache* statics and
// takes no lock of its own. Rebuilding SHA-256-hashes the entire multi-GiB
// snapshot and must never run on the net message-handler thread, which passes
// fAllowBuild=false and is told "not ready" until an off-thread warmer (init's
// PreflightBootstrapSnapshotService or the scheduled freeze task) has populated
// the cache. Returns false (error set) on a cold cache with fAllowBuild=false,
// or on a CollectBootstrapSnapshotFiles failure.
static bool EnsureBootstrapSnapshotCache(const boost::filesystem::path& source, bool fAllowBuild, std::string& error)
{
    if (bootstrapSnapshotCacheSource != source || bootstrapSnapshotCacheFiles.empty()) {
        if (!fAllowBuild) {
            error = "bootstrap snapshot manifest not ready";
            return false;
        }
        if (!CollectBootstrapSnapshotFiles(source, true, bootstrapSnapshotCacheFiles, bootstrapSnapshotCacheMtimes, bootstrapSnapshotCacheBytes, error)) {
            return false;
        }
        bootstrapSnapshotCacheSource = source;
    }
    return true;
}

static bool GetBootstrapSnapshotFileList(const boost::filesystem::path& source, std::vector<CBootstrapSnapshotFile>& files, uint64_t& total_bytes, std::string& error, bool fAllowBuild)
{
    LOCK(cs_bootstrap_snapshot);

    if (!EnsureBootstrapSnapshotCache(source, fAllowBuild, error)) {
        return false;
    }

    files = bootstrapSnapshotCacheFiles;
    total_bytes = bootstrapSnapshotCacheBytes;
    return true;
}

bool BootstrapServeSnapshotMatchesCompiledAnchor(std::string& warning)
{
    // Only meaningful for an enabled serve from a prepared source directory.
    if (!GetBoolArg("-bootstrapserve", false) || !mapArgs.count("-bootstrapsourcedir")) {
        return true;
    }
    const boost::filesystem::path source = boost::filesystem::system_complete(mapArgs["-bootstrapsourcedir"]);
    if (!BootstrapSnapshotPathsExist(source)) {
        return true; // nothing retained to serve yet — not a drift condition
    }
    // A v2 self-snapshot (sibling .meta) is intentionally NOT a compiled anchor; it
    // is served only to trustless-mode clients that validate it themselves, so it
    // is not drift. Leave that path alone.
    {
        BootstrapServeMeta meta;
        if (ReadBootstrapServeMeta(source, meta)) {
            return true;
        }
    }
    // Read the served chainstate's tip and check it matches a compiled anchor by
    // block hash. A mismatch is operator drift: the snapshot was (re)generated at a
    // height this binary does not anchor, so anchor-mode clients would download it
    // and only then reject it on the per-file hash check.
    uint256 best;
    try {
        CCoinsViewDB servedb(source / "chainstate", 1 << 23, false, false);
        best = servedb.GetBestBlock();
    } catch (const std::exception& e) {
        warning = strprintf("could not read the served snapshot's chainstate to check it against the compiled "
                            "fast-sync anchors: %s", e.what());
        return false;
    }
    if (best.IsNull()) {
        warning = "the snapshot in -bootstrapsourcedir has no chainstate best block; clients will reject it";
        return false;
    }
    const std::vector<CFastSyncAnchorData>& anchors = Params().FastSyncAnchors();
    for (size_t i = 0; i < anchors.size(); ++i) {
        if (anchors[i].hashBlock == best) {
            return true;
        }
    }
    warning = strprintf(
        "the snapshot in -bootstrapsourcedir has chainstate tip %s, which matches no compiled fast-sync anchor; "
        "anchor-mode clients will download it and then reject it. Regenerate the snapshot at a compiled anchor "
        "height, or run a binary whose anchor matches this snapshot.",
        best.ToString());
    return false;
}

bool GetBootstrapSnapshotManifest(CBootstrapSnapshotManifest& manifest, std::string& error, bool fAllowBuild)
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

    // Option B: a self-snapshot serve dir is described by a sibling .meta. Serve
    // it as a version-2 manifest carrying its real height/block hash and the
    // UTXO-set commitment — no compiled anchor involved.
    BootstrapServeMeta meta;
    if (ReadBootstrapServeMeta(source, meta)) {
        manifest.SetNull();
        manifest.nVersion = 2;
        manifest.strNetwork = Params().NetworkIDString();
        manifest.nHeight = meta.nHeight;
        manifest.hashBlock = meta.hashBlock;
        // hashAnchorSha256/Sha3 are decorative anchor-string hashes with no trust
        // weight; a self-snapshot has no compiled anchor, so leave them null.
        manifest.hashChainstateSerialized = meta.hashChainstateSerialized;
        if (!GetBootstrapSnapshotFileList(source, manifest.vFiles, manifest.nSnapshotBytes, error, fAllowBuild)) {
            return false;
        }
        manifest.nChunkSize = BOOTSTRAP_SNAPSHOT_CHUNK_SIZE;
        return true;
    }

    // Advertise the anchor this serve copy actually corresponds to. For an
    // auto-serve copy that came from a (possibly now-non-primary) compiled anchor,
    // the sibling marker tells us which one; otherwise fall back to the primary
    // (manual -bootstrapsourcedir serve). Advertising the true anchor means an
    // anchor-mode client accepts or rejects from the small manifest, before
    // downloading anything.
    const CFastSyncAnchorData* marked = ResolveServedAnchorFromMarker(source);
    const CFastSyncAnchorData& anchor = marked ? *marked : Params().FastSyncAnchor();
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
    if (!GetBootstrapSnapshotFileList(source, manifest.vFiles, manifest.nSnapshotBytes, error, fAllowBuild)) {
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

// Single source of truth for the compiled Zcash parameter SHA-256s.
// Listed in compiled order, which is also the served manifest order. Also
// re-used by InitSanityCheck via GetZcashParamSpecs() so the startup hash
// check and the bootstrap-protocol hash check can never disagree.
static const ZcashParamSpec ZCASH_PARAM_FILES_RAW[] = {
    {"sapling-output.params", "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4", 3592860ULL},
    {"sapling-spend.params",  "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13", 47958396ULL},
    {"sprout-groth16.params", "b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50", 725523612ULL},
    {"sprout-proving.key",    "8bc20a7f013b2b58970cddd2e7ea028975c88ae7ceb9259a5344a16bc2c0eef7", 910173851ULL},
    {"sprout-verifying.key",  "4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82", 1449ULL},
};
static const size_t ZCASH_PARAM_FILE_COUNT = sizeof(ZCASH_PARAM_FILES_RAW) / sizeof(ZCASH_PARAM_FILES_RAW[0]);

const std::vector<ZcashParamSpec>& GetZcashParamSpecs()
{
    static const std::vector<ZcashParamSpec> specs(
        ZCASH_PARAM_FILES_RAW,
        ZCASH_PARAM_FILES_RAW + ZCASH_PARAM_FILE_COUNT);
    return specs;
}

// Internal indexed access: avoids paying for the vector copy on every chunk.
static const ZcashParamSpec& ZcashParamAt(size_t i)
{
    return ZCASH_PARAM_FILES_RAW[i];
}

static const ZcashParamSpec* FindZcashParam(const std::string& name)
{
    for (size_t i = 0; i < ZCASH_PARAM_FILE_COUNT; ++i) {
        if (name == ZCASH_PARAM_FILES_RAW[i].name) {
            return &ZCASH_PARAM_FILES_RAW[i];
        }
    }
    return NULL;
}

static uint256 ZcashParamExpectedHash(const ZcashParamSpec& param)
{
    return uint256S(std::string("0x") + param.sha256hex);
}

bool ZcashParamsPresentAndValid()
{
    const boost::filesystem::path dir = ZC_GetParamsDir();
    for (size_t i = 0; i < ZCASH_PARAM_FILE_COUNT; ++i) {
        const boost::filesystem::path path = dir / ZcashParamAt(i).name;
        if (!boost::filesystem::is_regular_file(path)) {
            return false;
        }
        uint256 have;
        std::string hashError;
        if (!HashBootstrapSnapshotFile(path, have, hashError)) {
            // Unreadable / I/O error -> treat as not valid so the auto-fetch
            // path (or a clear error from InitSanityCheck) gets a chance to run.
            return false;
        }
        if (have != ZcashParamExpectedHash(ZcashParamAt(i))) {
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
        const boost::filesystem::path path = dir / ZcashParamAt(i).name;
        if (!boost::filesystem::is_regular_file(path) || !IsSafeBootstrapEntry(path)) {
            continue; // only advertise parameter files we actually hold
        }
        CBootstrapSnapshotFile file;
        file.strPath = ZcashParamAt(i).name;
        file.nSize = boost::filesystem::file_size(path);
        if (file.nSize != ZcashParamAt(i).nSize) {
            continue;
        }
        file.hashSha256 = ZcashParamExpectedHash(ZcashParamAt(i));
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
    // Param chunks are validated by hash (against the compiled ZcashParamExpectedHash
    // set), not by mtime: GetZcashParamManifest rebuilds and re-stats on every call,
    // so there is no cached reference mtime to compare against (unlike the cached
    // snapshot path in OpenBootstrapSnapshotFile). StatOpenBootstrapSnapshotFile still
    // requires an mtime out-param, so we capture it into an unused local. The file_size
    // it returns IS used below as the freshness/size guard.
    std::time_t file_mtime_unused = 0;
    if (!StatOpenBootstrapSnapshotFile(fp, file_size, file_mtime_unused) || file_size != file.nSize) {
        fclose(fp);
        error = strprintf("zcash param file changed: %s", file.strPath);
        return false;
    }
    if (!ValidateBootstrapChunkRange(request.nOffset, request.nLength, file.nSize,
                                     BOOTSTRAP_SNAPSHOT_CHUNK_SIZE, "zcash param", error)) {
        fclose(fp);
        return false;
    }
    if (!BootstrapFseek64(fp, (int64_t)request.nOffset)) {
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

static bool DownloadZcashParamFile(SOCKET socket, uint32_t file_index, uint64_t size, uint32_t chunk_size, const boost::filesystem::path& part_path, const std::string& display_name, int timeout_ms, std::string& error)
{
    boost::filesystem::create_directories(part_path.parent_path());
    FILE* fp = fopen(part_path.string().c_str(), "wb");
    if (!fp) {
        error = strprintf("could not create zcash param staging file: %s", part_path.string());
        return false;
    }

    std::deque<CBootstrapSnapshotChunkRequest> inflight;
    uint64_t next_offset = 0;
    uint64_t received = 0;
    int last_percent = -1;
    int64_t last_emit_ms = 0;
    int last_emit_decile = -1;
    const int64_t started = GetTimeMillis();
    int64_t throughputWindowStartMs = started;
    uint64_t throughputBytesAtWindowStart = 0;
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
        if (ShutdownRequested()) {
            error = "bootstrap param download aborted: shutdown requested";
            ok = false;
            break;
        }
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
        received += chunk.vData.size();
        if (BootstrapDownloadTooSlow(throughputWindowStartMs, throughputBytesAtWindowStart,
                                     received, GetTimeMillis())) {
            error = "zcash param download too slow (peer stalled or throttling); aborting";
            ok = false;
            break;
        }
        const int percent = size > 0 ? (int)((received * 100) / size) : 100;
        if (percent != last_percent) {
            last_percent = percent;
            const int64_t elapsed_ms = std::max<int64_t>(1, GetTimeMillis() - started);
            EmitBootstrapProgress(
                strprintf("Fetching params %-22s %3d%%  %.1f MB/s",
                    display_name.c_str(),
                    percent,
                    (received / 1048576.0) / (elapsed_ms / 1000.0)),
                percent, percent >= 100, last_emit_ms, last_emit_decile);
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
            const ZcashParamSpec& param = ZcashParamAt(i);
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
            if (size != param.nSize) {
                error = strprintf("zcash param peer advertised invalid size for %s: got %llu expected %llu",
                    param.name,
                    (unsigned long long)size,
                    (unsigned long long)param.nSize);
                ok = false;
                break;
            }

            LogPrintf("Zcash params: downloading %s (%llu bytes) from peer %s\n", param.name, (unsigned long long)size, peer);
            const boost::filesystem::path part = boost::filesystem::path(dest.string() + ".part");
            boost::filesystem::remove(part);
            if (!DownloadZcashParamFile(socket, index, size, manifest.nChunkSize, part, param.name, BOOTSTRAP_NET_TIMEOUT_MS, error)) {
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
    // We are validating our OWN manifest (self-snapshots are v2); allow them.
    if (!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true)) {
        return false;
    }
    if (manifest.vFiles.empty()) {
        error = "bootstrap snapshot manifest has no files";
        return false;
    }
    return true;
}

static bool ValidateBootstrapChunkRange(uint64_t offset, uint64_t length, uint64_t fileSize,
                                        uint64_t chunkSize, const char* label, std::string& error)
{
    // Range must lie within the file with no offset+length overflow.
    if (offset > fileSize || length > fileSize - offset) {
        error = strprintf("%s chunk range exceeds file size", label);
        return false;
    }
    // Offsets must be aligned to the served chunk size. Callers validate against
    // the compile-time BOOTSTRAP_SNAPSHOT_CHUNK_SIZE because the server always
    // advertises nChunkSize == BOOTSTRAP_SNAPSHOT_CHUNK_SIZE
    // (BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE == BOOTSTRAP_SNAPSHOT_CHUNK_SIZE in
    // bootstrap.h). If the chunk size ever becomes configurable, callers must
    // pass the manifest's nChunkSize here instead.
    if (offset % chunkSize != 0) {
        error = strprintf("%s chunk offset is not aligned", label);
        return false;
    }
    const uint32_t expected_length = std::min<uint64_t>(chunkSize, fileSize - offset);
    if (length != expected_length) {
        error = strprintf("%s chunk length must be %u", label, expected_length);
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

bool ReadBootstrapSnapshotChunk(const CBootstrapSnapshotChunkRequest& request, CBootstrapSnapshotChunk& chunk, std::string& error, bool fAllowBuild)
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
        if (!EnsureBootstrapSnapshotCache(source, fAllowBuild, error)) {
            return false;
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
    if (!ValidateBootstrapChunkRange(request.nOffset, request.nLength, file.nSize,
                                     BOOTSTRAP_SNAPSHOT_CHUNK_SIZE, "bootstrap", error)) {
        fclose(fp);
        return false;
    }
    if (!BootstrapFseek64(fp, (int64_t)request.nOffset)) {
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

bool ValidateBootstrapSnapshotManifest(const CBootstrapSnapshotManifest& manifest, std::string& error, bool fTrustlessAllowed)
{
    if (manifest.nVersion != 1 && manifest.nVersion != 2) {
        error = "Bootstrap manifest has unsupported version";
        return false;
    }
    if (manifest.strNetwork != Params().NetworkIDString()) {
        error = "Bootstrap manifest is for a different network";
        return false;
    }

    if (manifest.nVersion == 1) {
        // v1: must equal one of the compiled fast-sync anchors (trustless-by-
        // compiled-constant). Accepting ANY compiled anchor (not just the primary)
        // lets old and new clients/servers interoperate across an anchor bump
        // without a hard version lockstep; every compiled anchor is still a
        // developer-reviewed commitment, so there is no forgery window.
        const CFastSyncAnchorData* anchor = Params().FindFastSyncAnchor(manifest.nHeight, manifest.hashBlock);
        if (anchor == NULL ||
            manifest.hashAnchorSha256 != anchor->hashAnchorSha256 ||
            manifest.hashAnchorSha3 != anchor->hashAnchorSha3) {
            error = "Bootstrap manifest does not match any compiled fast-sync anchor";
            return false;
        }
    } else if (!fTrustlessAllowed) {
        // v2 (self-snapshot) received in anchor mode: only acceptable if it is in
        // fact one of the compiled anchors (height/hash) and commits to THAT
        // anchor's compiled UTXO commitment — otherwise we have no compiled value
        // to verify it against, so reject before downloading.
        const CFastSyncAnchorData* anchor = Params().FindFastSyncAnchor(manifest.nHeight, manifest.hashBlock);
        if (anchor == NULL ||
            anchor->hashChainstateSerialized.IsNull() ||
            manifest.hashChainstateSerialized != anchor->hashChainstateSerialized) {
            error = "Bootstrap manifest is a self-snapshot but -bootstrapmode is not 'trustless'";
            return false;
        }
    } else {
        // v2 in trustless mode: accept a peer's self-snapshot at its own recent
        // tip. Its height/block hash and UTXO commitment are NOT trusted here;
        // they are verified after download by the provisional header/PoW/
        // checkpoint gate, the integrity check, and background full validation.
        if (manifest.hashChainstateSerialized.IsNull()) {
            error = "Bootstrap v2 manifest is missing its chainstate commitment";
            return false;
        }
        if (manifest.nHeight < 0 || manifest.hashBlock.IsNull()) {
            error = "Bootstrap v2 manifest has no tip height/hash";
            return false;
        }
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
        // Per-file cap: bound any single advertised file so a malicious peer
        // cannot point us at a single huge "file" before we ever hash it.
        if (it->nSize > (uint64_t)BOOTSTRAP_SNAPSHOT_MAX_FILE_BYTES) {
            error = strprintf("Bootstrap manifest file exceeds per-file cap: %s (%llu bytes)",
                it->strPath, (unsigned long long)it->nSize);
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

    // Aggregate cap: reject any manifest whose total exceeds the compiled
    // ceiling. Without this the per-file cap could be multiplied across many
    // files to still exhaust disk before any chunk is verified.
    if (total_bytes > (uint64_t)BOOTSTRAP_SNAPSHOT_MAX_TOTAL_BYTES) {
        error = strprintf("Bootstrap manifest exceeds total snapshot cap: %llu bytes",
            (unsigned long long)total_bytes);
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

    if (!pfrom->QueueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_SNAPSHOT, request)) {
        error = "too many pending bootstrap chunk requests";
        return false;
    }
    return true;
}

bool EnqueueBootstrapParamChunkRequest(CNode* pfrom, const CBootstrapSnapshotChunkRequest& request, std::string& error)
{
    // Same validation envelope as snapshot chunks: param files are also read
    // in aligned BOOTSTRAP_SNAPSHOT_CHUNK_SIZE chunks (see ReadZcashParamChunk).
    if (!GetBoolArg("-bootstrapserve", false)) {
        error = "bootstrap snapshot service is not enabled";
        return false;
    }
    if (request.nLength == 0 || request.nLength > BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE) {
        error = strprintf("invalid zcash param chunk length: %u", request.nLength);
        return false;
    }
    if (request.nOffset % BOOTSTRAP_SNAPSHOT_CHUNK_SIZE != 0) {
        error = "zcash param chunk offset is not aligned";
        return false;
    }

    if (!pfrom->QueueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_PARAMS, request)) {
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

// Test-only accessor for the tracked-IP cap. Declared extern (not in
// bootstrap.h) so unit tests can exercise the hard-cap eviction without
// hardcoding the constant or exposing it on the public header.
const size_t BootstrapServeMaxTrackedIpsForTest()
{
    return BOOTSTRAP_SERVE_MAX_TRACKED_IPS;
}

void ClearBootstrapServeQuota()
{
    LOCK(cs_bootstrap_serve_quota);
    bootstrapServeQuota.clear();
}

std::string BootstrapServeQuotaKey(const CNetAddr& addr)
{
    // IPv6: collapse to the /64 network prefix so an attacker rotating through a
    // (trivially available) /64 -- or a botnet spread across one -- counts as a
    // single quota bucket instead of getting a fresh bucket per address.
    // GetByte(n) returns ip[15-n] (network byte order), so the /64 network is
    // ip[0..7] == GetByte(15)..GetByte(8). We render it as a tagged hex string
    // that can never alias an IPv4 ToStringIP() (the "v6/64:" prefix and ':'
    // separators are not produced by the IPv4 dotted-quad form).
    if (addr.IsIPv6()) {
        std::string key = "v6/64:";
        for (int n = 15; n >= 8; --n) {
            key += strprintf("%02x", addr.GetByte(n) & 0xff);
        }
        return key;
    }
    // IPv4 (full address) and everything else (Tor, unroutable): full identity.
    // Full-address IPv4 keying is unchanged from the previous behavior, so
    // existing IPv4 clients are accounted exactly as before.
    return addr.ToStringIP();
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

    // Hard-enforce the bound: if every tracked window is still active (so the
    // expired-entry sweep above freed nothing), evict the entry with the oldest
    // (least-recently-reset) window until the map is back within the cap. This
    // guarantees the map can never grow without bound even under an attacker
    // cycling through >BOOTSTRAP_SERVE_MAX_TRACKED_IPS distinct, all-active IPs.
    // Each call adds at most one entry, so this loop normally erases at most one.
    while (bootstrapServeQuota.size() > BOOTSTRAP_SERVE_MAX_TRACKED_IPS) {
        std::map<std::string, BootstrapServeQuota>::iterator oldest = bootstrapServeQuota.begin();
        for (std::map<std::string, BootstrapServeQuota>::iterator it = bootstrapServeQuota.begin(); it != bootstrapServeQuota.end(); ++it) {
            if (it->second.windowStartMs < oldest->second.windowStartMs) {
                oldest = it;
            }
        }
        bootstrapServeQuota.erase(oldest);
    }
}

// Bytes one peer may be fed in a single SendMessages cycle. Serving a single
// chunk per cycle caps a peer at roughly chunk_size / message-handler-period
// (~1 MiB/s in practice), no matter how fast the link is. Bursting up to this
// budget per cycle lets a fast peer run at link/disk speed. Sized to the
// client pipeline window (BOOTSTRAP_PIPELINE_DEPTH chunks) so one cycle can
// refill the client's whole in-flight window. The send-buffer high-water check
// below bounds per-peer memory so a slow peer can't make this balloon.
static const size_t BOOTSTRAP_SERVE_BURST_BYTES =
    BOOTSTRAP_PIPELINE_DEPTH * (size_t)BOOTSTRAP_SNAPSHOT_CHUNK_SIZE;

bool SendQueuedBootstrapSnapshotChunk(CNode* pto)
{
    // Serve a burst of queued chunks per cycle rather than exactly one. Stops
    // early when the queue drains, the per-IP quota defers/blocks, a request is
    // unreadable, or this peer's send buffer is already deep (backpressure).
    size_t servedBytes = 0;
    while (servedBytes < BOOTSTRAP_SERVE_BURST_BYTES) {
        // Backpressure: if the peer's send queue has already grown past the
        // burst budget, stop and let the socket thread drain it before queueing
        // more. Keeps per-peer buffering bounded on slow links. The socket
        // thread mutates nSendSize under cs_vSend, so take it briefly for a
        // consistent read (this is a heuristic gate; correctness of the actual
        // sends relies only on PushMessage's own internal cs_vSend locking).
        size_t sendQueueSize;
        {
            LOCK(pto->cs_vSend);
            sendQueueSize = pto->nSendSize;
        }
        if (sendQueueSize >= BOOTSTRAP_SERVE_BURST_BYTES) {
            break;
        }

        CNode::BootstrapChunkKind kind = CNode::BOOTSTRAP_CHUNK_SNAPSHOT;
        CBootstrapSnapshotChunkRequest request;
        if (!pto->PopBootstrapChunkRequest(kind, request)) {
            break; // queue drained
        }

        // Select the right command name and serve function based on the request
        // kind. Snapshot and parameter chunks share queue/throttle/quota, but
        // each reads from its own backing file set.
        const char* getCmd = (kind == CNode::BOOTSTRAP_CHUNK_PARAMS) ? NetMsgType::GETBSPCHK : NetMsgType::GETBSCHK;
        const char* respCmd = (kind == CNode::BOOTSTRAP_CHUNK_PARAMS) ? NetMsgType::BSPCHK : NetMsgType::BSCHK;
        const char* chunkLabel = (kind == CNode::BOOTSTRAP_CHUNK_PARAMS) ? "zcash param" : "bootstrap snapshot";

        // Apply the per-IP daily serve quota only once we have a request to
        // serve, so peers with no bootstrap traffic never touch the quota lock.
        // Key on the address GROUP/prefix (IPv6 /64, full IPv4) so an attacker
        // rotating through a /64 cannot bypass the per-IP cap; the log still
        // shows the full address for diagnosis.
        const std::string ip = BootstrapServeQuotaKey(pto->addr);
        bool stop = false;
        if (!BootstrapServeAllowChunk(ip, pto->fWhitelisted, GetTimeMillis(), stop)) {
            if (stop) {
                LogPrint("net", "bootstrap serve quota exceeded for peer=%d (%s); rejecting chunk request\n", pto->id, ip);
                pto->PushMessage("reject", std::string(getCmd), REJECT_INVALID, std::string("bootstrap serve quota exceeded"));
            } else {
                // Throttled: put the request back and try again on a later cycle.
                pto->RequeueBootstrapChunkRequest(kind, request);
            }
            break; // over quota / throttled — end the burst this cycle
        }

        CBootstrapSnapshotChunk chunk;
        std::string error;
        // Runs on the message-handler thread: never let a chunk read rebuild the
        // (cold) snapshot cache inline (fAllowBuild=false) — it would re-hash the
        // whole multi-GiB snapshot and stall every peer. On "not ready" we reject
        // this request; the peer retries once the off-thread warmer has rebuilt.
        const bool ok = (kind == CNode::BOOTSTRAP_CHUNK_PARAMS)
            ? ReadZcashParamChunk(request, chunk, error)
            : ReadBootstrapSnapshotChunk(request, chunk, error, /*fAllowBuild=*/false);
        if (!ok) {
            LogPrint("net", "could not read %s chunk for peer=%d: %s\n", chunkLabel, pto->id, error);
            pto->PushMessage("reject", std::string(getCmd), REJECT_INVALID, std::string("invalid bootstrap chunk request"));
            break; // unreadable request — end the burst this cycle
        }

        LogPrint("net", "sending %s chunk file=%u offset=%llu bytes=%u peer=%d\n",
            chunkLabel,
            chunk.nFileIndex,
            (unsigned long long)chunk.nOffset,
            (unsigned int)chunk.vData.size(),
            pto->id);
        servedBytes += chunk.vData.size();
        pto->PushMessage(respCmd, chunk);
        BootstrapServeChargeBytes(ip, pto->fWhitelisted, GetTimeMillis(), chunk.vData.size());
    }
    return true;
}
