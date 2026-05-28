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

        if (!InstallStagedBootstrapChainData(staging, data_dir, error)) {
            return false;
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
    // Same invariant as the snapshot serve path: alignment/length are validated
    // against the compile-time BOOTSTRAP_SNAPSHOT_CHUNK_SIZE because the server
    // always advertises nChunkSize == BOOTSTRAP_SNAPSHOT_CHUNK_SIZE
    // (BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE == BOOTSTRAP_SNAPSHOT_CHUNK_SIZE in
    // bootstrap.h). Keep these equal if chunk size ever becomes configurable.
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
    // Offsets must be aligned to the served chunk size. We validate against the
    // compile-time constant rather than the manifest's nChunkSize because the
    // server always advertises nChunkSize == BOOTSTRAP_SNAPSHOT_CHUNK_SIZE
    // (see manifest construction; BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE ==
    // BOOTSTRAP_SNAPSHOT_CHUNK_SIZE in bootstrap.h). If the chunk size ever
    // becomes configurable, this check (and expected_length below) must use the
    // manifest's nChunkSize instead.
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
        // more. Keeps per-peer buffering bounded on slow links. (We hold
        // cs_vSend here via SendMessages, so the socket thread can't drain
        // concurrently — nSendSize only grows within one burst, and drains
        // between cycles once we release the lock.)
        if (pto->nSendSize >= BOOTSTRAP_SERVE_BURST_BYTES) {
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
        const std::string ip = pto->addr.ToStringIP();
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
        const bool ok = (kind == CNode::BOOTSTRAP_CHUNK_PARAMS)
            ? ReadZcashParamChunk(request, chunk, error)
            : ReadBootstrapSnapshotChunk(request, chunk, error);
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
