// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bootstrap resume tests, part 3 of 3: the parallel downloader against an in-process fake bootstrap
// server that can cut connections, tamper with data and change its manifest, with one server and with
// several. Nothing here weakens the verification contract: every reused byte is checked against the
// per-file SHA-256 of the manifest the (fake) peer serves.
// Each part is its own Boost suite.

#include "test/bootstrap_resume_testutil.h"

#ifndef WIN32

// ---------------------------------------------------------------------------
// The parallel downloader against an in-process fake bootstrap server
// ---------------------------------------------------------------------------

namespace {

struct ChunkLogEntry {
    uint32_t file;
    uint64_t offset;
    int conn;
};

class FakeBootstrapServer
{
public:
    FakeBootstrapServer(const Snapshot& snap) : snapshot(snap), listenFd(-1), port(0), stopping(false),
        connections(0), live(0), maxLive(0), maxLiveAfterFault(0), faulted(false), chunkDelayMs(0),
        firstChunkDelayMs(0), maxOpenConnections(0), oneChunkPerConnectionThenSilent(false), trickleChunks(false), open(0)
    {
        listenFd = socket(AF_INET, SOCK_STREAM, 0);
        BOOST_REQUIRE(listenFd >= 0);
        int one = 1;
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0;
        BOOST_REQUIRE_EQUAL(bind(listenFd, (sockaddr*)&sa, sizeof(sa)), 0);
        BOOST_REQUIRE_EQUAL(listen(listenFd, 64), 0);
        socklen_t len = sizeof(sa);
        BOOST_REQUIRE_EQUAL(getsockname(listenFd, (sockaddr*)&sa, &len), 0);
        port = ntohs(sa.sin_port);
        acceptor = std::thread([this]() { AcceptLoop(); });
    }

    ~FakeBootstrapServer()
    {
        stopping = true;
        shutdown(listenFd, SHUT_RDWR);
        close(listenFd);
        if (acceptor.joinable())
            acceptor.join();
        {
            std::lock_guard<std::mutex> lock(mtx);
            for (size_t i = 0; i < fds.size(); ++i)
                shutdown(fds[i], SHUT_RDWR);
        }
        for (size_t i = 0; i < handlers.size(); ++i)
            if (handlers[i].joinable())
                handlers[i].join();
    }

    CService Address() const { return CService(CNetAddr("127.0.0.1"), port); }

    // --- behaviour knobs (set before the download starts) ---
    // Called before a chunk is served; true => drop the connection instead.
    std::function<bool(int conn, uint32_t file, uint64_t offset, int seqInConn)> dropBefore;
    // Called on the bytes about to be sent; may tamper with them.
    std::function<void(int conn, uint32_t file, uint64_t offset, std::string& data)> tamper;
    // The manifest served to connection `conn` (default: the snapshot's).
    std::function<CBootstrapSnapshotManifest(int conn)> manifestFor;
    std::atomic<int> chunkDelayMs;
    // The first chunk served on each connection waits this long (a slow server).
    std::atomic<int> firstChunkDelayMs;
    // A connection that would be the (n+1)th simultaneous one is closed right after accept.
    std::atomic<int> maxOpenConnections;
    // After one chunk, a connection stays open and serves nothing more.
    std::atomic<bool> oneChunkPerConnectionThenSilent;
    // Chunks go out one byte at a time, 100 ms apart.
    std::atomic<bool> trickleChunks;

    // --- observations ---
    std::atomic<int> connections, live, maxLive, maxLiveAfterFault, open;
    std::atomic<bool> faulted;
    std::vector<ChunkLogEntry> Log() { std::lock_guard<std::mutex> lock(mtx); return chunkLog; }
    uint64_t FirstOffsetRequested(uint32_t file)
    {
        std::lock_guard<std::mutex> lock(mtx);
        uint64_t best = (uint64_t)-1;
        for (size_t i = 0; i < chunkLog.size(); ++i)
            if (chunkLog[i].file == file)
                best = std::min(best, chunkLog[i].offset);
        return best;
    }
    size_t RequestsFor(uint32_t file)
    {
        std::lock_guard<std::mutex> lock(mtx);
        size_t n = 0;
        for (size_t i = 0; i < chunkLog.size(); ++i)
            n += (chunkLog[i].file == file);
        return n;
    }
    void NoteFault()
    {
        faulted = true;
    }

private:
    bool RecvAll(int fd, char* p, size_t n)
    {
        size_t got = 0;
        while (got < n) {
            const ssize_t r = recv(fd, p + got, n - got, 0);
            if (r <= 0)
                return false;
            got += (size_t)r;
        }
        return true;
    }
    bool SendAll(int fd, const char* p, size_t n)
    {
        size_t sent = 0;
        while (sent < n) {
            const ssize_t r = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
            if (r <= 0)
                return false;
            sent += (size_t)r;
        }
        return true;
    }
    bool RecvFrame(int fd, std::string& command, CDataStream& payload)
    {
        CSerializeData message(CMessageHeader::HEADER_SIZE);
        if (!RecvAll(fd, &message[0], message.size()))
            return false;
        const unsigned char* h = (const unsigned char*)&message[0];
        const uint32_t len = h[16] | (h[17] << 8) | (h[18] << 16) | ((uint32_t)h[19] << 24);
        if (len > MAX_PROTOCOL_MESSAGE_LENGTH)
            return false;
        const size_t off = message.size();
        message.resize(off + len);
        if (len > 0 && !RecvAll(fd, &message[off], len))
            return false;
        std::string error;
        return DecodeBootstrapNetworkMessage(message, command, payload, error);
    }
    bool SendFrame(int fd, const char* command, const CDataStream& payload)
    {
        CSerializeData message;
        std::string error;
        if (!BuildBootstrapNetworkMessage(command, payload, message, error))
            return false;
        return SendAll(fd, message.data(), message.size());
    }

    void AcceptLoop()
    {
        while (!stopping) {
            sockaddr_in sa;
            socklen_t len = sizeof(sa);
            const int fd = accept(listenFd, (sockaddr*)&sa, &len);
            if (fd < 0)
                return;
            const int conn = connections.fetch_add(1);
            if (maxOpenConnections > 0 && open.load() >= maxOpenConnections) {
                close(fd); // full: refused right after accept
                continue;
            }
            open.fetch_add(1);
            std::lock_guard<std::mutex> lock(mtx);
            fds.push_back(fd);
            handlers.push_back(std::thread([this, fd, conn]() { Handle(fd, conn); }));
        }
    }

    void Handle(int fd, int conn)
    {
        struct Closer {
            int fd;
            std::atomic<int>& open;
            ~Closer() { shutdown(fd, SHUT_RDWR); close(fd); open.fetch_sub(1); }
        } closer{fd, open};
        std::string command;
        CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
        if (!RecvFrame(fd, command, payload) || command != "version")
            return;
        {
            CAddress addrYou(CService("127.0.0.1", 0), NODE_BOOTSTRAP);
            CAddress addrMe(CService("0.0.0.0", 0), NODE_BOOTSTRAP);
            const uint64_t services = NODE_NETWORK | NODE_BOOTSTRAP;
            const int64_t now = GetTime();
            const uint64_t nonce = 0x1234567 + conn;
            const std::string subver = "/fake-bootstrap:1/";
            CDataStream vp(SER_NETWORK, INIT_PROTO_VERSION);
            vp << PROTOCOL_VERSION << services << now << addrYou << addrMe << nonce << subver << 0 << true;
            if (!SendFrame(fd, "version", vp))
                return;
        }
        if (!RecvFrame(fd, command, payload) || command != "verack")
            return;
        if (!SendFrame(fd, "verack", CDataStream(SER_NETWORK, PROTOCOL_VERSION)))
            return;

        const int nowLive = live.fetch_add(1) + 1;
        {
            int prev = maxLive.load();
            while (nowLive > prev && !maxLive.compare_exchange_weak(prev, nowLive)) {}
            if (faulted) {
                prev = maxLiveAfterFault.load();
                while (nowLive > prev && !maxLiveAfterFault.compare_exchange_weak(prev, nowLive)) {}
            }
        }
        struct LiveGuard {
            std::atomic<int>& live;
            ~LiveGuard() { live.fetch_sub(1); }
        } guard{live};

        int seq = 0;
        while (!stopping) {
            if (!RecvFrame(fd, command, payload))
                return;
            if (command == NetMsgType::GETBSMAN) {
                CBootstrapSnapshotManifest m = manifestFor ? manifestFor(conn) : snapshot.manifest;
                CDataStream mp(SER_NETWORK, PROTOCOL_VERSION);
                mp << m;
                if (!SendFrame(fd, NetMsgType::BSMAN, mp))
                    return;
            } else if (command == NetMsgType::GETBSCHK) {
                CBootstrapSnapshotChunkRequest req;
                payload >> req;
                if (req.nFileIndex >= snapshot.contents.size())
                    return;
                const std::string& data = snapshot.contents[req.nFileIndex];
                if (req.nOffset > data.size() || req.nLength > data.size() - req.nOffset)
                    return;
                if (dropBefore && dropBefore(conn, req.nFileIndex, req.nOffset, seq)) {
                    NoteFault();
                    return; // closes the connection (RST/EOF from the client's view)
                }
                if (oneChunkPerConnectionThenSilent && seq >= 1) {
                    while (!stopping)
                        std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    return;
                }
                ++seq;
                {
                    std::lock_guard<std::mutex> lock(mtx);
                    ChunkLogEntry e = {req.nFileIndex, req.nOffset, conn};
                    chunkLog.push_back(e);
                }
                if (chunkDelayMs > 0)
                    std::this_thread::sleep_for(std::chrono::milliseconds(chunkDelayMs.load()));
                if (seq == 1 && firstChunkDelayMs > 0)
                    std::this_thread::sleep_for(std::chrono::milliseconds(firstChunkDelayMs.load()));
                std::string bytes = data.substr(req.nOffset, req.nLength);
                if (tamper)
                    tamper(conn, req.nFileIndex, req.nOffset, bytes);
                CBootstrapSnapshotChunk chunk;
                chunk.nFileIndex = req.nFileIndex;
                chunk.nOffset = req.nOffset;
                chunk.vData.assign(bytes.begin(), bytes.end());
                CDataStream cp(SER_NETWORK, PROTOCOL_VERSION);
                cp << chunk;
                if (trickleChunks) {
                    CSerializeData message;
                    std::string error;
                    if (!BuildBootstrapNetworkMessage(NetMsgType::BSCHK, cp, message, error))
                        return;
                    for (size_t i = 0; i < message.size() && !stopping; ++i) {
                        if (!SendAll(fd, message.data() + i, 1))
                            return;
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    continue;
                }
                if (!SendFrame(fd, NetMsgType::BSCHK, cp))
                    return;
            }
        }
    }

    const Snapshot& snapshot;
    int listenFd;
    uint16_t port;
    std::atomic<bool> stopping;
    std::thread acceptor;
    std::mutex mtx;
    std::vector<int> fds;
    std::vector<std::thread> handlers;
    std::vector<ChunkLogEntry> chunkLog;
};

void CheckAllFilesMatch(const Snapshot& s, const fs::path& staging)
{
    for (size_t i = 0; i < s.manifest.vFiles.size(); ++i) {
        const fs::path p = staging / s.manifest.vFiles[i].strPath;
        BOOST_REQUIRE_MESSAGE(fs::is_regular_file(p), "missing " << p.string());
        BOOST_CHECK_MESSAGE(ReadFile(p) == s.contents[i], "content mismatch in " << s.manifest.vFiles[i].strPath);
        BOOST_CHECK(!fs::exists(p.string() + ".part"));
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(bootstrap_resume_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(parallel_download_fetches_everything_over_four_streams)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(24);
    FakeBootstrapServer server(s);
    server.chunkDelayMs = 3;
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, tmp.path / "staging", 5000, 4, error), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_EQUAL(server.connections.load(), 4 + 0);
    BOOST_CHECK_EQUAL(server.maxLive.load(), 4);
}

BOOST_AUTO_TEST_CASE(a_failed_stream_reconnects_and_parallelism_is_restored)
{
    TempDir tmp;
    // Enough work (about 1000 chunks at 12 ms over 4 streams) that the cut stream's
    // reconnect (about 1 s) lands while the others still have plenty left to do.
    const Snapshot s = MakeSnapshot(150);
    FakeBootstrapServer server(s);
    server.chunkDelayMs = 12;
    // The second connection is cut after 3 chunks, mid-file. (The field report: after one
    // such cut the old client carried on with ONE stream for the rest of the download.)
    server.dropBefore = [](int conn, uint32_t, uint64_t, int seq) { return conn == 1 && seq == 3; };
    std::string error;
    const int64_t t0 = GetTimeMillis();
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, tmp.path / "staging", 5000, 4, error), error);
    BOOST_TEST_MESSAGE("download with a cut stream took " << (GetTimeMillis() - t0) << " ms, "
                       << server.connections.load() << " connections, max live after the fault "
                       << server.maxLiveAfterFault.load());
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK(server.faulted.load());
    BOOST_CHECK_GT(server.connections.load(), 4);       // the failed stream came back
    BOOST_CHECK_EQUAL(server.maxLive.load(), 4);
    // after the cut, all four streams were up at the same time again
    BOOST_CHECK_EQUAL(server.maxLiveAfterFault.load(), 4);
}

BOOST_AUTO_TEST_CASE(every_stream_can_fail_repeatedly_and_the_download_still_completes)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(16);
    FakeBootstrapServer server(s);
    server.chunkDelayMs = 2;
    // Every connection dies after 4 chunks, three times over, then the server behaves.
    std::atomic<int> cuts(0);
    server.dropBefore = [&cuts](int, uint32_t, uint64_t, int seq) {
        if (seq == 4 && cuts.load() < 6) {
            cuts.fetch_add(1);
            return true;
        }
        return false;
    };
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, tmp.path / "staging", 5000, 3, error), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_EQUAL(cuts.load(), 6);
    // Work done before each cut was kept (partial files continue from their last whole
    // chunk): the server served each chunk once, give or take a few in flight at a cut.
    size_t needed = 0;
    for (size_t i = 0; i < s.contents.size(); ++i)
        needed += (s.contents[i].size() + TEST_CHUNK - 1) / TEST_CHUNK;
    BOOST_CHECK_GE(server.Log().size(), needed);
    BOOST_CHECK_LE(server.Log().size(), needed + 6 * 16);
}

BOOST_AUTO_TEST_CASE(resume_reuses_verified_files_and_continues_partial_ones)
{
    TempDir tmp;
    const fs::path staging = tmp.path / "staging";
    const Snapshot s = MakeSnapshot(12);
    const CBootstrapSnapshotManifest& m = s.manifest;

    // State an earlier, killed run could leave behind
    WriteFile(staging / m.vFiles[0].strPath, s.contents[0]);                                   // done
    WriteFile(staging / m.vFiles[3].strPath, s.contents[3]);                                   // done
    WriteFile(staging / (m.vFiles[4].strPath + ".part"), s.contents[4].substr(0, 2 * TEST_CHUNK + 50)); // partial
    std::string bad = s.contents[5];
    bad[bad.size() - 1] ^= 0x7f;
    WriteFile(staging / m.vFiles[5].strPath, bad);                                             // corrupted "complete" file
    WriteFile(staging / (m.vFiles[6].strPath + ".part"), s.contents[6].substr(0, TEST_CHUNK - 1)); // too short to keep
    WriteFile(staging / "blocks" / "stale-from-another-snapshot.dat", "garbage");

    FakeBootstrapServer server(s);
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, staging, 5000, 4, error), error);
    CheckAllFilesMatch(s, staging);
    BOOST_CHECK(!fs::exists(staging / "blocks" / "stale-from-another-snapshot.dat"));

    // verified files were never requested again
    BOOST_CHECK_EQUAL(server.RequestsFor(0), 0);
    BOOST_CHECK_EQUAL(server.RequestsFor(3), 0);
    // the partial file continued from its last whole chunk
    BOOST_CHECK_EQUAL(server.FirstOffsetRequested(4), 2 * TEST_CHUNK);
    // the corrupted and the too-short files were fetched from the start
    BOOST_CHECK_EQUAL(server.FirstOffsetRequested(5), 0);
    BOOST_CHECK_EQUAL(server.FirstOffsetRequested(6), 0);
    // and bytes on the wire are what was missing
    uint64_t wire = 0;
    const std::vector<ChunkLogEntry> log = server.Log();
    for (size_t i = 0; i < log.size(); ++i)
        wire += std::min<uint64_t>(TEST_CHUNK, s.contents[log[i].file].size() - log[i].offset);
    const uint64_t have = s.contents[0].size() + s.contents[3].size() + 2 * TEST_CHUNK;
    BOOST_CHECK_EQUAL(wire, m.nSnapshotBytes - have);
}

BOOST_AUTO_TEST_CASE(a_torn_partial_file_is_detected_and_fetched_again_from_the_start)
{
    TempDir tmp;
    const fs::path staging = tmp.path / "staging";
    const Snapshot s = MakeSnapshot(8);
    const CBootstrapSnapshotManifest& m = s.manifest;

    // A .part whose bytes before the resume offset are WRONG (a torn write of a crashed run):
    // the resume point cannot tell, only the whole-file hash can.
    std::string torn = s.contents[4].substr(0, 2 * TEST_CHUNK + 50);
    torn[10] ^= 0x55;
    WriteFile(staging / (m.vFiles[4].strPath + ".part"), torn);

    FakeBootstrapServer server(s);
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, staging, 5000, 2, error), error);
    CheckAllFilesMatch(s, staging); // never accepted: the final file is the genuine content
    // first attempt continued at 2 chunks, found the hash wrong, then asked for the file from byte 0
    BOOST_CHECK_EQUAL(server.FirstOffsetRequested(4), 0);
    const std::vector<ChunkLogEntry> log = server.Log();
    bool continued = false;
    for (size_t i = 0; i < log.size(); ++i)
        continued |= (log[i].file == 4 && log[i].offset == 2 * TEST_CHUNK);
    BOOST_CHECK(continued);
}

BOOST_AUTO_TEST_CASE(a_peer_that_serves_wrong_bytes_is_given_up_on)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(6);
    FakeBootstrapServer server(s);
    // file 4 is always served with a flipped byte: its hash can never match the manifest
    server.tamper = [](int, uint32_t file, uint64_t offset, std::string& data) {
        if (file == 4 && offset == 0 && !data.empty())
            data[0] ^= 1;
    };
    std::string error;
    BOOST_CHECK(!DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, tmp.path / "staging", 5000, 2, error));
    BOOST_CHECK_MESSAGE(error.find("hash mismatch") != std::string::npos, error);
    // the corrupt file is never left in place as if it were good
    BOOST_CHECK(!fs::exists(tmp.path / "staging" / s.manifest.vFiles[4].strPath));
    BOOST_CHECK(!fs::exists(tmp.path / "staging" / (s.manifest.vFiles[4].strPath + ".part")));
}

BOOST_AUTO_TEST_CASE(a_manifest_that_changes_mid_download_ends_the_attempt_but_keeps_the_files)
{
    TempDir tmp;
    const fs::path staging = tmp.path / "staging";
    const Snapshot s = MakeSnapshot(10);
    FakeBootstrapServer server(s);
    server.chunkDelayMs = 1;
    // later connections are served a different manifest (the server rebuilt its snapshot)
    server.manifestFor = [&s](int conn) {
        CBootstrapSnapshotManifest m = s.manifest;
        if (conn >= 1)
        {
            m.hashBlock = uint256S("deadbeef");
            // rebuilt: no file of the new snapshot equals one of the trusted manifest
            for (size_t i = 0; i < m.vFiles.size(); ++i)
                m.vFiles[i].hashSha256 = Sha256Of("rebuilt " + m.vFiles[i].strPath);
        }
        return m;
    };
    std::string error;
    BOOST_CHECK(!DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, staging, 5000, 3, error));
    BOOST_CHECK_MESSAGE(error.find("differs from the master manifest") != std::string::npos, error);
    // nothing deleted on failure: a later attempt resumes from here
    BOOST_CHECK(fs::exists(staging));
}

BOOST_AUTO_TEST_CASE(single_stream_download_uses_the_same_engine)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(9);
    FakeBootstrapServer server(s);
    server.dropBefore = [](int conn, uint32_t, uint64_t, int seq) { return conn == 0 && seq == 5; };
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, tmp.path / "staging", 5000, 1, error), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_EQUAL(server.maxLive.load(), 1);
    BOOST_CHECK_EQUAL(server.connections.load(), 2);
}

BOOST_AUTO_TEST_CASE(a_dead_peer_fails_over_quickly_and_keeps_the_staging_directory)
{
    TempDir tmp;
    const fs::path staging = tmp.path / "staging";
    const Snapshot s = MakeSnapshot(6);
    WriteFile(staging / s.manifest.vFiles[0].strPath, s.contents[0]); // progress from an earlier attempt
    CService dead;
    {
        FakeBootstrapServer server(s);
        dead = server.Address();
    } // the listener is gone: connections to this port are refused
    const int64_t t0 = GetTimeMillis();
    std::string error;
    BOOST_CHECK(!DownloadBootstrapSnapshotParallel(dead, "dead", s.manifest, staging, 5000, 2, error));
    BOOST_CHECK_MESSAGE(error.find("delivered no data") != std::string::npos, error);
    // not the five-minute stall timeout: the next bootstrap peer is tried within seconds
    BOOST_CHECK_LT(GetTimeMillis() - t0, 30000); // real-clock: the property under test is that a dead peer is given up on within seconds, not after the five-minute stall timeout
    BOOST_CHECK(fs::exists(staging / s.manifest.vFiles[0].strPath)); // earlier progress untouched
}

// A full server refuses one of the four streams right after accept while the
// other three are being served slowly: three refusals in a row on the one
// stream must not end the attempt (it used to, because no chunk had completed
// yet), the streams that are being served finish the snapshot.
BOOST_AUTO_TEST_CASE(a_refused_stream_does_not_end_an_attempt_the_others_are_serving)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(24);
    FakeBootstrapServer server(s);
    server.maxOpenConnections = 3;
    server.firstChunkDelayMs = 4500; // longer than the ~3-4 s the refused stream needs to fail three times
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, tmp.path / "staging", 5000, 4, error), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_TEST_MESSAGE("refused-stream test: " << server.connections.load() << " connections, max open " << server.maxLive.load());
    BOOST_CHECK_GE(server.connections.load(), 4); // the fourth stream really was refused and retried
}

// A peer that serves one chunk per connection and then goes silent must not
// keep the attempt (and the failover to another peer) alive for ever: the
// attempt as a whole has to average the minimum throughput.
BOOST_AUTO_TEST_CASE(a_peer_that_serves_one_chunk_per_connection_is_given_up_on)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(8);
    FakeBootstrapServer server(s);
    server.oneChunkPerConnectionThenSilent = true;
    BootstrapSetWatchdogForTests(60 * 1000, 2000);
    const int64_t t0 = GetTimeMillis();
    std::string error;
    const bool ok = DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, tmp.path / "staging", 5000, 2, error);
    BootstrapSetWatchdogForTests(0, 0);
    BOOST_CHECK(!ok);
    BOOST_CHECK_MESSAGE(error.find("too slow") != std::string::npos, error);
    // the workers sit in a 5 s receive: the manager's decision reaches them at once
    BOOST_CHECK_LT(GetTimeMillis() - t0, 4500); // real-clock: the property under test is that the watchdog decision reaches the workers at once; the bound is far below the 5 s receive timeout
}

// A peer that trickles one byte every 100 ms inside a single message keeps
// every worker inside one receive: giving the attempt up must still end it.
BOOST_AUTO_TEST_CASE(a_trickling_peer_cannot_hold_the_attempt_after_the_watchdog_fires)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(4);
    FakeBootstrapServer server(s);
    server.trickleChunks = true;
    BootstrapSetWatchdogForTests(1500, 0);
    const int64_t t0 = GetTimeMillis();
    std::string error;
    const bool ok = DownloadBootstrapSnapshotParallel(server.Address(), "fake", s.manifest, tmp.path / "staging", 5000, 2, error);
    BootstrapSetWatchdogForTests(0, 0);
    BOOST_CHECK(!ok);
    BOOST_CHECK_MESSAGE(error.find("no progress") != std::string::npos, error);
    BOOST_CHECK_LT(GetTimeMillis() - t0, 6000); // real-clock: the property under test is that a trickling peer cannot hold the attempt past the watchdog (1.5 s), bounded well below the stall timeout
}

// A minimal SOCKS5 server that only does what a name proxy does: it takes the
// destination as a host name and connects to it itself.
class FakeNameProxy
{
public:
    FakeNameProxy(uint16_t targetPort) : target(targetPort), listenFd(-1), port(0), stopping(false), requests(0), unnamedRequests(0), foreignHosts(0)
    {
        listenFd = socket(AF_INET, SOCK_STREAM, 0);
        BOOST_REQUIRE(listenFd >= 0);
        int one = 1;
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOST_REQUIRE_EQUAL(bind(listenFd, (sockaddr*)&sa, sizeof(sa)), 0);
        BOOST_REQUIRE_EQUAL(listen(listenFd, 16), 0);
        socklen_t len = sizeof(sa);
        BOOST_REQUIRE_EQUAL(getsockname(listenFd, (sockaddr*)&sa, &len), 0);
        port = ntohs(sa.sin_port);
        acceptor = std::thread([this]() {
            while (!stopping) {
                const int fd = accept(listenFd, NULL, NULL);
                if (fd < 0)
                    return;
                std::lock_guard<std::mutex> lock(mtx);
                fds.push_back(fd);
                handlers.push_back(std::thread([this, fd]() { Serve(fd); }));
            }
        });
    }
    ~FakeNameProxy()
    {
        stopping = true;
        shutdown(listenFd, SHUT_RDWR);
        close(listenFd);
        if (acceptor.joinable())
            acceptor.join();
        {
            std::lock_guard<std::mutex> lock(mtx);
            for (size_t i = 0; i < fds.size(); ++i)
                shutdown(fds[i], SHUT_RDWR);
        }
        for (size_t i = 0; i < handlers.size(); ++i)
            if (handlers[i].joinable())
                handlers[i].join();
    }
    uint16_t Port() const { return port; }
    std::atomic<int> requests;          // CONNECT requests that named a host
    std::atomic<int> unnamedRequests;   // CONNECT requests that carried an address instead of a name
    std::atomic<int> foreignHosts;      // named requests whose host is not expectedHost
    std::string expectedHost;           // set before the first connection
    std::string lastHost;

private:
    static bool RecvAll(int fd, unsigned char* p, size_t n)
    {
        size_t got = 0;
        while (got < n) {
            const ssize_t r = recv(fd, p + got, n - got, 0);
            if (r <= 0)
                return false;
            got += (size_t)r;
        }
        return true;
    }
    void Serve(int fd)
    {
        unsigned char b[300];
        if (!RecvAll(fd, b, 2) || b[0] != 5 || !RecvAll(fd, b + 2, b[1]))
            return;
        const unsigned char choose[2] = {5, 0};
        if (send(fd, choose, 2, MSG_NOSIGNAL) != 2)
            return;
        if (!RecvAll(fd, b, 5))
            return;
        if (b[3] != 3) { // ATYP must be a domain name
            unnamedRequests.fetch_add(1);
            return;
        }
        const size_t hostLen = b[4];
        if (!RecvAll(fd, b + 5, hostLen + 2))
            return;
        {
            std::lock_guard<std::mutex> lock(mtx);
            lastHost.assign((const char*)b + 5, hostLen);
            if (lastHost != expectedHost)
                foreignHosts.fetch_add(1);
        }
        requests.fetch_add(1);
        const int up = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(target);
        if (up < 0 || connect(up, (sockaddr*)&sa, sizeof(sa)) != 0) {
            if (up >= 0)
                close(up);
            return;
        }
        const unsigned char ok[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        if (send(fd, ok, sizeof(ok), MSG_NOSIGNAL) != (ssize_t)sizeof(ok)) {
            close(up);
            return;
        }
        // relay both ways until either side closes
        std::thread back([fd, up]() {
            char buf[8192];
            ssize_t r;
            while ((r = recv(up, buf, sizeof(buf), 0)) > 0)
                if (send(fd, buf, (size_t)r, MSG_NOSIGNAL) != r)
                    break;
            shutdown(fd, SHUT_RDWR);
        });
        char buf[8192];
        ssize_t r;
        while ((r = recv(fd, buf, sizeof(buf), 0)) > 0)
            if (send(up, buf, (size_t)r, MSG_NOSIGNAL) != r)
                break;
        shutdown(up, SHUT_RDWR);
        back.join();
        close(up);
    }

    uint16_t target;
    int listenFd;
    uint16_t port;
    std::atomic<bool> stopping;
    std::thread acceptor;
    std::mutex mtx;
    std::vector<int> fds;
    std::vector<std::thread> handlers;
};

// A peer named by host name behind a name proxy has no address (the first
// connection went through the proxy by name): every stream must reconnect by
// name as well, with one stream as with several.
BOOST_AUTO_TEST_CASE(streams_reconnect_by_name_through_a_name_proxy)
{
    for (int streams = 1; streams <= 3; streams += 2) {
        TempDir tmp;
        const Snapshot s = MakeSnapshot(5);
        FakeBootstrapServer server(s);
        FakeNameProxy proxy(server.Address().GetPort());
        proxy.expectedHost = "snapshot.invalid";
        BOOST_REQUIRE(SetNameProxy(proxyType(CService("127.0.0.1", proxy.Port()))));
        std::string error;
        const bool ok = DownloadBootstrapSnapshotParallel(CService("0.0.0.0", 0),
            strprintf("snapshot.invalid:%u", (unsigned int)server.Address().GetPort()),
            s.manifest, tmp.path / "staging", 5000, streams, error);
        ClearProxies();
        BOOST_REQUIRE_MESSAGE(ok, error);
        CheckAllFilesMatch(s, tmp.path / "staging");
        // The number of connections is not fixed: a stream opens one only while files are still
        // pending, so with a small snapshot the first stream can fetch every file before the other
        // streams look at the queue (nStreams is also capped by the file count). What must hold is that
        // at least one connection was made and that EVERY connection went through the proxy by name.
        BOOST_CHECK_GE(proxy.requests.load(), 1);
        BOOST_CHECK_EQUAL(proxy.unnamedRequests.load(), 0);
        BOOST_CHECK_EQUAL(proxy.foreignHosts.load(), 0);
        BOOST_CHECK_EQUAL(proxy.lastHost, "snapshot.invalid");
    }
}

// ---------------------------------------------------------------------------
// Multi-server download against fake servers
// ---------------------------------------------------------------------------

namespace {
std::string PeerName(const FakeBootstrapServer& s) { return strprintf("127.0.0.1:%u", (unsigned int)s.Address().GetPort()); }
size_t ChunksOf(const Snapshot& s)
{
    size_t n = 0;
    for (size_t i = 0; i < s.manifest.vFiles.size(); ++i)
        n += (s.manifest.vFiles[i].nSize + TEST_CHUNK - 1) / TEST_CHUNK;
    return n;
}
struct PolicyGuard {
    explicit PolicyGuard(const BootstrapPeerPolicy& p) { BootstrapSetPeerPolicyForTests(&p); }
    ~PolicyGuard() { BootstrapSetPeerPolicyForTests(NULL); }
};
} // namespace

BOOST_AUTO_TEST_CASE(two_servers_both_serve_and_no_chunk_is_fetched_twice)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(14);
    FakeBootstrapServer a(s), b(s);
    a.chunkDelayMs = 15;
    b.chunkDelayMs = 15;
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                            std::vector<std::string>(1, PeerName(b))), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_GT(a.Log().size(), 0U);
    BOOST_CHECK_GT(b.Log().size(), 0U);
    BOOST_CHECK_EQUAL(a.Log().size() + b.Log().size(), ChunksOf(s));
}

// A manifest of another snapshot (height, block) that shares no file with the trusted one.
static CBootstrapSnapshotManifest ManifestSharingNothing(const CBootstrapSnapshotManifest& m)
{
    CBootstrapSnapshotManifest o = m;
    o.nHeight += 1;
    for (size_t i = 0; i < o.vFiles.size(); ++i)
        o.vFiles[i].hashSha256 = Sha256Of(std::string("other snapshot file ") + itostr((int)i));
    return o;
}

BOOST_AUTO_TEST_CASE(a_server_with_a_different_snapshot_sharing_no_file_is_ignored)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(8);
    FakeBootstrapServer a(s), b(s);
    b.manifestFor = [&s](int) { return ManifestSharingNothing(s.manifest); };
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                            std::vector<std::string>(1, PeerName(b))), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_EQUAL(b.Log().size(), 0U); // not one chunk asked of it
    BOOST_CHECK_EQUAL(a.Log().size(), ChunksOf(s));
    // the validated server itself changing to another snapshot, with no other left, still ends the attempt
    TempDir tmp2;
    FakeBootstrapServer c(s);
    c.manifestFor = [&s](int conn) { return conn > 0 ? ManifestSharingNothing(s.manifest) : s.manifest; };
    BOOST_CHECK(!DownloadBootstrapSnapshotParallel(c.Address(), PeerName(c), s.manifest, tmp2.path / "staging", 5000, 2, error));
}

BOOST_AUTO_TEST_CASE(a_server_at_another_height_serves_the_files_identical_to_the_trusted_manifest)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(8);
    FakeBootstrapServer a(s), b(s);
    a.chunkDelayMs = 10;
    b.chunkDelayMs = 10;
    b.manifestFor = [&s](int) {
        CBootstrapSnapshotManifest m = s.manifest;
        m.nHeight += 1; // another snapshot (height); every file is the same bytes
        return m;
    };
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                            std::vector<std::string>(1, PeerName(b))), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_GT(a.Log().size(), 0U);
    BOOST_CHECK_GT(b.Log().size(), 0U); // shared files come from both servers
    BOOST_CHECK_EQUAL(a.Log().size() + b.Log().size(), ChunksOf(s));
}

BOOST_AUTO_TEST_CASE(a_server_with_another_manifest_serves_the_files_it_shares)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(12);
    // the second server's snapshot: another file order and one file that differs (same anchor)
    Snapshot s2 = s;
    std::reverse(s2.manifest.vFiles.begin(), s2.manifest.vFiles.end());
    std::reverse(s2.contents.begin(), s2.contents.end());
    const size_t altered = 4; // index in s2; master index = 11 - 4 = 7
    s2.contents[altered] = Bytes(s2.contents[altered].size(), 999);
    s2.manifest.vFiles[altered].hashSha256 = Sha256Of(s2.contents[altered]);
    BOOST_REQUIRE(SerializeHash(s2.manifest) != SerializeHash(s.manifest));
    FakeBootstrapServer a(s), b(s2);
    a.chunkDelayMs = 10;
    b.chunkDelayMs = 10;
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                            std::vector<std::string>(1, PeerName(b))), error);
    CheckAllFilesMatch(s, tmp.path / "staging"); // the trusted manifest's bytes, whoever served them
    BOOST_CHECK_GT(b.Log().size(), 0U);
    BOOST_CHECK_EQUAL(b.RequestsFor((uint32_t)altered), 0U); // never asked for the file it does not share
    BOOST_CHECK_GT(a.RequestsFor((uint32_t)(11 - altered)), 0U);
    BOOST_CHECK_EQUAL(a.Log().size() + b.Log().size(), ChunksOf(s));
}


BOOST_AUTO_TEST_CASE(a_server_that_serves_corrupt_bytes_costs_a_retry_not_the_attempt)
{
    for (int corruptIsPrimary = 0; corruptIsPrimary < 2; ++corruptIsPrimary) {
        TempDir tmp;
        const Snapshot s = MakeSnapshot(10);
        FakeBootstrapServer a(s), b(s);
        FakeBootstrapServer& bad = corruptIsPrimary ? a : b;
        FakeBootstrapServer& good = corruptIsPrimary ? b : a;
        bad.tamper = [](int, uint32_t, uint64_t offset, std::string& data) {
            if (offset == 0 && !data.empty())
                data[0] ^= 1; // every file it serves is wrong
        };
        std::string error;
        BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                                std::vector<std::string>(1, PeerName(b))), error);
        CheckAllFilesMatch(s, tmp.path / "staging");
        BOOST_CHECK_GT(good.Log().size(), 0U);
    }
}

BOOST_AUTO_TEST_CASE(a_server_that_disappears_mid_download_leaves_the_rest_to_the_other)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(14);
    FakeBootstrapServer a(s), b(s);
    a.chunkDelayMs = 5;
    b.chunkDelayMs = 5;
    std::atomic<int> served(0);
    // b answers a few requests, cutting connections in the middle of files, and then never again
    b.dropBefore = [&served](int, uint32_t, uint64_t, int) { return served.fetch_add(1) >= 12; };
    std::string error;
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                            std::vector<std::string>(1, PeerName(b))), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_GT(a.Log().size(), 0U);
    // and the same when the first (validated) server is the one that goes
    TempDir tmp2;
    FakeBootstrapServer c(s), d(s);
    std::atomic<int> served2(0);
    c.dropBefore = [&served2](int, uint32_t, uint64_t, int) { return served2.fetch_add(1) >= 12; };
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(c.Address(), PeerName(c), s.manifest, tmp2.path / "staging", 5000, 4, error,
                                                            std::vector<std::string>(1, PeerName(d))), error);
    CheckAllFilesMatch(s, tmp2.path / "staging");
}

BOOST_AUTO_TEST_CASE(a_stream_the_server_defers_moves_to_the_other_server)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 500;
    pol.stallMs = 1000;
    PolicyGuard guard(pol);
    TempDir tmp;
    const Snapshot s = MakeSnapshot(10);
    FakeBootstrapServer a(s), b(s);
    b.chunkDelayMs = 6000; // over its serving cap: it does not answer in time
    std::string error;
    const int64_t t0 = GetTimeMillis();
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                            std::vector<std::string>(1, PeerName(b))), error);
    BOOST_CHECK_LT(GetTimeMillis() - t0, 45000); // real-clock: the property under test is fail-over speed: it would take minutes if its streams stayed on b (loaded hosts need slack)
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_GE(a.Log().size(), ChunksOf(s) - 40U);
}

BOOST_AUTO_TEST_CASE(partial_files_fetched_from_one_server_continue_from_the_other)
{
    // no stream moves here: a moved stream drops the requests in flight, which the servers count twice
    BootstrapPeerPolicy still;
    still.slowFraction = 0;
    still.stallMs = (int64_t)1 << 40;
    still.stealFactor = 1e9;
    PolicyGuard guard(still);
    TempDir tmp;
    const Snapshot s = MakeSnapshot(8);
    std::string error;
    {
        // first run: the only server cuts every connection after a handful of chunks and the attempt dies
        FakeBootstrapServer a(s);
        std::atomic<int> served(0);
        a.dropBefore = [&served](int, uint32_t, uint64_t, int) { return served.fetch_add(1) >= 20; };
        BootstrapSetWatchdogForTests(1500, 1500);
        const bool ok = DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 2000, 2, error);
        BootstrapSetWatchdogForTests(0, 0);
        BOOST_CHECK(!ok);
    }
    // second run: two other servers finish it; what the first run stored is not fetched again
    // what the first run left behind (verified files and aligned .part prefixes; the last chunk of a
    // .part is always re-requested), counted from the disk so the check does not depend on timing
    size_t stored = 0;
    for (size_t i = 0; i < s.manifest.vFiles.size(); ++i) {
        const boost::filesystem::path f = tmp.path / "staging" / s.manifest.vFiles[i].strPath;
        boost::system::error_code ec;
        if (boost::filesystem::exists(f, ec)) {
            stored += (s.manifest.vFiles[i].nSize + TEST_CHUNK - 1) / TEST_CHUNK;
        } else if (boost::filesystem::exists(f.string() + ".part", ec)) {
            const uint64_t ps = boost::filesystem::file_size(f.string() + ".part", ec);
            stored += ps / TEST_CHUNK > 0 ? ps / TEST_CHUNK - 1 : 0;
        }
    }
    BOOST_CHECK_GT(stored, 0U);
    FakeBootstrapServer b(s), c(s);
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(b.Address(), PeerName(b), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                            std::vector<std::string>(1, PeerName(c))), error);
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_LE(b.Log().size() + c.Log().size(), ChunksOf(s) - stored);
}


BOOST_AUTO_TEST_CASE(a_fast_secondary_holding_few_files_does_not_make_the_download_slower)
{
    BootstrapPeerPolicy pol; // what -bootstrapschedwindowms=1000 sets
    pol.windowMs = 1000;
    pol.stallMs = 2000;
    pol.moveCooldownMs = pol.penaltyMs = 3000;
    pol.stealMinSeconds = 1;
    PolicyGuard guard(pol);
    const Snapshot s = MakeSnapshot(60);
    int64_t alone = 0, both = 0;
    {
        TempDir tmp;
        FakeBootstrapServer a(s);
        a.chunkDelayMs = 40;
        std::string error;
        const int64_t t0 = GetTimeMillis();
        BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error), error);
        alone = GetTimeMillis() - t0;
    }
    {
        TempDir tmp;
        FakeBootstrapServer a(s), b(s);
        a.chunkDelayMs = 40;
        b.chunkDelayMs = 2;
        CBootstrapSnapshotManifest other = s.manifest; // another height: shares only the first 8 files
        for (size_t i = 8; i < other.vFiles.size(); ++i)
            other.vFiles[i].hashSha256 = uint256S(strprintf("0x%x", (unsigned)(1000 + i)));
        b.manifestFor = [&](int) { return other; };
        std::string error;
        const int64_t t0 = GetTimeMillis();
        BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 5000, 4, error,
                                                                std::vector<std::string>(1, PeerName(b))), error);
        both = GetTimeMillis() - t0;
        CheckAllFilesMatch(s, tmp.path / "staging");
        // The primary must get all its streams: with the secondary out of files, no stream may sit on it (that was
        // the failure: the primary never got its 4th stream). Wall times are far too noisy on a loaded host for a
        // tight comparison, so the time check below only catches a stall.
        BOOST_CHECK_GE(a.maxLive.load(), 4);
        BOOST_TEST_MESSAGE("partial secondary: alone " << alone << " ms, with a fast partial secondary " << both << " ms; a connections="
                           << a.connections.load() << " b connections=" << b.connections.load());
    }
    // twice as long and three seconds of noise: a stall, not jitter
    BOOST_CHECK_MESSAGE(both <= alone * 2 + 3000, "a fast partial secondary made it slower: " << both << " ms vs " << alone << " ms alone");
}

// ---- downloads against fake servers: liveness ----

BOOST_AUTO_TEST_CASE(a_secondary_that_lies_mid_file_and_hands_over_does_not_cost_the_attempt)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(10);
    FakeBootstrapServer a(s), b(s);
    a.chunkDelayMs = 4; // honest primary, a little slower
    // the secondary: an honest first chunk, wrong bytes after it, and it never serves a file's last chunk, so
    // the honest primary always finishes the files the secondary touched
    b.tamper = [](int, uint32_t, uint64_t offset, std::string& data) {
        if (offset >= TEST_CHUNK && !data.empty())
            data[0] ^= 1;
    };
    b.dropBefore = [&s](int, uint32_t file, uint64_t offset, int) {
        return offset + TEST_CHUNK >= s.contents[file].size();
    };
    BootstrapSetWatchdogForTests(30000, 30000);
    std::string error;
    const bool ok = DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 3000, 4, error,
                                                      std::vector<std::string>(1, PeerName(b)));
    BootstrapSetWatchdogForTests(0, 0);
    BOOST_CHECK_MESSAGE(ok, "download with an honest, reachable primary failed: " << error);
    if (ok)
        CheckAllFilesMatch(s, tmp.path / "staging");
}

BOOST_AUTO_TEST_CASE(a_resumed_prefix_written_by_a_lying_server_is_fetched_again_from_one_server)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(6);
    std::string error;
    {
        // first run: the only server writes wrong bytes after the first chunk of every file and never serves a
        // last chunk, so the attempt ends and leaves torn .part files behind
        FakeBootstrapServer liar(s);
        liar.tamper = [](int, uint32_t, uint64_t offset, std::string& data) {
            if (offset >= TEST_CHUNK && !data.empty())
                data[0] ^= 1;
        };
        liar.dropBefore = [&s](int, uint32_t file, uint64_t offset, int) { return offset + TEST_CHUNK >= s.contents[file].size(); };
        BootstrapSetWatchdogForTests(2000, 2000);
        const bool ok = DownloadBootstrapSnapshotParallel(liar.Address(), PeerName(liar), s.manifest, tmp.path / "staging", 1500, 2, error);
        BootstrapSetWatchdogForTests(0, 0);
        BOOST_CHECK(!ok);
    }
    // second run: two honest servers. Each resumed .part fails its hash (unknown origin); the file is fetched again
    // from byte 0 from one of them and nobody is benched or the attempt lost.
    error.clear();
    FakeBootstrapServer a(s), b(s);
    const bool ok2 = DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 3000, 4, error,
                                                       std::vector<std::string>(1, PeerName(b)));
    BootstrapSetWatchdogForTests(0, 0);
    BOOST_CHECK_MESSAGE(ok2, error);
    if (ok2)
        CheckAllFilesMatch(s, tmp.path / "staging");
}

BOOST_AUTO_TEST_CASE(a_primary_that_refreshes_its_snapshot_ends_the_attempt_at_once)
{
    // The only server refreshes its snapshot: later connections get a manifest that differs in ONE file (as a
    // growing block bundle tail would). The attempt ends at once ("manifest differs"); the caller retries with
    // the new manifest. It must not idle until a watchdog or reconnect in a storm.
    TempDir tmp;
    const Snapshot s = MakeSnapshot(10);
    FakeBootstrapServer a(s);
    CBootstrapSnapshotManifest changed = s.manifest;
    const uint32_t last = (uint32_t)changed.vFiles.size() - 1;
    changed.vFiles[last].hashSha256 = uint256S("0x77");
    a.manifestFor = [&](int conn) { return conn < 4 ? s.manifest : changed; };
    a.dropBefore = [](int conn, uint32_t, uint64_t, int seq) { return conn < 4 && seq == 2; };
    BootstrapSetWatchdogForTests(6000, 6000);
    std::string error;
    const int64_t t0 = GetTimeMillis();
    const bool ok = DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 3000, 4, error);
    const int64_t ms = GetTimeMillis() - t0;
    BootstrapSetWatchdogForTests(0, 0);
    BOOST_CHECK(!ok);
    BOOST_CHECK_MESSAGE(error.find("differs from the master manifest") != std::string::npos, error);
    BOOST_CHECK_MESSAGE(ms < 3000, "the attempt idled " << ms << " ms over " << a.connections.load() << " connections before ending (" << error << ")"); // real-clock: the property under test is that a changed manifest ends the attempt at once instead of idling to the stall timeout
    BOOST_CHECK_LT(a.connections.load(), 12);
}

BOOST_AUTO_TEST_CASE(after_a_refresh_of_the_primary_the_next_attempt_keeps_the_shared_files)
{
    TempDir tmp;
    const Snapshot s = MakeSnapshot(10);
    // the refreshed snapshot: the last file grew (here: other bytes), the other nine are the same
    Snapshot s2 = s;
    const size_t last = s2.contents.size() - 1;
    s2.contents[last] = Bytes(s2.contents[last].size(), 77);
    s2.manifest.vFiles[last].hashSha256 = Sha256Of(s2.contents[last]);
    std::string error;
    {
        FakeBootstrapServer a(s);
        a.chunkDelayMs = 3;
        a.manifestFor = [&](int conn) { return conn < 2 ? s.manifest : s2.manifest; };
        a.dropBefore = [](int conn, uint32_t, uint64_t, int seq) { return conn < 2 && seq == 7; };
        BootstrapSetWatchdogForTests(20000, 20000);
        const bool ok = DownloadBootstrapSnapshotParallel(a.Address(), PeerName(a), s.manifest, tmp.path / "staging", 3000, 2, error);
        BootstrapSetWatchdogForTests(0, 0);
        BOOST_CHECK(!ok);
        BOOST_CHECK_MESSAGE(error.find("differs from the master manifest") != std::string::npos, error);
    }
    size_t staged = 0;
    for (size_t i = 0; i + 1 < s.manifest.vFiles.size(); ++i)
        if (fs::exists(tmp.path / "staging" / s.manifest.vFiles[i].strPath))
            ++staged;
    // the caller starts again with the new manifest: the staged files that are still the same are reused
    error.clear();
    FakeBootstrapServer b(s2);
    BOOST_REQUIRE_MESSAGE(DownloadBootstrapSnapshotParallel(b.Address(), PeerName(b), s2.manifest, tmp.path / "staging", 5000, 4, error), error);
    CheckAllFilesMatch(s2, tmp.path / "staging");
    BOOST_CHECK_MESSAGE(staged > 0, "the first attempt staged no complete file; the test proves nothing");
    BOOST_CHECK_LT(b.Log().size(), ChunksOf(s2)); // the staged files were not fetched again
}
BOOST_AUTO_TEST_SUITE_END()

#endif // !WIN32
