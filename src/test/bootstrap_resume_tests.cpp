// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for resuming an interrupted bootstrap snapshot download:
//  - the pure decision logic (staging identity, marker, per-file verdicts, work
//    queue, reconnect backoff, binary-unit formatting),
//  - the staging directory handling and the staged-file scan on a real directory,
//  - the parallel downloader against an in-process fake bootstrap server that can
//    cut connections, tamper with data and change its manifest.
// Nothing here weakens the verification contract: every reused byte is checked
// against the per-file SHA-256 of the manifest the (fake) peer serves.

#include "bootstrap.h"
#include "bootstrap_resume.h"

#include "chainparams.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "net.h"
#include "netbase.h"
#include "protocol.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/test/unit_test.hpp>

namespace fs = boost::filesystem;

namespace {

uint256 Sha256Of(const std::string& data)
{
    CSHA256 hasher;
    if (!data.empty())
        hasher.Write((const unsigned char*)data.data(), data.size());
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    return uint256S("0x" + HexStr(digest, digest + CSHA256::OUTPUT_SIZE));
}

// Deterministic pseudo-random bytes; distinct seeds give distinct contents.
std::string Bytes(size_t n, unsigned int seed)
{
    std::string s;
    s.resize(n);
    unsigned int x = seed * 2654435761u + 1u;
    for (size_t i = 0; i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        s[i] = (char)((x >> 16) & 0xff);
    }
    return s;
}

void WriteFile(const fs::path& path, const std::string& contents)
{
    fs::create_directories(path.parent_path());
    fs::ofstream f(path, std::ios::binary);
    f.write(contents.data(), contents.size());
}

std::string ReadFile(const fs::path& path)
{
    fs::ifstream f(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

struct TempDir {
    fs::path path;
    TempDir() : path(fs::temp_directory_path() / UniquePath("bootstrap-resume-test-%%%%-%%%%-%%%%")) { fs::create_directories(path); }
    ~TempDir() { boost::system::error_code ec; fs::remove_all(path, ec); }
};

const uint32_t TEST_CHUNK = 16 * 1024;

// A synthetic snapshot: chainstate/ and blocks/ files of assorted sizes (one empty).
struct Snapshot {
    CBootstrapSnapshotManifest manifest;
    std::vector<std::string> contents;
};

Snapshot MakeSnapshot(int nFiles, int firstSeed = 1)
{
    Snapshot s;
    CBootstrapSnapshotManifest& m = s.manifest;
    m.SetNull();
    m.nVersion = 1;
    m.strNetwork = Params().NetworkIDString();
    m.nHeight = 3126937;
    m.hashBlock = uint256S("0000000000000000000000000000000000000000000000000000000000abcdef");
    m.hashAnchorSha256 = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    m.hashAnchorSha3 = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    m.nChunkSize = TEST_CHUNK;
    for (int i = 0; i < nFiles; ++i) {
        CBootstrapSnapshotFile f;
        const size_t size = (i == 1) ? 0 : (size_t)(TEST_CHUNK * 2 + 777 + ((i * 7919) % 150000));
        f.strPath = (i % 3 == 0) ? strprintf("chainstate/%06d.ldb", i) : strprintf("blocks/blk%05d.dat", i);
        s.contents.push_back(Bytes(size, firstSeed + i));
        f.nSize = size;
        f.hashSha256 = Sha256Of(s.contents.back());
        m.nSnapshotBytes += size;
        m.vFiles.push_back(f);
    }
    return s;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(bootstrap_resume_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(staging_identity_is_stable_for_an_anchor)
{
    const Snapshot a = MakeSnapshot(6);
    const std::string name = BootstrapStagingDirName(a.manifest);
    BOOST_CHECK_EQUAL(name.compare(0, strlen(BOOTSTRAP_STAGING_PREFIX), BOOTSTRAP_STAGING_PREFIX), 0);
    BOOST_CHECK_EQUAL(name.size(), strlen(BOOTSTRAP_STAGING_PREFIX) + 16);
    // not a function of time or process: same manifest, same name
    BOOST_CHECK_EQUAL(name, BootstrapStagingDirName(MakeSnapshot(6).manifest));

    // a growing server (more files, a v3 block-bundle tip) keeps the anchor identity ...
    Snapshot grown = MakeSnapshot(9);
    BOOST_CHECK(BootstrapStagingIdentity(grown.manifest) == BootstrapStagingIdentity(a.manifest));
    BOOST_CHECK_EQUAL(BootstrapStagingDirName(grown.manifest), name);
    grown.manifest.nVersion = 3;
    grown.manifest.nBlockTipHeight = grown.manifest.nHeight + 4000;
    grown.manifest.hashBlockTip = uint256S("00000000000000000000000000000000000000000000000000000000000d00d");
    grown.manifest.hashChainstateSerialized = uint256S("33");
    BOOST_CHECK_EQUAL(BootstrapStagingDirName(grown.manifest), name);
    // ... while the full manifest id changes with every file-list change
    BOOST_CHECK(BootstrapManifestId(grown.manifest) != BootstrapManifestId(a.manifest));
    BOOST_CHECK(BootstrapManifestId(a.manifest) == BootstrapManifestId(MakeSnapshot(6).manifest));

    // a different anchor is a different snapshot
    Snapshot other = MakeSnapshot(6);
    other.manifest.nHeight += 1;
    BOOST_CHECK(BootstrapStagingIdentity(other.manifest) != BootstrapStagingIdentity(a.manifest));
    other = MakeSnapshot(6);
    other.manifest.hashBlock = uint256S("99");
    BOOST_CHECK(BootstrapStagingIdentity(other.manifest) != BootstrapStagingIdentity(a.manifest));
    other = MakeSnapshot(6);
    other.manifest.hashAnchorSha256 = uint256S("98");
    BOOST_CHECK(BootstrapStagingIdentity(other.manifest) != BootstrapStagingIdentity(a.manifest));

    // a v2 self-snapshot has no compiled anchor: its own commitment is part of its identity
    Snapshot v2a = MakeSnapshot(6), v2b = MakeSnapshot(6);
    v2a.manifest.nVersion = v2b.manifest.nVersion = 2;
    v2a.manifest.hashChainstateSerialized = uint256S("aa");
    v2b.manifest.hashChainstateSerialized = uint256S("bb");
    BOOST_CHECK(BootstrapStagingIdentity(v2a.manifest) != BootstrapStagingIdentity(v2b.manifest));
}

BOOST_AUTO_TEST_CASE(staging_marker_roundtrip_and_rejects_garbage)
{
    const Snapshot s = MakeSnapshot(4);
    BootstrapStagingMarker m;
    m.nVersion = BOOTSTRAP_STAGING_MARKER_VERSION;
    m.identity = BootstrapStagingIdentity(s.manifest);
    m.manifestId = BootstrapManifestId(s.manifest);
    const std::string text = FormatBootstrapStagingMarker(m);
    BootstrapStagingMarker parsed;
    BOOST_REQUIRE(ParseBootstrapStagingMarker(text, parsed));
    BOOST_CHECK(parsed.identity == m.identity);
    BOOST_CHECK(parsed.manifestId == m.manifestId);

    BootstrapStagingMarker junk;
    BOOST_CHECK(!ParseBootstrapStagingMarker("", junk));
    BOOST_CHECK(!ParseBootstrapStagingMarker("hello", junk));
    BOOST_CHECK(!ParseBootstrapStagingMarker(text.substr(0, text.size() / 2), junk));
    BOOST_CHECK(!ParseBootstrapStagingMarker(std::string(text.size(), '\0'), junk));
    BOOST_CHECK(!ParseBootstrapStagingMarker(std::string(5000, 'a'), junk));
    std::string wrongVersion = text;
    wrongVersion.replace(wrongVersion.find(" 1\n"), 3, " 9\n");
    BOOST_CHECK(!ParseBootstrapStagingMarker(wrongVersion, junk));
    std::string notHex = text;
    notHex[notHex.find("identity ") + 9] = 'g';
    BOOST_CHECK(!ParseBootstrapStagingMarker(notHex, junk));
    BootstrapStagingMarker nullId = m;
    nullId.identity.SetNull();
    BOOST_CHECK(!ParseBootstrapStagingMarker(FormatBootstrapStagingMarker(nullId), junk));
}

BOOST_AUTO_TEST_CASE(staging_reuse_verdicts)
{
    const Snapshot s = MakeSnapshot(5);
    const uint256 id = BootstrapStagingIdentity(s.manifest);
    const uint256 man = BootstrapManifestId(s.manifest);
    BootstrapStagingMarker m;
    m.nVersion = BOOTSTRAP_STAGING_MARKER_VERSION;
    m.identity = id;
    m.manifestId = man;
    BOOST_CHECK_EQUAL(BootstrapDecideStagingReuse(false, false, BootstrapStagingMarker(), id, man), BSV_FRESH);
    BOOST_CHECK_EQUAL(BootstrapDecideStagingReuse(true, true, m, id, man), BSV_REUSE_SAME_MANIFEST);
    BootstrapStagingMarker grown = m;
    grown.manifestId = uint256S("77");
    BOOST_CHECK_EQUAL(BootstrapDecideStagingReuse(true, true, grown, id, man), BSV_REUSE_SAME_ANCHOR);
    BootstrapStagingMarker other = m;
    other.identity = uint256S("88");
    BOOST_CHECK_EQUAL(BootstrapDecideStagingReuse(true, true, other, id, man), BSV_DISCARD_OTHER_SNAPSHOT);
    BOOST_CHECK_EQUAL(BootstrapDecideStagingReuse(true, false, m, id, man), BSV_DISCARD_BAD_MARKER);
    // a directory that is not there is never reused, whatever the marker says
    BOOST_CHECK_EQUAL(BootstrapDecideStagingReuse(false, true, m, id, man), BSV_FRESH);
}

BOOST_AUTO_TEST_CASE(resume_offsets_are_chunk_aligned)
{
    const uint32_t C = 1024 * 1024;
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(0, 10 * C, C), 0);
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(C - 1, 10 * C, C), 0);          // less than one whole chunk: start over
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(C, 10 * C, C), C);
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(3 * C + 12345, 10 * C, C), 3 * C); // torn trailing chunk is re-fetched
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(9 * C, 10 * C, C), 9 * C);
    // a .part as big as the file still re-requests the last chunk, so it takes the normal verify path
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(10 * C, 10 * C, C), 9 * C);
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(10 * C - 5, 10 * C, C), 9 * C);
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(10 * C + 1, 10 * C, C), 0);     // longer than the file: unusable
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(5 * C, 5 * C + 1, C), 5 * C);   // file is 5 chunks and a byte
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(100, 0, C), 0);
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(100, 100, 0), 0);
    // a one-chunk file never resumes mid-file
    BOOST_CHECK_EQUAL(BootstrapResumeOffset(C - 1, C, C), 0);
}

BOOST_AUTO_TEST_CASE(staged_file_decisions)
{
    const uint32_t C = 1024;
    const uint64_t size = 10 * C + 100;
    BootstrapStagedFileFacts f;

    // nothing on disk
    BootstrapStagedDecision d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_FETCH_ALL);
    BOOST_CHECK(!d.discardFinal && !d.discardPart);

    // complete and matching
    f.finalExists = true; f.finalSize = size; f.finalHashOk = true;
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_KEEP);
    BOOST_CHECK(!d.discardFinal && !d.discardPart);
    // a leftover .part beside a verified file is garbage
    f.partExists = true; f.partSize = 5 * C;
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_KEEP);
    BOOST_CHECK(d.discardPart);

    // right size, wrong hash: never trusted, deleted, fetched again from the start
    f = BootstrapStagedFileFacts();
    f.finalExists = true; f.finalSize = size; f.finalHashOk = false;
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_FETCH_ALL);
    BOOST_CHECK(d.discardFinal);
    BOOST_CHECK_EQUAL(d.resumeOffset, 0);
    // wrong size
    f.finalSize = size - 1; f.finalHashOk = true; // even a (nonsensical) true hash flag cannot save a wrong size
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_FETCH_ALL);
    BOOST_CHECK(d.discardFinal);
    // a .part beside a bad final file has no provenance either
    f.partExists = true; f.partSize = 4 * C;
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_FETCH_ALL);
    BOOST_CHECK(d.discardFinal && d.discardPart);

    // partial file
    f = BootstrapStagedFileFacts();
    f.partExists = true; f.partSize = 4 * C + 17;
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_RESUME_PART);
    BOOST_CHECK_EQUAL(d.resumeOffset, 4 * C);
    BOOST_CHECK(!d.discardPart && !d.discardFinal);
    // too short to be worth keeping
    f.partSize = C - 1;
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_FETCH_ALL);
    BOOST_CHECK(d.discardPart);
    // longer than the file
    f.partSize = size + 1;
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_FETCH_ALL);
    BOOST_CHECK(d.discardPart);
    // full size: continue at the last chunk
    f.partSize = size;
    d = BootstrapDecideStagedFile(size, C, f);
    BOOST_CHECK_EQUAL(d.action, BSA_RESUME_PART);
    BOOST_CHECK_EQUAL(d.resumeOffset, 10 * C);
}

BOOST_AUTO_TEST_CASE(work_queue_hands_back_unfinished_files)
{
    std::vector<uint32_t> files;
    files.push_back(7); files.push_back(3); files.push_back(9);
    BootstrapWorkQueue q(files);
    BOOST_CHECK(!q.AllDone());
    uint32_t a = 0, b = 0, c = 0, d = 0;
    BOOST_REQUIRE(q.Claim(a)); BOOST_CHECK_EQUAL(a, 7);
    BOOST_REQUIRE(q.Claim(b)); BOOST_CHECK_EQUAL(b, 3);
    BOOST_CHECK_EQUAL(q.PendingCount(), 1);
    BOOST_CHECK_EQUAL(q.ClaimedCount(), 2);
    // a stream dies holding file 3: it comes back first, before untouched files
    q.Release(b);
    BOOST_CHECK_EQUAL(q.ClaimedCount(), 1);
    BOOST_REQUIRE(q.Claim(c)); BOOST_CHECK_EQUAL(c, 3);
    q.Complete(a);
    q.Complete(c);
    BOOST_CHECK_EQUAL(q.DoneCount(), 2);
    BOOST_CHECK(!q.AllDone());
    BOOST_REQUIRE(q.Claim(d)); BOOST_CHECK_EQUAL(d, 9);
    BOOST_CHECK(!q.HasPending());
    BOOST_CHECK(!q.AllDone());          // still in flight
    uint32_t none = 0;
    BOOST_CHECK(!q.Claim(none));
    q.Complete(d);
    BOOST_CHECK(q.AllDone());
    // completing or releasing something that was never claimed changes nothing
    q.Release(1234);
    q.Complete(1234);
    BOOST_CHECK(q.AllDone());
    BOOST_CHECK_EQUAL(q.DoneCount(), 3);

    // a failed verification forces a restart from byte 0 and counts strikes
    BootstrapWorkQueue q2(files);
    BOOST_CHECK(!q2.MustRestart(7));
    BOOST_CHECK_EQUAL(q2.AddStrike(7), 1);
    BOOST_CHECK(q2.MustRestart(7));
    BOOST_CHECK(!q2.MustRestart(3));
    BOOST_CHECK_EQUAL(q2.AddStrike(7), 2);
}

BOOST_AUTO_TEST_CASE(reconnect_backoff_grows_and_is_capped)
{
    BOOST_CHECK_EQUAL(BootstrapReconnectDelayMs(0, 123), 0);
    BOOST_CHECK_EQUAL(BootstrapReconnectDelayMs(-4, 123), 0);
    int64_t previousBase = 0;
    const int64_t bases[] = {1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000};
    for (int failures = 1; failures <= 8; ++failures) {
        const int64_t base = bases[failures - 1];
        for (unsigned int seed = 0; seed < 5000; seed += 37) {
            const int64_t delay = BootstrapReconnectDelayMs(failures, seed);
            BOOST_CHECK_MESSAGE(delay >= base - base / 4 && delay <= base + base / 4,
                                "failures=" << failures << " seed=" << seed << " delay=" << delay);
        }
        BOOST_CHECK(base >= previousBase);
        previousBase = base;
    }
    // jitter really differs between streams
    std::set<int64_t> distinct;
    for (unsigned int seed = 0; seed < 64; ++seed)
        distinct.insert(BootstrapReconnectDelayMs(3, seed * 977));
    BOOST_CHECK(distinct.size() > 8);
    BOOST_CHECK_EQUAL(BootstrapReconnectDelayMs(1000000, 1) <= 37500, true);
}

BOOST_AUTO_TEST_CASE(binary_units_are_labelled_as_such)
{
    // the figure from the field report: an 11.2 GB snapshot is 10.43 GiB
    BOOST_CHECK_EQUAL(BootstrapFormatGiB(11200000000ULL), "10.43 GiB");
    BOOST_CHECK_EQUAL(BootstrapFormatGiB(1073741824ULL), "1.00 GiB");
    BOOST_CHECK_EQUAL(BootstrapFormatGiB(0), "0.00 GiB");
    BOOST_CHECK_EQUAL(BootstrapFormatGiB(1610612736ULL), "1.50 GiB");

    BOOST_CHECK_EQUAL(BootstrapFormatProgressLine(42, 4402341478ULL, 10522669875ULL, 210.5, 4),
                      "Bootstrap snapshot:  42%  4.10 / 9.80 GiB  210.5 MiB/s  (4 streams)");
    BOOST_CHECK_EQUAL(BootstrapFormatProgressLine(7, 784334336ULL, 11200000000ULL, 12.0, 0),
                      "Bootstrap snapshot:   7%  0.73 / 10.43 GiB  12.0 MiB/s");
    BOOST_CHECK_EQUAL(BootstrapFormatProgressLine(100, 1073741824ULL, 1073741824ULL, 0.0, 1),
                      "Bootstrap snapshot: 100%  1.00 / 1.00 GiB  0.0 MiB/s  (1 streams)");
    // the legacy single-digit prefix the wallet parses is unchanged: "Bootstrap snapshot:" then the percent
    const std::string line = BootstrapFormatProgressLine(5, 1, 2, 3.0, 4);
    BOOST_CHECK_EQUAL(line.compare(0, 20, "Bootstrap snapshot: "), 0);
    BOOST_CHECK(line.find("GB ") == std::string::npos);
    BOOST_CHECK(line.find("MB/s") == std::string::npos);
}

// ---------------------------------------------------------------------------
// Staging directory and scan on a real directory
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Multi-server scheduling (pure logic)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(peer_board_spreads_streams_round_robin)
{
    BootstrapPeerBoard two(2, 4);
    BOOST_CHECK_EQUAL(two.Assign(0, 0), 0);
    BOOST_CHECK_EQUAL(two.Assign(1, 0), 1);
    BOOST_CHECK_EQUAL(two.Assign(2, 0), 0);
    BOOST_CHECK_EQUAL(two.Assign(3, 0), 1);
    // one peer: every stream goes to it, as before
    BootstrapPeerBoard one(1, 3);
    for (int s = 0; s < 3; ++s)
        BOOST_CHECK_EQUAL(one.Assign(s, 0), 0);
    BOOST_CHECK_EQUAL(one.UsablePeers(), 1U);
}

BOOST_AUTO_TEST_CASE(peer_board_never_assigns_an_ignored_or_failing_peer_first)
{
    BootstrapPeerBoard b(3, 3);
    b.ManifestMismatch(0);
    BOOST_CHECK_EQUAL(b.UsablePeers(), 2U);
    for (int s = 0; s < 3; ++s)
        BOOST_CHECK(b.Assign(s, 0) != 0);
    b.ManifestMismatch(1);
    b.ManifestMismatch(2);
    BOOST_CHECK_EQUAL(b.UsablePeers(), 0U);
    BOOST_CHECK_EQUAL(b.Assign(0, 0), -1);
    BOOST_CHECK(b.Peer(0, 0).ignored);

    // a peer that just failed to connect is avoided while another is usable, then tried again
    BootstrapPeerBoard c(2, 2);
    c.ConnectFailed(0, 0);
    BOOST_CHECK_EQUAL(c.Assign(0, 100), 1);
    BOOST_CHECK_EQUAL(c.Assign(1, 100), 1);
    BootstrapPeerBoard d(2, 2);
    d.ConnectFailed(0, 0);
    BOOST_CHECK_EQUAL(d.Assign(0, 70000), 0); // cooldown over
    d.ConnectFailed(0, 70000);
    d.ConnectFailed(0, 70001);
    d.ConnectFailed(1, 70002);
    BOOST_CHECK(d.Assign(1, 70003) >= 0); // all failing: still picks one, never -1
}

BOOST_AUTO_TEST_CASE(peer_board_moves_a_stream_the_server_defers)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 2000;
    BootstrapPeerBoard b(2, 4, pol);
    for (int s = 0; s < 4; ++s)
        b.Attach(s, b.Assign(s, 0), 0);
    BOOST_CHECK_EQUAL(b.StreamPeer(1), 1);
    // streams 0 and 2 (peer 0) are served, streams 1 and 3 (peer 1, over its cap) get nothing
    for (int64_t t = 100; t <= 3000; t += 100) {
        b.NoteChunk(0, 10, 1000, t);
        b.NoteChunk(2, 11, 1000, t);
    }
    BOOST_CHECK(b.Rebalance(1500).empty()); // not yet stalled long enough
    const std::vector<BootstrapMove> mv = b.Rebalance(3000);
    BOOST_REQUIRE_EQUAL(mv.size(), 2U);
    for (size_t i = 0; i < mv.size(); ++i) {
        BOOST_CHECK(mv[i].stream == 1 || mv[i].stream == 3);
        BOOST_CHECK(mv[i].reason == BMR_STALLED);
    }
    BOOST_CHECK(b.Rebalance(3100).empty()); // a stream already asked to move is not asked again
    b.Detach(1);
    BOOST_CHECK_EQUAL(b.Assign(1, 3200), 0); // the server that deferred it is avoided for a while
    // with a single usable peer a quiet stream stays put (the receive timeout handles it)
    BootstrapPeerBoard solo(1, 1, pol);
    solo.Attach(0, solo.Assign(0, 0), 0);
    BOOST_CHECK(solo.Rebalance(60000).empty());
}

BOOST_AUTO_TEST_CASE(peer_board_moves_a_stream_off_a_much_slower_server_but_keeps_one)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.moveCooldownMs = 1000;
    pol.stallMs = 1000000;
    BootstrapPeerBoard b(2, 4, pol);
    for (int s = 0; s < 4; ++s)
        b.Attach(s, b.Assign(s, 0), 0);
    for (int64_t t = 100; t <= 2000; t += 100) {
        b.NoteChunk(0, 10, 10000, t); // 100 kB/s on peer 0
        b.NoteChunk(2, 11, 10000, t);
        b.NoteChunk(1, 12, 100, t);   // 1 kB/s on peer 1
        b.NoteChunk(3, 13, 100, t);
    }
    std::vector<BootstrapMove> mv = b.Rebalance(2000);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_CHECK(mv[0].reason == BMR_SLOW);
    BOOST_CHECK(mv[0].stream == 1 || mv[0].stream == 3);
    const int movedStream = mv[0].stream;
    const int stayed = movedStream == 1 ? 3 : 1;
    b.Detach(movedStream);
    BOOST_CHECK_EQUAL(b.Assign(movedStream, 2100), 0); // goes to the fast server
    // the last stream on the slow server is left alone: it keeps the rate measured
    for (int64_t t = 2100; t <= 4000; t += 100) {
        b.NoteChunk(0, 10, 10000, t);
        b.NoteChunk(2, 11, 10000, t);
        b.NoteChunk(stayed, 14, 100, t);
    }
    BOOST_CHECK(b.Rebalance(4000).empty());
    BOOST_CHECK(b.Peer(0, 4000).mibps > b.Peer(1, 4000).mibps);
}

BOOST_AUTO_TEST_CASE(peer_board_idle_stream_steals_from_a_much_slower_holder)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 1000000;
    pol.stealMinSeconds = 15;
    BootstrapPeerBoard b(2, 3, pol);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    b.NoteClaim(0, 8, 100000, false);
    b.NoteClaim(1, 7, 1000000, false);
    b.SetIdle(2, true); // nothing queued for stream 2
    for (int64_t t = 100; t <= 2000; t += 100) {
        b.NoteChunk(0, 8, 100, t); // both servers equally slow
        b.NoteChunk(1, 7, 100, t);
    }
    BOOST_CHECK(b.Rebalance(2000).empty()); // no steal while the holder is not much slower
    for (int64_t t = 2100; t <= 4000; t += 100) {
        b.NoteChunk(0, 8, 10000, t); // peer 0 speeds up to 100 kB/s
        b.NoteChunk(1, 7, 10, t);
    }
    std::vector<BootstrapMove> mv = b.Rebalance(4000);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_CHECK_EQUAL(mv[0].stream, 1);
    BOOST_CHECK(mv[0].reason == BMR_STEAL);

    // a nearly finished file is not worth taking over
    BootstrapPeerBoard c(2, 3, pol);
    c.Attach(0, c.Assign(0, 0), 0);
    c.Attach(1, c.Assign(1, 0), 0);
    c.NoteClaim(1, 7, 500, false);
    c.SetIdle(2, true);
    for (int64_t t = 100; t <= 2000; t += 100) {
        c.NoteChunk(0, 8, 10000, t);
        c.NoteChunk(1, 7, 10, t);
    }
    BOOST_CHECK(c.Rebalance(2000).empty());
    // and nothing is stolen when no stream is idle
    BootstrapPeerBoard d(2, 2, pol);
    d.Attach(0, d.Assign(0, 0), 0);
    d.Attach(1, d.Assign(1, 0), 0);
    d.NoteClaim(1, 7, 1000000, false);
    for (int64_t t = 100; t <= 2000; t += 100) {
        d.NoteChunk(0, 8, 10000, t);
        d.NoteChunk(1, 7, 10, t);
    }
    BOOST_CHECK(d.Rebalance(2000).empty());
}

BOOST_AUTO_TEST_CASE(peer_board_blames_the_peer_that_supplied_a_bad_file)
{
    // a file supplied by one peer only: that peer is benched as soon as another is usable
    BootstrapPeerBoard b(2, 2);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    b.NoteClaim(1, 5, 100, false);
    b.NoteChunk(1, 5, 100, 10);
    BOOST_CHECK(b.HashFailed(1, 5));
    BOOST_CHECK(b.Peer(1, 20).banned);
    BOOST_CHECK(!b.Peer(0, 20).banned);
    b.Detach(1);
    BOOST_CHECK_EQUAL(b.Assign(1, 30), 0);
    // streams still on the benched peer are told to leave
    BootstrapPeerBoard c(2, 2);
    c.Attach(0, c.Assign(0, 0), 0);
    c.Attach(1, c.Assign(1, 0), 0);
    c.NoteClaim(0, 6, 100, false);
    c.NoteChunk(0, 6, 100, 10);
    c.HashFailed(0, 6); // peer 0 benched, stream 0 is on it
    const std::vector<BootstrapMove> mv = c.Rebalance(100);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_CHECK_EQUAL(mv[0].stream, 0);
    BOOST_CHECK(mv[0].reason == BMR_UNUSABLE);

    // the only usable peer is never benched: the plain strike limit decides
    BootstrapPeerBoard solo(1, 1);
    solo.Attach(0, solo.Assign(0, 0), 0);
    solo.NoteClaim(0, 5, 100, false);
    solo.NoteChunk(0, 5, 100, 10);
    BOOST_CHECK(!solo.HashFailed(0, 5));
    BOOST_CHECK(!solo.Peer(0, 20).banned);

    // bytes of unknown origin already on disk: the culprit is unknown, only a second failure benches
    BootstrapPeerBoard m(2, 2);
    m.Attach(0, m.Assign(0, 0), 0);
    m.Attach(1, m.Assign(1, 0), 0);
    m.NoteClaim(0, 9, 100, true); // resumed from disk
    m.NoteChunk(0, 9, 50, 10);
    BOOST_CHECK(m.HashFailed(0, 9));
    BOOST_CHECK(!m.Peer(0, 20).banned);
    m.NoteClaim(0, 9, 100, false);
    m.NoteChunk(0, 9, 50, 30);
    m.NoteChunk(1, 9, 50, 30); // two suppliers
    BOOST_CHECK(m.HashFailed(0, 9));
    BOOST_CHECK(m.Peer(0, 40).banned); // its second failure; the other has one and stays
    BOOST_CHECK(!m.Peer(1, 40).banned);
    BOOST_CHECK_EQUAL(m.UsablePeers(), 1U);
}

BOOST_AUTO_TEST_CASE(progress_line_names_the_servers_only_when_there_are_several)
{
    BOOST_CHECK_EQUAL(BootstrapFormatProgressLine(42, 4402341478ULL, 10522669875ULL, 210.5, 4, 2),
                      "Bootstrap snapshot:  42%  4.10 / 9.80 GiB  210.5 MiB/s  (4 streams, 2 servers)");
    BOOST_CHECK_EQUAL(BootstrapFormatProgressLine(42, 4402341478ULL, 10522669875ULL, 210.5, 4, 1),
                      BootstrapFormatProgressLine(42, 4402341478ULL, 10522669875ULL, 210.5, 4));
    std::vector<std::string> names;
    names.push_back("a:1");
    names.push_back("b:2");
    std::vector<BootstrapPeerSnapshot> snap(2);
    snap[0].streams = 2;
    snap[0].mibps = 12.5;
    snap[1].ignored = true;
    const std::string line = BootstrapPeerSummary(names, snap);
    BOOST_CHECK(line.find("a:1 2 streams 12.5 MiB/s") != std::string::npos);
    BOOST_CHECK(line.find("different snapshot") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(prepare_staging_reuses_discards_and_marks)
{
    TempDir tmp;
    const fs::path datadir = tmp.path;
    const Snapshot s = MakeSnapshot(6);
    fs::path staging;
    BootstrapStagingVerdict verdict;
    std::string error;

    // leftovers: a per-epoch directory of the old naming scheme, and an unrelated directory
    fs::create_directories(datadir / "bootstrap-peer-staging-1700000000" / "blocks");
    WriteFile(datadir / "bootstrap-peer-staging-1700000000" / "blocks" / "x", "old");
    fs::create_directories(datadir / "other");

    BOOST_REQUIRE(BootstrapPrepareStaging(datadir, s.manifest, staging, verdict, error));
    BOOST_CHECK_EQUAL(verdict, BSV_FRESH);
    BOOST_CHECK_EQUAL(staging.filename().string(), BootstrapStagingDirName(s.manifest));
    BOOST_CHECK(fs::is_regular_file(staging / BOOTSTRAP_STAGING_MARKER));
    BOOST_CHECK(!fs::exists(datadir / "bootstrap-peer-staging-1700000000")); // stale directory removed
    BOOST_CHECK(fs::exists(datadir / "other"));                               // unrelated left alone

    // some progress, then "the process dies" and starts again
    WriteFile(staging / "blocks" / "blk00002.dat", s.contents[2]);
    BOOST_REQUIRE(BootstrapPrepareStaging(datadir, s.manifest, staging, verdict, error));
    BOOST_CHECK_EQUAL(verdict, BSV_REUSE_SAME_MANIFEST);
    BOOST_CHECK(fs::exists(staging / "blocks" / "blk00002.dat"));

    // the server grew: same anchor, more files: the directory (and its files) are reused
    Snapshot grown = MakeSnapshot(8);
    BOOST_REQUIRE(BootstrapPrepareStaging(datadir, grown.manifest, staging, verdict, error));
    BOOST_CHECK_EQUAL(verdict, BSV_REUSE_SAME_ANCHOR);
    BOOST_CHECK(fs::exists(staging / "blocks" / "blk00002.dat"));
    BOOST_CHECK_EQUAL(staging.filename().string(), BootstrapStagingDirName(s.manifest));
    BOOST_REQUIRE(BootstrapPrepareStaging(datadir, grown.manifest, staging, verdict, error));
    BOOST_CHECK_EQUAL(verdict, BSV_REUSE_SAME_MANIFEST); // the marker now names the grown manifest

    // a new snapshot (different anchor): the old staging directory is discarded
    Snapshot next = MakeSnapshot(6);
    next.manifest.nHeight += 100000;
    next.manifest.hashBlock = uint256S("5678");
    fs::path nextStaging;
    BOOST_REQUIRE(BootstrapPrepareStaging(datadir, next.manifest, nextStaging, verdict, error));
    BOOST_CHECK_EQUAL(verdict, BSV_FRESH);
    BOOST_CHECK(nextStaging != staging);
    BOOST_CHECK(!fs::exists(staging));
    BOOST_CHECK(fs::is_directory(nextStaging));
    BOOST_CHECK(!fs::exists(nextStaging / "blocks" / "blk00002.dat"));

    // a directory with the right name but no/garbled marker is not trusted
    WriteFile(nextStaging / "blocks" / "blk00004.dat", "whatever");
    WriteFile(nextStaging / BOOTSTRAP_STAGING_MARKER, "garbage");
    BOOST_REQUIRE(BootstrapPrepareStaging(datadir, next.manifest, nextStaging, verdict, error));
    BOOST_CHECK_EQUAL(verdict, BSV_DISCARD_BAD_MARKER);
    BOOST_CHECK(!fs::exists(nextStaging / "blocks" / "blk00004.dat"));
    BOOST_CHECK(fs::is_regular_file(nextStaging / BOOTSTRAP_STAGING_MARKER));
    fs::remove(nextStaging / BOOTSTRAP_STAGING_MARKER);
    WriteFile(nextStaging / "blocks" / "blk00004.dat", "whatever");
    BOOST_REQUIRE(BootstrapPrepareStaging(datadir, next.manifest, nextStaging, verdict, error));
    BOOST_CHECK_EQUAL(verdict, BSV_DISCARD_BAD_MARKER);
    BOOST_CHECK(!fs::exists(nextStaging / "blocks" / "blk00004.dat"));

    // a plain file squatting on the directory name is replaced
    fs::remove_all(nextStaging);
    WriteFile(nextStaging, "i am a file");
    BOOST_REQUIRE(BootstrapPrepareStaging(datadir, next.manifest, nextStaging, verdict, error));
    BOOST_CHECK_EQUAL(verdict, BSV_FRESH);
    BOOST_CHECK(fs::is_directory(nextStaging));

    // nobody needs the staging directories once the node has a real chain
    BOOST_CHECK_EQUAL(RemoveStaleBootstrapStaging(datadir), 1);
    BOOST_CHECK(!fs::exists(nextStaging));
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(prepare_staging_never_opens_a_marker_that_is_not_a_regular_file)
{
    // A FIFO in place of the marker would block the startup thread in fopen(): it is
    // never opened, and the directory counts as having no valid marker.
    TempDir tmp;
    const Snapshot s = MakeSnapshot(3);
    const fs::path dir = tmp.path / BootstrapStagingDirName(s.manifest);
    fs::create_directories(dir / "blocks");
    WriteFile(dir / "blocks" / "x", "x");
    BOOST_REQUIRE_EQUAL(mkfifo((dir / BOOTSTRAP_STAGING_MARKER).string().c_str(), 0600), 0);
    fs::path staging;
    BootstrapStagingVerdict verdict;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BootstrapPrepareStaging(tmp.path, s.manifest, staging, verdict, error), error);
    BOOST_CHECK_EQUAL(verdict, BSV_DISCARD_BAD_MARKER);
    BOOST_CHECK(fs::is_regular_file(fs::symlink_status(staging / BOOTSTRAP_STAGING_MARKER)));
    BOOST_CHECK(!fs::exists(staging / "blocks" / "x"));
}
#endif

BOOST_AUTO_TEST_CASE(scan_keeps_verified_resumes_partial_and_deletes_the_rest)
{
    TempDir tmp;
    const fs::path staging = tmp.path / "staging";
    const Snapshot s = MakeSnapshot(10);
    const CBootstrapSnapshotManifest& m = s.manifest;
    fs::create_directories(staging);

    // 0: complete and right.  1: the empty file (handled by the downloader).
    WriteFile(staging / m.vFiles[0].strPath, s.contents[0]);
    // 2: complete size, one flipped bit
    std::string flipped = s.contents[2];
    flipped[flipped.size() / 2] ^= 0x01;
    WriteFile(staging / m.vFiles[2].strPath, flipped);
    // 3: truncated "final" file
    WriteFile(staging / m.vFiles[3].strPath, s.contents[3].substr(0, s.contents[3].size() - 10));
    // 4: partial, three whole chunks and a torn fourth
    WriteFile(staging / (m.vFiles[4].strPath + ".part"), s.contents[4].substr(0, 3 * TEST_CHUNK + 100));
    // 5: partial but shorter than a chunk
    WriteFile(staging / (m.vFiles[5].strPath + ".part"), s.contents[5].substr(0, 100));
    // 6: complete-looking .part with no final file
    WriteFile(staging / (m.vFiles[6].strPath + ".part"), s.contents[6]);
    // 7: both a verified final file and a stale .part
    WriteFile(staging / m.vFiles[7].strPath, s.contents[7]);
    WriteFile(staging / (m.vFiles[7].strPath + ".part"), "stale");
    // 8: a .part longer than the file
    WriteFile(staging / (m.vFiles[8].strPath + ".part"), s.contents[8] + "extra");
    // 9: nothing.  Strays: unknown file in a known dir, unknown top-level entries.
    WriteFile(staging / "blocks" / "unknown.dat", "x");
    WriteFile(staging / "chainstate" / "LOCK", "x");
    WriteFile(staging / "wallet.dat", "x");
    WriteFile(staging / BOOTSTRAP_STAGING_MARKER, "marker survives the scan");

    std::vector<uint32_t> pending;
    uint64_t completed = 0;
    BootstrapResumeStats stats;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BootstrapResumeScan(m, staging, pending, completed, stats, error), error);

    BOOST_CHECK_EQUAL(stats.filesKept, 2);       // files 0 and 7
    BOOST_CHECK_EQUAL(stats.bytesKept, s.contents[0].size() + s.contents[7].size());
    BOOST_CHECK_EQUAL(stats.filesResumed, 2);    // files 4 and 6
    BOOST_CHECK_EQUAL(stats.filesDiscarded, 2);  // files 2 and 3
    BOOST_CHECK_EQUAL(stats.strayRemoved, 3);
    BOOST_CHECK_EQUAL(stats.bytesHashed, s.contents[0].size() + s.contents[2].size() + s.contents[7].size());

    std::set<uint32_t> pend(pending.begin(), pending.end());
    const uint32_t expectPending[] = {2, 3, 4, 5, 6, 8, 9};
    BOOST_CHECK_EQUAL(pend.size(), sizeof(expectPending) / sizeof(expectPending[0]));
    for (size_t i = 0; i < sizeof(expectPending) / sizeof(expectPending[0]); ++i)
        BOOST_CHECK_MESSAGE(pend.count(expectPending[i]), "file " << expectPending[i] << " should be pending");
    BOOST_CHECK(!pend.count(0));
    BOOST_CHECK(!pend.count(7));
    BOOST_CHECK(!pend.count(1)); // zero-length: nothing to fetch

    // completed = verified bytes + the chunk-aligned bytes of partial files that will continue
    const uint64_t last6 = ((s.contents[6].size() - 1) / TEST_CHUNK) * TEST_CHUNK;
    BOOST_CHECK_EQUAL(completed, s.contents[0].size() + s.contents[7].size() + 3 * TEST_CHUNK + last6);

    BOOST_CHECK(fs::exists(staging / m.vFiles[0].strPath));
    BOOST_CHECK(!fs::exists(staging / m.vFiles[2].strPath));      // corrupt file deleted, not trusted
    BOOST_CHECK(!fs::exists(staging / m.vFiles[3].strPath));
    BOOST_CHECK(fs::exists(staging / (m.vFiles[4].strPath + ".part")));
    BOOST_CHECK(!fs::exists(staging / (m.vFiles[5].strPath + ".part")));
    BOOST_CHECK(fs::exists(staging / (m.vFiles[6].strPath + ".part")));
    BOOST_CHECK(!fs::exists(staging / (m.vFiles[7].strPath + ".part")));
    BOOST_CHECK(!fs::exists(staging / (m.vFiles[8].strPath + ".part")));
    BOOST_CHECK(!fs::exists(staging / "blocks" / "unknown.dat"));
    BOOST_CHECK(!fs::exists(staging / "chainstate" / "LOCK"));
    BOOST_CHECK(!fs::exists(staging / "wallet.dat"));
    BOOST_CHECK(fs::exists(staging / BOOTSTRAP_STAGING_MARKER));

    // a second scan finds the same thing (nothing left to delete)
    BootstrapResumeStats again;
    std::vector<uint32_t> pending2;
    uint64_t completed2 = 0;
    BOOST_REQUIRE(BootstrapResumeScan(m, staging, pending2, completed2, again, error));
    BOOST_CHECK_EQUAL(again.filesDiscarded, 0);
    BOOST_CHECK_EQUAL(again.strayRemoved, 0);
    BOOST_CHECK_EQUAL(completed2, completed);

    // an unsafe manifest path is refused outright
    CBootstrapSnapshotManifest evil = m;
    evil.vFiles[0].strPath = "../../etc/passwd";
    BOOST_CHECK(!BootstrapResumeScan(evil, staging, pending2, completed2, again, error));
#ifndef WIN32
    // Symlinks in staging are never followed: each link is unlinked and its target is
    // left alone, and a link standing in for a manifest file means that file is fetched
    // again. A directory where a manifest file belongs is removed too (it could never be
    // replaced by the verified file, so keeping it would fail every later attempt).
    const fs::path outsideDir = tmp.path / "outside";
    fs::create_directories(outsideDir);
    WriteFile(outsideDir / "keep.dat", s.contents[0]);
    fs::create_directory_symlink(outsideDir, staging / "blocks" / "linkdir");
    fs::remove(staging / m.vFiles[0].strPath);
    fs::create_symlink(outsideDir / "keep.dat", staging / m.vFiles[0].strPath);
    fs::remove(staging / m.vFiles[7].strPath);
    fs::create_directories(staging / m.vFiles[7].strPath / "sub");
    WriteFile(staging / m.vFiles[7].strPath / "sub" / "x", "x");
    BootstrapResumeStats links;
    BOOST_REQUIRE_MESSAGE(BootstrapResumeScan(m, staging, pending2, completed2, links, error), error);
    BOOST_CHECK_EQUAL(links.strayRemoved, 3);
    BOOST_CHECK_EQUAL(links.filesKept, 0);
    BOOST_CHECK(!fs::exists(fs::symlink_status(staging / "blocks" / "linkdir")));
    BOOST_CHECK(!fs::exists(fs::symlink_status(staging / m.vFiles[0].strPath)));
    BOOST_CHECK(!fs::exists(fs::symlink_status(staging / m.vFiles[7].strPath)));
    BOOST_CHECK(fs::is_regular_file(fs::symlink_status(outsideDir / "keep.dat")));
    BOOST_CHECK(ReadFile(outsideDir / "keep.dat") == s.contents[0]);
    BOOST_CHECK(fs::exists(staging / (m.vFiles[4].strPath + ".part"))); // unrelated progress survives
    const std::set<uint32_t> pendLinks(pending2.begin(), pending2.end());
    BOOST_CHECK(pendLinks.count(0));
    BOOST_CHECK(pendLinks.count(7));
#endif
}

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
    BOOST_CHECK_LT(GetTimeMillis() - t0, 30000);
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
    BOOST_CHECK_LT(GetTimeMillis() - t0, 4500);
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
    BOOST_CHECK_LT(GetTimeMillis() - t0, 6000);
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
    BOOST_CHECK_LT(GetTimeMillis() - t0, 45000); // would take minutes if its streams stayed on b (loaded hosts need slack)
    CheckAllFilesMatch(s, tmp.path / "staging");
    BOOST_CHECK_GE(a.Log().size(), ChunksOf(s) - 40U);
}

BOOST_AUTO_TEST_CASE(partial_files_fetched_from_one_server_continue_from_the_other)
{
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


// Read-only manifest probe, run only with ZCL_PROBE_PEER=host:port (and ZCL_PROBE_OUT=<file>): handshake and
// manifest request, no chunk. Writes one line per file plus a header; skipped otherwise.
BOOST_AUTO_TEST_CASE(probe_manifest_of_a_live_server)
{
    const char* peer = getenv("ZCL_PROBE_PEER");
    const char* out = getenv("ZCL_PROBE_OUT");
    if (!peer || !out)
        return;
    CBootstrapSnapshotManifest m;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BootstrapProbeManifest(peer, m, error), error);
    FILE* f = fopen(out, "w");
    BOOST_REQUIRE(f);
    fprintf(f, "peer %s\nversion %d network %s height %d block %s\nfiles %u bytes %llu chunk %u\nblocktip %d %s\nmanifest_hash %s\nanchor256 %s\nanchor3 %s\n",
            peer, (int)m.nVersion, m.strNetwork.c_str(), m.nHeight, m.hashBlock.ToString().c_str(),
            (unsigned)m.vFiles.size(), (unsigned long long)m.nSnapshotBytes, (unsigned)m.nChunkSize,
            m.nBlockTipHeight, m.hashBlockTip.ToString().c_str(), SerializeHash(m).ToString().c_str(),
            m.hashAnchorSha256.ToString().c_str(), m.hashAnchorSha3.ToString().c_str());
    for (size_t i = 0; i < m.vFiles.size(); ++i)
        fprintf(f, "F %s %llu %s\n", m.vFiles[i].strPath.c_str(), (unsigned long long)m.vFiles[i].nSize, m.vFiles[i].hashSha256.ToString().c_str());
    fclose(f);
}

#endif // !WIN32

BOOST_AUTO_TEST_SUITE_END()
