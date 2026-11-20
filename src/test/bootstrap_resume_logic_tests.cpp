// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bootstrap resume tests, part 1 of 3: the pure decision logic (staging identity, marker, per-file
// verdicts, work queue, reconnect backoff, binary units, progress line), the staging directory
// handling, the interrupted-install recovery and the staged-file scan on a real directory.
// Each part is its own Boost suite.

#include "test/bootstrap_resume_testutil.h"

BOOST_FIXTURE_TEST_SUITE(bootstrap_resume_logic_tests, BasicTestingSetup)

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

// A start after a kill during the install of a downloaded snapshot (pending marker written, then
// blocks/ and chainstate/ renamed out of the staging directory one after the other).
namespace {
void TouchFile(const fs::path& p, const std::string& content = "x")
{
    fs::create_directories(p.parent_path());
    std::ofstream(p.string().c_str(), std::ios::binary) << content;
}
// a datadir as an interrupted install leaves it: which of the directories are installed, which are still staged
fs::path MakeInterruptedInstall(const fs::path& dir, bool blocks, bool chainstate, bool marker, bool stagingBlocks, bool stagingChainstate, bool staging = true)
{
    fs::create_directories(dir);
    if (blocks) TouchFile(dir / "blocks" / "index" / "000001.ldb", "blocks-installed");
    if (chainstate) TouchFile(dir / "chainstate" / "000001.ldb", "chainstate-installed");
    if (marker) BOOST_REQUIRE(WriteBootstrapTrustlessPending(dir, 5, uint256S("01"), uint256S("02")));
    const fs::path st = dir / (std::string(BOOTSTRAP_STAGING_PREFIX) + "0123456789abcdef");
    if (staging) {
        TouchFile(st / BOOTSTRAP_STAGING_MARKER, "z23-bootstrap-staging 1\n");
        if (stagingBlocks) TouchFile(st / "blocks" / "blk00000.dat", "staged-blocks");
        if (stagingChainstate) TouchFile(st / "chainstate" / "000001.ldb", "staged-chainstate");
    }
    return st;
}
} // namespace

BOOST_AUTO_TEST_CASE(interrupted_install_is_recovered_or_refused_never_deleted)
{
    std::string error;
    {   // no marker: the directories are the user's chain data, nothing is touched
        TempDir tmp;
        MakeInterruptedInstall(tmp.path, true, true, false, false, false, false);
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(tmp.path, error), BIR_NONE);
        BOOST_CHECK(fs::exists(tmp.path / "blocks" / "index" / "000001.ldb"));
        BOOST_CHECK(fs::exists(tmp.path / "chainstate" / "000001.ldb"));
        // a lone blocks/ without a marker is not an install either
        TempDir lone;
        MakeInterruptedInstall(lone.path, true, false, false, false, true);
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(lone.path, error), BIR_NONE);
        BOOST_CHECK(fs::exists(lone.path / "blocks" / "index" / "000001.ldb"));
    }
    {   // marker, nothing installed yet: the marker is cleared, the staged snapshot kept
        TempDir tmp;
        const fs::path st = MakeInterruptedInstall(tmp.path, false, false, true, true, true);
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(tmp.path, error), BIR_STALE_MARKER);
        BOOST_CHECK(!BootstrapTrustlessPendingExists(tmp.path));
        BOOST_CHECK(fs::exists(st / "blocks" / "blk00000.dat") && fs::exists(st / "chainstate" / "000001.ldb"));
    }
    {   // both installed: the marker stays for the verification, the staging husk goes
        TempDir tmp;
        const fs::path st = MakeInterruptedInstall(tmp.path, true, true, true, false, false);
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(tmp.path, error), BIR_INSTALLED);
        BOOST_CHECK(BootstrapTrustlessPendingExists(tmp.path));
        BOOST_CHECK(fs::exists(tmp.path / "blocks" / "index" / "000001.ldb"));
        BOOST_CHECK(fs::exists(tmp.path / "chainstate" / "000001.ldb"));
        BOOST_CHECK(!fs::exists(st));
    }
    {   // blocks/ installed, chainstate/ still staged: blocks/ goes back, marker cleared, a second start sees nothing
        TempDir tmp;
        const fs::path st = MakeInterruptedInstall(tmp.path, true, false, true, false, true);
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(tmp.path, error), BIR_ROLLED_BACK);
        BOOST_CHECK(!fs::exists(tmp.path / "blocks"));
        BOOST_CHECK(fs::exists(st / "blocks" / "index" / "000001.ldb"));
        BOOST_CHECK(fs::exists(st / "chainstate" / "000001.ldb"));
        BOOST_CHECK(!BootstrapTrustlessPendingExists(tmp.path));
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(tmp.path, error), BIR_NONE);
    }
    {   // the mirror image (chainstate/ alone, as an unordered power loss could show)
        TempDir tmp;
        const fs::path st = MakeInterruptedInstall(tmp.path, false, true, true, true, false);
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(tmp.path, error), BIR_ROLLED_BACK);
        BOOST_CHECK(!fs::exists(tmp.path / "chainstate"));
        BOOST_CHECK(fs::exists(st / "chainstate" / "000001.ldb") && fs::exists(st / "blocks" / "blk00000.dat"));
    }
    {   // blocks/ with a marker but no staging directory to return it to: refused, untouched
        TempDir tmp;
        MakeInterruptedInstall(tmp.path, true, false, true, false, false, false);
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(tmp.path, error), BIR_REFUSE);
        BOOST_CHECK(error.find("left untouched") != std::string::npos);
        BOOST_CHECK(fs::exists(tmp.path / "blocks" / "index" / "000001.ldb"));
        BOOST_CHECK(BootstrapTrustlessPendingExists(tmp.path));
    }
    {   // a staging directory that still holds its own blocks/ is not where this blocks/ came from
        TempDir tmp;
        MakeInterruptedInstall(tmp.path, true, false, true, true, true);
        BOOST_CHECK_EQUAL(RecoverInterruptedBootstrapInstall(tmp.path, error), BIR_REFUSE);
        BOOST_CHECK(fs::exists(tmp.path / "blocks" / "index" / "000001.ldb"));
    }
}

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
