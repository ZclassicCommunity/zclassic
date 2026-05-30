// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"
#include "bootstrap.h"
#include "bootstrapvalidation.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "crypto/sha256.h"
#include "main.h"
#include "net.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "util.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <iterator>
#include <map>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/test/unit_test.hpp>

// Non-static handler in main.cpp; exposed so we can drive it directly here to
// exercise the Misbehaving paths added for malformed bootstrap-snapshot messages.
extern bool ProcessMessage(CNode* pfrom, std::string strCommand, CDataStream& vRecv, int64_t nTimeReceived);

// Test-only accessor (defined in bootstrap.cpp, not the public header) for the
// per-IP quota tracked-address cap, so the hard-cap eviction test can size its
// flood without hardcoding the constant. Declared at global scope so it links
// against the global-namespace definition.
extern size_t BootstrapServeMaxTrackedIpsForTest();

// Serve-quota bucket-key helper (defined in bootstrap.cpp; collapses an IPv6 /64
// to one quota bucket while keeping IPv4 full-address). Declared at global scope
// so it links against the global-namespace definition, mirroring the other
// test-only seams above.
extern std::string BootstrapServeQuotaKey(const CNetAddr& addr);

// Windowed minimum-throughput watchdog (defined in bootstrap.cpp, not the
// public header). Declared at global scope so it links against the
// global-namespace definition. Caller keeps windowStartMs/bytesAtWindowStart
// as locals; returns true to abort when a full window stayed below the floor.
extern bool BootstrapDownloadTooSlow(int64_t&, uint64_t&, uint64_t, int64_t);

// Test-only seam (defined in bootstrapvalidation.cpp, not the public header) to
// drive a terminal latch so we can verify the finalization-hold flag releases on
// VALIDATED/FAILED without a full chain + background thread.
extern void BootstrapValidationSetTerminalStateForTest(int state);

static CBootstrapSnapshotFile TestBootstrapSnapshotFile()
{
    CBootstrapSnapshotFile file;
    file.strPath = "blocks/blk00000.dat";
    file.nSize = 0x1122334455667788ULL;
    file.hashSha256 = uint256S("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    return file;
}

static void CheckFileEqual(const CBootstrapSnapshotFile& actual, const CBootstrapSnapshotFile& expected)
{
    BOOST_CHECK_EQUAL(actual.strPath, expected.strPath);
    BOOST_CHECK_EQUAL(actual.nSize, expected.nSize);
    BOOST_CHECK(actual.hashSha256 == expected.hashSha256);
}

static CBootstrapSnapshotManifest ValidBootstrapManifest()
{
    const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();

    CBootstrapSnapshotManifest manifest;
    manifest.SetNull();
    manifest.strNetwork = Params().NetworkIDString();
    manifest.nHeight = anchor.nHeight;
    manifest.hashBlock = anchor.hashBlock;
    manifest.hashAnchorSha256 = anchor.hashAnchorSha256;
    manifest.hashAnchorSha3 = anchor.hashAnchorSha3;
    manifest.nChunkSize = BOOTSTRAP_SNAPSHOT_CHUNK_SIZE;

    CBootstrapSnapshotFile file;
    file.strPath = "blocks/blk00000.dat";
    file.nSize = 12;
    file.hashSha256 = uint256S("010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    manifest.vFiles.push_back(file);
    manifest.nSnapshotBytes = file.nSize;
    return manifest;
}

// A well-formed v3 (GROWABLE) manifest: identical to ValidBootstrapManifest()
// except its CHAINSTATE is PINNED at the compiled anchor (nHeight/hashBlock plus
// the reused hashChainstateSerialized commitment, exactly like an accepted v2),
// and it additionally advertises a post-anchor block bundle grown to
// nBlockTipHeight/hashBlockTip. nHeight/hashBlock keep their anchor meaning; the
// new fields carry NO commitment (the client validates the bundled blocks itself).
static CBootstrapSnapshotManifest ValidV3BootstrapManifest()
{
    const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();

    CBootstrapSnapshotManifest manifest = ValidBootstrapManifest();
    manifest.nVersion = 3;
    // The anchor's compiled UTXO commitment (reused v2 field), so the anchor
    // identity matches in both modes.
    manifest.hashChainstateSerialized = anchor.hashChainstateSerialized;
    // The grown block-bundle tip: strictly above the pinned anchor height, with a
    // non-null tip hash.
    manifest.nBlockTipHeight = anchor.nHeight + 5000;
    manifest.hashBlockTip = uint256S("00000000000000000000000000000000000000000000000000000000d00dfeed");
    return manifest;
}

static void RestoreArg(const std::string& arg, bool had_arg, const std::string& value)
{
    if (had_arg) {
        mapArgs[arg] = value;
    } else {
        mapArgs.erase(arg);
    }
}

static void WriteFixtureFile(const boost::filesystem::path& path, const std::string& contents)
{
    boost::filesystem::create_directories(path.parent_path());
    boost::filesystem::ofstream file(path);
    file << contents;
}

// SHA-256 over a byte buffer, computed exactly the way bootstrap.cpp hashes
// snapshot files (CSHA256 -> hex -> uint256), so the round-trip test can check a
// reassembled file against the manifest's per-file hash.
static uint256 Sha256OfBytes(const std::vector<unsigned char>& data)
{
    CSHA256 hasher;
    if (!data.empty()) {
        hasher.Write(&data[0], data.size());
    }
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    return uint256S("0x" + HexStr(digest, digest + CSHA256::OUTPUT_SIZE));
}

// Deterministic pseudo-random bytes so fixtures are reproducible without
// Math.random/time. Distinct `seed`s give distinct file contents.
static std::string DeterministicBytes(size_t n, unsigned int seed)
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

BOOST_FIXTURE_TEST_SUITE(bootstrap_snapshot_protocol_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bootstrap_snapshot_file_serialization)
{
    const CBootstrapSnapshotFile file = TestBootstrapSnapshotFile();
    const std::string expected =
        "13626c6f636b732f626c6b30303030302e646174"
        "8877665544332211"
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << file;

    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), expected);

    CBootstrapSnapshotFile decoded;
    ss >> decoded;
    CheckFileEqual(decoded, file);
    BOOST_CHECK_EQUAL(ss.size(), 0);
}

BOOST_AUTO_TEST_CASE(bootstrap_snapshot_manifest_serialization)
{
    CBootstrapSnapshotManifest manifest;
    manifest.nVersion = 1;
    manifest.strNetwork = "main";
    manifest.nHeight = 123456;
    manifest.hashBlock = uint256S("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    manifest.hashAnchorSha256 = uint256S("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    manifest.hashAnchorSha3 = uint256S("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
    manifest.nSnapshotBytes = 0x123456789abcdef0ULL;
    manifest.nChunkSize = 0x00020000U;
    manifest.vFiles.push_back(TestBootstrapSnapshotFile());

    CBootstrapSnapshotFile file2;
    file2.strPath = "chainstate/000003.ldb";
    file2.nSize = 0x0102030405060708ULL;
    file2.hashSha256 = uint256S("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
    manifest.vFiles.push_back(file2);

    const std::string expected =
        "01000000046d61696e40e20100"
        "3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
        "5f5e5d5c5b5a595857565554535251504f4e4d4c4b4a49484746454443424140"
        "7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160"
        "f0debc9a785634120000020002"
        "13626c6f636b732f626c6b30303030302e6461748877665544332211"
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        "15636861696e73746174652f3030303030332e6c6462080706050403020100"
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << manifest;

    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), expected);

    CBootstrapSnapshotManifest decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.nVersion, manifest.nVersion);
    BOOST_CHECK_EQUAL(decoded.strNetwork, manifest.strNetwork);
    BOOST_CHECK_EQUAL(decoded.nHeight, manifest.nHeight);
    BOOST_CHECK(decoded.hashBlock == manifest.hashBlock);
    BOOST_CHECK(decoded.hashAnchorSha256 == manifest.hashAnchorSha256);
    BOOST_CHECK(decoded.hashAnchorSha3 == manifest.hashAnchorSha3);
    BOOST_CHECK_EQUAL(decoded.nSnapshotBytes, manifest.nSnapshotBytes);
    BOOST_CHECK_EQUAL(decoded.nChunkSize, manifest.nChunkSize);
    BOOST_REQUIRE_EQUAL(decoded.vFiles.size(), manifest.vFiles.size());
    CheckFileEqual(decoded.vFiles[0], manifest.vFiles[0]);
    CheckFileEqual(decoded.vFiles[1], manifest.vFiles[1]);
    BOOST_CHECK_EQUAL(ss.size(), 0);
}

BOOST_AUTO_TEST_CASE(bootstrap_snapshot_manifest_serialization_v2)
{
    // A version-2 manifest is byte-for-byte a version-1 manifest (same field
    // order) with the 32-byte UTXO-set commitment appended at the end. This locks
    // the version-gated wire format so the deployed v1 swarm keeps interoperating:
    // the only differences from the v1 vector above are the leading version word
    // (02 vs 01) and the trailing commitment.
    CBootstrapSnapshotManifest manifest;
    manifest.nVersion = 2;
    manifest.strNetwork = "main";
    manifest.nHeight = 123456;
    manifest.hashBlock = uint256S("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    manifest.hashAnchorSha256 = uint256S("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    manifest.hashAnchorSha3 = uint256S("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
    manifest.nSnapshotBytes = 0x123456789abcdef0ULL;
    manifest.nChunkSize = 0x00020000U;
    manifest.vFiles.push_back(TestBootstrapSnapshotFile());

    CBootstrapSnapshotFile file2;
    file2.strPath = "chainstate/000003.ldb";
    file2.nSize = 0x0102030405060708ULL;
    file2.hashSha256 = uint256S("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
    manifest.vFiles.push_back(file2);

    manifest.hashChainstateSerialized = uint256S("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");

    const std::string expected =
        "02000000046d61696e40e20100"
        "3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
        "5f5e5d5c5b5a595857565554535251504f4e4d4c4b4a49484746454443424140"
        "7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160"
        "f0debc9a785634120000020002"
        "13626c6f636b732f626c6b30303030302e6461748877665544332211"
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        "15636861696e73746174652f3030303030332e6c6462080706050403020100"
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180";

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << manifest;

    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), expected);

    CBootstrapSnapshotManifest decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.nVersion, manifest.nVersion);
    BOOST_CHECK_EQUAL(decoded.strNetwork, manifest.strNetwork);
    BOOST_CHECK_EQUAL(decoded.nHeight, manifest.nHeight);
    BOOST_CHECK(decoded.hashBlock == manifest.hashBlock);
    BOOST_CHECK(decoded.hashAnchorSha256 == manifest.hashAnchorSha256);
    BOOST_CHECK(decoded.hashAnchorSha3 == manifest.hashAnchorSha3);
    BOOST_CHECK_EQUAL(decoded.nSnapshotBytes, manifest.nSnapshotBytes);
    BOOST_CHECK_EQUAL(decoded.nChunkSize, manifest.nChunkSize);
    BOOST_REQUIRE_EQUAL(decoded.vFiles.size(), manifest.vFiles.size());
    CheckFileEqual(decoded.vFiles[0], manifest.vFiles[0]);
    CheckFileEqual(decoded.vFiles[1], manifest.vFiles[1]);
    BOOST_CHECK(decoded.hashChainstateSerialized == manifest.hashChainstateSerialized);
    BOOST_CHECK_EQUAL(ss.size(), 0);
}

BOOST_AUTO_TEST_CASE(bootstrap_snapshot_manifest_serialization_v3)
{
    // A version-3 manifest is byte-for-byte a version-2 manifest (same field
    // order, including the trailing UTXO-set commitment) with two more fields
    // appended at the very end: the GROWABLE post-anchor block-bundle tip height
    // (4-byte LE int) and that tip's block hash (32 bytes). This locks the
    // version-gated wire format so v1 and v2 stay byte-identical: the ONLY
    // differences from the v2 vector are the leading version word (03 vs 02) and
    // the two appended fields. nHeight/hashBlock keep their anchor meaning; the
    // appended fields carry no commitment.
    CBootstrapSnapshotManifest manifest;
    manifest.nVersion = 3;
    manifest.strNetwork = "main";
    manifest.nHeight = 123456;
    manifest.hashBlock = uint256S("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    manifest.hashAnchorSha256 = uint256S("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    manifest.hashAnchorSha3 = uint256S("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
    manifest.nSnapshotBytes = 0x123456789abcdef0ULL;
    manifest.nChunkSize = 0x00020000U;
    manifest.vFiles.push_back(TestBootstrapSnapshotFile());

    CBootstrapSnapshotFile file2;
    file2.strPath = "chainstate/000003.ldb";
    file2.nSize = 0x0102030405060708ULL;
    file2.hashSha256 = uint256S("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
    manifest.vFiles.push_back(file2);

    manifest.hashChainstateSerialized = uint256S("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    // 200000 == 0x00030d40 -> little-endian "400d0300".
    manifest.nBlockTipHeight = 200000;
    manifest.hashBlockTip = uint256S("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");

    const std::string expected =
        "03000000046d61696e40e20100"
        "3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
        "5f5e5d5c5b5a595857565554535251504f4e4d4c4b4a49484746454443424140"
        "7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160"
        "f0debc9a785634120000020002"
        "13626c6f636b732f626c6b30303030302e6461748877665544332211"
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        "15636861696e73746174652f3030303030332e6c6462080706050403020100"
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180"
        "400d0300"
        "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0";

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << manifest;

    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), expected);

    CBootstrapSnapshotManifest decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.nVersion, manifest.nVersion);
    BOOST_CHECK_EQUAL(decoded.strNetwork, manifest.strNetwork);
    BOOST_CHECK_EQUAL(decoded.nHeight, manifest.nHeight);
    BOOST_CHECK(decoded.hashBlock == manifest.hashBlock);
    BOOST_CHECK(decoded.hashAnchorSha256 == manifest.hashAnchorSha256);
    BOOST_CHECK(decoded.hashAnchorSha3 == manifest.hashAnchorSha3);
    BOOST_CHECK_EQUAL(decoded.nSnapshotBytes, manifest.nSnapshotBytes);
    BOOST_CHECK_EQUAL(decoded.nChunkSize, manifest.nChunkSize);
    BOOST_REQUIRE_EQUAL(decoded.vFiles.size(), manifest.vFiles.size());
    CheckFileEqual(decoded.vFiles[0], manifest.vFiles[0]);
    CheckFileEqual(decoded.vFiles[1], manifest.vFiles[1]);
    BOOST_CHECK(decoded.hashChainstateSerialized == manifest.hashChainstateSerialized);
    BOOST_CHECK_EQUAL(decoded.nBlockTipHeight, manifest.nBlockTipHeight);
    BOOST_CHECK(decoded.hashBlockTip == manifest.hashBlockTip);
    BOOST_CHECK_EQUAL(ss.size(), 0);

    // The v3 wire format is a strict superset of v2: the v3 bytes begin with the
    // exact v2 vector (modulo the leading version word) and only append the two
    // new fields. Re-encoding the SAME manifest as v2 (clearing the v3-only
    // fields) must reproduce the v2 prefix byte-for-byte, proving v1/v2 vectors
    // are unchanged and the append is purely additive.
    CBootstrapSnapshotManifest asV2 = manifest;
    asV2.nVersion = 2;
    asV2.nBlockTipHeight = -1;
    asV2.hashBlockTip.SetNull();
    CDataStream ssV2(SER_NETWORK, PROTOCOL_VERSION);
    ssV2 << asV2;
    const std::string v2Hex = HexStr(ssV2.begin(), ssV2.end());
    // The appended v3 fields are 4 + 32 = 36 bytes = 72 hex chars.
    const std::string v3Hex = expected;
    BOOST_REQUIRE_GE(v3Hex.size(), v2Hex.size());
    // v3 minus its 72-char tail, with the version word forced back to 02, equals v2.
    std::string v3Body = v3Hex.substr(0, v3Hex.size() - 72);
    v3Body.replace(0, 8, "02000000");
    BOOST_CHECK_EQUAL(v3Body, v2Hex);
}

BOOST_AUTO_TEST_CASE(bootstrap_snapshot_chunk_request_serialization)
{
    CBootstrapSnapshotChunkRequest request;
    request.nFileIndex = 7;
    request.nOffset = 0x0102030405060708ULL;
    request.nLength = 0x00010000U;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << request;

    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), "07000000080706050403020100000100");

    CBootstrapSnapshotChunkRequest decoded;
    ss >> decoded;
    BOOST_CHECK_EQUAL(decoded.nFileIndex, request.nFileIndex);
    BOOST_CHECK_EQUAL(decoded.nOffset, request.nOffset);
    BOOST_CHECK_EQUAL(decoded.nLength, request.nLength);
    BOOST_CHECK_EQUAL(ss.size(), 0);
}

BOOST_AUTO_TEST_CASE(bootstrap_snapshot_chunk_serialization)
{
    CBootstrapSnapshotChunk chunk;
    chunk.nFileIndex = 7;
    chunk.nOffset = 0x0102030405060708ULL;
    chunk.vData = ParseHex("0011223344");

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << chunk;

    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), "070000000807060504030201050011223344");

    CBootstrapSnapshotChunk decoded;
    ss >> decoded;
    BOOST_CHECK_EQUAL(decoded.nFileIndex, chunk.nFileIndex);
    BOOST_CHECK_EQUAL(decoded.nOffset, chunk.nOffset);
    BOOST_CHECK(decoded.vData == chunk.vData);
    BOOST_CHECK_EQUAL(ss.size(), 0);
}

BOOST_AUTO_TEST_CASE(bootstrap_snapshot_chunk_request_queue)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);

    // Fill the queue until the per-peer cap rejects a request. The cap bounds
    // the bootstrap client's in-flight pipeline window; this test does not hard
    // code its value so it tracks net.cpp's MAX_BOOTSTRAP_CHUNK_REQUESTS_PER_PEER.
    const size_t kSanityCap = 4096;
    size_t accepted = 0;
    for (size_t i = 0; i < kSanityCap; ++i) {
        CBootstrapSnapshotChunkRequest request;
        request.nFileIndex = 1;
        request.nOffset = (uint64_t)i * 512 * 1024;
        request.nLength = 512 * 1024;
        if (!node.QueueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_SNAPSHOT, request)) {
            break;
        }
        ++accepted;
    }
    // The cap must allow real pipelining (more than one) but stay bounded.
    BOOST_CHECK_GT(accepted, 1u);
    BOOST_CHECK_LT(accepted, kSanityCap);

    // A further request is rejected while the queue is full. Param chunks also
    // share the cap (snapshot + params drain through the same queue).
    CBootstrapSnapshotChunkRequest overflow;
    overflow.nFileIndex = 1;
    overflow.nOffset = (uint64_t)accepted * 512 * 1024;
    overflow.nLength = 512 * 1024;
    BOOST_CHECK(!node.QueueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_SNAPSHOT, overflow));
    BOOST_CHECK(!node.QueueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_PARAMS, overflow));

    // Requests pop in FIFO order with their kind tag preserved, and the queue
    // empties after `accepted` pops.
    for (size_t i = 0; i < accepted; ++i) {
        CNode::BootstrapChunkKind poppedKind = CNode::BOOTSTRAP_CHUNK_PARAMS;
        CBootstrapSnapshotChunkRequest popped;
        BOOST_REQUIRE(node.PopBootstrapChunkRequest(poppedKind, popped));
        BOOST_CHECK_EQUAL((int)poppedKind, (int)CNode::BOOTSTRAP_CHUNK_SNAPSHOT);
        BOOST_CHECK_EQUAL(popped.nFileIndex, 1u);
        BOOST_CHECK_EQUAL(popped.nOffset, (uint64_t)i * 512 * 1024);
        BOOST_CHECK_EQUAL(popped.nLength, (uint32_t)(512 * 1024));
    }

    CNode::BootstrapChunkKind emptyKind = CNode::BOOTSTRAP_CHUNK_SNAPSHOT;
    CBootstrapSnapshotChunkRequest popped;
    BOOST_CHECK(!node.PopBootstrapChunkRequest(emptyKind, popped));
}

BOOST_AUTO_TEST_CASE(bootstrap_param_chunk_request_queue_preserves_kind_and_order)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);

    // Interleave snapshot and param chunk requests, then verify the consumer
    // sees each one with its original kind and request fields. This is the
    // contract SendQueuedBootstrapSnapshotChunk relies on to route to the right
    // serve function.
    CBootstrapSnapshotChunkRequest r1;
    r1.nFileIndex = 0; r1.nOffset = 0; r1.nLength = 512 * 1024;
    CBootstrapSnapshotChunkRequest r2;
    r2.nFileIndex = 7; r2.nOffset = 512 * 1024; r2.nLength = 512 * 1024;
    CBootstrapSnapshotChunkRequest r3;
    r3.nFileIndex = 1; r3.nOffset = 1024 * 1024; r3.nLength = 512 * 1024;

    BOOST_REQUIRE(node.QueueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_SNAPSHOT, r1));
    BOOST_REQUIRE(node.QueueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_PARAMS, r2));
    BOOST_REQUIRE(node.QueueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_SNAPSHOT, r3));

    CNode::BootstrapChunkKind k = CNode::BOOTSTRAP_CHUNK_PARAMS;
    CBootstrapSnapshotChunkRequest got;
    BOOST_REQUIRE(node.PopBootstrapChunkRequest(k, got));
    BOOST_CHECK_EQUAL((int)k, (int)CNode::BOOTSTRAP_CHUNK_SNAPSHOT);
    BOOST_CHECK_EQUAL(got.nFileIndex, 0u);

    BOOST_REQUIRE(node.PopBootstrapChunkRequest(k, got));
    BOOST_CHECK_EQUAL((int)k, (int)CNode::BOOTSTRAP_CHUNK_PARAMS);
    BOOST_CHECK_EQUAL(got.nFileIndex, 7u);

    // Requeue must preserve kind too: the front of the queue becomes the
    // requeued item, and a subsequent pop returns it with the same kind tag.
    node.RequeueBootstrapChunkRequest(CNode::BOOTSTRAP_CHUNK_PARAMS, r2);
    BOOST_REQUIRE(node.PopBootstrapChunkRequest(k, got));
    BOOST_CHECK_EQUAL((int)k, (int)CNode::BOOTSTRAP_CHUNK_PARAMS);
    BOOST_CHECK_EQUAL(got.nFileIndex, 7u);

    BOOST_REQUIRE(node.PopBootstrapChunkRequest(k, got));
    BOOST_CHECK_EQUAL((int)k, (int)CNode::BOOTSTRAP_CHUNK_SNAPSHOT);
    BOOST_CHECK_EQUAL(got.nFileIndex, 1u);
}

BOOST_AUTO_TEST_CASE(bootstrap_param_chunk_enqueue_validates_envelope)
{
    const bool hadServe = mapArgs.count("-bootstrapserve");
    const std::string oldServe = hadServe ? mapArgs["-bootstrapserve"] : "";

    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);

    // Without -bootstrapserve the enqueue is refused regardless of fields.
    mapArgs.erase("-bootstrapserve");
    std::string error;
    CBootstrapSnapshotChunkRequest request;
    request.nFileIndex = 0;
    request.nOffset = 0;
    request.nLength = 512 * 1024;
    BOOST_CHECK(!EnqueueBootstrapParamChunkRequest(&node, request, error));
    BOOST_CHECK(error.find("not enabled") != std::string::npos);

    // With service enabled, length and offset are validated symmetrically with
    // the snapshot enqueue path (param files use the same alignment).
    mapArgs["-bootstrapserve"] = "1";

    request.nLength = 0;
    BOOST_CHECK(!EnqueueBootstrapParamChunkRequest(&node, request, error));
    BOOST_CHECK(error.find("length") != std::string::npos);

    request.nLength = BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE + 1;
    BOOST_CHECK(!EnqueueBootstrapParamChunkRequest(&node, request, error));
    BOOST_CHECK(error.find("length") != std::string::npos);

    request.nLength = 512 * 1024;
    request.nOffset = 1; // misaligned
    BOOST_CHECK(!EnqueueBootstrapParamChunkRequest(&node, request, error));
    BOOST_CHECK(error.find("aligned") != std::string::npos);

    // A well-formed request enqueues with the PARAMS kind tag so the drain
    // routes to ReadZcashParamChunk rather than ReadBootstrapSnapshotChunk.
    request.nOffset = 0;
    BOOST_REQUIRE(EnqueueBootstrapParamChunkRequest(&node, request, error));
    CNode::BootstrapChunkKind k = CNode::BOOTSTRAP_CHUNK_SNAPSHOT;
    CBootstrapSnapshotChunkRequest popped;
    BOOST_REQUIRE(node.PopBootstrapChunkRequest(k, popped));
    BOOST_CHECK_EQUAL((int)k, (int)CNode::BOOTSTRAP_CHUNK_PARAMS);

    RestoreArg("-bootstrapserve", hadServe, oldServe);
}

BOOST_AUTO_TEST_CASE(bootstrap_param_chunk_drains_through_serve_quota)
{
    // Param chunks served via the queue path go through the same per-IP
    // BootstrapServeChargeBytes accounting as snapshot chunks. We can't easily
    // call SendQueuedBootstrapSnapshotChunk in a unit test (it pushes on a
    // socket), but we can verify the quota path itself accumulates the same
    // way for any caller -- snapshot or params -- by charging both kinds and
    // checking the cumulative ledger.
    const bool hadCap = mapArgs.count("-bootstrapservemaxbytesperday");
    const bool hadKbps = mapArgs.count("-bootstrapservethrottlekbps");
    const std::string oldCap = hadCap ? mapArgs["-bootstrapservemaxbytesperday"] : "";
    const std::string oldKbps = hadKbps ? mapArgs["-bootstrapservethrottlekbps"] : "";

    ClearBootstrapServeQuota();
    mapArgs["-bootstrapservemaxbytesperday"] = "1000";
    mapArgs["-bootstrapservethrottlekbps"] = "0"; // hard stop

    const int64_t t0 = 1000000;
    const std::string ip = "198.51.100.3";
    bool stop = false;

    // Snapshot bytes and param bytes accumulate against the same daily cap.
    BootstrapServeChargeBytes(ip, /*whitelisted=*/false, t0, 400);   // snapshot serve
    BootstrapServeChargeBytes(ip, /*whitelisted=*/false, t0, 400);   // param serve
    BOOST_CHECK(BootstrapServeAllowChunk(ip, false, t0, stop));       // 800 < 1000
    BOOST_CHECK(!stop);
    BootstrapServeChargeBytes(ip, /*whitelisted=*/false, t0, 400);   // 1200 >= 1000
    BOOST_CHECK(!BootstrapServeAllowChunk(ip, false, t0, stop));      // over cap
    BOOST_CHECK(stop);

    ClearBootstrapServeQuota();
    RestoreArg("-bootstrapservemaxbytesperday", hadCap, oldCap);
    RestoreArg("-bootstrapservethrottlekbps", hadKbps, oldKbps);
}

BOOST_AUTO_TEST_CASE(bootstrap_serve_quota_throttle_and_stop)
{
    const bool hadCap = mapArgs.count("-bootstrapservemaxbytesperday");
    const bool hadKbps = mapArgs.count("-bootstrapservethrottlekbps");
    const std::string oldCap = hadCap ? mapArgs["-bootstrapservemaxbytesperday"] : "";
    const std::string oldKbps = hadKbps ? mapArgs["-bootstrapservethrottlekbps"] : "";

    const int64_t t0 = 1000000;
    const std::string ip = "203.0.113.7";
    bool stop = false;

    // --- Hard-stop mode: throttle rate 0, cap 1000 bytes ---
    ClearBootstrapServeQuota();
    mapArgs["-bootstrapservemaxbytesperday"] = "1000";
    mapArgs["-bootstrapservethrottlekbps"] = "0";

    BOOST_CHECK(BootstrapServeAllowChunk(ip, false, t0, stop));        // nothing served yet
    BootstrapServeChargeBytes(ip, false, t0, 600);
    BOOST_CHECK(BootstrapServeAllowChunk(ip, false, t0, stop));        // 600 < 1000
    BOOST_CHECK(!stop);
    BootstrapServeChargeBytes(ip, false, t0, 600);                    // now 1200 >= 1000
    BOOST_CHECK(!BootstrapServeAllowChunk(ip, false, t0, stop));       // over cap, stop
    BOOST_CHECK(stop);

    // Whitelisted peers bypass the quota entirely.
    BOOST_CHECK(BootstrapServeAllowChunk(ip, true, t0, stop));
    BOOST_CHECK(!stop);

    // Window rollover clears the cap.
    BOOST_CHECK(BootstrapServeAllowChunk(ip, false, t0 + 24 * 60 * 60 * 1000LL, stop));

    // --- Throttle mode: 1 KiB/s, cap 1000 bytes ---
    ClearBootstrapServeQuota();
    mapArgs["-bootstrapservemaxbytesperday"] = "1000";
    mapArgs["-bootstrapservethrottlekbps"] = "1"; // 1024 bytes/s

    BootstrapServeChargeBytes(ip, false, t0, 1000);                   // reaches cap; bytes=1024B/s
    // 1000 bytes at 1024 B/s schedules the next send ~976ms out.
    BOOST_CHECK(!BootstrapServeAllowChunk(ip, false, t0 + 500, stop)); // too soon
    BOOST_CHECK(!stop);                                                // throttled, not stopped
    BOOST_CHECK(BootstrapServeAllowChunk(ip, false, t0 + 1000, stop)); // gap elapsed

    // --- Unlimited: cap 0 ---
    ClearBootstrapServeQuota();
    mapArgs["-bootstrapservemaxbytesperday"] = "0";
    BootstrapServeChargeBytes(ip, false, t0, 1000000000);
    BOOST_CHECK(BootstrapServeAllowChunk(ip, false, t0, stop));
    BOOST_CHECK(!stop);

    ClearBootstrapServeQuota();
    RestoreArg("-bootstrapservemaxbytesperday", hadCap, oldCap);
    RestoreArg("-bootstrapservethrottlekbps", hadKbps, oldKbps);
}

BOOST_AUTO_TEST_CASE(bootstrap_serve_global_aggregate_caps)
{
    // The per-IP quota keys on address group, so an attacker spread across many /64s
    // can still sum to unbounded aggregate upload. The opt-in process-wide caps bound
    // it. Defaults (0/0) are a no-op; whitelisted peers always bypass.
    const bool hadKbps = mapArgs.count("-bootstrapservemaxtotalkbps");
    const bool hadPeers = mapArgs.count("-bootstrapservemaxpeers");
    const std::string oldKbps = hadKbps ? mapArgs["-bootstrapservemaxtotalkbps"] : "";
    const std::string oldPeers = hadPeers ? mapArgs["-bootstrapservemaxpeers"] : "";
    const int64_t t0 = 2000000;

    // --- aggregate byte-rate cap: 8 kbit/s = 1000 bytes over the 1s window ---
    ClearBootstrapServeGlobal();
    mapArgs["-bootstrapservemaxtotalkbps"] = "8";
    mapArgs["-bootstrapservemaxpeers"] = "0"; // peer cap off
    BOOST_CHECK(BootstrapServeGlobalAllow(1, false, 600, t0));            // 600 <= 1000
    BootstrapServeGlobalCharge(1, false, 600, t0);
    BOOST_CHECK(BootstrapServeGlobalAllow(2, false, 400, t0));            // 600+400 == 1000
    BootstrapServeGlobalCharge(2, false, 400, t0);
    BOOST_CHECK(!BootstrapServeGlobalAllow(3, false, 1, t0));             // 1001 > 1000 -> defer
    BOOST_CHECK(BootstrapServeGlobalAllow(3, false, 600, t0 + 1000));     // window rollover clears it
    BOOST_CHECK(BootstrapServeGlobalAllow(99, true, 1000000000, t0));     // whitelisted bypass

    // --- concurrent-serving-peer cap ---
    ClearBootstrapServeGlobal();
    mapArgs["-bootstrapservemaxtotalkbps"] = "0"; // rate cap off
    mapArgs["-bootstrapservemaxpeers"] = "2";
    BOOST_CHECK(BootstrapServeGlobalAllow(10, false, 100, t0)); BootstrapServeGlobalCharge(10, false, 100, t0);
    BOOST_CHECK(BootstrapServeGlobalAllow(11, false, 100, t0)); BootstrapServeGlobalCharge(11, false, 100, t0);
    BOOST_CHECK(!BootstrapServeGlobalAllow(12, false, 100, t0));          // 3rd new peer deferred (2 active)
    BOOST_CHECK(BootstrapServeGlobalAllow(10, false, 100, t0));           // already-active peer continues
    BOOST_CHECK(BootstrapServeGlobalAllow(12, true, 100, t0));            // whitelisted bypass
    BOOST_CHECK(BootstrapServeGlobalAllow(12, false, 100, t0 + 1000));    // idle peers aged out -> slot frees

    // --- both unlimited (default): never defers, however much is served ---
    ClearBootstrapServeGlobal();
    mapArgs["-bootstrapservemaxtotalkbps"] = "0";
    mapArgs["-bootstrapservemaxpeers"] = "0";
    for (int i = 0; i < 500; ++i) {
        BOOST_CHECK(BootstrapServeGlobalAllow(i, false, 1000000, t0));
        BootstrapServeGlobalCharge(i, false, 1000000, t0);
    }

    ClearBootstrapServeGlobal();
    RestoreArg("-bootstrapservemaxtotalkbps", hadKbps, oldKbps);
    RestoreArg("-bootstrapservemaxpeers", hadPeers, oldPeers);
}

BOOST_AUTO_TEST_CASE(bootstrap_serve_quota_hard_caps_tracked_ips)
{
    // The per-IP quota map must stay bounded even when every tracked window is
    // still active (an attacker cycling through many distinct source IPs within
    // the same 24h window). The old eviction sweep only dropped fully-expired
    // windows, so this exercised the new hard-cap eviction of the oldest-window
    // entry. The map size is file-local in bootstrap.cpp, so we observe the
    // bound behaviorally: a "victim" IP charged over the cap at the earliest
    // window must be evicted once enough newer IPs are tracked, after which it
    // is no longer rate-limited (AllowChunk returns true because it is gone).
    const bool hadCap = mapArgs.count("-bootstrapservemaxbytesperday");
    const bool hadKbps = mapArgs.count("-bootstrapservethrottlekbps");
    const std::string oldCap = hadCap ? mapArgs["-bootstrapservemaxbytesperday"] : "";
    const std::string oldKbps = hadKbps ? mapArgs["-bootstrapservethrottlekbps"] : "";

    ClearBootstrapServeQuota();
    mapArgs["-bootstrapservemaxbytesperday"] = "1000";
    mapArgs["-bootstrapservethrottlekbps"] = "0"; // hard stop once over cap

    const int64_t tVictim = 1000000;     // earliest window -> oldest, evicted first
    const int64_t tFlood = tVictim + 1;  // 1ms later: still well within the 24h window
    const std::string victim = "198.51.100.123";

    // Charge the victim over the daily cap; it is now tracked and rate-limited.
    BootstrapServeChargeBytes(victim, /*whitelisted=*/false, tVictim, 2000);
    bool stop = false;
    BOOST_CHECK(!BootstrapServeAllowChunk(victim, false, tVictim, stop)); // over cap
    BOOST_CHECK(stop);

    // Flood the map with strictly more than the cap of distinct, active IPs.
    // None of these windows have expired (same tFlood), so only the new
    // hard-cap eviction can keep the map bounded -- and the victim (oldest
    // windowStartMs) is the one that must be dropped.
    const size_t cap_ips = BootstrapServeMaxTrackedIpsForTest();
    for (size_t i = 0; i <= cap_ips; ++i) {
        BootstrapServeChargeBytes(strprintf("10.%u.%u.%u",
                                            (unsigned)((i >> 16) & 0xff),
                                            (unsigned)((i >> 8) & 0xff),
                                            (unsigned)(i & 0xff)),
                                  /*whitelisted=*/false, tFlood, 1);
    }

    // The victim has been evicted: it is no longer tracked, so it is treated as
    // a fresh address and allowed again despite having been charged over cap.
    stop = false;
    BOOST_CHECK(BootstrapServeAllowChunk(victim, false, tFlood, stop));
    BOOST_CHECK(!stop);

    ClearBootstrapServeQuota();
    RestoreArg("-bootstrapservemaxbytesperday", hadCap, oldCap);
    RestoreArg("-bootstrapservethrottlekbps", hadKbps, oldKbps);
}

BOOST_AUTO_TEST_CASE(bootstrap_serve_quota_keys_ipv6_by_64_prefix)
{
    // The serve quota must be keyed on the address GROUP/prefix (IPv6 /64, full
    // IPv4) so an attacker rotating through a trivially-available IPv6 /64 -- or
    // a botnet spread across one -- shares a single quota bucket instead of
    // getting a fresh bucket per address.

    // Two distinct hosts in the SAME /64 collapse to one key...
    const CNetAddr a("2001:db8:abcd:1234::1");
    const CNetAddr b("2001:db8:abcd:1234:ffff:ffff:ffff:fffe");
    BOOST_CHECK_EQUAL(BootstrapServeQuotaKey(a), BootstrapServeQuotaKey(b));

    // ...but a DIFFERENT /64 (one bit different in the 8th network byte) does not.
    const CNetAddr c("2001:db8:abcd:1235::1");
    BOOST_CHECK(BootstrapServeQuotaKey(a) != BootstrapServeQuotaKey(c));

    // IPv4 stays full-address: two distinct IPv4 hosts must NOT collapse, even in
    // the same /16 (the GetGroup() granularity we deliberately avoided).
    const CNetAddr v4a("203.0.113.7");
    const CNetAddr v4b("203.0.113.8");
    BOOST_CHECK(BootstrapServeQuotaKey(v4a) != BootstrapServeQuotaKey(v4b));
    BOOST_CHECK_EQUAL(BootstrapServeQuotaKey(v4a), std::string("203.0.113.7"));

    // Behavioral check: charging one address in the /64 over the cap rate-limits
    // the OTHER address in the same /64 (shared bucket).
    const bool hadCap = mapArgs.count("-bootstrapservemaxbytesperday");
    const bool hadKbps = mapArgs.count("-bootstrapservethrottlekbps");
    const std::string oldCap = hadCap ? mapArgs["-bootstrapservemaxbytesperday"] : "";
    const std::string oldKbps = hadKbps ? mapArgs["-bootstrapservethrottlekbps"] : "";

    ClearBootstrapServeQuota();
    mapArgs["-bootstrapservemaxbytesperday"] = "1000";
    mapArgs["-bootstrapservethrottlekbps"] = "0"; // hard stop once over cap

    const int64_t t0 = 1000000;
    bool stop = false;
    const std::string keyA = BootstrapServeQuotaKey(a);
    const std::string keyB = BootstrapServeQuotaKey(b);
    BOOST_CHECK_EQUAL(keyA, keyB);

    BootstrapServeChargeBytes(keyA, /*whitelisted=*/false, t0, 2000); // over cap via host A
    // Host B in the same /64 is now rate-limited despite never being charged.
    BOOST_CHECK(!BootstrapServeAllowChunk(keyB, false, t0, stop));
    BOOST_CHECK(stop);

    // A host in a different /64 is unaffected.
    BOOST_CHECK(BootstrapServeAllowChunk(BootstrapServeQuotaKey(c), false, t0, stop));
    BOOST_CHECK(!stop);

    ClearBootstrapServeQuota();
    RestoreArg("-bootstrapservemaxbytesperday", hadCap, oldCap);
    RestoreArg("-bootstrapservethrottlekbps", hadKbps, oldKbps);
}

BOOST_AUTO_TEST_CASE(bootstrap_download_throughput_watchdog)
{
    // BootstrapDownloadTooSlow is a windowed minimum-throughput watchdog the
    // bootstrap *client* runs while downloading a snapshot. The caller keeps
    // windowStartMs/bytesAtWindowStart as locals (seeded to the download start
    // time and 0) and calls after each chunk with cumulative bytes and now.
    // It returns true only when a full window elapsed below the byte/sec floor.
    //
    // The exact floor (~32 KiB/s) and window (~60s) are file-local constants in
    // bootstrap.cpp and not visible here, so every case below uses rates and
    // elapsed times that are obviously above/below or larger/smaller than any
    // plausible value, so the test does not depend on the precise constants.
    const int64_t t0 = 1000000;

    // (a) Before a window completes, it never aborts. A zero-elapsed call and a
    // small elapsed clearly under any plausible window both return false even
    // with no bytes received -- there is no completed window to judge yet.
    {
        int64_t ws = t0;
        uint64_t bws = 0;
        BOOST_CHECK(!BootstrapDownloadTooSlow(ws, bws, 0, t0));          // elapsed 0
        BOOST_CHECK(!BootstrapDownloadTooSlow(ws, bws, 0, t0 + 1000));   // 1s, far under window
    }

    // (b) Trickle: a full window (well over any plausible window) elapses with
    // almost no bytes -- ~1.7 B/s for 1 KiB over 10 minutes -- far below any
    // plausible floor, so the watchdog aborts. Fresh state so (a) cannot leak in.
    {
        int64_t ws = t0;
        uint64_t bws = 0;
        const int64_t now = t0 + 10 * 60 * 1000; // 10 minutes
        BOOST_CHECK(BootstrapDownloadTooSlow(ws, bws, 1024, now)); // ~1.7 B/s -> abort
    }

    // (c) Healthy window: a full window elapses with plenty of bytes (~1 MiB/s
    // over 10 minutes), far above any plausible floor, so it does not abort and
    // it advances the window bookkeeping to the current point.
    {
        int64_t ws = t0;
        uint64_t bws = 0;
        const int64_t now = t0 + 10 * 60 * 1000;               // 600s
        const uint64_t total = (uint64_t)600 * 1024 * 1024;    // 600 MiB (~1 MiB/s)
        BOOST_CHECK(!BootstrapDownloadTooSlow(ws, bws, total, now));
        // A healthy completed window resets the baseline to "now" so the next
        // window is measured from here forward.
        BOOST_CHECK_EQUAL(ws, now);
        BOOST_CHECK_EQUAL(bws, total);
    }

    // (d) Late stall caught despite a fast start. This is the key case proving
    // the watchdog is windowed, not a cumulative average: a peer cannot bank
    // early speed to cover a later stall.
    {
        int64_t ws = t0;
        uint64_t bws = 0;

        // First window is healthy (~1 MiB/s), so no abort and the baseline
        // advances to (now1, 600 MiB).
        const int64_t now1 = t0 + 600 * 1000;                  // +600s
        const uint64_t bytes1 = (uint64_t)600 * 1024 * 1024;   // 600 MiB
        BOOST_CHECK(!BootstrapDownloadTooSlow(ws, bws, bytes1, now1));
        BOOST_CHECK_EQUAL(ws, now1);
        BOOST_CHECK_EQUAL(bws, bytes1);

        // Second window: another full window elapses but only 1 KiB more arrives
        // *within that new window*. Even though the cumulative average over the
        // whole download is still ~0.5 MiB/s, the new window alone is ~1.7 B/s,
        // so the watchdog aborts.
        const int64_t now2 = now1 + 600 * 1000;                // another +600s
        const uint64_t bytes2 = bytes1 + 1024;                 // +1 KiB only
        BOOST_CHECK(BootstrapDownloadTooSlow(ws, bws, bytes2, now2)); // late stall -> abort
    }
}

BOOST_AUTO_TEST_CASE(bootstrap_network_message_roundtrip)
{
    CBootstrapSnapshotChunkRequest request;
    request.nFileIndex = 3;
    request.nOffset = 512 * 1024;
    request.nLength = 512 * 1024;

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << request;

    CSerializeData message;
    std::string error;
    BOOST_CHECK(BuildBootstrapNetworkMessage(NetMsgType::GETBSCHK, payload, message, error));
    BOOST_CHECK(error.empty());

    std::string command;
    CDataStream decodedPayload(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(DecodeBootstrapNetworkMessage(message, command, decodedPayload, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(command, NetMsgType::GETBSCHK);

    CBootstrapSnapshotChunkRequest decoded;
    decodedPayload >> decoded;
    BOOST_CHECK_EQUAL(decoded.nFileIndex, request.nFileIndex);
    BOOST_CHECK_EQUAL(decoded.nOffset, request.nOffset);
    BOOST_CHECK_EQUAL(decoded.nLength, request.nLength);
    BOOST_CHECK_EQUAL(decodedPayload.size(), 0);
}

BOOST_AUTO_TEST_CASE(bootstrap_network_message_empty_payload)
{
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    CSerializeData message;
    std::string error;
    BOOST_CHECK(BuildBootstrapNetworkMessage(NetMsgType::GETBSMAN, payload, message, error));

    std::string command;
    CDataStream decodedPayload(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(DecodeBootstrapNetworkMessage(message, command, decodedPayload, error));
    BOOST_CHECK_EQUAL(command, NetMsgType::GETBSMAN);
    BOOST_CHECK_EQUAL(decodedPayload.size(), 0);
}

BOOST_AUTO_TEST_CASE(bootstrap_network_message_checksum_failure)
{
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint32_t(1);

    CSerializeData message;
    std::string error;
    BOOST_CHECK(BuildBootstrapNetworkMessage(NetMsgType::GETBSCHK, payload, message, error));
    BOOST_REQUIRE_GT(message.size(), CMessageHeader::HEADER_SIZE);
    message.back() ^= 0x01;

    std::string command;
    CDataStream decodedPayload(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(!DecodeBootstrapNetworkMessage(message, command, decodedPayload, error));
    BOOST_CHECK(error.find("checksum") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(bootstrap_network_message_header_failures)
{
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint32_t(1);

    CSerializeData message;
    std::string error;
    BOOST_CHECK(BuildBootstrapNetworkMessage(NetMsgType::GETBSCHK, payload, message, error));
    BOOST_REQUIRE_GT(message.size(), CMessageHeader::HEADER_SIZE);

    CSerializeData badStart = message;
    badStart[0] ^= 0x01;
    std::string command;
    CDataStream decodedPayload(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(!DecodeBootstrapNetworkMessage(badStart, command, decodedPayload, error));
    BOOST_CHECK(error.find("header") != std::string::npos);

    CSerializeData truncated = message;
    truncated.pop_back();
    BOOST_CHECK(!DecodeBootstrapNetworkMessage(truncated, command, decodedPayload, error));
    BOOST_CHECK(error.find("size mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(bootstrap_fresh_chain_datadir_checks_chain_files)
{
    boost::filesystem::path root = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("zclassic-bootstrap-fresh-%%%%-%%%%-%%%%");
    boost::filesystem::create_directories(root);

    std::string error;
    BOOST_CHECK(IsBootstrapFreshChainDatadir(root, error));

    boost::filesystem::create_directories(root / "blocks");
    BOOST_CHECK(!IsBootstrapFreshChainDatadir(root, error));
    BOOST_CHECK(error.find("blocks") != std::string::npos);
    boost::filesystem::remove_all(root / "blocks");

    boost::filesystem::create_directories(root / "chainstate");
    BOOST_CHECK(!IsBootstrapFreshChainDatadir(root, error));
    BOOST_CHECK(error.find("chainstate") != std::string::npos);
    boost::filesystem::remove_all(root / "chainstate");

    {
        boost::filesystem::ofstream file(root / "bootstrap.dat");
        file << "bootstrap";
    }
    BOOST_CHECK(!IsBootstrapFreshChainDatadir(root, error));
    BOOST_CHECK(error.find("bootstrap.dat") != std::string::npos);
    boost::filesystem::remove(root / "bootstrap.dat");

    {
        boost::filesystem::ofstream file(root / "blk00000.dat");
        file << "block";
    }
    BOOST_CHECK(!IsBootstrapFreshChainDatadir(root, error));
    BOOST_CHECK(error.find("legacy block file") != std::string::npos);

    boost::filesystem::remove_all(root);
}

BOOST_AUTO_TEST_CASE(bootstrap_import_datadir_refuses_existing_without_force)
{
    boost::filesystem::path source = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("zclassic-bootstrap-import-source-%%%%-%%%%-%%%%");
    boost::filesystem::path dest = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("zclassic-bootstrap-import-dest-%%%%-%%%%-%%%%");

    WriteFixtureFile(source / "blocks" / "blk00000.dat", "source-block");
    WriteFixtureFile(source / "blocks" / "index" / "000001.ldb", "source-index");
    WriteFixtureFile(source / "chainstate" / "000003.ldb", "source-state");
    WriteFixtureFile(dest / "blocks" / "blk00000.dat", "existing-block");

    std::string error;
    BOOST_CHECK(!ImportBootstrapDatadir(source, dest, false, error));
    BOOST_CHECK(error.find("bootstrapforce") != std::string::npos);
    BOOST_CHECK(boost::filesystem::exists(dest / "blocks" / "blk00000.dat"));

    boost::filesystem::remove_all(source);
    boost::filesystem::remove_all(dest);
}

BOOST_AUTO_TEST_CASE(bootstrap_import_datadir_force_backs_up_and_replaces)
{
    boost::filesystem::path source = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("zclassic-bootstrap-import-source-%%%%-%%%%-%%%%");
    boost::filesystem::path dest = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("zclassic-bootstrap-import-dest-%%%%-%%%%-%%%%");

    WriteFixtureFile(source / "blocks" / "blk00000.dat", "source-block");
    WriteFixtureFile(source / "blocks" / "index" / "000001.ldb", "source-index");
    WriteFixtureFile(source / "chainstate" / "000003.ldb", "source-state");
    WriteFixtureFile(dest / "blocks" / "blk00000.dat", "existing-block");
    WriteFixtureFile(dest / "chainstate" / "000003.ldb", "existing-state");

    std::string error;
    BOOST_REQUIRE(ImportBootstrapDatadir(source, dest, true, error));
    BOOST_CHECK(boost::filesystem::exists(dest / "blocks" / "blk00000.dat"));
    BOOST_CHECK(boost::filesystem::exists(dest / "chainstate" / "000003.ldb"));
    BOOST_CHECK_EQUAL(boost::filesystem::file_size(dest / "blocks" / "blk00000.dat"), 12);
    BOOST_CHECK_EQUAL(boost::filesystem::file_size(dest / "chainstate" / "000003.ldb"), 12);

    bool found_backup = false;
    boost::filesystem::directory_iterator end;
    for (boost::filesystem::directory_iterator it(dest); it != end; ++it) {
        if (boost::filesystem::is_directory(it->path()) &&
            it->path().filename().string().find("bootstrap-backup-") == 0) {
            found_backup = true;
        }
    }
    BOOST_CHECK(found_backup);

    boost::filesystem::remove_all(source);
    boost::filesystem::remove_all(dest);
}

BOOST_AUTO_TEST_CASE(bootstrap_manifest_validation_rejects_bad_metadata)
{
    std::string error;
    CBootstrapSnapshotManifest manifest = ValidBootstrapManifest();
    BOOST_CHECK(ValidateBootstrapSnapshotManifest(manifest, error));

    // An unsupported manifest version is rejected as a version error. v3 is now a
    // valid version (the growable post-anchor block bundle), so use 4 here.
    manifest = ValidBootstrapManifest();
    manifest.nVersion = 4;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("version") != std::string::npos);

    // A v2 self-snapshot (commitment present, not equal to the compiled anchor) is
    // rejected in the default anchor mode, but accepted in trustless mode (its
    // contents are verified after download, not here). The tip must be strictly
    // above the last compiled checkpoint (SEC-TRUST-1) for trustless to accept it,
    // so use a height above the anchor/checkpoint.
    manifest = ValidBootstrapManifest();
    manifest.nVersion = 2;
    manifest.nHeight = Params().FastSyncAnchor().nHeight + 1000;
    manifest.hashChainstateSerialized = uint256S("0101010101010101010101010101010101010101010101010101010101010101");
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
    BOOST_CHECK(ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));

    // A v2 manifest missing its commitment is rejected even in trustless mode.
    manifest = ValidBootstrapManifest();
    manifest.nVersion = 2;
    manifest.hashChainstateSerialized.SetNull();
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));
    BOOST_CHECK(error.find("commitment") != std::string::npos);

    manifest = ValidBootstrapManifest();
    manifest.strNetwork = "wrong";
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("network") != std::string::npos);

    manifest = ValidBootstrapManifest();
    manifest.nChunkSize = BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE + 1;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("chunk") != std::string::npos);

    // WIRE-N1: the chunk size must be EXACTLY BOOTSTRAP_SNAPSHOT_CHUNK_SIZE, not
    // merely <= MAX. A smaller-but-otherwise-valid size would pass the old ceiling
    // check yet stall mid-download (the serve path only aligns to the compiled
    // size), so it must be rejected up front. This case is distinct from the
    // oversize one above precisely because CHUNK_SIZE == MAX_CHUNK_SIZE today.
    manifest = ValidBootstrapManifest();
    manifest.nChunkSize = BOOTSTRAP_SNAPSHOT_CHUNK_SIZE / 2;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("chunk") != std::string::npos);

    manifest = ValidBootstrapManifest();
    manifest.vFiles[0].strPath = "../blocks/blk00000.dat";
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("unsafe") != std::string::npos);

    manifest = ValidBootstrapManifest();
    manifest.vFiles[0].hashSha256.SetNull();
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("SHA-256") != std::string::npos);

    manifest = ValidBootstrapManifest();
    manifest.nSnapshotBytes += 1;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("sizes") != std::string::npos);

    manifest = ValidBootstrapManifest();
    manifest.vFiles.push_back(manifest.vFiles[0]);
    manifest.nSnapshotBytes += manifest.vFiles[0].nSize;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("duplicate") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(bootstrap_manifest_validation_matches_compiled_anchor)
{
    // The validator matches a manifest against the compiled fast-sync anchor SET
    // (FindFastSyncAnchor) and accepts ANY compiled anchor, not just the primary.
    // These run under MAIN params, which compile in one anchor, so they exercise
    // the lookup + per-anchor field checks against it. (Accepting a genuinely
    // older second anchor is the same lookup over a longer vector — covered by the
    // FindFastSyncAnchor unit test below and the two-node regtest E2E.)
    std::string error;
    const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();

    // A v1 manifest equal to a compiled anchor validates.
    CBootstrapSnapshotManifest manifest = ValidBootstrapManifest();
    BOOST_CHECK(ValidateBootstrapSnapshotManifest(manifest, error));

    // Right anchor height but a different block hash matches no compiled anchor.
    manifest = ValidBootstrapManifest();
    manifest.hashBlock = uint256S("00000000000000000000000000000000000000000000000000000000deadbeef");
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("anchor") != std::string::npos);

    // Right (height, hash) but a tampered decorative SHA digest is rejected.
    manifest = ValidBootstrapManifest();
    manifest.hashAnchorSha256 = uint256S("0101010101010101010101010101010101010101010101010101010101010101");
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));

    // A v2 manifest in anchor mode is accepted only when it equals a compiled
    // anchor AND commits to that anchor's compiled UTXO commitment. Every shipped
    // anchor is now guaranteed to carry a non-null commitment (enforced at startup
    // by Checkpoints::ValidateFastSyncAnchor), so this assertion is unconditional.
    BOOST_REQUIRE(!anchor.hashChainstateSerialized.IsNull());
    manifest = ValidBootstrapManifest();
    manifest.nVersion = 2;
    manifest.hashChainstateSerialized = anchor.hashChainstateSerialized;
    BOOST_CHECK(ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));

    // Same anchor identity but the wrong commitment is rejected in anchor mode.
    manifest.hashChainstateSerialized = uint256S("0202020202020202020202020202020202020202020202020202020202020202");
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));

    // A v2 anchor-mode manifest carrying a NULL commitment but a valid compiled
    // anchor identity must be rejected: the node has no compiled value to verify
    // it against, so it cannot be trusted in anchor mode (SEC-1 surface).
    manifest = ValidBootstrapManifest();
    manifest.nVersion = 2;
    manifest.hashChainstateSerialized.SetNull();
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
}

BOOST_AUTO_TEST_CASE(bootstrap_manifest_validation_v3_growable)
{
    // v3 = GROWABLE snapshot: chainstate PINNED at the compiled anchor (same
    // identity checks as an accepted v2 — nHeight/hashBlock/hashChainstateSerialized
    // must equal a compiled anchor) PLUS an append-only post-anchor block bundle
    // grown to nBlockTipHeight/hashBlockTip. The new tip fields carry NO commitment;
    // the client validates the bundled post-anchor blocks itself. They only need to
    // be well-formed here: a tip strictly above the anchor with a non-null hash.
    std::string error;
    const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();
    BOOST_REQUIRE(!anchor.hashChainstateSerialized.IsNull());

    // A well-formed v3 manifest pinned at a compiled anchor with a grown tip is
    // accepted in BOTH modes: its anchor identity matches the compiled anchor (so
    // anchor mode is satisfied exactly as for v2), and the grown block tip is
    // unpinned but well-formed.
    CBootstrapSnapshotManifest manifest = ValidV3BootstrapManifest();
    BOOST_CHECK(ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
    BOOST_CHECK(ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));

    // Wrong anchor commitment (right height/hash, tampered UTXO commitment) does
    // not match any compiled anchor -> rejected in both modes.
    manifest = ValidV3BootstrapManifest();
    manifest.hashChainstateSerialized = uint256S("0202020202020202020202020202020202020202020202020202020202020202");
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));

    // Wrong anchor identity (right commitment, but a block hash that matches no
    // compiled anchor) -> rejected in both modes.
    manifest = ValidV3BootstrapManifest();
    manifest.hashBlock = uint256S("00000000000000000000000000000000000000000000000000000000deadbeef");
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));

    // Wrong anchor height (matches no compiled anchor) -> rejected in both modes.
    manifest = ValidV3BootstrapManifest();
    manifest.nHeight = anchor.nHeight + 1;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));

    // A grown block tip at or below the pinned anchor height is self-contradictory
    // (the bundle is anchor+1 .. nBlockTipHeight) -> rejected in both modes.
    manifest = ValidV3BootstrapManifest();
    manifest.nBlockTipHeight = anchor.nHeight; // equal: not strictly above
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));

    manifest = ValidV3BootstrapManifest();
    manifest.nBlockTipHeight = anchor.nHeight - 1; // below the anchor
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));

    // A null grown-tip block hash is malformed even when the height is plausible
    // -> rejected in both modes.
    manifest = ValidV3BootstrapManifest();
    manifest.hashBlockTip.SetNull();
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/false));
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error, /*fTrustlessAllowed=*/true));
}

BOOST_AUTO_TEST_CASE(bootstrap_find_fast_sync_anchor)
{
    // The compiled anchor set is non-empty under MAIN params and contains the
    // primary; the lookup matches on (height, block hash) and rejects anything
    // else — the property ValidateBootstrapSnapshotManifest relies on to accept
    // any compiled anchor across an anchor bump.
    const CChainParams& params = Params();
    const CFastSyncAnchorData& primary = params.FastSyncAnchor();
    BOOST_REQUIRE(!params.FastSyncAnchors().empty());
    BOOST_CHECK_EQUAL(params.FastSyncAnchors().front().nHeight, primary.nHeight);

    const CFastSyncAnchorData* found = params.FindFastSyncAnchor(primary.nHeight, primary.hashBlock);
    BOOST_REQUIRE(found != NULL);
    BOOST_CHECK(found->hashBlock == primary.hashBlock);
    BOOST_CHECK(found->hashChainstateSerialized == primary.hashChainstateSerialized);

    // Wrong height or wrong hash → no match.
    BOOST_CHECK(params.FindFastSyncAnchor(primary.nHeight + 1, primary.hashBlock) == NULL);
    BOOST_CHECK(params.FindFastSyncAnchor(primary.nHeight,
        uint256S("00000000000000000000000000000000000000000000000000000000deadbeef")) == NULL);
}

BOOST_AUTO_TEST_CASE(bootstrap_validate_fast_sync_anchor_requires_commitment)
{
    // Startup guard: ValidateFastSyncAnchor must accept the compiled MAIN anchor
    // set, which is required to carry a non-null UTXO-set commitment for every
    // populated entry. This is the positive control for the SEC-1 startup check;
    // a null-commitment anchor (never shippable now) would make this fail with a
    // "no chainstate commitment" strError.
    const CChainParams& params = Params();
    BOOST_REQUIRE(!params.FastSyncAnchors().front().hashChainstateSerialized.IsNull());
    std::string strError;
    BOOST_CHECK(Checkpoints::ValidateFastSyncAnchor(params, strError));
    BOOST_CHECK(strError.empty());
}

BOOST_AUTO_TEST_CASE(bootstrap_manifest_validation_rejects_oversize)
{
    std::string error;

    // Per-file cap: a single advertised file larger than the compiled ceiling
    // is rejected before any chunk is requested.
    {
        CBootstrapSnapshotManifest manifest = ValidBootstrapManifest();
        manifest.vFiles[0].nSize = (uint64_t)BOOTSTRAP_SNAPSHOT_MAX_FILE_BYTES + 1ULL;
        manifest.nSnapshotBytes = manifest.vFiles[0].nSize;
        BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
        BOOST_CHECK(error.find("per-file cap") != std::string::npos);
    }

    // Aggregate cap: a manifest whose total exceeds the compiled total cap
    // is rejected even when each individual file is within the per-file cap.
    {
        CBootstrapSnapshotManifest manifest = ValidBootstrapManifest();
        manifest.vFiles.clear();

        const uint64_t per_file = (uint64_t)BOOTSTRAP_SNAPSHOT_MAX_FILE_BYTES;
        const uint64_t files_needed = ((uint64_t)BOOTSTRAP_SNAPSHOT_MAX_TOTAL_BYTES / per_file) + 1;
        uint64_t total = 0;
        for (uint64_t i = 0; i < files_needed; ++i) {
            CBootstrapSnapshotFile file;
            file.strPath = strprintf("blocks/blk%05u.dat", (unsigned int)i);
            file.nSize = per_file;
            file.hashSha256 = uint256S("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
            manifest.vFiles.push_back(file);
            total += file.nSize;
        }
        manifest.nSnapshotBytes = total;
        BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
        BOOST_CHECK(error.find("total snapshot cap") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(zcash_param_specs_pin_expected_sizes)
{
    const std::vector<ZcashParamSpec>& specs = GetZcashParamSpecs();
    BOOST_REQUIRE_EQUAL(specs.size(), 5);

    BOOST_CHECK_EQUAL(specs[0].name, "sapling-output.params");
    BOOST_CHECK_EQUAL(specs[0].nSize, 3592860ULL);
    BOOST_CHECK_EQUAL(specs[1].name, "sapling-spend.params");
    BOOST_CHECK_EQUAL(specs[1].nSize, 47958396ULL);
    BOOST_CHECK_EQUAL(specs[2].name, "sprout-groth16.params");
    BOOST_CHECK_EQUAL(specs[2].nSize, 725523612ULL);
    BOOST_CHECK_EQUAL(specs[3].name, "sprout-proving.key");
    BOOST_CHECK_EQUAL(specs[3].nSize, 910173851ULL);
    BOOST_CHECK_EQUAL(specs[4].name, "sprout-verifying.key");
    BOOST_CHECK_EQUAL(specs[4].nSize, 1449ULL);
}

BOOST_AUTO_TEST_CASE(bootstrap_manifest_and_chunk_service_helpers)
{
    const bool hadServe = mapArgs.count("-bootstrapserve");
    const bool hadSource = mapArgs.count("-bootstrapsourcedir");
    const std::string oldServe = hadServe ? mapArgs["-bootstrapserve"] : "";
    const std::string oldSource = hadSource ? mapArgs["-bootstrapsourcedir"] : "";

    boost::filesystem::path root = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("zclassic-bootstrap-source-%%%%-%%%%-%%%%");
    boost::filesystem::create_directories(root / "blocks" / "index");
    boost::filesystem::create_directories(root / "chainstate");

    {
        boost::filesystem::ofstream file(root / "blocks" / "blk00000.dat");
        file << "abcdef";
    }
    {
        boost::filesystem::ofstream file(root / "blocks" / "index" / "000001.ldb");
        file << "index";
    }
    {
        boost::filesystem::ofstream file(root / "chainstate" / "000003.ldb");
        file << "state";
    }

    mapArgs["-bootstrapserve"] = "1";
    mapArgs["-bootstrapsourcedir"] = root.string();

    CBootstrapSnapshotManifest manifest;
    std::string error;
    BOOST_REQUIRE(PreflightBootstrapSnapshotService(error));
    BOOST_REQUIRE(GetBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(ValidateBootstrapSnapshotManifest(manifest, error));
    // The serve file list sorts chainstate/ BEFORE blocks/ (so a growable v3 bundle's
    // appended block files never shift a pinned chainstate file's nFileIndex), then
    // lexicographically within each group. Client and server both index this same
    // manifest order, so it is internally consistent.
    BOOST_REQUIRE_EQUAL(manifest.vFiles.size(), 3);
    BOOST_CHECK_EQUAL(manifest.vFiles[0].strPath, "chainstate/000003.ldb");
    BOOST_CHECK_EQUAL(manifest.vFiles[1].strPath, "blocks/blk00000.dat");
    BOOST_CHECK_EQUAL(manifest.vFiles[2].strPath, "blocks/index/000001.ldb");
    BOOST_CHECK_EQUAL(manifest.nSnapshotBytes, 16);
    BOOST_CHECK(!manifest.vFiles[0].hashSha256.IsNull());

    // Exercise the chunk reader against the blocks file (now index 1, "abcdef", 6 bytes).
    const unsigned int blkIdx = 1;
    CBootstrapSnapshotChunkRequest request;
    request.nFileIndex = blkIdx;
    request.nOffset = 0;
    request.nLength = manifest.vFiles[blkIdx].nSize;

    CBootstrapSnapshotChunk chunk;
    BOOST_REQUIRE(ReadBootstrapSnapshotChunk(request, chunk, error));
    BOOST_CHECK_EQUAL(chunk.nFileIndex, request.nFileIndex);
    BOOST_CHECK_EQUAL(chunk.nOffset, request.nOffset);
    BOOST_CHECK_EQUAL(std::string(chunk.vData.begin(), chunk.vData.end()), "abcdef");

    request.nLength = 5; // != the 6-byte file size -> length mismatch
    BOOST_CHECK(!ReadBootstrapSnapshotChunk(request, chunk, error));
    BOOST_CHECK(error.find("length") != std::string::npos);

    request.nOffset = 1;
    request.nLength = 5;
    BOOST_CHECK(!ReadBootstrapSnapshotChunk(request, chunk, error));

    request.nFileIndex = 99;
    request.nOffset = 0;
    request.nLength = 1;
    BOOST_CHECK(!ReadBootstrapSnapshotChunk(request, chunk, error));
    BOOST_CHECK(error.find("out of range") != std::string::npos);

    WriteFixtureFile(root / "blocks" / "blk00000.dat", "abcdef-mutated");
    request.nFileIndex = blkIdx;
    request.nOffset = 0;
    request.nLength = manifest.vFiles[blkIdx].nSize;
    BOOST_CHECK(!ReadBootstrapSnapshotChunk(request, chunk, error));
    BOOST_CHECK(error.find("changed after manifest creation") != std::string::npos);

    RestoreArg("-bootstrapserve", hadServe, oldServe);
    RestoreArg("-bootstrapsourcedir", hadSource, oldSource);
    boost::filesystem::remove_all(root);
}

// --- Misbehaviour tests: malformed bootstrap-protocol inputs must ban (issue #6) ---
//
// These tests drive ProcessMessage() directly so we can observe the
// nMisbehavior bump on the peer's CNodeState. We use TestingSetup as a
// per-case fixture because it RegisterNodeSignals(), which is what hooks
// CNode construction up to InitializeNode() so State(nodeid) is non-null.

BOOST_FIXTURE_TEST_CASE(bootstrap_getbschk_without_manifest_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION; // skip the pre-handshake guard in ProcessMessage
    BOOST_REQUIRE(!node.fBootstrapManifestSent);

    // A well-formed GETBSCHK payload but the peer never asked us for the
    // manifest -> state violation, must Misbehave (score 20 per main.cpp).
    CBootstrapSnapshotChunkRequest request;
    request.nFileIndex = 0;
    request.nOffset = 0;
    request.nLength = BOOTSTRAP_SNAPSHOT_CHUNK_SIZE;
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << request;

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));

    BOOST_CHECK(ProcessMessage(&node, NetMsgType::GETBSCHK, payload, GetTime()));

    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_getbschk_oversize_chunk_misbehaves_high, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;
    // Pretend the peer first requested the manifest, so we exercise the
    // size-overflow path rather than the state-violation path.
    node.fBootstrapManifestSent = true;

    // nLength larger than BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE is a size overflow
    // on a small bounded field -> score 100 ("obviously hostile") per main.cpp.
    CBootstrapSnapshotChunkRequest request;
    request.nFileIndex = 0;
    request.nOffset = 0;
    request.nLength = BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE + 1;
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << request;

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));

    BOOST_CHECK(ProcessMessage(&node, NetMsgType::GETBSCHK, payload, GetTime()));

    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 100);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_getbschk_misaligned_offset_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;
    node.fBootstrapManifestSent = true;

    // Offset not aligned to BOOTSTRAP_SNAPSHOT_CHUNK_SIZE is out-of-spec.
    CBootstrapSnapshotChunkRequest request;
    request.nFileIndex = 0;
    request.nOffset = 1; // not aligned
    request.nLength = BOOTSTRAP_SNAPSHOT_CHUNK_SIZE;
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << request;

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));

    BOOST_CHECK(ProcessMessage(&node, NetMsgType::GETBSCHK, payload, GetTime()));

    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_bschk_oversize_chunk_misbehaves_high, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;

    // Build a BSCHK with vData larger than BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE.
    // This is an unsolicited push AND a size overflow, so we expect at least
    // 10 (unsolicited) + 100 (oversize) = 110 misbehavior.
    CBootstrapSnapshotChunk chunk;
    chunk.nFileIndex = 0;
    chunk.nOffset = 0;
    chunk.vData.assign(BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE + 1, 0);
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << chunk;

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));

    BOOST_CHECK(ProcessMessage(&node, NetMsgType::BSCHK, payload, GetTime()));

    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 100);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_getbsman_trailing_bytes_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;

    // GETBSMAN takes no payload; any bytes are a clear protocol violation.
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint32_t(0xdeadbeef);

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));

    // Returns false (return error(...)), but the side effect we care about is
    // the Misbehaving call.
    ProcessMessage(&node, NetMsgType::GETBSMAN, payload, GetTime());

    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

// SEC-4: a malformed (truncated/garbage) payload on a bootstrap handler must be
// scored INSIDE the handler. Before the fix the deserialization throw unwound to
// the generic ios_base::failure catch in ProcessMessages(), which accrues no ban
// score. Each case feeds a deliberately too-short / garbage stream and asserts
// nMisbehavior climbs by at least 20.

BOOST_FIXTURE_TEST_CASE(bootstrap_bsman_malformed_payload_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;

    // One stray byte: far too short to deserialize a manifest -> throws.
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint8_t(0xff);

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));
    ProcessMessage(&node, NetMsgType::BSMAN, payload, GetTime());
    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_getbschk_malformed_payload_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;
    node.fBootstrapManifestSent = true; // get past the state gate to reach deserialize

    // Truncated fixed-shape request: a single byte cannot fill the struct.
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint8_t(0x01);

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));
    ProcessMessage(&node, NetMsgType::GETBSCHK, payload, GetTime());
    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_bschk_malformed_payload_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;

    // Garbage vData length prefix promising far more bytes than provided so the
    // CDataStream read runs off the end -> ios_base::failure.
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint32_t(0) << uint64_t(0); // nFileIndex, nOffset
    payload << uint8_t(0xff);              // truncated vector length / data

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));
    ProcessMessage(&node, NetMsgType::BSCHK, payload, GetTime());
    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_bspman_malformed_payload_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint8_t(0xff);

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));
    ProcessMessage(&node, NetMsgType::BSPMAN, payload, GetTime());
    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

// A well-formed v2 self-snapshot manifest at the peer's OWN recent tip (NOT a
// compiled anchor) must be ACCEPTED only when trustless mode is explicitly
// allowed, and REJECTED otherwise. The gossip/CNode BSMAN path always validates
// with fTrustlessAllowed=false (the default), so this is the guardrail that keeps
// the experimental, off-by-default trustless acceptance from ever being reachable
// from untrusted gossip. This pins ValidateBootstrapSnapshotManifest's
// fTrustlessAllowed gate directly — the one decision that separates "anchor-only,
// safe by compiled constant" from "provisional, verified later by re-derivation".
BOOST_AUTO_TEST_CASE(bootstrap_manifest_trustless_gate_rejects_self_snapshot_without_opt_in)
{
    CBootstrapSnapshotManifest m = ValidBootstrapManifest();
    m.nVersion = 2;
    // A tip that is NOT any compiled anchor (different height AND hash), i.e. a
    // server's own recent self-snapshot — exactly what a forged/untrusted peer
    // would advertise.
    m.nHeight = Params().FastSyncAnchor().nHeight + 1000;
    m.hashBlock = uint256S("0x00000000000000000000000000000000000000000000000000000000feedface");
    // Non-null commitment (trustless accepts any; it is verified after download by
    // background re-derivation, not here).
    m.hashChainstateSerialized = uint256S("0x0000000000000000000000000000000000000000000000000000000012345678");

    std::string err;
    // Gossip / anchor-mode path (fTrustlessAllowed defaults false): REJECTED.
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(m, err));
    BOOST_CHECK(!err.empty());
    // Explicit trustless opt-in: the SAME manifest is acceptable (its tip and
    // commitment are not trusted here — they are checked post-download).
    std::string err2;
    BOOST_CHECK(ValidateBootstrapSnapshotManifest(m, err2, /*fTrustlessAllowed=*/true));

    // SEC-TRUST-1: a trustless self-snapshot AT or BELOW the last compiled
    // checkpoint is rejected EVEN with trustless allowed — below the checkpoint the
    // provisional checkpoint loop and the background retarget re-check run zero
    // iterations, so a forged low-tip snapshot would latch a false VALIDATED. Only
    // a tip strictly above the last checkpoint is acceptable.
    const MapCheckpoints& cps = Params().Checkpoints().mapCheckpoints;
    BOOST_REQUIRE(!cps.empty());
    const int lastCheckpointHeight = cps.rbegin()->first;
    CBootstrapSnapshotManifest low = m;
    low.nHeight = lastCheckpointHeight; // at the checkpoint: needs strictly above
    std::string err3;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(low, err3, /*fTrustlessAllowed=*/true));
    BOOST_CHECK(err3.find("checkpoint") != std::string::npos);

    low.nHeight = lastCheckpointHeight - 1; // below the checkpoint: also rejected
    std::string err4;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(low, err4, /*fTrustlessAllowed=*/true));
}

// And the actual gossip handler must Misbehave a peer that pushes such a manifest:
// +10 (unsolicited BSMAN on a CNode socket) plus +10 (invalid manifest contents,
// because the handler validates with fTrustlessAllowed=false).
BOOST_FIXTURE_TEST_CASE(bootstrap_bsman_non_anchor_v2_manifest_misbehaves, TestingSetup)
{
    CBootstrapSnapshotManifest m = ValidBootstrapManifest();
    m.nVersion = 2;
    m.nHeight = Params().FastSyncAnchor().nHeight + 1000;
    m.hashBlock = uint256S("0x00000000000000000000000000000000000000000000000000000000feedface");
    m.hashChainstateSerialized = uint256S("0x0000000000000000000000000000000000000000000000000000000012345678");

    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << m;

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));
    ProcessMessage(&node, NetMsgType::BSMAN, payload, GetTime());
    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_getbspchk_malformed_payload_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;
    node.fBootstrapParamManifestSent = true; // get past the state gate

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint8_t(0x01);

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));
    ProcessMessage(&node, NetMsgType::GETBSPCHK, payload, GetTime());
    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

BOOST_FIXTURE_TEST_CASE(bootstrap_bspchk_malformed_payload_misbehaves, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0)), "", true);
    node.nVersion = PROTOCOL_VERSION;

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << uint32_t(0) << uint64_t(0);
    payload << uint8_t(0xff);

    CNodeStateStats before;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), before));
    ProcessMessage(&node, NetMsgType::BSPCHK, payload, GetTime());
    CNodeStateStats after;
    BOOST_REQUIRE(GetNodeStateStats(node.GetId(), after));
    BOOST_CHECK_GE(after.nMisbehavior - before.nMisbehavior, 20);
}

// End-to-end snapshot transfer: serve -> chunked pull -> reassemble -> verify
// -> install. This is the integration path the helper-level tests above don't
// cover. It drives the real serve entrypoints (GetBootstrapSnapshotManifest +
// ReadBootstrapSnapshotChunk) the way a downloading peer does -- fetch the
// manifest, then pull every file one BOOTSTRAP_SNAPSHOT_CHUNK_SIZE chunk at a
// time (including a file that spans multiple chunks) -- reassembles each file,
// checks it against the manifest's per-file SHA-256 (the integrity binding the
// client trusts), confirms a single flipped byte breaks that hash, then
// ImportBootstrapDatadir()s the staged result into a fresh datadir and verifies
// the installed bytes match the originals end to end.
//
// We can use synthetic chainstate files because the compiled fast-sync anchor
// (which binds the chain *tip*) is copied into the manifest verbatim and is not
// recomputed from the served bytes -- so the manifest validates against the MAIN
// anchor that BasicTestingSetup selects, while the per-file SHA-256 still binds
// the actual transferred content. A two-node regtest test cannot exercise this:
// a regtest chainstate would never match the mainnet anchor digest.
BOOST_AUTO_TEST_CASE(bootstrap_snapshot_full_transfer_roundtrip)
{
    const bool hadServe = mapArgs.count("-bootstrapserve");
    const bool hadSource = mapArgs.count("-bootstrapsourcedir");
    const std::string oldServe = hadServe ? mapArgs["-bootstrapserve"] : "";
    const std::string oldSource = hadSource ? mapArgs["-bootstrapsourcedir"] : "";

    namespace fs = boost::filesystem;
    const fs::path root    = fs::temp_directory_path() / fs::unique_path("zclassic-bs-e2e-src-%%%%-%%%%-%%%%");
    const fs::path dest    = fs::temp_directory_path() / fs::unique_path("zclassic-bs-e2e-dst-%%%%-%%%%-%%%%");
    const fs::path staging = fs::temp_directory_path() / fs::unique_path("zclassic-bs-e2e-stg-%%%%-%%%%-%%%%");

    fs::create_directories(root / "blocks" / "index");
    fs::create_directories(root / "chainstate");

    // A spread of sizes: a tiny file, an exactly-one-chunk file, and a file that
    // spans multiple chunks (forces the offset/length tiling in the serve path).
    std::map<std::string, std::string> originals;
    originals["blocks/blk00000.dat"]     = DeterministicBytes(37, 1);
    originals["blocks/index/000001.ldb"] = DeterministicBytes(BOOTSTRAP_SNAPSHOT_CHUNK_SIZE, 2);
    originals["chainstate/000003.ldb"]   = DeterministicBytes((size_t)BOOTSTRAP_SNAPSHOT_CHUNK_SIZE * 2 + 1234, 3);
    for (std::map<std::string, std::string>::const_iterator it = originals.begin(); it != originals.end(); ++it) {
        fs::ofstream f(root / fs::path(it->first), std::ios::binary);
        f.write(it->second.data(), (std::streamsize)it->second.size());
    }

    mapArgs["-bootstrapserve"] = "1";
    mapArgs["-bootstrapsourcedir"] = root.string();

    std::string error;
    CBootstrapSnapshotManifest manifest;
    BOOST_REQUIRE_MESSAGE(GetBootstrapSnapshotManifest(manifest, error), error);
    BOOST_REQUIRE_MESSAGE(ValidateBootstrapSnapshotManifest(manifest, error), error);
    BOOST_REQUIRE_EQUAL(manifest.vFiles.size(), originals.size());

    // Pull every file in BOOTSTRAP_SNAPSHOT_CHUNK_SIZE pieces through the real
    // serve entrypoint and reassemble, exactly as the download client does.
    fs::create_directories(staging);
    bool sawMultiChunkFile = false;
    for (uint32_t i = 0; i < manifest.vFiles.size(); ++i) {
        const CBootstrapSnapshotFile& mf = manifest.vFiles[i];
        std::vector<unsigned char> assembled;
        assembled.reserve(mf.nSize);
        uint64_t chunks = 0;
        for (uint64_t off = 0; off < mf.nSize; off += BOOTSTRAP_SNAPSHOT_CHUNK_SIZE) {
            CBootstrapSnapshotChunkRequest req;
            req.nFileIndex = i;
            req.nOffset = off;
            req.nLength = (uint32_t)std::min<uint64_t>(BOOTSTRAP_SNAPSHOT_CHUNK_SIZE, mf.nSize - off);

            CBootstrapSnapshotChunk chunk;
            BOOST_REQUIRE_MESSAGE(ReadBootstrapSnapshotChunk(req, chunk, error), error);
            BOOST_CHECK_EQUAL(chunk.nFileIndex, i);
            BOOST_CHECK_EQUAL(chunk.nOffset, off);
            BOOST_CHECK_EQUAL(chunk.vData.size(), req.nLength);
            assembled.insert(assembled.end(), chunk.vData.begin(), chunk.vData.end());
            ++chunks;
        }
        if (mf.nSize > BOOTSTRAP_SNAPSHOT_CHUNK_SIZE) {
            BOOST_CHECK_GT(chunks, 1u); // the big file genuinely spanned >1 chunk
            sawMultiChunkFile = true;
        }

        // Reassembled bytes match what we served, and the manifest's per-file
        // SHA-256 binds those exact bytes (the integrity check a client trusts).
        const std::string& want = originals[mf.strPath];
        BOOST_REQUIRE_EQUAL(assembled.size(), want.size());
        BOOST_CHECK(std::equal(assembled.begin(), assembled.end(), (const unsigned char*)want.data()));
        BOOST_CHECK_MESSAGE(Sha256OfBytes(assembled) == mf.hashSha256, "manifest hash mismatch for " + mf.strPath);

        // Tamper detection: a single flipped byte must break the manifest hash,
        // which is exactly what makes a corrupt/malicious chunk detectable.
        std::vector<unsigned char> tampered = assembled;
        tampered[tampered.size() / 2] ^= 0x01;
        BOOST_CHECK(Sha256OfBytes(tampered) != mf.hashSha256);

        // Stage the verified file at its manifest-relative path.
        const fs::path out = staging / fs::path(mf.strPath);
        fs::create_directories(out.parent_path());
        fs::ofstream of(out, std::ios::binary);
        of.write((const char*)&assembled[0], (std::streamsize)assembled.size());
    }
    BOOST_CHECK(sawMultiChunkFile);
    BOOST_REQUIRE(BootstrapSnapshotPathsExist(staging));

    // Install the staged snapshot into a fresh datadir and confirm every file
    // round-tripped intact end to end.
    BOOST_REQUIRE_MESSAGE(ImportBootstrapDatadir(staging, dest, false, error), error);
    for (std::map<std::string, std::string>::const_iterator it = originals.begin(); it != originals.end(); ++it) {
        const fs::path installed = dest / fs::path(it->first);
        BOOST_REQUIRE_MESSAGE(fs::exists(installed), it->first);
        fs::ifstream in(installed, std::ios::binary);
        const std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        BOOST_CHECK_MESSAGE(got == it->second, "installed content mismatch for " + it->first);
    }

    RestoreArg("-bootstrapserve", hadServe, oldServe);
    RestoreArg("-bootstrapsourcedir", hadSource, oldSource);
    fs::remove_all(root);
    fs::remove_all(dest);
    fs::remove_all(staging);
}

// --- Auto-serve activation: a node only re-serves a retained snapshot copy when
// its sibling anchor marker still matches the binary's compiled anchor (issue #4). ---
//
// SetupAutoBootstrapServe looks for <data_dir>/bootstrap-serve-source (a complete
// blocks/index + chainstate tree per BootstrapSnapshotPathsExist) plus a sibling
// <data_dir>/bootstrap-serve-source.anchor marker file whose content equals
// "<anchor.nHeight> <anchor.hashBlock.ToString()>" (AutoServeAnchorMarker). On a
// match it points the serve machinery at the retained copy via mapArgs; on a
// stale/missing marker it removes the copy so we never serve bytes clients will
// reject.

// Build the marker line the way bootstrap.cpp's AutoServeAnchorMarker() does, so
// the "matching" case mirrors what a real retained copy would have written.
static std::string ExpectedAutoServeMarker()
{
    const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();
    return strprintf("%d %s", anchor.nHeight, anchor.hashBlock.ToString());
}

BOOST_AUTO_TEST_CASE(bootstrap_auto_serve_activates_on_matching_marker)
{
    const bool hadServe = mapArgs.count("-bootstrapserve");
    const bool hadSource = mapArgs.count("-bootstrapsourcedir");
    const std::string oldServe = hadServe ? mapArgs["-bootstrapserve"] : "";
    const std::string oldSource = hadSource ? mapArgs["-bootstrapsourcedir"] : "";

    namespace fs = boost::filesystem;
    const fs::path data_dir = fs::temp_directory_path() / fs::unique_path("zclassic-bootstrap-autoserve-ok-%%%%-%%%%-%%%%");
    const fs::path serveSrc = data_dir / "bootstrap-serve-source";
    // Empty dirs satisfy BootstrapSnapshotPathsExist (it only checks the tree).
    fs::create_directories(serveSrc / "blocks" / "index");
    fs::create_directories(serveSrc / "chainstate");
    BOOST_REQUIRE(BootstrapSnapshotPathsExist(serveSrc));

    // Correct marker, written as a sibling file next to the serve dir.
    WriteFixtureFile(data_dir / "bootstrap-serve-source.anchor", ExpectedAutoServeMarker() + "\n");

    // Start from a clean slate so we can assert the function set them.
    mapArgs.erase("-bootstrapserve");
    mapArgs.erase("-bootstrapsourcedir");

    std::string error;
    BOOST_CHECK(SetupAutoBootstrapServe(data_dir, error));
    BOOST_CHECK_EQUAL(mapArgs["-bootstrapsourcedir"], serveSrc.string());
    BOOST_CHECK_EQUAL(mapArgs["-bootstrapserve"], "1");
    // The retained copy must survive a successful activation.
    BOOST_CHECK(BootstrapSnapshotPathsExist(serveSrc));

    RestoreArg("-bootstrapserve", hadServe, oldServe);
    RestoreArg("-bootstrapsourcedir", hadSource, oldSource);
    fs::remove_all(data_dir);
}

BOOST_AUTO_TEST_CASE(bootstrap_auto_serve_rejects_stale_anchor)
{
    const bool hadServe = mapArgs.count("-bootstrapserve");
    const bool hadSource = mapArgs.count("-bootstrapsourcedir");
    const std::string oldServe = hadServe ? mapArgs["-bootstrapserve"] : "";
    const std::string oldSource = hadSource ? mapArgs["-bootstrapsourcedir"] : "";

    namespace fs = boost::filesystem;
    const fs::path data_dir = fs::temp_directory_path() / fs::unique_path("zclassic-bootstrap-autoserve-stale-%%%%-%%%%-%%%%");
    const fs::path serveSrc = data_dir / "bootstrap-serve-source";
    fs::create_directories(serveSrc / "blocks" / "index");
    fs::create_directories(serveSrc / "chainstate");
    BOOST_REQUIRE(BootstrapSnapshotPathsExist(serveSrc));

    // A marker for a different (older) anchor than this binary's compiled one.
    WriteFixtureFile(data_dir / "bootstrap-serve-source.anchor",
                     "1 0000000000000000000000000000000000000000000000000000000000000000\n");

    mapArgs.erase("-bootstrapserve");
    mapArgs.erase("-bootstrapsourcedir");

    std::string error;
    BOOST_CHECK(!SetupAutoBootstrapServe(data_dir, error));
    // A stale copy must be removed so we never serve bytes clients will reject.
    BOOST_CHECK(!BootstrapSnapshotPathsExist(serveSrc));

    RestoreArg("-bootstrapserve", hadServe, oldServe);
    RestoreArg("-bootstrapsourcedir", hadSource, oldSource);
    fs::remove_all(data_dir);
}

BOOST_AUTO_TEST_CASE(bootstrap_auto_serve_no_serve_dir)
{
    const bool hadServe = mapArgs.count("-bootstrapserve");
    const bool hadSource = mapArgs.count("-bootstrapsourcedir");
    const std::string oldServe = hadServe ? mapArgs["-bootstrapserve"] : "";
    const std::string oldSource = hadSource ? mapArgs["-bootstrapsourcedir"] : "";

    namespace fs = boost::filesystem;
    const fs::path data_dir = fs::temp_directory_path() / fs::unique_path("zclassic-bootstrap-autoserve-noserve-%%%%-%%%%-%%%%");
    fs::create_directories(data_dir);
    const fs::path marker = data_dir / "bootstrap-serve-source.anchor";
    // An orphan marker with no serve dir alongside it.
    WriteFixtureFile(marker, ExpectedAutoServeMarker() + "\n");
    BOOST_REQUIRE(fs::exists(marker));
    BOOST_REQUIRE(!BootstrapSnapshotPathsExist(data_dir / "bootstrap-serve-source"));

    mapArgs.erase("-bootstrapserve");
    mapArgs.erase("-bootstrapsourcedir");

    std::string error;
    BOOST_CHECK(!SetupAutoBootstrapServe(data_dir, error));
    // The orphan marker must be dropped so it can't confuse a later run.
    BOOST_CHECK(!fs::exists(marker));

    RestoreArg("-bootstrapserve", hadServe, oldServe);
    RestoreArg("-bootstrapsourcedir", hadSource, oldSource);
    fs::remove_all(data_dir);
}

// --- Bootstrap peer selection precedence (GetBootstrapPeerList): repeatable
// -bootstrappeer (mapMultiArgs) wins, then a single -bootstrappeer (mapArgs),
// then the compiled per-network defaults (Params().BootstrapPeers()). ---
BOOST_AUTO_TEST_CASE(bootstrap_peer_list_multi_and_single)
{
    const bool hadArg = mapArgs.count("-bootstrappeer");
    const std::string oldArg = hadArg ? mapArgs["-bootstrappeer"] : "";
    const bool hadMulti = mapMultiArgs.count("-bootstrappeer");
    const std::vector<std::string> oldMulti = hadMulti ? mapMultiArgs["-bootstrappeer"] : std::vector<std::string>();

    // (a) Repeatable entries take precedence and are returned in order.
    {
        std::vector<std::string> multi;
        multi.push_back("a:1");
        multi.push_back("b:2");
        mapMultiArgs["-bootstrappeer"] = multi;
        // A stray single value must not override the repeatable list.
        mapArgs["-bootstrappeer"] = "ignored:0";

        const std::vector<std::string> got = GetBootstrapPeerList();
        BOOST_REQUIRE_EQUAL(got.size(), 2u);
        BOOST_CHECK_EQUAL(got[0], "a:1");
        BOOST_CHECK_EQUAL(got[1], "b:2");
    }

    // (b) With only a single -bootstrappeer in mapArgs (mapMultiArgs cleared),
    // that lone value is returned.
    {
        mapMultiArgs.erase("-bootstrappeer");
        mapArgs["-bootstrappeer"] = "c:3";

        const std::vector<std::string> got = GetBootstrapPeerList();
        BOOST_REQUIRE_EQUAL(got.size(), 1u);
        BOOST_CHECK_EQUAL(got[0], "c:3");
    }

    // (c) With neither set, the compiled per-network defaults are returned
    // (non-empty on mainnet, which BasicTestingSetup selects).
    {
        mapMultiArgs.erase("-bootstrappeer");
        mapArgs.erase("-bootstrappeer");

        const std::vector<std::string> got = GetBootstrapPeerList();
        BOOST_CHECK(got == Params().BootstrapPeers());
        BOOST_CHECK(!got.empty());
    }

    // Restore BOTH containers.
    if (hadMulti) {
        mapMultiArgs["-bootstrappeer"] = oldMulti;
    } else {
        mapMultiArgs.erase("-bootstrappeer");
    }
    RestoreArg("-bootstrappeer", hadArg, oldArg);
}

// The trustless-bootstrap finalization hold (option B consensus-safety mitigation):
// a node holding an as-yet-unvalidated imported snapshot must PAUSE auto-finalization
// so the reorg-depth rule cannot permanently pin it to an unproven (possibly forged
// / wrong-fork) chain, then RESUME once the snapshot latches validated. A normal node
// (no snapshot in play) must never hold, so the consensus path is unchanged there.
// FindBlockToFinalize() reads BootstrapValidationHoldsFinalization() to do exactly this.
BOOST_AUTO_TEST_CASE(bootstrap_validation_finalization_hold)
{
    // BasicTestingSetup has no pblocktree, so the durable write is a no-op; the
    // in-memory latch and the lock-free hold flag (the part the consensus path
    // reads) still transition. Start from a known DISABLED baseline.
    LoadBootstrapValidationState();
    BOOST_CHECK_EQUAL(GetBootstrapValidationStatus().state, BVS_DISABLED);
    BOOST_CHECK(!BootstrapValidationHoldsFinalization()); // normal node: never holds

    // Provisional accept of a trustless snapshot -> hold finalization.
    BeginBootstrapValidation(123456, uint256S("0x1111"), uint256S("0x2222"));
    BOOST_CHECK_EQUAL(GetBootstrapValidationStatus().state, BVS_PROVISIONAL);
    BOOST_CHECK(BootstrapValidationHoldsFinalization());

    // Latch VALIDATED -> finalization resumes.
    BootstrapValidationSetTerminalStateForTest(BVS_VALIDATED);
    BOOST_CHECK_EQUAL(GetBootstrapValidationStatus().state, BVS_VALIDATED);
    BOOST_CHECK(!BootstrapValidationHoldsFinalization());

    // PROVISIONAL_PRUNED (background validation cannot complete because block data
    // is pruned/missing) is still an UNVERIFIED chainstate, so the hold MUST stay
    // engaged — auto-finalization remains paused until validation actually completes.
    BeginBootstrapValidation(123456, uint256S("0x1111"), uint256S("0x2222"));
    BOOST_CHECK(BootstrapValidationHoldsFinalization());
    BootstrapValidationSetTerminalStateForTest(BVS_PROVISIONAL_PRUNED);
    BOOST_CHECK_EQUAL(GetBootstrapValidationStatus().state, BVS_PROVISIONAL_PRUNED);
    BOOST_CHECK(BootstrapValidationHoldsFinalization()); // still unverified: keep holding

    // A FAILED latch also releases the hold (the node is about to discard and
    // reindex; staying paused would be pointless and would stall finalization).
    BeginBootstrapValidation(123456, uint256S("0x1111"), uint256S("0x2222"));
    BOOST_CHECK(BootstrapValidationHoldsFinalization());
    BootstrapValidationSetTerminalStateForTest(BVS_FAILED);
    BOOST_CHECK_EQUAL(GetBootstrapValidationStatus().state, BVS_FAILED);
    BOOST_CHECK(!BootstrapValidationHoldsFinalization());

    // Interrupting a validator thread that was never started is a safe no-op.
    InterruptBootstrapValidation();

    // Leave global state clean for any later test in this process image.
    LoadBootstrapValidationState();
    BOOST_CHECK_EQUAL(GetBootstrapValidationStatus().state, BVS_DISABLED);
    BOOST_CHECK(!BootstrapValidationHoldsFinalization());
}

// Crash-safety of the bootstrap install->verify handshake (STAB-N1 regression).
//
// The forgery check that makes a bootstrap snapshot safe to accept — anchor mode:
// VerifyImportedBootstrapAnchor (UTXO commitment vs the compiled anchor); trustless
// mode: ProvisionalAcceptTrustlessSnapshot + background re-derivation — runs AFTER
// the chain databases open, while the snapshot's chainstate has already been moved
// into the datadir. If the only record that "this snapshot still needs verifying"
// were an in-memory flag, a crash in that window would, on restart, leave the
// datadir non-fresh (so bootstrap does not re-run) with the flag lost (so the check
// never runs) — silently trusting a never-verified, possibly-forged UTXO set.
//
// The fix makes that record DURABLE: a marker is written (and fsync'd) BEFORE the
// install, and AppInit2 gates verification on the marker's presence, not on any
// in-memory flag. This test pins the marker lifecycle that underpins that contract:
// once written, the marker the post-restart gate keys off exists independently of
// process state, and survives until verification explicitly clears it.
BOOST_AUTO_TEST_CASE(bootstrap_pending_markers_are_durable_and_gate_verification)
{
    namespace fs = boost::filesystem;

    // --- anchor-mode marker (the production-default path) ---
    {
        const fs::path data_dir = fs::temp_directory_path() / fs::unique_path("zclassic-bs-anchor-pending-%%%%-%%%%-%%%%");
        fs::create_directories(data_dir);

        // A fresh datadir has no pending marker, so a normal (non-bootstrap) start
        // never runs the anchor-verify gate.
        BOOST_CHECK(!BootstrapAnchorPendingExists(data_dir));

        // BootstrapFromPeer writes this BEFORE installing the chainstate. It must
        // be durable and present immediately — this is exactly what a post-crash
        // restart sees, with no in-memory state carried over.
        const uint256 markedHash = uint256S("0x00000000000000000000000000000000000000000000000000000000000abc12");
        BOOST_REQUIRE(WriteBootstrapAnchorPending(data_dir, 3126937, markedHash));
        BOOST_CHECK(BootstrapAnchorPendingExists(data_dir));

        // It is a real on-disk file (durable), not just in-memory state, and it
        // records the height/hash line.
        const fs::path marker = data_dir / "bootstrap-anchor-pending";
        BOOST_REQUIRE(fs::exists(marker));
        BOOST_CHECK(fs::file_size(marker) > 0);

        // The marker's recorded (height, hash) round-trips through GetBootstrapAnchorPending.
        // For a v3 growable import this is the GROWN BUNDLE TIP that AppInit2 forward-connects
        // (the fix for the e2e-caught bug where the forward-connect guard never armed because
        // it keyed off pindexBestHeader, which LoadBlockIndexDB leaves at the anchor). Here we
        // record a tip ABOVE the anchor, exactly like a v3 import does.
        int readHeight = -1;
        uint256 readHash;
        BOOST_REQUIRE(GetBootstrapAnchorPending(data_dir, readHeight, readHash));
        BOOST_CHECK_EQUAL(readHeight, 3126937);
        BOOST_CHECK(readHash == markedHash);
        // A v3-style marker carrying the grown bundle tip (strictly above the anchor) reads back.
        const uint256 bundleTip = uint256S("0x0000039d98ad94ad29eb8dde19b8bdf94c3ac547d3e74ca521d72d65c6669f07");
        BOOST_REQUIRE(WriteBootstrapAnchorPending(data_dir, 3129658, bundleTip));
        BOOST_REQUIRE(GetBootstrapAnchorPending(data_dir, readHeight, readHash));
        BOOST_CHECK_EQUAL(readHeight, 3129658);
        BOOST_CHECK(readHash == bundleTip);

        // Only an explicit clear (which AppInit2 does after the commitment check
        // passes, or after discarding a rejected snapshot) removes it.
        BootstrapAnchorPendingClear(data_dir);
        BOOST_CHECK(!BootstrapAnchorPendingExists(data_dir));
        // After a clear the reader reports no marker.
        BOOST_CHECK(!GetBootstrapAnchorPending(data_dir, readHeight, readHash));
        BOOST_CHECK_EQUAL(readHeight, -1);

        fs::remove_all(data_dir);
    }

    // --- trustless-mode marker (off-by-default Option B path) ---
    {
        const fs::path data_dir = fs::temp_directory_path() / fs::unique_path("zclassic-bs-trustless-pending-%%%%-%%%%-%%%%");
        fs::create_directories(data_dir);

        BOOST_CHECK(!BootstrapTrustlessPendingExists(data_dir));
        // Now returns success/failure (it must, so BootstrapFromPeer can refuse to
        // install when the verification intent could not be persisted).
        BOOST_REQUIRE(WriteBootstrapTrustlessPending(data_dir, 4000000,
            uint256S("0xdef456"), uint256S("0x0789ab")));
        BOOST_CHECK(BootstrapTrustlessPendingExists(data_dir));

        const fs::path marker = data_dir / "bootstrap-trustless-pending";
        BOOST_REQUIRE(fs::exists(marker));
        BOOST_CHECK(fs::file_size(marker) > 0);

        BootstrapTrustlessPendingClear(data_dir);
        BOOST_CHECK(!BootstrapTrustlessPendingExists(data_dir));

        fs::remove_all(data_dir);
    }
}

// The imported-tip finalization hold (Deliverable 1): a node that imports blocks
// ABOVE the last compiled checkpoint must PAUSE auto-finalization until the live
// network corroborates that tip, so the 10-deep finalization rule cannot pin it to
// the bootstrap server's (possibly minority/forged) fork before it converges with
// the majority. This pins the arm/hold/release/get lifecycle and its independence
// from (and OR-ing with) the trustless-validation hold. (BasicTestingSetup has no
// pblocktree, so the durable persistence is a no-op; the in-memory hold — the part
// the consensus path reads via BootstrapValidationHoldsFinalization() — transitions.)
BOOST_AUTO_TEST_CASE(bootstrap_imported_tip_finalization_hold)
{
    // Known-clean baseline: no snapshot, no tip hold.
    LoadBootstrapValidationState();
    BOOST_CHECK(!BootstrapValidationHoldsFinalization());
    int h = 0; uint256 hash;
    GetBootstrapTipHold(h, hash);
    BOOST_CHECK_EQUAL(h, -1); // no hold armed

    // Arm the tip hold -> finalization is held, and the armed (height, hash) reads back.
    const uint256 tip = uint256S("0x00000000000000000000000000000000000000000000000000000000feedf00d");
    ArmBootstrapTipHold(3200000, tip);
    BOOST_CHECK(BootstrapValidationHoldsFinalization());
    GetBootstrapTipHold(h, hash);
    BOOST_CHECK_EQUAL(h, 3200000);
    BOOST_CHECK(hash == tip);

    // Release -> hold clears (no other hold engaged).
    ReleaseBootstrapTipHold();
    BOOST_CHECK(!BootstrapValidationHoldsFinalization());
    GetBootstrapTipHold(h, hash);
    BOOST_CHECK_EQUAL(h, -1);
    // Release is idempotent.
    ReleaseBootstrapTipHold();
    BOOST_CHECK(!BootstrapValidationHoldsFinalization());

    // The two holds are independent and OR-ed: with BOTH a trustless-PROVISIONAL
    // snapshot AND an armed tip hold, the node holds; clearing the tip hold while the
    // snapshot is still PROVISIONAL keeps the hold engaged; only when BOTH clear does
    // finalization resume.
    BeginBootstrapValidation(3200000, tip, uint256S("0x2222")); // -> BVS_PROVISIONAL
    BOOST_CHECK(BootstrapValidationHoldsFinalization());
    ArmBootstrapTipHold(3200000, tip);
    BOOST_CHECK(BootstrapValidationHoldsFinalization());
    ReleaseBootstrapTipHold();                                  // tip hold cleared...
    BOOST_CHECK(BootstrapValidationHoldsFinalization());        // ...but snapshot still PROVISIONAL
    BootstrapValidationSetTerminalStateForTest(BVS_VALIDATED);  // snapshot validated
    BOOST_CHECK(!BootstrapValidationHoldsFinalization());       // both clear -> resume

    // Leave global state clean for any later test in this process image.
    LoadBootstrapValidationState();
    BOOST_CHECK(!BootstrapValidationHoldsFinalization());
}

// The peer-aware finalization gate (Deliverable 1, D): a node must only finalize a
// block once the LIVE network corroborates the chain through it — past IBD, the block
// on the active chain, our best header a live descendant at the required depth, enough
// independent OUTBOUND peers building on it, and NO peer advertising a higher-work fork
// below it. These drive the pure decision core EvaluateTipCorroboration directly with
// synthetic chains + peer views (the production wrapper LiveNetworkCorroboratesTip just
// gathers these from globals), so every sub-condition is exercised in isolation.
namespace {
// Build a chain vIndex[0..n-1] with ascending height and nChainWork == height (a stand-in
// for monotonically increasing work), wired via pprev + BuildSkip so GetAncestor works.
static void BuildChain(std::vector<CBlockIndex>& v, int n, CBlockIndex* base = NULL)
{
    v.resize(n);
    for (int i = 0; i < n; ++i) {
        v[i].nHeight = (base ? base->nHeight + 1 : 0) + i;
        v[i].pprev = (i == 0) ? base : &v[i - 1];
        v[i].nChainWork = arith_uint256(v[i].nHeight);
        v[i].BuildSkip();
    }
}
static PeerTipView Peer(const CBlockIndex* best, bool inbound, unsigned char group)
{
    PeerTipView p;
    p.bestKnown = best;
    p.fInbound = inbound;
    p.group.assign(1, group); // distinct byte == distinct address group
    return p;
}
} // namespace

BOOST_AUTO_TEST_CASE(finalization_peer_corroboration_gate)
{
    // Main chain of 130 blocks. Candidate = height 110 (so a depth-10 corroboration
    // needs peers/header at >= height 120 on this chain). minDepth=10, minPeers=2.
    std::vector<CBlockIndex> chain;
    BuildChain(chain, 130);
    const CBlockIndex* candidate = &chain[110];
    const CBlockIndex* header120 = &chain[120];
    const CBlockIndex* tip = &chain[129];
    const int minDepth = 10, minPeers = 2;
    const int64_t startup = 1000;
    std::string why;

    // Two independent OUTBOUND peers at the tip on this chain, live best header -> RELEASE.
    std::vector<PeerTipView> good;
    good.push_back(Peer(tip, /*inbound*/false, 1));
    good.push_back(Peer(tip, /*inbound*/false, 2));
    BOOST_CHECK(EvaluateTipCorroboration(candidate, /*isIBD*/false, /*onActive*/true,
                header120, /*bhRecv*/startup + 5, startup, minDepth, minPeers, good, why));

    // T-IBD: still catching up -> HOLD.
    BOOST_CHECK(!EvaluateTipCorroboration(candidate, true, true, header120, startup + 5, startup,
                minDepth, minPeers, good, why));
    BOOST_CHECK(why.find("initial block download") != std::string::npos);

    // T-offchain: candidate not on the active chain -> HOLD.
    BOOST_CHECK(!EvaluateTipCorroboration(candidate, false, false, header120, startup + 5, startup,
                minDepth, minPeers, good, why));

    // T-disk-header: best header was NOT received live this session (recv < startup),
    // i.e. it was disk-loaded by a bootstrap import -> HOLD (this is the bootstrap case).
    BOOST_CHECK(!EvaluateTipCorroboration(candidate, false, true, header120, startup - 1, startup,
                minDepth, minPeers, good, why));
    BOOST_CHECK(why.find("live") != std::string::npos);

    // T-shallow-header: best header not deep enough above the candidate -> HOLD.
    const CBlockIndex* header115 = &chain[115];
    BOOST_CHECK(!EvaluateTipCorroboration(candidate, false, true, header115, startup + 5, startup,
                minDepth, minPeers, good, why));

    // T-too-few: only one outbound peer corroborates -> HOLD.
    std::vector<PeerTipView> onePeer;
    onePeer.push_back(Peer(tip, false, 1));
    BOOST_CHECK(!EvaluateTipCorroboration(candidate, false, true, header120, startup + 5, startup,
                minDepth, minPeers, onePeer, why));
    BOOST_CHECK(why.find("corroborate") != std::string::npos);

    // T-inbound-and-dup-group: inbound peers don't count, and two peers in the SAME group
    // count once -> still too few -> HOLD.
    std::vector<PeerTipView> weak;
    weak.push_back(Peer(tip, /*inbound*/true, 1));  // inbound: ignored
    weak.push_back(Peer(tip, false, 5));            // group 5
    weak.push_back(Peer(tip, false, 5));            // same group 5: counted once
    BOOST_CHECK(!EvaluateTipCorroboration(candidate, false, true, header120, startup + 5, startup,
                minDepth, minPeers, weak, why));

    // T-fork-veto: a peer (even inbound) advertising a strictly-higher-work chain that
    // forks BELOW the candidate vetoes finalization, even with enough corroborators.
    std::vector<CBlockIndex> fork;
    BuildChain(fork, 80, &chain[50]);     // forks off at height 50 (below the candidate),
                                          // tip at height 130 (above it, different fork)
    fork.back().nChainWork = arith_uint256(10000); // strictly heavier than the main tip
    std::vector<PeerTipView> withFork = good;
    withFork.push_back(Peer(&fork.back(), /*inbound*/true, 9)); // inbound, still vetoes
    BOOST_CHECK(!EvaluateTipCorroboration(candidate, false, true, header120, startup + 5, startup,
                minDepth, minPeers, withFork, why));
    BOOST_CHECK(why.find("forks below") != std::string::npos);

    // T-higher-work-same-fork-OK: a peer heavier but on the SAME chain (descends from the
    // candidate) is NOT a veto — it is corroboration.
    std::vector<PeerTipView> heavySame;
    heavySame.push_back(Peer(tip, false, 1));
    heavySame.push_back(Peer(tip, false, 2));
    BOOST_CHECK(EvaluateTipCorroboration(candidate, false, true, header120, startup + 5, startup,
                minDepth, minPeers, heavySame, why));
}

BOOST_AUTO_TEST_SUITE_END()
