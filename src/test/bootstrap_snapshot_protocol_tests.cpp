// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"
#include "bootstrap.h"
#include "chainparams.h"
#include "main.h"
#include "net.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/test/unit_test.hpp>

// Non-static handler in main.cpp; exposed so we can drive it directly here to
// exercise the Misbehaving paths added for malformed bootstrap-snapshot messages.
extern bool ProcessMessage(CNode* pfrom, std::string strCommand, CDataStream& vRecv, int64_t nTimeReceived);

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

    manifest = ValidBootstrapManifest();
    manifest.nVersion = 2;
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("version") != std::string::npos);

    manifest = ValidBootstrapManifest();
    manifest.strNetwork = "wrong";
    BOOST_CHECK(!ValidateBootstrapSnapshotManifest(manifest, error));
    BOOST_CHECK(error.find("anchor") != std::string::npos);

    manifest = ValidBootstrapManifest();
    manifest.nChunkSize = BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE + 1;
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
    BOOST_REQUIRE_EQUAL(manifest.vFiles.size(), 3);
    BOOST_CHECK_EQUAL(manifest.vFiles[0].strPath, "blocks/blk00000.dat");
    BOOST_CHECK_EQUAL(manifest.vFiles[1].strPath, "blocks/index/000001.ldb");
    BOOST_CHECK_EQUAL(manifest.vFiles[2].strPath, "chainstate/000003.ldb");
    BOOST_CHECK_EQUAL(manifest.nSnapshotBytes, 16);
    BOOST_CHECK(!manifest.vFiles[0].hashSha256.IsNull());

    CBootstrapSnapshotChunkRequest request;
    request.nFileIndex = 0;
    request.nOffset = 0;
    request.nLength = manifest.vFiles[0].nSize;

    CBootstrapSnapshotChunk chunk;
    BOOST_REQUIRE(ReadBootstrapSnapshotChunk(request, chunk, error));
    BOOST_CHECK_EQUAL(chunk.nFileIndex, request.nFileIndex);
    BOOST_CHECK_EQUAL(chunk.nOffset, request.nOffset);
    BOOST_CHECK_EQUAL(std::string(chunk.vData.begin(), chunk.vData.end()), "abcdef");

    request.nLength = 5;
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
    request.nFileIndex = 0;
    request.nOffset = 0;
    request.nLength = manifest.vFiles[0].nSize;
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

BOOST_AUTO_TEST_SUITE_END()
