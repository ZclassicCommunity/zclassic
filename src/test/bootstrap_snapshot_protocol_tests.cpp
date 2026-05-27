// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"
#include "bootstrap.h"
#include "chainparams.h"
#include "net.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/test/unit_test.hpp>

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
        if (!node.QueueBootstrapChunkRequest(request)) {
            break;
        }
        ++accepted;
    }
    // The cap must allow real pipelining (more than one) but stay bounded.
    BOOST_CHECK_GT(accepted, 1u);
    BOOST_CHECK_LT(accepted, kSanityCap);

    // A further request is rejected while the queue is full.
    CBootstrapSnapshotChunkRequest overflow;
    overflow.nFileIndex = 1;
    overflow.nOffset = (uint64_t)accepted * 512 * 1024;
    overflow.nLength = 512 * 1024;
    BOOST_CHECK(!node.QueueBootstrapChunkRequest(overflow));

    // Requests pop in FIFO order, and the queue empties after `accepted` pops.
    for (size_t i = 0; i < accepted; ++i) {
        CBootstrapSnapshotChunkRequest popped;
        BOOST_REQUIRE(node.PopBootstrapChunkRequest(popped));
        BOOST_CHECK_EQUAL(popped.nFileIndex, 1u);
        BOOST_CHECK_EQUAL(popped.nOffset, (uint64_t)i * 512 * 1024);
        BOOST_CHECK_EQUAL(popped.nLength, (uint32_t)(512 * 1024));
    }

    CBootstrapSnapshotChunkRequest popped;
    BOOST_CHECK(!node.PopBootstrapChunkRequest(popped));
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

BOOST_AUTO_TEST_SUITE_END()
