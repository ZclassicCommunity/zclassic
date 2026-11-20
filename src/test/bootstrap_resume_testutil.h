// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Helpers shared by the bootstrap resume test files (bootstrap_resume_logic_tests.cpp,
// bootstrap_peer_board_tests.cpp, bootstrap_resume_tests.cpp): deterministic bytes, file
// helpers, a temporary directory and a synthetic snapshot. Moved verbatim out of the
// single file those tests used to live in; every function is inline.

#ifndef ZCL_TEST_BOOTSTRAP_RESUME_TESTUTIL_H
#define ZCL_TEST_BOOTSTRAP_RESUME_TESTUTIL_H

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
#include <fstream>
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

namespace bootstrap_resume_testutil {

inline uint256 Sha256Of(const std::string& data)
{
    CSHA256 hasher;
    if (!data.empty())
        hasher.Write((const unsigned char*)data.data(), data.size());
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    return uint256S("0x" + HexStr(digest, digest + CSHA256::OUTPUT_SIZE));
}

// Deterministic pseudo-random bytes; distinct seeds give distinct contents.
inline std::string Bytes(size_t n, unsigned int seed)
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

inline void WriteFile(const fs::path& path, const std::string& contents)
{
    fs::create_directories(path.parent_path());
    fs::ofstream f(path, std::ios::binary);
    f.write(contents.data(), contents.size());
}

inline std::string ReadFile(const fs::path& path)
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

inline Snapshot MakeSnapshot(int nFiles, int firstSeed = 1)
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

} // namespace bootstrap_resume_testutil

using namespace bootstrap_resume_testutil;

#endif // ZCL_TEST_BOOTSTRAP_RESUME_TESTUTIL_H
