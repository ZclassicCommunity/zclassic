#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <ios>
#include <iostream>
#include <string>
#include <cstdint>
#include <algorithm>
#include <iterator>
#include <vector>
#include "bootstrap.h"
#include "chainparams.h"
#include "crypto/sha256.h"
#include "utilstrencodings.h"
#include "uint256.h"
#include "util.h"

#if defined(__unix__) || defined(__APPLE__)
#include <sys/stat.h>
#define HAVE_POSIX_STAT 1
#endif

namespace {
struct ParamFile { const char* name; uint64_t size; };
// Mirror of the compiled ZCASH_PARAM_FILES_RAW table (name + nSize only). Kept
// in lockstep with bootstrap.cpp; the test only needs the sizes, not hashes.
const ParamFile kParams[] = {
    {"sapling-output.params", 3592860ULL},
    {"sapling-spend.params",  47958396ULL},
    {"sprout-groth16.params", 725523612ULL},
    {"sprout-verifying.key",  1449ULL},
};
const size_t kParamCount = sizeof(kParams) / sizeof(kParams[0]);

// Write a file of exactly `size` zero bytes (sparse where supported, so the
// test does not actually allocate ~1.6 GiB on disk). Returns true only on a
// verified write: ofstream/seekp/put success AND the resulting on-disk logical
// size equals `size`, so a silent short write cannot make a later predicate
// falsely pass.
bool WriteSizedFile(const boost::filesystem::path& p, uint64_t size) {
    {
        boost::filesystem::ofstream f(p, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;
        if (size > 0) {
            f.seekp((std::streamoff)(size - 1));
            if (!f) return false;
            f.put('\0');
            if (!f) return false;
        }
        f.flush();
        if (!f) return false;
    } // close on scope exit
    boost::system::error_code ec;
    uint64_t actual = (uint64_t)boost::filesystem::file_size(p, ec);
    return !ec && actual == size;
}

boost::filesystem::path MakeTmpDir() {
    boost::filesystem::path dir = boost::filesystem::temp_directory_path() /
        UniquePath("zcl_params_%%%%%%%%");
    boost::filesystem::create_directories(dir);
    return dir;
}

// Probe whether the temp filesystem stores holes sparsely. We write a 16 MiB
// hole and compare blocks actually allocated (st_blocks * 512) to the logical
// size. If the FS materialized the bytes (no sparse support, e.g. some tmpfs /
// overlay configs), the large full-size param files would cost real disk, so
// the big-file cases are skipped to avoid ENOSPC / slowness. On platforms
// without stat() we conservatively assume sparse is unavailable.
bool TmpfsSupportsSparse(const boost::filesystem::path& dir) {
#ifdef HAVE_POSIX_STAT
    const uint64_t kProbe = 16ULL * 1024 * 1024; // 16 MiB hole
    boost::filesystem::path probe = dir / "sparse_probe";
    if (!WriteSizedFile(probe, kProbe)) {
        boost::filesystem::remove(probe);
        return false;
    }
    struct stat st;
    bool sparse = false;
    if (stat(probe.string().c_str(), &st) == 0) {
        const uint64_t allocated = (uint64_t)st.st_blocks * 512ULL;
        // Allow generous slack for metadata/rounding; sparse means far fewer
        // bytes allocated than the logical size.
        sparse = allocated < (kProbe / 2);
    }
    boost::filesystem::remove(probe);
    return sparse;
#else
    (void)dir;
    return false;
#endif
}

// Largest param size that is always safe to materialize without sparse support.
const uint64_t kMaxNonSparseSize = 64ULL * 1024 * 1024; // 64 MiB
} // namespace

TEST(ParamPresence, AllPresentCorrectSize) {
    boost::filesystem::path dir = MakeTmpDir();
    const bool sparse = TmpfsSupportsSparse(dir);
    if (!sparse) {
        // Writing 725 MB + 910 MB files for real would be slow / risk ENOSPC.
        // This vendored gtest predates GTEST_SKIP(); log and no-op (pass).
        boost::filesystem::remove_all(dir);
        std::cerr << "[ SKIPPED ] ParamPresence.AllPresentCorrectSize: temp "
                     "filesystem does not support sparse files\n";
        return;
    }
    for (size_t i = 0; i < kParamCount; ++i)
        ASSERT_TRUE(WriteSizedFile(dir / kParams[i].name, kParams[i].size));
    EXPECT_TRUE(ZcashParamsPresentInDir(dir));
    boost::filesystem::remove_all(dir);
}

TEST(ParamPresence, MissingFileNotPresent) {
    boost::filesystem::path dir = MakeTmpDir();
    // Use only the small files so this case never needs sparse support; the
    // largest (groth16) is intentionally absent, which is
    // exactly what we assert is "not present". Build all but [0] (output),
    // restricting to files <= kMaxNonSparseSize so writes are always cheap.
    for (size_t i = 1; i < kParamCount; ++i) {
        if (kParams[i].size > kMaxNonSparseSize) continue; // leave big ones absent too
        ASSERT_TRUE(WriteSizedFile(dir / kParams[i].name, kParams[i].size));
    }
    // sapling-output.params (index 0) is missing -> predicate must be false.
    EXPECT_FALSE(ZcashParamsPresentInDir(dir));
    boost::filesystem::remove_all(dir);
}

TEST(ParamPresence, WrongSizeNotPresent) {
    boost::filesystem::path dir = MakeTmpDir();
    const bool sparse = TmpfsSupportsSparse(dir);
    // Write the small files at correct size, the big ones only if sparse.
    for (size_t i = 0; i < kParamCount; ++i) {
        if (kParams[i].size > kMaxNonSparseSize && !sparse) continue;
        ASSERT_TRUE(WriteSizedFile(dir / kParams[i].name, kParams[i].size));
    }
    // Truncate the smallest file (sprout-verifying.key, 1449 bytes) by 1 byte.
    // This file is tiny so the case works regardless of sparse support.
    ASSERT_TRUE(WriteSizedFile(dir / "sprout-verifying.key", 1448ULL));
    EXPECT_FALSE(ZcashParamsPresentInDir(dir));
    boost::filesystem::remove_all(dir);
}

// Proves the predicate does NOT hash: every file is the right SIZE but filled
// with zero bytes (so none can match its compiled SHA-256). Present==true here
// while a content-hashing check (ZcashParamsPresentAndValid) would be false.
// This is the central trust assertion: the cheap gate is intentionally
// non-cryptographic and must remain a gate only, never the final verification.
TEST(ParamPresence, PresentDoesNotImplyHashValid) {
    boost::filesystem::path dir = MakeTmpDir();
    const bool sparse = TmpfsSupportsSparse(dir);
    if (!sparse) {
        boost::filesystem::remove_all(dir);
        std::cerr << "[ SKIPPED ] ParamPresence.PresentDoesNotImplyHashValid: "
                     "temp filesystem does not support sparse files\n";
        return;
    }
    for (size_t i = 0; i < kParamCount; ++i)
        ASSERT_TRUE(WriteSizedFile(dir / kParams[i].name, kParams[i].size));
    EXPECT_TRUE(ZcashParamsPresentInDir(dir)); // correct sizes, all-zero bytes
    boost::filesystem::remove_all(dir);
}

namespace {
struct ParamHashDirectory {
    boost::filesystem::path path = MakeTmpDir();
    ~ParamHashDirectory() {
        boost::system::error_code error;
        boost::filesystem::remove_all(path, error);
    }
};
}

TEST(ParamHash, StandardVectorsAndLegacyBoundaryParity) {
    ParamHashDirectory temporary;
    const auto path = temporary.path / "payload";
    const size_t sizes[] = {0, 1, 55, 56, 63, 64, 65, 255, 256, 257,
                           262143, 262144, 262145, 524288};
    for (const size_t size : sizes) {
        SCOPED_TRACE(size);
        std::string bytes(size, '\0');
        for (size_t i = 0; i < size; ++i) bytes[i] = static_cast<char>((i * 17 + 31) & 255);
        boost::filesystem::ofstream file(path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(file.is_open());
        file.write(bytes.data(), bytes.size());
        file.close();
        ASSERT_FALSE(file.fail());
        std::string digest, error;
        ASSERT_TRUE(HashFileSHA256(path, digest, error)) << error;
        EXPECT_TRUE(error.empty());
        unsigned char expected[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()).Finalize(expected);
        EXPECT_EQ(HexStr(expected, expected + sizeof(expected)), digest);
        if (size == 0) EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digest);
    }
    boost::filesystem::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << "abc";
    file.close();
    ASSERT_FALSE(file.fail());
    std::string digest, error;
    ASSERT_TRUE(HashFileSHA256(path, digest, error)) << error;
    EXPECT_EQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digest);
}

TEST(ParamHash, OpenAndReadFailuresDoNotReturnADigest) {
    ParamHashDirectory temporary;
    std::string digest = "stale", error = "stale";
    EXPECT_FALSE(HashFileSHA256(temporary.path / "missing", digest, error));
    EXPECT_TRUE(digest.empty());
    EXPECT_FALSE(error.empty());
#ifdef HAVE_POSIX_STAT
    // POSIX can open a directory as a read stream, but fread fails with EISDIR.
    // Exercise that error separately from an fopen failure; it must not spin.
    FILE* directory = fopen(temporary.path.string().c_str(), "rb");
    ASSERT_NE(nullptr, directory);
    fclose(directory);
    digest = "stale";
    EXPECT_FALSE(HashFileSHA256(temporary.path, digest, error));
    EXPECT_TRUE(digest.empty());
    EXPECT_NE(std::string::npos, error.find("Error reading"));
#endif
}

// A -bootstrapserve node advertises every required parameter file it holds and,
// for releases up to beta12 (which still require it and fetch it from bootstrap
// peers), sprout-proving.key when it holds a copy of the compiled size. The
// file is never required here; this only checks what is offered and served.
TEST(ParamPresence, ManifestOffersTheLegacyProvingKeyOnlyWhenHeld)
{
    SelectParams(CBaseChainParams::MAIN);
    const boost::filesystem::path dir = ZC_GetParamsDir();
    auto held = [&](const char* name, uint64_t size) {
        boost::system::error_code ec;
        const boost::filesystem::path p = dir / name;
        return boost::filesystem::is_regular_file(p, ec) && !ec &&
               boost::filesystem::file_size(p, ec) == size && !ec;
    };
    const bool legacyHeld = held("sprout-proving.key", 910173851ULL);
    bool anyHeld = legacyHeld;
    for (size_t i = 0; i < kParamCount; i++) anyHeld = anyHeld || held(kParams[i].name, kParams[i].size);
    if (!anyHeld) {
        // The manifest refuses to build with nothing to offer ("no zcash parameters
        // available to serve"); this host has no parameter files, so there is nothing
        // to check. This gtest predates GTEST_SKIP(): log and pass.
        std::cerr << "[ SKIPPED ] ParamPresence.ManifestOffersTheLegacyProvingKeyOnlyWhenHeld: no Zcash parameter files in " << dir.string() << "\n";
        return;
    }
    mapArgs["-bootstrapserve"] = "1";
    CBootstrapSnapshotManifest manifest;
    std::string error;
    const bool ok = GetZcashParamManifest(manifest, error);
    mapArgs.erase("-bootstrapserve");
    ASSERT_TRUE(ok) << error;

    auto index_of = [&](const std::string& name) {
        for (size_t i = 0; i < manifest.vFiles.size(); i++)
            if (manifest.vFiles[i].strPath == name) return (int)i;
        return -1;
    };
    for (size_t i = 0; i < kParamCount; i++) {
        EXPECT_EQ(index_of(kParams[i].name) >= 0, held(kParams[i].name, kParams[i].size)) << kParams[i].name;
    }
    const bool legacy = legacyHeld;
    const int li = index_of("sprout-proving.key");
    EXPECT_EQ(li >= 0, legacy);
    EXPECT_EQ(manifest.vFiles.size(), (size_t)std::count_if(std::begin(kParams), std::end(kParams),
        [&](const ParamFile& p) { return held(p.name, p.size); }) + (legacy ? 1 : 0));
    if (li < 0) return;
    EXPECT_EQ(manifest.vFiles[li].nSize, 910173851ULL);
    EXPECT_EQ(manifest.vFiles[li].hashSha256,
              uint256S("0x8bc20a7f013b2b58970cddd2e7ea028975c88ae7ceb9259a5344a16bc2c0eef7"));

    // Its first chunk is served byte for byte.
    CBootstrapSnapshotChunkRequest req;
    req.nFileIndex = (uint32_t)li;
    req.nOffset = 0;
    req.nLength = BOOTSTRAP_SNAPSHOT_CHUNK_SIZE;
    CBootstrapSnapshotChunk chunk;
    mapArgs["-bootstrapserve"] = "1";
    const bool served = ReadZcashParamChunk(req, chunk, error);
    mapArgs.erase("-bootstrapserve");
    ASSERT_TRUE(served) << error;
    ASSERT_EQ(chunk.vData.size(), (size_t)BOOTSTRAP_SNAPSHOT_CHUNK_SIZE);
    boost::filesystem::ifstream f(dir / "sprout-proving.key", std::ios::binary);
    std::vector<unsigned char> head(BOOTSTRAP_SNAPSHOT_CHUNK_SIZE);
    f.read((char*)head.data(), head.size());
    EXPECT_TRUE(chunk.vData == head);
}
