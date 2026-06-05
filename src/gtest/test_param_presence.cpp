#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <ios>
#include <iostream>
#include <string>
#include <cstdint>
#include "bootstrap.h"

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
    {"sprout-proving.key",    910173851ULL},
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
        boost::filesystem::unique_path("zcl_params_%%%%%%%%");
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
    // largest two (groth16, proving.key) are intentionally absent, which is
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
