// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Differential tests for the LevelDB CRC32C: the run-time selected Extend()
// (SSE4.2 on x86-64, ARMv8 CRC32 on aarch64) against the portable table
// implementation. The value is an on-disk format, so it must match bit for bit.

#include <gtest/gtest.h>

#include <chrono>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include "leveldb/util/crc32c.h"

namespace {

using leveldb::crc32c::Extend;
using leveldb::crc32c::ExtendPortable;

void FillLcg(std::vector<char>& buf, uint32_t seed)
{
    uint32_t s = seed;
    for (size_t i = 0; i < buf.size(); i++) {
        s = s * 1664525u + 1013904223u;
        buf[i] = static_cast<char>(s >> 24);
    }
}

} // namespace

TEST(LevelDbCrc32c, PublishedVectors)
{
    EXPECT_EQ(0xe3069283u, leveldb::crc32c::Value("123456789", 9));
    std::vector<char> zeros(32, 0), ones(32, static_cast<char>(0xff));
    EXPECT_EQ(0x8a9136aau, leveldb::crc32c::Value(zeros.data(), zeros.size()));
    EXPECT_EQ(0x62a8ab43u, leveldb::crc32c::Value(ones.data(), ones.size()));
    EXPECT_EQ(0xe3069283u, ExtendPortable(0, "123456789", 9));
}

TEST(LevelDbCrc32c, MatchesPortableAllLengthsAndAlignments)
{
    // 32 buffers, each at start misalignment seed%8, every length 0..9000.
    for (uint32_t seed = 1; seed <= 32; seed++) {
        std::vector<char> buf(9000 + 8);
        FillLcg(buf, seed * 0x9e3779b9u);
        const uint32_t init = seed * 2654435761u;
        const size_t a = seed % 8;
        for (size_t n = 0; n <= 9000; n++) {
            ASSERT_EQ(ExtendPortable(init, buf.data() + a, n),
                      Extend(init, buf.data() + a, n))
                << "seed " << seed << " align " << a << " len " << n;
        }
    }
    // Every misalignment 0..7 on one buffer, short lengths.
    std::vector<char> buf(400);
    FillLcg(buf, 99);
    for (size_t a = 0; a < 8; a++) {
        for (size_t n = 0; n <= 300; n++) {
            ASSERT_EQ(ExtendPortable(0x1234u, buf.data() + a, n),
                      Extend(0x1234u, buf.data() + a, n))
                << "align " << a << " len " << n;
        }
    }
}

TEST(LevelDbCrc32c, ChainedExtendSplitsAtEveryPoint)
{
    std::vector<char> buf(257);
    FillLcg(buf, 77);
    const uint32_t whole = ExtendPortable(0, buf.data(), buf.size());
    for (size_t k = 0; k <= buf.size(); k++) {
        uint32_t c = Extend(0, buf.data(), k);
        c = Extend(c, buf.data() + k, buf.size() - k);
        ASSERT_EQ(whole, c) << "split " << k;
    }
}

TEST(LevelDbCrc32c, MaskRoundTrip)
{
    for (uint32_t v : {0u, 1u, 0xe3069283u, 0xffffffffu, 0x80000000u}) {
        EXPECT_EQ(v, leveldb::crc32c::Unmask(leveldb::crc32c::Mask(v)));
        EXPECT_NE(v, leveldb::crc32c::Mask(v));
    }
}

TEST(LevelDbCrc32c, ThroughputReport)
{
    std::vector<char> buf(64u << 20);
    FillLcg(buf, 5);
    auto time = [&](uint32_t (*f)(uint32_t, const char*, size_t), uint32_t* out) {
        auto t0 = std::chrono::steady_clock::now();
        *out = f(0, buf.data(), buf.size());
        std::chrono::duration<double> d = std::chrono::steady_clock::now() - t0;
        return 64.0 / d.count();
    };
    uint32_t a = 0, b = 0;
    const double portable = time(ExtendPortable, &a);
    const double selected = time(Extend, &b);
    EXPECT_EQ(a, b);
    printf("leveldb crc32c: hardware=%d portable=%.0f MiB/s selected=%.0f MiB/s\n",
           leveldb::crc32c::HaveHardwareCrc32c() ? 1 : 0, portable, selected);
}
