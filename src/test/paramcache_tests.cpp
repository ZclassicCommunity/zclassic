// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "paramcache.h"

#include "random.h"
#include "test/test_bitcoin.h"
#include "tinyformat.h"
#include "util.h"
#include "utiltime.h"

#include <stdio.h>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

#ifndef WIN32
#include <sys/stat.h>
#endif

namespace fs = boost::filesystem;

BOOST_FIXTURE_TEST_SUITE(paramcache_tests, BasicTestingSetup)

static const std::string HASH_A = "aa3c1e0e4a1b2c3d4e5f60718293a4b5c6d7e8f9000102030405060708090a0b";
static const std::string HASH_B = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static fs::path MakeTempDir(const char* tag)
{
    fs::path p = GetTempPath() / strprintf("paramcache_%s_%lu_%i", tag, (unsigned long)GetTime(), (int)GetRand(1000000));
    fs::create_directories(p);
    return p;
}

static void WriteText(const fs::path& p, const std::string& s)
{
    FILE* f = fopen(p.string().c_str(), "wb");
    BOOST_REQUIRE(f != NULL);
    BOOST_REQUIRE_EQUAL(fwrite(s.data(), 1, s.size(), f), s.size());
    fclose(f);
#ifndef WIN32
    chmod(p.string().c_str(), 0600);
#endif
}

static ParamCacheRecords SampleRecords()
{
    ParamCacheRecords recs;
    ParamCacheRecord a;
    a.size = 47958396;
    a.mtime = 1760600000;
    a.verifiedHash = HASH_A;
    recs["sapling-spend.params"] = a;
    ParamCacheRecord b;
    b.size = 1449;
    b.mtime = -5;
    b.verifiedHash = HASH_B;
    recs["sprout-verifying.key"] = b;
    return recs;
}

static bool SameRecords(const ParamCacheRecords& x, const ParamCacheRecords& y)
{
    if (x.size() != y.size())
        return false;
    for (ParamCacheRecords::const_iterator it = x.begin(); it != x.end(); ++it) {
        ParamCacheRecords::const_iterator jt = y.find(it->first);
        if (jt == y.end() || jt->second.size != it->second.size || jt->second.mtime != it->second.mtime ||
            jt->second.verifiedHash != it->second.verifiedHash)
            return false;
    }
    return true;
}

// The text the base release wrote to <datadir>/params-verify.cache (format v1).
static std::string LegacyText(const std::string& epoch)
{
    return "v 1\n"
           "epoch " + epoch + "\n"
           "p sapling-spend.params 47958396 1760600000 " + HASH_A + "\n"
           "p sprout-verifying.key 1449 -5 " + HASH_B + "\n";
}

BOOST_AUTO_TEST_CASE(epoch_is_stable_hex)
{
    const std::string e = CompiledParamEpoch();
    BOOST_CHECK_EQUAL(e.size(), 64U);
    BOOST_CHECK_EQUAL(e, CompiledParamEpoch());
}

BOOST_AUTO_TEST_CASE(legacy_text_parses)
{
    const std::string epoch = CompiledParamEpoch();
    ParamCacheFile f;
    BOOST_REQUIRE(ParamCacheParse(LegacyText(epoch), epoch, "", f));
    BOOST_CHECK_EQUAL(f.version, 1);
    BOOST_CHECK(SameRecords(f.records, SampleRecords()));
    // Blank lines and any key order were accepted by the v1 reader.
    ParamCacheFile g;
    BOOST_CHECK(ParamCacheParse("\np sapling-spend.params 1 2 " + HASH_A + "\n\nepoch " + epoch + "\n", epoch, "", g));
    BOOST_CHECK_EQUAL(g.records.size(), 1U);
}

BOOST_AUTO_TEST_CASE(legacy_epoch_mismatch_is_cold)
{
    const std::string epoch = CompiledParamEpoch();
    const std::string other(64, 'f');
    ParamCacheFile f;
    BOOST_CHECK(!ParamCacheParse(LegacyText(other), epoch, "", f));
    BOOST_CHECK(f.records.empty());
    BOOST_CHECK(!ParamCacheParse("v 1\np sapling-spend.params 1 2 " + HASH_A + "\n", epoch, "", f));
}

BOOST_AUTO_TEST_CASE(legacy_malformed_is_cold)
{
    const std::string epoch = CompiledParamEpoch();
    const std::string head = "v 1\nepoch " + epoch + "\n";
    std::string upper = HASH_A;
    for (size_t i = 0; i < upper.size(); ++i)
        upper[i] = (char)toupper(upper[i]);
    const std::string bad[] = {
        "v 2\n",
        "v\n",
        "epoch short\n",
        "p sapling-spend.params 1 2\n",
        "p sapling-spend.params x 2 " + HASH_A + "\n",
        "q sapling-spend.params 1 2 " + HASH_A + "\n",
        "p dup 1 2 " + HASH_A + "\np dup 1 2 " + HASH_A + "\n",
        "p upper 1 2 " + upper + "\n",
        "p short 1 2 abcdef\n",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        ParamCacheFile f;
        BOOST_CHECK_MESSAGE(!ParamCacheParse(head + bad[i], epoch, "", f), "accepted: " + bad[i]);
    }
}

BOOST_AUTO_TEST_CASE(serialize_parse_round_trip)
{
    ParamCacheFile in;
    in.version = 1;
    in.epoch = CompiledParamEpoch();
    in.records = SampleRecords();
    ParamCacheFile out;
    BOOST_REQUIRE(ParamCacheParse(ParamCacheSerialize(in), in.epoch, "", out));
    BOOST_CHECK(SameRecords(out.records, in.records));
}

BOOST_AUTO_TEST_CASE(store_then_load)
{
    const fs::path dir = MakeTempDir("store");
    ParamCacheRecords recs = SampleRecords();
    StoreVerifiedParamCache(dir, recs);
    ParamCacheRecords got;
    BOOST_CHECK(LoadVerifiedParamCache(dir, got));
    BOOST_CHECK(SameRecords(got, recs));
    fs::remove_all(dir);
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(group_writable_cache_is_rejected)
{
    const fs::path dir = MakeTempDir("mode");
    const std::string epoch = CompiledParamEpoch();
    const fs::path file = dir / "params-verify.cache";
    WriteText(file, LegacyText(epoch));
    ParamCacheFile f;
    BOOST_CHECK(ParamCacheLoad(file, epoch, "", f));
    BOOST_REQUIRE_EQUAL(chmod(file.string().c_str(), 0620), 0);
    BOOST_CHECK(!ParamCacheLoad(file, epoch, "", f));
    BOOST_REQUIRE_EQUAL(chmod(file.string().c_str(), 0602), 0);
    BOOST_CHECK(!ParamCacheLoad(file, epoch, "", f));
    ParamCacheRecords got;
    BOOST_CHECK(!LoadVerifiedParamCache(dir, got));
    BOOST_CHECK(got.empty());
    fs::remove_all(dir);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
