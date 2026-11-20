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
#include <unistd.h>
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

static const std::string PDIR = "/srv/params";

static ParamCacheFile SampleFile()
{
    ParamCacheFile in;
    in.version = 2;
    in.epoch = CompiledParamEpoch();
    in.paramsDir = PDIR;
    in.records = SampleRecords();
    return in;
}

BOOST_AUTO_TEST_CASE(serialize_parse_round_trip)
{
    const ParamCacheFile in = SampleFile();
    const std::string text = ParamCacheSerialize(in);
    BOOST_CHECK_EQUAL(text.substr(0, 26), "zclassic-params-verify v2\n");
    BOOST_CHECK(text.find("\nepoch " + in.epoch + "\nparamsdir " + PDIR + "\n") != std::string::npos);
    BOOST_CHECK(text.find("\nsapling-spend.params|47958396|1760600000|" + HASH_A + "\n") != std::string::npos);
    ParamCacheFile out;
    BOOST_REQUIRE(ParamCacheParse(text, in.epoch, PDIR, out));
    BOOST_CHECK_EQUAL(out.version, 2);
    BOOST_CHECK_EQUAL(out.paramsDir, PDIR);
    BOOST_CHECK(SameRecords(out.records, in.records));
    // No records is a valid (if useless) cache.
    ParamCacheFile empty = in;
    empty.records.clear();
    BOOST_CHECK(ParamCacheParse(ParamCacheSerialize(empty), in.epoch, PDIR, out));
    BOOST_CHECK(out.records.empty());
}

BOOST_AUTO_TEST_CASE(epoch_mismatch_is_cold)
{
    ParamCacheFile in = SampleFile();
    in.epoch = std::string(64, 'e');
    ParamCacheFile out;
    BOOST_CHECK(!ParamCacheParse(ParamCacheSerialize(in), CompiledParamEpoch(), PDIR, out));
    BOOST_CHECK(out.records.empty());
}

BOOST_AUTO_TEST_CASE(params_dir_mismatch_is_cold)
{
    const ParamCacheFile in = SampleFile();
    const std::string text = ParamCacheSerialize(in);
    ParamCacheFile out;
    BOOST_CHECK(!ParamCacheParse(text, in.epoch, "/srv/other", out));
    BOOST_CHECK(!ParamCacheParse(text, in.epoch, PDIR + "/", out));
    BOOST_CHECK(!ParamCacheParse(text, in.epoch, "", out));
    BOOST_CHECK(out.records.empty());
}

BOOST_AUTO_TEST_CASE(malformed_is_cold)
{
    const std::string epoch = CompiledParamEpoch();
    const std::string head = "zclassic-params-verify v2\nepoch " + epoch + "\nparamsdir " + PDIR + "\n";
    const std::string rec = "sapling-spend.params|1|2|" + HASH_A + "\n";
    std::string upper = HASH_A;
    for (size_t i = 0; i < upper.size(); ++i)
        upper[i] = (char)toupper(upper[i]);
    ParamCacheFile out;
    BOOST_REQUIRE(ParamCacheParse(head + rec, epoch, PDIR, out));
    const std::string bad[] = {
        "zclassic-params-verify v3\nepoch " + epoch + "\nparamsdir " + PDIR + "\n" + rec, // unknown version
        "zclassic-params-verify v2\nparamsdir " + PDIR + "\nepoch " + epoch + "\n" + rec, // order
        "zclassic-params-verify v2\nepoch " + epoch + "\n",                             // no params dir
        "zclassic-params-verify v2\n",
        head + rec.substr(0, rec.size() - 1),                                           // no final newline
        head + "\n" + rec,                                                              // empty line
        head + "sapling-spend.params|1|2|" + HASH_A + "\r\n",                           // CR
        head + "sapling-spend.params|1|2\n",                                            // three fields
        head + "sapling-spend.params|1|2|" + HASH_A + "|x\n",                           // five fields
        head + "|1|2|" + HASH_A + "\n",                                                 // no name
        head + "sapling-spend.params||2|" + HASH_A + "\n",                              // empty size
        head + "sapling-spend.params|+1|2|" + HASH_A + "\n",                            // signed size
        head + "sapling-spend.params|-1|2|" + HASH_A + "\n",
        head + "sapling-spend.params|1x|2|" + HASH_A + "\n",
        head + "sapling-spend.params|18446744073709551616|2|" + HASH_A + "\n",          // overflow
        head + "sapling-spend.params|1|9223372036854775808|" + HASH_A + "\n",
        head + "sapling-spend.params|1| 2|" + HASH_A + "\n",
        head + "sapling-spend.params|1|-|" + HASH_A + "\n",
        head + "sapling-spend.params|1|2|" + upper + "\n",                              // uppercase hex
        head + "sapling-spend.params|1|2|" + HASH_A.substr(1) + "\n",                   // short hash
        head + rec + rec,                                                               // duplicate
        head + "p sapling-spend.params 1 2 " + HASH_A + "\n",                           // v1 record in v2
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        ParamCacheFile f;
        BOOST_CHECK_MESSAGE(!ParamCacheParse(bad[i], epoch, PDIR, f), "accepted case " << i);
        BOOST_CHECK(f.records.empty());
    }
}

BOOST_AUTO_TEST_CASE(store_refuses_unserializable)
{
    const fs::path dir = MakeTempDir("unser");
    ParamCacheFile in = SampleFile();
    in.paramsDir = "/srv/a\nb";
    std::string error;
    BOOST_CHECK(!ParamCacheStore(dir / "c", in, error));
    in = SampleFile();
    in.records["bad|name"] = in.records.begin()->second;
    BOOST_CHECK(!ParamCacheStore(dir / "c", in, error));
    BOOST_CHECK(!fs::exists(dir / "c"));
    BOOST_CHECK(fs::is_empty(dir));
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(v2_store_then_load)
{
    const fs::path params = MakeTempDir("params");
    const fs::path data = MakeTempDir("data");
    const ParamCacheRecords recs = SampleRecords();
    BOOST_REQUIRE(StoreVerifiedParamCache(params, recs));
    const fs::path primary = params / "zclassic-params-verify.cache";
    BOOST_CHECK(primary == ParamCachePrimaryPath(params));
    BOOST_REQUIRE(fs::exists(primary));
#ifndef WIN32
    struct stat st;
    BOOST_REQUIRE_EQUAL(stat(primary.string().c_str(), &st), 0);
    BOOST_CHECK_EQUAL(st.st_mode & 0777, 0600);
#endif
    ParamCacheFile f;
    BOOST_REQUIRE(ParamCacheLoad(primary, CompiledParamEpoch(), ParamCacheCanonicalDir(params), f));
    BOOST_CHECK_EQUAL(f.version, 2);
    ParamCacheRecords got;
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, data, got), PARAMCACHE_PRIMARY);
    BOOST_CHECK(got == recs);
    // Nothing is written to the datadir, and no temp file is left beside the cache.
    BOOST_CHECK(fs::is_empty(data));
    size_t n = 0;
    for (fs::directory_iterator it(params); it != fs::directory_iterator(); ++it)
        ++n;
    BOOST_CHECK_EQUAL(n, 1U);
    fs::remove_all(params);
    fs::remove_all(data);
}

BOOST_AUTO_TEST_CASE(legacy_file_is_read_when_primary_absent)
{
    const fs::path params = MakeTempDir("params");
    const fs::path data = MakeTempDir("data");
    const std::string epoch = CompiledParamEpoch();
    WriteText(ParamCacheLegacyPath(data), LegacyText(epoch));
    ParamCacheRecords got;
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, data, got), PARAMCACHE_LEGACY);
    BOOST_CHECK(got == SampleRecords());
    // A store writes only the primary; the legacy file is left as it was.
    BOOST_REQUIRE(StoreVerifiedParamCache(params, got));
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, data, got), PARAMCACHE_PRIMARY);
    BOOST_CHECK(got == SampleRecords());
    ParamCacheFile legacy;
    BOOST_CHECK(ParamCacheLoad(ParamCacheLegacyPath(data), epoch, "", legacy));
    BOOST_CHECK_EQUAL(legacy.version, 1);
    fs::remove_all(params);
    fs::remove_all(data);
}

BOOST_AUTO_TEST_CASE(unusable_primary_does_not_fall_back)
{
    const fs::path params = MakeTempDir("params");
    const fs::path data = MakeTempDir("data");
    const std::string epoch = CompiledParamEpoch();
    WriteText(ParamCacheLegacyPath(data), LegacyText(epoch));
    // A v1 text in the primary location, then a v2 text for another params dir.
    WriteText(ParamCachePrimaryPath(params), LegacyText(epoch));
    ParamCacheRecords got;
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, data, got), PARAMCACHE_NONE);
    BOOST_CHECK(got.empty());
    WriteText(ParamCachePrimaryPath(params), ParamCacheSerialize(SampleFile()));
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, data, got), PARAMCACHE_NONE);
    BOOST_CHECK(got.empty());
    // A legacy-location file in v2 form is not honoured either.
    const fs::path params2 = MakeTempDir("params2");
    ParamCacheFile v2 = SampleFile();
    v2.paramsDir = ParamCacheCanonicalDir(params2);
    WriteText(ParamCacheLegacyPath(data), ParamCacheSerialize(v2));
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params2, data, got), PARAMCACHE_NONE);
    fs::remove_all(params);
    fs::remove_all(params2);
    fs::remove_all(data);
}

BOOST_AUTO_TEST_CASE(two_datadirs_share_one_params_dir)
{
    const fs::path params = MakeTempDir("params");
    const fs::path dataA = MakeTempDir("dataA");
    const fs::path dataB = MakeTempDir("dataB");
    ParamCacheRecords got;
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, dataA, got), PARAMCACHE_NONE);
    BOOST_REQUIRE(StoreVerifiedParamCache(params, SampleRecords()));
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, dataA, got), PARAMCACHE_PRIMARY);
    BOOST_CHECK(got == SampleRecords());
    got.clear();
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, dataB, got), PARAMCACHE_PRIMARY);
    BOOST_CHECK(got == SampleRecords());
    // A non-canonical spelling of the same directory still hits.
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params / "." , dataB, got), PARAMCACHE_PRIMARY);
    fs::remove_all(params);
    fs::remove_all(dataA);
    fs::remove_all(dataB);
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(group_writable_cache_is_rejected)
{
    const fs::path params = MakeTempDir("mode");
    const fs::path data = MakeTempDir("data");
    const std::string epoch = CompiledParamEpoch();
    BOOST_REQUIRE(StoreVerifiedParamCache(params, SampleRecords()));
    const fs::path file = ParamCachePrimaryPath(params);
    const std::string dir = ParamCacheCanonicalDir(params);
    ParamCacheFile f;
    BOOST_CHECK(ParamCacheLoad(file, epoch, dir, f));
    BOOST_REQUIRE_EQUAL(chmod(file.string().c_str(), 0620), 0); // g+w
    BOOST_CHECK(!ParamCacheLoad(file, epoch, dir, f));
    ParamCacheRecords got;
    BOOST_CHECK_EQUAL(LoadVerifiedParamCache(params, data, got), PARAMCACHE_NONE);
    BOOST_CHECK(got.empty());
    BOOST_REQUIRE_EQUAL(chmod(file.string().c_str(), 0602), 0); // o+w
    BOOST_CHECK(!ParamCacheLoad(file, epoch, dir, f));
    BOOST_REQUIRE_EQUAL(chmod(file.string().c_str(), 0644), 0); // read bits alone are fine
    BOOST_CHECK(ParamCacheLoad(file, epoch, dir, f));
    // The legacy file gets the same gate.
    WriteText(ParamCacheLegacyPath(data), LegacyText(epoch));
    BOOST_REQUIRE_EQUAL(chmod(ParamCacheLegacyPath(data).string().c_str(), 0620), 0);
    BOOST_CHECK(!ParamCacheLoad(ParamCacheLegacyPath(data), epoch, "", f));
    fs::remove_all(params);
    fs::remove_all(data);
}

BOOST_AUTO_TEST_CASE(read_only_params_dir_is_not_an_error)
{
    if (geteuid() == 0)
        return; // root writes through the mode bits
    const fs::path params = MakeTempDir("ro");
    BOOST_REQUIRE_EQUAL(chmod(params.string().c_str(), 0555), 0);
    BOOST_CHECK(!StoreVerifiedParamCache(params, SampleRecords()));
    BOOST_CHECK(!StoreVerifiedParamCache(params, SampleRecords())); // logged once, still false
    BOOST_CHECK(fs::is_empty(params));
    chmod(params.string().c_str(), 0755);
    fs::remove_all(params);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
