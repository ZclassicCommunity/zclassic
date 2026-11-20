// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "shutdownmarker.h"
#include "phasetimer.h"

#include "random.h"
#include "test/test_bitcoin.h"
#include "tinyformat.h"
#include "util.h"
#include "utiltime.h"

#include <algorithm>
#include <ctype.h>
#include <stdio.h>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

#ifndef WIN32
#include <sys/stat.h>
#include <sys/time.h>
#endif

namespace fs = boost::filesystem;

BOOST_FIXTURE_TEST_SUITE(shutdownmarker_tests, BasicTestingSetup)

static ShutdownBinding SampleBinding()
{
    ShutdownBinding b;
    b.tipHash = uint256S("00000a1b2c3d4e5f60718293a4b5c6d7e8f9000102030405060708090a0b0c0d");
    b.tipHeight = 1234567;
    b.coinsBest = b.tipHash;
    b.filesDigest = uint256S("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    return b;
}

static fs::path MakeTempDir()
{
    fs::path p = GetTempPath() / strprintf("shutdownmarker_%lu_%i", (unsigned long)GetTime(), (int)GetRand(1000000));
    fs::create_directories(p);
    return p;
}

static void WriteText(const fs::path& p, const std::string& s)
{
    FILE* f = fopen(p.string().c_str(), "wb");
    BOOST_REQUIRE(f != NULL);
    BOOST_REQUIRE_EQUAL(fwrite(s.data(), 1, s.size(), f), s.size());
    fclose(f);
}

static bool SameBinding(const ShutdownBinding& a, const ShutdownBinding& b)
{
    return a.tipHash == b.tipHash && a.tipHeight == b.tipHeight && a.coinsBest == b.coinsBest &&
           a.filesDigest == b.filesDigest;
}

static std::string Replace(std::string s, const std::string& from, const std::string& to)
{
    size_t pos = s.find(from);
    BOOST_REQUIRE(pos != std::string::npos);
    return s.replace(pos, from.size(), to);
}

BOOST_AUTO_TEST_CASE(serialize_parse_round_trip)
{
    const ShutdownBinding b = SampleBinding();
    const std::string text = SerializeBinding(b);
    BOOST_CHECK(text.find("magic=ZCLSHUT\n") == 0);
    BOOST_CHECK(text.find("version=1\n") != std::string::npos);
    BOOST_CHECK(text.find("height=1234567\n") != std::string::npos);
    ShutdownBinding out;
    BOOST_CHECK(ParseBinding(text, out));
    BOOST_CHECK(SameBinding(b, out));
}

BOOST_AUTO_TEST_CASE(parse_rejects_malformed)
{
    const std::string good = SerializeBinding(SampleBinding());
    const std::string tipLine = "tip=" + SampleBinding().tipHash.GetHex() + "\n";
    ShutdownBinding out;
    BOOST_CHECK(ParseBinding(good, out));

    // missing key
    BOOST_CHECK(!ParseBinding(Replace(good, tipLine, ""), out));
    // extra key
    BOOST_CHECK(!ParseBinding(good + "extra=1\n", out));
    // repeated key
    BOOST_CHECK(!ParseBinding(good + tipLine, out));
    // bad hex: a non-hex digit, and a short value
    BOOST_CHECK(!ParseBinding(Replace(good, tipLine, "tip=" + std::string(63, '0') + "g\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, tipLine, "tip=" + std::string(62, '0') + "\n"), out));
    // bad height
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", "height=-1\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", "height=12x\n"), out));
    // wrong magic or version
    BOOST_CHECK(!ParseBinding(Replace(good, "magic=ZCLSHUT\n", "magic=ZCLSHUX\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "version=1\n", "version=2\n"), out));
    // truncated (no final newline), empty, and a line without '='
    BOOST_CHECK(!ParseBinding(good.substr(0, good.size() - 1), out));
    BOOST_CHECK(!ParseBinding("", out));
    BOOST_CHECK(!ParseBinding(good + "garbage\n", out));
    // out is untouched by failures
    ShutdownBinding fresh;
    BOOST_CHECK(!ParseBinding("magic=ZCLSHUT\n", fresh));
    BOOST_CHECK_EQUAL(fresh.tipHeight, -1);
}

// Line framing, key set and value rules of ParseBinding, one malformed shape at
// a time (characterization: these pin today's results).
BOOST_AUTO_TEST_CASE(parse_binding_framing_and_values)
{
    const ShutdownBinding sample = SampleBinding();
    const std::string good = SerializeBinding(sample);
    const std::string tipLine = "tip=" + sample.tipHash.GetHex() + "\n";
    const std::string coinsLine = "coins=" + sample.coinsBest.GetHex() + "\n";
    const std::string filesLine = "files=" + sample.filesDigest.GetHex() + "\n";
    ShutdownBinding out;

    // framing: an empty key, a blank line, CRLF endings, a lone newline
    BOOST_CHECK(!ParseBinding("=x\n" + good, out));
    BOOST_CHECK(!ParseBinding(Replace(good, tipLine, tipLine + "=\n"), out));
    BOOST_CHECK(!ParseBinding(good + "\n", out));
    BOOST_CHECK(!ParseBinding("\n", out));
    BOOST_CHECK(!ParseBinding(Replace(good, "magic=ZCLSHUT\n", "magic=ZCLSHUT\r\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, tipLine, "tip=" + sample.tipHash.GetHex() + "\r\n"), out));
    // an embedded NUL in the height value
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", std::string("height=12\0" "34567\n", 16)), out));

    // key set: six keys with one unknown in place of a known one, a key that
    // differs only in case, and a key with a trailing space
    BOOST_CHECK(!ParseBinding(Replace(good, coinsLine, "coin=" + sample.coinsBest.GetHex() + "\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "magic=", "Magic="), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "version=", "version ="), out));
    // each key missing in turn
    BOOST_CHECK(!ParseBinding(Replace(good, "magic=ZCLSHUT\n", ""), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "version=1\n", ""), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", ""), out));
    BOOST_CHECK(!ParseBinding(Replace(good, coinsLine, ""), out));
    BOOST_CHECK(!ParseBinding(Replace(good, filesLine, ""), out));
    // a repeated key whose second value is the same
    BOOST_CHECK(!ParseBinding(Replace(good, "version=1\n", "version=1\nversion=1\n"), out));

    // values: an '=' inside a value belongs to the value
    BOOST_CHECK(!ParseBinding(Replace(good, tipLine, "tip==" + sample.tipHash.GetHex().substr(1) + "\n"), out));
    // bad hex in coins and files, a 65-digit and an empty hash
    BOOST_CHECK(!ParseBinding(Replace(good, coinsLine, "coins=" + std::string(64, 'z') + "\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, filesLine, "files=" + std::string(65, '0') + "\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, filesLine, "files=\n"), out));
    // height: empty, padded, beyond int32, a magic and version with padding
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", "height=\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", "height= 1234567\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", "height=1234567 \n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", "height=2147483648\n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "magic=ZCLSHUT\n", "magic=ZCLSHUT \n"), out));
    BOOST_CHECK(!ParseBinding(Replace(good, "version=1\n", "version=01\n"), out));

    // accepted: any line order, upper-case hex, height 0 and INT32_MAX
    std::string reordered = Replace(good, "magic=ZCLSHUT\n", "");
    reordered = Replace(reordered, filesLine, filesLine + "magic=ZCLSHUT\n");
    BOOST_CHECK(ParseBinding(reordered, out));
    BOOST_CHECK(SameBinding(sample, out));
    std::string upper = sample.tipHash.GetHex();
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    BOOST_CHECK(ParseBinding(Replace(good, tipLine, "tip=" + upper + "\n"), out));
    BOOST_CHECK(out.tipHash == sample.tipHash);
    BOOST_CHECK(ParseBinding(Replace(good, "height=1234567\n", "height=0\n"), out));
    BOOST_CHECK_EQUAL(out.tipHeight, 0);
    BOOST_CHECK(ParseBinding(Replace(good, "height=1234567\n", "height=2147483647\n"), out));
    BOOST_CHECK_EQUAL(out.tipHeight, 2147483647);

    // a failure late in the parse (the last value checked) leaves out as it was
    ShutdownBinding kept = sample;
    kept.tipHeight = 7;
    BOOST_CHECK(!ParseBinding(Replace(good, "height=1234567\n", "height=-5\n"), kept));
    BOOST_CHECK(!ParseBinding(Replace(good, filesLine, "files=" + std::string(64, 'g') + "\n"), kept));
    BOOST_CHECK_EQUAL(kept.tipHeight, 7);
    BOOST_CHECK(kept.filesDigest == sample.filesDigest);
}

BOOST_AUTO_TEST_CASE(write_and_consume_single_use)
{
    const fs::path dir = MakeTempDir();
    const fs::path marker = dir / SHUTDOWN_MARKER_FILENAME;
    ShutdownBinding out;

    BOOST_CHECK(!ConsumeCleanMarker(dir, out)); // no marker

    BOOST_REQUIRE(WriteCleanMarker(dir, SampleBinding()));
    BOOST_CHECK(fs::exists(marker));
    BOOST_CHECK(!fs::exists(dir / (std::string(SHUTDOWN_MARKER_FILENAME) + ".tmp")));
    BOOST_CHECK(ConsumeCleanMarker(dir, out));
    BOOST_CHECK(SameBinding(out, SampleBinding()));
    BOOST_CHECK(!fs::exists(marker));
    BOOST_CHECK(!ConsumeCleanMarker(dir, out)); // second consume

    // A corrupt marker is removed too, and the parse result is false.
    WriteText(marker, "magic=ZCLSHUT\nversion=1\n");
    BOOST_CHECK(!ConsumeCleanMarker(dir, out));
    BOOST_CHECK(!fs::exists(marker));
    BOOST_CHECK(!ConsumeCleanMarker(dir, out));

    // An oversized marker is not trusted and is removed.
    WriteText(marker, SerializeBinding(SampleBinding()) + std::string(5000, '#'));
    BOOST_CHECK(!ConsumeCleanMarker(dir, out));
    BOOST_CHECK(!fs::exists(marker));

    // A leftover temp file from an interrupted write is removed and never trusted.
    WriteText(dir / (std::string(SHUTDOWN_MARKER_FILENAME) + ".tmp"), SerializeBinding(SampleBinding()));
    BOOST_CHECK(!ConsumeCleanMarker(dir, out));
    BOOST_CHECK(!fs::exists(dir / (std::string(SHUTDOWN_MARKER_FILENAME) + ".tmp")));

    fs::remove_all(dir);
}

#ifndef WIN32
static void SetMtime(const fs::path& p, long sec, long usec)
{
    struct timeval tv[2];
    tv[0].tv_sec = sec; tv[0].tv_usec = usec;
    tv[1].tv_sec = sec; tv[1].tv_usec = usec;
    BOOST_REQUIRE_EQUAL(utimes(p.string().c_str(), tv), 0);
}
#endif

BOOST_AUTO_TEST_CASE(files_digest_tracks_size_and_mtime)
{
    const fs::path dir = MakeTempDir();
    const uint256 empty = ComputeFilesDigest(dir);
    BOOST_CHECK(ComputeFilesDigest(dir) == empty);

    fs::create_directories(dir / "blocks" / "index");
    fs::create_directories(dir / "chainstate");
    WriteText(dir / "blocks" / "blk00000.dat", "abc");
    WriteText(dir / "blocks" / "rev00000.dat", "r");
    WriteText(dir / "blocks" / "index" / "CURRENT", "MANIFEST-000002\n");
    WriteText(dir / "blocks" / "index" / "000003.log", "l");
    WriteText(dir / "chainstate" / "CURRENT", "MANIFEST-000004\n");
    WriteText(dir / "chainstate" / "MANIFEST-000004", "m");
    WriteText(dir / "chainstate" / "000005.ldb", "t");
#ifndef WIN32
    SetMtime(dir / "blocks" / "blk00000.dat", 1700000000, 0);
    SetMtime(dir / "chainstate" / "CURRENT", 1700000000, 0);
#endif
    const uint256 base = ComputeFilesDigest(dir);
    BOOST_CHECK(base != empty);
    BOOST_CHECK(ComputeFilesDigest(dir) == base); // stable

    // Files the digest does not cover do not change it.
    WriteText(dir / "blocks" / "index" / "LOG", "leveldb info log");
    WriteText(dir / "chainstate" / "LOCK", "");
    WriteText(dir / "peers.dat", "x");
    WriteText(dir / "blocks" / "notablock.txt", "x");
    BOOST_CHECK(ComputeFilesDigest(dir) == base);

#ifndef WIN32
    // An mtime change alone, below one second, changes it; restoring it restores the digest.
    SetMtime(dir / "chainstate" / "CURRENT", 1700000000, 500000);
    const uint256 touched = ComputeFilesDigest(dir);
    BOOST_CHECK(touched != base);
    SetMtime(dir / "chainstate" / "CURRENT", 1700000000, 0);
    BOOST_CHECK(ComputeFilesDigest(dir) == base);

    // A size change (same mtime) changes it.
    WriteText(dir / "blocks" / "blk00000.dat", "abcd");
    SetMtime(dir / "blocks" / "blk00000.dat", 1700000000, 0);
    BOOST_CHECK(ComputeFilesDigest(dir) != base);
    WriteText(dir / "blocks" / "blk00000.dat", "abc");
    SetMtime(dir / "blocks" / "blk00000.dat", 1700000000, 0);
    BOOST_CHECK(ComputeFilesDigest(dir) == base);
#endif

    // A new covered file changes it, and so does removing one.
    WriteText(dir / "blocks" / "blk00001.dat", "");
    BOOST_CHECK(ComputeFilesDigest(dir) != base);
    fs::remove(dir / "blocks" / "blk00001.dat");
    BOOST_CHECK(ComputeFilesDigest(dir) == base);
    fs::remove(dir / "chainstate" / "000005.ldb");
    BOOST_CHECK(ComputeFilesDigest(dir) != base);

    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(phase_line_format)
{
    BOOST_CHECK_EQUAL(FormatPhaseLine("Shutdown", "db-close", 1234), "Shutdown: db-close took 1234 ms\n");
    BOOST_CHECK_EQUAL(FormatPhaseLine("Shutdown", "zmq", 0), "Shutdown: zmq took 0 ms\n");
    BOOST_CHECK_EQUAL(PHASE_TIMER_LOG_MIN_MS, 100);
}

BOOST_AUTO_TEST_SUITE_END()
