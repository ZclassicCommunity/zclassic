// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/rpcstats.h"

#include "utiltime.h"

#include "test/test_bitcoin.h"

#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

BOOST_FIXTURE_TEST_SUITE(rpcstats_tests, BasicTestingSetup)

static const UniValue* MethodStat(const UniValue& info, const std::string& name)
{
    const UniValue& methods = info["methods"];
    for (size_t i = 0; i < methods.getKeys().size(); i++)
        if (methods.getKeys()[i] == name)
            return &methods.getValues()[i];
    return NULL;
}

static int ActiveCount(const UniValue& info, const std::string& name)
{
    int n = 0;
    const UniValue& a = info["active_commands"];
    for (size_t i = 0; i < a.size(); i++)
        if (a[i]["method"].get_str() == name)
            n++;
    return n;
}

BOOST_AUTO_TEST_CASE(begin_end_counts_and_max)
{
    uint64_t a = RpcCallBegin("rpcstats_t_count");
    BOOST_CHECK(a != 0);
    BOOST_CHECK_EQUAL(ActiveCount(RpcStatsToJSON(), "rpcstats_t_count"), 1);
    MilliSleep(5);
    RpcCallEnd(a, true);
    BOOST_CHECK_EQUAL(ActiveCount(RpcStatsToJSON(), "rpcstats_t_count"), 0);
    uint64_t b = RpcCallBegin("rpcstats_t_count");
    RpcCallEnd(b, true);

    const UniValue info = RpcStatsToJSON();
    const UniValue* s = MethodStat(info, "rpcstats_t_count");
    BOOST_REQUIRE(s != NULL);
    BOOST_CHECK_EQUAL((*s)["count"].get_int64(), 2);
    BOOST_CHECK_EQUAL((*s)["errors"].get_int64(), 0);
    BOOST_CHECK((*s)["max_us"].get_int64() >= 5000);
    BOOST_CHECK((*s)["total_us"].get_int64() >= (*s)["max_us"].get_int64());
}

BOOST_AUTO_TEST_CASE(errors_counted)
{
    RpcCallEnd(RpcCallBegin("rpcstats_t_err"), false);
    RpcCallEnd(RpcCallBegin("rpcstats_t_err"), true);
    RpcCallEnd(RpcCallBegin("rpcstats_t_err"), false);
    const UniValue info = RpcStatsToJSON();
    const UniValue* s = MethodStat(info, "rpcstats_t_err");
    BOOST_REQUIRE(s != NULL);
    BOOST_CHECK_EQUAL((*s)["count"].get_int64(), 3);
    BOOST_CHECK_EQUAL((*s)["errors"].get_int64(), 2);
}

BOOST_AUTO_TEST_CASE(overflow_does_not_crash)
{
    std::vector<uint64_t> ids;
    int zeros = 0;
    for (int i = 0; i < 200; i++) {
        uint64_t id = RpcCallBegin("rpcstats_t_nest");
        if (id == 0) zeros++;
        ids.push_back(id);
    }
    BOOST_CHECK_EQUAL(zeros, 200 - 128);
    BOOST_CHECK_EQUAL(ActiveCount(RpcStatsToJSON(), "rpcstats_t_nest"), 128);
    for (size_t i = 0; i < ids.size(); i++)
        RpcCallEnd(ids[i], true);
    BOOST_CHECK_EQUAL(ActiveCount(RpcStatsToJSON(), "rpcstats_t_nest"), 0);
    // slots are reusable afterwards
    uint64_t again = RpcCallBegin("rpcstats_t_nest");
    BOOST_CHECK(again != 0);
    RpcCallEnd(again, true);
}

BOOST_AUTO_TEST_CASE(slow_threshold_boundaries)
{
    BOOST_CHECK(!IsSlowRpc(999 * 1000, 1000));
    BOOST_CHECK(!IsSlowRpc(999999, 1000));
    BOOST_CHECK(IsSlowRpc(1000 * 1000, 1000));
    BOOST_CHECK(IsSlowRpc(1000 * 1000 + 1, 1000));
    BOOST_CHECK(!IsSlowRpc(1000000000LL, 0));
    BOOST_CHECK(!IsSlowRpc(0, 0));
}

BOOST_AUTO_TEST_CASE(json_shape)
{
    {
        RpcCallScope ok_scope("rpcstats_t_scope");
        ok_scope.ok = true;
    }
    { RpcCallScope fail_scope("rpcstats_t_scope"); }
    uint64_t live = RpcCallBegin("rpcstats_t_live");

    const UniValue info = RpcStatsToJSON();
    BOOST_CHECK(info.isObject());
    BOOST_CHECK(info["active_commands"].isArray());
    BOOST_CHECK(info["methods"].isObject());
    BOOST_REQUIRE_EQUAL(ActiveCount(info, "rpcstats_t_live"), 1);
    const UniValue& a = info["active_commands"];
    for (size_t i = 0; i < a.size(); i++) {
        BOOST_CHECK(a[i].isObject());
        BOOST_CHECK(a[i]["method"].isStr());
        BOOST_CHECK(a[i]["duration_us"].isNum());
    }
    const UniValue* s = MethodStat(info, "rpcstats_t_scope");
    BOOST_REQUIRE(s != NULL);
    BOOST_CHECK_EQUAL((*s)["count"].get_int64(), 2);
    BOOST_CHECK_EQUAL((*s)["errors"].get_int64(), 1);
    BOOST_CHECK((*s)["total_us"].isNum());
    BOOST_CHECK((*s)["max_us"].isNum());
    RpcCallEnd(live, true);
}

BOOST_AUTO_TEST_CASE(method_name_cap)
{
    for (int i = 0; i < 600; i++)
        RpcCallEnd(RpcCallBegin("rpcstats_t_cap" + std::to_string(i)), true);
    const UniValue info = RpcStatsToJSON();
    BOOST_CHECK(info["methods"].getKeys().size() <= 513);
    const UniValue* other = MethodStat(info, "(other)");
    BOOST_REQUIRE(other != NULL);
    BOOST_CHECK((*other)["count"].get_int64() >= 1);
}

BOOST_AUTO_TEST_SUITE_END()
