// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "httpserver.h"

#include <univalue.h>

#include <limits>
#include <string>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(httpserver_tests)

BOOST_AUTO_TEST_CASE(busy_reply_is_json_rpc_error)
{
    std::string body = BuildBusyReply(16, 4);
    UniValue v;
    BOOST_REQUIRE(v.read(body));
    BOOST_REQUIRE(v.isObject());
    BOOST_CHECK(v["result"].isNull());
    BOOST_CHECK(v["id"].isNull());
    const UniValue& err = v["error"];
    BOOST_REQUIRE(err.isObject());
    BOOST_CHECK_EQUAL(err["code"].get_int(), -32603);
    const std::string msg = err["message"].get_str();
    BOOST_CHECK(msg.find("RPC server busy") != std::string::npos);
    BOOST_CHECK(msg.find("depth 16") != std::string::npos);
    BOOST_CHECK(msg.find("threads 4") != std::string::npos);
    BOOST_CHECK(msg.find("-rpcworkqueue") != std::string::npos);
    BOOST_CHECK(msg.find("-rpcthreads") != std::string::npos);
    // compact body: no newline, so it is one line in the HTTP reply
    BOOST_CHECK(body.find('\n') == std::string::npos);
}

static bool TuningOk(int64_t threads, int64_t workqueue, int64_t timeout)
{
    std::string err;
    return ValidateRpcTuning(threads, workqueue, timeout, err);
}

BOOST_AUTO_TEST_CASE(rpc_tuning_defaults_are_valid)
{
    BOOST_CHECK(TuningOk(DEFAULT_HTTP_THREADS, DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT));
}

BOOST_AUTO_TEST_CASE(rpc_threads_boundaries)
{
    BOOST_CHECK(!TuningOk(0, DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(TuningOk(1, DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(TuningOk(256, DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(!TuningOk(257, DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(!TuningOk(-1, DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(!TuningOk(std::numeric_limits<int64_t>::max(), DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT));
}

BOOST_AUTO_TEST_CASE(rpc_workqueue_boundaries)
{
    BOOST_CHECK(!TuningOk(DEFAULT_HTTP_THREADS, 0, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(TuningOk(DEFAULT_HTTP_THREADS, 1, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(TuningOk(DEFAULT_HTTP_THREADS, 65536, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(!TuningOk(DEFAULT_HTTP_THREADS, 65537, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(!TuningOk(DEFAULT_HTTP_THREADS, -5, DEFAULT_HTTP_SERVER_TIMEOUT));
    BOOST_CHECK(!TuningOk(DEFAULT_HTTP_THREADS, std::numeric_limits<int64_t>::max(), DEFAULT_HTTP_SERVER_TIMEOUT));
}

BOOST_AUTO_TEST_CASE(rpc_timeout_boundaries)
{
    BOOST_CHECK(!TuningOk(DEFAULT_HTTP_THREADS, DEFAULT_HTTP_WORKQUEUE, 0));
    BOOST_CHECK(TuningOk(DEFAULT_HTTP_THREADS, DEFAULT_HTTP_WORKQUEUE, 1));
    BOOST_CHECK(TuningOk(DEFAULT_HTTP_THREADS, DEFAULT_HTTP_WORKQUEUE, 86400));
    BOOST_CHECK(!TuningOk(DEFAULT_HTTP_THREADS, DEFAULT_HTTP_WORKQUEUE, 86401));
    BOOST_CHECK(!TuningOk(DEFAULT_HTTP_THREADS, DEFAULT_HTTP_WORKQUEUE, -1));
    BOOST_CHECK(!TuningOk(DEFAULT_HTTP_THREADS, DEFAULT_HTTP_WORKQUEUE, std::numeric_limits<int64_t>::max()));
}

BOOST_AUTO_TEST_CASE(rpc_tuning_error_text)
{
    std::string err;
    BOOST_CHECK(!ValidateRpcTuning(0, DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT, err));
    BOOST_CHECK_EQUAL(err, "-rpcthreads=0 is invalid: must be between 1 and 256 (default 4)");

    BOOST_CHECK(!ValidateRpcTuning(DEFAULT_HTTP_THREADS, -5, DEFAULT_HTTP_SERVER_TIMEOUT, err));
    BOOST_CHECK_EQUAL(err, "-rpcworkqueue=-5 is invalid: must be between 1 and 65536 (default 16)");

    BOOST_CHECK(!ValidateRpcTuning(DEFAULT_HTTP_THREADS, DEFAULT_HTTP_WORKQUEUE, 86401, err));
    BOOST_CHECK_EQUAL(err, "-rpcservertimeout=86401 is invalid: must be between 1 and 86400 (default 30)");

    BOOST_CHECK(!ValidateRpcTuning(std::numeric_limits<int64_t>::max(), DEFAULT_HTTP_WORKQUEUE, DEFAULT_HTTP_SERVER_TIMEOUT, err));
    BOOST_CHECK(err.find("-rpcthreads=9223372036854775807 is invalid") == 0);
}

BOOST_AUTO_TEST_SUITE_END()
