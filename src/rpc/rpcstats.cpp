// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/rpcstats.h"

#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <map>
#include <mutex>

namespace {

const size_t MAX_INFLIGHT = 128;
const size_t MAX_METHODS = 512;
const char* const OTHER_METHOD = "(other)";

struct InFlight {
    bool used;
    uint64_t id;
    std::string method;
    int64_t start_us;
};

struct MethodStats {
    uint64_t count;
    int64_t total_us;
    int64_t max_us;
    uint64_t errors;
};

std::mutex g_inflight_mutex;
InFlight g_inflight[MAX_INFLIGHT];
uint64_t g_next_id = 1;

std::mutex g_stats_mutex;
std::map<std::string, MethodStats> g_stats;

void Account(const std::string& method, int64_t elapsed_us, bool ok)
{
    std::lock_guard<std::mutex> lock(g_stats_mutex);
    std::map<std::string, MethodStats>::iterator it = g_stats.find(method);
    if (it == g_stats.end()) {
        const std::string& key = g_stats.size() >= MAX_METHODS ? std::string(OTHER_METHOD) : method;
        it = g_stats.find(key);
        if (it == g_stats.end()) {
            MethodStats zero = {0, 0, 0, 0};
            it = g_stats.insert(std::make_pair(key, zero)).first;
        }
    }
    it->second.count++;
    it->second.total_us += elapsed_us;
    if (elapsed_us > it->second.max_us)
        it->second.max_us = elapsed_us;
    if (!ok)
        it->second.errors++;
}

} // namespace

void RpcCallAccount(const std::string& method, int64_t elapsed_us, bool ok)
{
    Account(method, elapsed_us, ok);
}

uint64_t RpcCallBegin(const std::string& method)
{
    const int64_t now = GetTimeMicros();
    std::lock_guard<std::mutex> lock(g_inflight_mutex);
    for (size_t i = 0; i < MAX_INFLIGHT; i++) {
        if (!g_inflight[i].used) {
            g_inflight[i].used = true;
            g_inflight[i].id = g_next_id++;
            g_inflight[i].method = method;
            g_inflight[i].start_us = now;
            return g_inflight[i].id;
        }
    }
    return 0;
}

void RpcCallEnd(uint64_t id, bool ok)
{
    const int64_t now = GetTimeMicros();
    std::string method;
    int64_t start_us = now;
    bool found = false;
    if (id != 0) {
        std::lock_guard<std::mutex> lock(g_inflight_mutex);
        for (size_t i = 0; i < MAX_INFLIGHT; i++) {
            if (g_inflight[i].used && g_inflight[i].id == id) {
                method = g_inflight[i].method;
                start_us = g_inflight[i].start_us;
                g_inflight[i].used = false;
                g_inflight[i].method.clear();
                found = true;
                break;
            }
        }
    }
    if (!found) {
        // table was full (id 0) or unknown id: no method name, count it as other
        RpcCallAccount(OTHER_METHOD, 0, ok);
        return;
    }
    Account(method, now - start_us, ok);
}

bool IsSlowRpc(int64_t elapsed_us, int64_t threshold_ms)
{
    if (threshold_ms <= 0)
        return false;
    return elapsed_us >= threshold_ms * 1000;
}

UniValue RpcStatsToJSON()
{
    const int64_t now = GetTimeMicros();
    UniValue active(UniValue::VARR);
    {
        std::lock_guard<std::mutex> lock(g_inflight_mutex);
        for (size_t i = 0; i < MAX_INFLIGHT; i++) {
            if (!g_inflight[i].used)
                continue;
            UniValue o(UniValue::VOBJ);
            o.pushKV("method", g_inflight[i].method);
            o.pushKV("duration_us", now - g_inflight[i].start_us);
            active.push_back(o);
        }
    }
    UniValue methods(UniValue::VOBJ);
    {
        std::lock_guard<std::mutex> lock(g_stats_mutex);
        for (std::map<std::string, MethodStats>::const_iterator it = g_stats.begin(); it != g_stats.end(); ++it) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("count", (int64_t)it->second.count);
            o.pushKV("total_us", it->second.total_us);
            o.pushKV("max_us", it->second.max_us);
            o.pushKV("errors", (int64_t)it->second.errors);
            methods.pushKV(it->first, o);
        }
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("active_commands", active);
    ret.pushKV("methods", methods);
    return ret;
}

RpcCallScope::RpcCallScope(const std::string& methodIn)
    : id(RpcCallBegin(methodIn)), ok(false), start_us(GetTimeMicros()), method(methodIn)
{
}

RpcCallScope::~RpcCallScope()
{
    const int64_t elapsed = GetTimeMicros() - start_us;
    if (id == 0)
        RpcCallAccount(method, elapsed, ok); // untracked (table full): keep real name
    else
        RpcCallEnd(id, ok);
    if (IsSlowRpc(elapsed, GetArg("-rpcslowlog", 1000)))
        LogPrintf("WARN: slow RPC %s took %d ms\n", SanitizeString(method), (int)(elapsed / 1000));
}
