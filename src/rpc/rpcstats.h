// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCLASSIC_RPC_RPCSTATS_H
#define ZCLASSIC_RPC_RPCSTATS_H

#include <stdint.h>
#include <string>

#include <univalue.h>

/**
 * RPC observability: an in-flight call table and per-method aggregates.
 * Method names and durations only; parameters are never recorded or logged.
 * Takes no cs_main; it uses two private mutexes that are never held together
 * with any other lock.
 */

/** Register a call as started. Returns a slot id, or 0 if the table is full. */
uint64_t RpcCallBegin(const std::string& method);

/** Retire a call. id 0 (table was full) only updates the aggregates. */
void RpcCallEnd(uint64_t id, bool ok);

/** Aggregate-only update for a call that has no in-flight slot. */
void RpcCallAccount(const std::string& method, int64_t elapsed_us, bool ok);

/** true when elapsed_us >= threshold_ms * 1000; threshold_ms <= 0 never. */
bool IsSlowRpc(int64_t elapsed_us, int64_t threshold_ms);

/** {"active_commands":[{method,duration_us}], "methods":{name:{count,total_us,max_us,errors}}} */
UniValue RpcStatsToJSON();

/** RAII helper: Begin on construction, End (and slow-call WARN) on destruction. */
struct RpcCallScope {
    uint64_t id;
    bool ok;
    int64_t start_us;
    std::string method;
    explicit RpcCallScope(const std::string& methodIn);
    ~RpcCallScope();
    RpcCallScope(const RpcCallScope&) = delete;
    RpcCallScope& operator=(const RpcCallScope&) = delete;
};

#endif // ZCLASSIC_RPC_RPCSTATS_H
