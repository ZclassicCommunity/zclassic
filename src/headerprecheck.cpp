// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "headerprecheck.h"

#include "chain.h"
#include "chainparams.h"
#include "init.h"
#include "main.h"
#include "pow.h"
#include "util.h"

#include <algorithm>
#include <atomic>
#include <thread>

size_t PreverifyHeadersEquihash(const std::vector<CBlockHeader>& headers)
{
    if (headers.size() < MIN_HEADER_PRECHECK_CANDIDATES)
        return 0;
    if (!GetBoolArg("-headerprecheck", DEFAULT_HEADER_PRECHECK))
        return 0;
    // Without the memo the pre-pass would have nowhere to leave its results.
    if (!GetEquihashMemoEnabled())
        return 0;
    const unsigned int nCores = std::thread::hardware_concurrency();
    if (nCores <= 1)
        return 0;

    // Candidate selection, under a brief cs_main: exactly the headers the
    // serial loop in ProcessMessage("headers") would hand to CheckBlockHeader.
    size_t nBegin = 0, nEnd = 0;
    {
        LOCK(cs_main);
        while (nBegin < headers.size() && mapBlockIndex.count(headers[nBegin].GetHash()))
            nBegin++;
        if (nBegin == headers.size())
            return 0;
        // The serial loop stops after one verification when the first new
        // header does not connect (prev block not found or marked invalid).
        BlockMap::const_iterator mi = mapBlockIndex.find(headers[nBegin].hashPrevBlock);
        if (mi == mapBlockIndex.end() || (mi->second->nStatus & BLOCK_FAILED_MASK))
            return 0;
    }
    nEnd = nBegin + 1;
    while (nEnd < headers.size() && headers[nEnd].hashPrevBlock == headers[nEnd - 1].GetHash())
        nEnd++;
    const size_t nCandidates = nEnd - nBegin;
    if (nCandidates < MIN_HEADER_PRECHECK_CANDIDATES)
        return 0;

    const size_t nWidth = std::min<size_t>(std::min<size_t>(nCores, MAX_HEADER_PRECHECK_THREADS),
                                           nCandidates / 2);

    // Thread safety: CheckEquihashSolutionMemo only touches the Equihash
    // option globals (loaded under std::call_once, then atomics), the
    // verification counters (atomics), the memo (its own std::mutex) and the
    // logger (its own mutex). Params() is read-only after startup. No cs_main
    // or other lock is needed or taken here.
    std::atomic<size_t> next(nBegin);
    std::atomic<size_t> nVerified(0);
    std::atomic<bool> stop(false);
    const CChainParams& chainparams = Params();

    auto worker = [&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            if (ShutdownRequested()) {
                stop = true;
                return;
            }
            const size_t i = next.fetch_add(1);
            if (i >= nEnd)
                return;
            bool fValid = false;
            try {
                fValid = CheckEquihashSolutionMemo(&headers[i], chainparams);
            } catch (...) {
                fValid = false;
            }
            nVerified++;
            if (!fValid)
                stop = true;
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(nWidth);
    try {
        for (size_t t = 1; t < nWidth; t++)
            threads.emplace_back(worker);
    } catch (const std::exception& e) {
        // Could not start (all) workers: run with what we have.
        LogPrint("net", "%s: started %u of %u workers: %s\n", __func__,
                 (unsigned)threads.size(), (unsigned)(nWidth - 1), e.what());
    }
    worker(); // the calling thread is one of the workers
    for (std::thread& t : threads)
        t.join();

    LogPrint("bench", "    - Header Equihash pre-pass: %u of %u candidates, %u threads\n",
             (unsigned)nVerified.load(), (unsigned)nCandidates, (unsigned)(threads.size() + 1));
    return nVerified.load();
}
