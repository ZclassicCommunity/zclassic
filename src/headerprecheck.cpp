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
#include <functional>
#include <thread>

namespace {

/** The cores the pre-pass may use for headers, or 0 when it must not run. */
unsigned int PrecheckCores(const std::vector<CBlockHeader>& headers)
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
    return nCores;
}

/** The index of the first header the serial loop would verify, or
 *  headers.size() when it would verify none. Takes a brief cs_main. */
size_t FirstCandidate(const std::vector<CBlockHeader>& headers)
{
    LOCK(cs_main);
    size_t nBegin = 0;
    while (nBegin < headers.size() && mapBlockIndex.count(headers[nBegin].GetHash()))
        nBegin++;
    if (nBegin == headers.size())
        return headers.size();
    // The serial loop stops after one verification when the first new
    // header does not connect (prev block not found or marked invalid).
    BlockMap::const_iterator mi = mapBlockIndex.find(headers[nBegin].hashPrevBlock);
    if (mi == mapBlockIndex.end() || (mi->second->nStatus & BLOCK_FAILED_MASK))
        return headers.size();
    return nBegin;
}

/** One past the last header continuous with headers[nBegin]. */
size_t CandidateEnd(const std::vector<CBlockHeader>& headers, size_t nBegin)
{
    size_t nEnd = nBegin + 1;
    while (nEnd < headers.size() && headers[nEnd].hashPrevBlock == headers[nEnd - 1].GetHash())
        nEnd++;
    return nEnd;
}

/** State the workers share. */
struct PrecheckWork {
    const std::vector<CBlockHeader>& headers;
    const size_t nEnd;
    const CChainParams& chainparams;
    std::atomic<size_t> next;
    std::atomic<size_t> nVerified;
    std::atomic<bool> stop;

    PrecheckWork(const std::vector<CBlockHeader>& headersIn, size_t nBegin, size_t nEndIn)
        : headers(headersIn), nEnd(nEndIn), chainparams(Params()), next(nBegin), nVerified(0), stop(false) {}
};

// Thread safety: CheckEquihashSolutionMemo only touches the Equihash
// option globals (loaded under std::call_once, then atomics), the
// verification counters (atomics), the memo (its own std::mutex) and the
// logger (its own mutex). Params() is read-only after startup. No cs_main
// or other lock is needed or taken here.
void PrecheckWorker(PrecheckWork& work)
{
    while (!work.stop.load(std::memory_order_relaxed)) {
        if (ShutdownRequested()) {
            work.stop = true;
            return;
        }
        const size_t i = work.next.fetch_add(1);
        if (i >= work.nEnd)
            return;
        bool fValid = false;
        try {
            fValid = CheckEquihashSolutionMemo(&work.headers[i], work.chainparams);
        } catch (...) {
            fValid = false;
        }
        work.nVerified++;
        if (!fValid)
            work.stop = true;
    }
}

/** Run nWidth workers (the calling thread is one of them); returns how many
 *  threads ran, the caller included. */
size_t RunPrecheckWorkers(PrecheckWork& work, size_t nWidth)
{
    std::vector<std::thread> threads;
    threads.reserve(nWidth);
    try {
        for (size_t t = 1; t < nWidth; t++)
            threads.emplace_back(PrecheckWorker, std::ref(work));
    } catch (const std::exception& e) {
        // Could not start (all) workers: run with what we have.
        LogPrint("net", "%s: started %u of %u workers: %s\n", "PreverifyHeadersEquihash",
                 (unsigned)threads.size(), (unsigned)(nWidth - 1), e.what());
    }
    PrecheckWorker(work); // the calling thread is one of the workers
    for (std::thread& t : threads)
        t.join();
    return threads.size() + 1;
}

} // namespace

size_t PreverifyHeadersEquihash(const std::vector<CBlockHeader>& headers)
{
    const unsigned int nCores = PrecheckCores(headers);
    if (nCores == 0)
        return 0;

    // Candidate selection: exactly the headers the serial loop in
    // ProcessMessage("headers") would hand to CheckBlockHeader.
    const size_t nBegin = FirstCandidate(headers);
    if (nBegin == headers.size())
        return 0;
    const size_t nEnd = CandidateEnd(headers, nBegin);
    const size_t nCandidates = nEnd - nBegin;
    if (nCandidates < MIN_HEADER_PRECHECK_CANDIDATES)
        return 0;

    const size_t nWidth = std::min<size_t>(std::min<size_t>(nCores, MAX_HEADER_PRECHECK_THREADS),
                                           nCandidates / 2);
    PrecheckWork work(headers, nBegin, nEnd);
    const size_t nThreads = RunPrecheckWorkers(work, nWidth);

    LogPrint("bench", "    - Header Equihash pre-pass: %u of %u candidates, %u threads\n",
             (unsigned)work.nVerified.load(), (unsigned)nCandidates, (unsigned)nThreads);
    return work.nVerified.load();
}
