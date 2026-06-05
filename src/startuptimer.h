// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ============================================================================
// src/startuptimer.h  --  ALWAYS-ON per-phase startup timing.
//
// A single global StartupTimer accumulates the wall time between successive
// phase boundaries during AppInit2 and, at "Done loading", LogPrintf's a
// SUMMARY table (each phase, its ms, and % of the AppInit2 total).
//
// Cost: each mark() is two GetTimeMicros() reads (on Linux a vDSO
// clock_gettime, ~20-30 ns, no syscall, no lock) plus one LogPrintf -- the
// same kind of line the existing ad-hoc "block index %15dms" / "wallet" /
// "rescan" checkpoints already emit. Across ~15 phase boundaries this is well
// under a microsecond against a cold startup measured in thousands of
// milliseconds: an unmeasurable skew. It is therefore unconditional (no flag).
//
// Startup is single-threaded (the timer is only touched on the AppInit2
// thread before StartNode spawns the net threads), so no locking is needed.
// ============================================================================
#ifndef BITCOIN_STARTUPTIMER_H
#define BITCOIN_STARTUPTIMER_H

#include <stdint.h>
#include <string>
#include <vector>

// One recorded phase, for the final SUMMARY table.
struct StartupPhase {
    std::string name;
    int64_t     micros;   // duration of this phase (since the previous mark)
};

class StartupTimer
{
public:
    StartupTimer();

    // Anchor the cumulative baseline at AppInit2 entry. Call once, first thing.
    void begin();

    // Record (phase, micros-since-last-mark). One-line call inserted at each
    // phase boundary, matching the existing nStart=GetTimeMillis() checkpoint
    // style. Reads the clock first, then LogPrintf's the per-phase line, so the
    // (potentially fsync-ing) debug.log write is never counted inside the phase
    // it closes.
    void mark(const char* phase);

    // Emit the per-phase SUMMARY table (name | ms | % of total) + an
    // (unaccounted) row + a TOTAL (AppInit2) row. Call once at "Done loading".
    void summary();

private:
    int64_t                  m_t0;    // GetTimeMicros() at begin()
    int64_t                  m_last;  // GetTimeMicros() at the previous mark()
    std::vector<StartupPhase> m_phases;
};

// The single global startup timer (defined in startuptimer.cpp).
extern StartupTimer g_startupTimer;

#endif // BITCOIN_STARTUPTIMER_H
