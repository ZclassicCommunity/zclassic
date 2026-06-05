// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "startuptimer.h"

#include "util.h"        // LogPrintf
#include "utiltime.h"    // GetTimeMicros

StartupTimer g_startupTimer;

StartupTimer::StartupTimer()
    : m_t0(0), m_last(0)
{
}

void StartupTimer::begin()
{
    m_t0 = GetTimeMicros();
    m_last = m_t0;
    m_phases.clear();
}

void StartupTimer::mark(const char* phase)
{
    const int64_t now = GetTimeMicros();   // capture before logging
    const int64_t dur = now - m_last;
    const int64_t elapsed = now - m_t0;
    m_last = now;
    m_phases.push_back(StartupPhase{ std::string(phase), dur });
    LogPrintf("[startup] %-22s %9.1f ms  (elapsed %9.1f ms)\n",
              phase, dur / 1000.0, elapsed / 1000.0);
}

void StartupTimer::summary()
{
    const int64_t total = GetTimeMicros() - m_t0;
    const double total_ms = total / 1000.0;
    LogPrintf("[startup] ============ STARTUP TIMING SUMMARY ============\n");
    LogPrintf("[startup] %-22s %12s %8s\n", "phase", "ms", "%");
    int64_t accounted = 0;
    for (size_t i = 0; i < m_phases.size(); ++i) {
        const StartupPhase& p = m_phases[i];
        accounted += p.micros;
        LogPrintf("[startup] %-22s %12.1f %7.1f%%\n",
                  p.name, p.micros / 1000.0,
                  total > 0 ? (100.0 * p.micros / total) : 0.0);
    }
    const int64_t unacc = total - accounted;
    LogPrintf("[startup] %-22s %12.1f %7.1f%%\n", "(unaccounted)",
              unacc / 1000.0,
              total > 0 ? (100.0 * unacc / total) : 0.0);
    LogPrintf("[startup] %-22s %12.1f %7.1f%%\n", "TOTAL (AppInit2)",
              total_ms, 100.0);
    LogPrintf("[startup] ================================================\n");
}
