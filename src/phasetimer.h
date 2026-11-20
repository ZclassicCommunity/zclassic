// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PHASETIMER_H
#define BITCOIN_PHASETIMER_H

// Scoped wall-clock timer for one step of a longer sequence (Shutdown()). The
// destructor logs "<scope>: <what> took <ms> ms" when the step took 100 ms or
// more, so a normal fast stop adds no log lines but a slow step is named.

#include "tinyformat.h"
#include "util.h"
#include "utiltime.h"

#include <stdint.h>
#include <string>

static const int64_t PHASE_TIMER_LOG_MIN_MS = 100;

inline std::string FormatPhaseLine(const char* scope, const char* what, int64_t ms)
{
    return strprintf("%s: %s took %d ms\n", scope, what, ms);
}

struct PhaseTimer {
    const char* scope;
    const char* what;
    int64_t t0;

    PhaseTimer(const char* scopeIn, const char* whatIn)
        : scope(scopeIn), what(whatIn), t0(GetTimeMillis()) {}
    ~PhaseTimer()
    {
        const int64_t ms = GetTimeMillis() - t0;
        if (ms >= PHASE_TIMER_LOG_MIN_MS)
            LogPrintf("%s", FormatPhaseLine(scope, what, ms));
    }

private:
    PhaseTimer(const PhaseTimer&);
    PhaseTimer& operator=(const PhaseTimer&);
};

#endif // BITCOIN_PHASETIMER_H
