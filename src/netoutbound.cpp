// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netoutbound.h"

bool OutboundDrawEligible(const COutboundDraw& draw, int64_t nANow, int nTries)
{
    if (draw.fLimited)
        return false;

    const int64_t nSinceTry = nANow - draw.nLastTry;

    // never redial within a minute: on a small table the relaxation below would
    // otherwise hand the same address (one that answers and drops us at once is
    // the one the tried table keeps) to every round and starve the others
    if (nSinceTry < OUTBOUND_MIN_REDIAL_SECONDS)
        return false;

    // only consider very recently tried nodes after 30 failed attempts
    if (nSinceTry < 600 && nTries < 30)
        return false;

    // nor, before as many draws, an address addrman counts as terrible: not seen
    // for a month (peers gossip addresses years old), or tried often without a
    // success. On a small table these are most of the dead addresses, and each
    // one dialled costs a connect timeout before a live peer is reached.
    if (draw.fTerrible && nTries < 30)
        return false;

    // do not allow non-default ports, unless after 50 invalid addresses selected already
    if (!draw.fDefaultPort && nTries < 50)
        return false;

    return true;
}

int SelectOutboundDraw(COutboundDrawSource& src, int64_t nANow)
{
    int nTries = 0;
    for (int nDraws = 0; nDraws < OUTBOUND_MAX_DRAWS; nDraws++) {
        const COutboundDraw draw = src.Draw();

        // an empty table: nothing to choose from this round
        if (!draw.fValid)
            break;

        // A free draw is not a candidate, but it does not use up the round either:
        // on a small table (a fresh node knows a handful of addresses) one such draw
        // would otherwise end the round before the port and recency rules could let
        // anything through.
        if (draw.fFree)
            continue;

        // If we didn't find an appropriate destination after trying 100 addresses fetched from addrman,
        // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
        // already-connected network ranges, ...) before trying new addrman addresses.
        nTries++;
        if (nTries > 100)
            break;

        if (OutboundDrawEligible(draw, nANow, nTries))
            return nDraws;
    }
    return -1;
}
