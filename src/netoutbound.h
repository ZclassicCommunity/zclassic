// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCLASSIC_NETOUTBOUND_H
#define ZCLASSIC_NETOUTBOUND_H

// The decision rules of one outbound selection round (SelectOutboundCandidate in
// net.cpp), with every input passed in: no address table, clock, lock or socket.

#include <stdint.h>

/** An address tried less than this many seconds ago is never dialled again, however
 *  small the table. */
static const int64_t OUTBOUND_MIN_REDIAL_SECONDS = 60;
/** Draws from the table in one selection round. */
static const int OUTBOUND_MAX_DRAWS = 300;

/** What the rules need to know about one draw from the address table. */
struct COutboundDraw {
    /** false: the table is empty, which ends the round. */
    bool fValid = false;
    /** Not a candidate, and not a try either: its network group has an outbound peer,
     *  it is our own address or a skipped host, or it is IPv6 without an IPv6 route. */
    bool fFree = false;
    /** Its network is limited (IsLimited). */
    bool fLimited = false;
    /** When it was last tried (0: never). */
    int64_t nLastTry = 0;
    /** CAddrInfo::IsTerrible at the round's time. */
    bool fTerrible = false;
    /** On the network's default port. */
    bool fDefaultPort = true;
};

/** Where a round's draws come from: net.cpp wraps an address table, tests a fixed list. */
class COutboundDrawSource
{
public:
    virtual ~COutboundDrawSource() {}
    virtual COutboundDraw Draw() = 0;
};

/** Whether a draw that is try number nTries (from 1) of the round may be dialled at
 *  nANow: not limited, not tried within OUTBOUND_MIN_REDIAL_SECONDS, and from the 30th
 *  try on also one tried within ten minutes or a terrible one, from the 50th try on
 *  also one on another port. */
bool OutboundDrawEligible(const COutboundDraw& draw, int64_t nANow, int nTries);

/** One selection round: up to OUTBOUND_MAX_DRAWS draws, ended early by an empty table
 *  or after 100 tries (draws that are not free). Returns the number (from 0) of the
 *  draw chosen, which is the last one taken from src, or -1 when none was. */
int SelectOutboundDraw(COutboundDrawSource& src, int64_t nANow);

#endif // ZCLASSIC_NETOUTBOUND_H
