// Copyright (c) 2011-2021 The Bitcoin Core developers
// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Self-contained port mapping for the P2P listen port.
 *
 * Implements NAT-PMP (RFC 6886) and PCP (RFC 6887) directly over raw UDP to the
 * default gateway, with NO external library (no miniupnpc / libnatpmp) and NO
 * UPnP. UPnP was removed from this lineage (CVE-2015-20111): unlike UPnP, both
 * NAT-PMP and PCP can only ever map the *requester's own* source address, so a
 * node can only ever open a hole for itself. That self-only property is the
 * whole security advantage and the reason this is safe to ship.
 *
 * Only our own GetListenPort() is mapped. This module touches zero consensus
 * state — it is pure network plumbing.
 */
#ifndef BITCOIN_MAPPORT_H
#define BITCOIN_MAPPORT_H

#include "scheduler.h"

#include <boost/thread.hpp>

/** -natpmp default value. MUST default off for the first beta. */
static const bool DEFAULT_NATPMP = false;

/**
 * Start the port-mapping worker thread. Safe to call at most once per Start/Stop
 * cycle. Mirrors StartTorControl(): registered with the init thread_group only
 * for symmetry — the worker is actually a private, separately-joined thread so
 * that Interrupt/Stop can guarantee a prompt, race-free shutdown.
 */
void StartMapPort(boost::thread_group& threadGroup, CScheduler& scheduler);

/** Signal the worker to stop. Returns promptly; does not block on the thread. */
void InterruptMapPort();

/** Join the worker thread. Must be called after InterruptMapPort(). */
void StopMapPort();

#endif // BITCOIN_MAPPORT_H
