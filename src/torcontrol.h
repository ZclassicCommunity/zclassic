// Copyright (c) 2015-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Functionality for communicating with Tor.
 */
#ifndef BITCOIN_TORCONTROL_H
#define BITCOIN_TORCONTROL_H

#include "scheduler.h"

#include <boost/thread.hpp>

extern const std::string DEFAULT_TOR_CONTROL;
static const bool DEFAULT_LISTEN_ONION = true;

void StartTorControl(boost::thread_group& threadGroup, CScheduler& scheduler);
void InterruptTorControl();
void StopTorControl();

/**
 * The embedded Tor was restarted (new loopback ports): make the control client
 * reconnect at once, backoff reset, and re-create the onion service from the
 * cached key. Safe from any thread; a no-op when the control client is off.
 */
void TorControlKick();

/** True when a -torcontrol address names this machine (loopback), so the Tor behind it shares our loopback. */
bool TorControlAddressIsLocal(const std::string& address);

#endif /* BITCOIN_TORCONTROL_H */
