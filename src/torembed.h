// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .
//
// Embedded Tor (dynhost fork) lifecycle glue for in-process v3 onion P2P
// reachability. The ONLY Tor-touching C++ TU is torembed.cpp. This header is
// kept free of any _Atomic-bearing include so it can be included anywhere.
#ifndef ZCLASSIC_TOREMBED_H
#define ZCLASSIC_TOREMBED_H

#include <string>
#include <cstdint>

enum EmbeddedTorState {
    EMBEDTOR_DISABLED  = 0,
    EMBEDTOR_BOOTSTRAP = 1,
    EMBEDTOR_READY     = 2,
    EMBEDTOR_PUBLISHED = 3,
    EMBEDTOR_REACHABLE = 4,
    EMBEDTOR_FAILED    = 5
};

//! True when libtor was compiled in (ENABLE_TOR).
bool TorEmbedAvailable();
//! e.g. "Tor 0.4.9.x" — surfaced to RPC for CVE/version triage.
std::string TorEmbedProviderVersion();

//! Non-blocking, idempotent. (T1: build-proof only; full lifecycle in T2.)
bool StartEmbeddedTor(const std::string& datadir, uint16_t p2pPort);
void InterruptEmbeddedTor();   //!< from Interrupt()
void StopEmbeddedTor();        //!< bounded join from Shutdown()

EmbeddedTorState GetEmbeddedTorState();
int  GetEmbeddedTorBootstrapPct();      //!< 0..100; -1 unknown
std::string GetEmbeddedTorOnion();      //!< "" until READY
uint16_t GetEmbeddedTorControlPort();
uint16_t GetEmbeddedTorSocksPort();
int  GetEmbeddedTorInboundOnionPeers(); //!< for RPC tor.inbound_onion_peers

#endif // ZCLASSIC_TOREMBED_H
