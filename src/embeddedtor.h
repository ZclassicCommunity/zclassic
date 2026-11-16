// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Embedded Tor: the Tor linked into this binary (configure
 * --with-embedded-tor), started and stopped by the daemon. Thin C++ wrapper
 * over src/c23/tor (zcl_tor_embed). In a build without embedded Tor every
 * function here is a stub and EmbeddedTorAvailable() is false.
 */
#ifndef ZCLASSIC_EMBEDDEDTOR_H
#define ZCLASSIC_EMBEDDEDTOR_H

#include <stdint.h>
#include <string>

/** -embeddedtor default. Off until the feature has had wider testing. */
static const bool DEFAULT_EMBEDDED_TOR = false;

enum EmbeddedTorMode {
    /** Tor runs on a thread of this process (the way Z23 embeds it). */
    EMBEDDED_TOR_INPROCESS,
    /** Tor runs as a child: this binary re-executed, own address space. */
    EMBEDDED_TOR_CHILD,
};

/** -embeddedtormode default ("inprocess"). */
extern const char* const DEFAULT_EMBEDDED_TOR_MODE;

/** True when this binary was built with embedded Tor. */
bool EmbeddedTorAvailable();

/** Parse an -embeddedtormode value ("inprocess" or "child"). */
bool ParseEmbeddedTorMode(const std::string& str, EmbeddedTorMode& mode);

/**
 * First thing in main(): when this process is the Tor child (child mode), run
 * Tor and return its exit status (>= 0). Otherwise return -1 and do nothing.
 */
int EmbeddedTorDispatch(int argc, char* argv[]);

/**
 * Launch Tor with its state in <datadir>/tor, a loopback SOCKS port and a
 * loopback control port (cookie authentication), both chosen by Tor at
 * runtime. Returns once the control port answers and the SOCKS port is known;
 * bootstrapping continues in the background. Call only while the datadir lock
 * is held.
 */
bool StartEmbeddedTor(const std::string& datadir, EmbeddedTorMode mode, std::string& strError);

/** Stop Tor and wait for it to be gone. Safe to call when it was never started. */
void StopEmbeddedTor();

/** True between a successful StartEmbeddedTor and StopEmbeddedTor. */
bool EmbeddedTorRunning();

/** Loopback SOCKS5 port of the running instance, 0 when not running. */
uint16_t EmbeddedTorSocksPort();

/** Loopback control port of the running instance, 0 when not running. */
uint16_t EmbeddedTorControlPort();

#endif // ZCLASSIC_EMBEDDEDTOR_H
