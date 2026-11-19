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

#include "torwatch.h"

#include <stdint.h>
#include <string>

class CScheduler;
namespace boost {
class thread_group;
}

/** -embeddedtor default. Off until the feature has had wider testing. */
static const bool DEFAULT_EMBEDDED_TOR = false;

enum EmbeddedTorMode {
    /** Tor runs on a thread of this process (the way Z23 embeds it). */
    EMBEDDED_TOR_INPROCESS,
    /** Tor runs as a child: this binary re-executed, own address space. */
    EMBEDDED_TOR_CHILD,
};

/** -embeddedtormode default: "child" on Linux, "inprocess" elsewhere. */
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

/**
 * Stop Tor and wait for it to be gone. Idempotent, safe to call when it was
 * never started; EmbeddedTorRunning() is false afterwards. Returns false only
 * when a running Tor did not stop within 15 s (its handle is then leaked,
 * since Tor may still use it).
 */
bool StopEmbeddedTor();

/** True between a successful StartEmbeddedTor and StopEmbeddedTor. */
bool EmbeddedTorRunning();

/** Loopback SOCKS5 port of the running instance, 0 when not running. */
uint16_t EmbeddedTorSocksPort();

/** Loopback control port of the running instance, 0 when not running. */
uint16_t EmbeddedTorControlPort();

/** Control cookie file of the running instance, empty when not running. */
std::string EmbeddedTorCookiePath();

/**
 * True while the started Tor is still running. False when it was never
 * started, was stopped, or has exited (thread returned or child process
 * gone) on its own.
 */
bool EmbeddedTorAlive();

/** Child process id of the running instance, 0 in-process or when not running. */
long EmbeddedTorChildPid();

/**
 * Tests only: the binary to re-execute as the Tor child (empty: this
 * process's own) and DisableNetwork for the next starts. The test binary does
 * not dispatch the child role, so a child-mode test points this at zclassicd.
 */
void SetEmbeddedTorTestOptions(const std::string& exePath, bool disableNetwork);

/**
 * Fail-soft restart driver, started once in init after the first start
 * succeeded. From then on a Tor that exits is stopped, the proxies it served
 * are pointed at a closed loopback port, and it is started again after 5, 15,
 * 45, 135, then every 300 s (inprocess mode: at most
 * TOR_MAX_RESTARTS_IN_PROCESS restarts). The node never shuts down for it.
 * A scheduler job (every 5 s) only decides; the stops and starts run on the
 * zcl-torwatch thread in `threadGroup`, which join_all stops before Shutdown()
 * stops Tor. rewireOnion/rewireClearnet say which proxies init gave the
 * embedded Tor (onion; IPv4, IPv6 and names), randomize is -proxyrandomize.
 */
void EmbeddedTorWatchStart(boost::thread_group& threadGroup, CScheduler& scheduler,
                           const std::string& datadir, EmbeddedTorMode mode, bool rewireOnion,
                           bool rewireClearnet, bool randomize);

/** "off" (not armed), "running", "restarting" or "failed" (no more restarts). */
std::string EmbeddedTorStatus();

/** Why Tor last stopped or failed to start; NONE while running. */
TorFault EmbeddedTorFault();

/** EmbeddedTorStatus(), with ":<fault token>" when failed. Never an onion name or free text. */
std::string EmbeddedTorStatusToken();

/**
 * True once the driver is armed: this node's Tor is the embedded one, also
 * while it is restarting. The control client then never falls back to
 * another Tor (-torcontrol default) and waits for the embedded one instead.
 */
bool EmbeddedTorManaged();

/**
 * True when the arguments ask for an onion-only node with the embedded Tor:
 * -embeddedtor=1 and an -onlynet list that names neither ipv4 nor ipv6. Such
 * a node must not open a clearnet connection, also not before Tor is up.
 */
bool EmbeddedTorOnionOnlyRequested();

#endif // ZCLASSIC_EMBEDDEDTOR_H
