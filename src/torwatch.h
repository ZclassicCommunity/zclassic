// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Fail-soft embedded Tor: the pure parts of the restart driver. Retry
 * schedule, a closed fault vocabulary read from Tor's log tail, onion-name
 * redaction and the restart policy step. No clock, no threads, no globals:
 * the caller passes the time in (the driver lives in embeddedtor.cpp).
 *
 * Derived from Z23 engine/composition/include/config/boot_tor_watch.h and
 * engine/composition/src/boot_tor_watch.c (retry constants, fault classes,
 * log-tail scan, redaction), changed: C++, millisecond clock, policy as a
 * plain struct.
 */
#ifndef ZCLASSIC_TORWATCH_H
#define ZCLASSIC_TORWATCH_H

#include <stdint.h>
#include <string>

/** First restart delay, growth factor and cap: 5 s, 15 s, 45 s, 135 s, then 300 s. */
static const int64_t TOR_RETRY_FIRST_MS = 5000;
static const int64_t TOR_RETRY_GROWTH = 3;
static const int64_t TOR_RETRY_CAP_MS = 300000;
/** A Tor that stays up this long resets the backoff. */
static const int64_t TOR_UP_SETTLE_MS = 30000;
/** At most this many bytes of the log tail are read per scan. */
static const uint64_t TOR_LOG_TAIL_BYTES = 8192;
/**
 * In-process Tor shares libevent and OpenSSL global state with the node, so
 * it is restarted at most this many times per process; a child process has
 * no such limit.
 */
static const int TOR_MAX_RESTARTS_IN_PROCESS = 3;

/** Why Tor stopped. Ordered by specificity: a higher value is more specific. */
enum class TorFault {
    NONE = 0,
    EXITED,         //!< gone, cause not recognised in the log
    START_LIMIT,    //!< in-process restart cap used up; never read from the log
    CONFIG_INVALID, //!< "Failed to parse/validate config"
    DATADIR,        //!< permissions on <datadir>/tor
    PORT_IN_USE,    //!< "Could not bind ...: Address already in use"
};

/** Fixed lowercase token for a fault ("none", "exited", ...). Never free text. */
const char* TorFaultToken(TorFault fault);

/** Delay before restart number attempts+1. Negative counts as 0; never overflows. */
int64_t TorRetryDelayMs(int attempts);

/** Classify one Tor log line; NONE when it names no known fault. */
TorFault TorClassifyLogLine(const std::string& line);

/**
 * Most specific fault in the log at `path`, reading at most the last
 * TOR_LOG_TAIL_BYTES after byte offset `scanFrom` (from 0 when the file has
 * shrunk below it). A missing or unreadable file is NONE. `nextOffset`, when
 * given, gets the file size (the offset to scan from next time). Never throws.
 */
TorFault TorScanLogTail(const std::string& path, uint64_t scanFrom, uint64_t* nextOffset);

/** Replace every v3 onion name (56+ base32 chars, then ".onion") with "<onion>". */
std::string TorRedactOnion(const std::string& line);

/** Restart bookkeeping. Zero-initialise, set inProcess, and pass to TorRestartStep. */
struct TorRestartPolicy {
    int attempts;            //!< consecutive restarts without a settled run
    int64_t nextAttemptMs;   //!< when the next start is due (valid while down)
    int64_t upSinceMs;       //!< when the last restart came up; 0 once settled
    int restartsThisProcess; //!< restarts so far (the start at boot does not count)
    bool inProcess;          //!< in-process mode: TOR_MAX_RESTARTS_IN_PROCESS applies
    bool gaveUp;             //!< sticky: no more restarts in this process
    bool down;               //!< Tor seen dead, restart scheduled
    bool starting;           //!< a start was handed out and has not reported back
};

enum class TorRestartDecision {
    NOTHING,           //!< nothing to do this tick
    STOP_AND_SCHEDULE, //!< Tor just died: release it; a start is scheduled at nextAttemptMs
    START_NOW,         //!< start Tor now, then report with TorRestartStarted
    GIVE_UP,           //!< in-process cap reached (returned once)
};

/**
 * One tick of the policy. `alive` is whether the started Tor is running.
 * START_NOW counts the attempt (attempts and restartsThisProcess grow by
 * one) and holds further decisions until TorRestartStarted.
 */
TorRestartDecision TorRestartStep(TorRestartPolicy& p, bool alive, int64_t nowMs);

/** Report the outcome of a START_NOW: up since nowMs, or the next start scheduled. */
void TorRestartStarted(TorRestartPolicy& p, bool ok, int64_t nowMs);

#endif // ZCLASSIC_TORWATCH_H
