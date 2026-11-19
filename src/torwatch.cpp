// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "torwatch.h"

#include <stdio.h>

const char* TorFaultToken(TorFault fault)
{
    switch (fault) {
    case TorFault::NONE: return "none";
    case TorFault::EXITED: return "exited";
    case TorFault::START_LIMIT: return "start_limit";
    case TorFault::CONFIG_INVALID: return "config_invalid";
    case TorFault::DATADIR: return "datadir";
    case TorFault::PORT_IN_USE: return "port_in_use";
    }
    return "none";
}

int64_t TorRetryDelayMs(int attempts)
{
    int64_t delay = TOR_RETRY_FIRST_MS;
    // The loop stops at the cap, so it runs at most a handful of times
    // whatever `attempts` is; a negative count runs it zero times.
    for (int i = 0; i < attempts && delay < TOR_RETRY_CAP_MS; i++)
        delay *= TOR_RETRY_GROWTH;
    return delay < TOR_RETRY_CAP_MS ? delay : TOR_RETRY_CAP_MS;
}

static bool Has(const std::string& line, const char* needle)
{
    return line.find(needle) != std::string::npos;
}

static TorFault MoreSpecific(TorFault a, TorFault b)
{
    return static_cast<int>(a) >= static_cast<int>(b) ? a : b;
}

TorFault TorClassifyLogLine(const std::string& line)
{
    TorFault fault = TorFault::NONE;
    if (Has(line, "Failed to parse/validate config") || Has(line, "Reading config failed"))
        fault = MoreSpecific(fault, TorFault::CONFIG_INVALID);
    if (Has(line, "Permission denied") || Has(line, "Couldn't access private data directory") ||
        (Has(line, "DataDirectory") && Has(line, "not")))
        fault = MoreSpecific(fault, TorFault::DATADIR);
    if (Has(line, "Address already in use") || Has(line, "Could not bind"))
        fault = MoreSpecific(fault, TorFault::PORT_IN_USE);
    return fault;
}

/** Size of an open file, or -1. */
static long FileSize(FILE* f)
{
    if (fseek(f, 0, SEEK_END) != 0)
        return -1;
    return ftell(f);
}

/** Most specific fault over the lines of `text`. */
static TorFault ClassifyText(const std::string& text)
{
    TorFault fault = TorFault::NONE;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos)
            end = text.size();
        fault = MoreSpecific(fault, TorClassifyLogLine(text.substr(start, end - start)));
        start = end + 1;
    }
    return fault;
}

TorFault TorScanLogTail(const std::string& path, uint64_t scanFrom, uint64_t* nextOffset)
{
    if (nextOffset)
        *nextOffset = scanFrom;
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
        return TorFault::NONE;
    const long size = FileSize(f);
    if (size < 0) {
        fclose(f);
        return TorFault::NONE;
    }
    const uint64_t usize = static_cast<uint64_t>(size);
    uint64_t from = scanFrom <= usize ? scanFrom : 0; // a truncated log starts over
    if (usize - from > TOR_LOG_TAIL_BYTES)
        from = usize - TOR_LOG_TAIL_BYTES;
    std::string text;
    if (fseek(f, static_cast<long>(from), SEEK_SET) == 0) {
        char buf[TOR_LOG_TAIL_BYTES];
        size_t got = fread(buf, 1, static_cast<size_t>(usize - from), f);
        text.assign(buf, got);
    }
    fclose(f);
    if (nextOffset)
        *nextOffset = usize;
    return ClassifyText(text);
}

static bool IsBase32Lower(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

std::string TorRedactOnion(const std::string& line)
{
    static const std::string suffix = ".onion";
    static const size_t V3_LEN = 56;
    std::string out;
    out.reserve(line.size());
    size_t i = 0;
    while (i < line.size()) {
        size_t run = 0;
        while (i + run < line.size() && IsBase32Lower(line[i + run]))
            run++;
        if (run == 0) {
            out.push_back(line[i++]);
            continue;
        }
        // A whole run is copied or replaced at once, so a shorter run inside
        // a longer one is never looked at on its own.
        if (run >= V3_LEN && line.compare(i + run, suffix.size(), suffix) == 0) {
            out += "<onion>";
            i += run + suffix.size();
        } else {
            out.append(line, i, run);
            i += run;
        }
    }
    return out;
}

TorRestartDecision TorRestartStep(TorRestartPolicy& p, bool alive, int64_t nowMs)
{
    if (p.gaveUp || p.starting)
        return TorRestartDecision::NOTHING;
    if (alive) {
        if (p.upSinceMs > 0 && nowMs - p.upSinceMs >= TOR_UP_SETTLE_MS) {
            p.attempts = 0;
            p.upSinceMs = 0;
        }
        return TorRestartDecision::NOTHING;
    }
    if (!p.down) {
        p.down = true;
        p.upSinceMs = 0;
        p.nextAttemptMs = nowMs + TorRetryDelayMs(p.attempts);
        return TorRestartDecision::STOP_AND_SCHEDULE;
    }
    if (nowMs < p.nextAttemptMs)
        return TorRestartDecision::NOTHING;
    if (p.inProcess && p.restartsThisProcess >= TOR_MAX_RESTARTS_IN_PROCESS) {
        p.gaveUp = true;
        return TorRestartDecision::GIVE_UP;
    }
    if (p.attempts < 64) // the delay is capped long before; keep the count bounded
        p.attempts++;
    p.restartsThisProcess++;
    p.starting = true;
    return TorRestartDecision::START_NOW;
}

void TorRestartStarted(TorRestartPolicy& p, bool ok, int64_t nowMs)
{
    p.starting = false;
    if (ok) {
        p.down = false;
        p.upSinceMs = nowMs > 0 ? nowMs : 1;
    } else {
        p.nextAttemptMs = nowMs + TorRetryDelayMs(p.attempts);
    }
}
