// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// One request at a time for a periodic poll, without ever getting stuck.
//
// Connection::doRPC() answers neither callback when the connection is shutting down (and drops a reply that
// lands after the shutdown began), and a restart replaces the Connection object. A poll that only cleared its
// "in flight" flag inside the callbacks would then stay blocked for the rest of the session. This guard lets a
// new request start when the old one is certainly never going to answer: it was sent on another connection, or it
// has been outstanding for longer than any request should take. A late answer to an abandoned request is
// recognised by its ticket and cannot clear a newer request's flag.
#ifndef ZCL_POLLGUARD_H
#define ZCL_POLLGUARD_H

#include <chrono>
#include <cstdint>

class PollGuard {
public:
    typedef std::int64_t Ticket;   // 0: no request may be sent now

    static std::int64_t nowMs()
    {
        using namespace std::chrono;
        return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
    }

    // Ask to send a request on `conn` (any stable identity of the connection). Returns the ticket to pass to end()
    // from the callbacks, or 0 when a request is still plausibly in flight, or the connection is shutting down.
    Ticket begin(const void* conn, bool connShuttingDown, std::int64_t now = nowMs(), std::int64_t staleMs = 60000)
    {
        if (connShuttingDown || conn == nullptr)
            return 0;
        if (ticket_ != 0 && conn_ == conn && now - since_ < staleMs)
            return 0;
        ticket_ = ++issued_;
        conn_ = conn;
        since_ = now;
        return ticket_;
    }

    // The request with this ticket was answered (either way). A superseded request's late answer is ignored.
    void end(Ticket t)
    {
        if (t != 0 && t == ticket_)
            ticket_ = 0;
    }

    bool inFlight() const { return ticket_ != 0; }

private:
    Ticket ticket_ = 0;
    Ticket issued_ = 0;
    const void* conn_ = nullptr;
    std::int64_t since_ = 0;
};

#endif // ZCL_POLLGUARD_H
